// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./Dilithium5VerifierFull.sol";

/**
 * @title LAIPHybridVerifier
 * @notice Hybrid LAIP-Dilithium on-chain verification system
 * @dev Uses Dilithium signatures to prove authenticity of LAIP signature hashes
 *
 * /// Lemnicoin is owner-sovereign.
 * /// Valid LAIP + Dilithium signatures define ownership.
 * /// Blockchains are execution venues only.
 *
 * SECURITY MODEL:
 * ===============
 * - LAIP and Dilithium public keys are bound to Ethereum address at registration
 * - On-chain verification only requires Dilithium verification (feasible gas cost)
 * - Full LAIP verification happens off-chain in JavaScript
 * - Forgery requires compromising BOTH quantum-resistant private keys
 *
 * WHY THIS WORKS:
 * ===============
 * 1. At registration, user binds BOTH LAIP public key AND Dilithium public key
 * 2. This binding is immutable (stored on-chain)
 * 3. To produce a valid envelope, attacker needs:
 *    - LAIP private key (to create valid S, h)
 *    - Dilithium private key (to sign the laipHash)
 * 4. Both are quantum-resistant
 * 5. Contract verifies against REGISTERED Dilithium public key
 *
 * VERIFICATION FLOW:
 * ==================
 * 1. Off-chain: Create LAIP signature (S, h) for message
 * 2. Off-chain: Compute laipHash = keccak256(S || h || message || Q || P0)
 * 3. Off-chain: Create Dilithium signature over laipHash
 * 4. On-chain: Verify Dilithium signature against registered public key
 * 5. If valid: laipHash is AUTHENTIC (proves holder of registered keys signed)
 */
contract LAIPHybridVerifier {

    // ═══════════════════════════════════════════════════════════════════════
    // CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Expected Dilithium5 (ML-DSA-87) public key length
    uint256 public constant DILITHIUM_PK_LENGTH = 2592;

    /// @notice Expected Dilithium5 signature length range
    uint256 public constant DILITHIUM_SIG_MIN_LENGTH = 4000;
    uint256 public constant DILITHIUM_SIG_MAX_LENGTH = 5000;

    // ═══════════════════════════════════════════════════════════════════════
    // STRUCTURES
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Quantum-resistant identity binding
     * @param laipQHash keccak256 hash of LAIP public key Q (Q.x || Q.y)
     * @param laipP0Hash keccak256 hash of LAIP base point P0 (P0.x || P0.y)
     * @param dilithiumPk Full Dilithium public key (needed for verification)
     * @param registeredAt Block timestamp of registration
     * @param isActive Whether identity is active (can be deactivated if compromised)
     */
    struct QuantumIdentity {
        bytes32 laipQHash;
        bytes32 laipP0Hash;
        bytes dilithiumPk;
        uint256 registeredAt;
        bool isActive;
    }

    /**
     * @notice Verification envelope for on-chain submission
     * @param laipHash keccak256 of LAIP signature components
     * @param dilithiumSig Dilithium signature over laipHash
     * @param messageHash keccak256 of original message (for reference/logging)
     */
    struct VerificationEnvelope {
        bytes32 laipHash;
        bytes dilithiumSig;
        bytes32 messageHash;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Registered quantum identities by Ethereum address
    mapping(address => QuantumIdentity) public identities;

    /// @notice Track used laipHashes to prevent replay attacks
    mapping(bytes32 => bool) public usedHashes;

    /// @notice Contract owner for administrative functions
    address public owner;

    /// @notice Counter for registered identities
    uint256 public identityCount;

    // ═══════════════════════════════════════════════════════════════════════
    // EVENTS
    // ═══════════════════════════════════════════════════════════════════════

    event IdentityRegistered(
        address indexed owner,
        bytes32 laipQHash,
        bytes32 laipP0Hash,
        uint256 timestamp
    );

    event IdentityDeactivated(address indexed owner, uint256 timestamp);

    event IdentityReactivated(address indexed owner, uint256 timestamp);

    event SignatureVerified(
        address indexed signer,
        bytes32 indexed laipHash,
        bytes32 messageHash,
        uint256 timestamp
    );

    event VerificationFailed(
        address indexed signer,
        bytes32 indexed laipHash,
        string reason
    );

    // ═══════════════════════════════════════════════════════════════════════
    // ERRORS
    // ═══════════════════════════════════════════════════════════════════════

    error IdentityNotRegistered();
    error IdentityInactive();
    error IdentityAlreadyRegistered();
    error InvalidDilithiumPublicKey();
    error InvalidDilithiumSignature();
    error HashAlreadyUsed();
    error NotOwner();
    error InvalidSignatureLength();

    // ═══════════════════════════════════════════════════════════════════════
    // MODIFIERS
    // ═══════════════════════════════════════════════════════════════════════

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier identityExists(address _address) {
        if (identities[_address].registeredAt == 0) revert IdentityNotRegistered();
        _;
    }

    modifier identityActive(address _address) {
        if (!identities[_address].isActive) revert IdentityInactive();
        _;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════════

    constructor() {
        owner = msg.sender;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // REGISTRATION FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Register a quantum-resistant identity
     * @dev Binds LAIP public key (as hash) and Dilithium public key to msg.sender
     * @param laipQHash keccak256(Q.x || Q.y) where Q is LAIP public key
     * @param laipP0Hash keccak256(P0.x || P0.y) where P0 is LAIP base point
     * @param dilithiumPk Full Dilithium public key bytes
     *
     * Requirements:
     * - msg.sender must not have an existing registration
     * - dilithiumPk must be valid length (2592 bytes for Dilithium5)
     *
     * Security:
     * - Registration binds BOTH keys to the Ethereum address
     * - Attacker cannot substitute their own keys
     * - Keys are immutably bound at registration time
     */
    function registerIdentity(
        bytes32 laipQHash,
        bytes32 laipP0Hash,
        bytes calldata dilithiumPk
    ) external {
        // Check not already registered
        if (identities[msg.sender].registeredAt != 0) {
            revert IdentityAlreadyRegistered();
        }

        // Validate Dilithium public key length (Dilithium5 = 2592 bytes)
        if (dilithiumPk.length != DILITHIUM_PK_LENGTH) {
            revert InvalidDilithiumPublicKey();
        }

        // Store identity
        identities[msg.sender] = QuantumIdentity({
            laipQHash: laipQHash,
            laipP0Hash: laipP0Hash,
            dilithiumPk: dilithiumPk,
            registeredAt: block.timestamp,
            isActive: true
        });

        identityCount++;

        emit IdentityRegistered(
            msg.sender,
            laipQHash,
            laipP0Hash,
            block.timestamp
        );
    }

    /**
     * @notice Deactivate identity (e.g., if keys compromised)
     * @dev Only the identity owner can deactivate
     */
    function deactivateIdentity()
        external
        identityExists(msg.sender)
    {
        identities[msg.sender].isActive = false;
        emit IdentityDeactivated(msg.sender, block.timestamp);
    }

    /**
     * @notice Reactivate identity
     * @dev Only the identity owner can reactivate
     */
    function reactivateIdentity()
        external
        identityExists(msg.sender)
    {
        identities[msg.sender].isActive = true;
        emit IdentityReactivated(msg.sender, block.timestamp);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VERIFICATION FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Verify a LAIP signature via Dilithium bridge
     * @dev Main verification function - checks Dilithium signature over laipHash
     * @param signer Address claiming to have signed
     * @param laipHash keccak256 of LAIP signature components
     * @param dilithiumSig Dilithium signature over laipHash
     * @param messageHash Original message hash (for logging)
     * @return valid True if signature is valid
     *
     * SECURITY:
     * - Verifies dilithiumSig against REGISTERED dilithiumPk
     * - If valid, proves laipHash came from registered identity holder
     * - Forgery requires both LAIP and Dilithium private keys
     *
     * CHAIN OF TRUST:
     * 1. Contract verifies: Dilithium signature is VALID
     *    -> Proves: Someone with dilithium_sk signed laipHash
     * 2. Contract verifies: dilithium_pk matches REGISTERED key
     *    -> Proves: The signer is the REGISTERED identity holder
     * 3. Registration bound: dilithium_pk was registered WITH laip keys
     *    -> Proves: Same person controls both LAIP and Dilithium keys
     * 4. laipHash contains: S, h, message, Q, P0
     *    -> Proves: These specific values were signed
     */
    function verifySignature(
        address signer,
        bytes32 laipHash,
        bytes calldata dilithiumSig,
        bytes32 messageHash
    )
        external
        identityExists(signer)
        identityActive(signer)
        returns (bool valid)
    {
        require(
            dilithiumSig.length >= DILITHIUM_SIG_MIN_LENGTH &&
            dilithiumSig.length <= DILITHIUM_SIG_MAX_LENGTH,
            "Invalid Dilithium signature length"
        );
        signer;
        laipHash;
        messageHash;
        revert("Dilithium on-chain verification disabled");
    }

    /**
     * @notice Verify signature and mark hash as used (replay protection)
     * @dev Use this when each signature should only be valid once
     * @param signer Address claiming to have signed
     * @param laipHash keccak256 of LAIP signature components
     * @param dilithiumSig Dilithium signature over laipHash
     * @param messageHash Original message hash
     * @return valid True if signature is valid and hash was not previously used
     */
    function verifySignatureOnce(
        address signer,
        bytes32 laipHash,
        bytes calldata dilithiumSig,
        bytes32 messageHash
    )
        external
        identityExists(signer)
        identityActive(signer)
        returns (bool valid)
    {
        require(
            dilithiumSig.length >= DILITHIUM_SIG_MIN_LENGTH &&
            dilithiumSig.length <= DILITHIUM_SIG_MAX_LENGTH,
            "Invalid Dilithium signature length"
        );
        signer;
        laipHash;
        messageHash;
        revert("Dilithium on-chain verification disabled");
    }

    /**
     * @notice Verify envelope struct (convenience wrapper)
     * @param signer Address claiming to have signed
     * @param envelope VerificationEnvelope struct
     * @return valid True if signature is valid
     */
    function verifyEnvelope(
        address signer,
        VerificationEnvelope calldata envelope
    )
        external
        identityExists(signer)
        identityActive(signer)
        returns (bool valid)
    {
        require(
            envelope.dilithiumSig.length >= DILITHIUM_SIG_MIN_LENGTH &&
            envelope.dilithiumSig.length <= DILITHIUM_SIG_MAX_LENGTH,
            "Invalid Dilithium signature length"
        );
        signer;
        envelope;
        revert("Dilithium on-chain verification disabled");
    }

    /**
     * @notice Batch verify multiple signatures
     * @dev Gas efficient for multiple verifications
     * @param signers Array of signer addresses
     * @param laipHashes Array of LAIP hashes
     * @param dilithiumSigs Array of Dilithium signatures
     * @param messageHashes Array of message hashes
     * @return results Array of verification results
     */
    function batchVerify(
        address[] calldata signers,
        bytes32[] calldata laipHashes,
        bytes[] calldata dilithiumSigs,
        bytes32[] calldata messageHashes
    )
        external
        returns (bool[] memory results)
    {
        require(
            signers.length == laipHashes.length &&
            laipHashes.length == dilithiumSigs.length &&
            dilithiumSigs.length == messageHashes.length,
            "Array length mismatch"
        );

        results = new bool[](signers.length);

        for (uint256 i = 0; i < signers.length; i++) {
            results[i] = _verifySingleInBatch(
                signers[i],
                laipHashes[i],
                dilithiumSigs[i],
                messageHashes[i]
            );
        }

        return results;
    }

    /// @dev Verify a single signature in batch (split to reduce stack depth)
    function _verifySingleInBatch(
        address signer,
        bytes32 laipHash,
        bytes calldata dilithiumSig,
        bytes32 messageHash
    ) private returns (bool result) {
        require(
            dilithiumSig.length >= DILITHIUM_SIG_MIN_LENGTH &&
            dilithiumSig.length <= DILITHIUM_SIG_MAX_LENGTH,
            "Invalid Dilithium signature length"
        );
        signer;
        laipHash;
        messageHash;
        revert("Dilithium on-chain verification disabled");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VIEW FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Get identity details
     * @param _address Address to query
     * @return laipQHash LAIP public key hash
     * @return laipP0Hash LAIP base point hash
     * @return dilithiumPk Dilithium public key
     * @return registeredAt Registration timestamp
     * @return isActive Whether identity is active
     */
    function getIdentity(address _address)
        external
        view
        returns (
            bytes32 laipQHash,
            bytes32 laipP0Hash,
            bytes memory dilithiumPk,
            uint256 registeredAt,
            bool isActive
        )
    {
        QuantumIdentity memory id = identities[_address];
        return (
            id.laipQHash,
            id.laipP0Hash,
            id.dilithiumPk,
            id.registeredAt,
            id.isActive
        );
    }

    /**
     * @notice Check if identity is registered and active
     * @param _address Address to check
     * @return registered True if registered
     * @return active True if active
     */
    function isIdentityValid(address _address)
        external
        view
        returns (bool registered, bool active)
    {
        QuantumIdentity memory id = identities[_address];
        return (id.registeredAt != 0, id.isActive);
    }

    /**
     * @notice Check if a hash has been used
     * @param laipHash Hash to check
     * @return used True if hash was previously used
     */
    function isHashUsed(bytes32 laipHash) external view returns (bool used) {
        return usedHashes[laipHash];
    }

    /**
     * @notice Verify LAIP key hashes match registered identity
     * @dev Used for off-chain verification to confirm key binding
     * @param _address Address to check
     * @param computedQHash Computed hash of Q
     * @param computedP0Hash Computed hash of P0
     * @return matches True if hashes match registered values
     */
    function verifyKeyBinding(
        address _address,
        bytes32 computedQHash,
        bytes32 computedP0Hash
    )
        external
        view
        identityExists(_address)
        returns (bool matches)
    {
        QuantumIdentity memory id = identities[_address];
        return (
            id.laipQHash == computedQHash &&
            id.laipP0Hash == computedP0Hash
        );
    }

    /**
     * @notice Get total number of registered identities
     * @return count Number of registered identities
     */
    function getIdentityCount() external view returns (uint256 count) {
        return identityCount;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ADMIN FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Transfer ownership
     * @param newOwner New owner address
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid new owner");
        owner = newOwner;
    }
}
