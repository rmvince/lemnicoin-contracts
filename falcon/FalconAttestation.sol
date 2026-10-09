// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./IZKNOXEthFalcon.sol";

/**
 * @title FalconAttestation
 * @notice Mixin for quantum-resistant transaction authorization via Falcon attestation
 * @author Lemnicoin Team
 *
 * @dev Security Model:
 * - User signs transaction intent with LAIP + ML-DSA-87 (quantum-resistant)
 * - EC2 attestor verifies both signatures off-chain
 * - Attestor signs attestation with Falcon-512 (quantum-resistant)
 * - This contract verifies only the Falcon attestation (~1.8M gas)
 *
 * Anti-Forgery Bindings (all included in signed digest):
 * - Chain binding: chainId in domain separator
 * - Contract binding: address(this) in domain separator
 * - Caller binding: user address in struct
 * - Action binding: to, amount in struct
 * - Replay protection: monotonic nonce per user
 * - Expiry: deadline timestamp
 * - Verification binding: quantumInputHash links to exact signatures verified
 *
 * The attestation is useless if copied to another chain, contract, caller,
 * or if the nonce doesn't match or deadline has passed.
 */
abstract contract FalconAttestation {

    // =========================================================================
    // CONFIGURATION
    // =========================================================================

    /// @notice ETHFALCON verifier contract
    IZKNOXEthFalcon public immutable FALCON_VERIFIER;

    /// @notice Attestor public key in NTT domain (32 uint256 values)
    uint256[32] public ATTESTOR_NTTH;

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Replay protection: monotonic nonce per user
    mapping(address => uint256) public pqAttestationNonce;

    // =========================================================================
    // EIP-712 DOMAIN SEPARATION
    // =========================================================================

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 private constant ATTEST_TYPEHASH =
        keccak256("PQAttestation(address user,address to,uint256 amount,bytes32 quantumInputHash,uint256 nonce,uint256 deadline)");

    bytes32 private constant NAME_HASH = keccak256("LemnicoinPQAttestation");
    bytes32 private constant VERSION_HASH = keccak256("1");

    // =========================================================================
    // EVENTS
    // =========================================================================

    event FalconAttestationVerified(
        address indexed user,
        address indexed to,
        uint256 amount,
        uint256 nonce,
        bytes32 quantumInputHash
    );

    event AttestorKeyUpdated(uint256[32] newNtth);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error AttestationExpired();
    error InvalidNonce(uint256 expected, uint256 provided);
    error InvalidSaltLength(uint256 length);
    error InvalidS2Length(uint256 length);
    error FalconVerificationFailed();
    error ZeroVerifierAddress();
    error ZeroRecipient();
    error InsufficientBalance();

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    /**
     * @param falconVerifier Address of deployed ZKNOX_ethfalcon contract
     * @param attestorNtth32 Attestor's Falcon public key in NTT domain (32 elements)
     */
    constructor(address falconVerifier, uint256[32] memory attestorNtth32) {
        if (falconVerifier == address(0)) revert ZeroVerifierAddress();
        FALCON_VERIFIER = IZKNOXEthFalcon(falconVerifier);

        // Copy attestor public key
        for (uint256 i = 0; i < 32; i++) {
            ATTESTOR_NTTH[i] = attestorNtth32[i];
        }
    }

    // =========================================================================
    // DOMAIN SEPARATOR
    // =========================================================================

    /**
     * @notice Compute EIP-712 domain separator
     * @dev Includes chainId and address(this) for cross-chain/cross-contract protection
     */
    function _domainSeparatorV4() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                NAME_HASH,
                VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
    }

    /**
     * @notice Compute the attestation digest that the attestor signed
     */
    function _attestationDigest(
        address user,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                ATTEST_TYPEHASH,
                user,
                to,
                amount,
                quantumInputHash,
                nonce,
                deadline
            )
        );

        return keccak256(
            abi.encodePacked("\x19\x01", _domainSeparatorV4(), structHash)
        );
    }

    // =========================================================================
    // SHARED FALCON VERIFICATION
    // =========================================================================

    /**
     * @dev Shared Falcon attestation verification: validates deadline, nonce,
     *      signature format, verifies Falcon signature, and consumes nonce.
     */
    function _verifyAndConsumeFalcon(
        address sender,
        bytes32 digest,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32
    ) internal {
        if (block.timestamp > deadline) revert AttestationExpired();
        uint256 expectedNonce = pqAttestationNonce[sender];
        if (nonce != expectedNonce) revert InvalidNonce(expectedNonce, nonce);
        if (falconSalt40.length != 40) revert InvalidSaltLength(falconSalt40.length);
        if (falconS2_32.length != 32) revert InvalidS2Length(falconS2_32.length);

        bool valid = FALCON_VERIFIER.verify(
            abi.encodePacked(digest),
            falconSalt40,
            _toMemoryArray(falconS2_32),
            _getAttestorNtth()
        );
        if (!valid) revert FalconVerificationFailed();

        pqAttestationNonce[sender] = nonce + 1;
    }

    // =========================================================================
    // MAIN VERIFICATION FUNCTION
    // =========================================================================

    /**
     * @notice Transfer authorized by Falcon attestation from EC2 server
     */
    function transferWithFalconAttestation(
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32
    ) external virtual returns (bool) {
        if (to == address(0)) revert ZeroRecipient();
        bytes32 digest = _attestationDigest(msg.sender, to, amount, quantumInputHash, nonce, deadline);
        _verifyAndConsumeFalcon(msg.sender, digest, nonce, deadline, falconSalt40, falconS2_32);
        _transfer(msg.sender, to, amount);
        emit FalconAttestationVerified(msg.sender, to, amount, nonce, quantumInputHash);
        return true;
    }

    /**
     * @notice Internal version that accepts sender as parameter
     * @dev Used by child contracts to avoid msg.sender issues with external calls
     */
    function _transferWithFalconAttestationFrom(
        address sender,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32
    ) internal returns (bool) {
        if (to == address(0)) revert ZeroRecipient();
        bytes32 digest = _attestationDigest(sender, to, amount, quantumInputHash, nonce, deadline);
        _verifyAndConsumeFalcon(sender, digest, nonce, deadline, falconSalt40, falconS2_32);
        _transfer(sender, to, amount);
        emit FalconAttestationVerified(sender, to, amount, nonce, quantumInputHash);
        return true;
    }

    // =========================================================================
    // BATCH VERIFICATION (for multiple transfers in one tx)
    // =========================================================================

    /**
     * @notice Batch multiple Falcon-attested transfers in one transaction
     * @dev Each transfer must have its own attestation. Gas savings from reduced base costs.
     */
    struct BatchTransferParams {
        address to;
        uint256 amount;
        bytes32 quantumInputHash;
        uint256 nonce;
        uint256 deadline;
        bytes falconSalt40;
        uint256[] falconS2_32;
    }

    function batchTransferWithFalconAttestation(
        BatchTransferParams[] calldata transfers
    ) external virtual returns (bool) {
        for (uint256 i = 0; i < transfers.length; i++) {
            BatchTransferParams calldata t = transfers[i];
            if (t.to == address(0)) revert ZeroRecipient();
            bytes32 digest = _attestationDigest(msg.sender, t.to, t.amount, t.quantumInputHash, t.nonce, t.deadline);
            _verifyAndConsumeFalcon(msg.sender, digest, t.nonce, t.deadline, t.falconSalt40, t.falconS2_32);
            _transfer(msg.sender, t.to, t.amount);
            emit FalconAttestationVerified(msg.sender, t.to, t.amount, t.nonce, t.quantumInputHash);
        }
        return true;
    }

    // =========================================================================
    // APPROVAL WITH FALCON ATTESTATION
    // =========================================================================

    /**
     * @notice Approve spender authorized by Falcon attestation
     * @dev Uses same attestation pattern for approvals.
     *      Child contracts should override to add additional verification (e.g. LAIP).
     */
    function approveWithFalconAttestation(
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32
    ) external virtual returns (bool) {
        return _approveWithFalconInternal(
            msg.sender, spender, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32
        );
    }

    /**
     * @notice Internal approval logic for reuse by child contracts
     */
    function _approveWithFalconInternal(
        address sender,
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32
    ) internal returns (bool) {
        if (spender == address(0)) revert ZeroRecipient();
        bytes32 approvalStructHash = keccak256(
            abi.encode(
                keccak256("PQApproval(address user,address spender,uint256 amount,bytes32 quantumInputHash,uint256 nonce,uint256 deadline)"),
                sender, spender, amount, quantumInputHash, nonce, deadline
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _domainSeparatorV4(), approvalStructHash)
        );
        _verifyAndConsumeFalcon(sender, digest, nonce, deadline, falconSalt40, falconS2_32);
        _approve(sender, spender, amount);
        return true;
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    /**
     * @notice Copy calldata array to memory (required by ETHFALCON interface)
     */
    function _toMemoryArray(uint256[] calldata arr) internal pure returns (uint256[] memory) {
        uint256[] memory result = new uint256[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) {
            result[i] = arr[i];
        }
        return result;
    }

    /**
     * @notice Get attestor public key as memory array (required by ETHFALCON interface)
     */
    function _getAttestorNtth() internal view returns (uint256[] memory) {
        uint256[] memory result = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            result[i] = ATTESTOR_NTTH[i];
        }
        return result;
    }

    /**
     * @notice Internal transfer function - must be implemented by inheriting contract
     */
    function _transfer(address from, address to, uint256 amount) internal virtual;

    /**
     * @notice Internal approve function - must be implemented by inheriting contract
     */
    function _approve(address owner, address spender, uint256 amount) internal virtual;

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get current nonce for a user
     */
    function getNonce(address user) external view returns (uint256) {
        return pqAttestationNonce[user];
    }

    /**
     * @notice Get current approval nonce for a user (alias for getNonce)
     * @dev Approvals and transfers share the same nonce to prevent cross-operation replay
     */
    function getApprovalNonce(address user) external view returns (uint256) {
        return pqAttestationNonce[user];
    }

    /**
     * @notice Compute what the attestation digest would be for given parameters
     * @dev Useful for dApp to verify attestor returned correct digest
     */
    function computeDigest(
        address user,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32) {
        return _attestationDigest(user, to, amount, quantumInputHash, nonce, deadline);
    }

    /**
     * @notice Compute approval digest
     */
    function computeApprovalDigest(
        address user,
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32) {
        bytes32 approvalStructHash = keccak256(
            abi.encode(
                keccak256("PQApproval(address user,address spender,uint256 amount,bytes32 quantumInputHash,uint256 nonce,uint256 deadline)"),
                user,
                spender,
                amount,
                quantumInputHash,
                nonce,
                deadline
            )
        );

        return keccak256(
            abi.encodePacked("\x19\x01", _domainSeparatorV4(), approvalStructHash)
        );
    }

    /**
     * @notice Get the domain separator
     */
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @notice Get attestor public key
     */
    function getAttestorPublicKey() external view returns (uint256[32] memory) {
        return ATTESTOR_NTTH;
    }

    // =========================================================================
    // ATTESTOR KEY ROTATION
    // =========================================================================

    /**
     * @notice Internal function to rotate the attestor public key
     * @dev Must be called by a protected external function in the inheriting contract
     * @param newNtth The new attestor public key in NTT domain (32 uint256 values)
     */
    function _rotateAttestorKey(uint256[32] memory newNtth) internal {
        for (uint256 i = 0; i < 32; i++) {
            ATTESTOR_NTTH[i] = newNtth[i];
        }
        emit AttestorKeyUpdated(newNtth);
    }
}
