// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./interfaces/IFactRegistry.sol";

/**
 * @title LemnicoinFactRegistry
 * @notice Self-contained Fact Registry for Lemnicoin STARK proof verification
 * @dev Implements the Fact Registry pattern for trustless verification
 *
 * /// Lemnicoin is owner-sovereign.
 * /// Valid LAIP + Dilithium signatures define ownership.
 * /// Blockchains are execution venues only.
 *
 * SECURITY MODEL (Model A - Trustless Soundness):
 * ===============================================
 * This contract stores facts (keccak256(programHash || outputHash)) that have been
 * verified by an authorized verifier. Unlike the trusted prover model where the
 * prover is trusted to only generate valid proofs, this model provides cryptographic
 * soundness:
 *
 * 1. Facts are only registered after full algebraic STARK verification
 * 2. Verification is performed by the Stone prover server
 * 3. Once registered, facts cannot be removed or modified
 * 4. On-chain verification is a simple storage lookup (~5K gas)
 *
 * INTEGRATION:
 * ============
 * 1. Stone prover generates STARK proof and verifies algebraically
 * 2. Stone prover submits fact to this registry via registerFact()
 * 3. DualSignatureSTARKVerifierImpl queries isValid() to check if fact exists
 *
 * This can be used alongside StarkWare's SHARP Fact Registry for:
 * - Development/testing (deploy your own registry)
 * - Alternative chains (where SHARP is not available)
 * - Custom verification logic
 */
contract LemnicoinFactRegistry is IFactRegistry {
    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Registered facts
    mapping(bytes32 => bool) private _facts;

    /// @notice Whether any fact has been registered
    bool private _hasRegisteredFact;

    /// @notice Authorized verifiers that can register facts
    mapping(address => bool) public authorizedVerifiers;

    /// @notice Contract owner
    address public owner;

    /// @notice Total number of facts registered
    uint256 public factCount;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event FactRegistered(
        bytes32 indexed fact,
        bytes32 indexed programHash,
        bytes32 indexed outputHash,
        address verifier,
        uint256 timestamp
    );

    event VerifierAuthorized(address indexed verifier, bool authorized);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error Unauthorized();
    error FactAlreadyRegistered();
    error InvalidFact();

    // =========================================================================
    // MODIFIERS
    // =========================================================================

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier onlyAuthorizedVerifier() {
        if (!authorizedVerifiers[msg.sender] && msg.sender != owner) {
            revert Unauthorized();
        }
        _;
    }

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    /**
     * @notice Deploy the Fact Registry
     * @param initialVerifier Address of initial authorized verifier (can be address(0))
     */
    constructor(address initialVerifier) {
        owner = msg.sender;

        if (initialVerifier != address(0)) {
            authorizedVerifiers[initialVerifier] = true;
            emit VerifierAuthorized(initialVerifier, true);
        }
    }

    // =========================================================================
    // IFactRegistry IMPLEMENTATION
    // =========================================================================

    /**
     * @notice Check if a fact has been verified and registered
     * @param fact The fact hash (keccak256 of the proven statement)
     * @return True if the fact is registered
     */
    function isValid(bytes32 fact) external view override returns (bool) {
        return _facts[fact];
    }

    /**
     * @notice Check if any fact has ever been registered in this registry
     * @return True if at least one fact exists
     */
    function hasRegisteredFact() external view override returns (bool) {
        return _hasRegisteredFact;
    }

    // =========================================================================
    // FACT REGISTRATION
    // =========================================================================

    /**
     * @notice Register a fact after verification
     * @dev Only authorized verifiers can register facts
     * @param programHash Hash of the Cairo program
     * @param outputHash Hash of the program output
     *
     * The fact is computed as: keccak256(abi.encodePacked(programHash, outputHash))
     *
     * SECURITY: This function should ONLY be called after the Stone prover
     * has performed full algebraic STARK verification. The verifier must
     * be trusted to only call this function for valid proofs.
     */
    function registerFact(
        bytes32 programHash,
        bytes32 outputHash
    ) external onlyAuthorizedVerifier {
        bytes32 fact = keccak256(abi.encodePacked(programHash, outputHash));

        if (_facts[fact]) revert FactAlreadyRegistered();
        if (fact == bytes32(0)) revert InvalidFact();

        _facts[fact] = true;
        _hasRegisteredFact = true;
        factCount++;

        emit FactRegistered(fact, programHash, outputHash, msg.sender, block.timestamp);
    }

    /**
     * @notice Register a pre-computed fact directly
     * @dev Only authorized verifiers can register facts
     * @param fact The pre-computed fact hash
     */
    function registerFactDirect(bytes32 fact) external onlyAuthorizedVerifier {
        if (_facts[fact]) revert FactAlreadyRegistered();
        if (fact == bytes32(0)) revert InvalidFact();

        _facts[fact] = true;
        _hasRegisteredFact = true;
        factCount++;

        emit FactRegistered(fact, bytes32(0), bytes32(0), msg.sender, block.timestamp);
    }

    /**
     * @notice Batch register multiple facts
     * @dev Only authorized verifiers can register facts
     * @param facts Array of fact hashes to register
     */
    function registerFactsBatch(bytes32[] calldata facts) external onlyAuthorizedVerifier {
        for (uint256 i = 0; i < facts.length; i++) {
            bytes32 fact = facts[i];

            if (fact == bytes32(0)) continue; // Skip invalid
            if (_facts[fact]) continue; // Skip already registered

            _facts[fact] = true;
            factCount++;

            emit FactRegistered(fact, bytes32(0), bytes32(0), msg.sender, block.timestamp);
        }

        _hasRegisteredFact = true;
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Authorize or revoke a verifier
     * @param verifier Address to authorize/revoke
     * @param authorized True to authorize, false to revoke
     */
    function setVerifierAuthorization(
        address verifier,
        bool authorized
    ) external onlyOwner {
        authorizedVerifiers[verifier] = authorized;
        emit VerifierAuthorized(verifier, authorized);
    }

    /**
     * @notice Transfer ownership
     * @param newOwner New owner address
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid new owner");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Check if an address is an authorized verifier
     * @param verifier Address to check
     * @return True if authorized
     */
    function isAuthorizedVerifier(address verifier) external view returns (bool) {
        return authorizedVerifiers[verifier] || verifier == owner;
    }

    /**
     * @notice Compute fact hash from components
     * @param programHash Hash of the Cairo program
     * @param outputHash Hash of the program output
     * @return Computed fact hash
     */
    function computeFact(
        bytes32 programHash,
        bytes32 outputHash
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(programHash, outputHash));
    }

    /**
     * @notice Get the total number of registered facts
     * @return Number of facts
     */
    function getFactCount() external view returns (uint256) {
        return factCount;
    }
}
