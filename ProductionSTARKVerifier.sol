// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./interfaces/IFactRegistry.sol";
import "./interfaces/ISTARKVerifier.sol";

/**
 * @title ProductionSTARKVerifier
 * @notice Production STARK verifier using StarkWare's SHARP (Shared Prover)
 * @dev This contract interfaces with StarkWare's deployed SHARP verifier on Ethereum
 *
 * Architecture:
 * 1. Off-chain: Stone prover generates STARK proof for Cairo program execution
 * 2. Off-chain: Proof is submitted to SHARP (Shared Prover) aggregation service
 * 3. On-chain: SHARP verifier verifies the aggregated proof and registers facts
 * 4. On-chain: This contract queries the fact registry to verify statements
 *
 * SHARP Verifier (Ethereum Mainnet): 0x47312450B3Ac8b5b8e247a6bB6d523e7605bDb60
 *
 * Fact Format:
 * fact = keccak256(abi.encodePacked(programHash, outputHash))
 * where:
 * - programHash: Hash of the Cairo program bytecode
 * - outputHash: Hash of the program output (public inputs + result)
 *
 * Security Model:
 * - 128-bit cryptographic security (STARK soundness)
 * - No trusted setup (transparent)
 * - Battle-tested (in production since 2020)
 */
contract ProductionSTARKVerifier is ISTARKVerifier {
    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice StarkWare's Fact Registry contract
    IFactRegistry public immutable factRegistry;

    /// @notice Hash of the Cairo program for dual signature verification
    bytes32 public immutable programHash;

    // SECURITY: Mock verification has been permanently removed.
    // All verification MUST go through the SHARP Fact Registry.
    // This ensures cryptographic soundness - forgery is computationally infeasible.

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidFactRegistry();
    error InvalidProgramHash();
    error ProofNotVerified();
    error InvalidProofFormat();

    // =========================================================================
    // EVENTS
    // =========================================================================

    event FactVerified(
        bytes32 indexed fact,
        bytes32 indexed programHash,
        bytes32 indexed outputHash
    );

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    /**
     * @notice Deploy the production STARK verifier
     * @param _factRegistry Address of StarkWare's SHARP Fact Registry (REQUIRED)
     *        Mainnet: 0x47312450B3Ac8b5b8e247a6bB6d523e7605bDb60
     *        Goerli:  0xAB43bA48c9edF4C2C4bB01237348D1D7B28ef168
     * @param _programHash Hash of the dual signature verification Cairo program (REQUIRED)
     *
     * SECURITY: A valid fact registry address is REQUIRED. This contract will NOT
     * function without a real SHARP Fact Registry. Mock verification has been
     * permanently removed to ensure cryptographic soundness.
     */
    constructor(
        address _factRegistry,
        bytes32 _programHash
    ) {
        if (_factRegistry == address(0)) {
            revert InvalidFactRegistry();
        }
        if (_programHash == bytes32(0)) {
            revert InvalidProgramHash();
        }

        factRegistry = IFactRegistry(_factRegistry);
        programHash = _programHash;
    }

    // =========================================================================
    // VERIFICATION
    // =========================================================================

    /**
     * @notice Verify a STARK proof via the fact registry
     * @param proof The proof data containing outputHash
     *        Format: outputHash (32 bytes) || optional metadata
     * @param expectedPublicInputHash Expected hash of public inputs
     * @return true if the fact is registered (proof was verified by SHARP)
     *
     * Flow:
     * 1. Extract outputHash from proof
     * 2. Compute fact = keccak256(programHash || outputHash)
     * 3. Query fact registry to check if fact exists
     * 4. Return true if fact is registered (meaning SHARP verified the proof)
     */
    function verifyProof(
        bytes calldata proof,
        bytes32 expectedPublicInputHash
    ) external view returns (bool) {
        // SECURITY: All verification goes through SHARP Fact Registry.
        // No mock verification - forgery resistance is guaranteed.

        if (proof.length < 32) {
            revert InvalidProofFormat();
        }

        // Extract output hash from proof
        bytes32 outputHash;
        assembly {
            outputHash := calldataload(proof.offset)
        }

        // The output hash must incorporate the public input hash
        // This ensures the proof is for the correct public inputs
        bytes32 expectedOutputHash = keccak256(
            abi.encodePacked(expectedPublicInputHash, outputHash)
        );

        // Compute the fact that should be registered
        // fact = keccak256(programHash || outputHash)
        bytes32 fact = keccak256(abi.encodePacked(programHash, expectedOutputHash));

        // Query the fact registry
        bool isValid = factRegistry.isValid(fact);

        if (!isValid) {
            revert ProofNotVerified();
        }

        return true;
    }

    /**
     * @notice Check if a specific fact is registered
     * @param outputHash The output hash from the Cairo program
     * @return true if the fact is registered
     */
    function isFactRegistered(bytes32 outputHash) external view returns (bool) {
        if (address(factRegistry) == address(0)) {
            return false;
        }

        bytes32 fact = keccak256(abi.encodePacked(programHash, outputHash));
        return factRegistry.isValid(fact);
    }

    /**
     * @notice Compute the fact hash for given output
     * @param outputHash The output hash from the Cairo program
     * @return The fact hash that should be registered
     */
    function computeFact(bytes32 outputHash) external view returns (bytes32) {
        return keccak256(abi.encodePacked(programHash, outputHash));
    }

    /**
     * @notice Compute expected output hash for dual signature verification
     * @param messageHash Hash of the message that was signed
     * @param laipQHash Hash of the LAIP-Q public key
     * @param dilithiumPkHash Hash of the Dilithium public key
     * @param sender Address of the transaction sender
     * @param nonce Transaction nonce
     * @return The expected output hash
     */
    function computeExpectedOutputHash(
        bytes32 messageHash,
        bytes32 laipQHash,
        bytes32 dilithiumPkHash,
        address sender,
        uint256 nonce
    ) external pure returns (bytes32) {
        // Cairo program output format:
        // [message_hash, laip_q_hash, dilithium_pk_hash, sender, nonce, verification_result]
        return keccak256(
            abi.encodePacked(
                messageHash,
                laipQHash,
                dilithiumPkHash,
                sender,
                nonce,
                uint256(1) // verification_result = 1 (success)
            )
        );
    }

}
