// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IRiscZeroStarkVerifier
 * @notice Interface for STARK-based dual signature verification (Model A)
 * @dev Used by Lemnicoin for quantum-resistant transfers via STARK proofs
 */
interface IRiscZeroStarkVerifier {
    /**
     * @notice Compute fact hash for a dual signature verification
     * @param messageHash The transaction hash that was signed
     * @param laipPubkeyHash Hash of the LAIP public key
     * @param dilithiumPubkeyHash Hash of the Dilithium public key
     * @return factHash The fact hash that would be registered upon successful verification
     */
    function computeFactHashFromInputs(
        bytes32 messageHash,
        bytes32 laipPubkeyHash,
        bytes32 dilithiumPubkeyHash
    ) external pure returns (bytes32);

    /**
     * @notice Check if a dual signature fact has been verified
     * @param factHash The fact hash to check
     * @return verified True if the fact was verified via STARK proof
     */
    function isFactVerified(bytes32 factHash) external view returns (bool);
}
