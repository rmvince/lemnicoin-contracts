// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ISTARKVerifier
 * @notice Interface for STARK proof verification
 * @dev This interface defines the contract that verifies Cairo STARK proofs
 *
 * /// Lemnicoin is owner-sovereign.
 * /// Valid LAIP + Dilithium signatures define ownership.
 * /// Blockchains are execution venues only.
 */
interface ISTARKVerifier {
    /**
     * @notice Public inputs that the STARK proof commits to
     * @dev These values are visible on-chain and verified against registered identity
     */
    struct PublicInputs {
        bytes32 messageHash;      // Hash of the signed message
        bytes32 laipQHash;        // keccak256(Qx || Qy) of 3072-bit LAIP pubkey
        bytes32 dilithiumPkHash;  // keccak256(dilithiumPk)
        address sender;           // Transaction sender
        uint256 nonce;            // Replay protection
    }

    /**
     * @notice Verify a STARK proof with explicit public inputs
     * @param inputs The public inputs the proof commits to
     * @param proof The STARK proof data
     * @return valid True if proof is valid for given inputs
     */
    function verifyProofWithInputs(
        PublicInputs calldata inputs,
        bytes calldata proof
    ) external returns (bool valid);

    /**
     * @notice Verify a raw STARK proof (inputs embedded in proof)
     * @param proof The complete STARK proof with embedded inputs
     * @return valid True if proof is valid
     */
    function verifyProof(bytes calldata proof) external returns (bool valid);

    /**
     * @notice Check if a proof has been used (replay protection)
     * @param proofHash Hash of the proof
     * @return used True if proof was already verified
     */
    function isProofUsed(bytes32 proofHash) external view returns (bool used);

    /**
     * @notice Get the verified Cairo program hash
     * @dev Only proofs from this program are accepted
     * @return programHash The program commitment
     */
    function verifiedProgramHash() external view returns (bytes32 programHash);
}
