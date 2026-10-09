// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./Poseidon2BabyBear.sol";

/**
 * @title MerkleVerifier
 * @notice Merkle tree verification using Poseidon2 hash for RISC Zero STARK proofs
 * @dev Uses Poseidon2 over BabyBear field for quantum-resistant commitments
 *
 * QUANTUM RESISTANCE:
 * Merkle trees with hash-based commitments are quantum-resistant.
 * The security relies only on collision resistance of the hash function.
 */
library MerkleVerifier {
    using Poseidon2BabyBear for uint256;

    /// @notice Verify a Merkle proof
    /// @param root The Merkle root commitment
    /// @param leaf The leaf value (field element)
    /// @param index The leaf index
    /// @param proof The Merkle proof (sibling hashes along the path)
    /// @return valid True if the proof is valid
    function verify(
        uint256 root,
        uint256 leaf,
        uint256 index,
        uint256[] memory proof
    ) internal pure returns (bool valid) {
        uint256 current = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            if (index & 1 == 0) {
                // Current is left child
                current = Poseidon2BabyBear.hash2(current, proof[i]);
            } else {
                // Current is right child
                current = Poseidon2BabyBear.hash2(proof[i], current);
            }
            index >>= 1;
        }

        return current == root;
    }

    /// @notice Verify multiple leaves at once (batch verification for FRI queries)
    /// @param root The Merkle root commitment
    /// @param leaves Array of leaf values
    /// @param indices Array of leaf indices
    /// @param proofs Array of Merkle proofs
    /// @return valid True if all proofs are valid
    function verifyBatch(
        uint256 root,
        uint256[] memory leaves,
        uint256[] memory indices,
        uint256[][] memory proofs
    ) internal pure returns (bool valid) {
        require(leaves.length == indices.length, "Length mismatch");
        require(leaves.length == proofs.length, "Proof count mismatch");

        for (uint256 i = 0; i < leaves.length; i++) {
            if (!verify(root, leaves[i], indices[i], proofs[i])) {
                return false;
            }
        }

        return true;
    }

    /// @notice Compute Merkle root from leaves
    /// @dev Used for testing and verification. In practice, provers compute this.
    /// @param leaves The leaf values
    /// @return root The Merkle root
    function computeRoot(uint256[] memory leaves) internal pure returns (uint256 root) {
        require(leaves.length > 0, "Empty leaves");

        // Pad to power of 2
        uint256 n = 1;
        while (n < leaves.length) {
            n *= 2;
        }

        uint256[] memory layer = new uint256[](n);
        for (uint256 i = 0; i < leaves.length; i++) {
            layer[i] = leaves[i];
        }
        // Remaining elements are 0

        // Build tree bottom-up
        while (n > 1) {
            uint256 nextN = n / 2;
            uint256[] memory nextLayer = new uint256[](nextN);
            for (uint256 i = 0; i < nextN; i++) {
                nextLayer[i] = Poseidon2BabyBear.hash2(layer[2 * i], layer[2 * i + 1]);
            }
            layer = nextLayer;
            n = nextN;
        }

        return layer[0];
    }

    /// @notice Verify a Merkle proof for a column of values (FRI uses multi-element columns)
    /// @param root The Merkle root
    /// @param column Array of field elements at the position
    /// @param index The column index
    /// @param proof The Merkle proof
    /// @return valid True if valid
    function verifyColumn(
        uint256 root,
        uint256[] memory column,
        uint256 index,
        uint256[] memory proof
    ) internal pure returns (bool valid) {
        // Hash column to single value
        uint256 leaf = Poseidon2BabyBear.hashMany(column);
        return verify(root, leaf, index, proof);
    }

    /// @notice Verify a Merkle proof (bytes32 overload for RiscZeroStarkVerifier)
    /// @param proof The Merkle proof path (sibling hashes)
    /// @param root The Merkle root commitment
    /// @param leaf The leaf value
    /// @param index The leaf index
    /// @return valid True if the proof is valid
    function verify(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf,
        uint256 index
    ) internal pure returns (bool valid) {
        uint256 current = uint256(leaf);

        for (uint256 i = 0; i < proof.length; i++) {
            if (index & 1 == 0) {
                // Current is left child
                current = Poseidon2BabyBear.hash2(current, uint256(proof[i]));
            } else {
                // Current is right child
                current = Poseidon2BabyBear.hash2(uint256(proof[i]), current);
            }
            index >>= 1;
        }

        return current == uint256(root);
    }
}
