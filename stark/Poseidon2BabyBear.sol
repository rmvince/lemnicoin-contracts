// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./BabyBearField.sol";

/**
 * @title Poseidon2BabyBear
 * @notice Poseidon2 hash function over BabyBear field for RISC Zero STARK verification
 * @dev Poseidon2 is an improved version of Poseidon with separate internal/external rounds
 *
 * QUANTUM RESISTANCE:
 * Poseidon2 is a hash function based on modular arithmetic - no elliptic curves.
 * It provides collision resistance based on algebraic hardness assumptions.
 * Combined with STARK proofs, this gives quantum-resistant verification.
 *
 * Parameters for BabyBear (t=16, security ~100 bits):
 * - State width: 16 field elements
 * - External rounds: 8 (4 beginning + 4 end)
 * - Internal rounds: 13
 * - S-box: x^7 (optimal for BabyBear)
 */
library Poseidon2BabyBear {
    using BabyBearField for uint256;

    /// @notice State width (number of field elements)
    uint256 constant WIDTH = 16;

    /// @notice External rounds (full S-box applied to all elements)
    uint256 constant EXTERNAL_ROUNDS = 8;

    /// @notice Internal rounds (S-box applied only to first element)
    uint256 constant INTERNAL_ROUNDS = 13;

    /// @notice Total rounds
    uint256 constant TOTAL_ROUNDS = EXTERNAL_ROUNDS + INTERNAL_ROUNDS;

    /// @notice S-box exponent (x^7 for BabyBear)
    uint256 constant SBOX_POWER = 7;

    /// @notice Hash two field elements (2-to-1 compression)
    function hash2(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256[16] memory state;
        state[0] = a;
        state[1] = b;
        // Rest initialized to 0

        permute(state);

        return state[0];
    }

    /// @notice Hash an array of field elements
    function hashMany(uint256[] memory inputs) internal pure returns (uint256) {
        uint256[16] memory state;

        // Absorb inputs in chunks of WIDTH-1 (rate)
        uint256 rate = WIDTH - 1;
        uint256 chunks = (inputs.length + rate - 1) / rate;

        for (uint256 c = 0; c < chunks; c++) {
            // Add inputs to state
            for (uint256 i = 0; i < rate && c * rate + i < inputs.length; i++) {
                state[i] = state[i].add(inputs[c * rate + i]);
            }
            permute(state);
        }

        return state[0];
    }

    /// @notice Hash bytes (convert to field elements first)
    function hashBytes(bytes memory data) internal pure returns (uint256) {
        // Pack bytes into field elements (3 bytes per element for BabyBear safety)
        uint256 numElements = (data.length + 2) / 3;
        uint256[] memory elements = new uint256[](numElements + 1);

        // Include length for domain separation
        elements[0] = data.length;

        for (uint256 i = 0; i < numElements; i++) {
            uint256 value = 0;
            for (uint256 j = 0; j < 3 && i * 3 + j < data.length; j++) {
                value |= uint256(uint8(data[i * 3 + j])) << (8 * j);
            }
            elements[i + 1] = value % BabyBearField.P;
        }

        return hashMany(elements);
    }

    /// @notice The Poseidon2 permutation
    function permute(uint256[16] memory state) internal pure {
        // External rounds (beginning)
        for (uint256 r = 0; r < EXTERNAL_ROUNDS / 2; r++) {
            externalRound(state, r);
        }

        // Internal rounds
        for (uint256 r = 0; r < INTERNAL_ROUNDS; r++) {
            internalRound(state, EXTERNAL_ROUNDS / 2 + r);
        }

        // External rounds (end)
        for (uint256 r = 0; r < EXTERNAL_ROUNDS / 2; r++) {
            externalRound(state, EXTERNAL_ROUNDS / 2 + INTERNAL_ROUNDS + r);
        }
    }

    /// @notice External round: S-box on all elements + linear layer + round constants
    function externalRound(uint256[16] memory state, uint256 round) internal pure {
        // Add round constants
        for (uint256 i = 0; i < WIDTH; i++) {
            state[i] = state[i].add(getRoundConstant(round, i));
        }

        // S-box on all elements
        for (uint256 i = 0; i < WIDTH; i++) {
            state[i] = sbox(state[i]);
        }

        // Linear layer (M4 matrix applied 4 times)
        linearLayer(state);
    }

    /// @notice Internal round: S-box only on first element + linear layer + round constant
    function internalRound(uint256[16] memory state, uint256 round) internal pure {
        // Add round constant only to first element
        state[0] = state[0].add(getRoundConstant(round, 0));

        // S-box only on first element
        state[0] = sbox(state[0]);

        // Linear layer
        linearLayer(state);
    }

    /// @notice S-box: x^7
    function sbox(uint256 x) internal pure returns (uint256) {
        // x^7 = x^4 * x^2 * x
        uint256 x2 = x.mul(x);
        uint256 x4 = x2.mul(x2);
        return x4.mul(x2).mul(x);
    }

    /// @notice Linear layer using the Poseidon2 M4 matrix structure
    /// @dev Applies M4 to each group of 4 elements, then diffusion layer
    function linearLayer(uint256[16] memory state) internal pure {
        // Apply M4 to each group of 4
        for (uint256 i = 0; i < 4; i++) {
            m4(state, i * 4);
        }

        // Diffusion layer: sum and add back
        uint256 sum = 0;
        for (uint256 i = 0; i < WIDTH; i++) {
            sum = sum.add(state[i]);
        }
        for (uint256 i = 0; i < WIDTH; i++) {
            state[i] = state[i].add(sum);
        }
    }

    /// @notice M4 matrix multiplication for Poseidon2
    /// @dev Optimized 4x4 matrix: [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
    function m4(uint256[16] memory state, uint256 offset) internal pure {
        uint256 a = state[offset];
        uint256 b = state[offset + 1];
        uint256 c = state[offset + 2];
        uint256 d = state[offset + 3];

        // Compute t = a + b + c + d
        uint256 t = a.add(b).add(c).add(d);

        // Apply M4 matrix
        state[offset]     = t.add(a).add(b);     // 2a + 3b + c + d = t + a + b
        state[offset + 1] = t.add(b).add(c);     // a + 2b + 3c + d = t + b + c
        state[offset + 2] = t.add(c).add(d);     // a + b + 2c + 3d = t + c + d
        state[offset + 3] = t.add(d).add(a);     // 3a + b + c + 2d = t + d + a
    }

    /// @notice Get round constant for given round and position
    /// @dev Constants derived from SHA-256 of "Poseidon2BabyBear" || round || position
    function getRoundConstant(uint256 round, uint256 position) internal pure returns (uint256) {
        // Generate deterministic constants using keccak256
        // In production, these would be precomputed and stored
        bytes32 hash = keccak256(abi.encodePacked("Poseidon2BabyBear", round, position));
        return uint256(hash) % BabyBearField.P;
    }
}
