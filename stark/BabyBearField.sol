// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title BabyBearField
 * @notice Field arithmetic for the BabyBear prime field used by RISC Zero
 * @dev BabyBear prime: p = 15 * 2^27 + 1 = 2013265921
 *
 * This field is used because:
 * 1. p < 2^31, fits in a 32-bit word (efficient on CPUs)
 * 2. p-1 has large power of 2 factor (2^27), excellent for FFT/NTT
 *
 * QUANTUM RESISTANCE:
 * Field operations are purely arithmetic - no elliptic curves involved.
 * Combined with hash-based commitments (Poseidon2), this provides QR verification.
 */
library BabyBearField {
    /// @notice The BabyBear prime: p = 15 * 2^27 + 1
    uint256 constant P = 2013265921;

    /// @notice The generator of the multiplicative group
    uint256 constant GENERATOR = 31;

    /// @notice 2^27 root of unity (for NTT operations)
    uint256 constant ROOT_OF_UNITY = 1927992256;

    /// @notice Add two field elements
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            uint256 sum = a + b;
            return sum >= P ? sum - P : sum;
        }
    }

    /// @notice Subtract two field elements
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return a >= b ? a - b : P - b + a;
        }
    }

    /// @notice Multiply two field elements
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return (a * b) % P;
        }
    }

    /// @notice Compute modular inverse using Fermat's little theorem
    /// @dev a^(-1) = a^(p-2) mod p
    function inv(uint256 a) internal pure returns (uint256) {
        require(a != 0, "Cannot invert zero");
        return exp(a, P - 2);
    }

    /// @notice Modular exponentiation
    function exp(uint256 base, uint256 exponent) internal pure returns (uint256) {
        unchecked {
            uint256 result = 1;
            base = base % P;

            while (exponent > 0) {
                if (exponent & 1 == 1) {
                    result = (result * base) % P;
                }
                exponent >>= 1;
                base = (base * base) % P;
            }

            return result;
        }
    }

    /// @notice Compute the nth root of unity
    /// @dev Returns omega such that omega^n = 1 and omega^(n/2) != 1
    function rootOfUnity(uint256 n) internal pure returns (uint256) {
        require(n > 0 && (n & (n - 1)) == 0, "n must be power of 2");
        require(n <= (1 << 27), "n too large for BabyBear");

        // ROOT_OF_UNITY^(2^27) = 1
        // We need omega such that omega^n = 1
        // So omega = ROOT_OF_UNITY^(2^27 / n)
        uint256 exponent = (1 << 27) / n;
        return exp(ROOT_OF_UNITY, exponent);
    }

    /// @notice Negate a field element
    function neg(uint256 a) internal pure returns (uint256) {
        return a == 0 ? 0 : P - a;
    }

    /// @notice Division in the field
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return mul(a, inv(b));
    }

    /// @notice Check if value is a valid field element
    function isValid(uint256 a) internal pure returns (bool) {
        return a < P;
    }

    /// @notice Reduce a value modulo P
    function reduce(uint256 a) internal pure returns (uint256) {
        return a % P;
    }

    /// @notice Alias for rootOfUnity (backwards compatibility)
    function getRootOfUnity(uint256 n) internal pure returns (uint256) {
        return rootOfUnity(n);
    }
}
