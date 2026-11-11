// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title NTT - Number Theoretic Transform
 * @dev NTT implementation for Dilithium polynomial operations
 *
 * Based on:
 * - https://github.com/ZKNoxHQ/NTT
 * - CRYSTALS-Dilithium specification
 *
 * The NTT is used for efficient polynomial multiplication in Dilithium.
 * It transforms polynomials from coefficient representation to NTT domain
 * and back, enabling O(n log n) multiplication instead of O(n²).
 *
 * PARAMETERS FOR DILITHIUM:
 * - Q = 8380417 (prime modulus)
 * - N = 256 (polynomial degree)
 * - Root of unity: 1753 (primitive 512-th root of unity mod Q)
 */
library NTT {
    // Dilithium parameters
    uint32 constant Q = 8380417;      // Prime modulus
    uint32 constant N = 256;          // Polynomial degree
    uint32 constant ROOT = 1753;      // Primitive 512-th root of unity mod Q
    uint32 constant QINV = 58728449;  // Q^(-1) mod 2^32 (for Montgomery)

    /**
     * @dev Forward NTT transform
     *
     * Transforms polynomial from coefficient to NTT representation.
     * Input: coefficients a[0], ..., a[255]
     * Output: NTT(a)[0], ..., NTT(a)[255]
     *
     * @param a Polynomial coefficients (length 256)
     * @return NTT representation of polynomial
     */
    function ntt(uint32[256] memory a) public pure returns (uint32[256] memory) {
        uint32[256] memory result = a;
        uint256 len = 128;
        uint256 k = 1;

        while (len >= 1) {
            uint256 start = 0;
            while (start < 256) {
                uint32 zeta = _zetasPow(k);
                k++;

                for (uint256 j = start; j < start + len; j++) {
                    uint32 t = _montgomeryReduce(uint64(zeta) * uint64(result[j + len]));
                    result[j + len] = _barrettReduce(result[j] + 2 * Q - t);
                    result[j] = _barrettReduce(result[j] + t);
                }

                start += 2 * len;
            }

            len >>= 1;
        }

        return result;
    }

    /**
     * @dev Inverse NTT transform
     *
     * Transforms polynomial from NTT back to coefficient representation.
     * Input: NTT(a)[0], ..., NTT(a)[255]
     * Output: coefficients a[0], ..., a[255]
     *
     * @param a NTT representation (length 256)
     * @return Coefficient representation
     */
    function invNTT(uint32[256] memory a) public pure returns (uint32[256] memory) {
        uint32[256] memory result = a;
        uint256 len = 1;
        uint256 k = 127;

        while (len <= 128) {
            uint256 start = 0;
            while (start < 256) {
                uint32 zeta = _zetasPow(k);
                k--;

                for (uint256 j = start; j < start + len; j++) {
                    uint32 t = result[j];
                    result[j] = _barrettReduce(t + result[j + len]);
                    result[j + len] = _barrettReduce(t + 2 * Q - result[j + len]);
                    result[j + len] = _montgomeryReduce(uint64(zeta) * uint64(result[j + len]));
                }

                start += 2 * len;
            }

            len <<= 1;
        }

        // Multiply by n^(-1) mod q = 8347681
        for (uint256 i = 0; i < 256; i++) {
            result[i] = _montgomeryReduce(uint64(result[i]) * 8347681);
        }

        return result;
    }

    /**
     * @dev Pointwise multiplication in NTT domain
     *
     * Multiply two polynomials in NTT representation.
     * This is O(n) instead of O(n²) in coefficient representation.
     *
     * @param a First polynomial (NTT representation)
     * @param b Second polynomial (NTT representation)
     * @return Product in NTT representation
     */
    function nttMultiply(uint32[256] memory a, uint32[256] memory b)
        public
        pure
        returns (uint32[256] memory)
    {
        uint32[256] memory result;

        for (uint256 i = 0; i < 256; i++) {
            result[i] = _montgomeryReduce(uint64(a[i]) * uint64(b[i]));
        }

        return result;
    }

    /**
     * @dev Barrett reduction
     *
     * Reduces a mod Q using Barrett's algorithm.
     * Faster than modulo for constant modulus.
     *
     * @param a Value to reduce (must be < 2*Q)
     * @return a mod Q
     */
    function _barrettReduce(uint32 a) private pure returns (uint32) {
        if (a < Q) return a;
        return a - Q;
    }

    /**
     * @dev Montgomery reduction
     *
     * Computes a * R^(-1) mod Q where R = 2^32.
     * Used for efficient modular arithmetic.
     *
     * @param a Value to reduce (64-bit)
     * @return Reduced value (32-bit)
     */
    function _montgomeryReduce(uint64 a) private pure returns (uint32) {
        uint32 t = uint32(uint64(uint32(a)) * uint64(QINV));
        t = uint32((a + uint64(t) * uint64(Q)) >> 32);
        return t;
    }

    /**
     * @dev Get zeta^k where zeta is the primitive root of unity
     *
     * Precomputed powers of zeta for NTT.
     * In production, these should be precomputed and stored in a lookup table.
     *
     * @param k Exponent
     * @return zeta^k mod Q
     */
    function _zetasPow(uint256 k) private pure returns (uint32) {
        // Simplified implementation - computes pow(ROOT, k) mod Q
        // In production, use precomputed lookup table for efficiency
        uint32 result = 1;
        uint32 base = ROOT;
        uint256 exp = k;

        while (exp > 0) {
            if (exp & 1 == 1) {
                result = _montgomeryReduce(uint64(result) * uint64(base));
            }
            base = _montgomeryReduce(uint64(base) * uint64(base));
            exp >>= 1;
        }

        return result;
    }

    /**
     * @dev Add two polynomials (coefficient or NTT representation)
     *
     * @param a First polynomial
     * @param b Second polynomial
     * @return Sum a + b
     */
    function polyAdd(uint32[256] memory a, uint32[256] memory b)
        public
        pure
        returns (uint32[256] memory)
    {
        uint32[256] memory result;

        for (uint256 i = 0; i < 256; i++) {
            result[i] = _barrettReduce(a[i] + b[i]);
        }

        return result;
    }

    /**
     * @dev Subtract two polynomials (coefficient or NTT representation)
     *
     * @param a First polynomial
     * @param b Second polynomial
     * @return Difference a - b
     */
    function polySub(uint32[256] memory a, uint32[256] memory b)
        public
        pure
        returns (uint32[256] memory)
    {
        uint32[256] memory result;

        for (uint256 i = 0; i < 256; i++) {
            result[i] = _barrettReduce(a[i] + Q - b[i]);
        }

        return result;
    }

    /**
     * @dev Multiply polynomial by scalar
     *
     * @param a Polynomial
     * @param scalar Scalar value
     * @return Product scalar * a
     */
    function polyScalarMul(uint32[256] memory a, uint32 scalar)
        public
        pure
        returns (uint32[256] memory)
    {
        uint32[256] memory result;

        for (uint256 i = 0; i < 256; i++) {
            result[i] = _montgomeryReduce(uint64(a[i]) * uint64(scalar));
        }

        return result;
    }
}
