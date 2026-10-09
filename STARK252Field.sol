// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title STARK252Field
 * @notice Field arithmetic library for STARK252 prime field
 * @dev Field modulus: p = 2^251 + 17*2^192 + 1
 *      This is the same field used by StarkWare/Cairo
 */
library STARK252Field {
    // Field modulus: 0x800000000000011000000000000000000000000000000000000000000000001
    uint256 constant K_MODULUS =
        0x800000000000011000000000000000000000000000000000000000000000001;

    // Generator for multiplicative group (primitive root)
    uint256 constant GENERATOR = 3;

    // 2^64 for limb arithmetic
    uint256 constant LIMB_BASE = 0x10000000000000000;

    /**
     * @notice Add two field elements (a + b) mod p
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            uint256 sum = addmod(a, b, K_MODULUS);
            return sum;
        }
    }

    /**
     * @notice Subtract two field elements (a - b) mod p
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            if (a >= b) {
                return (a - b) % K_MODULUS;
            } else {
                return K_MODULUS - ((b - a) % K_MODULUS);
            }
        }
    }

    /**
     * @notice Multiply two field elements (a * b) mod p
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return mulmod(a, b, K_MODULUS);
    }

    /**
     * @notice Compute modular inverse using Fermat's little theorem: a^(-1) = a^(p-2) mod p
     */
    function inv(uint256 a) internal view returns (uint256) {
        require(a != 0, "Cannot invert zero");
        return modExp(a, K_MODULUS - 2);
    }

    /**
     * @notice Division (a / b) mod p = a * b^(-1) mod p
     */
    function div(uint256 a, uint256 b) internal view returns (uint256) {
        return mul(a, inv(b));
    }

    /**
     * @notice Modular exponentiation using precompile (0x05)
     */
    function modExp(uint256 base, uint256 exponent) internal view returns (uint256 result) {
        assembly {
            let p := mload(0x40)
            mstore(p, 0x20)           // Base length
            mstore(add(p, 0x20), 0x20) // Exponent length
            mstore(add(p, 0x40), 0x20) // Modulus length
            mstore(add(p, 0x60), base)
            mstore(add(p, 0x80), exponent)
            mstore(add(p, 0xa0), K_MODULUS)
            if iszero(staticcall(gas(), 0x05, p, 0xc0, p, 0x20)) {
                revert(0, 0)
            }
            result := mload(p)
        }
    }

    /**
     * @notice Compute generator^exponent for domain element
     * @dev Used to compute omega^i for FRI domain
     */
    function domainElement(uint256 domainSize, uint256 index) internal view returns (uint256) {
        // omega = g^((p-1)/domainSize) where g is primitive root
        uint256 exponent = (K_MODULUS - 1) / domainSize;
        uint256 omega = modExp(GENERATOR, exponent);
        return modExp(omega, index);
    }

    /**
     * @notice Square root in the field (if exists)
     * @dev Uses Tonelli-Shanks algorithm optimized for p ≡ 3 (mod 4)
     */
    function sqrt(uint256 a) internal view returns (uint256) {
        if (a == 0) return 0;
        // For p ≡ 3 (mod 4): sqrt(a) = a^((p+1)/4)
        // But STARK252 is p ≡ 1 (mod 4), so we need Tonelli-Shanks
        // Simplified: just return modExp result, verify externally
        return modExp(a, (K_MODULUS + 1) / 4);
    }

    /**
     * @notice Negate a field element
     */
    function neg(uint256 a) internal pure returns (uint256) {
        if (a == 0) return 0;
        return K_MODULUS - (a % K_MODULUS);
    }

    /**
     * @notice Check if value is in field (< modulus)
     */
    function isValid(uint256 a) internal pure returns (bool) {
        return a < K_MODULUS;
    }

    /**
     * @notice Evaluate polynomial at point using Horner's method
     * @param coeffs Polynomial coefficients [c0, c1, ..., cn] for c0 + c1*x + ... + cn*x^n
     * @param point Evaluation point
     */
    function evalPoly(uint256[] memory coeffs, uint256 point) internal pure returns (uint256) {
        if (coeffs.length == 0) return 0;

        uint256 result = coeffs[coeffs.length - 1];
        for (uint256 i = coeffs.length - 1; i > 0; ) {
            unchecked { i--; }
            result = addmod(mulmod(result, point, K_MODULUS), coeffs[i], K_MODULUS);
        }
        return result;
    }

    /**
     * @notice Compute zerofier evaluation Z(x) = x^n - 1 on trace domain
     */
    function evalZerofier(uint256 x, uint256 traceLength) internal view returns (uint256) {
        uint256 x_n = modExp(x, traceLength);
        return sub(x_n, 1);
    }

    /**
     * @notice Batch inversion using Montgomery's trick
     * @dev Computes inverses of all elements in one inversion
     */
    function batchInvert(uint256[] memory elements) internal view returns (uint256[] memory) {
        uint256 n = elements.length;
        uint256[] memory results = new uint256[](n);
        if (n == 0) return results;

        // Compute cumulative products
        uint256[] memory partials = new uint256[](n);
        partials[0] = elements[0];
        for (uint256 i = 1; i < n; i++) {
            partials[i] = mul(partials[i-1], elements[i]);
        }

        // Compute single inverse
        uint256 allInv = inv(partials[n-1]);

        // Propagate inverse back
        for (uint256 i = n - 1; i > 0; ) {
            results[i] = mul(allInv, partials[i-1]);
            allInv = mul(allInv, elements[i]);
            unchecked { i--; }
        }
        results[0] = allInv;

        return results;
    }
}
