// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./LAIPBigInt.sol";

/**
 * @title LemniscateCurve
 * @notice Lemniscate curve arithmetic for 3072-bit LAIP signatures
 * @dev Implements point addition and scalar multiplication on the Bernoulli lemniscate
 *      Curve equation: (x² + y²)² = a²(x² - y²) mod p
 *
 *      We use the RATIONAL PARAMETRIZATION:
 *        x = a·t(1 + t²) / (1 + t⁴)
 *        y = a·t(1 - t²) / (1 + t⁴)
 *
 *      The group law in terms of parameter t is the TANGENT ADDITION FORMULA:
 *        t₃ = (t₁ + t₂) / (1 - t₁·t₂)
 *
 *      To extract t from a point: t² = (x - y)/(x + y), so t = √((x-y)/(x+y))
 */
library LemniscateCurve {
    using LAIPBigInt for bytes;

    // Custom errors
    error PointNotOnCurve();
    error InvalidPoint();
    error DivisionByZero();
    error PointAtInfinity();

    /**
     * @notice Add two t-parameters using the tangent addition formula
     * @dev t₃ = (t₁ + t₂) / (1 - t₁·t₂) mod p
     */
    function tAdd(
        bytes memory t1,
        bytes memory t2,
        bytes memory p
    ) internal view returns (bytes memory) {
        // num = t1 + t2
        bytes memory num = LAIPBigInt.modAdd(t1, t2, p);

        // prod = t1 * t2
        bytes memory prod = LAIPBigInt.modMul(t1, t2, p);

        // denom = 1 - prod = (p + 1 - prod) mod p
        bytes memory one = LAIPBigInt.fromUint256(1);
        bytes memory denom = LAIPBigInt.modSub(one, prod, p);

        // Check for point at infinity
        if (LAIPBigInt.isZero(denom)) {
            revert PointAtInfinity();
        }

        return _modDiv(num, denom, p);
    }

    /**
     * @notice Convert t-parameter to point (x, y) on the lemniscate
     * @dev x = a·t(1 + t²) / (1 + t⁴)
     *      y = a·t(1 - t²) / (1 + t⁴)
     */
    function tToPoint(
        bytes memory t,
        bytes memory a,
        bytes memory p
    ) internal view returns (bytes memory x, bytes memory y) {
        // Handle t = 0 -> (0, 0)
        if (LAIPBigInt.isZero(t)) {
            x = new bytes(1);
            y = new bytes(1);
            return (x, y);
        }

        bytes memory one = LAIPBigInt.fromUint256(1);

        // t² = t * t
        bytes memory t2 = LAIPBigInt.modMul(t, t, p);

        // t⁴ = t² * t²
        bytes memory t4 = LAIPBigInt.modMul(t2, t2, p);

        // denom = 1 + t⁴
        bytes memory denom = LAIPBigInt.modAdd(one, t4, p);

        // 1 + t²
        bytes memory onePlusT2 = LAIPBigInt.modAdd(one, t2, p);

        // 1 - t²
        bytes memory oneMinusT2 = LAIPBigInt.modSub(one, t2, p);

        // a * t
        bytes memory at = LAIPBigInt.modMul(a, t, p);

        // xNum = a * t * (1 + t²)
        bytes memory xNum = LAIPBigInt.modMul(at, onePlusT2, p);

        // yNum = a * t * (1 - t²)
        bytes memory yNum = LAIPBigInt.modMul(at, oneMinusT2, p);

        // x = xNum / denom
        x = _modDiv(xNum, denom, p);

        // y = yNum / denom
        y = _modDiv(yNum, denom, p);
    }

    /**
     * @notice Scalar multiplication on t-parameters
     * @dev Uses double-and-add algorithm directly on t values
     */
    function tScalarMult(
        bytes memory n,
        bytes memory t,
        bytes memory p
    ) internal view returns (bytes memory) {
        // Handle n = 0: return 0 (identity)
        if (LAIPBigInt.isZero(n)) {
            return new bytes(1);
        }

        // Handle n = 1: return t
        if (_isOne(n)) {
            return t;
        }

        // Double-and-add algorithm on t-parameters
        bytes memory result = new bytes(1); // t = 0 is identity
        bytes memory current = t;

        // Process each bit of n from LSB to MSB
        uint256 nLen = n.length;
        for (uint256 byteIdx = 0; byteIdx < nLen; byteIdx++) {
            uint8 b = uint8(n[nLen - 1 - byteIdx]);
            for (uint256 bitIdx = 0; bitIdx < 8; bitIdx++) {
                if ((b >> bitIdx) & 1 == 1) {
                    result = tAdd(result, current, p);
                }
                // Double: current = current + current
                current = tAdd(current, current, p);
            }
        }

        return result;
    }

    /**
     * @notice Scalar multiplication using t-parameter approach
     * @param n Scalar (as bytes, big-endian)
     * @param x x-coordinate of point
     * @param y y-coordinate of point
     * @param a Lemniscate parameter
     * @param p Prime modulus
     * @return rx x-coordinate of n*P
     * @return ry y-coordinate of n*P
     */
    function scalarMult(
        bytes memory n,
        bytes memory x,
        bytes memory y,
        bytes memory a,
        bytes memory p
    ) internal view returns (bytes memory rx, bytes memory ry) {
        // Handle n = 0: return identity (0, 0)
        if (LAIPBigInt.isZero(n)) {
            rx = new bytes(1);
            ry = new bytes(1);
            return (rx, ry);
        }

        // Handle identity point (0, 0)
        if (LAIPBigInt.isZero(x) && LAIPBigInt.isZero(y)) {
            rx = new bytes(1);
            ry = new bytes(1);
            return (rx, ry);
        }

        // Extract t from (x, y) with sign verification
        bytes memory t = extractTWithVerify(x, y, a, p);

        // Scalar multiply on t
        bytes memory resultT = tScalarMult(n, t, p);

        // Convert back to (x, y)
        return tToPoint(resultT, a, p);
    }

    /**
     * @notice Extract t-parameter from point (x, y)
     * @dev t² = (x - y)/(x + y), t = √(t²)
     *      Requires modular square root (Tonelli-Shanks)
     */
    function extractT(
        bytes memory x,
        bytes memory y,
        bytes memory p
    ) internal view returns (bytes memory) {
        // Handle identity
        if (LAIPBigInt.isZero(x) && LAIPBigInt.isZero(y)) {
            return new bytes(1);
        }

        // sum = x + y
        bytes memory sum = LAIPBigInt.modAdd(x, y, p);
        if (LAIPBigInt.isZero(sum)) {
            revert InvalidPoint();
        }

        // diff = x - y
        bytes memory diff = LAIPBigInt.modSub(x, y, p);

        // t² = diff / sum
        bytes memory t2 = _modDiv(diff, sum, p);

        // t = √(t²) using Tonelli-Shanks
        if (LAIPBigInt.isZero(t2)) {
            return new bytes(1);
        }

        return modSqrt(t2, p);
    }

    /**
     * @notice Extract t-parameter with sign verification
     * @dev Verifies which square root is correct by converting back to point
     * @param x x-coordinate of point
     * @param y y-coordinate of point
     * @param a Lemniscate parameter
     * @param p Prime modulus
     */
    function extractTWithVerify(
        bytes memory x,
        bytes memory y,
        bytes memory a,
        bytes memory p
    ) internal view returns (bytes memory) {
        // Handle identity
        if (LAIPBigInt.isZero(x) && LAIPBigInt.isZero(y)) {
            return new bytes(1);
        }

        // sum = x + y
        bytes memory sum = LAIPBigInt.modAdd(x, y, p);
        if (LAIPBigInt.isZero(sum)) {
            revert InvalidPoint();
        }

        // diff = x - y
        bytes memory diff = LAIPBigInt.modSub(x, y, p);

        // t² = diff / sum
        bytes memory t2 = _modDiv(diff, sum, p);

        // t = √(t²) using modular square root
        if (LAIPBigInt.isZero(t2)) {
            return new bytes(1);
        }

        bytes memory t = modSqrt(t2, p);

        // Verify: check if tToPoint(t) gives back (x, y)
        (bytes memory checkX, bytes memory checkY) = tToPoint(t, a, p);

        if (LAIPBigInt.eq(checkX, x) && LAIPBigInt.eq(checkY, y)) {
            return t;
        }

        // Use the other root: p - t
        return LAIPBigInt.modSub(p, t, p);
    }

    /**
     * @notice Modular square root using simplified method
     * @dev For p ≡ 3 (mod 4): √a = a^((p+1)/4) mod p
     *      For general p: use Tonelli-Shanks (more complex)
     */
    function modSqrt(
        bytes memory a,
        bytes memory p
    ) internal view returns (bytes memory) {
        // For p ≡ 3 (mod 4), use the simple formula: √a = a^((p+1)/4)
        // This works for most cryptographic primes

        bytes memory one = LAIPBigInt.fromUint256(1);

        // exp = (p + 1) / 4
        bytes memory pPlus1 = LAIPBigInt.modAdd(p, one, p);

        // Division by 4: right shift by 2 bits
        bytes memory exp = _divBy4(pPlus1);

        // √a = a^exp mod p
        return LAIPBigInt.modExp(a, exp, p);
    }

    /**
     * @notice Check if a point is on the lemniscate curve
     * @dev Verifies (x² + y²)² = a²(x² - y²) mod p
     */
    function isOnCurve(
        bytes memory x,
        bytes memory y,
        bytes memory a,
        bytes memory p
    ) internal view returns (bool) {
        bytes memory x2 = LAIPBigInt.modExp(x, LAIPBigInt.fromUint256(2), p);
        bytes memory y2 = LAIPBigInt.modExp(y, LAIPBigInt.fromUint256(2), p);

        bytes memory sum = LAIPBigInt.modAdd(x2, y2, p);
        if (LAIPBigInt.isZero(sum) || LAIPBigInt.eq(x2, y2)) {
            return false;
        }

        bytes memory left = LAIPBigInt.modExp(sum, LAIPBigInt.fromUint256(2), p);
        bytes memory a2 = LAIPBigInt.modExp(a, LAIPBigInt.fromUint256(2), p);
        bytes memory diff = LAIPBigInt.modSub(x2, y2, p);
        bytes memory right = LAIPBigInt.modMul(a2, diff, p);

        return LAIPBigInt.eq(left, right);
    }

    /**
     * @notice Check if two points are equal
     */
    function pointEq(
        bytes memory x1,
        bytes memory y1,
        bytes memory x2,
        bytes memory y2
    ) internal pure returns (bool) {
        return LAIPBigInt.eq(x1, x2) && LAIPBigInt.eq(y1, y2);
    }

    /**
     * @dev Modular division: a / b mod p = a * b^(p-2) mod p
     */
    function _modDiv(
        bytes memory numerator,
        bytes memory denominator,
        bytes memory p
    ) private view returns (bytes memory) {
        if (LAIPBigInt.isZero(denominator)) {
            revert DivisionByZero();
        }

        bytes memory two = LAIPBigInt.fromUint256(2);
        bytes memory pMinus2 = LAIPBigInt.modSub(p, two, p);
        bytes memory invDenom = LAIPBigInt.modExp(denominator, pMinus2, p);

        return LAIPBigInt.modMul(numerator, invDenom, p);
    }

    /**
     * @dev Divide bytes value by 4 (right shift by 2 bits)
     */
    function _divBy4(bytes memory data) private pure returns (bytes memory) {
        bytes memory result = new bytes(data.length);
        uint16 carry = 0;

        for (uint256 i = 0; i < data.length; i++) {
            uint16 current = (carry << 8) | uint8(data[i]);
            result[i] = bytes1(uint8(current >> 2));
            carry = current & 0x03;
        }

        return result;
    }

    /**
     * @dev Check if bytes value equals 1
     */
    function _isOne(bytes memory data) private pure returns (bool) {
        uint256 i = 0;
        while (i < data.length && data[i] == 0) {
            i++;
        }

        if (i == data.length) {
            return false;
        }

        if (data[i] != 0x01) {
            return false;
        }

        for (uint256 j = i + 1; j < data.length; j++) {
            if (data[j] != 0) {
                return false;
            }
        }

        return true;
    }
}
