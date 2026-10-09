// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./LAIPBigInt.sol";

/**
 * @title LAIPDebug
 * @dev Debug contract for isolating LAIP verification failures
 * Exposes each step separately to identify exactly where reverts occur
 */
contract LAIPDebug {
    using LAIPBigInt for bytes;

    // Events for debugging - emit intermediate values
    event DebugStep(string step, bool success, string message);
    event DebugValue(string name, bytes value);
    event DebugComparison(string name, bytes left, bytes right, bool equal);

    /**
     * @dev Test modExp with simple values to verify precompile works
     */
    function testModExpSimple() public view returns (bytes memory, bool) {
        // 2^2 mod 7 = 4
        bytes memory base = LAIPBigInt.fromUint256(2);
        bytes memory exp = LAIPBigInt.fromUint256(2);
        bytes memory mod = LAIPBigInt.fromUint256(7);

        bytes memory result = LAIPBigInt.modExp(base, exp, mod);
        // Result should be 4
        bool correct = LAIPBigInt.toUint256(result) == 4;
        return (result, correct);
    }

    /**
     * @dev Test modExp with 256-byte values to verify precompile handles large inputs
     */
    function testModExpLarge(
        bytes memory base,
        bytes memory modulus
    ) public view returns (bytes memory) {
        bytes memory exp = LAIPBigInt.fromUint256(2); // Just square it
        return LAIPBigInt.modExp(base, exp, modulus);
    }

    /**
     * @dev Test modAdd with 256-byte values
     */
    function testModAdd(
        bytes memory a,
        bytes memory b,
        bytes memory modulus
    ) public view returns (bytes memory) {
        return LAIPBigInt.modAdd(a, b, modulus);
    }

    /**
     * @dev Test modSub with 256-byte values
     */
    function testModSub(
        bytes memory a,
        bytes memory b,
        bytes memory modulus
    ) public view returns (bytes memory) {
        return LAIPBigInt.modSub(a, b, modulus);
    }

    /**
     * @dev Test modMul with 256-byte values
     */
    function testModMul(
        bytes memory a,
        bytes memory b,
        bytes memory modulus
    ) public view returns (bytes memory) {
        return LAIPBigInt.modMul(a, b, modulus);
    }

    /**
     * @dev Test isZero
     */
    function testIsZero(bytes memory value) public pure returns (bool) {
        return LAIPBigInt.isZero(value);
    }

    /**
     * @dev Test eq comparison
     */
    function testEq(bytes memory a, bytes memory b) public pure returns (bool) {
        return LAIPBigInt.eq(a, b);
    }

    /**
     * @dev Step-by-step isOnCurve verification
     * Returns intermediate values at each step to identify failures
     */
    function isOnCurveStepByStep(
        bytes memory x,
        bytes memory y,
        bytes memory a,
        bytes memory p
    ) public view returns (
        bytes memory x2,
        bytes memory y2,
        bytes memory sum,
        bool sumIsZero,
        bool x2EqY2,
        bytes memory left,
        bytes memory a2,
        bytes memory diff,
        bytes memory right,
        bool leftEqRight
    ) {
        // Step 1: Compute x²
        x2 = LAIPBigInt.modExp(x, LAIPBigInt.fromUint256(2), p);

        // Step 2: Compute y²
        y2 = LAIPBigInt.modExp(y, LAIPBigInt.fromUint256(2), p);

        // Step 3: Compute sum = x² + y²
        sum = LAIPBigInt.modAdd(x2, y2, p);

        // Step 4: Check degenerate cases
        sumIsZero = LAIPBigInt.isZero(sum);
        x2EqY2 = LAIPBigInt.eq(x2, y2);

        // If degenerate case, early return with zeros for remaining fields
        if (sumIsZero || x2EqY2) {
            left = new bytes(0);
            a2 = new bytes(0);
            diff = new bytes(0);
            right = new bytes(0);
            leftEqRight = false;
            return (x2, y2, sum, sumIsZero, x2EqY2, left, a2, diff, right, leftEqRight);
        }

        // Step 5: Compute left = (x² + y²)²
        left = LAIPBigInt.modExp(sum, LAIPBigInt.fromUint256(2), p);

        // Step 6: Compute a²
        a2 = LAIPBigInt.modExp(a, LAIPBigInt.fromUint256(2), p);

        // Step 7: Compute diff = x² - y²
        diff = LAIPBigInt.modSub(x2, y2, p);

        // Step 8: Compute right = a² * diff
        right = LAIPBigInt.modMul(a2, diff, p);

        // Step 9: Check equality
        leftEqRight = LAIPBigInt.eq(left, right);

        return (x2, y2, sum, sumIsZero, x2EqY2, left, a2, diff, right, leftEqRight);
    }

    /**
     * @dev Final isOnCurve check (same logic as LAIPVerifier)
     */
    function isOnCurve(
        bytes memory x,
        bytes memory y,
        bytes memory a,
        bytes memory p
    ) public view returns (bool) {
        // Compute x²
        bytes memory x2 = LAIPBigInt.modExp(x, LAIPBigInt.fromUint256(2), p);

        // Compute y²
        bytes memory y2 = LAIPBigInt.modExp(y, LAIPBigInt.fromUint256(2), p);

        // Check if (x² + y²) == 0 or x² == y² (degenerate cases)
        bytes memory sum = LAIPBigInt.modAdd(x2, y2, p);
        if (LAIPBigInt.isZero(sum) || LAIPBigInt.eq(x2, y2)) {
            return false;
        }

        // Compute left side: (x² + y²)²
        bytes memory left = LAIPBigInt.modExp(sum, LAIPBigInt.fromUint256(2), p);

        // Compute a²
        bytes memory a2 = LAIPBigInt.modExp(a, LAIPBigInt.fromUint256(2), p);

        // Compute (x² - y²)
        bytes memory diff = LAIPBigInt.modSub(x2, y2, p);

        // Compute right side: a²(x² - y²)
        bytes memory right = LAIPBigInt.modMul(a2, diff, p);

        // Check if left == right
        return LAIPBigInt.eq(left, right);
    }

    /**
     * @dev Check input byte lengths for debugging
     */
    function checkInputLengths(
        bytes memory x,
        bytes memory y,
        bytes memory a,
        bytes memory p
    ) public pure returns (
        uint256 xLen,
        uint256 yLen,
        uint256 aLen,
        uint256 pLen,
        bool allCorrect
    ) {
        xLen = x.length;
        yLen = y.length;
        aLen = a.length;
        pLen = p.length;
        allCorrect = (xLen == 256 && yLen == 256 && aLen == 256 && pLen == 256);
    }

    /**
     * @dev Gas estimation helper - returns how much gas isOnCurve uses
     */
    function estimateIsOnCurveGas(
        bytes memory x,
        bytes memory y,
        bytes memory a,
        bytes memory p
    ) public view returns (uint256 gasUsed, bool result) {
        uint256 gasBefore = gasleft();
        result = isOnCurve(x, y, a, p);
        gasUsed = gasBefore - gasleft();
    }
}
