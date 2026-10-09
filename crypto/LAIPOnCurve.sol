// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../LAIPBigInt3072.sol";

library BigInt {
    struct Int {
        bytes value;
    }

    function fromBytes(bytes memory data) internal pure returns (Int memory) {
        return Int({value: data});
    }

    function mulMod(
        Int memory a,
        Int memory b,
        Int memory modulus
    ) internal view returns (Int memory) {
        return Int({value: LAIPBigInt3072.modMul(a.value, b.value, modulus.value)});
    }

    function addMod(
        Int memory a,
        Int memory b,
        Int memory modulus
    ) internal view returns (Int memory) {
        return Int({value: LAIPBigInt3072.modAdd(a.value, b.value, modulus.value)});
    }

    function eq(Int memory a, Int memory b) internal pure returns (bool) {
        return LAIPBigInt3072.eq(a.value, b.value);
    }
}

library LAIPOnCurve {
    using BigInt for BigInt.Int;

    struct LAIPPublicKey {
        bytes x;
        bytes y;
        bytes p;
        bytes a;
        bytes P0;
    }

    error LAIPOffCurve();

    function validate(LAIPPublicKey memory pk) internal view {
        if (!onCurve(pk)) {
            revert LAIPOffCurve();
        }
    }

    function onCurve(LAIPPublicKey memory pk) internal view returns (bool) {
        BigInt.Int memory x = BigInt.fromBytes(pk.x);
        BigInt.Int memory y = BigInt.fromBytes(pk.y);
        BigInt.Int memory p = BigInt.fromBytes(pk.p);
        BigInt.Int memory a = BigInt.fromBytes(pk.a);

        // Lemniscate curve: (x² + y²)² = a² * (x² - y²) (mod p)

        // x2 = x*x mod p
        BigInt.Int memory x2 = x.mulMod(x, p);

        // y2 = y*y mod p
        BigInt.Int memory y2 = y.mulMod(y, p);

        // Degenerate point check: reject if (x² + y²) ≡ 0 or x² = y²
        BigInt.Int memory sum = x2.addMod(y2, p);
        if (LAIPBigInt3072.isZero(sum.value)) {
            return false;
        }
        if (x2.eq(y2)) {
            return false;
        }

        // left = (x² + y²)²
        BigInt.Int memory left = sum.mulMod(sum, p);

        // right = a² * (x² - y²)
        BigInt.Int memory a2 = a.mulMod(a, p);
        BigInt.Int memory diff = BigInt.Int({value: LAIPBigInt3072.modSub(x2.value, y2.value, p.value)});
        BigInt.Int memory right = a2.mulMod(diff, p);

        return left.eq(right);
    }
}
