// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./LAIPBigInt1024.sol";

contract LAIPProjectiveProbe {
    using LAIPBigInt1024 for bytes;

    function probePointToProjective(
        bytes memory x,
        bytes memory y,
        bytes memory a,
        bytes memory p
    ) external view returns (bytes memory u, bytes memory v, bool ok) {
        return _pointToProjectiveT(x, y, a, p);
    }

    function probeProjectiveEq(
        bytes memory u1,
        bytes memory v1,
        bytes memory u2,
        bytes memory v2,
        bytes memory p
    ) external view returns (bool) {
        return _projectiveEq(u1, v1, u2, v2, p);
    }

    function _pointToProjectiveT(
        bytes memory x,
        bytes memory y,
        bytes memory /* a */,
        bytes memory p
    ) private view returns (bytes memory u, bytes memory v, bool ok) {
        uint256 fieldLen = p.length;
        bytes memory zero = new bytes(fieldLen);
        bytes memory one = new bytes(fieldLen);
        one[fieldLen - 1] = 0x01;

        if (LAIPBigInt1024.isZero(x) && LAIPBigInt1024.isZero(y)) {
            return (zero, one, true);
        }

        // v = x + y
        v = LAIPBigInt1024.modAdd(x, y, p);
        if (LAIPBigInt1024.isZero(v)) {
            return (u, v, false);
        }

        // u = x − y (NOT squared - group law expects t = u/v, not t²)
        u = LAIPBigInt1024.modSub(x, y, p);

        return (u, v, true);
    }

    function _projectiveEq(
        bytes memory u1,
        bytes memory v1,
        bytes memory u2,
        bytes memory v2,
        bytes memory p
    ) private view returns (bool) {
        bool z1 = LAIPBigInt1024.isZero(u1);
        bool z2 = LAIPBigInt1024.isZero(u2);
        if (z1 && z2) return true;
        if (z1 || z2) return false;

        bytes memory left = LAIPBigInt1024.modMul(u1, v2, p);
        bytes memory right = LAIPBigInt1024.modMul(u2, v1, p);
        return LAIPBigInt1024.eq(left, right);
    }
}
