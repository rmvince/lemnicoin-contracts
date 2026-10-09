// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../LAIPBigInt3072.sol";

contract BigInt3072Harness {
    function modAdd(bytes memory a, bytes memory b, bytes memory p) external view returns (bytes memory) {
        return LAIPBigInt3072.modAdd(a, b, p);
    }

    function modSub(bytes memory a, bytes memory b, bytes memory p) external view returns (bytes memory) {
        return LAIPBigInt3072.modSub(a, b, p);
    }

    function modMul(bytes memory a, bytes memory b, bytes memory p) external view returns (bytes memory) {
        return LAIPBigInt3072.modMul(a, b, p);
    }
}
