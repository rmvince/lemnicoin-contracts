// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract LAIPVerifierDebug {
    event DebugFinal(
        bytes sUx,
        bytes sUy,
        bytes rUx,
        bytes rUy,
        bool matchOk
    );

    function debugCompare(
        bytes memory sUx,
        bytes memory sUy,
        bytes memory rUx,
        bytes memory rUy
    ) external {
        //emit DEBUG(Final(sUx, sUy, rUx, rUy, keccak256(sUx) == keccak256(rUx));
    }
}
