// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IStoneVerifier {
    function verifyProof(
        bytes calldata proof,
        bytes32 publicInputHash,
        bytes32 programHash
    ) external view returns (bool);
}
