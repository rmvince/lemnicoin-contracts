// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface ISTARKVerifier {
    function verifyProof(bytes calldata proof, bytes32 publicInputHash)
        external
        view
        returns (bool);
}
