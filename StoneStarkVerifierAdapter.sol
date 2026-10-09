// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./interfaces/ISTARKVerifier.sol";
import "./interfaces/IStoneVerifier.sol";

/**
 * @title StoneStarkVerifierAdapter
 * @notice Adapter that binds a Stone verifier contract to the ISTARKVerifier interface.
 * @dev The Stone verifier is assumed to validate the Cairo program and AIR constraints
 *      against the provided proof and public input hash.
 */
contract StoneStarkVerifierAdapter is ISTARKVerifier {
    error Unauthorized();
    error InvalidVerifier();
    error InvalidProgramHash();

    address public owner;
    address public stoneVerifier;
    bytes32 public programHash;

    constructor(address verifier, bytes32 cairoProgramHash) {
        if (verifier == address(0)) revert InvalidVerifier();
        if (cairoProgramHash == bytes32(0)) revert InvalidProgramHash();
        owner = msg.sender;
        stoneVerifier = verifier;
        programHash = cairoProgramHash;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    function setStoneVerifier(address verifier) external onlyOwner {
        if (verifier == address(0)) revert InvalidVerifier();
        stoneVerifier = verifier;
    }

    function setProgramHash(bytes32 cairoProgramHash) external onlyOwner {
        if (cairoProgramHash == bytes32(0)) revert InvalidProgramHash();
        programHash = cairoProgramHash;
    }

    function verifyProof(bytes calldata proof, bytes32 publicInputHash)
        external
        view
        returns (bool)
    {
        return IStoneVerifier(stoneVerifier).verifyProof(
            proof,
            publicInputHash,
            programHash
        );
    }
}
