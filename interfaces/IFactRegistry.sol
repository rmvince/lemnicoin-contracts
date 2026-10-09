// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

/**
 * @title IFactRegistry
 * @notice Interface for StarkWare's Fact Registry
 * @dev The Fact Registry is a contract that stores facts (hashes of verified statements)
 *      that have been proven by the STARK verifier. Once a fact is registered, it can be
 *      queried by other contracts to verify that a specific statement has been proven.
 *
 * Production deployment: https://etherscan.io/address/0x47312450b3ac8b5b8e247a6bb6d523e7605bdb60
 */
interface IFactRegistry {
    /**
     * @notice Check if a fact has been verified and registered
     * @param fact The fact hash (keccak256 of the proven statement)
     * @return true if the fact is registered, false otherwise
     */
    function isValid(bytes32 fact) external view returns (bool);

    /**
     * @notice Check if any fact has ever been registered in this registry
     * @return true if at least one fact exists
     */
    function hasRegisteredFact() external view returns (bool);
}
