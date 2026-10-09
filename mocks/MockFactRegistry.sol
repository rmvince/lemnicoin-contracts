// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../interfaces/IFactRegistry.sol";

/**
 * @title MockFactRegistry
 * @notice Test-only mock of StarkWare's SHARP Fact Registry
 * @dev FOR TESTING PURPOSES ONLY - provides no security!
 *
 * This mock allows tests to register facts and query them, simulating
 * the behavior of StarkWare's production Fact Registry without requiring
 * actual STARK proof verification.
 *
 * DO NOT DEPLOY TO PRODUCTION - use the real SHARP Fact Registry instead.
 */
contract MockFactRegistry is IFactRegistry {
    mapping(bytes32 => bool) private registeredFacts;

    event FactRegistered(bytes32 indexed fact);

    /**
     * @notice Register a fact (test helper)
     * @param fact The fact hash to register
     */
    function registerFact(bytes32 fact) external {
        registeredFacts[fact] = true;
        emit FactRegistered(fact);
    }

    /**
     * @notice Check if a fact is registered
     * @param fact The fact hash to check
     * @return True if the fact is registered
     */
    function isValid(bytes32 fact) external view override returns (bool) {
        return registeredFacts[fact];
    }

    /**
     * @notice Check if a fact has been registered (alias for isValid)
     */
    function hasRegisteredFact() external pure returns (bool) {
        // This mock always returns true to indicate it's functional
        return true;
    }
}
