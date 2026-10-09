// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../diamond/Modifiers.sol";

/// @title ForkGovKeyOverrideFacet — TEST ONLY, mainnet-FORK rehearsals only.
/// @notice Swaps the diamond's governance Falcon public key for a TEST key, so a fork rehearsal can
///         run the real, Falcon-signed runbook steps (signed by the test key's private half) against
///         the real deployed verifier and real mainnet state. Cut in by the impersonated Safe, used
///         once, cut out again. NEVER deploy or cut this into a real diamond.
contract ForkGovKeyOverrideFacet is Modifiers {
    function forkOnlySetGovernanceNtth(uint256[32] calldata ntth) external onlyOwner {
        for (uint256 i = 0; i < 32; i++) s.governanceAttestorNtth[i] = ntth[i];
    }
}
