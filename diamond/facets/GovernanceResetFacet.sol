// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {LibDiamond} from "../libraries/LibDiamond.sol";

/// @title GovernanceResetFacet — TEMPORARY facet to reset governance Falcon
/// @notice Deploy via diamondCut, call resetGovernanceFalcon(), then remove via diamondCut.
///         This is needed because governance was initialized with Dashlane-format NTTH
///         which is incompatible with the ETHFALCON verifier.
contract GovernanceResetFacet is Modifiers {
    function resetGovernanceFalcon() external {
        LibDiamond.enforceIsContractOwner();
        s.governanceFalconInitialized = false;
        s.governanceFalconVerifier = address(0);
        for (uint256 i = 0; i < 32; i++) {
            s.governanceAttestorNtth[i] = 0;
        }
        // Reset all governance nonces to 0 for the owner
        s.governanceNonce[msg.sender] = 0;
    }
}
