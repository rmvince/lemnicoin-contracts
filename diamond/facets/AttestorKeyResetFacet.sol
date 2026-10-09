// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {LibDiamond} from "../libraries/LibDiamond.sol";

/**
 * @title AttestorKeyResetFacet
 * @notice Temporary facet to force-set attestorNtth via diamondCut (owner-only).
 *         Bypasses governance when governance is broken/desynced.
 *         Should be removed after use.
 */
contract AttestorKeyResetFacet is Modifiers {
    function forceSetAttestorNtth(uint256[32] calldata newNtth) external {
        LibDiamond.enforceIsContractOwner();
        for (uint256 i = 0; i < 32; i++) {
            s.attestorNtth[i] = newNtth[i];
        }
    }
}
