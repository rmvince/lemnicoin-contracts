// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AttestorLivenessFacet} from "../facets/AttestorLivenessFacet.sol";
import {LibDiamond} from "../libraries/LibDiamond.sol";

/// @title AttestorLivenessHarness — test-only wrapper
/// @notice Exercises AttestorLivenessFacet standalone (no full Diamond). The constructor sets the
///         deployer as the diamond owner so the `onlyOwner` setters are callable in unit tests.
///         The gate logic under test lives entirely in the parent facet and in AppStorage.
contract AttestorLivenessHarness is AttestorLivenessFacet {
    constructor() {
        LibDiamond.setContractOwner(msg.sender);
    }
}
