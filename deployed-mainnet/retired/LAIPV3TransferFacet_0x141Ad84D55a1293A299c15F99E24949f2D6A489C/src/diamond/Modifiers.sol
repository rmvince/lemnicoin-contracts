// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AppStorage} from "./libraries/LibAppStorage.sol";
import {LibDiamond} from "./libraries/LibDiamond.sol";

error OnlyGuardian();
error OnlyCexGovernance();
error OnlyOwnerOrRekeyOperator();
error Paused();
error NotPaused();
error ReentrancyGuardReentrantCall();

// Reentrancy guard constants
uint256 constant _NOT_ENTERED = 1;
uint256 constant _ENTERED = 2;

/// @title Modifiers - Shared access-control modifiers for all Lemnicoin facets
/// @notice Every facet that needs AppStorage or access control should inherit this.
///         The first declared state variable is `AppStorage internal s` so that
///         all facets agree on the storage layout starting at slot 0.
contract Modifiers {
    AppStorage internal s;

    modifier onlyOwner() {
        LibDiamond.enforceIsContractOwner();
        _;
    }

    modifier onlyGuardian() {
        if (msg.sender != s.guardian) revert OnlyGuardian();
        _;
    }

    modifier onlyCexGovernance() {
        if (msg.sender != s.cexGovernanceSigner) revert OnlyCexGovernance();
        _;
    }

    /// @notice Allows either the diamond owner OR the dedicated rekey operator.
    ///         Used for attestor key rotation so automated rekey can continue
    ///         after ownership is transferred to a Gnosis Safe multisig.
    modifier onlyOwnerOrRekeyOperator() {
        if (msg.sender != LibDiamond.contractOwner() && msg.sender != s.rekeyOperator) {
            revert OnlyOwnerOrRekeyOperator();
        }
        _;
    }

    modifier whenNotPaused() {
        if (s.paused) revert Paused();
        _;
    }

    modifier whenPaused() {
        if (!s.paused) revert NotPaused();
        _;
    }

    /// @notice Prevents reentrancy attacks on functions that transfer ETH (M-04 fix)
    modifier nonReentrant() {
        // On first call, status is 0, which we treat as _NOT_ENTERED
        if (s.reentrancyStatus == _ENTERED) revert ReentrancyGuardReentrantCall();
        s.reentrancyStatus = _ENTERED;
        _;
        s.reentrancyStatus = _NOT_ENTERED;
    }
}
