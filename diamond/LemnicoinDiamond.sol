// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {LibDiamond} from "./libraries/LibDiamond.sol";
import {IDiamondCut} from "./interfaces/IDiamondCut.sol";

/// @title LemnicoinDiamond - EIP-2535 Diamond Proxy for Lemnicoin
/// @notice This is the single on-chain address for the Lemnicoin token.
///         All calls are delegated to facets registered via DiamondCut.
///         State lives here (slot 0 = AppStorage, keccak slot = DiamondStorage).
///
/// @dev Architecture rationale:
///   The monolithic Lemnicoin.sol exceeds Ethereum's 24 KB contract-size limit
///   once all quantum verification logic, governance, sessions, vesting, and
///   recovery code is included.  The diamond pattern splits the bytecode across
///   facets while preserving a single address and shared storage:
///
///   Facets:
///     DiamondCutFacet        — add / replace / remove facets
///     DiamondLoupeFacet      — EIP-2535 introspection
///     OwnershipFacet         — EIP-173 ownership
///     TokenFacet             — ERC-20 core
///     QuantumTransferFacet   — quantumTransfer, dualKeyProof, STARK proof
///     GovernanceFacet        — mint, pause, oracle, CEX whitelist, dilithium
///     KeyManagementFacet     — bindQuantumKeys, registerQuantumKeys
///     SessionFacet           — per-user CEX/DEX sessions
///     RecoveryFacet          — recoveryTransfer
///     VestingFacet           — vesting schedules, deployment phase
contract LemnicoinDiamond {
    constructor(
        address _contractOwner,
        address _diamondCutFacet
    ) payable {
        LibDiamond.setContractOwner(_contractOwner);

        // Add the diamondCut external function from the diamondCutFacet
        IDiamondCut.FacetCut[] memory cut = new IDiamondCut.FacetCut[](1);
        bytes4[] memory functionSelectors = new bytes4[](1);
        functionSelectors[0] = IDiamondCut.diamondCut.selector;
        cut[0] = IDiamondCut.FacetCut({
            facetAddress: _diamondCutFacet,
            action: IDiamondCut.FacetCutAction.Add,
            functionSelectors: functionSelectors
        });
        LibDiamond.diamondCut(cut, address(0), "");
    }

    // Find facet for function that is called and execute the
    // function if a facet is found and return any value.
    fallback() external payable {
        LibDiamond.DiamondStorage storage ds;
        bytes32 position = LibDiamond.DIAMOND_STORAGE_POSITION;
        // get diamond storage
        assembly {
            ds.slot := position
        }
        // get facet from function selector
        address facet = ds.selectorToFacetAndPosition[msg.sig].facetAddress;
        require(facet != address(0), "Diamond: Function does not exist");
        // Execute external function from facet using delegatecall and return any value.
        assembly {
            // copy function selector and any arguments
            calldatacopy(0, 0, calldatasize())
            // execute function call using the facet
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            // get any return value
            returndatacopy(0, 0, returndatasize())
            // return any return value or error back to the caller
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    /// @notice Accept ETH (for fee collection and stuck ETH recovery)
    receive() external payable {}
}
