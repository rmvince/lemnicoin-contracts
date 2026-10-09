// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AppStorage, LibAppStorage} from "../libraries/LibAppStorage.sol";
import {LibDiamond} from "../libraries/LibDiamond.sol";
import {IDiamondLoupe} from "../interfaces/IDiamondLoupe.sol";
import {IDiamondCut} from "../interfaces/IDiamondCut.sol";
import {IERC173} from "../interfaces/IERC173.sol";

error DiamondAlreadyInitialized();

/// @title DiamondInit — One-time initializer for Lemnicoin Diamond
/// @notice Called via delegatecall during the first diamondCut to set up
///         all state that the monolithic constructor used to handle.

contract DiamondInit {
    // H-05 audit fix: ERC-20 Transfer event for initial supply visibility
    event Transfer(address indexed from, address indexed to, uint256 value);
    /// @notice Parameters mirroring the monolithic Lemnicoin constructor
    struct InitParams {
        uint256 initialSupply;
        address oracleAddress;
        address guardian;
        address falconVerifier;
        uint256[32] attestorNtth;
    }

    /// @notice Initialise the diamond — MUST only be called once via delegatecall
    function init(InitParams calldata p) external {
        AppStorage storage s = LibAppStorage.appStorage();

        // Guard against re-initialisation
        if (bytes(s.name).length != 0) revert DiamondAlreadyInitialized();

        // --- ERC20 ---
        s.name = "Lemnicoin";
        s.symbol = "LEMNI";
        uint256 scaled = p.initialSupply * 10 ** 18;
        s.totalSupply = scaled;
        address owner = LibDiamond.contractOwner();
        s.balances[owner] = scaled;

        // H-05 audit fix: Emit Transfer event for initial supply (ERC-20 compliance)
        // This allows block explorers and indexers to track the initial token distribution
        emit Transfer(address(0), owner, scaled);

        // --- Guardian ---
        require(p.guardian != address(0), "DiamondInit: zero guardian");
        s.guardian = p.guardian;
        s.cexGovernanceSigner = LibDiamond.contractOwner();

        // --- Oracle ---
        s.priceOracle = p.oracleAddress;
        s.lastOracleUpdate = block.timestamp;

        // --- Falcon attestation ---
        require(p.falconVerifier != address(0), "DiamondInit: zero falcon verifier");
        s.falconVerifier = p.falconVerifier;
        for (uint256 i = 0; i < 32; i++) {
            s.attestorNtth[i] = p.attestorNtth[i];
        }

        // --- Deployment phase starts active ---
        s.deploymentPhaseActive = true;

        // --- ERC-165 interface support ---
        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
        ds.supportedInterfaces[type(IDiamondCut).interfaceId] = true;
        ds.supportedInterfaces[type(IDiamondLoupe).interfaceId] = true;
        ds.supportedInterfaces[type(IERC173).interfaceId] = true;
        // ERC20 doesn't define a formal interfaceId in EIP-165 but we add the common one
        // bytes4(keccak256("totalSupply()")) ^ bytes4(keccak256("balanceOf(address)")) ^
        // bytes4(keccak256("transfer(address,uint256)")) ^ ...
        ds.supportedInterfaces[0x36372b07] = true; // IERC20
    }
}
