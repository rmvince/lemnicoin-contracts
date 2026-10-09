// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {LemniVaultFactoryV6} from "./LemniVaultFactoryV6.sol";
import {ILaipV3Registry} from "./interfaces/ILaipV3Registry.sol";

/// @title LemniVaultFactoryV6Satellite — V6 factory that REQUIRES a V3 registration to deploy.
///
/// @notice On Polygon the SLH requirement is guaranteed by the login flow (every wallet migrates to
///         V3 at unlock, on the Diamond). Satellite chains have no login-time registration, so a
///         plain V6 factory there would happily mint lockboxes whose slhRequired() is false forever
///         — Falcon floor, silently. This subclass closes that: `_checkAccessGate` (the hook the
///         base factory left virtual for exactly this) refuses to deploy a lockbox until the holder
///         has registered their V3 keys on THIS chain's LaipV3SatelliteRegistry, so every lockbox
///         this factory ever creates carries the hash-family requirement from block one.
///
/// @dev NO-LOCKOUT ANALYSIS. The gate runs at CREATION only — it can never strand funds:
///        - deployVault/canDeploy refuse before any vault exists, when nothing is held;
///        - funds sent ahead to the predicted CREATE2 address stay claimable: register (one tx,
///          same seed the dApp already holds) and deploy — the address does not change;
///        - existing vaults, withdrawals, and escape() never consult this gate.
///      The V3 registration needs the same holder Falcon key the base factory already requires via
///      NoWithdrawalCredential, so no wallet that could deploy a v5 lockbox is shut out — it is one
///      extra signature from the same seed, which the dApp performs automatically.
contract LemniVaultFactoryV6Satellite is LemniVaultFactoryV6 {
    constructor(
        address authority_,
        address lemniToken_,
        address laipV3Registry_,
        address[] memory initialAssets,
        uint8[] memory initialTollDecs
    ) LemniVaultFactoryV6(authority_, lemniToken_, laipV3Registry_, initialAssets, initialTollDecs) {
        // A satellite factory without a registry would gate on a call to address(0) — refuse now.
        if (laipV3Registry_ == address(0)) revert ZeroAuthority();
    }

    /// @dev The holder must hold a V3 registration on this chain (canDeploy reports "ACCESS_GATE").
    function _checkAccessGate(address holder, address /*asset*/) internal view override returns (bool) {
        (, , , , bool registered) = ILaipV3Registry(laipV3Registry).getLaipV3Keys(holder);
        return registered;
    }
}
