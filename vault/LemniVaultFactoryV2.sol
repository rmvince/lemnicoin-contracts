// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {LemniVaultV2} from "./LemniVaultV2.sol";

/// @title LemniVaultFactoryV2 — deterministic per-(holder, asset, escape-address) vault deployer
/// @notice Deploys LemniVaultV2 vaults. Identical to LemniVaultFactory (v1) — same allowlist, same
///         read-only authority, same owner-is-a-creation-gate-never-a-fund-authority model — with ONE
///         addition: every vault is created with a holder-chosen `escapeAddress`, enabling the simple
///         attestor-free escape (LemniVaultV2.escape).
///
/// @dev THE ESCAPE ADDRESS IS PART OF THE VAULT'S IDENTITY. It is a constructor immutable, so it is
///      baked into the CREATE2 address, and the salt commits to it too. A given (holder, asset) with a
///      DIFFERENT escape address resolves to a DIFFERENT vault, which prevents a griefer from
///      front-running deployVault to squat a holder's slot with a bogus escape address: a wrong escape
///      address simply produces a different, unrelated address the holder never funds. The holder
///      computes their address from their OWN chosen escape address (computeVaultAddress), funds it,
///      then deploys — the address matches only if the escape address matches.
///
///      OWNER ≠ FUND AUTHORITY (unchanged from v1). The owner gates which assets may open a vault and
///      cannot move, freeze, or reach funds in any deployed vault. Preserves Vuln #1.
contract LemniVaultFactoryV2 is Ownable {
    /// @notice The LEMNI authority (Diamond on Polygon, or a LemniVaultAuthority elsewhere) every
    ///         vault reads its attestor key + Falcon verifier from.
    address public immutable authority;

    /// @notice Sentinel for the native gas token (POL) — the vault's receive()/native-send path.
    address public constant NATIVE = address(0);

    /// @notice asset => accepted for vault creation (NATIVE = address(0) for POL).
    mapping(address => bool) public allowedAsset;

    /// @notice holder => asset => most-recently-deployed vault (convenience pointer). Because the
    ///         escape address is part of the vault address, a holder MAY have more than one vault for
    ///         the same asset (distinct escape addresses); this records the latest. Authoritative
    ///         lookups should use computeVaultAddress(holder, asset, escapeAddress).
    mapping(address => mapping(address => address)) public vaultOf;

    /// @dev Kept BYTE-IDENTICAL to v1 so the existing attestor `vault-autoregister` watcher (which
    ///      allowlists new vaults with the attestor by listening for this event) works unchanged.
    event VaultDeployed(address indexed holder, address indexed asset, address vault);
    /// @notice The escape address a vault was created with (informational; also on the vault).
    event VaultEscapeConfigured(address indexed vault, address escapeAddress);
    event AssetAllowed(address indexed asset, bool allowed);

    error ZeroAuthority();
    error ZeroHolder();
    error ZeroEscapeAddress();
    error VaultAlreadyDeployed(address vault);
    error AssetNotAllowed(address asset);
    error AccessGateNotSatisfied();

    constructor(address authority_, address[] memory initialAssets) {
        if (authority_ == address(0)) revert ZeroAuthority();
        authority = authority_;
        for (uint256 i = 0; i < initialAssets.length; i++) {
            allowedAsset[initialAssets[i]] = true;
            emit AssetAllowed(initialAssets[i], true);
        }
    }

    // =========================================================================
    // ALLOWLIST (owner-gated; creation only — never touches funds) — §15
    // =========================================================================

    function setAssetAllowed(address asset, bool allowed) external onlyOwner {
        allowedAsset[asset] = allowed;
        emit AssetAllowed(asset, allowed);
    }

    // =========================================================================
    // DEPLOY
    // =========================================================================

    /// @notice Deploy the v2 vault for `(holder, asset)` with the holder's escape address, at its
    ///         deterministic CREATE2 address. Reverts if that exact vault already exists. Anyone may
    ///         trigger it — it grants no control over the vault — but the escape address binds the
    ///         address, so only the holder's chosen escape address resolves to the address they fund.
    function deployVault(
        address holder,
        address asset,
        address escapeAddress
    ) external returns (address vault) {
        if (holder == address(0)) revert ZeroHolder();
        if (!allowedAsset[asset]) revert AssetNotAllowed(asset);
        if (escapeAddress == address(0)) revert ZeroEscapeAddress();

        // v1 collateral toll (§16). Stubbed: orthogonal to security, never the lock.
        if (!_checkAccessGate(holder, asset)) revert AccessGateNotSatisfied();

        address predicted = computeVaultAddress(holder, asset, escapeAddress);
        if (predicted.code.length != 0) revert VaultAlreadyDeployed(predicted);

        vault = address(new LemniVaultV2{salt: _salt(holder, asset, escapeAddress)}(
            holder, asset, authority, escapeAddress
        ));
        vaultOf[holder][asset] = vault;
        emit VaultDeployed(holder, asset, vault);
        emit VaultEscapeConfigured(vault, escapeAddress);
    }

    // =========================================================================
    // DETERMINISTIC ADDRESS
    // =========================================================================

    /// @notice The address `(holder, asset, escapeAddress)`'s vault will have (or already has), before
    ///         deploy. Fund this address, then deploy with the SAME arguments.
    function computeVaultAddress(
        address holder,
        address asset,
        address escapeAddress
    ) public view returns (address) {
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                type(LemniVaultV2).creationCode,
                abi.encode(holder, asset, authority, escapeAddress)
            )
        );
        bytes32 data = keccak256(abi.encodePacked(
            bytes1(0xff), address(this), _salt(holder, asset, escapeAddress), initCodeHash
        ));
        return address(uint160(uint256(data)));
    }

    function _salt(address holder, address asset, address escapeAddress) internal pure returns (bytes32) {
        return keccak256(abi.encode(holder, asset, escapeAddress));
    }

    // =========================================================================
    // COLLATERAL TOLL — STUB for v1 (§16). Withdrawal/escape MUST NEVER be gated by price/ratio.
    // =========================================================================

    function _checkAccessGate(address /*holder*/, address /*asset*/) internal view virtual returns (bool) {
        return true;
    }
}
