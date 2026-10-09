// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {LemniVaultV3} from "./LemniVaultV3.sol";

/// @title LemniVaultFactoryV3 — deterministic per-(holder, asset, escape-address) vault deployer
/// @notice Deploys LemniVaultV3 vaults. Same model as v2 — same allowlist, same read-only authority,
///         same owner-is-a-creation-gate-never-a-fund-authority rule, same escape address baked into
///         the CREATE2 address — with the toll configuration the v3 vault needs to enforce the LEMNI
///         toll on-chain when the holder withdraws without the attestor.
///
/// @dev WHAT'S NEW vs v2. Each vault is built with two extra immutables: the LEMNI token address and
///      the asset's unit-toll scale. They exist because `withdrawWithHolderKey` has no attestor to
///      ask "does this holder still hold the toll?", so the vault answers it itself. Both come from
///      factory config rather than the caller: a vault must not be able to lie about its own toll.
///
///      TOLL SCALE. `unitTollDecimals[asset]` is set by the owner alongside the allowlist. An asset
///      configured as 1:1 (unit-toll) gets `unitTollScale = 10**decimals`; everything else gets 0,
///      meaning no withdrawal toll — matching the attestor's vault-toll-config.json, where $:$
///      (value-toll) assets are intentionally absent and never gated on withdrawal.
///
///      Setting the toll changes the CREATE2 address for that asset, so change it BEFORE holders
///      fund vaults for that asset. Existing vaults are immutable and unaffected.
contract LemniVaultFactoryV3 is Ownable {
    /// @notice The LEMNI authority (Diamond on Polygon, or a LemniVaultAuthority elsewhere) every
    ///         vault reads its attestor key, Falcon verifier, and holder key commitments from.
    address public immutable authority;

    /// @notice LEMNI token used for the on-chain withdrawal toll. Zero on chains where LEMNI cannot
    ///         be read in the same transaction — there the toll stays an off-chain check, as today.
    address public immutable lemniToken;

    /// @notice Sentinel for the native gas token (POL) — the vault's receive()/native-send path.
    address public constant NATIVE = address(0);

    /// @notice asset => accepted for vault creation (NATIVE = address(0) for POL).
    mapping(address => bool) public allowedAsset;

    /// @notice asset => decimals, for 1:1 (unit-toll) assets only. Absent/0 = not toll-gated.
    /// @dev Kept as decimals rather than the scale so config reads like the attestor's toll file.
    mapping(address => uint8) public unitTollDecimals;

    /// @notice holder => asset => most-recently-deployed vault (convenience pointer). Because the
    ///         escape address is part of the vault address, a holder MAY have more than one vault for
    ///         the same asset; this records the latest. Authoritative lookups should use
    ///         computeVaultAddress(holder, asset, escapeAddress).
    mapping(address => mapping(address => address)) public vaultOf;

    /// @dev Kept BYTE-IDENTICAL to v1/v2 so the attestor's `vault-autoregister` watcher works
    ///      unchanged against v3 vaults.
    event VaultDeployed(address indexed holder, address indexed asset, address vault);
    event VaultEscapeConfigured(address indexed vault, address escapeAddress);
    event AssetAllowed(address indexed asset, bool allowed);
    event AssetUnitTollSet(address indexed asset, uint8 decimals);

    error ZeroAuthority();
    error ZeroHolder();
    error ZeroEscapeAddress();
    error VaultAlreadyDeployed(address vault);
    error AssetNotAllowed(address asset);
    error AccessGateNotSatisfied();
    error LengthMismatch();
    error InvalidDecimals(uint8 decimals);

    /// @param authority_        LEMNI authority (read-only).
    /// @param lemniToken_       LEMNI token for the on-chain toll, or zero to disable it.
    /// @param initialAssets     Assets that may open a vault.
    /// @param initialTollDecs   Per-asset decimals for 1:1 assets, 0 for assets with no withdrawal
    ///                          toll. Must be the same length as `initialAssets`.
    constructor(
        address authority_,
        address lemniToken_,
        address[] memory initialAssets,
        uint8[] memory initialTollDecs
    ) {
        if (authority_ == address(0)) revert ZeroAuthority();
        if (initialAssets.length != initialTollDecs.length) revert LengthMismatch();

        authority = authority_;
        lemniToken = lemniToken_;

        for (uint256 i = 0; i < initialAssets.length; i++) {
            allowedAsset[initialAssets[i]] = true;
            emit AssetAllowed(initialAssets[i], true);

            if (initialTollDecs[i] != 0) {
                if (initialTollDecs[i] > 36) revert InvalidDecimals(initialTollDecs[i]);
                unitTollDecimals[initialAssets[i]] = initialTollDecs[i];
                emit AssetUnitTollSet(initialAssets[i], initialTollDecs[i]);
            }
        }
    }

    // =========================================================================
    // ALLOWLIST + TOLL CONFIG (owner-gated; creation only — never touches funds) — §15
    // =========================================================================

    function setAssetAllowed(address asset, bool allowed) external onlyOwner {
        allowedAsset[asset] = allowed;
        emit AssetAllowed(asset, allowed);
    }

    /// @notice Mark `asset` as 1:1 (unit-toll) with `decimals`, or pass 0 to remove the toll.
    /// @dev Only affects vaults deployed AFTER this call — and changes their deterministic address.
    ///      Configure an asset before holders fund vaults for it.
    function setAssetUnitToll(address asset, uint8 decimals) external onlyOwner {
        if (decimals > 36) revert InvalidDecimals(decimals);
        unitTollDecimals[asset] = decimals;
        emit AssetUnitTollSet(asset, decimals);
    }

    /// @notice 10**decimals for a 1:1 asset, or 0 when the asset carries no withdrawal toll.
    function unitTollScale(address asset) public view returns (uint256) {
        uint8 decs = unitTollDecimals[asset];
        if (decs == 0 || lemniToken == address(0)) return 0;
        return 10 ** uint256(decs);
    }

    // =========================================================================
    // DEPLOY
    // =========================================================================

    /// @notice Deploy the v3 vault for `(holder, asset)` with the holder's escape address, at its
    ///         deterministic CREATE2 address. Anyone may trigger it — it grants no control over the
    ///         vault — but the escape address binds the address, so only the holder's chosen escape
    ///         address resolves to the address they fund.
    function deployVault(
        address holder,
        address asset,
        address escapeAddress
    ) external returns (address vault) {
        if (holder == address(0)) revert ZeroHolder();
        if (!allowedAsset[asset]) revert AssetNotAllowed(asset);
        if (escapeAddress == address(0)) revert ZeroEscapeAddress();

        if (!_checkAccessGate(holder, asset)) revert AccessGateNotSatisfied();

        address predicted = computeVaultAddress(holder, asset, escapeAddress);
        if (predicted.code.length != 0) revert VaultAlreadyDeployed(predicted);

        vault = address(new LemniVaultV3{salt: _salt(holder, asset, escapeAddress)}(
            holder, asset, authority, escapeAddress, lemniToken, unitTollScale(asset)
        ));
        vaultOf[holder][asset] = vault;
        emit VaultDeployed(holder, asset, vault);
        emit VaultEscapeConfigured(vault, escapeAddress);
    }

    // =========================================================================
    // DETERMINISTIC ADDRESS
    // =========================================================================

    /// @notice The address `(holder, asset, escapeAddress)`'s vault will have (or already has),
    ///         before deploy. Fund this address, then deploy with the SAME arguments.
    function computeVaultAddress(
        address holder,
        address asset,
        address escapeAddress
    ) public view returns (address) {
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                type(LemniVaultV3).creationCode,
                abi.encode(holder, asset, authority, escapeAddress, lemniToken, unitTollScale(asset))
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
    // COLLATERAL TOLL — STUB (§16). Withdrawal/escape MUST NEVER be gated by price/ratio.
    // =========================================================================

    function _checkAccessGate(address /*holder*/, address /*asset*/) internal view virtual returns (bool) {
        return true;
    }
}
