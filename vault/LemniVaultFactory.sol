// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {LemniVault} from "./LemniVault.sol";

/// @title LemniVaultFactory — deterministic per-(holder, asset) vault deployer (Polygon v1)
/// @notice Deploys one thin vault per (holder, asset) at a CREATE2-deterministic address, and gates
///         creation to an explicit supported-asset allowlist (spec §15). The address is knowable
///         before deployment, so a holder can fund it before the vault exists; deploy on first use.
///
/// @dev ONE VAULT PER ASSET (not pooled, not multi-asset) — keeps the withdrawal attestation
///      byte-for-byte identical to LEMNI's (asset bound by vault identity) and isolates each
///      holder/asset (no honeypot, §6, §12).
///
///      ALLOWLIST OWNER ≠ FUND AUTHORITY. The `owner` here gates which assets may open a vault (and
///      will host the §16 collateral toll). It can NOT move, freeze, or reach funds in any deployed
///      vault — vaults have no owner/admin/upgrade/factory-callback. This preserves Vuln #1: the
///      owner is an economic/creation gate, never an ECDSA path to custody. The allowlist is an
///      explicit ACCEPT list: the owner MUST verify symbol()/decimals() on-chain and apply the §15c
///      rejection rules (fee-on-transfer, rebasing, ERC-777/hooks, reward-bearing LSTs, USDC.e,
///      low-liquidity/unverified, depositor-mintable) before allowing any asset.
contract LemniVaultFactory is Ownable {
    /// @notice The EXISTING LEMNI Diamond every vault reads its attestor key + Falcon verifier from.
    address public immutable authority;

    /// @notice Sentinel for the native gas token (POL) — the vault's receive()/native-send path.
    address public constant NATIVE = address(0);

    /// @notice asset => accepted for vault creation (NATIVE = address(0) for POL).
    mapping(address => bool) public allowedAsset;

    /// @notice holder => asset => deployed vault address (zero until deployed).
    mapping(address => mapping(address => address)) public vaultOf;

    event VaultDeployed(address indexed holder, address indexed asset, address vault);
    event AssetAllowed(address indexed asset, bool allowed);

    error ZeroAuthority();
    error ZeroHolder();
    error VaultAlreadyDeployed(address vault);
    error AssetNotAllowed(address asset);
    error AccessGateNotSatisfied();

    /// @param authority_     The LEMNI Diamond (read-only authority).
    /// @param initialAssets  Seed allowlist (verified Tier-1 set). Include `NATIVE` for POL.
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

    /// @notice Add/remove an asset from the supported-asset allowlist. Owner MUST have verified
    ///         symbol()/decimals() on-chain and applied the §15c rejection rules first.
    /// @dev Removing an asset only blocks NEW vault creation; it cannot reach funds in vaults that
    ///      already exist (those remain fully withdrawable via PQC attestation).
    function setAssetAllowed(address asset, bool allowed) external onlyOwner {
        allowedAsset[asset] = allowed;
        emit AssetAllowed(asset, allowed);
    }

    // =========================================================================
    // DEPLOY
    // =========================================================================

    /// @notice Deploy the vault for `(holder, asset)` at its deterministic CREATE2 address.
    ///         `asset == NATIVE` deploys a native (POL) vault. Idempotent; reverts if already
    ///         deployed or if the asset is not allowlisted. Anyone may trigger it — it grants no
    ///         control over the vault.
    function deployVault(address holder, address asset) external returns (address vault) {
        if (holder == address(0)) revert ZeroHolder();
        if (!allowedAsset[asset]) revert AssetNotAllowed(asset);
        address existing = vaultOf[holder][asset];
        if (existing != address(0)) revert VaultAlreadyDeployed(existing);

        // v1 collateral toll (§16). Stubbed: orthogonal to security, never the lock.
        if (!_checkAccessGate(holder, asset)) revert AccessGateNotSatisfied();

        vault = address(new LemniVault{salt: _salt(holder, asset)}(holder, asset, authority));
        vaultOf[holder][asset] = vault;
        emit VaultDeployed(holder, asset, vault);
    }

    // =========================================================================
    // DETERMINISTIC ADDRESS
    // =========================================================================

    /// @notice The address `(holder, asset)`'s vault will have (or already has), before deploy.
    function computeVaultAddress(address holder, address asset) public view returns (address) {
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(type(LemniVault).creationCode, abi.encode(holder, asset, authority))
        );
        bytes32 data = keccak256(abi.encodePacked(bytes1(0xff), address(this), _salt(holder, asset), initCodeHash));
        return address(uint160(uint256(data)));
    }

    function _salt(address holder, address asset) internal pure returns (bytes32) {
        return keccak256(abi.encode(holder, asset));
    }

    // =========================================================================
    // COLLATERAL TOLL — 1:1 / value-denominated LEMNI gate (STUB for v1, §16)
    // =========================================================================

    /// @notice The "stake N LEMNI to open protection" toll (§16) lives HERE, gating vault creation.
    ///         It is ORTHOGONAL to security and NOT the lock — protection comes 100% from the
    ///         deposit-into-vault, 0% from any pairing (§3). Two models the owner wires later:
    ///         - Model A (value-denominated): stablecoins + POL/WPOL → required = q*price_asset/price_LEMNI
    ///         - Model B (unit 1:1): WETH/WBTC/non-stables → required = q  (no oracle)
    /// @dev v1 STUB: always passes (per §16 build note — prove the PQC release path first, wire the
    ///      gate only after Tests A and B pass). Withdrawal of protected assets MUST NEVER be gated
    ///      by LEMNI price or collateral ratio. NO forced liquidation, NO liquidation engine.
    function _checkAccessGate(address /*holder*/, address /*asset*/) internal view virtual returns (bool) {
        return true;
    }
}
