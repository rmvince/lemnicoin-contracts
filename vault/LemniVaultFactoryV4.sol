// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {LemniVaultV4} from "./LemniVaultV4.sol";
import {ILemniAuthority} from "./interfaces/ILemniAuthority.sol";

/// @title LemniVaultFactoryV4 — deterministic per-(holder, asset, escape-address) vault deployer
///
/// @notice Same model as v3 — same allowlist, same read-only authority, same
///         owner-is-a-creation-gate-never-a-fund-authority rule, same escape address baked into the
///         CREATE2 address — plus the one precondition that makes v4's mandatory holder signature
///         safe: **a vault cannot be created for a holder who cannot sign for it.**
///
/// @dev THE PRECONDITION. `LemniVaultV4` requires the holder's Falcon signature on every withdrawal.
///      That is only an improvement if the holder actually has a registered key; without one it
///      would be a way to strand funds. The dApp registers the commitment at unlock, but that is a
///      transaction the user can decline, run out of gas on, or lose to an RPC failure — and today
///      that failure is swallowed silently.
///
///      So the invariant is enforced here instead of hoped for: `deployVault` reverts unless the
///      authority already holds a commitment for `holder`. A vault that cannot be withdrawn from
///      cannot come into existence. No client bug can produce one.
///
///      WHY NOT CHECK IT ONLY IN THE VAULT. The vault does check, at withdrawal time — but by then
///      the funds are already inside. Checking at creation is what converts "your withdrawal will
///      revert" into "you never got a vault to fund".
///
///      ADDRESS DERIVATION IS UNCHANGED IN SHAPE. Still CREATE2 over (holder, asset, escapeAddress),
///      so `computeVaultAddress` remains the way to learn where to send funds before deployment. The
///      addresses differ from v3's because the initcode differs — v4 vaults live at their own
///      addresses and v3 vaults are untouched.
contract LemniVaultFactoryV4 is Ownable {
    /// @notice The LEMNI authority every vault reads its attestor key, Falcon verifier, and holder
    ///         key commitments from.
    address public immutable authority;

    /// @notice LEMNI token used for the on-chain withdrawal toll. Zero disables it.
    address public immutable lemniToken;

    /// @notice Sentinel for the native gas token (POL).
    address public constant NATIVE = address(0);

    /// @notice asset => accepted for vault creation (NATIVE = address(0) for POL).
    mapping(address => bool) public allowedAsset;

    /// @notice asset => decimals, for 1:1 (unit-toll) assets only. Absent/0 = not toll-gated.
    mapping(address => uint8) public unitTollDecimals;

    /// @notice holder => asset => most-recently-deployed vault (convenience pointer).
    mapping(address => mapping(address => address)) public vaultOf;

    /// @dev Kept BYTE-IDENTICAL to v1/v2/v3 so the attestor's `vault-autoregister` watcher works
    ///      unchanged against v4 vaults.
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
    /// @notice v4: the holder has no Falcon key registered with the authority, so they could not
    ///         sign a withdrawal from the vault they are asking for.
    error HolderFalconKeyNotRegistered(address holder);
    /// @notice v4: the escape address may not be the holder's own wallet. Rejected here as well as
    ///         in the vault so the failure is cheap and the reason is unambiguous.
    error EscapeAddressIsHolder();

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
    // ALLOWLIST + TOLL CONFIG (owner-gated; creation only — never touches funds)
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

    function unitTollScale(address asset) public view returns (uint256) {
        uint8 decs = unitTollDecimals[asset];
        if (decs == 0 || lemniToken == address(0)) return 0;
        return 10 ** uint256(decs);
    }

    // =========================================================================
    // DEPLOY
    // =========================================================================

    /// @notice Deploy the v4 vault for `(holder, asset, escapeAddress)` at its deterministic CREATE2
    ///         address. Anyone may trigger it — it grants no control over the vault.
    /// @dev Reverts if `holder` has no registered Falcon commitment. That is the whole point: v4
    ///      requires the holder's signature to withdraw, so creating a vault for a holder who has
    ///      none would produce funds nobody can move.
    function deployVault(
        address holder,
        address asset,
        address escapeAddress
    ) external returns (address vault) {
        if (holder == address(0)) revert ZeroHolder();
        if (!allowedAsset[asset]) revert AssetNotAllowed(asset);
        if (escapeAddress == address(0)) revert ZeroEscapeAddress();
        if (escapeAddress == holder) revert EscapeAddressIsHolder();

        // The invariant that makes the mandatory holder signature safe.
        if (ILemniAuthority(authority).holderFalconCommitment(holder) == bytes32(0)) {
            revert HolderFalconKeyNotRegistered(holder);
        }

        if (!_checkAccessGate(holder, asset)) revert AccessGateNotSatisfied();

        address predicted = computeVaultAddress(holder, asset, escapeAddress);
        if (predicted.code.length != 0) revert VaultAlreadyDeployed(predicted);

        vault = address(new LemniVaultV4{salt: _salt(holder, asset, escapeAddress)}(
            holder, asset, authority, escapeAddress, lemniToken, unitTollScale(asset)
        ));
        vaultOf[holder][asset] = vault;
        emit VaultDeployed(holder, asset, vault);
        emit VaultEscapeConfigured(vault, escapeAddress);
    }

    // =========================================================================
    // DETERMINISTIC ADDRESS
    // =========================================================================

    /// @notice The address `(holder, asset, escapeAddress)`'s vault will have (or already has).
    ///         Fund this address, then deploy with the SAME arguments.
    /// @dev Pure address arithmetic — it does NOT check that the holder is registered, so a caller
    ///      can preview an address before registering. Use `canDeploy` to learn whether the
    ///      deployment would actually succeed.
    function computeVaultAddress(
        address holder,
        address asset,
        address escapeAddress
    ) public view returns (address) {
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                type(LemniVaultV4).creationCode,
                abi.encode(holder, asset, authority, escapeAddress, lemniToken, unitTollScale(asset))
            )
        );
        bytes32 data = keccak256(abi.encodePacked(
            bytes1(0xff), address(this), _salt(holder, asset, escapeAddress), initCodeHash
        ));
        return address(uint160(uint256(data)));
    }

    /// @notice Whether `deployVault(holder, asset, escapeAddress)` would succeed right now, and why
    ///         not if it would not.
    /// @dev So the dApp can tell a user "register your key first" BEFORE they send funds to a
    ///      computed address, rather than after.
    /// @return ok        true if the deployment would succeed
    /// @return reason    empty when ok, else a short machine-readable cause
    function canDeploy(
        address holder,
        address asset,
        address escapeAddress
    ) external view returns (bool ok, string memory reason) {
        if (holder == address(0)) return (false, "ZERO_HOLDER");
        if (!allowedAsset[asset]) return (false, "ASSET_NOT_ALLOWED");
        if (escapeAddress == address(0)) return (false, "ZERO_ESCAPE_ADDRESS");
        if (escapeAddress == holder) return (false, "ESCAPE_IS_HOLDER");
        if (ILemniAuthority(authority).holderFalconCommitment(holder) == bytes32(0)) {
            return (false, "HOLDER_FALCON_KEY_NOT_REGISTERED");
        }
        if (!_checkAccessGate(holder, asset)) return (false, "ACCESS_GATE");
        if (computeVaultAddress(holder, asset, escapeAddress).code.length != 0) {
            return (false, "ALREADY_DEPLOYED");
        }
        return (true, "");
    }

    function _salt(address holder, address asset, address escapeAddress) internal pure returns (bytes32) {
        return keccak256(abi.encode(holder, asset, escapeAddress));
    }

    // =========================================================================
    // COLLATERAL TOLL — STUB. Withdrawal/escape MUST NEVER be gated by price/ratio.
    // =========================================================================

    function _checkAccessGate(address /*holder*/, address /*asset*/) internal view virtual returns (bool) {
        return true;
    }
}
