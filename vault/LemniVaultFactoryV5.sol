// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {LemniVaultV5} from "./LemniVaultV5.sol";
import {ILemniAuthority} from "./interfaces/ILemniAuthority.sol";

/// @title LemniVaultFactoryV5 — deterministic per-(holder, asset, escape-address) vault deployer
///
/// @notice Same model and same CREATE2 shape as v4 — allowlist, read-only authority,
///         owner-is-a-creation-gate-never-a-fund-authority, escape address baked into the address.
///
/// @dev THE RING IS NOT A DEPLOYMENT PARAMETER. A v5 vault reads the holder's Multi-Sig ring
///      live from the authority (`getRing`), which is the SAME registry the LEMNI token uses. So
///      there is exactly ONE deploy path — a holder does not choose "ring vault" vs "single vault"
///      here. If they have registered a ring, every vault they own honours it automatically,
///      including vaults deployed and funded BEFORE the ring existed. Register the ring once; the
///      lockboxes follow.
///
///      THE CREATION PRECONDITION. v4 required a registered holder Falcon key, so a vault that could
///      never be withdrawn from could not be created. v5 keeps that guarantee but accepts EITHER
///      credential: a registered holder key (single-holder withdrawals) OR a registered ring (quorum
///      withdrawals). A holder with neither can sign nothing, so deployment is refused.
contract LemniVaultFactoryV5 is Ownable {
    address public immutable authority;
    address public immutable lemniToken;
    address public constant NATIVE = address(0);

    mapping(address => bool) public allowedAsset;
    mapping(address => uint8) public unitTollDecimals;
    mapping(address => mapping(address => address)) public vaultOf;

    /// @dev Kept BYTE-IDENTICAL to v1..v4 so the attestor's vault-autoregister watcher works unchanged.
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
    /// @notice The holder has neither a registered Falcon key nor a registered ring, so nobody could
    ///         authorise a withdrawal from the vault they are asking for.
    error NoWithdrawalCredential(address holder);
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

    /// @notice Deploy the v5 vault for `(holder, asset, escapeAddress)` at its deterministic CREATE2
    ///         address. Anyone may trigger it — it grants no control over the vault. Whether the
    ///         vault requires the holder's ring quorum is decided by the authority, not here.
    function deployVault(
        address holder,
        address asset,
        address escapeAddress
    ) external returns (address vault) {
        if (holder == address(0)) revert ZeroHolder();
        if (!allowedAsset[asset]) revert AssetNotAllowed(asset);
        if (escapeAddress == address(0)) revert ZeroEscapeAddress();
        if (escapeAddress == holder) revert EscapeAddressIsHolder();
        if (!_hasWithdrawalCredential(holder)) revert NoWithdrawalCredential(holder);
        if (!_checkAccessGate(holder, asset)) revert AccessGateNotSatisfied();

        address predicted = computeVaultAddress(holder, asset, escapeAddress);
        if (predicted.code.length != 0) revert VaultAlreadyDeployed(predicted);

        vault = address(new LemniVaultV5{salt: _salt(holder, asset, escapeAddress)}(
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
    function computeVaultAddress(
        address holder,
        address asset,
        address escapeAddress
    ) public view returns (address) {
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                type(LemniVaultV5).creationCode,
                abi.encode(holder, asset, authority, escapeAddress, lemniToken, unitTollScale(asset))
            )
        );
        bytes32 data = keccak256(abi.encodePacked(
            bytes1(0xff), address(this), _salt(holder, asset, escapeAddress), initCodeHash
        ));
        return address(uint160(uint256(data)));
    }

    /// @notice Whether `deployVault(holder, asset, escapeAddress)` would succeed now, and why not.
    function canDeploy(
        address holder,
        address asset,
        address escapeAddress
    ) external view returns (bool ok, string memory reason) {
        if (holder == address(0)) return (false, "ZERO_HOLDER");
        if (!allowedAsset[asset]) return (false, "ASSET_NOT_ALLOWED");
        if (escapeAddress == address(0)) return (false, "ZERO_ESCAPE_ADDRESS");
        if (escapeAddress == holder) return (false, "ESCAPE_IS_HOLDER");
        if (!_hasWithdrawalCredential(holder)) return (false, "NO_WITHDRAWAL_CREDENTIAL");
        if (!_checkAccessGate(holder, asset)) return (false, "ACCESS_GATE");
        if (computeVaultAddress(holder, asset, escapeAddress).code.length != 0) {
            return (false, "ALREADY_DEPLOYED");
        }
        return (true, "");
    }

    /// @dev A holder can authorise a withdrawal if they registered their own Falcon key OR a ring.
    function _hasWithdrawalCredential(address holder) internal view returns (bool) {
        if (ILemniAuthority(authority).holderFalconCommitment(holder) != bytes32(0)) return true;
        (, , bool registered) = ILemniAuthority(authority).getRing(holder);
        return registered;
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
