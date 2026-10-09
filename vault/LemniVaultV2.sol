// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

import {IZKNOXEthFalcon} from "../falcon/IZKNOXEthFalcon.sol";
import {ILemniAuthority} from "./interfaces/ILemniAuthority.sol";

/// @title LemniVaultV2 — quantum-resistant vault with a simple attestor-free escape (Polygon v2)
/// @notice Identical to LemniVault (v1) in every respect — same per-(holder, asset) custody, same
///         LEMNI-identical post-quantum Falcon withdrawal — PLUS one tiny, additive outflow:
///         `escape()`. It sweeps the ENTIRE balance to a single address the holder locks in at
///         creation (`escapeAddress`), and can be triggered only by the holder wallet or that escape
///         wallet. No attestor, no dApp, no server, no seed, no signatures beyond an ordinary EVM
///         transaction. It exists so a vanished or malfunctioning attestor can never permanently trap
///         a holder's funds.
///
/// @dev WHY THIS IS SAFE (does NOT reintroduce Vuln #1). Vuln #1 forbids any path where an ECDSA key
///      moves funds to an ATTACKER. `escape()` is gated by an ECDSA check, but it can ONLY ever pay
///      `escapeAddress` — an address fixed in the constructor (immutable). So:
///        * A thief who steals the holder's hot key can, at most, push the funds to the holder's OWN
///          pre-chosen cold address — never to themselves. Recipient-binding, not the caller, is the
///          safety property (Vuln #2 style: the destination cannot be re-aimed).
///        * A quantum adversary who forges the holder's secp256k1 key is in the same position:
///          they can only relocate funds to the holder's cold wallet. Nothing is stealable.
///      This is the deliberate trade-off for radical simplicity: the escape sweeps to ONE fixed
///      address, not an arbitrary recipient. For arbitrary-recipient moves, use the attestor path.
///
///      NO OTHER AUTHORITY IS ADDED. Still no owner, admin, upgrade key, pause, or arbitrary-recipient
///      recovery. Funds leave only via (1) the attestor Falcon attestation (arbitrary recipient,
///      exactly as v1) or (2) escape() (holder/escape wallet, fixed recipient).
contract LemniVaultV2 is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // =========================================================================
    // IMMUTABLES
    // =========================================================================

    /// @notice The holder this vault was deployed for. Bound into the attestation as `user`; also one
    ///         of the two addresses permitted to trigger `escape()`.
    address public immutable holder;

    /// @notice The single asset this vault custodies. `address(0)` = native value (POL).
    address public immutable asset;

    /// @notice The LEMNI authority (Diamond on Polygon, LemniVaultAuthority elsewhere), read-only,
    ///         for the attestor key + Falcon verifier.
    ILemniAuthority public immutable authority;

    /// @notice The ONLY address `escape()` can ever pay, and the other address permitted to trigger
    ///         it. Chosen by the holder at creation and immutable thereafter. Pick a durable,
    ///         well-secured cold wallet you will always control — if it is lost, so is the escape lane
    ///         (funds then remain reachable only via the attestor path).
    address public immutable escapeAddress;

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Monotonic per-vault withdrawal nonce for the attestor path. Replay protection (Vuln #2).
    uint256 public withdrawalNonce;

    // =========================================================================
    // EIP-712 — IDENTICAL TO LEMNI (LibLemnicoin / FalconAttestation)
    // =========================================================================

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 private constant ATTEST_TYPEHASH = keccak256(
        "PQAttestation(address user,address to,uint256 amount,bytes32 quantumInputHash,uint256 nonce,uint256 deadline)"
    );

    bytes32 private constant NAME_HASH = keccak256("LemnicoinPQAttestation");
    bytes32 private constant VERSION_HASH = keccak256("1");

    // =========================================================================
    // EVENTS
    // =========================================================================

    event NativeDeposited(address indexed from, uint256 amount);
    event Withdrawn(
        address indexed recipient, uint256 amount, uint256 nonce, bytes32 quantumInputHash, address gasPayer
    );
    /// @notice Emitted when escape() sweeps the vault to the pre-committed escape address.
    event Escaped(address indexed escapeAddress, uint256 amount, address caller);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error ZeroAuthority();
    error ZeroRecipient();
    error ZeroEscapeAddress();
    error AttestationExpired();
    error InvalidNonce(uint256 expected, uint256 provided);
    error InvalidSaltLength(uint256 length);
    error InvalidS2Length(uint256 length);
    error FalconVerificationFailed();
    error NativeSendFailed();
    error NotNativeVault();
    error NotEscapeAuthorized();
    error NothingToEscape();

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor(address holder_, address asset_, address authority_, address escapeAddress_) {
        if (authority_ == address(0)) revert ZeroAuthority();
        if (escapeAddress_ == address(0)) revert ZeroEscapeAddress();
        holder = holder_;
        asset = asset_;
        authority = ILemniAuthority(authority_);
        escapeAddress = escapeAddress_;
    }

    // =========================================================================
    // DEPOSIT (in)
    // =========================================================================

    receive() external payable {
        if (asset != address(0)) revert NotNativeVault();
        emit NativeDeposited(msg.sender, msg.value);
    }

    // =========================================================================
    // WITHDRAW (out) — attestor path (arbitrary recipient), IDENTICAL TO v1
    // =========================================================================

    /// @notice Release `amount` to `recipient`, authorized SOLELY by a post-quantum dual-authority
    ///         Falcon attestation — verified exactly as LEMNI verifies a transfer. `msg.sender` is
    ///         the gas payer and carries NO authority (Vuln #1).
    function withdraw(
        address recipient,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32
    ) external nonReentrant {
        if (recipient == address(0)) revert ZeroRecipient();
        if (block.timestamp > deadline) revert AttestationExpired();
        if (nonce != withdrawalNonce) revert InvalidNonce(withdrawalNonce, nonce);
        if (falconSalt40.length != 40) revert InvalidSaltLength(falconSalt40.length);
        if (falconS2_32.length != 32) revert InvalidS2Length(falconS2_32.length);

        bytes32 digest = _attestationDigest(holder, recipient, amount, quantumInputHash, nonce, deadline);

        IZKNOXEthFalcon verifier = IZKNOXEthFalcon(authority.FALCON_VERIFIER());
        bool valid = verifier.verify(
            abi.encodePacked(digest), falconSalt40, _toMemoryArray(falconS2_32), _attestorNtth()
        );
        if (!valid) revert FalconVerificationFailed();

        withdrawalNonce = nonce + 1;

        if (asset == address(0)) {
            (bool ok, ) = payable(recipient).call{value: amount}("");
            if (!ok) revert NativeSendFailed();
        } else {
            IERC20(asset).safeTransfer(recipient, amount);
        }

        emit Withdrawn(recipient, amount, nonce, quantumInputHash, msg.sender);
    }

    // =========================================================================
    // ESCAPE (out) — attestor-free, fixed recipient, new in v2
    // =========================================================================

    /// @notice Sweep the ENTIRE vault balance to the pre-committed `escapeAddress`. Callable ONLY by
    ///         the holder wallet or the escape wallet, and can ONLY ever pay `escapeAddress`. No
    ///         attestor, dApp, or server — just an ordinary transaction from a wallet you control.
    ///
    /// @dev Un-stealable by construction: the destination is the immutable `escapeAddress`, so even a
    ///      compromised holder key (classical or quantum) can at most relocate funds to the holder's
    ///      OWN cold wallet. Recover by calling this from your escape (cold) wallet — via the dApp, a
    ///      tiny script, or a block explorer's "Write Contract" tab.
    function escape() external nonReentrant {
        if (msg.sender != holder && msg.sender != escapeAddress) revert NotEscapeAuthorized();

        uint256 amount;
        if (asset == address(0)) {
            amount = address(this).balance;
            if (amount == 0) revert NothingToEscape();
            (bool ok, ) = payable(escapeAddress).call{value: amount}("");
            if (!ok) revert NativeSendFailed();
        } else {
            amount = IERC20(asset).balanceOf(address(this));
            if (amount == 0) revert NothingToEscape();
            IERC20(asset).safeTransfer(escapeAddress, amount);
        }

        emit Escaped(escapeAddress, amount, msg.sender);
    }

    // =========================================================================
    // VIEWS
    // =========================================================================

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this))
        );
    }

    function computeAttestationDigest(
        address recipient,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32) {
        return _attestationDigest(holder, recipient, amount, quantumInputHash, nonce, deadline);
    }

    // =========================================================================
    // INTERNAL
    // =========================================================================

    function _attestationDigest(
        address user,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(ATTEST_TYPEHASH, user, to, amount, quantumInputHash, nonce, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function _attestorNtth() internal view returns (uint256[] memory out) {
        uint256[32] memory fixedKey = authority.getAttestorPublicKey();
        out = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            out[i] = fixedKey[i];
        }
    }

    function _toMemoryArray(uint256[] calldata arr) internal pure returns (uint256[] memory out) {
        out = new uint256[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) {
            out[i] = arr[i];
        }
    }
}
