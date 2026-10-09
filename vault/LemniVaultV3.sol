// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

import {IZKNOXEthFalcon} from "../falcon/IZKNOXEthFalcon.sol";
import {ILemniAuthority} from "./interfaces/ILemniAuthority.sol";

/// @title LemniVaultV3 — quantum vault with an attestor-free withdrawal the holder signs themselves
/// @notice Everything LemniVaultV2 does (per-(holder, asset) custody, Falcon-attested withdrawal,
///         fixed-recipient `escape()`) plus one addition: `withdrawWithHolderKey()`, which accepts a
///         withdrawal to ANY recipient when it is signed by the holder's OWN Falcon-512 key.
///
/// @dev WHY THIS EXISTS. v2 gave holders `escape()` — an attestor-free exit, but only ever to one
///      pre-chosen address. That covers "get my money out", not "pay someone" or "move part of it".
///      This closes that gap: if the attestor is unreachable, the holder signs the identical
///      attestation packet with a Falcon key derived from their own 48-word seed, and the vault
///      verifies it with the same on-chain verifier, at the same cost.
///
///      WHY IT DOES NOT WEAKEN THE VAULT (Vuln #1 unaffected). Authority still comes from a
///      post-quantum signature, never from `msg.sender`. The holder's key is quantum-resistant and
///      derived from the seed, so a stolen wallet key does not produce it, and a quantum adversary
///      who breaks secp256k1 still cannot forge Falcon. What changes is only WHOSE Falcon key may
///      authorise: the attestor's, or the holder's own registered key.
///
///      THE HOLDER KEY IS NOT STORED HERE. The vault reads a commitment to it from the authority, so
///      a single registration covers every vault the holder owns — including vaults deployed before
///      they ever registered — and rotation policy stays in one place.
///
///      THE LEMNI TOLL IS ENFORCED HERE, ON-CHAIN. On the attestor path the toll for 1:1 assets is a
///      condition of the attestor signing (off-chain, fail-open). With the attestor out of the loop
///      that check would vanish, so this path enforces it in the transaction itself — strictly
///      stronger, and impossible to bypass by going around the attestor.
///
///      STILL NO OWNER, admin, upgrade key, pause, or arbitrary-recipient recovery. Funds leave only
///      via (1) attestor attestation, (2) holder attestation, or (3) escape() to the fixed address.
contract LemniVaultV3 is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // =========================================================================
    // IMMUTABLES
    // =========================================================================

    /// @notice The holder this vault was deployed for. Bound into the attestation as `user`, the
    ///         account whose Falcon key may sign, and one of the two addresses that may `escape()`.
    address public immutable holder;

    /// @notice The single asset this vault custodies. `address(0)` = native value (POL).
    address public immutable asset;

    /// @notice The LEMNI authority (Diamond on Polygon, LemniVaultAuthority elsewhere), read-only:
    ///         attestor key, Falcon verifier, and holder key commitments.
    ILemniAuthority public immutable authority;

    /// @notice The ONLY address `escape()` can ever pay, and the other address permitted to trigger
    ///         it. Chosen by the holder at creation and immutable thereafter.
    address public immutable escapeAddress;

    /// @notice LEMNI token, for the on-chain toll check. Zero disables it (chains where LEMNI is not
    ///         readable in the same transaction — the toll is enforced off-chain there, as today).
    address public immutable lemniToken;

    /// @notice 10**decimals of this asset if it is a 1:1 (unit-toll) asset, else 0 for no toll.
    ///         Required LEMNI = ceil(amount / unitTollScale) whole tokens, mirroring the attestor's
    ///         requiredUnitLemni() exactly.
    uint256 public immutable unitTollScale;

    /// @dev One whole LEMNI (18 decimals).
    uint256 private constant LEMNI_UNIT = 1e18;

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Monotonic withdrawal nonce, SHARED by both attestation paths so a packet can never be
    ///         replayed against the other one.
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
    /// @notice Emitted when a withdrawal was authorised by the holder's own key, not the attestor's.
    event WithdrawnWithHolderKey(
        address indexed recipient, uint256 amount, uint256 nonce, bytes32 quantumInputHash, address gasPayer
    );
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
    error InvalidNtthLength(uint256 length);
    error FalconVerificationFailed();
    error NativeSendFailed();
    error NotNativeVault();
    error NotEscapeAuthorized();
    error NothingToEscape();
    error HolderFalconKeyNotRegistered();
    error HolderFalconKeyMismatch();
    error LemniTollNotMet(uint256 required, uint256 held);

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor(
        address holder_,
        address asset_,
        address authority_,
        address escapeAddress_,
        address lemniToken_,
        uint256 unitTollScale_
    ) {
        if (authority_ == address(0)) revert ZeroAuthority();
        if (escapeAddress_ == address(0)) revert ZeroEscapeAddress();
        holder = holder_;
        asset = asset_;
        authority = ILemniAuthority(authority_);
        escapeAddress = escapeAddress_;
        lemniToken = lemniToken_;
        unitTollScale = unitTollScale_;
    }

    // =========================================================================
    // DEPOSIT (in)
    // =========================================================================

    receive() external payable {
        if (asset != address(0)) revert NotNativeVault();
        emit NativeDeposited(msg.sender, msg.value);
    }

    // =========================================================================
    // WITHDRAW (out) — attestor path, IDENTICAL TO v1/v2
    // =========================================================================

    /// @notice Release `amount` to `recipient`, authorized SOLELY by the attestor's Falcon
    ///         attestation. `msg.sender` is the gas payer and carries NO authority (Vuln #1).
    function withdraw(
        address recipient,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32
    ) external nonReentrant {
        bytes32 digest =
            _validateAndDigest(recipient, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32);

        if (!_falconVerify(digest, falconSalt40, falconS2_32, _attestorNtth())) revert FalconVerificationFailed();

        withdrawalNonce = nonce + 1;
        _payOut(recipient, amount);

        emit Withdrawn(recipient, amount, nonce, quantumInputHash, msg.sender);
    }

    // =========================================================================
    // WITHDRAW (out) — holder-signed path, new in v3
    // =========================================================================

    /// @notice Same withdrawal, authorized by the HOLDER'S OWN Falcon key instead of the attestor's.
    /// @dev For when the attestor is unreachable. The digest, nonce, deadline and verifier are
    ///      identical to `withdraw`, so the dApp can re-sign a packet it had prepared for the
    ///      attestor and submit it here unchanged.
    ///
    ///      `holderNtth` arrives in calldata (32 words is too costly to store per vault) and is
    ///      bound to the holder by hashing it against the commitment the authority holds. Without a
    ///      registered commitment this path does not exist for that holder.
    ///
    ///      Unlike `withdraw`, this enforces the LEMNI toll on-chain for 1:1 assets — the attestor
    ///      is not here to do it.
    /// @param holderNtth The holder's registered Falcon public key (NTT domain, 32 words).
    function withdrawWithHolderKey(
        address recipient,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        uint256[] calldata holderNtth
    ) external nonReentrant {
        bytes32 digest =
            _validateAndDigest(recipient, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32);

        _requireHolderKey(holderNtth);
        _requireLemniToll(amount);

        if (!_falconVerify(digest, falconSalt40, falconS2_32, _toMemoryArray(holderNtth))) {
            revert FalconVerificationFailed();
        }

        withdrawalNonce = nonce + 1;
        _payOut(recipient, amount);

        emit WithdrawnWithHolderKey(recipient, amount, nonce, quantumInputHash, msg.sender);
    }

    // =========================================================================
    // ESCAPE (out) — attestor-free, fixed recipient, unchanged from v2
    // =========================================================================

    /// @notice Sweep the ENTIRE vault balance to the pre-committed `escapeAddress`. Callable ONLY by
    ///         the holder wallet or the escape wallet, and can ONLY ever pay `escapeAddress`.
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

    /// @notice LEMNI (base units) the holder must hold to withdraw `amount` on the holder-key path.
    ///         Zero when this vault's asset is not 1:1 tolled.
    function requiredLemniToll(uint256 amount) public view returns (uint256) {
        if (unitTollScale == 0 || lemniToken == address(0) || amount == 0) return 0;
        // ceil(amount / scale) whole LEMNI — mirrors the attestor's requiredUnitLemni().
        return ((amount + unitTollScale - 1) / unitTollScale) * LEMNI_UNIT;
    }

    /// @notice Whether the holder can currently use the attestor-free withdrawal path.
    function holderKeyRegistered() external view returns (bool) {
        return authority.holderFalconCommitment(holder) != bytes32(0);
    }

    // =========================================================================
    // INTERNAL
    // =========================================================================

    /// @dev Shared front half of both withdrawal paths: identical validation, identical digest.
    function _validateAndDigest(
        address recipient,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32
    ) internal view returns (bytes32) {
        if (recipient == address(0)) revert ZeroRecipient();
        if (block.timestamp > deadline) revert AttestationExpired();
        if (nonce != withdrawalNonce) revert InvalidNonce(withdrawalNonce, nonce);
        if (falconSalt40.length != 40) revert InvalidSaltLength(falconSalt40.length);
        if (falconS2_32.length != 32) revert InvalidS2Length(falconS2_32.length);
        return _attestationDigest(holder, recipient, amount, quantumInputHash, nonce, deadline);
    }

    /// @dev Revert unless `holderNtth` is exactly the key the holder registered with the authority.
    function _requireHolderKey(uint256[] calldata holderNtth) internal view {
        if (holderNtth.length != 32) revert InvalidNtthLength(holderNtth.length);

        bytes32 commitment = authority.holderFalconCommitment(holder);
        if (commitment == bytes32(0)) revert HolderFalconKeyNotRegistered();
        if (keccak256(abi.encodePacked(holderNtth)) != commitment) revert HolderFalconKeyMismatch();
    }

    /// @dev Revert unless the holder still holds the LEMNI toll for a 1:1 asset. No-op otherwise.
    function _requireLemniToll(uint256 amount) internal view {
        uint256 required = requiredLemniToll(amount);
        if (required == 0) return;

        uint256 held = IERC20(lemniToken).balanceOf(holder);
        if (held < required) revert LemniTollNotMet(required, held);
    }

    function _falconVerify(
        bytes32 digest,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        uint256[] memory ntth
    ) internal view returns (bool) {
        return IZKNOXEthFalcon(authority.FALCON_VERIFIER()).verify(
            abi.encodePacked(digest), falconSalt40, _toMemoryArray(falconS2_32), ntth
        );
    }

    function _payOut(address recipient, uint256 amount) internal {
        if (asset == address(0)) {
            (bool ok, ) = payable(recipient).call{value: amount}("");
            if (!ok) revert NativeSendFailed();
        } else {
            IERC20(asset).safeTransfer(recipient, amount);
        }
    }

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
