// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

import {IZKNOXEthFalcon} from "../falcon/IZKNOXEthFalcon.sol";
import {ILemniAuthority} from "./interfaces/ILemniAuthority.sol";

/// @title LemniVaultV5 — the lockbox honours the holder's ONE Multi-Sig ring
///
/// @notice Same custody model as v4 — per-(holder, asset), no owner/admin/upgrade key, `msg.sender`
///         never an authority, an immutable `escapeAddress` — with one addition: if the holder has
///         registered a Multi-Sig ring, this vault requires that ring's M-of-N quorum.
///
/// @dev THE ONE RING. The vault does NOT keep its own copy of the ring. It reads
///      `authority.getRing(holder)` live, which is the SAME registry the LEMNI token reads
///      (RingFacet on the Polygon Diamond) and the same member Falcon keys the Bitcoin ring uses.
///      A holder registers their ring ONCE and it governs their LEMNI, their lockboxes on this
///      chain, and their BTC — there is exactly one ring, so the layers can never disagree.
///
///      This mirrors how v4 already reads `holderFalconCommitment` from the authority rather than
///      storing it per-vault, and inherits the same properties: one registration covers every vault
///      the holder owns, and a holder who registers a ring AFTER funding a vault is covered
///      immediately — no migration, no new vault address, no re-deposit.
///
///      TWO SHAPES, DECIDED BY THE REGISTRY (not by the vault's own state):
///        - No ring registered: behaves EXACTLY like v4 — `withdraw` (attestor + holder) and
///          `withdrawWithHolderKey` (holder alone). v5 is therefore a clean drop-in for v4.
///        - Ring registered: the single-holder paths are CLOSED and funds move only via
///          `withdrawRing` (attestor + M members) or `withdrawRingMembersOnly` (M members alone).
///
///      Because ring registration is write-once at the authority, a vault can only ever move from
///      single-holder to ring — a strict increase in the authority required — never the reverse.
///
///      DEADLINES. The single-holder paths keep v4's tight 15-minute cap. Ring paths use a longer
///      cap (`MAX_RING_ATTESTATION_TTL`) because a quorum of people in different places cannot sign
///      inside fifteen minutes. That is safe for the same reason the ring is safe: the packet is
///      worthless without M independent signatures, and the shared nonce still burns on use.
///
///      WHY THE MEMBERS-ONLY PATH IS ALWAYS OPEN. It is the vault's founding guarantee: the
///      attestor's availability is never a condition of withdrawal, so no server can freeze a
///      lockbox. For a ring that means the M-member quorum can always spend without the attestor.
///
///      ESCAPE IS UNCHANGED, AND IS SINGLE-PARTY. `escape()` still sweeps the whole balance to the
///      immutable `escapeAddress`, callable by the holder wallet or the escape wallet with no
///      signature — the seed-free recovery lane. For a ring, that lane is NOT quorum-gated, so a
///      ring vault's `escapeAddress` should itself be a Multi-Sig address on the same ring, so
///      even the break-glass lands in quorum-controlled custody. The chain cannot tell a multisig
///      address from any other, so this is a setup rule, not something the contract can enforce.
contract LemniVaultV5 is ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice One ring member's Falcon signature plus the public key it must verify against.
    struct RingMemberSig {
        bytes salt40;        // Falcon salt (40 bytes)
        uint256[] s2_32;     // Falcon s2 (32 words)
        uint256[] ntth;      // member Falcon public key (NTT domain, 32 words)
    }

    // =========================================================================
    // IMMUTABLES
    // =========================================================================

    address public immutable holder;
    address public immutable asset;
    ILemniAuthority public immutable authority;
    address public immutable escapeAddress;
    address public immutable lemniToken;
    uint256 public immutable unitTollScale;

    uint256 private constant LEMNI_UNIT = 1e18;

    /// @notice Deadline cap for the single-holder paths — unchanged from v4.
    uint256 public constant MAX_ATTESTATION_TTL = 15 minutes;

    /// @notice Deadline cap for the RING paths. A quorum spread across people and places needs days,
    ///         not minutes; the quorum itself is what makes a long-lived packet safe.
    uint256 public constant MAX_RING_ATTESTATION_TTL = 7 days;

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Monotonic withdrawal nonce, SHARED by every withdrawal path so a packet can never be
    ///         replayed against another one.
    uint256 public withdrawalNonce;

    // =========================================================================
    // EIP-712 — identical to v1..v4 and to LEMNI
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
    event Withdrawn(address indexed recipient, uint256 amount, uint256 nonce, bytes32 quantumInputHash, address gasPayer);
    event WithdrawnWithHolderKey(address indexed recipient, uint256 amount, uint256 nonce, bytes32 quantumInputHash, address gasPayer);
    event WithdrawnRing(address indexed recipient, uint256 amount, uint256 nonce, bytes32 quantumInputHash, bool attestorCoSigned, address gasPayer);
    event Escaped(address indexed escapeAddress, uint256 amount, address caller);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error ZeroAuthority();
    error ZeroRecipient();
    error ZeroEscapeAddress();
    error EscapeAddressIsHolder();
    error AttestationExpired();
    error DeadlineTooFar(uint256 deadline, uint256 maxAllowed);
    error InvalidNonce(uint256 expected, uint256 provided);
    error InvalidSaltLength(uint256 length);
    error InvalidS2Length(uint256 length);
    error InvalidNtthLength(uint256 length);
    error AttestorFalconVerificationFailed();
    error HolderFalconVerificationFailed();
    error NativeSendFailed();
    error NotNativeVault();
    error NotEscapeAuthorized();
    error NothingToEscape();
    error HolderFalconKeyNotRegistered();
    error HolderFalconKeyMismatch();
    error LemniTollNotMet(uint256 required, uint256 held);
    /// @notice The holder has a Multi-Sig ring — use withdrawRing / withdrawRingMembersOnly.
    error UseRingWithdraw();
    /// @notice The holder has no ring — use withdraw / withdrawWithHolderKey.
    error NotRingVault();
    error RingThresholdNotMet(uint256 provided, uint256 required);
    error RingUnknownSignerKey(uint256 index);
    error RingDuplicateSigner(uint256 index);
    error RingMemberSigVerificationFailed(uint256 index);

    // =========================================================================
    // CONSTRUCTOR — identical shape to v4 (the ring is NOT baked in)
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
        if (escapeAddress_ == holder_) revert EscapeAddressIsHolder();

        holder = holder_;
        asset = asset_;
        authority = ILemniAuthority(authority_);
        escapeAddress = escapeAddress_;
        lemniToken = lemniToken_;
        unitTollScale = unitTollScale_;
    }

    // =========================================================================
    // DEPOSIT
    // =========================================================================

    receive() external payable {
        if (asset != address(0)) revert NotNativeVault();
        emit NativeDeposited(msg.sender, msg.value);
    }

    // =========================================================================
    // SINGLE-HOLDER WITHDRAWALS (v4 behavior; closed once a ring is registered)
    // =========================================================================

    function withdraw(
        address recipient,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata attestorSalt40,
        uint256[] calldata attestorS2_32,
        bytes calldata holderSalt40,
        uint256[] calldata holderS2_32,
        uint256[] calldata holderNtth
    ) external nonReentrant {
        if (isRing()) revert UseRingWithdraw();
        bytes32 digest = _validateAndDigest(recipient, amount, quantumInputHash, nonce, deadline, MAX_ATTESTATION_TTL);

        _requireSignatureShape(attestorSalt40, attestorS2_32);
        _requireSignatureShape(holderSalt40, holderS2_32);
        _requireHolderKey(holderNtth);

        if (!_falconVerify(digest, attestorSalt40, attestorS2_32, _attestorNtth())) {
            revert AttestorFalconVerificationFailed();
        }
        if (!_falconVerify(digest, holderSalt40, holderS2_32, _toMemoryArray(holderNtth))) {
            revert HolderFalconVerificationFailed();
        }

        withdrawalNonce = nonce + 1;
        _payOut(recipient, amount);
        emit Withdrawn(recipient, amount, nonce, quantumInputHash, msg.sender);
    }

    function withdrawWithHolderKey(
        address recipient,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata holderSalt40,
        uint256[] calldata holderS2_32,
        uint256[] calldata holderNtth
    ) external nonReentrant {
        if (isRing()) revert UseRingWithdraw();
        bytes32 digest = _validateAndDigest(recipient, amount, quantumInputHash, nonce, deadline, MAX_ATTESTATION_TTL);

        _requireSignatureShape(holderSalt40, holderS2_32);
        _requireHolderKey(holderNtth);
        _requireLemniToll(amount);

        if (!_falconVerify(digest, holderSalt40, holderS2_32, _toMemoryArray(holderNtth))) {
            revert HolderFalconVerificationFailed();
        }

        withdrawalNonce = nonce + 1;
        _payOut(recipient, amount);
        emit WithdrawnWithHolderKey(recipient, amount, nonce, quantumInputHash, msg.sender);
    }

    // =========================================================================
    // RING WITHDRAWALS (M-of-N, from the holder's ONE registered ring)
    // =========================================================================

    /// @notice Release `amount` to `recipient` with the attestor's Falcon signature AND >= M member
    ///         Falcon signatures over the same digest. The normal ring path.
    function withdrawRing(
        address recipient,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata attestorSalt40,
        uint256[] calldata attestorS2_32,
        RingMemberSig[] calldata memberSigs
    ) external nonReentrant {
        (bytes32[] memory commitments, uint8 m, bool registered) = authority.getRing(holder);
        if (!registered) revert NotRingVault();

        bytes32 digest = _validateAndDigest(recipient, amount, quantumInputHash, nonce, deadline, MAX_RING_ATTESTATION_TTL);

        _requireSignatureShape(attestorSalt40, attestorS2_32);
        _verifyRingQuorum(digest, memberSigs, commitments, m);

        if (!_falconVerify(digest, attestorSalt40, attestorS2_32, _attestorNtth())) {
            revert AttestorFalconVerificationFailed();
        }

        withdrawalNonce = nonce + 1;
        _payOut(recipient, amount);
        emit WithdrawnRing(recipient, amount, nonce, quantumInputHash, true, msg.sender);
    }

    /// @notice The same withdrawal with >= M member signatures ALONE — the attestor-free path, always
    ///         available so no server outage can freeze a lockbox. The attestor is not here to check
    ///         the LEMNI toll, so this path enforces it on-chain.
    function withdrawRingMembersOnly(
        address recipient,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        RingMemberSig[] calldata memberSigs
    ) external nonReentrant {
        (bytes32[] memory commitments, uint8 m, bool registered) = authority.getRing(holder);
        if (!registered) revert NotRingVault();

        bytes32 digest = _validateAndDigest(recipient, amount, quantumInputHash, nonce, deadline, MAX_RING_ATTESTATION_TTL);

        _verifyRingQuorum(digest, memberSigs, commitments, m);
        _requireLemniToll(amount);

        withdrawalNonce = nonce + 1;
        _payOut(recipient, amount);
        emit WithdrawnRing(recipient, amount, nonce, quantumInputHash, false, msg.sender);
    }

    // =========================================================================
    // ESCAPE — unchanged
    // =========================================================================

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

    /// @notice Whether this vault currently requires the holder's Multi-Sig quorum — read live
    ///         from the ONE ring registry, so it flips to true the moment the holder registers.
    function isRing() public view returns (bool) {
        (, , bool registered) = authority.getRing(holder);
        return registered;
    }

    /// @notice The holder's ring as this vault sees it.
    function ring()
        external
        view
        returns (bytes32[] memory memberCommitments, uint8 threshold, bool registered)
    {
        return authority.getRing(holder);
    }

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

    function requiredLemniToll(uint256 amount) public view returns (uint256) {
        if (unitTollScale == 0 || lemniToken == address(0) || amount == 0) return 0;
        return ((amount + unitTollScale - 1) / unitTollScale) * LEMNI_UNIT;
    }

    function holderKeyRegistered() external view returns (bool) {
        return authority.holderFalconCommitment(holder) != bytes32(0);
    }

    /// @notice The latest deadline a withdrawal submitted in the next block could carry — ring vaults
    ///         get the longer window.
    function maxAcceptableDeadline() external view returns (uint256) {
        return block.timestamp + (isRing() ? MAX_RING_ATTESTATION_TTL : MAX_ATTESTATION_TTL);
    }

    // =========================================================================
    // INTERNAL
    // =========================================================================

    function _validateAndDigest(
        address recipient,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        uint256 maxTtl
    ) internal view returns (bytes32) {
        if (recipient == address(0)) revert ZeroRecipient();
        if (block.timestamp > deadline) revert AttestationExpired();
        uint256 maxAllowed = block.timestamp + maxTtl;
        if (deadline > maxAllowed) revert DeadlineTooFar(deadline, maxAllowed);
        if (nonce != withdrawalNonce) revert InvalidNonce(withdrawalNonce, nonce);
        return _attestationDigest(holder, recipient, amount, quantumInputHash, nonce, deadline);
    }

    /// @dev Require >= `m` valid, distinct member Falcon signatures over `digest`, each under a key
    ///      in `commitments` (the holder's registered ring).
    function _verifyRingQuorum(
        bytes32 digest,
        RingMemberSig[] calldata sigs,
        bytes32[] memory commitments,
        uint8 m
    ) internal view {
        uint256 n = commitments.length;
        if (sigs.length < m) revert RingThresholdNotMet(sigs.length, m);
        if (sigs.length > n) revert RingThresholdNotMet(sigs.length, m);

        bytes32[] memory seen = new bytes32[](sigs.length);
        for (uint256 i = 0; i < sigs.length; i++) {
            RingMemberSig calldata sig = sigs[i];
            if (sig.salt40.length != 40) revert InvalidSaltLength(sig.salt40.length);
            if (sig.s2_32.length != 32) revert InvalidS2Length(sig.s2_32.length);
            if (sig.ntth.length != 32) revert InvalidNtthLength(sig.ntth.length);

            bytes32 commitment = keccak256(abi.encodePacked(sig.ntth));

            bool isMember = false;
            for (uint256 j = 0; j < n; j++) {
                if (commitments[j] == commitment) { isMember = true; break; }
            }
            if (!isMember) revert RingUnknownSignerKey(i);

            for (uint256 j = 0; j < i; j++) {
                if (seen[j] == commitment) revert RingDuplicateSigner(i);
            }
            seen[i] = commitment;

            bool ok = IZKNOXEthFalcon(authority.FALCON_VERIFIER()).verify(
                abi.encodePacked(digest), sig.salt40, _memToMemory(sig.s2_32), _memToMemory(sig.ntth)
            );
            if (!ok) revert RingMemberSigVerificationFailed(i);
        }
    }

    function _requireSignatureShape(bytes calldata salt40, uint256[] calldata s2_32) internal pure {
        if (salt40.length != 40) revert InvalidSaltLength(salt40.length);
        if (s2_32.length != 32) revert InvalidS2Length(s2_32.length);
    }

    function _requireHolderKey(uint256[] calldata holderNtth) internal view {
        if (holderNtth.length != 32) revert InvalidNtthLength(holderNtth.length);
        bytes32 commitment = authority.holderFalconCommitment(holder);
        if (commitment == bytes32(0)) revert HolderFalconKeyNotRegistered();
        if (keccak256(abi.encodePacked(holderNtth)) != commitment) revert HolderFalconKeyMismatch();
    }

    function _requireLemniToll(uint256 amount) internal view {
        uint256 required = requiredLemniToll(amount);
        if (required == 0) return;
        uint256 held = IERC20(lemniToken).balanceOf(holder);
        if (held < required) revert LemniTollNotMet(required, held);
    }

    function _falconVerify(
        bytes32 digest,
        bytes calldata salt40,
        uint256[] calldata s2_32,
        uint256[] memory ntth
    ) internal view returns (bool) {
        return IZKNOXEthFalcon(authority.FALCON_VERIFIER()).verify(
            abi.encodePacked(digest), salt40, _toMemoryArray(s2_32), ntth
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

    function _memToMemory(uint256[] memory arr) internal pure returns (uint256[] memory out) {
        out = new uint256[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) {
            out[i] = arr[i];
        }
    }
}
