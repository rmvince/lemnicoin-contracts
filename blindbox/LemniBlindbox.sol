// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

import {IZKNOXEthFalcon} from "../falcon/IZKNOXEthFalcon.sol";
import {ILemniAuthority} from "../vault/interfaces/ILemniAuthority.sol";
import {SlhDsaVerifier} from "../crypto/SlhDsaVerifier.sol";

/// @title LemniBlindbox — full-reserve shared privacy pool for one asset (Chaumian blind vouchers)
///
/// @notice One pool per (chain, asset). Value enters visibly (`deposit`), circulates as
///         blind-issued bearer VOUCHERS the chain and the issuer cannot link to any deposit, and
///         exits (`redeem`) to any address under dual authority: the issuer's per-epoch stamp over
///         the voucher message, plus the holder's ONE-TIME possession signature. `refresh`
///         transfers value inside the pool with no token movement, no sender, no recipient, and no
///         amount beyond the fixed denomination shape.
///
/// @dev NO NEW CRYPTOGRAPHY ON CHAIN — deliberately. Both authorities verify through verifiers the
///      system already deploys and trusts:
///        - the epoch STAMP through the ZKNOX ETHFALCON verifier (`authority.FALCON_VERIFIER()`),
///          exactly as every lockbox withdrawal does;
///        - the POSSESSION factor through the deployed SLH-DSA (FIPS 205, hash-family) verifier —
///          the same ~1.19M-gas SlhDsaVerifierV2 the V6 lockbox uses — against a FRESH SLH-DSA
///          key derived per voucher from the holder's seed. Fresh-per-voucher is what privacy
///          requires anyway (a reused key would link vouchers); a one-time hash-based key keeps
///          the possession factor outside the lattice family, so a lattice break does not turn a
///          stolen voucher file into spendable value.
///      Total redemption cost lands in the same class as a V6 holder-key withdrawal (~3M gas) —
///      an already-accepted cost in this system. A cheaper bespoke WOTS+ verifier is a future
///      gas OPTIMIZATION gated on cryptographer sign-off, never a v1 requirement.
///
///      CUSTODY MODEL — the lockbox doctrine, unchanged:
///        - This contract holds ALL reserves. No owner, no admin over funds, no upgrade key, no
///          pause. `issuer` is an issuance-clerk role (epoch keys, issuance confirmations); it can
///          stall NEW issuance but can never reach a single wei of reserves, never block a
///          redemption of an issued voucher, and never freeze a pending deposit past RECLAIM_DELAY.
///        - `msg.sender` carries ZERO spend authority on redemption paths. Whoever pays gas, pays
///          gas — authority is the epoch stamp plus the one-time possession key(s).
///
///      WHY INFLATION IS IMPOSSIBLE (not merely bounded): issuance counters increment ONLY in
///      `confirmIssuance`, which only accepts a hash for which a real `deposit`/`refresh` created
///      a pending record. The issuer cannot mint an issuance slot out of thin air, so a stamp with
///      no on-chain value event behind it never fits under `redeemedCount < issuedCount`. Aggregate
///      solvency is structural: every countable voucher is backed by value this contract holds.
///
///      NO-FREEZE: an issued voucher redeems forever with no issuer participation (the stamp is
///      verified on-chain against the stored epoch key). A pending deposit/refresh the issuer never
///      confirms is refundable to its fallback address after RECLAIM_DELAY — custody can never
///      strand inside an unissued voucher; the refund is transparent, so privacy degrades before
///      custody ever does.
///
///      UNLINKABILITY lives OFF-chain, in the blind signature: the issuer stamps a blinded message
///      whose contents (serial, one-time key commitment, recovery commitment) it never sees; the
///      chain stores only H(blindedMsg) at deposit and the opened voucher at redemption. Nothing
///      recorded anywhere connects the two — see docs/PATENTABLE_PRIVACY_BLINDBOX_ANALYSIS.md.
///
///      MULTI-SIG: a ring holder's voucher commits C_ot = keccak256(M || otPkHash_1..N) with each
///      member holding their own one-time key; redemption needs >= M one-time signatures. The
///      quorum lives INSIDE the commitment — unlike getRing(), it is not publicly readable until
///      the voucher is spent.
///
///      ESCAPE, PER VOUCHER: the voucher message commits (blind) to a recovery address.
///      `escapeRedeem` opens that commitment and pays ONLY the committed address, whoever calls it
///      — the same safe-direction asymmetry as the lockbox's `escape()`.
contract LemniBlindbox is ReentrancyGuard {
    using SafeERC20 for IERC20;

    struct OtSig {
        uint8 keyIndex;   // index into otPkHashes
        bytes slhPubKey;  // the one-time SLH-DSA public key; keccak256 of it must equal otPkHashes[keyIndex]
        bytes sig;        // SLH-DSA signature over the redemption/refresh digest
    }

    struct Pending {
        address fallbackAddress; // who may reclaim if issuance is never confirmed
        uint32 denomIndex;
        uint64 createdAt;
        bool confirmed;          // set once by the issuer; gates reclaim and the counters
        bool exists;
    }

    // =========================================================================
    // IMMUTABLES / CONFIG
    // =========================================================================

    /// @notice The pooled asset. address(0) = the chain's native asset.
    address public immutable asset;
    ILemniAuthority public immutable authority;
    /// @notice The deployed SLH-DSA verifier (SlhDsaVerifierV2 class) the possession factor
    ///         verifies through — the SAME contract the V6 lockbox uses on this chain.
    SlhDsaVerifier public immutable slhDsaVerifier;
    /// @notice LEMNI on this chain (coverage toll at deposit), or address(0) — no on-chain toll
    ///         (non-Polygon chains enforce coverage off-chain, exactly as the lockbox line does).
    address public immutable lemniToken;
    /// @notice Asset base-units per 1 LEMNI of required coverage — same dial as LemniVaultV6.
    uint256 public immutable unitTollScale;

    uint256 private constant LEMNI_UNIT = 1e18;
    /// @notice A redemption packet lingers at most this long — matches the ring TTL posture.
    uint256 public constant MAX_REDEEM_TTL = 7 days;
    /// @notice An unconfirmed pending deposit/refresh is refundable after this long.
    uint256 public constant RECLAIM_DELAY = 24 hours;
    uint256 public constant MAX_RING_KEYS = 3; // mirrors the ring ceiling everywhere else

    /// @notice Fixed denominations, ascending, in asset base units. Amounts without ZK range
    ///         proofs are done cash-style; a payment is a bundle of vouchers.
    uint256[] public denominations;

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Issuance clerk: registers epoch keys and confirms issuances. NEVER an authority
    ///         over reserves — see the contract doc comment.
    address public issuer;

    uint64 public currentEpoch;
    mapping(uint64 => uint256[32]) private _epochNtth;
    mapping(uint64 => bool) public epochKeyRegistered;

    mapping(bytes32 => bool) public spentSerial;
    /// @notice epoch => denomIndex => count. Redemptions under an epoch/denomination can never
    ///         exceed its confirmed issuances.
    mapping(uint64 => mapping(uint32 => uint256)) public issuedCount;
    mapping(uint64 => mapping(uint32 => uint256)) public redeemedCount;

    /// @notice H(blindedMsg) => pending issuance awaiting the issuer's on-chain confirmation.
    mapping(bytes32 => Pending) public pending;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event VoucherRequested(bytes32 indexed blindedMsgHash, uint32 denomIndex, uint64 epoch, address depositor);
    event IssuanceConfirmed(bytes32 indexed blindedMsgHash, uint32 denomIndex, uint64 epoch);
    event Reclaimed(bytes32 indexed blindedMsgHash, address fallbackAddress, uint256 amount);
    /// @dev Deliberately does NOT index recipient: the serial is the only identity a redemption has.
    event Redeemed(bytes32 indexed serial, uint32 denomIndex, uint64 epoch, address recipient, address gasPayer);
    event Refreshed(bytes32 indexed oldSerial, bytes32 indexed newBlindedMsgHash, uint64 newEpoch);
    event EscapeRedeemed(bytes32 indexed serial, address recoveryAddress, address caller);
    event EpochAdvanced(uint64 indexed epoch);
    event IssuerHandedOver(address indexed oldIssuer, address indexed newIssuer);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error ZeroAuthority();
    error ZeroSlhVerifier();
    error ZeroIssuer();
    error NotIssuer();
    error NoDenominations();
    error BadDenomIndex();
    error DepositorNotRegistered();
    error ZeroFallback();
    error PendingAlreadyExists();
    error UnknownPending();
    error AlreadyConfirmed();
    error ReclaimTooEarly(uint256 readyAt);
    error NotFallbackAddress();
    error WrongNativeAmount();
    error NotNativePool();
    error NativeSendFailed();
    error ZeroRecipient();
    error RedeemExpired();
    error DeadlineTooFar(uint256 deadline, uint256 maxAllowed);
    error SerialAlreadySpent();
    error UnknownEpoch(uint64 epoch);
    error StampVerificationFailed();
    error InvalidSaltLength(uint256 length);
    error InvalidS2Length(uint256 length);
    error BadOtCommitmentShape();
    error OtThresholdNotMet(uint256 provided, uint256 required);
    error OtDuplicateKey(uint256 index);
    error OtBadKeyIndex(uint256 index);
    error OtKeyMismatch(uint256 index);
    error OtSigVerificationFailed(uint256 index);
    error EpochExhausted(uint64 epoch, uint32 denomIndex);
    error LemniTollNotMet(uint256 required, uint256 held);

    modifier onlyIssuer() {
        if (msg.sender != issuer) revert NotIssuer();
        _;
    }

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor(
        address asset_,
        address authority_,
        address slhDsaVerifier_,
        address lemniToken_,
        uint256 unitTollScale_,
        address issuer_,
        uint256[] memory denominations_,
        uint256[32] memory firstEpochNtth
    ) {
        if (authority_ == address(0)) revert ZeroAuthority();
        if (slhDsaVerifier_ == address(0)) revert ZeroSlhVerifier();
        if (issuer_ == address(0)) revert ZeroIssuer();
        if (denominations_.length == 0) revert NoDenominations();

        asset = asset_;
        authority = ILemniAuthority(authority_);
        slhDsaVerifier = SlhDsaVerifier(slhDsaVerifier_);
        lemniToken = lemniToken_;
        unitTollScale = unitTollScale_;
        issuer = issuer_;
        denominations = denominations_;

        currentEpoch = 1;
        _epochNtth[1] = firstEpochNtth;
        epochKeyRegistered[1] = true;
        emit EpochAdvanced(1);
    }

    // =========================================================================
    // VOUCHER / DIGEST CONSTRUCTION (mirrored bit-for-bit by shared/blindbox/voucher.mjs)
    // =========================================================================

    /// @notice The message the issuer's epoch key stamps — built by the holder INSIDE the blind
    ///         envelope; the issuer and the chain first see it opened at redemption.
    /// @dev Own domain tag + chainId + pool address: a stamp for one pool can never redeem from
    ///      another, same separation discipline as LEMNI_LOCKBOX_WITHDRAW.
    function voucherMessage(
        bytes32 serial,
        bytes32 cOt,
        uint32 denomIndex,
        uint64 epoch,
        bytes32 recoveryCommit
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "LEMNI_BLINDBOX_VOUCHER", block.chainid, address(this),
            serial, cOt, uint256(denomIndex), uint256(epoch), recoveryCommit));
    }

    /// @notice The one-time key commitment: threshold M over up to MAX_RING_KEYS member one-time
    ///         SLH-DSA public-key hashes (keccak256 of each key, the V6 commitment shape). A
    ///         single holder is simply M=1, N=1.
    function otCommitment(uint8 threshold, bytes32[] memory otPkHashes) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(threshold, otPkHashes));
    }

    /// @notice The (blind) escape clause: H(tag || recoveryAddress || salt). Opened only by
    ///         escapeRedeem; normal redemption reveals it opaquely.
    function recoveryCommitment(address recoveryAddress, bytes32 recoverySalt) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("LEMNI_BLINDBOX_RECOVERY", recoveryAddress, recoverySalt));
    }

    function redeemDigest(bytes32 serial, address recipient, uint256 deadline) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "LEMNI_BLINDBOX_REDEEM", block.chainid, address(this), serial, recipient, deadline));
    }

    function refreshDigest(
        bytes32 serial,
        bytes32 newBlindedMsgHash,
        address fallbackAddress,
        uint256 deadline
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "LEMNI_BLINDBOX_REFRESH", block.chainid, address(this),
            serial, newBlindedMsgHash, fallbackAddress, deadline));
    }

    // =========================================================================
    // DEPOSIT — the visible edge. Policy is enforced HERE, where everything is public anyway.
    // =========================================================================

    /// @notice Shield one denomination. `blindedMsgHash` = H(blinded voucher message); the blinded
    ///         message itself goes to the issuer off-chain, which matches it to this event.
    /// @param fallbackAddress Refund target if issuance is never confirmed (normally the depositor;
    ///        never forced to be, so a compromised-wallet holder can route the refund somewhere safe).
    function deposit(uint32 denomIndex, bytes32 blindedMsgHash, address fallbackAddress)
        external
        payable
        nonReentrant
    {
        if (denomIndex >= denominations.length) revert BadDenomIndex();
        if (fallbackAddress == address(0)) revert ZeroFallback();
        if (pending[blindedMsgHash].exists) revert PendingAlreadyExists();
        // Only quantum-registered holders (or ring accounts) may shield — the same creation gate
        // the vault factory applies, read from the same authority.
        if (authority.holderFalconCommitment(msg.sender) == bytes32(0)) {
            (, , bool ringRegistered) = authority.getRing(msg.sender);
            if (!ringRegistered) revert DepositorNotRegistered();
        }

        uint256 amount = denominations[denomIndex];
        _requireLemniToll(amount);

        if (asset == address(0)) {
            if (msg.value != amount) revert WrongNativeAmount();
        } else {
            if (msg.value != 0) revert NotNativePool();
            IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);
        }

        pending[blindedMsgHash] = Pending({
            fallbackAddress: fallbackAddress,
            denomIndex: denomIndex,
            createdAt: uint64(block.timestamp),
            confirmed: false,
            exists: true
        });
        emit VoucherRequested(blindedMsgHash, denomIndex, currentEpoch, msg.sender);
    }

    /// @notice The issuer acknowledges, ON-CHAIN, that it blind-signed these requests. This is the
    ///         ONLY place issuance counters move — see "why inflation is impossible" above.
    function confirmIssuance(bytes32[] calldata blindedMsgHashes) external onlyIssuer {
        for (uint256 i = 0; i < blindedMsgHashes.length; i++) {
            Pending storage p = pending[blindedMsgHashes[i]];
            if (!p.exists) revert UnknownPending();
            if (p.confirmed) revert AlreadyConfirmed();
            p.confirmed = true;
            issuedCount[currentEpoch][p.denomIndex] += 1;
            emit IssuanceConfirmed(blindedMsgHashes[i], p.denomIndex, currentEpoch);
        }
    }

    /// @notice Refund a deposit/refresh whose issuance was never confirmed. Custody can never
    ///         strand inside an unissued voucher; the refund is transparent by design.
    function reclaim(bytes32 blindedMsgHash) external nonReentrant {
        Pending memory p = pending[blindedMsgHash];
        if (!p.exists) revert UnknownPending();
        if (p.confirmed) revert AlreadyConfirmed();
        uint256 readyAt = uint256(p.createdAt) + RECLAIM_DELAY;
        if (block.timestamp < readyAt) revert ReclaimTooEarly(readyAt);
        if (msg.sender != p.fallbackAddress) revert NotFallbackAddress();

        delete pending[blindedMsgHash];
        uint256 amount = denominations[p.denomIndex];
        _payOut(p.fallbackAddress, amount);
        emit Reclaimed(blindedMsgHash, p.fallbackAddress, amount);
    }

    // =========================================================================
    // REDEEM — dual authority: epoch stamp + one-time possession signature(s)
    // =========================================================================

    function redeem(
        bytes32 serial,
        uint8 threshold,
        bytes32[] calldata otPkHashes,
        uint32 denomIndex,
        uint64 epoch,
        bytes32 recoveryCommit,
        bytes calldata stampSalt40,
        uint256[] calldata stampS2_32,
        address recipient,
        uint256 deadline,
        OtSig[] calldata otSigs
    ) external nonReentrant {
        if (recipient == address(0)) revert ZeroRecipient();
        _checkDeadline(deadline);
        _checkVoucher(serial, threshold, otPkHashes, denomIndex, epoch, recoveryCommit, stampSalt40, stampS2_32);
        _verifyOtQuorum(redeemDigest(serial, recipient, deadline), threshold, otPkHashes, otSigs);

        _spend(serial, denomIndex, epoch);
        _payOut(recipient, denominations[denomIndex]);
        emit Redeemed(serial, denomIndex, epoch, recipient, msg.sender);
    }

    /// @notice Move this voucher's value to a NEW blinded voucher (built by the payee, or by the
    ///         holder re-mixing) with no token movement. The in-pool private transfer.
    function refresh(
        bytes32 serial,
        uint8 threshold,
        bytes32[] calldata otPkHashes,
        uint32 denomIndex,
        uint64 epoch,
        bytes32 recoveryCommit,
        bytes calldata stampSalt40,
        uint256[] calldata stampS2_32,
        bytes32 newBlindedMsgHash,
        address fallbackAddress,
        uint256 deadline,
        OtSig[] calldata otSigs
    ) external nonReentrant {
        if (fallbackAddress == address(0)) revert ZeroFallback();
        if (pending[newBlindedMsgHash].exists) revert PendingAlreadyExists();
        _checkDeadline(deadline);
        _checkVoucher(serial, threshold, otPkHashes, denomIndex, epoch, recoveryCommit, stampSalt40, stampS2_32);
        _verifyOtQuorum(refreshDigest(serial, newBlindedMsgHash, fallbackAddress, deadline), threshold, otPkHashes, otSigs);

        _spend(serial, denomIndex, epoch);
        pending[newBlindedMsgHash] = Pending({
            fallbackAddress: fallbackAddress,
            denomIndex: denomIndex,
            createdAt: uint64(block.timestamp),
            confirmed: false,
            exists: true
        });
        emit Refreshed(serial, newBlindedMsgHash, currentEpoch);
    }

    /// @notice Break-glass, per voucher: open the recovery commitment and sweep this voucher's
    ///         value to the address that was fixed — blind — at issuance. No possession signature,
    ///         no deadline, callable by ANYONE holding the material: whoever presses the button,
    ///         the committed recovery address gets paid. The safe direction needs no quorum.
    function escapeRedeem(
        bytes32 serial,
        uint8 threshold,
        bytes32[] calldata otPkHashes,
        uint32 denomIndex,
        uint64 epoch,
        address recoveryAddress,
        bytes32 recoverySalt,
        bytes calldata stampSalt40,
        uint256[] calldata stampS2_32
    ) external nonReentrant {
        if (recoveryAddress == address(0)) revert ZeroRecipient();
        bytes32 recoveryCommit = recoveryCommitment(recoveryAddress, recoverySalt);
        _checkVoucher(serial, threshold, otPkHashes, denomIndex, epoch, recoveryCommit, stampSalt40, stampS2_32);

        _spend(serial, denomIndex, epoch);
        _payOut(recoveryAddress, denominations[denomIndex]);
        emit EscapeRedeemed(serial, recoveryAddress, msg.sender);
    }

    // =========================================================================
    // EPOCHS — the auto-rekey clock, and the anonymity-set boundary
    // =========================================================================

    /// @notice Rotate to a fresh stamping key. Old epochs' vouchers redeem forever against their
    ///         stored keys; only FUTURE issuance moves to the new key.
    function advanceEpoch(uint256[32] calldata newNtth) external onlyIssuer {
        uint64 next = currentEpoch + 1;
        _epochNtth[next] = newNtth;
        epochKeyRegistered[next] = true;
        currentEpoch = next;
        emit EpochAdvanced(next);
    }

    function handOverIssuer(address newIssuer) external onlyIssuer {
        if (newIssuer == address(0)) revert ZeroIssuer();
        emit IssuerHandedOver(issuer, newIssuer);
        issuer = newIssuer;
    }

    // =========================================================================
    // VIEWS
    // =========================================================================

    function denominationsCount() external view returns (uint256) {
        return denominations.length;
    }

    function epochKey(uint64 epoch) external view returns (uint256[32] memory) {
        return _epochNtth[epoch];
    }

    /// @notice Same coverage formula as LemniVaultV6 — the toll, not the lock. Checked at deposit
    ///         only; redemption is NEVER gated on LEMNI, price, or ratio.
    function requiredLemniToll(uint256 amount) public view returns (uint256) {
        if (unitTollScale == 0 || lemniToken == address(0) || amount == 0) return 0;
        return ((amount + unitTollScale - 1) / unitTollScale) * LEMNI_UNIT;
    }

    // =========================================================================
    // INTERNAL
    // =========================================================================

    function _checkDeadline(uint256 deadline) internal view {
        if (block.timestamp > deadline) revert RedeemExpired();
        uint256 maxAllowed = block.timestamp + MAX_REDEEM_TTL;
        if (deadline > maxAllowed) revert DeadlineTooFar(deadline, maxAllowed);
    }

    /// @dev Everything a voucher must prove BEFORE any state changes: unspent serial, well-formed
    ///      one-time commitment, a registered epoch, the epoch stamp verifying over the recomputed
    ///      message, and a free redemption slot under that epoch's confirmed issuance.
    function _checkVoucher(
        bytes32 serial,
        uint8 threshold,
        bytes32[] calldata otPkHashes,
        uint32 denomIndex,
        uint64 epoch,
        bytes32 recoveryCommit,
        bytes calldata stampSalt40,
        uint256[] calldata stampS2_32
    ) internal view {
        if (spentSerial[serial]) revert SerialAlreadySpent();
        if (denomIndex >= denominations.length) revert BadDenomIndex();
        if (threshold == 0 || otPkHashes.length == 0 || otPkHashes.length > MAX_RING_KEYS || threshold > otPkHashes.length) {
            revert BadOtCommitmentShape();
        }
        if (!epochKeyRegistered[epoch]) revert UnknownEpoch(epoch);
        if (stampSalt40.length != 40) revert InvalidSaltLength(stampSalt40.length);
        if (stampS2_32.length != 32) revert InvalidS2Length(stampS2_32.length);
        if (redeemedCount[epoch][denomIndex] >= issuedCount[epoch][denomIndex]) {
            revert EpochExhausted(epoch, denomIndex);
        }

        bytes32 cOt = otCommitment(threshold, _toMemoryB32(otPkHashes));
        bytes32 m = voucherMessage(serial, cOt, denomIndex, epoch, recoveryCommit);

        bool ok = IZKNOXEthFalcon(authority.FALCON_VERIFIER()).verify(
            abi.encodePacked(m), stampSalt40, _toMemoryArray(stampS2_32), _epochNtthMemory(epoch)
        );
        if (!ok) revert StampVerificationFailed();
    }

    /// @dev >= threshold valid one-time SLH-DSA signatures over `digest`, each under a DISTINCT
    ///      committed key. Mirrors _verifyRingQuorum's shape, through the DEPLOYED SLH verifier.
    ///      Direct call, no gas cap: starving the verifier must fail the whole redemption, or a
    ///      caller could skip the factor by under-funding gas (same rule as _verifyHolderSlh).
    function _verifyOtQuorum(
        bytes32 digest,
        uint8 threshold,
        bytes32[] calldata otPkHashes,
        OtSig[] calldata otSigs
    ) internal view {
        if (otSigs.length < threshold) revert OtThresholdNotMet(otSigs.length, threshold);
        if (otSigs.length > otPkHashes.length) revert OtThresholdNotMet(otSigs.length, threshold);

        uint256 seen; // bitmask over key indices (MAX_RING_KEYS <= 3)
        for (uint256 i = 0; i < otSigs.length; i++) {
            uint8 k = otSigs[i].keyIndex;
            if (k >= otPkHashes.length) revert OtBadKeyIndex(i);
            if (seen & (1 << k) != 0) revert OtDuplicateKey(i);
            seen |= (1 << k);
            if (keccak256(otSigs[i].slhPubKey) != otPkHashes[k]) revert OtKeyMismatch(i);
            if (!slhDsaVerifier.verify(otSigs[i].slhPubKey, abi.encodePacked(digest), otSigs[i].sig)) {
                revert OtSigVerificationFailed(i);
            }
        }
    }

    /// @dev Effects, in the lockbox order: burn first, then count, then (in the caller) pay.
    function _spend(bytes32 serial, uint32 denomIndex, uint64 epoch) internal {
        spentSerial[serial] = true;
        redeemedCount[epoch][denomIndex] += 1;
    }

    function _requireLemniToll(uint256 amount) internal view {
        uint256 required = requiredLemniToll(amount);
        if (required == 0) return;
        uint256 held = IERC20(lemniToken).balanceOf(msg.sender);
        if (held < required) revert LemniTollNotMet(required, held);
    }

    function _payOut(address recipient, uint256 amount) internal {
        if (asset == address(0)) {
            (bool ok, ) = payable(recipient).call{value: amount}("");
            if (!ok) revert NativeSendFailed();
        } else {
            IERC20(asset).safeTransfer(recipient, amount);
        }
    }

    function _epochNtthMemory(uint64 epoch) internal view returns (uint256[] memory out) {
        uint256[32] storage fixedKey = _epochNtth[epoch];
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

    function _toMemoryB32(bytes32[] calldata arr) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) {
            out[i] = arr[i];
        }
    }
}
