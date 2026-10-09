// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {RingConfig} from "../libraries/LibAppStorage.sol";
import {HolderFalconSig} from "../libraries/LibLemnicoin.sol";
import {LibRing, RingHolderAuth} from "../libraries/LibRing.sol";

error RingBypassDelayOutOfRange(uint256 provided, uint256 min, uint256 max);
error NotRingAccountOwner();

/// @title RingFacet — Multi-Sig ring registration, bypass and views
/// @notice A ring is N holder Falcon key commitments plus a threshold M, registered ONCE per
///         account. From that point the account's balance moves only through RingTransferFacet:
///         >= M member signatures over the shared EIP-712 digest, plus the attestor's signature
///         while the attestor is provably live. The single-signature paths (dual, holder-only,
///         session, recovery) are closed by LibLemnicoin.requireNotRingAccount.
contract RingFacet is Modifiers {

    /// @notice Bounds for the owner-configurable bypass maturation delay.
    uint256 public constant MIN_RING_BYPASS_DELAY = 1 days;
    uint256 public constant MAX_RING_BYPASS_DELAY = 30 days;

    event RingBypassDelaySet(uint256 delaySeconds);

    // =========================================================================
    // REGISTRATION — msg.sender only
    // =========================================================================

    /// @notice Register the caller's ring. Strictly msg.sender: if third parties could register
    ///         rings for arbitrary accounts, an attacker could enroll a victim into a ring of
    ///         attacker keys and freeze them out of their own balance.
    /// @param memberCommitments keccak256(abi.encodePacked(uint256[32] ntth)) per member key.
    /// @param threshold M — member signatures required per operation (>= 2).
    /// @param proofs One proof-of-possession Falcon signature PER member (same order), each over
    ///        ringRegistrationDigest(msg.sender, memberCommitments, threshold).
    /// @dev Only for callers with no quantum keys yet; reverts RingHolderAuthRequired otherwise —
    ///      use registerRingWithHolderAuth.
    function registerRing(
        bytes32[] calldata memberCommitments,
        uint8 threshold,
        HolderFalconSig[] calldata proofs
    ) external whenNotPaused {
        LibRing.registerRingFor(s, msg.sender, memberCommitments, threshold, proofs);
    }

    /// @notice Register the caller's ring when the caller already holds quantum keys. On top of
    ///         every member's proof, the caller's OWN holder Falcon key must sign the same
    ///         registration digest — and, for a LAIP-V3 account on a strict chain, its SLH-DSA key
    ///         must sign mu_trustless(digest, curveHash, 0). A stolen EVM key alone cannot ring an
    ///         account. (registerRing reverts RingHolderAuthRequired for such accounts.)
    function registerRingWithHolderAuth(
        bytes32[] calldata memberCommitments,
        uint8 threshold,
        HolderFalconSig[] calldata proofs,
        RingHolderAuth calldata holderAuth
    ) external whenNotPaused {
        LibRing.registerRingWithHolderAuthFor(s, msg.sender, memberCommitments, threshold, proofs, holderAuth);
    }

    /// @notice Whether registering `account`'s ring requires registerRingWithHolderAuth.
    function ringHolderAuthRequired(address account) external view returns (bool) {
        return LibRing.holderConsentRequired(s, account);
    }

    // =========================================================================
    // ATTESTOR BYPASS — the "alive but unhelpful attestor" escape hatch
    // =========================================================================

    /// @notice Submit an M-signed declaration that this ring will proceed without the attestor.
    ///         After the maturation delay, ring operations for `account` no longer require the
    ///         attestor's co-signature (until cancelled). Any address may submit — the member
    ///         signatures are the authority — so a lost gas wallet cannot block the escape.
    function declareRingAttestorBypass(
        address account,
        HolderFalconSig[] calldata memberSigs
    ) external whenNotPaused returns (uint256 maturesAt) {
        return LibRing.declareBypassFor(s, account, memberSigs);
    }

    /// @notice Cancel the caller's pending or matured bypass, restoring the attestor requirement.
    ///         Account-only, no quorum: cancelling only ever ADDS a required signature.
    function cancelRingAttestorBypass() external {
        LibRing.cancelBypassFor(s, msg.sender);
    }

    /// @notice Owner-set bypass maturation delay. 0 resets to the 7-day default.
    function setRingBypassDelay(uint256 delaySeconds) external onlyOwner {
        if (delaySeconds != 0 && (delaySeconds < MIN_RING_BYPASS_DELAY || delaySeconds > MAX_RING_BYPASS_DELAY)) {
            revert RingBypassDelayOutOfRange(delaySeconds, MIN_RING_BYPASS_DELAY, MAX_RING_BYPASS_DELAY);
        }
        s.ringBypassDelaySeconds = delaySeconds;
        emit RingBypassDelaySet(delaySeconds);
    }

    // =========================================================================
    // VIEWS
    // =========================================================================

    /// @notice The full ring definition for `account` (empty if none).
    function getRing(address account)
        external
        view
        returns (bytes32[] memory memberCommitments, uint8 threshold, bool registered)
    {
        RingConfig storage cfg = s.ringConfig[account];
        return (cfg.memberCommitments, cfg.threshold, cfg.registered);
    }

    function isRingAccount(address account) external view returns (bool) {
        return LibRing.isRingAccount(s, account);
    }

    /// @notice Everything a client needs to build a ring operation for `account`.
    /// @return registered        whether a ring exists
    /// @return threshold         M
    /// @return memberCount       N
    /// @return attestorRequired  whether the attestor's co-signature is required RIGHT NOW
    /// @return bypassMaturesAt   maturation timestamp of a declared bypass (0 = none)
    /// @return bypassNonce       current bypass declaration nonce (what members must sign over)
    function ringStatus(address account)
        external
        view
        returns (
            bool registered,
            uint8 threshold,
            uint256 memberCount,
            bool attestorRequired,
            uint256 bypassMaturesAt,
            uint256 bypassNonce
        )
    {
        RingConfig storage cfg = s.ringConfig[account];
        registered = cfg.registered;
        threshold = cfg.threshold;
        memberCount = cfg.memberCommitments.length;
        attestorRequired = registered && !LibRing.attestorWaived(s, account);
        bypassMaturesAt = s.ringBypassMaturesAt[account];
        bypassNonce = s.ringBypassNonce[account];
    }

    /// @notice The digest each member must Falcon-sign to register this exact ring.
    function ringRegistrationDigest(
        address account,
        bytes32[] calldata memberCommitments,
        uint8 threshold
    ) external view returns (bytes32) {
        return LibRing.registrationDigest(account, memberCommitments, threshold);
    }

    /// @notice The digest each member must Falcon-sign for `account`'s NEXT bypass declaration.
    function ringBypassDigest(address account) external view returns (bytes32) {
        return LibRing.bypassDigest(s, account);
    }

    function ringBypassDelaySeconds() external view returns (uint256) {
        return LibRing.effectiveBypassDelay(s);
    }
}
