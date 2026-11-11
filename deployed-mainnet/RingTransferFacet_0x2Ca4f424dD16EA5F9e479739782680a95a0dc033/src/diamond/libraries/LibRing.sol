// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AppStorage, LibAppStorage, RingConfig, LaipV3Keys} from "./LibAppStorage.sol";
import {LibSlhEconomics} from "./LibSlhEconomics.sol";
import {
    LibLemnicoin,
    HolderFalconSig,
    AttestationExpired,
    InvalidNonce,
    InvalidSaltLength,
    InvalidS2Length,
    InvalidNtthLength,
    ZeroRecipient
} from "./LibLemnicoin.sol";
import "../../falcon/IZKNOXEthFalcon.sol";

// =========================================================================
// ERRORS
// =========================================================================

error RingNotRegistered(address account);
error RingAlreadyRegistered(address account);
error RingInvalidMemberCount(uint256 count, uint256 min, uint256 max);
error RingInvalidThreshold(uint256 threshold, uint256 memberCount);
error RingZeroCommitment(uint256 index);
error RingDuplicateCommitment(uint256 index);
error RingProofCountMismatch(uint256 proofs, uint256 members);
error RingProofVerificationFailed(uint256 index);
error RingProofKeyMismatch(uint256 index);
/// @notice Fewer valid, distinct member signatures were supplied than the ring's threshold.
error RingThresholdNotMet(uint256 provided, uint256 required);
/// @notice A supplied signature's key is not a member of this ring.
error RingUnknownSignerKey(uint256 index);
/// @notice The same member key was supplied twice — each member counts once toward the threshold.
error RingDuplicateSigner(uint256 index);
error RingMemberSigVerificationFailed(uint256 index);
/// @notice The attestor is live (heartbeating) and no matured bypass exists, so its signature is
///         required alongside the member quorum — and it was not supplied or did not verify.
error RingAttestorSignatureRequired(address account);
error RingBypassNotActive(address account);
/// @notice The account already holds quantum keys (a holder Falcon key and/or LAIP-V3 keys), so its
///         OWN keys must consent to the ring — its EVM key alone may not enroll it.
error RingHolderAuthRequired(address account);

/// @notice The account holder's consent to a ring registration: a Falcon signature by the holder's
///         registered key over ringRegistrationDigest, plus — for a LAIP-V3 account on a strict
///         chain — an SLH-DSA signature over mu_trustless(digest, curveHash, 0). Ring registration
///         is write-once and the digest binds account, members, threshold, chain and contract, so
///         the SLH nonce is fixed at 0.
struct RingHolderAuth {
    HolderFalconSig falcon;
    bytes slhPubKey;
    bytes slhSig;
}

/// @notice Everything a ring transfer/approval needs beyond the transaction fields: the attestor's
///         Falcon signature (may be omitted — empty salt AND empty s2 — when the attestor is waived
///         by the liveness gate or a matured bypass) plus >= threshold member signatures.
struct RingAuth {
    bytes attestorSalt40;
    uint256[] attestorS2_32;
    HolderFalconSig[] memberSigs;
}

/// @title LibRing — M-of-N holder Falcon multisig ("Multi-Sig") for Lemnicoin accounts
/// @notice The quorum is enforced by the chain, not by attestor policy: a ring account's balance
///         moves only with >= threshold member Falcon signatures over the same EIP-712 digest every
///         other quantum path uses. The attestor's signature is additionally required exactly while
///         the attestor is provably live (the existing heartbeat gate) and no matured bypass exists,
///         so LAIP/ML-DSA verification stays in the loop in normal operation but no server outage —
///         or server refusal — can ever strand a ring's funds.
library LibRing {

    // Bounds on ring size. The verifier costs ~1.8M gas per Falcon signature, so N is capped well
    // inside the block gas limit; 2 members minimum because a 1-of-1 "ring" would be weaker than
    // the dual path it replaces.
    uint256 internal constant MIN_RING_MEMBERS = 2;
    uint256 internal constant MAX_RING_MEMBERS = 7;
    uint256 internal constant MIN_RING_THRESHOLD = 2;

    /// @notice Default maturation delay for an attestor-bypass declaration when the owner has not
    ///         configured one. Long enough for the ring (or the attestor's operators) to notice and
    ///         react to an unauthorized declaration; short enough that a censoring attestor delays
    ///         a ring by days, not forever.
    uint256 internal constant DEFAULT_RING_BYPASS_DELAY = 7 days;

    bytes32 private constant RING_REGISTRATION_TYPEHASH =
        keccak256("RingRegistration(address account,bytes32 membersHash,uint256 threshold)");
    bytes32 private constant RING_BYPASS_TYPEHASH =
        keccak256("RingAttestorBypass(address account,uint256 bypassNonce)");

    event RingRegistered(address indexed account, bytes32 membersHash, uint8 threshold, uint256 memberCount);
    event RingAttestationVerified(address indexed account, bytes32 digest, uint256 nonce, bool attestorCoSigned);
    event RingBypassDeclared(address indexed account, uint256 maturesAt, uint256 bypassNonce);
    event RingBypassCancelled(address indexed account, uint256 bypassNonce);

    // =========================================================================
    // VIEWS / PREDICATES
    // =========================================================================

    function isRingAccount(AppStorage storage s, address account) internal view returns (bool) {
        return s.ringConfig[account].registered;
    }

    /// @notice Whether the attestor's co-signature is currently waived for `account`.
    /// @dev Waived when the chain can prove the attestor is not live (the same heartbeat gate the
    ///      single-account holder-only path uses — including the gate being disabled, its
    ///      pre-upgrade semantics), or when an M-signed bypass declaration has matured.
    function attestorWaived(AppStorage storage s, address account) internal view returns (bool) {
        if (LibLemnicoin.holderOnlyPathOpen(s)) return true;
        uint256 maturesAt = s.ringBypassMaturesAt[account];
        return maturesAt != 0 && block.timestamp >= maturesAt;
    }

    function effectiveBypassDelay(AppStorage storage s) internal view returns (uint256) {
        uint256 d = s.ringBypassDelaySeconds;
        return d == 0 ? DEFAULT_RING_BYPASS_DELAY : d;
    }

    /// @notice EIP-712 digest each member signs to prove possession at registration. Bound to the
    ///         account, the exact member set and the threshold, so a proof can neither be replayed
    ///         for another account nor spliced into a different ring definition. Write-once
    ///         registration means no nonce is needed.
    function registrationDigest(
        address account,
        bytes32[] calldata memberCommitments,
        uint8 threshold
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                RING_REGISTRATION_TYPEHASH,
                account,
                keccak256(abi.encodePacked(memberCommitments)),
                uint256(threshold)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", LibLemnicoin.domainSeparatorV4(), structHash));
    }

    /// @notice EIP-712 digest members sign to declare (or that dies on cancel of) an attestor
    ///         bypass. The bypass nonce makes every declaration single-use: cancelling increments
    ///         it, so signatures gathered for an old declaration can never be replayed.
    function bypassDigest(AppStorage storage s, address account) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(RING_BYPASS_TYPEHASH, account, s.ringBypassNonce[account])
        );
        return keccak256(abi.encodePacked("\x19\x01", LibLemnicoin.domainSeparatorV4(), structHash));
    }

    // =========================================================================
    // REGISTRATION
    // =========================================================================

    /// @notice Register `account`'s ring: N member key commitments and a threshold M, with a
    ///         proof-of-possession Falcon signature from EVERY member over the registration digest.
    /// @dev Write-once, like every other quantum key: a stolen wallet key cannot re-ring an
    ///      account. Requiring all N proofs (not just M) means nobody can be enrolled without
    ///      having actually signed up — a ring containing a key nobody controls silently lowers
    ///      the real threshold the other members believe they have.
    ///
    ///      SECURITY — holder consent. An account that already holds quantum keys can only be ringed
    ///      with those keys' consent (registerRingWithHolderAuthFor). Without it, a stolen or
    ///      quantum-broken EVM key could enroll the account into a ring of attacker keys: every
    ///      single-holder path would close, and the attacker's quorum — whose SLH keys are the
    ///      MEMBERS', not the holder's — would move the balance and drain the lockboxes. This entry
    ///      point is therefore only for accounts with no quantum keys yet.
    function registerRingFor(
        AppStorage storage s,
        address account,
        bytes32[] calldata memberCommitments,
        uint8 threshold,
        HolderFalconSig[] calldata proofs
    ) internal {
        if (holderConsentRequired(s, account)) revert RingHolderAuthRequired(account);
        _registerRing(s, account, memberCommitments, threshold, proofs);
    }

    /// @notice registerRingFor for an account that holds quantum keys: its holder Falcon key (and,
    ///         for a LAIP-V3 account on a strict chain, its SLH-DSA key) must sign the registration.
    function registerRingWithHolderAuthFor(
        AppStorage storage s,
        address account,
        bytes32[] calldata memberCommitments,
        uint8 threshold,
        HolderFalconSig[] calldata proofs,
        RingHolderAuth calldata holderAuth
    ) internal {
        if (holderConsentRequired(s, account)) {
            bytes32 digest = registrationDigest(account, memberCommitments, threshold);
            LibLemnicoin.verifyHolderFalcon(s, account, digest, holderAuth.falcon);
            LaipV3Keys storage k = s.laipV3[account];
            if (k.registered && LibSlhEconomics.chainStrict(s)) {
                LibSlhEconomics.strictSlh(s, k, digest, 0, holderAuth.slhPubKey, holderAuth.slhSig);
            }
        }
        _registerRing(s, account, memberCommitments, threshold, proofs);
    }

    /// @notice True when `account` holds a holder Falcon key or LAIP-V3 keys, i.e. when its own
    ///         keys must consent to a ring registration.
    function holderConsentRequired(AppStorage storage s, address account) internal view returns (bool) {
        return s.holderFalconCommitment[account] != bytes32(0) || s.laipV3[account].registered;
    }

    function _registerRing(
        AppStorage storage s,
        address account,
        bytes32[] calldata memberCommitments,
        uint8 threshold,
        HolderFalconSig[] calldata proofs
    ) private {
        if (s.ringConfig[account].registered) revert RingAlreadyRegistered(account);

        uint256 n = memberCommitments.length;
        if (n < MIN_RING_MEMBERS || n > MAX_RING_MEMBERS) {
            revert RingInvalidMemberCount(n, MIN_RING_MEMBERS, MAX_RING_MEMBERS);
        }
        if (threshold < MIN_RING_THRESHOLD || threshold > n) {
            revert RingInvalidThreshold(threshold, n);
        }
        if (proofs.length != n) revert RingProofCountMismatch(proofs.length, n);

        for (uint256 i = 0; i < n; i++) {
            if (memberCommitments[i] == bytes32(0)) revert RingZeroCommitment(i);
            for (uint256 j = 0; j < i; j++) {
                if (memberCommitments[j] == memberCommitments[i]) revert RingDuplicateCommitment(i);
            }
        }

        bytes32 digest = registrationDigest(account, memberCommitments, threshold);

        for (uint256 i = 0; i < n; i++) {
            HolderFalconSig calldata p = proofs[i];
            _checkSigShape(p);
            if (keccak256(abi.encodePacked(p.ntth)) != memberCommitments[i]) {
                revert RingProofKeyMismatch(i);
            }
            bool ok = IZKNOXEthFalcon(s.falconVerifier).verify(
                abi.encodePacked(digest),
                p.salt40,
                LibLemnicoin._toMemoryArray(p.s2_32),
                LibLemnicoin._toMemoryArray(p.ntth)
            );
            if (!ok) revert RingProofVerificationFailed(i);
        }

        RingConfig storage cfg = s.ringConfig[account];
        cfg.memberCommitments = memberCommitments;
        cfg.threshold = threshold;
        cfg.registered = true;

        emit RingRegistered(account, keccak256(abi.encodePacked(memberCommitments)), threshold, n);
    }

    // =========================================================================
    // QUORUM VERIFICATION
    // =========================================================================

    /// @notice Revert unless `sigs` carries >= threshold valid Falcon signatures over `digest`,
    ///         each under a DISTINCT registered member key of `account`'s ring.
    /// @dev Strict: every supplied signature must be valid, from a member, and unique. Rejecting a
    ///      packet containing any invalid signature (rather than skipping it) gives the submitter
    ///      an exact error instead of a misleading threshold failure, and bounds gas by the ring
    ///      size rather than the calldata.
    function verifyRingQuorum(
        AppStorage storage s,
        address account,
        bytes32 digest,
        HolderFalconSig[] calldata sigs
    ) internal view {
        RingConfig storage cfg = s.ringConfig[account];
        if (!cfg.registered) revert RingNotRegistered(account);

        uint256 n = cfg.memberCommitments.length;
        if (sigs.length < cfg.threshold) revert RingThresholdNotMet(sigs.length, cfg.threshold);
        if (sigs.length > n) revert RingThresholdNotMet(sigs.length, cfg.threshold); // more sigs than members ⇒ duplicates guaranteed

        bytes32[] memory seen = new bytes32[](sigs.length);

        for (uint256 i = 0; i < sigs.length; i++) {
            HolderFalconSig calldata sig = sigs[i];
            _checkSigShape(sig);

            bytes32 commitment = keccak256(abi.encodePacked(sig.ntth));

            bool isMember = false;
            for (uint256 j = 0; j < n; j++) {
                if (cfg.memberCommitments[j] == commitment) { isMember = true; break; }
            }
            if (!isMember) revert RingUnknownSignerKey(i);

            for (uint256 j = 0; j < i; j++) {
                if (seen[j] == commitment) revert RingDuplicateSigner(i);
            }
            seen[i] = commitment;

            bool ok = IZKNOXEthFalcon(s.falconVerifier).verify(
                abi.encodePacked(digest),
                sig.salt40,
                LibLemnicoin._toMemoryArray(sig.s2_32),
                LibLemnicoin._toMemoryArray(sig.ntth)
            );
            if (!ok) revert RingMemberSigVerificationFailed(i);
        }
    }

    // =========================================================================
    // AUTHORISATION — the shared tail of every ring entrypoint
    // =========================================================================

    /// @notice Window + nonce + member quorum + (attestor signature unless waived), then burn the
    ///         nonce. The exact ring analogue of LibLemnicoin.requireDualFalcon.
    function requireRingAuth(
        AppStorage storage s,
        address account,
        bytes32 digest,
        uint256 nonce,
        uint256 deadline,
        RingAuth calldata auth
    ) internal {
        if (block.timestamp > deadline) revert AttestationExpired();
        uint256 expectedNonce = s.pqAttestationNonce[account];
        if (nonce != expectedNonce) revert InvalidNonce(expectedNonce, nonce);

        verifyRingQuorum(s, account, digest, auth.memberSigs);

        bool attestorSupplied = auth.attestorSalt40.length != 0 || auth.attestorS2_32.length != 0;
        bool attestorCoSigned;
        if (attestorSupplied) {
            // A supplied attestor signature is always verified — never silently ignored — so a
            // packet claiming attestor participation cannot execute with a garbage signature.
            LibLemnicoin.verifyAttestorFalcon(s, digest, auth.attestorSalt40, auth.attestorS2_32);
            attestorCoSigned = true;
        } else if (!attestorWaived(s, account)) {
            revert RingAttestorSignatureRequired(account);
        }

        s.pqAttestationNonce[account] = nonce + 1;

        emit RingAttestationVerified(account, digest, nonce, attestorCoSigned);
    }

    // =========================================================================
    // TRANSFER / APPROVAL AUTHORISATION
    // =========================================================================

    /// @notice Authorise a ring transfer. Signature-authorised: `from` need not be msg.sender —
    ///         the digest pins from/to/amount/nonce/deadline, so any submitter can only execute
    ///         exactly the transfer the quorum signed. This removes the account EOA as a liveness
    ///         single point (a ring whose gas wallet is lost can still move funds).
    function authorizeRingTransfer(
        AppStorage storage s,
        address from,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        RingAuth calldata auth
    ) internal {
        if (to == address(0)) revert ZeroRecipient();
        bytes32 digest = LibLemnicoin.attestationDigest(from, to, amount, quantumInputHash, nonce, deadline);
        requireRingAuth(s, from, digest, nonce, deadline, auth);
    }

    /// @notice Authorise a ring approval (PQApproval digest).
    function authorizeRingApproval(
        AppStorage storage s,
        address owner_,
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        RingAuth calldata auth
    ) internal {
        if (spender == address(0)) revert ZeroRecipient();
        bytes32 digest = LibLemnicoin.approvalDigest(owner_, spender, amount, quantumInputHash, nonce, deadline);
        requireRingAuth(s, owner_, digest, nonce, deadline, auth);
    }

    // =========================================================================
    // ATTESTOR BYPASS — the "alive but unhelpful attestor" escape
    // =========================================================================

    /// @notice Declare, with a full member quorum, that this ring intends to proceed without the
    ///         attestor. After `effectiveBypassDelay` the attestor's co-signature stops being
    ///         required for this account (until cancelled). Anyone may SUBMIT the declaration —
    ///         the member signatures are the authority — so a lost gas wallet cannot block it.
    function declareBypassFor(
        AppStorage storage s,
        address account,
        HolderFalconSig[] calldata memberSigs
    ) internal returns (uint256 maturesAt) {
        bytes32 digest = bypassDigest(s, account);
        verifyRingQuorum(s, account, digest, memberSigs);

        // Burn this declaration's digest so the same signatures cannot re-arm a bypass later.
        uint256 usedNonce = s.ringBypassNonce[account];
        s.ringBypassNonce[account] = usedNonce + 1;

        maturesAt = block.timestamp + effectiveBypassDelay(s);
        s.ringBypassMaturesAt[account] = maturesAt;
        emit RingBypassDeclared(account, maturesAt, usedNonce);
    }

    /// @notice Cancel a pending or matured bypass, restoring the attestor requirement.
    /// @dev Deliberately callable with no member quorum by the facet (which restricts it to the
    ///      account itself): cancelling is strictly safety-increasing — it re-adds a required
    ///      signature — so the cheapest key may do it.
    function cancelBypassFor(AppStorage storage s, address account) internal {
        if (s.ringBypassMaturesAt[account] == 0) revert RingBypassNotActive(account);
        s.ringBypassMaturesAt[account] = 0;
        // Also kill any signatures gathered against the current declaration digest.
        s.ringBypassNonce[account] += 1;
        emit RingBypassCancelled(account, s.ringBypassNonce[account]);
    }

    // =========================================================================
    // INTERNAL
    // =========================================================================

    function _checkSigShape(HolderFalconSig calldata sig) private pure {
        if (sig.salt40.length != 40) revert InvalidSaltLength(sig.salt40.length);
        if (sig.s2_32.length != 32) revert InvalidS2Length(sig.s2_32.length);
        if (sig.ntth.length != 32) revert InvalidNtthLength(sig.ntth.length);
    }
}
