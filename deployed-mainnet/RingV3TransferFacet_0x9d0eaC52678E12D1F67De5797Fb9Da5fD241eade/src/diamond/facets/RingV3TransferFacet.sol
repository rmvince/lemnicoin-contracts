// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {LaipV3Keys} from "../libraries/LibAppStorage.sol";
import {LibERC20} from "../libraries/LibERC20.sol";
import {LibLemnicoin} from "../libraries/LibLemnicoin.sol";
import {LibRing, RingAuth} from "../libraries/LibRing.sol";
import {LibSlhEconomics} from "../libraries/LibSlhEconomics.sol";
import {SlhDsaVerifier} from "../../crypto/SlhDsaVerifier.sol";

error RingV3NotARingAccount();
error RingV3MemberCountMismatch();
error RingV3MemberKeyMismatch(address member);
error RingV3MemberNotRegistered(address member);
error RingV3SlhKeyMismatch(address member);
error RingV3SlhVerificationFailed(address member);
error RingV3AmountZero();
error RingV3ApprovalExceedsBalance(uint256 amount, uint256 balance);
error InsufficientGasProvisioned(uint256 provided, uint256 required);

/// @title RingV3TransferFacet — Multi-Sig ring transfers where EACH MEMBER signs with their own keys
/// @notice ADD-ONLY facet putting Multi-Sig ring accounts in the same five-scenario grid as every
///         other wallet, without inventing anything special for them.
///
///         THE MODEL. A ring member is just a wallet. It has its own seed, its own holder Falcon key
///         and its own LAIP-V3 registration, exactly like any other Lemnicoin wallet. So a member
///         signs a ring operation the way they would sign their own transfer — Falcon plus the
///         SLH-DSA hash factor — and when M of N members have signed, the funds move. There is no
///         ring-level key, and nothing extra to register: each member's SLH public key hash is read
///         from THAT MEMBER'S OWN `laipV3` registration.
///
///         This is deliberately not a ring-account key. Requiring one would have re-introduced a
///         single seed that the whole M-of-N account depends on for liveness — the exact thing a
///         ring exists to avoid.
///
///         THE GAS GATE IS RETIRED. With the optimized verifier (~1.2M gas per member) even a
///         7-member ring's strict operation fits comfortably inside a 30M block, so ring
///         strictness no longer depends on `block.gaslimit` or the ring's size. What DOES still
///         scale with the threshold is the ECONOMIC rule: an M-of-N ring pays M verifications, so
///         its 1% break-even sits M times higher than a single wallet's.
contract RingV3TransferFacet is Modifiers {

    /// Protocol constant: SHA3-256(encodePoint(LOS P0)) — the lemniscate anchor folded into mu.
    bytes32 internal constant LOS_COMMITMENT =
        0x5011820df0d8c8de5cee136edec7512fdb2ae279a33e7b25a52192e7931e04bb;

    /// @notice One member's contribution of the hash-family factor, signed by their own wallet.
    struct MemberSlh {
        /// @notice The member's wallet address — whose `laipV3` registration holds the key hash.
        address member;
        /// @notice That wallet's SLH-DSA public key (checked against its registered hash).
        bytes slhPubKey;
        /// @notice SLH-DSA over mu_trustless(m, thatWallet.curveHash, nonce).
        bytes slhSig;
    }

    event RingV3Transfer(
        address indexed from, address indexed to, uint256 amount, uint256 nonce, bool slhVerified
    );
    event RingV3Approval(
        address indexed owner, address indexed spender, uint256 amount, uint256 nonce, bool slhVerified
    );

    /// @notice RETIRED — the block-gas-limit gate is gone (the optimized verifier fits M member
    ///         verifications in any real chain's blocks). Always 0, for every ring and both values
    ///         of `attestorCoSigned`. Kept so existing clients decoding this selector keep working;
    ///         0 reads correctly as "every block gas limit qualifies".
    function ringV3StrictMinBlockGas(address, bool) public pure returns (uint256) {
        return 0;
    }

    /// @notice Whether THIS ring must supply the per-member SLH factor right now. True for every
    ///         registered ring whenever the chain-wide rule is strict (verifier wired, no owner
    ///         override) — ring size no longer weakens it. `attestorCoSigned` is kept for ABI
    ///         compatibility; it no longer affects the answer.
    function ringV3SlhStrict(address account, bool) public view returns (bool) {
        if (s.slhDsaVerifier == address(0)) return false;
        if (s.laipV3RelaxSlh) return false;
        return s.ringConfig[account].threshold != 0; // not a ring -> this path never applies
    }

    /// @notice The complete rule for a ring operation of this size: strict AND requiring the M
    ///         verifications must not cost the ring more than 1% of the value it is moving. A ring
    ///         is charged M SLH verifications, not one, so the 1% test is measured against M x the
    ///         single-verification cost — the ring is judged on what IT would pay.
    ///
    ///         Consulted only inside the strict branch, so like every other use of the economic rule
    ///         it can only relax, never tighten, and can never freeze a ring.
    function ringV3SlhRequired(address account, bool attestorCoSigned, uint256 amount)
        public view returns (bool)
    {
        if (!ringV3SlhStrict(account, attestorCoSigned)) return false;
        uint256 marginalGas = s.ringConfig[account].threshold * LibSlhEconomics.SLH_MARGINAL_GAS;
        return !LibSlhEconomics.economicallyExemptForGas(s, account, amount, marginalGas);
    }

    /// @notice As `ringV3SlhRequired`, but with the basefee supplied by the caller — the form
    ///         clients should use, since most nodes run `eth_call` with a base fee of zero and a
    ///         simulation of the no-argument form would therefore always answer "required".
    function ringV3SlhRequiredAt(
        address account,
        bool attestorCoSigned,
        uint256 amount,
        uint256 basefeeWei
    ) external view returns (bool) {
        if (!ringV3SlhStrict(account, attestorCoSigned)) return false;
        uint256 marginalGas = s.ringConfig[account].threshold * LibSlhEconomics.SLH_MARGINAL_GAS;
        return !LibSlhEconomics.economicallyExemptForGasAt(s, account, amount, marginalGas, basefeeWei);
    }

    function _transferHash(address from, address to, uint256 amount) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("LEMNICOIN_TRANSFER", block.chainid, from, to, amount));
    }

    function _approveHash(address owner_, address spender, uint256 amount) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("LEMNICOIN_APPROVE", block.chainid, owner_, spender, amount));
    }

    function _muTrustless(bytes32 m, bytes32 curveHash, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(m, curveHash, bytes32(nonce), LOS_COMMITMENT));
    }

    /// @dev ENTRY GAS FLOOR, member-scaled — same rationale as LAIPV3TransferFacet's: the gas a
    ///      ring operation needs drifts slightly between a wallet's estimate and the mined block,
    ///      and wallets that substitute a bare estimate for the dApp's buffered limit turn that
    ///      drift into an out-of-gas revert at ~98% of a multi-million-gas limit. Requiring a
    ///      minimum gasleft() at entry bakes the headroom into every estimator's answer. Scaled by
    ///      the SLH-signing member count (each adds a Falcon verify ~1.85M + an SLH verify ~1.1M);
    ///      the unused gas is refunded, and under-provisioning reverts in the first ~50k gas.
    ///      SCOPED to `required` (ringV3SlhRequired for this exact operation): under the owner's
    ///      emergency relax or the economic exemption the never-block guarantees hold — no floor.
    ///      `gEntry` is gasleft() sampled at the FIRST line of the entrypoint, BEFORE the caller
    ///      computes ringV3SlhRequired (which reads the price oracle). That oracle read's cost
    ///      varies between eth_estimateGas and mining, and must not move this threshold — otherwise
    ///      a bare-estimate send lands just under it. Each SLH-signing member costs ~3.0M on-chain
    ///      (a Falcon verify ~1.8M + an SLH verify ~1.2M); the floor adds a small margin over that
    ///      (3.4M/member + 3.0M base) — enough headroom to absorb per-block drift, while keeping the
    ///      maximum supported ring (M-of-7) at ~26.8M, safely under a 30M-block chain's limit.
    function _requireGasProvisioned(uint256 gEntry, bool required, uint256 slhSigners) internal pure {
        if (!required) return;
        uint256 floor = 3_000_000 + 3_400_000 * slhSigners;
        if (gEntry < floor) revert InsufficientGasProvisioned(gEntry, floor);
    }

    /// @notice Ring transfer: the member quorum, with each signing member also supplying the
    ///         hash-family factor from their own wallet.
    function quantumTransferRingV3(
        address from,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        RingAuth calldata auth,
        MemberSlh[] calldata memberSlh
    ) external payable whenNotPaused nonReentrant returns (bool) {
        uint256 gEntry = gasleft(); // sample BEFORE the oracle-reading ringV3SlhRequired
        _requireGasProvisioned(
            gEntry, ringV3SlhRequired(from, auth.attestorSalt40.length != 0, amount), memberSlh.length
        );
        if (amount == 0) revert RingV3AmountZero();
        if (!s.ringConfig[from].registered) revert RingV3NotARingAccount();

        bytes32 m = _transferHash(from, to, amount);
        uint256 n0 = s.pqAttestationNonce[from]; // captured before the quorum layer increments it
        bool attestorCoSigned = auth.attestorSalt40.length != 0;

        LibLemnicoin.collectProtocolFee(amount);

        // FLOOR (required): >= threshold member Falcon signatures over the EIP-712 digest, plus the
        // attestor's while it is live. Reverts unless the quorum is satisfied.
        LibRing.authorizeRingTransfer(s, from, to, amount, quantumInputHash, nonce, deadline, auth);

        bool slhVerified = _verifyMemberSlh(
            auth, memberSlh, m, n0, ringV3SlhRequired(from, attestorCoSigned, amount)
        );
        // Charge the ring's own rolling budget for value that moved without the hash family, so a
        // ring cannot split a drain into sub-threshold pieces any more than a single wallet can.
        if (!slhVerified) LibSlhEconomics.noteSlhFree(s, from, amount);

        LibERC20._transfer(from, to, amount);
        emit RingV3Transfer(from, to, amount, nonce, slhVerified);
        return true;
    }

    /// @notice Ring approval — a standing right to move funds, so it carries the same factors, over
    ///         its own domain-separated message so the two are never interchangeable.
    function quantumApproveRingV3(
        address owner_,
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        RingAuth calldata auth,
        MemberSlh[] calldata memberSlh
    ) external payable whenNotPaused nonReentrant returns (bool) {
        uint256 gEntry = gasleft(); // sample BEFORE the oracle-reading ringV3SlhRequired
        _requireGasProvisioned(
            gEntry, ringV3SlhRequired(owner_, auth.attestorSalt40.length != 0, amount), memberSlh.length
        );
        if (!s.ringConfig[owner_].registered) revert RingV3NotARingAccount();
        if (amount > 0 && amount > s.balances[owner_]) {
            revert RingV3ApprovalExceedsBalance(amount, s.balances[owner_]);
        }

        bytes32 mA = _approveHash(owner_, spender, amount);
        uint256 n0 = s.pqAttestationNonce[owner_];
        bool attestorCoSigned = auth.attestorSalt40.length != 0;

        LibLemnicoin.collectProtocolFee(amount);
        LibRing.authorizeRingApproval(s, owner_, spender, amount, quantumInputHash, nonce, deadline, auth);

        bool slhVerified = _verifyMemberSlh(
            auth, memberSlh, mA, n0, ringV3SlhRequired(owner_, attestorCoSigned, amount)
        );
        if (!slhVerified) LibSlhEconomics.noteSlhFree(s, owner_, amount);

        LibERC20._approve(owner_, spender, amount);
        s.quantumApprovedSpender[owner_][spender] = (amount > 0);
        emit RingV3Approval(owner_, spender, amount, nonce, slhVerified);
        return true;
    }

    /// @dev Verify the hash-family factor from EVERY member who signed the quorum.
    ///
    ///      Each entry must line up with `auth.memberSigs[i]`, and is bound to a real wallet by
    ///      checking that the member address has registered exactly the Falcon key that signed
    ///      (`holderFalconCommitment[member] == keccak256(ntth)`). The quorum layer has already
    ///      proved that key belongs to the ring, so this chains: ring member -> Falcon key ->
    ///      wallet address -> that wallet's own V3 SLH key. Nothing extra is registered anywhere.
    ///
    ///      strict  -> every signing member must supply a valid SLH signature; anything missing,
    ///                 mismatched or invalid reverts.
    ///      relaxed -> owner override / no verifier / economic exemption: the quorum's Falcon
    ///                 signatures are the floor and this returns false without blocking the operation.
    function _verifyMemberSlh(
        RingAuth calldata auth,
        MemberSlh[] calldata memberSlh,
        bytes32 m,
        uint256 nonce,
        bool strict
    ) internal view returns (bool) {
        if (!strict) return false; // Falcon quorum floor; see ringV3SlhStrict
        address verifier = s.slhDsaVerifier;
        require(verifier != address(0), "SLH verifier unset");
        require(memberSlh.length != 0, "SLH required");
        if (memberSlh.length != auth.memberSigs.length) revert RingV3MemberCountMismatch();

        for (uint256 i = 0; i < memberSlh.length; i++) {
            address member = memberSlh[i].member;

            // This address really is the wallet behind the member key that signed the quorum.
            if (s.holderFalconCommitment[member] != keccak256(abi.encodePacked(auth.memberSigs[i].ntth))) {
                revert RingV3MemberKeyMismatch(member);
            }

            // That wallet's OWN V3 registration supplies the key hash and the curve hash.
            LaipV3Keys storage k = s.laipV3[member];
            if (!k.registered) revert RingV3MemberNotRegistered(member);
            if (keccak256(memberSlh[i].slhPubKey) != k.slhdsaPkHash) revert RingV3SlhKeyMismatch(member);

            bytes memory mu = abi.encodePacked(_muTrustless(m, k.curveHash, nonce));
            if (!SlhDsaVerifier(verifier).verify(memberSlh[i].slhPubKey, mu, memberSlh[i].slhSig)) {
                revert RingV3SlhVerificationFailed(member);
            }
        }
        return true;
    }
}
