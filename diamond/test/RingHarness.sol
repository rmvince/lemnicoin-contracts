// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {LibLemnicoin, HolderFalconSig} from "../libraries/LibLemnicoin.sol";
import {LibRing, RingAuth, RingHolderAuth} from "../libraries/LibRing.sol";
import {RingConfig, LaipV3Keys} from "../libraries/LibAppStorage.sol";

/// @title RingHarness — TEST ONLY. Direct access to LibRing's rules.
///
/// @notice Same rationale as DualFalconHarness: the ring rules live in LibRing, but the production
///         entrypoints sit behind LAIP verification, the price-oracle fee and Diamond wiring. This
///         harness exercises the rules with nothing else in the way, and exposes the storage knobs
///         (verifier, attestor key, liveness gate) a Diamond deployment would have configured.
///
///         NEVER cut this into a real Diamond: the setters below are unguarded on purpose.
contract RingHarness is Modifiers {
    // =========================================================================
    // SETUP — stand-ins for DiamondInit / KeyManagementFacet / AttestorLivenessFacet
    // =========================================================================

    function setVerifier(address verifier) external {
        s.falconVerifier = verifier;
    }

    function setAttestorNtth(uint256[32] calldata ntth) external {
        s.attestorNtth = ntth;
    }

    function setHolderCommitment(address account, bytes32 commitment) external {
        s.holderFalconCommitment[account] = commitment;
    }

    /// @dev Liveness gate controls, in place of AttestorLivenessFacet + heartbeat cron.
    function setLivenessGate(uint256 outageBlocks, uint256 lastHeartbeatBlock) external {
        s.holderOnlyOutageBlocks = outageBlocks;
        s.attestorLastHeartbeatBlock = lastHeartbeatBlock;
    }

    function heartbeat() external {
        s.attestorLastHeartbeatBlock = block.number;
    }

    function setRingBypassDelay(uint256 delaySeconds) external {
        s.ringBypassDelaySeconds = delaySeconds;
    }

    /// @dev LAIP-V3 stand-ins (LAIPV3Facet registration + LAIPV3TransferFacet admin).
    function setLaipV3(address account, bytes32 curveHash, bytes32 slhdsaPkHash) external {
        s.laipV3[account] = LaipV3Keys({
            curveHash: curveHash, slhdsaPkHash: slhdsaPkHash, mldsaPkHash: bytes32(uint256(1)),
            paramId: bytes32(uint256(1)), registered: true
        });
    }

    function setSlhDsaVerifier(address verifier) external {
        s.slhDsaVerifier = verifier;
    }

    function setLaipV3RelaxSlh(bool relaxed) external {
        s.laipV3RelaxSlh = relaxed;
    }

    // =========================================================================
    // PRODUCTION LOGIC UNDER TEST
    // =========================================================================

    /// @notice The real registration path, with an arbitrary account (facet restricts to msg.sender).
    function registerRing(
        address account,
        bytes32[] calldata memberCommitments,
        uint8 threshold,
        HolderFalconSig[] calldata proofs
    ) external {
        LibRing.registerRingFor(s, account, memberCommitments, threshold, proofs);
    }

    /// @notice The holder-consent registration path, with an arbitrary account.
    function registerRingWithHolderAuth(
        address account,
        bytes32[] calldata memberCommitments,
        uint8 threshold,
        HolderFalconSig[] calldata proofs,
        RingHolderAuth calldata holderAuth
    ) external {
        LibRing.registerRingWithHolderAuthFor(s, account, memberCommitments, threshold, proofs, holderAuth);
    }

    function ringHolderAuthRequired(address account) external view returns (bool) {
        return LibRing.holderConsentRequired(s, account);
    }

    function ringTransfer(
        address from,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        RingAuth calldata auth
    ) external {
        LibRing.authorizeRingTransfer(s, from, to, amount, quantumInputHash, nonce, deadline, auth);
    }

    function ringApprove(
        address owner_,
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        RingAuth calldata auth
    ) external {
        LibRing.authorizeRingApproval(s, owner_, spender, amount, quantumInputHash, nonce, deadline, auth);
    }

    function declareBypass(address account, HolderFalconSig[] calldata memberSigs)
        external
        returns (uint256)
    {
        return LibRing.declareBypassFor(s, account, memberSigs);
    }

    function cancelBypass(address account) external {
        LibRing.cancelBypassFor(s, account);
    }

    /// @notice The dual path, to prove it is CLOSED for ring accounts and open for others.
    function dualTransfer(
        address user,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        HolderFalconSig calldata holderSig
    ) external {
        LibLemnicoin.transferWithDualFalconAttestationFrom(
            user, to, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32, holderSig
        );
    }

    /// @notice The holder-only path, to prove it too is CLOSED for ring accounts.
    function holderOnlyTransfer(
        address user,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        uint256[] calldata holderNtth
    ) external {
        LibLemnicoin.transferWithHolderFalconAttestationFrom(
            user, to, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32, holderNtth
        );
    }

    // =========================================================================
    // VIEWS
    // =========================================================================

    function attestationDigest(
        address user,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32) {
        return LibLemnicoin.attestationDigest(user, to, amount, quantumInputHash, nonce, deadline);
    }

    function approvalDigest(
        address user,
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32) {
        return LibLemnicoin.approvalDigest(user, spender, amount, quantumInputHash, nonce, deadline);
    }

    function registrationDigest(
        address account,
        bytes32[] calldata memberCommitments,
        uint8 threshold
    ) external view returns (bytes32) {
        return LibRing.registrationDigest(account, memberCommitments, threshold);
    }

    function bypassDigest(address account) external view returns (bytes32) {
        return LibRing.bypassDigest(s, account);
    }

    function pqAttestationNonce(address account) external view returns (uint256) {
        return s.pqAttestationNonce[account];
    }

    function getRing(address account)
        external
        view
        returns (bytes32[] memory memberCommitments, uint8 threshold, bool registered)
    {
        RingConfig storage cfg = s.ringConfig[account];
        return (cfg.memberCommitments, cfg.threshold, cfg.registered);
    }

    function attestorWaived(address account) external view returns (bool) {
        return LibRing.attestorWaived(s, account);
    }

    function bypassMaturesAt(address account) external view returns (uint256) {
        return s.ringBypassMaturesAt[account];
    }

    function bypassNonce(address account) external view returns (uint256) {
        return s.ringBypassNonce[account];
    }
}
