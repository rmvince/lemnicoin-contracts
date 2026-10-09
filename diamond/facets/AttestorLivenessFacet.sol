// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";

/// @title AttestorLivenessFacet — heartbeat + configuration for the holder-only time-lock gate
/// @notice Turns the single-signature holder-only transfer path into a genuine 2-of-2 fallback.
///
///         The attestor service posts a periodic `attestorHeartbeat()` from a dedicated EOA
///         (`attestorHeartbeatSigner`). While those heartbeats keep arriving, the holder-only path
///         (`quantumTransferWithHolderKey`) is time-locked shut, so every transfer must be dual
///         (attestor + holder). If the attestor goes silent for `holderOnlyOutageBlocks` (N) blocks —
///         a genuine outage — the holder-only path opens so a holder can still move their funds with
///         their own Falcon key alone.
///
///         Setting N to 0 disables the gate (holder-only always allowed) — the pre-upgrade behavior,
///         so adding this facet is non-breaking until the owner configures it.
contract AttestorLivenessFacet is Modifiers {
    /// @notice A minimum window so a too-short value cannot quietly weaken the 2-of-2 (a 1-block
    ///         window would let a single missed heartbeat open the solo path). ~30 min on Polygon.
    uint256 public constant MIN_OUTAGE_BLOCKS = 900;
    /// @notice A maximum window so the escape hatch cannot be accidentally locked shut forever if
    ///         the attestor truly dies. ~30 days on Polygon.
    uint256 public constant MAX_OUTAGE_BLOCKS = 1_296_000;

    event AttestorHeartbeat(address indexed signer, uint256 blockNumber);
    event AttestorHeartbeatSignerSet(address indexed signer);
    event HolderOnlyOutageBlocksSet(uint256 outageBlocks);

    error HeartbeatSignerNotSet();
    error NotAttestorHeartbeatSigner();
    error OutageWindowOutOfRange(uint256 provided, uint256 min, uint256 max);

    // ---------------------------------------------------------------------
    // Attestor-operated
    // ---------------------------------------------------------------------

    /// @notice Record that the attestor is alive as of this block. Cheap; call it on a schedule
    ///         (e.g. every few minutes) well inside the outage window.
    /// @dev Only the configured heartbeat EOA may call this. It never touches the attestor's Falcon
    ///      signing key — liveness and signing authority are deliberately separate addresses.
    function attestorHeartbeat() external {
        if (s.attestorHeartbeatSigner == address(0)) revert HeartbeatSignerNotSet();
        if (msg.sender != s.attestorHeartbeatSigner) revert NotAttestorHeartbeatSigner();
        s.attestorLastHeartbeatBlock = block.number;
        emit AttestorHeartbeat(msg.sender, block.number);
    }

    // ---------------------------------------------------------------------
    // Owner-operated configuration
    // ---------------------------------------------------------------------

    /// @notice Set the EOA allowed to post heartbeats. Setting address(0) disables heartbeating
    ///         (which, if the gate is enabled, means the holder-only path stays open once stale).
    function setAttestorHeartbeatSigner(address signer) external onlyOwner {
        s.attestorHeartbeatSigner = signer;
        emit AttestorHeartbeatSignerSet(signer);
    }

    /// @notice Set N, the number of blocks of attestor silence after which the holder-only path
    ///         opens. 0 disables the gate. Otherwise must be within [MIN, MAX].
    /// @dev Enabling the gate (N > 0) stamps a fresh heartbeat so the path closes immediately for the
    ///      full window — there is no gap between enabling and the first attestor heartbeat during
    ///      which the solo path would be open. Configure `attestorHeartbeatSigner` and start the
    ///      heartbeat cron BEFORE (or right after) enabling.
    function setHolderOnlyOutageBlocks(uint256 outageBlocks) external onlyOwner {
        if (outageBlocks != 0 && (outageBlocks < MIN_OUTAGE_BLOCKS || outageBlocks > MAX_OUTAGE_BLOCKS)) {
            revert OutageWindowOutOfRange(outageBlocks, MIN_OUTAGE_BLOCKS, MAX_OUTAGE_BLOCKS);
        }
        s.holderOnlyOutageBlocks = outageBlocks;
        if (outageBlocks != 0) {
            s.attestorLastHeartbeatBlock = block.number;
        }
        emit HolderOnlyOutageBlocksSet(outageBlocks);
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    /// @notice Current state of the liveness gate.
    /// @return signer              the heartbeat EOA (0 if unset)
    /// @return lastHeartbeatBlock  block of the most recent heartbeat
    /// @return outageBlocks        N (0 = gate disabled)
    /// @return holderOnlyOpen      whether the holder-only path is open right now
    /// @return opensAtBlock        first block the holder-only path opens (0 if gate disabled or
    ///                             already open)
    function attestorLiveness()
        external
        view
        returns (
            address signer,
            uint256 lastHeartbeatBlock,
            uint256 outageBlocks,
            bool holderOnlyOpen,
            uint256 opensAtBlock
        )
    {
        signer = s.attestorHeartbeatSigner;
        lastHeartbeatBlock = s.attestorLastHeartbeatBlock;
        outageBlocks = s.holderOnlyOutageBlocks;
        // Mirror of LibLemnicoin.holderOnlyPathOpen — inlined so this facet needs no library link.
        if (outageBlocks == 0) {
            holderOnlyOpen = true;
        } else {
            holderOnlyOpen = block.number > lastHeartbeatBlock + outageBlocks;
            if (!holderOnlyOpen) {
                opensAtBlock = lastHeartbeatBlock + outageBlocks + 1;
            }
        }
    }
}
