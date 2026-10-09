// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";

error EmptyWalletList();
error TooManyWallets();
error WalletWhitelistFuseActive();

/// @title WalletWhitelistFacet — Governance-controlled sender->recipient bypass
/// @notice Allows specific sender->recipient pairs to use transfer()/approve()
///         without quantum signatures. Controlled via 3-step governance
///         (propose/guardian-approve/execute). Guardian can permanently disable
///         via one-way fuse.
contract WalletWhitelistFacet is Modifiers {

    event WalletWhitelistPairSet(address indexed sender, address indexed recipient, bool allowed);
    event WalletWhitelistToggleProposed(bool enabled);
    event WalletWhitelistToggled(bool enabled, uint256 timestamp);
    event WalletWhitelistGuardianApproved(bool enabled);
    event WalletWhitelistFuseActivated();

    // =========================================================================
    // PAIR MANAGEMENT
    // =========================================================================

    /// @notice Set allowed sender->recipient pairs for the wallet whitelist
    /// @dev Only owner (governance) can manage pairs. Pairs have no effect
    ///      unless walletWhitelistEnabled is true.
    /// @param sender The wallet address that will be allowed to send
    /// @param recipients Array of recipient addresses the sender can transfer to
    /// @param allowed True to whitelist, false to remove
    function setWalletWhitelistPairs(
        address sender,
        address[] calldata recipients,
        bool allowed
    ) external onlyOwner {
        if (recipients.length == 0) revert EmptyWalletList();
        if (recipients.length > 100) revert TooManyWallets();
        for (uint256 i = 0; i < recipients.length; i++) {
            s.walletWhitelistPair[sender][recipients[i]] = allowed;
            emit WalletWhitelistPairSet(sender, recipients[i], allowed);
        }
    }

    // =========================================================================
    // 3-STEP TOGGLE GOVERNANCE
    // =========================================================================

    /// @notice Step 1: Propose enabling or disabling the wallet whitelist bypass
    /// @param enabled True to enable, false to disable
    function proposeWalletWhitelistToggle(bool enabled) external onlyOwner {
        if (s.walletWhitelistFuseActivated && enabled) revert WalletWhitelistFuseActive();
        s.pendingWalletWhitelistState = enabled;
        s.pendingWalletWhitelistActive = true;
        s.walletWhitelistGuardianApproval = false;
        emit WalletWhitelistToggleProposed(enabled);
    }

    /// @notice Step 2: Guardian approves the pending toggle
    /// @param enabled Must match the pending proposed state
    function approveWalletWhitelistToggle(bool enabled) external onlyGuardian {
        require(s.pendingWalletWhitelistActive, "No pending proposal");
        require(s.pendingWalletWhitelistState == enabled, "State mismatch");
        s.walletWhitelistGuardianApproval = true;
        emit WalletWhitelistGuardianApproved(enabled);
    }

    /// @notice Step 3: Execute the toggle after guardian approval
    function executeWalletWhitelistToggle() external onlyOwner {
        require(s.pendingWalletWhitelistActive, "No pending proposal");
        require(s.walletWhitelistGuardianApproval, "Guardian approval missing");
        if (s.walletWhitelistFuseActivated && s.pendingWalletWhitelistState) {
            revert WalletWhitelistFuseActive();
        }
        s.walletWhitelistEnabled = s.pendingWalletWhitelistState;
        s.pendingWalletWhitelistActive = false;
        s.walletWhitelistGuardianApproval = false;
        emit WalletWhitelistToggled(s.walletWhitelistEnabled, block.timestamp);
    }

    // =========================================================================
    // GUARDIAN FUSE (permanent disable)
    // =========================================================================

    /// @notice Permanently disable the wallet whitelist bypass (one-way fuse)
    function activateWalletWhitelistFuse() external onlyGuardian {
        if (s.walletWhitelistFuseActivated) return;
        s.walletWhitelistFuseActivated = true;
        s.walletWhitelistEnabled = false;
        s.pendingWalletWhitelistActive = false;
        s.walletWhitelistGuardianApproval = false;
        emit WalletWhitelistFuseActivated();
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function walletWhitelistPair(address sender, address recipient) external view returns (bool) {
        return s.walletWhitelistPair[sender][recipient];
    }

    function walletWhitelistEnabled() external view returns (bool) {
        return s.walletWhitelistEnabled;
    }

    function walletWhitelistFuseActivated() external view returns (bool) {
        return s.walletWhitelistFuseActivated;
    }

    function pendingWalletWhitelistActive() external view returns (bool) {
        return s.pendingWalletWhitelistActive;
    }

    function walletWhitelistGuardianApproval() external view returns (bool) {
        return s.walletWhitelistGuardianApproval;
    }
}
