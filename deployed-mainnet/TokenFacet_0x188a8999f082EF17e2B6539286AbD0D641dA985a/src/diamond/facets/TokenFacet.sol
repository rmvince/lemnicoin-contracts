// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {LibERC20} from "../libraries/LibERC20.sol";
import {LibDiamond} from "../libraries/LibDiamond.sol";

error UseTransferWithEnvelope();
error UseQuantumApprove();
error TransferFromRestrictedRecipient();

/// @title TokenFacet — ERC-20 core for Lemnicoin Diamond
/// @notice Handles balanceOf, transfer, transferFrom, allowance, and the
///         quantum-restricted approve() override.
contract TokenFacet is Modifiers {
    // =========================================================================
    // INTERNAL HELPERS
    // =========================================================================

    /// @dev Returns true if the account has quantum keys on-chain (bound OR registered).
    ///      "Bound" = full key data stored via bindQuantumKeys (challenge-response).
    ///      "Registered" = key hashes stored via registerQuantumKeysOffChain (dApp path).
    ///      Either state means the account has opted into quantum protection.
    function _hasQuantumKeys(address account) internal view returns (bool) {
        return s.quantumKeys[account].bound || s.quantumKeyHashes[account].registered;
    }
    // =========================================================================
    // ERC-20 VIEW FUNCTIONS
    // =========================================================================

    function name() external view returns (string memory) {
        return s.name;
    }

    function symbol() external view returns (string memory) {
        return s.symbol;
    }

    function decimals() external pure returns (uint8) {
        return 18;
    }

    function totalSupply() external view returns (uint256) {
        return s.totalSupply;
    }

    function balanceOf(address account) external view returns (uint256) {
        return s.balances[account];
    }

    function allowance(address owner_, address spender) external view returns (uint256) {
        return s.allowances[owner_][spender];
    }

    /// @notice Returns true if the spender was approved via quantumApprove()
    function isQuantumApprovedSpender(address owner_, address spender) external view returns (bool) {
        return s.quantumApprovedSpender[owner_][spender];
    }

    // =========================================================================
    // ERC-20 STATE-CHANGING FUNCTIONS
    // =========================================================================

    /// @notice Standard ERC-20 transfer with quantum restrictions
    /// @dev Allowed for:
    ///   - Zero-amount transfers (ERC-20 compliant no-op, helps wallet simulations)
    ///   - Owner during deployment phase
    ///   - Senders who have NOT bound quantum keys (normal ERC-20 behavior)
    ///   - FROM whitelisted CEX addresses (withdrawals only, not deposits)
    ///   - Governance-approved sender->recipient wallet whitelist pairs
    ///   - FROM whitelisted DEX pool contracts (buy outbound only, not sell inbound)
    ///   - To addresses in caller's active per-user session
    ///   Otherwise reverts — use quantumTransfer() or transferWithFalconEnvelope()
    function transfer(address to, uint256 amount) external returns (bool) {
        // Zero-amount transfers always succeed — no tokens move, no security impact.
        // This ensures ERC-20 compliance and prevents wallets (MetaMask/Blockaid)
        // from flagging LEMNI as a scam token during simulation checks.
        if (amount == 0) {
            emit LibERC20.Transfer(msg.sender, to, 0);
            return true;
        }

        // During deployment phase, owner can transfer freely
        if (s.deploymentPhaseActive && msg.sender == LibDiamond.contractOwner()) {
            LibERC20._transfer(msg.sender, to, amount);
            return true;
        }

        // No quantum keys on-chain — allow normal ERC-20 transfer.
        // Before key registration, security is standard ECDSA (same as any ERC-20).
        // Once keys are registered or bound (one-way ratchet), this path is closed
        // and all transfers require Falcon attestation + LAIP verification.
        if (!_hasQuantumKeys(msg.sender)) {
            LibERC20._transfer(msg.sender, to, amount);
            return true;
        }

        // Allow CEX WITHDRAWALS: whitelisted CEX sends tokens to users.
        // Deposits (user -> CEX) require quantum signatures via quantumTransfer()
        // or transferFrom() to prevent stolen-key theft via CEX passthrough.
        if (s.cexBypassEnabled && s.isWhitelistedCEX[msg.sender]) {
            LibERC20._transfer(msg.sender, to, amount);
            return true;
        }

        // Allow standard transfers for governance-approved sender->recipient pairs
        if (s.walletWhitelistEnabled && s.walletWhitelistPair[msg.sender][to]) {
            LibERC20._transfer(msg.sender, to, amount);
            return true;
        }

        // Allow DEX pool OUTBOUND only: pool sends LEMNI to buyer after a swap.
        // Inbound (user -> pool) is NOT allowed here — sells go through
        // transferFrom() (which already allows whitelisted pool recipients).
        // This prevents stolen-key theft via direct transfer(pool, amount) + swap().
        if (s.isWhitelistedDEXPool[msg.sender]) {
            LibERC20._transfer(msg.sender, to, amount);
            return true;
        }

        // Allow transfers to addresses in user's active session
        if (s.userCexSession[msg.sender][to] > block.timestamp) {
            LibERC20._transfer(msg.sender, to, amount);
            return true;
        }

        revert UseTransferWithEnvelope();
    }

    /// @notice Standard ERC-20 approve — allowed for unbound wallets and governance-approved pairs.
    /// @dev Once quantum keys are bound, all approvals MUST go through quantumApprove()
    ///      which requires Falcon attestation + LAIP verification.
    function approve(address spender, uint256 amount) external returns (bool) {
        // No quantum keys on-chain — allow normal ERC-20 approve
        if (!_hasQuantumKeys(msg.sender)) {
            LibERC20._approve(msg.sender, spender, amount);
            return true;
        }

        // Allow approve for governance-approved sender->spender pairs
        if (s.walletWhitelistEnabled && s.walletWhitelistPair[msg.sender][spender]) {
            LibERC20._approve(msg.sender, spender, amount);
            return true;
        }

        revert UseQuantumApprove();
    }

    /// @notice transferFrom — unrestricted for unbound wallets, gated for bound wallets
    /// @dev When the token owner (from) has NOT bound quantum keys, this behaves like
    ///      a standard ERC-20 transferFrom with no restrictions.
    ///      When keys ARE bound, enforces two gates:
    ///      1. SPENDER must be quantum-approved or governance-approved
    ///      2. RECIPIENT must be whitelisted (DEX pool, CEX, or msg.sender)
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        // Zero-amount transferFrom always succeeds (same rationale as transfer)
        if (amount == 0) {
            emit LibERC20.Transfer(from, to, 0);
            return true;
        }

        // During deployment phase, owner can transfer freely
        if (s.deploymentPhaseActive && from == LibDiamond.contractOwner()) {
            LibERC20._spendAllowance(from, msg.sender, amount);
            LibERC20._transfer(from, to, amount);
            return true;
        }

        // No quantum keys on-chain for the token owner — allow normal ERC-20 transferFrom.
        // The allowance check in _spendAllowance is the only gate needed.
        if (!_hasQuantumKeys(from)) {
            LibERC20._spendAllowance(from, msg.sender, amount);
            LibERC20._transfer(from, to, amount);
            return true;
        }

        // === Quantum-bound path: full restrictions apply ===

        // Gate 1: Spender must be quantum-approved or governance-approved.
        bool approvedSpender = s.quantumApprovedSpender[from][msg.sender] ||
            (s.walletWhitelistEnabled && s.walletWhitelistPair[from][msg.sender]) ||
            (s.cexBypassEnabled && s.isWhitelistedCEX[msg.sender]);

        if (!approvedSpender) revert UseQuantumApprove();

        // Gate 2: Recipient must be whitelisted
        bool allowedRecipient = (to == msg.sender) ||
            (s.cexBypassEnabled && s.isWhitelistedCEX[to]) ||
            s.isWhitelistedDEXPool[to];

        if (!allowedRecipient) revert TransferFromRestrictedRecipient();

        LibERC20._spendAllowance(from, msg.sender, amount);
        LibERC20._transfer(from, to, amount);
        return true;
    }

    // burn() and burnFrom() intentionally removed.
    // All burns must go through QuantumBurnFacet.quantumBurn() which requires
    // Falcon attestation + LAIP verification, preventing stolen wallets from
    // maliciously burning tokens.
}
