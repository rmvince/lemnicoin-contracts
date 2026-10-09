// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";

error EmptyFeeExemptList();
error TooManyFeeExemptAccounts();

/// @title FeeExemptionFacet — Governance-controlled per-wallet protocol-fee exemption
/// @notice Lets the owner mark wallets so they pay NO native protocol fee (the 12-40 bps
///         charged as msg.value on quantum transfer/approve/recovery paths). This is the
///         blanket per-wallet counterpart to the pair-based WalletWhitelistFacet.
///
/// @dev Design notes:
///      - The exemption only ever WAIVES the fee (see LibLemnicoin.collectProtocolFee). It
///        never gates a transfer and cannot freeze funds. Defaults to false for everyone,
///        so adding this facet is non-breaking.
///      - The protocol fee is REVENUE, not a fund-safety control. Exempting a wallet only
///        forgoes fee income on that wallet's transfers; it cannot move another account's
///        funds or bypass any quantum signature. The gate is therefore `onlyOwner` (a plain
///        owner transaction), deliberately NOT the heavier Falcon-governance flow used by
///        the DEX/CEX whitelists — this keeps management simple (a single owner tx). If the
///        owner is a multisig (Safe), that multisig's own policy applies.
contract FeeExemptionFacet is Modifiers {

    event FeeExemptionUpdated(address indexed account, bool exempt);

    /// @notice Set protocol-fee exemption for a batch of wallets.
    /// @param accounts Wallet addresses to update.
    /// @param exempt True to exempt (pay no fee), false to remove the exemption.
    function setFeeExempt(address[] calldata accounts, bool exempt) external onlyOwner {
        if (accounts.length == 0) revert EmptyFeeExemptList();
        if (accounts.length > 100) revert TooManyFeeExemptAccounts();
        for (uint256 i = 0; i < accounts.length; i++) {
            s.feeExempt[accounts[i]] = exempt;
            emit FeeExemptionUpdated(accounts[i], exempt);
        }
    }

    /// @notice True if `account` is exempt from the native protocol fee.
    function isFeeExempt(address account) external view returns (bool) {
        return s.feeExempt[account];
    }
}
