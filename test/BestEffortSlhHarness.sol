// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {SlhDsaVerifier} from "../crypto/SlhDsaVerifier.sol";

error SlhDsaVerificationFailed();

/// @notice Test harness isolating the EXACT best-effort SLH gas logic from LAIPV3TransferFacet, so
///         the "out-of-gas -> disregarded, never reverts" behavior can be proven directly against the
///         real verifier without the full diamond/Falcon plumbing. Kept byte-for-byte in step with
///         LAIPV3TransferFacet._bestEffortSlh.
contract BestEffortSlhHarness {
    uint256 internal constant SLH_GAS_RESERVE = 1_500_000;
    uint256 internal constant SLH_MIN_ATTEMPT = 1_300_000; // mirrors LibSlhEconomics (V2 verifier)

    address public verifier;
    bool public killed;

    // Records the outcome of the last call for assertions (this is a state-changing fn so the
    // gas-bounded sub-call OOG can be caught — a view fn would still work, but we want to persist).
    bool public lastSlhVerified;
    bool public lastCompleted; // true if the function ran to the end without reverting

    constructor(address _verifier) { verifier = _verifier; }
    function setKilled(bool k) external { killed = k; }

    /// Mirrors _bestEffortSlh + the "transfer proceeds" tail. Returns slhVerified; the fact that it
    /// returns at all (lastCompleted=true) proves the transfer was not blocked.
    function transferBestEffort(bytes calldata slhPubKey, bytes calldata mu, bytes calldata slhSig)
        external
        returns (bool slhVerified)
    {
        lastCompleted = false;
        slhVerified = _bestEffortSlh(slhPubKey, mu, slhSig);
        // "transfer" tail — always runs unless a real forgery reverted above.
        lastSlhVerified = slhVerified;
        lastCompleted = true;
        return slhVerified;
    }

    function _bestEffortSlh(bytes calldata slhPubKey, bytes calldata mu, bytes calldata slhSig)
        internal
        view
        returns (bool)
    {
        if (verifier == address(0) || killed) return false;
        if (slhSig.length == 0 || slhPubKey.length == 0) return false;

        if (gasleft() <= SLH_GAS_RESERVE + SLH_MIN_ATTEMPT) return false; // won't fit -> disregard
        uint256 cap = gasleft() - SLH_GAS_RESERVE;

        try SlhDsaVerifier(verifier).verify{gas: cap}(slhPubKey, mu, slhSig) returns (bool ok) {
            if (!ok) revert SlhDsaVerificationFailed(); // ran but invalid -> reject (forgery)
            return true;
        } catch {
            return false; // OOG or revert -> disregarded
        }
    }
}
