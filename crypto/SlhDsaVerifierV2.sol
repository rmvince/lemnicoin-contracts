// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {SlhDsaSha2_128sFast} from "./SlhDsaSha2_128sFast.sol";

/// @title SlhDsaVerifierV2 — drop-in replacement for SlhDsaVerifier built on the gas-optimized
///        FIPS 205 SLH-DSA-SHA2-128s implementation. IDENTICAL external interface and accept/reject
///        behaviour; adopted by pointing the diamond at it with `setSlhDsaVerifier(address)` — no
///        facet changes, the cut stays add-only.
///
///        Same operational contract as V1: pure hashing, no state, callable with a bounded gas
///        budget so best-effort callers can catch an out-of-gas, while an INVALID signature returns
///        false rather than reverting.
contract SlhDsaVerifierV2 {
    /// @param pk      32-byte SLH-DSA-SHA2-128s public key (PK.seed || PK.root)
    /// @param message the signed message (mu, 32 bytes in this system)
    /// @param sig     7856-byte signature
    function verify(bytes calldata pk, bytes calldata message, bytes calldata sig)
        external
        view
        returns (bool)
    {
        return SlhDsaSha2_128sFast.verify(pk, message, sig);
    }
}
