// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {SlhDsaSha2_128s} from "./SlhDsaSha2_128s.sol";

/// @title SlhDsaVerifier — external wrapper around the FIPS 205 SLH-DSA-SHA2-128s verifier.
/// @notice Deployed as its OWN contract so callers can invoke it with a bounded gas budget via
///         `try verifier.verify{gas: cap}(...)`. That is what makes the on-chain Lemniscate (LOS/
///         SLH-DSA) check BEST-EFFORT: if the ~24.6M-gas verification cannot fit in the caller's gas
///         budget, the external call runs out of gas and the caller CATCHES it, proceeding on the
///         Falcon signature(s) alone — the transfer is never blocked by Lemniscate gas. A present but
///         INVALID signature still returns false (the caller decides to reject), which is distinct
///         from an out-of-gas.
///
///         Pure hashing (SHA-256 precompile), no secret input, no state — safe to call statically.
contract SlhDsaVerifier {
    /// @param pk      32-byte SLH-DSA-SHA2-128s public key
    /// @param message the signed message (mu, 32 bytes)
    /// @param sig     7856-byte signature
    /// @return true iff the signature is valid; false for a well-formed-but-invalid signature or a
    ///         wrong-length input. Runs out of gas (revert) if given less than it needs — callers use
    ///         try/catch to treat that as "disregarded".
    function verify(bytes calldata pk, bytes calldata message, bytes calldata sig)
        external
        view
        returns (bool)
    {
        return SlhDsaSha2_128s.verify(pk, message, sig);
    }
}
