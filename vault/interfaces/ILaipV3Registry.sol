// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ILaipV3Registry — the LAIP-V3 key registry a lockbox reads.
///
/// @notice Implemented by the LEMNI Diamond (LAIPV3Facet + LAIPV3TransferFacet). LemniVaultV6 reads
///         it to decide whether the hash-family factor applies to a given wallet, and to bind a
///         presented SLH public key to the one that wallet actually committed to.
///
/// @dev WHY A SEPARATE INTERFACE FROM ILemniAuthority. The two registries are genuinely different
///      contracts holding different state, and conflating them would mean duplicating V3
///      registrations into LemniVaultAuthority — a second copy that can drift from the one the token
///      enforces against, which is exactly the failure mode the "ONE ring" design avoids elsewhere.
///      So a lockbox reads member Falcon commitments and the ring from the AUTHORITY (its own
///      custody registry) and V3 keys from the DIAMOND (the token's registry), each from its single
///      source of truth.
interface ILaipV3Registry {
    /// @notice A wallet's LAIP-V3 registration. `registered` is a write-once ratchet.
    function getLaipV3Keys(address account)
        external
        view
        returns (bytes32 curveHash, bytes32 slhdsaPkHash, bytes32 mldsaPkHash, bytes32 paramId, bool registered);

    /// @notice The chain's SLH-DSA verifier, or address(0) when none is wired. Zero means the
    ///         hash-family factor cannot be checked here, so a lockbox falls back to the Falcon
    ///         floor rather than demanding a check nothing can perform.
    function slhDsaVerifier() external view returns (address);
}
