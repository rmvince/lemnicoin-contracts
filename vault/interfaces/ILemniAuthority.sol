// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ILemniAuthority
/// @notice Minimal view-only interface onto the EXISTING, UNMODIFIED LEMNI Diamond
///         (EIP-2535) deployed on Polygon at 0x02011c7B7D9C6dfc563c92197557e8BE490a85b4.
/// @dev    The vault reuses two primitives the Diamond already exposes as public views:
///           - getAttestorPublicKey(): the EC2 attestor's Falcon-512 public key (NTT domain)
///           - FALCON_VERIFIER():      the deployed ZKNOX on-chain Falcon verifier
///         Reading these live (rather than caching them in the vault) means an attestor-key
///         rotation on the Diamond propagates to every vault automatically, with no per-vault
///         migration. Nothing here mutates LEMNI state — this satisfies the "do not alter
///         LEMNI" requirement (§4, §12).
interface ILemniAuthority {
    /// @notice Attestor's Falcon public key in the NTT domain (32 words).
    function getAttestorPublicKey() external view returns (uint256[32] memory);

    /// @notice Address of the deployed ZKNOX ETHFALCON verifier contract.
    function FALCON_VERIFIER() external view returns (address);

    /// @notice keccak256(abi.encodePacked(uint256[32] ntth)) of `account`'s OWN Falcon key, or zero
    ///         if they have not registered one.
    /// @dev Lets a vault accept a withdrawal the holder signed themselves when the attestor is
    ///      unreachable. Reading it from the authority (rather than storing it per-vault) means one
    ///      registration covers every vault the holder owns, and a holder who registers after their
    ///      vault was deployed is still covered.
    function holderFalconCommitment(address account) external view returns (bytes32);

    /// @notice `account`'s Multi-Sig ring: the member Falcon key commitments and threshold M.
    /// @dev THE ONE RING. This is the SAME registry the LEMNI token reads (RingFacet on the Polygon
    ///      Diamond) and the same member keys the Bitcoin ring uses — so a holder registers their
    ///      ring ONCE and every layer honours it. A vault reads it live, exactly as it reads
    ///      `holderFalconCommitment`, which means:
    ///        - one registration covers every vault the holder owns, on this chain;
    ///        - a holder who registers a ring AFTER funding a vault is covered immediately, with no
    ///          migration and no new vault address;
    ///        - the ring cannot drift out of sync between the token and the lockbox, because there
    ///          is only one copy of it.
    /// @return memberCommitments keccak256(abi.encodePacked(uint256[32] ntth)) per member (empty if none)
    /// @return threshold M — member signatures required (0 if no ring)
    /// @return registered whether a ring exists for `account`
    function getRing(address account)
        external
        view
        returns (bytes32[] memory memberCommitments, uint8 threshold, bool registered);
}
