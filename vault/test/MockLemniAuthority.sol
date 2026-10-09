// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {ILemniAuthority} from "../interfaces/ILemniAuthority.sol";

/// @title MockLemniAuthority — TEST ONLY stand-in for the LEMNI Diamond's read-only surface.
/// @notice Exposes the same two views the real Diamond exposes (getAttestorPublicKey,
///         FALCON_VERIFIER) so the vault can be tested against the exact interface it uses in
///         production. Supports attestor-key rotation to exercise the live-read behavior.
contract MockLemniAuthority is ILemniAuthority {
    uint256[32] private _attestorNtth;
    address private _falconVerifier;

    constructor(address falconVerifier_, uint256[32] memory attestorNtth_) {
        _falconVerifier = falconVerifier_;
        _attestorNtth = attestorNtth_;
    }

    function getAttestorPublicKey() external view override returns (uint256[32] memory) {
        return _attestorNtth;
    }

    function FALCON_VERIFIER() external view override returns (address) {
        return _falconVerifier;
    }

    /// @notice Simulate an attestor-key rotation on the Diamond.
    function rotateAttestorKey(uint256[32] memory newNtth) external {
        _attestorNtth = newNtth;
    }

    mapping(address => bytes32) private _holderFalconCommitment;

    function holderFalconCommitment(address account) external view override returns (bytes32) {
        return _holderFalconCommitment[account];
    }

    error HolderFalconKeyImmutable();

    /// @notice Register a holder Falcon key. Mirrors the real authority, including the immutability
    ///         rule — re-registering the same key is a no-op, a different one reverts.
    function registerHolderFalconKey(uint256[32] calldata ntth) external {
        bytes32 commitment = keccak256(abi.encodePacked(ntth));
        bytes32 existing = _holderFalconCommitment[msg.sender];
        if (existing != bytes32(0)) {
            if (existing != commitment) revert HolderFalconKeyImmutable();
            return;
        }
        _holderFalconCommitment[msg.sender] = commitment;
    }

    /// @notice TEST ONLY: register on behalf of `holder`, so tests need not impersonate them.
    function setHolderFalconCommitmentFor(address holder, bytes32 commitment) external {
        _holderFalconCommitment[holder] = commitment;
    }

    // =========================================================================
    // MULTI-SIG RING — the one registry v5 vaults read
    // =========================================================================

    struct Ring {
        bytes32[] memberCommitments;
        uint8 threshold;
        bool registered;
    }

    mapping(address => Ring) private _ring;

    function getRing(address account)
        external
        view
        override
        returns (bytes32[] memory memberCommitments, uint8 threshold, bool registered)
    {
        Ring storage r = _ring[account];
        return (r.memberCommitments, r.threshold, r.registered);
    }

    /// @notice TEST ONLY: set a ring for `holder` without proof-of-possession, so tests can arrange
    ///         "has a ring" / "has no ring" directly. Production registration verifies every member.
    function setRingFor(address holder, bytes32[] calldata memberCommitments, uint8 threshold) external {
        Ring storage r = _ring[holder];
        r.memberCommitments = memberCommitments;
        r.threshold = threshold;
        r.registered = memberCommitments.length > 0;
    }
}
