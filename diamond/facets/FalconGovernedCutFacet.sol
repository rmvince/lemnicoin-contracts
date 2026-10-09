// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {IDiamondCut} from "../interfaces/IDiamondCut.sol";
import {LibDiamond} from "../libraries/LibDiamond.sol";
import {LibLemnicoin} from "../libraries/LibLemnicoin.sol";

error ZeroNewOwner();

/// @title FalconGovernedCutFacet — post-quantum dual-gated upgrade + ownership authority
///
/// @notice Adds Falcon-governed twins of the two root-of-trust operations:
///         `diamondCutWithFalcon` and `transferOwnershipWithFalcon`. Each requires BOTH
///           * the ECDSA leg: msg.sender is the diamond owner (the Gnosis Safe), AND
///           * the post-quantum leg: a Falcon-512 governance signature over the EXACT
///             action payload, verified via LibLemnicoin.requireFalconGovernance —
///             the same gate rotateAttestorKeyWithGovernance already uses in production.
///         A compromise of the Safe's ECDSA keys alone (including a future quantum
///         compromise) can no longer upgrade the diamond or move its ownership through
///         these entrypoints.
///
/// @dev ROLLOUT (phase 1 of the hardening plan — see DEPLOYMENT-FALCON-GOVERNANCE.md):
///      this facet is cut in ADDITIVELY. The legacy ECDSA-only DiamondCutFacet and
///      OwnershipFacet selectors are left untouched, so a defect here is removable with
///      one ordinary Safe-signed diamondCut (Remove these two selectors) — governance
///      cannot be bricked by this facet. Retiring the legacy selectors is a separate,
///      later decision, taken only after this path has executed real production cuts.
///
///      The governance signature binds signer + action + payload + nonce + deadline +
///      chainId + diamond address (EIP-712, domain "LemnicoinGovernance"/"1"), so a
///      signature authorizes one exact cut, once, on one chain, and expires.
contract FalconGovernedCutFacet is Modifiers {
    /// @notice Falcon-governed add/replace/remove of facets, with optional init delegatecall.
    /// @dev Payload signed is abi.encode(_diamondCut, _init, _calldata): any change to the
    ///      cut, the init target, or its calldata invalidates the signature.
    /// @param _diamondCut  Facet cuts to apply (EIP-2535 semantics, as DiamondCutFacet)
    /// @param _init        Address to delegatecall after the cut (address(0) = none)
    /// @param _calldata    Calldata for the init delegatecall
    /// @param nonce        Current governance nonce of msg.sender (replay protection)
    /// @param deadline     Unix timestamp after which the governance signature is invalid
    /// @param falconSalt40 40-byte salt of the Falcon governance signature
    /// @param falconS2     Falcon signature polynomial (32 words)
    function diamondCutWithFalcon(
        IDiamondCut.FacetCut[] calldata _diamondCut,
        address _init,
        bytes calldata _calldata,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender,
            "DIAMOND_CUT",
            abi.encode(_diamondCut, _init, _calldata),
            nonce,
            deadline,
            falconSalt40,
            falconS2
        );
        LibDiamond.diamondCut(_diamondCut, _init, _calldata);
    }

    /// @notice Falcon-governed transfer of diamond ownership (EIP-173 semantics).
    /// @dev Payload signed is abi.encode(_newOwner). Zero address is rejected: unlike the
    ///      legacy OwnershipFacet, renouncing ownership is not offered on this path.
    function transferOwnershipWithFalcon(
        address _newOwner,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2
    ) external onlyOwner {
        if (_newOwner == address(0)) revert ZeroNewOwner();
        LibLemnicoin.requireFalconGovernance(
            msg.sender,
            "TRANSFER_OWNERSHIP",
            abi.encode(_newOwner),
            nonce,
            deadline,
            falconSalt40,
            falconS2
        );
        LibDiamond.setContractOwner(_newOwner);
    }
}
