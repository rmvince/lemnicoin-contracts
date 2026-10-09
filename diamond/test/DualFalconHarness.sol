// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {LibLemnicoin, HolderFalconSig} from "../libraries/LibLemnicoin.sol";

/// @title DualFalconHarness — TEST ONLY. Direct access to LibLemnicoin's signature rules.
///
/// @notice The dual-signature rule lives in `LibLemnicoin`, but every production entrypoint that
///         uses it sits behind LAIP curve verification, a price-oracle fee and the Diamond's own
///         wiring. Exercising the rule through those means a test that fails for a dozen reasons
///         unrelated to the thing under test — and, worse, a test that could PASS because a
///         precondition reverted first rather than because the signature rule held.
///
/// @dev This harness inherits `Modifiers`, so it declares `AppStorage internal s` as its first state
///      variable and therefore agrees with every facet about slot 0. It writes the few storage
///      fields the rule reads (the verifier address, the attestor key, holder commitments) directly,
///      which is exactly what a Diamond deployment would have done, and then calls the library
///      functions with nothing else in the way.
///
///      NEVER cut this into a real Diamond: the setters below are unguarded on purpose.
contract DualFalconHarness is Modifiers {
    // =========================================================================
    // SETUP — stand-ins for DiamondInit and KeyManagementFacet
    // =========================================================================

    function setVerifier(address verifier) external {
        s.falconVerifier = verifier;
    }

    function setAttestorNtth(uint256[32] calldata ntth) external {
        s.attestorNtth = ntth;
    }

    /// @dev The production registration (KeyManagementFacet.registerHolderFalconKey) is write-once
    ///      and keyed on msg.sender. This writes the same slot for an arbitrary account so a test
    ///      can set up "registered" and "not registered" holders without a full facet.
    function setHolderCommitment(address account, bytes32 commitment) external {
        s.holderFalconCommitment[account] = commitment;
    }

    // =========================================================================
    // VIEWS
    // =========================================================================

    function holderFalconCommitment(address account) external view returns (bytes32) {
        return s.holderFalconCommitment[account];
    }

    function pqAttestationNonce(address account) external view returns (uint256) {
        return s.pqAttestationNonce[account];
    }

    function attestationDigest(
        address user,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32) {
        return LibLemnicoin.attestationDigest(user, to, amount, quantumInputHash, nonce, deadline);
    }

    function approvalDigest(
        address user,
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32) {
        return LibLemnicoin.approvalDigest(user, spender, amount, quantumInputHash, nonce, deadline);
    }

    // =========================================================================
    // THE THREE AUTHORISATION PATHS, WITH NOTHING ELSE IN THE WAY
    // =========================================================================

    /// @notice The attestor's signature alone — the path that must close once a holder registers.
    function attestorOnlyTransfer(
        address user,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32
    ) external {
        LibLemnicoin.transferWithFalconAttestationFrom(
            user, to, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32
        );
    }

    /// @notice Both signatures over the same digest.
    function dualTransfer(
        address user,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        HolderFalconSig calldata holderSig
    ) external {
        LibLemnicoin.transferWithDualFalconAttestationFrom(
            user, to, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32, holderSig
        );
    }

    /// @notice The holder's signature alone — the attestor-outage path.
    function holderOnlyTransfer(
        address user,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        uint256[] calldata holderNtth
    ) external {
        LibLemnicoin.transferWithHolderFalconAttestationFrom(
            user, to, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32, holderNtth
        );
    }

    // =========================================================================
    // APPROVAL + BURN — same rule, different digest
    // =========================================================================

    function attestorOnlyApprove(
        address user,
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32
    ) external {
        LibLemnicoin.approveWithFalconInternal(
            user, spender, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32
        );
    }

    function dualApprove(
        address user,
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        HolderFalconSig calldata holderSig
    ) external {
        LibLemnicoin.approveWithDualFalconInternal(
            user, spender, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32, holderSig
        );
    }

    function attestorOnlyBurn(
        address user,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32
    ) external {
        LibLemnicoin.verifyFalconAttestationForBurn(
            user, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32
        );
    }

    function dualBurn(
        address user,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        HolderFalconSig calldata holderSig
    ) external {
        LibLemnicoin.verifyDualFalconAttestationForBurn(
            user, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32, holderSig
        );
    }
}
