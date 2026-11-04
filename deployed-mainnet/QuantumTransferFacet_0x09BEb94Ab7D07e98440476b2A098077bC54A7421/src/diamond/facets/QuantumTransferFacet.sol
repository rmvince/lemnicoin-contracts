// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {AppStorage, FalconEnvelope, LibAppStorage} from "../libraries/LibAppStorage.sol";
import {LibERC20} from "../libraries/LibERC20.sol";
import {LibLemnicoin} from "../libraries/LibLemnicoin.sol";
import {InsufficientFee, InvalidFeeCollector, FeeTransferFailed, HolderFalconSig} from "../libraries/LibLemnicoin.sol";
import {LibDiamond} from "../libraries/LibDiamond.sol";
import "../../crypto/LAIPOnCurve.sol";
import "../../PriceOracle.sol";
import "../../falcon/IZKNOXEthFalcon.sol";
import {LibSlhEconomics} from "../libraries/LibSlhEconomics.sol";
// M-03 audit fix: Removed PriceOracle import - using LibLemnicoin.collectProtocolFee() instead

error TxBodyHashMismatch();
error ApprovalExceedsBalance(uint256 amount, uint256 balance);

/// @title QuantumTransferFacet — Quantum-protected transfer methods
/// @notice Handles quantumTransfer (Falcon-attested) and quantumApprove.
/// @dev Dead code removed per C-01/C-02 audit findings. Reentrancy protection added per M-04.
contract QuantumTransferFacet is Modifiers {

    event QuantumTransferWithFee(
        address indexed from, address indexed to, uint256 amount, uint256 feePaid, bytes32 txBodyHash
    );
    event FalconApproval(
        address indexed owner, address indexed spender, uint256 amount, bytes32 quantumInputHash, uint256 nonce
    );

    // =========================================================================
    // QUANTUM TRANSFER (Falcon-attested + LAIP on-chain + protocol fee)
    // =========================================================================

    /// @notice Transfer tokens with Falcon attestation and LAIP verification
    /// @dev Protected by nonReentrant to prevent reentrancy via fee refund (M-04)
    ///
    ///      ATTESTOR-ONLY and therefore PERMANENTLY CLOSED for every account — the library reverts
    ///      with `AttestorOnlyPathClosed`. Everyone uses `quantumTransferDual` (attestor + holder) or,
    ///      during an attestor outage, `quantumTransferWithHolderKey`. See requireAttestorOnlyAllowed
    ///      in LibLemnicoin for why the attestor's signature alone can never move funds.
    function quantumTransfer(
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        LAIPOnCurve.LAIPPublicKey calldata laipPk
    ) external payable whenNotPaused nonReentrant returns (bool) {
        LibSlhEconomics.requireNotV3Downgrade(s, msg.sender); // NO-DOWNGRADE: see LibSlhEconomics
        // FIRST, before anything else can revert for a different reason. The library checks this
        // too, but only after LAIP verification and the fee — so a caller (or a verification
        // script) probing whether this path is closed would get LAIPCommitmentMismatch and learn
        // nothing. Cheapest check, clearest error, and it is the one that decides.
        LibLemnicoin.requireAttestorOnlyAllowed(s, msg.sender);

        LibLemnicoin.requireLaipVerification(msg.sender, laipPk);
        LibLemnicoin.collectProtocolFee(amount);

        LibLemnicoin.transferWithFalconAttestationFrom(
            msg.sender, to, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32
        );

        LibERC20._transfer(msg.sender, to, amount);
        return true;
    }

    /// @notice Same transfer, signed by the sender's OWN Falcon key rather than the attestor's.
    /// @dev The attestor-free path, for when the attestor is unreachable. It is time-locked by the
    ///      attestor-liveness gate (see LibLemnicoin.requireHolderOnlyPathOpen): while the attestor
    ///      heartbeats this path reverts with `HolderOnlyPathTimeLocked`, so every transfer must go
    ///      through `quantumTransferDual` (a true 2-of-2); it opens only after the attestor has been
    ///      silent for `holderOnlyOutageBlocks`. When the gate is disabled (N == 0) it is always open,
    ///      the pre-upgrade behavior. Every other gate is unchanged — LAIP verification, protocol fee,
    ///      nonce, deadline, digest and the same ZKNOX verifier. Requires a Falcon key registered via
    ///      KeyManagementFacet.registerHolderFalconKey().
    /// @param holderNtth The sender's registered Falcon public key (NTT domain, 32 words).
    function quantumTransferWithHolderKey(
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        uint256[] calldata holderNtth,
        LAIPOnCurve.LAIPPublicKey calldata laipPk
    ) external payable whenNotPaused nonReentrant returns (bool) {
        LibSlhEconomics.requireNotV3Downgrade(s, msg.sender); // NO-DOWNGRADE: see LibSlhEconomics
        // Attestor-liveness gate: while the attestor is heartbeating, this single-signature path is
        // time-locked shut so every transfer must be dual (2-of-2). It opens only after the attestor
        // has been silent for `holderOnlyOutageBlocks`. No-op when the gate is disabled (N == 0).
        LibLemnicoin.requireHolderOnlyPathOpen(s);

        LibLemnicoin.requireLaipVerification(msg.sender, laipPk);
        LibLemnicoin.collectProtocolFee(amount);

        LibLemnicoin.transferWithHolderFalconAttestationFrom(
            msg.sender, to, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32, holderNtth
        );

        LibERC20._transfer(msg.sender, to, amount);
        return true;
    }

    // =========================================================================
    // DUAL SIGNATURE — the attestor's Falcon signature AND the sender's own
    // =========================================================================

    /// @notice The same transfer, requiring BOTH the attestor's Falcon signature and the sender's
    ///         own over the identical digest.
    /// @dev This is the path a registered holder uses. Losing the attestor's key stops being a
    ///      universal spending key: an attacker holding it and nothing else can move no balance at
    ///      all, because the second signature is not theirs to produce.
    ///
    ///      Every other gate is unchanged — LAIP verification, protocol fee, nonce, deadline, digest
    ///      and the same ZKNOX verifier. The cost is one extra Falcon verification (~1.8M gas).
    /// @param holderSig The sender's Falcon salt, s2 and registered public key.
    function quantumTransferDual(
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        HolderFalconSig calldata holderSig,
        LAIPOnCurve.LAIPPublicKey calldata laipPk
    ) external payable whenNotPaused nonReentrant returns (bool) {
        LibSlhEconomics.requireNotV3Downgrade(s, msg.sender); // NO-DOWNGRADE: see LibSlhEconomics
        LibLemnicoin.requireLaipVerification(msg.sender, laipPk);
        LibLemnicoin.collectProtocolFee(amount);

        LibLemnicoin.transferWithDualFalconAttestationFrom(
            msg.sender, to, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32, holderSig
        );

        LibERC20._transfer(msg.sender, to, amount);
        return true;
    }

    /// @notice The same approval, requiring BOTH signatures.
    /// @dev An approval is a standing right to move funds later, so it needs the holder's signature
    ///      for exactly the reason a transfer does.
    function quantumApproveDual(
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        HolderFalconSig calldata holderSig,
        LAIPOnCurve.LAIPPublicKey calldata laipPk
    ) external payable whenNotPaused nonReentrant returns (bool) {
        LibSlhEconomics.requireNotV3Downgrade(s, msg.sender); // NO-DOWNGRADE: see LibSlhEconomics
        if (amount > 0 && amount > s.balances[msg.sender]) {
            revert ApprovalExceedsBalance(amount, s.balances[msg.sender]);
        }

        LibLemnicoin.requireLaipVerification(msg.sender, laipPk);
        LibLemnicoin.collectProtocolFee(amount);

        LibLemnicoin.approveWithDualFalconInternal(
            msg.sender, spender, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32, holderSig
        );

        LibERC20._approve(msg.sender, spender, amount);
        s.quantumApprovedSpender[msg.sender][spender] = (amount > 0);

        emit FalconApproval(msg.sender, spender, amount, quantumInputHash, nonce);
        return true;
    }

    // =========================================================================
    // QUANTUM APPROVE (Falcon-attested + LAIP on-chain)
    // =========================================================================

    /// @notice Approve spender with Falcon attestation and LAIP verification
    /// @dev Protected by nonReentrant to prevent reentrancy via fee refund (M-04)
    ///      ATTESTOR-ONLY — closed to accounts that have registered their own Falcon key. Those use
    ///      `quantumApproveDual`.
    function quantumApprove(
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        LAIPOnCurve.LAIPPublicKey calldata laipPk
    ) external payable whenNotPaused nonReentrant returns (bool) {
        LibSlhEconomics.requireNotV3Downgrade(s, msg.sender); // NO-DOWNGRADE: see LibSlhEconomics
        // First, for the same reason as quantumTransfer above.
        LibLemnicoin.requireAttestorOnlyAllowed(s, msg.sender);

        // Prevent approving more than the wallet's balance.
        // This blocks MAX uint256 approvals and any inflated amounts.
        // Setting amount to 0 is allowed (revokes the approval).
        if (amount > 0 && amount > s.balances[msg.sender]) {
            revert ApprovalExceedsBalance(amount, s.balances[msg.sender]);
        }

        LibLemnicoin.requireLaipVerification(msg.sender, laipPk);
        LibLemnicoin.collectProtocolFee(amount);

        LibLemnicoin.approveWithFalconInternal(
            msg.sender, spender, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32
        );

        LibERC20._approve(msg.sender, spender, amount);
        s.quantumApprovedSpender[msg.sender][spender] = (amount > 0);

        emit FalconApproval(msg.sender, spender, amount, quantumInputHash, nonce);
        return true;
    }

    // =========================================================================
    // FALCON ENVELOPE TRANSFER
    // =========================================================================

    /// @notice Transfer with Falcon envelope (alternative method)
    /// @dev Protected by nonReentrant to prevent reentrancy via fee transfer (M-04)
    ///
    ///      ATTESTOR-ONLY, and it is the one attestor-only path with no dual counterpart: it signs a
    ///      bespoke envelope hash rather than the EIP-712 PQAttestation digest every other path
    ///      shares, so a second signature here would not cover the same bytes as anything else. It
    ///      is therefore simply CLOSED to registered holders, who have `quantumTransferDual` for the
    ///      identical transfer. Nothing is lost — this is an alternative encoding, not a capability.
    function transferWithFalconEnvelope(
        address to,
        uint256 amount,
        FalconEnvelope calldata env,
        LAIPOnCurve.LAIPPublicKey calldata laipPk,
        bytes calldata falconSig
    ) external payable whenNotPaused nonReentrant returns (bool) {
        LibSlhEconomics.requireNotV3Downgrade(s, msg.sender); // NO-DOWNGRADE: see LibSlhEconomics
        LibLemnicoin.requireAttestorOnlyAllowed(s, msg.sender);
        require(s.laipKeyCommitment[msg.sender] == env.laipPubKeyCommitment, "LAIP commitment mismatch");
        LAIPOnCurve.validate(laipPk);

        PriceOracle oracle = PriceOracle(s.priceOracle);
        uint256 minFeeWei = oracle.getMinFeeInWei(amount);
        if (msg.value < minFeeWei) revert InsufficientFee();

        uint256 nextNonce = s.pqAttestationNonce[msg.sender] + 1;
        bytes32 expectedTxHash = LibLemnicoin.computeTxBodyHash(
            block.chainid, msg.sender, to, amount, nextNonce
        );
        if (expectedTxHash != env.txHash) revert TxBodyHashMismatch();

        bytes32 envelopeHash = keccak256(
            abi.encode(env.txHash, env.laipPubKeyCommitment, keccak256(env.laipPublicKey))
        );

        (bytes memory salt, uint256[] memory s2) = LibLemnicoin.splitFalconSig(falconSig);

        require(
            IZKNOXEthFalcon(s.falconVerifier).verify(
                abi.encodePacked(envelopeHash), salt, s2, _getAttestorNtth()
            ),
            "Falcon verification failed"
        );

        s.pqAttestationNonce[msg.sender] = nextNonce;
        LibERC20._transfer(msg.sender, to, amount);

        emit QuantumTransferWithFee(msg.sender, to, amount, msg.value, env.txHash);
        return true;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @notice Get attestation nonce for a user
    /// @dev H-01 fix: Unified to use only pqAttestationNonce (removed quantumNonce confusion)
    function getNonce(address user) external view returns (uint256) {
        return s.pqAttestationNonce[user];
    }

    function getApprovalNonce(address user) external view returns (uint256) {
        return s.pqAttestationNonce[user];
    }

    /// @notice Get attestation nonce for a user (compatibility with monolithic Lemnicoin)
    function pqAttestationNonce(address user) external view returns (uint256) {
        return s.pqAttestationNonce[user];
    }

    function computeDigest(
        address user, address to, uint256 amount, bytes32 quantumInputHash, uint256 nonce, uint256 deadline
    ) external view returns (bytes32) {
        return LibLemnicoin.attestationDigest(user, to, amount, quantumInputHash, nonce, deadline);
    }

    function computeApprovalDigest(
        address user, address spender, uint256 amount, bytes32 quantumInputHash, uint256 nonce, uint256 deadline
    ) external view returns (bytes32) {
        return LibLemnicoin.approvalDigest(user, spender, amount, quantumInputHash, nonce, deadline);
    }

    function domainSeparator() external view returns (bytes32) {
        return LibLemnicoin.domainSeparatorV4();
    }

    function getAttestorPublicKey() external view returns (uint256[32] memory) {
        return s.attestorNtth;
    }

    function priceOracle() external view returns (address) {
        return s.priceOracle;
    }

    function FALCON_VERIFIER() external view returns (address) {
        return s.falconVerifier;
    }

    // =========================================================================
    // INTERNAL HELPERS
    // =========================================================================

    function _getAttestorNtth() internal view returns (uint256[] memory) {
        uint256[] memory result = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            result[i] = s.attestorNtth[i];
        }
        return result;
    }
}
