// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {LibERC20} from "../libraries/LibERC20.sol";
import {LibLemnicoin} from "../libraries/LibLemnicoin.sol";
import {LibRing, RingAuth} from "../libraries/LibRing.sol";
import "../../crypto/LAIPOnCurve.sol";
import {LibSlhEconomics} from "../libraries/LibSlhEconomics.sol";

error RingApprovalExceedsBalance(uint256 amount, uint256 balance);

/// @title RingTransferFacet — quantum transfers/approvals for Multi-Sig ring accounts
/// @notice The chain-enforced M-of-N: every operation needs >= threshold member Falcon signatures
///         over the same EIP-712 digest the dual path uses, plus the attestor's Falcon signature
///         while the attestor is provably live (heartbeat gate) and no matured bypass exists.
///
///         Entrypoints take an explicit `from` and are callable by ANY address: the signatures and
///         the digest (which pins from, to, amount, nonce, deadline) are the complete authority,
///         so a submitter can only ever execute exactly the operation the quorum signed. This
///         removes the account's ECDSA key as a liveness single point — a ring that lost its gas
///         wallet can still move funds through any member's wallet.
contract RingTransferFacet is Modifiers {

    event RingQuantumTransfer(
        address indexed from, address indexed to, uint256 amount, uint256 nonce, uint256 feePaid, bool attestorCoSigned
    );
    event RingQuantumApproval(
        address indexed owner, address indexed spender, uint256 amount, uint256 nonce
    );

    // =========================================================================
    // TRANSFER
    // =========================================================================

    /// @notice Ring transfer: LAIP verification + protocol fee + member quorum (+ attestor while
    ///         live) + ERC20 transfer.
    function quantumTransferRing(
        address from,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        RingAuth calldata auth,
        LAIPOnCurve.LAIPPublicKey calldata /* laipPk (unused; see note) */
    ) external payable whenNotPaused nonReentrant returns (bool) {
        LibSlhEconomics.requireNotV3Downgrade(s, from); // NO-DOWNGRADE: the RING account, not the member
        // NO requireLaipVerification here — deliberately. The ring's authority is the M-of-N MEMBER
        // Falcon quorum, verified against `from`'s registered ring inside authorizeRingTransfer
        // (which reverts unless >= threshold distinct member keys of `from`'s ring signed THIS
        // digest, pinning from/to/amount/nonce/deadline). That fully authenticates `from`.
        //
        // Requiring `from`'s own LAIP key on top of that was a copy of the dual path's shape, and it
        // is BOTH redundant (the ring, not the account's single key, is the authority — the entire
        // point of a ring) AND unsatisfiable for a normally-onboarded account: the dApp's login
        // registers keys via KeyManagementFacet.registerQuantumKeys, which sets `registered` and
        // `laipQHash` but never `laipKeyCommitment`/`laipValidatedQHash` — so requireLaipVerification
        // always reverted LAIPCommitmentMismatch on the ring path. The laipPk parameter is retained
        // (unused) only to keep the function selector/ABI stable for already-deployed callers.
        LibLemnicoin.collectProtocolFee(amount);

        LibRing.authorizeRingTransfer(s, from, to, amount, quantumInputHash, nonce, deadline, auth);

        LibERC20._transfer(from, to, amount);

        emit RingQuantumTransfer(
            from, to, amount, nonce, msg.value, auth.attestorSalt40.length != 0
        );
        return true;
    }

    // =========================================================================
    // APPROVAL
    // =========================================================================

    /// @notice Ring approval — a standing right to move funds later, so it needs exactly the same
    ///         quorum a transfer does.
    function quantumApproveRing(
        address owner_,
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        RingAuth calldata auth,
        LAIPOnCurve.LAIPPublicKey calldata /* laipPk (unused; see quantumTransferRing) */
    ) external payable whenNotPaused nonReentrant returns (bool) {
        LibSlhEconomics.requireNotV3Downgrade(s, owner_); // NO-DOWNGRADE: the RING account, not the member
        if (amount > 0 && amount > s.balances[owner_]) {
            revert RingApprovalExceedsBalance(amount, s.balances[owner_]);
        }

        // See quantumTransferRing: the member quorum authenticates owner_; no account-level LAIP
        // check (redundant, and unsatisfiable for a normally-onboarded account).
        LibLemnicoin.collectProtocolFee(amount);

        LibRing.authorizeRingApproval(s, owner_, spender, amount, quantumInputHash, nonce, deadline, auth);

        LibERC20._approve(owner_, spender, amount);
        s.quantumApprovedSpender[owner_][spender] = (amount > 0);

        emit RingQuantumApproval(owner_, spender, amount, nonce);
        return true;
    }

    // =========================================================================
    // VIEWS
    // =========================================================================

    /// @notice The digest members (and the attestor) sign for a ring transfer — identical to the
    ///         dual path's PQAttestation digest, so attestor-side verification code is unchanged.
    function ringTransferDigest(
        address from,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32) {
        return LibLemnicoin.attestationDigest(from, to, amount, quantumInputHash, nonce, deadline);
    }

    /// @notice The digest members sign for a ring approval (PQApproval).
    function ringApprovalDigest(
        address owner_,
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32) {
        return LibLemnicoin.approvalDigest(owner_, spender, amount, quantumInputHash, nonce, deadline);
    }
}
