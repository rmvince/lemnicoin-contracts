// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {LaipV3Keys, MAX_SESSION_DURATION, MIN_SESSION_DURATION} from "../libraries/LibAppStorage.sol";
import {LibERC20} from "../libraries/LibERC20.sol";
import {LibLemnicoin, HolderFalconSig} from "../libraries/LibLemnicoin.sol";
import {LibSlhEconomics, LaipV3SlhKeyMismatch, SlhDsaVerificationFailed} from "../libraries/LibSlhEconomics.sol";

error V3CapNotRegistered(address account);
error V3CapNotSameSeed();
error V3CapRecoveryFromSelf();
error V3CapZeroRecipient();
error V3CapZeroAmount();
error V3CapInvalidCexAddress();
error V3CapInvalidSessionDuration();

/// @title LAIPV3CapabilitiesFacet — recovery, CEX sessions and burn, under the V3 grid
///
/// @notice WHY THIS EXISTS. The V3 rollout added the SLH-DSA hash-family factor to transfers and
///         approvals, but left recovery ("lojack"), CEX sessions and burn on their V1/V2 code, which
///         is authorised by Falcon signatures alone. That made those three the weakest doors in the
///         building on a V3 wallet: a V3 transfer needs Falcon AND the hash family, while a recovery
///         — which moves the WHOLE balance in one call — needed only Falcon. This closes that gap.
///         Every capability a holder has is now available at V3 strength.
///
///         Each entrypoint is the exact V1/V2 semantic with the hash-family factor added, and each
///         obeys the SAME five-scenario grid as a transfer, through the SAME code
///         (LibSlhEconomics.slhRequired) — so the rule cannot drift between operations.
///
/// @dev    ADD-ONLY. This facet adds selectors; it replaces nothing. The V1/V2 entrypoints keep
///         working exactly as before, so no wallet loses a capability and nothing is frozen.
///
///         REUSES THE EXISTING EIP-712 DIGESTS. The Falcon layer signs the same `PQRecovery`,
///         `PQSession` and `PQAttestation` digests the V1/V2 paths use, so the ATTESTOR needs no
///         change at all to co-sign these operations — its existing signing code already produces
///         them. Only the extra SLH-DSA signature is new, and that one the holder's own wallet makes.
///
///         SEED IDENTITY COMES FROM V3 STORAGE. Recovery's whole premise is "prove this second
///         address is also me". The legacy facet proves it by matching the V1/V2 `quantumKeyHashes`
///         of the two addresses. Here it is matched on `laipV3` instead: V3 keys are derived from
///         the SEED ALONE (shared/laip-v3 `deriveV3Keys(seedPhrase)` takes no address), so two
///         addresses belonging to one seed carry byte-identical curve/SLH/ML-DSA hashes — and
///         therefore an identical `ownershipCommitmentV3`, which binds all three together.
contract LAIPV3CapabilitiesFacet is Modifiers {

    bytes32 private constant RECOVERY_TYPEHASH =
        keccak256("PQRecovery(address from,address recoveredBy,address to,uint256 amount,bytes32 quantumInputHash,uint256 nonce,uint256 deadline)");
    bytes32 private constant SESSION_TYPEHASH =
        keccak256("PQSession(address user,address cexAddress,uint256 duration,bytes32 quantumInputHash,uint256 nonce,uint256 deadline)");

    /// Mirrors the legacy events byte-for-byte (same name, same argument types, so the same topic0
    /// from the same diamond address) so existing indexers and exchange integrations keep working
    /// without a single off-chain change. The V3 events alongside them carry `slhVerified`.
    event RecoveryTransferExecuted(
        address indexed from, address indexed recoveredBy, address indexed to, uint256 amount, uint256 nonce
    );
    event CexSessionCreated(address indexed user, address indexed cexAddress, uint256 expiry, uint256 nonce);

    event LaipV3Recovery(
        address indexed from, address indexed recoveredBy, address indexed to,
        uint256 amount, uint256 nonce, bool slhVerified
    );
    event LaipV3CexSession(
        address indexed user, address indexed cexAddress, uint256 expiry, uint256 nonce, bool slhVerified
    );
    event LaipV3Burn(address indexed from, uint256 amount, uint256 nonce, bool slhVerified);

    // ---------------------------------------------------------------------
    // Message domains for the SLH factor. Distinct strings, so a signature taken for one operation
    // can NEVER be replayed as another — the mu they feed differ at the first byte of m's preimage.
    // ---------------------------------------------------------------------

    /// @notice m = keccak256("LEMNICOIN_RECOVERY" || chainId || from || recoveredBy || to || amount).
    ///         `recoveredBy` is inside the message on purpose: a recovery signature obtained for one
    ///         rescuer cannot be reused by a different one.
    function _recoveryMessage(address from, address recoveredBy, address to, uint256 amount)
        internal view returns (bytes32)
    {
        return keccak256(abi.encodePacked(
            "LEMNICOIN_RECOVERY", block.chainid, from, recoveredBy, to, amount
        ));
    }

    /// @notice m = keccak256("LEMNICOIN_SESSION" || chainId || user || cexAddress || duration).
    function _sessionMessage(address user, address cexAddress, uint256 duration)
        internal view returns (bytes32)
    {
        return keccak256(abi.encodePacked("LEMNICOIN_SESSION", block.chainid, user, cexAddress, duration));
    }

    /// @notice m = keccak256("LEMNICOIN_BURN" || chainId || from || amount).
    function _burnMessage(address from, uint256 amount) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("LEMNICOIN_BURN", block.chainid, from, amount));
    }

    function _requireV3(address account) internal view returns (LaipV3Keys storage k) {
        k = s.laipV3[account];
        if (!k.registered) revert V3CapNotRegistered(account);
    }

    // =====================================================================================
    // LOJACK — recover funds from a wallet whose EVM key was stolen
    // =====================================================================================
    /// @notice Move `from`'s balance to `to`, called by a SECOND address that the same 48-word seed
    ///         owns. The thief holding `from`'s EVM key cannot do this in reverse: the authority is
    ///         `from`'s holder Falcon signature plus `from`'s SLH-DSA signature, both of which come
    ///         from the seed, not from the EVM key.
    ///
    /// @param slhPubKey `from`'s SLH-DSA public key. Mandatory whenever the factor is required.
    /// @param slhSig    `from`'s SLH-DSA signature over
    ///                  mu_trustless(_recoveryMessage(from, msg.sender, to, amount), curveHash, nonce).
    /// @param holderSig `from`'s holder Falcon signature — the compromised wallet's, not the
    ///                  rescuer's. That is the correct binding: it is `from`'s balance that moves.
    function recoveryTransferV3(
        address from,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        bytes calldata slhPubKey,
        bytes calldata slhSig,
        HolderFalconSig calldata holderSig
    ) external payable whenNotPaused nonReentrant returns (bool) {
        if (amount == 0) revert V3CapZeroAmount();
        if (to == address(0)) revert V3CapZeroRecipient();
        if (from == msg.sender) revert V3CapRecoveryFromSelf();

        LaipV3Keys storage fromKeys = _requireV3(from);
        _requireSameSeed(from, msg.sender);

        uint256 n0 = s.pqAttestationNonce[from]; // captured before the Falcon layer burns it

        // FLOOR (required): attestor Falcon + `from`'s holder Falcon over the PQRecovery digest —
        // the identical digest the legacy path uses, so the attestor needs no new code.
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", LibLemnicoin.domainSeparatorV4(),
            keccak256(abi.encode(
                RECOVERY_TYPEHASH, from, msg.sender, to, amount, quantumInputHash, nonce, deadline))));
        LibLemnicoin.requireDualFalcon(from, digest, nonce, deadline, falconSalt40, falconS2_32, holderSig);

        // HASH FAMILY: same rule, same code, as a V3 transfer of the same size.
        bytes32 m = _recoveryMessage(from, msg.sender, to, amount);
        bool slhVerified = LibSlhEconomics.slhRequired(s, from, amount)
            ? LibSlhEconomics.strictSlh(s, fromKeys, m, n0, slhPubKey, slhSig)
            : LibSlhEconomics.bestEffortSlh(s, fromKeys, m, n0, slhPubKey, slhSig);
        if (!slhVerified) LibSlhEconomics.noteSlhFree(s, from, amount);

        // effects before interactions: move the tokens, then take the fee (whose refund calls out).
        LibERC20._transfer(from, to, amount);
        LibLemnicoin.collectProtocolFee(amount);

        emit RecoveryTransferExecuted(from, msg.sender, to, amount, nonce);
        emit LaipV3Recovery(from, msg.sender, to, amount, nonce, slhVerified);
        return true;
    }

    /// @dev Two addresses belong to the same seed iff their V3 registrations are identical. Checking
    ///      `ownershipCommitmentV3` alone would be enough — it is
    ///      keccak256(curveHash, mldsaPkHash, slhdsaPkHash) and is validated at registration — but
    ///      the three hashes are compared explicitly too, so this does not depend on that commitment
    ///      never being loosened.
    function _requireSameSeed(address from, address rescuer) internal view {
        LaipV3Keys storage a = s.laipV3[from];
        LaipV3Keys storage b = s.laipV3[rescuer];
        if (!b.registered) revert V3CapNotRegistered(rescuer);
        if (a.curveHash != b.curveHash ||
            a.slhdsaPkHash != b.slhdsaPkHash ||
            a.mldsaPkHash != b.mldsaPkHash ||
            s.ownershipCommitmentV3[from] != s.ownershipCommitmentV3[rescuer]) {
            revert V3CapNotSameSeed();
        }
    }

    // =====================================================================================
    // CEX SESSIONS
    // =====================================================================================
    /// @notice Open a CEX session at V3 strength.
    ///
    /// @dev NO ECONOMIC EXEMPTION HERE, deliberately. `sessionTransfer` carries no per-transfer
    ///      quantum check and no amount cap, so an open session is a bearer right to the WHOLE
    ///      balance for its duration. There is no "amount" to price the 1% rule against, and the
    ///      value at stake is the entire wallet — so whenever the chain can fit the verify, the
    ///      hash-family factor is required. Creating the session is the only gate there is; it gets
    ///      the strongest one.
    function createCexSessionV3(
        address cexAddress,
        uint256 duration,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        bytes calldata slhPubKey,
        bytes calldata slhSig,
        HolderFalconSig calldata holderSig
    ) external payable whenNotPaused nonReentrant returns (bool) {
        if (cexAddress == address(0)) revert V3CapInvalidCexAddress();
        if (duration < MIN_SESSION_DURATION || duration > MAX_SESSION_DURATION) {
            revert V3CapInvalidSessionDuration();
        }
        LaipV3Keys storage k = _requireV3(msg.sender);

        uint256 n0 = s.pqAttestationNonce[msg.sender];

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", LibLemnicoin.domainSeparatorV4(),
            keccak256(abi.encode(
                SESSION_TYPEHASH, msg.sender, cexAddress, duration, quantumInputHash, nonce, deadline))));
        LibLemnicoin.requireDualFalcon(msg.sender, digest, nonce, deadline, falconSalt40, falconS2_32, holderSig);

        bytes32 m = _sessionMessage(msg.sender, cexAddress, duration);
        bool slhVerified = LibSlhEconomics.chainStrict(s)
            ? LibSlhEconomics.strictSlh(s, k, m, n0, slhPubKey, slhSig)
            : LibSlhEconomics.bestEffortSlh(s, k, m, n0, slhPubKey, slhSig);

        uint256 expiry = block.timestamp + duration;
        s.userCexSession[msg.sender][cexAddress] = expiry;

        emit CexSessionCreated(msg.sender, cexAddress, expiry, nonce);
        emit LaipV3CexSession(msg.sender, cexAddress, expiry, nonce, slhVerified);
        return true;
    }

    // =====================================================================================
    // BURN
    // =====================================================================================
    /// @notice Burn at V3 strength. Destroying a holder's balance is an attack even though nothing
    ///         is stolen, so burn gets the same factors as a transfer of the same size — including
    ///         the 1% rule, since burning dust should not cost more than the dust is worth.
    function quantumBurnV3(
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        bytes calldata slhPubKey,
        bytes calldata slhSig,
        HolderFalconSig calldata holderSig
    ) external payable whenNotPaused nonReentrant returns (bool) {
        if (amount == 0) revert V3CapZeroAmount();
        LaipV3Keys storage k = _requireV3(msg.sender);

        uint256 n0 = s.pqAttestationNonce[msg.sender];

        // The burn digest is the shared PQAttestation one with recipient = address(0), exactly as
        // quantumBurnDual builds it — so, again, no attestor change.
        LibLemnicoin.verifyDualFalconAttestationForBurn(
            msg.sender, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32, holderSig
        );

        bytes32 m = _burnMessage(msg.sender, amount);
        bool slhVerified = LibSlhEconomics.slhRequired(s, msg.sender, amount)
            ? LibSlhEconomics.strictSlh(s, k, m, n0, slhPubKey, slhSig)
            : LibSlhEconomics.bestEffortSlh(s, k, m, n0, slhPubKey, slhSig);
        if (!slhVerified) LibSlhEconomics.noteSlhFree(s, msg.sender, amount);

        LibERC20._burn(msg.sender, amount);
        LibLemnicoin.collectProtocolFee(amount);

        emit LaipV3Burn(msg.sender, amount, nonce, slhVerified);
        return true;
    }

    // ===================== VIEWS =====================

    /// @notice Whether `rescuer` is provably the same seed as `from`, and may therefore lojack it.
    ///         Clients call this before offering recovery, so the user is never sent into a revert.
    function canRecoverV3(address from, address rescuer) external view returns (bool) {
        LaipV3Keys storage a = s.laipV3[from];
        LaipV3Keys storage b = s.laipV3[rescuer];
        if (!a.registered || !b.registered || from == rescuer) return false;
        return a.curveHash == b.curveHash
            && a.slhdsaPkHash == b.slhdsaPkHash
            && a.mldsaPkHash == b.mldsaPkHash
            && s.ownershipCommitmentV3[from] == s.ownershipCommitmentV3[rescuer];
    }

    /// @notice Whether opening a CEX session requires the SLH factor right now. No amount argument:
    ///         a session is uncapped, so the economic exemption never applies to it.
    function cexSessionV3SlhRequired() external view returns (bool) {
        return LibSlhEconomics.chainStrict(s);
    }
}
