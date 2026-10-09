// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AppStorage, LibAppStorage} from "./LibAppStorage.sol";
import "../../PriceOracle.sol";
import "../../crypto/LAIPOnCurve.sol";
import "../../falcon/IZKNOXEthFalcon.sol";

error InsufficientFee();
error InvalidFeeCollector();
error FeeTransferFailed();
error RefundFailed();
error LAIPCommitmentMismatch();
error LAIPQHashMismatch();
error LAIPCurveNotValidated();
error QuantumKeysNotRegistered();
error AttestationExpired();
error InvalidNonce(uint256 expected, uint256 provided);
error InvalidSaltLength(uint256 length);
error InvalidS2Length(uint256 length);
error FalconVerificationFailed();
error ZeroRecipient();
error GovernanceNotInitialized();
error GovernanceAttestationExpired();
error GovernanceInvalidNonce(uint256 expected, uint256 provided);
error GovernanceInvalidSaltLength(uint256 length);
error GovernanceInvalidS2Length(uint256 length);
error GovernanceFalconVerificationFailed();
error HolderFalconKeyNotRegistered();
error InvalidNtthLength(uint256 length);
error HolderFalconKeyMismatch();
/// @notice The attestor's signature alone is no longer sufficient for this account, because it has
///         registered a Falcon key of its own. Use the `*Dual` entrypoint (attestor + holder) or,
///         if the attestor is unreachable, `quantumTransferWithHolderKey`.
/// @dev This is what converts "the holder CAN also sign" into "the holder MUST also sign". Without
///      it the attestor-only entrypoints stay open and a stolen attestor key still moves every
///      balance — the dual path would be advice rather than a control.
error AttestorOnlyPathClosed(address user);
/// @notice The holder's Falcon signature did not verify against their registered key.
error HolderFalconVerificationFailed();
/// @notice The single-signature holder-only path is time-locked shut because the attestor is still
///         proving liveness (heartbeating). It opens at `opensAtBlock` if the attestor stays silent
///         until then; use `quantumTransferDual` (attestor + holder) in the meantime.
error HolderOnlyPathTimeLocked(uint256 opensAtBlock);
/// @notice This account registered a Multi-Sig ring (M-of-N member keys), so every path that
///         accepts a SINGLE holder signature — dual, holder-only, session, recovery — is closed to
///         it. Use the ring entrypoints (RingTransferFacet), which require the member quorum.
/// @dev Without this closure the ring would be decorative: one member seed (or the account's old
///      single holder key) plus the attestor could bypass the quorum entirely.
error RingAccountMustUseRingPath(address account);

/// @notice A holder's own Falcon signature plus the public key it must verify against.
/// @dev Bundled into one struct rather than three loose parameters purely so the dual-signature
///      entrypoints stay inside Solidity's stack limits — `quantumTransfer` already carries eight
///      arguments including a struct.
struct HolderFalconSig {
    /// @notice Falcon salt (exactly 40 bytes).
    bytes salt40;
    /// @notice Falcon s2 (exactly 32 words).
    uint256[] s2_32;
    /// @notice The holder's Falcon public key in NTT domain (32 words), checked against the
    ///         commitment they registered. Supplied by the caller because storing 32 words per
    ///         holder is expensive; the commitment check is what binds it to the holder.
    uint256[] ntth;
}

/// @title LibLemnicoin - Shared helpers for Lemnicoin Diamond facets
/// @notice Contains Falcon attestation/governance helpers, LAIP verification,
///         protocol fee collection, EIP-712 domain separators, and tx-body hashing.
library LibLemnicoin {

    // =========================================================================
    // EVENTS
    // =========================================================================

    event ProtocolFeeCollected(address indexed from, address indexed collector, uint256 feeWei);
    event ExcessRefunded(address indexed to, uint256 amount);
    event FalconAttestationVerified(
        address indexed user, address indexed to, uint256 amount, uint256 nonce, bytes32 quantumInputHash
    );
    event GovernanceFalconVerified(address indexed signer, bytes32 actionHash, uint256 nonce);

    // =========================================================================
    // EIP-712 CONSTANTS
    // =========================================================================

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant ATTEST_TYPEHASH =
        keccak256("PQAttestation(address user,address to,uint256 amount,bytes32 quantumInputHash,uint256 nonce,uint256 deadline)");
    bytes32 private constant APPROVAL_TYPEHASH =
        keccak256("PQApproval(address user,address spender,uint256 amount,bytes32 quantumInputHash,uint256 nonce,uint256 deadline)");
    bytes32 private constant NAME_HASH = keccak256("LemnicoinPQAttestation");
    bytes32 private constant VERSION_HASH = keccak256("1");

    bytes32 private constant GOV_EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant GOV_ACTION_TYPEHASH =
        keccak256("GovernanceAction(address signer,bytes32 actionHash,uint256 nonce,uint256 deadline)");
    bytes32 private constant GOV_NAME_HASH = keccak256("LemnicoinGovernance");
    bytes32 private constant GOV_VERSION_HASH = keccak256("1");

    // =========================================================================
    // LAIP VERIFICATION
    // =========================================================================

    /// @notice Verify LAIP public key commitment and Q hash match validated keys
    /// @dev Curve validation must be done via validateLaipCurve() before first transfer.
    ///      This function only checks the Q matches what was validated on-chain.
    ///      If Q was never validated, transaction fails as forgery.
    function requireLaipVerification(
        address account,
        LAIPOnCurve.LAIPPublicKey calldata laipPk
    ) internal view {
        AppStorage storage s = LibAppStorage.appStorage();

        // Verify quantum keys are registered
        if (!s.quantumKeyHashes[account].registered) revert QuantumKeysNotRegistered();

        // Verify commitment matches (try both old and new formats)
        // New format: hash(x, y, P0x||P0y, a, p) where P0 contains both coordinates
        bytes32 commitmentNew = keccak256(
            abi.encodePacked(laipPk.x, laipPk.y, laipPk.P0, laipPk.a, laipPk.p)
        );

        // Old format: hash(x, y, P0x, a, p) where P0 only had P0x
        // P0 is 768 bytes (384*2), split it into P0x (first 384) and P0y (last 384)
        bytes memory P0x = new bytes(384);
        for (uint i = 0; i < 384; i++) {
            P0x[i] = laipPk.P0[i];
        }
        bytes32 commitmentOld = keccak256(
            abi.encodePacked(laipPk.x, laipPk.y, P0x, laipPk.a, laipPk.p)
        );

        // Accept either format
        if (s.laipKeyCommitment[account] != commitmentNew &&
            s.laipKeyCommitment[account] != commitmentOld) {
            revert LAIPCommitmentMismatch();
        }

        // Verify Q hash matches registered laipQHash
        bytes32 qHash = keccak256(abi.encodePacked(laipPk.x, laipPk.y));
        if (s.quantumKeyHashes[account].laipQHash != qHash) revert LAIPQHashMismatch();

        // Verify Q was validated on-chain via validateLaipCurve()
        // If not validated, this is a forgery attempt
        if (s.laipValidatedQHash[account] != qHash) revert LAIPCurveNotValidated();
    }

    // =========================================================================
    // PROTOCOL FEE COLLECTION
    // =========================================================================

    /// @notice Collect protocol fee; refund excess ETH
    /// @dev Fee-exempt wallets (s.feeExempt[msg.sender], set by governance via
    ///      FeeExemptionFacet) pay nothing: any native value they attached is refunded in
    ///      full and the function returns before the oracle is consulted. The exemption can
    ///      only ever WAIVE the fee — it never blocks a transfer, so it cannot freeze funds.
    function collectProtocolFee(uint256 amount) internal {
        AppStorage storage s = LibAppStorage.appStorage();

        // Per-wallet fee exemption: skip the fee entirely and refund any attached value.
        if (s.feeExempt[msg.sender]) {
            if (msg.value > 0) {
                (bool refundSuccess,) = msg.sender.call{value: msg.value}("");
                if (!refundSuccess) revert RefundFailed();
                emit ExcessRefunded(msg.sender, msg.value);
            }
            return;
        }

        if (s.priceOracle == address(0)) return;

        PriceOracle oracle = PriceOracle(s.priceOracle);
        uint256 requiredFee = oracle.getMinFeeInWei(amount);
        if (msg.value < requiredFee) revert InsufficientFee();

        address payable collector = oracle.feeCollector();

        if (requiredFee > 0 && collector != address(0)) {
            (bool feeSuccess,) = collector.call{value: requiredFee}("");
            if (!feeSuccess) revert FeeTransferFailed();
            emit ProtocolFeeCollected(msg.sender, collector, requiredFee);
        }

        uint256 excess = msg.value - requiredFee;
        if (excess > 0) {
            (bool refundSuccess,) = msg.sender.call{value: excess}("");
            if (!refundSuccess) revert RefundFailed();
            emit ExcessRefunded(msg.sender, excess);
        }
    }

    // =========================================================================
    // TX BODY HASH
    // =========================================================================

    function computeTxBodyHash(
        uint256 chainId,
        address from,
        address to,
        uint256 amount,
        uint256 nonce
    ) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(chainId, address(this), from, to, amount, nonce));
    }

    function computeApprovalBodyHash(
        uint256 chainId,
        address owner_,
        address spender,
        uint256 amount,
        uint256 nonce
    ) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(chainId, address(this), owner_, spender, amount, nonce));
    }

    // =========================================================================
    // FALCON ATTESTATION HELPERS
    // =========================================================================

    /// @notice EIP-712 domain separator for attestation
    function domainSeparatorV4() internal view returns (bytes32) {
        return keccak256(
            abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this))
        );
    }

    /// @notice Compute attestation digest for transfers
    function attestationDigest(
        address user,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(ATTEST_TYPEHASH, user, to, amount, quantumInputHash, nonce, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparatorV4(), structHash));
    }

    /// @notice Compute approval digest
    function approvalDigest(
        address user,
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 approvalStructHash = keccak256(
            abi.encode(APPROVAL_TYPEHASH, user, spender, amount, quantumInputHash, nonce, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparatorV4(), approvalStructHash));
    }

    /// @notice Verify Falcon attestation and execute transfer.
    /// @dev ATTESTOR-ONLY, and therefore closed to any account that has registered a Falcon key of
    ///      its own — those must use the dual-signature entrypoint (or the holder-only one during an
    ///      attestor outage). See `requireAttestorOnlyAllowed` for why this is conditional.
    function transferWithFalconAttestationFrom(
        address sender,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32
    ) internal returns (bool) {
        AppStorage storage s = LibAppStorage.appStorage();

        if (to == address(0)) revert ZeroRecipient();
        if (block.timestamp > deadline) revert AttestationExpired();
        requireAttestorOnlyAllowed(s, sender);

        uint256 expectedNonce = s.pqAttestationNonce[sender];
        if (nonce != expectedNonce) revert InvalidNonce(expectedNonce, nonce);
        if (falconSalt40.length != 40) revert InvalidSaltLength(falconSalt40.length);
        if (falconS2_32.length != 32) revert InvalidS2Length(falconS2_32.length);

        bytes32 digest = attestationDigest(sender, to, amount, quantumInputHash, nonce, deadline);

        bool valid = IZKNOXEthFalcon(s.falconVerifier).verify(
            abi.encodePacked(digest),
            falconSalt40,
            _toMemoryArray(falconS2_32),
            _getAttestorNtth(s)
        );
        if (!valid) revert FalconVerificationFailed();

        s.pqAttestationNonce[sender] = nonce + 1;

        emit FalconAttestationVerified(sender, to, amount, nonce, quantumInputHash);
        return true;
    }

    /// @notice Same transfer, authorised by the SENDER'S OWN Falcon key instead of the attestor's.
    /// @dev The attestor-free path. The digest, nonce, deadline and verifier are identical to
    ///      transferWithFalconAttestationFrom — only the key that signed differs, so a packet the
    ///      dApp built for the attestor can be re-signed locally and submitted here unchanged.
    ///
    ///      The holder's public key is not stored on-chain (32 words is expensive); only a hash of
    ///      it is, at registration. The caller supplies the full key here and it is checked against
    ///      that commitment, so this can only ever verify against the key the holder registered.
    ///
    ///      SECURITY: `holderNtth` comes from calldata, so the commitment check is what binds it to
    ///      the sender. Without a registered commitment there is no fallback path at all.
    function transferWithHolderFalconAttestationFrom(
        address sender,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        uint256[] calldata holderNtth
    ) internal returns (bool) {
        AppStorage storage s = LibAppStorage.appStorage();

        if (to == address(0)) revert ZeroRecipient();
        if (block.timestamp > deadline) revert AttestationExpired();
        // A ring account's outage path is "threshold member signatures, no attestor" on the ring
        // entrypoints — never a single holder key. Checked before anything else so a probing call
        // learns the real reason.
        requireNotRingAccount(s, sender);

        uint256 expectedNonce = s.pqAttestationNonce[sender];
        if (nonce != expectedNonce) revert InvalidNonce(expectedNonce, nonce);
        if (falconSalt40.length != 40) revert InvalidSaltLength(falconSalt40.length);
        if (falconS2_32.length != 32) revert InvalidS2Length(falconS2_32.length);

        _requireHolderFalconKey(s, sender, holderNtth);

        bytes32 digest = attestationDigest(sender, to, amount, quantumInputHash, nonce, deadline);

        bool valid = IZKNOXEthFalcon(s.falconVerifier).verify(
            abi.encodePacked(digest),
            falconSalt40,
            _toMemoryArray(falconS2_32),
            _toMemoryArray(holderNtth)
        );
        if (!valid) revert FalconVerificationFailed();

        s.pqAttestationNonce[sender] = nonce + 1;

        emit FalconAttestationVerified(sender, to, amount, nonce, quantumInputHash);
        return true;
    }

    /// @notice Holder-only APPROVAL: the sender's own Falcon key authorises an allowance, with no
    ///         attestor signature. The approval counterpart of transferWithHolderFalconAttestationFrom.
    /// @dev Added for the V3 attestor-independent approve (LAIPV3TransferFacet.quantumApproveV3).
    ///      V1/V2 deliberately had no holder-only approve, because a V1/V2 wallet always retained a
    ///      dual approve. A V3 wallet does not: the no-downgrade gate closes the legacy approve to
    ///      it, so without this helper an attestor outage would leave V3 wallets unable to grant an
    ///      allowance at all. Callers MUST apply the attestor-liveness gate
    ///      (requireHolderOnlyPathOpen) exactly as the holder-only transfer path does — this helper
    ///      does not open a permanent single-signature approve.
    ///      Ring accounts are excluded (single holder signature is insufficient authority for them),
    ///      the nonce is checked and burned here, and the holder key is bound to its commitment.
    function approveWithHolderFalconInternal(
        address sender,
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        HolderFalconSig calldata holderSig
    ) internal returns (bool) {
        AppStorage storage s = LibAppStorage.appStorage();

        if (spender == address(0)) revert ZeroRecipient();
        if (block.timestamp > deadline) revert AttestationExpired();
        requireNotRingAccount(s, sender);

        uint256 expectedNonce = s.pqAttestationNonce[sender];
        if (nonce != expectedNonce) revert InvalidNonce(expectedNonce, nonce);

        bytes32 digest = approvalDigest(sender, spender, amount, quantumInputHash, nonce, deadline);
        // Verifies salt/s2/ntth lengths, binds ntth to the registered commitment, and checks the
        // signature — the same helper every holder-Falcon path uses.
        verifyHolderFalcon(s, sender, digest, holderSig);

        s.pqAttestationNonce[sender] = nonce + 1;
        return true;
    }

    /// @notice Revert unless `holderNtth` is exactly the Falcon key `holder` registered.
    function _requireHolderFalconKey(
        AppStorage storage s,
        address holder,
        uint256[] calldata holderNtth
    ) internal view {
        if (holderNtth.length != 32) revert InvalidNtthLength(holderNtth.length);

        bytes32 commitment = s.holderFalconCommitment[holder];
        if (commitment == bytes32(0)) revert HolderFalconKeyNotRegistered();
        if (keccak256(abi.encodePacked(holderNtth)) != commitment) revert HolderFalconKeyMismatch();
    }

    // =========================================================================
    // DUAL SIGNATURE — the attestor's Falcon signature AND the holder's own
    // =========================================================================
    //
    // THE PROBLEM THIS SOLVES. Every attestor-signed entrypoint above treats one Falcon signature,
    // under one key held by one server, as the complete authority to move a user's balance. The
    // holder's own post-quantum keys are checked only OFF-chain, by that same server. So possession
    // of the attestor's private key was sufficient to move every balance, with no user involvement:
    // a universal spending key, and every piece of infrastructure hardening around it was an attempt
    // to keep one secret safe rather than to make losing it survivable.
    //
    // THE RULE. A holder who has registered a Falcon key must sign alongside the attestor. Both
    // signatures cover the SAME digest, so neither party can be shown a different transfer from the
    // one that executes, and an attacker holding the attestor's key alone can move nothing.
    //
    // PERMANENTLY CLOSED — attestor-only is disabled for EVERY account, unconditionally. Previously
    // this was conditional (open only until a holder registered a Falcon key) to avoid freezing
    // unregistered holders. That condition is now removed by design: the dApp derives and registers a
    // holder Falcon key at login, so every real account has one, and no legitimate flow needs an
    // attestor-only path. The attestor's signature alone must NEVER move funds — a compromised
    // attestor key would otherwise drain any account that had not yet registered.
    //
    // CONSEQUENCE (accepted): an account that holds funds but has never registered a holder Falcon key
    // cannot use any quantum path until it registers one via KeyManagementFacet.registerHolderFalconKey
    // (a normal transaction the dApp performs automatically at login/unlock). After that one-time
    // registration it transacts through the *Dual entrypoints, or quantumTransferWithHolderKey during
    // an attestor outage. This is not a permanent freeze — it makes "register your own Falcon key" a
    // hard prerequisite for spending, which is exactly the intent.

    /// @notice Revert on EVERY attestor-only entrypoint — the caller must instead co-sign with its own
    ///         Falcon key (the *Dual paths, or quantumTransferWithHolderKey).
    /// @dev The single chokepoint every attestor-only path calls, so the closure cannot be missed and
    ///      any future attestor-only entrypoint that routes through here is closed automatically. `s`
    ///      is unused now that the check is unconditional.
    function requireAttestorOnlyAllowed(AppStorage storage, address user) internal view {
        revert AttestorOnlyPathClosed(user);
    }

    /// @notice Revert if `user` has registered a Multi-Sig ring — single-holder-signature
    ///         paths are closed to ring accounts (see RingAccountMustUseRingPath).
    function requireNotRingAccount(AppStorage storage s, address user) internal view {
        if (s.ringConfig[user].registered) revert RingAccountMustUseRingPath(user);
    }


    // =========================================================================
    // ATTESTOR LIVENESS GATE — makes the holder-only path a true 2-of-2 fallback
    // =========================================================================
    // The holder-only path (quantumTransferWithHolderKey) is a single-signature escape hatch. On its
    // own it means the holder's key alone can always move funds, so the "dual" requirement is advice
    // rather than a control. This gate makes it a control: while the attestor heartbeats, the
    // holder-only path is CLOSED (every transfer must be dual = attestor + holder), and it OPENS only
    // after the attestor has been silent for `holderOnlyOutageBlocks` (N) blocks — a genuine outage.
    // N == 0 disables the gate (holder-only always allowed), which is the pre-upgrade behavior.

    /// @notice Whether the single-signature holder-only path is currently open.
    /// @dev Open iff the gate is disabled (N == 0) OR the attestor has gone silent for more than N
    ///      blocks. While the attestor heartbeats this is false, which is what forces the 2-of-2.
    function holderOnlyPathOpen(AppStorage storage s) internal view returns (bool) {
        uint256 n = s.holderOnlyOutageBlocks;
        if (n == 0) return true;
        return block.number > s.attestorLastHeartbeatBlock + n;
    }

    /// @notice Revert unless the holder-only path is open (see holderOnlyPathOpen).
    function requireHolderOnlyPathOpen(AppStorage storage s) internal view {
        uint256 n = s.holderOnlyOutageBlocks;
        if (n == 0) return;
        uint256 opensAtBlock = s.attestorLastHeartbeatBlock + n + 1; // first block the path is open
        if (block.number < opensAtBlock) revert HolderOnlyPathTimeLocked(opensAtBlock);
    }

    /// @notice Verify the holder's own Falcon signature over `digest` against their registered key.
    function verifyHolderFalcon(
        AppStorage storage s,
        address holder,
        bytes32 digest,
        HolderFalconSig calldata sig
    ) internal view {
        if (sig.salt40.length != 40) revert InvalidSaltLength(sig.salt40.length);
        if (sig.s2_32.length != 32) revert InvalidS2Length(sig.s2_32.length);
        if (sig.ntth.length != 32) revert InvalidNtthLength(sig.ntth.length);

        bytes32 commitment = s.holderFalconCommitment[holder];
        if (commitment == bytes32(0)) revert HolderFalconKeyNotRegistered();
        if (keccak256(abi.encodePacked(sig.ntth)) != commitment) revert HolderFalconKeyMismatch();

        bool valid = IZKNOXEthFalcon(s.falconVerifier).verify(
            abi.encodePacked(digest),
            sig.salt40,
            _toMemoryArray(sig.s2_32),
            _toMemoryArray(sig.ntth)
        );
        if (!valid) revert HolderFalconVerificationFailed();
    }

    /// @notice Verify the ATTESTOR's Falcon signature over `digest`.
    function verifyAttestorFalcon(
        AppStorage storage s,
        bytes32 digest,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32
    ) internal view {
        if (falconSalt40.length != 40) revert InvalidSaltLength(falconSalt40.length);
        if (falconS2_32.length != 32) revert InvalidS2Length(falconS2_32.length);

        bool valid = IZKNOXEthFalcon(s.falconVerifier).verify(
            abi.encodePacked(digest),
            falconSalt40,
            _toMemoryArray(falconS2_32),
            _getAttestorNtth(s)
        );
        if (!valid) revert FalconVerificationFailed();
    }

    /// @notice Shared tail of every dual-signature entrypoint: check the window and the nonce, then
    ///         require BOTH signatures over the one digest, then burn the nonce.
    /// @dev The order matters for diagnosis, not for safety — the attestor is checked first so an
    ///      attestor-side problem reverts with `FalconVerificationFailed` rather than being masked
    ///      by the holder's key. Both must pass regardless.
    function requireDualFalcon(
        address user,
        bytes32 digest,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        HolderFalconSig calldata holderSig
    ) internal {
        AppStorage storage s = LibAppStorage.appStorage();

        // Every caller of this tail (dual transfer/approve/burn, SessionFacet, RecoveryFacet)
        // accepts ONE holder signature — insufficient authority for a ring account, whose quorum
        // is enforced only on the ring entrypoints. One check here closes them all.
        requireNotRingAccount(s, user);

        if (block.timestamp > deadline) revert AttestationExpired();
        uint256 expectedNonce = s.pqAttestationNonce[user];
        if (nonce != expectedNonce) revert InvalidNonce(expectedNonce, nonce);

        verifyAttestorFalcon(s, digest, falconSalt40, falconS2_32);
        verifyHolderFalcon(s, user, digest, holderSig);

        s.pqAttestationNonce[user] = nonce + 1;
    }

    /// @notice Dual-signature transfer: identical to `transferWithFalconAttestationFrom` except that
    ///         the holder must sign the same digest as well.
    function transferWithDualFalconAttestationFrom(
        address sender,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        HolderFalconSig calldata holderSig
    ) internal returns (bool) {
        if (to == address(0)) revert ZeroRecipient();

        bytes32 digest = attestationDigest(sender, to, amount, quantumInputHash, nonce, deadline);
        requireDualFalcon(sender, digest, nonce, deadline, falconSalt40, falconS2_32, holderSig);

        emit FalconAttestationVerified(sender, to, amount, nonce, quantumInputHash);
        return true;
    }

    /// @notice Dual-signature approval.
    function approveWithDualFalconInternal(
        address sender,
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        HolderFalconSig calldata holderSig
    ) internal returns (bool) {
        if (spender == address(0)) revert ZeroRecipient();

        bytes32 digest = approvalDigest(sender, spender, amount, quantumInputHash, nonce, deadline);
        requireDualFalcon(sender, digest, nonce, deadline, falconSalt40, falconS2_32, holderSig);
        return true;
    }

    /// @notice Dual-signature burn. Reuses the transfer digest with `to = address(0)`, exactly as
    ///         the attestor-only burn does.
    function verifyDualFalconAttestationForBurn(
        address sender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        HolderFalconSig calldata holderSig
    ) internal returns (bool) {
        bytes32 digest = attestationDigest(sender, address(0), amount, quantumInputHash, nonce, deadline);
        requireDualFalcon(sender, digest, nonce, deadline, falconSalt40, falconS2_32, holderSig);

        emit FalconAttestationVerified(sender, address(0), amount, nonce, quantumInputHash);
        return true;
    }

    /// @notice Verify Falcon attestation for burn operations (allows address(0))
    function verifyFalconAttestationForBurn(
        address sender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32
    ) internal returns (bool) {
        AppStorage storage s = LibAppStorage.appStorage();

        if (block.timestamp > deadline) revert AttestationExpired();
        requireAttestorOnlyAllowed(s, sender);

        uint256 expectedNonce = s.pqAttestationNonce[sender];
        if (nonce != expectedNonce) revert InvalidNonce(expectedNonce, nonce);
        if (falconSalt40.length != 40) revert InvalidSaltLength(falconSalt40.length);
        if (falconS2_32.length != 32) revert InvalidS2Length(falconS2_32.length);

        // Use address(0) as "to" for burn digest
        bytes32 digest = attestationDigest(sender, address(0), amount, quantumInputHash, nonce, deadline);

        bool valid = IZKNOXEthFalcon(s.falconVerifier).verify(
            abi.encodePacked(digest),
            falconSalt40,
            _toMemoryArray(falconS2_32),
            _getAttestorNtth(s)
        );
        if (!valid) revert FalconVerificationFailed();

        s.pqAttestationNonce[sender] = nonce + 1;

        emit FalconAttestationVerified(sender, address(0), amount, nonce, quantumInputHash);
        return true;
    }

    /// @notice Internal Falcon approval
    function approveWithFalconInternal(
        address sender,
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32
    ) internal returns (bool) {
        AppStorage storage s = LibAppStorage.appStorage();

        if (spender == address(0)) revert ZeroRecipient();
        if (block.timestamp > deadline) revert AttestationExpired();
        requireAttestorOnlyAllowed(s, sender);

        uint256 expectedNonce = s.pqAttestationNonce[sender];
        if (nonce != expectedNonce) revert InvalidNonce(expectedNonce, nonce);
        if (falconSalt40.length != 40) revert InvalidSaltLength(falconSalt40.length);
        if (falconS2_32.length != 32) revert InvalidS2Length(falconS2_32.length);

        bytes32 digest = approvalDigest(sender, spender, amount, quantumInputHash, nonce, deadline);

        bool valid = IZKNOXEthFalcon(s.falconVerifier).verify(
            abi.encodePacked(digest),
            falconSalt40,
            _toMemoryArray(falconS2_32),
            _getAttestorNtth(s)
        );
        if (!valid) revert FalconVerificationFailed();

        s.pqAttestationNonce[sender] = nonce + 1;
        return true;
    }

    // =========================================================================
    // FALCON GOVERNANCE HELPERS
    // =========================================================================

    /// @notice EIP-712 domain separator for governance
    function govDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(GOV_EIP712_DOMAIN_TYPEHASH, GOV_NAME_HASH, GOV_VERSION_HASH, block.chainid, address(this))
        );
    }

    /// @notice Compute governance action digest
    function governanceDigest(
        address signer,
        bytes32 actionHash,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(GOV_ACTION_TYPEHASH, signer, actionHash, nonce, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", govDomainSeparator(), structHash));
    }

    /// @notice Verify Falcon governance attestation
    function requireFalconGovernance(
        address signer,
        string memory action,
        bytes memory payload,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2
    ) internal {
        AppStorage storage s = LibAppStorage.appStorage();

        if (!s.governanceFalconInitialized) revert GovernanceNotInitialized();
        if (block.timestamp > deadline) revert GovernanceAttestationExpired();

        uint256 expectedNonce = s.governanceNonce[signer];
        if (nonce != expectedNonce) revert GovernanceInvalidNonce(expectedNonce, nonce);
        if (falconSalt40.length != 40) revert GovernanceInvalidSaltLength(falconSalt40.length);
        if (falconS2.length != 32) revert GovernanceInvalidS2Length(falconS2.length);

        bytes32 actionHash = keccak256(abi.encodePacked(action, payload));
        bytes32 digest = governanceDigest(signer, actionHash, nonce, deadline);

        bool valid = IZKNOXEthFalcon(s.governanceFalconVerifier).verify(
            abi.encodePacked(digest),
            falconSalt40,
            _govToMemoryArray(falconS2),
            _getGovAttestorNtth(s)
        );
        if (!valid) revert GovernanceFalconVerificationFailed();

        s.governanceNonce[signer] = nonce + 1;
        emit GovernanceFalconVerified(signer, actionHash, nonce);
    }

    // =========================================================================
    // ARRAY CONVERSION HELPERS
    // =========================================================================

    function _toMemoryArray(uint256[] calldata arr) internal pure returns (uint256[] memory) {
        uint256[] memory result = new uint256[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) {
            result[i] = arr[i];
        }
        return result;
    }

    function _getAttestorNtth(AppStorage storage s) internal view returns (uint256[] memory) {
        uint256[] memory result = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            result[i] = s.attestorNtth[i];
        }
        return result;
    }

    function _govToMemoryArray(uint256[] calldata arr) internal pure returns (uint256[] memory) {
        uint256[] memory result = new uint256[](32);
        for (uint256 i = 0; i < 32 && i < arr.length; i++) {
            result[i] = arr[i];
        }
        return result;
    }

    function _getGovAttestorNtth(AppStorage storage s) internal view returns (uint256[] memory) {
        uint256[] memory result = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            result[i] = s.governanceAttestorNtth[i];
        }
        return result;
    }

    /// @notice Split a packed Falcon signature into salt and s2 components
    function splitFalconSig(bytes calldata falconSig)
        internal
        pure
        returns (bytes memory salt, uint256[] memory s2)
    {
        uint256 expectedLength = 40 + 32 * 32;
        require(falconSig.length == expectedLength, "Invalid Falcon signature length");

        salt = new bytes(40);
        for (uint256 i = 0; i < 40; i++) {
            salt[i] = falconSig[i];
        }

        s2 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            uint256 offset = 40 + i * 32;
            uint256 value;
            assembly {
                value := calldataload(add(falconSig.offset, offset))
            }
            s2[i] = value;
        }
    }
}
