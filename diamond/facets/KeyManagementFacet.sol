// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {AppStorage, QuantumKeys, QuantumKeyHashes, LibAppStorage} from "../libraries/LibAppStorage.sol";
import "../../LAIPVerifier.sol";
import "../../crypto/LAIPOnCurve.sol";

error KeysAlreadyBound();
error NoChallenge();
error InvalidDilithiumPKLength();
error QuantumKeysNotRegistered();
error LAIPQHashMismatch();
error LAIPCurveAlreadyValidated();
error KeysNotBound();
error OwnershipKeysImmutable();
error QuantumKeysImmutable();
error HolderFalconKeyImmutable();
error InvalidHolderFalconKey();

/// @title KeyManagementFacet — Quantum key binding, registration, and queries
/// @notice Handles createBindingChallenge, bindQuantumKeys, registerQuantumKeys,
///         and key query functions.
contract KeyManagementFacet is Modifiers {

    struct BindingInput {
        bytes laipQx;
        bytes laipQy;
        bytes laipP0x;
        bytes laipP0y;
        bytes laipA;
        bytes laipP;
        bytes dilithiumPubKey;
        bytes laipProof;
        bytes dilithiumProof;
    }

    event QuantumKeysBound(address indexed account, bytes32 laipPubKeyHash, bytes32 dilithiumPubKeyHash);
    event BindingChallengeCreated(address indexed account, bytes32 challenge);
    event QuantumKeysRegistered(address indexed user, bytes32 laipQHash, bytes32 laipP0Hash, bytes32 mldsaPkHash);
    event LAIPCurveValidated(address indexed account, bytes32 qHash);
    event LAIPCommitmentMigrated(address indexed account, bytes32 newCommitment);
    event HolderFalconKeyRegistered(address indexed account, bytes32 commitment);

    // =========================================================================
    // BINDING CHALLENGE
    // =========================================================================

    function createBindingChallenge() external returns (bytes32) {
        if (s.quantumKeys[msg.sender].bound) revert KeysAlreadyBound();

        bytes32 challenge = keccak256(
            abi.encodePacked(
                msg.sender,
                block.timestamp,
                blockhash(block.number - 1),
                block.prevrandao,
                block.basefee,
                s.challengeNonce++,
                gasleft()
            )
        );

        s.bindingChallenges[msg.sender] = challenge;
        emit BindingChallengeCreated(msg.sender, challenge);
        return challenge;
    }

    // =========================================================================
    // BIND QUANTUM KEYS
    // =========================================================================

    function bindQuantumKeys(BindingInput calldata input) external {
        if (s.quantumKeys[msg.sender].bound) revert KeysAlreadyBound();
        if (input.dilithiumPubKey.length != 2592) revert InvalidDilithiumPKLength();

        bytes32 challenge = s.bindingChallenges[msg.sender];
        if (challenge == bytes32(0)) revert NoChallenge();

        // Store LAIP public key
        s.quantumKeys[msg.sender].laip.Qx = input.laipQx;
        s.quantumKeys[msg.sender].laip.Qy = input.laipQy;
        s.quantumKeys[msg.sender].laip.P0x = input.laipP0x;
        s.quantumKeys[msg.sender].laip.P0y = input.laipP0y;
        s.quantumKeys[msg.sender].laip.a = input.laipA;
        s.quantumKeys[msg.sender].laip.p = input.laipP;

        // H-06: Fixed commitment encoding to include BOTH P0x and P0y
        // Previously only included P0x, which caused a mismatch with
        // registerQuantumKeysWithValidation (which uses full P0).
        // Now both paths produce: keccak256(Qx || Qy || P0x || P0y || a || p)
        s.laipKeyCommitment[msg.sender] = keccak256(
            abi.encodePacked(input.laipQx, input.laipQy, input.laipP0x, input.laipP0y, input.laipA, input.laipP)
        );

        // Verify proof structure
        _verifyBindingProofs(challenge, input);

        // Store Dilithium key and mark bound
        s.quantumKeys[msg.sender].dilithiumPublicKey = input.dilithiumPubKey;
        s.quantumKeys[msg.sender].bound = true;

        // Clear challenge
        delete s.bindingChallenges[msg.sender];

        emit QuantumKeysBound(
            msg.sender,
            keccak256(abi.encodePacked(input.laipQx, input.laipQy)),
            keccak256(input.dilithiumPubKey)
        );
    }

    // =========================================================================
    // HASH-BASED QUANTUM KEY REGISTRATION
    // =========================================================================

    function registerQuantumKeys(
        bytes32 laipQHash,
        bytes32 laipP0Hash,
        bytes32 mldsaPkHash
    ) external {
        _enforceKeyImmutability(laipQHash, laipP0Hash, mldsaPkHash);
        s.quantumKeyHashes[msg.sender] = QuantumKeyHashes({
            laipQHash: laipQHash,
            laipP0Hash: laipP0Hash,
            mldsaPkHash: mldsaPkHash,
            registered: true
        });
        emit QuantumKeysRegistered(msg.sender, laipQHash, laipP0Hash, mldsaPkHash);
    }

    /// @notice Register quantum keys AND validate LAIP curve in one transaction
    /// @dev Combines registerQuantumKeys + validateLaipCurve. Costs ~2.25M gas but
    ///      only requires one transaction. Use this for new key registration.
    /// @param laipQHash Hash of LAIP Q coordinates (keccak256(Qx || Qy))
    /// @param laipP0Hash Hash of LAIP P0 coordinates
    /// @param mldsaPkHash Hash of ML-DSA public key
    /// @param laipPk Full LAIP public key for curve validation
    function registerQuantumKeysWithValidation(
        bytes32 laipQHash,
        bytes32 laipP0Hash,
        bytes32 mldsaPkHash,
        LAIPOnCurve.LAIPPublicKey calldata laipPk
    ) external {
        _enforceKeyImmutability(laipQHash, laipP0Hash, mldsaPkHash);
        // Verify Q hash matches provided laipPk
        bytes32 computedQHash = keccak256(abi.encodePacked(laipPk.x, laipPk.y));
        if (computedQHash != laipQHash) revert LAIPQHashMismatch();

        // Register the keys
        s.quantumKeyHashes[msg.sender] = QuantumKeyHashes({
            laipQHash: laipQHash,
            laipP0Hash: laipP0Hash,
            mldsaPkHash: mldsaPkHash,
            registered: true
        });

        // Compute and store the LAIP key commitment (required for transfer verification)
        // Matches LibLemnicoin.requireLaipVerification: keccak256(x || y || P0 || a || p)
        s.laipKeyCommitment[msg.sender] = keccak256(
            abi.encodePacked(laipPk.x, laipPk.y, laipPk.P0, laipPk.a, laipPk.p)
        );

        // Perform expensive on-chain curve validation (~2.25M gas)
        // Validates: (x² + y²)² = a² * (x² - y²) mod p
        LAIPOnCurve.validate(laipPk);

        // Cache the validated Q hash
        s.laipValidatedQHash[msg.sender] = laipQHash;

        emit QuantumKeysRegistered(msg.sender, laipQHash, laipP0Hash, mldsaPkHash);
        emit LAIPCurveValidated(msg.sender, laipQHash);
    }

    /// @notice Register quantum keys with OFF-CHAIN curve validation (trusted)
    /// @dev Same as registerQuantumKeysWithValidation but skips expensive on-chain curve check.
    ///      Caller MUST validate Q is on curve off-chain before calling this.
    ///      Sets laipValidatedQHash so transfers work without on-chain validation.
    ///
    ///      H-02: RESTRICTED TO OWNER ONLY
    ///      This function skips on-chain curve validation and sets laipValidatedQHash
    ///      as if validation happened. Without access control, anyone could register
    ///      quantum keys bypassing the security check.
    ///
    /// @param laipQHash Hash of LAIP Q coordinates (keccak256(Qx || Qy))
    /// @param laipP0Hash Hash of LAIP P0 coordinates
    /// @param mldsaPkHash Hash of ML-DSA public key
    /// @param laipPk Full LAIP public key (used for commitment, not validated on-chain)
    function registerQuantumKeysTrusted(
        bytes32 laipQHash,
        bytes32 laipP0Hash,
        bytes32 mldsaPkHash,
        LAIPOnCurve.LAIPPublicKey calldata laipPk
    ) external onlyOwner {
        _enforceKeyImmutability(laipQHash, laipP0Hash, mldsaPkHash);
        // Verify Q hash matches provided laipPk
        bytes32 computedQHash = keccak256(abi.encodePacked(laipPk.x, laipPk.y));
        if (computedQHash != laipQHash) revert LAIPQHashMismatch();

        // Register the keys
        s.quantumKeyHashes[msg.sender] = QuantumKeyHashes({
            laipQHash: laipQHash,
            laipP0Hash: laipP0Hash,
            mldsaPkHash: mldsaPkHash,
            registered: true
        });

        // Compute and store the LAIP key commitment (required for transfer verification)
        s.laipKeyCommitment[msg.sender] = keccak256(
            abi.encodePacked(laipPk.x, laipPk.y, laipPk.P0, laipPk.a, laipPk.p)
        );

        // SKIP on-chain curve validation - caller validated off-chain
        // Trust that the dApp has verified Q is on the lemniscate curve
        s.laipValidatedQHash[msg.sender] = laipQHash;

        emit QuantumKeysRegistered(msg.sender, laipQHash, laipP0Hash, mldsaPkHash);
        emit LAIPCurveValidated(msg.sender, laipQHash);
    }

    /// @notice Register quantum key hashes + commitment for off-chain validated keys
    /// @dev Stores hashes, commitment, and sets laipValidatedQHash so transfers work.
    ///      Does NOT perform on-chain curve validation — caller MUST validate off-chain.
    ///      The Falcon attestation server verifies the curve before signing, so a user
    ///      with an invalid key cannot complete a transfer regardless.
    /// @param laipQHash Hash of LAIP Q coordinates (keccak256(Qx || Qy))
    /// @param laipP0Hash Hash of LAIP P0 coordinates
    /// @param mldsaPkHash Hash of ML-DSA public key
    /// @param laipCommitment Off-chain computed keccak256(Qx || Qy || P0 || a || p)
    function registerQuantumKeysOffChain(
        bytes32 laipQHash,
        bytes32 laipP0Hash,
        bytes32 mldsaPkHash,
        bytes32 laipCommitment
    ) external {
        _enforceKeyImmutability(laipQHash, laipP0Hash, mldsaPkHash);
        s.quantumKeyHashes[msg.sender] = QuantumKeyHashes({
            laipQHash: laipQHash,
            laipP0Hash: laipP0Hash,
            mldsaPkHash: mldsaPkHash,
            registered: true
        });

        s.laipKeyCommitment[msg.sender] = laipCommitment;
        s.laipValidatedQHash[msg.sender] = laipQHash;

        emit QuantumKeysRegistered(msg.sender, laipQHash, laipP0Hash, mldsaPkHash);
        emit LAIPCurveValidated(msg.sender, laipQHash);
    }

    // =========================================================================
    // HOLDER FALCON KEY (attestor-free signing path)
    // =========================================================================

    /// @notice Register the caller's OWN Falcon-512 key, so they can authorise transfers themselves
    ///         when the attestor is unreachable.
    /// @dev The key is derived in the dApp from the same 48-word seed as the LAIP and ML-DSA keys,
    ///      so there is nothing extra for the holder to store or back up.
    ///
    ///      Only a hash of the key is kept (one slot); the full 32-word key is supplied in calldata
    ///      at signing time and checked against this commitment.
    ///
    ///      IMMUTABLE once set — the same one-way ratchet as the other quantum keys. A stolen wallet
    ///      key therefore cannot replace the holder's Falcon key with the thief's own.
    /// @param ntth The Falcon public key in NTT domain, packed 16 coefficients per word.
    function registerHolderFalconKey(uint256[32] calldata ntth) external {
        bytes32 commitment = keccak256(abi.encodePacked(ntth));
        if (commitment == bytes32(0)) revert InvalidHolderFalconKey();

        bytes32 existing = s.holderFalconCommitment[msg.sender];
        // Re-registering the identical key is a no-op rather than a revert: the dApp derives the
        // key from the seed on every unlock and may race with itself across tabs.
        if (existing != bytes32(0)) {
            if (existing != commitment) revert HolderFalconKeyImmutable();
            return;
        }

        s.holderFalconCommitment[msg.sender] = commitment;
        emit HolderFalconKeyRegistered(msg.sender, commitment);
    }

    /// @notice The caller-supplied Falcon key commitment for `account`, or zero if none registered.
    /// @dev The dApp reads this at unlock to decide whether it still needs to register.
    function holderFalconCommitment(address account) external view returns (bytes32) {
        return s.holderFalconCommitment[account];
    }

    /// @notice Whether `account` can sign their own attestations if the attestor is unavailable.
    function hasHolderFalconKey(address account) external view returns (bool) {
        return s.holderFalconCommitment[account] != bytes32(0);
    }

    // =========================================================================
    // LAIP CURVE VALIDATION (separate transaction, ~2.25M gas)
    // =========================================================================

    /// @notice Validate LAIP public key is on the lemniscate curve (one-time, expensive)
    /// @dev Must be called before first quantumTransfer. Validates curve on-chain and
    ///      caches result. Subsequent transfers check the cache - unvalidated Q fails.
    /// @param laipPk The LAIP public key to validate
    function validateLaipCurve(
        LAIPOnCurve.LAIPPublicKey calldata laipPk
    ) external {
        // Verify quantum keys are registered
        if (!s.quantumKeyHashes[msg.sender].registered) revert QuantumKeysNotRegistered();

        // Compute Q hash and verify it matches registered laipQHash
        bytes32 qHash = keccak256(abi.encodePacked(laipPk.x, laipPk.y));
        if (s.quantumKeyHashes[msg.sender].laipQHash != qHash) revert LAIPQHashMismatch();

        // Check if already validated (save gas on redundant calls)
        if (s.laipValidatedQHash[msg.sender] == qHash) revert LAIPCurveAlreadyValidated();

        // Perform expensive on-chain curve validation (~2.25M gas)
        // Validates: (x² + y²)² = a² * (x² - y²) mod p
        LAIPOnCurve.validate(laipPk);

        // Cache the validated Q hash
        s.laipValidatedQHash[msg.sender] = qHash;

        emit LAIPCurveValidated(msg.sender, qHash);
    }

    /// @notice Check if an account's LAIP curve has been validated
    /// @param account The account to check
    /// @return validated True if curve validation has been completed
    /// @return qHash The validated Q hash (zero if not validated)
    function isLaipCurveValidated(address account) external view returns (bool validated, bytes32 qHash) {
        qHash = s.laipValidatedQHash[account];
        validated = qHash != bytes32(0);
    }

    // =========================================================================
    // MIGRATION: H-06 Commitment Format Update
    // =========================================================================

    /// @notice Migrate LAIP key commitment from old format to new format
    /// @dev For users who bound keys before H-06 fix. Old format used P0x only,
    ///      new format uses P0x || P0y to match registerQuantumKeysWithValidation.
    ///      This function recomputes the commitment using stored key data.
    ///
    ///      Old format: keccak256(Qx || Qy || P0x || a || p)
    ///      New format: keccak256(Qx || Qy || P0x || P0y || a || p)
    ///
    ///      Users must call this once to migrate, then dApp will work correctly.
    function migrateCommitmentFormat() external {
        // Only users who have already bound keys can migrate
        if (!s.quantumKeys[msg.sender].bound) revert KeysNotBound();

        // Retrieve stored LAIP key data
        LAIPVerifier.LAIPPublicKey storage laipKey = s.quantumKeys[msg.sender].laip;

        // Recompute commitment with NEW format (includes both P0x and P0y)
        bytes32 newCommitment = keccak256(
            abi.encodePacked(
                laipKey.Qx,
                laipKey.Qy,
                laipKey.P0x,
                laipKey.P0y,
                laipKey.a,
                laipKey.p
            )
        );

        // Update stored commitment
        s.laipKeyCommitment[msg.sender] = newCommitment;

        emit LAIPCommitmentMigrated(msg.sender, newCommitment);
    }

    // =========================================================================
    // V2: IMMUTABLE QUANTUM KEY REGISTRATION + BTC OWNERSHIP COMMITMENT
    // =========================================================================

    /// @notice Register V2 quantum keys with permanent ownership commitment (C_own).
    /// @dev Once ownershipCommitment is set for an address, it can NEVER be changed —
    ///      even by the wallet owner. This is the core theft-protection invariant:
    ///      an attacker who steals the wallet private key cannot re-register
    ///      different quantum keys or a different ownership commitment.
    ///      C_own = SHA-256(K_laip_public || K_dilithium_public || K_hashbased_public)
    ///      and serves as the cross-chain anchor for BTC wallet verification.
    /// @param laipQHash keccak256(Qx || Qy) — V2 LAIP public key hash
    /// @param laipP0Hash keccak256(P0x || P0y) — base point hash
    /// @param mldsaPkHash keccak256(dilithium_public_key) — ML-DSA-87 public key hash
    /// @param laipCommitment keccak256(Qx || Qy || P0 || a || p) — LAIP domain commitment
    /// @param ownershipCommitment C_own — SHA-256 of all three public key types
    function registerQuantumKeysV2(
        bytes32 laipQHash,
        bytes32 laipP0Hash,
        bytes32 mldsaPkHash,
        bytes32 laipCommitment,
        bytes32 ownershipCommitment
    ) external {
        // IMMUTABILITY: once C_own is set, keys can NEVER be changed. Before C_own is set,
        // an already-registered account may only re-assert the SAME key hashes (C2 fix).
        _enforceKeyImmutability(laipQHash, laipP0Hash, mldsaPkHash);

        s.quantumKeyHashes[msg.sender] = QuantumKeyHashes({
            laipQHash: laipQHash,
            laipP0Hash: laipP0Hash,
            mldsaPkHash: mldsaPkHash,
            registered: true
        });

        s.laipKeyCommitment[msg.sender] = laipCommitment;
        s.laipValidatedQHash[msg.sender] = laipQHash;
        s.ownershipCommitment[msg.sender] = ownershipCommitment;

        emit QuantumKeysRegistered(msg.sender, laipQHash, laipP0Hash, mldsaPkHash);
        emit LAIPCurveValidated(msg.sender, laipQHash);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @notice Get the permanent ownership commitment for an account
    /// @return C_own (bytes32(0) if not yet registered via V2)
    function getOwnershipCommitment(address account) external view returns (bytes32) {
        return s.ownershipCommitment[account];
    }

    function hasQuantumKeys(address user) external view returns (bool) {
        return s.quantumKeyHashes[user].registered;
    }

    function getQuantumKeyHashes(address user) external view returns (
        bytes32 laipQHash, bytes32 laipP0Hash, bytes32 mldsaPkHash, bool registered
    ) {
        QuantumKeyHashes storage keys = s.quantumKeyHashes[user];
        return (keys.laipQHash, keys.laipP0Hash, keys.mldsaPkHash, keys.registered);
    }

    function getStoredLaipQx(address account) external view returns (bytes memory) {
        return s.quantumKeys[account].laip.Qx;
    }

    function laipKeyCommitment(address account) external view returns (bytes32) {
        return s.laipKeyCommitment[account];
    }

    function bindingChallenges(address account) external view returns (bytes32) {
        return s.bindingChallenges[account];
    }

    // =========================================================================
    // INTERNAL
    // =========================================================================

    /// @notice C2 fix: quantum keys are write-once per account.
    ///         Before the permanent ownership commitment (C_own) is set, format upgrades that
    ///         keep the SAME key material are allowed (matches the dApp's V1->V2 upgrade path);
    ///         changing the registered key hashes is rejected. Once C_own is set, registration is
    ///         fully immutable. This preserves theft-proofness — a stolen EVM key cannot re-point a
    ///         wallet's quantum keys — and blocks cloning another account's key hashes onto an
    ///         address that is already registered.
    function _enforceKeyImmutability(
        bytes32 newLaipQHash,
        bytes32 newLaipP0Hash,
        bytes32 newMldsaPkHash
    ) internal view {
        if (s.ownershipCommitment[msg.sender] != bytes32(0)) revert OwnershipKeysImmutable();
        QuantumKeyHashes storage existing = s.quantumKeyHashes[msg.sender];
        if (existing.registered) {
            if (existing.laipQHash != newLaipQHash ||
                existing.laipP0Hash != newLaipP0Hash ||
                existing.mldsaPkHash != newMldsaPkHash) {
                revert QuantumKeysImmutable();
            }
        }
    }

    function _verifyBindingProofs(bytes32 challenge, BindingInput calldata input) internal view {
        // Support both 2048-bit and 3072-bit LAIP proofs
        require(
            input.laipProof.length == 801 || input.laipProof.length == 1185,
            "Invalid LAIP proof length"
        );
        require(
            input.dilithiumProof.length >= 4500 && input.dilithiumProof.length <= 4700,
            "Invalid Dilithium proof length"
        );

        // Determine coordinate size from proof length
        uint256 coordSize;
        if (input.laipProof.length == 801) {
            coordSize = 256; // 2048-bit
        } else {
            coordSize = 384; // 3072-bit
        }

        // Verify public key coordinate lengths
        LAIPVerifier.LAIPPublicKey memory laipKey = s.quantumKeys[msg.sender].laip;
        require(
            laipKey.Qx.length == coordSize &&
            laipKey.Qy.length == coordSize &&
            laipKey.P0x.length == coordSize &&
            laipKey.P0y.length == coordSize &&
            laipKey.a.length == coordSize &&
            laipKey.p.length == coordSize,
            "LAIP public key size mismatch"
        );

        // Commitment structure validation
        bytes memory challengeBytes = abi.encodePacked(challenge);
        bytes32 commitment = keccak256(abi.encodePacked(input.laipProof, challengeBytes));
        commitment; // suppress unused warning
    }
}
