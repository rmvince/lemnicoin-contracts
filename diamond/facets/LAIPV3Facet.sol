// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {AppStorage, LaipV3Keys, LibAppStorage} from "../libraries/LibAppStorage.sol";
import {LibLemnicoin, HolderFalconSig} from "../libraries/LibLemnicoin.sol";

error LaipV3AlreadyRegistered();
error LaipV3ZeroHash();
error LaipV3NotRegisteredLegacy();
error LaipV3HolderKeyRequired();
error LaipV3CommitmentMismatch();
error LaipV3RingAccountUnsupported();

/// @title LAIPV3Facet — registration & migration for LAIP-V3 quantum keys
/// @notice ADDITIVE facet. Introduces the isogeny-KEM curve commitment plus the on-chain-verifiable
///         SLH-DSA (LOS/hash-based) public-key hash, and the V3 ownership commitment C_own_v3.
///
///         THEFT-PROOFNESS (critical). V3 registration is authorized by the account's HOLDER FALCON
///         KEY, verified on chain — NOT by the EVM key alone. An attacker who steals only the EVM
///         private key therefore cannot register attacker-controlled V3 keys and drain the wallet via
///         the V3 paths: they cannot produce the holder Falcon signature (it is derived from the seed).
///         This restores the same possession invariant the V2 immutable ratchet provides — the V3 key
///         slot is independent storage, so it needs its own possession proof, which is exactly the
///         holder Falcon signature required here. (The holder Falcon key is the strongest on-chain-
///         verifiable authority in the system; the seed owner registers it lazily on first login.)
///
///         FUND-SAFETY INVARIANTS (never frozen out):
///         1. Writes ONLY new storage (laipV3, ownershipCommitmentV3). NEVER touches quantumKeyHashes,
///            ownershipCommitment (the live BTC anchor), laipKeyCommitment, or holderFalconCommitment.
///            A wallet that adopts V3 always retains its working V1/V2 + dual-Falcon path.
///         2. Legacy `ownershipCommitment` preserved and readable forever; BTC tooling adopts C_own_v3
///            on its own schedule.
///         3. registerHolderFalconKey and the lazy holder-Falcon registration flow are untouched.
///         4. V3 registration is a write-once ratchet (identical re-assert is a no-op; any change reverts).
contract LAIPV3Facet is Modifiers {

    event LaipV3Registered(
        address indexed account, bytes32 curveHash, bytes32 slhdsaPkHash, bytes32 mldsaPkHash, bytes32 paramId
    );
    event LaipV3OwnershipCommitmentSet(address indexed account, bytes32 cOwnV3);

    /// @notice The digest the holder Falcon key must sign to authorize a V3 registration/migration.
    ///         Binds the full V3 key set to this chain and account, so a signature cannot be replayed
    ///         onto a different account, chain, or key set.
    function laipV3AuthDigest(
        address account,
        bytes32 curveHash,
        bytes32 slhdsaPkHash,
        bytes32 mldsaPkHash,
        bytes32 paramId,
        bytes32 cOwnV3
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "LAIP_V3_REGISTER", block.chainid, account, curveHash, slhdsaPkHash, mldsaPkHash, paramId, cOwnV3
        ));
    }

    /// @notice Register (or migrate to) LAIP-V3 keys, authorized by the caller's holder Falcon key.
    /// @dev Write-once. Re-submitting the IDENTICAL registration is a no-op (multi-tab race tolerance);
    ///      any change reverts LaipV3AlreadyRegistered. Requires holderFalconCommitment set and a valid
    ///      Falcon signature over laipV3AuthDigest(...). Same entry point for new and legacy wallets.
    function registerQuantumKeysV3(
        bytes32 curveHash,
        bytes32 slhdsaPkHash,
        bytes32 mldsaPkHash,
        bytes32 paramId,
        bytes32 cOwnV3,
        HolderFalconSig calldata holderSig
    ) external {
        _registerV3(curveHash, slhdsaPkHash, mldsaPkHash, paramId, cOwnV3, holderSig, false);
    }

    /// @notice Explicit migration alias for legacy wallets (requires an existing V1/V2 registration),
    ///         making the upgrade intent auditable on chain. Same theft-proof holder-Falcon authorization.
    function migrateToLaipV3(
        bytes32 curveHash,
        bytes32 slhdsaPkHash,
        bytes32 mldsaPkHash,
        bytes32 paramId,
        bytes32 cOwnV3,
        HolderFalconSig calldata holderSig
    ) external {
        _registerV3(curveHash, slhdsaPkHash, mldsaPkHash, paramId, cOwnV3, holderSig, true);
    }

    function _registerV3(
        bytes32 curveHash,
        bytes32 slhdsaPkHash,
        bytes32 mldsaPkHash,
        bytes32 paramId,
        bytes32 cOwnV3,
        HolderFalconSig calldata holderSig,
        bool requireLegacy
    ) internal {
        if (curveHash == bytes32(0) || slhdsaPkHash == bytes32(0) || cOwnV3 == bytes32(0)) {
            revert LaipV3ZeroHash();
        }
        // Validate the ownership commitment is the real binding of the three key hashes, so a caller
        // cannot register a C_own_v3 that doesn't match the keys it is committing to (data integrity;
        // C_own_v3 is the V3 hash-based-inclusive anchor).
        if (cOwnV3 != keccak256(abi.encodePacked(curveHash, mldsaPkHash, slhdsaPkHash))) {
            revert LaipV3CommitmentMismatch();
        }
        // ADD-ONLY INVARIANT (critical): V3 is a LAYER ON TOP of the V1/V2 registration, never a
        // replacement for it, so V1/V2 registration is required for BOTH entrypoints.
        //
        // This is what keeps the diamond cut purely ADDITIVE. The already-deployed TokenFacet closes
        // the plain-ERC20 gate on `quantumKeyHashes[account].registered`; by guaranteeing that flag
        // is set for every V3 wallet, a V3 wallet is protected by the EXISTING gate and TokenFacet
        // never has to be replaced. Without this, a V3-only wallet would keep an open plain
        // `transfer()` and be drainable by a stolen EVM key despite having registered quantum keys.
        //
        // No practical change to onboarding: the dApp already registers V1/V2 key hashes at unlock
        // (registerQuantumKeysForFalcon) before the holder-Falcon and V3 steps run.
        if (!s.quantumKeyHashes[msg.sender].registered) revert LaipV3NotRegisteredLegacy();
        requireLegacy; // both entrypoints now enforce it; the alias remains for auditability

        // Ring accounts ARE allowed to register V3. They cannot use the single-holder V3
        // entrypoints (requireNotRingAccount closes those to them, correctly — one seed must never
        // satisfy an M-of-N account), so they use RingV3TransferFacet instead: the same member
        // quorum PLUS the SLH-DSA hash-family factor. Without a V3 registration a ring sits in
        // scenario 1 of the grid and keeps its existing Falcon-only ring paths.

        // THEFT-PROOF AUTHORIZATION: the holder Falcon key (from the seed) must authorize these V3 keys.
        // A stolen EVM key alone cannot pass this. holderFalconCommitment must be set first (lazy reg).
        if (s.holderFalconCommitment[msg.sender] == bytes32(0)) revert LaipV3HolderKeyRequired();
        bytes32 authDigest = laipV3AuthDigest(msg.sender, curveHash, slhdsaPkHash, mldsaPkHash, paramId, cOwnV3);
        LibLemnicoin.verifyHolderFalcon(s, msg.sender, authDigest, holderSig);

        LaipV3Keys storage k = s.laipV3[msg.sender];
        if (k.registered) {
            if (k.curveHash != curveHash ||
                k.slhdsaPkHash != slhdsaPkHash ||
                k.mldsaPkHash != mldsaPkHash ||
                k.paramId != paramId ||
                s.ownershipCommitmentV3[msg.sender] != cOwnV3) {
                revert LaipV3AlreadyRegistered();
            }
            return;
        }

        s.laipV3[msg.sender] = LaipV3Keys({
            curveHash: curveHash,
            slhdsaPkHash: slhdsaPkHash,
            mldsaPkHash: mldsaPkHash,
            paramId: paramId,
            registered: true
        });
        s.ownershipCommitmentV3[msg.sender] = cOwnV3;

        emit LaipV3Registered(msg.sender, curveHash, slhdsaPkHash, mldsaPkHash, paramId);
        emit LaipV3OwnershipCommitmentSet(msg.sender, cOwnV3);
    }

    // ===================== VIEWS =====================

    function getLaipV3Keys(address account) external view returns (
        bytes32 curveHash, bytes32 slhdsaPkHash, bytes32 mldsaPkHash, bytes32 paramId, bool registered
    ) {
        LaipV3Keys storage k = s.laipV3[account];
        return (k.curveHash, k.slhdsaPkHash, k.mldsaPkHash, k.paramId, k.registered);
    }

    function hasLaipV3(address account) external view returns (bool) {
        return s.laipV3[account].registered;
    }

    /// @notice C_own_v3 for an account (zero if not registered). Distinct from the legacy
    ///         getOwnershipCommitment(), which remains the live BTC anchor.
    function getOwnershipCommitmentV3(address account) external view returns (bytes32) {
        return s.ownershipCommitmentV3[account];
    }
}
