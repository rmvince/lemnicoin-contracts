// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IZKNOXEthFalcon} from "../falcon/IZKNOXEthFalcon.sol";
import {ILemniAuthority} from "./interfaces/ILemniAuthority.sol";

/// @title LaipV3SatelliteRegistry — LAIP-V3 key registry for chains that have no LEMNI Diamond.
///
/// @notice On Polygon, LemniVaultV6 reads V3 registrations (and the SLH-DSA verifier) from the
///         Diamond. A lockbox on Base / Arbitrum / Optimism / Avalanche cannot call Polygon, so
///         without a registry ON ITS OWN CHAIN it can only ever run at the Falcon floor. This
///         contract is that registry: the same `ILaipV3Registry` surface LemniVaultV6 reads, the
///         same registration entrypoint and AUTH DIGEST the dApp and vault popup already produce —
///         `keccak256(pack("LAIP_V3_REGISTER", block.chainid, account, ...keys...))` is chain-bound
///         but not contract-bound, so the EXISTING client signing works here with only the chain id
///         swapped — and the same theft-proof rule: only the holder's seed-derived Falcon key can
///         register V3 keys, verified against the commitment already held by this chain's
///         LemniVaultAuthority.
///
/// @dev WHAT IS DELIBERATELY DIFFERENT FROM THE DIAMOND'S LAIPV3Facet:
///        - No V1/V2-legacy prerequisite. On Polygon that rule keeps the TokenFacet's plain-ERC20
///          gate closed for V3 wallets; there is no token on satellite chains, so the anchor here
///          is the authority's holderFalconCommitment (which the vault factory already requires
///          via NoWithdrawalCredential before any lockbox exists).
///        - No transfer/approve/session machinery. Lockboxes are the only consumer.
///      WHAT IS DELIBERATELY THE SAME: field validation, the cOwnV3 binding, write-once semantics
///      (identical re-submit is a no-op; any change reverts), and the Falcon authorization flow —
///      byte-compatible with the dApp's ensureLaipV3Registered service and the vault popup's
///      v3_register signing.
///
///      FREEZE-SAFETY: `slhDsaVerifier` at zero means every V6 vault on this chain answers
///      slhRequired()=false and runs at the Falcon floor — registration can never strand funds.
///      Setting the verifier to zero is therefore this chain's emergency relax, mirroring the
///      Diamond's setLaipV3RelaxSlh.
contract LaipV3SatelliteRegistry is Ownable {
    /// @notice The holder's own Falcon signature authorising a registration. Identical layout to
    ///         the Diamond's HolderFalconSig, so one client encoding serves both registries.
    struct HolderFalconSig {
        bytes salt40;
        uint256[] s2_32;
        uint256[] ntth;
    }

    struct LaipV3Keys {
        bytes32 curveHash;
        bytes32 slhdsaPkHash;
        bytes32 mldsaPkHash;
        bytes32 paramId;
        bool registered;
    }

    /// @notice This chain's LemniVaultAuthority: the single source of holder Falcon commitments and
    ///         the chain's ZKNOX Falcon verifier — the same two reads every vault here performs.
    ILemniAuthority public immutable authority;

    /// @notice The chain's SLH-DSA verifier, or zero when the hash-family factor is not enforceable
    ///         here (ILaipV3Registry.slhDsaVerifier). Zero = every V6 vault falls back to the
    ///         Falcon floor; that is the no-lockout guarantee, so changing this is owner-only.
    address public slhDsaVerifier;

    mapping(address => LaipV3Keys) private _keys;
    mapping(address => bytes32) public ownershipCommitmentV3;

    event LaipV3Registered(
        address indexed account, bytes32 curveHash, bytes32 slhdsaPkHash, bytes32 mldsaPkHash, bytes32 paramId
    );
    event LaipV3OwnershipCommitmentSet(address indexed account, bytes32 cOwnV3);
    event SlhDsaVerifierSet(address verifier);

    error ZeroAuthority();
    error LaipV3ZeroHash();
    error LaipV3CommitmentMismatch();
    error LaipV3AlreadyRegistered();
    error LaipV3HolderKeyRequired();
    error InvalidSaltLength(uint256 got);
    error InvalidS2Length(uint256 got);
    error InvalidNtthLength(uint256 got);
    error HolderFalconKeyMismatch();
    error HolderFalconVerificationFailed();

    constructor(address authority_) {
        if (authority_ == address(0)) revert ZeroAuthority();
        authority = ILemniAuthority(authority_);
    }

    // =========================================================================
    // REGISTRATION
    // =========================================================================

    /// @notice The digest the holder's Falcon key must sign — BYTE-IDENTICAL to
    ///         LAIPV3Facet.laipV3AuthDigest, with this chain's id inside, which is what lets the
    ///         unmodified vault popup and dApp produce it. A signature made for one chain is
    ///         worthless on any other; on the same chain a replay can only re-assert the identical
    ///         registration (a no-op), because registration is write-once below.
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

    /// @notice Register the caller's LAIP-V3 keys on this chain, authorised by their holder Falcon
    ///         key. Write-once: re-submitting the IDENTICAL registration is a no-op (multi-tab race
    ///         tolerance); any change reverts LaipV3AlreadyRegistered.
    function registerQuantumKeysV3(
        bytes32 curveHash,
        bytes32 slhdsaPkHash,
        bytes32 mldsaPkHash,
        bytes32 paramId,
        bytes32 cOwnV3,
        HolderFalconSig calldata holderSig
    ) external {
        if (curveHash == bytes32(0) || slhdsaPkHash == bytes32(0) || cOwnV3 == bytes32(0)) {
            revert LaipV3ZeroHash();
        }
        // cOwnV3 must be the real binding of the three key hashes (same order as the Diamond).
        if (cOwnV3 != keccak256(abi.encodePacked(curveHash, mldsaPkHash, slhdsaPkHash))) {
            revert LaipV3CommitmentMismatch();
        }

        // THEFT-PROOF AUTHORIZATION — a stolen EVM key alone cannot pass this. The Falcon key
        // must be the one whose commitment the AUTHORITY holds for msg.sender (registered there
        // by the lazy holder-key flow every lockbox already requires).
        _verifyHolderFalcon(
            msg.sender,
            laipV3AuthDigest(msg.sender, curveHash, slhdsaPkHash, mldsaPkHash, paramId, cOwnV3),
            holderSig
        );

        LaipV3Keys storage k = _keys[msg.sender];
        if (k.registered) {
            if (k.curveHash != curveHash ||
                k.slhdsaPkHash != slhdsaPkHash ||
                k.mldsaPkHash != mldsaPkHash ||
                k.paramId != paramId ||
                ownershipCommitmentV3[msg.sender] != cOwnV3) {
                revert LaipV3AlreadyRegistered();
            }
            return;
        }

        _keys[msg.sender] = LaipV3Keys({
            curveHash: curveHash,
            slhdsaPkHash: slhdsaPkHash,
            mldsaPkHash: mldsaPkHash,
            paramId: paramId,
            registered: true
        });
        ownershipCommitmentV3[msg.sender] = cOwnV3;

        emit LaipV3Registered(msg.sender, curveHash, slhdsaPkHash, mldsaPkHash, paramId);
        emit LaipV3OwnershipCommitmentSet(msg.sender, cOwnV3);
    }

    function _verifyHolderFalcon(address holder, bytes32 digest, HolderFalconSig calldata sig) internal view {
        if (sig.salt40.length != 40) revert InvalidSaltLength(sig.salt40.length);
        if (sig.s2_32.length != 32) revert InvalidS2Length(sig.s2_32.length);
        if (sig.ntth.length != 32) revert InvalidNtthLength(sig.ntth.length);

        bytes32 commitment = authority.holderFalconCommitment(holder);
        if (commitment == bytes32(0)) revert LaipV3HolderKeyRequired();
        if (keccak256(abi.encodePacked(sig.ntth)) != commitment) revert HolderFalconKeyMismatch();

        bool valid = IZKNOXEthFalcon(authority.FALCON_VERIFIER()).verify(
            abi.encodePacked(digest), sig.salt40, sig.s2_32, sig.ntth
        );
        if (!valid) revert HolderFalconVerificationFailed();
    }

    // =========================================================================
    // VIEWS — the ILaipV3Registry surface LemniVaultV6 reads, plus the views the
    // dApp's ensureLaipV3Registered service expects from a registry.
    // =========================================================================

    function getLaipV3Keys(address account) external view returns (
        bytes32 curveHash, bytes32 slhdsaPkHash, bytes32 mldsaPkHash, bytes32 paramId, bool registered
    ) {
        LaipV3Keys storage k = _keys[account];
        return (k.curveHash, k.slhdsaPkHash, k.mldsaPkHash, k.paramId, k.registered);
    }

    function hasLaipV3(address account) external view returns (bool) {
        return _keys[account].registered;
    }

    /// @notice Passthrough so the registration service reads one contract, not two.
    function holderFalconCommitment(address account) external view returns (bytes32) {
        return authority.holderFalconCommitment(account);
    }

    /// @notice Always unregistered: there is no V1/V2 legacy registry on satellite chains. The dApp
    ///         reads this to choose register-vs-migrate and correctly always registers here.
    function getQuantumKeyHashes(address) external pure returns (
        bytes32 laipQHash, bytes32 laipP0Hash, bytes32 mldsaPkHash, bool registered
    ) {
        return (bytes32(0), bytes32(0), bytes32(0), false);
    }

    // =========================================================================
    // ADMIN
    // =========================================================================

    /// @notice Wire (or, in an emergency, un-wire) this chain's SLH-DSA verifier. Zero relaxes
    ///         every V6 vault on this chain to the Falcon floor — the no-lockout lever.
    function setSlhDsaVerifier(address verifier) external onlyOwner {
        slhDsaVerifier = verifier;
        emit SlhDsaVerifierSet(verifier);
    }
}
