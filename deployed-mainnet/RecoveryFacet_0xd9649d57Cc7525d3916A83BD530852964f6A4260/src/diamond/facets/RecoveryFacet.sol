// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {AppStorage, QuantumKeyHashes, LibAppStorage} from "../libraries/LibAppStorage.sol";
import {LibERC20} from "../libraries/LibERC20.sol";
import {LibLemnicoin} from "../libraries/LibLemnicoin.sol";
import {ZeroRecipient, AttestationExpired, InvalidNonce, InvalidSaltLength, InvalidS2Length, FalconVerificationFailed, HolderFalconSig} from "../libraries/LibLemnicoin.sol";
import "../../crypto/LAIPOnCurve.sol";
import "../../falcon/IZKNOXEthFalcon.sol";
import {LibSlhEconomics} from "../libraries/LibSlhEconomics.sol";

error RecoveryFromSelf();
error QuantumKeysNotRegistered();
error QuantumKeyMismatch();
error ZeroAmount();

/// @title RecoveryFacet — Wallet recovery using quantum key hashes
/// @notice Allows recovering LEMNI from a compromised wallet when both
///         wallets share the same quantum key hashes.
contract RecoveryFacet is Modifiers {

    bytes32 private constant RECOVERY_TYPEHASH =
        keccak256("PQRecovery(address from,address recoveredBy,address to,uint256 amount,bytes32 quantumInputHash,uint256 nonce,uint256 deadline)");

    event RecoveryTransferExecuted(
        address indexed from, address indexed recoveredBy, address indexed to, uint256 amount, uint256 nonce
    );

    // =========================================================================
    // RECOVERY TRANSFER
    // =========================================================================

    /// @dev Protected by nonReentrant to prevent reentrancy via fee refund (M-04)
    ///
    ///      ATTESTOR-ONLY and therefore PERMANENTLY CLOSED — use `recoveryTransferDual`. That costs
    ///      the recoverer nothing: recovery already requires proving possession of `from`'s quantum
    ///      keys, which come from the same 48-word seed as `from`'s Falcon key, so whoever can
    ///      legitimately recover can produce `from`'s holder Falcon signature too.
    function recoveryTransfer(
        address from,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        LAIPOnCurve.LAIPPublicKey calldata laipPk
    ) external payable whenNotPaused nonReentrant returns (bool) {
        LibSlhEconomics.requireNotV3DowngradePair(s, from, msg.sender); // NO-DOWNGRADE (both sides)
        // First, so the reason this path refused is unambiguous — and so it costs nothing to find
        // out. The guard is on `from`, the wallet whose balance moves, not on the caller.
        LibLemnicoin.requireAttestorOnlyAllowed(s, from);

        _recoveryPreflight(from, to, amount, laipPk);

        if (block.timestamp > deadline) revert AttestationExpired();

        uint256 expectedNonce = s.pqAttestationNonce[from];
        if (nonce != expectedNonce) revert InvalidNonce(expectedNonce, nonce);
        if (falconSalt40.length != 40) revert InvalidSaltLength(falconSalt40.length);
        if (falconS2_32.length != 32) revert InvalidS2Length(falconS2_32.length);

        bytes32 digest = _recoveryDigest(from, msg.sender, to, amount, quantumInputHash, nonce, deadline);

        bool valid = IZKNOXEthFalcon(s.falconVerifier).verify(
            abi.encodePacked(digest),
            falconSalt40,
            LibLemnicoin._toMemoryArray(falconS2_32),
            _getAttestorNtth()
        );
        if (!valid) revert FalconVerificationFailed();

        s.pqAttestationNonce[from] = nonce + 1;
        LibERC20._transfer(from, to, amount);

        emit RecoveryTransferExecuted(from, msg.sender, to, amount, nonce);
        return true;
    }

    /// @notice The same recovery, requiring BOTH the attestor's Falcon signature and the compromised
    ///         wallet's own over the identical `PQRecovery` digest.
    /// @dev The holder key belongs to `from` — the compromised wallet — not to the caller. That is
    ///      the correct binding: recovery moves `from`'s balance, so it is `from`'s key that must
    ///      authorise it, and the recoverer holds that key precisely because they hold the seed.
    ///      The digest still names `msg.sender` as `recoveredBy`, so a signature obtained for one
    ///      recovery cannot be replayed by a different recoverer.
    function recoveryTransferDual(
        address from,
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
        LibSlhEconomics.requireNotV3DowngradePair(s, from, msg.sender); // NO-DOWNGRADE (both sides)
        _recoveryPreflight(from, to, amount, laipPk);

        bytes32 digest = _recoveryDigest(from, msg.sender, to, amount, quantumInputHash, nonce, deadline);
        LibLemnicoin.requireDualFalcon(from, digest, nonce, deadline, falconSalt40, falconS2_32, holderSig);

        LibERC20._transfer(from, to, amount);

        emit RecoveryTransferExecuted(from, msg.sender, to, amount, nonce);
        return true;
    }

    /// @dev Everything both recovery paths check before they diverge on which signatures they want.
    ///      Extracted so the two entrypoints cannot drift apart — and so the dual variant's extra
    ///      argument does not push either of them past the stack limit.
    function _recoveryPreflight(
        address from,
        address to,
        uint256 amount,
        LAIPOnCurve.LAIPPublicKey calldata laipPk
    ) internal {
        // LAIP on-chain verification against compromised wallet's stored commitment
        LibLemnicoin.requireLaipVerification(from, laipPk);
        LibLemnicoin.collectProtocolFee(amount);

        if (from == msg.sender) revert RecoveryFromSelf();

        QuantumKeyHashes storage fromKeys = s.quantumKeyHashes[from];
        QuantumKeyHashes storage callerKeys = s.quantumKeyHashes[msg.sender];

        if (!fromKeys.registered) revert QuantumKeysNotRegistered();
        if (!callerKeys.registered) revert QuantumKeysNotRegistered();

        if (fromKeys.laipQHash != callerKeys.laipQHash ||
            fromKeys.laipP0Hash != callerKeys.laipP0Hash ||
            fromKeys.mldsaPkHash != callerKeys.mldsaPkHash) {
            revert QuantumKeyMismatch();
        }

        if (to == address(0)) revert ZeroRecipient();
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function canRecoverFrom(address from, address recoveredBy) external view returns (bool) {
        QuantumKeyHashes storage fromKeys = s.quantumKeyHashes[from];
        QuantumKeyHashes storage callerKeys = s.quantumKeyHashes[recoveredBy];

        if (!fromKeys.registered || !callerKeys.registered) return false;

        return (fromKeys.laipQHash == callerKeys.laipQHash &&
                fromKeys.laipP0Hash == callerKeys.laipP0Hash &&
                fromKeys.mldsaPkHash == callerKeys.mldsaPkHash);
    }

    function computeRecoveryDigest(
        address from, address recoveredBy, address to, uint256 amount,
        bytes32 quantumInputHash, uint256 nonce, uint256 deadline
    ) external view returns (bytes32) {
        return _recoveryDigest(from, recoveredBy, to, amount, quantumInputHash, nonce, deadline);
    }

    // =========================================================================
    // INTERNAL
    // =========================================================================

    function _recoveryDigest(
        address from, address recoveredBy, address to, uint256 amount,
        bytes32 quantumInputHash, uint256 nonce, uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(RECOVERY_TYPEHASH, from, recoveredBy, to, amount, quantumInputHash, nonce, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", LibLemnicoin.domainSeparatorV4(), structHash));
    }

    function _getAttestorNtth() internal view returns (uint256[] memory) {
        uint256[] memory result = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            result[i] = s.attestorNtth[i];
        }
        return result;
    }
}
