// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {AppStorage, MAX_SESSION_DURATION, MIN_SESSION_DURATION, LibAppStorage} from "../libraries/LibAppStorage.sol";
import {LibLemnicoin, HolderFalconSig} from "../libraries/LibLemnicoin.sol";
import {LibERC20} from "../libraries/LibERC20.sol";
import "../../crypto/LAIPOnCurve.sol";
import "../../falcon/IZKNOXEthFalcon.sol";
import {LibSlhEconomics} from "../libraries/LibSlhEconomics.sol";

error InvalidCEXAddress();
error InvalidSessionDuration();
error SessionDeadlineExpired();
error SessionNonceMismatch(uint256 expected, uint256 provided);
error InvalidSessionSalt();
error InvalidSessionS2();
error SessionFalconVerificationFailed();
error SessionNotFound();
error SessionExpired();
error SessionNotActive();

/// @title SessionFacet — Per-user CEX/DEX session management
/// @notice Handles createCexSession, revokeCexSession, and session queries.
contract SessionFacet is Modifiers {

    event CexSessionCreated(address indexed user, address indexed cexAddress, uint256 expiry, uint256 nonce);
    event CexSessionRevoked(address indexed user, address indexed cexAddress);
    event SessionTransfer(address indexed from, address indexed to, uint256 amount);

    bytes32 private constant SESSION_TYPEHASH = keccak256(
        "PQSession(address user,address cexAddress,uint256 duration,bytes32 quantumInputHash,uint256 nonce,uint256 deadline)"
    );

    // =========================================================================
    // CREATE SESSION
    // =========================================================================

    /// @notice Open a CEX session, authorised by the attestor's Falcon signature.
    /// @dev A session is a standing right for a third party to receive transfers, so it is an
    ///      authority to move funds and is treated like one: ATTESTOR-ONLY, and therefore
    ///      PERMANENTLY CLOSED for every account. Everyone uses `createCexSessionDual`.
    function createCexSession(
        address cexAddress,
        uint256 duration,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        LAIPOnCurve.LAIPPublicKey calldata laipPk
    ) external whenNotPaused {
        LibSlhEconomics.requireNotV3Downgrade(s, msg.sender); // NO-DOWNGRADE: see LibSlhEconomics
        LibLemnicoin.requireAttestorOnlyAllowed(s, msg.sender);
        bytes32 digest = _sessionPreflight(cexAddress, duration, quantumInputHash, nonce, deadline, laipPk);

        if (falconSalt40.length != 40) revert InvalidSessionSalt();
        if (falconS2_32.length != 32) revert InvalidSessionS2();

        // Verify Falcon signature
        bool valid = IZKNOXEthFalcon(s.falconVerifier).verify(
            abi.encodePacked(digest),
            falconSalt40,
            LibLemnicoin._toMemoryArray(falconS2_32),
            _getAttestorNtth()
        );
        if (!valid) revert SessionFalconVerificationFailed();

        // Consume nonce
        s.pqAttestationNonce[msg.sender] = nonce + 1;

        _openSession(cexAddress, duration, nonce);
    }

    /// @notice The same session, requiring BOTH the attestor's Falcon signature and the user's own.
    function createCexSessionDual(
        address cexAddress,
        uint256 duration,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        HolderFalconSig calldata holderSig,
        LAIPOnCurve.LAIPPublicKey calldata laipPk
    ) external whenNotPaused {
        LibSlhEconomics.requireNotV3Downgrade(s, msg.sender); // NO-DOWNGRADE: see LibSlhEconomics
        bytes32 digest = _sessionPreflight(cexAddress, duration, quantumInputHash, nonce, deadline, laipPk);

        // Deliberately the shared dual helper, which re-checks the deadline and nonce and burns the
        // nonce itself — the session path must not keep its own copy of that logic and drift.
        LibLemnicoin.requireDualFalcon(
            msg.sender, digest, nonce, deadline, falconSalt40, falconS2_32, holderSig
        );

        _openSession(cexAddress, duration, nonce);
    }

    /// @dev Shared validation for both session paths; returns the digest they must both cover.
    function _sessionPreflight(
        address cexAddress,
        uint256 duration,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        LAIPOnCurve.LAIPPublicKey calldata laipPk
    ) internal view returns (bytes32) {
        // LAIP on-chain verification
        LibLemnicoin.requireLaipVerification(msg.sender, laipPk);

        if (cexAddress == address(0)) revert InvalidCEXAddress();
        if (duration < MIN_SESSION_DURATION || duration > MAX_SESSION_DURATION) {
            revert InvalidSessionDuration();
        }
        if (block.timestamp > deadline) revert SessionDeadlineExpired();

        uint256 expectedNonce = s.pqAttestationNonce[msg.sender];
        if (nonce != expectedNonce) revert SessionNonceMismatch(expectedNonce, nonce);

        return _sessionDigest(msg.sender, cexAddress, duration, quantumInputHash, nonce, deadline);
    }

    function _openSession(address cexAddress, uint256 duration, uint256 nonce) internal {
        uint256 expiry = block.timestamp + duration;
        s.userCexSession[msg.sender][cexAddress] = expiry;
        emit CexSessionCreated(msg.sender, cexAddress, expiry, nonce);
    }

    // =========================================================================
    // REVOKE SESSION
    // =========================================================================

    function revokeCexSession(address cexAddress) external {
        if (s.userCexSession[msg.sender][cexAddress] == 0) revert SessionNotFound();
        delete s.userCexSession[msg.sender][cexAddress];
        emit CexSessionRevoked(msg.sender, cexAddress);
    }

    // =========================================================================
    // SESSION TRANSFER
    // =========================================================================

    /// @notice Transfer tokens to a whitelisted CEX address using an active session
    /// @dev No quantum signature required - session was already verified at creation
    ///      Protected by nonReentrant to prevent reentrancy via fee refund (M-04)
    /// @param to The CEX address to transfer to (must have active session)
    /// @param amount The amount of tokens to transfer
    function sessionTransfer(address to, uint256 amount) external payable whenNotPaused nonReentrant returns (bool) {
        // Check session is active
        uint256 expiry = s.userCexSession[msg.sender][to];
        if (expiry == 0) revert SessionNotFound();
        if (block.timestamp > expiry) revert SessionExpired();

        // Collect protocol fee
        LibLemnicoin.collectProtocolFee(amount);

        // Transfer tokens
        LibERC20._transfer(msg.sender, to, amount);

        emit SessionTransfer(msg.sender, to, amount);
        return true;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function getCexSession(address user, address cexAddress)
        external view returns (bool active, uint256 expiry)
    {
        expiry = s.userCexSession[user][cexAddress];
        active = expiry > block.timestamp;
    }

    function getSessionNonce(address user) external view returns (uint256) {
        return s.pqAttestationNonce[user];
    }

    function computeSessionDigest(
        address user, address cexAddress, uint256 duration,
        bytes32 quantumInputHash, uint256 nonce, uint256 deadline
    ) external view returns (bytes32) {
        return _sessionDigest(user, cexAddress, duration, quantumInputHash, nonce, deadline);
    }

    function userCexSession(address user, address cexAddress) external view returns (uint256) {
        return s.userCexSession[user][cexAddress];
    }

    // =========================================================================
    // INTERNAL
    // =========================================================================

    function _sessionDigest(
        address user, address cexAddress, uint256 duration,
        bytes32 quantumInputHash, uint256 nonce, uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(SESSION_TYPEHASH, user, cexAddress, duration, quantumInputHash, nonce, deadline)
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
