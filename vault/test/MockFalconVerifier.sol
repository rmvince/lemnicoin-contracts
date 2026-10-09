// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IZKNOXEthFalcon} from "../../falcon/IZKNOXEthFalcon.sol";

/// @title MockFalconVerifier — controllable stand-in for the deployed ZKNOX ETHFALCON verifier.
/// @notice TEST ONLY. Models the security-relevant property of Falcon verification: a signature
///         is valid ONLY for the exact message (digest) that was signed. We "sign" by registering
///         a digest via authorize(); verify() then returns true only for that exact 32-byte
///         message. Any change to the spend changes the vault's digest, so it is not registered
///         and verification fails — exactly mirroring the real verifier's behavior for the tests
///         that matter (Vuln #1 and Vuln #2). Against the real Diamond this mock is replaced by
///         the live verifier and real attestor signatures; the vault code under test is identical.
contract MockFalconVerifier is IZKNOXEthFalcon {
    /// @dev Registered (attestor-signed) digests.
    mapping(bytes32 => bool) public signed;

    /// @notice Simulate the EC2 attestor signing the given 32-byte digest.
    function authorize(bytes32 digest) external {
        signed[digest] = true;
    }

    /// @notice Simulate revoking / never having signed a digest.
    function deauthorize(bytes32 digest) external {
        signed[digest] = false;
    }

    /// @dev Registered (digest, key) pairs — a signature by one key must not verify under another.
    mapping(bytes32 => bool) public signedByKey;

    /// @notice Simulate a SPECIFIC key signing `digest`. Unlike authorize(), this binds the
    ///         signature to the key, which is what the holder-key path turns on.
    function authorizeFor(bytes32 digest, uint256[32] calldata ntth) external {
        signedByKey[_pair(digest, keccak256(abi.encodePacked(ntth)))] = true;
    }

    function _pair(bytes32 digest, bytes32 keyHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(digest, keyHash));
    }

    /// @inheritdoc IZKNOXEthFalcon
    /// @dev `h` is abi.encodePacked(digest) — 32 bytes. We require a well-formed sig (length
    ///      checks mirror the real interface) and a registered digest.
    function verify(
        bytes memory h,
        bytes memory salt,
        uint256[] memory s2,
        uint256[] memory ntth
    ) external view override returns (bool) {
        if (h.length != 32) return false;
        if (salt.length != 40) return false;
        if (s2.length != 32) return false;
        if (ntth.length != 32) return false;
        bytes32 digest = bytes32(h);

        // Key-agnostic authorisation (v1/v2 tests: "the attestor signed this"), or key-bound
        // authorisation (v3 tests: "THIS key signed this, and no other key will do").
        if (signed[digest]) return true;

        uint256[32] memory key;
        for (uint256 i = 0; i < 32; i++) {
            key[i] = ntth[i];
        }
        return signedByKey[_pair(digest, keccak256(abi.encodePacked(key)))];
    }
}
