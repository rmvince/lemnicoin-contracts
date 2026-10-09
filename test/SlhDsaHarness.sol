// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {SlhDsaSha2_128s} from "../crypto/SlhDsaSha2_128s.sol";
import {SlhDsaSha2_128sFast} from "../crypto/SlhDsaSha2_128sFast.sol";

/// @notice Test-only wrapper to call the SLH-DSA verifier and measure gas.
contract SlhDsaHarness {
    bytes32 internal constant LOS_COMMITMENT =
        0x5011820df0d8c8de5cee136edec7512fdb2ae279a33e7b25a52192e7931e04bb;

    function verify(bytes memory pk, bytes memory message, bytes memory sig) external view returns (bool) {
        return SlhDsaSha2_128s.verify(pk, message, sig);
    }

    /// The optimized implementation, side by side, so tests can assert byte-for-byte agreement.
    function verifyFast(bytes calldata pk, bytes calldata message, bytes calldata sig) external view returns (bool) {
        return SlhDsaSha2_128sFast.verify(pk, message, sig);
    }

    /// Mirrors LAIPV3TransferFacet._muTrustless so a test can prove client/chain agreement.
    function muTrustless(bytes32 m, bytes32 curveHash, uint256 nonce) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(m, curveHash, bytes32(nonce), LOS_COMMITMENT));
    }
}
