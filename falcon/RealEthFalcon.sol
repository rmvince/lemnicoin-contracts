// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./IZKNOXEthFalcon.sol";

// Import ETHFALCON library components
import "../../lib/ETHFALCON/src/ZKNOX_common.sol";
import "../../lib/ETHFALCON/src/ZKNOX_falcon_utils.sol";
import "../../lib/ETHFALCON/src/ZKNOX_falcon_core.sol";
import "../../lib/ETHFALCON/src/ZKNOX_HashToPoint.sol";

/**
 * @title RealEthFalcon
 * @notice Real ETHFALCON Falcon-512 signature verifier
 * @dev Uses ZKNOX's ETHFALCON library for actual cryptographic verification
 *
 * Gas cost: ~1.6-1.8M for verification
 *
 * This contract provides real Falcon-512 signature verification.
 * The verification uses:
 * - Keccak256-based hash-to-point (RIP variant, compatible with Python ETHFALCON signer)
 * - NTT-domain polynomial operations
 * - Signature norm bound checking
 *
 * See: https://github.com/ZKNoxHQ/ETHFALCON
 */
contract RealEthFalcon is IZKNOXEthFalcon {

    /**
     * @notice Verify a Falcon-512 signature
     * @param h The 32-byte message hash that was signed
     * @param salt 40-byte salt/nonce used in signing
     * @param s2 Signature polynomial (uint256[32] for falcon_S256)
     * @param ntth Public key in NTT domain (uint256[32])
     * @return result True if signature is valid
     */
    function verify(
        bytes memory h,
        bytes memory salt,
        uint256[] memory s2,
        uint256[] memory ntth
    ) external pure override returns (bool result) {
        // M-11 audit fix: Validate message hash length
        // Strictly enforce 32 bytes (keccak256 digest) to reduce misuse risk
        // from other callers/integrations passing non-standard hash lengths
        if (h.length != 32) {
            revert("invalid message hash: expected 32 bytes");
        }

        // Validate salt length (40 bytes required for Falcon-512)
        if (salt.length != 40) {
            revert("invalid salt length");
        }

        // Validate s2 length (signature polynomial)
        if (s2.length != falcon_S256) {
            revert("invalid s2 length");
        }

        // M-10 audit fix: Validate ntth length (public key in NTT domain)
        // Must be exactly 32 uint256 values for Falcon-512
        if (ntth.length != falcon_S256) {
            revert("invalid ntth length");
        }

        // F-03: Validate s2 coefficients are in valid range [0, q-1]
        // This prevents crafted out-of-range coefficients from interacting
        // with NTT multiplication in unexpected ways
        // Note: is_compact=false triggers expansion of the 32-element compact polynomial
        // to 512 individual coefficients before checking each against q
        if (!falcon_checkPolynomialRange(s2, false)) {
            revert("s2 coefficients out of range");
        }

        // Hash the message to polynomial points using Keccak256 (RIP variant)
        // This is compatible with Python ETHFALCON signer using KeccakPRNG
        uint256[] memory hashed = hashToPointRIP(salt, h);

        // Verify using the core Falcon verification
        result = falcon_core(s2, ntth, hashed);

        return result;
    }

    /**
     * @notice Get algorithm identifier
     */
    function algorithm() external pure returns (string memory) {
        return "Falcon-512-RIP";
    }
}
