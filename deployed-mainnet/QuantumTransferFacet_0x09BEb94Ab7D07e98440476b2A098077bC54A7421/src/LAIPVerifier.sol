// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title LAIPVerifier (Stub)
 * @notice Simplified stub for backward compatibility
 * @dev Full LAIP verification has been moved off-chain to the Falcon attestation server.
 *      This stub provides type definitions and structural-only checks.
 *      For quantum-resistant transfers, use LemnicoinFalcon with Falcon attestation.
 */
library LAIPVerifier {
    // LAIP signature structure
    struct LAIPSignature {
        bytes Rx; // R point x-coordinate
        bytes Ry; // R point y-coordinate
        bytes s;  // Schnorr response
    }

    // LAIP public key structure
    struct LAIPPublicKey {
        bytes Qx;  // Public key point x-coordinate
        bytes Qy;  // Public key point y-coordinate
        bytes P0x; // Base point x-coordinate
        bytes P0y; // Base point y-coordinate
        bytes a;   // Domain parameter a
        bytes p;   // Domain parameter p (prime modulus)
        uint256 coordSize;
    }

    /**
     * @notice Decode packed bytes into LAIPSignature struct
     * @dev Format: Rx || Ry || s (coordSize*2 + sSize bytes)
     */
    function decodeSignature(bytes memory packed) internal pure returns (LAIPSignature memory) {
        // Detect coordinate size from packed length
        // 3072-bit: coordSize=384, packed = 384*2 + 417 = 1185
        // 2048-bit: coordSize=256, packed = 256*2 + 289 = 801
        // 1024-bit: coordSize=128, packed = 128*2 + 161 = 417

        uint256 coordSize;
        uint256 sSize;

        if (packed.length >= 1185) {
            coordSize = 384;
            sSize = packed.length - 768;
        } else if (packed.length >= 801) {
            coordSize = 256;
            sSize = packed.length - 512;
        } else if (packed.length >= 417) {
            coordSize = 128;
            sSize = packed.length - 256;
        } else {
            revert("LAIPVerifier: invalid signature length");
        }

        bytes memory Rx = new bytes(coordSize);
        bytes memory Ry = new bytes(coordSize);
        bytes memory s = new bytes(sSize);

        for (uint256 i = 0; i < coordSize; i++) {
            Rx[i] = packed[i];
            Ry[i] = packed[coordSize + i];
        }

        for (uint256 i = 0; i < sSize; i++) {
            s[i] = packed[coordSize * 2 + i];
        }

        return LAIPSignature({Rx: Rx, Ry: Ry, s: s});
    }

    /**
     * @notice Structural-only verification (format checks, no cryptographic verification)
     * @dev Use for binding when JS has already verified the full signature
     */
    function verifyStructuralOnly(
        LAIPSignature memory signature,
        LAIPPublicKey memory publicKey
    ) internal pure returns (bool) {
        // Check that signature components are non-empty
        if (signature.Rx.length == 0 || signature.Ry.length == 0 || signature.s.length == 0) {
            return false;
        }

        // Check that signature R coordinates match public key coordinate size
        uint256 coordSize = publicKey.coordSize;
        if (coordSize == 0) {
            coordSize = publicKey.Qx.length;
        }

        if (signature.Rx.length != coordSize || signature.Ry.length != coordSize) {
            return false;
        }

        // Check that public key has valid coordinates
        if (publicKey.Qx.length != coordSize || publicKey.Qy.length != coordSize) {
            return false;
        }

        return true;
    }

    /**
     * @notice Full verification (DEPRECATED - use Falcon attestation)
     * @dev For quantum-resistant transfers, use LemnicoinFalcon.transferWithFalconAttestation()
     *      On-chain LAIP verification has been moved to the EC2 attestation server.
     */
    function verify(
        LAIPSignature memory /* signature */,
        bytes memory /* message */,
        LAIPPublicKey memory /* publicKey */
    ) internal pure returns (bool) {
        // DEPRECATED: Full on-chain LAIP verification is no longer supported
        // Use the Falcon attestation system instead:
        // 1. Sign with LAIP + ML-DSA client-side
        // 2. Submit to EC2 attestor for verification
        // 3. Attestor signs with Falcon-512
        // 4. Submit Falcon attestation to LemnicoinFalcon contract
        revert("LAIPVerifier: use Falcon attestation for quantum-resistant transfers");
    }

    /**
     * @notice Lightweight verification (DEPRECATED)
     */
    function verifyLightweight(
        LAIPSignature memory /* signature */,
        LAIPPublicKey memory /* publicKey */
    ) internal pure returns (bool) {
        revert("LAIPVerifier: use Falcon attestation for quantum-resistant transfers");
    }
}
