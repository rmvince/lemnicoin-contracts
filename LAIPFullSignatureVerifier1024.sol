// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "./LAIPBigInt1024.sol";
/**
 * @title LAIPFullSignatureVerifier1024
 * @dev Full LAIP signature verification library for 1024-bit keys
 *
 * Gas-optimized version for on-chain verification.
 * 1024-bit operations are ~8x cheaper than 2048-bit operations.
 *
 * This library performs on-chain verification of LAIP signatures.
 * All point construction is performed off-chain by the signer.
 */
library LAIPFullSignatureVerifier1024 {
    using LAIPBigInt1024 for bytes;
    // 1024-bit = 128 bytes for coordinates
    uint256 constant COORD_SIZE = 128;
    // s field: s = r + e*k where e is 256-bit, k is up to 1024-bit
    // Maximum s is approximately 256 + 1024 = 1280 bits = 160 bytes, +1 for safety
    uint256 constant S_SIZE = 161;
    // Total signature: 128 + 128 + 161 = 417 bytes
    uint256 constant SIG_SIZE = 417;
    struct LAIPSignature {
        bytes Rx; // R point x-coordinate (128 bytes)
        bytes Ry; // R point y-coordinate (128 bytes)
        bytes s;  // Schnorr response (161 bytes max)
    }
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
     * @notice Full LAIP verification for 1024-bit keys
     */
   function verifyLAIP1024Projective(
		LAIPPublicKey calldata pubKey,
		bytes calldata sP0_u,
		bytes calldata sP0_v,
		bytes calldata ReQ_u,
		bytes calldata ReQ_v
	) external view returns (bool) {
		uint256[4] memory p = LAIPBigInt1024.toUint1024(pubKey.p);
		uint256[4] memory sP0u = LAIPBigInt1024.toUint1024(sP0_u);
		uint256[4] memory sP0v = LAIPBigInt1024.toUint1024(sP0_v);
		uint256[4] memory reQu = LAIPBigInt1024.toUint1024(ReQ_u);
		uint256[4] memory reQv = LAIPBigInt1024.toUint1024(ReQ_v);
		// Check: sP0_u * ReQ_v == ReQ_u * sP0_v (mod p)
		return
			_eqUint1024(
				LAIPBigInt1024.modMul(sP0u, reQv, p),
				LAIPBigInt1024.modMul(reQu, sP0v, p)
			);
	}
    /**
     * @dev Decode LAIP signature from bytes
     * Format: Rx (128 bytes) || Ry (128 bytes) || s (33 bytes) = 289 bytes
     */
    function decodeSignature(bytes memory signatureBytes)
        public
        view
        returns (LAIPSignature memory signature)
    {
        require(signatureBytes.length == SIG_SIZE, "LAIPFullSigVerifier1024: signature must be 289 bytes");
        signature.Rx = new bytes(COORD_SIZE);
        for (uint256 i = 0; i < COORD_SIZE; i++) {
            signature.Rx[i] = signatureBytes[i];
        }
        signature.Ry = new bytes(COORD_SIZE);
        for (uint256 i = 0; i < COORD_SIZE; i++) {
            signature.Ry[i] = signatureBytes[COORD_SIZE + i];
        }
        signature.s = new bytes(S_SIZE);
        for (uint256 i = 0; i < S_SIZE; i++) {
            signature.s[i] = signatureBytes[2 * COORD_SIZE + i];
        }
        return signature;
    }
    /**
     * @dev Check if point (x, y) is on the lemniscate curve
     * Equation: (x^2 + y^2)^2 = a^2(x^2 - y^2)
     */
    function isOnCurve(
        bytes memory x,
        bytes memory y,
        bytes memory a,
        bytes memory p
    ) public view returns (bool) {
        bytes memory x2 = LAIPBigInt1024.modExp(x, LAIPBigInt1024.fromUint256(2), p);
        bytes memory y2 = LAIPBigInt1024.modExp(y, LAIPBigInt1024.fromUint256(2), p);
        bytes memory sum = LAIPBigInt1024.modAdd(x2, y2, p);
        if (LAIPBigInt1024.isZero(sum) || LAIPBigInt1024.eq(x2, y2)) {
            return false;
        }
        bytes memory left = LAIPBigInt1024.modExp(sum, LAIPBigInt1024.fromUint256(2), p);
        bytes memory a2 = LAIPBigInt1024.modExp(a, LAIPBigInt1024.fromUint256(2), p);
        bytes memory diff = LAIPBigInt1024.modSub(x2, y2, p);
        bytes memory right = LAIPBigInt1024.modMul(a2, diff, p);
        return LAIPBigInt1024.eq(left, right);
    }
    function _bytes32ToBytes(bytes32 data) private pure returns (bytes memory out) {
        out = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            out[i] = data[i];
        }
    }
    function _canon(bytes memory x, uint256 len) internal pure returns (bytes memory out) {
        if (x.length == len) return x;
        require(x.length < len, "canon: oversize");
        out = new bytes(len);
        uint256 off = len - x.length;
        for (uint256 i = 0; i < x.length; i++) {
            out[off + i] = x[i];
        }
    }
    /// @dev Canonicalize scalar to exact field width for MSB-first scalar multiplication
    /// Takes least-significant p.length bytes (big-endian) or left-pads if shorter
    function _canonicalizeScalar(bytes memory s, bytes memory p) private pure returns (bytes memory) {
        uint256 L = p.length;
        bytes memory out = new bytes(L);
        if (s.length >= L) {
            // Take least-significant L bytes
            for (uint256 i = 0; i < L; i++) {
                out[i] = s[s.length - L + i];
            }
        } else {
            // Left-pad with zeros
            uint256 offset = L - s.length;
            for (uint256 i = 0; i < s.length; i++) {
                out[offset + i] = s[i];
            }
        }
        return out;
    }
    function _trimLeadingZerosLocal(bytes memory data) private pure returns (bytes memory) {
        uint256 firstNonZero = 0;
        while (firstNonZero < data.length && data[firstNonZero] == 0x00) {
            firstNonZero++;
        }
        if (firstNonZero == data.length) {
            bytes memory zero = new bytes(1);
            zero[0] = 0x00;
            return zero;
        }
        bytes memory trimmed = new bytes(data.length - firstNonZero);
        for (uint256 i = 0; i < trimmed.length; i++) {
            trimmed[i] = data[firstNonZero + i];
        }
        return trimmed;
    }

	function _eqUint1024(uint256[4] memory a, uint256[4] memory b) private pure returns (bool) {
		for (uint256 i = 0; i < 4; i++) {
			if (a[i] != b[i]) {
				return false;
			}
		}
		return true;
	}
}
