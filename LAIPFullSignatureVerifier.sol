// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "./LAIPBigInt.sol";
/**
 * @title LAIPFullSignatureVerifier
 * @dev Full LAIP signature verification library for 2048-bit keys
 *
 * Gas-optimized version for on-chain verification.
 *
 * This library performs on-chain verification of LAIP signatures.
 * All point construction is performed off-chain by the signer.
 */
library LAIPFullSignatureVerifier {
    using LAIPBigInt for bytes;
    // 2048-bit = 256 bytes for coordinates
    uint256 constant COORD_SIZE = 256;
    // s field: s = r + e*k where e is 256-bit, k is up to 2048-bit
    // Maximum s is approximately 256 + 2048 = 2304 bits = 288 bytes, +1 for safety
    uint256 constant S_SIZE = 289;
    // Total signature: 256 + 256 + 289 = 801 bytes
    uint256 constant SIG_SIZE = 801;
    struct LAIPSignature {
        bytes Rx; // R point x-coordinate (256 bytes)
        bytes Ry; // R point y-coordinate (256 bytes)
        bytes s;  // Schnorr response (289 bytes max)
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
    struct FinalEq {
        bytes sU;
        bytes sV;
        bytes rU;
        bytes rV;
        bytes eQU;
        bytes eQV;
    }
    /**
     * @notice Full LAIP verification for 2048-bit keys
     */
	function verifyLAIP(
        LAIPPublicKey calldata pubKey,
        LAIPSignature calldata sig,
        bytes32 messageHash
    ) external view returns (bool) {
        return _verifyLAIPInternal(pubKey, sig, messageHash);
    }
    function _verifyLAIPInternal(
		LAIPPublicKey calldata publicKey,
		LAIPSignature calldata signature,
		bytes32 dilithiumHash
	) internal view returns (bool) {
		// Fiat–Shamir challenge: MUST be byte-for-byte identical to JS
		bytes32 eHash = keccak256(
			bytes.concat(
				signature.Rx,
				signature.Ry,
				publicKey.Qx,
				publicKey.Qy,
				abi.encodePacked(dilithiumHash),
				publicKey.P0x,
				publicKey.P0y
			)
		);
		bytes memory e = _canonicalizeScalar(
			abi.encodePacked(eHash),
			publicKey.p
		);
		if (!_validateInputs(signature, publicKey)) return false;
		FinalEq memory eq;
		bool ok = true;
		bool stepOk;
		(eq.sU, eq.sV, stepOk) =
			_scalarMulProjectiveT(
				_canonicalizeScalar(signature.s, publicKey.p),
				publicKey.P0x,
				publicKey.P0y,
				publicKey.a,
				publicKey.p
			);
		if (!stepOk) ok = false;
		(eq.eQU, eq.eQV, stepOk) =
			_scalarMulProjectiveT(
				_canonicalizeScalar(e, publicKey.p),
				publicKey.Qx,
				publicKey.Qy,
				publicKey.a,
				publicKey.p
			);
		if (!stepOk) ok = false;
		(eq.rU, eq.rV, stepOk) =
			_pointToProjectiveT(
				signature.Rx,
				signature.Ry,
				publicKey.a,
				publicKey.p
			);
		if (!stepOk) ok = false;
		(eq.rU, eq.rV, stepOk) =
			_projectiveAdd(
				eq.rU,
				eq.rV,
				eq.eQU,
				eq.eQV,
				publicKey.p
			);
		if (!stepOk) ok = false;
		if (!_checkSchnorrEqProjective(
			eq.sU,
			eq.sV,
			eq.rU,
			eq.rV,
			publicKey.p
		)) {
			ok = false;
		}
		return ok;
	}
    function _validateInputs(
        LAIPSignature calldata signature,
        LAIPPublicKey calldata publicKey
    ) internal view returns (bool) {
        if (signature.Rx.length != publicKey.p.length) return false;
        if (signature.Ry.length != publicKey.p.length) return false;
        if (publicKey.Qx.length != publicKey.p.length) return false;
        if (publicKey.Qy.length != publicKey.p.length) return false;
        if (publicKey.P0x.length != publicKey.p.length) return false;
        if (publicKey.P0y.length != publicKey.p.length) return false;
        if (!isOnCurve(signature.Rx, signature.Ry, publicKey.a, publicKey.p)) return false;
        if (!isOnCurve(publicKey.Qx, publicKey.Qy, publicKey.a, publicKey.p)) return false;
        return true;
    }
    function _computeSchnorrProjective(
        LAIPSignature memory signature,
        LAIPPublicKey memory publicKey,
        bytes memory e
    ) internal view returns (bytes memory sU, bytes memory sV, bytes memory tU, bytes memory tV) {
        bytes memory sCanon = _canon(signature.s, publicKey.coordSize);
        bytes memory eCanon = _canonicalizeScalar(e, publicKey.p);
        (sU, sV) = _projectiveMulChecked(sCanon, publicKey.P0x, publicKey.P0y, publicKey.a, publicKey.p);
        (tU, tV) = _computeProjectiveSum(signature, publicKey, eCanon);
    }
    function _computeProjectiveSum(
        LAIPSignature memory signature,
        LAIPPublicKey memory publicKey,
        bytes memory eCanon
    ) internal view returns (bytes memory tU, bytes memory tV) {
        (bytes memory eU, bytes memory eV) = _projectiveMulChecked(
            eCanon,
            publicKey.Qx,
            publicKey.Qy,
            publicKey.a,
            publicKey.p
        );
        (bytes memory rU, bytes memory rV) = _projectiveFromAffineChecked(
            signature.Rx,
            signature.Ry,
            publicKey.a,
            publicKey.p
        );
        (tU, tV) = _projectiveAddChecked(rU, rV, eU, eV, publicKey.p);
    }
    function _projectiveMulChecked(
        bytes memory scalar,
        bytes memory x,
        bytes memory y,
        bytes memory a,
        bytes memory p
    ) internal view returns (bytes memory u, bytes memory v) {
        bool ok;
        (u, v, ok) = _scalarMulProjectiveT(scalar, x, y, a, p);
        require(ok, "LAIP: scalar mul failed");
    }
    function _projectiveFromAffineChecked(
        bytes memory x,
        bytes memory y,
        bytes memory a,
        bytes memory p
    ) internal view returns (bytes memory u, bytes memory v) {
        bool ok;
        (u, v, ok) = _pointToProjectiveT(x, y, a, p);
        require(ok, "LAIP: invalid projective point");
    }
    function _projectiveAddChecked(
        bytes memory u1,
        bytes memory v1,
        bytes memory u2,
        bytes memory v2,
        bytes memory p
    ) internal view returns (bytes memory u3, bytes memory v3) {
        bool ok;
        (u3, v3, ok) = _projectiveAdd(u1, v1, u2, v2, p);
        require(ok, "LAIP: projective add failed");
    }
    /**
     * @dev Decode LAIP signature from bytes
     * Format: Rx (256 bytes) || Ry (256 bytes) || s (289 bytes) = 801 bytes
     */
    function decodeSignature(bytes memory signatureBytes)
        public
        pure
        returns (LAIPSignature memory signature)
    {
        require(signatureBytes.length == SIG_SIZE, "LAIPFullSigVerifier: signature must be 801 bytes");
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
        bytes memory x2 = LAIPBigInt.modExp(x, LAIPBigInt.fromUint256(2), p);
        bytes memory y2 = LAIPBigInt.modExp(y, LAIPBigInt.fromUint256(2), p);
        bytes memory sum = LAIPBigInt.modAdd(x2, y2, p);
        if (LAIPBigInt.isZero(sum) || LAIPBigInt.eq(x2, y2)) {
            return false;
        }
        bytes memory left = LAIPBigInt.modExp(sum, LAIPBigInt.fromUint256(2), p);
        bytes memory a2 = LAIPBigInt.modExp(a, LAIPBigInt.fromUint256(2), p);
        bytes memory diff = LAIPBigInt.modSub(x2, y2, p);
        bytes memory right = LAIPBigInt.modMul(a2, diff, p);
        return LAIPBigInt.eq(left, right);
    }
    // ================================================================
    // Internal lemniscate arithmetic (projective t-parameter)
    // ================================================================
    // CRITICAL INVARIANT:
    // All scalars passed to _scalarMulProjectiveT MUST already be
    // canonicalized to exactly p.length bytes before calling.
    // Use _canonicalizeScalar(scalar, p) at every call site.
    /// @dev Scalar multiplication returning projective-t coordinates (u, v)
    /// DOES NOT convert to affine - avoids modular inversion
    function _scalarMulProjectiveT(
        bytes memory scalar,
        bytes memory x,
        bytes memory y,
        bytes memory a,
        bytes memory p
    ) internal view returns (bytes memory u, bytes memory v, bool ok) {
        (bytes memory baseU, bytes memory baseV, bool baseOk) = _pointToProjectiveT(x, y, a, p);
        if (!baseOk) {
            return (u, v, false);
        }
        uint256 fieldLen = p.length;
        // Ensure base coords are padded to field length
        baseU = _padToLength(baseU, fieldLen);
        baseV = _padToLength(baseV, fieldLen);
        // CRITICAL: Create immutable copies for use in loop (viaIR aliasing protection)
        bytes memory fixedBaseU = _copyBytes(baseU);
        bytes memory fixedBaseV = _copyBytes(baseV);
        return _scalarMulProjectiveTInner(scalar, fixedBaseU, fixedBaseV, p, fieldLen);
    }
    /// @dev Inner loop for scalar multiplication (split for stack depth management)
    function _scalarMulProjectiveTInner(
        bytes memory scalar,
        bytes memory fixedBaseU,
        bytes memory fixedBaseV,
        bytes memory p,
        uint256 fieldLen
    ) private view returns (bytes memory u, bytes memory v, bool ok) {
        // accumulator = identity (t = 0/1)
        u = new bytes(fieldLen);
        v = new bytes(fieldLen);
        v[fieldLen - 1] = 0x01;
        // Find first non-zero byte (skip leading zeros)
        uint256 startByte = 0;
        while (startByte < scalar.length && uint8(scalar[startByte]) == 0) {
            startByte++;
        }
        // If scalar is all zeros, return identity
        if (startByte == scalar.length) {
            return (u, v, true);
        }
        // MSB-first double-and-add: iterate bytes left to right, bits 7 down to 0
        bool firstBitFound = false;
        for (uint256 byteIdx = startByte; byteIdx < scalar.length; byteIdx++) {
            (u, v, firstBitFound, ok) = _processByteScalarMul(
                uint8(scalar[byteIdx]),
                firstBitFound,
                u, v,
                fixedBaseU, fixedBaseV,
                p
            );
            if (!ok) return (u, v, false);
        }
        return (u, v, true);
    }
    /// @dev Process a single byte of the scalar in double-and-add
    function _processByteScalarMul(
        uint8 b,
        bool firstBitFound,
        bytes memory u,
        bytes memory v,
        bytes memory baseU,
        bytes memory baseV,
        bytes memory p
    ) private view returns (bytes memory, bytes memory, bool, bool) {
        bool ok;
        for (uint8 bitPos = 0; bitPos < 8; bitPos++) {
            uint8 bit = (b >> (7 - bitPos)) & 1;
            if (!firstBitFound) {
                if (bit == 1) {
                    firstBitFound = true;
                    u = _copyBytes(baseU);
                    v = _copyBytes(baseV);
                }
            } else {
                (u, v, ok) = _doubleAndMaybeAdd(u, v, baseU, baseV, p, bit);
                if (!ok) return (u, v, firstBitFound, false);
            }
        }
        return (u, v, firstBitFound, true);
    }
    /// @dev Double accumulator and conditionally add base point
    function _doubleAndMaybeAdd(
        bytes memory u,
        bytes memory v,
        bytes memory baseU,
        bytes memory baseV,
        bytes memory p,
        uint8 bit
    ) private view returns (bytes memory, bytes memory, bool) {
        bool ok;
        (u, v, ok) = _projectiveDouble(u, v, p);
        if (!ok) return (u, v, false);
        if (bit == 1) {
            return _projectiveAdd(u, v, baseU, baseV, p);
        }
        return (u, v, true);
    }
    /// @dev Pad bytes to target length (left-pad with zeros for big-endian)
    function _padToLength(bytes memory data, uint256 targetLen) private pure returns (bytes memory) {
        if (data.length >= targetLen) {
            return _copyBytes(data); // Always return fresh copy
        }
        bytes memory padded = new bytes(targetLen);
        uint256 offset = targetLen - data.length;
        for (uint256 i = 0; i < data.length; i++) {
            padded[offset + i] = data[i];
        }
        return padded;
    }
    function _projectiveAdd(
        bytes memory u1,
        bytes memory v1,
        bytes memory u2,
        bytes memory v2,
        bytes memory p
    ) internal view returns (bytes memory u3, bytes memory v3, bool ok) {
        uint256 L = p.length;
        // Identity fast-path (t = 0)
        if (LAIPBigInt.isZero(u1)) return (_copyBytes(u2), _copyBytes(v2), true);
        if (LAIPBigInt.isZero(u2)) return (_copyBytes(u1), _copyBytes(v1), true);
        bool inf1 = LAIPBigInt.isZero(v1); // v==0 => t = ∞
        bool inf2 = LAIPBigInt.isZero(v2);
        // ∞ + ∞ = 0 (limit of tan addition: tends to 0)
        if (inf1 && inf2) {
            bytes memory zu = new bytes(L);
            bytes memory zv = new bytes(L);
            zv[L - 1] = 0x01;
            return (zu, zv, true);
        }
        // ∞ + t = -1/t   (tan(pi/2 + a) = -cot(a) = -1/t)
        if (inf1) {
            bytes memory zero = new bytes(L);
            bytes memory newU = LAIPBigInt.modSub(zero, v2, p); // -v2
            bytes memory newV = _copyBytes(u2);                    //  u2
            // Ensure not mistaken for identity: if u2==0, caller already hit identity-path above.
            return (newU, newV, true);
        }
        if (inf2) {
            bytes memory zero = new bytes(L);
            bytes memory newU = LAIPBigInt.modSub(zero, v1, p); // -v1
            bytes memory newV = _copyBytes(u1);                    //  u1
            return (newU, newV, true);
        }
        // General case:
        // t3 = (t1 + t2) / (1 - t1*t2)
        // with t = u/v => numerator = u1*v2 + u2*v1
        //                 denom    = v1*v2 - u1*u2
        // Split into separate functions to avoid stack-too-deep
        bytes memory numerator = _computeProjectiveAddNumerator(u1, v1, u2, v2, p);
        bytes memory denominator = _computeProjectiveAddDenominator(u1, v1, u2, v2, p);
        // If denom == 0, result is t = ∞ (not a failure)
        if (LAIPBigInt.isZero(denominator)) {
            bytes memory infU = new bytes(L);
            bytes memory infV = new bytes(L);
            infU[L - 1] = 0x01; // u=1
            // v=0
            return (infU, infV, true);
        }
        return (numerator, denominator, true);
    }
    /// @dev Compute numerator for projective addition: u1*v2 + u2*v1
    function _computeProjectiveAddNumerator(
        bytes memory u1,
        bytes memory v1,
        bytes memory u2,
        bytes memory v2,
        bytes memory p
    ) private view returns (bytes memory) {
        bytes memory u1v2 = LAIPBigInt.modMul(u1, v2, p);
        bytes memory u2v1 = LAIPBigInt.modMul(u2, v1, p);
        return LAIPBigInt.modAdd(u1v2, u2v1, p);
    }
    /// @dev Compute denominator for projective addition: v1*v2 - u1*u2
    function _computeProjectiveAddDenominator(
        bytes memory u1,
        bytes memory v1,
        bytes memory u2,
        bytes memory v2,
        bytes memory p
    ) private view returns (bytes memory) {
        bytes memory v1v2 = LAIPBigInt.modMul(v1, v2, p);
        bytes memory u1u2 = LAIPBigInt.modMul(u1, u2, p);
        return LAIPBigInt.modSub(v1v2, u1u2, p);
    }
    function _projectiveDouble(
        bytes memory u,
        bytes memory v,
        bytes memory p
    ) internal view returns (bytes memory du, bytes memory dv, bool ok) {
        uint256 L = p.length;
        // 2·0 = 0
        if (LAIPBigInt.isZero(u)) {
            bytes memory zu = new bytes(L);
            bytes memory zv = new bytes(L);
            zv[L - 1] = 0x01;
            return (zu, zv, true);
        }
        // 2·∞ = 0  (tan(pi) = 0)
        if (LAIPBigInt.isZero(v)) {
            bytes memory zu = new bytes(L);
            bytes memory zv = new bytes(L);
            zv[L - 1] = 0x01;
            return (zu, zv, true);
        }
        // tan(2A) = 2t / (1 - t^2)
        // with t=u/v => numerator = 2*u*v ; denom = v^2 - u^2
        bytes memory two = new bytes(L);
        two[L - 1] = 0x02;
        bytes memory uv = LAIPBigInt.modMul(u, v, p);
        bytes memory numerator = LAIPBigInt.modMul(two, uv, p);
        bytes memory v2 = LAIPBigInt.modMul(v, v, p);
        bytes memory u2 = LAIPBigInt.modMul(u, u, p);
        bytes memory denominator = LAIPBigInt.modSub(v2, u2, p);
        // If denom == 0, result is ∞ (t = ±1 doubles to ∞)
        if (LAIPBigInt.isZero(denominator)) {
            bytes memory infU = new bytes(L);
            bytes memory infV = new bytes(L);
            infU[L - 1] = 0x01;
            return (infU, infV, true);
        }
        return (numerator, denominator, true);
    }
    function _pointToProjectiveT(
        bytes memory x,
        bytes memory y,
        bytes memory /* a */,
        bytes memory p
    ) internal view returns (bytes memory u, bytes memory v, bool ok) {
        uint256 L = p.length;
        bytes memory zero = new bytes(L);
        bytes memory one  = new bytes(L);
        one[L - 1] = 0x01;
        // Identity (explicit)
        if (LAIPBigInt.isZero(x) && LAIPBigInt.isZero(y)) {
            return (zero, one, true); // 0/1
        }
        // v = x + y
        v = LAIPBigInt.modAdd(x, y, p);
        // u = x - y
        u = LAIPBigInt.modSub(x, y, p);
        // If v == 0, this is the "infinite t" class (x + y == 0)
        // Do NOT fail—return canonical infinity (1/0).
        if (LAIPBigInt.isZero(v)) {
            bytes memory infU = new bytes(L);
            bytes memory infV = new bytes(L);
            infU[L - 1] = 0x01;
            return (infU, infV, true);
        }
        return (u, v, true);
    }
    /// @dev Create a fresh copy of bytes (critical for viaIR compatibility)
    function _copyBytes(bytes memory data) private pure returns (bytes memory) {
        bytes memory copy = new bytes(data.length);
        for (uint256 i = 0; i < data.length; i++) {
            copy[i] = data[i];
        }
        return copy;
    }
    function _checkSchnorrEqProjective(
		bytes memory sU,
		bytes memory sV,
		bytes memory rU,
		bytes memory rV,
		bytes memory p
	) internal view returns (bool) {
		bool sInf = LAIPBigInt.isZero(sV); // s == ∞
		bool rInf = LAIPBigInt.isZero(rV); // r == ∞
		// ∞ == ∞
		if (sInf && rInf) return true;
		// ∞ != finite
		if (sInf || rInf) return false;
		// Cross-multiply for projective equality
		bytes memory left  = LAIPBigInt.modMul(sU, rV, p);
		bytes memory right = LAIPBigInt.modMul(rU, sV, p);
		return LAIPBigInt.eq(left, right);
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
}
