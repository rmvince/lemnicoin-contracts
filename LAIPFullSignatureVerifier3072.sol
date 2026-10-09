// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "./LAIPBigInt3072.sol";
/**
 * @title LAIPFullSignatureVerifier3072
 * @dev Full LAIP signature verification library for 3072-bit keys
 *
 * /// Lemnicoin is owner-sovereign.
 * /// Valid LAIP + Dilithium signatures define ownership.
 * /// Blockchains are execution venues only.
 *
 * This library performs FULL on-chain verification of LAIP signatures.
 * All scalar multiplications are computed on-chain for maximum security.
 *
 * 3072-bit provides maximum quantum security with ~384 bytes per coordinate.
 *
 * VERIFICATION ALGORITHM:
 * 1. Compute Fiat-Shamir challenge e = H(R || Q || message || P0)
 * 2. Compute s·P0 via full scalar multiplication
 * 3. Compute e·Q via full scalar multiplication
 * 4. Compute R + e·Q via projective addition
 * 5. Verify s·P0 == R + e·Q (cross-multiplication in projective)
 */
library LAIPFullSignatureVerifier3072 {
    using LAIPBigInt3072 for bytes;
    // 3072-bit = 384 bytes for coordinates
    uint256 constant COORD_SIZE = 384;
    // s field: s = r + e*k where e is 256-bit, k is up to 3072-bit
    // Maximum s is approximately 256 + 3072 = 3328 bits = 416 bytes, +1 for safety
    uint256 constant S_SIZE = 417;
    // Total signature: 384 + 384 + 417 = 1185 bytes
    uint256 constant SIG_SIZE = 1185;
    struct LAIPSignature {
        bytes Rx; // R point x-coordinate (384 bytes)
        bytes Ry; // R point y-coordinate (384 bytes)
        bytes s;  // Schnorr response (417 bytes max)
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
     * @notice Full LAIP verification for 3072-bit keys
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
    /**
     * @dev Decode LAIP signature from bytes
     * Format: Rx (384 bytes) || Ry (384 bytes) || s (417 bytes) = 1185 bytes
     */
    function decodeSignature(bytes memory signatureBytes)
        public
        pure
        returns (LAIPSignature memory signature)
    {
        require(signatureBytes.length == SIG_SIZE, "LAIPFullSigVerifier3072: signature must be 1185 bytes");
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
        bytes memory x2 = LAIPBigInt3072.modExp(x, LAIPBigInt3072.fromUint256(2), p);
        bytes memory y2 = LAIPBigInt3072.modExp(y, LAIPBigInt3072.fromUint256(2), p);
        bytes memory sum = LAIPBigInt3072.modAdd(x2, y2, p);
        if (LAIPBigInt3072.isZero(sum) || LAIPBigInt3072.eq(x2, y2)) {
            return false;
        }
        bytes memory left = LAIPBigInt3072.modExp(sum, LAIPBigInt3072.fromUint256(2), p);
        bytes memory a2 = LAIPBigInt3072.modExp(a, LAIPBigInt3072.fromUint256(2), p);
        bytes memory diff = LAIPBigInt3072.modSub(x2, y2, p);
        bytes memory right = LAIPBigInt3072.modMul(a2, diff, p);
        return LAIPBigInt3072.eq(left, right);
    }
    // ================================================================
    // Internal lemniscate arithmetic (projective t-parameter)
    // ================================================================
    /// @dev Scalar multiplication returning projective-t coordinates (u, v)
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
        baseU = _padToLength(baseU, fieldLen);
        baseV = _padToLength(baseV, fieldLen);
        bytes memory fixedBaseU = _copyBytes(baseU);
        bytes memory fixedBaseV = _copyBytes(baseV);
        return _scalarMulProjectiveTInner(scalar, fixedBaseU, fixedBaseV, p, fieldLen);
    }
    function _scalarMulProjectiveTInner(
        bytes memory scalar,
        bytes memory fixedBaseU,
        bytes memory fixedBaseV,
        bytes memory p,
        uint256 fieldLen
    ) private view returns (bytes memory u, bytes memory v, bool ok) {
        u = new bytes(fieldLen);
        v = new bytes(fieldLen);
        v[fieldLen - 1] = 0x01;
        uint256 startByte = 0;
        while (startByte < scalar.length && uint8(scalar[startByte]) == 0) {
            startByte++;
        }
        if (startByte == scalar.length) {
            return (u, v, true);
        }
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
    function _padToLength(bytes memory data, uint256 targetLen) private pure returns (bytes memory) {
        if (data.length >= targetLen) {
            return _copyBytes(data);
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
        if (LAIPBigInt3072.isZero(u1)) return (_copyBytes(u2), _copyBytes(v2), true);
        if (LAIPBigInt3072.isZero(u2)) return (_copyBytes(u1), _copyBytes(v1), true);
        bool inf1 = LAIPBigInt3072.isZero(v1);
        bool inf2 = LAIPBigInt3072.isZero(v2);
        if (inf1 && inf2) {
            bytes memory zu = new bytes(L);
            bytes memory zv = new bytes(L);
            zv[L - 1] = 0x01;
            return (zu, zv, true);
        }
        if (inf1) {
            bytes memory zero = new bytes(L);
            bytes memory newU = LAIPBigInt3072.modSub(zero, v2, p);
            bytes memory newV = _copyBytes(u2);
            return (newU, newV, true);
        }
        if (inf2) {
            bytes memory zero = new bytes(L);
            bytes memory newU = LAIPBigInt3072.modSub(zero, v1, p);
            bytes memory newV = _copyBytes(u1);
            return (newU, newV, true);
        }
        bytes memory numerator = _computeProjectiveAddNumerator(u1, v1, u2, v2, p);
        bytes memory denominator = _computeProjectiveAddDenominator(u1, v1, u2, v2, p);
        if (LAIPBigInt3072.isZero(denominator)) {
            bytes memory infU = new bytes(L);
            bytes memory infV = new bytes(L);
            infU[L - 1] = 0x01;
            return (infU, infV, true);
        }
        return (numerator, denominator, true);
    }
    function _computeProjectiveAddNumerator(
        bytes memory u1,
        bytes memory v1,
        bytes memory u2,
        bytes memory v2,
        bytes memory p
    ) private view returns (bytes memory) {
        bytes memory u1v2 = LAIPBigInt3072.modMul(u1, v2, p);
        bytes memory u2v1 = LAIPBigInt3072.modMul(u2, v1, p);
        return LAIPBigInt3072.modAdd(u1v2, u2v1, p);
    }
    function _computeProjectiveAddDenominator(
        bytes memory u1,
        bytes memory v1,
        bytes memory u2,
        bytes memory v2,
        bytes memory p
    ) private view returns (bytes memory) {
        bytes memory v1v2 = LAIPBigInt3072.modMul(v1, v2, p);
        bytes memory u1u2 = LAIPBigInt3072.modMul(u1, u2, p);
        return LAIPBigInt3072.modSub(v1v2, u1u2, p);
    }
    function _projectiveDouble(
        bytes memory u,
        bytes memory v,
        bytes memory p
    ) internal view returns (bytes memory du, bytes memory dv, bool ok) {
        uint256 L = p.length;
        if (LAIPBigInt3072.isZero(u)) {
            bytes memory zu = new bytes(L);
            bytes memory zv = new bytes(L);
            zv[L - 1] = 0x01;
            return (zu, zv, true);
        }
        if (LAIPBigInt3072.isZero(v)) {
            bytes memory zu = new bytes(L);
            bytes memory zv = new bytes(L);
            zv[L - 1] = 0x01;
            return (zu, zv, true);
        }
        bytes memory two = new bytes(L);
        two[L - 1] = 0x02;
        bytes memory uv = LAIPBigInt3072.modMul(u, v, p);
        bytes memory numerator = LAIPBigInt3072.modMul(two, uv, p);
        bytes memory v2 = LAIPBigInt3072.modMul(v, v, p);
        bytes memory u2 = LAIPBigInt3072.modMul(u, u, p);
        bytes memory denominator = LAIPBigInt3072.modSub(v2, u2, p);
        if (LAIPBigInt3072.isZero(denominator)) {
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
        if (LAIPBigInt3072.isZero(x) && LAIPBigInt3072.isZero(y)) {
            return (zero, one, true);
        }
        v = LAIPBigInt3072.modAdd(x, y, p);
        u = LAIPBigInt3072.modSub(x, y, p);
        if (LAIPBigInt3072.isZero(v)) {
            bytes memory infU = new bytes(L);
            bytes memory infV = new bytes(L);
            infU[L - 1] = 0x01;
            return (infU, infV, true);
        }
        return (u, v, true);
    }
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
        bool sInf = LAIPBigInt3072.isZero(sV);
        bool rInf = LAIPBigInt3072.isZero(rV);
        if (sInf && rInf) return true;
        if (sInf || rInf) return false;
        bytes memory left  = LAIPBigInt3072.modMul(sU, rV, p);
        bytes memory right = LAIPBigInt3072.modMul(rU, sV, p);
        return LAIPBigInt3072.eq(left, right);
    }
    function _canonicalizeScalar(bytes memory s, bytes memory p) private pure returns (bytes memory) {
        uint256 L = p.length;
        bytes memory out = new bytes(L);
        if (s.length >= L) {
            for (uint256 i = 0; i < L; i++) {
                out[i] = s[s.length - L + i];
            }
        } else {
            uint256 offset = L - s.length;
            for (uint256 i = 0; i < s.length; i++) {
                out[offset + i] = s[i];
            }
        }
        return out;
    }
}
