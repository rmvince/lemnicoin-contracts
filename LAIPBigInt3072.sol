// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title LAIPBigInt3072
 * @dev BigInteger library for 3072-bit LAIP operations
 * Uses EIP-198 modexp precompile for efficient large number arithmetic
 *
 * /// Lemnicoin is owner-sovereign.
 * /// Valid LAIP + Dilithium signatures define ownership.
 * /// Blockchains are execution venues only.
 *
 * This version supports 3072-bit keys for maximum quantum security.
 * 3072-bit = 384 bytes per coordinate
 *
 * Based on EIP-198: https://eips.ethereum.org/EIPS/eip-198
 * Precompile address: 0x0000000000000000000000000000000000000005
 */
library LAIPBigInt3072 {
    // EIP-198 modexp precompile address
    address constant MODEXP_PRECOMPILE = address(0x05);

    // Size constants for LAIP (3072-bit = 384 bytes)
    uint256 constant LAIP_BYTE_SIZE = 384;
    uint256 constant LAIP_BIT_SIZE = 3072;

    /**
     * @dev Modular exponentiation: (base^exponent) % modulus
     * Uses EIP-198 precompile for efficiency
     */
    function modExp(
        bytes memory base,
        bytes memory exponent,
        bytes memory modulus
    ) public view returns (bytes memory) {
        uint256 baseLen = base.length;
        uint256 expLen = exponent.length;
        uint256 modLen = modulus.length;

        require(modLen > 0, "LAIPBigInt3072: modulus cannot be zero");
        require(modLen <= LAIP_BYTE_SIZE, "LAIPBigInt3072: modulus too large");

        bytes memory input = abi.encodePacked(
            uint256(baseLen),
            uint256(expLen),
            uint256(modLen),
            base,
            exponent,
            modulus
        );

        bytes memory output = new bytes(modLen);
        bool success;

        assembly {
            success := staticcall(
                gas(),
                0x05,
                add(input, 0x20),
                mload(input),
                add(output, 0x20),
                modLen
            )
        }

        require(success, "LAIPBigInt3072: modexp precompile failed");
        return output;
    }

    /**
     * @dev Modular addition: (a + b) % modulus
     */
    function modAdd(
        bytes memory a,
        bytes memory b,
        bytes memory modulus
    ) public view returns (bytes memory) {
        uint256 L = modulus.length;
        require(L > 0 && L <= LAIP_BYTE_SIZE, "LAIPBigInt3072: bad modulus len");

        bytes memory p  = _toFixedLen(modulus, L);
        bytes memory aa = _canonicalizeOperand(a, p);
        bytes memory bb = _canonicalizeOperand(b, p);

        // low = (aa + bb) mod 2^k, carry = 0/1 indicating overflow past k bits
        (bytes memory low, uint256 carry) = _addFixedRaw(aa, bb);

        if (carry == 0) {
            // low is the true sum, just reduce if >= p
            if (_geFixed(low, p)) {
                low = _subFixed(low, p);
            }
            return low;
        }

        // carry==1 => true sum is (2^k + low).
        // Reduce once by subtracting p: (2^k + low) - p = low + (2^k - p).
        bytes memory delta = _negMod2k(p); // delta = 2^k - p as L bytes

        (bytes memory r, uint256 c2) = _addFixedRaw(low, delta);
        if (c2 == 1 || _geFixed(r, p)) {
            r = _subFixed(r, p);
        }
        return r;
    }

    function modSub(
        bytes memory a,
        bytes memory b,
        bytes memory modulus
    ) public view returns (bytes memory) {
        uint256 L = modulus.length;
        require(L > 0 && L <= LAIP_BYTE_SIZE, "LAIPBigInt3072: bad modulus len");

        bytes memory p  = _toFixedLen(modulus, L);
        bytes memory aa = _canonicalizeOperand(a, p);
        bytes memory bb = _canonicalizeOperand(b, p);

        if (_geFixed(aa, bb)) {
            return _subFixed(aa, bb);
        }

        // aa < bb => (aa - bb) mod p = p - (bb - aa)
        bytes memory diff = _subFixed(bb, aa);
        return _subFixed(p, diff);
    }

    // 2's complement in fixed width: returns (0 - x) mod 2^k = 2^k - x
    function _negMod2k(bytes memory x) private pure returns (bytes memory out) {
        uint256 L = x.length;
        out = new bytes(L);

        uint256 carry = 1;
        for (uint256 k = 0; k < L; k++) {
            uint256 i = L - 1 - k;
            uint256 inv = uint256(uint8(~x[i]));
            uint256 t = inv + carry;
            out[i] = bytes1(uint8(t & 0xFF));
            carry = t >> 8;
        }
    }

    function modMul(
        bytes memory a,
        bytes memory b,
        bytes memory modulus
    ) public view returns (bytes memory) {
        uint256 L = modulus.length;
        require(L > 0 && L <= LAIP_BYTE_SIZE, "LAIPBigInt3072: bad modulus len");

        // Canonicalize operands into field range
        bytes memory p  = _toFixedLen(modulus, L);
        bytes memory aa = _canonicalizeOperand(a, p);
        bytes memory bb = _canonicalizeOperand(b, p);

        // Use 2-squaring identity:
        // (a+b)^2 - (a-b)^2 = 4ab  =>  ab = ((a+b)^2 - (a-b)^2) / 4  (mod p)
        bytes memory sum = modAdd(aa, bb, modulus);
        bytes memory diff = modSub(aa, bb, modulus);

        bytes memory exp2 = hex"02";
        bytes memory sumSq  = modExp(sum,  exp2, modulus);
        bytes memory diffSq = modExp(diff, exp2, modulus);

        bytes memory fourAB = modSub(sumSq, diffSq, modulus);

        // divide by 4 = divide by 2 twice (mod prime)
        bytes memory half = _divBy2ModFixed(fourAB, modulus);
        bytes memory quarter = _divBy2ModFixed(half, modulus);

        return quarter;
    }

    function _canonicalizeOperand(bytes memory x, bytes memory modulus) private view returns (bytes memory) {
        bytes memory expOne = hex"01";
        return modExp(x, expOne, modulus);
    }

    // -------------------- helpers (fixed-width, no trimming) --------------------

    function _toFixedLen(bytes memory x, uint256 L) private pure returns (bytes memory out) {
        out = new bytes(L);
        if (x.length >= L) {
            // take least-significant L bytes (big-endian)
            uint256 off = x.length - L;
            for (uint256 i = 0; i < L; i++) out[i] = x[off + i];
        } else {
            // left pad
            uint256 off2 = L - x.length;
            for (uint256 i = 0; i < x.length; i++) out[off2 + i] = x[i];
        }
    }

    function _geFixed(bytes memory a, bytes memory b) private pure returns (bool) {
        for (uint256 i = 0; i < a.length; i++) {
            uint8 ai = uint8(a[i]);
            uint8 bi = uint8(b[i]);
            if (ai > bi) return true;
            if (ai < bi) return false;
        }
        return true; // equal
    }

    function _subFixed(bytes memory a, bytes memory b) private pure returns (bytes memory out) {
        uint256 L = a.length;
        out = new bytes(L);

        uint256 borrow = 0;
        for (uint256 k = 0; k < L; k++) {
            uint256 i = L - 1 - k;
            uint256 av = uint8(a[i]);
            uint256 bv = uint8(b[i]);

            uint256 subtrahend = bv + borrow;
            if (av >= subtrahend) {
                out[i] = bytes1(uint8(av - subtrahend));
                borrow = 0;
            } else {
                out[i] = bytes1(uint8(256 + av - subtrahend));
                borrow = 1;
            }
        }
    }

    function _addFixedRaw(bytes memory a, bytes memory b) private pure returns (bytes memory out, uint256 carry) {
        uint256 L = a.length;
        out = new bytes(L);

        uint256 c = 0;
        for (uint256 k = 0; k < L; k++) {
            uint256 i = L - 1 - k;
            uint256 sum = uint256(uint8(a[i])) + uint256(uint8(b[i])) + c;
            out[i] = bytes1(uint8(sum & 0xFF));
            c = sum >> 8;
        }
        carry = c;
    }

    function _divBy2ModFixed(bytes memory x, bytes memory modulus) private pure returns (bytes memory) {
        uint256 L = modulus.length;
        bytes memory xx = _toFixedLen(x, L);
        bytes memory mm = _toFixedLen(modulus, L);

        bool isEven = (uint8(xx[L - 1]) & 1) == 0;

        if (isEven) {
            return _rightShift1FixedWithTopBit(xx, 0);
        } else {
            (bytes memory s, uint256 carryByte) = _addFixedRaw(xx, mm);
            return _rightShift1FixedWithTopBit(s, uint8(carryByte));
        }
    }

    function _rightShift1FixedWithTopBit(bytes memory data, uint8 topBit) private pure returns (bytes memory out) {
        uint256 L = data.length;
        out = new bytes(L);

        uint8 carry = topBit & 1;

        for (uint256 i = 0; i < L; i++) {
            uint8 cur = uint8(data[i]);
            out[i] = bytes1((carry << 7) | (cur >> 1));
            carry = cur & 1;
        }
    }

    function _padLeft(bytes memory data, uint256 targetLen) private pure returns (bytes memory) {
        bytes memory padded = new bytes(targetLen);

        if (data.length >= targetLen) {
            uint256 srcOffset = data.length - targetLen;
            for (uint256 i = 0; i < targetLen; i++) {
                padded[i] = data[srcOffset + i];
            }
        } else {
            uint256 offset = targetLen - data.length;
            for (uint256 i = 0; i < data.length; i++) {
                padded[offset + i] = data[i];
            }
        }

        return padded;
    }

    function _trimLeadingZeros(bytes memory data) private pure returns (bytes memory) {
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

    function isZero(bytes memory data) public pure returns (bool) {
        for (uint256 i = 0; i < data.length; i++) {
            if (data[i] != 0) {
                return false;
            }
        }
        return true;
    }

    function eq(bytes memory a, bytes memory b) public pure returns (bool) {
        uint256 ia = 0;
        uint256 ib = 0;

        while (ia < a.length && a[ia] == 0) ia++;
        while (ib < b.length && b[ib] == 0) ib++;

        uint256 lenA = a.length - ia;
        uint256 lenB = b.length - ib;

        if (lenA != lenB) return false;

        for (uint256 i = 0; i < lenA; i++) {
            if (a[ia + i] != b[ib + i]) return false;
        }
        return true;
    }

    function toUint256(bytes memory data) public pure returns (uint256) {
        require(data.length <= 32, "LAIPBigInt3072: data too large for uint256");

        uint256 result = 0;
        for (uint256 i = 0; i < data.length; i++) {
            result = result * 256 + uint8(data[i]);
        }
        return result;
    }

    function fromUint256(uint256 value) public pure returns (bytes memory) {
        if (value == 0) {
            bytes memory zero = new bytes(1);
            zero[0] = 0x00;
            return zero;
        }

        uint256 temp = value;
        uint256 length = 0;
        while (temp > 0) {
            length++;
            temp >>= 8;
        }

        bytes memory result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[length - 1 - i] = bytes1(uint8(value & 0xFF));
            value >>= 8;
        }

        return result;
    }
}
