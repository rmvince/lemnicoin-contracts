// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title LAIPBigInt1024
 * @dev BigInteger library for 1024-bit LAIP operations
 * Uses EIP-198 modexp precompile for efficient large number arithmetic
 *
 * This is a gas-optimized version for on-chain verification.
 * 1024-bit operations are ~8x cheaper than 2048-bit operations.
 *
 * Based on EIP-198: https://eips.ethereum.org/EIPS/eip-198
 * Precompile address: 0x0000000000000000000000000000000000000005
 */
library LAIPBigInt1024 {
    // EIP-198 modexp precompile address
    address constant MODEXP_PRECOMPILE = address(0x05);

    // Size constants for LAIP (1024-bit = 128 bytes)
    uint256 constant LAIP_BYTE_SIZE = 128;
    uint256 constant LAIP_BIT_SIZE = 1024;

    function toUint1024(bytes memory b) internal pure returns (uint256[4] memory out) {
        require(b.length == LAIP_BYTE_SIZE, "LAIPBigInt1024: invalid 1024-bit length");
        assembly {
            mstore(add(out, 0x20), mload(add(b, 0x20)))
            mstore(add(out, 0x40), mload(add(b, 0x40)))
            mstore(add(out, 0x60), mload(add(b, 0x60)))
            mstore(add(out, 0x80), mload(add(b, 0x80)))
        }
    }

    function modMul(
        uint256[4] memory a,
        uint256[4] memory b,
        uint256[4] memory modulus
    ) internal view returns (uint256[4] memory result) {
        bytes memory aa = _uint1024ToBytes(a);
        bytes memory bb = _uint1024ToBytes(b);
        bytes memory mm = _uint1024ToBytes(modulus);
        bytes memory rr = modMul(aa, bb, mm);
        return toUint1024(rr);
    }

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

        require(modLen > 0, "LAIPBigInt1024: modulus cannot be zero");
        require(modLen <= LAIP_BYTE_SIZE, "LAIPBigInt1024: modulus too large");

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

        require(success, "LAIPBigInt1024: modexp precompile failed");
        return output;
    }

    /**
     * @dev Modular addition: (a + b) % modulus
     */
    function modAdd(
		bytes memory a,
		bytes memory b,
		bytes memory modulus
	) public pure returns (bytes memory) {
		uint256 L = modulus.length;
		require(L > 0 && L <= LAIP_BYTE_SIZE, "LAIPBigInt1024: bad modulus len");

		bytes memory aa = _toFixedLen(a, L);
		bytes memory bb = _toFixedLen(b, L);
		bytes memory p  = _toFixedLen(modulus, L);

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
		// For aa,bb<p, carry==1 implies low<p, so r < 2^k and c2 should be 0.
		// (If you ever hit c2==1, the logic still works with the next compare/sub.)
		if (c2 == 1 || _geFixed(r, p)) {
			r = _subFixed(r, p);
		}
		return r;
	}

	function modSub(
		bytes memory a,
		bytes memory b,
		bytes memory modulus
	) public pure returns (bytes memory) {
		uint256 L = modulus.length;
		require(L > 0 && L <= LAIP_BYTE_SIZE, "LAIPBigInt1024: bad modulus len");

		bytes memory aa = _toFixedLen(a, L);
		bytes memory bb = _toFixedLen(b, L);
		bytes memory p  = _toFixedLen(modulus, L);

		if (_geFixed(aa, bb)) {
			return _subFixed(aa, bb);
		}

		// aa < bb => (aa - bb) mod p = p - (bb - aa)
		bytes memory diff = _subFixed(bb, aa);  // bb - aa  (diff < p)
		return _subFixed(p, diff);              // p - diff (in [1, p-1])
	}

	// 2's complement in fixed width: returns (0 - x) mod 2^k = 2^k - x
	function _negMod2k(bytes memory x) private pure returns (bytes memory out) {
		uint256 L = x.length;
		out = new bytes(L);

		uint256 carry = 1;
		for (uint256 k = 0; k < L; k++) {
			uint256 i = L - 1 - k;
			uint256 inv = uint256(uint8(~x[i]));     // bitwise NOT of the byte
			uint256 t = inv + carry;
			out[i] = bytes1(uint8(t & 0xFF));
			carry = t >> 8;                          // 0 or 1
		}
	}


    function modMul(
        bytes memory a,
        bytes memory b,
        bytes memory modulus
    ) public view returns (bytes memory) {
		uint256 L = modulus.length;
		require(L > 0 && L <= LAIP_BYTE_SIZE, "LAIPBigInt1024: bad modulus len");

		// Keep operands fixed-width
		bytes memory aa = _toFixedLen(a, L);
		bytes memory bb = _toFixedLen(b, L);

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
		// both same length
		for (uint256 i = 0; i < a.length; i++) {
			uint8 ai = uint8(a[i]);
			uint8 bi = uint8(b[i]);
			if (ai > bi) return true;
			if (ai < bi) return false;
		}
		return true; // equal
	}

	function _subFixed(bytes memory a, bytes memory b) private pure returns (bytes memory out) {
		// out = a - b, assumes a >= b, both fixed-length
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
		// out = (a+b) mod 2^(8L), carry is 0/1, both fixed-length
		uint256 L = a.length;
		out = new bytes(L);

		uint256 c = 0;
		for (uint256 k = 0; k < L; k++) {
			uint256 i = L - 1 - k;
			uint256 sum = uint256(uint8(a[i])) + uint256(uint8(b[i])) + c;
			out[i] = bytes1(uint8(sum & 0xFF));
			c = sum >> 8;
		}
		carry = c; // 0 or 1
	}

	function _divBy2ModFixed(bytes memory x, bytes memory modulus) private pure returns (bytes memory) {
		uint256 L = modulus.length;
		bytes memory xx = _toFixedLen(x, L);
		bytes memory mm = _toFixedLen(modulus, L);

		bool isEven = (uint8(xx[L - 1]) & 1) == 0;

		if (isEven) {
			// x/2
			return _rightShift1FixedWithTopBit(xx, 0);
		} else {
			// (x + p) / 2  — MUST preserve carry into the shift
			(bytes memory s, uint256 carryByte) = _addFixedRaw(xx, mm); // carryByte is 0 or 1
			return _rightShift1FixedWithTopBit(s, uint8(carryByte));
		}
	}


	function _rightShift1Fixed(bytes memory data) private pure returns (bytes memory out) {
		return _rightShift1FixedWithTopBit(data, 0);
	}

	function _rightShift1FixedWithTopBit(bytes memory data, uint8 topBit) private pure returns (bytes memory out) {
		uint256 L = data.length;
		out = new bytes(L);

		// topBit is the bit just above the MSB of data (i.e., carry from an L-byte add)
		uint8 carry = topBit & 1;

		for (uint256 i = 0; i < L; i++) {
			uint8 cur = uint8(data[i]);
			out[i] = bytes1((carry << 7) | (cur >> 1));
			carry = cur & 1;
		}
	}


    /**
     * @dev Schoolbook multiplication of two big integers
     * Returns a*b as a byte array (up to 256 bytes for 1024-bit inputs)
     */
    function _multiply(bytes memory a, bytes memory b) private pure returns (bytes memory) {
        if (a.length == 0 || b.length == 0) {
            bytes memory zero = new bytes(1);
            return zero;
        }

        // Result can be at most a.length + b.length bytes
        uint256 resultLen = a.length + b.length;
        bytes memory result = new bytes(resultLen);

        // Schoolbook multiplication
        for (uint256 i = 0; i < a.length; i++) {
            uint256 aIdx = a.length - 1 - i;
            uint256 carry = 0;

            for (uint256 j = 0; j < b.length; j++) {
                uint256 bIdx = b.length - 1 - j;
                uint256 resIdx = resultLen - 1 - i - j;

                uint256 prod = uint256(uint8(a[aIdx])) * uint256(uint8(b[bIdx]))
                             + uint256(uint8(result[resIdx])) + carry;

                result[resIdx] = bytes1(uint8(prod & 0xFF));
                carry = prod >> 8;
            }

            // Propagate remaining carry
            uint256 carryIdx = resultLen - 1 - i - b.length;
            while (carry > 0 && carryIdx < resultLen) {
                uint256 sum = uint256(uint8(result[carryIdx])) + carry;
                result[carryIdx] = bytes1(uint8(sum & 0xFF));
                carry = sum >> 8;
                if (carryIdx == 0) break;
                carryIdx--;
            }
        }

        return _trimLeadingZeros(result);
    }

    function _addBytesRaw(bytes memory a, bytes memory b) private pure returns (bytes memory) {
        uint256 maxLen = a.length > b.length ? a.length : b.length;
        bytes memory aPadded = _padLeft(a, maxLen);
        bytes memory bPadded = _padLeft(b, maxLen);

        bytes memory result = new bytes(maxLen + 1);
        uint256 carry = 0;

        for (uint256 i = 0; i < maxLen; i++) {
            uint256 idx = maxLen - 1 - i;
            uint256 sum = uint256(uint8(aPadded[idx])) +
                         uint256(uint8(bPadded[idx])) +
                         carry;
            result[idx + 1] = bytes1(uint8(sum & 0xFF));
            carry = sum >> 8;
        }
        result[0] = bytes1(uint8(carry));

        return _trimLeadingZeros(result);
    }

    function _divBy2Mod(bytes memory x, bytes memory modulus) private pure returns (bytes memory) {
        bool isEven = x.length == 0 || (uint8(x[x.length - 1]) & 1) == 0;

        bytes memory toShift;
        if (isEven) {
            toShift = x;
        } else {
            toShift = _addBytesRaw(x, modulus);
        }

        return _rightShift1(toShift);
    }

    function _rightShift1(bytes memory data) private pure returns (bytes memory) {
        if (data.length == 0) {
            bytes memory zero = new bytes(1);
            return zero;
        }

        bytes memory result = new bytes(data.length);
        uint8 carry = 0;

        for (uint256 i = 0; i < data.length; i++) {
            uint8 current = uint8(data[i]);
            result[i] = bytes1((carry << 7) | (current >> 1));
            carry = current & 1;
        }

        return _trimLeadingZeros(result);
    }

    /// @dev Compare two big integers for equality (canonical - trims leading zeros)
    function eq(bytes memory a, bytes memory b) public pure returns (bool) {
        // Canonicalize by trimming leading zeros
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

    function _compare(bytes memory a, bytes memory b) private pure returns (int8) {
        uint256 maxLen = a.length > b.length ? a.length : b.length;
        bytes memory aPadded = _padLeft(a, maxLen);
        bytes memory bPadded = _padLeft(b, maxLen);

        for (uint256 i = 0; i < maxLen; i++) {
            if (uint8(aPadded[i]) < uint8(bPadded[i])) return -1;
            if (uint8(aPadded[i]) > uint8(bPadded[i])) return 1;
        }
        return 0;
    }

    function _subtract(bytes memory a, bytes memory b) private pure returns (bytes memory) {
        uint256 maxLen = a.length > b.length ? a.length : b.length;
        bytes memory aPadded = _padLeft(a, maxLen);
        bytes memory bPadded = _padLeft(b, maxLen);
        bytes memory result = new bytes(maxLen);

        int256 borrow = 0;
        for (uint256 i = 0; i < maxLen; i++) {
            uint256 idx = maxLen - 1 - i;
            int256 diff = int256(uint256(uint8(aPadded[idx]))) -
                         int256(uint256(uint8(bPadded[idx]))) -
                         borrow;

            if (diff < 0) {
                diff += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }

            result[idx] = bytes1(uint8(uint256(diff)));
        }

        return _trimLeadingZeros(result);
    }

    /// @dev Modular reduction, ALWAYS creating fresh memory copy
    /// This is critical for viaIR compatibility - returning input directly causes memory issues
    function _mod(bytes memory a, bytes memory modulus) private pure returns (bytes memory) {
        if (_compare(a, modulus) < 0) {
            // Must create fresh copy - never return input directly with viaIR
            bytes memory copy = new bytes(a.length);
            for (uint256 i = 0; i < a.length; i++) {
                copy[i] = a[i];
            }
            return copy;
        }

        // Create fresh copy to work with
        bytes memory result = new bytes(a.length);
        for (uint256 i = 0; i < a.length; i++) {
            result[i] = a[i];
        }

        while (_compare(result, modulus) >= 0) {
            result = _subtract(result, modulus);
        }

        return _trimLeadingZeros(result);
    }

    /// @dev Left-pad bytes to target length, ALWAYS creating a fresh copy
    /// This is critical for viaIR compatibility - returning input directly causes memory issues
    function _padLeft(bytes memory data, uint256 targetLen) private pure returns (bytes memory) {
        bytes memory padded = new bytes(targetLen);

        if (data.length >= targetLen) {
            // Copy the rightmost targetLen bytes (big-endian alignment)
            uint256 srcOffset = data.length - targetLen;
            for (uint256 i = 0; i < targetLen; i++) {
                padded[i] = data[srcOffset + i];
            }
        } else {
            // Pad with leading zeros
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

    function _max3(uint256 a, uint256 b, uint256 c) private pure returns (uint256) {
        uint256 max = a;
        if (b > max) max = b;
        if (c > max) max = c;
        return max;
    }

    function isZero(bytes memory data) public pure returns (bool) {
        for (uint256 i = 0; i < data.length; i++) {
            if (data[i] != 0) {
                return false;
            }
        }
        return true;
    }

    function toUint256(bytes memory data) public pure returns (uint256) {
        require(data.length <= 32, "LAIPBigInt1024: data too large for uint256");

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

    function _uint1024ToBytes(uint256[4] memory value) private pure returns (bytes memory out) {
        out = new bytes(LAIP_BYTE_SIZE);
        assembly {
            mstore(add(out, 0x20), mload(value))
            mstore(add(out, 0x40), mload(add(value, 0x20)))
            mstore(add(out, 0x60), mload(add(value, 0x40)))
            mstore(add(out, 0x80), mload(add(value, 0x60)))
        }
    }
}
