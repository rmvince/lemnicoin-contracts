// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SlhDsaSha2_128sFast — gas-optimized on-chain SLH-DSA (SPHINCS+) verifier, FIPS 205,
///        SHA2-128s parameter set. FUNCTIONALLY IDENTICAL to SlhDsaSha2_128s (same accept/reject on
///        every input); rewritten around a single fixed memory workspace.
///
/// WHY THIS EXISTS. The reference implementation costs ~24.6M gas, but the ~2,100 SHA-256
/// precompile calls it makes are only ~0.2M of that. The rest is Solidity overhead: every hash call
/// allocates several fresh `bytes` (the 48-byte pad, the 22-byte ADRS, the concatenated input, the
/// staticcall return buffer, the truncated output) and copies them byte-by-byte through
/// bounds-checked indexing — and since Solidity never frees memory, ~2,100 calls of temporaries grow
/// the memory high-water mark past a megabyte, where EVM memory expansion is quadratic.
///
/// THE FIX, and the whole trick: hashing in SLH-DSA-SHA2 is always
///     Trunc16( SHA256( PK.seed || 0^48 || ADRS_c(22B) || message ) )
/// so ONE preallocated buffer serves every call for the whole verification:
///
///     ws+  0..63    PK.seed || 48 zero bytes  — written ONCE, constant for every call
///     ws+ 64..85    ADRS_c                    — rewritten per call with a single MSTORE
///     ws+ 86..645   message area (560B max)   — MCOPY/CALLDATACOPY in place
///     ws+672..703   SHA-256 output scratch
///     ws+736..975   FORS roots (14 x 16B, +16B slack for the 32B stores)
///     ws+992..1551  WOTS+ tmp   (35 x 16B)
///
/// Memory never grows past this 1,600-byte workspace, so expansion cost is nil, and each hash call
/// is one MSTORE (the ADRS word), one copy (the message), one STATICCALL. A WOTS+ chain step is
/// even less: the SHA-256 output is written DIRECTLY over the message area, so the next iteration's
/// input is already in place and only the 1-byte hash address needs an MSTORE8.
///
/// EQUIVALENCE ARGUMENT. Every intermediate value feeds the final root comparison through the hash
/// chain, so ANY divergence from the reference — one wrong ADRS byte, one wrong offset — makes the
/// FIPS 205 test vectors fail to verify. The vector suite (slhdsa_vectors.json, noble-generated)
/// passing on this implementation is therefore a near-complete correctness proof of the compute
/// path; the rejection side is the same computation ending in a failed comparison, tested
/// separately. Verification is pure hashing: no secret input, no state, nothing data-dependent to
/// leak.
///
/// PARAMETERS (SLH-DSA-SHA2-128s): n=16, h=63, d=7, h'=9, a=12, k=14, w=16, len=35.
/// Public key = 32 bytes (PK.seed || PK.root). Signature = 7856 bytes.
library SlhDsaSha2_128sFast {
    uint256 private constant N = 16;
    uint256 private constant HP = 9;        // h' = h/d
    uint256 private constant D = 7;
    uint256 private constant A = 12;        // FORS tree height
    uint256 private constant K = 14;        // FORS trees
    uint256 private constant LEN = 35;      // WOTS+ len1(32) + len2(3)
    uint256 private constant SIG_LEN = 7856;
    uint256 private constant PK_LEN = 32;
    uint256 private constant WOTS_SIG = LEN * N;        // 560
    uint256 private constant XMSS_SIG = (HP + LEN) * N; // 704
    uint256 private constant FORS_SIG = K * (A + 1) * N; // 2912

    // ADRS types (FIPS 205)
    uint256 private constant WOTS_HASH = 0;
    uint256 private constant WOTS_PK = 1;
    uint256 private constant TREE = 2;
    uint256 private constant FORS_TREE = 3;
    uint256 private constant FORS_ROOTS = 4;

    // Workspace offsets
    uint256 private constant ADRS_OFF = 64;
    uint256 private constant MSG_OFF = 86;
    uint256 private constant SCRATCH = 672;
    uint256 private constant ROOTS = 736;
    uint256 private constant WTMP = 992;
    uint256 private constant WS_SIZE = 1600;

    /// @notice Verify an SLH-DSA-SHA2-128s signature over `message` (the 32-byte mu in this system).
    /// @param pk 32-byte public key (PK.seed(16) || PK.root(16))
    /// @param message the signed message
    /// @param sig 7856-byte signature
    function verify(bytes calldata pk, bytes calldata message, bytes calldata sig)
        internal view returns (bool)
    {
        if (pk.length != PK_LEN || sig.length != SIG_LEN) return false;

        // ---- workspace ----
        uint256 ws;
        uint256 sigOff; // absolute calldata offset of the signature bytes
        assembly ("memory-safe") {
            ws := mload(0x40)
            mstore(0x40, add(ws, WS_SIZE))
            // constant first SHA-256 block: PK.seed(16) || 48 zero bytes
            calldatacopy(ws, pk.offset, 16)
            mstore(add(ws, 16), 0)
            mstore(add(ws, 32), 0)
            sigOff := sig.offset
        }

        // ---- Hmsg (FIPS 205): R = sig[0:16]; pure-mode prefix 0x00 || ctxLen(0x00) || M ----
        //   inner  = SHA256(R || PK.seed || PK.root || 0x0000 || M)
        //   digest = MGF1-SHA256(R || PK.seed || inner, 30)
        //          = first 30 bytes of SHA256(R || PK.seed || inner || counter(0)), since 30 < 32.
        // HARDENING: assembly assignment into bytesNN bypasses the compiler's value cleaning, so the
        // low 16 bytes of each word would carry adjacent calldata. Nothing below reads those bytes
        // under the current compiler (bytes.concat copies exactly 16, the final compare shifts them
        // out) — but that is a property of THIS compiler's codegen, not of the source. Mask them off
        // so no future compiler or refactor can ever leak neighbouring calldata into a hash input.
        bytes16 rB;
        bytes16 seedB;
        bytes16 rootB;
        assembly ("memory-safe") {
            let hi := shl(128, sub(shl(128, 1), 1)) // 0xffff...ffff0000...0000
            rB := and(calldataload(sig.offset), hi)
            seedB := and(calldataload(pk.offset), hi)
            rootB := and(calldataload(add(pk.offset, 16)), hi)
        }
        bytes32 inner = sha256(bytes.concat(rB, seedB, rootB, hex"0000", message));
        uint256 digest = uint256(sha256(bytes.concat(rB, seedB, inner, hex"00000000")));

        // md = digest[0:21]; idxTree = digest[21:28] mod 2^54; idxLeaf = digest[28:30] mod 2^9
        uint256 md = digest >> 88;                                   // 168-bit, right-aligned
        uint256 idxTree = (digest >> 32) & ((1 << 54) - 1);          // low 54 of bytes 21..27
        uint256 idxLeaf = (digest >> 16) & (uint256(1 << HP) - 1);   // low 9 of bytes 28..29

        bytes32 node = _forsPkFromSig(ws, sigOff + 16, md, idxTree, idxLeaf);

        // ---- ht_verify: 7 XMSS layers up to PK.root ----
        uint256 htOff = sigOff + 16 + FORS_SIG;
        node = _xmssPkFromSig(ws, idxLeaf, htOff, node, 0, idxTree);
        for (uint256 j = 1; j < D; j++) {
            idxLeaf = idxTree & ((1 << HP) - 1);
            idxTree >>= HP;
            node = _xmssPkFromSig(ws, idxLeaf, htOff + j * XMSS_SIG, node, j, idxTree);
        }
        return (uint256(node) >> 128) == (uint256(bytes32(rootB)) >> 128);
    }

    /// @dev Write the 22-byte compressed ADRS with ONE mstore (bytes 22..31 of the word land in the
    ///      message area and are overwritten by the message write that MUST follow). Field layout is
    ///      byte-identical to the reference `adrsc`: layer(1) tree(8) type(1) 00 00 keypair(2)
    ///      00 00 00 chainOrHeight(1) treeIndex(4); a non-zero hash address overrides byte 21.
    function _setAdrs(
        uint256 ws, uint256 layer, uint256 tree, uint256 typ,
        uint256 keypair, uint256 chainH, uint256 treeIdx, uint256 hashAddr
    ) private pure {
        uint256 ti = treeIdx & 0xFFFFFFFF;
        if (hashAddr != 0) ti = (ti & 0xFFFFFF00) | (hashAddr & 0xFF);
        uint256 w = ((layer & 0xFF) << 248)
            | ((tree & 0xFFFFFFFFFFFFFFFF) << 184)
            | ((typ & 0xFF) << 176)
            | ((keypair & 0xFFFF) << 144)
            | ((chainH & 0xFF) << 112)
            | (ti << 80);
        assembly ("memory-safe") { mstore(add(ws, ADRS_OFF), w) }
    }

    /// @dev SHA-256 over ws[0 .. 86+msgLen). Returns the raw 32-byte digest; callers use the high
    ///      16 bytes (Trunc_n). The precompile cannot fail given gas; an OOG propagates as intended.
    function _sha(uint256 ws, uint256 msgLen) private view returns (bytes32 out) {
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 2, ws, add(MSG_OFF, msgLen), add(ws, SCRATCH), 32)) {
                revert(0, 0)
            }
            out := mload(add(ws, SCRATCH))
        }
    }

    /// @dev WOTS+ chain, fully in place: the 16-byte start value sits at ws+86; each step writes the
    ///      digest straight back over ws+86 so the next input is already staged, and only the hash
    ///      address (ADRS byte 21) changes. Zero steps leaves the start value untouched — same as
    ///      the reference. Matches the reference's byte-21 semantics: step i=0 writes 0, which is
    ///      what the un-overridden treeIndex low byte (0 in a WOTS chain) held anyway.
    function _chainSteps(uint256 ws, uint256 start, uint256 steps) private view {
        assembly ("memory-safe") {
            for { let i := start let end := add(start, steps) } lt(i, end) { i := add(i, 1) } {
                mstore8(add(ws, 85), i)
                if iszero(staticcall(gas(), 2, ws, 102, add(ws, MSG_OFF), 32)) { revert(0, 0) }
            }
        }
    }

    /// @dev wots_PKFromSig. `mNode` carries the 16-byte message in its HIGH half (the low half is
    ///      digest residue and is never read).
    function _wotsPkFromSig(
        uint256 ws, uint256 sigOff, bytes32 mNode, uint256 layer, uint256 tree, uint256 keypair
    ) private view returns (bytes32) {
        // base_w digits: the 32 nibbles of the 16-byte message, high-first, then 3 checksum digits.
        uint256 v = uint256(mNode) >> 128;
        uint256 csum = 32 * 15;
        for (uint256 i = 0; i < 32; i++) csum -= (v >> (4 * i)) & 0xF; // sum of digits, any order
        uint256 c16 = (csum << 4) & 0xFFFF; // reference: csum <<= 4, then 2 bytes BE, base_w(3)

        for (uint256 i = 0; i < LEN; i++) {
            uint256 digit = i < 32
                ? (v >> (4 * (31 - i))) & 0xF
                : (c16 >> (4 * (34 - i) + 4)) & 0xF; // digits 32,33,34 <- bits 15..12, 11..8, 7..4
            _setAdrs(ws, layer, tree, WOTS_HASH, keypair, i, 0, 0);
            uint256 src = sigOff + i * N;
            assembly ("memory-safe") { calldatacopy(add(ws, MSG_OFF), src, N) }
            _chainSteps(ws, digit, 15 - digit);
            uint256 dst = ws + WTMP + i * N;
            assembly ("memory-safe") { mcopy(dst, add(ws, MSG_OFF), N) }
        }
        // compress: T_len over the 560-byte chain-head concatenation
        _setAdrs(ws, layer, tree, WOTS_PK, keypair, 0, 0, 0);
        assembly ("memory-safe") { mcopy(add(ws, MSG_OFF), add(ws, WTMP), 560) } // 560 = WOTS_SIG
        return _sha(ws, WOTS_SIG);
    }

    /// @dev xmss_PKFromSig: WOTS+ pk, then h'=9 auth-path levels.
    function _xmssPkFromSig(
        uint256 ws, uint256 idx, uint256 sigOff, bytes32 mNode, uint256 layer, uint256 tree
    ) private view returns (bytes32 node) {
        node = _wotsPkFromSig(ws, sigOff, mNode, layer, tree, idx);
        uint256 authOff = sigOff + WOTS_SIG;
        uint256 ti = idx;
        for (uint256 k = 0; k < HP; k++) {
            bool left = (idx >> k) & 1 == 0;
            ti = left ? ti / 2 : (ti - 1) / 2;
            _setAdrs(ws, layer, tree, TREE, 0, k + 1, ti, 0);
            uint256 src = authOff + k * N;
            if (left) {
                assembly ("memory-safe") {
                    mstore(add(ws, MSG_OFF), node)                 // bytes 86..101 = node
                    calldatacopy(add(ws, add(MSG_OFF, N)), src, N) // bytes 102..117 = auth
                }
            } else {
                assembly ("memory-safe") {
                    calldatacopy(add(ws, MSG_OFF), src, N)         // bytes 86..101 = auth
                    mstore(add(ws, add(MSG_OFF, N)), node)         // bytes 102..117 = node
                }
            }
            node = _sha(ws, 2 * N);
        }
    }

    /// @dev fors_pkFromSig: k=14 trees, each a leaf hash plus a=12 auth levels, then T_k over roots.
    function _forsPkFromSig(
        uint256 ws, uint256 forsOff, uint256 md, uint256 tree, uint256 idxLeaf
    ) private view returns (bytes32) {
        for (uint256 i = 0; i < K; i++) {
            // FORS index i: the i-th 12-bit big-endian chunk of the 168-bit md.
            uint256 idx = (md >> (168 - A * (i + 1))) & ((1 << A) - 1);
            uint256 base = forsOff + i * ((A + 1) * N);
            uint256 t = i * (1 << A) + idx;

            _setAdrs(ws, 0, tree, FORS_TREE, idxLeaf, 0, t, 0);
            assembly ("memory-safe") { calldatacopy(add(ws, MSG_OFF), base, N) }
            bytes32 node = _sha(ws, N);

            uint256 authOff = base + N;
            for (uint256 j = 0; j < A; j++) {
                bool left = (idx >> j) & 1 == 0;
                t = left ? t / 2 : (t - 1) / 2;
                _setAdrs(ws, 0, tree, FORS_TREE, idxLeaf, j + 1, t, 0);
                uint256 src = authOff + j * N;
                if (left) {
                    assembly ("memory-safe") {
                        mstore(add(ws, MSG_OFF), node)
                        calldatacopy(add(ws, add(MSG_OFF, N)), src, N)
                    }
                } else {
                    assembly ("memory-safe") {
                        calldatacopy(add(ws, MSG_OFF), src, N)
                        mstore(add(ws, add(MSG_OFF, N)), node)
                    }
                }
                node = _sha(ws, 2 * N);
            }
            // Root i -> roots buffer. The 32-byte store spills 16B into the next slot (or the slack
            // word after root 13); every spilled byte is overwritten before it is read.
            uint256 dst = ws + ROOTS + i * N;
            assembly ("memory-safe") { mstore(dst, node) }
        }
        _setAdrs(ws, 0, tree, FORS_ROOTS, idxLeaf, 0, 0, 0);
        assembly ("memory-safe") { mcopy(add(ws, MSG_OFF), add(ws, ROOTS), mul(K, N)) }
        return _sha(ws, K * N);
    }
}
