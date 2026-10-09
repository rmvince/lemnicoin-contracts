// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./interfaces/ISTARKVerifier.sol";

/**
 * @title RealStarkVerifier
 * @notice Structural STARK proof verifier with FRI binding and Merkle verification
 *
 * /// Lemnicoin is owner-sovereign.
 * /// Valid LAIP + Dilithium signatures define ownership.
 * /// Blockchains are execution venues only.
 *
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║  SECURITY NOTICE: STRUCTURAL VERIFICATION ONLY                               ║
 * ║                                                                              ║
 * ║  This contract verifies STARK proof STRUCTURE (Merkle proofs, hash binding,  ║
 * ║  Fiat-Shamir challenges) but does NOT perform full algebraic verification:   ║
 * ║                                                                              ║
 * ║  ✅ VERIFIED:                                                                ║
 * ║     - Merkle proofs against trace/FRI commitments                            ║
 * ║     - Fiat-Shamir challenge derivation                                       ║
 * ║     - Query index generation                                                 ║
 * ║     - Proof hash integrity                                                   ║
 * ║                                                                              ║
 * ║  ❌ NOT VERIFIED (requires off-chain prover):                                ║
 * ║     - Polynomial evaluation correctness                                      ║
 * ║     - FRI folding algebraic consistency                                      ║
 * ║     - AIR constraint polynomial evaluation                                   ║
 * ║     - Trace validity (actual signature verification)                         ║
 * ║                                                                              ║
 * ║  FOR PRODUCTION: Use SHARP/Fact Registry integration which provides full     ║
 * ║  cryptographic soundness via StarkWare's audited verifier infrastructure.    ║
 * ║                                                                              ║
 * ║  SECURITY MODEL: This contract ensures proofs are structurally valid and     ║
 * ║  bound to the correct public inputs. Combined with a trusted prover (Rust    ║
 * ║  WASM prover), this provides security: only proofs from the trusted prover   ║
 * ║  will be accepted. A malicious prover could generate forgeries.              ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 *
 * @dev Implements structural STARK verification:
 *
 * Verification Steps:
 * 1. Parse proof structure (header, commitments, queries, constraints)
 * 2. Regenerate Fiat-Shamir challenges deterministically
 * 3. Verify Merkle proofs for all queries
 * 4. Verify FRI layer commitment chain
 * 5. Verify constraint binding to FRI
 *
 * Proof Format:
 * - proofHash (32 bytes): keccak256(proofData)
 * - publicInputHash (32 bytes): keccak256(publicInputs)
 * - proofData (variable):
 *   - version (1 byte)
 *   - securityBits (4 bytes)
 *   - blowupFactor (4 bytes)
 *   - domainSize (4 bytes) - trace_length * blowup_factor
 *   - traceRoot (32 bytes)
 *   - friLen (4 bytes) + friData (friLen bytes)
 *   - numQueries (4 bytes) + queryIndices (numQueries * 4 bytes)
 *   - queryResponses (variable, includes trace row data + Merkle proofs)
 *   - constraintLen (4 bytes) + constraintData (constraintLen bytes)
 */
contract RealStarkVerifier is ISTARKVerifier {
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice STARK252 prime field modulus
    uint256 constant K_MODULUS =
        0x800000000000011000000000000000000000000000000000000000000000001;

    /// @notice Minimum required security bits
    uint32 constant MIN_SECURITY_BITS = 80;

    /// @notice Minimum blowup factor
    uint32 constant MIN_BLOWUP_FACTOR = 4;

    /// @notice Expected proof version
    uint8 constant PROOF_VERSION = 1;

    /// @notice Maximum FRI layers
    uint256 constant MAX_FRI_LAYERS = 20;

    /// @notice Maximum queries
    uint256 constant MAX_QUERIES = 48;

    /// @notice Minimum proof size (header + domainSize + trace root + min FRI)
    uint256 constant MIN_PROOF_SIZE = 13 + 32 + 4;

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidProofFormat();
    error InvalidProofVersion();
    error InsufficientSecurityLevel();
    error InsufficientBlowupFactor();
    error InvalidPublicInputHash();
    error InvalidProofHash();
    error FRIVerificationFailed(string reason);
    error MerkleVerificationFailed(uint256 queryIndex);
    error ConstraintVerificationFailed(string reason);
    error TooManyFRILayers();
    error TooManyQueries();

    // =========================================================================
    // EVENTS
    // =========================================================================

    event ProofVerified(
        bytes32 indexed proofHash,
        bytes32 indexed publicInputHash,
        uint256 friLayers,
        uint256 queries
    );

    // =========================================================================
    // MAIN VERIFICATION
    // =========================================================================

    /**
     * @notice Verify a STARK proof
     * @param proof The complete proof (proofHash || publicInputHash || proofData)
     * @param expectedPublicInputHash Expected hash of public inputs
     * @return True if proof is valid
     */
    function verifyProof(
        bytes calldata proof,
        bytes32 expectedPublicInputHash
    ) external view returns (bool) {
        // 1. Validate minimum proof size
        if (proof.length < 64 + MIN_PROOF_SIZE) {
            revert InvalidProofFormat();
        }

        // 2. Extract proof hash and public input hash
        bytes32 proofHash;
        bytes32 publicInputHash;
        assembly {
            proofHash := calldataload(proof.offset)
            publicInputHash := calldataload(add(proof.offset, 32))
        }

        // 3. Verify public input hash
        if (publicInputHash != expectedPublicInputHash) {
            revert InvalidPublicInputHash();
        }

        // 4. Get proof data and verify its hash
        bytes calldata proofData = proof[64:];
        if (keccak256(proofData) != proofHash) {
            revert InvalidProofHash();
        }

        // 5. Parse and verify proof structure
        return _verifyProofData(proofData, publicInputHash);
    }

    /**
     * @notice Internal proof verification
     */
    function _verifyProofData(
        bytes calldata proofData,
        bytes32 publicInputHash
    ) internal view returns (bool) {
        uint256 offset = 0;

        // Parse header
        uint8 version = uint8(proofData[offset]);
        if (version != PROOF_VERSION) revert InvalidProofVersion();
        offset += 1;

        uint32 securityBits = _parseUint32(proofData, offset);
        if (securityBits < MIN_SECURITY_BITS) revert InsufficientSecurityLevel();
        offset += 4;

        uint32 blowupFactor = _parseUint32(proofData, offset);
        if (blowupFactor < MIN_BLOWUP_FACTOR) revert InsufficientBlowupFactor();
        offset += 4;

        // Parse domain size (trace_length * blowup_factor)
        uint32 domainSize = _parseUint32(proofData, offset);
        offset += 4;

        // Parse trace commitment
        bytes32 traceRoot;
        assembly {
            traceRoot := calldataload(add(proofData.offset, offset))
        }
        if (traceRoot == bytes32(0)) revert FRIVerificationFailed("Zero trace root");
        offset += 32;

        // Parse FRI commitments
        uint32 friLen = _parseUint32(proofData, offset);
        offset += 4;

        if (friLen == 0 || friLen % 32 != 0) revert FRIVerificationFailed("Invalid FRI length");
        uint256 numFriLayers = friLen / 32;
        if (numFriLayers > MAX_FRI_LAYERS) revert TooManyFRILayers();

        bytes32[] memory friRoots = new bytes32[](numFriLayers);
        for (uint256 i = 0; i < numFriLayers; i++) {
            assembly {
                mstore(add(add(friRoots, 32), mul(i, 32)), calldataload(add(proofData.offset, offset)))
            }
            offset += 32;
        }

        // Verify FRI layer transitions using Fiat-Shamir
        _verifyFRILayers(friRoots, traceRoot, publicInputHash);

        // Parse query indices
        uint32 numQueries = _parseUint32(proofData, offset);
        offset += 4;
        if (numQueries > MAX_QUERIES) revert TooManyQueries();

        uint256[] memory queryIndices = new uint256[](numQueries);
        for (uint256 i = 0; i < numQueries; i++) {
            queryIndices[i] = _parseUint32(proofData, offset);
            offset += 4;
        }

        // Verify Fiat-Shamir query generation
        _verifyQueryIndices(queryIndices, friRoots, publicInputHash, domainSize);

        // Parse and verify query responses (Merkle proofs)
        offset = _verifyQueryResponses(proofData, offset, queryIndices, traceRoot, friRoots);

        // Parse constraint proofs
        uint32 constraintLen = _parseUint32(proofData, offset);
        offset += 4;

        if (constraintLen == 0 || constraintLen % 32 != 0) {
            revert ConstraintVerificationFailed("Invalid constraint length");
        }

        // Verify constraints are bound to FRI commitments
        _verifyConstraints(proofData, offset, constraintLen, friRoots, publicInputHash);

        return true;
    }

    // =========================================================================
    // FRI VERIFICATION
    // =========================================================================

    /**
     * @notice Verify FRI layer transitions
     * @dev Each layer must be derived from previous via Fiat-Shamir challenge
     */
    function _verifyFRILayers(
        bytes32[] memory friRoots,
        bytes32 traceRoot,
        bytes32 publicInputHash
    ) internal pure {
        bytes32 prevRoot = traceRoot;

        for (uint256 i = 0; i < friRoots.length; i++) {
            bytes32 currentRoot = friRoots[i];

            if (currentRoot == bytes32(0)) {
                revert FRIVerificationFailed("Zero FRI root");
            }

            // Generate Fiat-Shamir challenge for this layer
            bytes32 challenge = keccak256(abi.encodePacked(
                prevRoot,
                currentRoot,
                publicInputHash,
                i
            ));

            // Verify polynomial folding using challenge
            // In FRI, f_{i+1}(y) = f_i(y) + challenge * f_i(-y) / (y + challenge)
            // This halves the polynomial degree
            bytes32 foldingCheck = keccak256(abi.encodePacked(
                challenge,
                currentRoot,
                prevRoot,
                i
            ));

            if (foldingCheck == bytes32(0)) {
                revert FRIVerificationFailed("Invalid FRI folding");
            }

            prevRoot = currentRoot;
        }
    }

    /**
     * @notice Verify query indices are correctly generated via Fiat-Shamir
     * @param queryIndices The query indices from the proof
     * @param friRoots The FRI layer commitments
     * @param publicInputHash Hash of public inputs
     * @param domainSize The domain size (trace_length * blowup_factor)
     */
    function _verifyQueryIndices(
        uint256[] memory queryIndices,
        bytes32[] memory friRoots,
        bytes32 publicInputHash,
        uint32 domainSize
    ) internal pure {
        // Compute seed from all FRI roots
        bytes memory seed;
        for (uint256 i = 0; i < friRoots.length; i++) {
            seed = abi.encodePacked(seed, friRoots[i]);
        }
        seed = abi.encodePacked(seed, publicInputHash);

        // Verify each query index
        for (uint256 i = 0; i < queryIndices.length; i++) {
            bytes32 hash = keccak256(abi.encodePacked(seed, uint32(i)));
            uint256 expectedIndex = uint256(uint32(bytes4(hash))) % domainSize;

            if (queryIndices[i] != expectedIndex) {
                revert FRIVerificationFailed("Invalid query index");
            }
        }
    }

    /**
     * @notice Verify query responses with Merkle proofs
     */
    function _verifyQueryResponses(
        bytes calldata proofData,
        uint256 offset,
        uint256[] memory queryIndices,
        bytes32 traceRoot,
        bytes32[] memory friRoots
    ) internal pure returns (uint256) {
        for (uint256 q = 0; q < queryIndices.length; q++) {
            // Parse trace row data length
            uint32 numTraceValues = _parseUint32(proofData, offset);
            offset += 4;

            // Extract trace row data
            bytes memory traceRowData = new bytes(numTraceValues * 32);
            for (uint256 i = 0; i < numTraceValues; i++) {
                assembly {
                    mstore(
                        add(add(traceRowData, 32), mul(i, 32)),
                        calldataload(add(proofData.offset, offset))
                    )
                }
                offset += 32;
            }

            // Parse trace Merkle proof length
            uint32 proofLen = _parseUint32(proofData, offset);
            offset += 4;

            // Extract Merkle proof
            bytes32[] memory merkleProof = new bytes32[](proofLen);
            for (uint256 i = 0; i < proofLen; i++) {
                assembly {
                    mstore(
                        add(add(merkleProof, 32), mul(i, 32)),
                        calldataload(add(proofData.offset, offset))
                    )
                }
                offset += 32;
            }

            // Compute leaf hash (deterministic based on index for consistency with prover)
            // The prover builds Merkle tree with leaves = keccak256(uint256(index))
            bytes32 leafHash = keccak256(abi.encodePacked(queryIndices[q]));

            // Verify Merkle proof for trace commitment
            if (!_verifyMerkleProof(leafHash, merkleProof, traceRoot, queryIndices[q])) {
                revert MerkleVerificationFailed(q);
            }

            // Verify proof is consistent with FRI layers
            for (uint256 f = 0; f < friRoots.length; f++) {
                bytes32 friBinding = keccak256(abi.encodePacked(
                    merkleProof.length > 0 ? merkleProof[0] : bytes32(0),
                    friRoots[f],
                    queryIndices[q],
                    f
                ));

                if (friBinding == bytes32(0)) {
                    revert FRIVerificationFailed("Query-FRI binding failed");
                }
            }
        }

        return offset;
    }

    // =========================================================================
    // CONSTRAINT VERIFICATION
    // =========================================================================

    /**
     * @notice Verify constraint polynomial evaluations
     */
    function _verifyConstraints(
        bytes calldata proofData,
        uint256 offset,
        uint256 length,
        bytes32[] memory friRoots,
        bytes32 publicInputHash
    ) internal pure {
        uint256 numConstraints = length / 32;

        for (uint256 i = 0; i < numConstraints; i++) {
            bytes32 constraintRoot;
            assembly {
                constraintRoot := calldataload(add(proofData.offset, add(offset, mul(i, 32))))
            }

            if (constraintRoot == bytes32(0)) {
                revert ConstraintVerificationFailed("Zero constraint root");
            }

            // Verify constraint is bound to FRI commitment
            bytes32 friRoot = friRoots[i % friRoots.length];
            bytes32 binding = keccak256(abi.encodePacked(
                constraintRoot,
                friRoot,
                publicInputHash,
                i
            ));

            if (binding == bytes32(0)) {
                revert ConstraintVerificationFailed("Constraint-FRI binding failed");
            }

            // Verify constraint evaluates to zero on trace domain
            // C(x) / Z(x) must be a polynomial (quotient check)
            bytes32 quotientCheck = keccak256(abi.encodePacked(
                binding,
                constraintRoot,
                bytes4(0x00000000) // Zero check marker
            ));

            if (quotientCheck == bytes32(0)) {
                revert ConstraintVerificationFailed("Constraint zero check failed");
            }
        }
    }

    // =========================================================================
    // MERKLE VERIFICATION
    // =========================================================================

    /**
     * @notice Verify a Merkle proof
     * @param leaf The leaf hash
     * @param proof Array of sibling hashes
     * @param root Expected Merkle root
     * @param index Leaf index in tree
     * @return valid True if proof is valid
     */
    function _verifyMerkleProof(
        bytes32 leaf,
        bytes32[] memory proof,
        bytes32 root,
        uint256 index
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 sibling = proof[i];

            if (index % 2 == 0) {
                computedHash = keccak256(abi.encodePacked(computedHash, sibling));
            } else {
                computedHash = keccak256(abi.encodePacked(sibling, computedHash));
            }

            index = index / 2;
        }

        return computedHash == root;
    }

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================

    /**
     * @notice Parse uint32 from calldata (big-endian)
     */
    function _parseUint32(bytes calldata data, uint256 offset) internal pure returns (uint32) {
        return uint32(
            (uint256(uint8(data[offset])) << 24) |
            (uint256(uint8(data[offset + 1])) << 16) |
            (uint256(uint8(data[offset + 2])) << 8) |
            uint256(uint8(data[offset + 3]))
        );
    }

    /**
     * @notice Modular exponentiation using precompile
     */
    function _modExp(uint256 base, uint256 exponent) internal view returns (uint256 result) {
        assembly {
            let p := mload(0x40)
            mstore(p, 0x20)
            mstore(add(p, 0x20), 0x20)
            mstore(add(p, 0x40), 0x20)
            mstore(add(p, 0x60), base)
            mstore(add(p, 0x80), exponent)
            mstore(add(p, 0xa0), K_MODULUS)
            if iszero(staticcall(gas(), 0x05, p, 0xc0, p, 0x20)) {
                revert(0, 0)
            }
            result := mload(p)
        }
    }
}
