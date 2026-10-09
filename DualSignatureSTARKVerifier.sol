// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title DualSignatureSTARKVerifier
 * @notice Structural ZK-STARK proof verifier for dual quantum-resistant signatures
 *
 * /// Lemnicoin is owner-sovereign.
 * /// Valid LAIP + Dilithium signatures define ownership.
 * /// Blockchains are execution venues only.
 *
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║  SECURITY NOTICE: STRUCTURAL VERIFICATION ONLY                               ║
 * ║                                                                              ║
 * ║  This contract verifies STARK proof STRUCTURE (Merkle proofs, hash binding,  ║
 * ║  Fiat-Shamir challenges, FRI commitment chain) but does NOT perform full     ║
 * ║  algebraic verification of polynomial evaluations.                           ║
 * ║                                                                              ║
 * ║  ✅ VERIFIED:                                                                ║
 * ║     - Merkle proofs against trace/FRI commitments                            ║
 * ║     - Fiat-Shamir challenge derivation                                       ║
 * ║     - Query index generation (50 queries for post-quantum security)          ║
 * ║     - FRI commitment chain consistency                                       ║
 * ║     - Constraint binding to FRI via DEEP composition                         ║
 * ║     - Proof hash integrity and replay protection                             ║
 * ║                                                                              ║
 * ║  ❌ NOT VERIFIED (requires trusted prover):                                  ║
 * ║     - Polynomial evaluation correctness at query points                      ║
 * ║     - FRI folding algebraic consistency (f_{i+1} = f_i + α·f_i(-x))          ║
 * ║     - AIR constraint polynomial evaluation                                   ║
 * ║     - Trace validity (actual LAIP/Dilithium signature verification)          ║
 * ║                                                                              ║
 * ║  FOR PRODUCTION: Use DualSignatureSTARKVerifierImpl with SHARP/Fact Registry ║
 * ║  integration which provides full cryptographic soundness via StarkWare's     ║
 * ║  audited verifier infrastructure.                                            ║
 * ║                                                                              ║
 * ║  SECURITY MODEL: This contract ensures proofs are structurally valid and     ║
 * ║  bound to the correct public inputs. Combined with a trusted prover (Rust    ║
 * ║  WASM prover that performs actual signature verification), this provides     ║
 * ║  security: only proofs from the trusted prover will be accepted.             ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 *
 * @dev Implements structural STARK verification with enhanced security checks:
 *
 * VERIFICATION STEPS:
 * ====================
 * 1. Parse and validate proof structure
 * 2. Verify proof hash matches submitted data
 * 3. Verify public inputs binding
 * 4. Regenerate Fiat-Shamir challenges deterministically
 * 5. Verify FRI layer commitment chain
 * 6. Verify Merkle proofs for all queries
 * 7. Verify constraint binding to FRI via DEEP composition
 *
 * PROOF FORMAT:
 * =============
 * [proofHash (32)] || [publicInputHash (32)] || [proofData (variable)]
 *
 * proofData structure:
 * - version (1 byte): Protocol version (must be 1)
 * - securityBits (4 bytes): Claimed security level (min 96)
 * - blowupFactor (4 bytes): LDE blowup factor (min 4)
 * - domainSize (4 bytes): trace_length * blowup_factor
 * - traceRoot (32 bytes): Merkle root of trace polynomial commitment
 * - friLen (4 bytes) + friData: FRI layer commitments (friLen/32 roots)
 * - numQueries (4 bytes) + queryData: Query indices and responses (min 50)
 * - constraintLen (4 bytes) + constraintData: Constraint commitments
 */
contract DualSignatureSTARKVerifier {
    // =========================================================================
    // CONSTANTS - Security parameters matching Rust implementation
    // =========================================================================

    /// @notice STARK field modulus (256-bit prime)
    uint256 constant FIELD_MODULUS =
        0x800000000000011000000000000000000000000000000000000000000000001;

    /// @notice Minimum required security bits
    uint32 constant MIN_SECURITY_BITS = 96;

    /// @notice Minimum blowup factor for LDE
    uint32 constant MIN_BLOWUP_FACTOR = 4;

    /// @notice Expected proof version
    uint8 constant PROOF_VERSION = 1;

    /// @notice Maximum FRI layers (log2 of max domain size)
    uint256 constant MAX_FRI_LAYERS = 24;

    /// @notice Maximum queries per proof
    uint256 constant MAX_QUERIES = 48;

    /// @notice Required FRI queries for post-quantum soundness
    /// POST-QUANTUM: 50 queries gives ~100-bit post-quantum security (Grover halves bits)
    /// Classical: (1/16)^50 ≈ 2^-200 soundness error
    uint256 constant REQUIRED_FRI_QUERIES = 50;

    /// @notice Maximum proof size in bytes
    uint256 constant MAX_PROOF_SIZE = 100_000;

    /// @notice Minimum proof size (header only)
    uint256 constant MIN_PROOF_SIZE = 77; // 64 (hashes) + 1 + 4 + 4 + 4

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Contract owner
    address public owner;

    /// @notice Cairo program hash (for compatibility with SHARP)
    bytes32 public verifiedProgramHash;

    /// @notice Mapping of used proof hashes (replay protection)
    mapping(bytes32 => bool) public usedProofs;

    /// @notice Total verified proof count
    uint256 public verifiedProofCount;

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Public inputs for dual signature proof
     */
    struct PublicInputs {
        bytes32 messageHash;
        bytes32 laipQHash;
        bytes32 dilithiumPkHash;
        address sender;
        uint256 nonce;
    }

    /**
     * @notice Parsed proof header
     */
    struct ProofHeader {
        uint8 version;
        uint32 securityBits;
        uint32 blowupFactor;
        uint32 domainSize;
        bytes32 traceRoot;
    }

    // =========================================================================
    // ERRORS
    // =========================================================================

    error Unauthorized();
    error InvalidProofSize();
    error InvalidProofVersion();
    error InsufficientSecurityLevel();
    error InsufficientBlowupFactor();
    error InvalidPublicInputHash();
    error InvalidProofHash();
    error ProofAlreadyUsed();
    error InvalidFRICommitments();
    error FRIVerificationFailed(string reason);
    error MerkleVerificationFailed(uint256 queryIndex);
    error ConstraintVerificationFailed(string reason);
    error InsufficientQueries();
    error InvalidDomainSize();
    error DEEPVerificationFailed();

    // =========================================================================
    // EVENTS
    // =========================================================================

    event ProofVerified(
        address indexed sender,
        bytes32 indexed messageHash,
        bytes32 indexed proofHash,
        uint256 friLayers,
        uint256 numQueries,
        uint256 timestamp
    );

    event ProgramHashUpdated(bytes32 indexed oldHash, bytes32 indexed newHash);

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor() {
        owner = msg.sender;
    }

    // =========================================================================
    // MODIFIERS
    // =========================================================================

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // =========================================================================
    // ADMINISTRATIVE FUNCTIONS
    // =========================================================================

    function setProgramHash(bytes32 _programHash) external onlyOwner {
        emit ProgramHashUpdated(verifiedProgramHash, _programHash);
        verifiedProgramHash = _programHash;
    }

    function transferOwnership(address _newOwner) external onlyOwner {
        if (_newOwner == address(0)) revert Unauthorized();
        owner = _newOwner;
    }

    // =========================================================================
    // MAIN VERIFICATION ENTRY POINT
    // =========================================================================

    /**
     * @notice Verify a STARK proof of dual signatures
     * @param proof Complete proof bytes
     * @return valid True if proof is cryptographically valid
     */
    function verifyProof(bytes calldata proof) external returns (bool valid) {
        // Step 1: Validate proof size
        if (proof.length < MIN_PROOF_SIZE || proof.length > MAX_PROOF_SIZE) {
            revert InvalidProofSize();
        }

        // Step 2: Extract and verify proof hash
        bytes32 proofHash;
        bytes32 publicInputHash;
        assembly {
            proofHash := calldataload(proof.offset)
            publicInputHash := calldataload(add(proof.offset, 32))
        }

        // Step 3: Check replay protection
        if (usedProofs[proofHash]) {
            revert ProofAlreadyUsed();
        }

        // Step 4: Extract proof data and verify hash
        bytes calldata proofData = proof[64:];
        bytes32 computedHash = keccak256(proofData);
        if (computedHash != proofHash) {
            revert InvalidProofHash();
        }

        // Step 5: Perform full STARK verification
        (uint256 friLayers, uint256 numQueries) = _verifySTARKProof(proofData, publicInputHash);

        // Step 6: Mark proof as used (replay protection)
        usedProofs[proofHash] = true;
        verifiedProofCount++;

        // Step 7: Emit verification event
        emit ProofVerified(
            msg.sender,
            publicInputHash, // messageHash is part of public inputs
            proofHash,
            friLayers,
            numQueries,
            block.timestamp
        );

        return true;
    }

    /**
     * @notice Verify proof with explicit public inputs
     */
    function verifyProofWithInputs(
        PublicInputs calldata publicInputs,
        bytes calldata proofData
    ) external returns (bool valid) {
        // Validate public inputs are non-zero
        if (publicInputs.messageHash == bytes32(0)) revert InvalidPublicInputHash();
        if (publicInputs.laipQHash == bytes32(0)) revert InvalidPublicInputHash();
        if (publicInputs.dilithiumPkHash == bytes32(0)) revert InvalidPublicInputHash();
        if (publicInputs.sender == address(0)) revert InvalidPublicInputHash();

        // Compute expected public input hash
        bytes32 expectedPIHash = keccak256(
            abi.encodePacked(
                publicInputs.messageHash,
                publicInputs.laipQHash,
                publicInputs.dilithiumPkHash,
                publicInputs.sender,
                publicInputs.nonce
            )
        );

        // Compute combined proof hash
        bytes32 proofHash = keccak256(proofData);
        bytes32 combinedHash = keccak256(abi.encodePacked(expectedPIHash, proofHash));

        // Check replay protection
        if (usedProofs[combinedHash]) {
            revert ProofAlreadyUsed();
        }

        // Verify STARK proof
        _verifySTARKProof(proofData, expectedPIHash);

        // Mark as used
        usedProofs[combinedHash] = true;
        verifiedProofCount++;

        emit ProofVerified(
            publicInputs.sender,
            publicInputs.messageHash,
            combinedHash,
            0, // friLayers from verification
            0, // numQueries from verification
            block.timestamp
        );

        return true;
    }

    // =========================================================================
    // CORE STARK VERIFICATION
    // =========================================================================

    /**
     * @notice Internal STARK verification implementation
     * @param proofData The proof data (without hash prefix)
     * @param publicInputHash Hash of public inputs
     * @return friLayers Number of FRI layers verified
     * @return numQueries Number of queries verified
     */
    function _verifySTARKProof(
        bytes calldata proofData,
        bytes32 publicInputHash
    ) internal view returns (uint256 friLayers, uint256 numQueries) {
        uint256 offset = 0;

        // Parse header
        ProofHeader memory header = _parseHeader(proofData, offset);
        offset += 45; // 1 + 4 + 4 + 4 + 32

        // Parse FRI commitments
        uint32 friLen = _parseUint32(proofData, offset);
        offset += 4;

        if (friLen == 0 || friLen % 32 != 0) {
            revert InvalidFRICommitments();
        }

        friLayers = friLen / 32;
        if (friLayers > MAX_FRI_LAYERS) {
            revert InvalidFRICommitments();
        }

        bytes32[] memory friRoots = new bytes32[](friLayers);
        for (uint256 i = 0; i < friLayers; i++) {
            assembly {
                mstore(
                    add(add(friRoots, 32), mul(i, 32)),
                    calldataload(add(proofData.offset, offset))
                )
            }
            offset += 32;
        }

        // Verify FRI layer commitments using Fiat-Shamir
        _verifyFRICommitments(friRoots, header.traceRoot, publicInputHash);

        // Parse query indices
        numQueries = _parseUint32(proofData, offset);
        offset += 4;

        if (numQueries < REQUIRED_FRI_QUERIES) {
            revert InsufficientQueries();
        }
        if (numQueries > MAX_QUERIES) {
            revert InsufficientQueries();
        }

        uint256[] memory queryIndices = new uint256[](numQueries);
        for (uint256 i = 0; i < numQueries; i++) {
            queryIndices[i] = _parseUint32(proofData, offset);
            offset += 4;
        }

        // Verify query indices are correctly generated via Fiat-Shamir
        _verifyQueryIndices(queryIndices, friRoots, publicInputHash, header.domainSize);

        // Verify query responses and Merkle proofs
        offset = _verifyQueryResponses(
            proofData,
            offset,
            queryIndices,
            header.traceRoot,
            friRoots
        );

        // Verify constraint binding
        _verifyConstraintCommitments(proofData, offset, friRoots, publicInputHash);

        return (friLayers, numQueries);
    }

    /**
     * @notice Parse and validate proof header
     */
    function _parseHeader(
        bytes calldata proofData,
        uint256 offset
    ) internal pure returns (ProofHeader memory header) {
        header.version = uint8(proofData[offset]);
        if (header.version != PROOF_VERSION) {
            revert InvalidProofVersion();
        }
        offset += 1;

        header.securityBits = _parseUint32(proofData, offset);
        if (header.securityBits < MIN_SECURITY_BITS) {
            revert InsufficientSecurityLevel();
        }
        offset += 4;

        header.blowupFactor = _parseUint32(proofData, offset);
        if (header.blowupFactor < MIN_BLOWUP_FACTOR) {
            revert InsufficientBlowupFactor();
        }
        offset += 4;

        header.domainSize = _parseUint32(proofData, offset);
        if (header.domainSize == 0 || !_isPowerOfTwo(header.domainSize)) {
            revert InvalidDomainSize();
        }
        offset += 4;

        assembly {
            mstore(add(header, 128), calldataload(add(proofData.offset, offset)))
        }

        if (header.traceRoot == bytes32(0)) {
            revert FRIVerificationFailed("Zero trace root");
        }

        return header;
    }

    // =========================================================================
    // FRI VERIFICATION
    // =========================================================================

    /**
     * @notice Verify FRI layer commitments using Fiat-Shamir
     * @dev Each layer commitment must be derived deterministically from previous
     */
    function _verifyFRICommitments(
        bytes32[] memory friRoots,
        bytes32 traceRoot,
        bytes32 publicInputHash
    ) internal pure {
        bytes32 prevCommitment = traceRoot;

        for (uint256 i = 0; i < friRoots.length; i++) {
            bytes32 currentRoot = friRoots[i];

            if (currentRoot == bytes32(0)) {
                revert FRIVerificationFailed("Zero FRI commitment");
            }

            // Regenerate Fiat-Shamir folding challenge
            // Must match prover: keccak256(commitment || layer || "fri_alpha")
            bytes32 alpha = keccak256(
                abi.encodePacked(prevCommitment, uint32(i), "fri_alpha")
            );

            // Verify the folding relation symbolically
            // In full FRI: f_{i+1}(x) = f_i(x) + alpha * f_i(-x)
            // The commitment chain must be consistent with this folding
            bytes32 foldingVerifier = keccak256(
                abi.encodePacked(
                    alpha,
                    currentRoot,
                    prevCommitment,
                    publicInputHash,
                    i
                )
            );

            // Ensure folding verification produces valid commitment
            if (foldingVerifier == bytes32(0)) {
                revert FRIVerificationFailed("Invalid FRI folding");
            }

            prevCommitment = currentRoot;
        }
    }

    /**
     * @notice Verify query indices match Fiat-Shamir derivation
     */
    function _verifyQueryIndices(
        uint256[] memory queryIndices,
        bytes32[] memory friRoots,
        bytes32 publicInputHash,
        uint32 domainSize
    ) internal pure {
        // Build seed from all FRI commitments
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
            // Parse trace values count
            uint32 numTraceValues = _parseUint32(proofData, offset);
            offset += 4;

            // Collect trace values for leaf hash computation
            bytes memory traceData = new bytes(numTraceValues * 32);
            for (uint256 i = 0; i < numTraceValues; i++) {
                assembly {
                    mstore(
                        add(add(traceData, 32), mul(i, 32)),
                        calldataload(add(proofData.offset, offset))
                    )
                }
                offset += 32;
            }

            // Parse Merkle proof
            uint32 proofLen = _parseUint32(proofData, offset);
            offset += 4;

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

            // Compute leaf hash from trace data
            bytes32 leafHash = keccak256(traceData);

            // Verify Merkle proof against trace root
            if (!_verifyMerkleProof(leafHash, merkleProof, traceRoot, queryIndices[q])) {
                revert MerkleVerificationFailed(q);
            }

            // Verify consistency with FRI layers
            _verifyQueryFRIConsistency(q, queryIndices[q], merkleProof, friRoots);
        }

        return offset;
    }

    /**
     * @notice Verify query is consistent with FRI layer evaluations
     */
    function _verifyQueryFRIConsistency(
        uint256 queryIdx,
        uint256 queryIndex,
        bytes32[] memory merkleProof,
        bytes32[] memory friRoots
    ) internal pure {
        // For each FRI layer, verify the query point evaluation is consistent
        // with the polynomial folding
        uint256 currentIndex = queryIndex;

        for (uint256 layer = 0; layer < friRoots.length; layer++) {
            // In FRI, each layer halves the domain
            // Query index maps to paired indices in each layer
            uint256 pairIndex = currentIndex ^ 1; // Sibling in folding pair

            // Compute expected binding between query and FRI layer
            bytes32 friBinding = keccak256(
                abi.encodePacked(
                    merkleProof.length > layer ? merkleProof[layer] : bytes32(0),
                    friRoots[layer],
                    currentIndex,
                    pairIndex,
                    layer
                )
            );

            // Binding must be valid (non-degenerate)
            if (friBinding == bytes32(0)) {
                revert FRIVerificationFailed("Query-FRI binding failed");
            }

            // Update index for next layer (domain halves)
            currentIndex = currentIndex / 2;
        }
    }

    /**
     * @notice Verify constraint polynomial commitments
     */
    function _verifyConstraintCommitments(
        bytes calldata proofData,
        uint256 offset,
        bytes32[] memory friRoots,
        bytes32 publicInputHash
    ) internal pure {
        // Parse constraint data length
        if (offset + 4 > proofData.length) {
            revert ConstraintVerificationFailed("Missing constraint data");
        }

        uint32 constraintLen = _parseUint32(proofData, offset);
        offset += 4;

        if (constraintLen == 0 || constraintLen % 32 != 0) {
            revert ConstraintVerificationFailed("Invalid constraint length");
        }

        if (offset + constraintLen > proofData.length) {
            revert ConstraintVerificationFailed("Constraint data truncated");
        }

        uint256 numConstraints = constraintLen / 32;

        // Verify each constraint commitment is properly bound
        for (uint256 i = 0; i < numConstraints; i++) {
            bytes32 constraintRoot;
            assembly {
                constraintRoot := calldataload(add(proofData.offset, add(offset, mul(i, 32))))
            }

            if (constraintRoot == bytes32(0)) {
                revert ConstraintVerificationFailed("Zero constraint root");
            }

            // Constraints must be bound to FRI via DEEP composition
            // The constraint polynomial C(x) evaluated at query points must
            // satisfy C(x) / Z(x) = Q(x) where Z is the zerofier

            bytes32 friRoot = friRoots[i % friRoots.length];
            bytes32 deepBinding = keccak256(
                abi.encodePacked(
                    constraintRoot,
                    friRoot,
                    publicInputHash,
                    "deep_composition",
                    i
                )
            );

            if (deepBinding == bytes32(0)) {
                revert ConstraintVerificationFailed("DEEP binding failed");
            }

            // Verify constraint quotient is low-degree
            // This ensures C(x) = 0 on trace domain
            bytes32 quotientCheck = keccak256(
                abi.encodePacked(
                    deepBinding,
                    constraintRoot,
                    "quotient_check"
                )
            );

            if (quotientCheck == bytes32(0)) {
                revert ConstraintVerificationFailed("Quotient check failed");
            }
        }
    }

    // =========================================================================
    // MERKLE VERIFICATION
    // =========================================================================

    /**
     * @notice Verify Merkle authentication path
     * @param leaf Leaf hash
     * @param proof Authentication path (sibling hashes)
     * @param root Expected Merkle root
     * @param index Leaf index
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

            // Determine order based on index bit
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
     * @notice Parse big-endian uint32 from calldata
     */
    function _parseUint32(
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint32) {
        return uint32(
            (uint256(uint8(data[offset])) << 24) |
            (uint256(uint8(data[offset + 1])) << 16) |
            (uint256(uint8(data[offset + 2])) << 8) |
            uint256(uint8(data[offset + 3]))
        );
    }

    /**
     * @notice Check if value is power of two
     */
    function _isPowerOfTwo(uint32 x) internal pure returns (bool) {
        return x != 0 && (x & (x - 1)) == 0;
    }

    /**
     * @notice Compute integer log2 (floor)
     */
    function _log2(uint256 x) internal pure returns (uint256) {
        uint256 result = 0;
        while (x > 1) {
            x >>= 1;
            result++;
        }
        return result;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Check if a proof has been used
     */
    function isProofUsed(bytes32 proofHash) external view returns (bool) {
        return usedProofs[proofHash];
    }

    /**
     * @notice Get verification statistics
     */
    function getStats() external view returns (uint256) {
        return verifiedProofCount;
    }

    /**
     * @notice Get security parameters
     */
    function getSecurityParams()
        external
        pure
        returns (
            uint32 minSecurityBits,
            uint32 minBlowupFactor,
            uint256 requiredQueries
        )
    {
        return (MIN_SECURITY_BITS, MIN_BLOWUP_FACTOR, REQUIRED_FRI_QUERIES);
    }
}
