// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./ILAIPOnChainVerifier.sol";
import "./interfaces/ISTARKVerifier.sol";

/**
 * @title LAIPOnChainVerifierStark
 * @notice STARK-based dual-key verifier that preserves the DualKeyEnvelope ABI.
 * @dev Selected STARK stack (open-source, self-hosted, Keccak-friendly, EVM verified):
 *      - Cairo + Stone/Prover stack with open-source Ethereum verifier contracts.
 *      - No subscription service required; proofs are generated and verified in-house.
 *
 *      Public statement proven by the STARK includes:
 *      - LAIP-1024 verification (true scalar mult + add, not projective shortcut).
 *      - Dilithium verification (full signature verification).
 *      - LAIP-3072 commitment/continuity (long-term key continuity enforced in AIR).
 *      - Message binding to transfer data (from/to/amount/nonce/chainId).
 *
 *      ABI preservation strategy:
 *      - laipSignature: carries the packed LAIP signature bytes.
 *      - sP0_u: carries the STARK proof bytes.
 *      - Rx/Ry: carries the LAIP-3072 commitment bytes (continuity anchor).
 *      - eHash: Keccak public input hash committed to the proof.
 */
contract LAIPOnChainVerifierStark is ILAIPOnChainVerifier {
    struct QuantumIdentity {
        bytes32 laip1024QHash;
        bytes32 laip1024P0Hash;
        bytes32 laip3072CommitHash;
        bytes32 dilithiumPkHash;
        uint256 registeredAt;
        bool isActive;
    }

    mapping(address => QuantumIdentity) public identities;
    mapping(bytes32 => bool) public usedSignatureHashes;

    address public owner;
    uint256 public identityCount;
    address public starkVerifier;

    event IdentityRegistered(
        address indexed owner,
        bytes32 laip1024QHash,
        bytes32 laip1024P0Hash,
        bytes32 laip3072CommitHash,
        uint256 timestamp
    );
    event IdentityDeactivated(address indexed owner, uint256 timestamp);
    event IdentityReactivated(address indexed owner, uint256 timestamp);
    event StarkVerifierUpdated(address indexed verifier);

    error IdentityAlreadyRegistered();
    error IdentityNotRegistered();
    error IdentityInactive();
    error PublicKeyHashMismatch();
    error BasePointHashMismatch();
    error LAIP3072CommitmentMismatch();
    error DilithiumPublicKeyMismatch();
    error InvalidPublicInputHash();
    error MissingStarkProof();
    error MissingLAIP3072Commitment();
    error SignatureAlreadyUsed();
    error InvalidStarkVerifier();
    error NotOwner();
    error StarkProofRejected();

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert NotOwner();
        }
        _;
    }

    modifier identityExists(address signer) {
        if (identities[signer].registeredAt == 0) {
            revert IdentityNotRegistered();
        }
        _;
    }

    modifier identityActive(address signer) {
        if (!identities[signer].isActive) {
            revert IdentityInactive();
        }
        _;
    }

    constructor(address verifier) {
        owner = msg.sender;
        if (verifier == address(0)) {
            revert InvalidStarkVerifier();
        }
        starkVerifier = verifier;
    }

    function registerIdentity(
        bytes32 laip1024QHash,
        bytes32 laip1024P0Hash,
        bytes32 laip3072CommitHash,
        bytes32 dilithiumPkHash
    ) external {
        if (identities[msg.sender].registeredAt != 0) {
            revert IdentityAlreadyRegistered();
        }

        identities[msg.sender] = QuantumIdentity({
            laip1024QHash: laip1024QHash,
            laip1024P0Hash: laip1024P0Hash,
            laip3072CommitHash: laip3072CommitHash,
            dilithiumPkHash: dilithiumPkHash,
            registeredAt: block.timestamp,
            isActive: true
        });

        identityCount++;

        emit IdentityRegistered(
            msg.sender,
            laip1024QHash,
            laip1024P0Hash,
            laip3072CommitHash,
            block.timestamp
        );
    }

    function deactivateIdentity() external identityExists(msg.sender) {
        identities[msg.sender].isActive = false;
        emit IdentityDeactivated(msg.sender, block.timestamp);
    }

    function reactivateIdentity() external identityExists(msg.sender) {
        identities[msg.sender].isActive = true;
        emit IdentityReactivated(msg.sender, block.timestamp);
    }

    function verifyDualKeySignature(
        address signer,
        DualKeyEnvelope calldata envelope
    ) external identityExists(signer) identityActive(signer) returns (bool valid) {
        DualKeyEnvelope memory env = envelope;
        _verifyDualKeyProof(signer, env);
        return true;
    }

    function verifyDualKeySignatureOnce(
        address signer,
        DualKeyEnvelope calldata envelope
    ) external identityExists(signer) identityActive(signer) returns (bool valid) {
        DualKeyEnvelope memory env = envelope;
        _verifyDualKeyProof(signer, env);
        _consumeDualKeyProof(env);
        return true;
    }

    function isIdentityValid(address _addr)
        external
        view
        returns (bool registered, bool active)
    {
        registered = identities[_addr].registeredAt != 0;
        active = identities[_addr].isActive;
    }

    function setStarkVerifier(address verifier) external onlyOwner {
        if (verifier == address(0)) {
            revert InvalidStarkVerifier();
        }
        starkVerifier = verifier;
        emit StarkVerifierUpdated(verifier);
    }

    function _verifyDualKeyProof(
        address signer,
        DualKeyEnvelope memory envelope
    ) internal {
        _verifyKeyBindings(identities[signer], envelope);

        bytes32 expectedPublicInputHash = _computePublicInputHash(envelope);
        if (envelope.eHash == bytes32(0) || envelope.eHash != expectedPublicInputHash) {
            revert InvalidPublicInputHash();
        }

        bytes memory proof = envelope.sP0_u.length > 0
            ? envelope.sP0_u
            : envelope.laipSignature;
        if (proof.length == 0) {
            revert MissingStarkProof();
        }

        if (!ISTARKVerifier(starkVerifier).verifyProof(proof, envelope.eHash)) {
            revert StarkProofRejected();
        }
    }

    function _verifyKeyBindings(
        QuantumIdentity storage identity,
        DualKeyEnvelope memory envelope
    ) internal view {
        bytes32 computedQHash = keccak256(abi.encodePacked(envelope.Qx, envelope.Qy));
        if (computedQHash != identity.laip1024QHash) {
            revert PublicKeyHashMismatch();
        }

        bytes32 computedP0Hash = keccak256(
            abi.encodePacked(envelope.domainParams.P0x, envelope.domainParams.P0y)
        );
        if (computedP0Hash != identity.laip1024P0Hash) {
            revert BasePointHashMismatch();
        }

        if (envelope.Rx.length == 0 && envelope.Ry.length == 0) {
            revert MissingLAIP3072Commitment();
        }

        bytes32 computedCommitHash = keccak256(
            abi.encodePacked(envelope.Rx, envelope.Ry)
        );
        if (computedCommitHash != identity.laip3072CommitHash) {
            revert LAIP3072CommitmentMismatch();
        }

        bytes32 providedPkHash = keccak256(envelope.dilithiumPk);
        if (providedPkHash != identity.dilithiumPkHash) {
            revert DilithiumPublicKeyMismatch();
        }
    }

    function _consumeDualKeyProof(DualKeyEnvelope memory envelope) internal {
        bytes32 combinedHash = keccak256(
            abi.encodePacked(envelope.laipSignature, envelope.dilithiumSignature, envelope.eHash)
        );

        if (usedSignatureHashes[combinedHash]) {
            revert SignatureAlreadyUsed();
        }

        usedSignatureHashes[combinedHash] = true;
    }

    function _computePublicInputHash(
        DualKeyEnvelope memory envelope
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                envelope.laipSignature,
                envelope.Qx,
                envelope.Qy,
                envelope.domainParams.P0x,
                envelope.domainParams.P0y,
                envelope.domainParams.a,
                envelope.domainParams.p,
                envelope.dilithiumSignature,
                envelope.dilithiumPk,
                envelope.message,
                envelope.Rx,
                envelope.Ry
            )
        );
    }
}
