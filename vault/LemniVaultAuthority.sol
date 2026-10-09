// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IZKNOXEthFalcon} from "../falcon/IZKNOXEthFalcon.sol";
import {ILemniAuthority} from "./interfaces/ILemniAuthority.sol";
import {ILaipV3Registry} from "./interfaces/ILaipV3Registry.sol";
import {SlhDsaVerifier} from "../crypto/SlhDsaVerifier.sol";

/// @title LemniVaultAuthority — standalone attestor-key/verifier authority for vaults on chains
///        that have NO LEMNI Diamond (e.g. Base, Ethereum).
///
/// @notice On Polygon, `LemniVault` reads its attestor public key and Falcon verifier live from the
///         LEMNI Diamond (`ILemniAuthority`). Other EVM chains have no Diamond, so this contract
///         provides the SAME two read views vaults depend on — plus the SAME Falcon-governance key
///         rotation path the Diamond exposes — so the existing `falcon-attestor/scripts/auto-rekey.js`
///         rotates this contract with NO changes (it already calls
///         `rotateAttestorKeyWithGovernance`, `governanceNonce`, `governanceFalconInitialized`,
///         and reads `governanceAttestorNtth`).
///
/// @dev DESIGN — mirror the Diamond, add nothing custodial.
///      * Reuses the EXACT governance digest scheme from `LibLemnicoin`:
///        domain `name="LemnicoinGovernance", version="1"`, typehash
///        `GovernanceAction(address signer,bytes32 actionHash,uint256 nonce,uint256 deadline)`,
///        `actionHash = keccak256(abi.encodePacked(action, payload))`. The `verifyingContract` is
///        THIS contract on THIS chain — so a Base authority can only ever authorize Base actions.
///      * The action strings match the Diamond byte-for-byte: `"ROTATE_ATTESTOR"` (payload
///        `abi.encode(newNtth)`) and `"SET_FALCON_VERIFIER"` (payload `abi.encode(newVerifier)`).
///      * This contract holds NO user funds and can move none. Its entire authority is: return two
///        public views, and — with a Falcon governance signature — update those two values. It has
///        NO mint, NO pause, NO transfer, NO custody. Compromise of its owner/rekey keys alone
///        changes nothing (rotation ALSO requires the Falcon governance signature).
///      * It is chain-local: it grants ZERO power over the Polygon Diamond or any other chain.
///        It merely holds public copies of the attestor NTTH and governance NTTH (public keys).
contract LemniVaultAuthority is ILemniAuthority {
    // =========================================================================
    // ROLES (ECDSA) — gate WHO may submit a rotation tx. Never sufficient alone:
    // every mutation also requires a Falcon governance signature (see below).
    // =========================================================================

    /// @notice Owner (deployer, ideally a multisig). Can rotate keys and manage the rekey operator.
    address public owner;

    /// @notice Optional dedicated rekey operator, mirroring the Diamond's `rekeyOperator`. Lets an
    ///         automated rotation signer rotate keys without being the owner. address(0) = unset.
    address public rekeyOperator;

    // =========================================================================
    // AUTHORITY STATE — the two values vaults read, plus governance material.
    // =========================================================================

    /// @notice The transfer-attestor Falcon public key (NTT domain, 32 words). Read by every vault.
    uint256[32] private _attestorNtth;

    /// @notice The deployed ZKNOX Falcon verifier used by vaults on this chain. Read by every vault.
    address private _falconVerifier;

    /// @notice The GOVERNANCE Falcon public key (NTT domain) — verifies rotation actions. This is a
    ///         separate key from the transfer attestor; identical split to the Diamond.
    uint256[32] private _governanceAttestorNtth;

    /// @notice The Falcon verifier used to check GOVERNANCE signatures. Usually the same ZKNOX
    ///         verifier as `_falconVerifier`, but kept independent to match the Diamond.
    address public governanceFalconVerifier;

    /// @notice Set once `initializeGovernance` has run. Rotation reverts until then.
    bool public governanceFalconInitialized;

    /// @notice Per-signer monotonic governance nonce (replay protection). Keyed by the ECDSA sender
    ///         that submits the rotation, exactly as the Diamond keys `governanceNonce[msg.sender]`.
    mapping(address => uint256) public governanceNonce;

    /// @notice A holder's Multi-Sig ring on this chain — the ONE registry v5 vaults read.
    struct Ring {
        bytes32[] memberCommitments;
        uint8 threshold;
        bool registered;
    }

    /// @notice One member's proof-of-possession at ring registration.
    struct RingProof {
        bytes salt40;
        uint256[] s2_32;
        uint256[] ntth;
    }

    /// @notice holder => their Multi-Sig ring. Write-once, read live by every v5 vault.
    mapping(address => Ring) internal _ring;

    uint256 internal constant MIN_RING_MEMBERS = 2;
    uint256 internal constant MAX_RING_MEMBERS = 7;
    uint256 internal constant MIN_RING_THRESHOLD = 2;

    bytes32 internal constant RING_REGISTRATION_TYPEHASH =
        keccak256("RingRegistration(address account,bytes32 membersHash,uint256 threshold)");

    /// @notice holder => keccak256(abi.encodePacked(uint256[32] ntth)) of their OWN Falcon key.
    ///         Set once by the holder, then immutable. Zero means no attestor-free path.
    mapping(address => bytes32) internal _holderFalconCommitment;

    /// @notice This chain's LAIP-V3 key registry (LaipV3SatelliteRegistry), set ONCE by governance.
    ///         Ring registration reads it to demand the holder's SLH-DSA consent from V3 accounts.
    ///         Zero until wired (the registry is deployed after, and points at, this authority).
    address public laipV3Registry;

    /// @notice A verifier swap is TIMELOCKED: proposed under owner + Falcon governance, applied no
    ///         earlier than FALCON_VERIFIER_DELAY later. The verifier decides every vault withdrawal
    ///         on this chain, so an instant swap would let a compromised owner + governance key
    ///         install an always-true verifier and drain every vault in one block. The delay gives
    ///         holders time to see the proposal and escape() first.
    uint256 public constant FALCON_VERIFIER_DELAY = 2 days;
    address public pendingFalconVerifier;
    uint256 public pendingFalconVerifierEta;

    /// @dev mu_trustless provenance anchor — identical to LibSlhEconomics / LemniVaultV6.
    bytes32 internal constant LOS_COMMITMENT =
        0x5011820df0d8c8de5cee136edec7512fdb2ae279a33e7b25a52192e7931e04bb;

    // =========================================================================
    // EIP-712 GOVERNANCE CONSTANTS — IDENTICAL to LibLemnicoin.
    // =========================================================================

    bytes32 private constant GOV_EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant GOV_ACTION_TYPEHASH =
        keccak256("GovernanceAction(address signer,bytes32 actionHash,uint256 nonce,uint256 deadline)");
    bytes32 private constant GOV_NAME_HASH = keccak256("LemnicoinGovernance");
    bytes32 private constant GOV_VERSION_HASH = keccak256("1");

    // =========================================================================
    // EVENTS — mirror the Diamond's GovernanceFacet.
    // =========================================================================

    event GovernanceFalconInitialized(address verifier);
    event GovernanceFalconVerified(address indexed signer, bytes32 actionHash, uint256 nonce);
    event AttestorKeyUpdated(uint256[32] newNtth);
    event FalconVerifierUpdated(address indexed newVerifier);
    event FalconVerifierProposed(address indexed newVerifier, uint256 eta);
    event FalconVerifierProposalCancelled(address indexed newVerifier);
    event LaipV3RegistrySet(address indexed registry);
    event RekeyOperatorUpdated(address indexed newOperator);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event HolderFalconKeyRegistered(address indexed account, bytes32 commitment);
    event RingRegistered(address indexed account, bytes32 membersHash, uint8 threshold, uint256 memberCount);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error NotAuthorized();
    error ZeroAddress();
    error GovernanceAlreadyInitialized();
    error GovernanceNotInitialized();
    error GovernanceAttestationExpired();
    error GovernanceInvalidNonce(uint256 expected, uint256 provided);
    error GovernanceInvalidSaltLength(uint256 length);
    error GovernanceInvalidS2Length(uint256 length);
    error GovernanceFalconVerificationFailed();
    error HolderFalconKeyImmutable();
    error InvalidHolderFalconKey();
    error RingAlreadyRegistered();
    error RingInvalidMemberCount(uint256 count);
    error RingInvalidThreshold(uint256 threshold, uint256 memberCount);
    error RingZeroCommitment(uint256 index);
    error RingDuplicateCommitment(uint256 index);
    error RingProofCountMismatch(uint256 proofs, uint256 members);
    error RingProofKeyMismatch(uint256 index);
    error RingProofVerificationFailed(uint256 index);
    error RingHolderAuthRequired(address account);
    error HolderFalconKeyMismatch();
    error HolderFalconVerificationFailed();
    error SlhRequired();
    error SlhKeyMismatch();
    error SlhVerificationFailed();
    error LaipV3RegistryAlreadySet();
    error NoPendingFalconVerifier();
    error FalconVerifierDelayNotPassed(uint256 eta);

    // =========================================================================
    // MODIFIERS
    // =========================================================================

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotAuthorized();
        _;
    }

    /// @dev Mirrors the Diamond's `onlyOwnerOrRekeyOperator`.
    modifier onlyOwnerOrRekeyOperator() {
        if (msg.sender != owner && (rekeyOperator == address(0) || msg.sender != rekeyOperator)) {
            revert NotAuthorized();
        }
        _;
    }

    // =========================================================================
    // CONSTRUCTOR — seed the CURRENT public keys + verifier so vaults work immediately.
    // =========================================================================

    /// @param owner_               Deployer / multisig that administers this authority.
    /// @param falconVerifier_      ZKNOX Falcon verifier deployed on this chain (transfer path).
    /// @param attestorNtth_        Current transfer-attestor public key (copy of the live Polygon one).
    /// @param governanceVerifier_  Verifier for governance signatures (usually == falconVerifier_).
    /// @param governanceNtth_      Current governance public key (copy of the live Polygon one).
    constructor(
        address owner_,
        address falconVerifier_,
        uint256[32] memory attestorNtth_,
        address governanceVerifier_,
        uint256[32] memory governanceNtth_
    ) {
        if (owner_ == address(0) || falconVerifier_ == address(0) || governanceVerifier_ == address(0)) {
            revert ZeroAddress();
        }
        owner = owner_;
        _falconVerifier = falconVerifier_;
        _attestorNtth = attestorNtth_;
        governanceFalconVerifier = governanceVerifier_;
        _governanceAttestorNtth = governanceNtth_;
        governanceFalconInitialized = true; // seeded at construction; rotation ready immediately
        emit OwnershipTransferred(address(0), owner_);
        emit GovernanceFalconInitialized(governanceVerifier_);
        emit AttestorKeyUpdated(attestorNtth_);
    }

    // =========================================================================
    // ILemniAuthority — the two views every vault reads live.
    // =========================================================================

    /// @inheritdoc ILemniAuthority
    function getAttestorPublicKey() external view override returns (uint256[32] memory) {
        return _attestorNtth;
    }

    /// @inheritdoc ILemniAuthority
    function FALCON_VERIFIER() external view override returns (address) {
        return _falconVerifier;
    }

    /// @inheritdoc ILemniAuthority
    function holderFalconCommitment(address account) external view override returns (bytes32) {
        return _holderFalconCommitment[account];
    }

    // =========================================================================
    // MULTI-SIG RING — the ONE ring registry for this chain
    // =========================================================================

    /// @inheritdoc ILemniAuthority
    function getRing(address account)
        external
        view
        override
        returns (bytes32[] memory memberCommitments, uint8 threshold, bool registered)
    {
        Ring storage r = _ring[account];
        return (r.memberCommitments, r.threshold, r.registered);
    }

    /// @notice Register the caller's Multi-Sig ring: N member Falcon key commitments and a
    ///         threshold M, with a proof-of-possession signature from EVERY member.
    /// @dev The chain-local twin of RingFacet.registerRing on the Polygon Diamond. Once set, every
    ///      v5 vault this holder owns on this chain requires the quorum — including vaults deployed
    ///      and funded before the ring existed, because vaults read this registry live.
    ///
    ///      Write-once, msg.sender-only: nobody can enroll a victim into a ring, and a stolen wallet
    ///      key cannot re-ring an account. Requiring all N proofs (not just M) means a key nobody
    ///      controls cannot be enrolled — that would silently lower the real quorum.
    ///
    ///      SECURITY — holder consent: only for accounts with no quantum keys yet. An account that
    ///      holds a holder Falcon key (or LAIP-V3 keys) must use registerRingWithHolderAuth, so a
    ///      stolen EVM key alone can never enroll it into a ring of attacker keys.
    function registerRing(
        bytes32[] calldata memberCommitments,
        uint8 threshold,
        RingProof[] calldata proofs
    ) external {
        if (ringHolderAuthRequired(msg.sender)) revert RingHolderAuthRequired(msg.sender);
        _registerRing(memberCommitments, threshold, proofs);
    }

    /// @notice Register the caller's ring when it already holds quantum keys: the caller's OWN
    ///         holder Falcon key must sign the registration digest, and — when the caller has
    ///         LAIP-V3 keys in this chain's registry and an SLH verifier is wired there — its
    ///         SLH-DSA key must sign mu_trustless(digest, curveHash, 0). Identical rule and message
    ///         to the Diamond's RingFacet.registerRingWithHolderAuth.
    function registerRingWithHolderAuth(
        bytes32[] calldata memberCommitments,
        uint8 threshold,
        RingProof[] calldata proofs,
        RingProof calldata holderFalcon,
        bytes calldata slhPubKey,
        bytes calldata slhSig
    ) external {
        bytes32 commitment = _holderFalconCommitment[msg.sender];
        (bytes32 curveHash, bytes32 slhdsaPkHash, bool v3) = _laipV3Keys(msg.sender);
        if (commitment != bytes32(0) || v3) {
            bytes32 digest = ringRegistrationDigest(msg.sender, memberCommitments, threshold);
            if (holderFalcon.salt40.length != 40) revert GovernanceInvalidSaltLength(holderFalcon.salt40.length);
            if (holderFalcon.s2_32.length != 32) revert GovernanceInvalidS2Length(holderFalcon.s2_32.length);
            if (holderFalcon.ntth.length != 32) revert InvalidHolderFalconKey();
            if (commitment == bytes32(0) || keccak256(abi.encodePacked(holderFalcon.ntth)) != commitment) {
                revert HolderFalconKeyMismatch();
            }
            if (!IZKNOXEthFalcon(_falconVerifier).verify(
                abi.encodePacked(digest), holderFalcon.salt40,
                _toMemoryArray(holderFalcon.s2_32), _toMemoryArray(holderFalcon.ntth)
            )) revert HolderFalconVerificationFailed();

            if (v3) {
                address slhVerifier = ILaipV3Registry(laipV3Registry).slhDsaVerifier();
                if (slhVerifier != address(0)) {
                    if (slhPubKey.length == 0 || slhSig.length == 0) revert SlhRequired();
                    if (keccak256(slhPubKey) != slhdsaPkHash) revert SlhKeyMismatch();
                    bytes memory mu = abi.encodePacked(
                        keccak256(abi.encodePacked(digest, curveHash, bytes32(0), LOS_COMMITMENT))
                    );
                    if (!SlhDsaVerifier(slhVerifier).verify(slhPubKey, mu, slhSig)) revert SlhVerificationFailed();
                }
            }
        }
        _registerRing(memberCommitments, threshold, proofs);
    }

    /// @notice Whether `account` must use registerRingWithHolderAuth (it holds quantum keys).
    function ringHolderAuthRequired(address account) public view returns (bool) {
        if (_holderFalconCommitment[account] != bytes32(0)) return true;
        (, , bool v3) = _laipV3Keys(account);
        return v3;
    }

    function _laipV3Keys(address account) internal view returns (bytes32 curveHash, bytes32 slhdsaPkHash, bool registered) {
        if (laipV3Registry == address(0)) return (bytes32(0), bytes32(0), false);
        (curveHash, slhdsaPkHash, , , registered) = ILaipV3Registry(laipV3Registry).getLaipV3Keys(account);
    }

    function _registerRing(
        bytes32[] calldata memberCommitments,
        uint8 threshold,
        RingProof[] calldata proofs
    ) internal {
        Ring storage r = _ring[msg.sender];
        if (r.registered) revert RingAlreadyRegistered();

        uint256 n = memberCommitments.length;
        if (n < MIN_RING_MEMBERS || n > MAX_RING_MEMBERS) revert RingInvalidMemberCount(n);
        if (threshold < MIN_RING_THRESHOLD || threshold > n) revert RingInvalidThreshold(threshold, n);
        if (proofs.length != n) revert RingProofCountMismatch(proofs.length, n);

        for (uint256 i = 0; i < n; i++) {
            if (memberCommitments[i] == bytes32(0)) revert RingZeroCommitment(i);
            for (uint256 j = 0; j < i; j++) {
                if (memberCommitments[j] == memberCommitments[i]) revert RingDuplicateCommitment(i);
            }
        }

        bytes32 digest = ringRegistrationDigest(msg.sender, memberCommitments, threshold);

        for (uint256 i = 0; i < n; i++) {
            RingProof calldata p = proofs[i];
            if (p.salt40.length != 40) revert GovernanceInvalidSaltLength(p.salt40.length);
            if (p.s2_32.length != 32) revert GovernanceInvalidS2Length(p.s2_32.length);
            if (p.ntth.length != 32) revert InvalidHolderFalconKey();
            if (keccak256(abi.encodePacked(p.ntth)) != memberCommitments[i]) revert RingProofKeyMismatch(i);

            bool ok = IZKNOXEthFalcon(_falconVerifier).verify(
                abi.encodePacked(digest), p.salt40, _toMemoryArray(p.s2_32), _toMemoryArray(p.ntth)
            );
            if (!ok) revert RingProofVerificationFailed(i);
        }

        r.memberCommitments = memberCommitments;
        r.threshold = threshold;
        r.registered = true;

        emit RingRegistered(msg.sender, keccak256(abi.encodePacked(memberCommitments)), threshold, n);
    }

    /// @notice The EIP-712 digest each member must Falcon-sign to register this exact ring here.
    /// @dev Bound to this authority (address(this)) and this chain, so a proof gathered for the
    ///      Diamond's ring cannot be replayed here and vice versa.
    function ringRegistrationDigest(
        address account,
        bytes32[] calldata memberCommitments,
        uint8 threshold
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                RING_REGISTRATION_TYPEHASH,
                account,
                keccak256(abi.encodePacked(memberCommitments)),
                uint256(threshold)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", _ringDomainSeparator(), structHash));
    }

    function _ringDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("LemnicoinPQAttestation"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }

    /// @notice Register the caller's OWN Falcon-512 key on this chain, so they can authorise vault
    ///         withdrawals themselves when the attestor is unreachable.
    /// @dev Mirrors KeyManagementFacet.registerHolderFalconKey on the Polygon Diamond. Holders
    ///      register per chain, since each chain's vaults read their own authority.
    ///
    ///      IMMUTABLE once set: a stolen wallet key cannot swap in the thief's Falcon key.
    ///      Re-registering the identical key is a no-op (the dApp re-derives it on every unlock).
    /// @param ntth The Falcon public key in NTT domain, packed 16 coefficients per word.
    function registerHolderFalconKey(uint256[32] calldata ntth) external {
        bytes32 commitment = keccak256(abi.encodePacked(ntth));
        if (commitment == bytes32(0)) revert InvalidHolderFalconKey();

        bytes32 existing = _holderFalconCommitment[msg.sender];
        if (existing != bytes32(0)) {
            if (existing != commitment) revert HolderFalconKeyImmutable();
            return;
        }

        _holderFalconCommitment[msg.sender] = commitment;
        emit HolderFalconKeyRegistered(msg.sender, commitment);
    }

    // =========================================================================
    // GOVERNANCE VIEWS — read by auto-rekey.js (verifyGovernanceKeyMatch / nonce lookups).
    // =========================================================================

    /// @notice Governance public key word `index` (0..31). Matches the Diamond's public getter.
    function governanceAttestorNtth(uint256 index) external view returns (uint256) {
        return _governanceAttestorNtth[index];
    }

    // =========================================================================
    // ROTATION — attestor key. IDENTICAL call shape + digest to the Diamond, so
    // auto-rekey.js's rotateAttestorKeyWithGovernance path works unchanged.
    // =========================================================================

    /// @notice Rotate the transfer-attestor public key. Requires BOTH an authorized ECDSA sender
    ///         (owner or rekey operator) AND a Falcon governance signature over `"ROTATE_ATTESTOR"`.
    function rotateAttestorKeyWithGovernance(
        uint256[32] calldata newNtth,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2
    ) external onlyOwnerOrRekeyOperator {
        _requireFalconGovernance("ROTATE_ATTESTOR", abi.encode(newNtth), nonce, deadline, falconSalt40, falconS2);
        for (uint256 i = 0; i < 32; i++) {
            _attestorNtth[i] = newNtth[i];
        }
        emit AttestorKeyUpdated(newNtth);
    }

    /// @notice PROPOSE a new Falcon verifier for vaults on this chain. Requires owner + Falcon
    ///         governance signature over `"SET_FALCON_VERIFIER"` (unchanged action, so existing
    ///         signing tooling works). Takes effect only via executeFalconVerifier after
    ///         FALCON_VERIFIER_DELAY. A new proposal replaces a pending one and restarts the clock.
    function setFalconVerifier(
        address newVerifier,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2
    ) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();
        _requireFalconGovernance(
            "SET_FALCON_VERIFIER", abi.encode(newVerifier), nonce, deadline, falconSalt40, falconS2
        );
        pendingFalconVerifier = newVerifier;
        pendingFalconVerifierEta = block.timestamp + FALCON_VERIFIER_DELAY;
        emit FalconVerifierProposed(newVerifier, pendingFalconVerifierEta);
    }

    /// @notice Apply the pending verifier once its delay has passed. Owner-only; the Falcon
    ///         approval was given at proposal time over this exact address.
    function executeFalconVerifier() external onlyOwner {
        address next = pendingFalconVerifier;
        if (next == address(0)) revert NoPendingFalconVerifier();
        if (block.timestamp < pendingFalconVerifierEta) revert FalconVerifierDelayNotPassed(pendingFalconVerifierEta);
        pendingFalconVerifier = address(0);
        pendingFalconVerifierEta = 0;
        _falconVerifier = next;
        emit FalconVerifierUpdated(next);
    }

    /// @notice Cancel a pending verifier proposal. Owner-only; cancelling can only keep the current,
    ///         already-trusted verifier in place.
    function cancelFalconVerifier() external onlyOwner {
        address next = pendingFalconVerifier;
        if (next == address(0)) revert NoPendingFalconVerifier();
        pendingFalconVerifier = address(0);
        pendingFalconVerifierEta = 0;
        emit FalconVerifierProposalCancelled(next);
    }

    /// @notice Wire this chain's LAIP-V3 registry — ONCE, under owner + Falcon governance
    ///         (`"SET_LAIPV3_REGISTRY"`). Write-once so it can never be unset to switch off the
    ///         SLH consent that ring registration demands of V3 accounts.
    function setLaipV3Registry(
        address registry,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2
    ) external onlyOwner {
        if (registry == address(0)) revert ZeroAddress();
        if (laipV3Registry != address(0)) revert LaipV3RegistryAlreadySet();
        _requireFalconGovernance("SET_LAIPV3_REGISTRY", abi.encode(registry), nonce, deadline, falconSalt40, falconS2);
        laipV3Registry = registry;
        emit LaipV3RegistrySet(registry);
    }

    /// @notice Rotate the GOVERNANCE Falcon public key itself. Requires the OWNER (never the
    ///         rekey operator) AND a Falcon signature by the CURRENT governance key over
    ///         `"UPDATE_GOV_ATTESTOR"` — byte-for-byte the Diamond's updateGovernanceAttestorKey.
    /// @dev Owner-only for the same reason as on the Diamond: the rekey operator shares a host with
    ///      the governance key, so letting it rotate that key would let one host compromise lock the
    ///      owner out of every governance action.
    function updateGovernanceAttestorKey(
        uint256[32] calldata newNtth,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2
    ) external onlyOwner {
        _requireFalconGovernance("UPDATE_GOV_ATTESTOR", abi.encode(newNtth), nonce, deadline, falconSalt40, falconS2);
        for (uint256 i = 0; i < 32; i++) {
            _governanceAttestorNtth[i] = newNtth[i];
        }
    }

    // =========================================================================
    // ROLE MANAGEMENT — dual-gated like every other mutation. The authority holds no
    // funds, but its owner is the ECDSA leg of the two-factor rotation gate: were
    // ownership itself ECDSA-only, a (quantum-)stolen owner key could hand the role to
    // an attacker or strand rotation by revoking the operator. With the Falcon leg
    // required here too, ECDSA compromise alone can neither take over nor deny.
    // =========================================================================

    /// @notice Set or revoke the dedicated rekey operator. Requires owner + Falcon
    ///         governance signature over `"SET_REKEY_OPERATOR"`. address(0) revokes.
    function setRekeyOperator(
        address newOperator,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2
    ) external onlyOwner {
        _requireFalconGovernance("SET_REKEY_OPERATOR", abi.encode(newOperator), nonce, deadline, falconSalt40, falconS2);
        rekeyOperator = newOperator;
        emit RekeyOperatorUpdated(newOperator);
    }

    /// @notice Transfer ownership (e.g. to a Gnosis Safe multisig). Requires owner + Falcon
    ///         governance signature over `"TRANSFER_OWNERSHIP"`.
    function transferOwnership(
        address newOwner,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2
    ) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        _requireFalconGovernance("TRANSFER_OWNERSHIP", abi.encode(newOwner), nonce, deadline, falconSalt40, falconS2);
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // =========================================================================
    // INTERNAL — Falcon governance verification, byte-for-byte per LibLemnicoin.
    // =========================================================================

    function _govDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(GOV_EIP712_DOMAIN_TYPEHASH, GOV_NAME_HASH, GOV_VERSION_HASH, block.chainid, address(this))
        );
    }

    function _governanceDigest(address signer, bytes32 actionHash, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(GOV_ACTION_TYPEHASH, signer, actionHash, nonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", _govDomainSeparator(), structHash));
    }

    function _requireFalconGovernance(
        string memory action,
        bytes memory payload,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2
    ) internal {
        if (!governanceFalconInitialized) revert GovernanceNotInitialized();
        if (block.timestamp > deadline) revert GovernanceAttestationExpired();

        uint256 expectedNonce = governanceNonce[msg.sender];
        if (nonce != expectedNonce) revert GovernanceInvalidNonce(expectedNonce, nonce);
        if (falconSalt40.length != 40) revert GovernanceInvalidSaltLength(falconSalt40.length);
        if (falconS2.length != 32) revert GovernanceInvalidS2Length(falconS2.length);

        bytes32 actionHash = keccak256(abi.encodePacked(action, payload));
        bytes32 digest = _governanceDigest(msg.sender, actionHash, nonce, deadline);

        bool valid = IZKNOXEthFalcon(governanceFalconVerifier).verify(
            abi.encodePacked(digest), falconSalt40, _toMemoryArray(falconS2), _govNtthMemory()
        );
        if (!valid) revert GovernanceFalconVerificationFailed();

        governanceNonce[msg.sender] = nonce + 1;
        emit GovernanceFalconVerified(msg.sender, actionHash, nonce);
    }

    function _govNtthMemory() internal view returns (uint256[] memory out) {
        out = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            out[i] = _governanceAttestorNtth[i];
        }
    }

    function _toMemoryArray(uint256[] calldata arr) internal pure returns (uint256[] memory out) {
        out = new uint256[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) {
            out[i] = arr[i];
        }
    }
}
