// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

import {IZKNOXEthFalcon} from "../falcon/IZKNOXEthFalcon.sol";
import {ILemniAuthority} from "./interfaces/ILemniAuthority.sol";

/// @title LemniVaultV4 — the holder's own Falcon signature is required for every withdrawal
///
/// @notice Same custody model as v3 — per-(holder, asset), no owner, no admin, no upgrade key, no
///         pause, `msg.sender` never an authority — with one change that reshapes the threat model:
///         **there is no longer an attestor-only withdrawal path.**
///
/// @dev WHY. In v3, `withdraw()` verified exactly one thing: a Falcon signature under the attestor's
///      key. The holder's own post-quantum keys were checked only off-chain, by the attestor. So
///      possession of the attestor's private key was sufficient to move every vault's balance on
///      every chain, with no user involvement — it was a universal withdrawal key, and every piece of
///      infrastructure hardening around it was an attempt to keep one secret safe rather than to make
///      losing it survivable.
///
///      v4 makes losing it survivable. Funds now leave only via:
///
///        1. `withdraw()`               — attestor Falcon signature **AND** holder Falcon signature
///        2. `withdrawWithHolderKey()`  — holder Falcon signature alone, for when the attestor is
///                                        unreachable; enforces the LEMNI toll on-chain in its place
///        3. `escape()`                 — the entire balance to the immutable `escapeAddress`
///
///      Every path that pays an arbitrary recipient requires the holder's key. An attacker holding
///      the attestor's key and nothing else can move nothing.
///
///      WHY PATH 2 DOES NOT UNDO PATH 1. The two fail differently. An attacker with the attestor key
///      is blocked on both (no holder signature). An attacker with the holder's seed can use path 2 —
///      but a stolen seed is total compromise of a self-custodial wallet by definition, and that was
///      equally true in v3. Requiring both on path 1 costs nothing and buys defence in depth; the
///      security floor is "the holder's signature is always required".
///
///      WHY `escape()` MATTERS MORE NOW. It is the only path that does not need the seed — the holder
///      wallet sweeps to a pre-committed address. That makes it the safety net for a lost seed, so
///      v4 refuses to construct a vault whose escape address is the holder's own wallet: a thief with
///      the wallet key would otherwise defeat the net with a single call.
///
///      DEADLINES ARE BOUNDED. v3 checked only `block.timestamp > deadline`, so a packet could be
///      minted valid for years. v4 caps it at `MAX_ATTESTATION_TTL` from the block it lands in.
///
///      THE HOLDER KEY IS NOT STORED HERE. The vault reads a commitment from the authority, so one
///      registration covers every vault the holder owns. `LemniVaultFactoryV4` refuses to deploy for
///      a holder who has not registered — which is what makes requiring the signature safe rather
///      than a way to strand funds.
contract LemniVaultV4 is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // =========================================================================
    // IMMUTABLES
    // =========================================================================

    /// @notice The holder this vault was deployed for. Bound into the attestation as `user`, the
    ///         account whose Falcon key must sign, and one of the two addresses that may `escape()`.
    address public immutable holder;

    /// @notice The single asset this vault custodies. `address(0)` = native value (POL).
    address public immutable asset;

    /// @notice The LEMNI authority (Diamond on Polygon, LemniVaultAuthority elsewhere), read-only:
    ///         attestor key, Falcon verifier, and holder key commitments.
    ILemniAuthority public immutable authority;

    /// @notice The ONLY address `escape()` can ever pay, and the other address permitted to trigger
    ///         it. Chosen by the holder at creation, immutable thereafter, and — new in v4 —
    ///         required to differ from `holder`.
    address public immutable escapeAddress;

    /// @notice LEMNI token, for the on-chain toll check. Zero disables it.
    address public immutable lemniToken;

    /// @notice 10**decimals of this asset if it is a 1:1 (unit-toll) asset, else 0 for no toll.
    uint256 public immutable unitTollScale;

    /// @dev One whole LEMNI (18 decimals).
    uint256 private constant LEMNI_UNIT = 1e18;

    /// @notice The furthest into the future an attestation may be valid, measured from the block it
    ///         is mined in. The dApp asks for 10 minutes; this bounds what the chain will accept, so
    ///         a captured packet expires whatever deadline it was minted with.
    uint256 public constant MAX_ATTESTATION_TTL = 15 minutes;

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Monotonic withdrawal nonce, SHARED by both withdrawal paths so a packet can never be
    ///         replayed against the other one.
    uint256 public withdrawalNonce;

    // =========================================================================
    // EIP-712 — IDENTICAL TO v1/v2/v3 AND TO LEMNI (LibLemnicoin / FalconAttestation)
    // =========================================================================

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 private constant ATTEST_TYPEHASH = keccak256(
        "PQAttestation(address user,address to,uint256 amount,bytes32 quantumInputHash,uint256 nonce,uint256 deadline)"
    );

    bytes32 private constant NAME_HASH = keccak256("LemnicoinPQAttestation");
    bytes32 private constant VERSION_HASH = keccak256("1");

    // =========================================================================
    // EVENTS
    // =========================================================================

    event NativeDeposited(address indexed from, uint256 amount);

    /// @notice A withdrawal authorised by BOTH the attestor and the holder.
    event Withdrawn(
        address indexed recipient, uint256 amount, uint256 nonce, bytes32 quantumInputHash, address gasPayer
    );
    /// @notice A withdrawal authorised by the holder alone — the attestor-unreachable path.
    event WithdrawnWithHolderKey(
        address indexed recipient, uint256 amount, uint256 nonce, bytes32 quantumInputHash, address gasPayer
    );
    event Escaped(address indexed escapeAddress, uint256 amount, address caller);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error ZeroAuthority();
    error ZeroRecipient();
    error ZeroEscapeAddress();
    /// @notice v4: the escape address may not be the holder's own wallet — it is the lane that
    ///         survives a stolen wallet key, so it must not be defeated by one.
    error EscapeAddressIsHolder();
    error AttestationExpired();
    /// @notice v4: the deadline is further ahead than MAX_ATTESTATION_TTL allows.
    error DeadlineTooFar(uint256 deadline, uint256 maxAllowed);
    error InvalidNonce(uint256 expected, uint256 provided);
    error InvalidSaltLength(uint256 length);
    error InvalidS2Length(uint256 length);
    error InvalidNtthLength(uint256 length);
    /// @notice The attestor's signature over the withdrawal digest did not verify.
    error AttestorFalconVerificationFailed();
    /// @notice The holder's signature over the withdrawal digest did not verify.
    error HolderFalconVerificationFailed();
    error NativeSendFailed();
    error NotNativeVault();
    error NotEscapeAuthorized();
    error NothingToEscape();
    error HolderFalconKeyNotRegistered();
    error HolderFalconKeyMismatch();
    error LemniTollNotMet(uint256 required, uint256 held);

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor(
        address holder_,
        address asset_,
        address authority_,
        address escapeAddress_,
        address lemniToken_,
        uint256 unitTollScale_
    ) {
        if (authority_ == address(0)) revert ZeroAuthority();
        if (escapeAddress_ == address(0)) revert ZeroEscapeAddress();
        // The escape lane exists so a stolen wallet key cannot reach the funds. Pointing it at the
        // holder's own wallet hands a thief the whole balance in one call, which is the failure this
        // vault is built to prevent — so it is rejected outright rather than merely discouraged.
        if (escapeAddress_ == holder_) revert EscapeAddressIsHolder();

        holder = holder_;
        asset = asset_;
        authority = ILemniAuthority(authority_);
        escapeAddress = escapeAddress_;
        lemniToken = lemniToken_;
        unitTollScale = unitTollScale_;
    }

    // =========================================================================
    // DEPOSIT (in)
    // =========================================================================

    receive() external payable {
        if (asset != address(0)) revert NotNativeVault();
        emit NativeDeposited(msg.sender, msg.value);
    }

    // =========================================================================
    // WITHDRAW (out) — dual signature: attestor AND holder
    // =========================================================================

    /// @notice Release `amount` to `recipient`, authorized by BOTH the attestor's Falcon signature
    ///         and the holder's own. `msg.sender` is the gas payer and carries NO authority.
    /// @dev Both signatures cover the SAME digest, so neither party can be shown a different
    ///      withdrawal from the one that executes.
    /// @param attestorSalt40 The attestor's Falcon salt (40 bytes).
    /// @param attestorS2_32  The attestor's Falcon s2 (32 words).
    /// @param holderSalt40   The holder's Falcon salt (40 bytes).
    /// @param holderS2_32    The holder's Falcon s2 (32 words).
    /// @param holderNtth     The holder's registered Falcon public key (NTT domain, 32 words).
    function withdraw(
        address recipient,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata attestorSalt40,
        uint256[] calldata attestorS2_32,
        bytes calldata holderSalt40,
        uint256[] calldata holderS2_32,
        uint256[] calldata holderNtth
    ) external nonReentrant {
        bytes32 digest = _validateAndDigest(recipient, amount, quantumInputHash, nonce, deadline);

        _requireSignatureShape(attestorSalt40, attestorS2_32);
        _requireSignatureShape(holderSalt40, holderS2_32);
        _requireHolderKey(holderNtth);

        if (!_falconVerify(digest, attestorSalt40, attestorS2_32, _attestorNtth())) {
            revert AttestorFalconVerificationFailed();
        }
        if (!_falconVerify(digest, holderSalt40, holderS2_32, _toMemoryArray(holderNtth))) {
            revert HolderFalconVerificationFailed();
        }

        withdrawalNonce = nonce + 1;
        _payOut(recipient, amount);

        emit Withdrawn(recipient, amount, nonce, quantumInputHash, msg.sender);
    }

    // =========================================================================
    // WITHDRAW (out) — holder alone, for when the attestor is unreachable
    // =========================================================================

    /// @notice The same withdrawal, authorized by the HOLDER'S key alone.
    /// @dev This is the outage path, and it is why requiring both signatures above cannot lock a
    ///      holder out of their own funds: the attestor's availability is never a condition of
    ///      withdrawal. It is not a weaker path — the holder's signature is required either way —
    ///      it simply drops the attestor's.
    ///
    ///      The attestor is not here to check the LEMNI toll, so this path enforces it on-chain.
    function withdrawWithHolderKey(
        address recipient,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata holderSalt40,
        uint256[] calldata holderS2_32,
        uint256[] calldata holderNtth
    ) external nonReentrant {
        bytes32 digest = _validateAndDigest(recipient, amount, quantumInputHash, nonce, deadline);

        _requireSignatureShape(holderSalt40, holderS2_32);
        _requireHolderKey(holderNtth);
        _requireLemniToll(amount);

        if (!_falconVerify(digest, holderSalt40, holderS2_32, _toMemoryArray(holderNtth))) {
            revert HolderFalconVerificationFailed();
        }

        withdrawalNonce = nonce + 1;
        _payOut(recipient, amount);

        emit WithdrawnWithHolderKey(recipient, amount, nonce, quantumInputHash, msg.sender);
    }

    // =========================================================================
    // ESCAPE (out) — attestor-free, seed-free, fixed recipient
    // =========================================================================

    /// @notice Sweep the ENTIRE vault balance to the pre-committed `escapeAddress`. Callable ONLY by
    ///         the holder wallet or the escape wallet, and can ONLY ever pay `escapeAddress`.
    /// @dev The only path that needs no seed, which makes it the recovery lane for a lost seed
    ///      phrase. The constructor guarantees `escapeAddress != holder`, so a stolen wallet key
    ///      moves funds to the holder's own cold address and nowhere else.
    function escape() external nonReentrant {
        if (msg.sender != holder && msg.sender != escapeAddress) revert NotEscapeAuthorized();

        uint256 amount;
        if (asset == address(0)) {
            amount = address(this).balance;
            if (amount == 0) revert NothingToEscape();
            (bool ok, ) = payable(escapeAddress).call{value: amount}("");
            if (!ok) revert NativeSendFailed();
        } else {
            amount = IERC20(asset).balanceOf(address(this));
            if (amount == 0) revert NothingToEscape();
            IERC20(asset).safeTransfer(escapeAddress, amount);
        }

        emit Escaped(escapeAddress, amount, msg.sender);
    }

    // =========================================================================
    // VIEWS
    // =========================================================================

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this))
        );
    }

    /// @notice The digest BOTH signatures must cover. Unchanged from v1/v2/v3, so the attestor,
    ///         the dApp and the vault popup all build it exactly as they did before.
    function computeAttestationDigest(
        address recipient,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32) {
        return _attestationDigest(holder, recipient, amount, quantumInputHash, nonce, deadline);
    }

    /// @notice LEMNI (base units) the holder must hold to withdraw `amount` on the holder-only path.
    function requiredLemniToll(uint256 amount) public view returns (uint256) {
        if (unitTollScale == 0 || lemniToken == address(0) || amount == 0) return 0;
        return ((amount + unitTollScale - 1) / unitTollScale) * LEMNI_UNIT;
    }

    /// @notice Whether this vault's holder can sign at all. Always true for a vault deployed by
    ///         `LemniVaultFactoryV4`, which refuses unregistered holders — kept as a view so
    ///         monitoring can assert the invariant rather than assume it.
    function holderKeyRegistered() external view returns (bool) {
        return authority.holderFalconCommitment(holder) != bytes32(0);
    }

    /// @notice The latest deadline a withdrawal submitted in the next block could carry.
    function maxAcceptableDeadline() external view returns (uint256) {
        return block.timestamp + MAX_ATTESTATION_TTL;
    }

    // =========================================================================
    // INTERNAL
    // =========================================================================

    /// @dev Shared front half of both withdrawal paths: identical validation, identical digest.
    function _validateAndDigest(
        address recipient,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        if (recipient == address(0)) revert ZeroRecipient();
        if (block.timestamp > deadline) revert AttestationExpired();
        // A deadline is a promise about how long an authorisation stays live. Unbounded, one signed
        // packet is a standing instruction; bounded, it is a request that expires.
        uint256 maxAllowed = block.timestamp + MAX_ATTESTATION_TTL;
        if (deadline > maxAllowed) revert DeadlineTooFar(deadline, maxAllowed);
        if (nonce != withdrawalNonce) revert InvalidNonce(withdrawalNonce, nonce);
        return _attestationDigest(holder, recipient, amount, quantumInputHash, nonce, deadline);
    }

    function _requireSignatureShape(bytes calldata salt40, uint256[] calldata s2_32) internal pure {
        if (salt40.length != 40) revert InvalidSaltLength(salt40.length);
        if (s2_32.length != 32) revert InvalidS2Length(s2_32.length);
    }

    /// @dev Revert unless `holderNtth` is exactly the key the holder registered with the authority.
    function _requireHolderKey(uint256[] calldata holderNtth) internal view {
        if (holderNtth.length != 32) revert InvalidNtthLength(holderNtth.length);

        bytes32 commitment = authority.holderFalconCommitment(holder);
        if (commitment == bytes32(0)) revert HolderFalconKeyNotRegistered();
        if (keccak256(abi.encodePacked(holderNtth)) != commitment) revert HolderFalconKeyMismatch();
    }

    /// @dev Revert unless the holder still holds the LEMNI toll for a 1:1 asset. No-op otherwise.
    function _requireLemniToll(uint256 amount) internal view {
        uint256 required = requiredLemniToll(amount);
        if (required == 0) return;

        uint256 held = IERC20(lemniToken).balanceOf(holder);
        if (held < required) revert LemniTollNotMet(required, held);
    }

    function _falconVerify(
        bytes32 digest,
        bytes calldata salt40,
        uint256[] calldata s2_32,
        uint256[] memory ntth
    ) internal view returns (bool) {
        return IZKNOXEthFalcon(authority.FALCON_VERIFIER()).verify(
            abi.encodePacked(digest), salt40, _toMemoryArray(s2_32), ntth
        );
    }

    function _payOut(address recipient, uint256 amount) internal {
        if (asset == address(0)) {
            (bool ok, ) = payable(recipient).call{value: amount}("");
            if (!ok) revert NativeSendFailed();
        } else {
            IERC20(asset).safeTransfer(recipient, amount);
        }
    }

    function _attestationDigest(
        address user,
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(ATTEST_TYPEHASH, user, to, amount, quantumInputHash, nonce, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function _attestorNtth() internal view returns (uint256[] memory out) {
        uint256[32] memory fixedKey = authority.getAttestorPublicKey();
        out = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            out[i] = fixedKey[i];
        }
    }

    function _toMemoryArray(uint256[] calldata arr) internal pure returns (uint256[] memory out) {
        out = new uint256[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) {
            out[i] = arr[i];
        }
    }
}
