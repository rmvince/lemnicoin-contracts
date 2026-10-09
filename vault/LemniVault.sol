// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

import {IZKNOXEthFalcon} from "../falcon/IZKNOXEthFalcon.sol";
import {ILemniAuthority} from "./interfaces/ILemniAuthority.sol";

/// @title LemniVault — per-user, single-asset, quantum-resistant, theft-proof vault (Polygon v1)
/// @notice A thin per-holder, per-asset vault. It accepts deposits of ONE asset (a specific ERC-20,
///         or native value when `asset == address(0)`) and releases it through EXACTLY ONE outflow
///         path: a post-quantum dual-authority Falcon attestation, verified **exactly as LEMNI
///         verifies its own transfers**. There is no other way for funds to leave.
///
/// @dev ATTESTATION IS IDENTICAL TO LEMNI (by design requirement). The digest uses the SAME
///      EIP-712 domain (`name = "LemnicoinPQAttestation"`, `version = "1"`) and the SAME
///      `PQAttestation(address user,address to,uint256 amount,bytes32 quantumInputHash,uint256
///      nonce,uint256 deadline)` struct that the LEMNI Diamond and the EC2 attestor already use.
///      The ONLY field that differs in value is the domain's `verifyingContract`, which is this
///      vault — exactly as LEMNI sets it to its own address. The attestor therefore needs NO new
///      code: its existing transfer-attestation path already takes `verifyingContract`, `user`,
///      `to`, `amount`, `nonce`, `deadline` as parameters and takes the nonce from the request.
///
///      WHY ONE ASSET PER VAULT. LEMNI's `PQAttestation` has no `asset` field because LEMNI only
///      ever moves the LEMNI token — the asset is implicit in the Diamond. To keep the attestation
///      byte-for-byte identical, this vault binds the asset the same way: implicitly, via the vault
///      address. The asset is fixed at deployment (`asset` immutable). A holder who wants to protect
///      several assets gets one vault per asset (deterministic addresses from the factory). This is
///      what keeps Vuln #2's "no re-aim across asset" closed: there is no asset parameter to re-aim.
///
///   SECURITY MODEL (spec §3, §5, §8):
///
///   Protection is "held-under", never "held-beside" — the asset is QR/theft-proof because it sits
///   inside this contract and the contract only releases on a valid PQC attestation.
///
///   Vuln #1 — NO ECDSA ESCAPE PATH. No owner, admin, upgrade key, or recovery path. `holder` is
///   bound into the attestation (the `user` field) and emitted in events, but confers no on-chain
///   authority. `msg.sender` on withdraw() is "whoever paid the gas" and is never consulted for
///   authorization. Breaking the holder's secp256k1 key moves nothing.
///
///   Vuln #2 — EVERY AUTHORIZATION IS BOUND TO THE EXACT SPEND. The attested digest commits to
///   {chainId, vault (=verifyingContract), holder, recipient, amount, nonce, deadline,
///   quantumInputHash}; the asset is bound by the vault's identity. A captured attestation cannot
///   be replayed (monotonic nonce) nor re-aimed at a different recipient or amount (digest changes)
///   nor a different asset (different vault entirely).
contract LemniVault is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // =========================================================================
    // IMMUTABLES
    // =========================================================================

    /// @notice The holder this vault was deployed for. Bound into the attestation as `user`.
    ///         Grants NO on-chain authority (the holder cannot withdraw, pause, upgrade, or recover
    ///         by holding this address's key).
    address public immutable holder;

    /// @notice The single asset this vault custodies. `address(0)` = native value (MATIC/POL).
    address public immutable asset;

    /// @notice The EXISTING LEMNI Diamond, read-only, for the attestor key + Falcon verifier.
    ILemniAuthority public immutable authority;

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Monotonic per-vault withdrawal nonce. Replay protection (Vuln #2).
    uint256 public withdrawalNonce;

    // =========================================================================
    // EIP-712 — IDENTICAL TO LEMNI (LibLemnicoin / FalconAttestation)
    // =========================================================================

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev The EXACT typehash LEMNI uses for transfer attestations.
    bytes32 private constant ATTEST_TYPEHASH = keccak256(
        "PQAttestation(address user,address to,uint256 amount,bytes32 quantumInputHash,uint256 nonce,uint256 deadline)"
    );

    /// @dev The EXACT domain name/version LEMNI uses. Only `verifyingContract` (this vault) differs.
    bytes32 private constant NAME_HASH = keccak256("LemnicoinPQAttestation");
    bytes32 private constant VERSION_HASH = keccak256("1");

    // =========================================================================
    // EVENTS
    // =========================================================================

    event NativeDeposited(address indexed from, uint256 amount);
    event Withdrawn(
        address indexed recipient, uint256 amount, uint256 nonce, bytes32 quantumInputHash, address gasPayer
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error ZeroAuthority();
    error ZeroRecipient();
    error AttestationExpired();
    error InvalidNonce(uint256 expected, uint256 provided);
    error InvalidSaltLength(uint256 length);
    error InvalidS2Length(uint256 length);
    error FalconVerificationFailed();
    error NativeSendFailed();
    error NotNativeVault();

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor(address holder_, address asset_, address authority_) {
        if (authority_ == address(0)) revert ZeroAuthority();
        holder = holder_;       // identification + attestation binding only; no authority
        asset = asset_;         // address(0) = native
        authority = ILemniAuthority(authority_);
    }

    // =========================================================================
    // DEPOSIT (in)
    // =========================================================================

    /// @notice Accept native value (MATIC/POL). Only meaningful for a native vault (asset == 0).
    receive() external payable {
        if (asset != address(0)) revert NotNativeVault();
        emit NativeDeposited(msg.sender, msg.value);
    }

    // =========================================================================
    // WITHDRAW (out) — the ONLY outflow path
    // =========================================================================

    /// @notice Release `amount` of this vault's asset to `recipient`, authorized SOLELY by a
    ///         post-quantum dual-authority Falcon attestation — verified exactly as LEMNI verifies
    ///         a transfer. `msg.sender` is the gas payer and carries NO authority (§8, Vuln #1).
    /// @param recipient        Destination address (the `to` field of the LEMNI PQAttestation).
    /// @param amount           Amount to release (mind decimals; USDC/USDT = 6).
    /// @param quantumInputHash Links the attestation to the exact LAIP + ML-DSA signatures the
    ///                         attestor verified off-chain (identical to LEMNI).
    /// @param nonce            Must equal the vault's current `withdrawalNonce`.
    /// @param deadline         Unix expiry; rejected after this.
    /// @param falconSalt40     40-byte Falcon salt from the attestor.
    /// @param falconS2_32      Falcon signature polynomial (32 words) from the attestor.
    function withdraw(
        address recipient,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32
    ) external nonReentrant {
        if (recipient == address(0)) revert ZeroRecipient();
        if (block.timestamp > deadline) revert AttestationExpired();
        if (nonce != withdrawalNonce) revert InvalidNonce(withdrawalNonce, nonce);
        if (falconSalt40.length != 40) revert InvalidSaltLength(falconSalt40.length);
        if (falconS2_32.length != 32) revert InvalidS2Length(falconS2_32.length);

        // --- AUTHORIZATION: the LEMNI attestation digest, verbatim, with verifyingContract = this ---
        bytes32 digest = _attestationDigest(holder, recipient, amount, quantumInputHash, nonce, deadline);

        IZKNOXEthFalcon verifier = IZKNOXEthFalcon(authority.FALCON_VERIFIER());
        bool valid = verifier.verify(
            abi.encodePacked(digest),
            falconSalt40,
            _toMemoryArray(falconS2_32),
            _attestorNtth()
        );
        if (!valid) revert FalconVerificationFailed();

        // --- EFFECTS before INTERACTION ---
        withdrawalNonce = nonce + 1;

        if (asset == address(0)) {
            (bool ok, ) = payable(recipient).call{value: amount}("");
            if (!ok) revert NativeSendFailed();
        } else {
            IERC20(asset).safeTransfer(recipient, amount);
        }

        emit Withdrawn(recipient, amount, nonce, quantumInputHash, msg.sender);
    }

    // =========================================================================
    // VIEWS
    // =========================================================================

    /// @notice EIP-712 domain separator — identical scheme to LEMNI, verifyingContract = this vault.
    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this))
        );
    }

    /// @notice The exact digest the attestor must sign — the LEMNI `PQAttestation` digest with
    ///         `user = holder` and `verifyingContract = this vault`. The dApp passes
    ///         {chainId, verifyingContract=this, user=holder, to=recipient, amount, nonce, deadline}
    ///         to the attestor's existing transfer endpoint to obtain it.
    function computeAttestationDigest(
        address recipient,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32) {
        return _attestationDigest(holder, recipient, amount, quantumInputHash, nonce, deadline);
    }

    // =========================================================================
    // INTERNAL
    // =========================================================================

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
