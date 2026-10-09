// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "../../LAIPVerifier.sol";

/// @title LibAppStorage - Shared storage layout for Lemnicoin Diamond
/// @notice All facets share this single storage struct at slot 0.
///         NEVER reorder or remove fields — only append new fields at the end.
///         Changing field order will corrupt storage for deployed diamonds.

// =========================================================================
// STRUCT DEFINITIONS (used inside AppStorage mappings)
// =========================================================================

struct QuantumKeys {
    LAIPVerifier.LAIPPublicKey laip;
    bytes dilithiumPublicKey; // 2592 bytes
    bool bound;
}

struct QuantumKeyHashes {
    bytes32 laipQHash;      // keccak256(laipQx || laipQy)
    bytes32 laipP0Hash;     // keccak256(laipP0x || laipP0y)
    bytes32 mldsaPkHash;    // keccak256(mldsaPublicKey)
    bool registered;
}

struct VestingSchedule {
    uint256 totalAmount;
    uint256 unlocked;       // Not used — vesting calculated dynamically
    uint256 startTime;
    uint256 cliffDuration;
    uint256 vestingDuration;
}

struct PendingTransfer {
    address from;
    address to;
    uint256 amount;
    bytes32 txBodyHash;
    bytes dilithiumSignature;
    bytes laipSignature;
    uint256 feePaid;
    uint256 nonce;
    bool exists;
}

struct FalconEnvelope {
    bytes32 txHash;
    bytes32 laipPubKeyCommitment;
    bytes laipPublicKey;
    bytes laipSignature;
    bytes dilithiumSignature;
}

/// @notice Time-locked token grant that releases 100% at unlockDate
struct TimeLock {
    uint256 amount;
    uint256 unlockDate;
    bool active;
}

/// @notice M-of-N ring of holder Falcon keys governing one account ("Multi-Sig").
/// @dev Only keccak256 commitments of the member keys are stored (one slot each); the full
///      32-word NTT-domain keys travel in calldata at signing time and are checked against
///      these commitments, exactly like the single holderFalconCommitment.
struct RingConfig {
    bytes32[] memberCommitments; // keccak256(abi.encodePacked(uint256[32] ntth)) per member
    uint8 threshold;             // M — signatures required per operation
    bool registered;             // write-once ratchet, same as the other quantum keys
}

/// @notice LAIP-V3 quantum key registration (isogeny KEM curve + on-chain-verifiable SLH-DSA).
/// @dev Only hashes and a small parameter id live on chain; full keys travel in calldata at use
///      time and are checked against these commitments, exactly like the V1/V2 hashes.
struct LaipV3Keys {
    bytes32 curveHash;      // keccak256(enc(A_wallet)) — CSIDH public curve coefficient hash
    bytes32 slhdsaPkHash;   // keccak256(SLH-DSA-SHA2-128s public key) — the LOS/hash-based signer
    bytes32 mldsaPkHash;    // keccak256(ML-DSA-87 public key) — carried for C_own_v3 continuity
    bytes32 paramId;        // e.g. keccak256("laip-csidh-p1024") — versions the isogeny parameter set
    bool registered;        // write-once ratchet
}

// =========================================================================
// APP STORAGE — the single source of truth for all facets
// =========================================================================

struct AppStorage {
    // --- ERC20 ---
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowances;
    uint256 totalSupply;
    string name;
    string symbol;

    // --- Pausable ---
    bool paused;

    // --- Access control ---
    address guardian;
    address cexGovernanceSigner;

    // --- Quantum key management ---
    mapping(address => QuantumKeys) quantumKeys;
    mapping(address => uint256) quantumNonce;
    mapping(address => bytes32) laipKeyCommitment;
    mapping(address => QuantumKeyHashes) quantumKeyHashes;
    mapping(address => bytes32) bindingChallenges;
    uint256 challengeNonce;

    // --- Dilithium verifier validation ---
    bool dilithiumVerifierValidated;
    bool dilithiumValidationGuardianApproval;

    // --- CEX whitelist ---
    mapping(address => bool) isWhitelistedCEX;
    bool cexBypassEnabled;
    bool pendingCexBypassState;
    uint256 pendingCexBypassEta;
    bool cexBypassGuardianApproval;
    bool cexBypassFuseActivated;
    address pendingCexGovernanceSigner;

    // --- Per-user CEX/DEX sessions ---
    mapping(address => mapping(address => uint256)) userCexSession;

    // --- Oracle ---
    address priceOracle;
    bool laipTransferEnabled;
    address pendingOracle;
    uint256 pendingOracleEta;
    bool oracleGuardianApproval;
    uint256 lastOracleUpdate;

    // --- External verifier references (DEPRECATED - C-01/C-02 audit) ---
    // These fields are kept for storage layout compatibility but are no longer used.
    // All transfers now use Falcon attestation via QuantumTransferFacet.
    address dualKeyVerifier;  // DEPRECATED: removed transferWithDualKeyProof
    address starkVerifier;    // DEPRECATED: removed transferWithStarkProof

    // --- Pending transfers ---
    mapping(bytes32 => PendingTransfer) pendingTransfers;

    // --- Deployment phase ---
    bool deploymentPhaseActive;
    mapping(address => VestingSchedule) vestingSchedules;

    // --- Falcon attestation (was FalconAttestation mixin) ---
    address falconVerifier;           // IZKNOXEthFalcon address
    uint256[32] attestorNtth;         // Attestor public key in NTT domain
    mapping(address => uint256) pqAttestationNonce;

    // --- Falcon governance (was FalconGovernance mixin) ---
    address governanceFalconVerifier; // IZKNOXEthFalcon address
    uint256[32] governanceAttestorNtth;
    bool governanceFalconInitialized;
    mapping(address => uint256) governanceNonce;

    // --- LAIP curve validation cache ---
    // Stores keccak256(x || y) after on-chain curve validation via validateLaipCurve().
    // Transfers check this cache - if Q not validated, transaction fails as forgery.
    mapping(address => bytes32) laipValidatedQHash;

    // --- Time-locked grants (added post-deployment) ---
    // Multiple time locks per beneficiary, indexed by lock ID
    mapping(address => mapping(uint256 => TimeLock)) timeLocks;
    mapping(address => uint256) timeLockCount;

    // --- Reentrancy guard (M-04 fix) ---
    uint256 reentrancyStatus;

    // --- DEX pool whitelist (always active, no toggle/fuse) ---
    // Whitelisted DEX pool/pair contracts can send LEMNI outbound (transfer)
    // and receive LEMNI inbound (transferFrom recipient check).
    // Security: LEMNI can only enter a pool through quantum-protected paths
    // (quantumApprove + transferFrom). approve() does NOT bypass for DEX pools.
    mapping(address => bool) isWhitelistedDEXPool;

    // --- Wallet whitelist (governance-controlled sender->recipient bypass) ---
    // Allows specific sender->recipient pairs to use transfer()/approve()
    // without quantum signatures. Enable/disable via 3-step governance.
    // Guardian can permanently disable via fuse.
    mapping(address => mapping(address => bool)) walletWhitelistPair;
    bool walletWhitelistEnabled;
    bool pendingWalletWhitelistState;
    bool pendingWalletWhitelistActive;
    bool walletWhitelistGuardianApproval;
    bool walletWhitelistFuseActivated;

    // --- Oracle disable/enable toggle ---
    // Stores the oracle address when fees are temporarily disabled via disablePriceOracle().
    // enablePriceOracle() restores priceOracle from this field.
    address savedPriceOracle;

    // --- Rekey operator (Safe migration support) ---
    // Dedicated address that can rotate attestor keys (with Falcon governance sig)
    // without needing to be the diamond owner. This allows automated key rotation
    // to continue after ownership is transferred to a Gnosis Safe multisig.
    address rekeyOperator;

    // --- Quantum-approved spender tracking ---
    // Set to true ONLY when quantumApprove() is called. transferFrom() checks
    // this to ensure the spender's allowance was set through the quantum-protected
    // path (Falcon attestation + LAIP verification), not via a pre-existing
    // allowance from the old approve() bypass bug.
    mapping(address => mapping(address => bool)) quantumApprovedSpender;

    // --- Circuit breaker (auto-pause on anomalous transfer volume) ---
    // Tracks rolling transfer volume in a time window. If cumulative volume
    // exceeds the threshold, the contract auto-pauses without governance action.
    // Normal unpause governance flow (owner + Falcon) resumes operations.
    uint256 circuitBreakerWindowStart;   // start timestamp of current window
    uint256 circuitBreakerWindowVolume;  // cumulative transfer volume in current window
    uint256 circuitBreakerThreshold;     // max volume before auto-pause (0 = disabled)
    uint256 circuitBreakerWindow;        // window duration in seconds (e.g., 3600 = 1 hour)

    // --- Circuit breaker exclusions (liquidity infrastructure) ---
    // Transfers where either `from` or `to` is in this set are NOT counted
    // toward circuit breaker volume. Typical entries: deployer wallet,
    // Uniswap router, NonfungiblePositionManager, pool addresses.
    mapping(address => bool) circuitBreakerExcluded;

    // --- V2 Ownership Commitment (BTC cross-chain anchor) ---
    // C_own = SHA-256(K_laip_public || K_dilithium_public || K_hashbased_public)
    // Once set (non-zero), CANNOT be changed — even by the wallet owner.
    // This is the core theft-protection invariant: an attacker who steals
    // the wallet private key cannot re-register different quantum keys.
    // Also serves as the cross-chain anchor for BTC wallet verification.
    mapping(address => bytes32) ownershipCommitment;

    // --- Holder Falcon key (attestor-free signing path) ---
    // keccak256(abi.encodePacked(uint256[32] ntth)) for the holder's OWN Falcon-512 key, derived
    // in the dApp from the same 48-word seed as their LAIP and ML-DSA keys. When the attestor
    // cannot be reached, the holder signs the identical attestation packet themselves and passes
    // the full ntth in calldata; the chain hashes it and compares against this commitment.
    //
    // Storing only the hash keeps registration to one slot. Set once and then IMMUTABLE — the same
    // one-way ratchet as the other quantum keys, so a stolen wallet key cannot swap in a new one.
    //
    // NOTE: appended at the END of AppStorage. Diamond storage is layout-sensitive; new fields must
    // only ever be added here, never inserted above.
    mapping(address => bytes32) holderFalconCommitment;

    // --- Attestor liveness gate (holder-only path time-lock) ---
    // The single-signature holder-only path (quantumTransferWithHolderKey) is an escape hatch for
    // when the attestor is unreachable. To make normal operation a TRUE 2-of-2, that path is kept
    // CLOSED while the attestor proves it is alive, and only OPENS after the attestor has been
    // silent for `holderOnlyOutageBlocks` blocks.
    //
    //   attestorHeartbeatSigner   — the EOA the attestor service uses to post heartbeats. Set by
    //                               the owner. Distinct from the attestor's Falcon key (attestorNtth)
    //                               so heartbeating never touches the signing key.
    //   attestorLastHeartbeatBlock — block.number of the most recent heartbeat.
    //   holderOnlyOutageBlocks     — N. If 0 the gate is DISABLED and the holder-only path is always
    //                               allowed (exactly the pre-upgrade behavior), so this upgrade is
    //                               non-breaking until the owner configures it.
    //
    // Appended at the END — never insert above this.
    address attestorHeartbeatSigner;
    uint256 attestorLastHeartbeatBlock;
    uint256 holderOnlyOutageBlocks;

    // --- Multi-Sig rings (M-of-N holder Falcon multisig) ---
    // A ring account's balance moves only with >= threshold member Falcon signatures over the same
    // EIP-712 digest, plus the attestor's signature while the attestor is provably live (the same
    // liveness gate the holder-only path uses). Ring accounts have their single-signature paths
    // (dual / holder-only / session / recovery) closed in LibLemnicoin.requireDualFalcon and
    // transferWithHolderFalconAttestationFrom.
    //
    //   ringConfig          — the write-once ring definition per account.
    //   ringBypassNonce     — replay protection for bypass declarations/cancellations.
    //   ringBypassMaturesAt — timestamp an M-signed "proceed without the attestor" declaration
    //                         matures (0 = none active). The escape for an attestor that heartbeats
    //                         but refuses to co-sign; guarantees a ring is never frozen by us.
    //   ringBypassDelaySeconds — owner-set maturation delay (0 = use the 7-day default).
    //
    // Appended at the END — never insert above this.
    mapping(address => RingConfig) ringConfig;
    mapping(address => uint256) ringBypassNonce;
    mapping(address => uint256) ringBypassMaturesAt;
    uint256 ringBypassDelaySeconds;

    // --- LAIP-V3: isogeny KEM + hash-based (LOS/SLH-DSA) quantum keys ---
    // V3 is strictly ADDITIVE. Legacy V1/V2 registration (quantumKeyHashes, ownershipCommitment,
    // laipKeyCommitment) is preserved untouched, so a V3-migrated wallet can ALWAYS still transact
    // on its existing V1/V2 + dual-Falcon path — funds are never frozen by adopting V3.
    //
    //   laipV3          — per-account V3 key registration (see LaipV3Keys). Write-once ratchet.
    //   ownershipCommitmentV3 — C_own_v3 = keccak256(curveHash || mldsaPkHash || slhdsaPkHash),
    //                           the V3 hash-based-inclusive ownership anchor. Legacy `ownershipCommitment`
    //                           (the BTC cross-chain anchor) is DELIBERATELY left in place and readable
    //                           forever; BTC tooling adopts C_own_v3 on its own schedule.
    //
    // Appended at the END — never insert above this.
    mapping(address => LaipV3Keys) laipV3;
    mapping(address => bytes32) ownershipCommitmentV3;

    // Controls whether the on-chain SLH-DSA (LOS / hash family) is REQUIRED on the attestor-independent
    // path. Default false = STRICT: every such transfer must present a valid SLH signature that verifies
    // on chain, or it reverts — so the transfer always requires Falcon AND the hash family (immune to a
    // Falcon/lattice break). Owner sets this true ONLY on a chain whose blocks genuinely cannot fit the
    // ~24.6M-gas verification; there the path relaxes to best-effort/Falcon-only. This is a deliberate
    // per-chain governance decision, NOT an attacker-triggerable per-transaction skip.
    bool laipV3RelaxSlh;

    // Address of the external SlhDsaVerifier contract, called with a bounded gas budget so an
    // out-of-gas in the ~24.6M verification is caught and the transfer proceeds on Falcon. If zero,
    // the on-chain SLH-DSA check is skipped entirely (Falcon-only). Set by the owner post-deploy.
    address slhDsaVerifier;

    // --- LAIP-V3 ECONOMIC SLH EXEMPTION (the "1% rule") ---
    // A strict on-chain SLH-DSA verify costs ~24.6M gas. On a small transfer that gas can be worth
    // more than the value being moved, so the holder is made to pay more for the hash-family factor
    // than the factor protects. When that is true the factor is dropped and the transfer proceeds on
    // the Falcon floor.
    //
    // The rule is deliberately gated by an ORACLE-INDEPENDENT ceiling, because the value half of the
    // comparison comes from PriceOracle, whose LEMNI leg is a Uniswap V3 SPOT price and is therefore
    // manipulable inside a single block. The ceiling means no amount of price manipulation, and no
    // amount of basefee inflation, can widen the exemption past a fixed number of LEMNI per window.
    //
    //   slhExemptMaxAmount   — EXPLICIT governance ceiling, in LEMNI wei, on (a) any single exempt
    //                          transfer and (b) the rolling per-account total moved without on-chain
    //                          SLH. 0 = use the self-calibrating default (see LibSlhEconomics
    //                          .effectiveCeiling): the break-even amount under the live oracle,
    //                          clamped by totalSupply / DEFAULT_SUPPLY_DIVISOR so a manipulated
    //                          price cannot widen it. The rule is therefore ON by default.
    //   slhExemptDisabled    — governance kill switch for the whole economic exemption. false by
    //                          default, i.e. the rule is active. Setting it true restores the
    //                          pre-1%-rule behaviour: SLH required wherever the chain fits it.
    //   slhExemptWindow      — length of the rolling window in seconds. 0 = 1 day.
    //   slhExemptWindowStart — per-account start of the current window.
    //   slhExemptUsed        — per-account LEMNI wei moved without on-chain SLH in the current window.
    //
    // Appended at the END — never insert above this.
    uint256 slhExemptMaxAmount;
    uint256 slhExemptWindow;
    mapping(address => uint256) slhExemptWindowStart;
    mapping(address => uint256) slhExemptUsed;
    bool slhExemptDisabled;

    // --- Protocol fee exemption (per-wallet, governance-controlled) ---
    // Wallets in this set pay NO native protocol fee (the 12-40 bps collected in native
    // POL/ETH as msg.value) on ANY quantum transfer/approve/recovery path. This is the
    // blanket per-wallet counterpart to the pair-based walletWhitelist: it only ever SKIPS
    // the fee, never gates a transfer, so it can never freeze funds. Defaults to false for
    // every address (non-breaking). Managed by the owner via FeeExemptionFacet.setFeeExempt.
    //
    // SECURITY NOTE: the fee is protocol REVENUE, not a fund-safety control. Exempting a
    // wallet costs the protocol fee income on that wallet's transfers and nothing more; it
    // cannot be used to move another account's funds or bypass any quantum signature.
    //
    // Appended at the END — never insert above this.
    mapping(address => bool) feeExempt;
}

// =========================================================================
// CONSTANTS (not stored — compiled into bytecode)
// =========================================================================

uint256 constant MAX_SUPPLY = 1_000_000_000 * 10 ** 18;

// Session duration limits (audit fix #6: reduced from 24h to 4h to limit exposure window)
// SECURITY: Even with a valid session, attackers only have a 4-hour window if they
// compromise a session. Users should create sessions only when actively trading.
uint256 constant MAX_SESSION_DURATION = 4 hours;
uint256 constant MIN_SESSION_DURATION = 5 minutes;

uint256 constant ORACLE_UPDATE_DELAY = 1 days;
uint256 constant ORACLE_UPDATE_COOLDOWN = 1 hours;

// CEX bypass requires 1-day timelock + guardian approval (defense in depth)
// SECURITY: cexBypassEnabled defaults to false. Once cexBypassFuseActivated is set,
// CEX bypass can NEVER be re-enabled (permanent shutdown via guardian fuse).
uint256 constant CEX_BYPASS_DELAY = 1 days;

uint256 constant PENDING_TRANSFER_TIMEOUT = 100;

library LibAppStorage {
    /// @notice Returns the AppStorage struct at slot 0.
    ///         All facets MUST use this (or declare `AppStorage internal s;`
    ///         as their first state variable) so they agree on layout.
    function appStorage() internal pure returns (AppStorage storage s) {
        assembly {
            s.slot := 0
        }
    }
}
