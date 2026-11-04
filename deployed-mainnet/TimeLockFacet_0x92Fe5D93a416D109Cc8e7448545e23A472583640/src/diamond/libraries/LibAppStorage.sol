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
