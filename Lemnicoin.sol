// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title Lemnicoin — ABI-only interface of the retired monolithic token contract
/// @notice The monolithic implementation was REMOVED (2026-08): production is the
///         Lemnicoin Diamond (EIP-2535) and the monolith's re-registration paths
///         (mutable registerQuantumKeys, access-control-free registerQuantumKeysTrusted)
///         made it unsafe to keep deployable. This interface preserves the exact ABI
///         so operational scripts keep talking to the live Diamond via
///         ethers.getContractAt("Lemnicoin", DIAMOND_ADDRESS). An interface has no
///         bytecode: it cannot be deployed, by anyone, ever.
interface Lemnicoin {
    struct BatchTransferParams {
        address to;
        uint256 amount;
        bytes32 quantumInputHash;
        uint256 nonce;
        uint256 deadline;
        bytes falconSalt40;
        uint256[] falconS2_32;
    }

    struct BindingInput {
        bytes laipQx;
        bytes laipQy;
        bytes laipP0x;
        bytes laipP0y;
        bytes laipA;
        bytes laipP;
        bytes dilithiumPubKey;
        bytes laipProof;
        bytes dilithiumProof;
    }

    struct LAIPPublicKey {
        bytes x;
        bytes y;
        bytes p;
        bytes a;
        bytes P0;
    }

    struct LAIPVerifier_LAIPPublicKey {
        bytes Qx;
        bytes Qy;
        bytes P0x;
        bytes P0y;
        bytes a;
        bytes p;
        uint256 coordSize;
    }

    struct FalconEnvelope {
        bytes32 txHash;
        bytes32 laipPubKeyCommitment;
        bytes laipPublicKey;
        bytes laipSignature;
        bytes dilithiumSignature;
    }

    error AttestationExpired();
    error BadDilProofLen();
    error DeploymentPhaseEnded();
    error DilVerifierValidated();
    error EmptyCEXList();
    error EmptyWalletList();
    error ExceedsMaxSupply();
    error FalconVerificationFailed();
    error FeeTransferFailed();
    error GuardianApprovalMissing();
    error InsufficientBalance();
    error InsufficientFee();
    error InvalidBeneficiary();
    error InvalidCEXAddress();
    error InvalidDilithiumPKLength();
    error InvalidFalconSigLength();
    error InvalidFeeCollector();
    error InvalidGuardian();
    error InvalidLAIPProofLength();
    error InvalidNonce(uint256 expected, uint256 provided);
    error InvalidOracle();
    error InvalidS2Length(uint256 length);
    error InvalidSaltLength(uint256 length);
    error InvalidSessionDuration();
    error InvalidSigner();
    error KeysAlreadyBound();
    error LAIPCommitmentMismatch();
    error LAIPCurveNotValidated();
    error LAIPKeySizeMismatch();
    error LAIPOffCurve();
    error LAIPQHashMismatch();
    error NoChallenge();
    error NoPendingOracle();
    error NoPendingSigner();
    error NoQKeys();
    error OnlyGuardian();
    error OracleCooldown();
    error QuantumKeyMismatch();
    error RecoveryFromSelf();
    error RefundFailed();
    error ScheduleExists();
    error SessionNotFound();
    error TokensLocked();
    error TooManyCEX();
    error TooManyWallets();
    error TxBodyHashMismatch();
    error UseQApprove();
    error UseQuantumApprove();
    error UseQuantumTransfer();
    error UseTransferWithEnvelope();
    error WithdrawFailed();
    error ZeroAmount();
    error ZeroRecipient();
    error ZeroVerifierAddress();

    event Approval(address indexed owner, address indexed spender, uint256 value);
    event AttestorKeyUpdated(uint256[32] newNtth);
    event BindingChallengeCreated(address indexed account, bytes32 challenge);
    event CEXBypassFuseActivated();
    event CEXBypassGuardianApproved(bool enabled);
    event CEXBypassToggleProposed(bool enabled, uint256 eta);
    event CEXBypassToggled(bool enabled, uint256 timestamp);
    event CEXGovernanceSignerUpdated(address indexed newSigner);
    event CEXWhitelistRemoved(address[] cexAddresses, uint256 timestamp);
    event CEXWhitelistUpdated(address[] cexAddresses, uint256 timestamp);
    event CexSessionCreated(address indexed user, address indexed cexAddress, uint256 expiry, uint256 nonce);
    event CexSessionRevoked(address indexed user, address indexed cexAddress);
    event DeploymentPhaseClosed(uint256 timestamp);
    event DilithiumVerifierGuardianApproved();
    event DilithiumVerifierValidationFinalized(uint256 timestamp);
    event DistributionTransfer(address indexed to, uint256 amount);
    event ExcessRefunded(address indexed to, uint256 amount);
    event FalconApproval(address indexed owner, address indexed spender, uint256 amount, bytes32 quantumInputHash, uint256 nonce);
    event FalconAttestationVerified(address indexed user, address indexed to, uint256 amount, uint256 nonce, bytes32 quantumInputHash);
    event LAIPCurveValidated(address indexed user, bytes32 qHash);
    event LaipTransferToggled(bool enabled);
    event OracleGuardianApproved(address indexed newOracle);
    event OracleUpdateProposed(address indexed newOracle, uint256 eta);
    event OracleUpdated(address indexed newOracle, uint256 timestamp);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Paused(address account);
    event ProtocolFeeCollected(address indexed from, address indexed collector, uint256 feeWei);
    event QuantumApproval(address indexed owner, address indexed spender, uint256 amount, bytes32 txBodyHash);
    event QuantumKeysBound(address indexed account, bytes32 laipPubKeyHash, bytes32 dilithiumPubKeyHash);
    event QuantumKeysRegistered(address indexed user, bytes32 laipQHash, bytes32 laipP0Hash, bytes32 mldsaPkHash);
    event QuantumTransferWithFee(address indexed from, address indexed to, uint256 amount, uint256 feePaid, bytes32 txBodyHash);
    event RecoveryTransferExecuted(address indexed from, address indexed recoveredBy, address indexed to, uint256 amount, uint256 nonce);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Unpaused(address account);
    event VestingScheduleCreated(address indexed beneficiary, uint256 totalAmount, uint256 startTime, uint256 cliffDuration, uint256 vestingDuration);
    event WalletWhitelistFuseActivated();
    event WalletWhitelistGuardianApproved(bool enabled);
    event WalletWhitelistPairSet(address indexed sender, address indexed recipient, bool allowed);
    event WalletWhitelistToggleProposed(bool enabled);
    event WalletWhitelistToggled(bool enabled, uint256 timestamp);

    function ATTESTOR_NTTH(uint256) external view returns (uint256);
    function CEX_BYPASS_DELAY() external view returns (uint256);
    function FALCON_VERIFIER() external view returns (address);
    function MAX_SESSION_DURATION() external view returns (uint256);
    function MAX_SUPPLY() external view returns (uint256);
    function MIN_SESSION_DURATION() external view returns (uint256);
    function ORACLE_UPDATE_COOLDOWN() external view returns (uint256);
    function ORACLE_UPDATE_DELAY() external view returns (uint256);
    function SESSION_FEE_REFERENCE_AMOUNT() external view returns (uint256);
    function activateCEXBypassFuse() external;
    function activateWalletWhitelistFuse() external;
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function approveCEXBypassToggle(bool enabled) external;
    function approveDilithiumVerifierValidation() external;
    function approveOracle(address newOracle) external;
    function approveWalletWhitelistToggle(bool enabled) external;
    function approveWithFalconAttestation(address, uint256, bytes32, uint256, uint256, bytes calldata, uint256[] calldata) external pure returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function batchTransferWithFalconAttestation(BatchTransferParams[] calldata) external pure returns (bool);
    function bindQuantumKeys(BindingInput calldata input) external;
    function bindingChallenges(address) external view returns (bytes32);
    function burn(uint256 amount) external;
    function burnFrom(address account, uint256 amount) external;
    function canRecoverFrom(address from, address recoveredBy) external view returns (bool);
    function cexBypassEnabled() external view returns (bool);
    function cexBypassFuseActivated() external view returns (bool);
    function cexBypassGuardianApproval() external view returns (bool);
    function cexGovernanceSigner() external view returns (address);
    function computeApprovalDigest(address user, address spender, uint256 amount, bytes32 quantumInputHash, uint256 nonce, uint256 deadline) external view returns (bytes32);
    function computeDigest(address user, address to, uint256 amount, bytes32 quantumInputHash, uint256 nonce, uint256 deadline) external view returns (bytes32);
    function computeRecoveryDigest(address from, address recoveredBy, address to, uint256 amount, bytes32 quantumInputHash, uint256 nonce, uint256 deadline) external view returns (bytes32);
    function computeSessionDigest(address user, address cexAddress, uint256 duration, bytes32 quantumInputHash, uint256 nonce, uint256 deadline) external view returns (bytes32);
    function createBindingChallenge() external returns (bytes32);
    function createCexSession(address cexAddress, uint256 duration, bytes32 quantumInputHash, uint256 nonce, uint256 deadline, bytes calldata falconSalt40, uint256[] calldata falconS2_32, LAIPPublicKey calldata laipPk) external payable;
    function createVestingSchedule(address beneficiary, uint256 amount, uint256 startTime, uint256 cliffDuration, uint256 vestingDuration) external;
    function decimals() external view returns (uint8);
    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool);
    function deploymentPhaseActive() external view returns (bool);
    function dilithiumVerifierValidated() external view returns (bool);
    function distributionTransfer(address to, uint256 amount) external;
    function domainSeparator() external view returns (bytes32);
    function endDeploymentPhase() external;
    function executeCEXBypassToggle() external;
    function executeCexGovernanceSigner() external;
    function executeWalletWhitelistToggle() external;
    function finalizeDilithiumVerifierValidation() external;
    function getApprovalNonce(address user) external view returns (uint256);
    function getAttestorPublicKey() external view returns (uint256[32] memory);
    function getCexSession(address user, address cexAddress) external view returns (bool active, uint256 expiry);
    function getNonce(address user) external view returns (uint256);
    function getQuantumKeyHashes(address user) external view returns (bytes32 laipQHash, bytes32 laipP0Hash, bytes32 mldsaPkHash, bool registered);
    function getSessionNonce(address user) external view returns (uint256);
    function guardian() external view returns (address);
    function hasQuantumKeys(address user) external view returns (bool);
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool);
    function isFeeExempt(address account) external view returns (bool);
    function isWhitelistedCEX(address) external view returns (bool);
    function laipKeyCommitment(address) external view returns (bytes32);
    function laipTransferEnabled() external view returns (bool);
    function laipValidatedQHash(address) external view returns (bytes32);
    function lastOracleUpdate() external view returns (uint256);
    function mint(address to, uint256 amount) external;
    function name() external view returns (string memory);
    function oracleGuardianApproval() external view returns (bool);
    function owner() external view returns (address);
    function pause() external;
    function paused() external view returns (bool);
    function pendingCexBypassEta() external view returns (uint256);
    function pendingCexGovernanceSigner() external view returns (address);
    function pendingOracle() external view returns (address);
    function pendingOracleEta() external view returns (uint256);
    function pendingWalletWhitelistActive() external view returns (bool);
    function pqAttestationNonce(address) external view returns (uint256);
    function priceOracle() external view returns (address);
    function proposeCEXBypassToggle(bool enabled) external;
    function proposeOracle(address newOracle) external;
    function proposeWalletWhitelistToggle(bool enabled) external;
    function quantumApprove(address spender, uint256 amount, bytes32 quantumInputHash, uint256 nonce, uint256 deadline, bytes calldata falconSalt40, uint256[] calldata falconS2_32, LAIPPublicKey calldata laipPk) external payable returns (bool);
    function quantumBurn(uint256 amount, bytes32 quantumInputHash, uint256 nonce, uint256 deadline, bytes calldata falconSalt40, uint256[] calldata falconS2_32, LAIPPublicKey calldata laipPk) external payable returns (bool);
    function quantumKeyHashes(address) external view returns (bytes32 laipQHash, bytes32 laipP0Hash, bytes32 mldsaPkHash, bool registered);
    function quantumKeys(address) external view returns (LAIPVerifier_LAIPPublicKey memory laip, bytes memory dilithiumPublicKey, bool bound);
    function quantumNonce(address) external view returns (uint256);
    function quantumTransfer(address to, uint256 amount, bytes32 quantumInputHash, uint256 nonce, uint256 deadline, bytes calldata falconSalt40, uint256[] calldata falconS2_32, LAIPPublicKey calldata laipPk) external payable returns (bool);
    function recoveryTransfer(address from, address to, uint256 amount, bytes32 quantumInputHash, uint256 nonce, uint256 deadline, bytes calldata falconSalt40, uint256[] calldata falconS2_32, LAIPPublicKey calldata laipPk) external payable returns (bool);
    function registerQuantumKeys(bytes32 laipQHash, bytes32 laipP0Hash, bytes32 mldsaPkHash, bytes32 laipCommitment) external;
    function registerQuantumKeysTrusted(bytes32 laipQHash, bytes32 laipP0Hash, bytes32 mldsaPkHash, LAIPPublicKey calldata laipPk) external;
    function registerQuantumKeysWithValidation(bytes32 laipQHash, bytes32 laipP0Hash, bytes32 mldsaPkHash, LAIPPublicKey calldata laipPk) external;
    function removeFromCEXWhitelist(address[] calldata cexAddresses) external;
    function renounceOwnership() external;
    function revokeCexSession(address cexAddress) external;
    function rotateAttestorKey(uint256[32] calldata newNtth) external;
    function sessionTransfer(address to, uint256 amount) external payable returns (bool);
    function setCexGovernanceSigner(address newSigner) external;
    function setFeeExempt(address[] calldata accounts, bool exempt) external;
    function setLaipTransferEnabled(bool enabled) external;
    function setWalletWhitelistPairs(address sender, address[] calldata recipients, bool allowed) external;
    function symbol() external view returns (string memory);
    function totalSupply() external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transferOwnership(address newOwner) external;
    function transferWithFalconAttestation(address, uint256, bytes32, uint256, uint256, bytes calldata, uint256[] calldata) external pure returns (bool);
    function transferWithFalconEnvelope(address to, uint256 amount, FalconEnvelope calldata env, LAIPPublicKey calldata laipPk, bytes calldata falconSig) external payable returns (bool success);
    function unpause() external;
    function updateCEXWhitelist(address[] calldata cexAddresses) external;
    function updateOracle(address newOracle) external;
    function userCexSession(address, address) external view returns (uint256);
    function validateDilithiumVerifierForTesting() external;
    function vestingSchedules(address) external view returns (uint256 totalAmount, uint256 unlocked, uint256 startTime, uint256 cliffDuration, uint256 vestingDuration);
    function walletWhitelistEnabled() external view returns (bool);
    function walletWhitelistFuseActivated() external view returns (bool);
    function walletWhitelistGuardianApproval() external view returns (bool);
    function walletWhitelistPair(address, address) external view returns (bool);
    function withdrawETH() external;
}
