// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {AppStorage, MAX_SUPPLY, CEX_BYPASS_DELAY, ORACLE_UPDATE_DELAY, ORACLE_UPDATE_COOLDOWN, LibAppStorage} from "../libraries/LibAppStorage.sol";
import {LibERC20} from "../libraries/LibERC20.sol";
import {LibLemnicoin} from "../libraries/LibLemnicoin.sol";
import {LibDiamond} from "../libraries/LibDiamond.sol";
import "../../falcon/IZKNOXEthFalcon.sol";

error ExceedsMaxSupply();
error WithdrawFailed();
error InvalidOracle();
error OracleCooldown();
error EmptyCEXList();
error TooManyCEX();
error InvalidSigner();
error NoPendingSigner();
error NoPendingOracle();
error InvalidGuardian();
error InvalidVerifier();
error GuardianApprovalMissing();
error DilithiumVerifierAlreadyValidated();
error DilithiumVerifierUnvalidated();
error DeploymentPhaseEnded();
error DeploymentPhaseActive();
error GovernanceAlreadyInitialized();
error GovernanceZeroVerifier();
error LaipTransferToggled();
error OracleAlreadyDisabled();
error OracleNotDisabled();
error InvalidRekeyOperator();
error InvalidCEXAddress();
error EmptyDEXPoolList();
error TooManyDEXPools();
error InvalidDEXPoolAddress();
error InvalidCircuitBreakerParams();
error EmptyExclusionList();
error TooManyExclusions();

/// @title GovernanceFacet — Governance, minting, pausing, oracle, CEX/DEX whitelist, dilithium
/// @notice All owner/guardian-gated administrative operations.
contract GovernanceFacet is Modifiers {

    // Events
    event OracleUpdated(address indexed newOracle, uint256 timestamp);
    event OracleUpdateProposed(address indexed newOracle, uint256 eta);
    event OracleGuardianApproved(address indexed newOracle);
    event OracleDisabled(address indexed savedOracle, uint256 timestamp);
    event OracleEnabled(address indexed restoredOracle, uint256 timestamp);
    event CEXWhitelistUpdated(address[] cexAddresses, uint256 timestamp);
    event CEXWhitelistRemoved(address[] cexAddresses, uint256 timestamp);
    event CEXBypassToggleProposed(bool enabled, uint256 eta);
    event CEXBypassToggled(bool enabled, uint256 timestamp);
    event CEXBypassGuardianApproved(bool enabled);
    event CEXBypassFuseActivated();
    event CEXGovernanceSignerUpdated(address indexed newSigner);
    event DEXPoolWhitelistUpdated(address[] poolAddresses, uint256 timestamp);
    event DEXPoolWhitelistRemoved(address[] poolAddresses, uint256 timestamp);
    event DilithiumVerifierGuardianApproved();
    event DilithiumVerifierValidationFinalized(uint256 timestamp);
    event LaipTransferEnabled(bool enabled);
    event GovernanceFalconInitialized(address verifier);
    event DeploymentPhaseClosed(uint256 timestamp);
    event AttestorKeyUpdated(uint256[32] newNtth);
    event FalconVerifierUpdated(address indexed newVerifier);
    event RekeyOperatorUpdated(address indexed newOperator);
    event GuardianUpdated(address indexed newGuardian);
    event CircuitBreakerConfigured(uint256 threshold, uint256 window);
    event CircuitBreakerExclusionsUpdated(address[] addresses, bool excluded);

    // =========================================================================
    // FALCON GOVERNANCE INITIALIZATION
    // =========================================================================

    function initializeFalconGovernance(
        address verifier,
        uint256[32] calldata attestorNtth32
    ) external onlyOwner {
        if (s.governanceFalconInitialized) revert GovernanceAlreadyInitialized();
        if (verifier == address(0)) revert GovernanceZeroVerifier();

        s.governanceFalconVerifier = verifier;
        for (uint256 i = 0; i < 32; i++) {
            s.governanceAttestorNtth[i] = attestorNtth32[i];
        }
        s.governanceFalconInitialized = true;
        emit GovernanceFalconInitialized(verifier);
    }

    /// @notice Rotate the GOVERNANCE Falcon key. Owner (Safe) only — never the rekey operator.
    /// @dev The rekey operator is a hot EOA on the attestor host, where the governance key also
    ///      lives. Letting it call this meant one host compromise could replace the governance key
    ///      and permanently lock the Safe out of every Falcon-gated action (unpause, cuts,
    ///      setRekeyOperator). The operator keeps rotateAttestorKeyWithGovernance for daily rekeys.
    function updateGovernanceAttestorKey(
        uint256[32] calldata newNtth,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "UPDATE_GOV_ATTESTOR", abi.encode(newNtth), nonce, deadline, falconSalt40, falconS2
        );
        for (uint256 i = 0; i < 32; i++) {
            s.governanceAttestorNtth[i] = newNtth[i];
        }
    }

    // H-03: REMOVED rotateAttestorKey (owner-only, no governance Falcon)
    // The unprotected version was a security risk: if the owner key is compromised,
    // an attacker could silently rotate the attestor to their own key and sign
    // arbitrary transfers. Use rotateAttestorKeyWithGovernance instead, which
    // requires both owner signature AND Falcon governance attestation.

    /**
     * @notice Rotate the transfer attestor public key with Falcon governance signature
     * @dev Requires owner + Falcon governance signature. Use this for higher security
     *      when governance Falcon is initialized.
     *
     *      SECURITY: This is a critical operation. Requires both:
     *        - Ethereum owner signature (onlyOwner modifier)
     *        - Falcon governance attestation (requireFalconGovernance)
     *
     * @param newNtth The new attestor public key in NTT domain (32 uint256 values)
     * @param nonce Governance nonce for replay protection
     * @param deadline Unix timestamp after which the attestation is invalid
     * @param falconSalt40 40-byte salt from Falcon signature
     * @param falconS2 32 uint256 values - Falcon signature polynomial
     */
    function rotateAttestorKeyWithGovernance(
        uint256[32] calldata newNtth,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwnerOrRekeyOperator {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "ROTATE_ATTESTOR", abi.encode(newNtth), nonce, deadline, falconSalt40, falconS2
        );
        for (uint256 i = 0; i < 32; i++) {
            s.attestorNtth[i] = newNtth[i];
        }
        emit AttestorKeyUpdated(newNtth);
    }

    /**
     * @notice Update the Falcon verifier contract address (F-04)
     * @dev Requires owner + Falcon governance signature. Use this to deploy a fixed
     *      RealEthFalcon verifier without redeploying the entire Diamond.
     *
     *      SECURITY: This is a critical operation. Requires both:
     *        - Ethereum owner signature (onlyOwner modifier)
     *        - Falcon governance attestation (requireFalconGovernance)
     *
     * @param newVerifier The new Falcon verifier contract address
     * @param nonce Governance nonce for replay protection
     * @param deadline Unix timestamp after which the attestation is invalid
     * @param falconSalt40 40-byte salt from Falcon signature
     * @param falconS2 32 uint256 values - Falcon signature polynomial
     */
    function setFalconVerifier(
        address newVerifier,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        if (newVerifier == address(0)) revert InvalidVerifier();
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "SET_FALCON_VERIFIER", abi.encode(newVerifier), nonce, deadline, falconSalt40, falconS2
        );
        s.falconVerifier = newVerifier;
        emit FalconVerifierUpdated(newVerifier);
    }

    // =========================================================================
    // REKEY OPERATOR MANAGEMENT
    // =========================================================================

    /// @notice Set or revoke the dedicated rekey operator address.
    /// @dev Owner-only + Falcon governance. The rekey operator can rotate attestor
    ///      keys (with Falcon governance sig) without being the diamond owner.
    ///      Set to address(0) to revoke. This allows automated key rotation to
    ///      continue after ownership is transferred to a Gnosis Safe multisig.
    function setRekeyOperator(
        address newOperator,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "SET_REKEY_OPERATOR", abi.encode(newOperator), nonce, deadline, falconSalt40, falconS2
        );
        s.rekeyOperator = newOperator;
        emit RekeyOperatorUpdated(newOperator);
    }

    // =========================================================================
    // CIRCUIT BREAKER CONFIGURATION
    // =========================================================================

    /// @notice Configure the automatic transfer volume circuit breaker.
    /// @dev Requires owner + Falcon governance. Set threshold to 0 to disable.
    ///      When enabled, if cumulative transfer volume in a rolling window exceeds
    ///      the threshold, the contract auto-pauses immediately. Use the normal
    ///      unpause() governance flow to resume after investigation.
    /// @param threshold Max transfer volume (in wei) allowed per window. 0 = disabled.
    /// @param window Window duration in seconds (e.g., 3600 = 1 hour).
    function setCircuitBreakerParams(
        uint256 threshold,
        uint256 window,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "SET_CIRCUIT_BREAKER", abi.encode(threshold, window),
            nonce, deadline, falconSalt40, falconS2
        );
        // If enabling (threshold > 0), window must be at least 10 minutes
        if (threshold > 0 && window < 600) revert InvalidCircuitBreakerParams();
        s.circuitBreakerThreshold = threshold;
        s.circuitBreakerWindow = window;
        // Reset the current window to avoid stale data triggering a false positive
        s.circuitBreakerWindowStart = block.timestamp;
        s.circuitBreakerWindowVolume = 0;
        emit CircuitBreakerConfigured(threshold, window);
    }

    /// @notice Add or remove addresses from the circuit breaker exclusion set.
    /// @dev Excluded addresses' transfers are not counted toward volume.
    ///      Typical entries: deployer wallet, Uniswap router, position manager, pool.
    /// @param addresses Addresses to update.
    /// @param excluded True to exclude (skip counting), false to re-include.
    function setCircuitBreakerExclusions(
        address[] calldata addresses,
        bool excluded,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "SET_CB_EXCLUSIONS", abi.encode(addresses, excluded),
            nonce, deadline, falconSalt40, falconS2
        );
        if (addresses.length == 0) revert EmptyExclusionList();
        if (addresses.length > 20) revert TooManyExclusions();
        for (uint256 i = 0; i < addresses.length; i++) {
            s.circuitBreakerExcluded[addresses[i]] = excluded;
        }
        emit CircuitBreakerExclusionsUpdated(addresses, excluded);
    }

    // =========================================================================
    // MINT / PAUSE / UNPAUSE
    // =========================================================================

    function mint(
        address to, uint256 amount,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "MINT", abi.encode(to, amount), nonce, deadline, falconSalt40, falconS2
        );
        if (s.totalSupply + amount > MAX_SUPPLY) revert ExceedsMaxSupply();
        LibERC20._mint(to, amount);
    }

    function pause(
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "PAUSE", bytes(""), nonce, deadline, falconSalt40, falconS2
        );
        s.paused = true;
    }

    function unpause(
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "UNPAUSE", bytes(""), nonce, deadline, falconSalt40, falconS2
        );
        s.paused = false;
    }

    function setLaipTransferEnabled(
        bool enabled,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "SET_LAIP_TRANSFER", abi.encode(enabled), nonce, deadline, falconSalt40, falconS2
        );
        s.laipTransferEnabled = enabled;
        emit LaipTransferEnabled(enabled);
    }

    function withdrawETH(
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "WITHDRAW_ETH", bytes(""), nonce, deadline, falconSalt40, falconS2
        );
        uint256 balance = address(this).balance;
        (bool sent,) = LibDiamond.contractOwner().call{value: balance}("");
        if (!sent) revert WithdrawFailed();
    }

    /// @notice Replace the guardian (the independent second party for oracle and CEX-bypass
    ///         changes). Requires owner + Falcon governance over `"SET_GUARDIAN"`.
    /// @dev There was no way to change the guardian after init, so it could not be separated from
    ///      the rekey operator and CEX governance signer — collapsing the "second party" into one
    ///      hot key. This lets the Safe move it to an independent key (e.g. its own multisig).
    function setGuardian(
        address newGuardian,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "SET_GUARDIAN", abi.encode(newGuardian), nonce, deadline, falconSalt40, falconS2
        );
        if (newGuardian == address(0)) revert InvalidSigner();
        s.guardian = newGuardian;
        emit GuardianUpdated(newGuardian);
    }

    // =========================================================================
    // ORACLE GOVERNANCE
    // =========================================================================

    function proposeOracle(
        address newOracle,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "PROPOSE_ORACLE", abi.encode(newOracle), nonce, deadline, falconSalt40, falconS2
        );
        if (newOracle == address(0)) revert InvalidOracle();
        s.pendingOracle = newOracle;
        s.pendingOracleEta = block.timestamp + ORACLE_UPDATE_DELAY;
        s.oracleGuardianApproval = false;
        emit OracleUpdateProposed(newOracle, s.pendingOracleEta);
    }

    function approveOracle(
        address newOracle,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyGuardian {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "APPROVE_ORACLE", abi.encode(newOracle), nonce, deadline, falconSalt40, falconS2
        );
        if (newOracle != s.pendingOracle) revert InvalidOracle();
        if (s.pendingOracleEta == 0) revert NoPendingOracle();
        s.oracleGuardianApproval = true;
        emit OracleGuardianApproved(newOracle);
    }

    function updateOracle(
        address newOracle,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "UPDATE_ORACLE", abi.encode(newOracle), nonce, deadline, falconSalt40, falconS2
        );
        if (!s.oracleGuardianApproval) revert OracleCooldown();
        if (newOracle != s.pendingOracle) revert InvalidOracle();
        if (s.pendingOracleEta == 0 || block.timestamp < s.pendingOracleEta) revert OracleCooldown();
        if (block.timestamp < s.lastOracleUpdate + ORACLE_UPDATE_COOLDOWN) revert OracleCooldown();

        s.priceOracle = newOracle;
        s.lastOracleUpdate = block.timestamp;
        s.pendingOracle = address(0);
        s.pendingOracleEta = 0;
        s.oracleGuardianApproval = false;
        emit OracleUpdated(newOracle, block.timestamp);
    }

    // =========================================================================
    // ORACLE DISABLE / ENABLE (no timelock — for temporary fee bypass)
    // =========================================================================

    /// @notice Temporarily disable fee collection by zeroing the price oracle.
    ///         The current oracle address is saved so enablePriceOracle() can restore it.
    /// @dev Requires owner + Falcon governance. No timelock or guardian approval needed.
    function disablePriceOracle(
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "DISABLE_ORACLE", bytes(""), nonce, deadline, falconSalt40, falconS2
        );
        if (s.priceOracle == address(0)) revert OracleAlreadyDisabled();
        s.savedPriceOracle = s.priceOracle;
        s.priceOracle = address(0);
        emit OracleDisabled(s.savedPriceOracle, block.timestamp);
    }

    /// @notice Re-enable fee collection by restoring the previously saved oracle address.
    /// @dev Requires owner + Falcon governance. No timelock or guardian approval needed.
    function enablePriceOracle(
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "ENABLE_ORACLE", bytes(""), nonce, deadline, falconSalt40, falconS2
        );
        if (s.savedPriceOracle == address(0)) revert OracleNotDisabled();
        s.priceOracle = s.savedPriceOracle;
        emit OracleEnabled(s.priceOracle, block.timestamp);
        s.savedPriceOracle = address(0);
    }

    // =========================================================================
    // REVOKE QUANTUM APPROVAL
    // =========================================================================

    event QuantumApprovalRevoked(address indexed wallet, address indexed spender, uint256 timestamp);

    /// @notice Revoke a wallet's quantumApprovedSpender flag and zero its allowance
    ///         for a specific spender. The wallet can still call quantumApprove() again.
    /// @dev Requires owner + Falcon governance attestation.
    function revokeQuantumApproval(
        address wallet,
        address spender,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "REVOKE_QUANTUM_APPROVAL", abi.encode(wallet, spender),
            nonce, deadline, falconSalt40, falconS2
        );
        s.quantumApprovedSpender[wallet][spender] = false;
        s.allowances[wallet][spender] = 0;
        emit QuantumApprovalRevoked(wallet, spender, block.timestamp);
    }

    // =========================================================================
    // CEX WHITELIST
    // =========================================================================

    function updateCEXWhitelist(
        address[] calldata cexAddresses,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyCexGovernance {
        if (cexAddresses.length == 0) revert EmptyCEXList();
        if (cexAddresses.length > 100) revert TooManyCEX();
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "UPDATE_CEX_WHITELIST",
            abi.encode(keccak256(abi.encodePacked(cexAddresses))),
            nonce, deadline, falconSalt40, falconS2
        );
        for (uint256 i = 0; i < cexAddresses.length; i++) {
            // M-07 audit fix: Validate no zero addresses in whitelist
            if (cexAddresses[i] == address(0)) revert InvalidCEXAddress();
            s.isWhitelistedCEX[cexAddresses[i]] = true;
        }
        emit CEXWhitelistUpdated(cexAddresses, block.timestamp);
    }

    function removeFromCEXWhitelist(
        address[] calldata cexAddresses,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyCexGovernance {
        if (cexAddresses.length == 0) revert EmptyCEXList();
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "REMOVE_CEX_WHITELIST",
            abi.encode(keccak256(abi.encodePacked(cexAddresses))),
            nonce, deadline, falconSalt40, falconS2
        );
        for (uint256 i = 0; i < cexAddresses.length; i++) {
            // M-07 audit fix: Validate no zero addresses
            if (cexAddresses[i] == address(0)) revert InvalidCEXAddress();
            s.isWhitelistedCEX[cexAddresses[i]] = false;
        }
        emit CEXWhitelistRemoved(cexAddresses, block.timestamp);
    }

    // =========================================================================
    // DEX POOL WHITELIST
    // =========================================================================
    // Same pattern as CEX whitelist: bidirectional, governance-protected.
    // No toggle or session — whitelisted pools can always send/receive LEMNI.
    // All DEX trades still pay QR 12-40 bps fees via quantumApprove path.

    /// @notice Whitelist DEX pool/pair contracts for unrestricted transfer
    /// @dev Requires cexGovernanceSigner + Falcon governance attestation.
    ///      Whitelisted pools can send and receive LEMNI via transfer()/transferFrom().
    function updateDEXPoolWhitelist(
        address[] calldata poolAddresses,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyCexGovernance {
        if (poolAddresses.length == 0) revert EmptyDEXPoolList();
        if (poolAddresses.length > 100) revert TooManyDEXPools();
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "UPDATE_DEX_POOL_WHITELIST",
            abi.encode(keccak256(abi.encodePacked(poolAddresses))),
            nonce, deadline, falconSalt40, falconS2
        );
        for (uint256 i = 0; i < poolAddresses.length; i++) {
            if (poolAddresses[i] == address(0)) revert InvalidDEXPoolAddress();
            s.isWhitelistedDEXPool[poolAddresses[i]] = true;
        }
        emit DEXPoolWhitelistUpdated(poolAddresses, block.timestamp);
    }

    /// @notice Remove DEX pool/pair contracts from whitelist
    function removeFromDEXPoolWhitelist(
        address[] calldata poolAddresses,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyCexGovernance {
        if (poolAddresses.length == 0) revert EmptyDEXPoolList();
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "REMOVE_DEX_POOL_WHITELIST",
            abi.encode(keccak256(abi.encodePacked(poolAddresses))),
            nonce, deadline, falconSalt40, falconS2
        );
        for (uint256 i = 0; i < poolAddresses.length; i++) {
            if (poolAddresses[i] == address(0)) revert InvalidDEXPoolAddress();
            s.isWhitelistedDEXPool[poolAddresses[i]] = false;
        }
        emit DEXPoolWhitelistRemoved(poolAddresses, block.timestamp);
    }

    // =========================================================================
    // CEX BYPASS TOGGLE
    // =========================================================================

    function proposeCEXBypassToggle(
        bool enabled,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyCexGovernance {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "PROPOSE_CEX_BYPASS", abi.encode(enabled), nonce, deadline, falconSalt40, falconS2
        );
        if (s.cexBypassFuseActivated && enabled) revert OracleCooldown();
        s.pendingCexBypassState = enabled;
        s.pendingCexBypassEta = block.timestamp + CEX_BYPASS_DELAY;
        s.cexBypassGuardianApproval = false;
        emit CEXBypassToggleProposed(enabled, s.pendingCexBypassEta);
    }

    function approveCEXBypassToggle(
        bool enabled,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyGuardian {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "APPROVE_CEX_BYPASS", abi.encode(enabled), nonce, deadline, falconSalt40, falconS2
        );
        if (s.pendingCexBypassEta == 0 || s.pendingCexBypassState != enabled) revert OracleCooldown();
        s.cexBypassGuardianApproval = true;
        emit CEXBypassGuardianApproved(enabled);
    }

    function executeCEXBypassToggle(
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyCexGovernance {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "EXECUTE_CEX_BYPASS", abi.encode(s.pendingCexBypassState),
            nonce, deadline, falconSalt40, falconS2
        );
        if (s.pendingCexBypassEta == 0 || block.timestamp < s.pendingCexBypassEta) revert OracleCooldown();
        if (!s.cexBypassGuardianApproval) revert OracleCooldown();
        if (s.cexBypassFuseActivated && s.pendingCexBypassState) revert OracleCooldown();

        s.cexBypassEnabled = s.pendingCexBypassState;
        s.pendingCexBypassEta = 0;
        s.cexBypassGuardianApproval = false;
        emit CEXBypassToggled(s.cexBypassEnabled, block.timestamp);
    }

    function activateCEXBypassFuse(
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyGuardian {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "ACTIVATE_CEX_FUSE", bytes(""), nonce, deadline, falconSalt40, falconS2
        );
        if (s.cexBypassFuseActivated) return;
        s.cexBypassFuseActivated = true;
        s.cexBypassEnabled = false;
        s.pendingCexBypassEta = 0;
        s.cexBypassGuardianApproval = false;
        emit CEXBypassFuseActivated();
    }

    // =========================================================================
    // CEX GOVERNANCE SIGNER
    // =========================================================================

    function setCexGovernanceSigner(
        address newSigner,
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyCexGovernance {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "SET_CEX_GOV_SIGNER", abi.encode(newSigner), nonce, deadline, falconSalt40, falconS2
        );
        if (newSigner == address(0)) revert InvalidSigner();
        s.pendingCexGovernanceSigner = newSigner;
    }

    function executeCexGovernanceSigner(
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyCexGovernance {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "EXECUTE_CEX_GOV_SIGNER", abi.encode(s.pendingCexGovernanceSigner),
            nonce, deadline, falconSalt40, falconS2
        );
        if (s.pendingCexGovernanceSigner == address(0)) revert NoPendingSigner();
        s.cexGovernanceSigner = s.pendingCexGovernanceSigner;
        s.pendingCexGovernanceSigner = address(0);
        emit CEXGovernanceSignerUpdated(s.cexGovernanceSigner);
    }

    // =========================================================================
    // DILITHIUM VERIFIER VALIDATION
    // =========================================================================

    function approveDilithiumVerifierValidation(
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyGuardian {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "APPROVE_DILITHIUM_VALIDATION", bytes(""), nonce, deadline, falconSalt40, falconS2
        );
        if (s.dilithiumVerifierValidated) revert DilithiumVerifierAlreadyValidated();
        s.dilithiumValidationGuardianApproval = true;
        emit DilithiumVerifierGuardianApproved();
    }

    function finalizeDilithiumVerifierValidation(
        uint256 nonce, uint256 deadline,
        bytes calldata falconSalt40, uint256[] calldata falconS2
    ) external onlyOwner {
        LibLemnicoin.requireFalconGovernance(
            msg.sender, "FINALIZE_DILITHIUM_VALIDATION", bytes(""), nonce, deadline, falconSalt40, falconS2
        );
        if (s.dilithiumVerifierValidated) revert DilithiumVerifierAlreadyValidated();
        if (!s.dilithiumValidationGuardianApproval) revert GuardianApprovalMissing();
        s.dilithiumVerifierValidated = true;
        s.dilithiumValidationGuardianApproval = false;
        emit DilithiumVerifierValidationFinalized(block.timestamp);
    }

    function approveDilithiumVerifierValidationDuringDeployment() external onlyGuardian {
        if (!s.deploymentPhaseActive) revert DeploymentPhaseEnded();
        if (s.dilithiumVerifierValidated) revert DilithiumVerifierAlreadyValidated();
        s.dilithiumValidationGuardianApproval = true;
        emit DilithiumVerifierGuardianApproved();
    }

    function finalizeDilithiumVerifierValidationDuringDeployment() external onlyOwner {
        if (!s.deploymentPhaseActive) revert DeploymentPhaseEnded();
        if (s.dilithiumVerifierValidated) revert DilithiumVerifierAlreadyValidated();
        if (!s.dilithiumValidationGuardianApproval) revert GuardianApprovalMissing();
        s.dilithiumVerifierValidated = true;
        s.dilithiumValidationGuardianApproval = false;
        emit DilithiumVerifierValidationFinalized(block.timestamp);
    }

    // M-05 audit fix: Removed validateDilithiumVerifierForTesting
    // Use finalizeDilithiumVerifierValidationDuringDeployment with proper guardian approval

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function guardian() external view returns (address) { return s.guardian; }
    function cexGovernanceSigner() external view returns (address) { return s.cexGovernanceSigner; }
    function dilithiumVerifierValidated() external view returns (bool) { return s.dilithiumVerifierValidated; }
    function cexBypassEnabled() external view returns (bool) { return s.cexBypassEnabled; }
    function cexBypassFuseActivated() external view returns (bool) { return s.cexBypassFuseActivated; }
    function isWhitelistedCEX(address addr) external view returns (bool) { return s.isWhitelistedCEX[addr]; }
    function isWhitelistedDEXPool(address addr) external view returns (bool) { return s.isWhitelistedDEXPool[addr]; }
    function deploymentPhaseActive() external view returns (bool) { return s.deploymentPhaseActive; }
    function laipTransferEnabled() external view returns (bool) { return s.laipTransferEnabled; }
    function savedPriceOracle() external view returns (address) { return s.savedPriceOracle; }
    function pendingOracle() external view returns (address) { return s.pendingOracle; }
    function pendingOracleEta() external view returns (uint256) { return s.pendingOracleEta; }
    function governanceFalconInitialized() external view returns (bool) { return s.governanceFalconInitialized; }
    function governanceNonce(address signer) external view returns (uint256) { return s.governanceNonce[signer]; }
    function governanceAttestorNtth(uint256 index) external view returns (uint256) { return s.governanceAttestorNtth[index]; }
    function paused() external view returns (bool) { return s.paused; }
    function rekeyOperator() external view returns (address) { return s.rekeyOperator; }
    function circuitBreakerThreshold() external view returns (uint256) { return s.circuitBreakerThreshold; }
    function circuitBreakerWindow() external view returns (uint256) { return s.circuitBreakerWindow; }
    function circuitBreakerWindowVolume() external view returns (uint256) { return s.circuitBreakerWindowVolume; }
    function circuitBreakerWindowStart() external view returns (uint256) { return s.circuitBreakerWindowStart; }
    function circuitBreakerExcluded(address addr) external view returns (bool) { return s.circuitBreakerExcluded[addr]; }
}
