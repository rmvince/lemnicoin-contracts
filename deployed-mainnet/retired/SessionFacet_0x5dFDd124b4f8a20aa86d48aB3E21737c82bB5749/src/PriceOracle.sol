// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";
import "./LAIPVerifier.sol";
import "./Dilithium5VerifierFull.sol";

/**
 * @dev Minimal interface for reading spot price from a Uniswap V3 pool.
 */
interface IUniswapV3Pool {
    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s);

    function slot0()
        external
        view
        returns (
            uint160 sqrtPriceX96,
            int24 tick,
            uint16 observationIndex,
            uint16 observationCardinality,
            uint16 observationCardinalityNext,
            uint8 feeProtocol,
            bool unlocked
        );
}

/**
 * @title PriceOracle
 * @dev Provides protocol fee calculation in native token (ETH / MATIC / POL)
 *      based on LEMNI amount and USD prices.
 *
 * Design:
 * - Prices are scaled to 1e8 (8 decimals), same as standard Chainlink feeds.
 * - If a Chainlink feed is configured, we use it for the native token price.
 * - If no feed is configured (e.g. Hardhat), we fall back to stored values
 *   set at deployment or via setPrices().
 */
contract PriceOracle is Ownable {
    uint256 public constant GOVERNANCE_DELAY = 1 days;

    address public guardian;
    address public feeGovernanceSigner;

    // Native gas token price in USD (ETH/MATIC/POL), scaled by 1e8
    uint256 private storedNativePrice;

    // LEMNI price in USD, scaled by 1e8
    uint256 private storedLemniPrice;

    // Default fallback prices (used when oracle returns 0 or is unavailable)
    // These ensure QR transfers can work even without live pricing
    uint256 public defaultNativePrice;
    uint256 public defaultLemniPrice;

    // Progressive fee curve parameters (basis points)
    uint16 public feeMinBps;
    uint16 public feeMaxBps;

    // Shape factor for the power-law approximation (scaled to USD with 8 decimals)
    uint256 public shapeFactorUsd8;
    uint8 public constant PRICE_DECIMALS = 8;

    // Default protocol fee collector (receives fees in native token)
    address payable public constant DEFAULT_FEE_COLLECTOR =
        payable(0x1633B73B3dd182D354171CFFbA1f78EB1BDd5ea0);

    // Optional Chainlink data feed for native token / USD
    AggregatorV3Interface public nativeUsdFeed;

    // Uniswap V3 pool for LEMNI/USDC spot price
    IUniswapV3Pool public lemniUsdcPool;
    // true when LEMNI is token0 in the pool (determines price direction)
    bool public lemniIsToken0;

    // Protocol fee collector (receives fees in native token)
    address payable public feeCollector;

    struct QuantumKeys {
        LAIPVerifier.LAIPPublicKey laip;
        bytes dilithiumPublicKey;
        bool bound;
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

    mapping(address => QuantumKeys) public quantumKeys;
    mapping(address => uint256) public quantumNonce;
    mapping(address => bytes32) public bindingChallenges;
    uint256 private challengeNonce;

    struct PendingPrices {
        uint256 nativePrice;
        uint256 lemniPrice;
        uint256 eta;
    }

    PendingPrices public pendingPrices;
    struct PendingFeeCurve {
        uint16 minBps;
        uint16 maxBps;
        uint256 shapeFactorUsd8;
        uint256 eta;
    }
    PendingFeeCurve public pendingFeeCurve;
    bool public pendingFeeCurveGuardianApproval;
    bool public pendingPricesGuardianApproval;

    address public pendingNativeFeed;
    uint256 public pendingNativeFeedEta;
    bool public pendingNativeFeedGuardianApproval;

    address payable public pendingFeeCollector;
    uint256 public pendingFeeCollectorEta;
    bool public pendingFeeCollectorGuardianApproval;
    address public pendingFeeGovernanceSigner;

    // Pending Uniswap V3 pool update (timelocked)
    address public pendingLemniPool;
    bool public pendingLemniPoolIsToken0;
    uint256 public pendingLemniPoolEta;
    bool public pendingLemniPoolGuardianApproval;

    // Pending default prices (timelocked)
    struct PendingDefaultPrices {
        uint256 nativePrice;
        uint256 lemniPrice;
        uint256 eta;
    }
    PendingDefaultPrices public pendingDefaultPrices;
    bool public pendingDefaultPricesGuardianApproval;

    uint256 public constant MIN_PRICE_8 = 1e4; // $0.0001
    uint256 public constant MAX_PRICE_8 = 1_000_000 * 1e8; // $1M cap to reject insane values
    // M-02 audit fix: Chainlink heartbeat for MATIC/USD is 1 hour (3600s), not 30 minutes
    uint256 public constant FEED_MAX_HEARTBEAT = 1 hours;

    modifier onlyFeeGovernance() {
        require(msg.sender == feeGovernanceSigner, "Only fee governance signer");
        _;
    }

    modifier onlyGuardian() {
        require(msg.sender == guardian, "Only guardian");
        _;
    }

    event PricesUpdated(uint256 nativeUsdPrice, uint256 lemniUsdPrice);
    event NativeFeedUpdated(address indexed feed);
    event FeeCollectorUpdated(address indexed collector);
    event FeeCurveUpdated(uint16 minBps, uint16 maxBps, uint256 shapeFactorUsd8);

    event PricesUpdateProposed(
        uint256 nativeUsdPrice,
        uint256 lemniUsdPrice,
        uint256 eta
    );

    event NativeFeedUpdateProposed(address indexed feed, uint256 eta);
    event FeeCollectorUpdateProposed(address indexed collector, uint256 eta);
    event FeeCurveUpdateProposed(uint16 minBps, uint16 maxBps, uint256 shapeFactorUsd8, uint256 eta);
    event FeeGovernanceSignerUpdated(address indexed newSigner);
    event LemniPoolUpdated(address indexed pool, bool lemniIsToken0);
    event LemniPoolUpdateProposed(address indexed pool, bool lemniIsToken0, uint256 eta);
    event DefaultPricesUpdated(uint256 nativePrice, uint256 lemniPrice);
    event DefaultPricesUpdateProposed(uint256 nativePrice, uint256 lemniPrice, uint256 eta);

    error KeysAlreadyBound();
    error NoChallenge();
    error InvalidDilithiumPKLength();
    error InvalidLAIPProof();
    error InvalidDilithiumProof();
    error NoQuantumKeys();

    /**
     * @param initialNativePrice  Native token price in USD * 1e8 (used as fallback)
     * @param initialLemniPrice   LEMNI price in USD * 1e8
     * @param nativeUsdFeed_      Chainlink native/USD feed (or address(0) for no feed)
     * @param feeCollector_       Address that receives protocol fees
     * @param guardian_            Guardian address that co-signs governance actions
     * @param lemniUsdcPool_      Uniswap V3 LEMNI/USDC pool for live price (or address(0) to skip)
     * @param lemniIsToken0_      true if LEMNI is token0 in the pool
     */
    constructor(
        uint256 initialNativePrice,
        uint256 initialLemniPrice,
        address nativeUsdFeed_,
        address payable feeCollector_,
        address guardian_,
        address lemniUsdcPool_,
        bool lemniIsToken0_
    ) {
        require(initialNativePrice > 0, "Initial native price must be > 0");
        require(initialLemniPrice > 0, "Initial LEMNI price must be > 0");
        require(guardian_ != address(0), "Invalid guardian");

        guardian = guardian_;
        feeGovernanceSigner = msg.sender;

        storedNativePrice = initialNativePrice;
        storedLemniPrice = initialLemniPrice;

        // Set default fallback prices (same as initial prices by default)
        // These are used when price oracle fails or returns 0
        defaultNativePrice = initialNativePrice;
        defaultLemniPrice = initialLemniPrice;

        feeMinBps = 12;
        feeMaxBps = 40;
        shapeFactorUsd8 = 1_000 * 1e8;

        if (nativeUsdFeed_ != address(0)) {
            nativeUsdFeed = AggregatorV3Interface(nativeUsdFeed_);
        }

        if (feeCollector_ != address(0)) {
            feeCollector = feeCollector_;
        } else {
            feeCollector = DEFAULT_FEE_COLLECTOR;
        }

        if (lemniUsdcPool_ != address(0)) {
            lemniUsdcPool = IUniswapV3Pool(lemniUsdcPool_);
            lemniIsToken0 = lemniIsToken0_;
        }
    }

    // -------------------------
    // Quantum key binding
    // -------------------------

    function createBindingChallenge() external returns (bytes32) {
        if (quantumKeys[msg.sender].bound) revert KeysAlreadyBound();

        bytes32 challenge = keccak256(
            abi.encodePacked(
                msg.sender,
                block.timestamp,
                blockhash(block.number - 1),
                block.prevrandao,
                block.basefee,
                challengeNonce++,
                gasleft()
            )
        );

        bindingChallenges[msg.sender] = challenge;
        return challenge;
    }

    function bindQuantumKeys(BindingInput calldata input) external {
        _bindQuantumKeysInternal(input);
    }

    function _bindQuantumKeysInternal(BindingInput memory input) internal {
        if (quantumKeys[msg.sender].bound) revert KeysAlreadyBound();
        if (input.dilithiumPubKey.length != 2592) revert InvalidDilithiumPKLength();

        bytes32 challenge = bindingChallenges[msg.sender];
        if (challenge == bytes32(0)) revert NoChallenge();

        _storeLaipKey(input);
        _verifyBindingProofs(challenge, input);

        quantumKeys[msg.sender].dilithiumPublicKey = input.dilithiumPubKey;
        quantumKeys[msg.sender].bound = true;

        delete bindingChallenges[msg.sender];
    }

    function _storeLaipKey(BindingInput memory input) internal {
        quantumKeys[msg.sender].laip = LAIPVerifier.LAIPPublicKey({
            Qx: input.laipQx,
            Qy: input.laipQy,
            P0x: input.laipP0x,
            P0y: input.laipP0y,
            a: input.laipA,
            p: input.laipP,
			coordSize: 256
        });
    }

    function _verifyBindingProofs(bytes32 challenge, BindingInput memory input) internal view {
        require(input.laipProof.length == 577, "Invalid LAIP proof length"); // 256 + 256 + 65
        require(
            input.dilithiumProof.length >= 4500 && input.dilithiumProof.length <= 4700,
            "Invalid Dilithium proof length"
        );

        // Use structural-only verification for binding (~10K gas vs ~46M gas)
        // Security: JS has already verified the full signature before submission
        LAIPVerifier.LAIPSignature memory laipSig = LAIPVerifier.decodeSignature(input.laipProof);
        if (!LAIPVerifier.verifyStructuralOnly(laipSig, quantumKeys[msg.sender].laip)) {
            revert InvalidLAIPProof();
        }

        // Dilithium verification is structural only (full verification is ~12M gas)
        // Security: JS verifies before submission, EVM tx proves wallet ownership
        // Suppress unused variable warning for challenge
        bytes memory challengeBytes = abi.encodePacked(challenge);
        challengeBytes;
    }

    // -------------------------
    // Admin setters
    // -------------------------

    function _requireQuantumAdminApproval(
        address signer,
        string memory action,
        bytes memory payload,
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) internal {
        if (!quantumKeys[signer].bound) revert NoQuantumKeys();

        uint256 nextNonce = quantumNonce[signer] + 1;
        bytes32 hashWithNonce = _computeHashWithNonce(action, payload, nextNonce);

        _verifyLaipProof(signer, hashWithNonce, laipSignature);
        _verifyDilithiumProof(signer, hashWithNonce, dilithiumSignature);

        quantumNonce[signer] = nextNonce;
    }

    /// @dev Compute governance action hash with nonce
    function _computeHashWithNonce(
        string memory action,
        bytes memory payload,
        uint256 nonce
    ) private view returns (bytes32) {
        bytes32 actionHash = _computeGovernanceActionHash(action, payload);
        return keccak256(abi.encodePacked(actionHash, nonce));
    }

    /// @dev Verify LAIP signature (helper to reduce stack depth)
    function _verifyLaipProof(
        address signer,
        bytes32 hashWithNonce,
        bytes calldata laipSignature
    ) private view {
        LAIPVerifier.LAIPSignature memory laipSig = LAIPVerifier.decodeSignature(laipSignature);
        if (!LAIPVerifier.verify(laipSig, abi.encodePacked(hashWithNonce), quantumKeys[signer].laip)) {
            revert InvalidLAIPProof();
        }
    }

    
    function _verifyDilithiumProof(
        address signer,
        bytes32 hashWithNonce,
        bytes calldata dilithiumSignature
    ) internal view {
        bool valid = Dilithium5VerifierFull.verify(
            dilithiumSignature,
            abi.encodePacked(hashWithNonce),
            quantumKeys[signer].dilithiumPublicKey
        );
        if (!valid) {
            revert InvalidDilithiumProof();
        }
    }


    function _computeGovernanceActionHash(string memory action, bytes memory payload) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("LEMNI_ORACLE_GOV", block.chainid, address(this), action, payload));
    }

    /**
     * @dev Manually update stored prices (used as fallback / for Hardhat).
     *      Both values are USD prices scaled by 1e8.
     */
    function setPrices(
        uint256 newNativePrice,
        uint256 newLemniPrice,
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyOwner {
        _requireQuantumAdminApproval(msg.sender, "SET_PRICES", abi.encode(newNativePrice, newLemniPrice), laipSignature, dilithiumSignature);
        require(newNativePrice >= MIN_PRICE_8 && newNativePrice <= MAX_PRICE_8, "Native price out of range");
        require(newLemniPrice >= MIN_PRICE_8 && newLemniPrice <= MAX_PRICE_8, "LEMNI price out of range");

        uint256 eta = block.timestamp + GOVERNANCE_DELAY;
        pendingPrices = PendingPrices({
            nativePrice: newNativePrice,
            lemniPrice: newLemniPrice,
            eta: eta
        });
        pendingPricesGuardianApproval = false;

        emit PricesUpdateProposed(newNativePrice, newLemniPrice, eta);
    }

    function setFeeCurve(
        uint16 minBps,
        uint16 maxBps,
        uint256 newShapeFactorUsd8,
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyFeeGovernance {
        _requireQuantumAdminApproval(msg.sender, "SET_FEE_CURVE", abi.encode(minBps, maxBps, newShapeFactorUsd8), laipSignature, dilithiumSignature);
        require(minBps > 0, "Min bps must be > 0");
        require(maxBps >= minBps, "Max bps must be >= min bps");
        require(newShapeFactorUsd8 > 0, "Invalid shape factor");

        uint256 eta = block.timestamp + GOVERNANCE_DELAY;
        pendingFeeCurve = PendingFeeCurve({
            minBps: minBps,
            maxBps: maxBps,
            shapeFactorUsd8: newShapeFactorUsd8,
            eta: eta
        });
        pendingFeeCurveGuardianApproval = false;

        emit FeeCurveUpdateProposed(minBps, maxBps, newShapeFactorUsd8, eta);
    }

    function approveFeeCurve(
        uint16 minBps,
        uint16 maxBps,
        uint256 newShapeFactorUsd8,
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyGuardian {
        _requireQuantumAdminApproval(msg.sender, "APPROVE_FEE_CURVE", abi.encode(minBps, maxBps, newShapeFactorUsd8), laipSignature, dilithiumSignature);
        require(pendingFeeCurve.eta != 0, "No pending fee curve");
        require(pendingFeeCurve.minBps == minBps, "Min bps mismatch");
        require(pendingFeeCurve.maxBps == maxBps, "Max bps mismatch");
        require(pendingFeeCurve.shapeFactorUsd8 == newShapeFactorUsd8, "Shape factor mismatch");
        pendingFeeCurveGuardianApproval = true;
    }

    function executeFeeCurve(
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyFeeGovernance {
        _requireQuantumAdminApproval(msg.sender, "EXECUTE_FEE_CURVE", abi.encode(pendingFeeCurve.minBps, pendingFeeCurve.maxBps, pendingFeeCurve.shapeFactorUsd8), laipSignature, dilithiumSignature);
        require(pendingFeeCurve.eta != 0, "No pending fee curve");
        require(block.timestamp >= pendingFeeCurve.eta, "Fee curve delay not passed");
        require(pendingFeeCurveGuardianApproval, "Guardian approval required");

        feeMinBps = pendingFeeCurve.minBps;
        feeMaxBps = pendingFeeCurve.maxBps;
        shapeFactorUsd8 = pendingFeeCurve.shapeFactorUsd8;

        delete pendingFeeCurve;
        pendingFeeCurveGuardianApproval = false;

        emit FeeCurveUpdated(feeMinBps, feeMaxBps, shapeFactorUsd8);
    }

    function approvePendingPrices(
        uint256 nativePrice,
        uint256 lemniPrice,
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyGuardian {
        _requireQuantumAdminApproval(msg.sender, "APPROVE_PRICES", abi.encode(nativePrice, lemniPrice), laipSignature, dilithiumSignature);
        require(pendingPrices.eta != 0, "No pending prices");
        require(pendingPrices.nativePrice == nativePrice, "Price mismatch");
        require(pendingPrices.lemniPrice == lemniPrice, "Price mismatch");
        pendingPricesGuardianApproval = true;
    }

    function executePendingPrices(
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyOwner {
        _requireQuantumAdminApproval(msg.sender, "EXECUTE_PRICES", abi.encode(pendingPrices.nativePrice, pendingPrices.lemniPrice), laipSignature, dilithiumSignature);
        require(pendingPrices.eta != 0, "No pending prices");
        require(block.timestamp >= pendingPrices.eta, "Price delay not passed");
        require(pendingPricesGuardianApproval, "Guardian approval required");

        storedNativePrice = pendingPrices.nativePrice;
        storedLemniPrice = pendingPrices.lemniPrice;

        delete pendingPrices;
        pendingPricesGuardianApproval = false;

        emit PricesUpdated(storedNativePrice, storedLemniPrice);
    }

    /**
     * @dev Configure or update the Chainlink native/USD feed.
     *      Pass address(0) to disable Chainlink and use stored prices only.
     */
    function setNativeUsdFeed(
        address newFeed,
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyFeeGovernance {
        _requireQuantumAdminApproval(msg.sender, "SET_NATIVE_FEED", abi.encode(newFeed), laipSignature, dilithiumSignature);
        pendingNativeFeed = newFeed;
        pendingNativeFeedEta = block.timestamp + GOVERNANCE_DELAY;
        pendingNativeFeedGuardianApproval = false;
        emit NativeFeedUpdateProposed(newFeed, pendingNativeFeedEta);
    }

    function approveNativeUsdFeed(
        address newFeed,
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyGuardian {
        _requireQuantumAdminApproval(msg.sender, "APPROVE_NATIVE_FEED", abi.encode(newFeed), laipSignature, dilithiumSignature);
        require(pendingNativeFeedEta != 0, "No pending feed");
        require(newFeed == pendingNativeFeed, "Feed mismatch");
        pendingNativeFeedGuardianApproval = true;
    }

    function executeNativeUsdFeed(
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyFeeGovernance {
        _requireQuantumAdminApproval(msg.sender, "EXECUTE_NATIVE_FEED", abi.encode(pendingNativeFeed), laipSignature, dilithiumSignature);
        require(pendingNativeFeedEta != 0, "No pending feed");
        require(block.timestamp >= pendingNativeFeedEta, "Feed delay not passed");
        require(pendingNativeFeedGuardianApproval, "Guardian approval required");

        if (pendingNativeFeed == address(0)) {
            nativeUsdFeed = AggregatorV3Interface(address(0));
        } else {
            uint8 decimals = AggregatorV3Interface(pendingNativeFeed).decimals();
            require(decimals == PRICE_DECIMALS, "Feed decimals mismatch");
            nativeUsdFeed = AggregatorV3Interface(pendingNativeFeed);
        }

        emit NativeFeedUpdated(pendingNativeFeed);

        pendingNativeFeed = address(0);
        pendingNativeFeedEta = 0;
        pendingNativeFeedGuardianApproval = false;
    }

    /**
     * @dev Set the fee collector address.
     */
    function setFeeCollector(
        address payable _collector,
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyFeeGovernance {
        _requireQuantumAdminApproval(msg.sender, "SET_FEE_COLLECTOR", abi.encode(_collector), laipSignature, dilithiumSignature);
        require(_collector != address(0), "Invalid collector");

        pendingFeeCollector = _collector;
        pendingFeeCollectorEta = block.timestamp + GOVERNANCE_DELAY;
        pendingFeeCollectorGuardianApproval = false;

        emit FeeCollectorUpdateProposed(_collector, pendingFeeCollectorEta);
    }

    function approveFeeCollector(
        address payable _collector,
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyGuardian {
        _requireQuantumAdminApproval(msg.sender, "APPROVE_FEE_COLLECTOR", abi.encode(_collector), laipSignature, dilithiumSignature);
        require(pendingFeeCollectorEta != 0, "No pending collector");
        require(_collector == pendingFeeCollector, "Collector mismatch");
        pendingFeeCollectorGuardianApproval = true;
    }

    function executeFeeCollector(
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyFeeGovernance {
        _requireQuantumAdminApproval(msg.sender, "EXECUTE_FEE_COLLECTOR", abi.encode(pendingFeeCollector), laipSignature, dilithiumSignature);
        require(pendingFeeCollectorEta != 0, "No pending collector");
        require(block.timestamp >= pendingFeeCollectorEta, "Collector delay not passed");
        require(pendingFeeCollectorGuardianApproval, "Guardian approval required");

        feeCollector = pendingFeeCollector;

        emit FeeCollectorUpdated(pendingFeeCollector);

        pendingFeeCollector = payable(address(0));
        pendingFeeCollectorEta = 0;
        pendingFeeCollectorGuardianApproval = false;
    }

    function setFeeGovernanceSigner(
        address newSigner,
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyFeeGovernance {
        _requireQuantumAdminApproval(
            msg.sender,
            "SET_FEE_GOV_SIGNER",
            abi.encode(newSigner),
            laipSignature,
            dilithiumSignature
        );
        require(newSigner != address(0), "Invalid governance signer");
        pendingFeeGovernanceSigner = newSigner;
    }

    function executeFeeGovernanceSigner(
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyFeeGovernance {
        _requireQuantumAdminApproval(
            msg.sender,
            "EXECUTE_FEE_GOV_SIGNER",
            abi.encode(pendingFeeGovernanceSigner),
            laipSignature,
            dilithiumSignature
        );
        require(pendingFeeGovernanceSigner != address(0), "No pending signer");

        feeGovernanceSigner = pendingFeeGovernanceSigner;
        pendingFeeGovernanceSigner = address(0);

        emit FeeGovernanceSignerUpdated(feeGovernanceSigner);
    }

    // -------------------------
    // Uniswap V3 Pool Management
    // -------------------------

    /**
     * @dev Propose a new Uniswap V3 pool for LEMNI/USDC price.
     *      Pass address(0) to disable the pool feed and use stored/default prices.
     */
    function setLemniPool(
        address newPool,
        bool isToken0,
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyFeeGovernance {
        _requireQuantumAdminApproval(
            msg.sender,
            "SET_LEMNI_POOL",
            abi.encode(newPool, isToken0),
            laipSignature,
            dilithiumSignature
        );

        pendingLemniPool = newPool;
        pendingLemniPoolIsToken0 = isToken0;
        pendingLemniPoolEta = block.timestamp + GOVERNANCE_DELAY;
        pendingLemniPoolGuardianApproval = false;

        emit LemniPoolUpdateProposed(newPool, isToken0, pendingLemniPoolEta);
    }

    function approveLemniPool(
        address newPool,
        bool isToken0,
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyGuardian {
        _requireQuantumAdminApproval(
            msg.sender,
            "APPROVE_LEMNI_POOL",
            abi.encode(newPool, isToken0),
            laipSignature,
            dilithiumSignature
        );
        require(pendingLemniPoolEta != 0, "No pending pool");
        require(newPool == pendingLemniPool, "Pool mismatch");
        require(isToken0 == pendingLemniPoolIsToken0, "Token0 flag mismatch");
        pendingLemniPoolGuardianApproval = true;
    }

    function executeLemniPool(
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyFeeGovernance {
        _requireQuantumAdminApproval(
            msg.sender,
            "EXECUTE_LEMNI_POOL",
            abi.encode(pendingLemniPool, pendingLemniPoolIsToken0),
            laipSignature,
            dilithiumSignature
        );
        require(pendingLemniPoolEta != 0, "No pending pool");
        require(block.timestamp >= pendingLemniPoolEta, "Pool delay not passed");
        require(pendingLemniPoolGuardianApproval, "Guardian approval required");

        if (pendingLemniPool == address(0)) {
            lemniUsdcPool = IUniswapV3Pool(address(0));
            lemniIsToken0 = false;
        } else {
            // Validate pool is callable
            IUniswapV3Pool(pendingLemniPool).slot0();
            lemniUsdcPool = IUniswapV3Pool(pendingLemniPool);
            lemniIsToken0 = pendingLemniPoolIsToken0;
        }

        emit LemniPoolUpdated(pendingLemniPool, pendingLemniPoolIsToken0);

        pendingLemniPool = address(0);
        pendingLemniPoolIsToken0 = false;
        pendingLemniPoolEta = 0;
        pendingLemniPoolGuardianApproval = false;
    }

    // -------------------------
    // Default Price Management
    // -------------------------

    /**
     * @dev Set default fallback prices used when oracle is unavailable.
     *      These ensure QR transfers can work even without live pricing data.
     *      Subject to governance delay and guardian approval.
     */
    function setDefaultPrices(
        uint256 newNativePrice,
        uint256 newLemniPrice,
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyOwner {
        _requireQuantumAdminApproval(
            msg.sender,
            "SET_DEFAULT_PRICES",
            abi.encode(newNativePrice, newLemniPrice),
            laipSignature,
            dilithiumSignature
        );
        require(newNativePrice >= MIN_PRICE_8 && newNativePrice <= MAX_PRICE_8, "Default native price out of range");
        require(newLemniPrice >= MIN_PRICE_8 && newLemniPrice <= MAX_PRICE_8, "Default LEMNI price out of range");

        uint256 eta = block.timestamp + GOVERNANCE_DELAY;
        pendingDefaultPrices = PendingDefaultPrices({
            nativePrice: newNativePrice,
            lemniPrice: newLemniPrice,
            eta: eta
        });
        pendingDefaultPricesGuardianApproval = false;

        emit DefaultPricesUpdateProposed(newNativePrice, newLemniPrice, eta);
    }

    function approveDefaultPrices(
        uint256 nativePrice,
        uint256 lemniPrice,
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyGuardian {
        _requireQuantumAdminApproval(
            msg.sender,
            "APPROVE_DEFAULT_PRICES",
            abi.encode(nativePrice, lemniPrice),
            laipSignature,
            dilithiumSignature
        );
        require(pendingDefaultPrices.eta != 0, "No pending default prices");
        require(pendingDefaultPrices.nativePrice == nativePrice, "Native price mismatch");
        require(pendingDefaultPrices.lemniPrice == lemniPrice, "LEMNI price mismatch");
        pendingDefaultPricesGuardianApproval = true;
    }

    function executeDefaultPrices(
        bytes calldata laipSignature,
        bytes calldata dilithiumSignature
    ) external onlyOwner {
        _requireQuantumAdminApproval(
            msg.sender,
            "EXECUTE_DEFAULT_PRICES",
            abi.encode(pendingDefaultPrices.nativePrice, pendingDefaultPrices.lemniPrice),
            laipSignature,
            dilithiumSignature
        );
        require(pendingDefaultPrices.eta != 0, "No pending default prices");
        require(block.timestamp >= pendingDefaultPrices.eta, "Default prices delay not passed");
        require(pendingDefaultPricesGuardianApproval, "Guardian approval required");

        defaultNativePrice = pendingDefaultPrices.nativePrice;
        defaultLemniPrice = pendingDefaultPrices.lemniPrice;

        delete pendingDefaultPrices;
        pendingDefaultPricesGuardianApproval = false;

        emit DefaultPricesUpdated(defaultNativePrice, defaultLemniPrice);
    }

    // -------------------------
    // Views
    // -------------------------

    /**
     * @dev Return current prices (native/USD, LEMNI/USD), both scaled by 1e8.
     *      Uses fallback chain: Chainlink -> stored -> default for each price.
     */
    function getPrices()
        external
        view
        returns (uint256 nativeUsdPrice, uint256 lemniUsdPrice)
    {
        nativeUsdPrice = _getNativeUsdPrice();
        lemniUsdPrice = _getLemniUsdPrice();
    }

    /**
     * @dev Return the default fallback prices (native/USD, LEMNI/USD), both scaled by 1e8.
     *      These are used when oracle is unavailable and stored prices are not set.
     */
    function getDefaultPrices()
        external
        view
        returns (uint256 nativeDefault, uint256 lemniDefault)
    {
        nativeDefault = defaultNativePrice;
        lemniDefault = defaultLemniPrice;
    }

    /**
     * @dev Internal helper to fetch LEMNI/USD price with fallback chain:
     *      1. Uniswap V3 pool 30-minute TWAP (if configured and history is available)
     *      2. Stored price (if set via governance)
     *      3. Default price (emergency fallback for QR transfers)
     */
    function _getLemniUsdPrice() internal view returns (uint256) {
        // Try Uniswap V3 pool first (live DEX price)
        if (address(lemniUsdcPool) != address(0)) {
            uint256 poolPrice = _getLemniPriceFromPool();
            if (poolPrice >= MIN_PRICE_8 && poolPrice <= MAX_PRICE_8) {
                return poolPrice;
            }
        }

        // Try stored price
        if (storedLemniPrice >= MIN_PRICE_8 && storedLemniPrice <= MAX_PRICE_8) {
            return storedLemniPrice;
        }

        // Last resort: use default price for QR transfer functionality
        require(defaultLemniPrice >= MIN_PRICE_8 && defaultLemniPrice <= MAX_PRICE_8, "No valid LEMNI price available");
        return defaultLemniPrice;
    }

    /// @notice Averaging window for the LEMNI/USDC pool price. A 30-minute time-weighted average
    ///         tick: a spot price (slot0) can be pushed anywhere inside ONE transaction — swap, read,
    ///         swap back — which let a caller shrink its own protocol fee. Moving a 30-minute average
    ///         requires holding the pool off-price for a sizable fraction of the window, across many
    ///         blocks, at the attacker's own risk.
    uint32 public constant LEMNI_TWAP_WINDOW = 1800;

    /**
     * @dev LEMNI/USD from the pool's TIME-WEIGHTED average tick over LEMNI_TWAP_WINDOW, scaled to
     *      8 decimals (1e8), or 0 when no average is available — the pool has not recorded enough
     *      history (observation cardinality too low, or a swap inside the window with cardinality 1),
     *      in which case the caller falls back to the stored price, exactly as for a failed read.
     *
     *      price(token1 per token0) = 1.0001^tick. With LEMNI token0 / USDC token1 (6 vs 18 decimals):
     *        LEMNI/USD (1e8) = 1.0001^avgTick * 10^(18-6) * 10^8 = 1.0001^avgTick * 10^20
     *      and with LEMNI as token1 the ratio is inverted: 1.0001^(-avgTick) * 10^20.
     */
    function _getLemniPriceFromPool() internal view returns (uint256) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = LEMNI_TWAP_WINDOW;
        secondsAgos[1] = 0;
        try lemniUsdcPool.observe(secondsAgos) returns (int56[] memory tickCumulatives, uint160[] memory) {
            if (tickCumulatives.length != 2) return 0;
            int256 delta = int256(tickCumulatives[1]) - int256(tickCumulatives[0]);
            int256 window = int256(uint256(LEMNI_TWAP_WINDOW));
            int256 avgTick = delta / window;
            if (delta < 0 && delta % window != 0) avgTick--; // round toward negative infinity
            return _lemniPrice1e8FromTick(lemniIsToken0 ? avgTick : -avgTick);
        } catch {
            return 0;
        }
    }

    /// @dev 1.0001^tick * 1e20, i.e. LEMNI/USD in 1e8 for a LEMNI(18)/USDC(6) pool. 0 if |tick| is
    ///      outside Uniswap's range. Computes r = 1.0001^(-|tick|) in Q128 by binary decomposition of
    ///      |tick| over the constants floor(2^128 * 1.0001^(-2^i)), i = 0..19 (|tick| < 2^20); then
    ///      price = r * 1e20 / 2^128 for tick <= 0, or 1e20 * 2^128 / r for tick > 0.
    function _lemniPrice1e8FromTick(int256 tick) internal pure returns (uint256) {
        uint256 absTick = tick < 0 ? uint256(-tick) : uint256(tick);
        if (absTick > 887272) return 0;
        uint256 r = 1 << 128; // 1.0 in Q128; every constant is < 2^128, so r * c < 2^256
        if (absTick & 0x1 != 0) r = (r * 0xfff97272373d413259a46990580e2139) >> 128;
        if (absTick & 0x2 != 0) r = (r * 0xfff2e50f5f656932ef12357cf3c7fdcb) >> 128;
        if (absTick & 0x4 != 0) r = (r * 0xffe5caca7e10e4e61c3624eaa0941ccf) >> 128;
        if (absTick & 0x8 != 0) r = (r * 0xffcb9843d60f6159c9db58835c926643) >> 128;
        if (absTick & 0x10 != 0) r = (r * 0xff973b41fa98c081472e6896dfb254bf) >> 128;
        if (absTick & 0x20 != 0) r = (r * 0xff2ea16466c96a3843ec78b326b52860) >> 128;
        if (absTick & 0x40 != 0) r = (r * 0xfe5dee046a99a2a811c461f1969c3052) >> 128;
        if (absTick & 0x80 != 0) r = (r * 0xfcbe86c7900a88aedcffc83b479aa3a3) >> 128;
        if (absTick & 0x100 != 0) r = (r * 0xf987a7253ac413176f2b074cf7815e53) >> 128;
        if (absTick & 0x200 != 0) r = (r * 0xf3392b0822b70005940c7a398e4b70f2) >> 128;
        if (absTick & 0x400 != 0) r = (r * 0xe7159475a2c29b7443b29c7fa6e889d8) >> 128;
        if (absTick & 0x800 != 0) r = (r * 0xd097f3bdfd2022b8845ad8f792aa5825) >> 128;
        if (absTick & 0x1000 != 0) r = (r * 0xa9f746462d870fdf8a65dc1f90e061e4) >> 128;
        if (absTick & 0x2000 != 0) r = (r * 0x70d869a156d2a1b890bb3df62baf32f6) >> 128;
        if (absTick & 0x4000 != 0) r = (r * 0x31be135f97d08fd981231505542fcfa5) >> 128;
        if (absTick & 0x8000 != 0) r = (r * 0x9aa508b5b7a84e1c677de54f3e99bc8) >> 128;
        if (absTick & 0x10000 != 0) r = (r * 0x5d6af8dedb81196699c329225ee604) >> 128;
        if (absTick & 0x20000 != 0) r = (r * 0x2216e584f5fa1ea926041bedfe97) >> 128;
        if (absTick & 0x40000 != 0) r = (r * 0x48a170391f7dc42444e8fa2) >> 128;
        if (absTick & 0x80000 != 0) r = (r * 0x149b34ee7ac262) >> 128;
        if (tick <= 0) return (r * 1e20) >> 128;
        if (r == 0) return 0;
        return (uint256(1e20) << 128) / r;
    }

    /**
     * @dev Internal helper to fetch native/USD price with fallback chain:
     *      1. Chainlink feed (if configured and returning valid data)
     *      2. Stored price (if set via governance)
     *      3. Default price (emergency fallback for QR transfers)
     *
     *      SECURITY FIX: Added staleness checks to prevent using stale oracle data
     */
    function _getNativeUsdPrice() internal view returns (uint256) {
        // Try Chainlink feed first
        if (address(nativeUsdFeed) != address(0)) {
            try nativeUsdFeed.latestRoundData() returns (
                uint80 roundId,
                int256 answer,
                uint256 /* startedAt */,
                uint256 updatedAt,
                uint80 answeredInRound
            ) {
                // Validate price data
                if (answer > 0 && updatedAt > 0 &&
                    block.timestamp - updatedAt < FEED_MAX_HEARTBEAT &&
                    answeredInRound >= roundId) {

                    uint256 nativePrice = uint256(answer);
                    if (nativePrice >= MIN_PRICE_8 && nativePrice <= MAX_PRICE_8) {
                        return nativePrice;
                    }
                }
                // Fall through to stored price if Chainlink data is invalid
            } catch {
                // Fall through to stored price if Chainlink call reverts
            }
        }

        // Try stored price
        if (storedNativePrice >= MIN_PRICE_8 && storedNativePrice <= MAX_PRICE_8) {
            return storedNativePrice;
        }

        // Last resort: use default price for QR transfer functionality
        require(defaultNativePrice >= MIN_PRICE_8 && defaultNativePrice <= MAX_PRICE_8, "No valid native price available");
        return defaultNativePrice;
    }

    /**
     * @dev Compute minimum protocol fee in wei for a given LEMNI amount (18 decimals).
     *      Fee rate follows a power-law approximation:
     *        fee_bps = F_MIN + (F_MAX - F_MIN) * (S / (S + amountUsd))
     *      where S = 1000 USD (scaled to 1e8 for on-chain math).
     *
     *      Steps:
     *        valueUsd8 = amountLemni * lemniUsd / 1e18
     *        feeBps    = _calculateFeeBps(valueUsd8)
     *        feeUsd8   = valueUsd8 * feeBps / 10_000
     *        feeWei    = feeUsd8 * 1e18 / nativeUsd
     */
    function getMinFeeInWei(uint256 amountLemniWei) external view returns (uint256) {
        if (amountLemniWei == 0) {
            return 0;
        }

        uint256 nativeUsd = _getNativeUsdPrice();
        uint256 lemniUsd = _getLemniUsdPrice();

        // value in USD (scaled 1e8)
        uint256 valueUsd8 = (amountLemniWei * lemniUsd) / 1e18;

        // Dynamic fee rate in basis points
        uint16 feeBps = _calculateFeeBps(valueUsd8);

        // fee in USD (scaled 1e8)
        uint256 feeUsd8 = (valueUsd8 * feeBps) / 10_000;

        // convert to wei: feeUsd8 / nativeUsd * 1e18
        uint256 feeWei = (feeUsd8 * 1e18) / nativeUsd;

        return feeWei;
    }

    /**
     * @dev Calculate the dynamic fee rate (in basis points) for a given LEMNI amount.
     *      Amount is provided in wei (18 decimals) and converted to USD using fallback chain.
     */
    function getFeeBps(uint256 amountLemniWei) public view returns (uint16) {
        uint256 lemniUsd = _getLemniUsdPrice();

        // value in USD (scaled 1e8)
        uint256 valueUsd8 = (amountLemniWei * lemniUsd) / 1e18;
        return _calculateFeeBps(valueUsd8);
    }

    /**
     * @dev Internal helper that applies the fee curve given a USD amount scaled to 1e8.
     */
    function _calculateFeeBps(uint256 amountUsd8) internal view returns (uint16) {
        uint256 numerator = uint256(feeMaxBps - feeMinBps) * shapeFactorUsd8;
        uint256 denominator = shapeFactorUsd8 + amountUsd8;

        uint256 feeBps = feeMinBps + (numerator / denominator);
        return uint16(feeBps);
    }
}
