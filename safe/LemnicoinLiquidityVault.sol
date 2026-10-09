// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LemnicoinLiquidityVault
/// @notice Time-locked custody for the LEMNI/USDC Uniswap V3 liquidity.
///
///         The vault owns the position NFTs *and* the working token balance.
///         Until `unlockTime`, there is no code path that returns principal to
///         any address:
///
///           • rebalance()    — operator repositions liquidity. Every mint and
///                              collect recipient is address(this). No address
///                              argument exists.
///           • collectFees()  — forwards ONLY the amount collect() returned in
///                              that same call, to an immutable feeRecipient,
///                              bounded by a per-window cap.
///           • withdrawAll()  — reverts before unlockTime. Sends to `owner`,
///                              which is immutable. No address argument.
///           • extendUnlock() — can only move unlockTime later, never earlier.
///
///         There is no proxy, no admin, no token rescue, and no swap function.
///         Every parameter is immutable except `unlockTime` (extend-only) and
///         the position set.
///
/// @dev WHY rebalance() IS ATOMIC — this is the security core, not a style
///      choice. Uniswap V3 settles fees and freed principal through the SAME
///      accumulator: decreaseLiquidity() credits principal into the position's
///      tokensOwed0/tokensOwed1 slots, which is exactly what collect() pays
///      out. A vault that exposed decreaseLiquidity() and a fee-forwarding
///      collect() as separate transactions would let principal walk out
///      through the fee door.
///
///      By performing decrease → collect → mint inside one transaction and
///      never exposing decreaseLiquidity() on its own, principal never
///      persists in tokensOwed between transactions. Anything collectFees()
///      observes is therefore accrued fees, structurally rather than by
///      convention.

// ─────────────────────────────────────────────────────────────────────────────
// Minimal external interfaces — declared inline to avoid a dependency on
// @uniswap/v3-periphery, matching the house style of LemnicoinLiquidityModule.
// ─────────────────────────────────────────────────────────────────────────────

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @dev ZKNOX ETHFALCON on-chain Falcon-512 verifier — the same stateless
///      verifier contract the diamond's governance gate uses
///      (LibLemnicoin.requireFalconGovernance). ~1.8M gas per verification.
interface IZKNOXEthFalcon {
    function verify(
        bytes memory h,
        bytes memory salt,
        uint256[] memory s2,
        uint256[] memory ntth
    ) external view returns (bool result);
}

interface INonfungiblePositionManager {
    struct MintParams {
        address token0;
        address token1;
        uint24 fee;
        int24 tickLower;
        int24 tickUpper;
        uint256 amount0Desired;
        uint256 amount1Desired;
        uint256 amount0Min;
        uint256 amount1Min;
        address recipient;
        uint256 deadline;
    }

    struct DecreaseLiquidityParams {
        uint256 tokenId;
        uint128 liquidity;
        uint256 amount0Min;
        uint256 amount1Min;
        uint256 deadline;
    }

    struct CollectParams {
        uint256 tokenId;
        address recipient;
        uint128 amount0Max;
        uint128 amount1Max;
    }

    function mint(MintParams calldata params)
        external
        payable
        returns (uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1);

    function decreaseLiquidity(DecreaseLiquidityParams calldata params)
        external
        payable
        returns (uint256 amount0, uint256 amount1);

    function collect(CollectParams calldata params)
        external
        payable
        returns (uint256 amount0, uint256 amount1);

    function burn(uint256 tokenId) external payable;

    function positions(uint256 tokenId)
        external
        view
        returns (
            uint96 nonce,
            address operator,
            address token0,
            address token1,
            uint24 fee,
            int24 tickLower,
            int24 tickUpper,
            uint128 liquidity,
            uint256 feeGrowthInside0LastX128,
            uint256 feeGrowthInside1LastX128,
            uint128 tokensOwed0,
            uint128 tokensOwed1
        );

    function transferFrom(address from, address to, uint256 tokenId) external;

    function ownerOf(uint256 tokenId) external view returns (address);
}

interface IUniswapV3Pool {
    function slot0()
        external
        view
        returns (
            uint160 sqrtPriceX96,
            int24 tick,
            uint16 observationIndex,
            uint16 observationCardinality,
            uint16 observationCardinalityNext,
            bool unlocked
        );

    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s);
}

// ─────────────────────────────────────────────────────────────────────────────
// Vault
// ─────────────────────────────────────────────────────────────────────────────

contract LemnicoinLiquidityVault {
    // ── Band specification ──────────────────────────────────────────────────

    /// @notice One liquidity band. Amounts are expressed in basis points of the
    ///         vault's balance at mint time rather than absolute amounts, so
    ///         band structure and the per-band token split are call arguments —
    ///         retunable at runtime without redeploying anything.
    struct BandParams {
        int24 tickLower;
        int24 tickUpper;
        uint16 bps0; // basis points of the vault's LEMNI balance
        uint16 bps1; // basis points of the vault's USDC balance
    }

    /// @notice One Falcon-512 governance signature over an EIP-712 action
    ///         digest (see _requireFalcon).
    struct FalconSig {
        uint256 nonce;
        uint256 deadline;
        bytes salt40;      // 40-byte Falcon salt
        uint256[] s2;      // signature polynomial, 32 words
    }

    // ── Immutables ──────────────────────────────────────────────────────────

    INonfungiblePositionManager public immutable positionManager;
    IUniswapV3Pool public immutable pool;
    address public immutable token0; // LEMNI (lower address)
    address public immutable token1; // USDC  (higher address)
    uint24 public immutable poolFee;

    /// @notice Receives forwarded fees. Immutable for the same reason.
    address public immutable feeRecipient;

    /// @notice Receives principal after unlockTime. Immutable — withdrawAll()
    ///         takes no address argument, so principal has exactly one possible
    ///         destination and it is fixed at deployment.
    address public immutable owner;

    // ── Guardrails (immutable) ──────────────────────────────────────────────

    /// @notice Minimum width of any minted band, in ticks. This is the primary
    ///         defence against value extraction disguised as a rebalance: the
    ///         attack requires a razor-thin range the attacker can sweep in one
    ///         trade. A wide band far from spot is not an extraction vector,
    ///         because crossing it costs the attacker the full range.
    int24 public immutable minBandWidth;

    /// @notice Maximum |spot − TWAP| permitted at rebalance time, in ticks.
    ///         This constrains *when* a rebalance may happen, not *where* bands
    ///         sit — so the operator keeps full placement freedom while
    ///         rebalancing into a manipulated price is blocked.
    int24 public immutable maxTwapDeviation;

    /// @notice TWAP observation window, in seconds.
    uint32 public immutable twapInterval;

    /// @notice Per-window ceiling on forwarded fees, and the window length.
    ///         A hard, on-chain cap on how much value can ever leave the vault
    ///         before unlockTime.
    uint256 public immutable maxFee0PerWindow;
    uint256 public immutable maxFee1PerWindow;
    uint256 public immutable feeWindow;

    /// @notice Bounds gas on rebalance() and withdrawAll().
    uint256 public constant MAX_BANDS = 10;

    // ── Post-quantum gate (immutable) ───────────────────────────────────────

    /// @notice ZKNOX ETHFALCON verifier. address(0) deploys the vault WITHOUT
    ///         post-quantum gating (ECDSA-only owner ops) — a deliberate,
    ///         loudly-documented deployment choice, not a runtime toggle.
    IZKNOXEthFalcon public immutable falconVerifier;

    /// @notice Optional escape horizon. 0 = never. If nonzero (must be after
    ///         unlockTime), owner-only ECDSA suffices for the gated operations
    ///         from this timestamp on. This converts "Falcon key lost =
    ///         principal stranded forever" into "delayed until this date",
    ///         and bounds the post-quantum guarantee explicitly: an attacker
    ///         holding only broken-ECDSA keys must wait until this horizon.
    uint256 public immutable ecdsaFallbackTime;

    // ── EIP-712 (mirrors the diamond's governance digest, own domain) ──────

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    /// @dev Identical struct shape to the diamond's GovernanceAction so the
    ///      existing governance signing tooling works here with only a
    ///      different domain (name below, verifyingContract = this vault).
    bytes32 private constant ACTION_TYPEHASH =
        keccak256("GovernanceAction(address signer,bytes32 actionHash,uint256 nonce,uint256 deadline)");
    bytes32 private constant NAME_HASH = keccak256("LemnicoinLiquidityVault");
    bytes32 private constant VERSION_HASH = keccak256("1");

    // ── Mutable state ───────────────────────────────────────────────────────

    /// @notice Engine key. May reposition liquidity; can never move value out.
    /// @dev Deliberately NOT immutable. This key is hot — it is loaded from AWS
    ///      Secrets Manager onto the engine host at boot. Over a 6-12 month
    ///      lock, an unrotatable operator means that losing or burning that key
    ///      freezes the liquidity in whatever bands it last held until
    ///      unlockTime, with no way to reposition.
    ///
    ///      Rotation does not weaken the lock. The operator's entire authority
    ///      is rebalance() — TWAP-gated, width-bounded, recipient always
    ///      address(this) — and collectFees(), which is capped and pays an
    ///      immutable recipient. No operator, present or future, can move
    ///      principal. So who may reposition is safe to change; where value can
    ///      go is not, and remains immutable.
    address public operator;

    /// @notice Falcon-512 governance public key in NTT form (32 words), the
    ///         post-quantum leg of the dual gate. Rotatable only by a call the
    ///         CURRENT key has signed (same ceremony as the diamond's
    ///         updateGovernanceAttestorKey).
    uint256[32] private falconNtth;

    /// @notice Replay protection for Falcon-gated operations.
    uint256 public falconNonce;

    /// @notice Principal is locked until this timestamp. Extend-only.
    uint256 public unlockTime;

    /// @notice Position NFTs currently held by the vault.
    uint256[] public tokenIds;

    /// @notice Guards against a tokenId being registered twice.
    mapping(uint256 => bool) public registered;

    // Rolling fee-forwarding window.
    uint256 public feeWindowStart;
    uint256 public feeWindowSpent0;
    uint256 public feeWindowSpent1;

    // ── Events ──────────────────────────────────────────────────────────────

    event Rebalanced(uint256 bandCount, uint256 balance0, uint256 balance1);
    event BandMinted(uint256 indexed tokenId, int24 tickLower, int24 tickUpper, uint256 amount0, uint256 amount1);
    event PositionClosed(uint256 indexed tokenId, uint256 amount0, uint256 amount1);
    event PositionReceived(uint256 indexed tokenId);
    event FeesForwarded(uint256 amount0, uint256 amount1);
    event FeesRetained(uint256 retained0, uint256 retained1);
    event UnlockExtended(uint256 oldUnlockTime, uint256 newUnlockTime);
    event OperatorChanged(address oldOperator, address newOperator);
    event FalconVerified(bytes32 indexed actionHash, uint256 nonce);
    event FalconKeyRotated(uint256 nonce);
    event WithdrawnAll(uint256 positionCount, uint256 amount0, uint256 amount1);

    // ── Errors ──────────────────────────────────────────────────────────────

    error OnlyOperator();
    error OnlyOwner();
    error StillLocked(uint256 unlocksAt);
    error UnlockNotLater();
    error UnlockInPast();
    error TooManyBands();
    error NoBands();
    error BandTooNarrow(int24 width);
    error TicksOutOfOrder();
    error BpsExceedsTotal();
    error PriceDeviatesFromTwap(int24 deviation);
    error WrongPosition(uint256 tokenId);
    error AlreadyRegistered(uint256 tokenId);
    error NotPositionManager();
    error FalconNotEnabled();
    error FalconSigExpired();
    error FalconBadNonce(uint256 expected, uint256 got);
    error FalconBadSaltLength(uint256 length);
    error FalconBadS2Length(uint256 length);
    error FalconVerificationFailed();
    error FallbackBeforeUnlock();
    error FalconKeyEmpty();
    error ZeroAddress();
    error TransferFailed();

    // ── Modifiers ───────────────────────────────────────────────────────────

    modifier onlyOperator() {
        if (msg.sender != operator) revert OnlyOperator();
        _;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    // ── Constructor ─────────────────────────────────────────────────────────

    struct VaultConfig {
        address positionManager;
        address pool;
        address token0;
        address token1;
        uint24 poolFee;
        address operator;
        address owner;
        address feeRecipient;
        uint256 unlockTime;
        int24 minBandWidth;
        int24 maxTwapDeviation;
        uint32 twapInterval;
        uint256 maxFee0PerWindow;
        uint256 maxFee1PerWindow;
        uint256 feeWindow;
        address falconVerifier;   // address(0) = deploy without the PQ gate
        uint256 ecdsaFallbackTime; // 0 = never; else must be after unlockTime
        uint256[32] falconNtth;   // Falcon-512 governance key, NTT form
    }

    constructor(VaultConfig memory cfg) {
        if (
            cfg.positionManager == address(0) ||
            cfg.pool == address(0) ||
            cfg.token0 == address(0) ||
            cfg.token1 == address(0) ||
            cfg.operator == address(0) ||
            cfg.owner == address(0) ||
            cfg.feeRecipient == address(0)
        ) revert ZeroAddress();
        if (cfg.unlockTime <= block.timestamp) revert UnlockInPast();

        positionManager = INonfungiblePositionManager(cfg.positionManager);
        pool = IUniswapV3Pool(cfg.pool);
        token0 = cfg.token0;
        token1 = cfg.token1;
        poolFee = cfg.poolFee;
        operator = cfg.operator;
        owner = cfg.owner;
        feeRecipient = cfg.feeRecipient;

        unlockTime = cfg.unlockTime;
        minBandWidth = cfg.minBandWidth;
        maxTwapDeviation = cfg.maxTwapDeviation;
        twapInterval = cfg.twapInterval;
        maxFee0PerWindow = cfg.maxFee0PerWindow;
        maxFee1PerWindow = cfg.maxFee1PerWindow;
        feeWindow = cfg.feeWindow;

        feeWindowStart = block.timestamp;

        falconVerifier = IZKNOXEthFalcon(cfg.falconVerifier);
        ecdsaFallbackTime = cfg.ecdsaFallbackTime;
        if (cfg.falconVerifier != address(0)) {
            if (cfg.ecdsaFallbackTime != 0 && cfg.ecdsaFallbackTime <= cfg.unlockTime) {
                revert FallbackBeforeUnlock();
            }
            bool nonZero;
            for (uint256 i = 0; i < 32; i++) {
                falconNtth[i] = cfg.falconNtth[i];
                if (cfg.falconNtth[i] != 0) nonZero = true;
            }
            if (!nonZero) revert FalconKeyEmpty();
        }
    }

    // ── Post-quantum gate ───────────────────────────────────────────────────

    /// @notice True while the Falcon leg of the dual gate is being enforced.
    function falconActive() public view returns (bool) {
        return address(falconVerifier) != address(0) &&
            (ecdsaFallbackTime == 0 || block.timestamp < ecdsaFallbackTime);
    }

    /// @dev The post-quantum leg of the dual gate, mirroring the diamond's
    ///      LibLemnicoin.requireFalconGovernance: an EIP-712 digest over
    ///      (signer, keccak(action‖payload), nonce, deadline) in this vault's
    ///      own domain, verified as a Falcon-512 signature by the same ZKNOX
    ///      verifier the diamond uses. Binds chainId and this contract's
    ///      address, so a signature authorizes one exact action, once, here.
    ///
    ///      Callers hold onlyOwner as the ECDSA leg; this adds the PQ leg, so
    ///      breaking the Safe's ECDSA keys alone — including by a future
    ///      quantum adversary — authorizes nothing on the gated paths.
    function _requireFalcon(
        string memory action,
        bytes memory payload,
        FalconSig calldata sig
    ) internal {
        if (!falconActive()) return;

        if (block.timestamp > sig.deadline) revert FalconSigExpired();
        if (sig.nonce != falconNonce) revert FalconBadNonce(falconNonce, sig.nonce);
        if (sig.salt40.length != 40) revert FalconBadSaltLength(sig.salt40.length);
        if (sig.s2.length != 32) revert FalconBadS2Length(sig.s2.length);

        bytes32 actionHash = keccak256(abi.encodePacked(action, payload));
        bytes32 structHash = keccak256(
            abi.encode(ACTION_TYPEHASH, msg.sender, actionHash, sig.nonce, sig.deadline)
        );
        bytes32 domainSeparator = keccak256(
            abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this))
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        uint256[] memory s2 = new uint256[](32);
        uint256[] memory ntth = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            s2[i] = sig.s2[i];
            ntth[i] = falconNtth[i];
        }

        if (!falconVerifier.verify(abi.encodePacked(digest), sig.salt40, s2, ntth)) {
            revert FalconVerificationFailed();
        }

        falconNonce = sig.nonce + 1;
        emit FalconVerified(actionHash, sig.nonce);
    }

    /// @notice Rotate the Falcon governance key. Dual-gated: the Safe signs
    ///         the transaction AND the CURRENT Falcon key signs the new key —
    ///         the same ceremony as the diamond's updateGovernanceAttestorKey,
    ///         so a compromised ECDSA owner cannot swap in an attacker's key.
    function rotateFalconKey(uint256[32] calldata newNtth, FalconSig calldata sig)
        external
        onlyOwner
    {
        if (address(falconVerifier) == address(0)) revert FalconNotEnabled();
        bool nonZero;
        for (uint256 i = 0; i < 32; i++) {
            if (newNtth[i] != 0) { nonZero = true; break; }
        }
        if (!nonZero) revert FalconKeyEmpty();

        _requireFalcon("ROTATE_FALCON_KEY", abi.encode(newNtth), sig);

        for (uint256 i = 0; i < 32; i++) {
            falconNtth[i] = newNtth[i];
        }
        emit FalconKeyRotated(falconNonce);
    }

    /// @notice The current Falcon governance key (NTT form).
    function falconKey() external view returns (uint256[32] memory) {
        return falconNtth;
    }

    // ── Rebalance ───────────────────────────────────────────────────────────

    /// @notice Close every position and re-mint the given bands, atomically.
    /// @dev Atomicity is what keeps principal out of the fee path — see the
    ///      contract-level note. Freed principal enters tokensOwed and is
    ///      collected back to this contract within the same transaction, so it
    ///      is never observable by collectFees().
    ///
    ///      The operator chooses where bands sit. It cannot choose where value
    ///      goes: every recipient below is address(this), and no address
    ///      argument is accepted.
    function rebalance(BandParams[] calldata bands) external onlyOperator {
        if (bands.length == 0) revert NoBands();
        if (bands.length > MAX_BANDS) revert TooManyBands();

        _requirePriceNearTwap();
        _validateBands(bands);

        _closeAllPositions();

        uint256 balance0 = IERC20(token0).balanceOf(address(this));
        uint256 balance1 = IERC20(token1).balanceOf(address(this));

        for (uint256 i = 0; i < bands.length; i++) {
            uint256 amount0 = (balance0 * bands[i].bps0) / 10_000;
            uint256 amount1 = (balance1 * bands[i].bps1) / 10_000;
            if (amount0 == 0 && amount1 == 0) continue;
            _mintBand(bands[i], amount0, amount1);
        }

        emit Rebalanced(bands.length, balance0, balance1);
    }

    /// @dev Unwind every held position back into this contract's balance.
    function _closeAllPositions() internal {
        uint256 count = tokenIds.length;
        for (uint256 i = 0; i < count; i++) {
            uint256 tokenId = tokenIds[i];
            (, , , , , , , uint128 liquidity, , , , ) = positionManager.positions(tokenId);

            if (liquidity > 0) {
                positionManager.decreaseLiquidity(
                    INonfungiblePositionManager.DecreaseLiquidityParams({
                        tokenId: tokenId,
                        liquidity: liquidity,
                        amount0Min: 0,
                        amount1Min: 0,
                        deadline: block.timestamp
                    })
                );
            }

            // Sweeps freed principal AND accrued fees back to this contract.
            // Recipient is address(this) — always, and not parameterised.
            (uint256 amount0, uint256 amount1) = positionManager.collect(
                INonfungiblePositionManager.CollectParams({
                    tokenId: tokenId,
                    recipient: address(this),
                    amount0Max: type(uint128).max,
                    amount1Max: type(uint128).max
                })
            );

            positionManager.burn(tokenId);
            registered[tokenId] = false;
            emit PositionClosed(tokenId, amount0, amount1);
        }
        delete tokenIds;
    }

    /// @dev Mint one band with the vault as recipient.
    function _mintBand(BandParams calldata band, uint256 amount0, uint256 amount1) internal {
        _approve(token0, amount0);
        _approve(token1, amount1);

        (uint256 tokenId, , uint256 used0, uint256 used1) = positionManager.mint(
            INonfungiblePositionManager.MintParams({
                token0: token0,
                token1: token1,
                fee: poolFee,
                tickLower: band.tickLower,
                tickUpper: band.tickUpper,
                amount0Desired: amount0,
                amount1Desired: amount1,
                amount0Min: 0,
                amount1Min: 0,
                recipient: address(this),
                deadline: block.timestamp
            })
        );

        // Drop any residual allowance so the position manager never holds a
        // standing approval against the vault between calls.
        _approve(token0, 0);
        _approve(token1, 0);

        tokenIds.push(tokenId);
        registered[tokenId] = true;
        emit BandMinted(tokenId, band.tickLower, band.tickUpper, used0, used1);
    }

    // ── Fees ────────────────────────────────────────────────────────────────

    /// @notice Collect accrued fees and forward them to the immutable
    ///         feeRecipient, bounded by the per-window cap.
    /// @dev Forwards ONLY what collect() returned in this call — never the
    ///      vault's balance, which holds principal residue between rebalances.
    ///      Anything above the window cap stays in the vault and remains
    ///      locked, matching the conservative behaviour of the engine's
    ///      existing capCycleFees().
    function collectFees() external {
        if (msg.sender != operator && msg.sender != owner) revert OnlyOperator();
        uint256 collected0;
        uint256 collected1;

        uint256 count = tokenIds.length;
        for (uint256 i = 0; i < count; i++) {
            (uint256 amount0, uint256 amount1) = positionManager.collect(
                INonfungiblePositionManager.CollectParams({
                    tokenId: tokenIds[i],
                    recipient: address(this),
                    amount0Max: type(uint128).max,
                    amount1Max: type(uint128).max
                })
            );
            collected0 += amount0;
            collected1 += amount1;
        }

        // Roll the window forward if it has elapsed.
        if (block.timestamp >= feeWindowStart + feeWindow) {
            feeWindowStart = block.timestamp;
            feeWindowSpent0 = 0;
            feeWindowSpent1 = 0;
        }

        uint256 send0 = _capped(collected0, feeWindowSpent0, maxFee0PerWindow);
        uint256 send1 = _capped(collected1, feeWindowSpent1, maxFee1PerWindow);

        feeWindowSpent0 += send0;
        feeWindowSpent1 += send1;

        if (send0 > 0) _transfer(token0, send0);
        if (send1 > 0) _transfer(token1, send1);

        emit FeesForwarded(send0, send1);

        uint256 retained0 = collected0 - send0;
        uint256 retained1 = collected1 - send1;
        if (retained0 > 0 || retained1 > 0) emit FeesRetained(retained0, retained1);
    }

    function _capped(uint256 amount, uint256 spent, uint256 cap) internal pure returns (uint256) {
        if (spent >= cap) return 0;
        uint256 remaining = cap - spent;
        return amount > remaining ? remaining : amount;
    }

    // ── Lock management ─────────────────────────────────────────────────────

    /// @notice Move the unlock date later. There is deliberately no way to
    ///         move it earlier — that is the property the whole contract exists
    ///         to provide.
    function extendUnlock(uint256 newUnlockTime, FalconSig calldata sig) external onlyOwner {
        if (newUnlockTime <= unlockTime) revert UnlockNotLater();
        _requireFalcon("EXTEND_UNLOCK", abi.encode(newUnlockTime), sig);
        uint256 old = unlockTime;
        unlockTime = newUnlockTime;
        emit UnlockExtended(old, newUnlockTime);
    }

    /// @notice Rotate the engine key. Does not affect the lock — see the note
    ///         on `operator`. Set to a dead address to halt rebalancing.
    function setOperator(address newOperator, FalconSig calldata sig) external onlyOwner {
        if (newOperator == address(0)) revert ZeroAddress();
        _requireFalcon("SET_OPERATOR", abi.encode(newOperator), sig);
        address old = operator;
        operator = newOperator;
        emit OperatorChanged(old, newOperator);
    }

    /// @notice After unlockTime, return everything to `owner`.
    /// @dev Positions are transferred as NFTs rather than unwound, so the owner
    ///      keeps the choice of when to exit. Takes no address argument: `owner`
    ///      is immutable and is the only possible destination for principal.
    function withdrawAll(FalconSig calldata sig) external onlyOwner {
        if (block.timestamp < unlockTime) revert StillLocked(unlockTime);
        _requireFalcon("WITHDRAW_ALL", "", sig);

        uint256 count = tokenIds.length;
        for (uint256 i = 0; i < count; i++) {
            // transferFrom, not safeTransferFrom: the ERC-721 receive callback
            // would revert if `owner` is a Safe without a fallback handler that
            // implements it, permanently bricking withdrawal.
            registered[tokenIds[i]] = false;
            positionManager.transferFrom(address(this), owner, tokenIds[i]);
        }
        delete tokenIds;

        uint256 amount0 = IERC20(token0).balanceOf(address(this));
        uint256 amount1 = IERC20(token1).balanceOf(address(this));
        if (amount0 > 0) _transferTo(token0, owner, amount0);
        if (amount1 > 0) _transferTo(token1, owner, amount1);

        emit WithdrawnAll(count, amount0, amount1);
    }

    // ── Validation ──────────────────────────────────────────────────────────

    /// @dev Reject rebalances while spot is far from the TWAP — i.e. while the
    ///      price may be under manipulation. Constrains timing, not placement.
    function _requirePriceNearTwap() internal view {
        (, int24 spotTick, , , , ) = pool.slot0();

        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = twapInterval;
        secondsAgos[1] = 0;

        (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);

        int56 delta = tickCumulatives[1] - tickCumulatives[0];
        int24 twapTick = int24(delta / int56(uint56(twapInterval)));
        // Round toward negative infinity, matching Uniswap's OracleLibrary.
        if (delta < 0 && (delta % int56(uint56(twapInterval)) != 0)) twapTick--;

        int24 deviation = spotTick > twapTick ? spotTick - twapTick : twapTick - spotTick;
        if (deviation > maxTwapDeviation) revert PriceDeviatesFromTwap(deviation);
    }

    /// @dev Every band must be wide enough that sweeping it is expensive, and
    ///      the per-token basis points must not exceed the vault's balance.
    function _validateBands(BandParams[] calldata bands) internal view {
        uint256 total0;
        uint256 total1;

        for (uint256 i = 0; i < bands.length; i++) {
            if (bands[i].tickUpper <= bands[i].tickLower) revert TicksOutOfOrder();

            int24 width = bands[i].tickUpper - bands[i].tickLower;
            if (width < minBandWidth) revert BandTooNarrow(width);

            total0 += bands[i].bps0;
            total1 += bands[i].bps1;
        }

        if (total0 > 10_000 || total1 > 10_000) revert BpsExceedsTotal();
    }

    // ── ERC-721 receipt ─────────────────────────────────────────────────────

    /// @notice Accept LEMNI/USDC position NFTs from the owner and register
    ///         them. This is how the initial migration works: the Safe
    ///         transfers its existing positions in and the vault picks them up.
    ///
    /// @dev `from` MUST be the owner, and the position count is capped.
    ///      Without both, anyone could mint dust positions on the same pool and
    ///      safeTransferFrom them here in a loop; `tokenIds` would grow without
    ///      bound until rebalance() AND withdrawAll() both exceeded the block
    ///      gas limit, locking the principal permanently. An unbounded array
    ///      that every value-bearing function must iterate is a brick, not an
    ///      inconvenience.
    ///
    ///      Note that Uniswap's position manager uses plain _mint (not
    ///      _safeMint), so minting a band inside rebalance() does not reach
    ///      this callback — only explicit safeTransferFrom does.
    function onERC721Received(
        address,
        address from,
        uint256 tokenId,
        bytes calldata
    ) external returns (bytes4) {
        if (msg.sender != address(positionManager)) revert NotPositionManager();
        if (from != owner) revert OnlyOwner();

        _register(tokenId);

        return this.onERC721Received.selector;
    }

    /// @notice Register a position the vault already owns but that was
    ///         transferred in with plain transferFrom, which fires no callback.
    ///         Without this an NFT could sit in the vault unreachable by both
    ///         rebalance() and withdrawAll().
    /// @dev Cannot move value: it only indexes a position the vault already
    ///      holds, verified via ownerOf.
    function registerPosition(uint256 tokenId) external onlyOwner {
        if (positionManager.ownerOf(tokenId) != address(this)) revert WrongPosition(tokenId);
        _register(tokenId);
    }

    function _register(uint256 tokenId) internal {
        if (registered[tokenId]) revert AlreadyRegistered(tokenId);
        if (tokenIds.length >= MAX_BANDS) revert TooManyBands();

        (, , address t0, address t1, uint24 fee, , , , , , , ) = positionManager.positions(tokenId);
        if (t0 != token0 || t1 != token1 || fee != poolFee) revert WrongPosition(tokenId);

        tokenIds.push(tokenId);
        registered[tokenId] = true;
        emit PositionReceived(tokenId);
    }

    // ── Views ───────────────────────────────────────────────────────────────

    function positionCount() external view returns (uint256) {
        return tokenIds.length;
    }

    function allPositions() external view returns (uint256[] memory) {
        return tokenIds;
    }

    function isLocked() external view returns (bool) {
        return block.timestamp < unlockTime;
    }

    /// @notice Fees still forwardable in the current window.
    function feeAllowanceRemaining() external view returns (uint256 remaining0, uint256 remaining1) {
        bool windowElapsed = block.timestamp >= feeWindowStart + feeWindow;
        uint256 spent0 = windowElapsed ? 0 : feeWindowSpent0;
        uint256 spent1 = windowElapsed ? 0 : feeWindowSpent1;
        remaining0 = spent0 >= maxFee0PerWindow ? 0 : maxFee0PerWindow - spent0;
        remaining1 = spent1 >= maxFee1PerWindow ? 0 : maxFee1PerWindow - spent1;
    }

    // ── Internal token helpers ──────────────────────────────────────────────

    function _approve(address token, uint256 amount) internal {
        if (!IERC20(token).approve(address(positionManager), amount)) revert TransferFailed();
    }

    function _transfer(address token, uint256 amount) internal {
        _transferTo(token, feeRecipient, amount);
    }

    function _transferTo(address token, address to, uint256 amount) internal {
        if (!IERC20(token).transfer(to, amount)) revert TransferFailed();
    }
}
