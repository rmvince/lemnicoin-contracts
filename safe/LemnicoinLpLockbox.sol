// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LemnicoinLpLockbox
/// @notice A simple time-locked box for the LEMNI/USDC Uniswap V3 liquidity.
///
///         The lockbox holds the position NFTs and any working token balance.
///         Until `unlockTime` there is NO code path that returns principal to
///         any address. Two things you CAN still do while locked, because
///         neither can remove value:
///
///           • addLiquidity / mintPosition — deposit MORE USDC/LEMNI into the
///             pool (e.g. reinforce the floor when a large buyer arrives).
///             Adding funds can never extract funds, so this stays open.
///           • collectFees — forward accrued fees (only) to an immutable
///             recipient, under a per-window cap.
///
///         After `unlockTime`, `withdrawAll` returns every position NFT and
///         every token to the immutable `owner` (the Safe), gated by a
///         post-quantum Falcon-512 signature in addition to the Safe's ECDSA.
///
///         This is the "leave the bands alone for a year" design: there is NO
///         rebalance, NO decreaseLiquidity, NO swap, NO proxy, NO admin, and NO
///         token rescue. The positions sit exactly where they are placed; you
///         may only add to them or add new ones, and take everything back after
///         the lock.
///
/// @dev WHY THERE IS NO decreaseLiquidity / rebalance. Uniswap V3 settles fees
///      and freed principal through the SAME `tokensOwed` accumulator that
///      `collect` pays out. By never exposing a way to decrease liquidity,
///      nothing but genuine trading fees can ever land in `tokensOwed`, so
///      `collectFees` provably forwards fees and not principal — no cap logic
///      or trust required to make that true. Principal can leave only via
///      `withdrawAll`, only after `unlockTime`, only to `owner`.

// ─────────────────────────────────────────────────────────────────────────────
// Minimal external interfaces (inline, matching the house style; note there is
// deliberately NO decreaseLiquidity or burn in this interface).
// ─────────────────────────────────────────────────────────────────────────────

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @dev ZKNOX ETHFALCON on-chain Falcon-512 verifier — the same stateless
///      verifier the LEMNI diamond's governance gate uses.
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

    struct IncreaseLiquidityParams {
        uint256 tokenId;
        uint256 amount0Desired;
        uint256 amount1Desired;
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

    function increaseLiquidity(IncreaseLiquidityParams calldata params)
        external
        payable
        returns (uint128 liquidity, uint256 amount0, uint256 amount1);

    function collect(CollectParams calldata params)
        external
        payable
        returns (uint256 amount0, uint256 amount1);

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

// ─────────────────────────────────────────────────────────────────────────────
// Lockbox
// ─────────────────────────────────────────────────────────────────────────────

contract LemnicoinLpLockbox {
    /// @notice One Falcon-512 governance signature over an EIP-712 action digest.
    struct FalconSig {
        uint256 nonce;
        uint256 deadline;
        bytes salt40;   // 40-byte Falcon salt
        uint256[] s2;   // signature polynomial, 32 words
    }

    // ── Immutables ────────────────────────────────────────────────────────────

    INonfungiblePositionManager public immutable positionManager;
    address public immutable token0; // LEMNI (lower address)
    address public immutable token1; // USDC  (higher address)
    uint24  public immutable poolFee;

    /// @notice Receives EVERYTHING on withdrawAll. Immutable — withdrawAll takes
    ///         no address argument, so principal has exactly one destination.
    address public immutable owner;

    /// @notice Receives forwarded fees. Immutable.
    address public immutable feeRecipient;

    /// @notice Per-window fee-forwarding ceiling and window length.
    uint256 public immutable maxFee0PerWindow;
    uint256 public immutable maxFee1PerWindow;
    uint256 public immutable feeWindow;

    /// @notice ZKNOX ETHFALCON verifier. address(0) = deploy WITHOUT the PQ gate
    ///         (test only). Otherwise the post-quantum leg of the withdraw gate.
    IZKNOXEthFalcon public immutable falconVerifier;

    /// @notice Optional escape horizon (must be after unlockTime; 0 = never).
    ///         From this time on, owner-only ECDSA suffices for gated ops.
    uint256 public immutable ecdsaFallbackTime;

    uint256 public constant MAX_POSITIONS = 20;

    // EIP-712 (own domain; same GovernanceAction shape as the diamond).
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant ACTION_TYPEHASH =
        keccak256("GovernanceAction(address signer,bytes32 actionHash,uint256 nonce,uint256 deadline)");
    bytes32 private constant NAME_HASH = keccak256("LemnicoinLpLockbox");
    bytes32 private constant VERSION_HASH = keccak256("1");

    // ── Mutable state ─────────────────────────────────────────────────────────

    /// @notice May add liquidity and collect fees. Never moves principal out.
    ///         Rotatable by the owner (no Falcon: the operator cannot extract).
    address public operator;

    /// @notice Falcon-512 governance key (NTT form, 32 words) — the PQ leg.
    uint256[32] private falconNtth;

    /// @notice Replay protection for Falcon-gated ops (withdraw / extend / rotate).
    uint256 public falconNonce;

    /// @notice Principal is locked until this timestamp. Extend-only.
    uint256 public unlockTime;

    /// @notice Position NFTs held by the lockbox.
    uint256[] public tokenIds;
    mapping(uint256 => bool) public registered;

    // Rolling fee window.
    uint256 public feeWindowStart;
    uint256 public feeWindowSpent0;
    uint256 public feeWindowSpent1;

    // ── Events ────────────────────────────────────────────────────────────────

    event PositionReceived(uint256 indexed tokenId);
    event LiquidityAdded(uint256 indexed tokenId, uint256 amount0, uint256 amount1);
    event PositionMinted(uint256 indexed tokenId, int24 tickLower, int24 tickUpper, uint256 amount0, uint256 amount1);
    event FeesForwarded(uint256 amount0, uint256 amount1);
    event FeesRetained(uint256 retained0, uint256 retained1);
    event OperatorChanged(address oldOperator, address newOperator);
    event UnlockExtended(uint256 oldUnlockTime, uint256 newUnlockTime);
    event FalconKeyRotated(uint256 nonce);
    event WithdrawnAll(uint256 positionCount, uint256 amount0, uint256 amount1);

    // ── Errors ────────────────────────────────────────────────────────────────

    error OnlyOwner();
    error OnlyOwnerOrOperator();
    error StillLocked(uint256 unlocksAt);
    error UnlockNotLater();
    error UnlockInPast();
    error TooManyPositions();
    error TicksOutOfOrder();
    error UnknownPosition(uint256 tokenId);
    error WrongPosition(uint256 tokenId);
    error AlreadyRegistered(uint256 tokenId);
    error NotPositionManager();
    error ZeroAddress();
    error TransferFailed();
    error FalconNotEnabled();
    error FalconSigExpired();
    error FalconBadNonce(uint256 expected, uint256 got);
    error FalconBadSaltLength(uint256 length);
    error FalconBadS2Length(uint256 length);
    error FalconVerificationFailed();
    error FallbackBeforeUnlock();
    error FalconKeyEmpty();
    error NothingProvided();

    // ── Modifiers ──────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }
    modifier onlyOwnerOrOperator() {
        if (msg.sender != owner && msg.sender != operator) revert OnlyOwnerOrOperator();
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────────────

    struct LockboxConfig {
        address positionManager;
        address token0;
        address token1;
        uint24  poolFee;
        address owner;
        address feeRecipient;
        address operator;
        uint256 unlockTime;
        uint256 maxFee0PerWindow;
        uint256 maxFee1PerWindow;
        uint256 feeWindow;
        address falconVerifier;   // address(0) = no PQ gate (test only)
        uint256 ecdsaFallbackTime; // 0 = never; else must be after unlockTime
        uint256[32] falconNtth;
    }

    constructor(LockboxConfig memory cfg) {
        if (
            cfg.positionManager == address(0) ||
            cfg.token0 == address(0) ||
            cfg.token1 == address(0) ||
            cfg.owner == address(0) ||
            cfg.feeRecipient == address(0) ||
            cfg.operator == address(0)
        ) revert ZeroAddress();
        if (cfg.unlockTime <= block.timestamp) revert UnlockInPast();

        positionManager = INonfungiblePositionManager(cfg.positionManager);
        token0 = cfg.token0;
        token1 = cfg.token1;
        poolFee = cfg.poolFee;
        owner = cfg.owner;
        feeRecipient = cfg.feeRecipient;
        operator = cfg.operator;
        unlockTime = cfg.unlockTime;
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

    // ── Deposit / add liquidity (safe while locked: adds can't extract) ────────

    /// @notice Add liquidity to a position the lockbox already holds, from the
    ///         lockbox's OWN token balance. Fund it by sending token0/token1 to
    ///         this contract first (e.g. a Safe batch: transfer, then this call).
    /// @dev No recipient argument; liquidity goes into the existing position,
    ///      which stays owned by the lockbox. Cannot move value out.
    function addLiquidity(
        uint256 tokenId,
        uint256 amount0Desired,
        uint256 amount1Desired,
        uint256 amount0Min,
        uint256 amount1Min
    ) external onlyOwnerOrOperator {
        if (!registered[tokenId]) revert UnknownPosition(tokenId);
        if (amount0Desired == 0 && amount1Desired == 0) revert NothingProvided();

        _approve(token0, amount0Desired);
        _approve(token1, amount1Desired);
        (, uint256 a0, uint256 a1) = positionManager.increaseLiquidity(
            INonfungiblePositionManager.IncreaseLiquidityParams({
                tokenId: tokenId,
                amount0Desired: amount0Desired,
                amount1Desired: amount1Desired,
                amount0Min: amount0Min,
                amount1Min: amount1Min,
                deadline: block.timestamp
            })
        );
        _approve(token0, 0);
        _approve(token1, 0);
        emit LiquidityAdded(tokenId, a0, a1);
    }

    /// @notice Mint a NEW position from the lockbox's own balance (e.g. add a
    ///         single-sided USDC band below spot to reinforce the floor). The
    ///         new NFT is owned by, and registered to, the lockbox.
    /// @dev No recipient argument (recipient is hardcoded to this contract).
    ///      Cannot move value out — it only deposits.
    function mintPosition(
        int24 tickLower,
        int24 tickUpper,
        uint256 amount0Desired,
        uint256 amount1Desired,
        uint256 amount0Min,
        uint256 amount1Min
    ) external onlyOwnerOrOperator returns (uint256 tokenId) {
        if (tickUpper <= tickLower) revert TicksOutOfOrder();
        if (amount0Desired == 0 && amount1Desired == 0) revert NothingProvided();
        if (tokenIds.length >= MAX_POSITIONS) revert TooManyPositions();

        _approve(token0, amount0Desired);
        _approve(token1, amount1Desired);
        uint256 a0;
        uint256 a1;
        (tokenId, , a0, a1) = positionManager.mint(
            INonfungiblePositionManager.MintParams({
                token0: token0,
                token1: token1,
                fee: poolFee,
                tickLower: tickLower,
                tickUpper: tickUpper,
                amount0Desired: amount0Desired,
                amount1Desired: amount1Desired,
                amount0Min: amount0Min,
                amount1Min: amount1Min,
                recipient: address(this),
                deadline: block.timestamp
            })
        );
        _approve(token0, 0);
        _approve(token1, 0);

        registered[tokenId] = true;
        tokenIds.push(tokenId);
        emit PositionMinted(tokenId, tickLower, tickUpper, a0, a1);
    }

    // ── Fees (fees only — no decrease path exists, so tokensOwed is fees) ───────

    function collectFees() external onlyOwnerOrOperator {
        uint256 collected0;
        uint256 collected1;
        uint256 count = tokenIds.length;
        for (uint256 i = 0; i < count; i++) {
            (uint256 a0, uint256 a1) = positionManager.collect(
                INonfungiblePositionManager.CollectParams({
                    tokenId: tokenIds[i],
                    recipient: address(this),
                    amount0Max: type(uint128).max,
                    amount1Max: type(uint128).max
                })
            );
            collected0 += a0;
            collected1 += a1;
        }

        if (block.timestamp >= feeWindowStart + feeWindow) {
            feeWindowStart = block.timestamp;
            feeWindowSpent0 = 0;
            feeWindowSpent1 = 0;
        }
        uint256 send0 = _capped(collected0, feeWindowSpent0, maxFee0PerWindow);
        uint256 send1 = _capped(collected1, feeWindowSpent1, maxFee1PerWindow);
        feeWindowSpent0 += send0;
        feeWindowSpent1 += send1;

        if (send0 > 0) _transferTo(token0, feeRecipient, send0);
        if (send1 > 0) _transferTo(token1, feeRecipient, send1);
        emit FeesForwarded(send0, send1);

        uint256 r0 = collected0 - send0;
        uint256 r1 = collected1 - send1;
        if (r0 > 0 || r1 > 0) emit FeesRetained(r0, r1);
    }

    function _capped(uint256 amount, uint256 spent, uint256 cap) internal pure returns (uint256) {
        if (spent >= cap) return 0;
        uint256 remaining = cap - spent;
        return amount > remaining ? remaining : amount;
    }

    // ── Lock management ────────────────────────────────────────────────────────

    /// @notice Rotate the add/collect operator. No Falcon: the operator cannot
    ///         move principal, so this is not a value-bearing change.
    function setOperator(address newOperator) external onlyOwner {
        if (newOperator == address(0)) revert ZeroAddress();
        emit OperatorChanged(operator, newOperator);
        operator = newOperator;
    }

    /// @notice Move the unlock date LATER (never earlier). Dual-gated.
    function extendUnlock(uint256 newUnlockTime, FalconSig calldata sig) external onlyOwner {
        if (newUnlockTime <= unlockTime) revert UnlockNotLater();
        _requireFalcon("EXTEND_UNLOCK", abi.encode(newUnlockTime), sig);
        uint256 old = unlockTime;
        unlockTime = newUnlockTime;
        emit UnlockExtended(old, newUnlockTime);
    }

    /// @notice After unlockTime, return every position NFT and all token balances
    ///         to `owner`. Dual-gated (Safe ECDSA + Falcon-512). No address arg.
    function withdrawAll(FalconSig calldata sig) external onlyOwner {
        if (block.timestamp < unlockTime) revert StillLocked(unlockTime);
        _requireFalcon("WITHDRAW_ALL", "", sig);

        uint256 count = tokenIds.length;
        for (uint256 i = 0; i < count; i++) {
            uint256 id = tokenIds[i];
            registered[id] = false;
            // transferFrom, not safeTransferFrom: a Safe without an ERC-721
            // receive handler must never be able to brick withdrawal.
            positionManager.transferFrom(address(this), owner, id);
        }
        delete tokenIds;

        uint256 a0 = IERC20(token0).balanceOf(address(this));
        uint256 a1 = IERC20(token1).balanceOf(address(this));
        if (a0 > 0) _transferTo(token0, owner, a0);
        if (a1 > 0) _transferTo(token1, owner, a1);
        emit WithdrawnAll(count, a0, a1);
    }

    // ── Post-quantum gate ──────────────────────────────────────────────────────

    function falconActive() public view returns (bool) {
        return address(falconVerifier) != address(0) &&
            (ecdsaFallbackTime == 0 || block.timestamp < ecdsaFallbackTime);
    }

    function _requireFalcon(string memory action, bytes memory payload, FalconSig calldata sig) internal {
        if (!falconActive()) return;
        if (block.timestamp > sig.deadline) revert FalconSigExpired();
        if (sig.nonce != falconNonce) revert FalconBadNonce(falconNonce, sig.nonce);
        if (sig.salt40.length != 40) revert FalconBadSaltLength(sig.salt40.length);
        if (sig.s2.length != 32) revert FalconBadS2Length(sig.s2.length);

        bytes32 actionHash = keccak256(abi.encodePacked(action, payload));
        bytes32 structHash = keccak256(abi.encode(ACTION_TYPEHASH, msg.sender, actionHash, sig.nonce, sig.deadline));
        bytes32 domainSeparator = keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
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
    }

    /// @notice Rotate the Falcon key. The CURRENT key signs the new key.
    function rotateFalconKey(uint256[32] calldata newNtth, FalconSig calldata sig) external onlyOwner {
        if (address(falconVerifier) == address(0)) revert FalconNotEnabled();
        bool nonZero;
        for (uint256 i = 0; i < 32; i++) { if (newNtth[i] != 0) { nonZero = true; break; } }
        if (!nonZero) revert FalconKeyEmpty();
        _requireFalcon("ROTATE_FALCON_KEY", abi.encode(newNtth), sig);
        for (uint256 i = 0; i < 32; i++) falconNtth[i] = newNtth[i];
        emit FalconKeyRotated(falconNonce);
    }

    function falconKey() external view returns (uint256[32] memory) { return falconNtth; }

    // ── ERC-721 receipt / registration ─────────────────────────────────────────

    /// @notice Accept LEMNI/USDC position NFTs from the owner (the migration
    ///         path). Accepts only from `owner`, only matching positions, capped.
    function onERC721Received(address, address from, uint256 tokenId, bytes calldata) external returns (bytes4) {
        if (msg.sender != address(positionManager)) revert NotPositionManager();
        if (from != owner) revert OnlyOwner();
        _register(tokenId);
        return this.onERC721Received.selector;
    }

    /// @notice Index a position the lockbox already owns but that arrived via a
    ///         plain transferFrom (no callback). Cannot move value.
    function registerPosition(uint256 tokenId) external onlyOwner {
        if (positionManager.ownerOf(tokenId) != address(this)) revert WrongPosition(tokenId);
        _register(tokenId);
    }

    function _register(uint256 tokenId) internal {
        if (registered[tokenId]) revert AlreadyRegistered(tokenId);
        if (tokenIds.length >= MAX_POSITIONS) revert TooManyPositions();
        (, , address t0, address t1, uint24 fee, , , , , , , ) = positionManager.positions(tokenId);
        if (t0 != token0 || t1 != token1 || fee != poolFee) revert WrongPosition(tokenId);
        registered[tokenId] = true;
        tokenIds.push(tokenId);
        emit PositionReceived(tokenId);
    }

    // ── Views ────────────────────────────────────────────────────────────────

    function positionCount() external view returns (uint256) { return tokenIds.length; }
    function allPositions() external view returns (uint256[] memory) { return tokenIds; }
    function isLocked() external view returns (bool) { return block.timestamp < unlockTime; }
    function feeAllowanceRemaining() external view returns (uint256 r0, uint256 r1) {
        bool elapsed = block.timestamp >= feeWindowStart + feeWindow;
        uint256 s0 = elapsed ? 0 : feeWindowSpent0;
        uint256 s1 = elapsed ? 0 : feeWindowSpent1;
        r0 = s0 >= maxFee0PerWindow ? 0 : maxFee0PerWindow - s0;
        r1 = s1 >= maxFee1PerWindow ? 0 : maxFee1PerWindow - s1;
    }

    // ── Internal token helpers ──────────────────────────────────────────────────

    function _approve(address token, uint256 amount) internal {
        if (!IERC20(token).approve(address(positionManager), amount)) revert TransferFailed();
    }
    function _transferTo(address token, address to, uint256 amount) internal {
        if (!IERC20(token).transfer(to, amount)) revert TransferFailed();
    }
}
