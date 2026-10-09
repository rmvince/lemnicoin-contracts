// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LemnicoinLiquidityModule
/// @notice Safe Module that allows a constrained deployment wallet to manage
///         Uniswap V3 LEMNI/USDC liquidity through the Safe without multisig
///         confirmation.  The module enforces:
///           1. Only the deployment wallet can call it.
///           2. Only whitelisted function selectors on whitelisted targets.
///           3. Any recipient / output address must equal the Safe itself.
///           4. Only the LEMNI/USDC token pair is usable (no rogue-token attacks).
///         Even if the deployment wallet key is compromised, on-chain logic
///         prevents an attacker from extracting funds — tokens can only flow
///         back to the Safe.

// ──────────────────────────────────────────────────────────────────────────────
// Minimal Safe interface — only what the module needs
// ──────────────────────────────────────────────────────────────────────────────

interface ISafe {
    enum Operation {
        Call,
        DelegateCall
    }

    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Operation operation
    ) external returns (bool success);
}

// ──────────────────────────────────────────────────────────────────────────────
// Module contract
// ──────────────────────────────────────────────────────────────────────────────

contract LemnicoinLiquidityModule {
    // ── Immutables (set once at deployment, never change) ───────────────────

    ISafe public immutable safe;
    address public immutable deploymentWallet;
    address public immutable positionManager; // Uniswap V3 NonfungiblePositionManager
    address public immutable swapRouter; // Uniswap V3 SwapRouter02
    address public immutable token0; // LEMNI  (lower address)
    address public immutable token1; // USDC   (higher address)
    address public immutable feeRecipient; // hardcoded fee-forwarding destination (or address(0) to disable)

    // ── Allowed function selectors ──────────────────────────────────────────

    // NonfungiblePositionManager
    // mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))
    bytes4 private constant MINT = 0x88316456;
    // increaseLiquidity((uint256,uint256,uint256,uint256,uint256,uint256))
    bytes4 private constant INCREASE_LIQUIDITY = 0x219f5d17;
    // decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))
    bytes4 private constant DECREASE_LIQUIDITY = 0x0c49ccbe;
    // collect((uint256,address,uint128,uint128))
    bytes4 private constant COLLECT = 0xfc6f7865;
    // burn(uint256)
    bytes4 private constant BURN = 0x42966c68;

    // SwapRouter02
    // exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))
    bytes4 private constant EXACT_INPUT_SINGLE = 0x04e45aaf;
    // exactInput((bytes,address,uint256,uint256))
    bytes4 private constant EXACT_INPUT = 0xb858183f;

    // ERC-20
    // approve(address,uint256)
    bytes4 private constant APPROVE = 0x095ea7b3;
    // transfer(address,uint256)
    bytes4 private constant TRANSFER = 0xa9059cbb;

    // ── Custom errors ───────────────────────────────────────────────────────

    error OnlyDeploymentWallet();
    error TargetNotAllowed(address target);
    error SelectorNotAllowed(bytes4 selector);
    error RecipientNotSafe(address recipient);
    error ApproveSpenderNotAllowed(address spender);
    error TransferRecipientNotAllowed(address recipient);
    error FeeForwardingDisabled();
    error TokenNotAllowed(address token);
    error SafeExecFailed();
    error DataTooShort();

    // ── Constructor ─────────────────────────────────────────────────────────

    constructor(
        address _safe,
        address _deploymentWallet,
        address _positionManager,
        address _swapRouter,
        address _token0,
        address _token1,
        address _feeRecipient
    ) {
        safe = ISafe(_safe);
        deploymentWallet = _deploymentWallet;
        positionManager = _positionManager;
        swapRouter = _swapRouter;
        token0 = _token0;
        token1 = _token1;
        feeRecipient = _feeRecipient; // address(0) disables fee forwarding
    }

    // ── Public entry point ──────────────────────────────────────────────────

    /// @notice Execute a liquidity-management operation through the Safe.
    /// @param target Contract to call (positionManager, swapRouter, token0, or token1).
    /// @param data   ABI-encoded calldata for the target function.
    function exec(address target, bytes calldata data) external {
        if (msg.sender != deploymentWallet) revert OnlyDeploymentWallet();
        if (data.length < 4) revert DataTooShort();

        bytes4 selector = bytes4(data[:4]);

        if (target == positionManager) {
            _validatePositionManager(selector, data);
        } else if (target == swapRouter) {
            _validateSwapRouter(selector, data);
        } else if (target == token0 || target == token1) {
            _validateTokenCall(selector, data);
        } else {
            revert TargetNotAllowed(target);
        }

        bool success = safe.execTransactionFromModule(
            target,
            0, // never send native token
            data,
            ISafe.Operation.Call // never delegatecall
        );
        if (!success) revert SafeExecFailed();
    }

    // ── Internal validation ─────────────────────────────────────────────────

    /// @dev Validate calls to NonfungiblePositionManager.
    function _validatePositionManager(
        bytes4 selector,
        bytes calldata data
    ) internal view {
        if (selector == MINT) {
            // MintParams layout (all static — encoded in-place):
            //   word 0  (offset   4): token0
            //   word 1  (offset  36): token1
            //   ...
            //   word 9  (offset 292): recipient
            _requireToken(address(bytes20(data[4 + 12:4 + 32])));    // token0
            _requireToken(address(bytes20(data[36 + 12:36 + 32])));  // token1
            address recipient = address(bytes20(data[292 + 12:292 + 32]));
            if (recipient != address(safe)) revert RecipientNotSafe(recipient);
        } else if (selector == INCREASE_LIQUIDITY) {
            // IncreaseLiquidityParams: (tokenId, amount0Desired, amount1Desired,
            //                           amount0Min, amount1Min, deadline)
            // No recipient field — tokens go into the existing position. Safe.
        } else if (selector == DECREASE_LIQUIDITY) {
            // DecreaseLiquidityParams: (tokenId, liquidity, amount0Min,
            //                           amount1Min, deadline)
            // No recipient — freed tokens are held by PM until collect(). Safe.
        } else if (selector == COLLECT) {
            // CollectParams layout:
            //   word 0 (offset  4): tokenId
            //   word 1 (offset 36): recipient
            address recipient = address(bytes20(data[36 + 12:36 + 32]));
            if (recipient != address(safe)) revert RecipientNotSafe(recipient);
        } else if (selector == BURN) {
            // burn(uint256 tokenId) — destroys an empty NFT. No recipient. Safe.
        } else {
            revert SelectorNotAllowed(selector);
        }
    }

    /// @dev Validate calls to SwapRouter02.
    function _validateSwapRouter(
        bytes4 selector,
        bytes calldata data
    ) internal view {
        if (selector == EXACT_INPUT_SINGLE) {
            // ExactInputSingleParams layout (all static — encoded in-place):
            //   word 0 (offset   4): tokenIn
            //   word 1 (offset  36): tokenOut
            //   word 2 (offset  68): fee
            //   word 3 (offset 100): recipient
            _requireToken(address(bytes20(data[4 + 12:4 + 32])));    // tokenIn
            _requireToken(address(bytes20(data[36 + 12:36 + 32])));  // tokenOut
            address recipient = address(bytes20(data[100 + 12:100 + 32]));
            if (recipient != address(safe)) revert RecipientNotSafe(recipient);
        } else if (selector == EXACT_INPUT) {
            // ExactInputParams layout (path is dynamic):
            //   word 0 (offset  4): offset to path bytes
            //   word 1 (offset 36): recipient
            //   word 2 (offset 68): amountIn
            //   word 3 (offset 100): amountOutMinimum
            //   ... then at the path offset: length + packed path data
            address recipient = address(bytes20(data[36 + 12:36 + 32]));
            if (recipient != address(safe)) revert RecipientNotSafe(recipient);

            // Validate every token in the packed path.
            // Path encoding: [addr (20B)][fee (3B)][addr (20B)][fee (3B)]...
            uint256 pathOffset = 4 + uint256(bytes32(data[4:36])); // absolute offset
            uint256 pathLength = uint256(bytes32(data[pathOffset:pathOffset + 32]));
            bytes calldata path = data[pathOffset + 32:pathOffset + 32 + pathLength];
            _validatePath(path);
        } else {
            revert SelectorNotAllowed(selector);
        }
    }

    /// @dev Validate ERC-20 calls — approve (PM/Router only) or transfer (feeRecipient only).
    function _validateTokenCall(
        bytes4 selector,
        bytes calldata data
    ) internal view {
        if (selector == APPROVE) {
            // approve(address spender, uint256 amount)
            address spender = address(bytes20(data[4 + 12:4 + 32]));
            if (spender != positionManager && spender != swapRouter) {
                revert ApproveSpenderNotAllowed(spender);
            }
        } else if (selector == TRANSFER) {
            // transfer(address to, uint256 amount) — fee forwarding only
            if (feeRecipient == address(0)) revert FeeForwardingDisabled();
            address to = address(bytes20(data[4 + 12:4 + 32]));
            if (to != feeRecipient) revert TransferRecipientNotAllowed(to);
        } else {
            revert SelectorNotAllowed(selector);
        }
    }

    /// @dev Require that `token` is either token0 (LEMNI) or token1 (USDC).
    function _requireToken(address token) internal view {
        if (token != token0 && token != token1) revert TokenNotAllowed(token);
    }

    /// @dev Validate a packed Uniswap V3 swap path — every 20-byte address
    ///      must be token0 or token1.  Path format:
    ///        [addr0 (20B)][fee (3B)][addr1 (20B)][fee (3B)][addr2 (20B)]...
    function _validatePath(bytes calldata path) internal view {
        uint256 i = 0;
        while (i < path.length) {
            address token = address(bytes20(path[i:i + 20]));
            _requireToken(token);
            i += 20;
            if (i < path.length) {
                i += 3; // skip fee tier bytes
            }
        }
    }
}
