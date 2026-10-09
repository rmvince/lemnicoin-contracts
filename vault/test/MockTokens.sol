// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title MockERC20 — standard ERC-20 with configurable decimals (e.g. 6 for USDC/USDT). TEST ONLY.
contract MockERC20 is ERC20 {
    uint8 private immutable _decimals;

    constructor(string memory name_, string memory symbol_, uint8 decimals_) ERC20(name_, symbol_) {
        _decimals = decimals_;
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @title MockNoReturnToken — USDT-style token whose transfer() returns NOTHING. TEST ONLY.
/// @notice Exercises the SafeERC20 path in the vault: a naive `IERC20.transfer` would revert on
///         decoding the (absent) return value, but SafeERC20 handles it.
contract MockNoReturnToken {
    string public name = "Tether-like";
    string public symbol = "USDTL";
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    /// @dev Deliberately returns nothing, like real USDT on mainnet.
    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
