// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract LemnicoinVesting {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    address public immutable beneficiary;
    uint256 public immutable releaseTime;
    bool public released;

    string public description;
    uint256 public immutable plannedAmount;

    event TokensReleased(address indexed beneficiary, uint256 amount, uint256 timestamp);

    constructor(
        address _token,
        address _beneficiary,
        uint256 _releaseTime,
        uint256 _plannedAmount,
        string memory _description
    ) {
        require(_token != address(0), "Token is zero");
        require(_beneficiary != address(0), "Beneficiary is zero");
        require(_releaseTime > block.timestamp, "Release time must be future");
        require(_plannedAmount > 0, "Amount must be > 0");

        token = IERC20(_token);
        beneficiary = _beneficiary;
        releaseTime = _releaseTime;
        plannedAmount = _plannedAmount;
        description = _description;
        released = false;
    }

    function release() external {
        require(block.timestamp >= releaseTime, "Tokens still locked");
        require(!released, "Already released");

        released = true;
        uint256 balance = token.balanceOf(address(this));
        require(balance > 0, "No tokens");

        token.safeTransfer(beneficiary, balance);
        emit TokensReleased(beneficiary, balance, block.timestamp);
    }

    function isUnlocked() public view returns (bool) {
        return block.timestamp >= releaseTime;
    }

    function getBalance() public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function getInfo() external view returns (
        address _token,
        address _beneficiary,
        uint256 _releaseTime,
        uint256 _plannedAmount,
        uint256 _actualBalance,
        bool _isUnlocked,
        bool _released,
        string memory _description
    ) {
        return (
            address(token),
            beneficiary,
            releaseTime,
            plannedAmount,
            getBalance(),
            isUnlocked(),
            released,
            description
        );
    }

    function timeUntilUnlock() external view returns (uint256) {
        if (block.timestamp >= releaseTime) return 0;
        return releaseTime - block.timestamp;
    }

    function getTimeRemaining() external view returns (
        uint256 vestingDays,
        uint256 vestingHours,
        uint256 vestingMinutes
    ) {
        if (block.timestamp >= releaseTime) return (0, 0, 0);

        uint256 remaining = releaseTime - block.timestamp;
        vestingDays = remaining / 86400;
        vestingHours = (remaining % 86400) / 3600;
        vestingMinutes = (remaining % 3600) / 60;

        return (vestingDays, vestingHours, vestingMinutes);
    }
}
