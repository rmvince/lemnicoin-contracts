// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract LemnicoinRecurring {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    address public immutable beneficiary;

    uint256 public immutable startTime;
    uint256 public immutable interval;
    uint256 public immutable amountPerRelease;
    uint256 public immutable totalReleases;

    uint256 public releasedCount;
    string public description;

    event TokensReleased(address indexed beneficiary, uint256 amount, uint256 releaseNumber, uint256 timestamp);

    constructor(
        address _token,
        address _beneficiary,
        uint256 _startTime,
        uint256 _interval,
        uint256 _amountPerRelease,
        uint256 _totalReleases,
        string memory _description
    ) {
        require(_token != address(0), "Token is zero");
        require(_beneficiary != address(0), "Beneficiary is zero");
        require(_startTime > block.timestamp, "Start must be future");
        require(_interval > 0, "Interval must be > 0");
        require(_amountPerRelease > 0, "Amount must be > 0");
        require(_totalReleases > 0, "Releases must be > 0");

        token = IERC20(_token);
        beneficiary = _beneficiary;
        startTime = _startTime;
        interval = _interval;
        amountPerRelease = _amountPerRelease;
        totalReleases = _totalReleases;
        description = _description;
        releasedCount = 0;
    }

    function release() external {
        require(msg.sender == beneficiary, "Only beneficiary");
        uint256 available = availableReleases();
        require(available > 0, "No releases available");

        uint256 totalAmount = available * amountPerRelease;
        releasedCount += available;

        token.safeTransfer(beneficiary, totalAmount);
        emit TokensReleased(beneficiary, totalAmount, releasedCount, block.timestamp);
    }

    function releaseMultiple(uint256 count) external {
        require(msg.sender == beneficiary, "Only beneficiary");
        require(count > 0, "Count must be > 0");

        uint256 available = availableReleases();
        require(available >= count, "Not enough available");

        uint256 totalAmount = count * amountPerRelease;
        releasedCount += count;

        token.safeTransfer(beneficiary, totalAmount);
        emit TokensReleased(beneficiary, totalAmount, releasedCount, block.timestamp);
    }

    function availableReleases() public view returns (uint256) {
        if (block.timestamp < startTime) return 0;

        uint256 elapsedTime = block.timestamp - startTime;
        uint256 dueReleases = (elapsedTime / interval) + 1;

        if (dueReleases > totalReleases) dueReleases = totalReleases;
        if (dueReleases <= releasedCount) return 0;

        return dueReleases - releasedCount;
    }

    function nextReleaseTime() public view returns (uint256) {
        if (releasedCount >= totalReleases) return 0;
        return startTime + (releasedCount * interval);
    }

    function isComplete() public view returns (bool) {
        return releasedCount >= totalReleases;
    }

    function getInfo() external view returns (
        address _beneficiary,
        uint256 _totalAmount,
        uint256 _releasedAmount,
        uint256 _availableAmount,
        uint256 _nextRelease,
        uint256 _releasesCompleted,
        uint256 _totalReleases,
        bool _isComplete,
        string memory _description
    ) {
        uint256 available = availableReleases();
        uint256 totalAmount = totalReleases * amountPerRelease;
        uint256 releasedAmount = releasedCount * amountPerRelease;
        uint256 availableAmount = available * amountPerRelease;

        return (
            beneficiary,
            totalAmount,
            releasedAmount,
            availableAmount,
            nextReleaseTime(),
            releasedCount,
            totalReleases,
            isComplete(),
            description
        );
    }

    function getReleaseSchedule() external view returns (uint256[] memory) {
        uint256[] memory schedule = new uint256[](totalReleases);
        for (uint256 i = 0; i < totalReleases; i++) {
            schedule[i] = startTime + (i * interval);
        }
        return schedule;
    }

    function getBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }
}
