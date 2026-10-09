// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title MockPriceOracle
 * @dev Simple mock for testing - always returns fixed values
 */
contract MockPriceOracle {
    address public feeCollector;

    constructor() {
        feeCollector = msg.sender;
    }

    function getMinFeeInWei(uint256 /* amountLemniWei */) external pure returns (uint256) {
        // Return a small fixed fee for testing
        return 0.001 ether;
    }

    function setFeeCollector(address _collector) external {
        feeCollector = _collector;
    }
}
