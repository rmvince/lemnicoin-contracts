// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {LibERC20} from "../libraries/LibERC20.sol";

/// @title BreakerHarness — TEST ONLY. LibERC20's transfer path (pause + circuit breaker) with the
///        storage knobs a Diamond deployment would have set. NEVER cut into a real Diamond.
contract BreakerHarness is Modifiers {
    function mint(address to, uint256 amount) external { LibERC20._mint(to, amount); }
    function setBreaker(uint256 threshold, uint256 window) external {
        s.circuitBreakerThreshold = threshold;
        s.circuitBreakerWindow = window;
    }
    function transfer(address to, uint256 amount) external { LibERC20._transfer(msg.sender, to, amount); }
    function paused() external view returns (bool) { return s.paused; }
    function windowVolume() external view returns (uint256) { return s.circuitBreakerWindowVolume; }
}
