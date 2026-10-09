// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AppStorage, VestingSchedule, TimeLock, LibAppStorage} from "./LibAppStorage.sol";

error ERC20TransferFromZero();
error ERC20TransferToZero();
error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed);
error ERC20ApproveFromZero();
error ERC20ApproveToZero();
error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed);
error ERC20MintToZero();
error ERC20BurnFromZero();
error ERC20BurnExceedsBalance(address account, uint256 balance, uint256 amount);
error TokensLocked();

/// @title LibERC20 - Internal ERC20 operations for Diamond facets
/// @notice Replicates OpenZeppelin ERC20 internal logic using AppStorage.
///         All state-changing ERC20 helpers live here so that any facet
///         can call them without code duplication.
library LibERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event CircuitBreakerTripped(uint256 volumeInWindow, uint256 threshold, uint256 windowStart);

    function _transfer(address from, address to, uint256 amount) internal {
        if (from == address(0)) revert ERC20TransferFromZero();
        if (to == address(0)) revert ERC20TransferToZero();

        AppStorage storage s = LibAppStorage.appStorage();

        _beforeTokenTransfer(s, from, to, amount);

        uint256 fromBalance = s.balances[from];
        if (fromBalance < amount) revert ERC20InsufficientBalance(from, fromBalance, amount);
        unchecked {
            s.balances[from] = fromBalance - amount;
            s.balances[to] += amount;
        }

        emit Transfer(from, to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        if (to == address(0)) revert ERC20MintToZero();

        AppStorage storage s = LibAppStorage.appStorage();

        _beforeTokenTransfer(s, address(0), to, amount);

        s.totalSupply += amount;
        unchecked {
            s.balances[to] += amount;
        }

        emit Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        if (from == address(0)) revert ERC20BurnFromZero();

        AppStorage storage s = LibAppStorage.appStorage();

        _beforeTokenTransfer(s, from, address(0), amount);

        uint256 balance = s.balances[from];
        if (balance < amount) revert ERC20BurnExceedsBalance(from, balance, amount);
        unchecked {
            s.balances[from] = balance - amount;
            s.totalSupply -= amount;
        }

        emit Transfer(from, address(0), amount);
    }

    function _approve(address owner_, address spender, uint256 amount) internal {
        if (owner_ == address(0)) revert ERC20ApproveFromZero();
        if (spender == address(0)) revert ERC20ApproveToZero();

        AppStorage storage s = LibAppStorage.appStorage();
        s.allowances[owner_][spender] = amount;

        emit Approval(owner_, spender, amount);
    }

    function _spendAllowance(address owner_, address spender, uint256 amount) internal {
        AppStorage storage s = LibAppStorage.appStorage();
        uint256 currentAllowance = s.allowances[owner_][spender];
        if (currentAllowance != type(uint256).max) {
            if (currentAllowance < amount) {
                revert ERC20InsufficientAllowance(spender, currentAllowance, amount);
            }
            unchecked {
                s.allowances[owner_][spender] = currentAllowance - amount;
            }
        }
    }

    /// @dev Mirrors the monolith's _beforeTokenTransfer: enforces pause + vesting + time locks + circuit breaker.
    function _beforeTokenTransfer(
        AppStorage storage s,
        address from,
        address to,
        uint256 amount
    ) private {
        // Pausable check
        require(!s.paused, "Pausable: paused");

        // Skip lock checks and circuit breaker for minting (from == address(0))
        if (from == address(0)) return;

        uint256 totalLocked = 0;

        // Vesting lock check
        VestingSchedule storage schedule = s.vestingSchedules[from];
        if (schedule.totalAmount > 0) {
            uint256 vested = _vestedAmount(schedule);
            totalLocked += schedule.totalAmount - vested;
        }

        // Time lock check
        uint256 timeLockCount = s.timeLockCount[from];
        for (uint256 i = 0; i < timeLockCount; i++) {
            TimeLock storage lock = s.timeLocks[from][i];
            if (lock.active && block.timestamp < lock.unlockDate) {
                totalLocked += lock.amount;
            }
        }

        // Ensure transfer doesn't exceed transferable balance
        if (totalLocked > 0) {
            uint256 transferable = s.balances[from] > totalLocked ? s.balances[from] - totalLocked : 0;
            if (amount > transferable) revert TokensLocked();
        }

        // Circuit breaker: track rolling transfer volume, auto-pause on anomaly.
        // Threshold of 0 means disabled (default for uninitialized storage).
        // Excluded addresses (liquidity infrastructure) are not counted, and neither are
        // self-transfers: they move nothing, and counting them let any wallet trip the breaker
        // (pausing every holder) by sending to itself in a loop.
        uint256 threshold = s.circuitBreakerThreshold;
        if (threshold > 0 && from != to && !s.circuitBreakerExcluded[from] && !s.circuitBreakerExcluded[to]) {
            uint256 window = s.circuitBreakerWindow;
            // If we've moved past the current window, start a new one
            if (block.timestamp >= s.circuitBreakerWindowStart + window) {
                s.circuitBreakerWindowStart = block.timestamp;
                s.circuitBreakerWindowVolume = amount;
            } else {
                s.circuitBreakerWindowVolume += amount;
            }

            // If volume exceeds threshold, auto-pause. The triggering transfer
            // still completes (state is already committed), but all subsequent
            // transfers will hit the "Pausable: paused" check at the top.
            // This mirrors how real circuit breakers work: trip on the threshold
            // crossing, freeze everything after.
            if (s.circuitBreakerWindowVolume > threshold) {
                s.paused = true;
                emit CircuitBreakerTripped(
                    s.circuitBreakerWindowVolume,
                    threshold,
                    s.circuitBreakerWindowStart
                );
            }
        }
    }

    /// @dev Internal vesting calculation
    function _vestedAmount(VestingSchedule storage schedule) internal view returns (uint256) {
        if (schedule.totalAmount == 0) return 0;
        if (block.timestamp < schedule.startTime) return 0;

        uint256 elapsed = block.timestamp - schedule.startTime;

        // Before cliff: nothing vested
        if (elapsed < schedule.cliffDuration) return 0;

        // After cliff + vesting duration: fully vested
        uint256 vestingElapsed = elapsed - schedule.cliffDuration;
        if (vestingElapsed >= schedule.vestingDuration) {
            return schedule.totalAmount;
        }

        // During vesting: linear release
        return (schedule.totalAmount * vestingElapsed) / schedule.vestingDuration;
    }
}
