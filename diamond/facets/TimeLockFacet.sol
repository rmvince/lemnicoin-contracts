// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {AppStorage, TimeLock, LibAppStorage} from "../libraries/LibAppStorage.sol";
import {LibERC20} from "../libraries/LibERC20.sol";

error InvalidBeneficiary();
error ZeroAmount();
error UnlockDateInPast();
error InsufficientBalance();
error TimeLockNotFound();
error TimeLockNotActive();
error TimeLockNotUnlocked();
error NewDateNotLaterThanCurrent();

/// @title TimeLockFacet — Time-released token grants
/// @notice Allows owner to allocate LEMNI that cannot be transferred until a specific date.
///         Unlike VestingFacet, this works post-deployment and supports multiple locks per address.
contract TimeLockFacet is Modifiers {

    event TimeLockCreated(
        address indexed beneficiary,
        uint256 indexed lockId,
        uint256 amount,
        uint256 unlockDate
    );
    event TimeLockReleased(
        address indexed beneficiary,
        uint256 indexed lockId,
        uint256 amount
    );
    event TimeLockRevoked(
        address indexed beneficiary,
        uint256 indexed lockId,
        uint256 amount
    );
    event TimeLockDateAmended(
        address indexed beneficiary,
        uint256 indexed lockId,
        uint256 oldUnlockDate,
        uint256 newUnlockDate
    );

    // =========================================================================
    // CREATE TIME LOCKS
    // =========================================================================

    /// @notice Create a time-locked grant for a beneficiary
    /// @param beneficiary Address that will receive the locked tokens
    /// @param amount Amount of LEMNI to lock
    /// @param unlockDate Unix timestamp when tokens become transferable
    /// @return lockId The ID of the created time lock
    function createTimeLock(
        address beneficiary,
        uint256 amount,
        uint256 unlockDate
    ) external onlyOwner returns (uint256 lockId) {
        if (beneficiary == address(0)) revert InvalidBeneficiary();
        if (amount == 0) revert ZeroAmount();
        if (unlockDate <= block.timestamp) revert UnlockDateInPast();

        // Transfer tokens from owner to beneficiary (visible but locked)
        LibERC20._transfer(msg.sender, beneficiary, amount);

        // Create the time lock
        lockId = s.timeLockCount[beneficiary];
        s.timeLocks[beneficiary][lockId] = TimeLock({
            amount: amount,
            unlockDate: unlockDate,
            active: true
        });
        s.timeLockCount[beneficiary] = lockId + 1;

        emit TimeLockCreated(beneficiary, lockId, amount, unlockDate);
    }

    /// @notice Create multiple time locks in a single transaction (batch)
    /// @param beneficiaries Array of beneficiary addresses
    /// @param amounts Array of amounts to lock
    /// @param unlockDates Array of unlock timestamps
    function createTimeLockBatch(
        address[] calldata beneficiaries,
        uint256[] calldata amounts,
        uint256[] calldata unlockDates
    ) external onlyOwner {
        require(
            beneficiaries.length == amounts.length && amounts.length == unlockDates.length,
            "Array length mismatch"
        );

        for (uint256 i = 0; i < beneficiaries.length; i++) {
            if (beneficiaries[i] == address(0)) revert InvalidBeneficiary();
            if (amounts[i] == 0) revert ZeroAmount();
            if (unlockDates[i] <= block.timestamp) revert UnlockDateInPast();

            LibERC20._transfer(msg.sender, beneficiaries[i], amounts[i]);

            uint256 lockId = s.timeLockCount[beneficiaries[i]];
            s.timeLocks[beneficiaries[i]][lockId] = TimeLock({
                amount: amounts[i],
                unlockDate: unlockDates[i],
                active: true
            });
            s.timeLockCount[beneficiaries[i]] = lockId + 1;

            emit TimeLockCreated(beneficiaries[i], lockId, amounts[i], unlockDates[i]);
        }
    }

    // =========================================================================
    // REVOKE (Owner can revoke unvested locks and reclaim tokens)
    // =========================================================================

    /// @notice Revoke a time lock before it unlocks (returns tokens to owner)
    /// @param beneficiary Address of the time lock holder
    /// @param lockId ID of the time lock to revoke
    function revokeTimeLock(address beneficiary, uint256 lockId) external onlyOwner {
        TimeLock storage lock = s.timeLocks[beneficiary][lockId];
        if (!lock.active) revert TimeLockNotActive();
        if (block.timestamp >= lock.unlockDate) revert TimeLockNotUnlocked(); // Already unlocked, can't revoke

        uint256 amount = lock.amount;
        lock.active = false;
        lock.amount = 0;

        // Return tokens to owner
        LibERC20._transfer(beneficiary, msg.sender, amount);

        emit TimeLockRevoked(beneficiary, lockId, amount);
    }

    // =========================================================================
    // AMEND TIME LOCK DATE
    // =========================================================================

    /// @notice Extend a time lock's unlock date to a later date
    /// @dev Only the owner can call this. The new date must be strictly later
    ///      than the current unlock date to prevent shortening lock periods.
    /// @param beneficiary Address of the time lock holder
    /// @param lockId ID of the time lock to amend
    /// @param newUnlockDate New unix timestamp (must be later than current unlockDate)
    function amendTimeLockDate(
        address beneficiary,
        uint256 lockId,
        uint256 newUnlockDate
    ) external onlyOwner {
        TimeLock storage lock = s.timeLocks[beneficiary][lockId];
        if (!lock.active) revert TimeLockNotActive();
        if (newUnlockDate <= lock.unlockDate) revert NewDateNotLaterThanCurrent();

        uint256 oldUnlockDate = lock.unlockDate;
        lock.unlockDate = newUnlockDate;

        emit TimeLockDateAmended(beneficiary, lockId, oldUnlockDate, newUnlockDate);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @notice Get the total locked amount for an address (across all time locks)
    /// @param account Address to check
    /// @return total Total amount still locked
    function totalTimeLocked(address account) public view returns (uint256 total) {
        uint256 count = s.timeLockCount[account];
        for (uint256 i = 0; i < count; i++) {
            TimeLock storage lock = s.timeLocks[account][i];
            if (lock.active && block.timestamp < lock.unlockDate) {
                total += lock.amount;
            }
        }
    }

    /// @notice Get the total unlocked amount for an address (time locks that have passed)
    /// @param account Address to check
    /// @return total Total amount now unlocked from time locks
    function totalTimeUnlocked(address account) public view returns (uint256 total) {
        uint256 count = s.timeLockCount[account];
        for (uint256 i = 0; i < count; i++) {
            TimeLock storage lock = s.timeLocks[account][i];
            if (lock.active && block.timestamp >= lock.unlockDate) {
                total += lock.amount;
            }
        }
    }

    /// @notice Get details of a specific time lock
    /// @param beneficiary Address of the time lock holder
    /// @param lockId ID of the time lock
    /// @return amount Amount locked
    /// @return unlockDate When it unlocks
    /// @return active Whether it's still active
    /// @return unlocked Whether the unlock date has passed
    function getTimeLock(address beneficiary, uint256 lockId)
        external
        view
        returns (
            uint256 amount,
            uint256 unlockDate,
            bool active,
            bool unlocked
        )
    {
        TimeLock storage lock = s.timeLocks[beneficiary][lockId];
        return (
            lock.amount,
            lock.unlockDate,
            lock.active,
            block.timestamp >= lock.unlockDate
        );
    }

    /// @notice Get the number of time locks for an address
    /// @param account Address to check
    /// @return Number of time locks (including inactive ones)
    function getTimeLockCount(address account) external view returns (uint256) {
        return s.timeLockCount[account];
    }

    /// @notice Get all active time locks for an address
    /// @param account Address to check
    /// @return lockIds Array of lock IDs
    /// @return amounts Array of amounts
    /// @return unlockDates Array of unlock dates
    /// @return unlockedFlags Array of whether each is unlocked
    function getAllTimeLocks(address account)
        external
        view
        returns (
            uint256[] memory lockIds,
            uint256[] memory amounts,
            uint256[] memory unlockDates,
            bool[] memory unlockedFlags
        )
    {
        uint256 count = s.timeLockCount[account];

        // Count active locks
        uint256 activeCount = 0;
        for (uint256 i = 0; i < count; i++) {
            if (s.timeLocks[account][i].active) activeCount++;
        }

        // Allocate arrays
        lockIds = new uint256[](activeCount);
        amounts = new uint256[](activeCount);
        unlockDates = new uint256[](activeCount);
        unlockedFlags = new bool[](activeCount);

        // Fill arrays
        uint256 idx = 0;
        for (uint256 i = 0; i < count; i++) {
            TimeLock storage lock = s.timeLocks[account][i];
            if (lock.active) {
                lockIds[idx] = i;
                amounts[idx] = lock.amount;
                unlockDates[idx] = lock.unlockDate;
                unlockedFlags[idx] = block.timestamp >= lock.unlockDate;
                idx++;
            }
        }
    }

    /// @notice Calculate total transferable balance (accounting for time locks and vesting)
    /// @param account Address to check
    /// @return Amount that can be transferred right now
    function transferableWithTimeLocks(address account) external view returns (uint256) {
        uint256 balance = s.balances[account];
        uint256 locked = totalTimeLocked(account);

        // Also account for vesting locks if any
        if (s.vestingSchedules[account].totalAmount > 0) {
            uint256 vested = LibERC20._vestedAmount(s.vestingSchedules[account]);
            uint256 vestingLocked = s.vestingSchedules[account].totalAmount - vested;
            locked += vestingLocked;
        }

        if (locked >= balance) return 0;
        return balance - locked;
    }
}
