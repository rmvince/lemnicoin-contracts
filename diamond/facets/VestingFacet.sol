// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {AppStorage, VestingSchedule, LibAppStorage} from "../libraries/LibAppStorage.sol";
import {LibERC20} from "../libraries/LibERC20.sol";
import {LibDiamond} from "../libraries/LibDiamond.sol";

error DeploymentPhaseEnded();
error InvalidBeneficiary();
error ZeroAmount();
error ScheduleExists();
error NoVestingSchedule();
error NewCliffNotLaterThanCurrent();

/// @title VestingFacet — Vesting schedules, deployment phase, and distribution
/// @notice Handles createVestingSchedule, distributionTransfer, endDeploymentPhase,
///         and vesting query functions.
contract VestingFacet is Modifiers {

    event DeploymentPhaseClosed(uint256 timestamp);
    event VestingScheduleCreated(
        address indexed beneficiary, uint256 totalAmount, uint256 startTime, uint256 cliffDuration, uint256 vestingDuration
    );
    event DistributionTransfer(address indexed to, uint256 amount);
    event VestingCliffAmended(
        address indexed beneficiary,
        uint256 oldCliffDuration,
        uint256 newCliffDuration
    );
    event VestingLockRemoved(
        address indexed beneficiary,
        uint256 totalAmount
    );

    // =========================================================================
    // DEPLOYMENT PHASE
    // =========================================================================

    function endDeploymentPhase() external onlyOwner {
        if (!s.deploymentPhaseActive) revert DeploymentPhaseEnded();
        s.deploymentPhaseActive = false;
        emit DeploymentPhaseClosed(block.timestamp);
    }

    function distributionTransfer(address to, uint256 amount) external onlyOwner {
        if (!s.deploymentPhaseActive) revert DeploymentPhaseEnded();
        LibERC20._transfer(msg.sender, to, amount);
        emit DistributionTransfer(to, amount);
    }

    // =========================================================================
    // VESTING SCHEDULES
    // =========================================================================

    function createVestingSchedule(
        address beneficiary,
        uint256 amount,
        uint256 startTime,
        uint256 cliffDuration,
        uint256 vestingDuration
    ) external onlyOwner {
        if (!s.deploymentPhaseActive) revert DeploymentPhaseEnded();
        if (beneficiary == address(0)) revert InvalidBeneficiary();
        if (amount == 0) revert ZeroAmount();
        if (s.vestingSchedules[beneficiary].totalAmount != 0) revert ScheduleExists();

        // Transfer tokens to beneficiary (visible in wallet but locked)
        LibERC20._transfer(msg.sender, beneficiary, amount);

        s.vestingSchedules[beneficiary] = VestingSchedule({
            totalAmount: amount,
            unlocked: 0,
            startTime: startTime,
            cliffDuration: cliffDuration,
            vestingDuration: vestingDuration
        });

        emit VestingScheduleCreated(beneficiary, amount, startTime, cliffDuration, vestingDuration);
    }

    // =========================================================================
    // AMEND CLIFF DATE
    // =========================================================================

    /// @notice Extend a vesting schedule's cliff duration to a later date
    /// @dev Only the owner can call this. The new cliff duration must be strictly
    ///      longer than the current one to prevent shortening lock periods.
    ///      Works post-deployment — does NOT require deploymentPhaseActive.
    /// @param beneficiary Address of the vesting schedule holder
    /// @param newCliffDuration New cliff duration in seconds (must be longer than current)
    function amendVestingCliffDate(
        address beneficiary,
        uint256 newCliffDuration
    ) external onlyOwner {
        VestingSchedule storage schedule = s.vestingSchedules[beneficiary];
        if (schedule.totalAmount == 0) revert NoVestingSchedule();
        if (newCliffDuration <= schedule.cliffDuration) revert NewCliffNotLaterThanCurrent();

        uint256 oldCliffDuration = schedule.cliffDuration;
        schedule.cliffDuration = newCliffDuration;

        emit VestingCliffAmended(beneficiary, oldCliffDuration, newCliffDuration);
    }

    // =========================================================================
    // REMOVE VESTING LOCK
    // =========================================================================

    /// @notice Remove the vesting lock from a wallet, making all tokens immediately transferable
    /// @dev Tokens stay in the beneficiary's wallet — only the lock is removed.
    /// @param beneficiary Address to unlock
    function removeVestingLock(address beneficiary) external onlyOwner {
        VestingSchedule storage schedule = s.vestingSchedules[beneficiary];
        if (schedule.totalAmount == 0) revert NoVestingSchedule();

        schedule.cliffDuration = 0;
        schedule.vestingDuration = 0;

        emit VestingLockRemoved(beneficiary, schedule.totalAmount);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function vestedAmount(address beneficiary) external view returns (uint256) {
        return LibERC20._vestedAmount(s.vestingSchedules[beneficiary]);
    }

    function lockedAmount(address beneficiary) external view returns (uint256) {
        VestingSchedule storage schedule = s.vestingSchedules[beneficiary];
        if (schedule.totalAmount == 0) return 0;
        return schedule.totalAmount - LibERC20._vestedAmount(schedule);
    }

    function transferableBalance(address account) external view returns (uint256) {
        VestingSchedule storage schedule = s.vestingSchedules[account];
        if (schedule.totalAmount == 0) {
            return s.balances[account]; // No vesting = all transferable
        }
        uint256 stillLocked = schedule.totalAmount - LibERC20._vestedAmount(schedule);
        return s.balances[account] - stillLocked;
    }

    function getVestingSchedule(address beneficiary) external view returns (
        uint256 totalAmount,
        uint256 unlocked,
        uint256 startTime,
        uint256 cliffDuration,
        uint256 vestingDuration
    ) {
        VestingSchedule storage schedule = s.vestingSchedules[beneficiary];
        return (
            schedule.totalAmount,
            schedule.unlocked,
            schedule.startTime,
            schedule.cliffDuration,
            schedule.vestingDuration
        );
    }
}
