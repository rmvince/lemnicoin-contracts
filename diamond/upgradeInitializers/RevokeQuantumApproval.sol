// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AppStorage, LibAppStorage} from "../libraries/LibAppStorage.sol";

/// @title RevokeQuantumApproval
/// @notice One-shot init contract: revokes quantumApprovedSpender and zeros the
///         ERC-20 allowance for a specific wallet→spender pair.
///         The wallet can still call quantumApprove() again in the future.
///         Executed via diamondCut _init.
contract RevokeQuantumApproval {
    function execute() external {
        AppStorage storage s = LibAppStorage.appStorage();

        // Wallet: 0xa4fE19550AeC451Aa89e749A2a1c49E0b915eB9D
        //   - quantumApprovedSpender is true despite no FalconApproval event
        //   - allowance is type(uint256).max (dapp never sets this — anomalous)
        // Spender: Uniswap V3 SwapRouter02 on Polygon
        address wallet  = 0xa4fE19550AeC451Aa89e749A2a1c49E0b915eB9D;
        address spender = 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45;

        s.quantumApprovedSpender[wallet][spender] = false;
        s.allowances[wallet][spender] = 0;
    }
}
