// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AppStorage, LibAppStorage} from "../libraries/LibAppStorage.sol";

/// @title RemoveRouterFromDEXWhitelist
/// @notice One-shot init contract: removes the Uniswap SwapRouter02 from
///         the DEX pool whitelist. Executed via diamondCut _init.
contract RemoveRouterFromDEXWhitelist {
    function execute() external {
        AppStorage storage s = LibAppStorage.appStorage();
        // Uniswap V3 SwapRouter02 on Polygon — should NOT be a "pool"
        s.isWhitelistedDEXPool[0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45] = false;
    }
}
