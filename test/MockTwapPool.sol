// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title MockTwapPool — TEST ONLY. A Uniswap V3 pool stand-in whose spot tick (slot0) and
///        30-minute tick cumulatives (observe) are set independently, so tests can show the oracle
///        follows the time-weighted average and ignores a manipulated spot price.
contract MockTwapPool {
    int24 public spotTick;
    int56 public cumulativeThen;  // tickCumulative at now - secondsAgos[0]
    int56 public cumulativeNow;   // tickCumulative at now
    bool public observeReverts;   // models observation cardinality too low ("OLD")

    function setSpotTick(int24 t) external { spotTick = t; }
    function setCumulatives(int56 thenC, int56 nowC) external { cumulativeThen = thenC; cumulativeNow = nowC; }
    function setObserveReverts(bool r) external { observeReverts = r; }

    function observe(uint32[] calldata secondsAgos)
        external view returns (int56[] memory tickCumulatives, uint160[] memory spl)
    {
        require(!observeReverts, "OLD");
        require(secondsAgos.length == 2 && secondsAgos[1] == 0, "shape");
        tickCumulatives = new int56[](2);
        tickCumulatives[0] = cumulativeThen;
        tickCumulatives[1] = cumulativeNow;
        spl = new uint160[](2);
    }

    function slot0() external view returns (uint160, int24, uint16, uint16, uint16, uint8, bool) {
        return (uint160(1) << 96, spotTick, 0, 1, 1, 0, true);
    }
}
