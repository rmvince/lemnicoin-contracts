// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title MockEconomicsOracle
 * @dev Test double for the two PUBLIC PriceOracle views the "1% rule" derives a transfer's native
 *      value from. It reproduces the real oracle's relationship exactly:
 *
 *          getMinFeeInWei(amount) = valueWei(amount) * feeBps / 10_000
 *
 *      so LibSlhEconomics.transferValueWei — which divides the fee back out by its own rate — can
 *      be tested against a known, settable value. `weiPerToken` stands in for the real oracle's
 *      LEMNI/USD and native/USD legs combined; setting it low simulates a crushed spot price.
 *
 *      `revertOnFeeBps` / `revertOnMinFee` exercise the fail-closed paths, and `feeBps = 0`
 *      exercises the zero-rate path.
 */
contract MockEconomicsOracle {
    address payable public feeCollector;

    uint16 public feeBps = 100;          // 1%
    uint256 public weiPerToken = 1 ether; // 1 LEMNI == 1 native
    bool public revertOnFeeBps;
    bool public revertOnMinFee;

    constructor() {
        feeCollector = payable(msg.sender);
    }

    function setFeeBps(uint16 b) external { feeBps = b; }
    function setWeiPerToken(uint256 w) external { weiPerToken = w; }
    function setRevertOnFeeBps(bool v) external { revertOnFeeBps = v; }
    function setRevertOnMinFee(bool v) external { revertOnMinFee = v; }
    function setFeeCollector(address payable c) external { feeCollector = c; }

    /// @dev The value, in native wei, of `amount` LEMNI wei — the quantity the 1% rule compares.
    function valueWei(uint256 amount) public view returns (uint256) {
        return (amount * weiPerToken) / 1e18;
    }

    function getFeeBps(uint256) external view returns (uint16) {
        require(!revertOnFeeBps, "oracle down");
        return feeBps;
    }

    function getMinFeeInWei(uint256 amount) external view returns (uint256) {
        require(!revertOnMinFee, "oracle down");
        return (valueWei(amount) * feeBps) / 10_000;
    }
}
