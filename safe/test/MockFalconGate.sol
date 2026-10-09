// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MockFalconGate — TEST ONLY
/// @notice Stands in for the ZKNOX ETHFALCON verifier in fork tests. Returns a
///         settable boolean so the vault's Falcon *gate wiring* (reject vs.
///         accept, ordering vs. the lock) can be proven without producing a
///         real Falcon-512 signature inside a JS test. The real cryptographic
///         verification is covered by ETHFALCON's own KAT test vectors and by
///         the deploy-time falconKey() check. NEVER deploy this to mainnet.
contract MockFalconGate {
    bool public result;

    function set(bool v) external {
        result = v;
    }

    function verify(bytes memory, bytes memory, uint256[] memory, uint256[] memory)
        external
        view
        returns (bool)
    {
        return result;
    }
}
