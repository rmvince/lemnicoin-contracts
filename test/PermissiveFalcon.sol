// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IZKNOXEthFalcon} from "../falcon/IZKNOXEthFalcon.sol";

/// @title PermissiveFalcon — TEST ONLY Falcon verifier that accepts any well-formed signature.
/// @notice Used by the V3 integration test to exercise facet LOGIC (the quantum gate, V3 registration,
///         and best-effort SLH) without reconstructing real Falcon signatures. Real Falcon binding is
///         covered by the existing dual/holder-key tests and the live ZKNOX verifier in production.
contract PermissiveFalcon is IZKNOXEthFalcon {
    function verify(bytes memory h, bytes memory salt, uint256[] memory s2, uint256[] memory ntth)
        external pure override returns (bool)
    {
        return h.length == 32 && salt.length == 40 && s2.length == 32 && ntth.length == 32;
    }
}
