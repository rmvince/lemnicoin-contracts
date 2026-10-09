// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IZKNOXEthFalcon} from "../../falcon/IZKNOXEthFalcon.sol";
import "../../../lib/ETHFALCON/src/ZKNOX_falcon_core.sol";
import "../../../lib/ETHFALCON/src/ZKNOX_HashToPoint.sol";

/// @title RealFalconVerifier — the ACTUAL ZKNOX ETHFALCON verification, deployable in tests.
/// @notice TEST ONLY, but the cryptography is real: `verify` is the body of ZKNOX_ethfalcon.verify,
///         calling the upstream `hashToPointRIP` and `falcon_core` unmodified. It exists only
///         because the upstream contract imports through a Foundry remapping we do not have here.
///
///         MockFalconVerifier proves the vault's ACCESS CONTROL. This proves the vault accepts real
///         Falcon signatures — specifically the ones the dApp produces in JavaScript — so the
///         holder-key path is verified end to end against the same code deployed on Polygon.
contract RealFalconVerifier is IZKNOXEthFalcon {
    /// @inheritdoc IZKNOXEthFalcon
    function verify(
        bytes memory h,
        bytes memory salt,
        uint256[] memory s2,
        uint256[] memory ntth
    ) external pure override returns (bool result) {
        if (salt.length != 40) return false;
        if (s2.length != 32) return false;
        if (ntth.length != 32) return false;

        uint256[] memory hashed = hashToPointRIP(salt, h);
        return falcon_core(s2, ntth, hashed);
    }
}
