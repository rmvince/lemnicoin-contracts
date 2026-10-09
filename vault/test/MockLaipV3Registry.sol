// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {ILaipV3Registry} from "../interfaces/ILaipV3Registry.sol";

/// @notice Test double for the LEMNI Diamond's LAIP-V3 registry, so a lockbox suite can drive the
///         hash-family factor without cutting a whole Diamond.
contract MockLaipV3Registry is ILaipV3Registry {
    struct Keys { bytes32 curveHash; bytes32 slhdsaPkHash; bytes32 mldsaPkHash; bytes32 paramId; bool registered; }
    mapping(address => Keys) private _keys;
    address private _verifier;

    function setVerifier(address v) external { _verifier = v; }

    function register(address account, bytes32 curveHash, bytes32 slhdsaPkHash) external {
        _keys[account] = Keys(curveHash, slhdsaPkHash, bytes32(0), bytes32(0), true);
    }

    function getLaipV3Keys(address account)
        external view override
        returns (bytes32, bytes32, bytes32, bytes32, bool)
    {
        Keys storage k = _keys[account];
        return (k.curveHash, k.slhdsaPkHash, k.mldsaPkHash, k.paramId, k.registered);
    }

    function slhDsaVerifier() external view override returns (address) { return _verifier; }
}
