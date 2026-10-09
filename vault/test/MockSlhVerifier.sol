// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice Key- and message-bound stand-in for SlhDsaVerifierV2, so a lockbox suite can drive the
///         vault's SLH POLICY without the ~1.2M-gas real verification in every case.
///
/// @dev Bound to (pk, message, sig) exactly — `authorize` must be called with the same triple the
///      vault will present, so a test that authorizes the wrong mu FAILS. That is deliberate: it
///      makes these tests a check on what the vault computes mu over, not merely on whether it
///      called a verifier. Real FIPS 205 verification is proven in SlhDsaVerifierV2.test.js.
contract MockSlhVerifier {
    mapping(bytes32 => bool) private _ok;

    function _k(bytes calldata pk, bytes calldata message, bytes calldata sig) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(keccak256(pk), keccak256(message), keccak256(sig)));
    }

    function authorize(bytes calldata pk, bytes calldata message, bytes calldata sig) external {
        _ok[_k(pk, message, sig)] = true;
    }

    function verify(bytes calldata pk, bytes calldata message, bytes calldata sig)
        external view returns (bool)
    {
        return _ok[_k(pk, message, sig)];
    }
}
