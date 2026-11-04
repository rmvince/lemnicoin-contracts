// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title IZKNOXEthFalcon
 * @notice Interface for the ETHFALCON verifier contract
 * @dev Deployed and verified on OP Sepolia: 0x2F27b854B719921f03f30d1e5d0aE8e0aE7f96cA
 *
 * ETHFALCON provides on-chain Falcon-512 signature verification.
 * Gas cost: ~1.8M for verification
 *
 * See: https://github.com/ZKNoxHQ/ETHFALCON
 */
interface IZKNOXEthFalcon {
    /**
     * @notice Verify a Falcon-512 signature
     * @param h The 32-byte message hash that was signed
     * @param salt 40-byte salt/nonce used in signing
     * @param s2 Signature polynomial (uint256[32] for falcon_S256)
     * @param ntth Public key in NTT domain (uint256[32])
     * @return result True if signature is valid
     */
    function verify(
        bytes memory h,
        bytes memory salt,
        uint256[] memory s2,
        uint256[] memory ntth
    ) external view returns (bool result);
}
