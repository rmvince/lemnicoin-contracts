// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title LemnicoinLib
 * @notice External library to reduce Lemnicoin contract bytecode size.
 * Functions here are deployed as a separate contract and called via DELEGATECALL,
 * so they execute in the storage context of the calling contract.
 */
library LemnicoinLib {
    // Custom errors (must match Lemnicoin.sol)
    error InvalidLAIPProofLength();
    error InvalidDilithiumProofLength();
    error LAIPKeySizeMismatch();
    error InvalidFalconSigLength();

    /**
     * @dev Split a packed Falcon signature into salt and s2 components
     * @param falconSig Packed signature (40 bytes salt + 32*32 bytes s2)
     * @return salt 40-byte Falcon salt
     * @return s2 32-element uint256 array of signature polynomial
     */
    function splitFalconSig(bytes calldata falconSig)
        external
        pure
        returns (bytes memory salt, uint256[] memory s2)
    {
        uint256 expectedLength = 40 + 32 * 32;
        if (falconSig.length != expectedLength) revert InvalidFalconSigLength();

        salt = new bytes(40);
        for (uint256 i = 0; i < 40; i++) {
            salt[i] = falconSig[i];
        }

        s2 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            uint256 offset = 40 + i * 32;
            uint256 value;
            assembly {
                value := calldataload(add(falconSig.offset, offset))
            }
            s2[i] = value;
        }
    }

    /**
     * @dev Verify binding proof structure (lightweight, no cryptographic verification)
     * @param proofLen Length of LAIP proof
     * @param dilithiumProofLen Length of Dilithium proof
     * @param qxLen Length of Qx coordinate
     * @param qyLen Length of Qy coordinate
     * @param p0xLen Length of P0x coordinate
     * @param p0yLen Length of P0y coordinate
     * @param aLen Length of a parameter
     * @param pLen Length of p parameter
     */
    function verifyBindingProofStructure(
        uint256 proofLen,
        uint256 dilithiumProofLen,
        uint256 qxLen,
        uint256 qyLen,
        uint256 p0xLen,
        uint256 p0yLen,
        uint256 aLen,
        uint256 pLen
    ) external pure {
        // Support both 2048-bit and 3072-bit LAIP proofs
        if (proofLen != 801 && proofLen != 1185) revert InvalidLAIPProofLength();
        if (dilithiumProofLen < 4500 || dilithiumProofLen > 4700) revert InvalidDilithiumProofLength();

        // Determine expected coordinate size from proof length
        uint256 coordSize;
        if (proofLen == 801) {
            coordSize = 256; // 2048-bit LAIP
        } else {
            coordSize = 384; // 3072-bit LAIP
        }

        // Verify public key coordinate lengths match the proof size
        if (
            qxLen != coordSize ||
            qyLen != coordSize ||
            p0xLen != coordSize ||
            p0yLen != coordSize ||
            aLen != coordSize ||
            pLen != coordSize
        ) revert LAIPKeySizeMismatch();
    }

    /**
     * @dev Compute vested amount for a beneficiary
     * @param totalAmount Total tokens in vesting schedule
     * @param startTime Vesting start timestamp
     * @param cliffDuration Cliff period in seconds
     * @param vestingDuration Linear vesting duration in seconds
     * @return Amount of tokens vested
     */
    function computeVestedAmount(
        uint256 totalAmount,
        uint256 startTime,
        uint256 cliffDuration,
        uint256 vestingDuration
    ) external view returns (uint256) {
        if (totalAmount == 0) return 0;
        if (block.timestamp < startTime) return 0;

        uint256 elapsed = block.timestamp - startTime;
        if (elapsed < cliffDuration) return 0;

        uint256 vestingElapsed = elapsed - cliffDuration;
        if (vestingElapsed >= vestingDuration) return totalAmount;

        return (totalAmount * vestingElapsed) / vestingDuration;
    }
}
