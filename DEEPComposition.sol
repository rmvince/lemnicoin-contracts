// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./STARK252Field.sol";

/**
 * @title DEEPComposition
 * @notice DEEP polynomial composition verification utilities
 * @dev Simplified implementation for stack-depth compatibility
 */
library DEEPComposition {
    using STARK252Field for uint256;

    uint256 constant K_MODULUS = 0x800000000000011000000000000000000000000000000000000000000000001;
    uint256 constant GENERATOR = 3;

    /**
     * @notice Generate OOD point via Fiat-Shamir
     */
    function generateOODPoint(
        bytes32 traceCommitment,
        bytes32 constraintCommitment
    ) internal pure returns (uint256) {
        bytes32 hash = keccak256(abi.encodePacked(traceCommitment, constraintCommitment, "ood_point"));
        return uint256(hash) % K_MODULUS;
    }

    /**
     * @notice Generate DEEP coefficients via Fiat-Shamir
     */
    function generateDEEPCoeffs(
        bytes32 traceCommitment,
        bytes32 constraintCommitment,
        uint256 oodPoint,
        uint256 numColumns
    ) internal pure returns (uint256[] memory coeffs) {
        uint256 totalCoeffs = 2 * numColumns + 1;
        coeffs = new uint256[](totalCoeffs);

        bytes memory seed = abi.encodePacked(traceCommitment, constraintCommitment, oodPoint, "deep_coeffs");

        for (uint256 i = 0; i < totalCoeffs; i++) {
            bytes32 hash = keccak256(abi.encodePacked(seed, uint32(i)));
            coeffs[i] = uint256(hash) % K_MODULUS;
        }

        return coeffs;
    }

    /**
     * @notice Compute trace domain generator
     */
    function computeTraceGenerator(
        uint256 traceLength,
        uint256 blowupFactor
    ) internal view returns (uint256) {
        uint256 ldeSize = traceLength * blowupFactor;
        uint256 omegaLDE = STARK252Field.modExp(GENERATOR, (K_MODULUS - 1) / ldeSize);
        return STARK252Field.modExp(omegaLDE, blowupFactor);
    }

    /**
     * @notice Evaluate zerofier at point
     */
    function evaluateZerofier(uint256 x, uint256 traceLength) internal view returns (uint256) {
        uint256 xPowN = STARK252Field.modExp(x, traceLength);
        return STARK252Field.sub(xPowN, 1);
    }
}
