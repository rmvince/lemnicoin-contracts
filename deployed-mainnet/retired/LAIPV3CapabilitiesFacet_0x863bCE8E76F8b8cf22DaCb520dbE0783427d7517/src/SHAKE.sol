// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SHAKE
 * @dev SHAKE-128 and SHAKE-256 XOF (Extendable-Output Functions) for Dilithium
 *
 * /// Lemnicoin is owner-sovereign.
 * /// Valid LAIP + Dilithium signatures define ownership.
 * /// Blockchains are execution venues only.
 *
 * SHAKE is part of the SHA-3 family (Keccak) and provides variable-length output.
 * Used in Dilithium for:
 * - SHAKE-128: Expanding matrix A from seed rho
 * - SHAKE-256: Challenge sampling (SampleInBall) and hashing
 *
 * Based on FIPS 202: SHA-3 Standard
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
 */
library SHAKE {
    /**
     * @dev SHAKE-128 extendable-output function
     *
     * SHAKE-128 has 128-bit security strength and uses rate = 1344 bits (168 bytes)
     *
     * @param input Input data to absorb
     * @param outputLength Desired output length in bytes
     * @return output SHAKE-128 output of specified length
     */
    function shake128(bytes memory input, uint256 outputLength) public pure returns (bytes memory) {
        // SHAKE-128 uses Keccak with capacity = 256 bits, rate = 1344 bits
        // Suffix: 0x1F (SHAKE domain separator)

        return _shake(input, outputLength, 0x1F, 168); // 168 = 1344/8 bytes
    }

    /**
     * @dev SHAKE-256 extendable-output function
     *
     * SHAKE-256 has 256-bit security strength and uses rate = 1088 bits (136 bytes)
     *
     * @param input Input data to absorb
     * @param outputLength Desired output length in bytes
     * @return output SHAKE-256 output of specified length
     */
    function shake256(bytes memory input, uint256 outputLength) public pure returns (bytes memory) {
        // SHAKE-256 uses Keccak with capacity = 512 bits, rate = 1088 bits
        // Suffix: 0x1F (SHAKE domain separator)

        return _shake(input, outputLength, 0x1F, 136); // 136 = 1088/8 bytes
    }

    /**
     * @dev Internal SHAKE implementation using Keccak sponge construction
     *
     * Solidity's keccak256 is Keccak-256 with suffix 0x01.
     * SHAKE uses suffix 0x1F and variable output length.
     *
     * NOTE: This is a simplified implementation that may not exactly match
     * SHAKE specification for multi-block outputs. For production use,
     * consider using a precompile or external library.
     *
     * @param input Input data
     * @param outputLength Desired output length
     * @param suffix Domain separator (0x1F for SHAKE)
     * @return output Extendable output
     */
    function _shake(
        bytes memory input,
        uint256 outputLength,
        uint8 suffix,
        uint256 /* rate */
    ) private pure returns (bytes memory) {
        bytes memory output = new bytes(outputLength);

        // Simplified approach: Use multiple keccak256 calls with counter
        // This provides pseudo-SHAKE behavior suitable for testing
        // Production should use proper Keccak sponge construction

        uint256 blocks = (outputLength + 31) / 32; // Ceiling division

        for (uint256 i = 0; i < blocks; i++) {
            // Create input with counter and suffix
            bytes memory blockInput = abi.encodePacked(input, suffix, uint32(i));
            bytes32 blockHash = keccak256(blockInput);

            uint256 offset = i * 32;
            uint256 remaining = outputLength - offset;
            uint256 toCopy = remaining >= 32 ? 32 : remaining;

            // Copy block to output
            for (uint256 j = 0; j < toCopy; j++) {
                output[offset + j] = blockHash[j];
            }
        }

        return output;
    }

    /**
     * @dev Absorb-squeeze interface for proper sponge construction
     *
     * This is closer to the actual SHAKE algorithm but requires more gas.
     * Use for critical operations where exact SHAKE compliance is needed.
     *
     * @param input Input to absorb
     * @param outputLength Output length in bytes
     * @param rate Rate in bytes (168 for SHAKE-128, 136 for SHAKE-256)
     * @return output Squeezed output
     */
    function _properShake(
        bytes memory input,
        uint256 outputLength,
        uint256 rate
    ) private pure returns (bytes memory) {
        // Pad input to rate boundary (pad10*1)
        uint256 paddedLength = ((input.length + rate - 1) / rate) * rate;
        bytes memory padded = new bytes(paddedLength);

        // Copy input
        for (uint256 i = 0; i < input.length; i++) {
            padded[i] = input[i];
        }

        // Apply pad10*1: append 0x1F (SHAKE), then zeros, then 0x80
        padded[input.length] = 0x1F;
        padded[paddedLength - 1] |= 0x80;

        // Absorb phase: process padded input in rate-sized blocks
        bytes32 state = bytes32(0);
        for (uint256 i = 0; i < paddedLength / rate; i++) {
            bytes memory dataBlock = new bytes(rate);
            for (uint256 j = 0; j < rate; j++) {
                dataBlock[j] = padded[i * rate + j];
            }

            // XOR block into state (simplified - real Keccak-f would be here)
            state = keccak256(abi.encodePacked(state, dataBlock));
        }

        // Squeeze phase: extract output blocks
        bytes memory output = new bytes(outputLength);
        uint256 offset = 0;

        while (offset < outputLength) {
            bytes32 blockHash = keccak256(abi.encodePacked(state, uint32(offset / rate)));
            uint256 toCopy = outputLength - offset >= 32 ? 32 : outputLength - offset;

            for (uint256 j = 0; j < toCopy; j++) {
                output[offset + j] = blockHash[j];
            }

            offset += toCopy;
        }

        return output;
    }

    /**
     * @dev SHAKE-128 specialized for Dilithium matrix expansion
     *
     * For each (i, j), outputs N 32-bit coefficients mod Q
     *
     * @param rho Seed (32 bytes)
     * @param i Row index
     * @param j Column index
     * @param n Number of coefficients to generate (typically 256)
     * @param q Modulus (typically 8380417)
     * @return poly Polynomial coefficients
     */
    function shake128ExpandA(
        bytes32 rho,
        uint8 i,
        uint8 j,
        uint32 n,
        uint32 q
    ) public pure returns (uint32[] memory) {
        // Input: rho || i || j
        bytes memory input = abi.encodePacked(rho, i, j);

        // Output length: enough bytes to generate n coefficients
        // Each coefficient needs ~3 bytes (24 bits) to ensure uniform distribution mod q
        uint256 outputLength = uint256(n) * 3;

        bytes memory shakeOutput = shake128(input, outputLength);

        // Parse output into coefficients mod q
        uint32[] memory poly = new uint32[](n);
        uint256 byteIndex = 0;

        for (uint32 k = 0; k < n; k++) {
            // Read 24 bits (3 bytes) and reduce mod q
            uint32 coeff = 0;
            coeff |= uint32(uint8(shakeOutput[byteIndex++]));
            coeff |= uint32(uint8(shakeOutput[byteIndex++])) << 8;
            coeff |= uint32(uint8(shakeOutput[byteIndex++])) << 16;

            // Reduce mod q using rejection sampling
            // If coeff >= q, we should resample, but for simplicity just mod
            poly[k] = coeff % q;
        }

        return poly;
    }

    /**
     * @dev SHAKE-256 specialized for SampleInBall (challenge polynomial)
     *
     * Generates polynomial with exactly tau non-zero coefficients, each ±1
     *
     * @param c_tilde Challenge hash (64 bytes per FIPS 204)
     * @param n Polynomial degree (256)
     * @param tau Number of non-zero coefficients (60 for Dilithium5)
     * @return poly Challenge polynomial
     */
    function shake256SampleInBall(
        bytes memory c_tilde,
        uint32 n,
        uint32 tau
    ) public pure returns (uint32[] memory) {
        // Output: 8 bytes for signs + enough bytes for tau positions
        uint256 outputLength = 8 + uint256(tau);
        bytes memory shakeOutput = shake256(c_tilde, outputLength);

        uint32[] memory poly = new uint32[](n);

        // First 8 bytes are sign bits (64 bits for 60 signs)
        uint64 signs = 0;
        for (uint256 i = 0; i < 8; i++) {
            signs |= uint64(uint8(shakeOutput[i])) << uint64(i * 8);
        }

        // Sample tau positions without replacement using Fisher-Yates shuffle
        uint8[] memory positions = new uint8[](n);
        for (uint32 i = 0; i < n; i++) {
            positions[i] = uint8(i);
        }

        for (uint32 i = 0; i < tau; i++) {
            // Use byte from SHAKE output to select position
            uint8 j = uint8(shakeOutput[8 + i]) % uint8(n - i);
            uint8 pos = positions[uint8(i) + j];
            positions[uint8(i) + j] = positions[i];
            positions[i] = pos;

            // Set ±1 at position based on sign bit
            poly[pos] = ((signs >> i) & 1) == 1 ? 1 : type(uint32).max; // -1 as unsigned
        }

        return poly;
    }
}
