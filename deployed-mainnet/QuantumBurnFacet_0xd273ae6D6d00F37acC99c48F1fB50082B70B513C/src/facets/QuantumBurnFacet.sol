// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../diamond/Modifiers.sol";
import {LibERC20} from "../diamond/libraries/LibERC20.sol";
import {LibLemnicoin, HolderFalconSig} from "../diamond/libraries/LibLemnicoin.sol";
import "../crypto/LAIPOnCurve.sol";
import {LibSlhEconomics} from "../diamond/libraries/LibSlhEconomics.sol";

/**
 * @title QuantumBurnFacet
 * @notice Diamond facet that adds quantum-resistant token burning
 * @dev CRITICAL SECURITY UPGRADE: Prevents stolen wallets from maliciously burning tokens
 *
 * This facet adds the quantumBurn() function to existing Lemnicoin Diamond deployments.
 * It requires the same triple quantum signature verification as quantumTransfer():
 * 1. LAIP-3072 signature (lemniscate curve)
 * 2. ML-DSA-87 signature (NIST FIPS 204)
 * 3. Falcon-512 attestation (NIST FIPS 205)
 *
 * Usage:
 * 1. Deploy this facet
 * 2. Add to Diamond using diamondCut()
 * 3. Existing contract address stays the same
 * 4. quantumBurn() becomes available immediately
 */
contract QuantumBurnFacet is Modifiers {

    /**
     * @notice Burn tokens with quantum signature verification
     * @dev SECURITY: Prevents stolen wallets from burning user tokens.
     *      Requires same Falcon attestation + LAIP verification as quantumTransfer.
     *
     *      ATTESTOR-ONLY, so it is CLOSED to accounts that have registered their own Falcon key —
     *      those use `quantumBurnDual`.
     * @param amount Amount of tokens to permanently destroy
     * @param quantumInputHash Hash of quantum signature inputs
     * @param nonce Attestation nonce (must match pqAttestationNonce[msg.sender])
     * @param deadline Expiration timestamp for attestation
     * @param falconSalt40 Falcon signature salt (40 bytes)
     * @param falconS2_32 Falcon signature s2 component (32 uint256 values)
     * @param laipPk LAIP public key for on-chain curve validation
     * @return bool Success indicator
     */
    function quantumBurn(
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        LAIPOnCurve.LAIPPublicKey calldata laipPk
    ) external payable whenNotPaused nonReentrant returns (bool) {
        LibSlhEconomics.requireNotV3Downgrade(s, msg.sender); // NO-DOWNGRADE: see LibSlhEconomics
        // First, so that probing whether this path is closed gives AttestorOnlyPathClosed rather
        // than whichever earlier precondition happens to fail. The library re-checks it anyway.
        LibLemnicoin.requireAttestorOnlyAllowed(s, msg.sender);

        require(amount > 0, "Zero amount");

        // LAIP verification (same as quantumTransfer)
        LibLemnicoin.requireLaipVerification(msg.sender, laipPk);

        // Collect protocol fee
        LibLemnicoin.collectProtocolFee(amount);

        // Verify Falcon attestation for burn operation
        LibLemnicoin.verifyFalconAttestationForBurn(
            msg.sender,
            amount,
            quantumInputHash,
            nonce,
            deadline,
            falconSalt40,
            falconS2_32
        );

        // Execute burn
        LibERC20._burn(msg.sender, amount);

        return true;
    }

    /**
     * @notice The same burn, requiring BOTH the attestor's Falcon signature and the holder's own.
     * @dev Burning is not theft, but it is still an irreversible loss inflicted on someone else's
     *      balance, so a compromised attestor key must not be able to do it either. `quantumBurn`
     *      above is attestor-only and is therefore closed to accounts that have registered a Falcon
     *      key — this is the path they use.
     * @param holderSig The holder's Falcon salt, s2 and registered public key.
     */
    function quantumBurnDual(
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        HolderFalconSig calldata holderSig,
        LAIPOnCurve.LAIPPublicKey calldata laipPk
    ) external payable whenNotPaused nonReentrant returns (bool) {
        LibSlhEconomics.requireNotV3Downgrade(s, msg.sender); // NO-DOWNGRADE: see LibSlhEconomics
        require(amount > 0, "Zero amount");

        LibLemnicoin.requireLaipVerification(msg.sender, laipPk);
        LibLemnicoin.collectProtocolFee(amount);

        LibLemnicoin.verifyDualFalconAttestationForBurn(
            msg.sender,
            amount,
            quantumInputHash,
            nonce,
            deadline,
            falconSalt40,
            falconS2_32,
            holderSig
        );

        LibERC20._burn(msg.sender, amount);

        return true;
    }
}
