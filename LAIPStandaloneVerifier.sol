// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "./LAIPFullSignatureVerifier.sol";
import "./LAIPBigInt.sol";
/**
 * @title LAIPStandaloneVerifier
 * @notice Isolated harness for full LAIP signature verification logic.
 * @dev Uses the standalone `LAIPFullSignatureVerifier` library to validate a
 *      complete LAIP signature (structure, curve membership, hash consistency,
 *      and Schnorr relation `s*P0 = R ⊕ e*Q`) without touching existing production
 *      flows. This gives the dApp an entry point to submit a packed signature,
 *      message bytes, and LAIP public parameters for on-chain validation.
 */
contract LAIPStandaloneVerifier {
    /**
     * @notice Verify a packed LAIP signature against the provided public key
     *         and message.
     * @dev Forwards to `LAIPFullSignatureVerifier.verify`, which performs:
     *      - Length validation for all coordinates and modulus
     *      - Curve membership for R and Q
     *      - Hash consistency (recomputes e)
     *      - Signature relationship check `s*P0 = R ⊕ e*Q`
 *
     *      Reverts with the library's custom errors on failure. Because the
     *      call is `view`, it can be used from off-chain clients to preflight
     *      verification before submitting a transaction.
     * @param signature Packed LAIP signature bytes: Rx || Ry || s (833 bytes).
     * @param message Arbitrary message bytes that were allegedly signed.
     * @param publicKey LAIP public key (Q, P0, a, p) to verify against.
     * @return valid True if all verification steps pass.
     */
    function verify(
        bytes calldata signature,
        bytes calldata message,
        LAIPFullSignatureVerifier.LAIPPublicKey calldata publicKey
    ) external view returns (bool valid) {
        LAIPFullSignatureVerifier.LAIPSignature memory sig =
            LAIPFullSignatureVerifier.decodeSignature(signature);
        bytes32 messageHash = keccak256(message);
		return LAIPFullSignatureVerifier.verifyLAIP(
			publicKey,
			sig,
			messageHash
		);
    }
    /**
     * @notice Test helper: check if point (x, y) is on the lemniscate curve
     * @dev Exposed for testing purposes
     */
    function isOnCurve(
        bytes memory x,
        bytes memory y,
        bytes memory a,
        bytes memory p
    ) external view returns (bool) {
        return LAIPFullSignatureVerifier.isOnCurve(x, y, a, p);
    }
    /**
     * @notice Debug: compute x^2 mod p
     */
    function debugModExp(bytes memory base, bytes memory exp, bytes memory mod) external view returns (bytes memory) {
        return LAIPBigInt.modExp(base, exp, mod);
    }
    /**
     * @notice Debug: compute (a + b) mod p
     */
    function debugModAdd(bytes memory a, bytes memory b, bytes memory mod) external view returns (bytes memory) {
        return LAIPBigInt.modAdd(a, b, mod);
    }
    /**
     * @notice Debug: compute (a - b) mod p
     */
    function debugModSub(bytes memory a, bytes memory b, bytes memory mod) external view returns (bytes memory) {
        return LAIPBigInt.modSub(a, b, mod);
    }
    /**
     * @notice Debug: compute (a * b) mod p
     */
    function debugModMul(bytes memory a, bytes memory b, bytes memory mod) external view returns (bytes memory) {
        return LAIPBigInt.modMul(a, b, mod);
    }
    /**
     * @notice Debug: check if a == b
     */
    function debugEq(bytes memory a, bytes memory b) external pure returns (bool) {
        return LAIPBigInt.eq(a, b);
    }
}
