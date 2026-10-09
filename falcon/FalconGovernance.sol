// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./IZKNOXEthFalcon.sol";

/**
 * @title FalconGovernance
 * @notice Mixin for quantum-resistant governance authorization via Falcon attestation
 * @author Lemnicoin Team
 *
 * @dev Security Model:
 * - Admin signs governance action with LAIP + ML-DSA (quantum-resistant) off-chain
 * - EC2 attestor verifies both signatures off-chain
 * - Attestor signs attestation with Falcon-512 (quantum-resistant)
 * - This contract verifies only the Falcon attestation
 *
 * Anti-Forgery Bindings (all included in signed digest):
 * - Chain binding: chainId in domain separator
 * - Contract binding: address(this) in domain separator
 * - Signer binding: admin address in struct
 * - Action binding: actionHash includes action type and parameters
 * - Replay protection: monotonic nonce per admin
 * - Expiry: deadline timestamp
 */
abstract contract FalconGovernance {

    // =========================================================================
    // CONFIGURATION
    // =========================================================================

    /// @notice ETHFALCON verifier contract (set in child constructor)
    IZKNOXEthFalcon public governanceFalconVerifier;

    /// @notice Governance attestor public key in NTT domain (32 uint256 values)
    uint256[32] public governanceAttestorNtth;

    /// @notice Whether governance Falcon verification is initialized
    bool public governanceFalconInitialized;

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Replay protection: monotonic nonce per admin for governance actions
    mapping(address => uint256) public governanceNonce;

    // =========================================================================
    // EIP-712 DOMAIN SEPARATION
    // =========================================================================

    bytes32 private constant GOV_EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 private constant GOV_ACTION_TYPEHASH =
        keccak256("GovernanceAction(address signer,bytes32 actionHash,uint256 nonce,uint256 deadline)");

    bytes32 private constant GOV_NAME_HASH = keccak256("LemnicoinGovernance");
    bytes32 private constant GOV_VERSION_HASH = keccak256("1");

    // =========================================================================
    // EVENTS
    // =========================================================================

    event GovernanceFalconVerified(
        address indexed signer,
        bytes32 actionHash,
        uint256 nonce
    );

    event GovernanceFalconInitialized(address verifier);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error GovernanceNotInitialized();
    error GovernanceAlreadyInitialized();
    error GovernanceAttestationExpired();
    error GovernanceInvalidNonce(uint256 expected, uint256 provided);
    error GovernanceInvalidSaltLength(uint256 length);
    error GovernanceInvalidS2Length(uint256 length);
    error GovernanceFalconVerificationFailed();
    error GovernanceZeroVerifier();

    // =========================================================================
    // INITIALIZATION (called by child contract)
    // =========================================================================

    /**
     * @notice Initialize governance Falcon verification
     * @param verifier Address of deployed ZKNOX_ethfalcon contract
     * @param attestorNtth32 Attestor's Falcon public key in NTT domain (32 elements)
     */
    function _initGovernanceFalcon(
        address verifier,
        uint256[32] memory attestorNtth32
    ) internal {
        if (governanceFalconInitialized) revert GovernanceAlreadyInitialized();
        if (verifier == address(0)) revert GovernanceZeroVerifier();

        governanceFalconVerifier = IZKNOXEthFalcon(verifier);

        for (uint256 i = 0; i < 32; i++) {
            governanceAttestorNtth[i] = attestorNtth32[i];
        }

        governanceFalconInitialized = true;
        emit GovernanceFalconInitialized(verifier);
    }

    // =========================================================================
    // DOMAIN SEPARATOR
    // =========================================================================

    /**
     * @notice Compute EIP-712 domain separator for governance
     */
    function _govDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                GOV_EIP712_DOMAIN_TYPEHASH,
                GOV_NAME_HASH,
                GOV_VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
    }

    /**
     * @notice Compute the governance action digest that the attestor signed
     */
    function _governanceDigest(
        address signer,
        bytes32 actionHash,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                GOV_ACTION_TYPEHASH,
                signer,
                actionHash,
                nonce,
                deadline
            )
        );

        return keccak256(
            abi.encodePacked("\x19\x01", _govDomainSeparator(), structHash)
        );
    }

    // =========================================================================
    // MAIN VERIFICATION FUNCTION
    // =========================================================================

    /**
     * @notice Verify Falcon attestation for a governance action
     * @param signer The admin performing the action
     * @param action The action name (e.g., "MINT", "PAUSE")
     * @param payload The action parameters encoded
     * @param nonce Must equal governanceNonce[signer]
     * @param deadline Unix timestamp after which attestation is invalid
     * @param falconSalt40 40-byte salt from Falcon signature
     * @param falconS2 32 uint256 values - signature polynomial
     */
    function _requireFalconGovernance(
        address signer,
        string memory action,
        bytes memory payload,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2
    ) internal {
        if (!governanceFalconInitialized) revert GovernanceNotInitialized();

        // Check deadline
        if (block.timestamp > deadline) {
            revert GovernanceAttestationExpired();
        }

        // Check nonce
        uint256 expectedNonce = governanceNonce[signer];
        if (nonce != expectedNonce) {
            revert GovernanceInvalidNonce(expectedNonce, nonce);
        }

        // Validate signature format
        if (falconSalt40.length != 40) {
            revert GovernanceInvalidSaltLength(falconSalt40.length);
        }
        if (falconS2.length != 32) {
            revert GovernanceInvalidS2Length(falconS2.length);
        }

        // Compute action hash
        bytes32 actionHash = keccak256(abi.encodePacked(action, payload));

        // Compute the digest (must match what attestor signed)
        bytes32 digest = _governanceDigest(signer, actionHash, nonce, deadline);

        // Verify Falcon signature
        bool valid = governanceFalconVerifier.verify(
            abi.encodePacked(digest),
            falconSalt40,
            _govToMemoryArray(falconS2),
            _getGovAttestorNtth()
        );

        if (!valid) {
            revert GovernanceFalconVerificationFailed();
        }

        // Consume nonce AFTER verification
        governanceNonce[signer] = nonce + 1;

        emit GovernanceFalconVerified(signer, actionHash, nonce);
    }

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================

    /**
     * @dev Get attestor NTTH as dynamic memory array for verifier call
     */
    function _getGovAttestorNtth() internal view returns (uint256[] memory) {
        uint256[] memory result = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            result[i] = governanceAttestorNtth[i];
        }
        return result;
    }

    /**
     * @dev Convert calldata array to dynamic memory array
     */
    function _govToMemoryArray(uint256[] calldata arr) internal pure returns (uint256[] memory) {
        uint256[] memory result = new uint256[](32);
        for (uint256 i = 0; i < 32 && i < arr.length; i++) {
            result[i] = arr[i];
        }
        return result;
    }

    /**
     * @notice Update governance attestor public key (only owner can call)
     * @dev Override in child contract to add access control
     */
    function _updateGovernanceAttestorKey(uint256[32] memory newNtth) internal {
        for (uint256 i = 0; i < 32; i++) {
            governanceAttestorNtth[i] = newNtth[i];
        }
    }
}
