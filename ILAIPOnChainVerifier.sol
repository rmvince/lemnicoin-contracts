// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ILAIPOnChainVerifier
 * @notice Interface for LAIPOnChainVerifier - Flipped Architecture Dual-Key Proof
 */
interface ILAIPOnChainVerifier {
    struct LAIPDomainParams {
        bytes p;
        bytes a;
        bytes P0x;
        bytes P0y;
    }

    struct DualKeyEnvelope {
        bytes laipSignature;
        bytes dilithiumSignature;
        bytes dilithiumPk;
        bytes message;
        bytes Qx;
        bytes Qy;
        LAIPDomainParams domainParams;
		bytes Rx;    
		bytes Ry;     
        bytes sP0_u;
        bytes sP0_v;
        bytes ReQ_u;
        bytes ReQ_v;
	    bytes32 eHash; 
    }

    function verifyDualKeySignature(
        address signer,
        DualKeyEnvelope calldata envelope
    ) external returns (bool valid);

    function verifyDualKeySignatureOnce(
        address signer,
        DualKeyEnvelope calldata envelope
    ) external returns (bool valid);

    function isIdentityValid(address _addr) external view returns (bool registered, bool active);
}
