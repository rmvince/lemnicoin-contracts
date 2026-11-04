# Deployed mainnet facet sources

The LEMNI Diamond on Polygon (`0x02011c7B7D9C6dfc563c92197557e8BE490a85b4`) is an EIP-2535 diamond with 24 facets. Eleven facets are built from the current source at the root of this repository. The twelve below are live on-chain at earlier versions of their source; each folder holds the exact source that reproduces the deployed runtime bytecode, plus the `standard-input.json` used to verify it on Polygonscan.

Compiler for all: solc 0.8.25, optimizer enabled, runs = 1, viaIR, EVM version cancun. OpenZeppelin Contracts 4.9.6 and Chainlink Contracts 1.2.0 are imported by some facets and are included in each `standard-input.json`.

| Facet | Deployed address | Source date | Source commit (private development repo) |
|---|---|---|---|
| LAIPV3CapabilitiesFacet | `0x863bCE8E76F8b8cf22DaCb520dbE0783427d7517` | 2026-09-28 | `6cd080e3f9` |
| LAIPV3TransferFacet | `0x141Ad84D55a1293A299c15F99E24949f2D6A489C` | 2026-09-28 | `6cd080e3f9` |
| QuantumBurnFacet | `0xd273ae6D6d00F37acC99c48F1fB50082B70B513C` | 2026-09-26 | `6e9db5fdda` |
| QuantumTransferFacet | `0x09BEb94Ab7D07e98440476b2A098077bC54A7421` | 2026-09-28 | `6cd080e3f9` |
| RecoveryFacet | `0xd9649d57Cc7525d3916A83BD530852964f6A4260` | 2026-09-28 | `6cd080e3f9` |
| RingTransferFacet | `0x55D2b353C1D241b6D4E50010104269e26Fb573Bf` | 2026-09-28 | `6cd080e3f9` |
| RingV3TransferFacet | `0x9929c2a360fE4Ac6DD4F58a3816DfaE95d44c828` | 2026-09-28 | `6cd080e3f9` |
| SessionFacet | `0x5dFDd124b4f8a20aa86d48aB3E21737c82bB5749` | 2026-09-28 | `6cd080e3f9` |
| TimeLockFacet | `0x92Fe5D93a416D109Cc8e7448545e23A472583640` | 2026-04-08 | `df58846765` |
| VestingFacet | `0x3Fd53Fc1b7d000b1B6DDaA765Ae5fA64c849D474` | 2026-09-26 | `6e9db5fdda` |
| VestingFacet | `0xaf0482CAdc57c2e0135Cb3647e19774e5F395C6B` | 2026-04-24 | `056560e4d4` |
| VestingFacet | `0x89a1F4d8C1a3aAC028412D0078990D094c07d49c` | 2026-04-08 | `df58846765` |

KeyManagementFacet (`0xeD79D936AC4A8212500214361bF104e51ff9eF56`): its runtime code is reproduced exactly by the current source at the repo root when the external library `LAIPBigInt3072` is linked at `0x3f7ce58bb476e8117bec8a5e7b6a217bf396ec97`. Only its embedded metadata hash differs (that hash covers comments and file paths, not executable code), so Polygonscan has not yet accepted it as verified.

Note: LAIPV3TransferFacet was compiled with Hardhat-style source paths (`contracts/...`); its `standard-input.json` uses those paths so that the metadata hash matches exactly.
