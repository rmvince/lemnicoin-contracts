# Deployed mainnet facet sources

The LEMNI Diamond on Polygon (`0x02011c7B7D9C6dfc563c92197557e8BE490a85b4`) is an EIP-2535 diamond with 24 facets. Eleven facets are built from the current source at the root of this repository. The twelve below are live on-chain at earlier versions of their source; each folder holds the exact source that reproduces the deployed runtime bytecode, plus the `standard-input.json` used to verify it on Polygonscan.

GovernanceFacet `0x535551A0b2eC14374242eED7196f2140cbBDB2AB` (cut in on 2026-11-06, governance nonce 14) is one of the eleven built from the root source. It caps `mint()` at 10,500,000 LEMNI, which is exactly the supply minted at genesis, so no LEMNI can ever be minted again. `maxSupply()` returns that cap on-chain. It replaced GovernanceFacet `0x0f66cf647B8446da308A3Ae3aC699Ca51Bc8D839` (1,000,000,000 cap, no getter), which no longer serves any function on the diamond. Both are verified on Polygonscan.

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

## 2026-11: circuit breaker v2 and a verifiable KeyManagementFacet

Ten contracts deployed and verified on Polygonscan (exact match) on 2026-11-11. Status: deployed, **awaiting the governance cut** (Gnosis Safe 2-of-3 + Falcon-512 signature, `diamondCutWithFalcon`). The cut is replace-only: the Diamond's 9 facets below take over exactly the functions of the facets they replace; nothing is added or removed. Until it executes, the facets in the table above (and TokenFacet and KeyManagementFacet at the repo root) remain the live ones.

What changes:

- **Circuit breaker v2** (`LibERC20._beforeTokenTransfer`): each token counts once per 24-hour window. LEMNI a wallet received in the current window and sends on is not counted again, so moving the same tokens back and forth between wallets can no longer add more to the window than the tokens actually moved. The threshold is unchanged at 1,100,000 LEMNI per 24 h. Two mappings are appended at the end of `AppStorage` (`cbReceivedWindow`, `cbReceived`); no existing storage moves. The breaker is compiled into every facet that moves tokens, so eight facets are rebuilt.
- **KeyManagementFacet**: the same executable code as `0xeD79D936AC4A8212500214361bF104e51ff9eF56`, rebuilt against a newly deployed `LAIPBigInt3072` library whose address is given to the compiler (`settings.libraries` in its `standard-input.json`), so facet and library verify as exact matches.

Each folder's `standard-input.json` is the exact compiler input the contract was built from; compiling it reproduces the deployed runtime bytecode byte for byte, metadata hash included. Source commit (private development repo): `779dfbd6`.

| Contract | Deployed address | Replaces |
|---|---|---|
| LAIPBigInt3072 (library) | `0x19672Af05925CDA00D61b062CD676D404d1dE108` | `0x3f7ce58bb476e8117bec8a5e7b6a217bf396ec97` |
| TokenFacet | `0x188a8999f082EF17e2B6539286AbD0D641dA985a` | `0xa17dFA47ceC417e9De49c8bBeE224A6A52A0FCA1` |
| SessionFacet | `0xd22c4Af3835137844a57b6769Bfd4224847084a5` | `0x5dFDd124b4f8a20aa86d48aB3E21737c82bB5749` |
| RecoveryFacet | `0x327E0A7DB099214581f483BE9bb190e68867a01c` | `0xd9649d57Cc7525d3916A83BD530852964f6A4260` |
| QuantumTransferFacet | `0x296438141AA79506f85F23Aab0074E31e7558Fb8` | `0x09BEb94Ab7D07e98440476b2A098077bC54A7421` |
| RingTransferFacet | `0x2Ca4f424dD16EA5F9e479739782680a95a0dc033` | `0x55D2b353C1D241b6D4E50010104269e26Fb573Bf` |
| LAIPV3TransferFacet | `0xf294C454A38BAF3E5F415e1E4bD3dF40Fa7A3a32` | `0x141Ad84D55a1293A299c15F99E24949f2D6A489C` |
| LAIPV3CapabilitiesFacet | `0x8003ecb5E52f3344b0BA094CB5b7C2d45fD40917` | `0x863bCE8E76F8b8cf22DaCb520dbE0783427d7517` |
| RingV3TransferFacet | `0x9d0eaC52678E12D1F67De5797Fb9Da5fD241eade` | `0x9929c2a360fE4Ac6DD4F58a3816DfaE95d44c828` |
| KeyManagementFacet | `0xfb9dC446439989FD6F8feCBBcf66476c82DFf15D` | `0xeD79D936AC4A8212500214361bF104e51ff9eF56` |

The repo-root `diamond/libraries/LibERC20.sol` and `LibAppStorage.sol` stay at the version the other live facets were built from; the v2 versions are in these folders' `src/`.

## Notes

KeyManagementFacet (`0xeD79D936AC4A8212500214361bF104e51ff9eF56`): its runtime code is reproduced exactly by the current source at the repo root when the external library `LAIPBigInt3072` is linked at `0x3f7ce58bb476e8117bec8a5e7b6a217bf396ec97`. Only its embedded metadata hash differs (that hash covers comments and file paths, not executable code), so Polygonscan has not yet accepted it as verified.

Note: LAIPV3TransferFacet was compiled with Hardhat-style source paths (`contracts/...`); its `standard-input.json` uses those paths so that the metadata hash matches exactly.
