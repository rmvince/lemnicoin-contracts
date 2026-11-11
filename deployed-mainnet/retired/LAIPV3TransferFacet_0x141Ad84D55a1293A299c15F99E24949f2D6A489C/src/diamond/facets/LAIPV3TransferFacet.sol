// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {AppStorage, LaipV3Keys, LibAppStorage} from "../libraries/LibAppStorage.sol";
import {LibERC20} from "../libraries/LibERC20.sol";
import {LibLemnicoin, HolderFalconSig} from "../libraries/LibLemnicoin.sol";
import {LibSlhEconomics, LaipV3SlhKeyMismatch, SlhDsaVerificationFailed} from "../libraries/LibSlhEconomics.sol";
import {SlhDsaVerifier} from "../../crypto/SlhDsaVerifier.sol";

error LaipV3NotRegistered();
error LaipV3AmountZero();
error LaipV3ApprovalExceedsBalance(uint256 amount, uint256 balance);
error InsufficientGasProvisioned(uint256 provided, uint256 required);

/// @title LAIPV3TransferFacet — V3-native transfers; Falcon is the floor, Lemniscate is best-effort
/// @notice V3 wallets register V3 keys (curve/SLH/ML-DSA hashes) instead of V2 LAIP, so they use these
///         V3-native entrypoints. Two paths, and the expensive on-chain SLH-DSA (LOS) check can NEVER
///         block a transfer:
///
///         DESIGN (per product requirement) — decided by whether the attestor is up, with the SLH
///         factor REQUIRED on both paths (the optimized ~1.2M verifier fits any real chain's
///         blocks, so the old block-gas-limit auto-relax is RETIRED):
///
///           attestor UP    quantumTransferV3Dual: holder Falcon + on-chain SLH
///                          + attestor Falcon                        (all three, ~5.0M on Polygon)
///           attestor DOWN  quantumTransferV3: holder Falcon + on-chain SLH   (~3.1M on Polygon)
///
///         STRICT means missing/invalid/out-of-gas SLH all revert. A sender-starved transaction
///         gas limit reverts their own transfer, never downgrades it. The Falcon floor remains
///         reachable two ways only: the owner's emergency setLaipV3RelaxSlh override (e.g. a
///         verifier defect found post-deploy), and the per-transfer ECONOMIC exemption (the 1%
///         rule) for amounts too small to be worth the verify.
///         And with NO quantum keys registered at all, the wallet is an ordinary ERC-20 (the
///         TokenFacet gate stays open) — none of this applies until the holder opts in.
///         The `slhVerified` flag in the event records whether the hash-family factor was actually
///         checked; it is never forgeable to true.
///
///         In the Dual path the attestor already verified CSIDH possession + SLH-DSA + ML-DSA off chain,
///         so on-chain it is the two Falcons. The on-chain SLH-DSA is the value-add precisely when the
///         attestor is ABSENT — the attestor-independent path below.
contract LAIPV3TransferFacet is Modifiers {

    // The chain-gas rule, its constants and the verification itself all live in LibSlhEconomics —
    // ONE definition shared by every V3 facet (transfers, approvals, recovery, CEX sessions, burn),
    // so the security rule cannot drift between operations.

    /// @dev `slhVerified` records whether the best-effort hash-family (SLH-DSA) factor was ACTUALLY
    ///      checked on-chain. It is caller-degradable to false (omit the sig, or starve gas) but NOT
    ///      forgeable to true (true requires a real SLH signature matching the registered key hash).
    ///      Off-chain consumers may trust `slhVerified=true`; `false` simply means Falcon-only.
    event LaipV3Transfer(
        address indexed from, address indexed to, uint256 amount, bytes32 txHash, uint8 path, bool slhVerified
    );
    event LaipV3Approval(
        address indexed owner, address indexed spender, uint256 amount, uint256 nonce, bool slhVerified
    );
    event LaipV3RelaxSlhSet(bool relaxed);
    event SlhDsaVerifierSet(address verifier);
    event SlhExemptPolicySet(bool enabled, uint256 maxAmount, uint256 windowSeconds);

    /// @notice Owner OVERRIDE: force-relax the on-chain SLH requirement to best-effort/Falcon-only.
    ///         This is the ONE escape hatch now that the block-gas-limit auto-relax is retired; it
    ///         exists only for an emergency (e.g. a verifier defect found post-deploy). Default false.
    function setLaipV3RelaxSlh(bool relaxed) external onlyOwner {
        s.laipV3RelaxSlh = relaxed;
        emit LaipV3RelaxSlhSet(relaxed);
    }

    /// @notice Owner sets the external SLH-DSA verifier contract. Required for the strict path to work.
    function setSlhDsaVerifier(address verifier) external onlyOwner {
        s.slhDsaVerifier = verifier;
        emit SlhDsaVerifierSet(verifier);
    }

    /// @notice Governance tunes the ECONOMIC SLH exemption (the "1% rule").
    ///
    ///         THE RULE IS ON BY DEFAULT. A freshly cut diamond has `enabled = true` and
    ///         `maxAmount = 0`, which means the ceiling calibrates itself per transfer:
    ///         `min(break-even amount under the live oracle, totalSupply / 1000)`. Nobody has to
    ///         guess a number for the chain, and the exemption still cannot be widened by a
    ///         manipulated price — the supply term has no oracle input at all.
    ///
    ///         `enabled = false` restores the pre-rule behaviour: on-chain SLH is required wherever
    ///         the chain's blocks fit the verify, whatever it costs. Use it if a defect is found in
    ///         the economic path post-deploy.
    ///
    ///         `maxAmount != 0` REPLACES the self-calibrating ceiling with a fixed one, in LEMNI
    ///         wei, capping both any single exempt transfer and the rolling per-account total moved
    ///         without on-chain SLH per window. Denominate it in LEMNI, never in dollars: the value
    ///         side of the 1% comparison comes from PriceOracle, whose LEMNI leg is a Uniswap V3
    ///         spot price and is flash-loan manipulable, so a value-denominated cap could be
    ///         widened by an attacker while a LEMNI-denominated one cannot.
    ///
    ///         `windowSeconds = 0` means the 1-day default.
    ///
    ///         None of these settings can freeze a wallet: the exemption is consulted only where
    ///         the chain-gas rule already said "strict", so it can only ever relax.
    function setSlhExemptPolicy(bool enabled, uint256 maxAmount, uint256 windowSeconds) external onlyOwner {
        s.slhExemptDisabled = !enabled;
        s.slhExemptMaxAmount = maxAmount;
        s.slhExemptWindow = windowSeconds;
        emit SlhExemptPolicySet(enabled, maxAmount, windowSeconds);
    }

    /// @dev Strict iff (a) a verifier is actually deployed and wired AND (b) the owner has not
    ///      force-relaxed. The old third condition — block.gaslimit fitting a ~24.6M verify — is
    ///      RETIRED: the optimized verifier needs ~1.2M, which fits any real chain's blocks.
    ///
    ///      FREEZE GUARD (a): with the no-downgrade gate closing the legacy V1/V2 entrypoints to V3
    ///      wallets, requiring a check we have no verifier for would strand them entirely — the V3
    ///      paths would revert "SLH verifier unset" and there would be nowhere else to go. An unset
    ///      verifier therefore means relaxed (Falcon floor), never a locked wallet. The verifier is
    ///      wired in the same deployment as the facets, so this is a safety net, not a normal state.
    function _slhStrictNow() internal view returns (bool) {
        return LibSlhEconomics.chainStrict(s);
    }

    /// @notice True when the V3 paths currently require on-chain SLH (strict). Clients poll this to
    ///         know whether the SLH signature is mandatory. False = relaxed, which now means only:
    ///         no verifier wired, or the owner's emergency override.
    function laipV3SlhStrict() external view returns (bool) {
        return _slhStrictNow();
    }

    /// @notice RETIRED — the block-gas-limit gate is gone (the optimized verifier fits any real
    ///         chain's blocks). Always 0. Kept so existing clients decoding this selector keep
    ///         working; 0 reads correctly as "every block gas limit qualifies".
    function laipV3SlhStrictMinBlockGas() external pure returns (uint256) {
        return 0;
    }

    function slhDsaVerifier() external view returns (address) {
        return s.slhDsaVerifier;
    }

    /// @dev The complete rule: on-chain SLH-DSA is REQUIRED iff the chain is strict (verifier wired,
    ///      no owner override) AND requiring it would not cost the holder more than 1% of the value
    ///      they are moving. The economic test is consulted only inside the strict branch, so it can
    ///      only ever relax — never make a relaxed chain strict, never freeze.
    function _slhRequired(address account, uint256 amount) internal view returns (bool) {
        if (!_slhStrictNow()) return false;
        return !LibSlhEconomics.economicallyExempt(s, account, amount);
    }

    /// @notice What a client MUST do for this exact transfer/approve: true = supply slhPubKey+slhSig
    ///         or the call reverts; false = the SLH factor may be omitted (the chain cannot fit it,
    ///         or it would cost more than 1% of the value).
    ///
    ///         The economic input is per-block (`block.basefee`), so a value read by
    ///         eth_call can flip before inclusion. Supplying the signature when it was not required
    ///         is always safe — it is simply verified. Omitting it when it becomes required reverts
    ///         the transfer harmlessly; re-read and retry.
    function laipV3SlhRequired(address account, uint256 amount) external view returns (bool) {
        return _slhRequired(account, amount);
    }

    /// @notice The economic exemption's state for this account.
    /// @param account the wallet
    /// @param amount  the transfer size the ceiling is being asked about — the self-calibrating
    ///                ceiling is per-transfer, so it needs one
    /// @param basefeeWei the basefee to price with; read it from the pending block header, since
    ///                nodes run eth_call with a base fee of zero
    /// @return enabled       whether the rule is active at all
    /// @return ceiling       the ceiling in LEMNI wei currently in force for `amount` (0 = the
    ///                       exemption cannot apply to it — disabled, unpriceable, or at/above the
    ///                       break-even, meaning SLH is simply required)
    /// @return windowSeconds rolling window length actually in force
    /// @return used          LEMNI wei this account has moved without on-chain SLH this window
    /// @return remaining     LEMNI wei it may still move without on-chain SLH this window
    function laipV3SlhExemptStatus(address account, uint256 amount, uint256 basefeeWei)
        external view
        returns (bool enabled, uint256 ceiling, uint256 windowSeconds, uint256 used, uint256 remaining)
    {
        enabled = !s.slhExemptDisabled;
        ceiling = LibSlhEconomics.currentCeiling(
            s, amount, LibSlhEconomics.SLH_MARGINAL_GAS, basefeeWei
        );
        windowSeconds = s.slhExemptWindow == 0 ? LibSlhEconomics.DEFAULT_WINDOW : s.slhExemptWindow;
        used = LibSlhEconomics.slhFreeUsed(s, account);
        remaining = used >= ceiling ? 0 : ceiling - used;
    }

    /// @notice The explicit governance ceiling, if one is set. 0 means the self-calibrating default
    ///         is in force — see `laipV3SlhExemptStatus` for what it actually resolves to.
    function laipV3SlhExemptMaxAmount() external view returns (uint256) {
        return s.slhExemptMaxAmount;
    }

    /// @notice As `laipV3SlhRequired`, but with the basefee supplied by the caller.
    ///
    ///         CLIENTS SHOULD USE THIS ONE. Most nodes execute `eth_call` with a base fee of zero,
    ///         so a simulation of `laipV3SlhRequired` reads `block.basefee == 0`, fails closed and
    ///         always answers "required". Read `baseFeePerGas` from the pending block header and
    ///         pass it here for the answer the transaction will actually get. Being wrong is safe
    ///         either way: over-report and the signature you supply is simply verified;
    ///         under-report and the call reverts cleanly with "SLH required", so re-read and retry.
    function laipV3SlhRequiredAt(address account, uint256 amount, uint256 basefeeWei)
        external view returns (bool)
    {
        if (!_slhStrictNow()) return false;
        return !LibSlhEconomics.economicallyExemptForGasAt(
            s, account, amount, LibSlhEconomics.SLH_MARGINAL_GAS, basefeeWei
        );
    }

    /// @notice The two sides of the 1% comparison, so the decision is auditable off-chain.
    ///         `slhCostWei` for any basefee is `slhMarginalGas * basefee`; the exemption applies
    ///         when that exceeds `thresholdBps` of `valueWei`. `valueWei` is 0 when the oracle
    ///         cannot price the amount, which always DENIES the exemption (fail closed).
    ///         Deliberately basefee-free so the answer is identical under `eth_call`.
    function laipV3SlhEconomics(uint256 amount)
        external view
        returns (uint256 valueWei, uint256 slhMarginalGas, uint256 thresholdBps)
    {
        valueWei = LibSlhEconomics.transferValueWei(s, amount);
        slhMarginalGas = LibSlhEconomics.SLH_MARGINAL_GAS;
        thresholdBps = LibSlhEconomics.SLH_ECONOMIC_BPS;
    }

    /// @notice m = keccak256("LEMNICOIN_TRANSFER" || chainId || from || to || amount).
    function _transferHash(address from, address to, uint256 amount) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("LEMNICOIN_TRANSFER", block.chainid, from, to, amount));
    }

    /// @notice m = keccak256("LEMNICOIN_APPROVE" || chainId || owner || spender || amount). A distinct
    ///         domain string so an approve SLH signature can never be replayed as a transfer or vice
    ///         versa (the mu they feed differ at the first byte of m's preimage).
    function _approveHash(address owner, address spender, uint256 amount) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("LEMNICOIN_APPROVE", block.chainid, owner, spender, amount));
    }

    function _requireV3(address account) internal view returns (LaipV3Keys storage k) {
        k = s.laipV3[account];
        if (!k.registered) revert LaipV3NotRegistered();
    }

    /// @dev ENTRY GAS FLOOR. These entrypoints run ~3-5.7M gas, and that need drifts a fraction
    ///      of a percent between a wallet's eth_estimateGas and the mined block (oracle rounds
    ///      rotate storage slots, the fee refund tracks the live price). Wallets that substitute
    ///      their own BARE estimate for the dApp's buffered gas limit (current MetaMask does)
    ///      therefore produce out-of-gas reverts that still burn the full ~5.4M — observed
    ///      repeatedly on Polygon mainnet. Requiring a minimum gasleft() at entry bakes the
    ///      headroom into estimation itself: no estimator can find success below the floor, so
    ///      EVERY wallet provisions it, execution runs with real slack, and the unused gas is
    ///      refunded as always. Under-provisioning now reverts here, in the first ~50k gas,
    ///      instead of at 98% of a 5.4M limit. Security: unchanged — less gas only ever fails
    ///      earlier; no verification can be skipped by starving or flooding gas.
    ///      Sized for the heaviest non-ring path (dual + on-chain SLH, ~5.7M observed) plus
    ///      drift slack; the check is on PROVIDED gas, so cheaper paths cost nothing extra.
    ///
    ///      SCOPED to _slhRequired(account, amount) — the exact condition under which the ~5.4M
    ///      SLH-verifying path runs. When the owner's emergency relax is on, or the transfer is
    ///      economically exempt, the never-block guarantees hold unchanged: no floor, low-gas
    ///      transfers keep working (see the 4relax-* tests). Estimation evaluates the same
    ///      condition against the same state, so estimates and execution agree on the floor.
    ///      VALUE: the dual-Falcon + SLH path genuinely costs ~6.7M gas, so the floor MUST sit
    ///      comfortably above that — otherwise it never forces a wallet's own eth_estimateGas up and
    ///      the bare estimate lands a hair under it. 8.0M gives ~1.3M of execution headroom over the
    ///      real cost, which absorbs the per-block gas drift (oracle round rotation, refund path).
    uint256 internal constant ENTRY_GAS_FLOOR = 8_000_000;

    function _requireGasProvisioned(uint256 amount) internal view {
        // Sample gasleft() BEFORE the oracle-reading _slhRequired: that read's cost varies between
        // eth_estimateGas and mining, and letting it move this threshold is exactly what made a
        // bare-estimate send land ~33k under the floor. When gas is plentiful — the case this floor
        // forces every wallet into — return immediately without even consulting the oracle, so the
        // boundary estimation sees is deterministic. Only a genuinely under-provisioned call pays
        // for the _slhRequired check (and then reverts with a clear reason).
        if (gasleft() >= ENTRY_GAS_FLOOR) return;
        if (_slhRequired(msg.sender, amount)) {
            revert InsufficientGasProvisioned(gasleft(), ENTRY_GAS_FLOOR);
        }
    }

    /// @notice mu_trustless = keccak256(m || curveHash || nonce(32B) || LOS_COMMITMENT). keccak256 so
    ///         the client and the chain agree byte-for-byte.
    function _muTrustless(bytes32 m, bytes32 curveHash, uint256 nonce) internal pure returns (bytes32) {
        return LibSlhEconomics.muTrustless(m, curveHash, nonce);
    }

    // ---------------------------------------------------------------------
    // Path 1 — DUAL (attestor up): attestor Falcon + holder Falcon + on-chain SLH-DSA whenever the
    // rule is strict (the normal state: ALL THREE are required).
    // When the chain cannot fit the verify, SLH auto-drops on-chain (the attestor still verified
    // SLH + ML-DSA + CSIDH possession off-chain before Falcon-signing).
    // ---------------------------------------------------------------------
    /// @param slhPubKey holder's 32-byte SLH-DSA public key. Mandatory in strict mode (the chain
    ///                  is strict); may be empty only when relaxed or economically exempt.
    /// @param slhSig    7856-byte SLH-DSA signature over mu_trustless(m, curveHash, nonce) — the SAME
    ///                  signature the attestor verified, so the wallet signs SLH exactly once.
    function quantumTransferV3Dual(
        address to,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        bytes calldata slhPubKey,
        bytes calldata slhSig,
        HolderFalconSig calldata holderSig
    ) external payable whenNotPaused nonReentrant returns (bool) {
        _requireGasProvisioned(amount);
        if (amount == 0) revert LaipV3AmountZero();
        LaipV3Keys storage k = _requireV3(msg.sender);

        // Verify signatures FIRST; then move the tokens; then collect the fee (whose refund is an
        // external call). Checks -> effects (transfer) -> interactions (fee/refund).
        // The dual layer enforces nonce == pqAttestationNonce, so the same nonce binds mu below.
        LibLemnicoin.transferWithDualFalconAttestationFrom(
            msg.sender, to, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32, holderSig
        );

        bytes32 m = _transferHash(msg.sender, to, amount);
        bool slhVerified = _slhRequired(msg.sender, amount)
            ? _strictSlh(k, m, nonce, slhPubKey, slhSig) // true, or reverts
            : _bestEffortSlh(k, m, nonce, slhPubKey, slhSig);
        // Charge EVERY value move that completed without the hash-family factor against the
        // account's rolling budget, so splitting a drain into sub-threshold pieces gains nothing.
        if (!slhVerified) LibSlhEconomics.noteSlhFree(s, msg.sender, amount);

        LibERC20._transfer(msg.sender, to, amount);
        LibLemnicoin.collectProtocolFee(amount);
        emit LaipV3Transfer(msg.sender, to, amount, m, 1, slhVerified);
        return true;
    }

    // ---------------------------------------------------------------------
    // APPROVE (V3-native): attestor Falcon + holder Falcon + on-chain SLH under the SAME chain-gated
    // rule as the transfer paths. Mirrors quantumApproveDual but binds to the V3 registration instead
    // of V2 LAIP, so a V3-native wallet can grant allowances (DEX approve+swap, permit-style flows).
    //
    // SECURITY (audit finding, closed): an approval is a standing right to move funds later — a
    // quantum-approved spender can then drain via plain transferFrom(to = spender). If approve needed
    // only the two Falcon signatures, an attacker holding a stolen EVM key AND a Falcon-algorithm
    // break would forge both Falcons, approve themselves, and bypass the SLH requirement entirely.
    // So the approve carries the same hash-family factor as a transfer, over its own domain-separated
    // m ("LEMNICOIN_APPROVE") so approve/transfer SLH signatures are never interchangeable.
    // ---------------------------------------------------------------------
    /// @param slhSig SLH-DSA signature over mu_trustless(_approveHash(owner,spender,amount), curveHash,
    ///               nonce). Mandatory in strict mode; may be empty only when the chain has relaxed.
    function quantumApproveV3Dual(
        address spender,
        uint256 amount,
        bytes32 quantumInputHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2_32,
        bytes calldata slhPubKey,
        bytes calldata slhSig,
        HolderFalconSig calldata holderSig
    ) external payable whenNotPaused nonReentrant returns (bool) {
        _requireGasProvisioned(amount);
        LaipV3Keys storage k = _requireV3(msg.sender);
        if (amount > 0 && amount > s.balances[msg.sender]) {
            revert LaipV3ApprovalExceedsBalance(amount, s.balances[msg.sender]);
        }

        // The dual layer enforces nonce == pqAttestationNonce, so the same nonce binds mu below.
        LibLemnicoin.approveWithDualFalconInternal(
            msg.sender, spender, amount, quantumInputHash, nonce, deadline, falconSalt40, falconS2_32, holderSig
        );

        bytes32 mA = _approveHash(msg.sender, spender, amount);
        bool slhVerified = _slhRequired(msg.sender, amount)
            ? _strictSlh(k, mA, nonce, slhPubKey, slhSig) // true, or reverts
            : _bestEffortSlh(k, mA, nonce, slhPubKey, slhSig);
        // An allowance is a standing right to move `amount` later, so it is charged against the
        // same rolling budget as a transfer — an attacker cannot buy an SLH-free approval and then
        // drain through it.
        if (!slhVerified) LibSlhEconomics.noteSlhFree(s, msg.sender, amount);

        LibERC20._approve(msg.sender, spender, amount);
        s.quantumApprovedSpender[msg.sender][spender] = (amount > 0);
        LibLemnicoin.collectProtocolFee(amount);

        emit LaipV3Approval(msg.sender, spender, amount, nonce, slhVerified);
        return true;
    }

    // ---------------------------------------------------------------------
    // Path 2 — ATTESTOR-INDEPENDENT: holder Falcon (REQUIRED) + on-chain SLH-DSA (LOS), which is
    // REQUIRED whenever the rule is strict (see _slhStrictNow).
    // Liveness-gated (only after the attestor has gone silent), same as the legacy holder-only path.
    // ---------------------------------------------------------------------
    /// @param slhPubKey holder's 32-byte SLH-DSA-SHA2-128s public key (checked vs slhdsaPkHash).
    ///                  Mandatory in strict mode; may be empty (Falcon-only) only when relaxed.
    /// @param slhSig    7856-byte SLH-DSA signature over mu_trustless. Same rule as slhPubKey.
    function quantumTransferV3(
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        bytes calldata slhPubKey,
        bytes calldata slhSig,
        HolderFalconSig calldata holderSig
    ) external payable whenNotPaused nonReentrant returns (bool) {
        _requireGasProvisioned(amount);
        if (amount == 0) revert LaipV3AmountZero();
        // Only usable while the attestor is provably silent (same gate as the legacy holder-only path).
        LibLemnicoin.requireHolderOnlyPathOpen(s);
        LaipV3Keys storage k = _requireV3(msg.sender);

        bytes32 m = _transferHash(msg.sender, to, amount);
        uint256 n0 = s.pqAttestationNonce[msg.sender]; // capture before the Falcon layer increments it

        // FLOOR (required): holder Falcon over the same transfer + nonce. Reverts if invalid.
        LibLemnicoin.transferWithHolderFalconAttestationFrom(
            msg.sender, to, amount, m, nonce, deadline, holderSig.salt40, holderSig.s2_32, holderSig.ntth
        );

        // Hash-family factor over the nonce-bound mu. Strict vs relaxed is never decided by anything
        // a caller submits:
        //  - STRICT (verifier wired, no owner override — the normal state): SLH is REQUIRED. Missing
        //    / invalid / out-of-gas all REVERT, so the transfer always requires Falcon AND the
        //    on-chain hash family. A sender starving the TRANSACTION gas limit only reverts their
        //    own transfer — they can never downgrade it to Falcon-only.
        //  - RELAXED (no verifier, or the owner's emergency override): best-effort — out-of-gas is
        //    disregarded and the transfer proceeds on the Falcon floor.
        bool slhVerified;
        if (_slhRequired(msg.sender, amount)) {
            slhVerified = _strictSlh(k, m, n0, slhPubKey, slhSig); // true, or reverts
        } else {
            slhVerified = _bestEffortSlh(k, m, n0, slhPubKey, slhSig);
        }
        if (!slhVerified) LibSlhEconomics.noteSlhFree(s, msg.sender, amount);

        // effects (transfer) before interactions (fee/refund).
        LibERC20._transfer(msg.sender, to, amount);
        LibLemnicoin.collectProtocolFee(amount);
        emit LaipV3Transfer(msg.sender, to, amount, m, 2, slhVerified);
        return true;
    }

    // ---------------------------------------------------------------------
    // APPROVE, attestor-independent: holder Falcon + on-chain SLH (chain-gated), liveness-gated.
    // This is the fourth corner of the matrix for approvals. V1/V2 had no attestor-down approve at
    // all, which meant a V3 wallet could not grant an allowance during an attestor outage — with the
    // no-downgrade gate closing the legacy approve, that would have been a real capability freeze.
    // Approvals now follow exactly the same four scenarios as transfers.
    // ---------------------------------------------------------------------
    function quantumApproveV3(
        address spender,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        bytes calldata slhPubKey,
        bytes calldata slhSig,
        HolderFalconSig calldata holderSig
    ) external payable whenNotPaused nonReentrant returns (bool) {
        _requireGasProvisioned(amount);
        // Only usable while the attestor is provably silent — same gate as the trustless transfer.
        LibLemnicoin.requireHolderOnlyPathOpen(s);
        LaipV3Keys storage k = _requireV3(msg.sender);
        if (amount > 0 && amount > s.balances[msg.sender]) {
            revert LaipV3ApprovalExceedsBalance(amount, s.balances[msg.sender]);
        }

        bytes32 mA = _approveHash(msg.sender, spender, amount);
        uint256 n0 = s.pqAttestationNonce[msg.sender]; // capture before the Falcon layer increments it

        // FLOOR (required): holder Falcon over the approval digest. Reverts if invalid, and burns
        // the nonce — so the SLH signature below, which binds n0, is single-use.
        LibLemnicoin.approveWithHolderFalconInternal(
            msg.sender, spender, amount, mA, nonce, deadline, holderSig
        );

        bool slhVerified = _slhRequired(msg.sender, amount)
            ? _strictSlh(k, mA, n0, slhPubKey, slhSig) // true, or reverts
            : _bestEffortSlh(k, mA, n0, slhPubKey, slhSig);
        if (!slhVerified) LibSlhEconomics.noteSlhFree(s, msg.sender, amount);

        LibERC20._approve(msg.sender, spender, amount);
        s.quantumApprovedSpender[msg.sender][spender] = (amount > 0);
        LibLemnicoin.collectProtocolFee(amount);

        emit LaipV3Approval(msg.sender, spender, amount, nonce, slhVerified);
        return true;
    }

    /// @dev Both delegate to LibSlhEconomics so transfers, approvals, recovery, CEX sessions and
    ///      burn all verify the hash-family factor through identical code.
    function _strictSlh(
        LaipV3Keys storage k, bytes32 m, uint256 nonce,
        bytes calldata slhPubKey, bytes calldata slhSig
    ) internal view returns (bool) {
        return LibSlhEconomics.strictSlh(s, k, m, nonce, slhPubKey, slhSig);
    }

    function _bestEffortSlh(
        LaipV3Keys storage k, bytes32 m, uint256 nonce,
        bytes calldata slhPubKey, bytes calldata slhSig
    ) internal view returns (bool) {
        return LibSlhEconomics.bestEffortSlh(s, k, m, nonce, slhPubKey, slhSig);
    }
}
