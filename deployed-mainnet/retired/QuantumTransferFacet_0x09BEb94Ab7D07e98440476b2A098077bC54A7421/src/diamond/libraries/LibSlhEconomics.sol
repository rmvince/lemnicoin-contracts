// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AppStorage, LaipV3Keys} from "./LibAppStorage.sol";
import {SlhDsaVerifier} from "../../crypto/SlhDsaVerifier.sol";

/// Declared at file scope so every V3 facet that uses this library reverts with the SAME custom
/// errors — clients decode one set of selectors regardless of which entrypoint they called.
error LaipV3SlhKeyMismatch();
error SlhDsaVerificationFailed();

/// THE NO-DOWNGRADE GATE's error. Raised when a V3-registered account calls a LEGACY (Falcon-only)
/// entrypoint while the chain is able to enforce the hash-family factor. The account is not stuck:
/// the V3 entrypoint for the same operation is, by the gate's own condition, guaranteed available.
error LaipV3LegacyPathClosed(address account);
import {PriceOracle} from "../../PriceOracle.sol";

/// @title LibSlhEconomics — THE ONE PLACE that decides when the SLH-DSA factor is required, and
///        the one place that verifies it. Every V3 facet routes through here so the rule cannot
///        drift between transfers, approvals, recovery, CEX sessions and burns.
///
/// The economic half of it is the "1% rule": never make a holder pay more for the hash-family factor
///        than the factor is protecting.
///
/// @notice A strict on-chain SLH-DSA verification costs ~1.2M gas with the optimized verifier
///         (SlhDsaVerifierV2), plus ~126k for the 7856-byte signature's calldata. On a large
///         transfer that is noise. On a small one it can still exceed the value being moved, which
///         would price ordinary users out of their own wallets. So when the on-chain cost of the
///         SLH factor exceeds `SLH_ECONOMIC_BPS` (1%) of the transfer's value, the factor is
///         dropped and the transfer proceeds on the Falcon floor (never make the security theatre
///         cost more than the asset).
///
/// ============================ WHY THIS CANNOT BE GAMED ============================
///
/// The exemption makes a transfer CHEAPER and WEAKER, so every input it reads is an attack surface.
/// Four independent locks, each of which alone denies the exemption:
///
///  1. COST IS PRICED FROM `block.basefee`, NEVER `tx.gasprice`.
///     `tx.gasprice` is chosen by the sender: an attacker would simply declare a 10,000 gwei gas
///     price, make the SLH "cost" astronomical, and skip the check on any transfer they liked.
///     `block.basefee` is set by the chain's own EIP-1559 consensus rule from the PREVIOUS block's
///     fullness. A sender cannot set it. Inflating it means filling many consecutive blocks at their
///     own expense — and lock 3 caps the payoff of doing so anyway.
///
///  2. AN ORACLE-INDEPENDENT ABSOLUTE CEILING, in LEMNI wei.
///     The value half of the comparison comes from PriceOracle, whose LEMNI leg is a Uniswap V3
///     SPOT price (`slot0`) and is therefore flash-loan manipulable within a single block. An
///     attacker could crush the pool price so that a large LEMNI amount reads as a few dollars and
///     "deserves" the exemption. The ceiling is denominated in LEMNI, not in value, so no price and
///     no basefee can ever exempt a transfer larger than it.
///
///     The rule is ON BY DEFAULT, so the ceiling has to size itself without a governance number.
///     `effectiveCeiling` computes `min(break-even amount under the live oracle, totalSupply /
///     DEFAULT_SUPPLY_DIVISOR)`. The first term is what the 1% rule itself already says is not
///     worth protecting, so under an honest oracle it never binds a legitimate transfer; the second
///     is a pure on-chain quantity an attacker cannot move, and is what a manipulated price runs
///     into. Governance may replace the whole thing with an explicit `slhExemptMaxAmount`, or turn
///     the exemption off with `slhExemptDisabled`.
///
///  3. A ROLLING PER-ACCOUNT BUDGET, charged in LEMNI, that defeats SPLITTING.
///     A per-transfer threshold on its own is trivially defeated by cutting one large drain into
///     many sub-threshold transfers. Every transfer that actually moves WITHOUT an on-chain SLH
///     verification is charged against a per-account rolling total, and once that total would exceed
///     the same ceiling the exemption is refused until the window rolls. So the ceiling bounds not
///     just one transfer but ALL SLH-free value an account can move per window. Splitting buys
///     nothing.
///
///  4. EVERY UNCERTAINTY FAILS CLOSED (to strict), never open.
///     Oracle unset, oracle reverting, a zero fee-bps, a zero derived value, or a zero basefee all
///     DENY the exemption. There is no input an attacker can suppress or corrupt into an exemption;
///     breaking the oracle only makes the chain stricter.
///
/// One residual, disclosed rather than hidden: a validator can nudge `block.timestamp` and so roll
/// the budget window slightly early. Consensus bounds that drift to seconds against a window of a
/// day, and the ceiling still applies to each window, so the effect is negligible.
///
/// Note what the exemption is NOT: it never touches the Falcon floor. A transfer that takes the
/// exemption still requires the holder's Falcon signature (and the attestor's, on the dual path);
/// only the second, hash-family factor is dropped. And it can only ever RELAX — it is consulted
/// solely where `_slhStrictNow()`/`ringV3SlhStrict()` already said "strict", so it can never turn a
/// relaxed chain into a strict one, and can never freeze a wallet.
library LibSlhEconomics {

    /// The marginal on-chain cost of REQUIRING the hash-family factor: the ~1.15M-gas SLH-DSA
    /// verification (SlhDsaVerifierV2, measured 1,185,265 on the FIPS vectors and 1,195,839 live on
    /// Amoy) plus the calldata for its 7856-byte signature (~126k at 16 gas/byte).
    uint256 internal constant SLH_MARGINAL_GAS = 1_300_000;

    /// The threshold, in basis points of the transfer's value. 100 bps = 1%.
    uint256 internal constant SLH_ECONOMIC_BPS = 100;

    /// Default rolling window when governance has not set one.
    uint256 internal constant DEFAULT_WINDOW = 1 days;

    /// The oracle-independent share of TOTAL SUPPLY one account may move without the hash-family
    /// factor per window, when governance has not set an explicit ceiling: one thousandth, i.e.
    /// 0.1%. This is a CIRCUIT BREAKER against oracle manipulation, not the normal operating limit
    /// — under an honest oracle the break-even term of `effectiveCeiling` is the smaller of the two
    /// and is what actually binds. Sized to be generous enough not to interfere with ordinary small
    /// transfers at any plausible LEMNI price, and tight enough that a total price break still
    /// bounds one account to 0.1% of supply per day.
    uint256 internal constant DEFAULT_SUPPLY_DIVISOR = 1_000;

    /// Sanity bound on the basefee we are willing to price with (1e18 wei = 1e9 gwei — many orders
    /// of magnitude above anything a real chain produces). Above it the exemption is simply refused,
    /// which both fails closed and makes the break-even arithmetic below unable to overflow. An
    /// overflow here would revert the transfer, i.e. freeze the wallet, so it is ruled out by
    /// construction rather than left to chance.
    uint256 internal constant MAX_PRICEABLE_BASEFEE = 1e18;

    /// @notice The transfer's value expressed in native wei, derived ONLY from public views on the
    ///         ALREADY-DEPLOYED PriceOracle — so this change needs no oracle redeployment.
    ///
    ///         PriceOracle computes, internally:
    ///             valueUsd8 = amount * lemniUsd / 1e18
    ///             feeUsd8   = valueUsd8 * feeBps / 10_000
    ///             feeWei    = feeUsd8 * 1e18 / nativeUsd
    ///         Neither `lemniUsd` nor `nativeUsd` is exposed, but the two public views
    ///         `getMinFeeInWei` and `getFeeBps` are, and dividing the fee back out by its own rate
    ///         recovers the value in the same wei units:
    ///             valueWei = feeWei * 10_000 / feeBps
    ///
    /// @return 0 whenever the value cannot be established — which callers MUST treat as "no
    ///         exemption" (fail closed). Both oracle calls are wrapped so a reverting or
    ///         self-destructed oracle can never revert a transfer through this path.
    function transferValueWei(AppStorage storage s, uint256 amount) internal view returns (uint256) {
        address oracle = s.priceOracle;
        if (oracle == address(0)) return 0;

        uint16 bps;
        try PriceOracle(oracle).getFeeBps(amount) returns (uint16 b) {
            bps = b;
        } catch {
            return 0;
        }
        if (bps == 0) return 0;

        uint256 feeWei;
        try PriceOracle(oracle).getMinFeeInWei(amount) returns (uint256 f) {
            feeWei = f;
        } catch {
            return 0;
        }
        if (feeWei == 0) return 0;

        return (feeWei * 10_000) / uint256(bps);
    }

    /// @notice LEMNI wei this account has already moved WITHOUT an on-chain SLH verification inside
    ///         the current rolling window. Returns 0 once the window has rolled.
    function slhFreeUsed(AppStorage storage s, address account) internal view returns (uint256) {
        uint256 w = s.slhExemptWindow == 0 ? DEFAULT_WINDOW : s.slhExemptWindow;
        if (block.timestamp >= s.slhExemptWindowStart[account] + w) return 0;
        return s.slhExemptUsed[account];
    }

    /// @notice Charge `amount` against the account's rolling SLH-free budget, rolling the window
    ///         first if it has expired. Called on EVERY transfer/approve that completes without an
    ///         on-chain SLH verification — not only the exempt ones — so the budget reflects all
    ///         value that actually moved unprotected by the hash family.
    function noteSlhFree(AppStorage storage s, address account, uint256 amount) internal {
        uint256 w = s.slhExemptWindow == 0 ? DEFAULT_WINDOW : s.slhExemptWindow;
        if (block.timestamp >= s.slhExemptWindowStart[account] + w) {
            s.slhExemptWindowStart[account] = block.timestamp;
            s.slhExemptUsed[account] = amount;
        } else {
            s.slhExemptUsed[account] += amount;
        }
    }

    /// @notice True iff requiring on-chain SLH for this transfer would cost more than
    ///         SLH_ECONOMIC_BPS of the value being moved, AND every anti-gaming lock permits it.
    ///         Callers consult this ONLY where the strictness rule already said "strict"; it can
    ///         therefore only ever relax, never tighten.
    function economicallyExempt(AppStorage storage s, address account, uint256 amount)
        internal view returns (bool)
    {
        return economicallyExemptForGasAt(s, account, amount, SLH_MARGINAL_GAS, block.basefee);
    }

    /// @notice As `economicallyExempt`, but for a caller whose SLH cost is not one verification.
    ///         A Multi-Sig ring requires one SLH verification PER SIGNING MEMBER, so an M-of-N ring
    ///         passes `M * SLH_MARGINAL_GAS` and its break-even sits M times higher — the 1% rule is
    ///         measured against what THAT account is actually being asked to pay.
    function economicallyExemptForGas(
        AppStorage storage s,
        address account,
        uint256 amount,
        uint256 marginalGas
    ) internal view returns (bool) {
        return economicallyExemptForGasAt(s, account, amount, marginalGas, block.basefee);
    }

    /// @notice The same decision with the basefee supplied explicitly.
    ///
    ///         ON CHAIN this is always called with `block.basefee` — the consensus value, which is
    ///         the whole point of Lock 1. The explicit form exists for CLIENTS: most nodes execute
    ///         `eth_call` with a base fee of ZERO (so that gas-price checks never fail a simulated
    ///         call), which means an off-chain simulation of the no-argument form would read
    ///         basefee 0, fail closed, and always report "SLH required". A client that wants the
    ///         real answer reads `baseFeePerGas` from the pending block header and passes it here.
    ///         Being wrong is safe in both directions: a client that over-reports simply signs an
    ///         SLH signature that is then verified, and one that under-reports gets a clean revert.
    function economicallyExemptForGasAt(
        AppStorage storage s,
        address account,
        uint256 amount,
        uint256 marginalGas,
        uint256 basefee
    ) internal view returns (bool) {
        // Governance kill switch: restores the pre-1%-rule behaviour. Off by default.
        if (s.slhExemptDisabled) return false;

        // Lock 1: the cost is priced from the CHAIN's basefee, never the sender's gas price.
        if (basefee == 0 || basefee > MAX_PRICEABLE_BASEFEE) return false; // fail closed (Lock 4)

        // Lock 4: any oracle failure yields 0 here and denies the exemption.
        uint256 valueWei = transferValueWei(s, amount);
        if (valueWei == 0) return false;

        // THE RULE. Exempt only when the cost STRICTLY exceeds 1% of the value, i.e. the value is
        // below the break-even. Written as one multiplication on the (bounded) cost side so a very
        // large `valueWei` can never overflow and revert the transfer.
        uint256 costWei = marginalGas * basefee;
        uint256 breakevenWei = costWei * (10_000 / SLH_ECONOMIC_BPS);
        if (valueWei >= breakevenWei) return false;

        // Lock 2: the oracle-independent ceiling.
        uint256 ceiling = effectiveCeiling(s, amount, valueWei, breakevenWei);
        if (ceiling == 0 || amount > ceiling) return false;

        // Lock 3: splitting a large drain into sub-threshold pieces gains nothing — the ceiling
        // bounds the account's TOTAL SLH-free value per window, not just one transfer.
        return slhFreeUsed(s, account) + amount <= ceiling;
    }

    /// @notice The ceiling, in LEMNI wei, on both a single exempt transfer and the account's rolling
    ///         SLH-free total for this window.
    ///
    ///         An explicit `slhExemptMaxAmount` set by governance wins outright. Otherwise it is
    ///         computed, so that the rule can be ON by default without anyone having to guess a
    ///         number for the chain:
    ///
    ///           breakevenAmount = amount * breakevenWei / valueWei
    ///               The LEMNI amount whose value equals the break-even. The oracle's value function
    ///               is linear in `amount`, so one division inverts it from the reads already done.
    ///               This is precisely what the 1% rule already declared not worth protecting, so
    ///               under an honest oracle it never blocks a legitimate small transfer — and since
    ///               we only get here with valueWei < breakevenWei, it is always > amount, meaning a
    ///               single transfer is never refused by this term. What it does bound is the
    ///               ROLLING total: an account can move one break-even's worth per window without
    ///               the hash family, and no more.
    ///
    ///           supplyCap = totalSupply / DEFAULT_SUPPLY_DIVISOR
    ///               A pure on-chain quantity, with no oracle input at all. This is the term that
    ///               catches a manipulated spot price: crushing the LEMNI price inflates
    ///               breakevenAmount without limit, and this clamps it.
    ///
    ///         The smaller of the two governs, so BOTH must permit the exemption.
    function effectiveCeiling(
        AppStorage storage s,
        uint256 amount,
        uint256 valueWei,
        uint256 breakevenWei
    ) internal view returns (uint256) {
        uint256 explicitCeiling = s.slhExemptMaxAmount;
        if (explicitCeiling != 0) return explicitCeiling;

        uint256 supplyCap = s.totalSupply / DEFAULT_SUPPLY_DIVISOR;
        if (valueWei == 0) return 0; // caller already guards this; belt and braces

        // amount * breakevenWei cannot overflow in practice: `amount` is bounded by total supply
        // and breakevenWei by MAX_PRICEABLE_BASEFEE, but clamp defensively rather than risk a
        // revert (which would freeze the transfer) on a pathological chain.
        if (breakevenWei != 0 && amount > type(uint256).max / breakevenWei) return supplyCap;
        uint256 breakevenAmount = (amount * breakevenWei) / valueWei;

        return breakevenAmount < supplyCap ? breakevenAmount : supplyCap;
    }

    /// @notice The ceiling currently in force for `amount`, for clients and for the status view.
    ///         Returns 0 when the exemption cannot apply at all (disabled, unpriceable, or above
    ///         break-even).
    function currentCeiling(AppStorage storage s, uint256 amount, uint256 marginalGas, uint256 basefee)
        internal view returns (uint256)
    {
        if (s.slhExemptDisabled) return 0;
        if (basefee == 0 || basefee > MAX_PRICEABLE_BASEFEE) return 0;
        uint256 valueWei = transferValueWei(s, amount);
        if (valueWei == 0) return 0;
        uint256 breakevenWei = (marginalGas * basefee) * (10_000 / SLH_ECONOMIC_BPS);
        if (valueWei >= breakevenWei) return 0;
        return effectiveCeiling(s, amount, valueWei, breakevenWei);
    }

    // =====================================================================================
    // THE STRICTNESS RULE, AND THE VERIFICATION ITSELF
    //
    // Defined here rather than in any one facet so that transfers, approvals, recovery, CEX
    // sessions and burns are all governed by exactly the same code. Two facets each carrying their
    // own copy of this logic is how a security rule quietly drifts apart.
    //
    // HISTORY: through the reference verifier era (~24.6M gas per verify) strictness also depended
    // on `block.gaslimit >= 29M` — a chain whose blocks could not fit the verify auto-relaxed to
    // the Falcon floor so funds were never frozen. The optimized verifier (~1.2M) fits comfortably
    // inside any real chain's blocks, so THE GAS GATE IS RETIRED: strictness now depends only on a
    // verifier being wired and the owner not having force-relaxed. The owner's setLaipV3RelaxSlh
    // override remains the one escape hatch should a verifier defect ever surface.
    // =====================================================================================

    /// Protocol constant: SHA3-256(encodePoint(LOS P0)) — the lemniscate provenance anchor in mu.
    bytes32 internal constant LOS_COMMITMENT =
        0x5011820df0d8c8de5cee136edec7512fdb2ae279a33e7b25a52192e7931e04bb;

    /// Gas reserved for the tail (fee, token movement, events) after a best-effort SLH attempt.
    uint256 internal constant SLH_GAS_RESERVE = 1_500_000;
    /// Don't attempt the sub-call unless it could plausibly complete (avoids guaranteed-OOG waste).
    uint256 internal constant SLH_MIN_ATTEMPT = 1_300_000;

    /// @notice mu_trustless = keccak256(m || curveHash || nonce(32B) || LOS_COMMITMENT). keccak256
    ///         so the client and the chain agree byte-for-byte.
    function muTrustless(bytes32 m, bytes32 curveHash, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(m, curveHash, bytes32(nonce), LOS_COMMITMENT));
    }

    /// @notice Whether the hash-family factor is required at all on this chain. False only when no
    ///         verifier is wired (FREEZE GUARD: requiring a check we have no verifier for would
    ///         strand every wallet) or under the owner's emergency override. The old block-gas-limit
    ///         condition is retired — the optimized verifier fits any real chain's blocks.
    function chainStrict(AppStorage storage s) internal view returns (bool) {
        if (s.slhDsaVerifier == address(0)) return false;
        return !s.laipV3RelaxSlh;
    }

    /// @notice THE NO-DOWNGRADE GATE. Call this at the top of every LEGACY (pre-V3, Falcon-only)
    ///         value-moving entrypoint, so a wallet that has registered V3 keys cannot quietly
    ///         transact at the old strength.
    ///
    /// WHY THIS HAS TO EXIST. Registering V3 keys is meant to ADD the hash-family (SLH-DSA) factor,
    /// which is the ONLY factor in the system that does not rest on lattice hardness — Falcon
    /// (NTRU) and ML-DSA (Module-LWE) fall together if lattices fall. Without this gate the older
    /// Falcon-only entrypoints stay callable, so the hash factor is merely OPTIONAL: any client
    /// (or anyone calling the contract directly) can pick the cheaper legacy route and drop it.
    /// That silently costs the wallet the one property V3 was added to provide.
    ///
    /// WHY IT CANNOT FREEZE A WALLET — the safety argument, stated as an invariant:
    ///
    ///     this gate closes legacy  <=>  chainStrict(s) is true
    ///
    /// and `chainStrict` is true exactly when a verifier is wired AND the owner has not
    /// force-relaxed — i.e. exactly when the V3 path is able to run. So:
    ///
    ///   • No verifier wired          -> chainStrict false -> legacy stays OPEN.
    ///   • Owner's emergency relax    -> chainStrict false -> legacy REOPENS for everyone, which is
    ///                                   what makes setLaipV3RelaxSlh a real escape hatch and not a
    ///                                   half-measure that leaves migrated wallets stranded.
    ///   • Chain strict               -> the V3 entrypoint verifies through a live verifier, so
    ///                                   there is always somewhere to go.
    ///
    /// The 1% economic exemption does NOT enter here on purpose: an exempt transfer still goes
    /// through the V3 entrypoint (which drops to best-effort internally). The exemption decides how
    /// the V3 path behaves, never whether the legacy path is open.
    ///
    /// @param account The account whose funds/allowance the operation moves — NOT necessarily
    ///        msg.sender (on recovery it is the compromised wallet).
    function requireNotV3Downgrade(AppStorage storage s, address account) internal view {
        if (!s.laipV3[account].registered) return; // never migrated: legacy IS its normal path
        if (!chainStrict(s)) return;               // chain cannot enforce V3: never strand anyone
        revert LaipV3LegacyPathClosed(account);
    }

    /// @notice Two-party form for RECOVERY, where the V3 path needs BOTH wallets registered.
    ///
    /// @dev LAIPV3CapabilitiesFacet.recoveryTransferV3 calls _requireSameSeed(from, rescuer), which
    ///      reverts V3CapNotRegistered(rescuer) unless the RESCUER is registered too. So closing the
    ///      legacy recovery purely on `from` would strand a genuine rescue whenever the compromised
    ///      wallet had migrated but the rescuing one had not — and recovery is the emergency path,
    ///      the very last place to introduce a dead end. Close it only when the V3 recovery is
    ///      actually usable: both sides registered.
    function requireNotV3DowngradePair(AppStorage storage s, address from, address rescuer)
        internal view
    {
        if (!s.laipV3[from].registered || !s.laipV3[rescuer].registered) return;
        if (!chainStrict(s)) return;
        revert LaipV3LegacyPathClosed(from);
    }

    /// @notice The complete rule for a value-carrying operation: strict on this chain AND
    ///         requiring the verify must not cost more than 1% of the value being moved.
    function slhRequired(AppStorage storage s, address account, uint256 amount)
        internal view returns (bool)
    {
        if (!chainStrict(s)) return false;
        return !economicallyExempt(s, account, amount);
    }

    /// @dev STRICT: the hash-family factor is REQUIRED. Reverts unless a valid SLH signature
    ///      verifies on chain. A starved/out-of-gas verify reverts the WHOLE transaction (the
    ///      direct call propagates the OOG), so an attacker cannot skip SLH by under-funding gas.
    function strictSlh(
        AppStorage storage s,
        LaipV3Keys storage k,
        bytes32 m,
        uint256 nonce,
        bytes calldata slhPubKey,
        bytes calldata slhSig
    ) internal view returns (bool) {
        address verifier = s.slhDsaVerifier;
        require(verifier != address(0), "SLH verifier unset");
        require(slhSig.length != 0 && slhPubKey.length != 0, "SLH required"); // cannot be omitted
        if (keccak256(slhPubKey) != k.slhdsaPkHash) revert LaipV3SlhKeyMismatch();

        bytes memory mu = abi.encodePacked(muTrustless(m, k.curveHash, nonce));
        // Direct call, no gas cap: a false result OR an out-of-gas both fail the operation.
        if (!SlhDsaVerifier(verifier).verify(slhPubKey, mu, slhSig)) revert SlhDsaVerificationFailed();
        return true;
    }

    /// @dev RELAXED / best-effort. Returns true iff the factor was actually verified.
    ///      no verifier / empty sig -> false. Key mismatch or a completed FALSE result -> revert
    ///      (a real forgery is never disregarded). Not enough gas, or an out-of-gas inside the
    ///      verifier -> false, so funds are never frozen on a chain that cannot fit the verify.
    function bestEffortSlh(
        AppStorage storage s,
        LaipV3Keys storage k,
        bytes32 m,
        uint256 nonce,
        bytes calldata slhPubKey,
        bytes calldata slhSig
    ) internal view returns (bool) {
        address verifier = s.slhDsaVerifier;
        if (verifier == address(0)) return false;
        if (slhSig.length == 0 || slhPubKey.length == 0) return false; // caller opted out
        if (keccak256(slhPubKey) != k.slhdsaPkHash) revert LaipV3SlhKeyMismatch();

        if (gasleft() <= SLH_GAS_RESERVE + SLH_MIN_ATTEMPT) return false; // won't fit; disregarded
        uint256 cap = gasleft() - SLH_GAS_RESERVE;

        bytes memory mu = abi.encodePacked(muTrustless(m, k.curveHash, nonce));
        try SlhDsaVerifier(verifier).verify{gas: cap}(slhPubKey, mu, slhSig) returns (bool ok) {
            if (!ok) revert SlhDsaVerificationFailed(); // ran to completion: a false result is a forgery
            return true;
        } catch {
            return false; // out of gas or internal revert -> proceed on the Falcon floor
        }
    }
}
