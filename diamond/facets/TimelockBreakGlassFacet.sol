// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Modifiers} from "../Modifiers.sol";
import {IDiamondCut} from "../interfaces/IDiamondCut.sol";
import {LibDiamond} from "../libraries/LibDiamond.sol";
import {LibLemnicoin} from "../libraries/LibLemnicoin.sol";

error BreakGlassAlreadyPending(bytes32 id, uint256 eta);
error BreakGlassNotQueued(bytes32 id);
error BreakGlassNotReady(bytes32 id, uint256 eta);
error BreakGlassWindowExpired(bytes32 id, uint256 expiredAt);
error BreakGlassIsCancelled(bytes32 id);
error BreakGlassIsExecuted(bytes32 id);
error BreakGlassZeroOwner();

/// @title TimelockBreakGlassFacet — ECDSA recovery path with a Falcon veto window
///
/// @notice The LAST-RESORT recovery mechanism that replaces the legacy ECDSA-only
///         diamondCut / transferOwnership selectors when they are removed in phase 3.
///         It restores an ECDSA-only capability — but only through a long, public,
///         cancellable timelock:
///
///           * QUEUE    — the diamond owner (the Gnosis Safe, plain ECDSA) queues one
///                        exact diamondCut or ownership transfer. Nothing happens yet.
///           * VETO     — at ANY point during the 30-day delay, a Falcon-512 governance
///                        signature cancels the queued action (same gate as all other
///                        governance: LibLemnicoin.requireFalconGovernance).
///           * EXECUTE  — only after the full delay, and only within a bounded grace
///                        window, the owner executes the exact queued action.
///
///         Purpose: if the Falcon governance key is ever lost, the Safe can still
///         recover the diamond — slowly and in public. If instead the Safe's ECDSA
///         keys are compromised (including by a quantum adversary), the attacker's
///         queued action sits visible on-chain for 30 days while the Falcon key
///         holder cancels it. ECDSA alone can therefore never change the diamond
///         faster than the quantum-safe key can respond.
///
/// @dev Storage lives in a dedicated diamond-storage slot (NOT AppStorage), so adding
///      this facet cannot disturb any existing layout. Queued actions are stored as
///      hashes only; execute re-supplies the full parameters and recomputes the hash,
///      so what was queued is byte-for-byte what can run. A cancelled or executed or
///      expired id can be re-queued (fresh 30-day clock); a pending one cannot.
///
///      Deliberate standoff property: after a Falcon cancel, a compromised Safe can
///      re-queue, but each round buys the defender another 30 days for the real
///      remediation (rotate the Safe via transferOwnershipWithFalcon). The defender
///      always moves faster than the attacker.
contract TimelockBreakGlassFacet is Modifiers {
    /// @notice Delay between queueing and the earliest possible execution.
    uint256 public constant BREAK_GLASS_DELAY = 30 days;
    /// @notice Execution window after the delay elapses; after it the action is dead.
    uint256 public constant BREAK_GLASS_GRACE = 30 days;

    bytes32 private constant BREAK_GLASS_STORAGE_SLOT = keccak256("lemnicoin.breakglass.storage");

    struct BreakGlassEntry {
        uint64 queuedAt;
        uint64 eta;
        bool cancelled;
        bool executed;
    }

    struct BreakGlassStorage {
        mapping(bytes32 => BreakGlassEntry) entries;
    }

    event BreakGlassQueued(bytes32 indexed id, bytes32 indexed kind, address indexed queuedBy, uint256 eta);
    event BreakGlassCancelled(bytes32 indexed id, address indexed cancelledBy);
    event BreakGlassExecuted(bytes32 indexed id, address indexed executedBy);

    bytes32 private constant KIND_CUT = keccak256("BREAK_GLASS_CUT");
    bytes32 private constant KIND_OWNERSHIP = keccak256("BREAK_GLASS_OWNERSHIP");

    function _bg() private pure returns (BreakGlassStorage storage bg) {
        bytes32 slot = BREAK_GLASS_STORAGE_SLOT;
        assembly {
            bg.slot := slot
        }
    }

    function _cutId(
        IDiamondCut.FacetCut[] calldata _diamondCut,
        address _init,
        bytes calldata _calldata
    ) private pure returns (bytes32) {
        return keccak256(abi.encode(KIND_CUT, _diamondCut, _init, _calldata));
    }

    function _ownershipId(address _newOwner) private pure returns (bytes32) {
        return keccak256(abi.encode(KIND_OWNERSHIP, _newOwner));
    }

    function _queue(bytes32 id, bytes32 kind) private {
        BreakGlassEntry storage e = _bg().entries[id];
        // Re-queue is allowed only when the entry is not pending: never queued,
        // cancelled, executed, or its grace window already lapsed.
        if (e.eta != 0 && !e.cancelled && !e.executed && block.timestamp <= uint256(e.eta) + BREAK_GLASS_GRACE) {
            revert BreakGlassAlreadyPending(id, e.eta);
        }
        uint256 eta = block.timestamp + BREAK_GLASS_DELAY;
        _bg().entries[id] = BreakGlassEntry({
            queuedAt: uint64(block.timestamp),
            eta: uint64(eta),
            cancelled: false,
            executed: false
        });
        emit BreakGlassQueued(id, kind, msg.sender, eta);
    }

    function _requireExecutable(bytes32 id) private view returns (BreakGlassEntry storage e) {
        e = _bg().entries[id];
        if (e.eta == 0) revert BreakGlassNotQueued(id);
        if (e.cancelled) revert BreakGlassIsCancelled(id);
        if (e.executed) revert BreakGlassIsExecuted(id);
        if (block.timestamp < e.eta) revert BreakGlassNotReady(id, e.eta);
        if (block.timestamp > uint256(e.eta) + BREAK_GLASS_GRACE) {
            revert BreakGlassWindowExpired(id, uint256(e.eta) + BREAK_GLASS_GRACE);
        }
    }

    // =========================================================================
    // QUEUE (owner ECDSA only — that is the point; the delay is the protection)
    // =========================================================================

    /// @notice Queue an exact diamondCut for execution after BREAK_GLASS_DELAY.
    /// @return id The action id to watch, cancel, or execute.
    function queueBreakGlassCut(
        IDiamondCut.FacetCut[] calldata _diamondCut,
        address _init,
        bytes calldata _calldata
    ) external onlyOwner returns (bytes32 id) {
        id = _cutId(_diamondCut, _init, _calldata);
        _queue(id, KIND_CUT);
    }

    /// @notice Queue an ownership transfer for execution after BREAK_GLASS_DELAY.
    function queueBreakGlassOwnership(address _newOwner) external onlyOwner returns (bytes32 id) {
        if (_newOwner == address(0)) revert BreakGlassZeroOwner();
        id = _ownershipId(_newOwner);
        _queue(id, KIND_OWNERSHIP);
    }

    // =========================================================================
    // VETO (Falcon governance — callable from any address holding a valid sig)
    // =========================================================================

    /// @notice Cancel a queued break-glass action with a Falcon governance signature.
    /// @dev Signed payload is abi.encode(id); the digest binds msg.sender, so the
    ///      canceller uses their own governanceNonce. Deliberately NOT onlyOwner:
    ///      in the compromised-Safe scenario the defender cancels from any address.
    function cancelBreakGlass(
        bytes32 id,
        uint256 nonce,
        uint256 deadline,
        bytes calldata falconSalt40,
        uint256[] calldata falconS2
    ) external {
        BreakGlassEntry storage e = _bg().entries[id];
        if (e.eta == 0) revert BreakGlassNotQueued(id);
        if (e.cancelled) revert BreakGlassIsCancelled(id);
        if (e.executed) revert BreakGlassIsExecuted(id);
        LibLemnicoin.requireFalconGovernance(
            msg.sender,
            "BREAK_GLASS_CANCEL",
            abi.encode(id),
            nonce,
            deadline,
            falconSalt40,
            falconS2
        );
        e.cancelled = true;
        emit BreakGlassCancelled(id, msg.sender);
    }

    // =========================================================================
    // EXECUTE (owner ECDSA, only after the delay, only inside the grace window)
    // =========================================================================

    /// @notice Execute a queued diamondCut whose delay has elapsed.
    /// @dev Parameters are re-supplied and re-hashed: only the byte-exact queued
    ///      cut can run.
    function executeBreakGlassCut(
        IDiamondCut.FacetCut[] calldata _diamondCut,
        address _init,
        bytes calldata _calldata
    ) external onlyOwner {
        bytes32 id = _cutId(_diamondCut, _init, _calldata);
        BreakGlassEntry storage e = _requireExecutable(id);
        e.executed = true;
        emit BreakGlassExecuted(id, msg.sender);
        LibDiamond.diamondCut(_diamondCut, _init, _calldata);
    }

    /// @notice Execute a queued ownership transfer whose delay has elapsed.
    function executeBreakGlassOwnership(address _newOwner) external onlyOwner {
        if (_newOwner == address(0)) revert BreakGlassZeroOwner();
        bytes32 id = _ownershipId(_newOwner);
        BreakGlassEntry storage e = _requireExecutable(id);
        e.executed = true;
        emit BreakGlassExecuted(id, msg.sender);
        LibDiamond.setContractOwner(_newOwner);
    }

    // =========================================================================
    // VIEWS
    // =========================================================================

    /// @notice Full state of a break-glass entry (eta == 0 means never queued).
    function breakGlassEntry(bytes32 id)
        external
        view
        returns (uint256 queuedAt, uint256 eta, bool cancelled, bool executed, bool pending)
    {
        BreakGlassEntry storage e = _bg().entries[id];
        pending = e.eta != 0 && !e.cancelled && !e.executed
            && block.timestamp <= uint256(e.eta) + BREAK_GLASS_GRACE;
        return (e.queuedAt, e.eta, e.cancelled, e.executed, pending);
    }

    /// @notice Compute the id a given cut would queue under (for tooling/UIs).
    function computeBreakGlassCutId(
        IDiamondCut.FacetCut[] calldata _diamondCut,
        address _init,
        bytes calldata _calldata
    ) external pure returns (bytes32) {
        return _cutId(_diamondCut, _init, _calldata);
    }

    /// @notice Compute the id an ownership transfer would queue under.
    function computeBreakGlassOwnershipId(address _newOwner) external pure returns (bytes32) {
        return _ownershipId(_newOwner);
    }
}
