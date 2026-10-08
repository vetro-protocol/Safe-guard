// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G10aHarness} from "test/guards/G10aBase.sol";

/// @title Round 10 (g10a): a REFERENCE MODEL of the per-Safe state machine, driven in lockstep with the
///        real guard through real Safe v1.4.1 transactions.
/// @dev The repository's invariant handlers assert ghosts about what happened; this one predicts every
///      verdict (mode changes, windows, approvals, the cooldown, the admin hand-over, the hooks) from a
///      model written from docs section 4 and compares the model's state with the guard's views after
///      every call. Model: raw mode, window end and owner, `lockedAt`, approval epoch, three approval
///      records, two allowlist bits, the admin and the pending admin. Universe: three payloads
///      (`settleDeposit(1)` on a venue, `transfer(stranger, 1)` on the token, the empty call to a third
///      venue), the admin (which hands over to one of two successors and back), the council, a per-Safe
///      guardian, a stranger, the curator and time.
contract G10aModelHandler {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 internal constant DOMAIN_SEPARATOR_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
    bytes32 internal constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    G10aHarness public immutable guard;
    address public immutable safe;
    uint256 internal immutable pk;
    address public immutable council;
    address public immutable guardian;
    address public immutable stranger;
    address public immutable s1;
    address public immutable s2;
    address public immutable venue;
    address public immutable token;
    address public immutable third;

    // ---- the model ----
    CuratorGuardPolicy.Mode public mRaw;
    uint64 public mUntil;
    bool public mCouncil;
    uint64 public mLockedAt;
    uint32 public mEpoch;
    uint64[3] public mExpiry;
    uint32[3] public mEpochAt;
    bool public mSettle;
    bool public mNative;
    address public mAdmin;
    address public mPending;
    uint48 public mSchedule;

    // ---- ghosts ----
    bool public verdictMismatch;
    bytes32 public lastTag;
    bool public slotDirty;
    bool public reportMismatch;
    uint256 public execs;
    uint256[3] public passedBy; // per outcome
    uint256 public refused;
    uint256 public handovers;
    uint256 public calls;

    constructor(
        G10aHarness guard_,
        address safe_,
        uint256 pk_,
        address admin_,
        address council_,
        address guardian_,
        address stranger_,
        address venue_,
        address token_,
        address third_,
        address s1_,
        address s2_
    ) {
        guard = guard_;
        safe = safe_;
        pk = pk_;
        mAdmin = admin_;
        council = council_;
        guardian = guardian_;
        stranger = stranger_;
        venue = venue_;
        token = token_;
        third = third_;
        s1 = s1_;
        s2 = s2_;
    }

    /*//////////////////////////////////////////////////////////////
                                 MODEL
    //////////////////////////////////////////////////////////////*/

    function mEffective() public view returns (CuratorGuardPolicy.Mode) {
        if (mRaw == CuratorGuardPolicy.Mode.Bypass && block.timestamp >= mUntil) return CuratorGuardPolicy.Mode.Lockdown;
        return mRaw;
    }

    /// @dev The admin's lifts, windows and approvals are refused for a day after a lockdown.
    function _cooling() internal view returns (bool) {
        return block.timestamp <= uint256(mLockedAt) + 1 days;
    }

    /// @dev A record exists under the current-epoch id (expired or not): what `revokeApproval` needs.
    function _recorded(uint256 p_) internal view returns (bool) {
        return mExpiry[p_] != 0 && mEpochAt[p_] == mEpoch;
    }

    /// @dev What the hooks spend: recorded and not past its expiry second.
    function _live(uint256 p_) internal view returns (bool) {
        return _recorded(p_) && block.timestamp <= mExpiry[p_];
    }

    function _toLockdown() internal {
        mRaw = CuratorGuardPolicy.Mode.Lockdown;
        mUntil = 0;
        mCouncil = false;
        mLockedAt = uint64(block.timestamp);
    }

    function _toEnforced() internal {
        mRaw = CuratorGuardPolicy.Mode.Enforced;
        mUntil = 0;
        mCouncil = false;
    }

    function _toBypass(uint64 d_, bool council_) internal {
        mRaw = CuratorGuardPolicy.Mode.Bypass;
        mUntil = uint64(block.timestamp) + d_;
        mCouncil = council_;
        ++mEpoch;
    }

    /// @dev Expected live expiry as `approvalExpiry` reports it (0 when voided by an epoch bump).
    function expectedExpiry(uint256 p_) external view returns (uint64) {
        return _recorded(p_) ? mExpiry[p_] : 0;
    }

    function payload(uint256 p_) public view returns (address _to, bytes memory _data) {
        if (p_ == 0) return (venue, abi.encodeCall(MockProtocol.settleDeposit, (1)));
        if (p_ == 1) return (token, abi.encodeCall(IERC20.transfer, (stranger, 1)));
        return (third, "");
    }

    function id(uint256 p_) public view returns (bytes32) {
        (address _to, bytes memory _data) = payload(p_);
        return guard.computeApprovalId(safe, address(0), _to, 0, _data, Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
                               PLUMBING
    //////////////////////////////////////////////////////////////*/

    function _as(address who_, bytes memory call_) internal returns (bool _ok) {
        ++calls;
        vm.prank(who_);
        (_ok, ) = address(guard).call(call_);
    }

    function _check(bool ok_, bool expected_, bytes32 tag_) internal {
        if (ok_ != expected_) {
            verdictMismatch = true;
            lastTag = tag_;
        }
    }

    /// @dev Durations around the edges of a cap: one second under the floor, the floor, the cap, one
    ///      second over the cap, or anything in between.
    function _dur(uint256 seed_, uint256 cap_) internal pure returns (uint64) {
        uint256 _k = seed_ % 8;
        if (_k == 0) return uint64(1 hours - 1);
        if (_k == 1) return uint64(1 hours);
        if (_k == 2) return uint64(cap_);
        if (_k == 3) return uint64(cap_ + 1);
        return uint64(1 hours + (seed_ >> 3) % (cap_ - 1 hours + 1));
    }

    function _inRange(uint64 d_, uint256 cap_) internal pure returns (bool) {
        return d_ >= 1 hours && d_ <= cap_;
    }

    /*//////////////////////////////////////////////////////////////
                                 ADMIN
    //////////////////////////////////////////////////////////////*/

    function admin_lockdown() external {
        bool _ok = _as(mAdmin, abi.encodeCall(guard.lockdown, (safe)));
        _check(_ok, true, "admin_lockdown");
        if (_ok) _toLockdown();
    }

    function admin_lockdownAndRevoke() external {
        bool _ok = _as(mAdmin, abi.encodeCall(guard.lockdownAndRevoke, (safe)));
        _check(_ok, true, "admin_lockdownAndRevoke");
        if (_ok) {
            _toLockdown();
            ++mEpoch;
        }
    }

    function admin_enforce() external {
        bool _expected = !_cooling();
        bool _ok = _as(mAdmin, abi.encodeCall(guard.enforce, (safe)));
        _check(_ok, _expected, "admin_enforce");
        if (_ok) _toEnforced();
    }

    function admin_bypass(uint256 seed_) external {
        uint64 _d = _dur(seed_, 180 days);
        bool _expected = !_cooling() && _inRange(_d, 180 days);
        bool _ok = _as(mAdmin, abi.encodeCall(guard.bypass, (safe, _d)));
        _check(_ok, _expected, "admin_bypass");
        if (_ok) _toBypass(_d, false);
    }

    function admin_approve(uint256 seed_) external {
        uint256 _p = seed_ % 3;
        uint64 _ttl = _dur(seed_ >> 2, 180 days);
        bool _expected = !_cooling() && mEffective() != CuratorGuardPolicy.Mode.Bypass && _inRange(_ttl, 180 days);
        (address _to, bytes memory _data) = payload(_p);
        bool _ok = _as(mAdmin, abi.encodeCall(guard.approveTransaction, (safe, address(0), _to, 0, _data, Operation.Call, _ttl)));
        _check(_ok, _expected, "admin_approve");
        if (_ok) {
            mExpiry[_p] = uint64(block.timestamp) + _ttl;
            mEpochAt[_p] = mEpoch;
        }
    }

    function admin_revokeAll() external {
        bool _ok = _as(mAdmin, abi.encodeCall(guard.revokeAllApprovals, (safe)));
        _check(_ok, true, "admin_revokeAll");
        if (_ok) ++mEpoch;
    }

    function admin_revokeApproval(uint256 seed_) external {
        _revokeApproval(mAdmin, seed_ % 3, "admin_revokeApproval");
    }

    function admin_allowSettle() external {
        CuratorGuardPolicy.ParamRule[] memory _none;
        bool _ok = _as(mAdmin, abi.encodeCall(guard.allowFunction, (safe, venue, MockProtocol.settleDeposit.selector, false, _none)));
        _check(_ok, true, "admin_allowSettle");
        if (_ok) mSettle = true;
    }

    function admin_allowNative() external {
        bool _ok = _as(mAdmin, abi.encodeCall(guard.setNativeTransferAllowed, (safe, third, true)));
        _check(_ok, true, "admin_allowNative");
        if (_ok) mNative = true;
    }

    /// @dev The two-step hand-over (delay 0 in the fixture): begin overwrites any pending transfer; the
    ///      current admin is refused as its own successor (`AdminIsGuarded`).
    function admin_begin(uint256 seed_) external {
        address _t = seed_ % 2 == 0 ? s1 : s2;
        bool _expected = _t != mAdmin;
        bool _ok = _as(mAdmin, abi.encodeCall(guard.beginDefaultAdminTransfer, (_t)));
        _check(_ok, _expected, "admin_begin");
        if (_ok) {
            mPending = _t;
            mSchedule = uint48(block.timestamp);
        }
    }

    function admin_cancel() external {
        bool _ok = _as(mAdmin, abi.encodeCall(guard.cancelDefaultAdminTransfer, ()));
        _check(_ok, true, "admin_cancel");
        if (_ok) {
            mPending = address(0);
            mSchedule = 0;
        }
    }

    /// @dev Accepted strictly after the schedule and at most 30 days after it (`DeadlinePassed`).
    function successor_accepts() external {
        if (mPending == address(0)) return;
        bool _expected = block.timestamp > mSchedule && block.timestamp <= uint256(mSchedule) + 30 days;
        bool _ok = _as(mPending, abi.encodeCall(guard.acceptDefaultAdminTransfer, ()));
        _check(_ok, _expected, "successor_accepts");
        if (_ok) {
            mAdmin = mPending;
            mPending = address(0);
            mSchedule = 0;
            ++handovers;
        }
    }

    /*//////////////////////////////////////////////////////////////
                                COUNCIL
    //////////////////////////////////////////////////////////////*/

    function council_lockdown() external {
        bool _ok = _as(council, abi.encodeCall(guard.lockdown, (safe)));
        _check(_ok, true, "council_lockdown");
        if (_ok) _toLockdown();
    }

    function council_lockdownAndRevoke() external {
        bool _ok = _as(council, abi.encodeCall(guard.lockdownAndRevoke, (safe)));
        _check(_ok, true, "council_lockdownAndRevoke");
        if (_ok) {
            _toLockdown();
            ++mEpoch;
        }
    }

    /// @dev Never held back by the cooldown.
    function council_enforce() external {
        bool _ok = _as(council, abi.encodeCall(guard.enforce, (safe)));
        _check(_ok, true, "council_enforce");
        if (_ok) _toEnforced();
    }

    function council_bypass(uint256 seed_) external {
        uint64 _d = _dur(seed_, 7 days);
        bool _expected = _inRange(_d, 7 days);
        bool _ok = _as(council, abi.encodeCall(guard.bypass, (safe, _d)));
        _check(_ok, _expected, "council_bypass");
        if (_ok) _toBypass(_d, true);
    }

    function council_approve(uint256 seed_) external {
        uint256 _p = seed_ % 3;
        uint64 _ttl = _dur(seed_ >> 2, 7 days);
        bool _expected = mEffective() != CuratorGuardPolicy.Mode.Bypass && _inRange(_ttl, 7 days);
        (address _to, bytes memory _data) = payload(_p);
        bool _ok = _as(council, abi.encodeCall(guard.approveTransaction, (safe, address(0), _to, 0, _data, Operation.Call, _ttl)));
        _check(_ok, _expected, "council_approve");
        if (_ok) {
            mExpiry[_p] = uint64(block.timestamp) + _ttl;
            mEpochAt[_p] = mEpoch;
        }
    }

    function council_revokeAll() external {
        bool _ok = _as(council, abi.encodeCall(guard.revokeAllApprovals, (safe)));
        _check(_ok, true, "council_revokeAll");
        if (_ok) ++mEpoch;
    }

    function council_revokeApproval(uint256 seed_) external {
        _revokeApproval(council, seed_ % 3, "council_revokeApproval");
    }

    /*//////////////////////////////////////////////////////////////
                               GUARDIAN
    //////////////////////////////////////////////////////////////*/

    function guardian_lockdown() external {
        bool _ok = _as(guardian, abi.encodeCall(guard.lockdown, (safe)));
        _check(_ok, true, "guardian_lockdown");
        if (_ok) _toLockdown();
    }

    function guardian_lockdownAndRevoke() external {
        bool _ok = _as(guardian, abi.encodeCall(guard.lockdownAndRevoke, (safe)));
        _check(_ok, true, "guardian_lockdownAndRevoke");
        if (_ok) {
            _toLockdown();
            ++mEpoch;
        }
    }

    function guardian_revokeAll() external {
        bool _ok = _as(guardian, abi.encodeCall(guard.revokeAllApprovals, (safe)));
        _check(_ok, true, "guardian_revokeAll");
        if (_ok) ++mEpoch;
    }

    function guardian_revokeApproval(uint256 seed_) external {
        _revokeApproval(guardian, seed_ % 3, "guardian_revokeApproval");
    }

    function guardian_revokeSettle() external {
        bool _ok = _as(guardian, abi.encodeCall(guard.revokeFunction, (safe, venue, MockProtocol.settleDeposit.selector)));
        _check(_ok, true, "guardian_revokeSettle"); // a no-op when not allowed
        if (_ok) mSettle = false;
    }

    function guardian_disableNative() external {
        bool _ok = _as(guardian, abi.encodeCall(guard.setNativeTransferAllowed, (safe, third, false)));
        _check(_ok, true, "guardian_disableNative");
        if (_ok) mNative = false;
    }

    /// @dev A record under the CURRENT-epoch id is revocable even when expired; one from an older epoch
    ///      is unreachable under that id (`ApprovalNotFound`).
    function _revokeApproval(address who_, uint256 p_, bytes32 tag_) internal {
        bool _expected = _recorded(p_);
        bool _ok = _as(who_, abi.encodeCall(guard.revokeApproval, (id(p_))));
        _check(_ok, _expected, tag_);
        if (_ok) mExpiry[p_] = 0;
    }

    /*//////////////////////////////////////////////////////////////
                               STRANGER
    //////////////////////////////////////////////////////////////*/

    function stranger_tries(uint256 seed_) external {
        bytes[4] memory _c;
        _c[0] = abi.encodeCall(guard.enforce, (safe));
        _c[1] = abi.encodeCall(guard.bypass, (safe, uint64(1 days)));
        _c[2] = abi.encodeCall(guard.lockdown, (safe));
        _c[3] = abi.encodeCall(guard.acceptDefaultAdminTransfer, ());
        _check(_as(stranger, _c[seed_ % 4]), false, "stranger");
    }

    /*//////////////////////////////////////////////////////////////
                                CURATOR
    //////////////////////////////////////////////////////////////*/

    /// @dev The owner-signed path, predicted from the model: a window passes everything in this
    ///      universe (venue calls), else a live approval, else Lockdown refuses, else the allowlist.
    function curator_exec(uint256 seed_) external {
        uint256 _p = seed_ % 3;
        (bool _expected, CuratorGuard.Outcome _outcome) = _predict(_p);
        (address _to, bytes memory _data) = payload(_p);
        ++execs;
        vm.recordLogs();
        (bool _ok, bytes32 _hash) = _execOwner(_to, _data);
        _check(_ok, _expected, "curator_exec");
        // The transient slot of (safe, owner path) is idle again, after a pass and after a refusal.
        if (guard.tslot(safe, 0) != 0) slotDirty = true;
        if (_ok) {
            ++passedBy[uint256(_outcome)];
            if (_outcome == CuratorGuard.Outcome.Approval) mExpiry[_p] = 0;
            _checkReported(_hash, _outcome);
        } else {
            ++refused;
            vm.getRecordedLogs(); // a refused transaction leaves no event, by construction (it reverted)
        }
    }

    function _predict(uint256 p_) internal view returns (bool _expected, CuratorGuard.Outcome _outcome) {
        CuratorGuardPolicy.Mode _eff = mEffective();
        if (_eff == CuratorGuardPolicy.Mode.Bypass) return (true, CuratorGuard.Outcome.Bypass);
        if (_live(p_)) return (true, CuratorGuard.Outcome.Approval);
        if (_eff == CuratorGuardPolicy.Mode.Lockdown) return (false, _outcome);
        return ((p_ == 0 && mSettle) || (p_ == 2 && mNative), CuratorGuard.Outcome.Policy);
    }

    /// @dev Signs with the curator key and executes through the genuine `execTransaction`.
    function _execOwner(address to_, bytes memory data_) internal returns (bool _ok, bytes32 _hash) {
        _hash = _safeTxHash(to_, data_, ISafe(safe).nonce());
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(pk, _hash);
        bytes memory _sig = abi.encodePacked(_r, _s, _v);
        try ISafe(safe).execTransaction(to_, 0, data_, Operation.Call, 0, 0, 0, address(0), payable(address(0)), _sig) returns (bool _r_) {
            _ok = _r_;
        } catch {}
    }

    function _checkReported(bytes32 hash_, CuratorGuard.Outcome expected_) internal {
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        uint256 _n;
        for (uint256 i; i < _logs.length; ++i) {
            if (_logs[i].emitter != address(guard) || _logs[i].topics[0] != CuratorGuard.TransactionChecked.selector) continue;
            ++_n;
            if (
                _logs[i].topics[1] != bytes32(uint256(uint160(safe))) ||
                _logs[i].topics[2] != hash_ ||
                _logs[i].topics[3] != bytes32(uint256(expected_)) ||
                keccak256(_logs[i].data) != keccak256(abi.encode(uint8(0)))
            ) reportMismatch = true;
        }
        if (_n != 1) reportMismatch = true;
    }

    function _safeTxHash(address to_, bytes memory data_, uint256 nonce_) internal view returns (bytes32) {
        bytes32 _domain = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, safe));
        bytes32 _structHash = keccak256(
            abi.encode(SAFE_TX_TYPEHASH, to_, uint256(0), keccak256(data_), uint8(0), uint256(0), uint256(0), uint256(0), address(0), address(0), nonce_)
        );
        return keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), _domain, _structHash));
    }

    /*//////////////////////////////////////////////////////////////
                                  TIME
    //////////////////////////////////////////////////////////////*/

    function time_passes(uint256 seed_) external {
        vm.warp(block.timestamp + 1 + (seed_ % 10 days));
    }
}

contract G10aStateInvariantsTest is CuratorGuardTestBase {
    G10aHarness internal h;
    G10aModelHandler internal handler;
    address internal s1 = makeAddr("successor-1");
    address internal s2 = makeAddr("successor-2");

    function setUp() public override {
        super.setUp();
        h = new G10aHarness(0, vetro, council);
        h.seedSafe(address(safe));
        vm.prank(address(safe));
        safe.setGuard(address(h));
        guard = h;
        MockProtocol _third = new MockProtocol();
        vm.prank(vetro);
        h.setGuardian(address(safe), guardian, true);
        handler = new G10aModelHandler(h, address(safe), signerPk, vetro, council, guardian, attacker, address(protocol), address(token), address(_third), s1, s2);
        targetContract(address(handler));
    }

    /// @dev Every verdict the guard gave (role calls and the hooks) is the one the model predicted.
    function invariant_g10a_every_verdict_matches_the_model() public view {
        assertFalse(handler.verdictMismatch(), string(abi.encodePacked("verdict mismatch: ", handler.lastTag())));
    }

    /// @dev The guard's state IS the model's state: raw mode, window end and owner, `lockedAt`, epoch,
    ///      effective mode, the three approval records, the admin and the pending admin.
    function invariant_g10a_the_guard_state_is_the_model_state() public view {
        address _safe = address(safe);
        assertEq(uint8(h.rawMode(_safe)), uint8(handler.mRaw()), "raw mode");
        (uint64 _until, bool _council) = h.bypassWindow(_safe);
        assertEq(_until, handler.mUntil(), "window end");
        assertEq(_council, handler.mCouncil(), "window owner");
        assertEq(h.lockedAt(_safe), handler.mLockedAt(), "lockedAt");
        assertEq(h.approvalEpoch(_safe), handler.mEpoch(), "epoch");
        assertEq(uint8(h.mode(_safe)), uint8(handler.mEffective()), "effective mode");
        for (uint256 p; p < 3; ++p) assertEq(h.approvalExpiry(handler.id(p)), handler.expectedExpiry(p), "approval record");
        assertEq(h.defaultAdmin(), handler.mAdmin(), "admin");
        (address _pending, uint48 _schedule) = h.pendingDefaultAdmin();
        assertEq(_pending, handler.mPending(), "pending admin");
        assertEq(_schedule, handler.mSchedule(), "pending schedule");
    }

    /// @dev Structural invariants of the mode record (docs section 4): a window end is set exactly in
    ///      raw `Bypass`, a council flag only there, nothing points into the future beyond the caps, the
    ///      admin is never zero and never the council.
    function invariant_g10a_mode_record_is_well_formed() public view {
        address _safe = address(safe);
        (uint64 _until, bool _council) = h.bypassWindow(_safe);
        bool _rawBypass = h.rawMode(_safe) == CuratorGuardPolicy.Mode.Bypass;
        assertEq(_until != 0, _rawBypass, "window end <=> raw Bypass");
        if (_council) assertTrue(_rawBypass, "council flag only in Bypass");
        assertLe(h.lockedAt(_safe), block.timestamp, "lockedAt in the past");
        assertLe(_until, block.timestamp + 180 days, "window end within the admin cap");
        if (_council) assertLe(_until, block.timestamp + 7 days, "council window within its cap");
        assertTrue(h.defaultAdmin() != address(0), "an admin always exists");
        assertFalse(h.hasRole(h.COUNCIL_ROLE(), h.defaultAdmin()), "the admin is never the council");
    }

    function invariant_g10a_transient_slot_is_idle_between_transactions() public view {
        assertFalse(handler.slotDirty(), "a stale transient slot survived a Safe transaction");
        assertEq(h.tslot(address(safe), 0), bytes32(0));
        assertEq(h.tslot(address(safe), 1), bytes32(0));
    }

    function invariant_g10a_every_passed_transaction_is_reported_once_with_the_predicted_outcome() public view {
        assertFalse(handler.reportMismatch(), "TransactionChecked missing, duplicated or wrong");
    }

    /// @dev Liveness anchor: the model drives every branch at least once, deterministically.
    function test_g10a_model_handler_is_live() public {
        handler.admin_allowSettle();
        handler.admin_enforce();
        handler.curator_exec(0); // Policy
        handler.curator_exec(1); // refused: transfer is never allowlisted
        handler.council_approve(49); // payload 1 (49 % 3), ttl in range (49 >> 2 = 12, kind 4)
        handler.curator_exec(1); // Approval
        handler.council_bypass(4); // in range
        handler.curator_exec(1); // Bypass
        handler.admin_approve(49); // refused: SafeInBypass
        handler.guardian_lockdown(); // closes the window, arms the cooldown
        handler.admin_enforce(); // refused: cooldown
        handler.council_enforce(); // lifts at once
        handler.time_passes(2 days);
        handler.admin_bypass(0); // refused: one second under the floor
        handler.admin_bypass(1); // the floor
        handler.admin_enforce();
        handler.admin_begin(0);
        handler.successor_accepts(); // refused: same second as the schedule
        handler.time_passes(0);
        handler.successor_accepts(); // s1 is the admin now
        handler.admin_lockdownAndRevoke(); // as s1
        handler.admin_begin(0); // refused: s1 is the admin
        handler.admin_begin(1);
        handler.time_passes(0);
        handler.successor_accepts(); // s2
        handler.stranger_tries(0);
        assertFalse(handler.verdictMismatch(), string(abi.encodePacked("verdict mismatch: ", handler.lastTag())));
        assertEq(handler.execs(), 4);
        assertEq(handler.passedBy(0) + handler.passedBy(1) + handler.passedBy(2), 3, "three outcomes seen");
        assertEq(handler.passedBy(0), 1);
        assertEq(handler.passedBy(1), 1);
        assertEq(handler.passedBy(2), 1);
        assertEq(handler.refused(), 1);
        assertEq(handler.handovers(), 2);
        assertEq(h.defaultAdmin(), s2);
        assertFalse(handler.reportMismatch());
        assertFalse(handler.slotDirty());
        invariant_g10a_the_guard_state_is_the_model_state();
        invariant_g10a_mode_record_is_well_formed();
    }
}
