// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/IAccessControlDefaultAdminRules.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title Round 11 (g11c): every time comparison of the guard family at its boundary second, fuzzed.
/// @dev   Each test warps to a fuzzed base time (never the fixture's constant) and probes the second
///        before, at and after the edge, so an off-by-one in either direction fails. The table the
///        tests pin (code, then the documented wording):
///          window:      covers `t .. t+d-1`, closed at `t+d`           (`_effectiveMode`: `>=`; docs 4 "t … t+d-1")
///          approval:    usable through `t+ttl` inclusive               (`_preCheck`: `<=`; docs 10 "valid at exactly their expiry")
///          cooldown:    admin held back through `lockedAt + 1 day`      (`_checkAdminOrCouncilFor`: `<=`; task prints "HELD BACK until" with `<=`)
///          executeBefore: runs through `deadline` inclusive            (`executeBefore`: `>`)
///          hand-over:   acceptable strictly after `schedule` (OZ `<`), through `schedule + 30 days` inclusive (`>`)
///          timelock:    Ready at exactly `scheduled + delay` (OZ `>` Waiting), delay caps inclusive, `updateDelay` edges inclusive
///          durations:   `bypass` and `ttl` accept exactly 1 hour and exactly the cap; `changeDefaultAdminDelay` 1 day .. 30 days inclusive
///        Same-block order: a window opened and used in one block, a lockdown and the admin's lift in one
///        block (refused), the council's lift in the same block (allowed), an approval issued and spent in one block.
contract CuratorGuardG11cTimeBoundariesTest is CuratorGuardTestBase {
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;
    bytes internal settleData;
    bytes internal transferData;

    function setUp() public override {
        super.setUp();
        settleData = abi.encodeCall(MockProtocol.settleDeposit, (1));
        transferData = abi.encodeCall(IERC20.transfer, (attacker, 1));
        _allow(address(protocol), SETTLE);
    }

    function _base(uint64 t_) internal returns (uint64 _t) {
        _t = uint64(bound(uint256(t_), 1_700_000_000, 4_000_000_000));
        vm.warp(_t);
    }

    function _pre(address to_, bytes memory data_) internal {
        vm.prank(address(safe));
        guard.checkTransaction(to_, 0, data_, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", curator);
    }

    function _post() internal {
        vm.prank(address(safe));
        guard.checkAfterExecution(bytes32(uint256(7)), true);
    }

    /*//////////////////////////////////////////////////////////////
                              BYPASS WINDOW
    //////////////////////////////////////////////////////////////*/

    /// @dev A window opened at `t` for `d` covers `t .. t+d-1` on the hook, the view and the approval
    ///      refusal; at `t+d` all three flip, in the same block for pre- and post-hook.
    function testFuzz_window_covers_t_to_t_plus_d_minus_one(uint64 t_, uint64 d_, bool council_) public {
        uint64 _t = _base(t_);
        uint64 _cap = council_ ? _H().maxCouncilBypass() : _H().maxAdminBypass();
        uint64 _d = uint64(bound(uint256(d_), _H().minBypass(), _cap));
        _enforce();
        vm.prank(council_ ? council : vetro);
        guard.bypass(address(safe), _d);
        (uint64 _until, bool _isCouncil) = guard.bypassWindow(address(safe));
        assertEq(_until, _t + _d, "bypassUntil = t + d");
        assertEq(_isCouncil, council_);

        // Same block as the opening: open.
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Bypass));
        // Last second of the window: a call outside the policy passes, pre- and post-hook agree.
        vm.warp(_t + _d - 1);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Bypass), "open at t+d-1");
        _pre(address(token), transferData);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(safe), bytes32(uint256(7)), 0, CuratorGuard.Outcome.Bypass);
        _post();
        vm.prank(council_ ? council : vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.SafeInBypass.selector, address(safe)));
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, settleData, Operation.Call, 1 hours);

        // First second after the window: Lockdown for the view, the hook and the post-hook.
        vm.warp(_t + _d);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown), "closed at t+d");
        vm.prank(address(safe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        guard.checkTransaction(address(protocol), 0, settleData, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", curator);
        vm.prank(address(safe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.MissingSnapshot.selector, address(safe)));
        guard.checkAfterExecution(bytes32(uint256(7)), true);
        vm.prank(council_ ? council : vetro);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, settleData, Operation.Call, 1 hours);
        // The raw record keeps the window end for forensics.
        (_until, ) = guard.bypassWindow(address(safe));
        assertEq(_until, _t + _d, "raw record kept after expiry");
    }

    /// @dev Durations: exactly `MIN_BYPASS` and exactly the role's cap are accepted, one second
    ///      outside either edge is `InvalidDuration`.
    function testFuzz_bypass_duration_edges(uint64 t_, bool council_) public {
        _base(t_);
        _enforce();
        address _who = council_ ? council : vetro;
        uint64 _min = _H().minBypass();
        uint64 _cap = council_ ? _H().maxCouncilBypass() : _H().maxAdminBypass();
        vm.prank(_who);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, _min - 1));
        guard.bypass(address(safe), _min - 1);
        vm.prank(_who);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, _cap + 1));
        guard.bypass(address(safe), _cap + 1);
        vm.prank(_who);
        guard.bypass(address(safe), _min);
        vm.prank(_who);
        guard.bypass(address(safe), _cap); // renewable: a second window replaces the first
        (uint64 _until, ) = guard.bypassWindow(address(safe));
        assertEq(_until, uint64(block.timestamp) + _cap);
        // The admin's cap is not the council's: one second above 7 days is refused for the council.
        if (council_) {
            vm.prank(council);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, _cap + 1));
            guard.bypass(address(safe), _cap + 1);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                APPROVALS
    //////////////////////////////////////////////////////////////*/

    /// @dev An approval issued at `t` with `ttl` is usable through `t + ttl` inclusive (hook and dry
    ///      run agree), gone at `t + ttl + 1`; `approvalExpiry` reports the raw expiry either way.
    function testFuzz_approval_usable_through_expiry_inclusive(uint64 t_, uint64 ttl_, bool council_, bool spend_) public {
        uint64 _t = _base(t_);
        uint64 _cap = council_ ? _H().maxCouncilApprovalTtl() : _H().maxAdminApprovalTtl();
        uint64 _ttl = uint64(bound(uint256(ttl_), _H().minApprovalTtl(), _cap));
        // Lockdown (the fixture's default): the approval is the only way through.
        vm.prank(council_ ? council : vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(protocol), 0, settleData, Operation.Call, _ttl);
        assertEq(guard.approvalExpiry(_id), _t + _ttl, "raw expiry");

        vm.warp(_t + _ttl);
        guard.validateTransaction(address(safe), address(protocol), 0, settleData, Operation.Call); // dry run: no revert
        if (spend_) {
            vm.expectEmit(true, true, false, true, address(guard));
            emit CuratorGuardPolicy.ApprovalConsumed(address(safe), _id, address(0));
            _pre(address(protocol), settleData);
            vm.expectEmit(true, true, true, true, address(guard));
            emit CuratorGuard.TransactionChecked(address(safe), bytes32(uint256(7)), 0, CuratorGuard.Outcome.Approval);
            _post();
            assertEq(guard.approvalExpiry(_id), 0, "consumed at exactly the expiry");
            return;
        }
        vm.warp(_t + _ttl + 1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        guard.validateTransaction(address(safe), address(protocol), 0, settleData, Operation.Call);
        vm.prank(address(safe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        guard.checkTransaction(address(protocol), 0, settleData, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", curator);
        assertEq(guard.approvalExpiry(_id), _t + _ttl, "an expired record is not consumed, only dead");
    }

    /// @dev `ttl`: exactly `MIN_APPROVAL_TTL` and exactly the role's cap accepted, one second outside refused.
    function testFuzz_approval_ttl_edges(uint64 t_, bool council_) public {
        _base(t_);
        address _who = council_ ? council : vetro;
        uint64 _min = _H().minApprovalTtl();
        uint64 _cap = council_ ? _H().maxCouncilApprovalTtl() : _H().maxAdminApprovalTtl();
        vm.prank(_who);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, _min - 1));
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, settleData, Operation.Call, _min - 1);
        vm.prank(_who);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, _cap + 1));
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, settleData, Operation.Call, _cap + 1);
        vm.prank(_who);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(protocol), 0, settleData, Operation.Call, _min);
        assertEq(guard.approvalExpiry(_id), uint64(block.timestamp) + _min);
        vm.prank(_who);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, settleData, Operation.Call, _cap);
        assertEq(guard.approvalExpiry(_id), uint64(block.timestamp) + _cap, "re-approval overwrites the expiry");
    }

    /*//////////////////////////////////////////////////////////////
                             LOCKDOWN COOLDOWN
    //////////////////////////////////////////////////////////////*/

    /// @dev The admin's `enforce`, `bypass` and `approveTransaction` (directly and through
    ///      `executeBefore`) are refused through `lockedAt + 1 day` INCLUSIVE and free one second later;
    ///      the council is never held back, in the lockdown's own block included.
    function testFuzz_cooldown_holds_through_lockedAt_plus_one_day_inclusive(uint64 t_, uint64 gap_) public {
        uint64 _t = _base(t_);
        _enforce();
        _addGuardian(guardian);
        vm.prank(guardian);
        guard.lockdown(address(safe));
        assertEq(guard.lockedAt(address(safe)), _t);
        uint64 _cooldown = _H().lockdownCooldown();
        // Any second in (t, t + cooldown]: held back.
        uint64 _probe = _t + uint64(bound(uint256(gap_), 0, _cooldown));
        vm.warp(_probe);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(safe)));
        guard.enforce(address(safe));
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(safe)));
        guard.bypass(address(safe), 1 hours);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(safe)));
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, settleData, Operation.Call, 1 hours);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(safe)));
        guard.executeBefore(type(uint64).max, abi.encodeCall(guard.enforce, (address(safe))));
        // The boundary second itself: still held back.
        vm.warp(_t + _cooldown);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(safe)));
        guard.enforce(address(safe));
        // The council in the lockdown's own block: never held back (lift, re-lock, lift again).
        vm.warp(_t);
        vm.prank(council);
        guard.enforce(address(safe));
        vm.prank(guardian);
        guard.lockdown(address(safe));
        vm.prank(council);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, settleData, Operation.Call, 1 hours);
        // One second after the boundary: the admin is free.
        vm.warp(_t + _cooldown + 1);
        vm.prank(vetro);
        guard.enforce(address(safe));
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Enforced));
    }

    /*//////////////////////////////////////////////////////////////
                               executeBefore
    //////////////////////////////////////////////////////////////*/

    /// @dev The wrapper runs through `deadline` inclusive and refuses from `deadline + 1`.
    function testFuzz_executeBefore_deadline_inclusive(uint64 t_, uint64 ahead_) public {
        uint64 _t = _base(t_);
        uint64 _deadline = _t + uint64(bound(uint256(ahead_), 0, 365 days));
        vm.warp(_deadline);
        vm.prank(council);
        guard.executeBefore(_deadline, abi.encodeCall(guard.enforce, (address(safe))));
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Enforced));
        vm.warp(_deadline + 1);
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, _deadline));
        guard.executeBefore(_deadline, abi.encodeCall(guard.lockdown, (address(safe))));
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Enforced), "nothing ran");
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN HAND-OVER
    //////////////////////////////////////////////////////////////*/

    /// @dev With a fuzzed admin delay `D`: acceptance is refused at exactly `t + D` (OpenZeppelin's
    ///      schedule is strict), accepted at `t + D + 1`, still accepted at `t + D + 30 days`
    ///      (the guard's acceptance deadline is inclusive) and `DeadlinePassed` one second later.
    function testFuzz_admin_transfer_schedule_strict_and_acceptance_deadline_inclusive(uint64 t_, uint48 delay_, bool late_) public {
        uint64 _t = _base(t_);
        uint48 _delay = uint48(bound(uint256(delay_), 0, uint256(_H().maxAdminDelay())));
        CuratorGuardHarness _g = new CuratorGuardHarness(_delay, vetro, council);
        address _next = makeAddr("next-admin");
        vm.prank(vetro);
        _g.beginDefaultAdminTransfer(_next);
        (address _pending, uint48 _schedule) = _g.pendingDefaultAdmin();
        assertEq(_pending, _next);
        assertEq(uint256(_schedule), uint256(_t) + _delay, "schedule = t + D");

        vm.warp(_schedule);
        vm.prank(_next);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminDelay.selector, _schedule)
        );
        _g.acceptDefaultAdminTransfer();
        if (!late_) {
            vm.warp(uint256(_schedule) + 1);
            vm.prank(_next);
            _g.acceptDefaultAdminTransfer();
            assertEq(_g.defaultAdmin(), _next);
            return;
        }
        uint256 _acceptBy = uint256(_schedule) + uint256(_H().maxAdminDelay());
        vm.warp(_acceptBy + 1);
        vm.prank(_next);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, uint64(_schedule)));
        _g.acceptDefaultAdminTransfer();
        vm.warp(_acceptBy);
        vm.prank(_next);
        _g.acceptDefaultAdminTransfer();
        assertEq(_g.defaultAdmin(), _next, "accepted at exactly schedule + 30 days");
    }

    /// @dev `changeDefaultAdminDelay`: 1 day and 30 days accepted, one second outside either refused.
    function testFuzz_admin_delay_change_edges(uint64 t_) public {
        _base(t_);
        uint48 _min = _H().minAdminDelay();
        uint48 _max = _H().maxAdminDelay();
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminDelayTooLong.selector, _min - 1));
        guard.changeDefaultAdminDelay(_min - 1);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminDelayTooLong.selector, _max + 1));
        guard.changeDefaultAdminDelay(_max + 1);
        vm.prank(vetro);
        guard.changeDefaultAdminDelay(_max);
        vm.prank(vetro);
        guard.changeDefaultAdminDelay(_min);
        // Constructor: exactly the cap accepted, one second above refused.
        new CuratorGuardHarness(_max, vetro, council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminDelayTooLong.selector, _max + 1));
        new CuratorGuardHarness(_max + 1, vetro, council);
    }

    /*//////////////////////////////////////////////////////////////
                                 TIMELOCK
    //////////////////////////////////////////////////////////////*/

    function _timelock(uint256 minDelay_) internal returns (CuratorGuardTimelock _tl, address _proposer, address _veto) {
        _proposer = makeAddr("proposer");
        _veto = makeAddr("veto");
        address[] memory _p = new address[](1);
        _p[0] = _proposer;
        address[] memory _c = new address[](1);
        _c[0] = _veto;
        _tl = new CuratorGuardTimelock(minDelay_, _p, _c);
    }

    /// @dev An operation scheduled at `t` with `delay == minDelay` is Waiting through `t + minDelay - 1`
    ///      and Ready at exactly `t + minDelay`; any other operation delay is refused (G10c-1) and the
    ///      `updateDelay` edges are inclusive.
    function testFuzz_timelock_ready_at_exactly_scheduled_plus_delay(uint64 t_, uint256 minDelay_) public {
        uint64 _t = _base(t_);
        uint256 _minDelay = bound(minDelay_, 1 hours, 30 days);
        (CuratorGuardTimelock _tl, address _proposer, ) = _timelock(_minDelay);
        CuratorGuardHarness _g = new CuratorGuardHarness(0, address(_tl), council);
        bytes memory _call = abi.encodeCall(_g.enforce, (address(safe)));
        bytes32 _id = _tl.hashOperation(address(_g), 0, _call, bytes32(0), bytes32("s"));

        // Delay at proposal: above `minDelay` refused by this contract (here one second above 30 days), below
        // `minDelay` refused by OpenZeppelin.
        vm.prank(_proposer);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, uint256(30 days) + 1));
        _tl.schedule(address(_g), 0, _call, bytes32(0), bytes32("s"), uint256(30 days) + 1);
        vm.prank(_proposer);
        vm.expectRevert(abi.encodeWithSelector(TimelockController.TimelockInsufficientDelay.selector, _minDelay - 1, _minDelay));
        _tl.schedule(address(_g), 0, _call, bytes32(0), bytes32("s"), _minDelay - 1);

        vm.prank(_proposer);
        _tl.schedule(address(_g), 0, _call, bytes32(0), bytes32("s"), _minDelay);
        assertEq(_tl.getTimestamp(_id), uint256(_t) + _minDelay);
        vm.warp(uint256(_t) + _minDelay - 1);
        assertFalse(_tl.isOperationReady(_id), "Waiting one second before");
        vm.expectRevert(
            abi.encodeWithSelector(TimelockController.TimelockUnexpectedOperationState.selector, _id, bytes32(uint256(1) << uint8(TimelockController.OperationState.Ready)))
        );
        _tl.execute(address(_g), 0, _call, bytes32(0), bytes32("s"));
        vm.warp(uint256(_t) + _minDelay);
        assertTrue(_tl.isOperationReady(_id), "Ready at exactly scheduled + delay");
        _tl.execute(address(_g), 0, _call, bytes32(0), bytes32("s"));
        assertEq(uint8(_g.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Enforced));

        // `updateDelay` edges, checked at proposal: 1 hour and 30 days accepted, one second outside refused.
        _scheduleUpdateDelay(_tl, _proposer, _minDelay, 1 hours - 1, true);
        _scheduleUpdateDelay(_tl, _proposer, _minDelay, uint256(30 days) + 1, true);
        _scheduleUpdateDelay(_tl, _proposer, _minDelay, 1 hours, false);
        _scheduleUpdateDelay(_tl, _proposer, _minDelay, 30 days, false);
    }

    function _scheduleUpdateDelay(CuratorGuardTimelock tl_, address proposer_, uint256 delay_, uint256 newDelay_, bool refused_) internal {
        bytes memory _call = abi.encodeCall(tl_.updateDelay, (newDelay_));
        vm.prank(proposer_);
        if (refused_) vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, newDelay_));
        tl_.schedule(address(tl_), 0, _call, bytes32(0), bytes32(newDelay_), delay_);
    }

    /// @dev `getMinDelay()` is clamped whatever was stored: a scheduled `updateDelay` cannot store an
    ///      out-of-range value (refused at proposal), so the clamp is reached only by construction
    ///      arguments, which are refused too: the effective delay is always the stored one. Pinned at
    ///      both edges of the clamp.
    function testFuzz_timelock_effective_delay_is_the_stored_one_inside_the_clamp(uint64 t_, uint256 minDelay_) public {
        _base(t_);
        uint256 _minDelay = bound(minDelay_, 1 hours, 30 days);
        (CuratorGuardTimelock _tl, , ) = _timelock(_minDelay);
        assertEq(_tl.getMinDelay(), _minDelay);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, uint256(1 hours) - 1));
        _timelock(uint256(1 hours) - 1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, uint256(30 days) + 1));
        _timelock(uint256(30 days) + 1);
    }

    /*//////////////////////////////////////////////////////////////
                          SAME-BLOCK ORDERING
    //////////////////////////////////////////////////////////////*/

    /// @dev Within one block (one timestamp): the order of the calls decides, never the clock. A
    ///      lockdown and the admin's lift in one block: the lift is refused whatever the order (the
    ///      cooldown starts at `lockedAt == now`); the council's lift lands; a window opened and used in
    ///      one block passes; an approval issued and spent in one block passes; a window opened after
    ///      an approval voids it in the same block.
    function testFuzz_same_block_order_dependence(uint64 t_) public {
        uint64 _t = _base(t_);
        _enforce();
        _addGuardian(guardian);
        // lockdown, then the admin: refused; the council: lifts.
        vm.prank(guardian);
        guard.lockdown(address(safe));
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(safe)));
        guard.enforce(address(safe));
        vm.prank(council);
        guard.enforce(address(safe));
        // approval issued and spent in the same block.
        vm.prank(council);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(token), 0, transferData, Operation.Call, 1 hours);
        assertEq(guard.approvalExpiry(_id), _t + 1 hours);
        _pre(address(token), transferData);
        _post();
        assertEq(guard.approvalExpiry(_id), 0, "spent in the block it was issued");
        // approval, then a window in the same block: the approval is void (epoch), the window carries.
        vm.prank(council);
        _id = guard.approveTransaction(address(safe), address(0), address(token), 0, transferData, Operation.Call, 1 hours);
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        assertEq(guard.approvalExpiry(_id), 0, "voided by the window's epoch bump");
        _pre(address(token), transferData);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(safe), bytes32(uint256(7)), 0, CuratorGuard.Outcome.Bypass);
        _post();
        // a lockdown inside the window's block ends it; the council's cooldown-free lift re-opens it.
        vm.prank(guardian);
        guard.lockdown(address(safe));
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        (uint64 _until, ) = guard.bypassWindow(address(safe));
        assertEq(_until, 0, "window record cleared by the lockdown");
    }
}
