// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IAccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/IAccessControlDefaultAdminRules.sol";

import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {G9cBase} from "test/guards/G9c_Base.sol";

/// @title Round 14, reviewer g14c: THE FLOOR AND EVERY CLOCK. Pins of the relations the one-day floor
///        (commit 4892722, G13f-3) creates or leaves between the system's clocks, on the production
///        topology (real Safe v1.4.1 proxies, a real `CuratorGuardTimelock` at 2 days lowered to the
///        floor from its own queue), each at the boundary second:
///          MIN_DELAY_FLOOR == LOCKDOWN_COOLDOWN == MIN_ADMIN_DELAY == 1 day   (new equalities)
///          MIN_DELAY_CAP   == MAX_ADMIN_DELAY   == the acceptance window == 30 days (unchanged)
///        Every test passes on the commit as shipped; none depends on a held item.
contract G14c_ClocksTest is G9cBase {
    /// @dev A timelock self-call (here `updateDelay`) scheduled by p1 at the live delay and executed by a stranger.
    function _selfCall(bytes memory data_, bytes32 salt_) internal {
        _schedule(p1, p1Pk, address(tl), data_, NONE, salt_);
        vm.warp(block.timestamp + tl.getMinDelay());
        _execute(address(tl), data_, NONE, salt_);
    }

    /// @dev The four clocks at the floor are equal and both floors are reachable from the queue: nothing on
    ///      chain orders `defaultAdminDelay` above `minDelay` (the deploy script's strict rule is the only one).
    function test_the_floors_are_equal_and_a_proposer_can_equalise_the_two_delays() public {
        assertEq(tl.MIN_DELAY_FLOOR(), 1 days, "timelock floor");
        assertEq(uint256(g.minAdminDelay()), 1 days, "admin-delay floor");
        assertEq(uint256(g.lockdownCooldown()), 1 days, "cooldown");
        assertEq(tl.MIN_DELAY_CAP(), uint256(g.maxAdminDelay()), "cap == acceptance window == 30 days");
        _selfCall(abi.encodeCall(tl.updateDelay, (1 days)), "floor");
        _adminCall(abi.encodeCall(g.changeDefaultAdminDelay, (uint48(1 days))), "admin-floor");
        vm.warp(block.timestamp + 2 days + 1); // 3 d -> 1 d takes effect after the difference (OpenZeppelin)
        assertEq(tl.getMinDelay(), uint256(g.defaultAdminDelay()), "equal: V2-10's unchained cancel is a one-second edge");
    }

    /// @dev At the floor the cooldown is covered by the delay: a lockdown at or before the schedule holds a
    ///      Ready lift back for at most the Ready second itself (the cooldown's inclusive edge coincides with
    ///      Ready only when the lockdown and the schedule share a timestamp); a lockdown one second before the
    ///      schedule never holds it. Before the follow-up (floor one hour) a lockdown up to 23 hours before
    ///      the schedule held a Ready lift for the rest of the day.
    function test_at_the_floor_a_lockdown_before_the_schedule_holds_a_ready_lift_at_most_one_second() public {
        _configureCurator();
        _selfCall(abi.encodeCall(tl.updateDelay, (1 days)), "floor");
        bytes memory _lift = abi.encodeCall(g.enforce, (address(curatorSafe)));
        // 1. lockdown and schedule in the same second: held at Ready, free one second later.
        vm.prank(council);
        g.lockdown(address(curatorSafe));
        uint256 _l = block.timestamp;
        bytes32 _id = _schedule(p1, p1Pk, address(g), _lift, NONE, "lift");
        vm.warp(_l + 1 days);
        assertTrue(tl.isOperationReady(_id), "Ready at exactly scheduled + floor");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(curatorSafe)));
        _execute(address(g), _lift, NONE, "lift");
        vm.warp(_l + 1 days + 1);
        _execute(address(g), _lift, NONE, "lift");
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Enforced));
        // 2. lockdown one second before the schedule: the lift lands in its Ready second.
        vm.prank(council);
        g.lockdown(address(curatorSafe));
        uint256 _l2 = block.timestamp;
        vm.warp(_l2 + 1);
        bytes32 _id2 = _schedule(p1, p1Pk, address(g), _lift, NONE, "lift-2");
        vm.warp(_l2 + 1 + 1 days);
        assertTrue(tl.isOperationReady(_id2));
        _execute(address(g), _lift, NONE, "lift-2");
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Enforced));
    }

    /// @dev Equal delays (both floors): the UNCHAINED cancel of V2-10, scheduled in the block the hostile begin
    ///      landed, is Ready at `T_b + 1 day` while OpenZeppelin accepts strictly after the schedule, so the
    ///      honest side has a one-second edge in chain time; from `T_b + 1 day + 1` the order inside the block
    ///      decides (a 12-second slot lands on the edge second once in twelve). The chained cancel of §7.5
    ///      needs no ordering at all.
    function test_at_equal_delays_the_unchained_cancel_is_ready_one_second_before_the_acceptance() public {
        _configureCurator();
        _selfCall(abi.encodeCall(tl.updateDelay, (1 days)), "floor");
        _adminCall(abi.encodeCall(g.changeDefaultAdminDelay, (uint48(1 days))), "admin-floor");
        vm.warp(block.timestamp + 2 days + 1);
        assertEq(uint256(g.defaultAdminDelay()), 1 days);
        CuratorGuardTimelock _tl2 = _newTimelock(1 days);
        bytes memory _begin = abi.encodeCall(g.beginDefaultAdminTransfer, (address(_tl2)));
        _scheduleOn(tl, p2, p2Pk, address(g), _begin, NONE, "begin"); // the compromised proposer, the veto asleep
        vm.warp(block.timestamp + 1 days);
        _execute(address(g), _begin, NONE, "begin");
        uint256 _tb = block.timestamp;
        (, uint48 _sched) = g.pendingDefaultAdmin();
        assertEq(uint256(_sched), _tb + 1 days, "schedule = T_b + adminDelay");
        bytes memory _cancel = abi.encodeCall(g.cancelDefaultAdminTransfer, ());
        bytes32 _cid = _schedule(p1, p1Pk, address(g), _cancel, NONE, "cancel"); // unchained, same block as the begin
        bytes memory _accept = abi.encodeCall(g.acceptDefaultAdminTransfer, ());
        bytes32 _aid = _scheduleOn(_tl2, p1, p1Pk, address(g), _accept, NONE, "accept");
        // T_b + 1 day: the cancel is Ready (`<=`), the acceptance is not yet possible (`<`).
        vm.warp(_tb + 1 days);
        assertTrue(tl.isOperationReady(_cid), "cancel Ready at exactly T_b + delay");
        assertTrue(_tl2.isOperationReady(_aid), "the successor's operation is Ready too");
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminDelay.selector, _sched)
        );
        _executeOn(_tl2, address(g), _accept, NONE, "accept");
        // T_b + 1 day + 1: both executable; whoever lands first wins.
        uint256 _snap = vm.snapshotState();
        vm.warp(_tb + 1 days + 1);
        _executeOn(_tl2, address(g), _accept, NONE, "accept");
        assertEq(g.defaultAdmin(), address(_tl2), "acceptance first: the hand-over completes");
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, address(tl), bytes32(0)));
        _execute(address(g), _cancel, NONE, "cancel"); // the old admin lost the role: the cancel is a stranger's call now
        vm.revertToState(_snap);
        vm.warp(_tb + 1 days + 1);
        _execute(address(g), _cancel, NONE, "cancel");
        (address _pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, address(0), "cancel first: nothing to accept");
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlInvalidDefaultAdmin.selector, address(_tl2))
        );
        _executeOn(_tl2, address(g), _accept, NONE, "accept");
        assertEq(g.defaultAdmin(), address(tl));
    }

    /// @dev The NatSpec's "a successor timelock at the slowest delay still makes it" (acceptance within
    ///      `MAX_ADMIN_DELAY` after the schedule, 30 days, equal to `MIN_DELAY_CAP`): exactly when the successor
    ///      schedules its acceptance no later than `defaultAdminDelay` after the begin landed; one second later
    ///      the acceptance is dead and the successor's queue keeps a Ready corpse only its veto clears.
    function test_a_successor_at_the_cap_makes_the_acceptance_iff_it_schedules_within_the_admin_delay() public {
        _configureCurator();
        CuratorGuardTimelock _tlB = _newTimelock(30 days);
        _adminCall(abi.encodeCall(g.beginDefaultAdminTransfer, (address(_tlB))), "begin");
        uint256 _tb = block.timestamp;
        (, uint48 _sched) = g.pendingDefaultAdmin();
        assertEq(uint256(_sched), _tb + ADMIN_DELAY);
        bytes memory _accept = abi.encodeCall(g.acceptDefaultAdminTransfer, ());
        uint256 _snap = vm.snapshotState();
        vm.warp(_tb + ADMIN_DELAY); // the latest schedule that still makes it
        bytes32 _id = _scheduleOn(_tlB, p1, p1Pk, address(g), _accept, NONE, "accept");
        vm.warp(block.timestamp + 30 days);
        assertEq(block.timestamp, uint256(_sched) + 30 days, "the inclusive edge of the acceptance window");
        assertTrue(_tlB.isOperationReady(_id));
        _executeOn(_tlB, address(g), _accept, NONE, "accept");
        assertEq(g.defaultAdmin(), address(_tlB), "accepted at exactly schedule + 30 days");
        vm.revertToState(_snap);
        vm.warp(_tb + ADMIN_DELAY + 1);
        bytes32 _late = _scheduleOn(_tlB, p1, p1Pk, address(g), _accept, NONE, "late");
        vm.warp(block.timestamp + 30 days);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, uint64(_sched)));
        _executeOn(_tlB, address(g), _accept, NONE, "late");
        assertTrue(_tlB.isOperationReady(_late), "a dead acceptance stays Ready on the successor");
        assertEq(g.defaultAdmin(), address(tl));
    }

    /// @dev No honest sub-day flow is lost to the one-day queue: an admin window of `MIN_BYPASS` (one hour)
    ///      and an approval of `MIN_APPROVAL_TTL` start their clocks when the operation EXECUTES, not when it
    ///      is scheduled, so they survive the floor's delay intact (§7.5's lane advice stands).
    function test_an_hour_long_admin_window_survives_the_one_day_queue() public {
        _configureCurator();
        _selfCall(abi.encodeCall(tl.updateDelay, (1 days)), "floor");
        bytes memory _w = _wrap(uint64(block.timestamp + 15 days), abi.encodeCall(g.bypass, (address(curatorSafe), uint64(1 hours))));
        _schedule(p1, p1Pk, address(g), _w, NONE, "window");
        vm.warp(block.timestamp + 1 days);
        _execute(address(g), _w, NONE, "window");
        (uint64 _until, bool _council) = g.bypassWindow(address(curatorSafe));
        assertEq(_until, uint64(block.timestamp) + 1 hours, "the hour starts at execution");
        assertFalse(_council);
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Bypass));
        vm.warp(block.timestamp + 1 hours);
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Lockdown), "closed at t + d");
    }
}
