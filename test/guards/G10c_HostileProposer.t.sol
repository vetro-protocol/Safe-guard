// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IAccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/IAccessControlDefaultAdminRules.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {G10cBase} from "test/guards/G10c_Base.sol";

/// @dev g10c, finding G10c-2 (the page rule) and G10c-4 (a removed proposer's queue). Docs section 6 and
///      7.7 tell the bots to page the veto Safe on a `CallScheduled` whose target is the timelock or a
///      foreign contract, or whose payload carries `grantRole` / `revokeRole` / `updateDelay` /
///      `beginDefaultAdminTransfer`. Everything a compromised proposer schedules ON THE GUARD with another
///      selector pages nothing by that letter: an approval of `setGuard(0)`, a 180-day admin window, and
///      `changeDefaultAdminDelay`, which quietly removes the second line of defence the runbook relies on
///      for a hand-over that slipped past the veto.
contract G10c_HostileProposerTest is G10cBase {
    address internal attacker = makeAddr("attacker-admin");
    bytes internal beginData;
    bytes internal cancelData;

    function setUp() public override {
        super.setUp();
        _configureCurator();
        beginData = abi.encodeCall(g.beginDefaultAdminTransfer, (attacker));
        cancelData = abi.encodeCall(g.cancelDefaultAdminTransfer, ());
    }

    /// @dev The letter of docs 6 / 7.7 for an operation addressed to the guard.
    function _pagesByTheLetter(address target_, bytes memory data_) internal view returns (bool) {
        if (target_ != address(g)) return true; // the timelock itself or a foreign contract
        bytes4 _s = _sel(data_);
        return
            _s == IAccessControl.grantRole.selector ||
            _s == IAccessControl.revokeRole.selector ||
            _s == TimelockController.updateDelay.selector ||
            _s == IAccessControlDefaultAdminRules.beginDefaultAdminTransfer.selector;
    }

    function _lowerAdminDelayToOneDay() internal returns (uint256 _inEffectFrom) {
        bytes memory _lower = abi.encodeCall(g.changeDefaultAdminDelay, (uint48(1 days)));
        assertFalse(_pagesByTheLetter(address(g), _lower), "changeDefaultAdminDelay is not in the page list");
        _schedule(p1, p1Pk, address(g), _lower, NONE, "lower");
        vm.warp(block.timestamp + MIN_DELAY);
        _execute(address(g), _lower, NONE, "lower");
        (uint48 _newDelay, uint48 _schedule) = g.pendingDefaultAdminDelay();
        assertEq(_newDelay, 1 days);
        // lowering waits the difference (3 days - 1 day): in effect once the schedule has passed
        assertEq(_schedule, block.timestamp + 2 days);
        _inEffectFrom = uint256(_schedule) + 1;
    }

    /// @dev An unwrapped approval of the curator Safe's own `setGuard(0)`, scheduled on the guard: nothing in
    ///      the page rule names it, anyone executes it after minDelay, and with the known quorum overlap
    ///      the proposer's keys are also a curator quorum, so the exit is signed at once.
    function test_G10c2_an_approval_of_setGuard_zero_scheduled_on_the_guard_pages_nothing_by_the_letter() public {
        bytes memory _exit = abi.encodeCall(ISafe.setGuard, (address(0)));
        bytes memory _approve = abi.encodeCall(
            g.approveTransaction,
            (address(curatorSafe), address(0), address(curatorSafe), 0, _exit, Operation.Call, uint64(180 days))
        );
        bytes memory _window = abi.encodeCall(g.bypass, (address(curatorSafe), uint64(180 days)));
        assertFalse(_pagesByTheLetter(address(g), _approve), "approveTransaction is not in the page list");
        assertFalse(_pagesByTheLetter(address(g), _window), "bypass is not in the page list");
        _schedule(p1, p1Pk, address(g), _approve, NONE, "quiet");
        vm.warp(block.timestamp + MIN_DELAY);
        _execute(address(g), _approve, NONE, "quiet"); // anyone
        assertTrue(_exec(curatorSafe, curatorPk, address(curatorSafe), 0, _exit, Operation.Call), "the approved exit");
        assertEq(_guardOf(curatorSafe), address(0), "the guard is gone two days after a CallScheduled the rule does not name");
    }

    /// @dev The documented second line at the deployed delays (admin delay 3 days > minDelay 2 days): a
    ///      hostile begin that slipped past the veto is cancelled by the honest proposer's scheduled
    ///      `cancelDefaultAdminTransfer` before the attacker can accept.
    function test_G10c2_the_documented_second_line_holds_while_the_admin_delay_exceeds_minDelay() public {
        _schedule(p1, p1Pk, address(g), beginData, NONE, "b");
        vm.warp(block.timestamp + MIN_DELAY);
        _execute(address(g), beginData, NONE, "b");
        (address _pending, uint48 _sched) = g.pendingDefaultAdmin();
        assertEq(_pending, attacker);
        assertEq(_sched, block.timestamp + ADMIN_DELAY);
        // the honest answer, scheduled once the begin is seen executed
        _schedule(p2, p2Pk, address(g), cancelData, NONE, "c");
        vm.warp(block.timestamp + MIN_DELAY);
        _execute(address(g), cancelData, NONE, "c");
        vm.warp(uint256(_sched) + 1);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlInvalidDefaultAdmin.selector, attacker));
        g.acceptDefaultAdminTransfer();
        assertEq(g.defaultAdmin(), address(tl));
    }

    /// @dev The same two moves after one un-paged `changeDefaultAdminDelay(1 day)`: the attacker's acceptance
    ///      (one day after the begin lands) comes before the honest cancel (minDelay after it is scheduled),
    ///      the attacker is the admin, exempt from everything, and approves the guard's removal at once.
    function test_G10c2_a_scheduled_changeDefaultAdminDelay_below_minDelay_removes_the_second_line() public {
        uint256 _from = _lowerAdminDelayToOneDay();
        bytes32 _bid = _schedule(p1, p1Pk, address(g), beginData, NONE, "b");
        // the honest side schedules an unchained cancel the moment it sees the begin (the runbook's answer)
        _schedule(p2, p2Pk, address(g), cancelData, NONE, "c");
        vm.warp(block.timestamp + MIN_DELAY);
        _execute(address(g), cancelData, NONE, "c"); // nothing pending yet: a no-op
        vm.warp(_from);
        assertEq(g.defaultAdminDelay(), 1 days);
        assertTrue(tl.isOperationReady(_bid));
        _execute(address(g), beginData, NONE, "b");
        (, uint48 _sched) = g.pendingDefaultAdmin();
        assertEq(_sched, block.timestamp + 1 days);
        _schedule(p2, p2Pk, address(g), cancelData, NONE, "c2"); // Ready in 2 days: a day too late
        vm.warp(uint256(_sched) + 1);
        vm.prank(attacker);
        g.acceptDefaultAdminTransfer();
        assertEq(g.defaultAdmin(), attacker, "the hand-over slipped past the second line");
        bytes memory _exit = abi.encodeCall(ISafe.setGuard, (address(0)));
        vm.prank(attacker);
        g.approveTransaction(address(curatorSafe), address(0), address(curatorSafe), 0, _exit, Operation.Call, 1 days);
        assertTrue(_exec(curatorSafe, curatorPk, address(curatorSafe), 0, _exit, Operation.Call));
        assertEq(_guardOf(curatorSafe), address(0));
    }

    /// @dev The better honest answer, at any admin delay: a `cancelDefaultAdminTransfer` chained behind the
    ///      hostile operation (`predecessor` = its id). It is executable by anyone in the block the begin
    ///      lands, whenever the attacker chooses to land it, and the acceptance needs at least a day.
    function test_G10c2_a_cancel_chained_behind_the_hostile_begin_wins_at_any_admin_delay() public {
        _lowerAdminDelayToOneDay();
        bytes32 _bid = _schedule(p1, p1Pk, address(g), beginData, NONE, "b");
        bytes32 _cid = _schedule(p2, p2Pk, address(g), cancelData, _bid, "c");
        // the attacker lets the begin sit Ready and lands it at a time of its choosing
        vm.warp(block.timestamp + 10 days);
        assertEq(g.defaultAdminDelay(), 1 days);
        _execute(address(g), beginData, NONE, "b");
        (, uint48 _sched) = g.pendingDefaultAdmin();
        assertEq(_sched, block.timestamp + 1 days);
        assertTrue(tl.isOperationReady(_cid));
        _execute(address(g), cancelData, _bid, "c"); // same block, anyone
        (address _pending, uint48 _s2) = g.pendingDefaultAdmin();
        assertEq(_pending, address(0));
        assertEq(_s2, 0);
        vm.warp(uint256(_sched) + 1);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlInvalidDefaultAdmin.selector, attacker));
        g.acceptDefaultAdminTransfer();
        assertEq(g.defaultAdmin(), address(tl));
    }

    /// @dev G10c-4 at `minDelay` (true with and without the G10c-1 clamp): the last operations a
    ///      proposer schedules before its removal is scheduled are Ready in the same block as the removal
    ///      and land after it, for anyone; the veto must cancel them whatever the removal does.
    function test_G10c4_the_last_operations_of_a_removed_proposer_land_after_its_removal() public {
        bytes memory _window = abi.encodeCall(g.bypass, (address(curatorSafe), uint64(180 days)));
        bytes32 _wid = _schedule(p1, p1Pk, address(g), _window, NONE, "last-window");
        bytes32 _prop = tl.PROPOSER_ROLE();
        bytes memory _remove = abi.encodeCall(IAccessControl.revokeRole, (_prop, address(p1)));
        _schedule(p2, p2Pk, address(tl), _remove, NONE, "remove"); // the same block
        vm.warp(block.timestamp + MIN_DELAY);
        _execute(address(tl), _remove, NONE, "remove");
        assertFalse(tl.hasRole(_prop, address(p1)));
        assertTrue(tl.isOperationReady(_wid), "still Ready after the role is gone");
        _execute(address(g), _window, NONE, "last-window");
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Bypass), "a 180-day admin window from a removed proposer");
        vm.prank(council);
        g.enforce(address(curatorSafe));
    }

    /// @dev G10c-4. Revoking a proposer does not touch its queue: what it scheduled before its removal stays
    ///      executable by anyone after the role is gone. With the operation delay pinned to the live
    ///      `getMinDelay()` (G10c-1) the queue outlives the role by at most `minDelay`, no longer by 30 days:
    ///      a 180-day admin window and a lockdown scheduled one second before the removal lands still land,
    ///      and the veto must cancel the whole queue, not just what paged.
    function test_G10c4_a_removed_proposers_long_dated_operations_survive_its_removal() public {
        uint256 _t0 = block.timestamp;
        bytes memory _window = abi.encodeCall(g.bypass, (address(curatorSafe), uint64(180 days)));
        bytes memory _lock = abi.encodeCall(g.lockdown, (address(curatorSafe)));
        bytes32 _prop = tl.PROPOSER_ROLE();
        // Long-dated operations are refused now (G10c-1): p1 cannot park anything past minDelay.
        vm.expectRevert(bytes("GS013"));
        _scheduleWithDelay(p1, p1Pk, address(g), _window, NONE, "late-window", 29 days);
        _schedule(p2, p2Pk, address(tl), abi.encodeCall(IAccessControl.revokeRole, (_prop, address(p1))), NONE, "remove");
        // One second before its removal lands, p1 schedules at the live minimum delay (its last act).
        vm.warp(_t0 + MIN_DELAY - 1);
        bytes32 _wid = _schedule(p1, p1Pk, address(g), _window, NONE, "late-window");
        bytes32 _lid = _schedule(p1, p1Pk, address(g), _lock, NONE, "late-lock");
        vm.warp(_t0 + MIN_DELAY);
        _execute(address(tl), abi.encodeCall(IAccessControl.revokeRole, (_prop, address(p1))), NONE, "remove");
        assertFalse(tl.hasRole(_prop, address(p1)));
        assertTrue(tl.isOperationPending(_wid) && tl.isOperationPending(_lid), "the queue outlives the role");
        // minDelay after p1's last act: anyone opens a 180-day ADMIN window on the curator Safe (nothing
        // checked inside it); the council closes it at once.
        vm.warp(_t0 + 2 * MIN_DELAY - 1);
        _execute(address(g), _window, NONE, "late-window");
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Bypass));
        (, bool _byCouncil) = g.bypassWindow(address(curatorSafe));
        assertFalse(_byCouncil, "an admin window: inert on both paths");
        vm.prank(council);
        g.enforce(address(curatorSafe));
        // The lockdown lands in the same second and re-arms the cooldown; the council lifts at once.
        _execute(address(g), _lock, NONE, "late-lock");
        assertEq(g.lockedAt(address(curatorSafe)), block.timestamp);
        vm.prank(council);
        g.enforce(address(curatorSafe));
        assertTrue(_settle());
        assertLe(block.timestamp - (_t0 + MIN_DELAY), MIN_DELAY, "the queue outlives the role by at most minDelay");
    }
}
