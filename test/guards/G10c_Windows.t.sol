// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G10cBase} from "test/guards/G10c_Base.sol";

/// @dev g10c: time and the open executor. A guarded veto Safe cancels at once from inside a council window
///      (G10c-5, a disagreement with g9c's "the exit takes a full minDelay"); the sync task's chained lift
///      under a slow signing round (G10c-8, pins G9e-5); an approval operation executed by a stranger the
///      second it is Ready runs its ttl from then (G10c-7, pins 7.5's "give admin approvals days").
contract G10c_WindowsTest is G10cBase {
    function test_G10c5_a_guarded_veto_safe_cancels_at_once_from_inside_a_council_window() public {
        _configureCurator();
        _installOn(veto, vetoPk); // the mistake: an unconfigured guarded veto Safe, in Lockdown
        bytes memory _hostile = abi.encodeCall(g.bypass, (address(curatorSafe), uint64(180 days)));
        bytes32 _hid = _schedule(p2, p2Pk, address(g), _hostile, NONE, "hostile");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(veto)));
        _cancel(_hid);
        uint256 _t = block.timestamp;
        vm.prank(council);
        g.bypass(address(veto), 1 hours);
        _cancel(_hid); // a plain call to a foreign contract: allowed inside a council window
        assertFalse(tl.isOperationPending(_hid));
        assertEq(block.timestamp, _t, "no delay at all");
        // The window does not carry the veto's own exit: that still takes a proposer's approval (7.6 step 5).
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, ISafe.setGuard.selector));
        _exec(veto, vetoPk, address(veto), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call);
    }

    /// @dev The sync task prepares the body (window minDelay + 14 days) and the lift (window minDelay +
    ///      cooldown + 1 day, predecessor = body) at T and counts both from T. A proposer Safe that takes
    ///      three days to sign schedules them at T + 3 d: the body lands at T + 5 d, the lift is Ready at
    ///      T + 5 d with a deadline of T + 4 d. Dead on arrival; without a council the Safe stays locked
    ///      until a new cycle (minDelay plus the next signing round).
    function test_G10c8_a_chained_lift_prepared_before_a_slow_signing_round_is_dead_while_its_body_lands() public {
        g = _newGuard(address(tl), address(0)); // no council: the lift is the admin's
        _configureCurator();
        _adminCall(abi.encodeCall(g.lockdown, (address(curatorSafe))), "incident");
        uint256 _prep = block.timestamp;
        bytes[] memory _body = new bytes[](1);
        _body[0] = _wrap(uint64(_prep + MIN_DELAY + 14 days), abi.encodeCall(g.allowFunction, (address(curatorSafe), address(protocol), MockProtocol.deposit.selector, false, _noRules())));
        uint64 _liftDeadline = uint64(_prep + MIN_DELAY + 1 days + 1 days);
        bytes[] memory _lift = new bytes[](1);
        _lift[0] = _wrap(_liftDeadline, abi.encodeCall(g.enforce, (address(curatorSafe))));
        vm.warp(_prep + 3 days); // the signing round
        bytes32 _bid = _scheduleBatch(p1, p1Pk, _guardTargets(1), _body, NONE, "body");
        bytes32 _lid = _scheduleBatch(p1, p1Pk, _guardTargets(1), _lift, _bid, "lift");
        vm.warp(_prep + 3 days + MIN_DELAY);
        _executeBatch(_guardTargets(1), _body, NONE, "body");
        assertTrue(tl.isOperationReady(_lid));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, _liftDeadline));
        _executeBatch(_guardTargets(1), _lift, _bid, "lift");
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Lockdown), "still frozen");
        // The next cycle: a fresh lift (its own operation), another minDelay after it is scheduled.
        bytes[] memory _lift2 = new bytes[](1);
        _lift2[0] = _wrap(uint64(block.timestamp + MIN_DELAY + 2 days), abi.encodeCall(g.enforce, (address(curatorSafe))));
        _scheduleBatch(p1, p1Pk, _guardTargets(1), _lift2, NONE, "lift-2");
        vm.warp(block.timestamp + MIN_DELAY);
        _executeBatch(_guardTargets(1), _lift2, NONE, "lift-2");
        assertTrue(_settle());
        assertEq(block.timestamp - _prep, 3 days + 2 * MIN_DELAY, "frozen for the signing round plus two cycles");
    }

    function test_G10c7_an_approval_executed_early_by_a_stranger_runs_its_ttl_from_then() public {
        _configureCurator();
        bytes memory _pause = abi.encodeCall(MockProtocol.wrap, ());
        bytes memory _approve = abi.encodeCall(g.approveTransaction, (address(curatorSafe), address(0), address(protocol), 0, _pause, Operation.Call, uint64(1 hours)));
        _schedule(p1, p1Pk, address(g), _approve, NONE, "a");
        vm.warp(block.timestamp + MIN_DELAY);
        _execute(address(g), _approve, NONE, "a"); // a stranger, the second it is Ready
        vm.warp(block.timestamp + 2 hours); // the signers meant to land the operation themselves, later
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.wrap.selector));
        _exec(curatorSafe, curatorPk, address(protocol), 0, _pause, Operation.Call);
    }
}
