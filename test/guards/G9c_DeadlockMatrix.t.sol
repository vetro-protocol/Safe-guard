// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IAccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/IAccessControlDefaultAdminRules.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G9cBase} from "test/guards/G9c_Base.sol";

/// @dev A Lagoon-shaped venue whose owner function re-homes custody (docs section 6: the one way out of
///      a veto-only deadlock is a council-approved custody move).
contract MockVault {
    address public safe;

    constructor(address safe_) {
        safe = safe_;
    }

    function updateSafe(address safe_) external {
        safe = safe_;
    }
}

/// @dev g9c: every deadlock or denial-of-service path of the role / time machinery with its recovery,
///      on the production topology with real Safes: the admin can never be lost; the veto-only
///      deadlock keeps the council lane and the guard; a re-lock loop without a council is bounded;
///      a cancelled predecessor strands its successor until the identical one is rescheduled; the
///      timelock's own roles cannot be renounced away.
contract G9c_DeadlockMatrixTest is G9cBase {
    function _expectAdminCallReverts(bytes memory data_, bytes32 salt_, bytes memory err_) internal {
        _schedule(p1, p1Pk, address(g), data_, NONE, salt_);
        vm.warp(block.timestamp + MIN_DELAY);
        vm.expectRevert(err_);
        _execute(address(g), data_, NONE, salt_);
    }

    function test_the_admin_role_can_neither_be_renounced_nor_revoked_nor_zeroed_in_any_state() public {
        _configureCurator();
        bytes32 _admin = g.DEFAULT_ADMIN_ROLE();
        bytes memory _renounce = abi.encodeCall(IAccessControl.renounceRole, (_admin, address(tl)));
        bytes4 _delayErr = IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminDelay.selector;
        // (a) nothing pending
        _expectAdminCallReverts(_renounce, "r1", abi.encodeWithSelector(_delayErr, uint48(0)));
        // (b) a pending successor whose delay passed: the library wants a pending ZERO address
        _adminCall(abi.encodeCall(g.beginDefaultAdminTransfer, (stranger)), "begin");
        (, uint48 _sched) = g.pendingDefaultAdmin();
        vm.warp(uint256(_sched) + 1);
        _expectAdminCallReverts(_renounce, "r2", abi.encodeWithSelector(_delayErr, _sched));
        // (c) after a cancel the schedule is unset again
        _adminCall(abi.encodeCall(g.cancelDefaultAdminTransfer, ()), "cancel");
        _expectAdminCallReverts(_renounce, "r3", abi.encodeWithSelector(_delayErr, uint48(0)));
        // (d) the zero address can never become pending
        _expectAdminCallReverts(abi.encodeCall(g.beginDefaultAdminTransfer, (address(0))), "zero", abi.encodeWithSelector(CuratorGuardPolicy.AdminCannotBeZero.selector));
        // (e) the library refuses `revokeRole` / `grantRole` of the admin role outright
        bytes4 _rulesErr = IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminRules.selector;
        _expectAdminCallReverts(abi.encodeCall(IAccessControl.revokeRole, (_admin, address(tl))), "rv", abi.encodeWithSelector(_rulesErr));
        _expectAdminCallReverts(abi.encodeCall(IAccessControl.grantRole, (_admin, stranger)), "gr", abi.encodeWithSelector(_rulesErr));
        assertEq(g.defaultAdmin(), address(tl));
    }

    /// @dev docs section 6: a compromised veto-only canceller is a deadlock, never a takeover. Nothing of
    ///      the admin's executes again (widening, the veto's own removal, a hand-over), the council lane
    ///      keeps settlement going, the guard stays on the Safe, and custody leaves only by a
    ///      council-approved venue call.
    function test_veto_only_canceller_deadlock_keeps_the_council_lane_and_the_guard_in_place() public {
        _configureCurator();
        MockVault _vault = new MockVault(address(curatorSafe));
        bytes memory _widen = abi.encodeCall(g.allowFunction, (address(curatorSafe), address(protocol), MockProtocol.deposit.selector, false, _noRules()));
        bytes memory _unveto = abi.encodeCall(IAccessControl.revokeRole, (tl.CANCELLER_ROLE(), address(veto)));
        bytes memory _handover = abi.encodeCall(g.beginDefaultAdminTransfer, (stranger));
        _cancel(_schedule(p1, p1Pk, address(g), _widen, NONE, "w"));
        _cancel(_schedule(p2, p2Pk, address(tl), _unveto, NONE, "u"));
        _cancel(_schedule(p1, p1Pk, address(g), _handover, NONE, "h"));
        vm.warp(block.timestamp + 30 days);
        assertFalse(tl.isOperationPending(tl.hashOperation(address(g), 0, _widen, NONE, "w")));
        assertTrue(tl.hasRole(tl.CANCELLER_ROLE(), address(veto)), "the veto keeps its seat");
        // The council lane: a lockdown, its lift, a 7-day approval of the custody move, settlement.
        vm.prank(council);
        g.lockdown(address(curatorSafe));
        vm.prank(council);
        g.enforce(address(curatorSafe));
        assertTrue(_settle());
        bytes memory _move = abi.encodeCall(MockVault.updateSafe, (stranger));
        vm.prank(council);
        g.approveTransaction(address(curatorSafe), address(0), address(_vault), 0, _move, Operation.Call, 7 days);
        assertTrue(_exec(curatorSafe, curatorPk, address(_vault), 0, _move, Operation.Call));
        assertEq(_vault.safe(), stranger, "custody re-homed by a council-approved venue call");
        // What the council can never do: take the guard off.
        bytes memory _exit = abi.encodeCall(ISafe.setGuard, (address(0)));
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, ISafe.setGuard.selector, Operation.Call));
        g.approveTransaction(address(curatorSafe), address(0), address(curatorSafe), 0, _exit, Operation.Call, 7 days);
        assertEq(_guardOf(curatorSafe), address(g));
    }

    /// @dev docs section 6: "without a council the bound is minDelay plus a day": the removal as its own
    ///      operation, the lift chained behind it with a window of cooldown + 1 day, a rogue per-Safe key
    ///      re-locking until the last second before its removal lands.
    function test_relock_loop_without_a_council_is_bounded_by_minDelay_plus_one_day() public {
        g = _newGuard(address(tl), address(0));
        _configureCurator();
        address _rogue = makeAddr("rogue");
        _adminCall(abi.encodeCall(g.setGuardian, (address(curatorSafe), _rogue, true)), "rogue");
        uint256 _t0 = block.timestamp;
        vm.prank(_rogue);
        g.lockdown(address(curatorSafe));
        bytes memory _remove = abi.encodeCall(g.setGuardian, (address(curatorSafe), _rogue, false));
        bytes32 _rid = _schedule(p1, p1Pk, address(g), _remove, NONE, "remove");
        bytes memory _lift = _wrap(uint64(_t0 + MIN_DELAY + 1 days + 1 days), abi.encodeCall(g.enforce, (address(curatorSafe))));
        _schedule(p1, p1Pk, address(g), _lift, _rid, "lift");
        for (uint256 i = 1; i <= 3; ++i) {
            vm.warp(_t0 + i * 12 hours);
            vm.prank(_rogue);
            g.lockdown(address(curatorSafe));
        }
        vm.warp(_t0 + MIN_DELAY - 1);
        vm.prank(_rogue);
        g.lockdown(address(curatorSafe));
        uint256 _lastLock = block.timestamp;
        vm.warp(_t0 + MIN_DELAY);
        _execute(address(g), _remove, NONE, "remove"); // the removal is never held back
        vm.prank(_rogue);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.lockdown(address(curatorSafe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(curatorSafe)));
        _execute(address(g), _lift, _rid, "lift");
        vm.warp(_lastLock + 1 days + 1);
        _execute(address(g), _lift, _rid, "lift");
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Enforced));
        assertTrue(_settle());
        assertLe(block.timestamp - _t0, MIN_DELAY + 1 days + 1, "frozen for at most minDelay plus a day");
    }

    /// @dev docs 7.5: "cancelling a predecessor does not cancel its successor ... or a proposer
    ///      re-schedules the identical predecessor and the successor fires".
    function test_cancelled_predecessor_strands_its_successor_until_the_identical_one_is_rescheduled() public {
        _configureCurator();
        bytes memory _a = abi.encodeCall(g.allowFunction, (address(curatorSafe), address(protocol), MockProtocol.deposit.selector, false, _noRules()));
        bytes memory _b = abi.encodeCall(g.setNativeTransferAllowed, (address(curatorSafe), address(protocol), true));
        bytes32 _aid = _schedule(p1, p1Pk, address(g), _a, NONE, "a");
        bytes32 _bid = _schedule(p1, p1Pk, address(g), _b, _aid, "b");
        _cancel(_aid);
        vm.warp(block.timestamp + 30 days);
        assertTrue(tl.isOperationReady(_bid), "the successor's own time has passed");
        vm.expectRevert(abi.encodeWithSelector(TimelockController.TimelockUnexecutedPredecessor.selector, _aid));
        _execute(address(g), _b, _aid, "b");
        assertEq(_schedule(p1, p1Pk, address(g), _a, NONE, "a"), _aid, "the same id is schedulable again");
        vm.warp(block.timestamp + MIN_DELAY);
        _execute(address(g), _a, NONE, "a");
        _execute(address(g), _b, _aid, "b");
        assertTrue(tl.isOperationDone(_bid));
        assertTrue(g.isNativeTransferAllowed(address(curatorSafe), address(protocol)));
    }

    /// @dev The timelock's roles cannot be renounced away: its own admin role (a scheduled self-call), the
    ///      open executor (nobody is `address(0)`), the last proposer and the last canceller (Safe
    ///      transactions of the holders themselves).
    function test_timelock_roles_cannot_be_renounced_into_a_deadlock() public {
        bytes memory _r1 = abi.encodeCall(IAccessControl.renounceRole, (tl.DEFAULT_ADMIN_ROLE(), address(tl)));
        _schedule(p1, p1Pk, address(tl), _r1, NONE, "r1");
        vm.warp(block.timestamp + MIN_DELAY);
        vm.expectRevert(CuratorGuardTimelock.SelfAdminRequired.selector);
        _execute(address(tl), _r1, NONE, "r1");
        bytes32 _prop = tl.PROPOSER_ROLE();
        bytes32 _canc = tl.CANCELLER_ROLE();
        _exec(p1, p1Pk, address(tl), 0, abi.encodeCall(IAccessControl.renounceRole, (_prop, address(p1))), Operation.Call);
        assertEq(tl.proposerCount(), 1);
        vm.expectRevert(bytes("GS013")); // LastRoleHolder inside the Safe transaction
        _exec(p2, p2Pk, address(tl), 0, abi.encodeCall(IAccessControl.renounceRole, (_prop, address(p2))), Operation.Call);
        assertTrue(tl.hasRole(_prop, address(p2)));
        vm.expectRevert(bytes("GS013"));
        _exec(veto, vetoPk, address(tl), 0, abi.encodeCall(IAccessControl.renounceRole, (_canc, address(veto))), Operation.Call);
        assertTrue(tl.hasRole(_canc, address(veto)));
        assertTrue(tl.hasRole(tl.EXECUTOR_ROLE(), address(0)));
    }
}
