// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G9cBase} from "test/guards/G9c_Base.sol";

/// @dev g9c: the admin hand-over of docs section 7.5 from the production timelock to a FRESH
///      `CuratorGuardTimelock`, end to end through both queues; its 30-day acceptance deadline; what a
///      council can do to it (finding G9c-1); roles on the pending admin (Info); a Safe pending admin
///      whose handler is the guard (Info).
contract G9c_HandoverTest is G9cBase {
    CuratorGuardTimelock internal tlB;
    bytes internal acceptData;

    function setUp() public override {
        super.setUp();
        _configureCurator();
        acceptData = abi.encodeCall(g.acceptDefaultAdminTransfer, ());
    }

    /// @dev A schedules and executes `beginDefaultAdminTransfer(B)`; returns the schedule it set.
    function _begin(bytes32 salt_) internal returns (uint48 _sched) {
        bytes memory _call = _wrap(uint64(block.timestamp + MIN_DELAY + 14 days), abi.encodeCall(g.beginDefaultAdminTransfer, (address(tlB))));
        _adminCall(_call, salt_);
        address _pending;
        (_pending, _sched) = g.pendingDefaultAdmin();
        assertEq(_pending, address(tlB), "pending admin");
        assertEq(_sched, uint48(block.timestamp + ADMIN_DELAY), "schedule = now + admin delay");
    }

    /// @dev The successor at the SLOWEST delay the contract allows (30 days): the acceptance still
    ///      lands inside the 30-day window after the schedule, roles / policies / approvals survive, the
    ///      old queue is powerless and the new one widens (docs section 7.5).
    function test_timelock_to_timelock_handover_end_to_end_at_the_slowest_successor_delay() public {
        tlB = _newTimelock(30 days);
        bytes memory _pause = abi.encodeCall(MockProtocol.wrap, ());
        _adminCall(abi.encodeCall(g.approveTransaction, (address(curatorSafe), address(0), address(protocol), 0, _pause, Operation.Call, uint64(180 days))), "approve");
        uint48 _sched = _begin("begin");
        bytes32 _id = _scheduleOn(tlB, p1, p1Pk, address(g), acceptData, NONE, "accept");
        vm.warp(block.timestamp + 30 days);
        assertTrue(tlB.isOperationReady(_id));
        assertLe(block.timestamp, uint256(_sched) + 30 days, "inside the acceptance window");
        _executeOn(tlB, address(g), acceptData, NONE, "accept");
        assertEq(g.defaultAdmin(), address(tlB), "B is the admin");
        assertFalse(g.hasRole(g.DEFAULT_ADMIN_ROLE(), address(tl)), "A is not");
        assertTrue(g.hasRole(g.COUNCIL_ROLE(), council), "council survives");
        assertTrue(_settle(), "policy intact");
        assertTrue(_exec(curatorSafe, curatorPk, address(protocol), 0, _pause, Operation.Call), "A's approval still consumable");
        bytes memory _widen = abi.encodeCall(g.allowFunction, (address(curatorSafe), address(protocol), MockProtocol.deposit.selector, false, _noRules()));
        _schedule(p1, p1Pk, address(g), _widen, NONE, "stale");
        vm.warp(block.timestamp + MIN_DELAY);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        _execute(address(g), _widen, NONE, "stale");
        _scheduleOn(tlB, p2, p2Pk, address(g), _widen, NONE, "fresh");
        vm.warp(block.timestamp + 30 days);
        _executeOn(tlB, address(g), _widen, NONE, "fresh");
        (bool _allowed, , ) = g.functionPermission(address(curatorSafe), address(protocol), MockProtocol.deposit.selector);
        assertTrue(_allowed, "B widens");
    }

    function test_acceptance_expires_30_days_after_the_schedule_and_the_admin_re_arms_it() public {
        tlB = _newTimelock(30 days);
        uint48 _sched = _begin("begin");
        // B's proposers notice four days later: ready at schedule + 31 days, a day late.
        vm.warp(block.timestamp + 4 days);
        bytes32 _late = _scheduleOn(tlB, p1, p1Pk, address(g), acceptData, NONE, "late");
        vm.warp(block.timestamp + 30 days);
        assertGt(block.timestamp, uint256(_sched) + 30 days);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, uint64(_sched)));
        _executeOn(tlB, address(g), acceptData, NONE, "late");
        assertTrue(tlB.isOperationReady(_late), "a dead operation stays Ready: only B's veto clears it");
        assertEq(g.defaultAdmin(), address(tl), "A is still the admin");
        uint48 _again = _begin("begin-2");
        assertGt(_again, _sched, "re-armed");
        _scheduleOn(tlB, p1, p1Pk, address(g), acceptData, NONE, "accept-2");
        vm.warp(block.timestamp + 30 days);
        _executeOn(tlB, address(g), acceptData, NONE, "accept-2");
        assertEq(g.defaultAdmin(), address(tlB));
    }

    /// @dev G9c-1. `_requireUnguarded(.., transfer = true)` reads state the COUNCIL writes (the effective
    ///      mode and the per-Safe guardians of the pending admin), so a council that does not cooperate
    ///      stalls the hand-over for as long as it holds the role: renewable 7-day windows, an `enforce`,
    ///      or a planted guardian. Neither the pending admin nor anyone without a role can clear them. The
    ///      admin's way out is one batch (revoke the council, clear the plant), after which the
    ///      acceptance lands if its 30-day window is still open. Docs section 4 says "a rogue council
    ///      cannot veto its successor", which holds for role GRANTS only.
    function test_G9c1_a_council_stalls_a_handover_until_the_admin_evicts_it_in_one_batch() public {
        tlB = _newTimelock(MIN_DELAY);
        uint48 _sched = _begin("begin");
        bytes32 _id = _scheduleOn(tlB, p1, p1Pk, address(g), acceptData, NONE, "accept");
        vm.warp(uint256(_sched) + 1);
        assertTrue(tlB.isOperationReady(_id));
        bytes memory _guarded = abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, address(tlB));
        // 1. a window on the pending admin, renewable without bound
        vm.prank(council);
        g.bypass(address(tlB), 7 days);
        vm.expectRevert(_guarded);
        _executeOn(tlB, address(g), acceptData, NONE, "accept");
        vm.warp(block.timestamp + 6 days);
        vm.prank(council);
        g.bypass(address(tlB), 7 days);
        vm.expectRevert(_guarded);
        _executeOn(tlB, address(g), acceptData, NONE, "accept");
        // the pending admin has no role to clear it
        vm.prank(address(tlB));
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.lockdown(address(tlB));
        // 2. an `enforce` instead of a window
        vm.prank(council);
        g.enforce(address(tlB));
        vm.expectRevert(_guarded);
        _executeOn(tlB, address(g), acceptData, NONE, "accept");
        // 3. a planted per-Safe guardian, with the mode back to Lockdown
        vm.startPrank(council);
        g.lockdown(address(tlB));
        g.setGuardian(address(tlB), stranger, true);
        vm.stopPrank();
        vm.expectRevert(_guarded);
        _executeOn(tlB, address(g), acceptData, NONE, "accept");
        // The admin's recovery: ONE batch that nothing the council does can hold back.
        bytes[] memory _d = new bytes[](3);
        _d[0] = abi.encodeCall(IAccessControl.revokeRole, (g.COUNCIL_ROLE(), council));
        _d[1] = abi.encodeCall(g.setGuardian, (address(tlB), stranger, false));
        _d[2] = abi.encodeCall(g.lockdown, (address(tlB)));
        _adminBatch(_d, "evict");
        assertFalse(g.hasRole(g.COUNCIL_ROLE(), council));
        assertLe(block.timestamp, uint256(_sched) + 30 days, "still inside the acceptance window");
        _executeOn(tlB, address(g), acceptData, NONE, "accept");
        assertEq(g.defaultAdmin(), address(tlB));
    }

    /// @dev Info. The transfer predicate reads `COUNCIL_ROLE` but not `GUARDIAN_ROLE`: a pending admin
    ///      that holds the deployment-wide guardian role keeps it as admin, a state the grant rail
    ///      ("never the admin") refuses to create directly.
    function test_the_pending_admin_keeps_a_guardian_role_through_the_handover_but_a_council_role_blocks_it() public {
        tlB = _newTimelock(MIN_DELAY);
        _begin("begin");
        _adminCall(abi.encodeCall(g.setDeploymentGuardian, (address(tlB), true)), "guardian");
        _adminCall(abi.encodeCall(IAccessControl.grantRole, (g.COUNCIL_ROLE(), address(tlB))), "council");
        _scheduleOn(tlB, p1, p1Pk, address(g), acceptData, NONE, "accept");
        vm.warp(block.timestamp + MIN_DELAY);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, address(tlB)));
        _executeOn(tlB, address(g), acceptData, NONE, "accept");
        _adminCall(abi.encodeCall(IAccessControl.revokeRole, (g.COUNCIL_ROLE(), address(tlB))), "uncouncil");
        _executeOn(tlB, address(g), acceptData, NONE, "accept");
        assertEq(g.defaultAdmin(), address(tlB));
        assertTrue(g.hasRole(g.GUARDIAN_ROLE(), address(tlB)), "admin and deployment-wide guardian at once");
        vm.prank(address(tlB));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, address(tlB)));
        g.setDeploymentGuardian(address(tlB), true);
    }

    /// @dev Every role surface refuses a Safe whose fallback handler is this guard (V2-100), the acceptance
    ///      included since the round-13 follow-up (G9a-3 / G9c-3): a stranger cannot complete a hand-over to
    ///      such a Safe through its forwarding, the admin keeps its late cancel, and the pending Safe accepts
    ///      only after it changes its handler, a plain Safe transaction.
    function test_a_stranger_cannot_complete_a_handover_to_a_safe_whose_handler_is_the_guard() public {
        (ISafe _dao, uint256 _daoPk) = _newSafe("dao-safe");
        _exec(_dao, _daoPk, address(_dao), 0, abi.encodeWithSelector(0xf08a0323, address(g)), Operation.Call); // setFallbackHandler(guard)
        _adminCall(_wrap(uint64(block.timestamp + 30 days), abi.encodeCall(g.beginDefaultAdminTransfer, (address(_dao)))), "begin");
        vm.warp(block.timestamp + ADMIN_DELAY + 1);
        address _adminBefore = g.defaultAdmin();
        vm.prank(stranger);
        (bool _ok, bytes memory _ret) = address(_dao).call(acceptData);
        assertFalse(_ok, "forwarded acceptance refused");
        assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector);
        assertEq(g.defaultAdmin(), _adminBefore, "admin unchanged");
        (address _pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, address(_dao), "the hand-over stays pending: the admin can still cancel");
        // Once the Safe drops the handler it accepts as itself, through a plain Safe transaction.
        _exec(_dao, _daoPk, address(_dao), 0, abi.encodeWithSelector(0xf08a0323, address(0)), Operation.Call);
        assertTrue(_exec(_dao, _daoPk, address(g), 0, acceptData, Operation.Call), "accepted as itself");
        assertEq(g.defaultAdmin(), address(_dao));
    }
}
