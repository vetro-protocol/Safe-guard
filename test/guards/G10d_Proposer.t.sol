// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IAccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/IAccessControlDefaultAdminRules.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G10dBase, HostileVenue} from "test/guards/G10d_Base.sol";

/// @title G10d_Proposer: a compromised proposer Safe, a front-runner on the queue, a stranger
/// @notice Round 10, reviewer g10d. `p1` is the compromised proposer (its one signer is the attacker),
///         `p2` and the veto Safe are honest, the council is honest unless replaced, `stranger` holds no
///         role and watches the queue. Every operation is a genuine Safe transaction of the proposer and
///         is executed by the stranger (the executor role is open).
contract G10d_ProposerTest is G10dBase {
    function setUp() public override {
        super.setUp();
        _configureCurator();
    }

    /*//////////////////////////////////////////////////////////////
                         COMPROMISED PROPOSER SAFE
    //////////////////////////////////////////////////////////////*/

    /// @dev The takeover batch (honest council out, attacker in, a 180-day admin window) is public for
    ///      minDelay and the veto cancels it. The veto's own removal cannot be scheduled bare (the last-holder
    ///      rail), only as grant-then-revoke, which the veto sees and cancels too. Re-scheduling is a war of
    ///      one Safe transaction per round for each side, and the compromised proposer can neither cancel
    ///      the honest proposer's operations nor its own removal.
    function test_compromised_proposer_takeover_is_vetoed_and_the_veto_cannot_be_removed_without_its_consent() public {
        (address[] memory _t, bytes[] memory _p) = _takeover();
        bytes32 _idA = _scheduleBatch(p1, p1Pk, _t, _p, NONE, "A");
        bytes memory _bare = abi.encodeCall(tl.revokeRole, (tl.CANCELLER_ROLE(), address(veto)));
        _schedule(p1, p1Pk, address(tl), _bare, NONE, "B");
        address[] memory _tt = new address[](2);
        _tt[0] = address(tl);
        _tt[1] = address(tl);
        bytes[] memory _pp = new bytes[](2);
        _pp[0] = abi.encodeCall(tl.grantRole, (tl.CANCELLER_ROLE(), stranger));
        _pp[1] = _bare;
        bytes32 _idC = _scheduleBatch(p1, p1Pk, _tt, _pp, NONE, "C");

        // The veto cancels A and C inside minDelay (one Safe transaction each).
        _cancel(_idA);
        _cancel(_idC);
        vm.warp(block.timestamp + MIN_DELAY);
        assertFalse(tl.isOperationPending(_idA));
        assertFalse(tl.isOperationPending(_idC));
        // B is Ready and dead: the last canceller cannot be removed.
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.LastRoleHolder.selector, tl.CANCELLER_ROLE()));
        tl.execute(address(tl), 0, _bare, NONE, "B");
        assertTrue(g.hasRole(g.COUNCIL_ROLE(), council));
        assertTrue(tl.hasRole(tl.CANCELLER_ROLE(), address(veto)));
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Enforced));

        // The war: every re-schedule is one cancel.
        for (uint256 i; i < 3; ++i) {
            bytes32 _id = _scheduleBatch(p1, p1Pk, _t, _p, NONE, bytes32(uint256(100 + i)));
            _cancel(_id);
            assertFalse(tl.isOperationPending(_id));
        }

        // The honest proposer schedules the compromised one's removal; p1 cannot cancel it (not a canceller:
        // its Safe transaction fails inside the Safe, GS013), and it lands after minDelay.
        bytes memory _remove = abi.encodeCall(tl.revokeRole, (tl.PROPOSER_ROLE(), address(p1)));
        bytes32 _idR = _schedule(p2, p2Pk, address(tl), _remove, NONE, "R");
        vm.expectRevert(bytes("GS013"));
        _exec(p1, p1Pk, address(tl), 0, abi.encodeCall(tl.cancel, (_idR)), Operation.Call);
        vm.warp(block.timestamp + MIN_DELAY);
        _execute(address(tl), _remove, NONE, "R");
        assertFalse(tl.hasRole(tl.PROPOSER_ROLE(), address(p1)));
        assertEq(tl.proposerCount(), 1);
    }

    /// @dev With the veto asleep every admin power lands after minDelay: the council is the attacker's key
    ///      and the curator Safe sits in a 180-day admin window. Custody still needs the curator's quorum:
    ///      no admin, council or stranger action produces a Safe transaction, and the window is useless
    ///      without signers. The honest curator keeps settling (reported Bypass); the woken veto and the
    ///      honest proposer evict the attacker and the new council lifts at once.
    function test_with_the_veto_asleep_every_admin_power_lands_but_custody_still_needs_the_curators_quorum() public {
        (address[] memory _t, bytes[] memory _p) = _takeover();
        _scheduleBatch(p1, p1Pk, _t, _p, NONE, "A");
        vm.warp(block.timestamp + MIN_DELAY);
        _executeBatch(_t, _p, NONE, "A");
        assertTrue(g.hasRole(g.COUNCIL_ROLE(), stranger));
        assertFalse(g.hasRole(g.COUNCIL_ROLE(), council));
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Bypass));
        uint256 _custody = _balance();

        _strangerCannotMoveCustody();
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.SafeInBypass.selector, address(curatorSafe)));
        g.approveTransaction(address(curatorSafe), address(0), address(token), 0, abi.encodeWithSelector(TRANSFER, stranger, 1), Operation.Call, 7 days);
        assertEq(_balance(), _custody);
        assertTrue(_settle(), "the curator settles under the window");

        // Recovery: p1 keeps scheduling, the veto (awake now) cancels; p2's eviction and p1's removal land.
        bytes32 _again = _scheduleBatch(p1, p1Pk, _t, _p, NONE, "again");
        _cancel(_again);
        address[] memory _te = _guardTargets(3);
        bytes[] memory _pe = new bytes[](3);
        _pe[0] = abi.encodeCall(g.revokeRole, (g.COUNCIL_ROLE(), stranger));
        _pe[1] = abi.encodeCall(g.grantRole, (g.COUNCIL_ROLE(), council));
        _pe[2] = abi.encodeCall(g.lockdownAndRevoke, (address(curatorSafe)));
        _scheduleBatch(p2, p2Pk, _te, _pe, NONE, "evict");
        bytes memory _remove = abi.encodeCall(tl.revokeRole, (tl.PROPOSER_ROLE(), address(p1)));
        _schedule(p2, p2Pk, address(tl), _remove, NONE, "remove");
        vm.warp(block.timestamp + MIN_DELAY);
        _executeBatch(_te, _pe, NONE, "evict");
        _execute(address(tl), _remove, NONE, "remove");
        assertFalse(g.hasRole(g.COUNCIL_ROLE(), stranger));
        assertFalse(tl.hasRole(tl.PROPOSER_ROLE(), address(p1)));
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        vm.prank(council);
        g.enforce(address(curatorSafe)); // the council is never held back by the cooldown
        assertTrue(_settle());
        assertEq(_balance(), _custody, "custody never moved");
    }

    /// @dev `updateDelay(1 hours)` was inside the clamp until the round-13 follow-up: a proposer could schedule
    ///      it and, once the veto missed it, every later operation of a compromised proposer was Ready in one
    ///      hour instead of two days. The floor is a day now (G13f-3): the hour is refused when PROPOSED (through
    ///      the proposer's Safe: `GS013`), the lowest a proposer can go is a day, the veto keeps a day on every
    ///      later operation, and the delay comes back through a one-day operation the honest proposer schedules.
    function test_fixed_updateDelay_below_a_day_is_refused_and_the_floor_keeps_the_veto_a_day() public {
        uint256 _live = tl.getMinDelay();
        bytes memory _hour = abi.encodeCall(tl.updateDelay, (1 hours));
        bytes memory _proposal = abi.encodeCall(tl.schedule, (address(tl), 0, _hour, NONE, bytes32("U"), _live));
        vm.expectRevert(bytes("GS013"));
        _exec(p1, p1Pk, address(tl), 0, _proposal, Operation.Call);

        bytes memory _floor = abi.encodeCall(tl.updateDelay, (1 days));
        _schedule(p1, p1Pk, address(tl), _floor, NONE, "U");
        vm.warp(block.timestamp + MIN_DELAY);
        _execute(address(tl), _floor, NONE, "U");
        assertEq(tl.getMinDelay(), 1 days, "the floor");

        (address[] memory _t, bytes[] memory _p) = _takeover();
        bytes32 _id = _scheduleBatch(p1, p1Pk, _t, _p, NONE, "A");
        vm.warp(block.timestamp + 1 hours);
        assertFalse(tl.isOperationReady(_id), "not ready after an hour");
        vm.warp(block.timestamp + 1 days - 1 hours);
        assertTrue(tl.isOperationReady(_id), "the veto has a full day per operation");
        _cancel(_id);

        bytes memory _restore = abi.encodeCall(tl.updateDelay, (2 days));
        _schedule(p2, p2Pk, address(tl), _restore, NONE, "V");
        vm.warp(block.timestamp + 1 days);
        _execute(address(tl), _restore, NONE, "V");
        assertEq(tl.getMinDelay(), 2 days);
    }

    /*//////////////////////////////////////////////////////////////
                      A FRONT-RUNNER WATCHING THE QUEUE
    //////////////////////////////////////////////////////////////*/

    /// @dev A Ready approval is executed by the front-runner the second it matures: its TTL (one hour here)
    ///      runs from then, and the signers find it expired. The control is the runbook's "give admin
    ///      approvals days, not hours".
    function test_front_runner_executes_a_ready_approval_early_and_its_ttl_expires_before_the_signers_act() public {
        bytes memory _payload = abi.encodeCall(MockProtocol.deposit, (1, address(curatorSafe))); // not allowlisted
        bytes memory _appr = abi.encodeCall(
            g.approveTransaction,
            (address(curatorSafe), address(0), address(protocol), 0, _payload, Operation.Call, uint64(1 hours))
        );
        _schedule(p1, p1Pk, address(g), _appr, NONE, "T");
        vm.warp(block.timestamp + MIN_DELAY);
        _execute(address(g), _appr, NONE, "T");
        vm.warp(block.timestamp + 1 hours + 1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector));
        _curatorExec(address(protocol), 0, _payload, Operation.Call);
    }

    /// @dev A hostile venue executes Ready admin operations INSIDE the curator's transaction (the executor
    ///      role is open): an admitted transaction completes and is reported as it was admitted, the next
    ///      one sees the new state; a lift or a window the cooldown holds back fails for the venue exactly
    ///      as it would for the operator.
    function test_a_venue_executing_ready_operations_inside_the_curators_transaction_changes_nothing_for_it() public {
        HostileVenue _venue = new HostileVenue();
        bytes[] memory _d = new bytes[](1);
        _d[0] = abi.encodeCall(g.allowFunction, (address(curatorSafe), address(_venue), HostileVenue.poke.selector, false, _noRules()));
        _adminBatch(_d, "venue");
        bytes memory _lock = abi.encodeCall(g.lockdown, (address(curatorSafe)));
        bytes memory _window = abi.encodeCall(g.bypass, (address(curatorSafe), uint64(1 days)));
        _schedule(p1, p1Pk, address(g), _lock, NONE, "L");
        _schedule(p1, p1Pk, address(g), _window, NONE, "W");
        vm.warp(block.timestamp + MIN_DELAY);
        bytes memory _poke = abi.encodeCall(HostileVenue.poke, (1));

        // The admin's lockdown executed mid-transaction: the admitted transaction completes (Policy), the next is refused.
        _venue.queueCall(address(tl), 0, abi.encodeCall(tl.execute, (address(g), 0, _lock, NONE, bytes32("L"))));
        vm.recordLogs();
        assertTrue(_curatorExec(address(_venue), 0, _poke, Operation.Call));
        assertTrue(_venue.ok(0));
        (uint256 _n, uint8 _outcome, ) = _reports(vm.getRecordedLogs(), address(g));
        assertEq(_n, 1);
        assertEq(_outcome, uint8(CuratorGuard.Outcome.Policy));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(curatorSafe)));
        _settle();

        // The Ready window is held back by the cooldown, for the venue as for anyone.
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(curatorSafe)));
        tl.execute(address(g), 0, _window, NONE, "W");

        // The council lifts at once; a day later the venue lands the window mid-transaction: the admitted
        // transaction is still reported Policy, the Safe reads Bypass afterwards.
        vm.prank(council);
        g.enforce(address(curatorSafe));
        vm.warp(block.timestamp + 1 days + 1); // the cooldown's edge is inclusive
        _venue.reset();
        _venue.queueCall(address(tl), 0, abi.encodeCall(tl.execute, (address(g), 0, _window, NONE, bytes32("W"))));
        vm.recordLogs();
        assertTrue(_curatorExec(address(_venue), 0, _poke, Operation.Call));
        assertTrue(_venue.ok(0));
        (_n, _outcome, ) = _reports(vm.getRecordedLogs(), address(g));
        assertEq(_n, 1);
        assertEq(_outcome, uint8(CuratorGuard.Outcome.Policy));
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Bypass));
    }

    /*//////////////////////////////////////////////////////////////
                           A STRANGER WITH NO ROLE
    //////////////////////////////////////////////////////////////*/

    /// @dev The stranger can execute what is Ready and nothing else: the timelock, the guard's role surface,
    ///      the admin transfer and the Safe all refuse it.
    function test_a_stranger_with_no_role_can_only_execute_what_is_ready() public {
        vm.startPrank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, tl.PROPOSER_ROLE()));
        tl.schedule(address(g), 0, abi.encodeCall(g.enforce, (address(curatorSafe))), NONE, "x", MIN_DELAY);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, tl.CANCELLER_ROLE()));
        tl.cancel(bytes32(uint256(1)));
        vm.expectRevert();
        tl.execute(address(g), 0, abi.encodeCall(g.enforce, (address(curatorSafe))), NONE, "never-scheduled");
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.lockdown(address(curatorSafe));
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.enforce(address(curatorSafe));
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.bypass(address(curatorSafe), 1 hours);
        vm.expectRevert(abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlInvalidDefaultAdmin.selector, stranger));
        g.acceptDefaultAdminTransfer();
        bytes32 _councilRole = g.COUNCIL_ROLE();
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, bytes32(0)));
        g.grantRole(_councilRole, stranger);
        vm.stopPrank();
        _strangerCannotMoveCustody();
        // What the stranger may do: execute a Ready operation, which is what the admin scheduled anyway.
        bytes memory _lock = abi.encodeCall(g.lockdown, (address(curatorSafe)));
        _schedule(p1, p1Pk, address(g), _lock, NONE, "L");
        vm.warp(block.timestamp + MIN_DELAY);
        _execute(address(g), _lock, NONE, "L");
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
    }
}
