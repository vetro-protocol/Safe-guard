// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G9cBase} from "test/guards/G9c_Base.sol";

/// @dev Round 13, reviewer g13f: THE LIVENESS KILLER. Not theft: denial, ransom and lock-out.
///      Every test runs on the production topology of G9cBase (real Safe v1.4.1 proxies behind every
///      principal, a real CuratorGuardTimelock, minDelay 2 days). The findings build on g9c's deadlock
///      matrix (bounded recoveries), g10c's hostile-proposer game and g11c's gas measurements by
///      quantifying what an attacker who BURNS one seat can deny, and for how long.

/// @dev G13f-1. A compromised proposer floods the timelock with pending operations that never expire
///      (no `executeBefore` wrapper). There is no on-chain cap; one key creates N pending ids and the
///      veto must cancel each (cancelling one leaves the rest). Every `curator-guard-sync` run lists the
///      queue and calls `isOperationPending` once per pending id (`pendingOperations`), so the flood is
///      a persistent O(N) tax on the honest tooling and the veto's review until every id is cancelled.
contract G13f_QueueFloodTest is G9cBase {
    function test_G13f1_one_proposer_floods_the_queue_with_non_expiring_operations() public {
        _configureCurator();
        uint256 _n = 64; // representative; the contract caps nothing, so this is unbounded
        bytes32[] memory _ids = new bytes32[](_n);
        bytes memory _junk = abi.encodeCall(g.enforce, (address(curatorSafe))); // harmless, never executed
        for (uint256 i; i < _n; ++i) {
            // A genuine proposer Safe transaction per id; in production one MultiSend creates them all.
            _ids[i] = _schedule(p1, p1Pk, address(g), _junk, NONE, bytes32(i + 1));
        }
        // All N are pending at once: the timelock keeps no bound (OZ `_schedule` only refuses a dup id).
        for (uint256 i; i < _n; ++i) assertTrue(tl.isOperationPending(_ids[i]), "pending");
        // They never expire: a bare operation has no `executeBefore` deadline, so it sits Ready forever.
        vm.warp(block.timestamp + 3650 days);
        for (uint256 i; i < _n; ++i) assertTrue(tl.isOperationReady(_ids[i]), "still ready years later");
        // The ONLY way to clear the queue is to cancel each id: cancelling one leaves the other N-1, so
        // the veto's cleanup is O(N) (one Safe transaction can batch the cancels, but each id must be
        // named and reviewed). This is the asymmetry: one key floods, the veto must triage every entry.
        _cancel(_ids[0]);
        assertFalse(tl.isOperationPending(_ids[0]));
        uint256 _stillPending;
        for (uint256 i = 1; i < _n; ++i) if (tl.isOperationPending(_ids[i])) ++_stillPending;
        assertEq(_stillPending, _n - 1, "cancelling one clears only one");
        // The honest sync task refuses to schedule a new policy change while ANY operation is pending
        // (without --allow-pending), and its queue listing is O(pending) eth_calls on every run: the
        // flood denies the routine tooling path until the veto has cancelled all N.
    }
}

/// @dev G13f-2. g9c bounded a guardian re-lock loop at "minDelay + 1 day" and g9c-5/6 noted that
///      deployment-wide `GUARDIAN_ROLE` is UNCAPPED and NOT enumerable on-chain. Put the two together:
///      a compromised council (before the admin can evict it after a minDelay) plants a SWARM of
///      deployment-wide guardian keys and locks the Safe down. Every key can re-lock independently, so
///      the admin's bounded recovery holds ONLY if it removes EVERY key in the batch; the set is
///      reconstructable only from `RoleGranted` logs (no on-chain enumeration), so one key missed to a
///      dropped/degraded log stream re-locks the Safe and the "minDelay + 1 day" bound is gone. There is
///      no council today (`helpers/address.ts`: empty), so this is the live recovery path, not a hedge.
contract G13f_GuardianSwarmTest is G9cBase {
    function _lockers(uint256 n_) internal pure returns (address[] memory _keys) {
        _keys = new address[](n_);
        for (uint256 i; i < n_; ++i) _keys[i] = address(uint160(0xDEAD0000 + i));
    }

    function test_G13f2_a_swarm_of_uncapped_deployment_guardians_outlives_eviction_without_full_enumeration() public {
        _configureCurator();
        uint256 _k = 40;
        address[] memory _keys = _lockers(_k);
        // The compromised council plants the swarm (uncapped: setDeploymentGuardian has no MAX) and locks.
        vm.startPrank(council);
        for (uint256 i; i < _k; ++i) g.setDeploymentGuardian(_keys[i], true);
        g.lockdown(address(curatorSafe));
        vm.stopPrank();
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        // The role is NOT enumerable on-chain: the guard exposes no member count for GUARDIAN_ROLE, only
        // a per-address `isGuardian`. A responder must rebuild the full set from `RoleGranted` logs.
        for (uint256 i; i < _k; ++i) assertTrue(g.isGuardian(address(curatorSafe), _keys[i]), "live locker");
        // The admin's recovery: revoke the council and remove the guardians, then lift. Model a SINGLE
        // dropped/degraded log: the admin removes only K-1 keys (it never learned _keys[_k-1]).
        bytes[] memory _d = new bytes[](_k); // revoke council + remove K-1 keys = _k calls
        _d[0] = abi.encodeCall(IAccessControl.revokeRole, (g.COUNCIL_ROLE(), council));
        for (uint256 i; i < _k - 1; ++i) _d[1 + i] = abi.encodeCall(g.setDeploymentGuardian, (_keys[i], false));
        _adminBatch(_d, "evict-and-deswarm"); // one minDelay; setGuardian/revokeRole are NOT held by the cooldown
        // The admin schedules its lift (enforce) as a timelock operation.
        bytes memory _lift = abi.encodeCall(g.enforce, (address(curatorSafe)));
        _schedule(p1, p1Pk, address(g), _lift, NONE, "lift");
        vm.warp(block.timestamp + MIN_DELAY); // the lift is Ready
        // The un-enumerated key re-locks the instant before the lift would hold, re-arming the cooldown.
        vm.prank(_keys[_k - 1]);
        g.lockdown(address(curatorSafe));
        uint256 _reLock = block.timestamp;
        // The admin's lift is now held back by the cooldown the MISSED key just re-armed: the documented
        // "minDelay + 1 day" bound assumes every locker was enumerated, and one missed key breaks it.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(curatorSafe)));
        _execute(address(g), _lift, NONE, "lift");
        // Only after the admin removes the LAST key (another minDelay) and its cooldown passes does the
        // lift hold: the recovery is ceil(K / batch-size) rounds plus every re-lock race, not a constant.
        _adminCall(abi.encodeCall(g.setDeploymentGuardian, (_keys[_k - 1], false)), "remove-last"); // warps MIN_DELAY > cooldown
        assertGt(block.timestamp, _reLock + 1 days); // the re-lock's cooldown has passed
        _execute(address(g), _lift, NONE, "lift"); // the same Ready operation, now unobstructed
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Enforced));
    }
}

/// @dev G13f-3, applied after round 13: `MIN_DELAY_FLOOR = 1 days`. A compromised proposer that could
///      schedule `updateDelay(1 hours)` would, once it executed, make EVERY later operation mature an hour
///      after scheduling, below the time a 2-of-3 veto Safe needs to convene. The hour is now refused when
///      PROPOSED (`DelayOutOfRange`, `GS013` through the proposer's Safe); the lowest the proposer can go
///      is the floor itself, a day, and the veto keeps a day on every operation.
contract G13f_DelayFloorRaceTest is G9cBase {
    function test_G13f3_the_one_day_floor_keeps_the_veto_a_day_on_every_operation() public {
        _configureCurator();
        assertEq(tl.getMinDelay(), MIN_DELAY);
        // Below the floor: refused at proposal, through the proposer's Safe and by the timelock's own error.
        bytes memory _toHour = abi.encodeCall(tl.updateDelay, (1 hours));
        uint256 _live = tl.getMinDelay();
        bytes memory _proposal = abi.encodeCall(tl.schedule, (address(tl), 0, _toHour, NONE, bytes32("to-hour"), _live));
        vm.expectRevert(bytes("GS013"));
        _exec(p1, p1Pk, address(tl), 0, _proposal, Operation.Call);
        vm.prank(address(p1));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, 1 hours));
        tl.schedule(address(tl), 0, _toHour, NONE, "to-hour", _live);
        // The floor itself is schedulable: the lowest delay a proposer can reach is a day.
        bytes memory _toFloor = abi.encodeCall(tl.updateDelay, (1 days));
        _schedule(p1, p1Pk, address(tl), _toFloor, NONE, "to-floor");
        vm.warp(block.timestamp + MIN_DELAY);
        _execute(address(tl), _toFloor, NONE, "to-floor");
        assertEq(tl.getMinDelay(), 1 days, "minDelay is the one-day floor");
        // A hostile widening scheduled now gives the veto a full day, not an hour.
        bytes memory _widen = abi.encodeCall(
            g.allowFunction,
            (address(curatorSafe), address(protocol), MockProtocol.deposit.selector, false, _noRules())
        );
        bytes32 _wid = _schedule(p1, p1Pk, address(g), _widen, NONE, "widen");
        vm.warp(block.timestamp + 1 hours);
        assertFalse(tl.isOperationReady(_wid), "not ready after an hour");
        vm.warp(block.timestamp + 1 days - 1 hours - 1);
        assertFalse(tl.isOperationReady(_wid), "not ready one second early");
        vm.warp(block.timestamp + 1);
        assertTrue(tl.isOperationReady(_wid), "ready exactly one day after scheduling: the veto keeps a day");
        assertFalse(_isAllowed(address(curatorSafe), address(protocol), MockProtocol.deposit.selector), "nothing widened yet");
    }

    function _isAllowed(address safe_, address target_, bytes4 selector_) internal view returns (bool _a) {
        (_a, , ) = g.functionPermission(safe_, target_, selector_);
    }
}
