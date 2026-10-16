// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G10cBase} from "test/guards/G10c_Base.sol";

/// @dev g10c, finding G10c-1 (operation-id squatting), pinned in its FIXED form. An operation id is
///      `keccak(target, value, data, predecessor, salt)`: it carries neither the proposer nor the delay.
///      Before the fix the timelock accepted any delay up to 30 days, so a compromised proposer that saw
///      the honest proposer's pending Safe transaction could schedule the identical operation first, 30
///      days out: the honest `scheduleBatch` reverted, a wrapped honest operation was dead on arrival at
///      its deadline, the squatter's own removal landed 30 days late, and a veto cancel reopened an id the
///      squatter took again. `_checkScheduled` now refuses any delay other than the live `getMinDelay()`:
///      a squat is the honest operation itself, on time, which the squatter can neither cancel nor retake.
contract G10c_IdSquatTest is G10cBase {
    bytes[] internal calls;
    bytes[] internal payloads;
    address[] internal targets;
    uint64 internal deadline;
    bytes32 internal salt;

    function setUp() public override {
        super.setUp();
        _configureCurator();
        // The honest widening exactly as the sync task schedules it: wrapped, deadline = now + minDelay + 14 days.
        calls.push(abi.encodeCall(g.allowFunction, (address(curatorSafe), address(protocol), MockProtocol.deposit.selector, false, _noRules())));
        deadline = uint64(block.timestamp + MIN_DELAY + 14 days);
        payloads.push(_wrap(deadline, calls[0]));
        targets = _guardTargets(1);
        salt = _taskSalt(calls, 0);
    }

    function _depositAllowed() internal view returns (bool _allowed) {
        (_allowed, , ) = g.functionPermission(address(curatorSafe), address(protocol), MockProtocol.deposit.selector);
    }

    function test_G10c1_a_longer_delay_is_refused_so_a_squat_cannot_park_the_honest_operation() public {
        uint256 _t0 = block.timestamp;
        // The rail, by its own error: a proposer asking for anything but the live minimum delay is refused.
        uint256[] memory _values = new uint256[](targets.length);
        vm.prank(address(p1));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, 30 days));
        tl.scheduleBatch(targets, _values, payloads, NONE, salt, 30 days);
        vm.prank(address(p1));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, MIN_DELAY + 1));
        tl.scheduleBatch(targets, _values, payloads, NONE, salt, MIN_DELAY + 1);
        // Through p1's Safe the same refusal fails the Safe transaction: nothing is scheduled.
        vm.expectRevert(bytes("GS013"));
        _scheduleBatchWithDelay(p1, p1Pk, targets, payloads, NONE, salt, 30 days);
        // The honest proposer schedules at the live minimum and the widening lands on time.
        bytes32 _id = _scheduleBatch(p2, p2Pk, targets, payloads, NONE, salt);
        assertEq(tl.getTimestamp(_id), _t0 + MIN_DELAY, "ready after minDelay, not the cap");
        vm.warp(_t0 + MIN_DELAY);
        assertTrue(tl.isOperationReady(_id));
        _executeBatch(targets, payloads, NONE, salt);
        assertTrue(_depositAllowed(), "the widening lands");
    }

    function test_G10c1_a_squat_at_the_honest_delay_is_the_honest_operation() public {
        uint256 _t0 = block.timestamp;
        // p1 (compromised) schedules the honest proposer's exact operation first: the only delay it may use
        // is the live minimum, so it has placed the honest operation itself.
        bytes32 _id = _scheduleBatchWithDelay(p1, p1Pk, targets, payloads, NONE, salt, MIN_DELAY);
        assertEq(tl.getTimestamp(_id), _t0 + MIN_DELAY);
        // The honest proposer's own schedule reverts (the id exists), and nothing is lost by it.
        vm.expectRevert(bytes("GS013"));
        _scheduleBatch(p2, p2Pk, targets, payloads, NONE, salt);
        // p1 can neither cancel it (proposers are not cancellers) nor re-place it with a longer delay.
        vm.expectRevert(bytes("GS013"));
        _exec(p1, p1Pk, address(tl), 0, abi.encodeCall(tl.cancel, (_id)), Operation.Call);
        vm.expectRevert(bytes("GS013"));
        _scheduleBatchWithDelay(p1, p1Pk, targets, payloads, NONE, salt, 30 days);
        vm.warp(_t0 + MIN_DELAY);
        _executeBatch(targets, payloads, NONE, salt);
        assertTrue(_depositAllowed(), "the operation lands inside the honest wrapper's deadline");
    }

    function test_G10c1_the_removal_of_a_compromised_proposer_lands_after_minDelay() public {
        uint256 _t0 = block.timestamp;
        bytes32 _prop = tl.PROPOSER_ROLE();
        bytes memory _remove = abi.encodeCall(IAccessControl.revokeRole, (_prop, address(p1)));
        // p1 cannot pre-park its own removal under the salts the honest side would try: every attempt
        // with a longer delay fails inside its Safe, and nothing is scheduled.
        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(bytes("GS013"));
            _scheduleWithDelay(p1, p1Pk, address(tl), _remove, NONE, bytes32(i), 30 days);
        }
        // The honest proposer schedules the removal at the live minimum delay and it lands after it.
        bytes32 _id = _schedule(p2, p2Pk, address(tl), _remove, NONE, bytes32(0));
        assertEq(tl.getTimestamp(_id), _t0 + MIN_DELAY);
        vm.warp(_t0 + MIN_DELAY);
        _execute(address(tl), _remove, NONE, bytes32(0));
        assertFalse(tl.hasRole(_prop, address(p1)), "removed after minDelay");
        assertEq(block.timestamp - _t0, MIN_DELAY, "the bound is minDelay, not the cap");
    }
}
