// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {G9cBase} from "test/guards/G9c_Base.sol";

/// @dev g9c: docs section 7.6 step 5 (a governance Safe that installed the guard on itself), run as
///      written with real Safes behind every principal, plus the two paths the text does not spell out
///      (the second proposer; the veto Safe) and the deadlock the deploy script's two-proposer rule exists for.
contract G9c_ProposerRecoveryTest is G9cBase {
    function _setGuardZero() internal pure returns (bytes memory) {
        return abi.encodeCall(ISafe.setGuard, (address(0)));
    }

    /// @dev The admin approval of `safe_`'s own `setGuard(0)`, wrapped as the task would.
    function _exitFor(ISafe safe_) internal view returns (bytes memory) {
        return
            _wrap(
                uint64(block.timestamp + MIN_DELAY + 3 days),
                abi.encodeCall(g.approveTransaction, (address(safe_), address(0), address(safe_), 0, _setGuardZero(), Operation.Call, uint64(3 days)))
            );
    }

    function _tryScheduleFrom(ISafe proposer_, uint256 pk_, bytes memory data_, bytes32 salt_) internal {
        _exec(proposer_, pk_, address(tl), 0, abi.encodeCall(tl.schedule, (address(g), 0, data_, NONE, salt_, MIN_DELAY)), Operation.Call);
    }

    /// @dev The documented recipe: council window on the proposer, schedule from inside it, `enforce`,
    ///      execute, signers run the approved `setGuard(0)`.
    function test_guarded_proposer_recovers_through_a_council_window_as_the_runbook_says() public {
        _configureCurator();
        _installOn(p1, p1Pk); // the mistake: an unconfigured guarded Safe, in Lockdown
        bytes memory _op = _exitFor(p1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(p1)));
        _tryScheduleFrom(p1, p1Pk, _op, "x");
        vm.prank(council);
        g.bypass(address(p1), 7 days);
        _tryScheduleFrom(p1, p1Pk, _op, "x"); // a venue call inside the council window
        vm.warp(block.timestamp + MIN_DELAY);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.SafeInBypass.selector, address(p1)));
        _execute(address(g), _op, NONE, "x");
        vm.prank(council);
        g.enforce(address(p1));
        _execute(address(g), _op, NONE, "x");
        assertTrue(_exec(p1, p1Pk, address(p1), 0, _setGuardZero(), Operation.Call), "approved exit");
        assertEq(_guardOf(p1), address(0));
        _tryScheduleFrom(p1, p1Pk, abi.encodeCall(g.lockdown, (address(curatorSafe))), "y"); // proposes again
    }

    /// @dev Info (docs 7.6 step 5 says "without a council ... nothing can ever be scheduled again"): with
    ///      TWO proposers the other one schedules the approval and no window is needed at all.
    function test_guarded_proposer_recovers_through_the_second_proposer_without_a_council() public {
        g = _newGuard(address(tl), address(0));
        _installOn(p1, p1Pk);
        bytes memory _op = _exitFor(p1);
        _tryScheduleFrom(p2, p2Pk, _op, "x");
        vm.warp(block.timestamp + MIN_DELAY);
        _execute(address(g), _op, NONE, "x");
        assertTrue(_exec(p1, p1Pk, address(p1), 0, _setGuardZero(), Operation.Call));
        assertEq(_guardOf(p1), address(0));
    }

    /// @dev A veto Safe that installed the guard on itself cannot cancel (its `cancel` is a Safe
    ///      transaction) until a proposer's approval of its `setGuard(0)` matures: for one `minDelay`
    ///      nothing is vetoed, and a hostile operation ready in the same block races the exit.
    function test_guarded_veto_safe_cannot_cancel_until_a_proposer_schedules_its_exit() public {
        _installOn(veto, vetoPk);
        bytes memory _hostile = abi.encodeCall(g.bypass, (address(curatorSafe), uint64(180 days)));
        bytes32 _hid = _schedule(p2, p2Pk, address(g), _hostile, NONE, "hostile");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(veto)));
        _cancel(_hid);
        bytes memory _op = _exitFor(veto);
        _tryScheduleFrom(p1, p1Pk, _op, "exit");
        vm.warp(block.timestamp + MIN_DELAY);
        assertTrue(tl.isOperationReady(_hid), "the hostile operation is ready in the same block as the exit");
        _execute(address(g), _op, NONE, "exit");
        assertTrue(_exec(veto, vetoPk, address(veto), 0, _setGuardZero(), Operation.Call));
        _cancel(_hid);
        assertFalse(tl.isOperationPending(_hid));
    }

    /// @dev The deadlock the two-proposer rule prevents: a SOLE proposer that guards itself with no
    ///      council leaves nobody able to issue the approval that would free it.
    function test_a_sole_proposer_guarding_itself_without_a_council_is_permanent() public {
        address[] memory _p = new address[](1);
        _p[0] = address(p1);
        address[] memory _c = new address[](1);
        _c[0] = address(veto);
        tl = new CuratorGuardTimelock(MIN_DELAY, _p, _c);
        g = _newGuard(address(tl), address(0));
        _installOn(p1, p1Pk);
        bytes memory _op = _exitFor(p1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(p1)));
        _tryScheduleFrom(p1, p1Pk, _op, "x");
        vm.expectRevert(bytes("GS013")); // p2 holds no role on this timelock: the inner call fails, the Safe reverts
        _tryScheduleFrom(p2, p2Pk, _op, "x");
        vm.expectRevert(bytes("GS013")); // the veto cannot propose
        _tryScheduleFrom(veto, vetoPk, _op, "x");
        vm.prank(address(veto));
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector); // and holds no guard role
        g.approveTransaction(address(p1), address(0), address(p1), 0, _setGuardZero(), Operation.Call, 1 days);
        assertEq(_guardOf(p1), address(g), "stuck for good");
    }
}
