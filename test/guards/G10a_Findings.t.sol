// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {StrangersBase} from "test/guards/CuratorGuardStrangersBase.sol";
import {G10aHarness} from "test/guards/G10aBase.sol";

/// @title Round 10, reviewer g10a: proof-of-concept tests for the findings of the state-machine lens.
/// @dev G10a-1: the post-hook's empty-slot branch reports `TransactionChecked(…, Bypass)` for a Safe on
///      which THIS guard is not installed (the installed-slot check lives in the pre-hook only), so a
///      guard reports for a Safe that never called its pre-hook. G10a-2: the guard accepts itself as a
///      council member, a deployment-wide guardian and a pending admin (dead seats), while `setGuardian`
///      and the timelock refuse the analogous seat.
contract G10aFindingsTest is StrangersBase {
    bytes32 internal TX_CHECKED = CuratorGuard.TransactionChecked.selector;

    function _guardSlot(ISafe safe_) internal view returns (address) {
        return address(uint160(uint256(bytes32(safe_.getStorageAt(uint256(GUARD_SLOT), 1)))));
    }

    /// @dev `TransactionChecked` logs of `emitter_` naming `safe_` under `hash_` with `outcome_`.
    function _reports(Vm.Log[] memory logs_, address emitter_, address safe_, bytes32 hash_, CuratorGuard.Outcome outcome_)
        internal
        view
        returns (uint256 _n)
    {
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter != emitter_ || logs_[i].topics[0] != TX_CHECKED) continue;
            if (
                logs_[i].topics[1] == bytes32(uint256(uint160(safe_))) &&
                logs_[i].topics[2] == hash_ &&
                logs_[i].topics[3] == bytes32(uint256(outcome_))
            ) ++_n;
        }
    }

    /*//////////////////////////////////////////////////////////////
                                 G10a-1
    //////////////////////////////////////////////////////////////*/

    /// @dev A Safe that never installed the guard (pre-install, or a replacement guard before adoption)
    ///      but has a window opened for it on the guard: the pre-hook refuses it (`GuardNotInstalled`),
    ///      the post-hook alone, reached as a plain Safe transaction, reports a `Bypass` outcome under any
    ///      hash the signers choose. Passes on the current code; pins the HELD finding G10a-1 (docs
    ///      section 10) and must flip if its fix (a silent return where the guard is not installed) lands.
    function test_G10a1_a_guard_reports_a_window_for_a_safe_that_never_installed_it() public {
        (address _curatorD, uint256 _pkD) = makeAddrAndKey("curatorD");
        ISafe _safeD = _newSafe(_curatorD);
        assertEq(_guardSlot(_safeD), address(0), "no guard on D");
        vm.prank(vetro);
        guard.bypass(address(_safeD), 1 hours); // an admin window on a Safe this guard is not installed on
        assertEq(uint8(guard.mode(address(_safeD))), uint8(CuratorGuardPolicy.Mode.Bypass));

        // The pre-hook keeps the documented promise.
        vm.prank(address(_safeD));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardNotInstalled.selector, address(_safeD)));
        guard.checkTransaction(address(protocol), 0, "", Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0));

        // The post-hook does not: D's signers execute a plain call into it and get a report.
        bytes32 _forged = keccak256("anything");
        vm.recordLogs();
        assertTrue(
            _execAs(_safeD, _pkD, address(guard), 0, abi.encodeCall(guard.checkAfterExecution, (_forged, true)), Operation.Call),
            "the unguarded Safe calls the post-hook"
        );
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_reports(_logs, address(guard), address(_safeD), _forged, CuratorGuard.Outcome.Bypass), 1, "a Bypass report for a Safe the guard is not installed on");
    }

    /// @dev The same through an installed guard's admin window: `guard` (installed on `safe`) refuses
    ///      only itself as a call target, so the Safe reaches `_next` (a replacement with a window
    ///      opened for this Safe) and `_next` reports a transaction it never pre-checked.
    function test_G10a1_an_uninstalled_replacement_reports_through_the_installed_guards_admin_window() public {
        G10aHarness _next = new G10aHarness(0, vetro, council);
        _next.seedSafe(address(safe));
        vm.startPrank(vetro);
        _next.bypass(address(safe), 1 hours); // a window on the replacement, before adoption
        guard.bypass(address(safe), 1 hours); // an admin window on the installed guard
        vm.stopPrank();
        bytes32 _forged = keccak256("anything-else");
        vm.recordLogs();
        assertTrue(_execSafeTx(address(_next), 0, abi.encodeCall(_next.checkAfterExecution, (_forged, true)), Operation.Call));
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_reports(_logs, address(_next), address(safe), _forged, CuratorGuard.Outcome.Bypass), 1, "the replacement reports before adoption");
        assertEq(_guardSlot(safe), address(guard), "nothing was swapped");
    }

    /// @dev What the fix must keep: a `setGuard(replacement)` executed inside an admin window of the
    ///      installed guard still passes (the old guard gets the post-hook with the slot already moved).
    ///      Passes on the current code and with the fix (the old guard then reports nothing for it).
    function test_G10a1_an_admin_window_swap_keeps_working() public {
        G10aHarness _next = new G10aHarness(0, vetro, council);
        _next.seedSafe(address(safe));
        vm.prank(vetro);
        guard.bypass(address(safe), 1 hours);
        assertTrue(_execSafeTx(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(_next))), Operation.Call), "swap inside the window");
        assertEq(_guardSlot(safe), address(_next), "adopted");
        // and the retired guard answers nothing on the pre-hook from now on
        vm.prank(address(safe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardNotInstalled.selector, address(safe)));
        guard.checkTransaction(address(protocol), 0, "", Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0));
    }

    /// @dev With the fix a RETIRED guard whose window is still open reports nothing either (the runbook
    ///      asks for `lockdownAndRevoke` on it, but the window outlives a forgotten step). On the current
    ///      code the retired guard still reports; the assertion is on the installed guard's behaviour,
    ///      which both versions share: exactly one report, from the installed guard, under the real hash.
    function test_G10a1_the_installed_guard_reports_exactly_once_under_the_real_hash() public {
        bytes32 _forged = keccak256("x");
        vm.prank(vetro);
        guard.bypass(address(safe), 1 hours);
        vm.recordLogs();
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(protocol.settleDeposit, (1)), Operation.Call));
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        uint256 _all;
        for (uint256 i; i < _logs.length; ++i) if (_logs[i].emitter == address(guard) && _logs[i].topics[0] == TX_CHECKED) ++_all;
        assertEq(_all, 1, "one report");
        assertEq(_reports(_logs, address(guard), address(safe), _forged, CuratorGuard.Outcome.Bypass), 0, "never under a foreign hash");
    }

    /*//////////////////////////////////////////////////////////////
                                 G10a-2
    //////////////////////////////////////////////////////////////*/

    /// @dev The guard accepts itself as council, as deployment-wide guardian and as pending admin: a
    ///      seat no caller can occupy (no code path makes the guard its own `msg.sender`; `executeBefore`
    ///      keeps the caller), and a hand-over nobody can accept, which blocks the admin from beginning
    ///      another until it is cancelled or expires. The per-Safe guardian setter and the timelock refuse
    ///      the analogous seat. Passes on the current code; pins the HELD finding G10a-2 (docs section 10):
    ///      with its fix the three calls revert `AdminIsGuarded(guard)` and this test must flip.
    function test_G10a2_the_guard_accepts_itself_as_council_guardian_and_pending_admin() public {
        bytes32 _council = guard.COUNCIL_ROLE();
        bytes32 _guardian = guard.GUARDIAN_ROLE();
        vm.startPrank(vetro);
        guard.beginDefaultAdminTransfer(address(guard));
        (address _pending, ) = guard.pendingDefaultAdmin();
        assertEq(_pending, address(guard), "a hand-over to the guard itself is scheduled");
        vm.stopPrank();
        // Nobody can accept it: `executeBefore` runs as the caller, never as the guard.
        vm.warp(block.timestamp + 1);
        vm.prank(attacker);
        vm.expectRevert();
        guard.executeBefore(uint64(block.timestamp + 1), abi.encodeCall(guard.acceptDefaultAdminTransfer, ()));
        (, uint48 _schedule) = guard.pendingDefaultAdmin();
        assertGt(_schedule, 0, "still pending until the admin cancels it or begins another hand-over");
        vm.startPrank(vetro);
        guard.cancelDefaultAdminTransfer();
        guard.grantRole(_council, address(guard));
        assertTrue(guard.hasRole(_council, address(guard)), "the guard is its own council member");
        guard.setDeploymentGuardian(address(guard), true);
        assertTrue(guard.hasRole(_guardian, address(guard)), "the guard is its own deployment-wide guardian");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(guard)));
        guard.setGuardian(address(safe), address(guard), true); // the per-Safe setter refuses the same seat
        vm.stopPrank();

        // The timelock refuses itself as a gated-role holder (`SelfHolder`): the rail the guard lacks.
        address[] memory _p = new address[](1);
        _p[0] = makeAddr("p");
        address[] memory _c = new address[](1);
        _c[0] = makeAddr("v");
        CuratorGuardTimelock _tl = new CuratorGuardTimelock(2 days, _p, _c);
        bytes32 _proposer = _tl.PROPOSER_ROLE();
        vm.prank(address(_tl));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.SelfHolder.selector, _proposer));
        _tl.grantRole(_proposer, address(_tl));
    }
}
