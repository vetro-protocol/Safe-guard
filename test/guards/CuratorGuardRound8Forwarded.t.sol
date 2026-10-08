// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @title Round 8 (V2-89): no approval is spent while the
///        Safe's fallback-handler slot holds this guard (state, not calldata shape), and the after-hooks
///        take exactly 68 bytes (a forwarded call of that length has a dirty `bool`).
contract CuratorGuardRound8ForwardedTest is CuratorGuardTestBase {
    bytes internal payload = abi.encodeCall(MockProtocol.settleDeposit, (7));

    function _handler(address handler_) internal {
        vm.prank(address(safe));
        (bool _ok, ) = address(safe).call(abi.encodeWithSignature("setFallbackHandler(address)", handler_));
        assertTrue(_ok);
    }

    function _preHook(bytes memory data_, address to_) internal view returns (bytes memory) {
        return
            abi.encodeCall(
                guard.checkTransaction,
                (to_, 0, data_, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", attacker)
            );
    }

    /// @dev Every padding 0..63 of a forwarded pre-hook and after-hook, through the Safe's real fallback.
    function test_no_padding_gets_a_forwarded_hook_call_through() public {
        _handler(address(guard));
        bytes32 _id = _approve(address(protocol), 0, payload, Operation.Call);
        bytes memory _pre = _preHook(payload, address(protocol));
        bytes memory _post = abi.encodeCall(guard.checkAfterExecution, (keccak256("never executed"), true));
        vm.recordLogs();
        vm.startPrank(attacker);
        for (uint256 pad; pad < 64; ++pad) {
            (bool _ok, bytes memory _ret) = address(safe).call(abi.encodePacked(_pre, new bytes(pad)));
            assertFalse(_ok, "forwarded pre-hook refused");
            assertEq(bytes4(_ret), CuratorGuard.ForwardedHookCall.selector);
            (_ok, ) = address(safe).call(abi.encodePacked(_post, new bytes(pad)));
            assertFalse(_ok, "forwarded after-hook refused");
        }
        // Shorter than the canonical after-hook too: 48 bytes sent, 68 forwarded, `success` = 12 bytes
        // of the caller's choice followed by the caller's address: a dirty bool, refused by the decoder.
        bytes memory _short = abi.encodePacked(guard.checkAfterExecution.selector, keccak256("never executed"), bytes12(0));
        assertEq(_short.length, 48);
        (bool _ok2, ) = address(safe).call(_short);
        assertFalse(_ok2, "exact-length forwarded after-hook refused");
        vm.stopPrank();
        assertGt(guard.approvalExpiry(_id), 0, "approval intact");
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        for (uint256 i; i < _logs.length; ++i) assertTrue(_logs[i].emitter != address(guard), "the guard emitted nothing");
    }

    /// @dev While the handler slot holds the guard the Safe itself cannot spend an approval either (it
    ///      would be a race against every stranger); the exit is the one R8H-1 names, a council window in
    ///      which the signers reset the handler. Policy traffic is not held back by this check.
    function test_the_window_exit_stays_open_and_policy_traffic_is_untouched() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        _handler(address(guard));
        bytes32 _id = _approve(address(protocol), 0, payload, Operation.Call);
        vm.expectRevert(CuratorGuard.ForwardedHookCall.selector);
        _execSafeTx(address(protocol), 0, payload, Operation.Call);
        assertGt(guard.approvalExpiry(_id), 0, "not spent, not burned");
        // The dry run says the same (it shares the approval-use check with the live hook).
        vm.expectRevert(CuratorGuard.ForwardedHookCall.selector);
        guard.validateTransaction(address(safe), address(protocol), 0, payload, Operation.Call);
        // A policy-allowed payload without an approval still runs (no handler requirement in this policy).
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call));
        // Repair: council window, the signers reset the handler, the council closes the window.
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        assertTrue(_execSafeTx(address(safe), 0, abi.encodeWithSignature("setFallbackHandler(address)", address(0)), Operation.Call));
        vm.prank(council);
        guard.enforce(address(safe));
        // Approvals work again (the window voided the old one: re-issue).
        _approve(address(protocol), 0, payload, Operation.Call);
        assertTrue(_execSafeTx(address(protocol), 0, payload, Operation.Call), "approved execution after the repair");
    }

    /// @dev Any other handler, and none, are untouched by the check: approvals are spent as before.
    function test_other_handlers_do_not_trip_the_check() public {
        _handler(address(protocol));
        _approve(address(protocol), 0, payload, Operation.Call);
        assertTrue(_execSafeTx(address(protocol), 0, payload, Operation.Call));
        _handler(address(0));
        _approve(address(protocol), 0, payload, Operation.Call);
        assertTrue(_execSafeTx(address(protocol), 0, payload, Operation.Call));
    }

    /// @dev What stays possible with the guard in the handler slot, and why it is harmless: a forwarded
    ///      pre-hook for a POLICY-allowed payload parks a snapshot in the Safe's transient slot. It dies
    ///      with the stranger's transaction and can only make a Safe transaction relayed LATER IN THAT SAME
    ///      transaction fail (`NestedExecution`), i.e. the stranger's own.
    function test_residual_a_forwarded_policy_pre_hook_only_parks_a_transient_snapshot() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        _handler(address(guard));
        vm.prank(attacker);
        (bool _ok, ) = address(safe).call(_preHook(abi.encodeCall(MockProtocol.settleDeposit, (1)), address(protocol)));
        assertTrue(_ok, "policy pre-hook answered");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.NestedExecution.selector, address(safe)));
        _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
    }
}
