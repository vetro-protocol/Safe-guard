// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {Enum} from "safe-contracts-v1.4.1/contracts/common/Enum.sol";
import {CompatibilityFallbackHandler} from "safe-contracts-v1.4.1/contracts/handler/CompatibilityFallbackHandler.sol";
import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";
import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {StrangersBase} from "test/guards/CuratorGuardStrangersBase.sol";

/// @dev Executes pre-signed Safe transactions of several Safes inside ONE call (a relayer, a keeper).
contract Relayer {
    function run(ISafe[] calldata safes_, bytes[] calldata calls_) external {
        for (uint256 i; i < safes_.length; ++i) {
            (bool _ok, bytes memory _ret) = address(safes_[i]).call(calls_[i]);
            if (!_ok) {
                assembly {
                    revert(add(_ret, 0x20), mload(_ret))
                }
            }
        }
    }
}

/// @title Round 8: isolation between Safes sharing one guard, nested Safe transactions (one Safe as the
///        other's target, module or relayed sibling): paths, slots and digests are per Safe.
contract CuratorGuardCrossSafeTest is StrangersBase {
    function _execTransactionCalldata(
        ISafe safe_,
        uint256 pk_,
        address to_,
        uint256 value_,
        bytes memory data_,
        Operation op_
    ) internal returns (bytes memory) {
        bytes memory _sig = _signatureFor(safe_, pk_, to_, value_, data_, op_);
        return abi.encodeCall(ISafe.execTransaction, (to_, value_, data_, op_, 0, 0, 0, address(0), payable(address(0)), _sig));
    }

    function _reports(Vm.Log[] memory logs_) internal view returns (address[] memory _safes, uint8[] memory _outcomes) {
        uint256 _n = _guardLogs(logs_, CuratorGuard.TransactionChecked.selector);
        _safes = new address[](_n);
        _outcomes = new uint8[](_n);
        uint256 _k;
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter == address(guard) && logs_[i].topics[0] == CuratorGuard.TransactionChecked.selector) {
                _safes[_k] = address(uint160(uint256(logs_[i].topics[1])));
                _outcomes[_k++] = uint8(uint256(logs_[i].topics[3])); // `outcome` is an indexed topic
            }
        }
    }

    /// @dev A's policy names B's `execTransaction` (a "generic executor" target, a documented policy
    ///      mistake, used here to produce a genuine nested execution of two guarded Safes). B runs an
    ///      APPROVED `setGuard(0)` inside A's POLICY transaction: slot (A,0) holds A's digest, slot
    ///      (B,0) the sentinel; B's configuration change is B's, A's digest still matches; two reports.
    function test_nested_sibling_execution_keeps_slots_and_digests_apart() public {
        vm.prank(vetro);
        guard.allowFunction(address(safe), address(safeB), ISafe.execTransaction.selector, false, _noRules());
        bytes memory _inner = abi.encodeCall(ISafe.setGuard, (address(0)));
        vm.prank(vetro);
        guard.approveTransaction(address(safeB), address(0), address(safeB), 0, _inner, Operation.Call, 1 days);
        bytes memory _outerData = _execTransactionCalldata(safeB, signerPkB, address(safeB), 0, _inner, Operation.Call);

        vm.recordLogs();
        assertTrue(_execSafeTx(address(safeB), 0, _outerData, Operation.Call), "outer passes");
        (address[] memory _safes, uint8[] memory _outcomes) = _reports(vm.getRecordedLogs());
        assertEq(_safes.length, 2, "one report per Safe");
        assertEq(_safes[0], address(safeB), "inner reported first (its post-hook runs first)");
        assertEq(_outcomes[0], uint8(CuratorGuard.Outcome.Approval), "B: approval");
        assertEq(_safes[1], address(safe), "outer reported last");
        assertEq(_outcomes[1], uint8(CuratorGuard.Outcome.Policy), "A: policy");
        assertEq(address(uint160(uint256(bytes32(safeB.getStorageAt(uint256(GUARD_SLOT), 1))))), address(0), "B removed its guard");
        assertEq(_installedGuard(), address(guard), "A still guarded");
        // Both slots are clear: the next transaction of each Safe is not a NestedExecution.
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call), "A again");
    }

    /// @dev The inner sibling B is an enabled (unguarded, v1.4.1) module of the outer A and uses that to
    ///      rewrite A's guard slot while A's snapshot is live: A's post-hook compares the digest and the
    ///      WHOLE transaction (B's included) reverts `SafeConfigChanged(A)`. The digest is per Safe and
    ///      fails closed across nesting.
    function test_inner_sibling_acting_as_a_module_of_the_outer_trips_the_outer_digest() public {
        vm.prank(address(safe));
        safe.enableModule(address(safeB)); // pre-install state the runbook forbids; the robustness case
        vm.startPrank(vetro);
        guard.allowFunction(address(safe), address(safeB), ISafe.execTransaction.selector, false, _noRules());
        guard.allowFunction(address(safeB), address(safe), ISafe.execTransactionFromModule.selector, false, _noRules());
        vm.stopPrank();
        bytes memory _viaModule = abi.encodeCall(ISafe.execTransactionFromModule, (address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call));
        bytes memory _outerData = _execTransactionCalldata(safeB, signerPkB, address(safe), 0, _viaModule, Operation.Call);

        // V2-86: the policy refuses to run at all next to an unhooked module, before
        // anything executes (before round 8 the same transaction died in A's post-hook with
        // `SafeConfigChanged(A)`).
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ModuleNotHooked.selector, address(safeB)));
        _execSafeTx(address(safeB), 0, _outerData, Operation.Call);
        assertEq(_installedGuard(), address(guard), "A's guard survives");
        assertEq(safeB.nonce(), 1, "B's nonce rolled back with the whole transaction");
    }

    /// @dev Two guarded Safes executed back to back by one relayer in one EVM transaction: each gets its
    ///      own snapshot, check and report; neither sees the other's slot.
    function test_sequential_sibling_transactions_in_one_evm_transaction_are_independent() public {
        Relayer _relayer = new Relayer();
        ISafe[] memory _safes = new ISafe[](3);
        bytes[] memory _calls = new bytes[](3);
        _safes[0] = safe;
        _calls[0] = _execTransactionCalldata(safe, signerPk, address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
        _safes[1] = safeB;
        _calls[1] = _execTransactionCalldata(safeB, signerPkB, address(protocolB), 0, abi.encodeCall(MockProtocol.settleDeposit, (2)), Operation.Call);
        // A again, right after B, with the nonce advanced by one.
        vm.store(address(safe), bytes32(uint256(5)), bytes32(uint256(2))); // temporarily: sign at nonce 2
        _safes[2] = safe;
        _calls[2] = _execTransactionCalldata(safe, signerPk, address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (3)), Operation.Call);
        vm.store(address(safe), bytes32(uint256(5)), bytes32(uint256(1)));

        vm.recordLogs();
        _relayer.run(_safes, _calls);
        (address[] memory _reported, uint8[] memory _outcomes) = _reports(vm.getRecordedLogs());
        assertEq(_reported.length, 3, "three reports");
        assertEq(_reported[0], address(safe));
        assertEq(_reported[1], address(safeB));
        assertEq(_reported[2], address(safe));
        for (uint256 i; i < 3; ++i) assertEq(_outcomes[i], uint8(CuratorGuard.Outcome.Policy));
        assertEq(protocol.lastAmount(), 3);
        assertEq(protocolB.lastAmount(), 2);
    }

    function test_lockdown_cooldown_and_epoch_are_per_safe() public {
        vm.prank(guardianA);
        guard.lockdownAndRevoke(address(safe));
        assertEq(uint8(guard.mode(address(safeB))), uint8(CuratorGuardPolicy.Mode.Enforced), "B untouched");
        assertEq(guard.lockedAt(address(safeB)), 0, "no cooldown on B");
        assertEq(guard.approvalEpoch(address(safeB)), 0, "B's epoch untouched");
        assertEq(guard.approvalEpoch(address(safe)), 1, "A's epoch bumped");
        // The admin is held back on A only.
        vm.startPrank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(safe)));
        guard.enforce(address(safe));
        guard.enforce(address(safeB));
        guard.bypass(address(safeB), 1 hours);
        vm.stopPrank();
        assertEq(uint8(guard.mode(address(safeB))), uint8(CuratorGuardPolicy.Mode.Bypass));
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        assertEq(guard.approvalEpoch(address(safeB)), 1, "B's window bumped B only");
        assertEq(guard.approvalEpoch(address(safe)), 1, "A unchanged by B's window");
    }

    /// @dev Safe v1.5.0 with the module guard: the outer guarded Safe A is an allowlisted MODULE of
    ///      the inner Safe M. A's policy transaction drives `M.execTransactionFromModule`; M's module
    ///      path (slot (M,1)) evaluates M's policy with A as the executor, while A's slot (A,0) holds A's
    ///      digest. Both pass and both are reported on their own path.
    function test_outer_safe_as_module_of_a_v150_sibling_runs_under_both_policies() public {
        (address _ownerM, uint256 _pkM) = makeAddrAndKey("ownerM");
        Safe150 _singleton = new Safe150();
        SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = _ownerM;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        ISafe _m = ISafe(address(_proxy));
        _H().seedSafe(address(_m)); // the fixture's locally compiled v1.5.0 proxy / singleton (the guard pins canonical Safe code)
        vm.startPrank(address(_m));
        _m.enableModule(address(safe));
        _m.setGuard(address(guard));
        _m.setModuleGuard(address(guard));
        vm.stopPrank();
        MockProtocol _venueM = new MockProtocol();
        vm.startPrank(vetro);
        guard.enforce(address(_m));
        guard.allowFunction(address(_m), address(_venueM), SETTLE, false, _noRules());
        guard.setModuleAllowed(address(_m), address(safe), true);
        guard.allowFunction(address(safe), address(_m), ISafe.execTransactionFromModule.selector, false, _noRules());
        vm.stopPrank();
        _pkM; // unused: M never signs here

        bytes memory _inner = abi.encodeCall(MockProtocol.settleDeposit, (9));
        bytes memory _viaModule = abi.encodeCall(ISafe.execTransactionFromModule, (address(_venueM), 0, _inner, Operation.Call));
        vm.recordLogs();
        assertTrue(_execSafeTx(address(_m), 0, _viaModule, Operation.Call), "A drives M");
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        (address[] memory _safes, ) = _reports(_logs);
        assertEq(_safes.length, 2, "two reports");
        assertEq(_safes[0], address(_m), "M (module path) first");
        assertEq(_safes[1], address(safe), "A (owner path) last");
        // M's report is on path 1; A's on path 0.
        uint256 _k;
        for (uint256 i; i < _logs.length; ++i) {
            if (_logs[i].emitter == address(guard) && _logs[i].topics[0] == CuratorGuard.TransactionChecked.selector) {
                uint8 _path = abi.decode(_logs[i].data, (uint8));
                assertEq(_path, _k == 0 ? 1 : 0, "path per Safe");
                ++_k;
            }
        }
        assertEq(_venueM.lastAmount(), 9);
        // M's policy, not A's, governs the inner payload: a venue M does not allow is refused inside A's
        // allowed call, and A's transaction fails as a whole (the Safe reverts on inner failure).
        bytes memory _viaModuleBad = abi.encodeCall(ISafe.execTransactionFromModule, (address(protocol), 0, _inner, Operation.Call));
        // (the inner hook's revert is swallowed by A's `execute`; with `safeTxGas == 0` A says GS013)
        vm.expectRevert("GS013");
        _execSafeTx(address(_m), 0, _viaModuleBad, Operation.Call);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), SETTLE));
        guard.validateModuleTransaction(address(_m), address(safe), address(protocol), 0, _inner, Operation.Call);
        // And a guardian of M removing A from M's module list switches the path off, whatever A's policy says.
        vm.prank(council);
        guard.setModuleAllowed(address(_m), address(safe), false);
        vm.expectRevert("GS013");
        _execSafeTx(address(_m), 0, _viaModule, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(safe)));
        guard.validateModuleTransaction(address(_m), address(safe), address(_venueM), 0, _inner, Operation.Call);
    }

    /// @dev A guarded Safe appointed as a guardian of a sibling cannot exercise that seat from its own
    ///      transactions in any mode (the guard is never a call target); only an admin-window batch entry
    ///      or an admin-approved batch reaches it (documented residuals R7D-7 / V2-36).
    function test_guarded_safe_as_guardian_of_a_sibling_cannot_act_from_its_transactions() public {
        vm.prank(vetro);
        guard.setGuardian(address(safeB), address(safe), true);
        assertTrue(guard.isGuardian(address(safeB), address(safe)), "A is a guardian of B");
        bytes memory _lock = abi.encodeCall(guard.lockdown, (address(safeB)));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, guard.lockdown.selector));
        _execSafeTx(address(guard), 0, _lock, Operation.Call);
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, guard.lockdown.selector));
        _execSafeTx(address(guard), 0, _lock, Operation.Call);
        vm.prank(vetro);
        guard.lockdown(address(safe));
        vm.warp(block.timestamp + 2 days);
        vm.prank(vetro);
        guard.bypass(address(safe), 1 hours);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, guard.lockdown.selector));
        _execSafeTx(address(guard), 0, _lock, Operation.Call);
        assertEq(uint8(guard.mode(address(safeB))), uint8(CuratorGuardPolicy.Mode.Enforced), "B never locked");
        // Admin window + batch entry: reachable (documented residual), and it is a narrowing only.
        _seedCodehash(address(multiSendCallOnly).codehash);
        vm.prank(vetro);
        guard.setMultiSendUnwrapper(address(safe), address(multiSendCallOnly), true);
        bytes memory _batch = _multiSendCalldata(_entry(address(guard), 0, _lock));
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall), "admin-window batch");
        assertEq(uint8(guard.mode(address(safeB))), uint8(CuratorGuardPolicy.Mode.Lockdown), "B locked by its guardian A");
    }

    /// @dev `OneOf` sets are keyed by `(target, selector, wordIndex)` INSIDE the Safe's policy: the same
    ///      venue function on two Safes has two independent member sets, and a guardian of one clears
    ///      only that one.
    function test_value_sets_of_the_same_function_are_per_safe() public {
        bytes32[] memory _a = new bytes32[](1);
        _a[0] = bytes32(uint256(1));
        bytes32[] memory _b = new bytes32[](1);
        _b[0] = bytes32(uint256(2));
        vm.startPrank(vetro);
        guard.allowFunction(address(safe), address(protocol), DEPOSIT, false, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        guard.allowFunction(address(safeB), address(protocol), DEPOSIT, false, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        guard.addAllowedValues(address(safe), address(protocol), DEPOSIT, 0, _a);
        guard.addAllowedValues(address(safeB), address(protocol), DEPOSIT, 0, _b);
        vm.stopPrank();
        assertEq(guard.allowedValues(address(safe), address(protocol), DEPOSIT, 0).length, 1);
        assertEq(guard.allowedValues(address(safe), address(protocol), DEPOSIT, 0)[0], _a[0]);
        assertEq(guard.allowedValues(address(safeB), address(protocol), DEPOSIT, 0)[0], _b[0]);
        // Each Safe passes only its own member.
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (1, attacker)), Operation.Call));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(protocol), DEPOSIT, uint16(0), bytes32(uint256(2))));
        _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (2, attacker)), Operation.Call);
        assertTrue(_execAs(safeB, signerPkB, address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (2, attacker)), Operation.Call));
        // A's guardian clears A's set only.
        vm.prank(guardianA);
        guard.clearAllowedValues(address(safe), address(protocol), DEPOSIT, 0);
        assertEq(guard.allowedValues(address(safe), address(protocol), DEPOSIT, 0).length, 0);
        assertEq(guard.allowedValues(address(safeB), address(protocol), DEPOSIT, 0).length, 1, "B's set survives");
    }

    /// @dev Safe A (guarded) is the sole OWNER of Safe B2 (guarded) and signs B2's transaction as an
    ///      EIP-1271 contract owner through the CompatibilityFallbackHandler. The Safe validates a
    ///      contract signature with a STATICCALL into A, so A's hooks never run: B2's transaction is
    ///      checked by B2's policy only, and A's policy, approvals and slot are not involved. (A's policy
    ///      tolerates the handler here; the shipped policy requires `address(0)`, which forbids this.)
    function test_safe_as_eip1271_owner_of_a_sibling_signs_without_reaching_its_own_hooks() public {
        CompatibilityFallbackHandler _handler = new CompatibilityFallbackHandler();
        vm.prank(address(safe));
        Safe(payable(address(safe))).setFallbackHandler(address(_handler));
        ISafe _b2 = _newSafe(address(safe));
        vm.prank(address(_b2));
        _b2.setGuard(address(guard));
        vm.startPrank(vetro);
        guard.enforce(address(_b2));
        guard.allowFunction(address(_b2), address(protocolB), SETTLE, false, _noRules());
        vm.stopPrank();

        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (11));
        bytes memory _txHashData = Safe(payable(address(_b2))).encodeTransactionData(
            address(protocolB), 0, _data, Enum.Operation.Call, 0, 0, 0, address(0), address(0), _b2.nonce()
        );
        // The handler's message hash for A over B2's txHashData, signed by A's EOA owner.
        bytes memory _messageData = _handler.encodeMessageDataForSafe(Safe(payable(address(safe))), _txHashData);
        bytes memory _ownerSig = _sign(keccak256(_messageData));
        // Contract signature: r = A, s = offset 65, v = 0, then length-prefixed inner signature.
        bytes memory _contractSig = abi.encodePacked(bytes32(uint256(uint160(address(safe)))), bytes32(uint256(65)), uint8(0), bytes32(_ownerSig.length), _ownerSig);

        vm.recordLogs();
        bool _ok = _b2.execTransaction(address(protocolB), 0, _data, Operation.Call, 0, 0, 0, address(0), payable(address(0)), _contractSig);
        assertTrue(_ok, "B2 executes with A's contract signature");
        (address[] memory _safes, uint8[] memory _outcomes) = _reports(vm.getRecordedLogs());
        assertEq(_safes.length, 1, "exactly one report: B2's");
        assertEq(_safes[0], address(_b2));
        assertEq(_outcomes[0], uint8(CuratorGuard.Outcome.Policy));
        assertEq(protocolB.lastAmount(), 11);
        // A's own next transaction is unaffected (no stale slot, no consumed approval).
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call));
    }

    /// @dev R8Q-1: the module-path `txHash` folds the Safe (`keccak256(abi.encode(safe, module, to,
    ///      value, keccak256(data), operation))`), so two Safes driven by the same module with the same
    ///      payload report DIFFERENT `txHash` topics, like the owner path's `safeTxHash` (which folds the
    ///      Safe through its domain separator). Identical payloads on ONE Safe still share it.
    function test_module_path_report_hash_is_bound_to_the_safe() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        ISafe[2] memory _s;
        for (uint256 k; k < 2; ++k) {
            Safe150 _singleton = new Safe150();
            SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
            address[] memory _owners = new address[](1);
            _owners[0] = curator;
            Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
            _s[k] = ISafe(address(_proxy));
            _H().seedSafe(address(_s[k]));
            vm.startPrank(address(_s[k]));
            _s[k].setGuard(address(guard));
            _s[k].setModuleGuard(address(guard));
            vm.stopPrank();
            vm.startPrank(vetro);
            guard.enforce(address(_s[k]));
            guard.setModuleAllowed(address(_s[k]), attacker, true);
            guard.allowFunction(address(_s[k]), address(protocol), SETTLE, false, _noRules());
            vm.stopPrank();
        }
        vm.prank(address(_s[0]));
        bytes32 _hA = guard.checkModuleTransaction(address(protocol), 0, _data, Operation.Call, attacker);
        vm.prank(address(_s[1]));
        bytes32 _hB = guard.checkModuleTransaction(address(protocol), 0, _data, Operation.Call, attacker);
        assertTrue(_hA != _hB, "the payload hash is bound to the Safe");
        assertEq(_hA, keccak256(abi.encode(address(_s[0]), attacker, address(protocol), uint256(0), keccak256(_data), Operation.Call)));
        vm.recordLogs();
        vm.prank(address(_s[0]));
        guard.checkAfterModuleExecution(_hA, true);
        vm.prank(address(_s[1]));
        guard.checkAfterModuleExecution(_hB, true);
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertTrue(_logs[0].topics[2] != _logs[1].topics[2], "distinct txHash topics");
        assertTrue(_logs[0].topics[1] != _logs[1].topics[1], "the safe topic differs too");
    }
}
