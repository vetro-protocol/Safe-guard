// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

// Review g17a (the contracts, cold): the reviewer's own invariants, written from the contract sources before
// the record was opened, exercised on the real Safe v1.4.1 build from lib/ (the shared fixture) and on the real
// v1.5.0 build (module path). Nothing here is applied to the repository: tmpfs copy only.

import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, CuratorGuardHarness, MaliciousMultiSend, MockProtocol, Reverter} from "test/guards/CuratorGuardTestBase.sol";
import {TestERC20} from "test/mocks/TestERC20.sol";

/// @dev Fails on its first call, succeeds afterwards: exercises "a failed approved execution keeps the approval".
contract FailOnce {
    bool public armed;
    uint256 public calls;

    function arm() external {
        armed = true;
    }

    function poke() external {
        if (!armed) revert("first");
        ++calls;
    }
}

contract G17a_Cold is CuratorGuardTestBase {
    bytes32 internal constant TX_CHECKED_SIG = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");

    /*//////////////////////////////////////////////////////////////
                I1  a policy transaction never changes the Safe's configuration
    //////////////////////////////////////////////////////////////*/

    /// A registered unwrapper whose code writes a Safe slot (stand-in for a canonical build that turned out to write
    /// storage): the post-hook compares the digest and the whole Safe transaction reverts, threshold untouched.
    function test_I1_config_write_inside_policy_tx_fails_closed() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        MaliciousMultiSend _mal = new MaliciousMultiSend(bytes32(uint256(4)), bytes32(uint256(7))); // threshold := 7
        _registerUnwrapper(address(_mal));
        bytes memory _batch = _multiSendCalldata(_entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1))));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(safe)));
        _execSafeTx(address(_mal), 0, _batch, Operation.DelegateCall);
        assertEq(safe.getThreshold(), 1, "threshold untouched");
    }

    /*//////////////////////////////////////////////////////////////
                I2  an approval is spent at most once and never by a failed execution
    //////////////////////////////////////////////////////////////*/

    function test_I2_approval_spent_once_kept_on_failure() public {
        _enforce();
        FailOnce _t = new FailOnce();
        bytes memory _data = abi.encodeCall(FailOnce.poke, ());
        bytes32 _id = _approve(address(_t), 0, _data, Operation.Call);
        assertGt(guard.approvalExpiry(_id), 0);

        // safeTxGas != 0: the Safe reports success == false to the post-hook, which reverts ApprovedExecutionFailed.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ApprovedExecutionFailed.selector, address(safe)));
        _execSafeTxWithGas(address(_t), 0, _data, Operation.Call, 200_000);
        assertGt(guard.approvalExpiry(_id), 0, "approval kept after a failed execution (safeTxGas != 0)");
        // safeTxGas == 0: the Safe itself reverts (GS013) before the post-hook; the pre-hook's consumption is rolled back.
        vm.expectRevert(bytes("GS013"));
        _execSafeTx(address(_t), 0, _data, Operation.Call);
        assertGt(guard.approvalExpiry(_id), 0, "approval kept after a failed execution (safeTxGas == 0)");
        assertEq(_t.calls(), 0, "nothing landed");

        _t.arm();
        assertTrue(_execSafeTx(address(_t), 0, _data, Operation.Call));
        assertEq(_t.calls(), 1);
        assertEq(guard.approvalExpiry(_id), 0, "consumed on the first success");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(_t), FailOnce.poke.selector));
        _execSafeTx(address(_t), 0, _data, Operation.Call);
    }

    function test_I2_approval_consumed_exactly_once() public {
        _enforce();
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (42));
        bytes32 _id = _approve(address(protocol), 0, _data, Operation.Call);
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call));
        assertEq(guard.approvalExpiry(_id), 0, "consumed");
        assertEq(protocol.lastAmount(), 42);
        // Second execution of the same payload: no approval, not allowlisted -> refused.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.settleDeposit.selector));
        _execSafeTx(address(protocol), 0, _data, Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
                I3  nobody but the admin widens
    //////////////////////////////////////////////////////////////*/

    function test_I3_only_the_admin_widens() public {
        _addGuardian(guardian);
        bytes32 _COUNCIL = guard.COUNCIL_ROLE();
        address[4] memory _callers = [council, guardian, attacker, address(safe)];
        bytes32[] memory _vals = new bytes32[](1);
        _vals[0] = _word(attacker);
        for (uint256 i; i < _callers.length; ++i) {
            address _c = _callers[i];
            vm.startPrank(_c);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.allowFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules());
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.addAllowedValues(address(safe), address(protocol), MockProtocol.deposit.selector, 1, _vals);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.setModuleAllowed(address(safe), attacker, true);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.setMultiSendUnwrapper(address(safe), address(multiSendCallOnly), true);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.setNativeTransferAllowed(address(safe), attacker, true);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.setRequiredFallbackHandler(address(safe), address(0), false);
            vm.expectRevert(); // AccessControlUnauthorizedAccount (OpenZeppelin): COUNCIL_ROLE is admin-managed
            guard.grantRole(_COUNCIL, attacker);
            vm.expectRevert(); // AccessControlEnforcedDefaultAdminRules
            guard.grantRole(bytes32(0), attacker);
            // approvals of a delegatecall or of an unlisted self-call: admin only
            if (_c == council) {
                vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, bytes4(0), Operation.DelegateCall));
            } else {
                vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            }
            guard.approveTransaction(address(safe), address(0), address(multiSendCallOnly), 0, "", Operation.DelegateCall, 1 days);
            if (_c == council) {
                vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, ISafe.setGuard.selector, Operation.Call));
            } else {
                vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            }
            guard.approveTransaction(address(safe), address(0), address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call, 1 days);
            // a window longer than the council cap, or by anyone else
            if (_c == council) {
                vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, uint64(7 days + 1)));
            } else {
                vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            }
            guard.bypass(address(safe), 7 days + 1);
            vm.stopPrank();
        }
    }

    /*//////////////////////////////////////////////////////////////
                I4  a Safe whose fallback handler is the guard exercises nothing through it
    //////////////////////////////////////////////////////////////*/

    function test_I4_forwarded_calls_exercise_nothing() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(safe), address(0), true);
        // The admin (by mistake) approves putting the guard into the handler slot; the signers execute it.
        bytes memory _bad = abi.encodeWithSelector(0xf08a0323, address(guard));
        _approve(address(safe), 0, _bad, Operation.Call);
        assertTrue(_execSafeTx(address(safe), 0, _bad, Operation.Call));
        assertEq(address(uint160(uint256(bytes32(safe.getStorageAt(uint256(FALLBACK_SLOT), 1))))), address(guard));

        // (a) policy traffic from the Safe is refused by the handler requirement
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FallbackHandlerNotAllowed.selector, address(guard)));
        _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);

        // (b) a stranger cannot burn an approval through the Safe's fallback (the repair approval included)
        bytes memory _repair = abi.encodeWithSelector(0xf08a0323, address(0));
        bytes32 _id = _approve(address(safe), 0, _repair, Operation.Call);
        bytes memory _fwd = abi.encodeCall(
            guard.checkTransaction,
            (address(safe), 0, _repair, Operation.Call, 0, 0, 0, address(0), payable(address(0)), bytes(""), attacker)
        );
        vm.prank(attacker);
        (bool _ok, bytes memory _ret) = address(safe).call(_fwd);
        assertFalse(_ok);
        assertEq(bytes4(_ret), CuratorGuard.ForwardedHookCall.selector, "forwarded pre-hook refused");
        assertGt(guard.approvalExpiry(_id), 0, "approval intact");
        // ... nor forge a report through the forwarded after-hook (68 + 20 bytes)
        vm.prank(attacker);
        (_ok, _ret) = address(safe).call(abi.encodeCall(guard.checkAfterExecution, (bytes32(uint256(1)), true)));
        assertFalse(_ok);
        assertEq(bytes4(_ret), CuratorGuard.ForwardedHookCall.selector, "forwarded after-hook refused");
        // ... nor exercise a role (the rails refuse any seat for a configured Safe anyway), nor the re-dispatcher
        bytes32 _GUARDIAN = guard.GUARDIAN_ROLE();
        vm.prank(attacker);
        (_ok, _ret) = address(safe).call(abi.encodeCall(guard.lockdown, (address(safe))));
        assertFalse(_ok);
        assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector, "forwarded role call refused");
        vm.prank(attacker);
        (_ok, _ret) = address(safe).call(abi.encodeCall(guard.executeBefore, (uint64(block.timestamp + 1), abi.encodeCall(guard.lockdown, (address(safe))))));
        assertFalse(_ok);
        assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector, "forwarded executeBefore refused");
        vm.prank(attacker);
        (_ok, _ret) = address(safe).call(abi.encodeCall(guard.renounceRole, (_GUARDIAN, address(safe))));
        assertFalse(_ok);
        assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector, "forwarded renounce refused");

        // (c) the way out: a council window, inside which the signers run the canonical repair
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        assertTrue(_execSafeTx(address(safe), 0, _repair, Operation.Call));
        assertEq(uint256(bytes32(safe.getStorageAt(uint256(FALLBACK_SLOT), 1))), 0, "handler removed");
    }

    /*//////////////////////////////////////////////////////////////
                I5  a council window never weakens the Safe (top level and batch entries)
    //////////////////////////////////////////////////////////////*/

    function test_I5_council_window_limits() public {
        _enforce();
        _registerUnwrapper(address(multiSendCallOnly));
        address _handler = makeAddr("handler");
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(safe), _handler, false); // named but not enforced: still unreachable
        vm.prank(council);
        guard.bypass(address(safe), 7 days);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Bypass));

        bytes[6] memory _weakening = [
            abi.encodeCall(ISafe.setGuard, (address(0))),
            abi.encodeCall(ISafe.enableModule, (attacker)),
            abi.encodeWithSelector(0xf08a0323, attacker),
            abi.encodeWithSelector(0x694e80c3, uint256(1)), // changeThreshold(1)
            abi.encodeWithSelector(0x0d582f13, address(protocol), uint256(2)), // addOwnerWithThreshold(contract, 2)
            abi.encodeWithSelector(0xe318b52b, address(1), curator, address(guard)) // swapOwner(_, curator, guard)
        ];
        for (uint256 i; i < _weakening.length; ++i) {
            bytes4 _sel = bytes4(_weakening[i]);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, _sel));
            _execSafeTx(address(safe), 0, _weakening[i], Operation.Call);
            // the same self-call as a batch entry
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, _sel));
            _execSafeTx(address(multiSendCallOnly), 0, _multiSendCalldata(_entry(address(safe), 0, _weakening[i])), Operation.DelegateCall);
        }
        // the named handler is part of the Safe
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, bytes4(0)));
        _execSafeTx(_handler, 0, "", Operation.Call);
        // no gas refund, no guard call, no raw delegatecall
        vm.expectRevert(CuratorGuard.GasRefundNotAllowed.selector);
        _execSafeTxWithRefund(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call, 1, address(0), attacker);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, CuratorGuardPolicy.lockdown.selector));
        _execSafeTx(address(guard), 0, abi.encodeCall(guard.lockdown, (address(safe))), Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.DelegateCallNotAllowed.selector, address(multiSend)));
        _execSafeTx(address(multiSend), 0, _multiSendCalldata(_entry(address(protocol), 0, "")), Operation.DelegateCall);
        // what a council window DOES allow the signers: any venue call, custody transfers included (documented two-party risk)
        uint256 _bal = token.balanceOf(address(safe));
        assertTrue(_execSafeTx(address(token), 0, abi.encodeWithSelector(0xa9059cbb, attacker, _bal), Operation.Call));
        assertEq(token.balanceOf(attacker), _bal, "a council window + the signers = custody");
        // and owner management with a threshold of at least 2 and keyless-looking seats
        assertTrue(_execSafeTx(address(safe), 0, abi.encodeWithSelector(0x0d582f13, attacker, uint256(2)), Operation.Call));
        assertEq(safe.getThreshold(), 2);
    }

    /*//////////////////////////////////////////////////////////////
                I6  windows expire on their own; a lockdown is never lifted by time
    //////////////////////////////////////////////////////////////*/

    function test_I6_window_expiry_boundary_and_lockdown_persistence() public {
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        uint256 _t = block.timestamp;
        _bypass(1 hours);
        vm.warp(_t + 1 hours - 1);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Bypass));
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (1, attacker)), Operation.Call));
        vm.warp(_t + 1 hours);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
        vm.warp(_t + 365 days);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown), "time never lifts a lockdown");
        (uint64 _until, bool _council) = guard.bypassWindow(address(safe));
        assertEq(_until, uint64(_t + 1 hours));
        assertFalse(_council);
    }

    /// A per-Safe guardian can keep the admin's lift away for as long as it re-locks (the council is not held back).
    function test_I6_guardian_relock_starves_the_admin_lift_not_the_council() public {
        _addGuardian(guardian);
        _enforce();
        for (uint256 i; i < 5; ++i) {
            vm.prank(guardian);
            guard.lockdown(address(safe));
            vm.warp(block.timestamp + 20 hours);
            vm.prank(vetro);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(safe)));
            guard.enforce(address(safe));
        }
        vm.prank(council);
        guard.enforce(address(safe));
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Enforced));
    }

    /*//////////////////////////////////////////////////////////////
                I7  OneOf sets never leak through a revoke
    //////////////////////////////////////////////////////////////*/

    function test_I7_oneof_sets_die_with_revoke() public {
        _enforce();
        bytes4 _sel = MockProtocol.deposit.selector;
        _allowWithRules(address(protocol), _sel, _rule(CuratorGuardPolicy.RuleKind.OneOf, 1, 0));
        bytes32[] memory _vals = new bytes32[](1);
        _vals[0] = _word(attacker);
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(protocol), _sel, 1, _vals);
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (1, attacker)), Operation.Call));

        vm.prank(vetro);
        guard.revokeFunction(address(safe), address(protocol), _sel);
        assertEq(guard.allowedValues(address(safe), address(protocol), _sel, 1).length, 0, "set gone with the revoke");
        // re-allow with the same OneOf rule: the set starts empty, the old member does not come back
        _allowWithRules(address(protocol), _sel, _rule(CuratorGuardPolicy.RuleKind.OneOf, 1, 0));
        assertEq(guard.allowedValues(address(safe), address(protocol), _sel, 1).length, 0, "re-allow starts empty");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(protocol), _sel, uint16(1), _word(attacker)));
        _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (1, attacker)), Operation.Call);
        // a re-allow that DROPS the OneOf rule clears the set (events), so a later rule cannot revive it
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(protocol), _sel, 1, _vals);
        _allowWithRules(address(protocol), _sel, _rule(CuratorGuardPolicy.RuleKind.EqualToSafe, 1, 0));
        _allowWithRules(address(protocol), _sel, _rule(CuratorGuardPolicy.RuleKind.OneOf, 1, 0));
        assertEq(guard.allowedValues(address(safe), address(protocol), _sel, 1).length, 0, "dropped rule's set cleared");
    }

    /*//////////////////////////////////////////////////////////////
                I9  TransactionChecked once per transaction: the admin-window exception
    //////////////////////////////////////////////////////////////*/

    /// Inside an ADMIN window the top-level target may not be the guard, but batch entries (and any delegatecalled
    /// code) are not decoded: an entry addressed to `checkAfterExecution` lands with the Safe as caller and emits a
    /// `TransactionChecked(safe, <any hash>, 0, Bypass)` of the guard's own making, before the genuine one. Docs section
    /// 4 step 5 states it ("reports inside one are not authoritative"); the contract NatSpec (rule 4, "true in every
    /// mode") overstates. No approval, role or policy state is reachable this way (checked below).
    function test_I9_admin_window_batch_entry_forges_a_report() public {
        _bypass(1 days);
        bytes32 _forged = keccak256("not a safe tx hash");
        bytes memory _batch = _multiSendCalldata(
            abi.encodePacked(
                _entry(address(guard), 0, abi.encodeCall(guard.checkAfterExecution, (_forged, true))),
                _entry(address(guard), 0, abi.encodeCall(guard.lockdown, (address(safe)))) // a role call: must fail the batch
            )
        );
        // the role call inside the batch reverts the batch (Unauthorized) -> the Safe transaction fails (GS013)
        vm.expectRevert(bytes("GS013"));
        _execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);

        _batch = _multiSendCalldata(_entry(address(guard), 0, abi.encodeCall(guard.checkAfterExecution, (_forged, true))));
        vm.recordLogs();
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall)); // an unregistered local build: any delegatecall goes in an admin window
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        uint256 _n;
        bytes32 _first;
        for (uint256 i; i < _logs.length; ++i) {
            if (_logs[i].emitter == address(guard) && _logs[i].topics[0] == TX_CHECKED_SIG) {
                if (_n == 0) _first = _logs[i].topics[2];
                ++_n;
            }
        }
        assertEq(_n, 2, "two reports for one Safe transaction");
        assertEq(_first, _forged, "the forged one comes first, Bypass outcome");
    }

    /*//////////////////////////////////////////////////////////////
                I11  executeBefore and the admin hand-over deadlines
    //////////////////////////////////////////////////////////////*/

    function test_I11_deadlines() public {
        uint64 _deadline = uint64(block.timestamp + 10);
        bytes memory _call = abi.encodeCall(guard.enforce, (address(safe)));
        vm.warp(_deadline + 1);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, _deadline));
        guard.executeBefore(_deadline, _call);
        vm.warp(_deadline);
        vm.prank(vetro);
        guard.executeBefore(_deadline, _call);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Enforced));
        // a stranger wrapping an admin call keeps its own identity
        vm.prank(attacker);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.executeBefore(_deadline, abi.encodeCall(guard.lockdown, (address(safe))));

        // admin hand-over: acceptance within 30 days of the schedule, by the pending admin only
        address _next = makeAddr("next-admin");
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(_next);
        (, uint48 _schedule) = guard.pendingDefaultAdmin();
        vm.warp(uint256(_schedule) + 30 days + 1);
        vm.prank(_next);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, uint64(_schedule)));
        guard.acceptDefaultAdminTransfer();
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(_next); // re-arm
        (, _schedule) = guard.pendingDefaultAdmin();
        vm.warp(uint256(_schedule) + 1);
        vm.prank(_next);
        guard.acceptDefaultAdminTransfer();
        assertEq(guard.defaultAdmin(), _next);
        // the old admin is now a stranger to the hooks' exemption, the new one exempt
        vm.prank(_next);
        vm.expectRevert(CuratorGuardPolicy.AdminCannotBeZero.selector);
        guard.beginDefaultAdminTransfer(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                I10  the timelock keeps its topology
    //////////////////////////////////////////////////////////////*/

    function test_I10_timelock_rails() public {
        address _p1 = makeAddr("proposer-1");
        address _p2 = makeAddr("proposer-2");
        address _veto = makeAddr("veto");
        address[] memory _props = new address[](2);
        _props[0] = _p1;
        _props[1] = _p2;
        address[] memory _cans = new address[](1);
        _cans[0] = _veto;
        CuratorGuardTimelock _tl = new CuratorGuardTimelock(1 days, _props, _cans);
        bytes32 _PR = _tl.PROPOSER_ROLE();
        bytes32 _CR = _tl.CANCELLER_ROLE();
        bytes32 _ER = _tl.EXECUTOR_ROLE();
        assertEq(_tl.proposerCount(), 2);
        assertEq(_tl.cancellerCount(), 1);
        assertFalse(_tl.hasRole(_CR, _p1), "proposers stripped of the veto");
        assertTrue(_tl.hasRole(_ER, address(0)), "open executor");
        assertTrue(_tl.hasRole(bytes32(0), address(_tl)), "self-admin");
        // constructor rails
        _cans[0] = _p1;
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.CancellerCannotPropose.selector, _p1));
        new CuratorGuardTimelock(1 days, _props, _cans);
        _cans[0] = _veto;
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, uint256(1 hours)));
        new CuratorGuardTimelock(1 hours, _props, _cans);

        // proposal-time rails: delay must be exactly the live min delay; updateDelay outside the clamp refused at schedule
        bytes memory _upd = abi.encodeCall(_tl.updateDelay, (1 hours));
        vm.startPrank(_p1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, uint256(2 days)));
        _tl.schedule(address(_tl), 0, _upd, 0, 0, 2 days);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, uint256(1 hours)));
        _tl.schedule(address(_tl), 0, _upd, 0, 0, 1 days);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.TargetHasNoCode.selector, attacker));
        _tl.schedule(attacker, 0, hex"01", 0, 0, 1 days);
        // role management stays a vetoable self-call and keeps the topology
        bytes[6] memory _bad = [
            abi.encodeCall(_tl.grantRole, (_CR, _p1)),
            abi.encodeCall(_tl.grantRole, (_PR, _veto)),
            abi.encodeCall(_tl.revokeRole, (_CR, _veto)),
            abi.encodeCall(_tl.grantRole, (bytes32(0), attacker)),
            abi.encodeCall(_tl.revokeRole, (_ER, address(0))),
            abi.encodeCall(_tl.grantRole, (_PR, address(_tl)))
        ];
        bytes[6] memory _errs = [
            abi.encodeWithSelector(CuratorGuardTimelock.ProposerCannotCancel.selector, _p1),
            abi.encodeWithSelector(CuratorGuardTimelock.CancellerCannotPropose.selector, _veto),
            abi.encodeWithSelector(CuratorGuardTimelock.LastRoleHolder.selector, _CR),
            abi.encodeWithSelector(CuratorGuardTimelock.SelfAdminRequired.selector),
            abi.encodeWithSelector(CuratorGuardTimelock.OpenExecutorRequired.selector),
            abi.encodeWithSelector(CuratorGuardTimelock.SelfHolder.selector, _PR)
        ];
        for (uint256 i; i < _bad.length; ++i) _tl.schedule(address(_tl), 0, _bad[i], 0, bytes32(i + 1), 1 days);
        vm.stopPrank();
        vm.warp(block.timestamp + 1 days);
        for (uint256 i; i < _bad.length; ++i) {
            vm.expectRevert(_errs[i]);
            _tl.execute(address(_tl), 0, _bad[i], 0, bytes32(i + 1));
        }
        // the last proposer cannot renounce; a non-last one can
        vm.prank(_p2);
        _tl.renounceRole(_PR, _p2);
        vm.prank(_p1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.LastRoleHolder.selector, _PR));
        _tl.renounceRole(_PR, _p1);
        vm.prank(_veto);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.LastRoleHolder.selector, _CR));
        _tl.renounceRole(_CR, _veto);
        // the clamp on a stored out-of-range delay (can only come from the constructor's range, so read-only check)
        assertEq(_tl.getMinDelay(), 1 days);
    }
}
