// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

// Review g21a (the contracts, bug classes): PoCs on the real Safe v1.4.1 build from lib/ (tmpfs copy; never applied).

import {stdError} from "forge-std/StdError.sol";
import {Vm} from "forge-std/Vm.sol";
import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IAccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/IAccessControlDefaultAdminRules.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {SettlementDeadline} from "contracts/helpers/SettlementDeadline.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, CuratorGuardHarness, MockProtocol, Reverter} from "test/guards/CuratorGuardTestBase.sol";

/// @dev An allowlisted venue that, when called, re-enters the Safe ONCE with a pre-signed `execTransaction`
///      (or meddles with the Safe's own configuration surface) and records what the Safe answered.
contract Reenterer {
    ISafe public immutable safe;
    bytes public innerCall;
    bool public innerOk;
    bytes4 public innerError;
    bytes public meddleReason;
    uint256 public pokes;

    constructor(ISafe safe_) {
        safe = safe_;
    }

    function arm(bytes calldata call_) external {
        innerCall = call_;
    }

    function poke(uint256) external {
        ++pokes;
        if (innerCall.length == 0) return;
        bytes memory _c = innerCall;
        delete innerCall;
        (bool _ok, bytes memory _ret) = address(safe).call(_c);
        innerOk = _ok;
        if (!_ok && _ret.length >= 4) innerError = bytes4(_ret);
    }

    /// @dev What a venue can do to the Safe's own surface from inside a guarded transaction: nothing.
    function meddle(uint8 which_) external {
        bytes memory _call = which_ == 0
            ? abi.encodeCall(ISafe.setGuard, (address(0)))
            : which_ == 1
                ? abi.encodeCall(ISafe.enableModule, (address(this)))
                : abi.encodeCall(ISafe.execTransactionFromModule, (address(this), 0, "", Operation.Call));
        (bool _ok, bytes memory _ret) = address(safe).call(_call);
        require(!_ok, "meddling succeeded");
        meddleReason = _ret;
    }
}

/// @dev Drives two signed Safe transactions in ONE EVM transaction, swallowing the first's revert.
contract Driver {
    function run(ISafe safe_, bytes calldata first_, bytes calldata second_) external returns (bool _firstOk, bytes4 _firstError, bool _secondOk) {
        (bool _ok, bytes memory _ret) = address(safe_).call(first_);
        _firstOk = _ok;
        if (!_ok && _ret.length >= 4) _firstError = bytes4(_ret);
        (_secondOk, ) = address(safe_).call(second_);
    }
}

/// @dev A timelock target that re-enters `execute` for its own (or another) ready operation while it runs.
contract ReentrantTarget {
    CuratorGuardTimelock public immutable tl;
    bytes32 public salt;
    bytes public innerData;
    bool public armed;
    uint256 public hits;
    bool public innerOk;
    bytes4 public innerError;

    constructor(CuratorGuardTimelock tl_) {
        tl = tl_;
    }

    function arm(bytes32 salt_, bytes memory data_) external {
        armed = true;
        salt = salt_;
        innerData = data_;
    }

    function disarm() external {
        armed = false;
    }

    function hit() external {
        ++hits;
        if (!armed) return;
        armed = false;
        (bool _ok, bytes memory _ret) = address(tl).call(
            abi.encodeCall(tl.execute, (address(this), 0, innerData, bytes32(0), salt))
        );
        innerOk = _ok;
        if (!_ok && _ret.length >= 4) innerError = bytes4(_ret);
    }

    function other() external {
        ++hits;
    }
}

contract G21a_BugClasses is CuratorGuardTestBase {
    SettlementDeadline internal deadline;
    Reverter internal reverter;

    bytes32 internal constant TRANSACTION_CHECKED = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");
    bytes32 internal constant EXECUTION_FAILURE = keccak256("ExecutionFailure(bytes32,uint256)");
    bytes32 internal constant EXECUTION_SUCCESS = keccak256("ExecutionSuccess(bytes32,uint256)");

    function setUp() public override {
        super.setUp();
        deadline = new SettlementDeadline();
        reverter = new Reverter();
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        _allow(address(deadline), SettlementDeadline.assertBefore.selector);
        _registerUnwrapper(address(multiSendCallOnly));
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _nonce() internal view returns (uint256) {
        return uint256(vm.load(address(safe), bytes32(NONCE_SLOT)));
    }

    /// @dev Full `execTransaction` calldata signed by the curator at an explicit nonce.
    function _signedCallAt(SafeTx memory t_, uint256 nonce_) internal view returns (bytes memory) {
        bytes32 _domainSeparator = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, address(safe)));
        bytes32 _hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), _domainSeparator, _safeTxHash(t_, nonce_)));
        return
            abi.encodeCall(
                ISafe.execTransaction,
                (t_.to, t_.value, t_.data, t_.op, t_.safeTxGas, 0, t_.gasPrice, t_.gasToken, payable(t_.refundReceiver), _sign(_hash))
            );
    }

    function _tx(address to_, uint256 value_, bytes memory data_, Operation op_, uint256 safeTxGas_) internal pure returns (SafeTx memory) {
        return SafeTx(to_, value_, data_, op_, safeTxGas_, 0, address(0), address(0));
    }

    function _countTopic(Vm.Log[] memory logs_, address emitter_, bytes32 topic0_) internal pure returns (uint256 _n, Vm.Log memory _last) {
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter == emitter_ && logs_[i].topics[0] == topic0_) {
                ++_n;
                _last = logs_[i];
            }
        }
    }

    function _batch(bytes memory a_, bytes memory b_) internal pure returns (bytes memory) {
        return _multiSendCalldata(abi.encodePacked(a_, b_));
    }

    /*//////////////////////////////////////////////////////////////
                    T1 / T2: A VENUE RE-ENTERING THE SAFE
    //////////////////////////////////////////////////////////////*/

    /// @dev A policy transaction's venue re-enters `execTransaction` of the same Safe with a pre-signed
    ///      policy (or approved) transaction: the inner one is refused `NestedExecution` before the window
    ///      and approval branches, the outer passes and is reported once, no approval is spent.
    function test_T1_venue_reenters_execTransaction_inner_refused_outer_reported_once() public {
        Reenterer _venue = new Reenterer(safe);
        _allow(address(_venue), Reenterer.poke.selector);
        uint256 _n = _nonce();
        // the inner transaction is signed for nonce n + 1: the Safe bumps the nonce before the pre-hook
        _venue.arm(_signedCallAt(_tx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call, 0), _n + 1));

        vm.recordLogs();
        assertTrue(_execSafeTx(address(_venue), 0, abi.encodeCall(Reenterer.poke, (1)), Operation.Call));
        assertFalse(_venue.innerOk(), "inner refused");
        assertEq(_venue.innerError(), CuratorGuard.NestedExecution.selector, "NestedExecution");
        assertEq(protocol.calls(), 0, "inner payload never ran");
        assertEq(_nonce(), _n + 1, "one nonce");
        (uint256 _reports, ) = _countTopic(vm.getRecordedLogs(), address(guard), TRANSACTION_CHECKED);
        assertEq(_reports, 1, "one report");

        // the inner one, now a plain second transaction at nonce n + 1, is still valid and lands on its own
        (bool _ok, ) = address(safe).call(_signedCallAt(_tx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call, 0), _n + 1));
        assertTrue(_ok);
        assertEq(protocol.calls(), 1);

        // an APPROVED inner transaction is refused the same way and the approval is kept
        bytes32 _id = _approve(address(protocol), 0, "", Operation.Call); // an empty zero-value call the policy refuses (no native permission)
        _venue.arm(_signedCallAt(_tx(address(protocol), 0, "", Operation.Call, 0), _nonce() + 1));
        assertTrue(_execSafeTx(address(_venue), 0, abi.encodeCall(Reenterer.poke, (2)), Operation.Call));
        assertEq(_venue.innerError(), CuratorGuard.NestedExecution.selector);
        assertGt(guard.approvalExpiry(_id), 0, "approval kept");
    }

    /// @dev The venue of an APPROVED transaction re-enters with a SECOND approved payload: refused
    ///      (`APPROVED_SENTINEL` is in the slot), the second approval survives, the first is consumed once.
    function test_T2_approved_payload_reentering_for_a_second_approval_is_refused() public {
        Reenterer _venue = new Reenterer(safe);
        bytes memory _outer = abi.encodeCall(Reenterer.poke, (7));
        bytes32 _first = _approve(address(_venue), 0, _outer, Operation.Call);
        bytes32 _second = _approve(address(protocol), 0, "", Operation.Call);
        _venue.arm(_signedCallAt(_tx(address(protocol), 0, "", Operation.Call, 0), _nonce() + 1));

        assertTrue(_execSafeTx(address(_venue), 0, _outer, Operation.Call));
        assertEq(_venue.innerError(), CuratorGuard.NestedExecution.selector);
        assertEq(guard.approvalExpiry(_first), 0, "first consumed");
        assertGt(guard.approvalExpiry(_second), 0, "second kept");
        // the second lands on its own afterwards
        (bool _ok, ) = address(safe).call(_signedCallAt(_tx(address(protocol), 0, "", Operation.Call, 0), _nonce()));
        assertTrue(_ok);
        assertEq(guard.approvalExpiry(_second), 0);
        assertEq(protocol.calls(), 1);
    }

    /// @dev From inside a guarded transaction a venue reaches none of the Safe's own `authorized` surface
    ///      (the Safe's own checks, before any guard): `setGuard`, `enableModule`, the module path.
    function test_T1b_venue_cannot_meddle_with_the_safe_from_inside() public {
        Reenterer _venue = new Reenterer(safe);
        _allow(address(_venue), Reenterer.meddle.selector);
        string[3] memory _expected = ["GS031", "GS031", "GS104"];
        for (uint8 i; i < 3; ++i) {
            assertTrue(_execSafeTx(address(_venue), 0, abi.encodeCall(Reenterer.meddle, (i)), Operation.Call));
            assertEq(abi.decode(_slice4(_venue.meddleReason()), (string)), _expected[i]);
        }
    }

    function _slice4(bytes memory b_) internal pure returns (bytes memory _r) {
        _r = new bytes(b_.length - 4);
        for (uint256 i; i < _r.length; ++i) _r[i] = b_[i + 4];
    }

    /*//////////////////////////////////////////////////////////////
              T3: TRANSIENT STATE ACROSS TWO SAFE TXS IN ONE EVM TX
    //////////////////////////////////////////////////////////////*/

    /// @dev An approved execution that fails with `safeTxGas != 0` reverts the whole `execTransaction`
    ///      (`ApprovedExecutionFailed`), which rolls the sentinel and the consumption back; a second signed
    ///      transaction in the SAME EVM transaction then passes (no leaked sentinel, no `NestedExecution`),
    ///      and the approval is still live.
    function test_T3_failed_approved_execution_leaves_no_transient_residue_for_the_next_safe_tx() public {
        Driver _driver = new Driver();
        bytes32 _id = _approve(address(reverter), 0, hex"deadbeef", Operation.Call);
        uint256 _n = _nonce();
        bytes memory _first = _signedCallAt(_tx(address(reverter), 0, hex"deadbeef", Operation.Call, 60_000), _n);
        bytes memory _second = _signedCallAt(_tx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (3)), Operation.Call, 0), _n);
        (bool _firstOk, bytes4 _firstError, bool _secondOk) = _driver.run(safe, _first, _second);
        assertFalse(_firstOk);
        assertEq(_firstError, CuratorGuard.ApprovedExecutionFailed.selector);
        assertTrue(_secondOk, "second passes in the same EVM tx");
        assertEq(protocol.calls(), 1);
        assertGt(guard.approvalExpiry(_id), 0, "approval kept");
        assertEq(_nonce(), _n + 1);
    }

    /*//////////////////////////////////////////////////////////////
                 T4: THE OPEN EXECUTOR RE-ENTERING THE TIMELOCK
    //////////////////////////////////////////////////////////////*/

    function test_T4_executor_reentering_the_same_operation_reverts_the_whole_execute_and_keeps_it_ready() public {
        address _proposer = makeAddr("proposer");
        address _canceller = makeAddr("canceller");
        address[] memory _p = new address[](1);
        _p[0] = _proposer;
        address[] memory _c = new address[](1);
        _c[0] = _canceller;
        CuratorGuardTimelock _tl = new CuratorGuardTimelock(1 days, _p, _c);
        ReentrantTarget _target = new ReentrantTarget(_tl);
        bytes32 _salt = keccak256("g21a");
        bytes memory _data = abi.encodeCall(ReentrantTarget.hit, ());
        vm.prank(_proposer);
        _tl.schedule(address(_target), 0, _data, bytes32(0), _salt, 1 days);
        bytes32 _id = _tl.hashOperation(address(_target), 0, _data, bytes32(0), _salt);
        vm.warp(block.timestamp + 1 days);
        assertTrue(_tl.isOperationReady(_id));

        _target.arm(_salt, _data);
        // the inner execute completes (the operation is still Ready inside the outer call) and marks the
        // operation Done; the outer `_afterCall` then finds it Done and reverts everything
        vm.expectRevert(
            abi.encodeWithSelector(
                TimelockController.TimelockUnexpectedOperationState.selector,
                _id,
                bytes32(uint256(1) << uint8(TimelockController.OperationState.Ready))
            )
        );
        vm.prank(attacker);
        _tl.execute(address(_target), 0, _data, bytes32(0), _salt);
        assertEq(_target.hits(), 0, "nothing of either frame survived");
        assertTrue(_tl.isOperationReady(_id), "still ready for an honest executor");

        _target.disarm();
        vm.prank(attacker);
        _tl.execute(address(_target), 0, _data, bytes32(0), _salt);
        assertEq(_target.hits(), 1);
        assertTrue(_tl.isOperationDone(_id));

        // re-entering a DIFFERENT ready operation from inside one is just an execution of both
        bytes memory _other = abi.encodeCall(ReentrantTarget.other, ());
        vm.startPrank(_proposer);
        _tl.schedule(address(_target), 0, _data, bytes32(0), keccak256("second"), 1 days);
        _tl.schedule(address(_target), 0, _other, bytes32(0), keccak256("third"), 1 days);
        vm.stopPrank();
        vm.warp(block.timestamp + 1 days);
        _target.arm(keccak256("third"), _other);
        vm.prank(attacker);
        _tl.execute(address(_target), 0, _data, bytes32(0), keccak256("second"));
        assertTrue(_target.innerOk(), "the other ready operation executed from inside");
        assertEq(_target.hits(), 3);
        assertTrue(_tl.isOperationDone(_tl.hashOperation(address(_target), 0, _data, bytes32(0), keccak256("second"))));
        assertTrue(_tl.isOperationDone(_tl.hashOperation(address(_target), 0, _other, bytes32(0), keccak256("third"))));
    }

    /*//////////////////////////////////////////////////////////////
                    T6: SETTLEMENT DEADLINE UNDER EVERY OPERATION
    //////////////////////////////////////////////////////////////*/

    function test_T6a_top_level_call_inclusive_edge_and_stale_revert_keeps_the_nonce() public {
        uint256 _d = block.timestamp + 600;
        bytes memory _call = abi.encodeCall(SettlementDeadline.assertBefore, (_d));
        vm.warp(_d);
        uint256 _n = _nonce();
        assertTrue(_execSafeTx(address(deadline), 0, _call, Operation.Call), "valid at the deadline second");
        vm.warp(_d + 1);
        vm.expectRevert("GS013");
        _execSafeTx(address(deadline), 0, _call, Operation.Call);
        assertEq(_nonce(), _n + 1, "the stale one kept the nonce");
    }

    /// @dev With `safeTxGas != 0` the Safe does NOT revert: the nonce is burnt, `ExecutionFailure` and the
    ///      guard's `TransactionChecked(Policy)` are both emitted (the report says "passed both hooks", not
    ///      "succeeded"). The stale settlement is dead either way (its nonce is gone).
    function test_T6b_stale_with_safeTxGas_burns_the_nonce_and_reports_policy() public {
        uint256 _d = block.timestamp + 600;
        bytes memory _call = abi.encodeCall(SettlementDeadline.assertBefore, (_d));
        vm.warp(_d + 1);
        uint256 _n = _nonce();
        vm.recordLogs();
        assertFalse(_execSafeTxWithGas(address(deadline), 0, _call, Operation.Call, 100_000));
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        (uint256 _f, ) = _countTopic(_logs, address(safe), EXECUTION_FAILURE);
        (uint256 _r, Vm.Log memory _report) = _countTopic(_logs, address(guard), TRANSACTION_CHECKED);
        assertEq(_f, 1, "ExecutionFailure");
        assertEq(_r, 1, "TransactionChecked");
        assertEq(uint256(_report.topics[3]), uint256(CuratorGuard.Outcome.Policy));
        assertEq(_nonce(), _n + 1, "nonce burnt");
    }

    function test_T6c_first_entry_of_a_batch_kills_a_stale_batch_and_passes_a_fresh_one() public {
        uint256 _d = block.timestamp + 600;
        bytes memory _batchData = _batch(
            _entry(address(deadline), 0, abi.encodeCall(SettlementDeadline.assertBefore, (_d))),
            _entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (5)))
        );
        vm.warp(_d + 1);
        uint256 _n = _nonce();
        vm.expectRevert("GS013");
        _execSafeTx(address(multiSendCallOnly), 0, _batchData, Operation.DelegateCall);
        assertEq(protocol.calls(), 0);
        assertEq(_nonce(), _n);
        vm.warp(_d);
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _batchData, Operation.DelegateCall));
        assertEq(protocol.lastAmount(), 5);
    }

    function test_T6d_value_to_the_helper_is_refused_by_the_guard_then_by_the_helper() public {
        uint256 _d = block.timestamp + 600;
        bytes memory _call = abi.encodeCall(SettlementDeadline.assertBefore, (_d));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ValueNotAllowed.selector, address(deadline), SettlementDeadline.assertBefore.selector));
        _execSafeTx(address(deadline), 1, _call, Operation.Call);
        // an author who sets allowValue on it: the helper is non-payable, the call fails, GS013, nonce kept
        vm.prank(vetro);
        guard.allowFunction(address(safe), address(deadline), SettlementDeadline.assertBefore.selector, true, _noRules());
        uint256 _n = _nonce();
        vm.expectRevert("GS013");
        _execSafeTx(address(deadline), 1, _call, Operation.Call);
        assertEq(_nonce(), _n);
        // as a batch entry with value: MultiSendCallOnly reverts the whole batch
        vm.expectRevert("GS013");
        _execSafeTx(address(multiSendCallOnly), 0, _batch(_entry(address(deadline), 1, _call), _entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (5)))), Operation.DelegateCall);
    }

    /// @dev Approved as a DELEGATECALL (admin): runs in the Safe's context, same clock, same verdict; a
    ///      stale one reverts and the approval is kept (the whole transaction reverts).
    function test_T6e_under_an_approved_delegatecall() public {
        uint256 _d = block.timestamp + 600;
        bytes memory _call = abi.encodeCall(SettlementDeadline.assertBefore, (_d));
        bytes32 _id = _approve(address(deadline), 0, _call, Operation.DelegateCall);
        vm.warp(_d + 1);
        vm.expectRevert("GS013");
        _execSafeTx(address(deadline), 0, _call, Operation.DelegateCall);
        assertGt(guard.approvalExpiry(_id), 0, "approval kept");
        vm.warp(_d);
        vm.recordLogs();
        assertTrue(_execSafeTx(address(deadline), 0, _call, Operation.DelegateCall));
        (, Vm.Log memory _report) = _countTopic(vm.getRecordedLogs(), address(guard), TRANSACTION_CHECKED);
        assertEq(uint256(_report.topics[3]), uint256(CuratorGuard.Outcome.Approval));
        assertEq(guard.approvalExpiry(_id), 0);
    }

    function test_T6f_under_a_council_window_batch_entry() public {
        uint256 _d = block.timestamp + 600;
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        bytes memory _batchData = _batch(
            _entry(address(deadline), 0, abi.encodeCall(SettlementDeadline.assertBefore, (_d))),
            _entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (9)))
        );
        vm.warp(_d + 1);
        vm.expectRevert("GS013");
        _execSafeTx(address(multiSendCallOnly), 0, _batchData, Operation.DelegateCall);
        vm.warp(_d);
        vm.recordLogs();
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _batchData, Operation.DelegateCall));
        (, Vm.Log memory _report) = _countTopic(vm.getRecordedLogs(), address(guard), TRANSACTION_CHECKED);
        assertEq(uint256(_report.topics[3]), uint256(CuratorGuard.Outcome.Bypass));
    }

    /// @dev The helper takes any deadline: `type(uint256).max` never expires (the signers' footgun, not the
    ///      guard's; the policy has no rule on the word, by design).
    function test_T6g_a_far_deadline_never_expires() public {
        vm.warp(block.timestamp + 365 days * 100);
        assertTrue(_execSafeTx(address(deadline), 0, abi.encodeCall(SettlementDeadline.assertBefore, (type(uint256).max)), Operation.Call));
    }

    /*//////////////////////////////////////////////////////////////
                        T7: THE TWO uint32 COUNTERS AT 2^32
    //////////////////////////////////////////////////////////////*/

    /// @dev Both counters are checked arithmetic: at `type(uint32).max` the next bump is `Panic(0x11)`,
    ///      which fails closed (the epoch bump takes `revokeAllApprovals`, `lockdownAndRevoke` and `bypass`
    ///      with it; the generation bump takes `revokeFunction` and `revokeTarget`); `lockdown`, `enforce`,
    ///      `revokeApproval` and the hooks are untouched. 2^32 bumps are 4.3 billion governance transactions.
    function test_T7_counters_at_uint32_max_panic_and_fail_closed() public {
        // epoch: mapping(address => uint32) at slot 8
        bytes32 _epochSlot = keccak256(abi.encode(address(safe), uint256(8)));
        vm.store(address(guard), _epochSlot, bytes32(uint256(type(uint32).max)));
        assertEq(guard.approvalEpoch(address(safe)), type(uint32).max);
        vm.prank(vetro);
        vm.expectRevert(stdError.arithmeticError);
        guard.revokeAllApprovals(address(safe));
        vm.prank(vetro);
        vm.expectRevert(stdError.arithmeticError);
        guard.bypass(address(safe), 1 hours);
        vm.prank(council);
        vm.expectRevert(stdError.arithmeticError);
        guard.lockdownAndRevoke(address(safe));
        vm.prank(council);
        guard.lockdown(address(safe)); // still works
        vm.prank(council);
        guard.enforce(address(safe));
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call));

        // generation: find the FunctionPermission record by recording a revocation, cross-check the formula
        vm.record();
        vm.prank(vetro);
        guard.revokeFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector);
        (, bytes32[] memory _writes) = vm.accesses(address(guard));
        bytes32 _record;
        for (uint256 i; i < _writes.length; ++i) {
            if (vm.load(address(guard), _writes[i]) == bytes32(uint256(1) << 16)) _record = _writes[i];
        }
        bytes32 _policy = keccak256(abi.encode(address(safe), uint256(3)));
        bytes32 _byTarget = keccak256(abi.encode(address(protocol), uint256(_policy) + 5));
        assertEq(_record, keccak256(abi.encode(bytes32(MockProtocol.settleDeposit.selector), _byTarget)), "generation lives at functions[target][selector] slot 0, byte 2");
        vm.store(address(guard), _record, bytes32(uint256(type(uint32).max) << 16));
        _allow(address(protocol), MockProtocol.settleDeposit.selector); // re-allow keeps the generation
        vm.prank(vetro);
        vm.expectRevert(stdError.arithmeticError);
        guard.revokeFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector);
        vm.prank(vetro);
        vm.expectRevert(stdError.arithmeticError);
        guard.revokeTarget(address(safe), address(protocol));
        vm.prank(council);
        guard.lockdown(address(safe)); // the incident primitive is unaffected
    }

    /*//////////////////////////////////////////////////////////////
                         T8: FALLBACK AND RECEIVE SURFACE
    //////////////////////////////////////////////////////////////*/

    function test_T8_no_fallback_no_receive_on_the_guard_and_the_helper_the_timelock_takes_ether() public {
        (bool _ok, ) = address(guard).call{value: 1}("");
        assertFalse(_ok, "guard: no receive");
        (_ok, ) = address(guard).call(hex"deadbeef");
        assertFalse(_ok, "guard: no fallback");
        (_ok, ) = address(guard).call{value: 1}(abi.encodeCall(guard.mode, (address(safe))));
        assertFalse(_ok, "guard: views are non-payable");
        (_ok, ) = address(deadline).call{value: 1}("");
        assertFalse(_ok, "helper: no receive");
        (_ok, ) = address(deadline).call(hex"deadbeef");
        assertFalse(_ok, "helper: no fallback");
        address[] memory _p = new address[](1);
        _p[0] = makeAddr("proposer");
        address[] memory _c = new address[](1);
        _c[0] = makeAddr("canceller");
        CuratorGuardTimelock _tl = new CuratorGuardTimelock(1 days, _p, _c);
        (_ok, ) = address(_tl).call{value: 1 ether}("");
        assertTrue(_ok, "timelock: OpenZeppelin receive()");
        (_ok, ) = address(_tl).call(hex"deadbeef");
        assertFalse(_ok, "timelock: no fallback");
        assertEq(address(_tl).balance, 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                              T9: CONSTRUCTORS
    //////////////////////////////////////////////////////////////*/

    function test_T9_constructor_edges() public {
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, vetro));
        new CuratorGuard(1 days, vetro, vetro);
        vm.expectRevert(abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlInvalidDefaultAdmin.selector, address(0)));
        new CuratorGuard(1 days, address(0), council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminDelayTooLong.selector, uint48(30 days + 1)));
        new CuratorGuard(30 days + 1, vetro, council);
        CuratorGuard _g = new CuratorGuard(30 days, vetro, address(0)); // no council, the cap
        assertEq(_g.defaultAdminDelay(), 30 days);
        assertFalse(_g.hasRole(_g.COUNCIL_ROLE(), council));
        _g = new CuratorGuard(0, vetro, council); // 0 is accepted by the constructor (the floor is on changes only)
        assertEq(_g.defaultAdminDelay(), 0);
        assertTrue(_g.supportsInterface(0xe6d7a83a) && _g.supportsInterface(0x58401ed8) && _g.supportsInterface(0x01ffc9a7));
        assertFalse(_g.supportsInterface(0xffffffff));

        // timelock: duplicates count once, a canceller that proposes is refused, the floors and caps
        address _p1 = makeAddr("p1");
        address _c1 = makeAddr("c1");
        address[] memory _p = new address[](2);
        _p[0] = _p1;
        _p[1] = _p1;
        address[] memory _c = new address[](2);
        _c[0] = _c1;
        _c[1] = _c1;
        CuratorGuardTimelock _tl = new CuratorGuardTimelock(1 days, _p, _c);
        assertEq(_tl.proposerCount(), 1);
        assertEq(_tl.cancellerCount(), 1);
        assertFalse(_tl.hasRole(_tl.CANCELLER_ROLE(), _p1));
        assertTrue(_tl.hasRole(_tl.EXECUTOR_ROLE(), address(0)));
        assertTrue(_tl.hasRole(_tl.DEFAULT_ADMIN_ROLE(), address(_tl)));
        _c[1] = _p1;
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.CancellerCannotPropose.selector, _p1));
        new CuratorGuardTimelock(1 days, _p, _c);
        _c[1] = _c1;
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, 1 days - 1));
        new CuratorGuardTimelock(1 days - 1, _p, _c);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, 30 days + 1));
        new CuratorGuardTimelock(30 days + 1, _p, _c);
        _c[0] = address(0);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.ZeroAddressHolder.selector, _tl.CANCELLER_ROLE()));
        new CuratorGuardTimelock(1 days, _p, _c);
    }

    /*//////////////////////////////////////////////////////////////
                  T10: ACCESS-CONTROL-DEFAULT-ADMIN-RULES EDGES
    //////////////////////////////////////////////////////////////*/

    function test_T10_admin_rules_edges() public {
        bytes32 _adminRole = guard.DEFAULT_ADMIN_ROLE();
        // the admin cannot renounce: the library needs a pending transfer to address(0), which the guard refuses
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminDelay.selector, uint48(0)));
        guard.renounceRole(_adminRole, vetro);
        vm.prank(vetro);
        vm.expectRevert(CuratorGuardPolicy.AdminCannotBeZero.selector);
        guard.beginDefaultAdminTransfer(address(0));
        // no second admin, ever
        address _next = makeAddr("next");
        vm.prank(vetro);
        vm.expectRevert(IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminRules.selector);
        guard.grantRole(_adminRole, _next);
        // not to itself, not to the council, not to a guarded Safe
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, vetro));
        guard.beginDefaultAdminTransfer(vetro);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, council));
        guard.beginDefaultAdminTransfer(council);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, address(safe)));
        guard.beginDefaultAdminTransfer(address(safe));
        // the pending admin cannot cancel, only the admin can; the pending admin cannot accept before the schedule
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(_next);
        (address _pending, uint48 _schedule) = guard.pendingDefaultAdmin();
        assertEq(_pending, _next);
        vm.prank(_next);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, _next, _adminRole));
        guard.cancelDefaultAdminTransfer();
        vm.prank(_next);
        vm.expectRevert(abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminDelay.selector, _schedule));
        guard.acceptDefaultAdminTransfer();
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlInvalidDefaultAdmin.selector, attacker));
        guard.acceptDefaultAdminTransfer();
        // delay change: bounds both ways, pending, rollback
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminDelayTooLong.selector, uint48(1 days - 1)));
        guard.changeDefaultAdminDelay(1 days - 1);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminDelayTooLong.selector, uint48(30 days + 1)));
        guard.changeDefaultAdminDelay(30 days + 1);
        vm.prank(vetro);
        guard.changeDefaultAdminDelay(2 days);
        (uint48 _newDelay, uint48 _effect) = guard.pendingDefaultAdminDelay();
        assertEq(_newDelay, 2 days);
        assertEq(_effect, block.timestamp + 2 days); // an increase waits min(newDelay, 5 days)
        vm.prank(vetro);
        guard.rollbackDefaultAdminDelay();
        (, _effect) = guard.pendingDefaultAdminDelay();
        assertEq(_effect, 0);
        // the hand-over completes after the schedule and the old admin is out
        vm.warp(block.timestamp + 1);
        vm.prank(_next);
        guard.acceptDefaultAdminTransfer();
        assertEq(guard.defaultAdmin(), _next);
        assertFalse(guard.hasRole(_adminRole, vetro));
        vm.prank(vetro);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.allowFunction(address(safe), address(protocol), MockProtocol.deposit.selector, false, _noRules());
    }

    /*//////////////////////////////////////////////////////////////
                             T11: THE YEAR 2106
    //////////////////////////////////////////////////////////////*/

    function test_T11_everything_works_past_2_pow_32_seconds() public {
        vm.warp(uint256(type(uint32).max) + 10);
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call));
        vm.prank(council);
        guard.lockdown(address(safe));
        assertEq(guard.lockedAt(address(safe)), uint64(block.timestamp));
        // the admin's cooldown is inclusive out here too
        vm.warp(block.timestamp + 1 days);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(safe)));
        guard.enforce(address(safe));
        vm.warp(block.timestamp + 1);
        vm.prank(vetro);
        guard.enforce(address(safe));
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        (uint64 _until, bool _council) = guard.bypassWindow(address(safe));
        assertEq(_until, uint64(block.timestamp + 1 hours));
        assertTrue(_council);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Bypass));
        vm.warp(block.timestamp + 1 hours);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        bytes32 _id = _councilApprove(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (2)), Operation.Call);
        assertEq(guard.approvalExpiry(_id), uint64(block.timestamp + 1 days));
        vm.warp(block.timestamp + 1 days);
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (2)), Operation.Call));
        vm.warp(block.timestamp + 1);
        assertEq(guard.approvalExpiry(_id), 0);
    }

    /*//////////////////////////////////////////////////////////////
                   T12: EVENTS AFTER A FAILED POLICY EXECUTION
    //////////////////////////////////////////////////////////////*/

    function test_T12_failed_policy_execution_reports_policy_next_to_the_safes_ExecutionFailure() public {
        _allow(address(reverter), bytes4(hex"12345678"));
        uint256 _n = _nonce();
        vm.recordLogs();
        assertFalse(_execSafeTxWithGas(address(reverter), 0, hex"12345678", Operation.Call, 100_000));
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        (uint256 _f, Vm.Log memory _failure) = _countTopic(_logs, address(safe), EXECUTION_FAILURE);
        (uint256 _s, ) = _countTopic(_logs, address(safe), EXECUTION_SUCCESS);
        (uint256 _r, Vm.Log memory _report) = _countTopic(_logs, address(guard), TRANSACTION_CHECKED);
        assertEq(_f, 1);
        assertEq(_s, 0);
        assertEq(_r, 1);
        assertEq(uint256(_report.topics[3]), uint256(CuratorGuard.Outcome.Policy));
        // the report's txHash is the Safe's own (the event's indexed hash) and the nonce moved
        assertEq(_report.topics[2], _failure.topics.length > 1 ? _failure.topics[1] : bytes32(0));
        assertEq(_nonce(), _n + 1);
        // with safeTxGas == 0 the same failure is GS013 and nothing is reported
        vm.recordLogs();
        vm.expectRevert("GS013");
        _execSafeTx(address(reverter), 0, hex"12345678", Operation.Call);
        (_r, ) = _countTopic(vm.getRecordedLogs(), address(guard), TRANSACTION_CHECKED);
        assertEq(_r, 0);
    }

    /*//////////////////////////////////////////////////////////////
                  T13: HOOK GAS AGAINST THE OWNER COUNT (v1.4.1)
    //////////////////////////////////////////////////////////////*/

    /// @dev The two hooks read `getOwners()` twice (the second read is warm): the cost is linear in the owner
    ///      count and stays far below a block at several hundred owners, which only the admin's approvals
    ///      (or the council, one plain key at a time) can create.
    function test_T13_hook_gas_at_hundreds_of_owners() public {
        uint256[3] memory _counts = [uint256(1), 100, 400];
        uint256 _previous;
        for (uint256 i; i < _counts.length; ++i) {
            ISafe _s = _freshSafe(_counts[i]);
            vm.prank(vetro);
            guard.enforce(address(_s));
            vm.prank(vetro);
            guard.allowFunction(address(_s), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules());
            ISafe _saved = safe;
            safe = _s;
            _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call); // warm the policy slots
            uint256 _g = gasleft();
            _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
            _g -= gasleft();
            safe = _saved;
            emit log_named_uint(string.concat("execTransaction, guarded, owners=", vm.toString(_counts[i])), _g);
            if (i > 0) emit log_named_uint("  per extra owner", (_g - _previous) / (_counts[i] - _counts[i - 1]));
            _previous = _g;
            assertLt(_g, 10_000_000);
        }
    }

    function _freshSafe(uint256 owners_) internal returns (ISafe _s) {
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        address[] memory _owners = new address[](owners_);
        _owners[0] = curator;
        for (uint256 i = 1; i < owners_; ++i) _owners[i] = makeAddr(string.concat("o", vm.toString(owners_), "-", vm.toString(i)));
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        _s = ISafe(address(_proxy));
        CuratorGuardHarness(address(guard)).seedSafe(address(_s));
        ISafe _saved = safe;
        safe = _s;
        _execSafeTx(address(_s), 0, abi.encodeCall(ISafe.setGuard, (address(guard))), Operation.Call);
        safe = _saved;
    }
}
