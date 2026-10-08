// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";
import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @dev A one-off migration library WITHOUT an event: writes the Safe's singleton slot (slot 0) when
///      delegatecalled. Models an approved delegatecall into non-canonical code (docs 7.5 approves
///      only the canonical `SafeMigration`, which emits `ChangedMasterCopy`; nothing on-chain forces it).
contract RawSingletonWriter {
    function migrate(address singleton_) external {
        assembly {
            sstore(0, singleton_)
        }
    }
}

interface IForwarded {
    function executeBefore(uint64 deadline_, bytes calldata call_) external returns (bytes memory);
}

/// @title G10e: the monitoring claims of docs section 7.7 pinned against the code (round 10, lens
///        incident response and monitoring). Evidence tests: each pins a sentence an alerting rule
///        or an operator depends on.
contract G10e_MonitoringTest is CuratorGuardTestBase {
    bytes32 internal constant TX_CHECKED = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");
    bytes32 internal constant EXEC_SUCCESS = keccak256("ExecutionSuccess(bytes32,uint256)");
    bytes32 internal constant APPROVAL_CONSUMED = keccak256("ApprovalConsumed(address,bytes32,address)");
    bytes32 internal constant MODE_UPDATED = keccak256("ModeUpdated(address,uint8,uint64,bool)");
    bytes32 internal constant APPROVALS_REVOKED = keccak256("ApprovalsRevoked(address,uint32)");
    bytes32 internal constant APPROVAL_REVOKED = keccak256("ApprovalRevoked(address,bytes32)");
    bytes32 internal constant CHANGED_MASTER_COPY = keccak256("ChangedMasterCopy(address)");

    function setUp() public override {
        super.setUp();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        _enforce();
    }

    function _settle() internal returns (bytes memory) {
        return abi.encodeCall(MockProtocol.settleDeposit, (1));
    }

    function _logsOf(address emitter_, bytes32 sig_, Vm.Log[] memory logs_) internal pure returns (uint256 _n) {
        for (uint256 i; i < logs_.length; ++i) if (logs_[i].emitter == emitter_ && logs_[i].topics[0] == sig_) ++_n;
    }

    /// 7.7: "on the owner path the report is the log immediately AFTER the Safe's ExecutionSuccess of the
    /// same hash" and "exactly one per Safe transaction that passed both hooks".
    function test_policy_report_is_the_log_right_after_ExecutionSuccess_and_there_is_exactly_one() public {
        vm.recordLogs();
        assertTrue(_execSafeTx(address(protocol), 0, _settle(), Operation.Call));
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_logsOf(address(guard), TX_CHECKED, _logs), 1, "one report");
        uint256 _last = _logs.length - 1;
        assertEq(_logs[_last].emitter, address(guard));
        assertEq(_logs[_last].topics[0], TX_CHECKED);
        assertEq(uint256(_logs[_last].topics[3]), uint256(CuratorGuard.Outcome.Policy), "outcome topic");
        assertEq(_logs[_last - 1].emitter, address(safe));
        assertEq(_logs[_last - 1].topics[0], EXEC_SUCCESS, "ExecutionSuccess right before the report");
        assertEq(_logs[_last - 1].topics[1], _logs[_last].topics[2], "same safeTxHash");
    }

    /// 7.7: "treat an Approval outcome as the consumption of the matching ApprovalConsumed": the
    /// consumption is logged BEFORE the inner call runs, the report after `ExecutionSuccess`.
    function test_approval_path_logs_ApprovalConsumed_first_and_the_Approval_report_last() public {
        bytes memory _data = abi.encodeWithSignature("setFallbackHandler(address)", address(0));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(safe), 0, _data, Operation.Call, 1 days);
        vm.recordLogs();
        assertTrue(_execSafeTx(address(safe), 0, _data, Operation.Call));
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_logs[0].emitter, address(guard));
        assertEq(_logs[0].topics[0], APPROVAL_CONSUMED, "consumption first");
        uint256 _last = _logs.length - 1;
        assertEq(_logs[_last].topics[0], TX_CHECKED);
        assertEq(uint256(_logs[_last].topics[3]), uint256(CuratorGuard.Outcome.Approval));
        assertEq(_logs[_last - 1].topics[0], EXEC_SUCCESS);
    }

    /// 7.7: "ModeUpdated ... may repeat the current mode, and its order relative to ApprovalsRevoked
    /// differs between bypass and lockdownAndRevoke".
    function test_ModeUpdated_repeats_and_its_order_against_ApprovalsRevoked_differs_per_call() public {
        vm.recordLogs();
        _enforce(); // already Enforced
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_logs.length, 1);
        assertEq(_logs[0].topics[0], MODE_UPDATED, "a repeat still logs");
        assertEq(uint256(_logs[0].topics[2]), uint256(CuratorGuardPolicy.Mode.Enforced));

        vm.recordLogs();
        _bypass(1 hours);
        _logs = vm.getRecordedLogs();
        assertEq(_logs[0].topics[0], APPROVALS_REVOKED, "bypass: ApprovalsRevoked first");
        assertEq(_logs[1].topics[0], MODE_UPDATED);

        vm.recordLogs();
        vm.prank(vetro);
        guard.lockdownAndRevoke(address(safe));
        _logs = vm.getRecordedLogs();
        assertEq(_logs[0].topics[0], MODE_UPDATED, "lockdownAndRevoke: ModeUpdated first");
        assertEq(_logs[1].topics[0], APPROVALS_REVOKED);
    }

    /// 7.7: "ApprovalRevoked (it may name a record that was already void or expired)".
    function test_ApprovalRevoked_names_an_expired_record() public {
        bytes memory _data = abi.encodeWithSignature("setFallbackHandler(address)", address(0));
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(safe), 0, _data, Operation.Call, 1 hours);
        vm.warp(block.timestamp + 2 hours);
        assertLt(guard.approvalExpiry(_id), block.timestamp, "expired: the view reports the past expiry, the caller compares");
        vm.recordLogs();
        vm.prank(vetro);
        guard.revokeApproval(_id);
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_logs.length, 1);
        assertEq(_logs[0].topics[0], APPROVAL_REVOKED);
    }

    /// Monitoring gap (G10e-2): an approved delegatecall into a non-canonical library rewrites the
    /// singleton with NO `ChangedMasterCopy` (only the canonical `SafeMigration` emits it); when the
    /// new singleton is a pinned build the policy path simply continues. Only `masterCopy()` tells.
    function test_raw_singleton_rewrite_emits_no_ChangedMasterCopy_and_the_policy_continues() public {
        Safe _other = new Safe(); // same code as the harness singleton: a pinned build
        RawSingletonWriter _lib = new RawSingletonWriter();
        bytes memory _data = abi.encodeCall(RawSingletonWriter.migrate, (address(_other)));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(_lib), 0, _data, Operation.DelegateCall, 1 days);
        address _before = address(uint160(uint256(vm.load(address(safe), bytes32(0)))));
        vm.recordLogs();
        assertTrue(_execSafeTx(address(_lib), 0, _data, Operation.DelegateCall));
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_logsOf(address(safe), CHANGED_MASTER_COPY, _logs), 0, "no ChangedMasterCopy");
        address _after = address(uint160(uint256(vm.load(address(safe), bytes32(0)))));
        assertEq(_after, address(_other), "singleton moved");
        assertTrue(_after != _before);
        // The next policy transaction passes: a monitor keyed on events never learns the release changed.
        vm.recordLogs();
        assertTrue(_execSafeTx(address(protocol), 0, _settle(), Operation.Call));
        _logs = vm.getRecordedLogs();
        assertEq(_logsOf(address(guard), TX_CHECKED, _logs), 1);
    }

    /// G9a-1 second opinion: a report forged through a Safe whose fallback handler is the guard has NO
    /// `ExecutionSuccess` in its transaction, so the 7.7 adjacency join rejects it; only a monitor that
    /// counts `TransactionChecked` alone is fooled. Pins the HELD defect G9a-1 as current behaviour
    /// (`executeBefore` re-dispatches a forwarded call): once that fix lands the forged call reverts
    /// and this test must flip to expect it (docs section 10, review G11d-3).
    function test_forged_report_through_executeBefore_has_no_ExecutionSuccess_beside_it() public {
        vm.prank(address(safe));
        (bool _ok, ) = address(safe).call(abi.encodeWithSignature("setFallbackHandler(address)", address(guard))); // the state 7.3 forbids
        assertTrue(_ok);
        _bypass(1 hours);
        bytes memory _inner = abi.encodeWithSelector(CuratorGuard.checkAfterExecution.selector, keccak256("forged"), true);
        vm.recordLogs();
        vm.prank(attacker);
        IForwarded(address(safe)).executeBefore(uint64(block.timestamp + 1 hours), _inner);
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_logs.length, 1, "exactly the forged report");
        assertEq(_logs[0].emitter, address(guard));
        assertEq(_logs[0].topics[0], TX_CHECKED);
        assertEq(uint256(_logs[0].topics[3]), uint256(CuratorGuard.Outcome.Bypass));
        assertEq(_logsOf(address(safe), EXEC_SUCCESS, _logs), 0, "orphan: no ExecutionSuccess to join");
    }

    /// 7.7 says a refused transaction "leaves no event"; the receipt of the signers' attempt is still a
    /// signal: `execTransaction` reverts with the guard's error, visible to a receipt-keyed monitor.
    function test_a_refused_transaction_reverts_execTransaction_with_the_guard_error_and_no_log() public {
        bytes memory _data = abi.encodeCall(MockProtocol.deposit, (1, attacker));
        vm.recordLogs();
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector)
        );
        _execSafeTx(address(protocol), 0, _data, Operation.Call);
        assertEq(vm.getRecordedLogs().length, 0, "nothing logged");
    }
}
