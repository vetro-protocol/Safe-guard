// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol, MaliciousMultiSend, Reverter} from "test/guards/CuratorGuardTestBase.sol";

/// @dev Reverts while armed, succeeds otherwise.
contract Flaky {
    bool public armed = true;
    uint256 public calls;

    function disarm() external {
        armed = false;
    }

    fallback() external payable {
        if (armed) revert("armed");
        ++calls;
    }
}

/// @dev Executes an arbitrary pre-encoded call (used to nest `execTransaction` of the same Safe).
contract Nester {
    bytes public lastError;

    function run(address target_, bytes calldata call_) external returns (bool ok) {
        bytes memory _ret;
        (ok, _ret) = target_.call(call_);
        if (!ok) lastError = _ret;
    }
}

/// @dev Allowlisted venue that re-enters the guard hooks while the Safe transaction is in flight.
contract ReentrantVenue {
    CuratorGuard public guard;
    address public safe;
    bytes public lastPreRevert;
    bytes public lastPostRevert;
    uint256 public calls;

    constructor(CuratorGuard guard_, address safe_) {
        guard = guard_;
        safe = safe_;
    }

    function poke(uint256) external {
        ++calls;
        // 1. Pre-hook as a stranger: must not touch any policy / approval of the real Safe.
        try
            guard.checkTransaction(
                address(this), 0, "", Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(this)
            )
        {} catch (bytes memory reason) {
            lastPreRevert = reason;
        }
        // 2. Post-hook as a stranger with success == false: must not restore anything.
        try guard.checkAfterExecution(bytes32(0), false) {} catch (bytes memory reason) {
            lastPostRevert = reason;
        }
    }
}

/// @dev A singleton that forwards everything to the genuine Safe singleton but lies in
///      `getStorageAt` about slot 0 (reports `pretend`), i.e. what a swapped implementation could
///      do to fool a digest that trusts the Safe's own views.
contract LyingSingleton {
    address public immutable real;
    address public immutable pretend;

    constructor(address real_, address pretend_) {
        real = real_;
        pretend = pretend_;
    }

    function getStorageAt(uint256 offset_, uint256 length_) external view returns (bytes memory _result) {
        _result = new bytes(length_ * 32);
        for (uint256 i; i < length_; ++i) {
            bytes32 _word;
            uint256 _slot = offset_ + i;
            assembly {
                _word := sload(_slot)
            }
            if (_slot == 0) _word = bytes32(uint256(uint160(pretend)));
            assembly {
                mstore(add(add(_result, 0x20), mul(i, 0x20)), _word)
            }
        }
    }

    fallback() external payable {
        address _real = real;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let _ok := delegatecall(gas(), _real, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(_ok) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
    }

    receive() external payable {}
}

/// @dev Writes two slots: enough to splice the owner linked list consistently.
contract MaliciousMultiSend2 {
    bytes32 internal immutable slotA;
    bytes32 internal immutable valueA;
    bytes32 internal immutable slotB;
    bytes32 internal immutable valueB;

    constructor(bytes32 slotA_, bytes32 valueA_, bytes32 slotB_, bytes32 valueB_) {
        slotA = slotA_;
        valueA = valueA_;
        slotB = slotB_;
        valueB = valueB_;
    }

    function multiSend(bytes memory) external payable {
        bytes32 _sa = slotA;
        bytes32 _va = valueA;
        bytes32 _sb = slotB;
        bytes32 _vb = valueB;
        assembly {
            sstore(_sa, _va)
            sstore(_sb, _vb)
        }
    }
}

/// @title Round-2 regressions: approval lifecycle, access control on every entry point, policy
///        bookkeeping, hook re-entrancy, two guarded Safes, and the configuration snapshot per slot.
contract CuratorGuardRound2Test is CuratorGuardTestBase {
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;
    bytes4 internal constant DEPOSIT = MockProtocol.deposit.selector;
    bytes4 internal constant APPROVE = IERC20.approve.selector;
    bytes4 internal constant TRANSFER = IERC20.transfer.selector;


    /*//////////////////////////////////////////////////////////////
            P01/P02: approvals must bind the EXACT calldata
    //////////////////////////////////////////////////////////////*/

    function test_approval_does_not_authorise_a_different_selector_on_the_same_target() public {
        _approve(address(token), 0, abi.encodeCall(IERC20.approve, (address(protocol), 1)), Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(token), 0, abi.encodeCall(IERC20.transfer, (attacker, 1_000_000e6)), Operation.Call);
        assertEq(token.balanceOf(attacker), 0);
    }

    function test_approval_does_not_authorise_different_arguments_for_the_same_selector() public {
        _approve(address(token), 0, abi.encodeCall(IERC20.transfer, (address(protocol), 1)), Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(token), 0, abi.encodeCall(IERC20.transfer, (attacker, 1)), Operation.Call);
        // Appended bytes are a different payload too.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(
            address(token),
            0,
            abi.encodePacked(abi.encodeCall(IERC20.transfer, (address(protocol), 1)), uint8(0)),
            Operation.Call
        );
    }

    /*//////////////////////////////////////////////////////////////
                G13: expiry boundary (valid AT expiry)
    //////////////////////////////////////////////////////////////*/

    function test_approval_is_valid_at_exactly_its_expiry() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, uint64(1 hours));
        uint64 _expiry = guard.approvalExpiry(_id);
        vm.warp(_expiry); // the expiry second itself is valid, on the dry run AND the live hook
        guard.validateTransaction(address(safe), address(protocol), 0, _data, Operation.Call);
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call));
        assertEq(guard.approvalExpiry(_id), 0, "consumed");
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, uint64(1 hours));
        vm.warp(block.timestamp + 1 hours + 1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        guard.validateTransaction(address(safe), address(protocol), 0, _data, Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
          G07: restored approval keeps its ORIGINAL expiry; retry
    //////////////////////////////////////////////////////////////*/

    /// @dev A failed approved attempt never costs the approval: with `safeTxGas != 0` the Safe reports
    ///      the failure and the post-hook reverts the whole transaction (`ApprovedExecutionFailed`),
    ///      with `safeTxGas == 0` the Safe reverts it itself (GS013). The retry after the callee is
    ///      fixed consumes it exactly once.
    function test_failed_approved_attempt_keeps_the_approval_until_a_successful_retry() public {
        Flaky _flaky = new Flaky();
        bytes memory _data = hex"deadbeef";
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(_flaky), 0, _data, Operation.Call, uint64(1 days));
        uint64 _expiry = guard.approvalExpiry(_id);

        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ApprovedExecutionFailed.selector, address(safe)));
        _execSafeTxWithGas(address(_flaky), 0, _data, Operation.Call, 100_000);
        vm.expectRevert(bytes("GS013"));
        _execSafeTx(address(_flaky), 0, _data, Operation.Call);
        assertEq(guard.approvalExpiry(_id), _expiry, "untouched, original expiry");
        assertEq(_flaky.calls(), 0);

        _flaky.disarm();
        assertTrue(_execSafeTx(address(_flaky), 0, _data, Operation.Call), "retry succeeds");
        assertEq(guard.approvalExpiry(_id), 0, "consumed on the successful retry");
        assertEq(_flaky.calls(), 1);

        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(_flaky), 0, _data, Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
       G06: the in-flight marker must be cleared after an approved tx
    //////////////////////////////////////////////////////////////*/

    /// @dev Same transaction (one test = one tx, transient storage persists): an approved execution
    ///      followed by a policy execution. The policy execution must still get its post-check
    ///      (G06 would skip it) and a failing policy execution must not resurrect the approval.
    function test_post_check_still_runs_after_an_approved_execution_in_the_same_transaction() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        bytes memory _approvedData = abi.encodeCall(MockProtocol.settleDeposit, (1));
        bytes32 _id = _approve(address(protocol), 0, _approvedData, Operation.Call);
        assertTrue(_execSafeTx(address(protocol), 0, _approvedData, Operation.Call));
        assertEq(guard.approvalExpiry(_id), 0, "consumed");

        // 1. A failing policy tx must NOT restore the consumed approval.
        Reverter _reverter = new Reverter();
        _allow(address(_reverter), bytes4(hex"deadbeef"));
        assertFalse(_execSafeTxWithGas(address(_reverter), 0, hex"deadbeef", Operation.Call, 100_000));
        assertEq(guard.approvalExpiry(_id), 0, "a later failed policy tx must not resurrect the approval");

        // 2. A policy tx that rewrites the guard slot must still be caught by the post-check.
        MaliciousMultiSend _evil = new MaliciousMultiSend(GUARD_SLOT, bytes32(0));
        _registerUnwrapper(address(_evil));
        bytes memory _batch = _multiSendCalldata(_entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (7))));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(safe)));
        _execSafeTx(address(_evil), 0, _batch, Operation.DelegateCall);
        assertEq(_installedGuard(), address(guard));
    }

    /*//////////////////////////////////////////////////////////////
              Bypass + in-flight approval + success == false
    //////////////////////////////////////////////////////////////*/

    function test_bypass_skips_the_refund_check_and_every_other_check() public {
        vm.prank(vetro);
        guard.bypass(address(safe), 1 days);
        Reverter _reverter = new Reverter();
        // A failing call with safeTxGas != 0 is simply reported as failed: nothing is recorded in Bypass.
        assertFalse(_execSafeTxWithGas(address(_reverter), 0, hex"deadbeef", Operation.Call, 100_000));
        // Bypass also lets a non-zero gasPrice through (the refund check is skipped in Bypass).
        uint256 _before = attacker.balance;
        vm.txGasPrice(1); // handlePayment pays min(gasPrice, tx.gasprice)
        assertTrue(
            _execSafeTxParams(
                SafeTx(address(token), 0, abi.encodeCall(IERC20.transfer, (attacker, 1)), Operation.Call, 200_000, 1, address(0), attacker)
            )
        );
        assertGt(attacker.balance, _before, "refund paid in Bypass");
    }

    /*//////////////////////////////////////////////////////////////
         revokeAllApprovals after a restoration: restored id is dead
    //////////////////////////////////////////////////////////////*/

    function test_stale_approval_record_reads_dead_after_revokeAllApprovals_and_can_be_cleaned() public {
        Reverter _reverter = new Reverter();
        bytes32 _id = _approve(address(_reverter), 0, hex"deadbeef", Operation.Call);
        assertGt(guard.approvalExpiry(_id), 0);
        vm.prank(vetro);
        guard.setGuardian(address(safe), guardian, true);
        vm.prank(guardian);
        guard.revokeAllApprovals(address(safe));
        // The entry is a dangling record under the old epoch: reported dead, never matched.
        assertEq(guard.approvalExpiry(_id), 0, "stale record reads as dead");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(_reverter), 0, hex"deadbeef", Operation.Call);
        // It can still be cleaned up by hand (by a guardian of its Safe).
        vm.prank(guardian);
        guard.revokeApproval(_id);
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ApprovalNotFound.selector, _id));
        guard.revokeApproval(_id);
    }

    /*//////////////////////////////////////////////////////////////
       Nested execTransaction of the same Safe inside an approved tx
    //////////////////////////////////////////////////////////////*/

    function _innerExecCalldata(address to_, bytes memory data_, uint256 safeTxGas_, uint256 nonce_) internal view returns (bytes memory) {
        SafeTx memory _t = SafeTx(to_, 0, data_, Operation.Call, safeTxGas_, 0, address(0), address(0));
        bytes32 _domainSeparator = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, address(safe)));
        bytes32 _hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), _domainSeparator, _safeTxHash(_t, nonce_)));
        return
            abi.encodeCall(
                ISafe.execTransaction,
                (to_, 0, data_, Operation.Call, safeTxGas_, 0, 0, address(0), payable(address(0)), _sign(_hash))
            );
    }

    /// @dev Same Safe, same path, nested: the inner pre-check sees the outer in-flight marker and
    ///      rejects (`NestedExecution`). The inner can therefore never restore or hide the outer
    ///      approval; the outer approval is consumed exactly once.
    function test_nested_execTransaction_inside_an_approved_payload_is_rejected() public {
        _enforce();
        Reverter _reverter = new Reverter();
        _allow(address(_reverter), bytes4(hex"deadbeef"));
        _allow(address(protocol), SETTLE);
        Nester _nester = new Nester();
        uint256 _nonce = safe.nonce();
        // Inner: a policy-allowed call that would report success == false (safeTxGas != 0).
        bytes memory _inner = _innerExecCalldata(address(_reverter), hex"deadbeef", 100_000, _nonce + 1);
        bytes memory _outer = abi.encodeCall(Nester.run, (address(safe), _inner));
        bytes32 _id = _approve(address(_nester), 0, _outer, Operation.Call);
        assertTrue(_execSafeTx(address(_nester), 0, _outer, Operation.Call), "outer succeeds (Nester swallows the inner revert)");
        assertEq(_nester.lastError(), abi.encodeWithSelector(CuratorGuard.NestedExecution.selector, address(safe)));
        assertEq(safe.nonce(), _nonce + 1, "inner never ran");
        assertEq(guard.approvalExpiry(_id), 0, "outer approval consumed, not restored");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(_nester), Nester.run.selector));
        _execSafeTx(address(_nester), 0, _outer, Operation.Call);

        // A benign nested policy transaction is rejected the same way (no snapshot smuggling).
        _inner = _innerExecCalldata(address(protocol), abi.encodeCall(MockProtocol.settleDeposit, (11)), 0, _nonce + 2);
        _outer = abi.encodeCall(Nester.run, (address(safe), _inner));
        _approve(address(_nester), 0, _outer, Operation.Call);
        assertTrue(_execSafeTx(address(_nester), 0, _outer, Operation.Call));
        assertEq(_nester.lastError(), abi.encodeWithSelector(CuratorGuard.NestedExecution.selector, address(safe)));
        assertEq(protocol.calls(), 0, "inner never executed");
    }

    /// @dev The snapshot half of the nested check: an outer POLICY transaction (no approval) whose
    ///      allowlisted target nests a same-Safe `execTransaction` is rejected by the snapshot marker.
    function test_nested_execTransaction_inside_a_policy_transaction_is_rejected() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        Nester _nester = new Nester();
        _allow(address(_nester), Nester.run.selector);
        uint256 _nonce = safe.nonce();
        bytes memory _inner = _innerExecCalldata(address(protocol), abi.encodeCall(MockProtocol.settleDeposit, (11)), 0, _nonce + 1);
        assertTrue(_execSafeTx(address(_nester), 0, abi.encodeCall(Nester.run, (address(safe), _inner)), Operation.Call));
        assertEq(_nester.lastError(), abi.encodeWithSelector(CuratorGuard.NestedExecution.selector, address(safe)));
        assertEq(safe.nonce(), _nonce + 1, "inner never ran");
        assertEq(protocol.calls(), 0);
    }

    /// @dev Sequential (not nested) Safe transactions inside one outer transaction are fine: the
    ///      post-check clears the snapshot and in-flight slots.
    function test_sequential_execTransactions_in_one_transaction_are_allowed() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        for (uint256 i = 1; i <= 3; ++i) {
            assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (i)), Operation.Call));
        }
        assertEq(protocol.calls(), 3);
    }


    /*//////////////////////////////////////////////////////////////
                 ACCESS CONTROL: every admin entry point
    //////////////////////////////////////////////////////////////*/

    /// @dev P03/P04: widening entry points not covered by `test_guardian_can_only_narrow`.
    function test_guardian_cannot_widen_via_allowFunctions_or_addAllowedValues() public {
        vm.prank(vetro);
        guard.setGuardian(address(safe), guardian, true);
        CuratorGuardPolicy.FunctionSpec[] memory _specs = new CuratorGuardPolicy.FunctionSpec[](1);
        _specs[0] = CuratorGuardPolicy.FunctionSpec(address(protocol), SETTLE, false, _noRules());
        bytes32[] memory _values = new bytes32[](1);
        _values[0] = _word(attacker);
        _allowWithRules(address(token), APPROVE, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));

        bytes32 _councilRole = guard.COUNCIL_ROLE();
        address[2] memory _callers = [guardian, attacker];
        for (uint256 i; i < 2; ++i) {
            vm.startPrank(_callers[i]);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.allowFunctions(address(safe), _specs);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.addAllowedValues(address(safe), address(token), APPROVE, 0, _values);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.setGuardian(address(safe), guardian, false);
            vm.expectRevert(
                abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, _callers[i], bytes32(0))
            );
            guard.beginDefaultAdminTransfer(_callers[i]);
            vm.expectRevert(
                abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, _callers[i], bytes32(0))
            );
            guard.grantRole(_councilRole, _callers[i]);
            vm.stopPrank();
        }
        assertFalse(_isAllowed(address(safe), address(protocol), SETTLE));
        assertEq(guard.allowedValues(address(safe), address(token), APPROVE, 0).length, 0);
        assertTrue(guard.isGuardian(address(safe), guardian));
    }

    /// @dev P05-P10, P29, P31: narrow-only entry points must still reject strangers.
    function test_strangers_cannot_narrow_either() public {
        _enforce();
        _allowWithRules(address(token), APPROVE, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        bytes32[] memory _values = new bytes32[](1);
        _values[0] = _word(address(protocol));
        _seedCodehash(address(multiSendCallOnly).codehash);
        vm.startPrank(vetro);
        guard.addAllowedValues(address(safe), address(token), APPROVE, 0, _values);
        guard.setMultiSendUnwrapper(address(safe), address(multiSendCallOnly), true);
        guard.setModuleAllowed(address(safe), attacker, true);
        guard.setNativeTransferAllowed(address(safe), address(protocol), true);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(protocol), 0, "", Operation.Call, uint64(1 hours));
        vm.stopPrank();

        vm.startPrank(attacker);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.revokeTarget(address(safe), address(token));
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.removeAllowedValues(address(safe), address(token), APPROVE, 0, _values);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.clearAllowedValues(address(safe), address(token), APPROVE, 0);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.setMultiSendUnwrapper(address(safe), address(multiSendCallOnly), false);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.setUnwrapperCodehash(address(multiSendCallOnly).codehash, false);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.setModuleAllowed(address(safe), attacker, false);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.setNativeTransferAllowed(address(safe), address(protocol), false);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.revokeApproval(_id);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.revokeAllApprovals(address(safe));
        vm.stopPrank();

        assertEq(guard.allowedValues(address(safe), address(token), APPROVE, 0).length, 1);
        assertTrue(_contains(guard.multiSendUnwrappers(address(safe)), address(multiSendCallOnly)));
        assertTrue(_contains(guard.modules(address(safe)), attacker));
        assertTrue(guard.isNativeTransferAllowed(address(safe), address(protocol)));
        assertGt(guard.approvalExpiry(_id), 0);
        assertEq(guard.approvalEpoch(address(safe)), 0);
    }

    /// @dev The guardian narrow surface that `test_guardian_can_only_narrow` does not exercise.
    function test_guardian_can_remove_and_clear_values_and_revoke_target() public {
        _enforce();
        _allowWithRules(address(token), APPROVE, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        bytes32[] memory _values = new bytes32[](2);
        _values[0] = _word(address(protocol));
        _values[1] = _word(attacker);
        vm.startPrank(vetro);
        guard.addAllowedValues(address(safe), address(token), APPROVE, 0, _values);
        guard.setGuardian(address(safe), guardian, true);
        vm.stopPrank();

        bytes32[] memory _one = new bytes32[](1);
        _one[0] = _word(attacker);
        vm.startPrank(guardian);
        guard.removeAllowedValues(address(safe), address(token), APPROVE, 0, _one);
        assertEq(guard.allowedValues(address(safe), address(token), APPROVE, 0).length, 1);
        guard.clearAllowedValues(address(safe), address(token), APPROVE, 0);
        assertEq(guard.allowedValues(address(safe), address(token), APPROVE, 0).length, 0);
        guard.revokeTarget(address(safe), address(token));
        vm.stopPrank();
        assertFalse(_isAllowed(address(safe), address(token), APPROVE));
        assertEq(guard.targets(address(safe)).length, 0);
    }

    /*//////////////////////////////////////////////////////////////
                       ZERO-ADDRESS GUARDS (P17-P19, P24)
    //////////////////////////////////////////////////////////////*/

    function test_zero_address_arguments_are_rejected() public {
        vm.startPrank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(0)));
        guard.setGuardian(address(safe), address(0), true);
        vm.expectRevert(CuratorGuardPolicy.AddressIsNull.selector);
        guard.setNativeTransferAllowed(address(0), address(protocol), true);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(0)));
        guard.setModuleAllowed(address(safe), address(0), true);
        vm.expectRevert(CuratorGuardPolicy.AddressIsNull.selector);
        guard.approveTransaction(address(0), address(0), address(protocol), 0, "", Operation.Call, uint64(1));
        vm.expectRevert(CuratorGuardPolicy.AddressIsNull.selector);
        guard.setMultiSendUnwrapper(address(0), address(multiSendCallOnly), true);
        vm.expectRevert(CuratorGuardPolicy.AddressIsNull.selector);
        guard.lockdown(address(0));
        vm.expectRevert(CuratorGuardPolicy.AddressIsNull.selector);
        guard.setRequiredFallbackHandler(address(0), address(0), true);
        vm.expectRevert(CuratorGuardPolicy.AddressIsNull.selector);
        guard.revokeAllApprovals(address(0));
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                 allowFunctions atomicity (partially invalid)
    //////////////////////////////////////////////////////////////*/

    function test_allowFunctions_is_atomic_when_a_later_spec_is_invalid() public {
        CuratorGuardPolicy.FunctionSpec[] memory _specs = new CuratorGuardPolicy.FunctionSpec[](3);
        _specs[0] = CuratorGuardPolicy.FunctionSpec(address(protocol), SETTLE, false, _noRules());
        _specs[1] = CuratorGuardPolicy.FunctionSpec(address(token), APPROVE, false, _noRules());
        _specs[2] = CuratorGuardPolicy.FunctionSpec(address(safe), ISafe.setGuard.selector, false, _noRules());
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(safe)));
        guard.allowFunctions(address(safe), _specs);
        assertFalse(_isAllowed(address(safe), address(protocol), SETTLE));
        assertFalse(_isAllowed(address(safe), address(token), APPROVE));
        assertEq(guard.targets(address(safe)).length, 0);

        // Same with an unbounded lower bound in the last spec.
        _specs[2] = CuratorGuardPolicy.FunctionSpec(
            address(token),
            TRANSFER,
            false,
            _rule(CuratorGuardPolicy.RuleKind.GreaterThanOrEqual, 1, bytes32(uint256(1)))
        );
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.UnboundedLowerBound.selector, 0));
        guard.allowFunctions(address(safe), _specs);
        assertFalse(_isAllowed(address(safe), address(protocol), SETTLE));
    }

    /*//////////////////////////////////////////////////////////////
                  OneOf set at the cap (P14) and revoke gas
    //////////////////////////////////////////////////////////////*/

    function test_oneOf_set_accepts_exactly_the_cap_and_revoke_stays_cheap() public {
        _enforce();
        _allowWithRules(address(token), APPROVE, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        uint256 _cap = _H().maxAllowedValues();
        bytes32[] memory _values = new bytes32[](_cap);
        for (uint256 i; i < _cap; ++i) _values[i] = bytes32(i + 1);
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(token), APPROVE, 0, _values);
        assertEq(guard.allowedValues(address(safe), address(token), APPROVE, 0).length, _cap);

        bytes32[] memory _oneMore = new bytes32[](1);
        _oneMore[0] = bytes32(uint256(_cap + 1));
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.TooManyValues.selector, _cap + 1));
        guard.addAllowedValues(address(safe), address(token), APPROVE, 0, _oneMore);
        // Re-adding an existing member is a no-op and stays within the cap.
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(token), APPROVE, 0, _values);

        vm.prank(vetro);
        uint256 _gas = gasleft();
        guard.revokeFunction(address(safe), address(token), APPROVE);
        _gas -= gasleft();
        emit log_named_uint("revokeFunction gas with 128 OneOf members", _gas);
        assertLt(_gas, 2_000_000);
        assertEq(guard.allowedValues(address(safe), address(token), APPROVE, 0).length, 0);
    }

    /*//////////////////////////////////////////////////////////////
                   P11: re-allow REPLACES the rule list
    //////////////////////////////////////////////////////////////*/

    function test_reallow_replaces_rules_instead_of_appending() public {
        _enforce();
        _allowWithRules(address(token), APPROVE, _rule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 1, bytes32(uint256(100))));
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(token), APPROVE, uint16(1), bytes32(uint256(101)))
        );
        _execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (address(protocol), 101)), Operation.Call);

        // Relax: raise the cap. The old cap must be gone.
        _allowWithRules(address(token), APPROVE, _rule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 1, bytes32(uint256(1_000))));
        (, , CuratorGuardPolicy.ParamRule[] memory _rules) = guard.functionPermission(address(safe), address(token), APPROVE);
        assertEq(_rules.length, 1, "rules replaced, not appended");
        assertTrue(_execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (address(protocol), 101)), Operation.Call));

        // Relax fully: no rules.
        _allow(address(token), APPROVE);
        (, , _rules) = guard.functionPermission(address(safe), address(token), APPROVE);
        assertEq(_rules.length, 0);
        assertTrue(_execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (address(protocol), 1_001)), Operation.Call));
    }

    /*//////////////////////////////////////////////////////////////
          P12/P13/G23: OneOf sets are keyed per (selector, word)
    //////////////////////////////////////////////////////////////*/

    function test_oneOf_sets_do_not_leak_across_words_or_selectors_of_the_same_target() public {
        _enforce();
        // deposit(uint256 assets, address receiver): OneOf on word 0 (amount) and word 1 (receiver).
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](2);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0);
        _rules[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, 1, 0);
        _allowWithRules(address(protocol), DEPOSIT, _rules);
        // settleDeposit(uint256): OneOf on word 0.
        _allowWithRules(address(protocol), SETTLE, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));

        bytes32[] memory _amounts = new bytes32[](1);
        _amounts[0] = bytes32(uint256(5));
        bytes32[] memory _receivers = new bytes32[](1);
        _receivers[0] = _word(address(safe));
        vm.startPrank(vetro);
        guard.addAllowedValues(address(safe), address(protocol), DEPOSIT, 0, _amounts);
        guard.addAllowedValues(address(safe), address(protocol), DEPOSIT, 1, _receivers);
        vm.stopPrank();

        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (5, address(safe))), Operation.Call));
        // Word 1 value used on word 0 of the same selector: rejected.
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(protocol), DEPOSIT, uint16(0), _word(address(safe)))
        );
        _execSafeTx(address(protocol), 0, abi.encodePacked(DEPOSIT, _word(address(safe)), _word(address(safe))), Operation.Call);
        // Word 0 value of `deposit` used on word 0 of `settleDeposit`: rejected.
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(protocol), SETTLE, uint16(0), bytes32(uint256(5)))
        );
        _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (5)), Operation.Call);
        assertEq(guard.allowedValues(address(safe), address(protocol), SETTLE, 0).length, 0);
    }

    /*//////////////////////////////////////////////////////////////
               ERC-4626 withdraw-shaped rules (receiver AND owner)
    //////////////////////////////////////////////////////////////*/

    function test_withdraw_shaped_rules_pin_receiver_and_owner_words() public {
        _enforce();
        bytes4 _withdraw = bytes4(keccak256("withdraw(uint256,address,address)"));
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](2);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualToSafe, 1, 0);
        _rules[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualToSafe, 2, 0);
        _allowWithRules(address(protocol), _withdraw, _rules);
        guard.validateTransaction(address(safe), address(protocol), 0, abi.encodeWithSelector(_withdraw, 1, address(safe), address(safe)), Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(protocol), _withdraw, uint16(1), _word(attacker)));
        guard.validateTransaction(address(safe), address(protocol), 0, abi.encodeWithSelector(_withdraw, 1, attacker, address(safe)), Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(protocol), _withdraw, uint16(2), _word(attacker)));
        guard.validateTransaction(address(safe), address(protocol), 0, abi.encodeWithSelector(_withdraw, 1, address(safe), attacker), Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
                 Events (R1-7 says monitors depend on them)
    //////////////////////////////////////////////////////////////*/

    function test_events_carry_full_rules_and_calldata() public {
        CuratorGuardPolicy.ParamRule[] memory _rules = _rule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 1, bytes32(uint256(7)));
        vm.prank(vetro);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuardPolicy.FunctionAllowed(address(safe), address(token), APPROVE, true, _rules);
        guard.allowFunction(address(safe), address(token), APPROVE, true, _rules);

        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (3));
        bytes32 _id = guard.computeApprovalId(address(safe), address(0), address(protocol), 0, _data, Operation.Call);
        uint64 _ttl = uint64(1 days);
        vm.prank(vetro);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuardPolicy.TransactionApproved(
            address(safe),
            _id,
            address(0),
            address(protocol),
            0,
            _data,
            Operation.Call,
            uint64(block.timestamp) + _ttl,
            0
        );
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, _ttl);

        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuardPolicy.ApprovalConsumed(address(safe), _id, address(0));
        _execSafeTx(address(protocol), 0, _data, Operation.Call);

        // No-op revoke of a never-allowed function must stay silent (R1-13).
        vm.recordLogs();
        vm.prank(vetro);
        guard.revokeFunction(address(safe), address(protocol), DEPOSIT);
        assertEq(vm.getRecordedLogs().length, 0, "silent no-op revoke");
    }

    /*//////////////////////////////////////////////////////////////
                     Evaluation order step 5 vs 6 (G04)
    //////////////////////////////////////////////////////////////*/

    function test_lockdown_wins_over_native_transfer_and_rules() public {
        // Lockdown is reported even when the payload would fail the policy for another reason.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(attacker, 1 ether, "", Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call);
        // Gas refund is rejected before Lockdown (step 3 before step 6).
        vm.expectRevert(CuratorGuard.GasRefundNotAllowed.selector);
        _execSafeTxWithRefund(attacker, 0, "", Operation.Call, 1, address(0), attacker);
    }

    /*//////////////////////////////////////////////////////////////
          Owner change mid-flight: the Safe accepts guard ownership
    //////////////////////////////////////////////////////////////*/

    /// @dev The admin is never constrained, so the guard refuses to hand the admin role to a Safe that
    ///      carries a policy (`AdminIsGuarded`); an unconfigured address can still become admin, and a
    ///      Safe that does so is then exempt from everything, including removing the guard.
    function test_guarded_safe_cannot_become_admin_but_an_unconfigured_safe_can() public {
        _enforce();
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, address(safe)));
        guard.beginDefaultAdminTransfer(address(safe));
        // Lockdown with guardians or a handler requirement counts as configured too.
        address _other = makeAddr("other-safe");
        vm.prank(vetro);
        guard.setGuardian(_other, guardian, true);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, _other));
        guard.beginDefaultAdminTransfer(_other);

        // A second, unconfigured Safe with the same curator key becomes admin and is exempt.
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        ISafe _safeB = ISafe(address(_proxy));
        _H().seedSafe(address(_safeB)); // seeded: the guard pins canonical Safe code (V2-85)
        vm.prank(address(_safeB));
        _safeB.setGuard(address(guard));
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(address(_safeB));
        vm.warp(block.timestamp + 1);
        safe = _safeB;
        // Unconfigured = Lockdown: B cannot even reach the guard to accept through its own guarded path
        // (an approval could not target the guard either; a Bypass window would be the operational way).
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(_safeB)));
        _execSafeTx(address(guard), 0, abi.encodeCall(guard.acceptDefaultAdminTransfer, ()), Operation.Call);
        vm.prank(address(_safeB));
        guard.acceptDefaultAdminTransfer();
        assertEq(guard.defaultAdmin(), address(_safeB));
        assertTrue(_execSafeTx(address(_safeB), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call), "exempt");
    }

    /*//////////////////////////////////////////////////////////////
                 Dry-run exemptions (G11) and short words (G22)
    //////////////////////////////////////////////////////////////*/

    function test_dry_run_honours_owner_exemption_and_bypass() public {
        // Owner Safe: anything passes the dry run.
        guard.validateTransaction(vetro, address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call);
        guard.validateModuleTransaction(vetro, attacker, address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call);
        // Admin window: anything passes the dry run on the owner path and for an allowlisted module; a
        // module off the allowlist stays out in every mode (round 8, R8R-1).
        vm.prank(vetro);
        guard.bypass(address(safe), 1 days);
        guard.validateTransaction(address(safe), address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, attacker));
        guard.validateModuleTransaction(address(safe), attacker, address(token), 1, abi.encodeCall(IERC20.transfer, (attacker, 1)), Operation.Call);
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), attacker, true);
        guard.validateModuleTransaction(address(safe), attacker, address(token), 1, abi.encodeCall(IERC20.transfer, (attacker, 1)), Operation.Call);
    }

    function test_rule_word_one_byte_short_is_ParamOutOfRange() public {
        _enforce();
        _allowWithRules(address(protocol), DEPOSIT, _rule(CuratorGuardPolicy.RuleKind.EqualToSafe, 1, 0));
        bytes memory _short = abi.encodePacked(DEPOSIT, uint256(5), new bytes(31)); // 67 bytes: word 1 is 1 byte short
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamOutOfRange.selector, address(protocol), DEPOSIT, uint16(1)));
        _execSafeTx(address(protocol), 0, _short, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamOutOfRange.selector, address(protocol), DEPOSIT, uint16(1)));
        guard.validateTransaction(address(safe), address(protocol), 0, _short, Operation.Call);
    }

    function test_multisend_short_payloads_are_MalformedMultiSend_not_untyped() public {
        _enforce();
        _registerUnwrapper(address(multiSendCallOnly));
        // 4-byte selector only (G28).
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        _execSafeTx(address(multiSendCallOnly), 0, abi.encodePacked(bytes4(0x8d80ff0a)), Operation.DelegateCall);
        // 36 bytes: selector + offset, no length word.
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        _execSafeTx(address(multiSendCallOnly), 0, abi.encodePacked(bytes4(0x8d80ff0a), uint256(0x20)), Operation.DelegateCall);
        // Entry header one byte short (84 of 85 bytes) (G29).
        bytes memory _packed = abi.encodePacked(uint8(0), address(protocol), uint256(0), new bytes(31));
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        _execSafeTx(address(multiSendCallOnly), 0, _multiSendCalldata(_packed), Operation.DelegateCall);
    }

    function test_ApprovalRevoked_names_the_safe_of_the_approval() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        bytes32 _id = _approve(address(protocol), 1 ether, _data, Operation.Call);
        assertGt(guard.approvalExpiry(_id), 0);
        vm.prank(vetro);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuardPolicy.ApprovalRevoked(address(safe), _id);
        guard.revokeApproval(_id);
    }


    function test_allowlisted_target_reentering_the_hooks_has_no_effect() public {
        _enforce();
        ReentrantVenue _venue = new ReentrantVenue(guard, address(safe));
        _allow(address(_venue), ReentrantVenue.poke.selector);
        // A live approval that a confused post-hook could restore / consume.
        bytes32 _id = _approve(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (9)), Operation.Call);
        uint64 _expiryBefore = guard.approvalExpiry(_id);

        assertTrue(_execSafeTx(address(_venue), 0, abi.encodeCall(ReentrantVenue.poke, (1)), Operation.Call));
        assertEq(_venue.calls(), 1);
        assertEq(bytes4(_venue.lastPreRevert()), CuratorGuard.SafeConfigUnreadable.selector, "stranger pre-hook: not a guarded Safe");
        assertEq(bytes4(_venue.lastPostRevert()), CuratorGuard.MissingSnapshot.selector, "stranger post-hook: no snapshot");
        assertEq(guard.approvalExpiry(_id), _expiryBefore, "approval untouched");
        assertEq(_installedGuard(), address(guard));
    }

    /*//////////////////////////////////////////////////////////////
                  Two Safes sharing the guard, nested
    //////////////////////////////////////////////////////////////*/

    /// @dev Safe A (Enforced) is allowed to call `execTransaction` on Safe B (Enforced); B executes
    ///      an allowed call. Hooks interleave: A.pre, B.pre, B.post, A.post; slots are keyed per Safe.
    function test_two_guarded_safes_nested_keep_separate_snapshots() public {
        // Second Safe with the same curator key and the same guard.
        ISafe _safeA = safe;
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        ISafe _safeB = ISafe(address(_proxy));
        _H().seedSafe(address(_safeB)); // seeded: the guard pins canonical Safe code (V2-85)
        vm.prank(address(_safeB));
        _safeB.setGuard(address(guard));

        vm.startPrank(vetro);
        guard.enforce(address(_safeA));
        guard.enforce(address(_safeB));
        guard.allowFunction(address(_safeA), address(_safeB), ISafe.execTransaction.selector, false, _noRules());
        guard.allowFunction(address(_safeB), address(protocol), SETTLE, false, _noRules());
        vm.stopPrank();

        // Inner (B) transaction, signed at B's nonce.
        safe = _safeB;
        SafeTx memory _inner = SafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (21)), Operation.Call, 0, 0, address(0), address(0));
        bytes memory _innerCall = abi.encodeCall(
            ISafe.execTransaction,
            (_inner.to, 0, _inner.data, Operation.Call, 0, 0, 0, address(0), payable(address(0)), _sign(_txHash(_inner)))
        );
        // Outer (A) transaction.
        safe = _safeA;
        assertTrue(_execSafeTx(address(_safeB), 0, _innerCall, Operation.Call));
        assertEq(protocol.lastAmount(), 21);
        assertEq(_safeB.nonce(), 1);

        // B's policy is enforced inside the nesting: a denied inner payload reverts the outer.
        safe = _safeB;
        SafeTx memory _bad = SafeTx(address(token), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call, 0, 0, address(0), address(0));
        bytes memory _badCall = abi.encodeCall(
            ISafe.execTransaction,
            (_bad.to, 0, _bad.data, Operation.Call, 0, 0, 0, address(0), payable(address(0)), _sign(_txHash(_bad)))
        );
        safe = _safeA;
        vm.expectRevert(bytes("GS013")); // inner revert surfaces as the outer call failing
        _execSafeTx(address(_safeB), 0, _badCall, Operation.Call);
    }

    bytes32 internal constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;
    address internal constant SENTINEL = address(0x1);

    function _ownerSlot(address key_) internal pure returns (bytes32) {
        return keccak256(abi.encode(key_, uint256(2))); // `owners` mapping is SafeStorage slot 2
    }

    function _runEvil(address evil_, bytes memory expectedRevert_) internal {
        _enforce();
        _allow(address(protocol), SETTLE);
        _registerUnwrapper(evil_);
        bytes memory _batch = _multiSendCalldata(_entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (7))));
        if (expectedRevert_.length > 0) vm.expectRevert(expectedRevert_);
        _execSafeTx(evil_, 0, _batch, Operation.DelegateCall);
    }

    /// @dev G17: an owner swap done through storage (owners[SENTINEL] -> attacker -> SENTINEL) keeps
    ///      ownerCount and threshold intact; only the owner LIST changes.
    function test_post_check_catches_an_owner_swap_that_keeps_count_and_threshold() public {
        // Sanity: the fixture Safe's list is SENTINEL -> curator -> SENTINEL.
        assertEq(address(uint160(uint256(vm.load(address(safe), _ownerSlot(SENTINEL))))), curator);
        MaliciousMultiSend2 _evil = new MaliciousMultiSend2(
            _ownerSlot(SENTINEL),
            _word(attacker),
            _ownerSlot(attacker),
            _word(SENTINEL)
        );
        _runEvil(address(_evil), abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(safe)));
        address[] memory _owners = safe.getOwners();
        assertEq(_owners.length, 1);
        assertEq(_owners[0], curator, "owner list intact");
    }

    /// @dev G18: the module-guard slot is part of the digest even on v1.4.1 (where it is unused).
    function test_post_check_catches_a_module_guard_write() public {
        MaliciousMultiSend _evil = new MaliciousMultiSend(MODULE_GUARD_SLOT, _word(attacker));
        _runEvil(address(_evil), abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(safe)));
        assertEq(vm.load(address(safe), MODULE_GUARD_SLOT), bytes32(0));
    }

    /// @dev G15: swapping the singleton for a DIFFERENT but functional singleton (same code) must be
    ///      caught by the typed check, not by the proxy breaking.
    function test_post_check_catches_a_singleton_swap_to_a_working_singleton() public {
        Safe _other = new Safe();
        bytes32 _before = vm.load(address(safe), bytes32(uint256(0)));
        MaliciousMultiSend _evil = new MaliciousMultiSend(bytes32(uint256(0)), _word(address(_other)));
        _runEvil(address(_evil), abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(safe)));
        assertEq(vm.load(address(safe), bytes32(uint256(0))), _before, "singleton intact");
    }

    /// @dev A swapped singleton that forwards everything but LIES about slot 0 in `getStorageAt`
    ///      would pass a digest read through the Safe's code; the digest also reads `masterCopy()`,
    ///      which the proxy bytecode answers itself, so the swap is caught.
    function test_post_check_catches_a_lying_singleton_through_masterCopy() public {
        address _real = address(uint160(uint256(vm.load(address(safe), bytes32(uint256(0))))));
        LyingSingleton _liar = new LyingSingleton(_real, _real);
        _H().seedSafeCodehash(address(_liar).codehash); // past the code pin (V2-85), the masterCopy comparison is what catches it
        MaliciousMultiSend _evil = new MaliciousMultiSend(bytes32(uint256(0)), _word(address(_liar)));
        _runEvil(address(_evil), abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(safe)));
        assertEq(address(uint160(uint256(vm.load(address(safe), bytes32(uint256(0)))))), _real, "singleton intact");
    }

    /// @dev ownerCount alone (slot 3) is covered by `getStorageAt(0, 5)`.
    function test_post_check_catches_an_ownerCount_write() public {
        MaliciousMultiSend _evil = new MaliciousMultiSend(bytes32(uint256(3)), bytes32(uint256(2)));
        _runEvil(address(_evil), abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(safe)));
    }

    /// @dev A write to an uncovered slot (nonce, slot 5) is NOT caught: documents the digest's scope.
    function test_post_check_does_not_cover_the_nonce_slot() public {
        uint256 _nonce = safe.nonce();
        MaliciousMultiSend _evil = new MaliciousMultiSend(bytes32(uint256(5)), bytes32(uint256(1_000)));
        _runEvil(address(_evil), "");
        assertEq(safe.nonce(), 1_000, "nonce rewritten and not caught (out of scope)");
        assertGt(1_000, _nonce);
    }

    function test_guard_hooks_can_never_be_approved_or_allowlisted_as_targets() public {
        bytes memory _data = abi.encodeCall(guard.checkAfterExecution, (bytes32(0), true));
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(guard)));
        guard.approveTransaction(address(safe), address(0), address(guard), 0, _data, Operation.Call, uint64(1 days));
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(guard)));
        guard.approveTransaction(address(safe), address(0), address(guard), 0, _data, Operation.Call, uint64(1 days));
        _enforce();
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, guard.checkAfterExecution.selector));
        _execSafeTx(address(guard), 0, _data, Operation.Call);
    }

    /// @dev A batch entry with 0-byte data to a contract (zero value) needs the native permission.
    function test_batch_entry_with_empty_data_and_zero_value_needs_native_permission() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        _registerUnwrapper(address(multiSendCallOnly));
        bytes memory _batch = _multiSendCalldata(
            abi.encodePacked(
                _entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1))),
                _entry(address(protocol), 0, "")
            )
        );
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.NativeTransferNotAllowed.selector, address(protocol)));
        _execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), address(protocol), true);
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall));
        assertEq(protocol.calls(), 2);
    }
}
