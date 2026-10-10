// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @title G11g evidence tests (comments and docs, third reading)
/// @notice Pins the facts behind the four comment and docs corrections of review g11g. All pass on the
///         shipped code: they document behaviour, they do not test a fix.
contract G11gEvidenceTest is CuratorGuardTestBase {
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;

    /// @dev `CuratorGuard.sol:741` says "Post-Cancun code cannot disappear" as the reason the `NotAContract`
    ///      check costs no liveness. An EIP-7702 delegated EOA carries a 23-byte designator
    ///      (`0xef0100 || address`), passes `to_.code.length == 0`, and loses that code when its key
    ///      clears the delegation: the policy entry then refuses `NotAContract` until it is re-pointed.
    function test_a_delegated_eoa_passes_the_code_check_and_loses_it_when_cleared() public {
        address _venue = makeAddr("delegated-eoa");
        vm.etch(_venue, abi.encodePacked(hex"ef0100", address(protocol)));
        assertEq(_venue.code.length, 23, "EIP-7702 designator");
        _enforce();
        _allow(_venue, SETTLE);
        bytes memory _call = abi.encodeCall(MockProtocol.settleDeposit, (1));
        // Passes the policy (the dry run never calls the venue; the live hook would, see the docs lens).
        guard.validateTransaction(address(safe), _venue, 0, _call, Operation.Call);
        // The delegation is cleared by its key (modelled by re-etching empty code): the entry is dead.
        vm.etch(_venue, "");
        assertEq(_venue.code.length, 0, "delegation cleared");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.NotAContract.selector, _venue));
        guard.validateTransaction(address(safe), _venue, 0, _call, Operation.Call);
    }

    /// @dev Rule 4 of the `CuratorGuard.sol` header lists "owner management" among the self-calls a
    ///      council window lets through; the allowlist only holds owner management within the council's
    ///      limits (threshold at least 2, a new owner without code). `changeThreshold(1)` is refused.
    function test_rule4_a_council_window_refuses_owner_management_outside_the_councils_limits() public {
        vm.prank(council);
        guard.bypass(address(safe), 1 days);
        bytes memory _data = abi.encodeWithSelector(bytes4(0x694e80c3), uint256(1)); // changeThreshold(uint256)
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, bytes4(0x694e80c3)));
        _execSafeTx(address(safe), 0, _data, Operation.Call);
        // An owner with code is refused by the same limits.
        bytes memory _swap = abi.encodeWithSelector(bytes4(0xe318b52b), address(1), curator, address(protocol)); // swapOwner(address,address,address)
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, bytes4(0xe318b52b)));
        _execSafeTx(address(safe), 0, _swap, Operation.Call);
    }

    /// @dev Docs sections 4, 6, 7.3 and 7.8 say a report can never be forged through a Safe whose fallback
    ///      handler is the guard (`ForwardedHookCall`). The 68-byte rule holds for a forwarded hook call;
    ///      a forwarded `executeBefore` re-dispatches the hook to itself at exactly 68 bytes with the Safe
    ///      as caller and, inside a window, emits a `TransactionChecked(Bypass)` for a hash of the
    ///      stranger's choice: that was the held review G9a-1, applied after round 13, so the wrapped call
    ///      is refused as well (`Unauthorized`) and nothing is reported.
    function test_a_stranger_cannot_forge_a_bypass_report_through_executeBefore_while_the_guard_is_the_handler() public {
        vm.prank(address(safe));
        Safe(payable(address(safe))).setFallbackHandler(address(guard));
        _bypass(1 days);
        bytes32 _hash = keccak256("any hash the stranger likes");
        bytes memory _hook = abi.encodeCall(CuratorGuard.checkAfterExecution, (_hash, true));
        bytes memory _wrapped = abi.encodeCall(CuratorGuardPolicy.executeBefore, (uint64(block.timestamp + 1), _hook));
        // The direct forwarded hook call is refused as documented: 68 + 20 bytes.
        vm.prank(attacker);
        (bool _ok, bytes memory _ret) = address(safe).call(_hook);
        assertFalse(_ok, "direct forwarded hook call refused");
        assertEq(bytes4(_ret), CuratorGuard.ForwardedHookCall.selector, "ForwardedHookCall");
        // The forwarded `executeBefore` is refused too: no report.
        vm.recordLogs();
        vm.prank(attacker);
        (_ok, _ret) = address(safe).call(_wrapped);
        assertFalse(_ok, "forwarded executeBefore refused");
        assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector, "Unauthorized");
        assertEq(vm.getRecordedLogs().length, 0, "no forged report");
    }

    /// @dev `CuratorGuardPolicy.sol:954-955`: the member-wise store writes the packed record with ONE
    ///      `sstore`. `vm.record` lists every storage write of the guard during `approveTransaction`.
    function test_approveTransaction_writes_one_storage_slot() public {
        _enforce();
        bytes memory _call = abi.encodeCall(MockProtocol.settleDeposit, (2));
        vm.record();
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _call, Operation.Call, 1 hours);
        (, bytes32[] memory _writes) = vm.accesses(address(guard));
        assertEq(_writes.length, 1, "one storage write");
    }

    /// @dev `CuratorGuardPolicy.sol:111-112` priced the iteration of a committed `OneOf` set per member
    ///      ("about 14k gas"); the figure is pricing-dependent (14.7k, 12.3k and 11.2k across three
    ///      readings) and now reads "a storage clear per member". Measures `clearAllowedValues` over 8 and
    ///      4 members and logs the slope; run with `--isolate` so the members sit in committed storage.
    function test_clearing_a_committed_oneof_member_costs_one_storage_clear() public {
        _enforce();
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](1);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, 0, bytes32(0));
        _allowWithRules(address(protocol), SETTLE, _rules);
        uint256 _g8 = _measureClear(8);
        uint256 _g4 = _measureClear(4);
        uint256 _perMember = (_g8 - _g4) / 4;
        emit log_named_uint("clearAllowedValues, 8 members", _g8);
        emit log_named_uint("clearAllowedValues, 4 members", _g4);
        emit log_named_uint("  => per committed member", _perMember);
        assertGt(_perMember, 3_000, "a member costs real gas");
        assertLt(_perMember, 20_000, "far below a block per member");
    }

    function _measureClear(uint256 n_) internal returns (uint256 _gas) {
        bytes32[] memory _values = new bytes32[](n_);
        for (uint256 i; i < n_; ++i) _values[i] = bytes32(uint256(1000 + i));
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(protocol), SETTLE, 0, _values);
        vm.prank(vetro);
        _gas = gasleft();
        guard.clearAllowedValues(address(safe), address(protocol), SETTLE, 0);
        _gas -= gasleft();
    }
}
