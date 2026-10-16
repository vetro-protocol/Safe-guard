// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";
import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @title Round 10 (g10f): pins for the round-9 code changes applied after round 13 (G9a-1, G9a-3 / G9c-3).
/// @dev   Every test here failed on the code shipped through round 13 and passes with the follow-up commit
///        (G9a-1 `_refuseForwarded()` first in `executeBefore`; G9a-3 / G9c-3 the same first in
///        `_acceptDefaultAdminTransfer`). Each is the killer of the mutant that removes the rail's line again
///        (the round-10 mutation results, kept with the review material). The pins for the two round-9
///        items that stay held (G9c-1, G9b-2) stay with the review material too.
contract CuratorGuardG10fHeldFixPinsTest is CuratorGuardTestBase {
    bytes32 internal constant FORGED = keccak256("g10f: no Safe transaction ever carried this hash");
    bytes32 internal constant REPORT_SIG = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");

    function _setHandler(ISafe safe_, address handler_) internal {
        vm.prank(address(safe_));
        (bool _ok, ) = address(safe_).call(abi.encodeWithSignature("setFallbackHandler(address)", handler_));
        assertTrue(_ok, "setFallbackHandler");
    }

    function _wrapped(bytes memory call_) internal view returns (bytes memory) {
        return abi.encodeCall(guard.executeBefore, (uint64(block.timestamp + 1 hours), call_));
    }

    function _reports(Vm.Log[] memory logs_) internal view returns (uint256 _count) {
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter == address(guard) && logs_[i].topics[0] == REPORT_SIG) ++_count;
        }
    }

    /// @dev A second real Safe v1.4.1 (1-of-1, no handler): the pending admin of the hand-over tests.
    function _newSafe(string memory name_) internal returns (ISafe _safe) {
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = makeAddr(name_);
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        _safe = ISafe(address(_proxy));
    }

    /*//////////////////////////////////////////////////////////////
                                  G9a-1
    //////////////////////////////////////////////////////////////*/

    /// @dev Shipped-policy shape, the guard in the Safe's handler slot (the state the policy forbids), a
    ///      council window open: the after-hooks wrapped in `executeBefore` are refused (`Unauthorized`)
    ///      with no report and no Safe transaction, on both paths.
    function test_pin_G9a1_executeBefore_refuses_a_caller_whose_handler_is_this_guard() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(safe), address(0), true);
        _setHandler(safe, address(guard));
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        uint256 _nonce = safe.nonce();

        vm.recordLogs();
        vm.prank(attacker);
        (bool _ok, bytes memory _ret) = address(safe).call(_wrapped(abi.encodeCall(guard.checkAfterExecution, (FORGED, true))));
        assertFalse(_ok, "forwarded executeBefore(checkAfterExecution) refused");
        assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector, "refused as a forwarded caller");
        vm.prank(attacker);
        (_ok, _ret) = address(safe).call(_wrapped(abi.encodeCall(guard.checkAfterModuleExecution, (FORGED, true))));
        assertFalse(_ok, "forwarded executeBefore(checkAfterModuleExecution) refused");
        assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector);
        assertEq(_reports(vm.getRecordedLogs()), 0, "no forged report");
        assertEq(safe.nonce(), _nonce, "no Safe transaction ran");

        // The wrapper still serves its callers: the council's own `executeBefore(bypass)` runs.
        vm.prank(council);
        guard.executeBefore(uint64(block.timestamp + 1 hours), abi.encodeCall(guard.bypass, (address(safe), 2 hours)));
        (uint64 _until, bool _byCouncil) = guard.bypassWindow(address(safe));
        assertEq(_until, uint64(block.timestamp + 2 hours));
        assertTrue(_byCouncil);
    }

    /// @dev Without a handler requirement the forwarded PRE-hook still parks a snapshot (the documented
    ///      residual); the wrapped after-hook can no longer clear and report it, so the parked snapshot
    ///      dies with the stranger's transaction as section 4 says: the curator's genuine transaction in
    ///      the same EVM transaction trips `NestedExecution`, nothing is reported, nothing executed.
    function test_pin_G9a1_a_parked_snapshot_cannot_be_laundered_through_executeBefore() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        _setHandler(safe, address(guard));
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        bytes memory _pre = abi.encodeCall(
            guard.checkTransaction,
            (address(protocol), 0, _settle, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", attacker)
        );
        vm.recordLogs();
        vm.startPrank(attacker);
        (bool _ok, ) = address(safe).call(_pre);
        assertTrue(_ok, "forwarded policy pre-hook parks a snapshot (documented residual)");
        bytes memory _ret;
        (_ok, _ret) = address(safe).call(_wrapped(abi.encodeCall(guard.checkAfterExecution, (FORGED, true))));
        vm.stopPrank();
        assertFalse(_ok, "wrapped after-hook refused");
        assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector);
        assertEq(_reports(vm.getRecordedLogs()), 0, "no report");
        assertEq(protocol.calls(), 0, "nothing executed");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.NestedExecution.selector, address(safe)));
        _execSafeTx(address(protocol), 0, _settle, Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
                               G9a-3 / G9c-3
    //////////////////////////////////////////////////////////////*/

    /// @dev A pending-admin Safe whose handler is this guard forwards anyone's `acceptDefaultAdminTransfer`
    ///      with itself as the caller: refused, so the admin keeps the late cancel; the hand-over proceeds
    ///      once the Safe's handler is gone, as its own transaction.
    function test_pin_G9c3_a_stranger_cannot_complete_a_handover_through_a_forwarding_safe() public {
        ISafe _dao = _newSafe("dao-owner");
        _setHandler(_dao, address(guard));
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(address(_dao));
        vm.warp(block.timestamp + 1);
        vm.prank(attacker);
        (bool _ok, bytes memory _ret) = address(_dao).call(abi.encodeCall(guard.acceptDefaultAdminTransfer, ()));
        assertFalse(_ok, "forwarded acceptance refused");
        assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector);
        assertEq(guard.defaultAdmin(), vetro, "the admin keeps the late cancel");
        vm.prank(vetro);
        guard.cancelDefaultAdminTransfer();
        (address _pending, ) = guard.pendingDefaultAdmin();
        assertEq(_pending, address(0));
        // Re-armed, and accepted by the Safe itself once its handler slot no longer holds the guard.
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(address(_dao));
        vm.warp(block.timestamp + 1);
        _setHandler(_dao, address(0));
        vm.prank(address(_dao));
        guard.acceptDefaultAdminTransfer();
        assertEq(guard.defaultAdmin(), address(_dao));
    }

    /// @dev Round 14 (g14d): the rail is the FIRST statement of `_acceptDefaultAdminTransfer`, ahead of the
    ///      hand-over predicate and the 30-day deadline, as the NatSpec and the follow-up commit say: a forwarded
    ///      pending-admin Safe sees `Unauthorized` even when it is guarded or late (`AdminIsGuarded` /
    ///      `DeadlinePassed` otherwise). Kills the order variant of the round-10 mutation set (H-AC3 / g14d M-AC2),
    ///      which the generated matrix cannot reach (no caller class is both forwarded and pending).
    function test_pin_G9c3_the_rail_is_the_first_statement_of_the_acceptance() public {
        ISafe _dao = _newSafe("dao-owner-late");
        _setHandler(_dao, address(guard));
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(address(_dao));
        // Admin-written state on the pending admin AFTER the begin: the predicate alone would now refuse it.
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(_dao), address(0), true);
        (, uint48 _schedule) = guard.pendingDefaultAdmin();
        vm.warp(uint256(_schedule) + 1);
        bytes memory _accept = abi.encodeCall(guard.acceptDefaultAdminTransfer, ());
        vm.prank(attacker);
        (bool _ok, bytes memory _ret) = address(_dao).call(_accept);
        assertFalse(_ok, "forwarded acceptance of a guarded pending admin refused");
        assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector, "the rail, before the hand-over predicate");
        // Past the 30-day acceptance window: still the rail, not the deadline.
        vm.warp(uint256(_schedule) + 30 days + 1);
        vm.prank(attacker);
        (_ok, _ret) = address(_dao).call(_accept);
        assertFalse(_ok, "forwarded late acceptance refused");
        assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector, "the rail, before the deadline");
        // Control: once the handler is gone the Safe itself meets the predicate (the state the admin wrote).
        _setHandler(_dao, address(0));
        vm.prank(address(_dao));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, address(_dao)));
        guard.acceptDefaultAdminTransfer();
    }
}
