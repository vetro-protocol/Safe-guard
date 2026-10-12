// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";
import {CompatibilityFallbackHandler} from "safe-contracts-v1.4.1/contracts/handler/CompatibilityFallbackHandler.sol";
import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G12eMatrixBase} from "test/guards/G12e_MatrixBase.sol";

/// @dev A storage writer for a delegatecall plant.
contract G19eWriter {
    function write(bytes32 slot_, bytes32 value_) external {
        assembly {
            sstore(slot_, value_)
        }
    }
}

/// @title Review g19e: what the RAW handler word in the digest means next to the masked reads (real Safe v1.4.1,
///        the guard installed through a genuine execTransaction, the shipped shape: requirement ON naming the real
///        CompatibilityFallbackHandler H).
contract G19e_DigestDirtyTest is CuratorGuardTestBase {
    CompatibilityFallbackHandler internal H;
    G19eWriter internal writer;
    bytes internal settle;
    bytes32 internal constant REPORT_SIG = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");

    function setUp() public override {
        super.setUp();
        H = new CompatibilityFallbackHandler();
        writer = new G19eWriter();
        settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(safe), address(H), true);
        // the clean word, as `setup(..., H, ...)` or an approved `setFallbackHandler(H)` would leave it
        vm.store(address(safe), FALLBACK_SLOT, bytes32(uint256(uint160(address(H)))));
    }

    function _w(address low_, uint96 h_) internal pure returns (bytes32) {
        return bytes32((uint256(h_) << 160) | uint256(uint160(low_)));
    }

    function _pre() internal returns (bool _ok, bytes memory _ret) {
        vm.prank(address(safe));
        (_ok, _ret) = address(guard).call(
            abi.encodeCall(guard.checkTransaction, (address(protocol), 0, settle, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", curator))
        );
    }

    function _post() internal returns (bool _ok, bytes memory _ret) {
        vm.prank(address(safe));
        (_ok, _ret) = address(guard).call(abi.encodeCall(guard.checkAfterExecution, (bytes32(uint256(0x1234)), true)));
    }

    function _reports(Vm.Log[] memory logs_) internal view returns (uint256 _n) {
        for (uint256 i; i < logs_.length; ++i) if (logs_[i].emitter == address(guard) && logs_[i].topics[0] == REPORT_SIG) ++_n;
    }

    /// T1: the word's high bits dirtied between the hooks (the low bits still H): `SafeConfigChanged`. The docs
    ///     (S4, "any write to the Safe's ... fallback handler") decide it: the digest is byte-exact, fail closed.
    function test_T1_high_bits_dirtied_between_the_hooks_is_SafeConfigChanged() public {
        (bool _ok, ) = _pre();
        assertTrue(_ok, "pre passes on the clean required handler");
        vm.store(address(safe), FALLBACK_SLOT, _w(address(H), 0xdead));
        (bool _ok2, bytes memory _ret) = _post();
        assertFalse(_ok2, "post refuses");
        assertEq(bytes4(_ret), CuratorGuard.SafeConfigChanged.selector, "SafeConfigChanged");
    }

    /// T1b: control, the same bytes rewritten: one Policy report.
    function test_T1b_control_the_same_bytes_pass() public {
        (bool _ok, ) = _pre();
        assertTrue(_ok);
        vm.store(address(safe), FALLBACK_SLOT, bytes32(uint256(uint160(address(H)))));
        vm.recordLogs();
        (bool _ok2, ) = _post();
        assertTrue(_ok2, "same bytes: served");
        assertEq(_reports(vm.getRecordedLogs()), 1, "one report");
    }

    /// T1c: a word ALREADY dirty whose low bits are the required handler: `_checkHandler` masks (tolerated, dry run
    ///      and hook alike) and the digest is stable across the transaction (same bytes pre and post).
    function test_T1c_a_dirty_required_handler_word_is_tolerated_and_stable() public {
        vm.store(address(safe), FALLBACK_SLOT, _w(address(H), 0xdead));
        guard.validateTransaction(address(safe), address(protocol), 0, settle, Operation.Call);
        (bool _ok, ) = _pre();
        assertTrue(_ok, "pre: the masked handler is the required one");
        vm.recordLogs();
        (bool _ok2, ) = _post();
        assertTrue(_ok2, "post: the dirty bytes did not move");
        assertEq(_reports(vm.getRecordedLogs()), 1);
        // and through the real Safe: a policy transaction lands under a Policy report
        vm.recordLogs();
        assertTrue(_execSafeTx(address(protocol), 0, settle, Operation.Call), "real transaction served");
        assertEq(_reports(vm.getRecordedLogs()), 1);
        assertEq(protocol.calls(), 1);
    }

    /// T1d: dirty -> clean between the hooks is `SafeConfigChanged` as well (both directions).
    function test_T1d_cleaned_between_the_hooks_is_SafeConfigChanged_too() public {
        vm.store(address(safe), FALLBACK_SLOT, _w(address(H), 0xbeef));
        (bool _ok, ) = _pre();
        assertTrue(_ok);
        vm.store(address(safe), FALLBACK_SLOT, bytes32(uint256(uint160(address(H)))));
        (bool _ok2, bytes memory _ret) = _post();
        assertFalse(_ok2);
        assertEq(bytes4(_ret), CuratorGuard.SafeConfigChanged.selector);
    }

    /// T1e: class 13's S3 cell through a REAL transaction (the matrix only calls the hook directly): a dirty word
    ///      whose low bits are the guard is `FallbackHandlerNotAllowed(guard)`, the error naming the masked address.
    function test_T1e_class13_S3_through_a_real_transaction() public {
        vm.store(address(safe), FALLBACK_SLOT, _w(address(guard), 0xdead));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FallbackHandlerNotAllowed.selector, address(guard)));
        _execSafeTx(address(protocol), 0, settle, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FallbackHandlerNotAllowed.selector, address(guard)));
        guard.validateTransaction(address(safe), address(protocol), 0, settle, Operation.Call);
        // the approval branch of the same Safe: the masked rail, ForwardedHookCall, hook and dry run alike
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, settle, Operation.Call, uint64(1 days));
        vm.expectRevert(CuratorGuard.ForwardedHookCall.selector);
        _execSafeTx(address(protocol), 0, settle, Operation.Call);
        vm.expectRevert(CuratorGuard.ForwardedHookCall.selector);
        guard.validateTransaction(address(safe), address(protocol), 0, settle, Operation.Call);
    }

    /// T2: the policy path cannot write the slot at all (so a mid-transaction plant is unreachable there): a
    ///     delegatecall to a writer, the self-call and a batch entry self-call are refused before execution.
    function test_T2_the_policy_path_cannot_write_the_handler_slot() public {
        bytes memory _plant = abi.encodeCall(G19eWriter.write, (FALLBACK_SLOT, _w(address(H), 0xdead)));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.DelegateCallNotAllowed.selector, address(writer)));
        _execSafeTx(address(writer), 0, _plant, Operation.DelegateCall);
        bytes memory _self = abi.encodeWithSignature("setFallbackHandler(address)", address(H));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, bytes4(0xf08a0323)));
        _execSafeTx(address(safe), 0, _self, Operation.Call);
        _registerUnwrapper(address(multiSendCallOnly));
        bytes memory _batch = _multiSendCalldata(bytes.concat(_entry(address(protocol), 0, settle), _entry(address(safe), 0, _self)));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, bytes4(0xf08a0323)));
        _execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
        assertEq(bytes32(safe.getStorageAt(uint256(FALLBACK_SLOT), 1)), bytes32(uint256(uint160(address(H)))), "untouched");
    }

    /// T2b: where the slot CAN be written (an admin-approved delegatecall) the digest is not consulted (an
    ///      Approval report), and the next policy transaction tolerates the dirty required word (T1c on chain).
    function test_T2b_an_approved_plant_is_reported_as_Approval_and_the_next_policy_transaction_tolerates_it() public {
        bytes memory _plant = abi.encodeCall(G19eWriter.write, (FALLBACK_SLOT, _w(address(H), 0xdead)));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(writer), 0, _plant, Operation.DelegateCall, uint64(1 days));
        vm.recordLogs();
        assertTrue(_execSafeTx(address(writer), 0, _plant, Operation.DelegateCall), "approved plant lands");
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_reports(_logs), 1);
        assertEq(bytes32(safe.getStorageAt(uint256(FALLBACK_SLOT), 1)), _w(address(H), 0xdead), "dirty word in the slot");
        vm.recordLogs();
        assertTrue(_execSafeTx(address(protocol), 0, settle, Operation.Call), "policy transaction served on the dirty required word");
        assertEq(_reports(vm.getRecordedLogs()), 1);
    }

    /// T3: the other raw compare: `_requireInstalled` reads the GUARD slot raw. A dirty guard word (low bits this
    ///     guard) planted by an approved delegatecall: the Safe still calls this guard (the EVM masks the target),
    ///     the pre-hook answers `GuardNotInstalled` in every mode, windows and approvals included (the rail runs
    ///     first): fail closed to a full stop, repairable by nothing the Safe can execute. Not a widening; the
    ///     admin who approves such a delegatecall could approve `setGuard(anything)` as well.
    function test_T3_a_dirty_guard_slot_word_fails_closed_everywhere() public {
        bytes memory _plant = abi.encodeCall(G19eWriter.write, (GUARD_SLOT, _w(address(guard), 0xdead)));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(writer), 0, _plant, Operation.DelegateCall, uint64(1 days));
        assertTrue(_execSafeTx(address(writer), 0, _plant, Operation.DelegateCall), "approved plant lands");
        assertEq(bytes32(safe.getStorageAt(uint256(GUARD_SLOT), 1)), _w(address(guard), 0xdead));
        assertEq(_installedGuard(), address(guard), "the low 160 bits still name this guard");
        // Enforced
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardNotInstalled.selector, address(safe)));
        _execSafeTx(address(protocol), 0, settle, Operation.Call);
        // a council window
        vm.prank(council);
        guard.bypass(address(safe), 1 days);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardNotInstalled.selector, address(safe)));
        _execSafeTx(address(protocol), 0, settle, Operation.Call);
        // an admin window
        vm.prank(vetro);
        guard.bypass(address(safe), 1 days);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardNotInstalled.selector, address(safe)));
        _execSafeTx(address(protocol), 0, settle, Operation.Call);
        vm.prank(vetro);
        guard.enforce(address(safe));
        // an admin approval of the repair itself
        bytes memory _repair = abi.encodeCall(ISafe.setGuard, (address(guard)));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(safe), 0, _repair, Operation.Call, uint64(1 days));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardNotInstalled.selector, address(safe)));
        _execSafeTx(address(safe), 0, _repair, Operation.Call);
        // the dry run does not model the installed-slot check (NatSpec): it answers as if installed
        guard.validateTransaction(address(safe), address(protocol), 0, settle, Operation.Call);
        // control: the clean word (what no Safe transaction can restore) serves again
        vm.store(address(safe), GUARD_SLOT, bytes32(uint256(uint160(address(guard)))));
        assertTrue(_execSafeTx(address(protocol), 0, settle, Operation.Call));
    }
}

/// @title Review g19e: the module-guard slot on a hooked v1.5.0 Safe (B of the matrix fixture) read raw: a dirty
///        module-guard word (low bits this guard) is `ModuleNotHooked` on the owner path and `GuardNotInstalled`
///        on the module path, while the Safe does call this guard's module hooks. Fail closed both ways.
contract G19e_DirtyModuleGuardWordTest is G12eMatrixBase {
    bytes32 internal constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    function test_T4_dirty_module_guard_word_on_v150_fails_closed_on_both_paths() public {
        _setState(3);
        // control: hooked, both paths served
        safe = safeB;
        signerPk = pkB;
        assertTrue(_execSafeTx(address(P), 0, SETTLE1, Operation.Call), "owner path served (control)");
        vm.prank(address(MOD));
        assertTrue(safeB.execTransactionFromModule(address(P), 0, SETTLE1, Operation.Call), "module path served (control)");
        // the dirty module-guard word
        vm.store(address(safeB), MODULE_GUARD_SLOT, bytes32((uint256(0xdead) << 160) | uint256(uint160(address(g)))));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ModuleNotHooked.selector, address(MODX)));
        _execSafeTx(address(P), 0, SETTLE1, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ModuleNotHooked.selector, address(MODX)));
        g.validateTransaction(address(safeB), address(P), 0, SETTLE1, Operation.Call);
        vm.prank(address(MOD));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardNotInstalled.selector, address(safeB)));
        safeB.execTransactionFromModule(address(P), 0, SETTLE1, Operation.Call);
    }
}
