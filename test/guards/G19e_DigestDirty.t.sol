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

    /// @dev Exactly one report, of `outcome_` (the third indexed argument of `TransactionChecked`).
    function _assertReport(Vm.Log[] memory logs_, CuratorGuard.Outcome outcome_, string memory what_) internal view {
        assertEq(_reports(logs_), 1, what_);
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter == address(guard) && logs_[i].topics[0] == REPORT_SIG) assertEq(uint256(logs_[i].topics[3]), uint256(outcome_), what_);
        }
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

    /// T3: `_requireInstalled` reads the GUARD slot as the Safe does, by its low 160 bits (Quantstamp GUARD-4; it
    ///     compared the full word before, and a dirty word was a full stop: `GuardNotInstalled` in every mode,
    ///     windows and approvals included, repairable by nothing the Safe could execute). A dirty guard word (low
    ///     bits this guard) planted by an approved delegatecall: the Safe still calls this guard (the EVM masks the
    ///     target) and the guard answers as installed: the policy, both windows and the approval exit are served,
    ///     and an approved `setGuard(guard)` writes the clean word back. Not a widening: the low bits are what the
    ///     Safe calls, and a word whose low bits name another account is refused as before.
    function test_T3_a_dirty_guard_slot_word_is_read_as_the_safe_reads_it_and_stays_repairable() public {
        bytes memory _plant = abi.encodeCall(G19eWriter.write, (GUARD_SLOT, _w(address(guard), 0xdead)));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(writer), 0, _plant, Operation.DelegateCall, uint64(1 days));
        assertTrue(_execSafeTx(address(writer), 0, _plant, Operation.DelegateCall), "approved plant lands");
        assertEq(bytes32(safe.getStorageAt(uint256(GUARD_SLOT), 1)), _w(address(guard), 0xdead));
        assertEq(_installedGuard(), address(guard), "the low 160 bits still name this guard");
        // Enforced: the policy lane is served
        vm.recordLogs();
        assertTrue(_execSafeTx(address(protocol), 0, settle, Operation.Call), "policy lane served on the dirty word");
        _assertReport(vm.getRecordedLogs(), CuratorGuard.Outcome.Policy, "a Policy report");
        // a council window
        vm.prank(council);
        guard.bypass(address(safe), 1 days);
        assertTrue(_execSafeTx(address(protocol), 0, settle, Operation.Call), "council window served");
        _assertReport(vm.getRecordedLogs(), CuratorGuard.Outcome.Bypass, "the council window, not the policy, served it");
        // an admin window
        vm.prank(vetro);
        guard.bypass(address(safe), 1 days);
        assertTrue(_execSafeTx(address(protocol), 0, settle, Operation.Call), "admin window served");
        _assertReport(vm.getRecordedLogs(), CuratorGuard.Outcome.Bypass, "the admin window, not the policy, served it");
        vm.prank(vetro);
        guard.enforce(address(safe));
        // an admin approval of the repair itself: the exit the full-word compare closed
        bytes memory _repair = abi.encodeCall(ISafe.setGuard, (address(guard)));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(safe), 0, _repair, Operation.Call, uint64(1 days));
        vm.recordLogs();
        assertTrue(_execSafeTx(address(safe), 0, _repair, Operation.Call), "approved repair lands");
        _assertReport(vm.getRecordedLogs(), CuratorGuard.Outcome.Approval, "an Approval report");
        assertEq(
            bytes32(safe.getStorageAt(uint256(GUARD_SLOT), 1)),
            bytes32(uint256(uint160(address(guard)))),
            "the Safe's own setGuard wrote the clean word"
        );
        assertTrue(_execSafeTx(address(protocol), 0, settle, Operation.Call), "served on the clean word");
        // control: a word whose LOW bits name another account is not this guard, whatever its high bits
        vm.store(address(safe), GUARD_SLOT, _w(address(0xBEEF), uint96(uint160(address(guard)))));
        vm.prank(address(safe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardNotInstalled.selector, address(safe)));
        guard.checkTransaction(address(protocol), 0, settle, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(this));
    }
}

/// @title Review g19e: dirty guard words on a hooked v1.5.0 Safe (B of the matrix fixture, two modules linked). A
///        dirty module-guard word (low bits this guard) is `ModuleNotHooked` on the policy lane of both paths (T4:
///        the configuration check compares the full word), while the Safe does call this guard's module hooks. The
///        installed-slot check reads the low 160 bits (Quantstamp GUARD-4), so the module hook answers and the
///        approval and admin-window exits of the module path stay open (T5; a council window leaves a module under
///        the policy). T6 is T3 on this build (a dirty transaction-guard word); T7 is the control on both slots (a
///        word whose low bits name another account).
contract G19e_DirtyModuleGuardWordTest is G12eMatrixBase {
    bytes32 internal constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;
    /// @dev `modules[SENTINEL_MODULES]`: `keccak256(abi.encode(address(1), uint256(1)))`.
    bytes32 internal constant MODULES_HEAD_SLOT = 0xcc69885fda6bcc1a4ace058b4a62bf5e179ea78fd58a1ccd71c22cc9b688792f;

    function test_T4_dirty_module_guard_word_on_v150_fails_closed_on_the_policy_lane_of_both_paths() public {
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
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ModuleNotHooked.selector, address(MODX)));
        safeB.execTransactionFromModule(address(P), 0, SETTLE1, Operation.Call);
    }

    function _w(address low_, uint96 h_) internal pure returns (bytes32) {
        return bytes32((uint256(h_) << 160) | uint256(uint160(low_)));
    }

    /// @dev Exactly one report of the guard under test, on `path_` (0 owner-signed, 1 module) with `outcome_`.
    function _assertReport(Vm.Log[] memory logs_, uint8 path_, CuratorGuard.Outcome outcome_) internal view {
        uint256 _n;
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter != address(g) || logs_[i].topics[0] != CuratorGuard.TransactionChecked.selector) continue;
            ++_n;
            assertEq(uint256(logs_[i].topics[3]), uint256(outcome_), "outcome");
            assertEq(abi.decode(logs_[i].data, (uint8)), path_, "path");
        }
        assertEq(_n, 1, "one report");
    }

    /// T5: the exits of the MODULE path on the dirty module-guard word of T4 (Quantstamp GUARD-4; the full-word
    ///     compare answered `GuardNotInstalled` to every module transaction, approved or inside an admin window):
    ///     the Safe calls this guard's module hooks, an approved module transaction is served and spent, an admin
    ///     window serves the module, and the owner-signed, approved `setModuleGuard(guard)` writes the clean word
    ///     back, after which the policy lane of both paths is served again.
    function test_T5_dirty_module_guard_word_on_v150_keeps_the_module_path_exits_and_is_repairable() public {
        _setState(3);
        safe = safeB;
        signerPk = pkB;
        vm.store(address(safeB), MODULE_GUARD_SLOT, _w(address(g), 0xdead));
        // the approval exit: `apprB` names (B, MOD, P, settleDeposit(9))
        vm.recordLogs();
        vm.prank(address(MOD));
        assertTrue(safeB.execTransactionFromModule(address(P), 0, SETTLE9, Operation.Call), "approved module transaction served");
        _assertReport(vm.getRecordedLogs(), 1, CuratorGuard.Outcome.Approval);
        assertEq(P.lastAmount(), 9, "executed");
        // spent: the same payload is on the policy lane again, which fails closed (T4)
        vm.prank(address(MOD));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ModuleNotHooked.selector, address(MODX)));
        safeB.execTransactionFromModule(address(P), 0, SETTLE9, Operation.Call);
        // the admin window exit
        vm.prank(vetro);
        g.bypass(address(safeB), uint64(1 days));
        vm.recordLogs();
        vm.prank(address(MOD));
        assertTrue(safeB.execTransactionFromModule(address(P), 0, SETTLE7, Operation.Call), "admin window serves the module");
        _assertReport(vm.getRecordedLogs(), 1, CuratorGuard.Outcome.Bypass);
        vm.prank(vetro);
        g.enforce(address(safeB));
        // the repair: owner-signed, approved by the admin
        bytes memory _repair = abi.encodeCall(ISafe.setModuleGuard, (address(g)));
        vm.prank(vetro);
        g.approveTransaction(address(safeB), address(0), address(safeB), 0, _repair, Operation.Call, uint64(1 days));
        vm.recordLogs();
        assertTrue(_execSafeTx(address(safeB), 0, _repair, Operation.Call), "approved repair lands");
        _assertReport(vm.getRecordedLogs(), 0, CuratorGuard.Outcome.Approval);
        assertEq(
            bytes32(safeB.getStorageAt(uint256(MODULE_GUARD_SLOT), 1)),
            bytes32(uint256(uint160(address(g)))),
            "the Safe's own setModuleGuard wrote the clean word"
        );
        vm.recordLogs();
        assertTrue(_execSafeTx(address(P), 0, SETTLE1, Operation.Call), "owner path: policy lane served on the clean word");
        _assertReport(vm.getRecordedLogs(), 0, CuratorGuard.Outcome.Policy);
        vm.recordLogs();
        vm.prank(address(MOD));
        assertTrue(safeB.execTransactionFromModule(address(P), 0, SETTLE1, Operation.Call), "module path: policy lane served on the clean word");
        _assertReport(vm.getRecordedLogs(), 1, CuratorGuard.Outcome.Policy);
    }

    /// T6: T3 on the v1.5.0 build: a dirty TRANSACTION-guard word (low bits this guard) on the hooked Safe B. The
    ///     policy lane, a council window (a call the policy does not allow, so the window is what serves it) and
    ///     the approved `setGuard(guard)` repair are served.
    function test_T6_dirty_guard_word_on_v150_is_read_as_the_safe_reads_it_and_stays_repairable() public {
        _setState(3);
        safe = safeB;
        signerPk = pkB;
        vm.store(address(safeB), GUARD_SLOT, _w(address(g), 0xdead));
        vm.recordLogs();
        assertTrue(_execSafeTx(address(P), 0, SETTLE1, Operation.Call), "policy lane served on the dirty word");
        _assertReport(vm.getRecordedLogs(), 0, CuratorGuard.Outcome.Policy);
        // a council window: `deposit` is not on B's allowlist
        bytes memory _deposit = abi.encodeCall(MockProtocol.deposit, (5, address(safeB)));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(P), DEPOSIT));
        _execSafeTx(address(P), 0, _deposit, Operation.Call);
        vm.prank(council);
        g.bypass(address(safeB), uint64(1 days));
        vm.recordLogs();
        assertTrue(_execSafeTx(address(P), 0, _deposit, Operation.Call), "council window served");
        _assertReport(vm.getRecordedLogs(), 0, CuratorGuard.Outcome.Bypass);
        vm.prank(council);
        g.enforce(address(safeB));
        // the approval exit: the repair itself
        bytes memory _repair = abi.encodeCall(ISafe.setGuard, (address(g)));
        vm.prank(vetro);
        g.approveTransaction(address(safeB), address(0), address(safeB), 0, _repair, Operation.Call, uint64(1 days));
        vm.recordLogs();
        assertTrue(_execSafeTx(address(safeB), 0, _repair, Operation.Call), "approved repair lands");
        _assertReport(vm.getRecordedLogs(), 0, CuratorGuard.Outcome.Approval);
        assertEq(
            bytes32(safeB.getStorageAt(uint256(GUARD_SLOT), 1)),
            bytes32(uint256(uint160(address(g)))),
            "the Safe's own setGuard wrote the clean word"
        );
        assertTrue(_execSafeTx(address(P), 0, SETTLE1, Operation.Call), "served on the clean word");
    }

    /// T7: the control of T5 and T6, per slot: a word whose LOW 160 bits do not name this guard is
    ///     `GuardNotInstalled` on that slot's path, whatever its high bits (this guard's address among them), with
    ///     a live approval (`apprB`, module path) and inside an admin window alike: the check still runs before
    ///     both exits. A Safe with such a word does not call this guard, so the hooks are called directly as the
    ///     Safe. The installed-slot check of a path reads its own slot only: the other path of the same Safe is
    ///     served (the owner path with the module-guard slot empty and no module linked, as its policy lane
    ///     compares that word in full).
    function test_T7_a_word_naming_another_account_is_GuardNotInstalled_on_its_own_path_only() public {
        bytes memory _err = abi.encodeWithSelector(CuratorGuard.GuardNotInstalled.selector, address(safeB));
        bytes32[6] memory _words = [
            _w(address(0xBEEF), uint96(uint160(address(g)))), // another account, this guard's low bytes above it
            bytes32(uint256(uint160(address(g))) << 96), // this guard's address in the HIGH 160 bits
            _w(address(0), type(uint96).max), // no guard, every high bit set
            bytes32(uint256(uint160(address(g))) ^ (1 << 159)), // one bit off, the highest of the address
            bytes32(uint256(uint160(address(g))) ^ 1), // one bit off, the lowest
            bytes32(uint256(uint160(address(safeB)))) // the Safe itself
        ];
        bytes32 _clean = bytes32(uint256(uint160(address(g))));
        safe = safeB;
        signerPk = pkB;
        for (uint8 _state = 3; _state <= 4; ++_state) {
            uint256 _snap = vm.snapshotState();
            _setState(_state);
            for (uint256 i; i < _words.length; ++i) {
                // the module-guard slot: the module path is refused, the approved payload included
                vm.store(address(safeB), MODULE_GUARD_SLOT, _words[i]);
                vm.prank(address(safeB));
                vm.expectRevert(_err);
                g.checkModuleTransaction(address(P), 0, SETTLE9, Operation.Call, address(MOD));
                vm.store(address(safeB), MODULE_GUARD_SLOT, _clean);
                // the transaction-guard slot: the owner path is refused
                vm.store(address(safeB), GUARD_SLOT, _words[i]);
                vm.prank(address(safeB));
                vm.expectRevert(_err);
                g.checkTransaction(address(P), 0, SETTLE1, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", curatorB);
                // ... and the module path of the same Safe, whose own slot is clean, is served
                vm.prank(address(MOD));
                assertTrue(safeB.execTransactionFromModule(address(P), 0, SETTLE1, Operation.Call), "module path reads its own slot");
                vm.store(address(safeB), GUARD_SLOT, _clean);
            }
            // the owner path with the module-guard slot EMPTY and no module linked is served (its own slot is clean)
            vm.store(address(safeB), MODULES_HEAD_SLOT, bytes32(uint256(1)));
            vm.store(address(safeB), MODULE_GUARD_SLOT, bytes32(0));
            assertTrue(_execSafeTx(address(P), 0, SETTLE1, Operation.Call), "owner path reads its own slot");
            vm.revertToState(_snap);
        }
    }
}
