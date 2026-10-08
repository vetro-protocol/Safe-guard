// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

/// @dev Minimal Safe module: whoever calls `exec` makes the Safe execute the payload.
contract DummyModule {
    function exec(ISafe safe_, address to_, uint256 value_, bytes calldata data_, Operation op_) external returns (bool) {
        return safe_.execTransactionFromModule(to_, value_, data_, op_);
    }
}

/// @title CuratorGuard module-guard tests (real Safe v1.5.0)
/// @notice v1.5.0 adds `setModuleGuard` + `IModuleGuard`; the guard holds module transactions to
///         the same per-Safe policy, gated by an explicit module allowlist.
contract CuratorGuardModuleTest is SafeTxHelper {
    CuratorGuard internal guard;
    DummyModule internal module;
    MockProtocol internal protocol;

    address internal vetro = makeAddr("vetro");


    address internal council = makeAddr("council");
    address internal attacker = makeAddr("attacker");
    address internal curator;

    bytes32 internal constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    function setUp() public {
        vm.warp(1_700_000_000); // a realistic time: Foundry's default timestamp of 1 sits inside the lockdown cooldown
        (curator, signerPk) = makeAddrAndKey("curator");
        Safe150 _singleton = new Safe150();
        SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        safe = ISafe(address(_proxy));

        guard = new CuratorGuardHarness(0, vetro, council);
        CuratorGuardHarness(address(guard)).seedSafe(address(safe)); // locally compiled Safe build: seeded, the guard pins canonical Safe code (V2-85)
        module = new DummyModule();
        protocol = new MockProtocol();

        // Self-authorized admin calls, impersonating the Safe (equivalent to pre-guard execTransactions).
        vm.startPrank(address(safe));
        safe.enableModule(address(module));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        vm.stopPrank();
        assertTrue(safe.isModuleEnabled(address(module)));
        assertEq(address(uint160(uint256(bytes32(safe.getStorageAt(uint256(MODULE_GUARD_SLOT), 1))))), address(guard));

        vm.prank(vetro);
        guard.enforce(address(safe));
        vm.prank(vetro);
        guard.allowFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules());
    }

    function test_module_not_allowlisted_is_rejected() public {
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module)));
        module.exec(safe, address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
    }

    function test_allowlisted_module_is_held_to_the_policy() public {
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(module), true);
        assertEq(guard.modules(address(safe))[0], address(module));
        assertEq(guard.modules(address(safe)).length, 1);

        assertTrue(module.exec(safe, address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (3)), Operation.Call));
        assertEq(protocol.lastAmount(), 3);

        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector)
        );
        module.exec(safe, address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (1, attacker)), Operation.Call);

        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, ISafe.setModuleGuard.selector));
        module.exec(safe, address(safe), 0, abi.encodeCall(ISafe.setModuleGuard, (address(0))), Operation.Call);

        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.DelegateCallNotAllowed.selector, attacker));
        module.exec(safe, attacker, 0, "", Operation.DelegateCall);
    }

    function test_module_path_respects_lockdown_and_bypass() public {
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(module), true);
        vm.prank(vetro);
        guard.lockdown(address(safe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        module.exec(safe, address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);

        vm.warp(block.timestamp + 1 days + 1); // the admin waits out the lockdown cooldown
        vm.prank(vetro);
        guard.bypass(address(safe), 1 days);
        assertTrue(module.exec(safe, address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (1, attacker)), Operation.Call));
    }

    function test_module_path_honours_an_approval_bound_to_the_module() public {
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(module), true);
        bytes memory _data = abi.encodeCall(MockProtocol.deposit, (1, attacker));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(module), address(protocol), 0, _data, Operation.Call, uint64(1 hours));
        guard.validateModuleTransaction(address(safe), address(module), address(protocol), 0, _data, Operation.Call);
        assertTrue(module.exec(safe, address(protocol), 0, _data, Operation.Call));
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector)
        );
        module.exec(safe, address(protocol), 0, _data, Operation.Call);
    }

    function test_approvals_are_bound_to_their_execution_path() public {
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(module), true);
        bytes memory _data = abi.encodeCall(MockProtocol.deposit, (1, attacker));
        // Owner-path approval: the module cannot spend it.
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, uint64(1 hours));
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector)
        );
        module.exec(safe, address(protocol), 0, _data, Operation.Call);
        // The signers can.
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call));

        // Module-bound approval: the signers cannot spend it.
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(module), address(protocol), 0, _data, Operation.Call, uint64(1 hours));
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector)
        );
        _execSafeTx(address(protocol), 0, _data, Operation.Call);
        assertTrue(module.exec(safe, address(protocol), 0, _data, Operation.Call));
    }

    /// @dev V2-75: a module-bound approval lets an allowlisted module run exactly that payload once; a
    ///      module off the allowlist spends no approval (a guardian's `setModuleAllowed(false)` is a
    ///      complete switch for that key), live and in the dry run.
    function test_module_bound_approval_requires_the_module_allowlist_at_use() public {
        bytes memory _data = abi.encodeCall(MockProtocol.deposit, (9, attacker)); // not policy-allowed
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(module), address(protocol), 0, _data, Operation.Call, uint64(1 hours));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module)));
        module.exec(safe, address(protocol), 0, _data, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module)));
        guard.validateModuleTransaction(address(safe), address(module), address(protocol), 0, _data, Operation.Call);
        assertGt(guard.approvalExpiry(_id), 0, "not consumed");
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(module), true);
        guard.validateModuleTransaction(address(safe), address(module), address(protocol), 0, _data, Operation.Call);
        assertTrue(module.exec(safe, address(protocol), 0, _data, Operation.Call));
        assertEq(guard.approvalExpiry(_id), 0, "consumed");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector));
        module.exec(safe, address(protocol), 0, _data, Operation.Call);
        // The guardian's removal of a module also disarms an approval issued while it was allowlisted.
        address _guardian = makeAddr("guardian");
        vm.prank(vetro);
        guard.setGuardian(address(safe), _guardian, true);
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(module), true);
        vm.prank(council);
        _id = guard.approveTransaction(address(safe), address(module), address(protocol), 0, _data, Operation.Call, uint64(1 hours));
        vm.prank(_guardian);
        guard.setModuleAllowed(address(safe), address(module), false);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module)));
        module.exec(safe, address(protocol), 0, _data, Operation.Call);
        assertGt(guard.approvalExpiry(_id), 0, "kept, inert until the module is allowed again");
    }

    function test_validateModuleTransaction_mirrors_live_check() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module)));
        guard.validateModuleTransaction(address(safe), address(module), address(protocol), 0, _data, Operation.Call);
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(module), true);
        guard.validateModuleTransaction(address(safe), address(module), address(protocol), 0, _data, Operation.Call);
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector)
        );
        guard.validateModuleTransaction(address(safe), address(module), address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (1, attacker)), Operation.Call);
    }

    /// @dev An approved owner-signed batch may trigger a policy-compliant module transaction
    ///      inside it: the two paths keep separate in-flight / snapshot slots.
    function test_module_transaction_nested_in_an_approved_owner_transaction() public {
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(module), true);
        bytes memory _inner = abi.encodeCall(MockProtocol.settleDeposit, (4));
        bytes memory _outer = abi.encodeCall(DummyModule.exec, (safe, address(protocol), 0, _inner, Operation.Call));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(module), 0, _outer, Operation.Call, uint64(1 hours));
        assertTrue(_execSafeTx(address(module), 0, _outer, Operation.Call));
        assertEq(protocol.lastAmount(), 4);
    }

    /// @dev The module path has no `safeTxGas`, so a failed module execution does reach the post-hook
    ///      with `success == false`. The guard then reverts (`ApprovedExecutionFailed`), which rolls the
    ///      consumption back atomically: a failed one-off never costs its approval, and there is no
    ///      restore state.
    function test_failed_approved_module_execution_reverts_and_keeps_the_approval() public {
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(module), true);
        bytes memory _data = abi.encodeCall(MockProtocol.wrap, ());
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(module), address(protocol), 1 ether, _data, Operation.Call, uint64(1 hours));
        uint64 _expiry = guard.approvalExpiry(_id);
        // The Safe holds no ETH: the module call fails; the post-hook reverts the whole module frame.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ApprovedExecutionFailed.selector, address(safe)));
        module.exec(safe, address(protocol), 1 ether, _data, Operation.Call);
        assertEq(guard.approvalExpiry(_id), _expiry, "approval untouched");
        // Fund the Safe: the retry consumes it exactly once.
        vm.deal(address(safe), 2 ether);
        assertTrue(module.exec(safe, address(protocol), 1 ether, _data, Operation.Call));
        assertEq(guard.approvalExpiry(_id), 0, "consumed");
        assertEq(protocol.lastValue(), 1 ether);
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.wrap.selector)
        );
        module.exec(safe, address(protocol), 1 ether, _data, Operation.Call);
    }

    function test_local_tx_hash_matches_safe_v150() public {
        // Advance the nonce first so the test pins NONCE_SLOT, not just the typehashes.
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call));
        assertEq(safe.nonce(), 1);
        SafeTx memory _t = SafeTx(address(protocol), 1, hex"deadbeef", Operation.Call, 7, 0, address(0), address(0));
        bytes32 _expected = safe.getTransactionHash(_t.to, _t.value, _t.data, _t.op, 7, 0, 0, address(0), address(0), safe.nonce());
        assertEq(_txHash(_t), _expected);
    }

    function test_owner_signed_path_still_guarded_on_v150() public {
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (5)), Operation.Call));
        assertEq(protocol.lastAmount(), 5);

        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, ISafe.setGuard.selector));
        _execSafeTx(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call);
    }

    function _noRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _rules) {}
}

contract SeqModule {
    struct Call {
        address to;
        uint256 value;
        bytes data;
        Operation op;
    }

    function exec(ISafe safe_, address to_, uint256 value_, bytes calldata data_, Operation op_) external returns (bool) {
        return safe_.execTransactionFromModule(to_, value_, data_, op_);
    }

    function execThenRevert(ISafe safe_, address to_, uint256 value_, bytes calldata data_, Operation op_) external {
        safe_.execTransactionFromModule(to_, value_, data_, op_);
        revert("after module exec");
    }

    function execMany(ISafe safe_, Call[] calldata calls_) external returns (bool ok) {
        ok = true;
        for (uint256 i; i < calls_.length; ++i) {
            ok = safe_.execTransactionFromModule(calls_[i].to, calls_[i].value, calls_[i].data, calls_[i].op) && ok;
        }
    }
}

/// @title Module-path edge cases (real Safe v1.5.0): module guard alone, snapshot and in-flight
///        slots per path, evaluation order.
contract CuratorGuardModulePathsTest is SafeTxHelper {
    CuratorGuard internal guard;
    SeqModule internal module;
    MockProtocol internal protocol;
    address internal vetro = makeAddr("vetro");

    address internal council = makeAddr("council");
    address internal attacker = makeAddr("attacker");
    address internal curator;
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    function _deploy() internal {
        vm.warp(1_700_000_000); // a realistic time: Foundry's default timestamp of 1 sits inside the lockdown cooldown
        (curator, signerPk) = makeAddrAndKey("curator");
        Safe150 _singleton = new Safe150();
        SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        safe = ISafe(address(_proxy));
        guard = new CuratorGuardHarness(0, vetro, council);
        CuratorGuardHarness(address(guard)).seedSafe(address(safe)); // locally compiled Safe build: seeded, the guard pins canonical Safe code (V2-85)
        module = new SeqModule();
        protocol = new MockProtocol();
        vm.prank(address(safe));
        safe.enableModule(address(module));
        vm.startPrank(vetro);
        guard.enforce(address(safe));
        guard.allowFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector, false, new CuratorGuardPolicy.ParamRule[](0));
        guard.setModuleAllowed(address(safe), address(module), true);
        vm.stopPrank();
    }

    /// @dev Module guard installed WITHOUT the transaction guard: modules are policed, signers are not.
    function test_module_guard_without_tx_guard_polices_modules_only() public {
        _deploy();
        vm.prank(address(safe));
        safe.setModuleGuard(address(guard));
        assertEq(address(uint160(uint256(bytes32(safe.getStorageAt(uint256(GUARD_SLOT), 1))))), address(0), "no tx guard");

        assertTrue(module.exec(safe, address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call));
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector)
        );
        module.exec(safe, address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (1, attacker)), Operation.Call);

        // Signers are unconstrained (expected: the install must set BOTH guards).
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (1, attacker)), Operation.Call));
        assertTrue(_execSafeTx(address(safe), 0, abi.encodeCall(ISafe.enableModule, (attacker)), Operation.Call));
        assertTrue(safe.isModuleEnabled(attacker));
    }

    /// @dev G34: the owner-path snapshot must not be overwritten by a module-path snapshot taken
    ///      AFTER an approved module transaction changed the configuration inside the same owner tx.
    ///      Sequence: A.pre (snapshot S0 @ path 0) -> module: approved `enableModule(x)` (no snapshot)
    ///      -> module: policy `settleDeposit` (snapshot S1 @ path 1) -> A.post must see S0 != now.
    function test_owner_snapshot_survives_a_later_module_path_snapshot() public {
        _deploy();
        vm.startPrank(address(safe));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        vm.stopPrank();

        bytes memory _enable = abi.encodeCall(ISafe.enableModule, (attacker));
        vm.startPrank(vetro);
        guard.approveTransaction(address(safe), address(module), address(safe), 0, _enable, Operation.Call, uint64(1 days));
        guard.allowFunction(address(safe), address(module), SeqModule.execMany.selector, false, new CuratorGuardPolicy.ParamRule[](0));
        vm.stopPrank();

        SeqModule.Call[] memory _calls = new SeqModule.Call[](2);
        _calls[0] = SeqModule.Call(address(safe), 0, _enable, Operation.Call);
        _calls[1] = SeqModule.Call(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (5)), Operation.Call);
        bytes memory _outer = abi.encodeCall(SeqModule.execMany, (safe, _calls));

        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(safe)));
        _execSafeTx(address(module), 0, _outer, Operation.Call);
        assertFalse(safe.isModuleEnabled(attacker), "rolled back");
    }

    /// @dev Path separation: an owner-path approval and a module-path approval in flight at once, the
    ///      inner (module) one failing. The inner post-hook reverts (`ApprovedExecutionFailed`), the
    ///      outer owner transaction carries `safeTxGas == 0`, so the whole Safe transaction reverts and
    ///      BOTH approvals are untouched; once the inner can succeed, both are consumed exactly once.
    function test_in_flight_state_is_kept_per_path() public {
        _deploy();
        vm.startPrank(address(safe));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        vm.stopPrank();

        bytes memory _inner = abi.encodeCall(MockProtocol.wrap, ());
        bytes memory _outer = abi.encodeCall(SeqModule.exec, (safe, address(protocol), 1 ether, _inner, Operation.Call)); // fails: no ETH
        vm.startPrank(vetro);
        bytes32 _modId = guard.approveTransaction(address(safe), address(module), address(protocol), 1 ether, _inner, Operation.Call, uint64(2 days));
        bytes32 _ownerId = guard.approveTransaction(address(safe), address(0), address(module), 0, _outer, Operation.Call, uint64(1 days));
        vm.stopPrank();
        uint64 _modExpiry = guard.approvalExpiry(_modId);
        uint64 _ownerExpiry = guard.approvalExpiry(_ownerId);

        // Safe v1.5.0 bubbles the inner revert reason when safeTxGas == 0 && gasPrice == 0.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ApprovedExecutionFailed.selector, address(safe)));
        _execSafeTx(address(module), 0, _outer, Operation.Call);
        assertEq(guard.approvalExpiry(_ownerId), _ownerExpiry, "owner approval untouched");
        assertEq(guard.approvalExpiry(_modId), _modExpiry, "module approval untouched");

        vm.deal(address(safe), 1 ether);
        assertTrue(_execSafeTx(address(module), 0, _outer, Operation.Call), "outer ok once the inner can pay");
        assertEq(guard.approvalExpiry(_ownerId), 0, "owner approval consumed");
        assertEq(guard.approvalExpiry(_modId), 0, "module approval consumed");
        // Both slots are clear: a fresh module tx is checked normally.
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(module), true);
        assertTrue(module.exec(safe, address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call));
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector)
        );
        module.exec(safe, address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (1, attacker)), Operation.Call);
    }

    /// @dev An outer approved owner transaction whose module reverts after a successful inner approved
    ///      module execution: with `safeTxGas == 0` the whole Safe transaction reverts (Safe v1.5.0
    ///      bubbles the inner revert reason where v1.4.1 says GS013), so BOTH approvals are untouched
    ///      (the inner consumption is rolled back with the revert); with `safeTxGas != 0` the owner
    ///      path refuses the approval outright.
    function test_outer_failure_rolls_back_the_inner_module_consumption() public {
        _deploy();
        vm.startPrank(address(safe));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        vm.stopPrank();
        bytes memory _inner = abi.encodeCall(MockProtocol.deposit, (1, attacker));
        bytes memory _outer = abi.encodeCall(SeqModule.execThenRevert, (safe, address(protocol), 0, _inner, Operation.Call));
        vm.startPrank(vetro);
        bytes32 _modId = guard.approveTransaction(address(safe), address(module), address(protocol), 0, _inner, Operation.Call, uint64(2 days));
        bytes32 _ownerId = guard.approveTransaction(address(safe), address(0), address(module), 0, _outer, Operation.Call, uint64(1 days));
        vm.stopPrank();
        uint64 _modExpiry = guard.approvalExpiry(_modId);
        uint64 _ownerExpiry = guard.approvalExpiry(_ownerId);
        // With `safeTxGas != 0` the Safe reports the failure instead of reverting: the post-hook reverts
        // the whole transaction itself (round 8, R8D-1: the pre-check no longer demands `safeTxGas == 0`).
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ApprovedExecutionFailed.selector, address(safe)));
        _execSafeTxWithGas(address(module), 0, _outer, Operation.Call, 300_000);
        vm.expectRevert(bytes("after module exec"));
        _execSafeTx(address(module), 0, _outer, Operation.Call);
        assertEq(guard.approvalExpiry(_modId), _modExpiry, "inner approval back (rolled back with the revert)");
        assertEq(guard.approvalExpiry(_ownerId), _ownerExpiry, "owner approval untouched");
    }

    /// @dev G04: evaluation order step 5 (module allowlist) before step 6 (Lockdown).
    function test_unlisted_module_under_lockdown_reports_ModuleNotAllowed() public {
        _deploy();
        vm.startPrank(address(safe));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        vm.stopPrank();
        vm.startPrank(vetro);
        guard.setModuleAllowed(address(safe), address(module), false);
        guard.lockdown(address(safe));
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module)));
        module.exec(safe, address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module)));
        guard.validateModuleTransaction(address(safe), address(module), address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
    }
}
