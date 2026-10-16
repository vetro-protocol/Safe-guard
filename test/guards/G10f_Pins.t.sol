// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";
import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @title Round 10 (g10f): killers for the mutants that survived the suite as shipped (second pass).
/// @dev   Every test passes on the current code and fails under the mutant named in its NatSpec
///        (the round-10 mutation results, kept with the review material). None of them is a defect: each pins a
///        documented behaviour the tree asserted nowhere.
/// @dev A role holder that answers `getStorageAt` with TWO words whose first is the guard's address:
///      not a Safe-shaped answer, so the forwarding probe must not take it for a forwarding Safe.
contract G10fTwoWordAnswer {
    address internal immutable guard;

    constructor(address guard_) {
        guard = guard_;
    }

    function getStorageAt(uint256, uint256) external view returns (bytes memory) {
        return abi.encodePacked(bytes32(uint256(uint160(guard))), bytes32(0));
    }

    function lockdown(address safe_) external {
        CuratorGuard(guard).lockdown(safe_);
    }
}

contract CuratorGuardG10fPinsTest is CuratorGuardTestBase {
    event NativeTransferUpdated(address indexed safe, address indexed target, bool allowed);
    event MultiSendUnwrapperUpdated(address indexed safe, address indexed multiSend, bool allowed);
    event AllowedValueRemoved(address indexed safe, address indexed target, bytes4 indexed selector, uint16 wordIndex, bytes32 value);

    bytes32 internal constant NATIVE_SIG = keccak256("NativeTransferUpdated(address,address,bool)");

    /// @dev A second real Safe v1.4.1 (1-of-1, no handler).
    function _newSafe(string memory name_) internal returns (ISafe _safe) {
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = makeAddr(name_);
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        _safe = ISafe(address(_proxy));
    }

    function _setHandler(ISafe safe_, address handler_) internal {
        vm.prank(address(safe_));
        (bool _ok, ) = address(safe_).call(abi.encodeWithSignature("setFallbackHandler(address)", handler_));
        assertTrue(_ok, "setFallbackHandler");
    }

    /// @dev X-41: `_checkAdmin` (every admin-only setter) refuses a forwarded caller too. An admin that is
    ///      a Safe with this guard in its handler slot forwards anyone's `allowFunction` with itself as the
    ///      caller: refused, nothing widened; the same Safe widens once its handler is gone. (Production's
    ///      admin is the timelock, which forwards nothing: this is the rail's own pin.)
    function test_an_admin_safe_whose_handler_is_the_guard_gives_a_stranger_no_admin_action() public {
        ISafe _dao = _newSafe("dao-owner");
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(address(_dao));
        vm.warp(block.timestamp + 1);
        vm.prank(address(_dao));
        guard.acceptDefaultAdminTransfer();
        assertEq(guard.defaultAdmin(), address(_dao));
        _setHandler(_dao, address(guard));
        bytes memory _widen = abi.encodeCall(
            guard.allowFunction,
            (address(safe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules())
        );
        vm.prank(attacker);
        (bool _ok, bytes memory _ret) = address(_dao).call(_widen);
        assertFalse(_ok, "forwarded admin action refused");
        assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector);
        assertFalse(_isAllowed(address(safe), address(protocol), MockProtocol.settleDeposit.selector), "nothing widened");
        vm.prank(attacker);
        (_ok, _ret) = address(_dao).call(abi.encodeCall(guard.setRequiredFallbackHandler, (address(safe), address(0), true)));
        assertFalse(_ok);
        assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector);
        _setHandler(_dao, address(0));
        vm.prank(address(_dao));
        guard.allowFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules());
        assertTrue(_isAllowed(address(safe), address(protocol), MockProtocol.settleDeposit.selector));
    }

    /// @dev X-45: the forwarding probe needs a Safe-shaped answer (exactly one word); a role holder whose
    ///      `getStorageAt` answers two words, the first being this guard, is an ordinary caller.
    function test_the_forwarding_probe_needs_a_safe_shaped_answer() public {
        G10fTwoWordAnswer _holder = new G10fTwoWordAnswer(address(guard));
        bytes32 _councilRole = guard.COUNCIL_ROLE();
        vm.prank(vetro);
        guard.grantRole(_councilRole, address(_holder));
        _enforce();
        _holder.lockdown(address(safe));
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
    }

    /// @dev X-21: `setDeploymentGuardian` refuses the zero address in both directions (a revoke of
    ///      `address(0)` is a typo, not a no-op).
    function test_setDeploymentGuardian_refuses_the_zero_address_in_both_directions() public {
        vm.prank(vetro);
        vm.expectRevert(CuratorGuardPolicy.AddressIsNull.selector);
        guard.setDeploymentGuardian(address(0), true);
        vm.prank(vetro);
        vm.expectRevert(CuratorGuardPolicy.AddressIsNull.selector);
        guard.setDeploymentGuardian(address(0), false);
    }

    /// @dev H-NT1 (no event), H-NT3 (event always `true`): `setNativeTransferAllowed` reports the new state
    ///      in `NativeTransferUpdated`, in both directions, and `targets` follows it.
    function test_native_transfer_setter_reports_the_new_state() public {
        vm.expectEmit(true, true, true, true, address(guard));
        emit NativeTransferUpdated(address(safe), address(protocol), true);
        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), address(protocol), true);
        assertTrue(guard.isNativeTransferAllowed(address(safe), address(protocol)));
        assertEq(guard.targets(address(safe)).length, 1);
        assertEq(guard.targets(address(safe))[0], address(protocol));

        vm.expectEmit(true, true, true, true, address(guard));
        emit NativeTransferUpdated(address(safe), address(protocol), false);
        vm.prank(council);
        guard.setNativeTransferAllowed(address(safe), address(protocol), false);
        assertFalse(guard.isNativeTransferAllowed(address(safe), address(protocol)));
        assertEq(guard.targets(address(safe)).length, 0, "pruned once nothing is allowed on the target");
    }

    /// @dev F-RU2 (on the held G9c-1 change): a role GRANT reads admin-written state only, so the council
    ///      may also hold the deployment-wide guardian role (narrow-only, harmless) and a re-grant of the
    ///      council role is a no-op; only the admin's succession refuses the council.
    function test_a_role_grant_never_reads_the_council_term() public {
        bytes32 _guardianRole = guard.GUARDIAN_ROLE();
        bytes32 _councilRole = guard.COUNCIL_ROLE();
        vm.prank(vetro);
        guard.setDeploymentGuardian(council, true);
        assertTrue(guard.hasRole(_guardianRole, council));
        vm.prank(vetro);
        guard.grantRole(_councilRole, council); // already held: no change, no revert
        assertTrue(guard.hasRole(_councilRole, council));
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, council));
        guard.beginDefaultAdminTransfer(council);
    }

    /// @dev PB055T / PB055O1 / PB055O2: `addAllowedValues` needs a `OneOf` rule on THAT word: a function
    ///      whose only rule on the word is `EqualTo`, or whose `OneOf` sits on another word, refuses.
    function test_addAllowedValues_needs_a_OneOf_rule_on_that_word() public {
        bytes32[] memory _values = new bytes32[](1);
        _values[0] = _word(address(protocol));
        _allowWithRules(address(protocol), MockProtocol.deposit.selector, _rule(CuratorGuardPolicy.RuleKind.EqualTo, 0, _word(address(protocol))));
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.NoOneOfRule.selector, uint16(0)));
        guard.addAllowedValues(address(safe), address(protocol), MockProtocol.deposit.selector, 0, _values);
        _allowWithRules(address(protocol), MockProtocol.deposit.selector, _rule(CuratorGuardPolicy.RuleKind.OneOf, 1, 0));
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.NoOneOfRule.selector, uint16(0)));
        guard.addAllowedValues(address(safe), address(protocol), MockProtocol.deposit.selector, 0, _values);
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(protocol), MockProtocol.deposit.selector, 1, _values);
        assertEq(guard.allowedValues(address(safe), address(protocol), MockProtocol.deposit.selector, 1).length, 1);
    }

    /// @dev PB056O2: a re-allow whose `OneOf` rule moved to another word clears the old word's set (one
    ///      `AllowedValueRemoved` per member, ahead of `FunctionAllowed`), and the new word starts empty.
    function test_a_reallow_clears_the_set_of_the_word_whose_OneOf_rule_moved() public {
        bytes32[] memory _values = new bytes32[](2);
        _values[0] = _word(address(protocol));
        _values[1] = _word(address(token));
        _allowWithRules(address(protocol), MockProtocol.deposit.selector, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(protocol), MockProtocol.deposit.selector, 0, _values);
        vm.recordLogs();
        _allowWithRules(address(protocol), MockProtocol.deposit.selector, _rule(CuratorGuardPolicy.RuleKind.OneOf, 1, 0));
        uint256 _removed;
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        for (uint256 i; i < _logs.length; ++i) {
            if (_logs[i].topics[0] == keccak256("AllowedValueRemoved(address,address,bytes4,uint16,bytes32)")) ++_removed;
        }
        assertEq(_removed, 2, "both members of the moved word removed");
        assertEq(guard.allowedValues(address(safe), address(protocol), MockProtocol.deposit.selector, 0).length, 0);
        assertEq(guard.allowedValues(address(safe), address(protocol), MockProtocol.deposit.selector, 1).length, 0);
    }

    /// @dev PB058O1 / PB058O2 / PB058T: `targets` keeps a target that still carries a function or the
    ///      native permission after a revocation; it goes once nothing is left.
    function test_pruneTarget_keeps_a_target_that_still_carries_something() public {
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        _allow(address(protocol), MockProtocol.deposit.selector);
        vm.prank(vetro);
        guard.revokeFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector);
        assertEq(guard.targets(address(safe)).length, 1, "one function left");
        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), address(protocol), true);
        vm.prank(vetro);
        guard.revokeFunction(address(safe), address(protocol), MockProtocol.deposit.selector);
        assertEq(guard.targets(address(safe)).length, 1, "the native permission is left");
        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), address(protocol), false);
        assertEq(guard.targets(address(safe)).length, 0, "nothing left");
    }

    /// @dev PB010T: `revokeTarget` reports the native permission only when it was on.
    function test_revokeTarget_reports_the_native_permission_only_when_it_was_on() public {
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        vm.recordLogs();
        vm.prank(vetro);
        guard.revokeTarget(address(safe), address(protocol));
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        for (uint256 i; i < _logs.length; ++i) assertTrue(_logs[i].topics[0] != NATIVE_SIG, "no native event without the permission");
        assertEq(guard.targets(address(safe)).length, 0);
        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), address(protocol), true);
        vm.expectEmit(true, true, true, true, address(guard));
        emit NativeTransferUpdated(address(safe), address(protocol), false);
        vm.prank(vetro);
        guard.revokeTarget(address(safe), address(protocol));
        assertFalse(guard.isNativeTransferAllowed(address(safe), address(protocol)));
    }

    /// @dev PB018F / PB018T: `MultiSendUnwrapperUpdated` fires on a change only (V2-96), both ways.
    function test_setMultiSendUnwrapper_reports_changes_only() public {
        _seedCodehash(address(multiSendCallOnly).codehash);
        vm.expectEmit(true, true, true, true, address(guard));
        emit MultiSendUnwrapperUpdated(address(safe), address(multiSendCallOnly), true);
        vm.prank(vetro);
        guard.setMultiSendUnwrapper(address(safe), address(multiSendCallOnly), true);
        vm.recordLogs();
        vm.prank(vetro);
        guard.setMultiSendUnwrapper(address(safe), address(multiSendCallOnly), true);
        assertEq(vm.getRecordedLogs().length, 0, "no-op registration: no event");
        vm.expectEmit(true, true, true, true, address(guard));
        emit MultiSendUnwrapperUpdated(address(safe), address(multiSendCallOnly), false);
        vm.prank(council);
        guard.setMultiSendUnwrapper(address(safe), address(multiSendCallOnly), false);
        vm.recordLogs();
        vm.prank(council);
        guard.setMultiSendUnwrapper(address(safe), address(multiSendCallOnly), false);
        assertEq(vm.getRecordedLogs().length, 0, "no-op removal: no event");
    }

    /// @dev GB032O1: only an approved DELEGATECALL into canonical `MultiSendCallOnly` code is decoded at
    ///      use; an approved plain call to that same code stays unparsed (a single-call approval), in the
    ///      dry run and in the live hook.
    function test_a_single_call_approval_into_canonical_code_stays_unparsed() public {
        _enforce();
        _seedCodehash(address(multiSendCallOnly).codehash);
        bytes memory _garbage = abi.encodeWithSelector(_H().multiSendSelector(), uint256(0x40), uint256(1), uint256(0));
        _approve(address(multiSendCallOnly), 0, _garbage, Operation.Call);
        guard.validateTransaction(address(safe), address(multiSendCallOnly), 0, _garbage, Operation.Call);
        vm.prank(address(safe));
        guard.checkTransaction(address(multiSendCallOnly), 0, _garbage, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", curator);
        assertEq(guard.approvalExpiry(guard.computeApprovalId(address(safe), address(0), address(multiSendCallOnly), 0, _garbage, Operation.Call)), 0, "consumed");
        vm.prank(address(safe));
        guard.checkAfterExecution(bytes32(0), true);
        // The same bytes as an approved DELEGATECALL are decoded and refused.
        _approve(address(multiSendCallOnly), 0, _garbage, Operation.DelegateCall);
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        guard.validateTransaction(address(safe), address(multiSendCallOnly), 0, _garbage, Operation.DelegateCall);
    }
}

/// @dev Timelock rails whose fall-through arms nothing exercised (TB005O1, TB008O1, TB010O1, TB017O1,
///      TB021O1, TB022O2): the base's length error for a short payload list, a foreign `updateDelay`
///      payload, a value-only operation to a key, and three role no-ops.
contract CuratorGuardG10fTimelockPinsTest is CuratorGuardTestBase {
    CuratorGuardTimelock internal tl;
    address internal proposer = makeAddr("proposer");
    address internal veto = makeAddr("veto");

    function _ops() internal returns (CuratorGuardTimelock) {
        address[] memory _p = new address[](1);
        _p[0] = proposer;
        address[] memory _c = new address[](1);
        _c[0] = veto;
        return new CuratorGuardTimelock(1 days, _p, _c);
    }

    function _run(address target_, uint256 value_, bytes memory data_, bytes32 salt_) internal {
        vm.prank(proposer);
        tl.schedule(target_, value_, data_, bytes32(0), salt_, 1 days);
        vm.warp(block.timestamp + 1 days);
        tl.execute(target_, value_, data_, bytes32(0), salt_);
    }

    function test_timelock_rails_fall_through_arms() public {
        tl = _ops();
        // TB005O1: fewer payloads than targets is the base contract's typed error, not a Panic.
        address[] memory _targets = new address[](2);
        _targets[0] = address(protocol);
        _targets[1] = address(protocol);
        uint256[] memory _values = new uint256[](2);
        bytes[] memory _payloads = new bytes[](1);
        _payloads[0] = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.prank(proposer);
        vm.expectRevert(abi.encodeWithSignature("TimelockInvalidOperationLength(uint256,uint256,uint256)", 2, 1, 2));
        tl.scheduleBatch(_targets, _values, _payloads, bytes32(0), bytes32(0), 1 days);
        // TB008O1: the updateDelay clamp applies to the timelock's own payload only; a venue's
        // `updateDelay(uint256)`-shaped call with a value outside the clamp is schedulable.
        vm.prank(proposer);
        tl.schedule(address(protocol), 0, abi.encodeWithSelector(tl.updateDelay.selector, uint256(0)), bytes32(0), bytes32("foreign"), 1 days);
        // TB010O1: a value-only operation to a key executes (the no-code rail is about calldata).
        address _key = makeAddr("payee");
        vm.deal(address(tl), 1 ether);
        _run(_key, 0.5 ether, "", bytes32("pay"));
        assertEq(_key.balance, 0.5 ether);
        // TB017O1: the separation rail is about PROPOSER_ROLE; a canceller may hold the executor role.
        _run(address(tl), 0, abi.encodeCall(tl.grantRole, (tl.EXECUTOR_ROLE(), veto)), bytes32("exec"));
        assertTrue(tl.hasRole(tl.EXECUTOR_ROLE(), veto));
        // TB021O1 / TB022O2: revoking a gated role from address(0), or the admin role from an account
        // that never held it, is a no-op, not a rail violation.
        _run(address(tl), 0, abi.encodeCall(tl.revokeRole, (tl.PROPOSER_ROLE(), address(0))), bytes32("zero"));
        _run(address(tl), 0, abi.encodeCall(tl.revokeRole, (tl.DEFAULT_ADMIN_ROLE(), proposer)), bytes32("admin"));
        assertEq(tl.proposerCount(), 1);
        assertTrue(tl.hasRole(tl.DEFAULT_ADMIN_ROLE(), address(tl)));
    }
}
