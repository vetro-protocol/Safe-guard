// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {ISafeModuleGuard, ISafeTransactionGuard, Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {StrangersBase} from "test/guards/CuratorGuardStrangersBase.sol";

/// @dev A contract stranger: forwards any call so `msg.sender` is a contract with code.
contract Forwarder {
    function fwd(address target_, bytes calldata data_) external returns (bool _ok, bytes memory _ret) {
        (_ok, _ret) = target_.call(data_);
    }
}

/// @dev A stranger that calls the guard from its constructor (no code at `msg.sender` yet).
contract Constructing {
    uint256 public okCount;
    uint256 public firstOk = type(uint256).max;

    constructor(address guard_, bytes[] memory calls_) {
        for (uint256 i; i < calls_.length; ++i) {
            (bool _ok, ) = guard_.call(calls_[i]);
            if (_ok) {
                ++okCount;
                if (firstOk == type(uint256).max) firstOk = i;
            }
        }
    }
}

/// @title Round 8: the guard as a public contract. Every state-changing selector of the ABI (34 of 65)
///        called by every kind of caller that is not the honest, configured Safe or a role holder.
contract CuratorGuardStrangersTest is StrangersBase {
    bytes32 internal liveApprovalA;
    bytes32 internal liveApprovalB;
    address internal unconfiguredSafe;
    Forwarder internal forwarder;

    function setUp() public override {
        super.setUp();
        forwarder = new Forwarder();
        unconfiguredSafe = address(_newSafe(makeAddr("owner-of-unconfigured")));
        vm.deal(address(forwarder), 1 ether);
        // Live approvals on A and B so `revokeApproval` has something to bite on.
        liveApprovalA = _approve(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (7)), Operation.Call);
        vm.prank(vetro);
        liveApprovalB = guard.approveTransaction(address(safeB), address(0), address(protocolB), 0, abi.encodeCall(MockProtocol.settleDeposit, (7)), Operation.Call, 1 days);
        // One OneOf value set on A so the value-set mutators are not vacuous.
        vm.startPrank(vetro);
        guard.allowFunction(address(safe), address(protocol), DEPOSIT, false, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, bytes32(0)));
        bytes32[] memory _vals = new bytes32[](1);
        _vals[0] = bytes32(uint256(1));
        guard.addAllowedValues(address(safe), address(protocol), DEPOSIT, 0, _vals);
        vm.stopPrank();
    }

    /// @dev Every mutator of the ABI, each with arguments aimed at Safe A (or at deployment-wide
    ///      state), both branches of the widen/narrow setters. 40 calls over 34 selectors.
    function _mutators(address caller_) internal view returns (bytes[] memory _c) {
        _c = new bytes[](40);
        bytes32[] memory _vals = new bytes32[](1);
        _vals[0] = bytes32(uint256(1));
        CuratorGuardPolicy.FunctionSpec[] memory _specs = new CuratorGuardPolicy.FunctionSpec[](1);
        _specs[0] = CuratorGuardPolicy.FunctionSpec(address(protocol), DEPOSIT, true, _noRules());
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        uint256 i;
        _c[i++] = abi.encodeCall(guard.acceptDefaultAdminTransfer, ());
        _c[i++] = abi.encodeCall(guard.addAllowedValues, (address(safe), address(protocol), DEPOSIT, 0, _vals));
        _c[i++] = abi.encodeCall(guard.allowFunction, (address(safe), address(protocol), DEPOSIT, true, _noRules()));
        _c[i++] = abi.encodeCall(guard.allowFunctions, (address(safe), _specs));
        _c[i++] = abi.encodeCall(guard.approveTransaction, (address(safe), address(0), address(protocol), 0, _settle, Operation.Call, uint64(1 days)));
        _c[i++] = abi.encodeCall(guard.beginDefaultAdminTransfer, (caller_));
        _c[i++] = abi.encodeCall(guard.bypass, (address(safe), uint64(1 days)));
        _c[i++] = abi.encodeCall(guard.cancelDefaultAdminTransfer, ());
        _c[i++] = abi.encodeCall(guard.changeDefaultAdminDelay, (uint48(1 days)));
        _c[i++] = abi.encodeCall(guard.checkAfterExecution, (bytes32(uint256(1)), true));
        _c[i++] = abi.encodeCall(guard.checkAfterModuleExecution, (bytes32(uint256(1)), true));
        _c[i++] = abi.encodeCall(guard.checkModuleTransaction, (address(protocol), 0, _settle, Operation.Call, caller_));
        _c[i++] = _checkTxCalldata(caller_);
        _c[i++] = abi.encodeCall(guard.clearAllowedValues, (address(safe), address(protocol), DEPOSIT, 0));
        _c[i++] = abi.encodeCall(guard.enforce, (address(safe)));
        _c[i++] = abi.encodeCall(guard.executeBefore, (uint64(block.timestamp + 1), abi.encodeCall(guard.lockdown, (address(safe)))));
        _c[i++] = abi.encodeCall(guard.grantRole, (guard.COUNCIL_ROLE(), caller_));
        _c[i++] = abi.encodeCall(guard.lockdown, (address(safe)));
        _c[i++] = abi.encodeCall(guard.lockdownAndRevoke, (address(safe)));
        _c[i++] = abi.encodeCall(guard.removeAllowedValues, (address(safe), address(protocol), DEPOSIT, 0, _vals));
        _c[i++] = abi.encodeCall(guard.renounceRole, (guard.COUNCIL_ROLE(), caller_));
        _c[i++] = abi.encodeCall(guard.revokeAllApprovals, (address(safe)));
        _c[i++] = abi.encodeCall(guard.revokeApproval, (liveApprovalA));
        _c[i++] = abi.encodeCall(guard.revokeFunction, (address(safe), address(protocol), SETTLE));
        _c[i++] = abi.encodeCall(guard.revokeRole, (guard.COUNCIL_ROLE(), council));
        _c[i++] = abi.encodeCall(guard.revokeTarget, (address(safe), address(protocol)));
        _c[i++] = abi.encodeCall(guard.rollbackDefaultAdminDelay, ());
        _c[i++] = abi.encodeCall(guard.setDeploymentGuardian, (caller_, true));
        _c[i++] = abi.encodeCall(guard.setDeploymentGuardian, (guardian, false));
        _c[i++] = abi.encodeCall(guard.setGuardian, (address(safe), caller_, true));
        _c[i++] = abi.encodeCall(guard.setGuardian, (address(safe), guardianA, false));
        _c[i++] = abi.encodeCall(guard.setModuleAllowed, (address(safe), caller_, true));
        _c[i++] = abi.encodeCall(guard.setModuleAllowed, (address(safe), caller_, false));
        _c[i++] = abi.encodeCall(guard.setMultiSendUnwrapper, (address(safe), address(multiSendCallOnly), true));
        _c[i++] = abi.encodeCall(guard.setMultiSendUnwrapper, (address(safe), address(multiSendCallOnly), false));
        _c[i++] = abi.encodeCall(guard.setNativeTransferAllowed, (address(safe), caller_, true));
        _c[i++] = abi.encodeCall(guard.setNativeTransferAllowed, (address(safe), address(protocol), false));
        _c[i++] = abi.encodeCall(guard.setRequiredFallbackHandler, (address(safe), address(0), true));
        _c[i++] = abi.encodeCall(guard.setUnwrapperCodehash, (_H().codehashV141(), false));
        _c[i++] = abi.encodeCall(guard.setUnwrapperCodehash, (_H().codehashV141(), true));
        require(i == 40, "count");
    }

    function _checkTxCalldata(address caller_) internal view returns (bytes memory) {
        return
            abi.encodeCall(
                guard.checkTransaction,
                (address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", caller_)
            );
    }

    /// @dev The 34 mutator selectors of the ABI (forge inspect, 10 runs), pinned so the list above
    ///      cannot silently miss one.
    function _mutatorSelectors() internal pure returns (bytes4[34] memory) {
        return [
            bytes4(0xcefc1429), bytes4(0xf75df182), bytes4(0x59feb37f), bytes4(0xbb2475a3), bytes4(0x799b4dc8),
            bytes4(0x634e93da), bytes4(0x3280d2ee), bytes4(0xd602b9fd), bytes4(0x649a5ec7), bytes4(0x93271368),
            bytes4(0x2acc37aa), bytes4(0x728c2972), bytes4(0x75f0bb52), bytes4(0xb6930f06), bytes4(0xa73714e4),
            bytes4(0x54aee2dd), bytes4(0x2f2ff15d), bytes4(0x3bfb58a9), bytes4(0x6cc42fac), bytes4(0x9252c365),
            bytes4(0x36568abe), bytes4(0x5250285f), bytes4(0x15ba5ae7), bytes4(0x0bdd9e66), bytes4(0xd547741f),
            bytes4(0xac1ac005), bytes4(0x0aa6220b), bytes4(0x4a9463f1), bytes4(0xfdabd9b2), bytes4(0xb97458f5),
            bytes4(0x03d708f7), bytes4(0x3023fbe2), bytes4(0x731ef68d), bytes4(0xcd6f1540)
        ];
    }

    function test_mutator_list_covers_every_state_changing_selector_of_the_abi() public view {
        bytes[] memory _c = _mutators(attacker);
        bytes4[34] memory _sels = _mutatorSelectors();
        for (uint256 s; s < 34; ++s) {
            bool _found;
            for (uint256 i; i < _c.length && !_found; ++i) _found = bytes4(_c[i]) == _sels[s];
            assertTrue(_found, "every ABI mutator is exercised");
        }
    }

    function _deploymentState() internal view returns (bytes32) {
        return keccak256(abi.encode(_state(guard, address(safe)), _state(guard, address(safeB)), _state(otherGuard, address(safeC))));
    }

    /// @dev Runs the whole mutator list as `caller_` (pranked) and asserts nothing changes. Returns the
    ///      number of calls that did not revert (only `renounceRole` of a role not held may).
    function _runAs(address caller_, bytes[] memory calls_) internal returns (uint256 _okCount, uint256 _firstOk) {
        _firstOk = type(uint256).max;
        for (uint256 i; i < calls_.length; ++i) {
            bytes32 _before = _deploymentState();
            vm.prank(caller_);
            (bool _ok, ) = address(guard).call(calls_[i]);
            assertEq(_deploymentState(), _before, "state unchanged");
            if (_ok) {
                ++_okCount;
                if (_firstOk == type(uint256).max) _firstOk = i;
            }
        }
    }

    function _assertOnlyRenounceNoop(uint256 okCount_, uint256 firstOk_, bytes[] memory calls_) internal pure {
        if (okCount_ == 0) return;
        assertEq(okCount_, 1, "at most one non-reverting call");
        assertEq(bytes4(calls_[firstOk_]), IAccessControl.renounceRole.selector, "only renounceRole (a no-op) may return");
    }

    function test_eoa_stranger_changes_nothing() public {
        bytes[] memory _c = _mutators(attacker);
        (uint256 _n, uint256 _first) = _runAs(attacker, _c);
        _assertOnlyRenounceNoop(_n, _first, _c);
    }

    function test_zero_address_sender_changes_nothing() public {
        // A mis-signed relay / an `eth_call` without `from`: `msg.sender == address(0)`.
        bytes[] memory _c = _mutators(address(0));
        (uint256 _n, uint256 _first) = _runAs(address(0), _c);
        _assertOnlyRenounceNoop(_n, _first, _c);
    }

    function test_contract_stranger_changes_nothing() public {
        bytes[] memory _c = _mutators(address(forwarder));
        for (uint256 i; i < _c.length; ++i) {
            bytes32 _before = _deploymentState();
            (bool _ok, ) = forwarder.fwd(address(guard), _c[i]);
            assertEq(_deploymentState(), _before, "state unchanged");
            if (_ok) assertEq(bytes4(_c[i]), IAccessControl.renounceRole.selector, "only renounceRole may return");
        }
    }

    function test_contract_under_construction_changes_nothing() public {
        bytes32 _before = _deploymentState();
        // The constructor's `msg.sender` has no code yet; the calls land as that address.
        address _predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        Constructing _c = new Constructing(address(guard), _mutators(_predicted));
        assertEq(address(_c), _predicted, "fixture");
        assertEq(_deploymentState(), _before, "state unchanged");
        assertLe(_c.okCount(), 1, "at most renounceRole");
    }

    function test_unconfigured_safe_as_sender_changes_nothing() public {
        // A real Safe v1.4.1 that nobody configured (as an unguarded module or a pranked call would make it).
        bytes[] memory _c = _mutators(unconfiguredSafe);
        (uint256 _n, uint256 _first) = _runAs(unconfiguredSafe, _c);
        _assertOnlyRenounceNoop(_n, _first, _c);
        // Its own hooks: Lockdown, nothing recorded (a second pre-hook is still SafeLockedDown, not
        // NestedExecution), the post-hook has no snapshot.
        // V2-88: a Safe whose guard slot does not name this guard is refused before its
        // policy is even looked at (`SafeLockedDown` before round 8).
        vm.startPrank(unconfiguredSafe);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardNotInstalled.selector, unconfiguredSafe));
        guard.checkTransaction(address(protocol), 0, "", Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", attacker);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardNotInstalled.selector, unconfiguredSafe));
        guard.checkTransaction(address(protocol), 0, "", Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", attacker);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.MissingSnapshot.selector, unconfiguredSafe));
        guard.checkAfterExecution(bytes32(0), true);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.MissingSnapshot.selector, unconfiguredSafe));
        guard.checkAfterModuleExecution(bytes32(0), true);
        vm.stopPrank();
    }

    function test_safe_configured_on_another_guard_as_sender_changes_nothing() public {
        bytes[] memory _c = _mutators(address(safeC));
        (uint256 _n, uint256 _first) = _runAs(address(safeC), _c);
        _assertOnlyRenounceNoop(_n, _first, _c);
        // On THIS guard, C is an unconfigured Safe: its hooks here fail closed although C is
        // `Enforced` with an allowlist on `otherGuard`.
        assertEq(uint8(otherGuard.mode(address(safeC))), uint8(CuratorGuardPolicy.Mode.Enforced), "C enforced elsewhere");
        assertEq(uint8(guard.mode(address(safeC))), uint8(CuratorGuardPolicy.Mode.Lockdown), "C unknown here");
        vm.prank(address(safeC));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardNotInstalled.selector, address(safeC)));
        guard.checkTransaction(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", attacker);
    }

    function test_another_guard_instance_as_sender_changes_nothing() public {
        bytes[] memory _c = _mutators(address(otherGuard));
        (uint256 _n, uint256 _first) = _runAs(address(otherGuard), _c);
        _assertOnlyRenounceNoop(_n, _first, _c);
    }

    function test_sibling_safe_as_sender_cannot_touch_a_sibling() public {
        // B is configured on the same guard; pranked as `msg.sender` (an unguarded v1.4.1 module of B or an
        // admin-approved batch entry could make B call the guard directly). Nothing aimed at A moves.
        bytes[] memory _c = _mutators(address(safeB));
        for (uint256 i; i < _c.length; ++i) {
            bytes4 _sel = bytes4(_c[i]);
            // B's own hooks are B's business (they revert here for lack of a live pre-hook / policy
            // target); they are keyed by `msg.sender`, so they can only touch B's slot and B's approvals.
            bytes32 _beforeA = _state(guard, address(safe));
            vm.prank(address(safeB));
            (bool _ok, ) = address(guard).call(_c[i]);
            assertEq(_state(guard, address(safe)), _beforeA, "A unchanged");
            if (_ok) {
                assertTrue(
                    _sel == IAccessControl.renounceRole.selector ||
                        _sel == ISafeTransactionGuard.checkTransaction.selector ||
                        _sel == ISafeModuleGuard.checkModuleTransaction.selector,
                    "only renounce or B's own hooks may return"
                );
            }
        }
    }

    function test_guardian_of_B_cannot_narrow_A_but_can_narrow_B() public {
        bytes[] memory _c = _mutators(guardianB);
        (uint256 _n, uint256 _first) = _runAs(guardianB, _c);
        _assertOnlyRenounceNoop(_n, _first, _c);
        // The same key is a legitimate narrower of B.
        vm.startPrank(guardianB);
        guard.revokeApproval(liveApprovalB);
        guard.lockdown(address(safeB));
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.revokeApproval(liveApprovalA);
        vm.stopPrank();
        assertEq(uint8(guard.mode(address(safeB))), uint8(CuratorGuardPolicy.Mode.Lockdown), "B locked");
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Enforced), "A untouched");
        assertGt(guard.approvalExpiry(liveApprovalA), 0, "A's approval survives");
    }

    /// @dev `executeBefore` keeps `msg.sender`: wrapping every mutator changes nothing for every
    ///      stranger kind either (the inner call re-checks the role).
    function test_executeBefore_wrapping_gives_strangers_nothing() public {
        address[5] memory _kinds = [attacker, address(0), unconfiguredSafe, address(safeC), guardianB];
        for (uint256 k; k < _kinds.length; ++k) {
            bytes[] memory _inner = _mutators(_kinds[k]);
            bytes[] memory _wrapped = new bytes[](_inner.length);
            for (uint256 i; i < _inner.length; ++i) {
                _wrapped[i] = abi.encodeCall(guard.executeBefore, (uint64(block.timestamp + 1 days), _inner[i]));
            }
            (uint256 _n, uint256 _first) = _runAs(_kinds[k], _wrapped);
            if (_n != 0) {
                assertEq(_n, 1, "at most one");
                assertEq(bytes4(_inner[_first]), IAccessControl.renounceRole.selector, "only renounceRole");
            }
        }
    }

    /// @dev Every view of the ABI answers a stranger without side effects (they are the public read
    ///      surface by design); none of them can be poisoned by a stranger because no stranger write
    ///      exists (the tests above).
    function test_views_answer_strangers_and_leak_only_public_state() public {
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        bytes32 _before = _deploymentState();
        vm.startPrank(attacker);
        guard.COUNCIL_ROLE();
        guard.DEFAULT_ADMIN_ROLE();
        guard.GUARDIAN_ROLE();
        guard.allowedValues(address(safe), address(protocol), DEPOSIT, 0);
        guard.approvalEpoch(address(safe));
        guard.approvalExpiry(liveApprovalA);
        guard.bypassWindow(address(safe));
        guard.computeApprovalId(address(safe), address(0), address(protocol), 0, _settle, Operation.Call);
        guard.defaultAdmin();
        guard.defaultAdminDelay();
        guard.defaultAdminDelayIncreaseWait();
        guard.functionPermission(address(safe), address(protocol), SETTLE);
        guard.getRoleAdmin(guard.COUNCIL_ROLE());
        guard.guardians(address(safe));
        guard.hasRole(guard.COUNCIL_ROLE(), council);
        guard.isGuardian(address(safe), guardianA);
        guard.isNativeTransferAllowed(address(safe), address(protocol));
        guard.isUnwrapperCodehash(_H().codehashV141());
        guard.lockedAt(address(safe));
        guard.mode(address(safe));
        guard.modules(address(safe));
        guard.multiSendUnwrappers(address(safe));
        guard.owner();
        guard.pendingDefaultAdmin();
        guard.pendingDefaultAdminDelay();
        guard.requiredFallbackHandler(address(safe));
        guard.selectors(address(safe), address(protocol));
        guard.supportsInterface(type(ISafeTransactionGuard).interfaceId);
        guard.targets(address(safe));
        guard.validateTransaction(address(safe), address(protocol), 0, _settle, Operation.Call);
        // The dry run tells a stranger that the approved payload passes under Lockdown: that is the
        // `TransactionApproved` event and `approvalExpiry`, both public already.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, attacker));
        guard.validateModuleTransaction(address(safe), attacker, address(protocol), 0, _settle, Operation.Call);
        vm.stopPrank();
        assertEq(_deploymentState(), _before, "views are side-effect free");
    }

    /// @dev An approval of A is unusable by B even with the identical payload (the id folds the Safe), and
    ///      the admin cannot issue one for B by mistake with A's id either (distinct ids).
    function test_approvals_are_safe_bound_across_siblings() public {
        bytes memory _payload = abi.encodeCall(MockProtocol.settleDeposit, (7));
        bytes32 _idA = guard.computeApprovalId(address(safe), address(0), address(protocol), 0, _payload, Operation.Call);
        bytes32 _idB = guard.computeApprovalId(address(safeB), address(0), address(protocol), 0, _payload, Operation.Call);
        assertEq(_idA, liveApprovalA, "A's id");
        assertTrue(_idA != _idB, "distinct ids");
        assertEq(guard.approvalExpiry(_idB), 0, "no approval for B on A's venue");
        // B tries A's approved payload on A's venue (not in B's policy): refused, A's approval untouched.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), SETTLE));
        _execAs(safeB, signerPkB, address(protocol), 0, _payload, Operation.Call);
        assertGt(guard.approvalExpiry(liveApprovalA), 0, "A's approval survives B's attempt");
        // A consumes its own.
        assertTrue(_execSafeTx(address(protocol), 0, _payload, Operation.Call), "A executes");
        assertEq(guard.approvalExpiry(liveApprovalA), 0, "consumed by A");
    }
}
