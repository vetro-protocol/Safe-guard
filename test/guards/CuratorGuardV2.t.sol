// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IAccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/IAccessControlDefaultAdminRules.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @dev An allowlisted venue that happens to hold a guard role and uses it inside the curator's
///      transaction: the only way a mode flip can land between the pre- and the post-hook.
contract RoleHoldingVenue {
    CuratorGuard internal immutable guard;
    address internal immutable safe;

    constructor(CuratorGuard guard_, address safe_) {
        guard = guard_;
        safe = safe_;
    }

    function flipToBypass() external {
        guard.bypass(safe, 1 days);
    }

    function flipToEnforced() external {
        guard.enforce(safe);
    }

    function poke() external {}
}

/// @dev A council-role venue that opens a Bypass window and then nests a same-Safe `execTransaction`
///      inside the curator's transaction (swallowing the revert so the outer transaction reports it).
contract FlipThenNestVenue {
    CuratorGuard internal immutable guard;
    address internal immutable safe;
    bytes public lastError;

    constructor(CuratorGuard guard_, address safe_) {
        guard = guard_;
        safe = safe_;
    }

    function run(bytes calldata inner_) external {
        guard.bypass(safe, 1 days);
        (bool _ok, bytes memory _err) = safe.call(inner_);
        if (!_ok) lastError = _err;
    }
}

/// @title CuratorGuard v2: roles, council limits, time-boxed Bypass, approval TTLs, timelock admin,
///        v1.5.0 MultiSend decoding. See docs/curator-guard.md section 13 (the v2 items).
contract CuratorGuardV2Test is CuratorGuardTestBase {
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;
    bytes4 internal constant DEPOSIT = MockProtocol.deposit.selector;
    bytes4 internal constant TRANSFER = IERC20.transfer.selector;
    bytes4 internal constant APPROVE = IERC20.approve.selector;

    address internal globalGuardian = makeAddr("global-guardian");
    address internal safeGuardian = makeAddr("safe-guardian");

    function setUp() public override {
        // Foundry's default `block.timestamp == 1` collides with TimelockController's `_DONE_TIMESTAMP`.
        vm.warp(1_700_000_000);
        super.setUp();
        vm.startPrank(vetro);
        guard.grantRole(guard.GUARDIAN_ROLE(), globalGuardian);
        guard.setGuardian(address(safe), safeGuardian, true);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                               ROLE MATRIX
    //////////////////////////////////////////////////////////////*/

    function test_constructor_roles_and_owner_view() public view {
        assertEq(guard.defaultAdmin(), vetro);
        assertEq(guard.owner(), vetro, "owner() is kept for readers and tooling");
        assertTrue(guard.hasRole(guard.COUNCIL_ROLE(), council));
        assertTrue(guard.hasRole(guard.GUARDIAN_ROLE(), globalGuardian));
        assertTrue(guard.isGuardian(address(safe), globalGuardian));
        assertTrue(guard.isGuardian(address(safe), safeGuardian));
        assertFalse(guard.isGuardian(attacker, safeGuardian), "per-Safe guardian is scoped");
        assertTrue(guard.isGuardian(attacker, globalGuardian), "deployment-wide guardian covers every Safe");
        assertEq(guard.guardians(address(safe)).length, 1);
        assertEq(guard.guardians(address(safe))[0], safeGuardian);
        assertTrue(guard.supportsInterface(0xe6d7a83a), "transaction guard id");
        assertTrue(guard.supportsInterface(0x58401ed8), "module guard id");
        assertTrue(guard.supportsInterface(type(IAccessControl).interfaceId), "access control id");
        assertTrue(guard.isUnwrapperCodehash(_H().codehashV150()));
    }

    function test_constructor_without_council_grants_no_council() public {
        CuratorGuard _g = new CuratorGuard(0, vetro, address(0));
        assertFalse(_g.hasRole(_g.COUNCIL_ROLE(), council));
        assertFalse(_g.hasRole(_g.COUNCIL_ROLE(), address(0)));
        assertEq(_g.defaultAdmin(), vetro);
    }

    /// @dev Widening entry points: admin only. Council, both guardian kinds and strangers are refused.
    function test_only_admin_widens() public {
        CuratorGuardPolicy.FunctionSpec[] memory _specs = new CuratorGuardPolicy.FunctionSpec[](1);
        _specs[0] = CuratorGuardPolicy.FunctionSpec(address(protocol), SETTLE, false, _noRules());
        bytes32[] memory _vals = new bytes32[](1);
        _vals[0] = _word(attacker);
        _allowWithRules(address(token), APPROVE, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        bytes32 _councilRole = guard.COUNCIL_ROLE();
        bytes32 _guardianRole = guard.GUARDIAN_ROLE();
        bytes32 _codehash = address(multiSendCallOnly).codehash;
        address[4] memory _callers = [council, globalGuardian, safeGuardian, attacker];
        for (uint256 i; i < 4; ++i) {
            vm.startPrank(_callers[i]);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.allowFunction(address(safe), address(protocol), DEPOSIT, false, _noRules());
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.allowFunctions(address(safe), _specs);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.addAllowedValues(address(safe), address(token), APPROVE, 0, _vals);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.setNativeTransferAllowed(address(safe), address(protocol), true);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.setMultiSendUnwrapper(address(safe), address(multiSendCallOnly), true);
            // Re-allowing a hash is admin OR council (round 3); for the council the non-canonical local
            // build is refused one step later, for everyone else the authorisation fails first.
            if (_callers[i] == council) {
                vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.UnwrapperCodehashNotAllowed.selector, _codehash));
            } else {
                vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            }
            guard.setUnwrapperCodehash(_codehash, true);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.setModuleAllowed(address(safe), attacker, true);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.setRequiredFallbackHandler(address(safe), address(0), false);
            vm.expectRevert(
                abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, _callers[i], bytes32(0))
            );
            guard.grantRole(_councilRole, _callers[i]);
            vm.expectRevert(
                abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, _callers[i], bytes32(0))
            );
            guard.grantRole(_guardianRole, _callers[i]);
            vm.expectRevert(
                abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, _callers[i], bytes32(0))
            );
            guard.beginDefaultAdminTransfer(_callers[i]);
            vm.stopPrank();
        }
        assertFalse(_isAllowed(address(safe), address(protocol), DEPOSIT));
        assertEq(guard.allowedValues(address(safe), address(token), APPROVE, 0).length, 0);
    }

    /// @dev Council fast lane: enforce, lockdown, short bypass, short approvals, per-Safe guardians,
    ///      any narrowing. Never the allowlist.
    function test_council_fast_lane() public {
        _allow(address(protocol), SETTLE);
        uint64 _councilTtl = _H().maxCouncilApprovalTtl();
        uint64 _councilBypass = _H().maxCouncilBypass();
        vm.startPrank(council);
        guard.enforce(address(safe));
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Enforced));
        guard.lockdown(address(safe));
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        guard.enforce(address(safe));
        guard.setGuardian(address(safe), attacker, true);
        assertTrue(guard.isGuardian(address(safe), attacker));
        guard.setGuardian(address(safe), attacker, false);
        assertFalse(guard.isGuardian(address(safe), attacker));
        guard.revokeFunction(address(safe), address(protocol), SETTLE);
        assertFalse(_isAllowed(address(safe), address(protocol), SETTLE));
        bytes32 _id = guard.approveTransaction(
            address(safe),
            address(0),
            address(protocol),
            0,
            abi.encodeCall(MockProtocol.settleDeposit, (3)),
            Operation.Call,
            _councilTtl
        );
        assertGt(guard.approvalExpiry(_id), 0);
        guard.revokeApproval(_id);
        guard.revokeAllApprovals(address(safe));
        guard.bypass(address(safe), _councilBypass);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Bypass));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, _councilBypass + 1));
        guard.bypass(address(safe), _councilBypass + 1);
        guard.enforce(address(safe));
        vm.stopPrank();
        assertEq(guard.approvalEpoch(address(safe)), 2, "revokeAll + bypass");
    }

    /// @dev Guardians (per-Safe and deployment-wide) narrow only; the per-Safe one is scoped.
    function test_guardians_narrow_only_and_per_safe_scope() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        bytes32 _id = _approve(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
        bytes32 _v141 = _H().codehashV141();
        address[2] memory _guardians = [safeGuardian, globalGuardian];
        for (uint256 i; i < 2; ++i) {
            vm.startPrank(_guardians[i]);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.enforce(address(safe));
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.bypass(address(safe), 1);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.setGuardian(address(safe), attacker, true);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.approveTransaction(address(safe), address(0), address(protocol), 0, "", Operation.Call, 1);
            vm.stopPrank();
        }
        // The per-Safe guardian cannot touch another Safe or deployment-wide state.
        vm.startPrank(safeGuardian);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.lockdown(attacker);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.revokeFunction(attacker, address(protocol), SETTLE);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.revokeAllApprovals(attacker);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.setUnwrapperCodehash(_v141, false);
        guard.revokeApproval(_id); // its own Safe's approval
        guard.lockdown(address(safe));
        vm.stopPrank();
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        assertTrue(guard.isUnwrapperCodehash(_v141));
        // The deployment-wide guardian can do both.
        vm.startPrank(globalGuardian);
        guard.lockdown(attacker);
        guard.setUnwrapperCodehash(_v141, false);
        vm.stopPrank();
        assertEq(uint8(guard.mode(attacker)), uint8(CuratorGuardPolicy.Mode.Lockdown));
        assertFalse(guard.isUnwrapperCodehash(_v141));
    }

    function test_revokeApproval_requires_a_narrower_of_the_approvals_safe() public {
        // Approval for ANOTHER Safe: the per-Safe guardian of our Safe may not revoke it.
        vm.prank(vetro);
        bytes32 _other = guard.approveTransaction(attacker, address(0), address(protocol), 0, "", Operation.Call, 1 days);
        vm.prank(safeGuardian);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.revokeApproval(_other);
        vm.prank(globalGuardian);
        guard.revokeApproval(_other);
        assertEq(guard.approvalExpiry(_other), 0);
    }

    function test_guardian_events_and_idempotence() public {
        vm.prank(council);
        vm.expectEmit(true, true, false, true, address(guard));
        emit CuratorGuardPolicy.GuardianUpdated(address(safe), attacker, true);
        guard.setGuardian(address(safe), attacker, true);
        vm.recordLogs();
        vm.prank(council);
        guard.setGuardian(address(safe), attacker, true); // no-op: no event
        assertEq(vm.getRecordedLogs().length, 0);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(0)));
        guard.setGuardian(address(safe), address(0), true);
    }

    /*//////////////////////////////////////////////////////////////
                        COUNCIL APPROVAL LIMITS
    //////////////////////////////////////////////////////////////*/

    function test_council_cannot_approve_what_weakens_the_safe() public {
        bytes[4] memory _denied = [
            abi.encodeCall(ISafe.setGuard, (address(0))),
            abi.encodeCall(ISafe.setModuleGuard, (address(0))),
            abi.encodeCall(ISafe.enableModule, (attacker)),
            abi.encodeWithSelector(0xf08a0323, attacker) // setFallbackHandler(address)
        ];
        for (uint256 i; i < 4; ++i) {
            bytes4 _sel = bytes4(_denied[i]);
            vm.prank(council);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, _sel, Operation.Call));
            guard.approveTransaction(address(safe), address(0), address(safe), 0, _denied[i], Operation.Call, 1 days);
            // The admin may.
            vm.prank(vetro);
            guard.approveTransaction(address(safe), address(0), address(safe), 0, _denied[i], Operation.Call, 1 days);
        }
        // Delegatecalls are admin-only too, whatever the target.
        bytes memory _batch = _multiSendCalldata(_entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1))));
        vm.prank(council);
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, bytes4(_batch), Operation.DelegateCall)
        );
        guard.approveTransaction(address(safe), address(0), address(multiSendCallOnly), 0, _batch, Operation.DelegateCall, 1 days);
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(multiSendCallOnly), 0, _batch, Operation.DelegateCall, 1 days);
    }

    function test_council_can_approve_owner_management_and_venue_calls() public {
        // Venue one-offs first (the owner change below raises the threshold to 2, after which the
        // single-signer fixture can no longer execute).
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (9));
        _councilApprove(address(protocol), 0, _data, Operation.Call);
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call));
        assertEq(protocol.lastAmount(), 9);
        // Owner management, never below a threshold of 2 (round 4): threshold 1 is admin-only.
        address _newOwner = makeAddr("new-owner");
        bytes memory _addSingleKey = abi.encodeCall(ISafe.addOwnerWithThreshold, (_newOwner, 1));
        vm.prank(council);
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, ISafe.addOwnerWithThreshold.selector, Operation.Call)
        );
        guard.approveTransaction(address(safe), address(0), address(safe), 0, _addSingleKey, Operation.Call, 1 days);
        bytes memory _add = abi.encodeCall(ISafe.addOwnerWithThreshold, (_newOwner, 2));
        bytes32 _id = _councilApprove(address(safe), 0, _add, Operation.Call);
        assertTrue(_execSafeTx(address(safe), 0, _add, Operation.Call));
        assertEq(safe.getOwners().length, 2);
        assertEq(safe.getThreshold(), 2);
        assertEq(guard.approvalExpiry(_id), 0, "consumed");
    }

    function test_approval_event_carries_absolute_expiry_and_epoch() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.prank(vetro);
        guard.revokeAllApprovals(address(safe));
        bytes32 _id = guard.computeApprovalId(address(safe), address(0), address(protocol), 0, _data, Operation.Call);
        vm.prank(council);
        vm.expectEmit(true, true, false, true, address(guard));
        emit CuratorGuardPolicy.TransactionApproved(
            address(safe),
            _id,
            address(0),
            address(protocol),
            0,
            _data,
            Operation.Call,
            uint64(block.timestamp + 2 days),
            1
        );
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, 2 days);
        assertEq(guard.approvalExpiry(_id), uint64(block.timestamp + 2 days));
        // Valid at exactly the expiry second, dead one second later.
        vm.warp(block.timestamp + 2 days);
        guard.validateTransaction(address(safe), address(protocol), 0, _data, Operation.Call);
        vm.warp(block.timestamp + 1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        guard.validateTransaction(address(safe), address(protocol), 0, _data, Operation.Call);
    }

    function test_approval_can_never_target_the_guard() public {
        bytes memory _data = abi.encodeCall(guard.lockdown, (address(safe)));
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(guard)));
        guard.approveTransaction(address(safe), address(0), address(guard), 0, _data, Operation.Call, 1 days);
    }

    /*//////////////////////////////////////////////////////////////
                         TIME-BOXED BYPASS
    //////////////////////////////////////////////////////////////*/

    function test_bypass_caps_per_role_and_rejects_zero() public {
        uint64 _adminBypass = _H().maxAdminBypass();
        assertEq(_adminBypass, 180 days);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, uint64(0)));
        guard.bypass(address(safe), 0);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, _adminBypass + 1));
        guard.bypass(address(safe), _adminBypass + 1);
        vm.prank(vetro);
        guard.bypass(address(safe), _adminBypass);
        (uint64 _until, bool _council) = guard.bypassWindow(address(safe));
        assertEq(_until, uint64(block.timestamp) + _adminBypass);
        assertFalse(_council, "admin window");
        vm.prank(attacker);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.bypass(address(safe), 1);
    }

    function test_expired_bypass_reads_and_behaves_as_lockdown() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        _bypass(1 hours);
        assertTrue(_execSafeTx(address(token), 0, abi.encodeCall(IERC20.transfer, (attacker, 1)), Operation.Call), "inert");
        vm.warp(block.timestamp + 1 hours);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown), "expired window = Lockdown");
        (uint64 _until, ) = guard.bypassWindow(address(safe));
        assertEq(_until, uint64(block.timestamp), "the raw window end is still readable");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, _data, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        guard.validateTransaction(address(safe), address(protocol), 0, _data, Operation.Call);
        // Approvals are possible again (the window is over) and the council can re-enforce.
        _approve(address(protocol), 0, _data, Operation.Call);
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call));
        vm.prank(council);
        guard.enforce(address(safe));
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call));
    }

    function test_bypass_window_ends_at_its_until_second_consistently_in_pre_and_post_hook() public {
        _enforce();
        _bypass(1 hours);
        vm.warp(block.timestamp + 1 hours - 1);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Bypass));
        assertTrue(_execSafeTx(address(token), 0, abi.encodeCall(IERC20.transfer, (attacker, 1)), Operation.Call));
        vm.warp(block.timestamp + 1);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
    }

    function test_mode_events_carry_the_window() public {
        vm.prank(vetro);
        vm.expectEmit(true, false, false, true, address(guard));
        emit CuratorGuardPolicy.ModeUpdated(address(safe), CuratorGuardPolicy.Mode.Bypass, uint64(block.timestamp + 3 days), false);
        guard.bypass(address(safe), 3 days);
        vm.prank(council);
        vm.expectEmit(true, false, false, true, address(guard));
        emit CuratorGuardPolicy.ModeUpdated(address(safe), CuratorGuardPolicy.Mode.Bypass, uint64(block.timestamp + 1 days), true);
        guard.bypass(address(safe), 1 days);
        vm.prank(council);
        vm.expectEmit(true, false, false, true, address(guard));
        emit CuratorGuardPolicy.ModeUpdated(address(safe), CuratorGuardPolicy.Mode.Enforced, 0, false);
        guard.enforce(address(safe));
        vm.prank(safeGuardian);
        vm.expectEmit(true, false, false, true, address(guard));
        emit CuratorGuardPolicy.ModeUpdated(address(safe), CuratorGuardPolicy.Mode.Lockdown, 0, false);
        guard.lockdown(address(safe));
    }

    /*//////////////////////////////////////////////////////////////
                    POST-HOOK ORDERING UNDER MID-TX FLIPS
    //////////////////////////////////////////////////////////////*/

    /// @dev A policy transaction during which the council flips the Safe into Bypass: the pre-hook
    ///      stored a digest, the post-hook must still compare and clear it (no stale slot), and the
    ///      next Safe transaction in the same EVM transaction must not see a false `NestedExecution`.
    function test_bypass_flip_inside_a_policy_transaction_leaves_no_stale_state() public {
        _enforce();
        RoleHoldingVenue _venue = new RoleHoldingVenue(guard, address(safe));
        bytes32 _councilRole = guard.COUNCIL_ROLE();
        vm.prank(vetro);
        guard.grantRole(_councilRole, address(_venue));
        _allow(address(_venue), RoleHoldingVenue.flipToBypass.selector);
        _allow(address(protocol), SETTLE);

        assertTrue(_execSafeTx(address(_venue), 0, abi.encodeCall(RoleHoldingVenue.flipToBypass, ()), Operation.Call));
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Bypass));
        // Same EVM transaction: passes under Bypass, no NestedExecution from a leftover snapshot.
        assertTrue(_execSafeTx(address(token), 0, abi.encodeCall(IERC20.transfer, (attacker, 1)), Operation.Call));
        _enforce();
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call));
    }

    /// @dev The reverse flip (Bypass -> Enforced inside the transaction) fails closed: the pre-hook
    ///      recorded nothing, the post-hook now expects a snapshot.
    function test_enforce_flip_inside_a_bypass_transaction_fails_closed() public {
        RoleHoldingVenue _venue = new RoleHoldingVenue(guard, address(safe));
        bytes32 _councilRole = guard.COUNCIL_ROLE();
        vm.prank(vetro);
        guard.grantRole(_councilRole, address(_venue));
        _bypass(1 days);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.MissingSnapshot.selector, address(safe)));
        _execSafeTx(address(_venue), 0, abi.encodeCall(RoleHoldingVenue.flipToEnforced, ()), Operation.Call);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Bypass), "rolled back");
    }

    /// @dev Approved execution during which the Safe's configuration changes is fine (that is what
    ///      approvals are for) and leaves the slot clean for the next transaction.
    function test_approved_execution_then_policy_execution_in_one_transaction() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        address _newOwner = makeAddr("new-owner");
        bytes memory _add = abi.encodeCall(ISafe.addOwnerWithThreshold, (_newOwner, 1));
        _approve(address(safe), 0, _add, Operation.Call);
        assertTrue(_execSafeTx(address(safe), 0, _add, Operation.Call));
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (2)), Operation.Call));
        assertEq(protocol.lastAmount(), 2);
    }

    /*//////////////////////////////////////////////////////////////
                      v1.5.0 MULTISEND: ZERO `to` ENTRY
    //////////////////////////////////////////////////////////////*/

    function test_multisend_entry_to_zero_address_is_malformed() public {
        _enforce();
        _registerUnwrapper(address(multiSendCallOnly));
        _allow(address(protocol), SETTLE);
        bytes memory _batch = _multiSendCalldata(
            abi.encodePacked(
                _entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1))),
                _entry(address(0), 0, abi.encodeCall(ISafe.setGuard, (address(0))))
            )
        );
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        _execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        guard.validateTransaction(address(safe), address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
        // Zero-value empty-data entries to the zero address are rejected before the native check too.
        _batch = _multiSendCalldata(_entry(address(0), 0, ""));
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        guard.validateTransaction(address(safe), address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
    }

    /*//////////////////////////////////////////////////////////////
                   ADMIN = TIMELOCK (production topology)
    //////////////////////////////////////////////////////////////*/

    function _timelockFixture(
        uint256 minDelay_
    ) internal returns (CuratorGuard _g, CuratorGuardTimelock _tl, address _proposer, address _canceller) {
        // Production topology: two proposer Safes and ONE dedicated veto Safe that proposes nothing
        // (never the council, never hot keys); the executor role is open; no deployer admin (the role
        // set is final at creation).
        _proposer = makeAddr("governance-safe");
        _canceller = makeAddr("dedicated-veto-safe");
        address[] memory _proposers = new address[](2);
        _proposers[0] = _proposer;
        _proposers[1] = makeAddr("second-proposer-safe");
        address[] memory _cancellers = new address[](1);
        _cancellers[0] = _canceller;
        _tl = new CuratorGuardTimelock(minDelay_, _proposers, _cancellers);
        assertFalse(_tl.hasRole(_tl.CANCELLER_ROLE(), _proposer), "proposers are not cancellers");
        assertFalse(_tl.hasRole(_tl.PROPOSER_ROLE(), _canceller), "the canceller is not a proposer");
        assertTrue(_tl.hasRole(_tl.EXECUTOR_ROLE(), address(0)), "open executor");
        assertFalse(_tl.hasRole(_tl.DEFAULT_ADMIN_ROLE(), address(this)), "no deployer admin");
        _g = new CuratorGuard(1 days, address(_tl), council);
        assertEq(_g.defaultAdmin(), address(_tl));
    }

    function test_timelocked_admin_widening_waits_for_the_delay_and_can_be_cancelled() public {
        (CuratorGuard _g, CuratorGuardTimelock _tl, address _proposer, address _canceller) = _timelockFixture(2 days);
        bytes memory _widen = abi.encodeCall(_g.allowFunction, (address(safe), address(protocol), SETTLE, false, _noRules()));
        bytes32 _salt = keccak256("policy@1");

        vm.prank(_proposer);
        _tl.schedule(address(_g), 0, _widen, bytes32(0), _salt, 2 days);
        bytes32 _opId = _tl.hashOperation(address(_g), 0, _widen, bytes32(0), _salt);
        assertTrue(_tl.isOperationPending(_opId));
        assertFalse(_isAllowedOn(_g, address(safe), address(protocol), SETTLE), "nothing applied yet");

        // Too early: the timelock refuses.
        vm.expectRevert(abi.encodeWithSelector(TimelockController.TimelockUnexpectedOperationState.selector, _opId, bytes32(uint256(1 << 2))));
        _tl.execute(address(_g), 0, _widen, bytes32(0), _salt);

        // Nobody but the timelock can call the guard's admin functions directly, including the proposer.
        vm.prank(_proposer);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        _g.allowFunction(address(safe), address(protocol), SETTLE, false, _noRules());

        vm.warp(block.timestamp + 2 days);
        vm.prank(attacker); // executor role is open
        _tl.execute(address(_g), 0, _widen, bytes32(0), _salt);
        assertTrue(_isAllowedOn(_g, address(safe), address(protocol), SETTLE));

        // A second widening is cancelled by the other proposer Safe (a canceller) during the window.
        bytes memory _widen2 = abi.encodeCall(_g.allowFunction, (address(safe), address(token), TRANSFER, false, _noRules()));
        vm.prank(_proposer);
        _tl.schedule(address(_g), 0, _widen2, bytes32(0), _salt, 2 days);
        bytes32 _opId2 = _tl.hashOperation(address(_g), 0, _widen2, bytes32(0), _salt);
        vm.prank(_canceller);
        _tl.cancel(_opId2);
        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(abi.encodeWithSelector(TimelockController.TimelockUnexpectedOperationState.selector, _opId2, bytes32(uint256(1 << 2))));
        _tl.execute(address(_g), 0, _widen2, bytes32(0), _salt);
        assertFalse(_isAllowedOn(_g, address(safe), address(token), TRANSFER));
    }

    /// @dev Round 5, R3D-2: a lift, a window or an approval that sat in the timelock queue before a
    ///      lockdown cannot be played by anyone for a day after it (it could otherwise be executed
    ///      atomically with a transaction the signers already signed); the council still acts at once,
    ///      and a lift wrapped with the task's one-day window dies during the cooldown.
    function test_queued_admin_actions_wait_out_the_lockdown_cooldown() public {
        (CuratorGuard _g, CuratorGuardTimelock _tl, address _proposer, ) = _timelockFixture(2 days);
        vm.prank(council);
        _g.setGuardian(address(safe), safeGuardian, true);
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        uint64 _liftDeadline = uint64(block.timestamp + 2 days + 1 days); // ready time + the one-day lift window
        bytes[3] memory _ops = [
            abi.encodeCall(_g.executeBefore, (_liftDeadline, abi.encodeCall(_g.enforce, (address(safe))))),
            abi.encodeCall(_g.bypass, (address(safe), uint64(30 days))),
            abi.encodeCall(_g.approveTransaction, (address(safe), address(0), address(protocol), 0, _settle, Operation.Call, uint64(3 days)))
        ];
        for (uint256 i; i < 3; ++i) {
            vm.prank(_proposer);
            _tl.schedule(address(_g), 0, _ops[i], bytes32(0), bytes32(i), 2 days);
        }
        vm.warp(block.timestamp + 2 days); // all three are ready
        vm.prank(safeGuardian);
        _g.lockdown(address(safe));
        uint256 _lockedAt = block.timestamp;
        bytes memory _cooldown = abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(safe));
        for (uint256 i; i < 3; ++i) {
            vm.prank(attacker); // the executor role is open
            vm.expectRevert(_cooldown);
            _tl.execute(address(_g), 0, _ops[i], bytes32(0), bytes32(i));
        }
        // The council is not held back: it acts live, with the incident in view.
        vm.prank(council);
        _g.enforce(address(safe));
        vm.prank(safeGuardian);
        _g.lockdownAndRevoke(address(safe)); // restarts the cooldown
        _lockedAt = block.timestamp;
        // The last second of the cooldown is still refused; the lift's own deadline is that second.
        vm.warp(_lockedAt + 1 days);
        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(_cooldown);
            _tl.execute(address(_g), 0, _ops[i], bytes32(0), bytes32(i));
        }
        vm.warp(_lockedAt + 1 days + 1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, _liftDeadline));
        _tl.execute(address(_g), 0, _ops[0], bytes32(0), bytes32(uint256(0))); // the queued lift is dead
        // What nobody cancelled during the day is executable again: cancelling is the cancellers' job.
        _tl.execute(address(_g), 0, _ops[2], bytes32(0), bytes32(uint256(2)));
        assertGt(_g.approvalExpiry(_g.computeApprovalId(address(safe), address(0), address(protocol), 0, _settle, Operation.Call)), 0);
    }

    function test_council_and_guardians_stay_immediate_under_a_timelocked_admin() public {
        (CuratorGuard _g, , , ) = _timelockFixture(2 days);
        vm.prank(council);
        _g.setGuardian(address(safe), safeGuardian, true);
        vm.prank(council);
        _g.enforce(address(safe));
        assertEq(uint8(_g.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Enforced));
        vm.prank(safeGuardian);
        _g.lockdown(address(safe));
        assertEq(uint8(_g.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        vm.prank(council);
        _g.bypass(address(safe), 1 hours);
        assertEq(uint8(_g.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Bypass));
    }

    function test_timelocked_approval_uses_a_relative_ttl_so_late_execution_still_works() public {
        (CuratorGuard _g, CuratorGuardTimelock _tl, address _proposer, ) = _timelockFixture(2 days);
        bytes memory _payload = abi.encodeCall(MockProtocol.settleDeposit, (1));
        bytes memory _approve = abi.encodeCall(
            _g.approveTransaction,
            (address(safe), address(0), address(protocol), 0, _payload, Operation.Call, uint64(30 days))
        );
        vm.prank(_proposer);
        _tl.schedule(address(_g), 0, _approve, bytes32(0), bytes32(0), 2 days);
        // Executed 40 days late: an absolute expiry would have reverted; the TTL counts from execution.
        vm.warp(block.timestamp + 42 days);
        _tl.execute(address(_g), 0, _approve, bytes32(0), bytes32(0));
        bytes32 _id = _g.computeApprovalId(address(safe), address(0), address(protocol), 0, _payload, Operation.Call);
        assertEq(_g.approvalExpiry(_id), uint64(block.timestamp + 30 days));
    }

    function test_admin_delay_applies_to_the_admin_transfer_itself() public {
        (CuratorGuard _g, CuratorGuardTimelock _tl, address _proposer, ) = _timelockFixture(1 hours);
        address _dao = makeAddr("dao-executor");
        bytes memory _begin = abi.encodeCall(_g.beginDefaultAdminTransfer, (_dao));
        vm.prank(_proposer);
        _tl.schedule(address(_g), 0, _begin, bytes32(0), bytes32(0), 1 hours);
        vm.warp(block.timestamp + 1 hours);
        _tl.execute(address(_g), 0, _begin, bytes32(0), bytes32(0));
        (address _pending, uint48 _schedule) = _g.pendingDefaultAdmin();
        assertEq(_pending, _dao);
        assertEq(_schedule, uint48(block.timestamp + 1 days), "1-day admin delay from the constructor");
        vm.prank(_dao);
        vm.expectRevert(abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminDelay.selector, _schedule));
        _g.acceptDefaultAdminTransfer();
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(_dao);
        _g.acceptDefaultAdminTransfer();
        assertEq(_g.defaultAdmin(), _dao);
        assertFalse(_g.hasRole(_g.DEFAULT_ADMIN_ROLE(), address(_tl)));
    }

    /*//////////////////////////////////////////////////////////////
                  SECOND SAFE: POLICIES AND GUARDIANS ARE PER SAFE
    //////////////////////////////////////////////////////////////*/

    function test_second_safe_has_its_own_mode_guardians_and_bypass_window() public {
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        address _safeB = address(_proxy);
        vm.prank(_safeB);
        ISafe(_safeB).setGuard(address(guard));

        _enforce();
        _bypass(1 days);
        assertEq(uint8(guard.mode(_safeB)), uint8(CuratorGuardPolicy.Mode.Lockdown), "B untouched by A's bypass");
        (uint64 _untilB, ) = guard.bypassWindow(_safeB);
        assertEq(_untilB, 0);
        assertEq(guard.approvalEpoch(_safeB), 0, "B's epoch untouched");
        vm.prank(safeGuardian);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.lockdown(_safeB);
        vm.prank(council);
        guard.setGuardian(_safeB, safeGuardian, true);
        vm.prank(safeGuardian);
        guard.lockdown(_safeB);
        assertEq(guard.guardians(_safeB).length, 1);
    }

    /*//////////////////////////////////////////////////////////////
                 ROUND-1 (v2) REGRESSIONS: COUNCIL BYPASS WINDOW
    //////////////////////////////////////////////////////////////*/

    /// @dev R5-A F2: a council-opened window turns the policy off but can never be used to remove or
    ///      weaken the guard, not even with cooperating signers, nor to delegatecall arbitrary code.
    function test_council_bypass_window_blocks_what_weakens_the_safe_but_nothing_else() public {
        _enforce();
        _registerUnwrapper(address(multiSendCallOnly));
        vm.prank(council);
        guard.bypass(address(safe), 1 days);
        (, bool _isCouncil) = guard.bypassWindow(address(safe));
        assertTrue(_isCouncil, "council window");

        // Policy is off: a transfer to a stranger passes (owner rotation: at the end, it raises the threshold).
        assertTrue(_execSafeTx(address(token), 0, abi.encodeCall(IERC20.transfer, (attacker, 1)), Operation.Call));

        bytes[4] memory _denied = [
            abi.encodeCall(ISafe.setGuard, (address(0))),
            abi.encodeCall(ISafe.setModuleGuard, (address(0))),
            abi.encodeCall(ISafe.enableModule, (attacker)),
            abi.encodeWithSelector(0xf08a0323, attacker) // setFallbackHandler(address)
        ];
        for (uint256 i; i < 4; ++i) {
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, bytes4(_denied[i])));
            _execSafeTx(address(safe), 0, _denied[i], Operation.Call);
        }
        // Arbitrary delegatecall targets stay closed; a registered MultiSendCallOnly works, but its
        // entries are held to the same denylist.
        bytes memory _entryBatch = _multiSendCalldata(_entry(address(token), 0, abi.encodeCall(IERC20.transfer, (attacker, 1))));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.DelegateCallNotAllowed.selector, address(multiSend)));
        _execSafeTx(address(multiSend), 0, _entryBatch, Operation.DelegateCall);
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _entryBatch, Operation.DelegateCall), "plain batch passes");
        bytes memory _evilBatch = _multiSendCalldata(
            abi.encodePacked(
                _entry(address(token), 0, abi.encodeCall(IERC20.transfer, (attacker, 1))),
                _entry(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))))
            )
        );
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, ISafe.setGuard.selector));
        _execSafeTx(address(multiSendCallOnly), 0, _evilBatch, Operation.DelegateCall);
        // The guard itself is never a target.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, guard.lockdown.selector));
        _execSafeTx(address(guard), 0, abi.encodeCall(guard.lockdown, (address(safe))), Operation.Call);
        assertEq(_installedGuard(), address(guard), "guard still installed");
        // Owner rotation passes, never below a threshold of 2 (round 4).
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, ISafe.addOwnerWithThreshold.selector));
        _execSafeTx(address(safe), 0, abi.encodeCall(ISafe.addOwnerWithThreshold, (makeAddr("x"), 1)), Operation.Call);
        assertTrue(_execSafeTx(address(safe), 0, abi.encodeCall(ISafe.addOwnerWithThreshold, (makeAddr("x"), 2)), Operation.Call));
        assertEq(safe.getThreshold(), 2);
        // A guardian ends the window at once.
        vm.prank(safeGuardian);
        guard.lockdown(address(safe));
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
    }

    function test_admin_bypass_window_is_fully_inert() public {
        _enforce();
        _bypass(1 days);
        (, bool _isCouncil) = guard.bypassWindow(address(safe));
        assertFalse(_isCouncil);
        assertTrue(_execSafeTx(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call));
        assertEq(_installedGuard(), address(0));
    }

    /// @dev R5-B Info #3: a window opened inside an outer policy transaction cannot be used to nest a
    ///      same-Safe execution that would consume the outer snapshot.
    function test_nested_execution_after_a_mid_transaction_bypass_flip_is_rejected() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        FlipThenNestVenue _venue = new FlipThenNestVenue(guard, address(safe));
        bytes32 _councilRole = guard.COUNCIL_ROLE();
        vm.prank(vetro);
        guard.grantRole(_councilRole, address(_venue));
        _allow(address(_venue), FlipThenNestVenue.run.selector);
        uint256 _nonce = safe.nonce();
        bytes memory _inner = _innerExecCalldata(address(protocol), abi.encodeCall(MockProtocol.settleDeposit, (11)), _nonce + 1);
        assertTrue(_execSafeTx(address(_venue), 0, abi.encodeCall(FlipThenNestVenue.run, (_inner)), Operation.Call));
        assertEq(_venue.lastError(), abi.encodeWithSelector(CuratorGuard.NestedExecution.selector, address(safe)));
        assertEq(protocol.calls(), 0, "inner never executed");
        assertEq(safe.nonce(), _nonce + 1, "inner never ran");
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Bypass), "the flip itself landed");
    }

    function _innerExecCalldata(address to_, bytes memory data_, uint256 nonce_) internal view returns (bytes memory) {
        SafeTx memory _t = SafeTx(to_, 0, data_, Operation.Call, 0, 0, address(0), address(0));
        bytes32 _domainSeparator = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, address(safe)));
        bytes32 _hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), _domainSeparator, _safeTxHash(_t, nonce_)));
        return
            abi.encodeCall(
                ISafe.execTransaction,
                (to_, 0, data_, Operation.Call, 0, 0, 0, address(0), payable(address(0)), _sign(_hash))
            );
    }

    /*//////////////////////////////////////////////////////////////
          ROUND-1 (v2) REGRESSIONS: ROLES, DEADLINES, ADMIN GUARDS
    //////////////////////////////////////////////////////////////*/

    /// @dev R5-A F3: a compromised deployment-wide responder key is removable on the fast lane.
    function test_council_manages_deployment_wide_guardians() public {
        address _bot = makeAddr("bot");
        bytes32 _guardianRole = guard.GUARDIAN_ROLE();
        vm.prank(council);
        guard.setDeploymentGuardian(_bot, true);
        assertTrue(guard.hasRole(_guardianRole, _bot));
        vm.prank(_bot);
        guard.lockdown(attacker);
        vm.prank(council);
        guard.setDeploymentGuardian(_bot, false);
        assertFalse(guard.hasRole(_guardianRole, _bot));
        vm.prank(_bot);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.lockdown(attacker);
        address[2] memory _notAllowed = [globalGuardian, safeGuardian];
        for (uint256 i; i < 2; ++i) {
            vm.prank(_notAllowed[i]);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.setDeploymentGuardian(_bot, true);
        }
        vm.prank(vetro);
        guard.setDeploymentGuardian(_bot, true);
        assertTrue(guard.isGuardian(attacker, _bot));
    }

    /// @dev R5-A F4 / R5-C: a queued operation that nobody executed in time must be dead, not latent.
    function test_executeBefore_runs_as_the_caller_only_before_the_deadline() public {
        bytes memory _call = abi.encodeCall(guard.allowFunction, (address(safe), address(protocol), SETTLE, false, _noRules()));
        uint64 _now = uint64(block.timestamp);
        vm.prank(attacker);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector); // the inner authorisation is the caller's
        guard.executeBefore(_now + 1, _call);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, _now - 1));
        guard.executeBefore(_now - 1, _call);
        vm.prank(vetro);
        guard.executeBefore(_now, _call);
        assertTrue(_isAllowed(address(safe), address(protocol), SETTLE));
        // Inner revert reasons bubble up unchanged.
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(0)));
        guard.executeBefore(_now, abi.encodeCall(guard.allowFunction, (address(safe), address(0), SETTLE, false, _noRules())));
        // A council bypass wrapped by the council works the same way (msg.sender is kept).
        vm.prank(council);
        guard.executeBefore(_now, abi.encodeCall(guard.bypass, (address(safe), 1 hours)));
        (, bool _isCouncil) = guard.bypassWindow(address(safe));
        assertTrue(_isCouncil);
    }

    function test_timelocked_bypass_wrapped_with_a_deadline_dies_when_stale() public {
        (CuratorGuard _g, CuratorGuardTimelock _tl, address _proposer, ) = _timelockFixture(2 days);
        uint64 _deadline = uint64(block.timestamp + 2 days + 1 days);
        bytes memory _wrapped = abi.encodeCall(_g.executeBefore, (_deadline, abi.encodeCall(_g.bypass, (address(safe), 30 days))));
        vm.prank(_proposer);
        _tl.schedule(address(_g), 0, _wrapped, bytes32(0), bytes32(0), 2 days);
        // Executed in time: the window opens.
        vm.warp(block.timestamp + 2 days);
        _tl.execute(address(_g), 0, _wrapped, bytes32(0), bytes32(0));
        assertEq(uint8(_g.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Bypass));
        // The same payload scheduled again (new salt) and forgotten for months is dead.
        vm.prank(_proposer);
        _tl.schedule(address(_g), 0, _wrapped, bytes32(0), bytes32(uint256(1)), 2 days);
        vm.warp(block.timestamp + 90 days);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, _deadline));
        _tl.execute(address(_g), 0, _wrapped, bytes32(0), bytes32(uint256(1)));
        assertEq(uint8(_g.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown), "the earlier window expired, nothing new opened");
    }

    /// @dev R5-C: a typo'd admin delay (milliseconds) would take ~1,000 days to undo.
    function test_admin_delay_change_is_capped() public {
        uint48 _cap = _H().maxAdminDelay();
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminDelayTooLong.selector, uint48(86_400_000)));
        guard.changeDefaultAdminDelay(86_400_000);
        vm.prank(vetro);
        guard.changeDefaultAdminDelay(_cap);
        (uint48 _newDelay, ) = guard.pendingDefaultAdminDelay();
        assertEq(_newDelay, _cap);
    }

    /// @dev R5-C: `ttl` mistaken for an absolute timestamp fails closed (caps are days, timestamps are
    ///      ~1.7e9), it can never create a years-long approval or window.
    function test_absolute_timestamp_passed_as_ttl_or_duration_is_refused() public {
        uint64 _ts = uint64(block.timestamp + 1 days);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, _ts));
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, "", Operation.Call, _ts);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, _ts));
        guard.bypass(address(safe), _ts);
    }

    /*//////////////////////////////////////////////////////////////
               ROUND-1 (v2) REGRESSIONS: HOOK STATE MACHINE
    //////////////////////////////////////////////////////////////*/

    /// @dev R5-B S1: the Safe caches the guard before the pre-hook, so an approved `setGuard(0)` still
    ///      gets its post-hook on this guard and leaves the slot clean for a same-transaction re-install.
    function test_approved_guard_removal_still_gets_its_post_hook_and_leaves_no_state() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        bytes memory _remove = abi.encodeCall(ISafe.setGuard, (address(0)));
        _approve(address(safe), 0, _remove, Operation.Call);
        vm.expectCall(address(guard), abi.encodeWithSelector(guard.checkAfterExecution.selector));
        assertTrue(_execSafeTx(address(safe), 0, _remove, Operation.Call));
        assertEq(_installedGuard(), address(0));
        vm.prank(address(safe));
        safe.setGuard(address(guard));
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call), "no stale state");
    }

    /// @dev R5-B S2: the refund check precedes the approval branch, so a refund cannot ride on an
    ///      approval and a rejected attempt leaves the approval untouched.
    function test_gas_refund_is_rejected_even_with_a_live_approval() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        bytes32 _id = _approve(address(protocol), 0, _data, Operation.Call);
        vm.txGasPrice(1);
        vm.expectRevert(CuratorGuard.GasRefundNotAllowed.selector);
        _execSafeTxWithRefund(address(protocol), 0, _data, Operation.Call, 1, address(0), attacker);
        assertGt(guard.approvalExpiry(_id), 0, "approval untouched");
    }

    /// @dev R5-B I1 (documented behaviour): an approval that matches an allowlisted payload captures
    ///      it (the execution is reported as `Approval` and consumes it), with any `safeTxGas` since
    ///      round 8 (R8D-1).
    function test_approval_matching_an_allowlisted_payload_captures_it() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        bytes32 _id = _approve(address(protocol), 0, _data, Operation.Call);
        vm.expectEmit(true, false, false, false, address(guard));
        emit CuratorGuard.TransactionChecked(address(safe), bytes32(0), 0, CuratorGuard.Outcome.Approval);
        assertTrue(_execSafeTxWithGas(address(protocol), 0, _data, Operation.Call, 100_000), "approved, safeTxGas free");
        assertEq(guard.approvalExpiry(_id), 0, "consumed by the approved execution");
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call), "policy path afterwards");
    }

    /*//////////////////////////////////////////////////////////////
                    ROUND-2 (v2) REGRESSIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev R5-F: a `bypass(safe, 7)` typed in the wrong unit must not void every approval for a
    ///      useless seven-second window.
    function test_bypass_has_a_one_hour_floor() public {
        uint64 _floor = _H().minBypass();
        assertEq(_floor, 1 hours);
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, uint64(7)));
        guard.bypass(address(safe), 7);
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, _floor - 1));
        guard.bypass(address(safe), _floor - 1);
        vm.prank(council);
        guard.bypass(address(safe), _floor);
    }

    /// @dev R5-F: the dry run must mirror the council-window denylist.
    function test_dry_run_mirrors_the_council_window_denylist() public {
        vm.prank(council);
        guard.bypass(address(safe), 1 days);
        bytes memory _remove = abi.encodeCall(ISafe.setGuard, (address(0)));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, ISafe.setGuard.selector));
        guard.validateTransaction(address(safe), address(safe), 0, _remove, Operation.Call);
        guard.validateTransaction(address(safe), address(token), 0, abi.encodeCall(IERC20.transfer, (attacker, 1)), Operation.Call);
        _enforce();
        _bypass(1 days);
        guard.validateTransaction(address(safe), address(safe), 0, _remove, Operation.Call);
    }

    /// @dev R5-F: the constructor delay is capped like `changeDefaultAdminDelay`; the council and a
    ///      Safe configured only through modules / unwrappers can never become admin; a Safe is never
    ///      its own guardian.
    function test_constructor_delay_cap_admin_guards_and_self_guardian() public {
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminDelayTooLong.selector, uint48(31 days)));
        new CuratorGuard(31 days, vetro, council);
        new CuratorGuard(30 days, vetro, council);

        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, council));
        guard.beginDefaultAdminTransfer(council);
        address _other = makeAddr("module-only-safe");
        vm.prank(vetro);
        guard.setModuleAllowed(_other, attacker, true);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, _other));
        guard.beginDefaultAdminTransfer(_other);

        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(safe)));
        guard.setGuardian(address(safe), address(safe), true);
    }

    /// @dev R5-F: the handler getter answers in the setter's order.
    function test_required_handler_getter_matches_setter_order() public {
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(safe), attacker, true);
        (address _handler, bool _enforce) = guard.requiredFallbackHandler(address(safe));
        assertEq(_handler, attacker);
        assertTrue(_enforce);
    }

    /*//////////////////////////////////////////////////////////////
                    ROUND-3 (v2) REGRESSIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev R5-G F1: a forbidden canonical hash is re-allowed on the fast lane (the set stays fixed).
    function test_council_may_reallow_a_canonical_hash_after_a_guardian_forbid() public {
        bytes32 _v141 = _H().codehashV141();
        vm.prank(globalGuardian);
        guard.setUnwrapperCodehash(_v141, false);
        assertFalse(guard.isUnwrapperCodehash(_v141));
        vm.prank(globalGuardian);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.setUnwrapperCodehash(_v141, true);
        vm.prank(council);
        guard.setUnwrapperCodehash(_v141, true);
        assertTrue(guard.isUnwrapperCodehash(_v141));
        bytes32 _local = address(multiSendCallOnly).codehash;
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.UnwrapperCodehashNotAllowed.selector, _local));
        guard.setUnwrapperCodehash(_local, true);
    }

    /// @dev R5-G F2: resetting the handler to zero never weakens the Safe, so the council may approve
    ///      it (the fix for a guard installed before the handler was removed) and a council window lets
    ///      it through; any other handler, or a malformed payload, is still refused.
    function test_council_may_approve_resetting_the_handler_to_zero_but_nothing_else() public {
        bytes memory _reset = abi.encodeWithSelector(0xf08a0323, address(0));
        bytes memory _other = abi.encodeWithSelector(0xf08a0323, attacker);
        bytes memory _padded = abi.encodePacked(_reset, bytes1(0x00));
        bytes32 _id = _councilApprove(address(safe), 0, _reset, Operation.Call);
        assertGt(guard.approvalExpiry(_id), 0);
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, bytes4(_other), Operation.Call));
        guard.approveTransaction(address(safe), address(0), address(safe), 0, _other, Operation.Call, 1 days);
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, bytes4(_padded), Operation.Call));
        guard.approveTransaction(address(safe), address(0), address(safe), 0, _padded, Operation.Call, 1 days);
        assertTrue(_execSafeTx(address(safe), 0, _reset, Operation.Call), "approved reset executes");

        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        assertTrue(_execSafeTx(address(safe), 0, _reset, Operation.Call), "reset allowed inside a council window");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, bytes4(_other)));
        _execSafeTx(address(safe), 0, _other, Operation.Call);
    }

    /// @dev R5-G F3: the admin-is-guarded predicate is re-checked when the pending admin accepts.
    function test_pending_admin_configured_during_the_delay_cannot_accept() public {
        address _next = makeAddr("next-admin");
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(_next);
        vm.prank(council);
        guard.setGuardian(_next, guardian, true);
        vm.warp(block.timestamp + 1);
        vm.prank(_next);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, _next));
        guard.acceptDefaultAdminTransfer();
        vm.prank(council);
        guard.setGuardian(_next, guardian, false);
        vm.prank(_next);
        guard.acceptDefaultAdminTransfer();
        assertEq(guard.defaultAdmin(), _next);
    }
}
