// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {Test} from "forge-std/Test.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @dev Round 6 (docs/curator-guard.md section 13.2): the timelock's fixed topology and guard rails
///      (V2-63, V2-65, V2-67), the council lane's precompile exclusion (V2-69), the council
///      approval's module binding (V2-70), the constructor's council check, the `lockedAt` view and
///      the effective-mode admin hand-over (V2-72).
contract CuratorGuardTimelockTest is Test {
    address internal p1 = makeAddr("governance-proposer-safe");
    address internal p2 = makeAddr("break-glass-proposer-safe");
    address internal veto = makeAddr("dedicated-veto-safe");
    address internal veto2 = makeAddr("successor-veto-safe");
    address internal stranger = makeAddr("stranger");
    bytes32 internal constant NO_PREDECESSOR = bytes32(0);

    function setUp() public {
        vm.warp(1_700_000_000);
    }

    function _list(address a_) internal pure returns (address[] memory _l) {
        _l = new address[](1);
        _l[0] = a_;
    }

    function _list(address a_, address b_) internal pure returns (address[] memory _l) {
        _l = new address[](2);
        _l[0] = a_;
        _l[1] = b_;
    }

    /// @dev The production shape: two proposers, one dedicated veto Safe.
    function _deploy() internal returns (CuratorGuardTimelock) {
        return new CuratorGuardTimelock(2 days, _list(p1, p2), _list(veto));
    }

    /// @dev Schedules a self-call from `proposer_`, waits the delay and executes it as anyone.
    function _selfCall(CuratorGuardTimelock tl_, address proposer_, bytes memory data_, bytes32 salt_) internal {
        uint256 _delay = tl_.getMinDelay();
        vm.prank(proposer_);
        tl_.schedule(address(tl_), 0, data_, NO_PREDECESSOR, salt_, _delay);
        vm.warp(block.timestamp + _delay);
        vm.prank(stranger);
        tl_.execute(address(tl_), 0, data_, NO_PREDECESSOR, salt_);
    }

    function _selfCallReverts(CuratorGuardTimelock tl_, address proposer_, bytes memory data_, bytes32 salt_, bytes memory err_) internal {
        uint256 _delay = tl_.getMinDelay();
        vm.prank(proposer_);
        tl_.schedule(address(tl_), 0, data_, NO_PREDECESSOR, salt_, _delay);
        vm.warp(block.timestamp + _delay);
        vm.prank(stranger);
        vm.expectRevert(err_);
        tl_.execute(address(tl_), 0, data_, NO_PREDECESSOR, salt_);
    }

    function test_topology_is_fixed_at_construction_with_no_deployer_admin() public {
        CuratorGuardTimelock _tl = _deploy();
        assertTrue(_tl.hasRole(_tl.PROPOSER_ROLE(), p1));
        assertTrue(_tl.hasRole(_tl.PROPOSER_ROLE(), p2));
        assertTrue(_tl.hasRole(_tl.CANCELLER_ROLE(), veto), "the designated veto");
        assertFalse(_tl.hasRole(_tl.PROPOSER_ROLE(), veto), "the veto proposes nothing");
        assertFalse(_tl.hasRole(_tl.CANCELLER_ROLE(), p1), "OpenZeppelin's proposer = canceller is undone");
        assertFalse(_tl.hasRole(_tl.CANCELLER_ROLE(), p2));
        assertTrue(_tl.hasRole(_tl.EXECUTOR_ROLE(), address(0)), "open executor");
        assertTrue(_tl.hasRole(_tl.DEFAULT_ADMIN_ROLE(), address(_tl)), "self-administered");
        assertFalse(_tl.hasRole(_tl.DEFAULT_ADMIN_ROLE(), address(this)), "the deployer never held the admin role");
        assertEq(_tl.proposerCount(), 2);
        assertEq(_tl.cancellerCount(), 1);
        assertEq(_tl.getMinDelay(), 2 days);
        // Duplicates in a list are one holder; two veto Safes are expressible (the deploy script refuses).
        CuratorGuardTimelock _tl2 = new CuratorGuardTimelock(2 days, _list(p1, p1), _list(veto, veto2));
        assertEq(_tl2.proposerCount(), 1);
        assertEq(_tl2.cancellerCount(), 2);
    }

    /// @dev V2-74: proposing and vetoing are separated, at construction and ever after. A canceller
    ///      that could also propose would be an unvetoed takeover once compromised.
    function test_a_canceller_never_proposes_and_a_proposer_never_cancels() public {
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.CancellerCannotPropose.selector, p1));
        new CuratorGuardTimelock(2 days, _list(p1, p2), _list(p1));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.CancellerCannotPropose.selector, p2));
        new CuratorGuardTimelock(2 days, _list(p1, p2), _list(veto, p2));
        CuratorGuardTimelock _tl = _deploy();
        bytes32 _prop = _tl.PROPOSER_ROLE();
        bytes32 _canc = _tl.CANCELLER_ROLE();
        _selfCallReverts(_tl, p1, abi.encodeCall(IAccessControl.grantRole, (_canc, p2)), "pc", abi.encodeWithSelector(CuratorGuardTimelock.ProposerCannotCancel.selector, p2));
        _selfCallReverts(_tl, p1, abi.encodeCall(IAccessControl.grantRole, (_prop, veto)), "cp", abi.encodeWithSelector(CuratorGuardTimelock.CancellerCannotPropose.selector, veto));
        // A fresh account may take either role, and the other one only after giving the first up.
        _selfCall(_tl, p1, abi.encodeCall(IAccessControl.grantRole, (_canc, veto2)), "g1");
        _selfCallReverts(_tl, p1, abi.encodeCall(IAccessControl.grantRole, (_prop, veto2)), "g2", abi.encodeWithSelector(CuratorGuardTimelock.CancellerCannotPropose.selector, veto2));
        _selfCall(_tl, p1, abi.encodeCall(IAccessControl.revokeRole, (_canc, veto2)), "g3");
        _selfCall(_tl, p1, abi.encodeCall(IAccessControl.grantRole, (_prop, veto2)), "g4");
        assertTrue(_tl.hasRole(_prop, veto2));
        assertFalse(_tl.hasRole(_canc, veto2));
    }

    /// @dev R7A-1: `address(0)` can neither schedule nor cancel; counting it as a holder would defeat
    ///      the last-holder rail, so it is refused everywhere but as the open executor.
    function test_the_zero_address_never_holds_a_gated_role() public {
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.ZeroAddressHolder.selector, keccak256("PROPOSER_ROLE")));
        new CuratorGuardTimelock(2 days, _list(address(0)), _list(veto));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.ZeroAddressHolder.selector, keccak256("CANCELLER_ROLE")));
        new CuratorGuardTimelock(2 days, _list(p1, p2), _list(address(0)));
        CuratorGuardTimelock _tl = _deploy();
        for (uint256 i; i < 3; ++i) {
            bytes32 _role = i == 0 ? _tl.PROPOSER_ROLE() : i == 1 ? _tl.CANCELLER_ROLE() : _tl.DEFAULT_ADMIN_ROLE();
            _selfCallReverts(_tl, p1, abi.encodeCall(IAccessControl.grantRole, (_role, address(0))), bytes32(i), abi.encodeWithSelector(CuratorGuardTimelock.ZeroAddressHolder.selector, _role));
        }
        assertEq(_tl.proposerCount(), 2);
        assertEq(_tl.cancellerCount(), 1);
        assertTrue(_tl.hasRole(_tl.EXECUTOR_ROLE(), address(0)));
    }

    function test_constructor_refuses_an_empty_role_or_a_delay_out_of_range() public {
        vm.expectRevert(CuratorGuardTimelock.NoProposer.selector);
        new CuratorGuardTimelock(2 days, new address[](0), _list(veto));
        vm.expectRevert(CuratorGuardTimelock.NoCanceller.selector);
        new CuratorGuardTimelock(2 days, _list(p1, p2), new address[](0));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, 1 days - 1));
        new CuratorGuardTimelock(1 days - 1, _list(p1, p2), _list(veto));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, 1 hours));
        new CuratorGuardTimelock(1 hours, _list(p1, p2), _list(veto)); // the pre-round-13 floor is refused
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, 30 days + 1));
        new CuratorGuardTimelock(30 days + 1, _list(p1, p2), _list(veto));
        assertEq(new CuratorGuardTimelock(1 days, _list(p1, p2), _list(veto)).getMinDelay(), 1 days);
        assertEq(new CuratorGuardTimelock(30 days, _list(p1, p2), _list(veto)).getMinDelay(), 30 days);
    }

    /// @dev R6D-5: the effective delay is clamped whatever the raw slot holds, exact at both edges
    ///      (R7-B). Since round 8 an `updateDelay` outside the clamp is refused when it is PROPOSED
    ///      (`CuratorGuardRound8Timelock.t.sol`), so the raw slot is written directly here: the clamp
    ///      stays as the last line.
    function test_min_delay_is_clamped_whatever_the_raw_slot_holds() public {
        CuratorGuardTimelock _tl = _deploy();
        bytes32 _slot = bytes32(uint256(2)); // `_minDelay` (forge inspect storage-layout)
        vm.store(address(_tl), _slot, bytes32(uint256(48)));
        assertEq(_tl.getMinDelay(), 1 days, "floor");
        vm.prank(p2);
        vm.expectRevert(abi.encodeWithSelector(TimelockController.TimelockInsufficientDelay.selector, 48, 1 days));
        _tl.schedule(address(_tl), 0, "", NO_PREDECESSOR, "x", 48);
        vm.store(address(_tl), _slot, bytes32(uint256(172_800_000)));
        assertEq(_tl.getMinDelay(), 30 days, "cap");
        vm.store(address(_tl), _slot, bytes32(type(uint256).max));
        assertEq(_tl.getMinDelay(), 30 days, "no overflow in schedule");
        vm.store(address(_tl), _slot, bytes32(uint256(1 days - 1)));
        assertEq(_tl.getMinDelay(), 1 days, "1 d - 1 s reads as the floor");
        vm.store(address(_tl), _slot, bytes32(uint256(1 days + 1)));
        assertEq(_tl.getMinDelay(), 1 days + 1, "1 d + 1 s is inside the range");
        vm.store(address(_tl), _slot, bytes32(uint256(30 days + 1)));
        assertEq(_tl.getMinDelay(), 30 days, "30 d + 1 s reads as the cap");
        vm.store(address(_tl), _slot, bytes32(uint256(30 days - 1)));
        assertEq(_tl.getMinDelay(), 30 days - 1, "30 d - 1 s is inside the range");
        vm.store(address(_tl), _slot, bytes32(uint256(2 days)));
        _selfCall(_tl, p1, abi.encodeCall(TimelockController.updateDelay, (3 days)), "fine");
        assertEq(_tl.getMinDelay(), 3 days);
    }

    /// @dev R6D-5: the open executor and the timelock's own admin role cannot be dropped, through
    ///      `revokeRole` or `renounceRole`.
    function test_open_executor_and_self_admin_cannot_be_revoked() public {
        CuratorGuardTimelock _tl = _deploy();
        bytes32 _exec = _tl.EXECUTOR_ROLE();
        bytes32 _admin = _tl.DEFAULT_ADMIN_ROLE();
        _selfCallReverts(_tl, p1, abi.encodeCall(IAccessControl.revokeRole, (_exec, address(0))), "e1", abi.encodeWithSelector(CuratorGuardTimelock.OpenExecutorRequired.selector));
        _selfCallReverts(_tl, p1, abi.encodeCall(IAccessControl.revokeRole, (_admin, address(_tl))), "a1", abi.encodeWithSelector(CuratorGuardTimelock.SelfAdminRequired.selector));
        _selfCallReverts(_tl, p1, abi.encodeCall(IAccessControl.renounceRole, (_admin, address(_tl))), "a2", abi.encodeWithSelector(CuratorGuardTimelock.SelfAdminRequired.selector));
        // A named executor may be added next to the open one, and removed again.
        _selfCall(_tl, p1, abi.encodeCall(IAccessControl.grantRole, (_exec, stranger)), "e2");
        assertTrue(_tl.hasRole(_exec, stranger));
        _selfCall(_tl, p1, abi.encodeCall(IAccessControl.revokeRole, (_exec, stranger)), "e3");
        assertFalse(_tl.hasRole(_exec, stranger));
        assertTrue(_tl.hasRole(_exec, address(0)));
        assertTrue(_tl.hasRole(_admin, address(_tl)));
    }

    /// @dev R6D-5 / R6D-8: both proposers rotating from one bad list cannot empty a role; a revoke of a
    ///      role not held leaves the counters alone (R7-B).
    function test_last_proposer_and_last_canceller_cannot_be_removed() public {
        CuratorGuardTimelock _tl = _deploy();
        bytes32 _prop = _tl.PROPOSER_ROLE();
        bytes32 _canc = _tl.CANCELLER_ROLE();
        _selfCallReverts(_tl, p1, abi.encodeCall(IAccessControl.revokeRole, (_canc, veto)), "c1", abi.encodeWithSelector(CuratorGuardTimelock.LastRoleHolder.selector, _canc));
        _selfCall(_tl, p1, abi.encodeCall(IAccessControl.revokeRole, (_prop, stranger)), "np1");
        _selfCall(_tl, p1, abi.encodeCall(IAccessControl.revokeRole, (_canc, p2)), "nc1"); // a proposer never held it
        _selfCall(_tl, p1, abi.encodeCall(IAccessControl.renounceRole, (_prop, address(_tl))), "nr1"); // the timelock holds no proposer role
        assertEq(_tl.proposerCount(), 2, "no-op revokes leave proposerCount");
        assertEq(_tl.cancellerCount(), 1, "no-op revokes leave cancellerCount");
        _selfCall(_tl, p1, abi.encodeCall(IAccessControl.revokeRole, (_prop, p2)), "p1");
        assertEq(_tl.proposerCount(), 1);
        _selfCallReverts(_tl, p1, abi.encodeCall(IAccessControl.revokeRole, (_prop, p1)), "p2", abi.encodeWithSelector(CuratorGuardTimelock.LastRoleHolder.selector, _prop));
        // Rotation works in the right order: grant the successor, then revoke.
        _selfCall(_tl, p1, abi.encodeCall(IAccessControl.grantRole, (_canc, veto2)), "c2");
        assertEq(_tl.cancellerCount(), 2);
        _selfCall(_tl, p1, abi.encodeCall(IAccessControl.revokeRole, (_canc, veto)), "c3");
        assertEq(_tl.cancellerCount(), 1);
        assertTrue(_tl.hasRole(_canc, veto2));
        assertFalse(_tl.hasRole(_canc, veto));
        // Re-granting a held role changes no count.
        _selfCall(_tl, p1, abi.encodeCall(IAccessControl.grantRole, (_prop, p1)), "p3");
        assertEq(_tl.proposerCount(), 1);
    }

    /// @dev R6D-3 / V2-74: a compromised proposer is cancellable and removable; a compromised veto
    ///      Safe is a deadlock (it schedules nothing and vetoes its own removal), never a takeover.
    function test_a_compromised_proposer_is_removable_and_a_compromised_veto_is_only_a_deadlock() public {
        CuratorGuardTimelock _tl = _deploy();
        bytes32 _prop = _tl.PROPOSER_ROLE();
        bytes32 _canc = _tl.CANCELLER_ROLE();
        // p2's hostile operation: the veto stops it.
        bytes memory _hostile = abi.encodeCall(IAccessControl.grantRole, (_prop, stranger));
        vm.prank(p2);
        _tl.schedule(address(_tl), 0, _hostile, NO_PREDECESSOR, "h", 2 days);
        bytes32 _hid = _tl.hashOperation(address(_tl), 0, _hostile, NO_PREDECESSOR, "h");
        vm.prank(veto);
        _tl.cancel(_hid);
        assertFalse(_tl.isOperationPending(_hid));
        // p2's removal: p2 cannot cancel it.
        bytes memory _remove = abi.encodeCall(IAccessControl.revokeRole, (_prop, p2));
        vm.prank(p1);
        _tl.schedule(address(_tl), 0, _remove, NO_PREDECESSOR, "r", 2 days);
        bytes32 _rid = _tl.hashOperation(address(_tl), 0, _remove, NO_PREDECESSOR, "r");
        vm.prank(p2);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, p2, _canc));
        _tl.cancel(_rid);
        vm.warp(block.timestamp + 2 days);
        _tl.execute(address(_tl), 0, _remove, NO_PREDECESSOR, "r");
        assertFalse(_tl.hasRole(_prop, p2));
        // The veto Safe cannot schedule anything, and the one thing it can keep is its own seat.
        vm.prank(veto);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, veto, _prop));
        _tl.schedule(address(_tl), 0, _hostile, NO_PREDECESSOR, "v", 2 days);
        bytes memory _removeVeto = abi.encodeCall(IAccessControl.revokeRole, (_canc, veto));
        vm.prank(p1);
        _tl.schedule(address(_tl), 0, _removeVeto, NO_PREDECESSOR, "rv", 2 days);
        bytes32 _rv = _tl.hashOperation(address(_tl), 0, _removeVeto, NO_PREDECESSOR, "rv");
        vm.prank(veto);
        _tl.cancel(_rv);
        assertTrue(_tl.hasRole(_canc, veto));
    }
}

contract CuratorGuardRound6Test is CuratorGuardTestBase {
    bytes4 internal constant ADD_OWNER = bytes4(keccak256("addOwnerWithThreshold(address,uint256)"));
    bytes4 internal constant SWAP_OWNER = bytes4(keccak256("swapOwner(address,address,address)"));

    /// @dev V2-69: the identity precompile (0x04) has no code and echoes an EIP-1271 query back as the
    ///      magic value on Safe builds without the pre-call code check: the council lane refuses the
    ///      whole low address range as a new owner; the admin still may (through the timelock).
    function test_council_cannot_bring_in_a_precompile_as_owner() public {
        address[3] memory _low = [address(0x4), address(0x1), address(0xffff)];
        for (uint256 i; i < _low.length; ++i) {
            bytes memory _add = abi.encodeCall(ISafe.addOwnerWithThreshold, (_low[i], 2));
            bytes memory _swap = abi.encodeWithSelector(SWAP_OWNER, address(0x1), curator, _low[i]);
            vm.prank(council);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, ADD_OWNER, Operation.Call));
            guard.approveTransaction(address(safe), address(0), address(safe), 0, _add, Operation.Call, 1 days);
            vm.prank(council);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, SWAP_OWNER, Operation.Call));
            guard.approveTransaction(address(safe), address(0), address(safe), 0, _swap, Operation.Call, 1 days);
            assertGt(guard.approvalExpiry(_approve(address(safe), 0, _add, Operation.Call)), 0, "admin may");
        }
        // The first address above the range, keyless, is a plain (dead) seat the rule cannot tell apart.
        bytes memory _ok = abi.encodeCall(ISafe.addOwnerWithThreshold, (address(0x10000), 2));
        assertGt(guard.approvalExpiry(_councilApprove(address(safe), 0, _ok, Operation.Call)), 0);
        // Inside a council window: live hook and dry run agree.
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        bytes memory _add4 = abi.encodeCall(ISafe.addOwnerWithThreshold, (address(0x4), 2));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, ADD_OWNER));
        guard.validateTransaction(address(safe), address(safe), 0, _add4, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, ADD_OWNER));
        _execSafeTx(address(safe), 0, _add4, Operation.Call);
        guard.validateTransaction(address(safe), address(safe), 0, _ok, Operation.Call);
    }

    /// @dev R6A-6: the council is exempt from nothing and the admin from everything, so one account
    ///      cannot be both from the constructor either (`beginDefaultAdminTransfer` already refused it).
    function test_constructor_refuses_the_council_as_admin() public {
        address _x = makeAddr("one-safe-for-both");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, _x));
        new CuratorGuard(1 days, _x, _x);
        CuratorGuard _g = new CuratorGuard(1 days, _x, address(0));
        assertEq(_g.defaultAdmin(), _x);
        assertFalse(_g.hasRole(_g.COUNCIL_ROLE(), _x));
    }

    /// @dev R6D-12: the cooldown reference is readable (bots and the sync task need it).
    function test_lockedAt_view_tracks_the_last_lockdown() public {
        _addGuardian(guardian);
        assertEq(guard.lockedAt(address(safe)), 0, "never locked");
        _enforce();
        assertEq(guard.lockedAt(address(safe)), 0, "enforce does not touch it");
        vm.warp(block.timestamp + 10);
        vm.prank(guardian);
        guard.lockdown(address(safe));
        assertEq(guard.lockedAt(address(safe)), uint64(block.timestamp));
        vm.warp(block.timestamp + 3 hours);
        vm.prank(council);
        guard.enforce(address(safe));
        assertEq(guard.lockedAt(address(safe)), uint64(block.timestamp - 3 hours), "a lift keeps the reference");
        vm.prank(council);
        guard.lockdownAndRevoke(address(safe));
        assertEq(guard.lockedAt(address(safe)), uint64(block.timestamp), "every lockdown moves it");
        assertEq(guard.lockedAt(makeAddr("other-safe")), 0, "per Safe");
    }

    /// @dev V2-72: a council window on the pending admin blocks the acceptance only while it is live;
    ///      once it expired the hand-over proceeds without an explicit `lockdown`.
    function test_admin_handover_proceeds_once_a_council_window_on_the_pending_admin_expired() public {
        address _dao = makeAddr("dao");
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(_dao);
        vm.prank(council);
        guard.bypass(_dao, 1 hours);
        vm.warp(block.timestamp + 30 minutes);
        vm.prank(_dao);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, _dao));
        guard.acceptDefaultAdminTransfer();
        vm.warp(block.timestamp + 31 minutes);
        vm.prank(_dao);
        guard.acceptDefaultAdminTransfer();
        assertEq(guard.defaultAdmin(), _dao);
        // The stale raw window on the new admin is inert: the admin is exempt from the hooks.
        (uint64 _until, bool _council) = guard.bypassWindow(_dao);
        assertTrue(_until != 0 && _council);
        assertEq(uint8(guard.mode(_dao)), uint8(CuratorGuardPolicy.Mode.Lockdown));
    }

    /// @dev V2-70: a council approval bound to a module names an allowlisted module only (the fast
    ///      lane never re-arms a module a guardian removed); the admin's approvals are not bound.
    function test_council_approvals_bind_to_allowlisted_modules_only() public {
        _addGuardian(guardian);
        address _module = makeAddr("automation-module");
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, _module));
        guard.approveTransaction(address(safe), _module, address(protocol), 0, _settle, Operation.Call, 1 days);
        vm.prank(vetro);
        bytes32 _adminId = guard.approveTransaction(address(safe), _module, address(protocol), 0, _settle, Operation.Call, 1 days);
        assertGt(guard.approvalExpiry(_adminId), 0, "admin may");
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), _module, true);
        vm.prank(council);
        bytes32 _id = guard.approveTransaction(address(safe), _module, address(protocol), 0, _settle, Operation.Call, 1 days);
        assertGt(guard.approvalExpiry(_id), 0, "allowlisted module");
        vm.prank(guardian);
        guard.setModuleAllowed(address(safe), _module, false);
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, _module));
        guard.approveTransaction(address(safe), _module, address(protocol), 0, _settle, Operation.Call, 1 days);
        // Owner-path approvals (executor 0) are unaffected.
        assertGt(guard.approvalExpiry(_councilApprove(address(protocol), 0, _settle, Operation.Call)), 0);
    }
}
