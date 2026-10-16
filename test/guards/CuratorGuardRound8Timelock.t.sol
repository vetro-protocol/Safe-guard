// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {Test} from "forge-std/Test.sol";

import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";

/// @dev Round 8 (docs/curator-guard.md section 13.2): the timelock's proposal-time rails (delay cap,
///      codeless targets, `updateDelay` range), the self-holder and single-admin rails, the bypass
///      attempts against them and the liveness of every legitimate rotation in one batch (the clamp
///      itself is pinned in `CuratorGuardRound6.t.sol`, on the raw slot).
contract CuratorGuardRound8TimelockTest is Test {
    address internal p1 = makeAddr("governance-proposer-safe");
    address internal p2 = makeAddr("break-glass-proposer-safe");
    address internal p3 = makeAddr("new-proposer-1");
    address internal p4 = makeAddr("new-proposer-2");
    address internal veto = makeAddr("dedicated-veto-safe");
    address internal veto2 = makeAddr("successor-veto-safe");
    address internal stranger = makeAddr("stranger");
    address internal guardLike = address(new Round8Sink());
    bytes32 internal constant NO_PRED = bytes32(0);
    CuratorGuardTimelock internal tl;
    bytes32 internal PROP;
    bytes32 internal CANC;
    bytes32 internal EXEC;
    bytes32 internal ADMIN;

    function setUp() public {
        vm.warp(1_700_000_000);
        tl = new CuratorGuardTimelock(2 days, _list(p1, p2), _list(veto));
        PROP = tl.PROPOSER_ROLE();
        CANC = tl.CANCELLER_ROLE();
        EXEC = tl.EXECUTOR_ROLE();
        ADMIN = tl.DEFAULT_ADMIN_ROLE();
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

    function _selfBatch(bytes[] memory payloads_) internal view returns (address[] memory _t, uint256[] memory _v) {
        _t = new address[](payloads_.length);
        _v = new uint256[](payloads_.length);
        for (uint256 i; i < payloads_.length; ++i) _t[i] = address(tl);
    }

    function _runSelfBatch(address proposer_, bytes[] memory payloads_, bytes32 salt_) internal returns (bytes32 _id) {
        (address[] memory _t, uint256[] memory _v) = _selfBatch(payloads_);
        uint256 _delay = tl.getMinDelay();
        vm.prank(proposer_);
        tl.scheduleBatch(_t, _v, payloads_, NO_PRED, salt_, _delay);
        _id = tl.hashOperationBatch(_t, _v, payloads_, NO_PRED, salt_);
        vm.warp(block.timestamp + _delay);
        vm.prank(stranger);
        tl.executeBatch(_t, _v, payloads_, NO_PRED, salt_);
    }

    function _runSelfBatchExpect(address proposer_, bytes[] memory payloads_, bytes32 salt_, bytes memory err_) internal {
        (address[] memory _t, uint256[] memory _v) = _selfBatch(payloads_);
        uint256 _delay = tl.getMinDelay();
        vm.prank(proposer_);
        tl.scheduleBatch(_t, _v, payloads_, NO_PRED, salt_, _delay);
        vm.warp(block.timestamp + _delay);
        vm.prank(stranger);
        vm.expectRevert(err_);
        tl.executeBatch(_t, _v, payloads_, NO_PRED, salt_);
    }

    function _selfCall(address proposer_, bytes memory data_, bytes32 salt_) internal {
        uint256 _delay = tl.getMinDelay();
        vm.prank(proposer_);
        tl.schedule(address(tl), 0, data_, NO_PRED, salt_, _delay);
        vm.warp(block.timestamp + _delay);
        vm.prank(stranger);
        tl.execute(address(tl), 0, data_, NO_PRED, salt_);
    }

    function _selfCallReverts(address proposer_, bytes memory data_, bytes32 salt_, bytes memory err_) internal {
        uint256 _delay = tl.getMinDelay();
        vm.prank(proposer_);
        tl.schedule(address(tl), 0, data_, NO_PRED, salt_, _delay);
        vm.warp(block.timestamp + _delay);
        vm.prank(stranger);
        vm.expectRevert(err_);
        tl.execute(address(tl), 0, data_, NO_PRED, salt_);
    }

    /*//////////////////////////////////////////////////////////////
                         F-4 / F-5: RAILS AND BYPASSES
    //////////////////////////////////////////////////////////////*/

    function test_timelock_never_holds_a_gated_role_by_construction_or_grant() public {
        address _predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.SelfHolder.selector, keccak256("PROPOSER_ROLE")));
        new CuratorGuardTimelock(2 days, _list(_predicted), _list(veto));
        _predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.SelfHolder.selector, keccak256("CANCELLER_ROLE")));
        new CuratorGuardTimelock(2 days, _list(p1), _list(_predicted));
        _selfCallReverts(p1, abi.encodeCall(IAccessControl.grantRole, (PROP, address(tl))), "sp", abi.encodeWithSelector(CuratorGuardTimelock.SelfHolder.selector, PROP));
        _selfCallReverts(p1, abi.encodeCall(IAccessControl.grantRole, (CANC, address(tl))), "sc", abi.encodeWithSelector(CuratorGuardTimelock.SelfHolder.selector, CANC));
        // the executor role to self is harmless and still allowed (the role is open anyway)
        _selfCall(p1, abi.encodeCall(IAccessControl.grantRole, (EXEC, address(tl))), "se");
        assertTrue(tl.hasRole(EXEC, address(tl)));
        assertEq(tl.proposerCount(), 2);
        assertEq(tl.cancellerCount(), 1);
    }

    /// Bypass attempts: through a batch, through a nested `execute`, mixed with other role changes,
    /// and the phantom-then-strip sequence of the pristine PoC. All refused at the single writer.
    function test_bypass_attempts_batch_and_nested_execute() public {
        bytes[] memory _p = new bytes[](3);
        _p[0] = abi.encodeCall(IAccessControl.grantRole, (PROP, address(tl)));
        _p[1] = abi.encodeCall(IAccessControl.revokeRole, (PROP, p1));
        _p[2] = abi.encodeCall(IAccessControl.revokeRole, (PROP, p2));
        _runSelfBatchExpect(p1, _p, "rot", abi.encodeWithSelector(CuratorGuardTimelock.SelfHolder.selector, PROP));
        // nested: op A = execute(op B), op B = grantRole(CANCELLER, tl)
        bytes memory _b = abi.encodeCall(IAccessControl.grantRole, (CANC, address(tl)));
        uint256 _delay = tl.getMinDelay();
        vm.prank(p1);
        tl.schedule(address(tl), 0, _b, NO_PRED, "B", _delay);
        bytes memory _a = abi.encodeCall(TimelockController.execute, (address(tl), 0, _b, NO_PRED, bytes32("B")));
        vm.prank(p1);
        tl.schedule(address(tl), 0, _a, NO_PRED, "A", _delay);
        vm.warp(block.timestamp + _delay);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.SelfHolder.selector, CANC));
        tl.execute(address(tl), 0, _a, NO_PRED, "A");
        assertFalse(tl.hasRole(PROP, address(tl)) || tl.hasRole(CANC, address(tl)));
        assertEq(tl.proposerCount(), 2);
    }

    function test_no_second_admin_ever_and_self_grant_stays_idempotent() public {
        _selfCallReverts(p1, abi.encodeCall(IAccessControl.grantRole, (ADMIN, stranger)), "a1", abi.encodeWithSelector(CuratorGuardTimelock.SelfAdminRequired.selector));
        _selfCallReverts(p1, abi.encodeCall(IAccessControl.grantRole, (ADMIN, p1)), "a2", abi.encodeWithSelector(CuratorGuardTimelock.SelfAdminRequired.selector));
        _selfCallReverts(p1, abi.encodeCall(IAccessControl.grantRole, (ADMIN, address(0))), "a3", abi.encodeWithSelector(CuratorGuardTimelock.ZeroAddressHolder.selector, ADMIN));
        _selfCall(p1, abi.encodeCall(IAccessControl.grantRole, (ADMIN, address(tl))), "a4"); // no-op
        bytes[] memory _p = new bytes[](2);
        _p[0] = abi.encodeCall(IAccessControl.grantRole, (PROP, p3));
        _p[1] = abi.encodeCall(IAccessControl.grantRole, (ADMIN, p3));
        _runSelfBatchExpect(p1, _p, "mix", abi.encodeWithSelector(CuratorGuardTimelock.SelfAdminRequired.selector));
        assertFalse(tl.hasRole(ADMIN, stranger) || tl.hasRole(ADMIN, p1) || tl.hasRole(ADMIN, p3));
        assertTrue(tl.hasRole(ADMIN, address(tl)));
        // a stranger / proposer calling grantRole directly is still the access error
        vm.prank(p1);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, p1, ADMIN));
        tl.grantRole(PROP, p3);
    }

    /*//////////////////////////////////////////////////////////////
                       LIVENESS: LEGITIMATE ROTATIONS
    //////////////////////////////////////////////////////////////*/

    /// Both proposers AND the veto rotated in ONE batch under every rail (grants first, then revokes).
    function test_full_rotation_in_one_batch_still_works() public {
        bytes[] memory _p = new bytes[](6);
        _p[0] = abi.encodeCall(IAccessControl.grantRole, (PROP, p3));
        _p[1] = abi.encodeCall(IAccessControl.grantRole, (PROP, p4));
        _p[2] = abi.encodeCall(IAccessControl.grantRole, (CANC, veto2));
        _p[3] = abi.encodeCall(IAccessControl.revokeRole, (PROP, p1));
        _p[4] = abi.encodeCall(IAccessControl.revokeRole, (PROP, p2));
        _p[5] = abi.encodeCall(IAccessControl.revokeRole, (CANC, veto));
        bytes32 _id = _runSelfBatch(p1, _p, "rotate-all");
        assertTrue(tl.isOperationDone(_id));
        assertTrue(tl.hasRole(PROP, p3) && tl.hasRole(PROP, p4) && tl.hasRole(CANC, veto2));
        assertFalse(tl.hasRole(PROP, p1) || tl.hasRole(PROP, p2) || tl.hasRole(CANC, veto));
        assertEq(tl.proposerCount(), 2);
        assertEq(tl.cancellerCount(), 1);
        // the new proposers can schedule and the new veto can cancel
        vm.prank(p3);
        tl.schedule(guardLike, 0, abi.encodeCall(Round8Sink.ping, ()), NO_PRED, "n", 2 days);
        bytes32 _nid = tl.hashOperation(guardLike, 0, abi.encodeCall(Round8Sink.ping, ()), NO_PRED, "n");
        vm.prank(veto2);
        tl.cancel(_nid);
        // revokes-before-grants in one batch is still refused by the last-holder rail (unchanged)
        bytes[] memory _q = new bytes[](2);
        _q[0] = abi.encodeCall(IAccessControl.revokeRole, (CANC, veto2));
        _q[1] = abi.encodeCall(IAccessControl.grantRole, (CANC, veto));
        _runSelfBatchExpect(p3, _q, "wrong-order", abi.encodeWithSelector(CuratorGuardTimelock.LastRoleHolder.selector, CANC));
    }

    /// A delay change inside the range, a widening-shaped call to a contract, a value transfer to a
    /// key, and an empty batch all still schedule and execute.
    function test_legitimate_operations_still_schedule() public {
        _selfCall(p1, abi.encodeCall(TimelockController.updateDelay, (3 days)), "d");
        assertEq(tl.getMinDelay(), 3 days);
        vm.prank(p1);
        tl.schedule(guardLike, 0, abi.encodeCall(Round8Sink.ping, ()), NO_PRED, "w", 3 days);
        vm.prank(p1);
        tl.schedule(stranger, 1 ether, "", NO_PRED, "v", 3 days); // plain value transfer to a key: allowed
        vm.prank(p1);
        // G10c-1: only the live minDelay schedules; a longer delay would let one proposer take another's operation id.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, 30 days));
        tl.schedule(guardLike, 0, "", NO_PRED, "e", 30 days);
        address[] memory _t = new address[](0);
        bytes[] memory _pl = new bytes[](0);
        uint256[] memory _v = new uint256[](0);
        vm.prank(p1);
        tl.scheduleBatch(_t, _v, _pl, NO_PRED, "empty", 3 days);
    }

    /*//////////////////////////////////////////////////////////////
                              TL1: RAILS
    //////////////////////////////////////////////////////////////*/

    function test_schedule_refusals_and_the_proposer_check_comes_first() public {
        // a stranger gets the access error, not a rail error (refinement)
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, PROP));
        tl.schedule(stranger, 0, "", NO_PRED, "s", type(uint256).max);
        vm.prank(p1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, 172_800_000));
        tl.schedule(guardLike, 0, "", NO_PRED, "ms", 172_800_000);
        vm.prank(p1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, type(uint256).max));
        tl.schedule(guardLike, 0, "", NO_PRED, "max", type(uint256).max);
        vm.prank(p1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.TargetHasNoCode.selector, stranger));
        tl.schedule(stranger, 0, abi.encodeCall(Round8Sink.ping, ()), NO_PRED, "nc", 2 days);
        vm.prank(p1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, 48));
        tl.schedule(address(tl), 0, abi.encodeCall(TimelockController.updateDelay, (48)), NO_PRED, "u1", 2 days);
        vm.prank(p1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, 172_800_000));
        tl.schedule(address(tl), 0, abi.encodeCall(TimelockController.updateDelay, (172_800_000)), NO_PRED, "u2", 2 days);
        // trailing bytes do not hide the value (the base decoder ignores them, the rail reads word 0)
        bytes memory _padded = abi.encodePacked(abi.encodeCall(TimelockController.updateDelay, (48)), bytes32(uint256(3 days)));
        vm.prank(p1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, 48));
        tl.schedule(address(tl), 0, _padded, NO_PRED, "u3", 2 days);
        // batch: the rails apply per entry; a length mismatch is still the base error
        address[] memory _t = _list(address(tl), guardLike);
        bytes[] memory _p = new bytes[](2);
        _p[0] = abi.encodeCall(TimelockController.updateDelay, (3 days));
        _p[1] = abi.encodeCall(Round8Sink.ping, ());
        uint256[] memory _v = new uint256[](2);
        _t[1] = stranger;
        vm.prank(p1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.TargetHasNoCode.selector, stranger));
        tl.scheduleBatch(_t, _v, _p, NO_PRED, "b1", 2 days);
        uint256[] memory _v1 = new uint256[](1);
        // refinement (2): with a `values` mismatch the base's length error keeps precedence even when an
        // entry would trip a rail (`_t[1]` is still the codeless stranger here)
        vm.prank(p1);
        vm.expectRevert(abi.encodeWithSelector(TimelockController.TimelockInvalidOperationLength.selector, 2, 2, 1));
        tl.scheduleBatch(_t, _v1, _p, NO_PRED, "b2-codeless", 2 days);
        _t[1] = guardLike;
        vm.prank(p1);
        vm.expectRevert(abi.encodeWithSelector(TimelockController.TimelockInvalidOperationLength.selector, 2, 2, 1));
        tl.scheduleBatch(_t, _v1, _p, NO_PRED, "b2", 2 days);
    }

    /// The code can vanish (or never appear) between proposal and execution: `_execute` refuses, the
    /// operation stays Ready, the veto can cancel.
    function test_schedule_execute_refuses_a_target_whose_code_is_gone() public {
        Round8Sink _s = new Round8Sink();
        bytes memory _d = abi.encodeCall(Round8Sink.ping, ());
        vm.prank(p1);
        tl.schedule(address(_s), 0, _d, NO_PRED, "gone", 2 days);
        bytes32 _id = tl.hashOperation(address(_s), 0, _d, NO_PRED, "gone");
        vm.etch(address(_s), "");
        vm.warp(block.timestamp + 2 days);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.TargetHasNoCode.selector, address(_s)));
        tl.execute(address(_s), 0, _d, NO_PRED, "gone");
        assertTrue(tl.isOperationReady(_id));
        vm.prank(veto);
        tl.cancel(_id);
    }

    /// The clamp's edges are inclusive on the scheduled path and anything outside is refused when proposed.
    function test_updateDelay_edges_are_inclusive_and_outside_is_refused_at_proposal() public {
        _selfCall(p1, abi.encodeCall(TimelockController.updateDelay, (1 days)), "edge-lo");
        assertEq(tl.getMinDelay(), 1 days);
        _selfCall(p1, abi.encodeCall(TimelockController.updateDelay, (30 days)), "edge-hi");
        assertEq(tl.getMinDelay(), 30 days);
        vm.prank(p1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, 1 days - 1));
        tl.schedule(address(tl), 0, abi.encodeCall(TimelockController.updateDelay, (1 days - 1)), NO_PRED, "lo-1", 30 days);
        vm.prank(p1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, 30 days + 1));
        tl.schedule(address(tl), 0, abi.encodeCall(TimelockController.updateDelay, (30 days + 1)), NO_PRED, "hi+1", 30 days);
    }
}

contract Round8Sink {
    uint256 public n;

    function ping() external {
        ++n;
    }

    receive() external payable {}
}
