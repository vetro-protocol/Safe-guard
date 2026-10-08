// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {StrangersBase} from "test/guards/CuratorGuardStrangersBase.sol";

/// @title Round 8: the timelock's public surface for strangers, and the guard behind a real timelock admin.
contract CuratorGuardTimelockSurfaceTest is StrangersBase {
    CuratorGuardTimelock internal tl;
    address internal p1 = makeAddr("proposer-1");
    address internal p2 = makeAddr("proposer-2");
    address internal veto = makeAddr("veto");
    bytes32 internal constant NONE = bytes32(0);

    function setUp() public override {
        super.setUp();
        address[] memory _p = new address[](2);
        _p[0] = p1;
        _p[1] = p2;
        address[] memory _c = new address[](1);
        _c[0] = veto;
        tl = new CuratorGuardTimelock(2 days, _p, _c);
        // Hand the guard's admin role to the timelock (delay 0 in the fixture).
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(address(tl));
        vm.warp(block.timestamp + 1);
        vm.prank(address(tl));
        guard.acceptDefaultAdminTransfer();
        assertEq(guard.defaultAdmin(), address(tl));
    }

    function _schedule(address target_, bytes memory data_, bytes32 salt_, bytes32 pred_) internal returns (bytes32 _id) {
        uint256 _delay = tl.getMinDelay();
        vm.prank(p1);
        tl.schedule(target_, 0, data_, pred_, salt_, _delay);
        _id = tl.hashOperation(target_, 0, data_, pred_, salt_);
    }

    function test_stranger_surface_of_the_timelock() public {
        bytes memory _data = abi.encodeCall(guard.enforce, (address(safe)));
        bytes32 _proposer = tl.PROPOSER_ROLE();
        bytes32 _canceller = tl.CANCELLER_ROLE();
        bytes32 _executor = tl.EXECUTOR_ROLE();
        vm.startPrank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, attacker, _proposer));
        tl.schedule(address(guard), 0, _data, NONE, 0, 2 days);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, attacker, _canceller));
        tl.cancel(bytes32(uint256(1)));
        vm.expectRevert(abi.encodeWithSelector(TimelockController.TimelockUnauthorizedCaller.selector, attacker));
        tl.updateDelay(1 hours);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, attacker, bytes32(0)));
        tl.grantRole(_proposer, attacker);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, attacker, bytes32(0)));
        tl.revokeRole(_canceller, veto);
        // renouncing the open executor role as the zero address is impossible (confirmation mismatch)
        vm.expectRevert(IAccessControl.AccessControlBadConfirmation.selector);
        tl.renounceRole(_executor, address(0));
        // the timelock accepts ETH and NFTs from anyone (OpenZeppelin): stuck until a proposer moves them
        vm.deal(attacker, 1 ether);
        (bool _ok, ) = address(tl).call{value: 1 ether}("");
        assertTrue(_ok, "receive()");
        assertEq(tl.onERC721Received(attacker, attacker, 1, ""), IERC721Receiver.onERC721Received.selector);
        vm.stopPrank();
        // a stranger executes a ready operation (open executor): by design
        bytes32 _id = _schedule(address(guard), _data, bytes32(uint256(1)), NONE);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(TimelockController.TimelockUnexpectedOperationState.selector, _id, bytes32(1 << uint8(TimelockController.OperationState.Ready))));
        tl.execute(address(guard), 0, _data, NONE, bytes32(uint256(1)));
        vm.warp(block.timestamp + 2 days);
        vm.prank(attacker);
        tl.execute(address(guard), 0, _data, NONE, bytes32(uint256(1)));
        assertTrue(tl.isOperationDone(_id));
    }

    /// @dev An `executeBefore`-wrapped operation whose deadline passed can be executed by nobody, stays
    ///      `Ready` forever (never `Done`), blocks every operation chained behind it as predecessor, and
    ///      the stale `Ready` state is cleared only by the canceller: "cancel what you do not execute".
    function test_dead_wrapped_operation_stays_ready_and_blocks_its_successors() public {
        uint64 _deadline = uint64(block.timestamp + 3 days);
        bytes memory _widen = abi.encodeCall(
            guard.executeBefore,
            (_deadline, abi.encodeCall(guard.allowFunction, (address(safe), address(protocol), DEPOSIT, false, _noRules())))
        );
        bytes32 _idWiden = _schedule(address(guard), _widen, bytes32(uint256(2)), NONE);
        bytes memory _lift = abi.encodeCall(guard.executeBefore, (uint64(block.timestamp + 30 days), abi.encodeCall(guard.enforce, (address(safe)))));
        bytes32 _idLift = _schedule(address(guard), _lift, bytes32(uint256(3)), _idWiden);
        vm.warp(_deadline + 1);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, _deadline));
        tl.execute(address(guard), 0, _widen, NONE, bytes32(uint256(2)));
        assertTrue(tl.isOperationReady(_idWiden), "stays ready, never done");
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(TimelockController.TimelockUnexecutedPredecessor.selector, _idWiden));
        tl.execute(address(guard), 0, _lift, _idWiden, bytes32(uint256(3)));
        vm.prank(veto);
        tl.cancel(_idWiden);
        assertFalse(tl.isOperation(_idWiden));
        assertTrue(tl.isOperationPending(_idLift), "the successor is now unexecutable for good: cancel it too");
    }

    /// @dev Through the real timelock, the guard's hooks treat the timelock as the exempt admin and
    ///      everything else as a stranger: a scheduled hook call does nothing, a scheduled role call as
    ///      the admin works, and the timelock's own address as a `safe` argument is a dead policy.
    function test_guard_behind_a_timelock_admin() public {
        // A scheduled call into a hook as the admin: returns, no state, no event.
        bytes memory _hook = abi.encodeCall(guard.checkAfterExecution, (bytes32(uint256(7)), true));
        _schedule(address(guard), _hook, bytes32(uint256(4)), NONE);
        vm.warp(block.timestamp + 2 days);
        vm.recordLogs();
        vm.prank(attacker);
        tl.execute(address(guard), 0, _hook, NONE, bytes32(uint256(4)));
        assertEq(_guardLogs(vm.getRecordedLogs(), CuratorGuard.TransactionChecked.selector), 0, "admin reports nothing");
        // The council may still lock down and act; the old admin EOA is now a stranger.
        vm.prank(vetro);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.enforce(address(safe));
        vm.prank(council);
        guard.lockdown(address(safe));
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
    }

    /// @dev R6B-O2 ("validateModuleTransaction(safe, address(0), …) answered by an owner-path approval",
    ///      recorded as not changed in round 6) is stale since V2-75 moved the module-allowlist check
    ///      ahead of the approval branch in the dry run as well: the zero module is refused first.
    function test_dry_run_with_a_zero_module_no_longer_answers_from_an_owner_path_approval() public {
        bytes memory _payload = abi.encodeCall(MockProtocol.settleDeposit, (7));
        vm.prank(council);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _payload, Operation.Call, 1 days);
        guard.validateTransaction(address(safe), address(protocol), 0, _payload, Operation.Call); // owner path: approved
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(0)));
        guard.validateModuleTransaction(address(safe), address(0), address(protocol), 0, _payload, Operation.Call);
    }
}
