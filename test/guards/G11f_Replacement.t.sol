// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @title G11f: a replacement guard and the state the retired guard keeps (round 11)
contract G11fReplacementTest is CuratorGuardTestBase {
    bytes32 internal constant SETTLE = bytes32(MockProtocol.settleDeposit.selector);

    function _synced() internal returns (CuratorGuardHarness _next) {
        _next = new CuratorGuardHarness(0, vetro, council);
        _next.seedSafe(address(safe));
        vm.startPrank(vetro);
        _next.enforce(address(safe));
        _next.allowFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules());
        vm.stopPrank();
    }

    function _swapTo(CuratorGuard installed_, address next_) internal {
        bytes memory _swap = abi.encodeCall(ISafe.setGuard, (next_));
        vm.prank(vetro);
        installed_.approveTransaction(address(safe), address(0), address(safe), 0, _swap, Operation.Call, 1 days);
        assertTrue(_execSafeTx(address(safe), 0, _swap, Operation.Call));
        assertEq(_installedGuard(), next_, "swapped");
    }

    /// @dev Approvals live in the guard that issued them. After a swap the retired guard's unexpired approvals
    ///      are dormant (the replacement checks the transaction, the retired guard is not consulted), and a
    ///      swap BACK revives them: a standing 180-day one-off approved months earlier executes the moment the
    ///      old guard is in the slot again. This is what the runbook's `lockdownAndRevoke` on the retired
    ///      guard is for; without it a rollback carries the old guard's whole approval book with it.
    function test_G11f_a_retired_guard_keeps_its_approvals_and_a_swap_back_revives_them() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        bytes memory _oneOff = abi.encodeCall(IERC20.transfer, (attacker, 1e6));
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(token), 0, _oneOff, Operation.Call, 180 days);

        CuratorGuardHarness _next = _synced();
        _swapTo(guard, address(_next));

        // Dormant on the replacement.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(token), IERC20.transfer.selector));
        _execSafeTx(address(token), 0, _oneOff, Operation.Call);
        assertGt(guard.approvalExpiry(_id), 0, "still recorded on the retired guard");

        // A rollback 30 days later (an approval on the replacement of setGuard(old)).
        vm.warp(block.timestamp + 30 days);
        _swapTo(_next, address(guard));
        assertTrue(_execSafeTx(address(token), 0, _oneOff, Operation.Call), "the stale one-off executes under the old guard");
        assertEq(token.balanceOf(attacker), 1e6);
    }

    /// @dev The runbook's step closes it: `lockdownAndRevoke` on the retired guard right after the swap.
    function test_G11f_lockdownAndRevoke_on_the_retired_guard_closes_the_rollback_door() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        bytes memory _oneOff = abi.encodeCall(IERC20.transfer, (attacker, 1e6));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(token), 0, _oneOff, Operation.Call, 180 days);

        CuratorGuardHarness _next = _synced();
        _swapTo(guard, address(_next));
        vm.prank(council);
        guard.lockdownAndRevoke(address(safe));

        vm.warp(block.timestamp + 30 days);
        _swapTo(_next, address(guard));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(token), 0, _oneOff, Operation.Call);
        // And nothing else runs on the re-installed guard until the council lifts it: fail-closed re-install.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
    }

    /// @dev The retired guard's role holders and policy also outlive the swap: a council window opened on the
    ///      OLD guard after the swap is inert for the Safe (the installed guard decides), and the old guard's
    ///      hooks refuse the Safe (`GuardNotInstalled`) if anything reaches them on the policy path.
    function test_G11f_a_window_on_the_retired_guard_is_inert_and_its_hooks_refuse_the_safe() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        CuratorGuardHarness _next = _synced();
        _swapTo(guard, address(_next));
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(token), IERC20.transfer.selector));
        _execSafeTx(address(token), 0, abi.encodeCall(IERC20.transfer, (attacker, 1)), Operation.Call);
        vm.prank(address(safe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardNotInstalled.selector, address(safe)));
        guard.checkTransaction(address(protocol), 0, "", Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0));
    }
}
