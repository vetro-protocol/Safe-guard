// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {G9cBase} from "test/guards/G9c_Base.sol";

/// @title Round 14 (g14b), finding G14b-1: the section 7.8 repair recipe applied to a pending-admin Safe.
/// @dev   The row for `ForwardedHookCall` / `Unauthorized` (extended by commit 4892722 to the hand-over
///        acceptance) prescribes "a council window, `setFallbackHandler(0)` inside it, `enforce`". On a
///        pending-admin Safe, which this guard never guards, a live window and the `Enforced` mode it
///        leaves behind are themselves `AdminIsGuarded` refusals of the acceptance (the predicate reads the
///        effective mode, V2-72) until `lockdown(newAdmin)` restores it. The repair is the Safe's own
///        `setFallbackHandler(0)` transaction and nothing else.
contract G14b_DocsRecipeTest is G9cBase {
    bytes4 internal constant SET_FALLBACK_HANDLER = 0xf08a0323;

    function setUp() public override {
        super.setUp();
        _configureCurator();
    }

    function test_E1_the_window_recipe_of_7_8_stalls_a_pending_admin_safe_until_lockdown() public {
        (ISafe _dao, uint256 _pk) = _newSafe("dao-recipe");
        assertTrue(_exec(_dao, _pk, address(_dao), 0, abi.encodeWithSelector(SET_FALLBACK_HANDLER, address(g)), Operation.Call));
        _adminCall(_wrap(uint64(block.timestamp + MIN_DELAY + 1 days), abi.encodeCall(g.beginDefaultAdminTransfer, (address(_dao)))), "e1");
        vm.warp(block.timestamp + ADMIN_DELAY + 1);
        bytes memory _accept = abi.encodeCall(g.acceptDefaultAdminTransfer, ());

        // The symptom the row describes.
        vm.prank(address(_dao));
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.acceptDefaultAdminTransfer();

        // The row's repair, followed literally: a council window on the Safe, the handler dropped inside it, `enforce`.
        vm.prank(council);
        g.bypass(address(_dao), 1 hours);
        assertTrue(_exec(_dao, _pk, address(_dao), 0, abi.encodeWithSelector(SET_FALLBACK_HANDLER, address(0)), Operation.Call));
        vm.prank(address(_dao));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, address(_dao)));
        g.acceptDefaultAdminTransfer(); // a live window on the pending admin refuses the acceptance
        vm.prank(council);
        g.enforce(address(_dao));
        vm.prank(address(_dao));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, address(_dao)));
        g.acceptDefaultAdminTransfer(); // `Enforced` is not `Lockdown`: still refused
        assertEq(g.defaultAdmin(), address(tl), "the hand-over is stalled by the recipe itself");

        // What repairs the recipe's damage: `lockdown(newAdmin)` (council, admin or a guardian), then the acceptance.
        vm.prank(council);
        g.lockdown(address(_dao));
        assertTrue(_exec(_dao, _pk, address(g), 0, _accept, Operation.Call), "accepted once the mode is Lockdown again");
        assertEq(g.defaultAdmin(), address(_dao));
    }
}
