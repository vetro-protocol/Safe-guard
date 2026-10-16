// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuardTestBase} from "test/guards/CuratorGuardTestBase.sol";

/// @title Review g15d: the held decision G9b-2 made observable.
/// @dev   G9b-2 (`NativeTransferUpdated` on change only; held, "leave" by every round since 10) is the one held
///        change whose application the tree could not notice: the round-15 campaign's mutant H-NT4, the change
///        itself, survived the unit suite (`G10f_Pins` reports both directions of a REAL change, which the change
///        keeps). This pins the current behaviour, a report on every call, a no-op included; flip it together with
///        G9b-2 if that is ever applied.
contract G15dHeldPinsTest is CuratorGuardTestBase {
    event NativeTransferUpdated(address indexed safe, address indexed target, bool allowed);

    function test_native_transfer_setter_reports_a_no_op_call_too() public {
        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), address(protocol), true);
        assertTrue(guard.isNativeTransferAllowed(address(safe), address(protocol)));

        vm.expectEmit(true, true, true, true, address(guard));
        emit NativeTransferUpdated(address(safe), address(protocol), true);
        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), address(protocol), true); // the same state again: reported
        assertEq(guard.targets(address(safe)).length, 1, "the target is listed once");

        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), address(protocol), false);
        vm.expectEmit(true, true, true, true, address(guard));
        emit NativeTransferUpdated(address(safe), address(protocol), false);
        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), address(protocol), false); // a no-op revocation: reported too
        assertEq(guard.targets(address(safe)).length, 0);
    }
}
