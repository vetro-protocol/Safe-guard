// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

// Review g22g (round 22, the verdict): the one rail commit cabea06 added to the guard, `approveTransaction` refusing a
// zero target (review G17a-3, +18 bytes), is pinned by nothing in the unit tree but the build pin (every
// `approveTransaction` call of the 151 suites at cabea06 passes `address(0)` as the EXECUTOR, none as the target). These tests pin
// the rail's behaviour on the real Safe v1.4.1 build from lib/ (the shared fixture) so that a mutant dropping
// `|| to_ == address(0)` dies to a behavioural test, not only to the hash. Adopted at the round-22 close (G22g-1, G22b-1).

import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

contract G22g_ZeroTargetPin is CuratorGuardTestBase {
    bytes4 internal immutable INVALID_TARGET = CuratorGuardPolicy.InvalidTarget.selector;

    /// The admin lane: a value to the zero address with empty calldata (the paste-error burn G17a-3 named) is refused
    /// at issuance, before anything is stored.
    function test_admin_cannot_approve_a_value_to_the_zero_address() public {
        _enforce();
        bytes32 _id = guard.computeApprovalId(address(safe), address(0), address(0), 1 ether, "", Operation.Call);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(INVALID_TARGET, address(0)));
        guard.approveTransaction(address(safe), address(0), address(0), 1 ether, "", Operation.Call, 1 days);
        assertEq(guard.approvalExpiry(_id), 0, "nothing stored");
    }

    /// The council lane (plain calls, no self-call): the target check runs before the council's own rules, so the
    /// council is refused with the same error, not with `CouncilCannotApprove`.
    function test_council_cannot_approve_a_value_to_the_zero_address() public {
        _enforce();
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(INVALID_TARGET, address(0)));
        guard.approveTransaction(address(safe), address(0), address(0), 1 ether, "", Operation.Call, 7 days);
    }

    /// With calldata or as a delegatecall the zero address was already refused before the rail (no code): the error is
    /// the same, so the rail changes nothing for those shapes.
    function test_zero_target_with_calldata_or_delegatecall_refused_as_before() public {
        _enforce();
        vm.startPrank(vetro);
        vm.expectRevert(abi.encodeWithSelector(INVALID_TARGET, address(0)));
        guard.approveTransaction(address(safe), address(0), address(0), 0, hex"12345678", Operation.Call, 1 days);
        vm.expectRevert(abi.encodeWithSelector(INVALID_TARGET, address(0)));
        guard.approveTransaction(address(safe), address(0), address(0), 0, "", Operation.DelegateCall, 1 days);
        vm.stopPrank();
    }

    /// Positive control, so the pin is not vacuous: the same value with empty calldata to an account WITH code is
    /// still an approvable shape (the one-off ether transfer of docs section 7.6).
    function test_positive_control_a_value_to_a_contract_is_still_approvable() public {
        _enforce();
        bytes32 _id = _approve(address(protocol), 1 ether, "", Operation.Call);
        assertGt(guard.approvalExpiry(_id), 0, "approved");
    }

    /// The native lane and the approval lane agree on the zero address: neither can name it.
    function test_native_lane_agrees_the_zero_address_is_never_a_target() public {
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(INVALID_TARGET, address(0)));
        guard.setNativeTransferAllowed(address(safe), address(0), true);
    }
}
