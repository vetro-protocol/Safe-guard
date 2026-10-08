// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {StrangersBase} from "test/guards/CuratorGuardStrangersBase.sol";

/// @title Round 8: role holders as `msg.sender` of the HOOKS, and role holders' own addresses as the `safe`
///        ARGUMENT of the role surface (dead policies).
contract CuratorGuardRolesAsCallersTest is StrangersBase {
    function _pre(address who_) internal {
        vm.prank(who_);
        guard.checkTransaction(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", attacker);
    }

    /// @dev The council, a guardian and a deployment-wide guardian are strangers to the hooks: their
    ///      role gives them no policy, so they are unconfigured Safes there (Lockdown, nothing recorded).
    function test_role_holders_are_unconfigured_safes_to_the_hooks() public {
        vm.prank(vetro);
        guard.setDeploymentGuardian(guardian, true);
        address[3] memory _who = [council, guardianA, guardian];
        for (uint256 i; i < _who.length; ++i) {
            // V2-88: an EOA cannot answer `getStorageAt` (`SafeLockedDown` before round 8).
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigUnreadable.selector, _who[i]));
            _pre(_who[i]);
            vm.prank(_who[i]);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.MissingSnapshot.selector, _who[i]));
            guard.checkAfterExecution(bytes32(0), true);
        }
        // The admin is exempt: both hooks return, nothing is recorded, nothing is reported.
        vm.recordLogs();
        _pre(vetro);
        vm.prank(vetro);
        guard.checkAfterExecution(bytes32(0), true);
        assertEq(_guardLogs(vm.getRecordedLogs(), CuratorGuard.TransactionChecked.selector), 0, "admin: silent");
    }

    /// @dev Role holders' addresses as the `safe` argument: the council cannot act on itself (V2-38);
    ///      others can shape a policy for the council / admin / guard addresses, which is dead state:
    ///      the council's and admin's calls into the role surface are not Safe transactions, and the
    ///      guard never calls itself. Nothing of it leaks into a real Safe.
    function test_dead_policies_on_role_addresses_are_inert() public {
        bytes32 _a = _state(guard, address(safe));
        vm.startPrank(vetro);
        guard.enforce(council);
        guard.allowFunction(council, address(protocol), SETTLE, false, _noRules());
        guard.setGuardian(council, attacker, true);
        guard.enforce(address(guard));
        guard.approveTransaction(council, address(0), address(protocol), 0, "", Operation.Call, 1 days);
        vm.stopPrank();
        vm.startPrank(council);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.enforce(council);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.bypass(council, 1 hours);
        guard.lockdown(council); // narrowing itself is allowed and harmless
        guard.bypass(vetro, 1 hours); // a window "on the admin": the admin is exempt anyway
        vm.stopPrank();
        // The council still acts as the council (its policy state is not consulted by the role surface) …
        vm.prank(council);
        guard.lockdown(address(safeB));
        assertEq(uint8(guard.mode(address(safeB))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        // … the attacker planted as "guardian of the council" can narrow the council's dead policy only …
        vm.startPrank(attacker);
        guard.lockdownAndRevoke(council);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.lockdown(address(safe));
        vm.stopPrank();
        // … and the admin, whatever its "mode", is exempt in the hooks and unconstrained in the role surface
        // (B's own cooldown, started by the council's lockdown above, is the only thing holding it back).
        assertEq(uint8(guard.mode(vetro)), uint8(CuratorGuardPolicy.Mode.Bypass));
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(safeB)));
        guard.enforce(address(safeB));
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(vetro);
        guard.enforce(address(safeB));
        assertEq(_state(guard, address(safe)), _a, "A untouched by all of it");
    }
}
