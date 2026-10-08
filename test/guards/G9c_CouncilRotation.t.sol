// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {G9cBase} from "test/guards/G9c_Base.sol";

/// @dev g9c: the council rotation batch of docs section 6 / 7.5 through the real timelock, with
///      everything a council can leave behind in its last hour, the old council trying to veto its
///      successor, the new council clearing the residue at once, and the batch that can never execute.
contract G9c_CouncilRotationTest is G9cBase {
    address internal newCouncil = makeAddr("new-council");
    address internal k1 = makeAddr("planted-per-safe-guardian");
    address internal k2 = makeAddr("planted-deployment-guardian");

    function setUp() public override {
        super.setUp();
        _configureCurator();
    }

    function _rotation() internal view returns (bytes[] memory _d) {
        _d = new bytes[](3);
        _d[0] = abi.encodeCall(IAccessControl.revokeRole, (g.COUNCIL_ROLE(), council));
        _d[1] = abi.encodeCall(IAccessControl.grantRole, (g.COUNCIL_ROLE(), newCouncil));
        _d[2] = abi.encodeCall(g.lockdownAndRevoke, (address(curatorSafe)));
    }

    function test_rotation_batch_clears_the_old_councils_residue_and_the_new_council_lifts_at_once() public {
        // The old council's last hour: two planted guardians and a 7-day window.
        vm.startPrank(council);
        g.setGuardian(address(curatorSafe), k1, true);
        g.setDeploymentGuardian(k2, true);
        g.bypass(address(curatorSafe), 7 days);
        vm.stopPrank();
        bytes[] memory _d = _rotation();
        bytes32 _id = _scheduleBatch(p1, p1Pk, _guardTargets(3), _d, NONE, "rotate");
        // While the batch waits the old council tries to veto its successor: the grant reads none of it.
        vm.startPrank(council);
        g.setGuardian(newCouncil, k1, true);
        g.bypass(newCouncil, 7 days);
        vm.stopPrank();
        vm.warp(block.timestamp + MIN_DELAY);
        _executeBatch(_guardTargets(3), _d, NONE, "rotate");
        assertTrue(tl.isOperationDone(_id));
        assertFalse(g.hasRole(g.COUNCIL_ROLE(), council));
        assertTrue(g.hasRole(g.COUNCIL_ROLE(), newCouncil), "a rogue council cannot veto its successor");
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Lockdown), "window closed");
        vm.prank(council);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.enforce(address(curatorSafe));
        // The new council lifts inside the cooldown the batch's own lockdown started, and removes the plants.
        vm.startPrank(newCouncil);
        g.setGuardian(address(curatorSafe), k1, false);
        g.setDeploymentGuardian(k2, false);
        g.enforce(address(curatorSafe));
        vm.stopPrank();
        assertTrue(_settle(), "settlement resumes at once");
        vm.prank(k1);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.lockdown(address(curatorSafe));
        vm.prank(k2);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.lockdown(address(curatorSafe));
    }

    /// @dev docs 7.5: "never bundled with a lift". The batch re-locks every time it is tried, so its own
    ///      `enforce` is always inside the cooldown: a dead operation that stays Ready until the veto cancels it.
    function test_a_rotation_bundled_with_a_lift_can_never_execute() public {
        bytes[] memory _r = _rotation();
        bytes[] memory _d = new bytes[](4);
        (_d[0], _d[1], _d[2]) = (_r[0], _r[1], _r[2]);
        _d[3] = abi.encodeCall(g.enforce, (address(curatorSafe)));
        bytes32 _id = _scheduleBatch(p1, p1Pk, _guardTargets(4), _d, NONE, "bundled");
        bytes memory _cooldown = abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(curatorSafe));
        vm.warp(block.timestamp + MIN_DELAY);
        vm.expectRevert(_cooldown);
        _executeBatch(_guardTargets(4), _d, NONE, "bundled");
        vm.warp(block.timestamp + 30 days);
        vm.expectRevert(_cooldown);
        _executeBatch(_guardTargets(4), _d, NONE, "bundled");
        assertTrue(tl.isOperationReady(_id), "dead but Ready");
        _cancel(_id);
        assertFalse(tl.isOperationPending(_id));
    }
}
