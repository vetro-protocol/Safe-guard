// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G10cBase} from "test/guards/G10c_Base.sol";

/// @dev g10c, finding G10c-3 (a council's last-hour NARROWING outlives the rotation) and G10c-6 (the
///      per-Safe guardian cap as a council lever; a last-second plant on a pending admin). Docs section 6
///      lists what a council leaves behind (a window, approvals, a planted guardian) and says the new
///      council clears it at once. A revocation is not on that list and the new council cannot undo it:
///      only the timelock widens, so the freeze lasts one more `minDelay` unless the full policy
///      re-assertion is chained behind the rotation in the same cycle.
contract G10c_HostileCouncilTest is G10cBase {
    address internal newCouncil = makeAddr("new-council");

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

    function _reassertion() internal view returns (bytes[] memory _re) {
        _re = new bytes[](1);
        _re[0] = abi.encodeCall(g.allowFunction, (address(curatorSafe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules()));
    }

    function test_G10c3_a_councils_last_hour_narrowing_outlives_the_rotation_and_costs_another_minDelay() public {
        uint256 _t0 = block.timestamp;
        bytes[] memory _d = _rotation();
        _scheduleBatch(p1, p1Pk, _guardTargets(3), _d, NONE, "rotate");
        // The council's last hour: it narrows (what a bot is told never to do) and locks down.
        vm.startPrank(council);
        g.revokeTarget(address(curatorSafe), address(protocol));
        g.lockdown(address(curatorSafe));
        vm.stopPrank();
        vm.warp(_t0 + MIN_DELAY);
        _executeBatch(_guardTargets(3), _d, NONE, "rotate");
        assertTrue(g.hasRole(g.COUNCIL_ROLE(), newCouncil));
        vm.prank(newCouncil);
        g.enforce(address(curatorSafe)); // the lift the docs promise, at once
        // ... but the allowlist is empty and the new council cannot widen: settlement stays refused.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.settleDeposit.selector));
        _settle();
        vm.prank(newCouncil);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.allowFunction(address(curatorSafe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules());
        // Only the timelock re-widens: one more minDelay of frozen settlement.
        _adminCall(_reassertion()[0], "rewiden");
        assertTrue(_settle());
        assertEq(block.timestamp - _t0, 2 * MIN_DELAY, "two cycles, not one");
    }

    /// @dev The full re-assertion of the policy file (every `allowFunction`, and every `addAllowedValues`
    ///      since a revocation bumps the generation and empties the `OneOf` sets), chained behind the
    ///      rotation with `predecessor`: a revocation at any time before it executes is undone in the same cycle.
    function test_G10c3_a_full_re_assertion_chained_behind_the_rotation_undoes_the_narrowing_in_one_cycle() public {
        uint256 _t0 = block.timestamp;
        bytes[] memory _d = _rotation();
        bytes32 _rid = _scheduleBatch(p1, p1Pk, _guardTargets(3), _d, NONE, "rotate");
        bytes[] memory _re = _reassertion();
        _scheduleBatch(p1, p1Pk, _guardTargets(1), _re, _rid, "reassert");
        vm.prank(council);
        g.revokeTarget(address(curatorSafe), address(protocol));
        vm.warp(_t0 + MIN_DELAY);
        _executeBatch(_guardTargets(3), _d, NONE, "rotate");
        _executeBatch(_guardTargets(1), _re, _rid, "reassert");
        vm.prank(newCouncil);
        g.enforce(address(curatorSafe));
        assertTrue(_settle());
        assertEq(block.timestamp - _t0, MIN_DELAY, "one cycle");
    }

    /// @dev G10c-6 (Info). The per-Safe guardian set is capped at 32 and council-writable: a council that
    ///      fills it makes the admin's scheduled `setGuardian(safe, bot, true)` (the sync task provisions
    ///      the policy file's guardians this way) revert `TooManyValues`. The batch that evicts the council
    ///      must also empty the set.
    function test_G10c6_a_council_fills_the_per_safe_guardian_set_and_the_admins_setGuardian_dies() public {
        vm.startPrank(council);
        for (uint256 i; i < 32; ++i) g.setGuardian(address(curatorSafe), address(uint160(0x10000 + i)), true);
        vm.stopPrank();
        assertEq(g.guardians(address(curatorSafe)).length, 32);
        bytes memory _bot = abi.encodeCall(g.setGuardian, (address(curatorSafe), makeAddr("bot"), true));
        _schedule(p1, p1Pk, address(g), _bot, NONE, "bot");
        vm.warp(block.timestamp + MIN_DELAY);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.TooManyValues.selector, 32));
        _execute(address(g), _bot, NONE, "bot");
        // The remedy in one batch: evict, empty the set, seat the bot.
        bytes[] memory _d = new bytes[](34);
        _d[0] = abi.encodeCall(IAccessControl.revokeRole, (g.COUNCIL_ROLE(), council));
        for (uint256 i; i < 32; ++i) _d[1 + i] = abi.encodeCall(g.setGuardian, (address(curatorSafe), address(uint160(0x10000 + i)), false));
        _d[33] = _bot;
        _adminBatch(_d, "evict-and-seat");
        assertEq(g.guardians(address(curatorSafe)).length, 1);
        assertTrue(g.isGuardian(address(curatorSafe), makeAddr("bot")));
    }

    /// @dev G10c-6 (Info, extends G9c-1). The eviction batch names the plant it sees when it is prepared;
    ///      a plant made after that (the council's last second, before the batch executes) survives the
    ///      council and costs one more operation. Still inside the 30-day acceptance window at these delays.
    function test_G10c6_a_last_second_plant_on_the_pending_admin_needs_a_second_eviction_round() public {
        CuratorGuardTimelock _tlB = _newTimelock(MIN_DELAY);
        bytes memory _accept = abi.encodeCall(g.acceptDefaultAdminTransfer, ());
        _adminCall(_wrap(uint64(block.timestamp + MIN_DELAY + 14 days), abi.encodeCall(g.beginDefaultAdminTransfer, (address(_tlB)))), "begin");
        (, uint48 _sched) = g.pendingDefaultAdmin();
        _scheduleOn(_tlB, p1, p1Pk, address(g), _accept, NONE, "accept");
        address _k1 = makeAddr("plant-1");
        address _k2 = makeAddr("plant-2");
        vm.prank(council);
        g.setGuardian(address(_tlB), _k1, true);
        bytes[] memory _d = new bytes[](3);
        _d[0] = abi.encodeCall(IAccessControl.revokeRole, (g.COUNCIL_ROLE(), council));
        _d[1] = abi.encodeCall(g.setGuardian, (address(_tlB), _k1, false));
        _d[2] = abi.encodeCall(g.lockdown, (address(_tlB)));
        _scheduleBatch(p1, p1Pk, _guardTargets(3), _d, NONE, "evict");
        vm.warp(block.timestamp + MIN_DELAY);
        vm.prank(council);
        g.setGuardian(address(_tlB), _k2, true); // the last second
        _executeBatch(_guardTargets(3), _d, NONE, "evict");
        assertFalse(g.hasRole(g.COUNCIL_ROLE(), council));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, address(_tlB)));
        _executeOn(_tlB, address(g), _accept, NONE, "accept");
        _adminCall(abi.encodeCall(g.setGuardian, (address(_tlB), _k2, false)), "clean");
        assertLe(block.timestamp, uint256(_sched) + 30 days, "still inside the acceptance window");
        _executeOn(_tlB, address(g), _accept, NONE, "accept");
        assertEq(g.defaultAdmin(), address(_tlB));
    }
}
