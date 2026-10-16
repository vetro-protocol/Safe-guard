// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IAccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/IAccessControlDefaultAdminRules.sol";

import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {G9cBase} from "test/guards/G9c_Base.sol";
import {TestERC20} from "test/mocks/TestERC20.sol";

/// @title Round 14, reviewer g14g (the adversary of the change): the follow-up chained with what is still held.
/// @dev   The production topology of `G9cBase` (real Safe v1.4.1 proxies behind the curator, two proposers and the
///        veto; a real `CuratorGuardTimelock` at 2 days; the guard's admin delay 3 days; an EOA council). The
///        attacker holds one proposer Safe (p2) and the veto sleeps. `G13g_HeldChain` already runs the chain of
///        the items the follow-up did NOT touch (the self-seat, the stall, the uninstalled-guard report). This
///        drill adds what the follow-up itself created: `MIN_DELAY_FLOOR` now equals `MIN_ADMIN_DELAY` (and
///        `LOCKDOWN_COOLDOWN`), so a proposer that lowers BOTH delays to their floors turns the UNCHAINED cancel
///        of a hostile hand-over into a one-second race (test 1), which the cancel CHAINED behind the begin
///        (docs 7.5) still wins whenever the attacker lands the begin (test 2); and the held G13f-2b swarm
///        against a council seated in the eviction batch (test 3). Custody never moves without curator keys.
///        WRITTEN AGAINST THE COMMIT'S FIXTURE AND NOT RUN: the host disk was at 102-165 MB during round 14
///        (the brief stops builds under 1 GB). Every assertion is derived line by line from OpenZeppelin 5.2.0
///        (`_delayChangeWait`, `_hasSchedulePassed`, `getOperationState`, `_beforeCall`) and the guard's code.
contract G14g_HeldChain2Test is G9cBase {
    TestERC20 internal token;
    address internal attacker = makeAddr("attacker");
    address internal hostileCouncil = makeAddr("hostile-council");
    address internal newCouncil = makeAddr("new-council");
    uint256 internal constant CUSTODY = 1_000_000e6;
    uint256 internal constant SWARM = 8;

    function setUp() public override {
        super.setUp();
        _configureCurator();
        token = new TestERC20("USD Coin", "USDC");
        token.mint(address(curatorSafe), CUSTODY);
    }

    /// @dev A hostile proposer schedules one call at the LIVE minimum delay and the sleeping veto lets it land.
    function _hostile(address target_, bytes memory data_, bytes32 salt_) internal {
        _scheduleOn(tl, p2, p2Pk, target_, data_, NONE, salt_);
        vm.warp(block.timestamp + tl.getMinDelay());
        _executeOn(tl, target_, data_, NONE, salt_);
    }

    /// @dev The honest proposer schedules one guard batch at the live delay; anyone executes it. Returns the
    ///      chain time the round took.
    function _honestBatch(bytes[] memory payloads_, bytes32 salt_) internal returns (uint256) {
        uint256 _t0 = block.timestamp;
        _exec(p1, p1Pk, address(tl), 0, _scheduleBatchCall(payloads_, salt_), Operation.Call);
        vm.warp(block.timestamp + tl.getMinDelay());
        _executeBatch(_guardTargets(payloads_.length), payloads_, NONE, salt_);
        return block.timestamp - _t0;
    }

    /// @dev Kept apart from `_honestBatch` so the legacy codegen stays within the stack limit (as G13g did).
    function _scheduleBatchCall(bytes[] memory payloads_, bytes32 salt_) internal view returns (bytes memory) {
        uint256[] memory _v = new uint256[](payloads_.length);
        return abi.encodeCall(tl.scheduleBatch, (_guardTargets(payloads_.length), _v, payloads_, NONE, salt_, tl.getMinDelay()));
    }

    /// @dev Steps 1 and 2 of the chain. The hour is refused when proposed (the follow-up's floor), so the
    ///      hostile proposer lowers the timelock to the floor, a day, then the guard's admin delay to ITS floor,
    ///      a day, through the timelock. Both are vetoable; the veto sleeps. OpenZeppelin applies a shorter
    ///      admin delay only after the difference (two days) has passed; then the two delays are EQUAL, the
    ///      ordering V2-10 and the deploy script want strictly the other way, enforced at deploy only.
    function _equalise() internal {
        bytes memory _hour = abi.encodeCall(
            tl.schedule,
            (address(tl), 0, abi.encodeCall(tl.updateDelay, (1 hours)), NONE, bytes32("hour"), tl.getMinDelay())
        );
        vm.expectRevert(bytes("GS013"));
        _exec(p2, p2Pk, address(tl), 0, _hour, Operation.Call);
        _hostile(address(tl), abi.encodeCall(tl.updateDelay, (1 days)), "floor");
        assertEq(tl.getMinDelay(), 1 days, "the floor");
        _hostile(address(g), abi.encodeCall(g.changeDefaultAdminDelay, (uint48(1 days))), "admin-delay");
        assertEq(g.defaultAdminDelay(), 3 days, "OpenZeppelin waits the difference before a shorter admin delay applies");
        vm.warp(block.timestamp + 2 days + 1);
        assertEq(g.defaultAdminDelay(), 1 days, "the admin delay at its floor");
        assertEq(uint256(g.defaultAdminDelay()), tl.getMinDelay(), "equal: what the deploy script forbids at deploy only");
    }

    /// @dev Test 1, the equalisation. The hostile begin lands at `_tb`; the honest reflex, an UNCHAINED cancel
    ///      scheduled in that same block, is Ready at `_tb + 1 day`, the schedule's own second, and the
    ///      acceptance opens one second later (`_hasSchedulePassed` is strict): one slot of exclusive
    ///      executability at best (and a same-block ordering race when the cancel is scheduled a block later),
    ///      where the old floors (an hour against a day) left the cancel a 23-hour margin. The attacker, who is
    ///      awake, takes the seat; custody still needs the quorum.
    function test_at_the_floors_an_unchained_cancel_is_a_one_second_race_the_awake_attacker_wins() public {
        _equalise();
        _hostile(address(g), abi.encodeCall(g.beginDefaultAdminTransfer, (attacker)), "begin");
        uint256 _tb = block.timestamp;
        (address _pending, uint48 _schedule) = g.pendingDefaultAdmin();
        assertEq(_pending, attacker);
        assertEq(uint256(_schedule), _tb + 1 days, "acceptable one day after the begin landed");
        bytes memory _cancel = abi.encodeCall(g.cancelDefaultAdminTransfer, ());
        bytes32 _cid = _scheduleOn(tl, p1, p1Pk, address(g), _cancel, NONE, "cancel");
        vm.warp(_tb + 1 days);
        assertTrue(tl.isOperationReady(_cid), "the unchained cancel is Ready at the schedule's second");
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminDelay.selector, _schedule)
        );
        g.acceptDefaultAdminTransfer();
        // One second later both are executable and the order inside the block decides.
        vm.warp(_tb + 1 days + 1);
        vm.prank(attacker);
        g.acceptDefaultAdminTransfer();
        assertEq(g.defaultAdmin(), attacker, "the seat is lost by one slot: the unchained cancel's margin is gone at the floors");
        // The honest cancel, executed now, is refused: the timelock is no longer the admin.
        vm.expectRevert();
        _executeOn(tl, address(g), _cancel, NONE, "cancel");
        assertEq(token.balanceOf(address(curatorSafe)), CUSTODY, "an admin alone moves no custody");
    }

    /// @dev Test 2, the documented answer (docs 7.5): a cancel CHAINED behind the hostile begin (predecessor =
    ///      its id), scheduled while the begin is pending, and the eviction of the proposer in the same round.
    ///      Ready operations never expire, so whenever the attacker lands the begin (here five days late, after
    ///      its own eviction) anyone executes the cancel in the same block and the acceptance never opens.
    function test_the_chained_cancel_wins_at_the_floors_and_the_eviction_lands_in_one_round() public {
        _equalise();
        bytes memory _begin = abi.encodeCall(g.beginDefaultAdminTransfer, (attacker));
        bytes32 _bid = _scheduleOn(tl, p2, p2Pk, address(g), _begin, NONE, "begin");
        bytes memory _cancel = abi.encodeCall(g.cancelDefaultAdminTransfer, ());
        _scheduleOn(tl, p1, p1Pk, address(g), _cancel, _bid, "chained-cancel");
        bytes memory _evict = abi.encodeCall(IAccessControl.revokeRole, (tl.PROPOSER_ROLE(), address(p2)));
        _scheduleOn(tl, p1, p1Pk, address(tl), _evict, NONE, "evict");
        uint256 _t0 = block.timestamp;
        vm.warp(_t0 + 1 days);
        _executeOn(tl, address(tl), _evict, NONE, "evict");
        assertFalse(tl.hasRole(tl.PROPOSER_ROLE(), address(p2)), "the hostile proposer is out in one round of one day");
        assertEq(tl.proposerCount(), 1);
        // Its queue outlives it (G10c-4): the begin is Ready and the attacker lands it when it likes.
        vm.warp(_t0 + 6 days);
        _executeOn(tl, address(g), _begin, NONE, "begin");
        (address _pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, attacker, "the hand-over is pending");
        _executeOn(tl, address(g), _cancel, _bid, "chained-cancel");
        (_pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, address(0), "cancelled in the block the begin landed, at any admin delay");
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlInvalidDefaultAdmin.selector, attacker));
        g.acceptDefaultAdminTransfer();
        assertEq(g.defaultAdmin(), address(tl), "the timelock keeps the seat");
        // The evicted proposer cannot schedule again (its Safe transaction fails as GS013).
        bytes memory _again = abi.encodeCall(tl.schedule, (address(g), 0, _begin, NONE, bytes32("again"), tl.getMinDelay()));
        vm.expectRevert(bytes("GS013"));
        _exec(p2, p2Pk, address(tl), 0, _again, Operation.Call);
        assertEq(token.balanceOf(address(curatorSafe)), CUSTODY, "no custody moved");
    }

    /// @dev Test 3, the held G13f-2b. A hostile council (seated at the floor by the sleeping veto) plants a
    ///      swarm of deployment-wide guardians and locks the curator Safe down; the honest eviction batch
    ///      misses one key. With a NEW council seated in that batch the miss costs nothing: the council is never
    ///      held by the cooldown, so after the re-lock it removes the key and lifts in one block. Without a
    ///      council (today's empty seat) the admin pays one round of one day plus the cooldown per missed key
    ///      (`G13f_GuardianSwarmTest`), a round the follow-up made a day instead of an hour.
    function test_a_hostile_councils_swarm_costs_nothing_against_a_seated_council() public {
        bytes32 _councilRole = g.COUNCIL_ROLE();
        _hostile(address(tl), abi.encodeCall(tl.updateDelay, (1 days)), "floor");
        _hostile(address(g), abi.encodeCall(IAccessControl.grantRole, (_councilRole, hostileCouncil)), "council");
        address[] memory _keys = new address[](SWARM);
        vm.startPrank(hostileCouncil);
        for (uint256 i; i < SWARM; ++i) {
            _keys[i] = address(uint160(0xDEAD0000 + i));
            g.setDeploymentGuardian(_keys[i], true);
        }
        g.lockdown(address(curatorSafe));
        vm.stopPrank();
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Lockdown), "frozen");
        // One round of one day: the hostile council out, a new one in, SWARM-1 keys removed (one missed to a
        // dropped log), no lift in the batch (never bundle a lift with an eviction).
        bytes[] memory _evict = new bytes[](SWARM + 1);
        _evict[0] = abi.encodeCall(IAccessControl.revokeRole, (_councilRole, hostileCouncil));
        _evict[1] = abi.encodeCall(IAccessControl.grantRole, (_councilRole, newCouncil));
        for (uint256 i; i + 1 < SWARM; ++i) _evict[2 + i] = abi.encodeCall(g.setDeploymentGuardian, (_keys[i], false));
        assertEq(_honestBatch(_evict, "evict"), 1 days, "the eviction lands in one day at the floor");
        assertFalse(g.hasRole(_councilRole, hostileCouncil));
        vm.prank(newCouncil);
        g.enforce(address(curatorSafe));
        assertTrue(_settle(), "settlement resumes at once: the council is never held by the cooldown");
        // The missed key re-locks; the seated council removes it and lifts again in the same block.
        vm.prank(_keys[SWARM - 1]);
        g.lockdown(address(curatorSafe));
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Lockdown), "re-locked by the missed key");
        vm.startPrank(newCouncil);
        g.setDeploymentGuardian(_keys[SWARM - 1], false);
        g.enforce(address(curatorSafe));
        vm.stopPrank();
        assertTrue(_settle(), "the swarm is a nuisance against a seated council, not a round");
        vm.prank(_keys[SWARM - 1]);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.lockdown(address(curatorSafe));
        assertEq(token.balanceOf(address(curatorSafe)), CUSTODY, "no custody moved");
    }
}
