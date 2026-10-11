// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IAccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/IAccessControlDefaultAdminRules.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {G9cBase} from "test/guards/G9c_Base.sol";

/// @title Round 16, reviewer g16b: THE TIME ATTACKER AT ONE DAY. Measurements on the production topology of
///        `G9cBase` (real Safe v1.4.1 proxies, a real `CuratorGuardTimelock` at the deploy default of 2 days,
///        the guard's admin delay at the default 3 days), each at the boundary second. The attacker holds one
///        proposer Safe (p2) and the veto sleeps; `stranger` is the open executor.
/// @dev   Notation: D = the live `getMinDelay()`, A = the live `defaultAdminDelay()`, C = `LOCKDOWN_COOLDOWN`,
///        T1 = the chain time of a hostile `CallScheduled`, r = the honest side's reaction (the time from T1 to
///        its own `CallScheduled`). The law every hand-over test below measures: against an attacker that
///        executes the begin at its Ready second, a cancel (chained or not) wins iff r <= A; at r == A the
///        honest side keeps exactly one second (one mainnet block: every constant is a multiple of 12 and
///        block timestamps are slot-aligned); D cancels out.
contract G16b_TimeAttackTest is G9cBase {
    address internal attacker = makeAddr("attacker");
    address internal key = makeAddr("deployment-guardian-key");

    function _begin() internal view returns (bytes memory) {
        return abi.encodeCall(g.beginDefaultAdminTransfer, (attacker));
    }

    function _cancelCall() internal view returns (bytes memory) {
        return abi.encodeCall(g.cancelDefaultAdminTransfer, ());
    }

    function _accept() internal {
        vm.prank(attacker);
        g.acceptDefaultAdminTransfer();
    }

    function _acceptReverts(bytes memory err_) internal {
        vm.prank(attacker);
        vm.expectRevert(err_);
        g.acceptDefaultAdminTransfer();
    }

    function _enforcedDelay(uint48 schedule_) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminDelay.selector, schedule_);
    }

    function _notPending() internal view returns (bytes memory) {
        return abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlInvalidDefaultAdmin.selector, attacker);
    }

    function _notAdmin() internal view returns (bytes memory) {
        return abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, address(tl), bytes32(0));
    }

    /// @dev A timelock self-call scheduled by p1 at the live delay and executed by a stranger (g14c's helper).
    function _selfCall(bytes memory data_, bytes32 salt_) internal {
        _schedule(p1, p1Pk, address(tl), data_, NONE, salt_);
        vm.warp(block.timestamp + tl.getMinDelay());
        _execute(address(tl), data_, NONE, salt_);
    }

    /// @dev A hostile one-call operation (p2) at the live delay, landed by the sleeping veto's absence (g14g's helper).
    function _hostile(address target_, bytes memory data_, bytes32 salt_) internal {
        _scheduleOn(tl, p2, p2Pk, target_, data_, NONE, salt_);
        vm.warp(block.timestamp + tl.getMinDelay());
        _executeOn(tl, target_, data_, NONE, salt_);
    }

    /*//////////////////////////////////////////////////////////////
          T1: THE REACTION LAW AT THE DEPLOY DEFAULTS (D = 2 d, A = 3 d)
    //////////////////////////////////////////////////////////////*/

    /// @dev Docs 7.5: "a cancelDefaultAdminTransfer CHAINED behind it ... anyone executes it in the block the begin
    ///      lands, whenever the attacker lands it, so it wins at any admin delay". Measured: the chained cancel is
    ///      Ready `D` after ITS OWN CallScheduled, so against a begin executed at its Ready second it wins iff it was
    ///      scheduled within A (3 days) of the hostile CallScheduled: at r = A one exclusive second, at r = A + 1 the
    ///      builder's order, at r = A + 2 the attacker's seat. No delay was moved: this is the shipped configuration.
    function test_T1_at_the_defaults_a_chained_cancel_wins_iff_scheduled_within_A_of_the_hostile_CallScheduled() public {
        _configureCurator();
        uint256 _t1 = block.timestamp;
        bytes32 _bid = _scheduleOn(tl, p2, p2Pk, address(g), _begin(), NONE, "begin");
        uint256 _snap0 = vm.snapshotState();
        // The attacker executes the begin at its Ready second (T1 + D); the acceptance opens at T1 + D + A + 1.
        vm.warp(_t1 + MIN_DELAY);
        _executeOn(tl, address(g), _begin(), NONE, "begin");
        (address _pending, uint48 _schedule) = g.pendingDefaultAdmin();
        assertEq(_pending, attacker);
        assertEq(uint256(_schedule), _t1 + MIN_DELAY + ADMIN_DELAY, "schedule = T_b + A = T1 + 5 d");
        uint256 _snap = vm.snapshotState();

        // (a) r = A: the chained cancel is Ready at T1 + A + D = the schedule's second; OpenZeppelin accepts strictly
        //     after it: one exclusive second for the honest side.
        vm.warp(_t1 + ADMIN_DELAY);
        _scheduleOn(tl, p1, p1Pk, address(g), _cancelCall(), _bid, "cancel-a");
        vm.warp(_t1 + ADMIN_DELAY + MIN_DELAY);
        assertEq(block.timestamp, uint256(_schedule), "the edge second");
        _acceptReverts(_enforcedDelay(_schedule));
        _executeOn(tl, address(g), _cancelCall(), _bid, "cancel-a");
        (_pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, address(0), "r = A: the chained cancel wins by one second");
        vm.warp(block.timestamp + 1);
        _acceptReverts(_notPending());
        vm.revertToState(_snap);

        // (b) r = A + 1: both executable in the same second; the builder's order decides, both ways.
        vm.warp(_t1 + ADMIN_DELAY + 1);
        _scheduleOn(tl, p1, p1Pk, address(g), _cancelCall(), _bid, "cancel-b");
        vm.warp(_t1 + ADMIN_DELAY + MIN_DELAY + 1);
        uint256 _snapB = vm.snapshotState();
        _accept();
        assertEq(g.defaultAdmin(), attacker, "r = A + 1, acceptance first: the seat is lost");
        vm.expectRevert(_notAdmin());
        _executeOn(tl, address(g), _cancelCall(), _bid, "cancel-b");
        vm.revertToState(_snapB);
        _executeOn(tl, address(g), _cancelCall(), _bid, "cancel-b");
        _acceptReverts(_notPending());
        assertEq(g.defaultAdmin(), address(tl), "r = A + 1, cancel first: the seat is kept");
        vm.revertToState(_snap);

        // (c) r = A + 2: the chained cancel is one second late at the deploy defaults, chained or not.
        vm.warp(_t1 + ADMIN_DELAY + 2);
        _scheduleOn(tl, p1, p1Pk, address(g), _cancelCall(), _bid, "cancel-c");
        bytes32 _unchained = _scheduleOn(tl, p1, p1Pk, address(g), _cancelCall(), NONE, "cancel-c-unchained");
        vm.warp(_t1 + ADMIN_DELAY + MIN_DELAY + 1);
        assertFalse(tl.isOperationReady(_unchained), "neither cancel is Ready when the acceptance opens");
        _accept();
        assertEq(g.defaultAdmin(), attacker, "r = A + 2: the attacker's seat, at the shipped delays");
        vm.warp(block.timestamp + 1);
        vm.expectRevert(_notAdmin());
        _executeOn(tl, address(g), _cancelCall(), _bid, "cancel-c");
        vm.revertToState(_snap);

        // (d) The unchained cancel obeys the same law: scheduled at the begin's execution (r = D) it keeps A - D
        //     (a day and the edge second at the defaults); scheduled at r = A it keeps the edge second alone.
        vm.warp(_t1 + MIN_DELAY);
        bytes32 _atExec = _scheduleOn(tl, p1, p1Pk, address(g), _cancelCall(), NONE, "cancel-d");
        vm.warp(_t1 + 2 * MIN_DELAY);
        assertTrue(tl.isOperationReady(_atExec), "Ready a day before the acceptance opens");
        vm.warp(_t1 + MIN_DELAY + ADMIN_DELAY);
        _acceptReverts(_enforcedDelay(_schedule));
        _executeOn(tl, address(g), _cancelCall(), NONE, "cancel-d");
        (_pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, address(0));
        vm.revertToState(_snap0);

        // (e) The veto's own window is D plus however long the attacker waits: a Ready begin held in reserve for
        //     twenty days is still cancellable, and cancelling it costs the attacker the whole round.
        vm.warp(_t1 + 20 days);
        assertTrue(tl.isOperationReady(_bid), "held in reserve, never expiring");
        _cancel(_bid);
        assertFalse(tl.isOperation(_bid), "the veto clears it whenever it wakes, before the attacker lands it");
        (_pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, address(0));
    }

    /*//////////////////////////////////////////////////////////////
          T3: INVERTED DELAYS IN ONE BATCH (D = 30 d above A = 1 d)
    //////////////////////////////////////////////////////////////*/

    /// @dev Both knobs in ONE operation at the live 2-day delay: `updateDelay(30 days)` (the cap) next to
    ///      `changeDefaultAdminDelay(1 day)` (the floor). The delays are then INVERTED, the case the governance
    ///      summary names "accepted before an unchained cancel is Ready": an unchained cancel scheduled when the
    ///      begin lands is 29 days late, the honest rollback of the admin delay can no longer be Ready inside
    ///      OpenZeppelin's two-day wait (the timelock is at 30 days now), and the chained cancel wins iff it is
    ///      scheduled within the NEW admin delay, one day, of the hostile begin's CallScheduled, 30 days before
    ///      that begin can land. The veto keeps the whole month.
    function test_T3_inverting_the_delays_in_one_batch_leaves_the_chained_cancel_one_day_to_be_scheduled() public {
        _configureCurator();
        address[] memory _t = new address[](2);
        _t[0] = address(tl);
        _t[1] = address(g);
        bytes[] memory _d = new bytes[](2);
        _d[0] = abi.encodeCall(tl.updateDelay, (30 days));
        _d[1] = abi.encodeCall(g.changeDefaultAdminDelay, (uint48(1 days)));
        _scheduleBatch(p2, p2Pk, _t, _d, NONE, "invert");
        uint256 _t0 = block.timestamp;
        vm.warp(_t0 + MIN_DELAY);
        _executeBatch(_t, _d, NONE, "invert");
        assertEq(tl.getMinDelay(), 30 days, "the timelock at its cap at once");
        (uint48 _pendingDelay, uint48 _effect) = g.pendingDefaultAdminDelay();
        assertEq(uint256(_pendingDelay), 1 days);
        assertEq(uint256(_effect), _t0 + MIN_DELAY + 2 days, "the admin floor applies after the 3 d - 1 d difference");
        // The honest rollback cannot be Ready inside that wait any more: the timelock is at 30 days.
        bytes32 _rb = _scheduleOn(tl, p1, p1Pk, address(g), abi.encodeCall(g.rollbackDefaultAdminDelay, ()), NONE, "rollback");
        assertEq(tl.getTimestamp(_rb), _t0 + MIN_DELAY + 30 days, "Ready 28 days after the lowering took effect");
        // The hostile begin, scheduled in the same block as the batch executed: Ready 30 days out.
        uint256 _t1 = block.timestamp;
        bytes32 _bid = _scheduleOn(tl, p2, p2Pk, address(g), _begin(), NONE, "begin");
        uint256 _snap = vm.snapshotState();

        // (a) The chained cancel scheduled r = A_new = 1 day after the hostile CallScheduled: one exclusive second.
        vm.warp(_t1 + 1 days);
        _scheduleOn(tl, p1, p1Pk, address(g), _cancelCall(), _bid, "cancel-a");
        vm.warp(_t1 + 30 days);
        _executeOn(tl, address(g), _begin(), NONE, "begin");
        (, uint48 _schedule) = g.pendingDefaultAdmin();
        assertEq(uint256(_schedule), _t1 + 30 days + 1 days, "the acceptance opens a day and a second after the begin lands");
        vm.warp(_t1 + 31 days);
        _acceptReverts(_enforcedDelay(_schedule));
        _executeOn(tl, address(g), _cancelCall(), _bid, "cancel-a");
        (address _pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, address(0), "r = A_new: the chained cancel wins by one second, a month after it was scheduled");
        vm.revertToState(_snap);

        // (b) Scheduled r = A_new + 2: the seat is the attacker's, chained or not; an unchained cancel scheduled when
        //     the begin lands is Ready 29 days after the acceptance opened.
        vm.warp(_t1 + 1 days + 2);
        _scheduleOn(tl, p1, p1Pk, address(g), _cancelCall(), _bid, "cancel-b");
        vm.warp(_t1 + 30 days);
        _executeOn(tl, address(g), _begin(), NONE, "begin");
        bytes32 _late = _scheduleOn(tl, p1, p1Pk, address(g), _cancelCall(), NONE, "cancel-late");
        assertEq(tl.getTimestamp(_late), _t1 + 60 days, "an unchained cancel at the begin's landing: 29 days late");
        vm.warp(_t1 + 31 days + 1);
        _accept();
        assertEq(g.defaultAdmin(), attacker, "r = A_new + 2: the attacker's seat");
        vm.revertToState(_snap);

        // (c) The veto: the begin sits a month in public; one cancel at any time before the attacker lands it.
        vm.warp(_t1 + 29 days);
        _cancel(_bid);
        assertFalse(tl.isOperation(_bid));
    }

    /*//////////////////////////////////////////////////////////////
       T4: THE ROLLBACK EDGE (D_default == A_default - A_floor == 2 d)
    //////////////////////////////////////////////////////////////*/

    /// @dev A hostile `changeDefaultAdminDelay(1 day)` executed at E0 takes effect at E0 + 2 d (OpenZeppelin waits
    ///      the difference 3 d - 1 d) and can be undone by `rollbackDefaultAdminDelay` until then. Through the
    ///      2-day timelock the honest rollback is Ready at exactly E0 + 2 d only if it is scheduled in the block
    ///      the hostile change executed (`schedule < now` is strict: the edge second belongs to the rollback);
    ///      scheduled one second later it lands, undoes nothing, and the admin delay sits at its floor for five
    ///      days and a second until a re-raise takes effect.
    function test_T4_the_honest_rollback_of_a_lowered_admin_delay_must_be_scheduled_in_the_block_the_lowering_lands() public {
        _configureCurator();
        bytes memory _lower = abi.encodeCall(g.changeDefaultAdminDelay, (uint48(1 days)));
        _scheduleOn(tl, p2, p2Pk, address(g), _lower, NONE, "lower");
        vm.warp(block.timestamp + MIN_DELAY);
        _executeOn(tl, address(g), _lower, NONE, "lower");
        uint256 _e0 = block.timestamp;
        (, uint48 _effect) = g.pendingDefaultAdminDelay();
        assertEq(uint256(_effect), _e0 + 2 days, "the OpenZeppelin wait equals the default timelock delay");
        bytes memory _rollback = abi.encodeCall(g.rollbackDefaultAdminDelay, ());
        uint256 _snap = vm.snapshotState();

        // (a) Scheduled in the same block: Ready at the effect second, where the pending delay has NOT passed yet.
        _scheduleOn(tl, p1, p1Pk, address(g), _rollback, NONE, "rb-a");
        vm.warp(_e0 + 2 days);
        assertEq(uint256(g.defaultAdminDelay()), 3 days, "still 3 days at the effect second (strict)");
        _executeOn(tl, address(g), _rollback, NONE, "rb-a");
        vm.warp(_e0 + 2 days + 1);
        assertEq(uint256(g.defaultAdminDelay()), 3 days, "rolled back: the lowering never took effect");
        vm.revertToState(_snap);

        // (b) Scheduled one second later: the rollback lands after the lowering materialised and undoes nothing.
        vm.warp(_e0 + 1);
        _scheduleOn(tl, p1, p1Pk, address(g), _rollback, NONE, "rb-b");
        vm.warp(_e0 + 2 days + 1);
        _executeOn(tl, address(g), _rollback, NONE, "rb-b");
        assertEq(uint256(g.defaultAdminDelay()), 1 days, "one second late: the floor is in force");
        // The re-raise: a scheduled `changeDefaultAdminDelay(3 days)` (an increase waits min(new, 5 d)).
        bytes memory _raise = abi.encodeCall(g.changeDefaultAdminDelay, (uint48(3 days)));
        _scheduleOn(tl, p1, p1Pk, address(g), _raise, NONE, "raise");
        vm.warp(block.timestamp + MIN_DELAY);
        _executeOn(tl, address(g), _raise, NONE, "raise");
        (, uint48 _back) = g.pendingDefaultAdminDelay();
        assertEq(uint256(_back), block.timestamp + 3 days);
        vm.warp(uint256(_back));
        assertEq(uint256(g.defaultAdminDelay()), 1 days, "a day for five days and a second after the lowering landed");
        vm.warp(uint256(_back) + 1);
        assertEq(uint256(g.defaultAdminDelay()), 3 days);
    }

    /*//////////////////////////////////////////////////////////////
         T5: THE ADMIN'S LIFT WITHOUT A COUNCIL AT THE FLOOR (D = C)
    //////////////////////////////////////////////////////////////*/

    /// @dev The lift of a lockdown at L, scheduled at L + r, lands at max(L + r + D, L + C + 1): with D = C and
    ///      any signing round r >= 1 s that is D + r after the lockdown, the cooldown is inside the delay (docs 6
    ///      "minDelay plus the one-day cooldown" is the RE-LOCK bound, measured next). With the sync's lift deadline
    ///      T_prep + D + C + 1 d: a re-lock at Ready - 1 lands the lift at D + C after the schedule, a re-lock at
    ///      T_prep + D + 1 d - 1 lands it in the deadline's own second, a re-lock AT T_prep + D + 1 d kills it.
    function test_T5_at_the_floor_the_admin_lift_is_minDelay_plus_the_signing_round_and_the_relock_bound_is_exact() public {
        _configureCurator();
        _selfCall(abi.encodeCall(tl.updateDelay, (1 days)), "floor");
        vm.prank(council);
        g.setDeploymentGuardian(key, true);
        vm.prank(key);
        g.lockdown(address(curatorSafe));
        uint256 _l = block.timestamp;
        uint256 _r = 1 hours; // the proposer Safe's signing round
        uint256 _prep = _l + _r;
        uint64 _deadline = uint64(_prep + 1 days + 1 days + 1 days); // T_prep + D + C + 1 d (--unlock-deadline-days 1)
        bytes memory _lift = _wrap(_deadline, abi.encodeCall(g.enforce, (address(curatorSafe))));
        vm.warp(_prep);
        bytes32 _id = _schedule(p1, p1Pk, address(g), _lift, NONE, "lift");
        uint256 _ready = _prep + 1 days;
        assertEq(tl.getTimestamp(_id), _ready);
        uint256 _snap = vm.snapshotState();

        // (a) No re-lock: the lift lands at Ready = L + D + r; the cooldown (through L + C inclusive) is inside it.
        vm.warp(_ready);
        _execute(address(g), _lift, NONE, "lift");
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Enforced));
        assertEq(block.timestamp - _l, 1 days + _r, "recovery = minDelay + the signing round, not minDelay + the cooldown");
        vm.revertToState(_snap);

        // (b) A re-lock one second before Ready: held until Ready + C, i.e. D + C after the schedule (docs 6's bound).
        vm.warp(_ready - 1);
        vm.prank(key);
        g.lockdown(address(curatorSafe));
        vm.warp(_ready);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(curatorSafe)));
        _execute(address(g), _lift, NONE, "lift");
        vm.warp(_ready - 1 + 1 days);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(curatorSafe)));
        _execute(address(g), _lift, NONE, "lift");
        vm.warp(_ready + 1 days);
        _execute(address(g), _lift, NONE, "lift");
        assertEq(block.timestamp - _prep, 2 days, "D + C from the schedule");
        vm.revertToState(_snap);

        // (c) The last re-lock the lift survives: at deadline - C - 1 it lands in the deadline's own second.
        vm.warp(uint256(_deadline) - 1 days - 1);
        vm.prank(key);
        g.lockdown(address(curatorSafe));
        vm.warp(uint256(_deadline));
        _execute(address(g), _lift, NONE, "lift");
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Enforced), "landed at the inclusive deadline");
        vm.revertToState(_snap);

        // (d) A re-lock AT deadline - C (= T_prep + D + 1 d): the cooldown outlives the deadline by one second.
        vm.warp(uint256(_deadline) - 1 days);
        assertEq(block.timestamp, _prep + 1 days + 1 days, "T_prep + D + u days");
        vm.prank(key);
        g.lockdown(address(curatorSafe));
        vm.warp(uint256(_deadline));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(curatorSafe)));
        _execute(address(g), _lift, NONE, "lift");
        vm.warp(uint256(_deadline) + 1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, _deadline));
        _execute(address(g), _lift, NONE, "lift");
        assertTrue(tl.isOperationReady(_id), "dead, and Ready for ever until the veto clears it");
    }

    /*//////////////////////////////////////////////////////////////
       T6: A STOCK OF READY BEGINS AT THE FLOORS NEEDS AS MANY CANCELS
    //////////////////////////////////////////////////////////////*/

    /// @dev At the floors (both delays a day, g14g's chain) each begin the attacker landed is answered by one Ready
    ///      cancel; a second Ready begin re-opens the window in the next block, and the honest resupply, scheduled
    ///      when that begin lands, is Ready in the schedule's own second (the edge) or, one block later, after the
    ///      acceptance opened. The honest side therefore needs a stock no smaller than the attacker's, or the veto's
    ///      one batched cancel while the stock still sits in the queue.
    function test_T6_at_the_floors_a_stock_of_two_begins_against_one_cancel_is_won_by_the_resupplys_block() public {
        _configureCurator();
        _hostile(address(tl), abi.encodeCall(tl.updateDelay, (1 days)), "floor");
        _hostile(address(g), abi.encodeCall(g.changeDefaultAdminDelay, (uint48(1 days))), "admin-delay");
        vm.warp(block.timestamp + 2 days + 1);
        assertEq(uint256(g.defaultAdminDelay()), tl.getMinDelay(), "equal");
        uint256 _t = block.timestamp;
        _scheduleOn(tl, p2, p2Pk, address(g), _begin(), NONE, "b1");
        _scheduleOn(tl, p2, p2Pk, address(g), _begin(), NONE, "b2");
        _scheduleOn(tl, p1, p1Pk, address(g), _cancelCall(), NONE, "c1");
        vm.warp(_t + 1 days);
        _executeOn(tl, address(g), _begin(), NONE, "b1");
        _executeOn(tl, address(g), _cancelCall(), NONE, "c1");
        (address _pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, address(0), "one begin, one cancel");
        vm.warp(_t + 1 days + 12);
        _executeOn(tl, address(g), _begin(), NONE, "b2");
        (_pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, attacker, "the second begin re-opens the window; no cancel left in the queue");
        uint256 _snap = vm.snapshotState();
        // The resupply scheduled in the block the second begin landed: Ready in the schedule's second, the edge.
        _scheduleOn(tl, p1, p1Pk, address(g), _cancelCall(), NONE, "c2");
        vm.warp(_t + 2 days + 12);
        _executeOn(tl, address(g), _cancelCall(), NONE, "c2");
        (_pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, address(0), "resupplied in the same block: the edge second is the honest side's");
        vm.revertToState(_snap);
        // One block later: the acceptance opens before the resupply is Ready.
        vm.warp(_t + 1 days + 24);
        bytes32 _c2 = _scheduleOn(tl, p1, p1Pk, address(g), _cancelCall(), NONE, "c2");
        vm.warp(_t + 2 days + 13);
        assertFalse(tl.isOperationReady(_c2));
        _accept();
        assertEq(g.defaultAdmin(), attacker, "one block of reaction: the stock decides at the floors");
    }

    /*//////////////////////////////////////////////////////////////
       T7: ANY EXECUTED DELAY CHANGE KILLS EVERY SIGNED, UNLANDED PROPOSAL
    //////////////////////////////////////////////////////////////*/

    /// @dev The proposal-time rail accepts exactly the live `getMinDelay()`. A Ready `updateDelay` executed by anyone
    ///      in the block before an honest proposer Safe's signed `scheduleBatch` lands makes that Safe transaction fail
    ///      (GS013: `DelayOutOfRange` for a now-too-long delay, `TimelockInsufficientDelay` for a too-short one): a
    ///      signing round per delay change, the honest side's own `updateDelay` included.
    function test_T7_a_delay_change_landed_first_costs_the_honest_proposer_its_signed_round_both_ways() public {
        _configureCurator();
        bytes memory _payload = abi.encodeCall(g.setDeploymentGuardian, (key, true));
        // The hostile lowering sits Ready; the honest proposal (signed at 2 days) lands one block after it executes.
        bytes memory _lower = abi.encodeCall(tl.updateDelay, (1 days));
        _scheduleOn(tl, p2, p2Pk, address(tl), _lower, NONE, "lower");
        vm.warp(block.timestamp + MIN_DELAY);
        _executeOn(tl, address(tl), _lower, NONE, "lower");
        bytes memory _sched = abi.encodeCall(tl.schedule, (address(g), 0, _payload, NONE, bytes32("honest"), MIN_DELAY));
        vm.expectRevert(bytes("GS013"));
        _exec(p1, p1Pk, address(tl), 0, _sched, Operation.Call);
        // The typed refusal, from the proposer Safe's own frame: the signed delay is now above the live one.
        vm.prank(address(p1));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, MIN_DELAY));
        tl.schedule(address(g), 0, _payload, NONE, bytes32("honest"), MIN_DELAY);
        assertEq(tl.getTimestamp(tl.hashOperation(address(g), 0, _payload, NONE, bytes32("honest"))), 0, "nothing scheduled");
        // The honest side's own raise does the same to every proposal signed at the old delay.
        _selfCall(abi.encodeCall(tl.updateDelay, (3 days)), "raise");
        vm.prank(address(p1));
        vm.expectRevert(
            abi.encodeWithSelector(TimelockController.TimelockInsufficientDelay.selector, uint256(1 days), uint256(3 days))
        );
        tl.schedule(address(g), 0, _payload, NONE, bytes32("honest"), 1 days);
        bytes memory _again = abi.encodeCall(tl.schedule, (address(g), 0, _payload, NONE, bytes32("honest"), 3 days));
        assertTrue(_exec(p1, p1Pk, address(tl), 0, _again, Operation.Call), "re-signed at the live delay");
    }
}
