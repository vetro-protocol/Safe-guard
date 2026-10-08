// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {CuratorGuardTestBase, CuratorGuardHarness} from "test/guards/CuratorGuardTestBase.sol";

/// @title Round 11 (g11c): the sync task's `executeBefore` windows, counted from PREPARATION (G9e-5), measured
///        through a real `CuratorGuardTimelock` at the deployed delays (minDelay 48 h, cooldown 1 day,
///        `--deadline-days 14`, `--unlock-deadline-days 1`).
/// @dev   The task fixes `deadline = prep + minDelay + W` when it prepares the batch (W = 14 days for the
///        body, cooldown + 1 day for the lift) and the operation is Ready `minDelay` after the proposer
///        Safe executes `scheduleBatch` at `prep + signing`. The window that remains is `W - signing`:
///        the lift is dead on arrival once the signing round exceeds 2 days, the body once it exceeds
///        14 days, and an operation whose Ready second equals its deadline is executable in that one
///        second only (a block lands on a given second with probability 1/12).
contract CuratorGuardG11cLiftWindowTest is CuratorGuardTestBase {
    uint256 internal constant MIN_DELAY = 48 hours;
    uint256 internal constant COOLDOWN = 1 days;
    uint256 internal constant BODY_WINDOW = 14 days;
    uint256 internal constant UNLOCK_WINDOW = 1 days;

    CuratorGuardTimelock internal tl;
    CuratorGuard internal g;
    address internal proposer = makeAddr("proposer");

    function setUp() public override {
        super.setUp();
        address[] memory _p = new address[](1);
        _p[0] = proposer;
        address[] memory _c = new address[](1);
        _c[0] = makeAddr("veto");
        tl = new CuratorGuardTimelock(MIN_DELAY, _p, _c);
        g = new CuratorGuardHarness(0, address(tl), council);
        CuratorGuardHarness(address(g)).seedSafe(address(safe));
    }

    function _wrapped(uint64 deadline_, bytes memory call_) internal view returns (bytes memory) {
        return abi.encodeCall(g.executeBefore, (deadline_, call_));
    }

    /// @dev Body and lift prepared at `prep`, scheduled `signing` seconds later: alive or dead exactly
    ///      as the arithmetic says, for every signing delay from 0 to 15 days.
    function testFuzz_windows_shrink_by_the_signing_delay(uint256 signing_) public {
        uint256 _prep = block.timestamp;
        uint256 _signing = bound(signing_, 0, 15 days);
        uint64 _bodyDeadline = uint64(_prep + MIN_DELAY + BODY_WINDOW);
        uint64 _liftDeadline = uint64(_prep + MIN_DELAY + COOLDOWN + UNLOCK_WINDOW);
        bytes memory _body = _wrapped(_bodyDeadline, abi.encodeCall(g.setRequiredFallbackHandler, (address(safe), address(0), true)));
        bytes memory _lift = _wrapped(_liftDeadline, abi.encodeCall(g.enforce, (address(safe))));
        // The Safe is in Lockdown from a lockdown that happened well before preparation (no cooldown left).
        vm.warp(_prep + _signing);
        vm.startPrank(proposer);
        tl.schedule(address(g), 0, _body, bytes32(0), bytes32("body"), MIN_DELAY);
        bytes32 _bodyId = tl.hashOperation(address(g), 0, _body, bytes32(0), bytes32("body"));
        tl.schedule(address(g), 0, _lift, _bodyId, bytes32("lift"), MIN_DELAY);
        vm.stopPrank();
        uint256 _ready = _prep + _signing + MIN_DELAY;
        vm.warp(_ready);
        bool _bodyAlive = _ready <= _bodyDeadline;
        bool _liftAlive = _ready <= _liftDeadline;
        assertEq(_bodyAlive, _signing <= BODY_WINDOW, "body dies once signing exceeds 14 days");
        assertEq(_liftAlive, _signing <= COOLDOWN + UNLOCK_WINDOW, "lift dies once signing exceeds 2 days");
        if (!_bodyAlive) vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, _bodyDeadline));
        tl.execute(address(g), 0, _body, bytes32(0), bytes32("body"));
        if (!_bodyAlive) return; // the lift's predecessor never executes: it is stuck behind a dead body
        if (!_liftAlive) vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, _liftDeadline));
        tl.execute(address(g), 0, _lift, _bodyId, bytes32("lift"));
        if (_liftAlive) assertEq(uint8(g.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Enforced));
    }

    /// @dev Exactly two days of signing: the lift's Ready second IS its deadline, alive for that one
    ///      second and dead the next; a lockdown one second after the lift was prepared leaves it alive
    ///      only if the cooldown ends inside the window.
    function test_lift_alive_for_one_second_when_signing_takes_exactly_the_window() public {
        uint256 _prep = block.timestamp;
        uint64 _liftDeadline = uint64(_prep + MIN_DELAY + COOLDOWN + UNLOCK_WINDOW);
        bytes memory _lift = _wrapped(_liftDeadline, abi.encodeCall(g.enforce, (address(safe))));
        vm.warp(_prep + COOLDOWN + UNLOCK_WINDOW); // scheduleBatch lands exactly 2 days after preparation
        vm.prank(proposer);
        tl.schedule(address(g), 0, _lift, bytes32(0), bytes32("lift"), MIN_DELAY);
        bytes32 _id = tl.hashOperation(address(g), 0, _lift, bytes32(0), bytes32("lift"));
        assertEq(tl.getTimestamp(_id), uint256(_liftDeadline), "Ready second == deadline");
        vm.warp(_liftDeadline + 1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, _liftDeadline));
        tl.execute(address(g), 0, _lift, bytes32(0), bytes32("lift"));
        vm.warp(_liftDeadline);
        tl.execute(address(g), 0, _lift, bytes32(0), bytes32("lift"));
        assertEq(uint8(g.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Enforced));
    }

    /// @dev A lockdown AFTER preparation re-arms the cooldown: with instant signing the lift survives a
    ///      lockdown up to `prep + minDelay + unlockDays` and dies one second later, before the deadline.
    function testFuzz_a_lockdown_after_preparation_kills_the_lift_a_day_before_its_deadline(uint256 lockAt_) public {
        uint256 _prep = block.timestamp;
        uint64 _liftDeadline = uint64(_prep + MIN_DELAY + COOLDOWN + UNLOCK_WINDOW);
        bytes memory _lift = _wrapped(_liftDeadline, abi.encodeCall(g.enforce, (address(safe))));
        vm.prank(proposer);
        tl.schedule(address(g), 0, _lift, bytes32(0), bytes32("lift"), MIN_DELAY);
        vm.prank(council);
        g.setGuardian(address(safe), guardian, true); // the fixture's guardian, seated by the council on the new guard
        uint256 _lockAt = bound(lockAt_, _prep + 1, _liftDeadline);
        vm.warp(_lockAt);
        vm.prank(guardian);
        g.lockdown(address(safe));
        // Earliest admin lift: lockedAt + cooldown + 1; latest: the deadline.
        uint256 _earliest = _lockAt + COOLDOWN + 1;
        uint256 _ready = _prep + MIN_DELAY;
        uint256 _from = _earliest > _ready ? _earliest : _ready;
        bool _alive = _from <= _liftDeadline;
        assertEq(_alive, _lockAt + COOLDOWN + 1 <= _liftDeadline, "alive iff the cooldown ends inside the window");
        vm.warp(_from <= _liftDeadline ? _from : _liftDeadline);
        if (!_alive) {
            vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(safe)));
            tl.execute(address(g), 0, _lift, bytes32(0), bytes32("lift"));
            return;
        }
        tl.execute(address(g), 0, _lift, bytes32(0), bytes32("lift"));
        assertEq(uint8(g.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Enforced));
    }
}
