// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IAccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/IAccessControlDefaultAdminRules.sol";

import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G9cBase} from "test/guards/G9c_Base.sol";
import {TestERC20} from "test/mocks/TestERC20.sol";

/// @dev Fires two Ready operations of one timelock in ONE transaction: a hostile begin and the cancel chained
///      behind it. `execute` reverts on failure, so the pair lands as one or not at all.
contract G16aPair {
    function fire(
        CuratorGuardTimelock tl_,
        address target_,
        bytes calldata begin_,
        bytes32 beginSalt_,
        bytes calldata cancel_,
        bytes32 beginId_,
        bytes32 cancelSalt_
    ) external {
        tl_.execute(target_, 0, begin_, bytes32(0), beginSalt_);
        tl_.execute(target_, 0, cancel_, beginId_, cancelSalt_);
    }
}

/// @title Round 16, reviewer g16a: THE INSIDER WHO READ THE FOLLOW-UP.
/// @dev   Production topology of `G9cBase` (real Safe v1.4.1 proxies behind the curator, two proposers and the
///        veto; a real `CuratorGuardTimelock` at 2 days; the guard's admin delay 3 days; an EOA council). The
///        attacker holds one proposer Safe (p2) and the veto is lost: the setting in which §7.5's CHAINED cancel
///        is the honest side's only answer to a hostile `beginDefaultAdminTransfer`. The follow-up's floor made
///        the two delays equalisable (G14g-2) and §7.5 answers with "chain the cancel: anyone executes it in the
///        block the begin lands, whenever the attacker lands it". The insider's reading: the hostile begin carries
///        no deadline and the attacker chooses WHEN it lands; the honest chained cancel, if wrapped in
///        `executeBefore` like every other scheduled call of the house style, is waited out (tests 1 and 2); the
///        remedies are a bare cancel (test 5), firing the pair oneself (test 3), chaining behind the LAST hostile
///        operation (test 4) and the eviction that ends the ladder.
contract G16a_InsiderTest is G9cBase {
    TestERC20 internal token;
    G16aPair internal pair;
    address internal attacker = makeAddr("attacker");
    uint256 internal constant CUSTODY = 1_000_000e6;

    bytes internal beginData;
    bytes internal cancelBare;

    function setUp() public override {
        super.setUp();
        _configureCurator();
        token = new TestERC20("USD Coin", "USDC");
        token.mint(address(curatorSafe), CUSTODY);
        pair = new G16aPair();
        beginData = abi.encodeCall(g.beginDefaultAdminTransfer, (attacker));
        cancelBare = abi.encodeCall(g.cancelDefaultAdminTransfer, ());
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev A hostile proposer schedules one call at the LIVE minimum delay and the lost veto lets it land.
    function _hostile(address target_, bytes memory data_, bytes32 salt_) internal {
        _scheduleOn(tl, p2, p2Pk, target_, data_, NONE, salt_);
        vm.warp(block.timestamp + tl.getMinDelay());
        _executeOn(tl, target_, data_, NONE, salt_);
    }

    /// @dev G14g-2's equalisation: both delays to their one-day floors (two vetoable operations the lost veto
    ///      never cancels; OpenZeppelin applies the shorter admin delay after the two-day difference).
    function _equalise() internal {
        _hostile(address(tl), abi.encodeCall(tl.updateDelay, (1 days)), "floor");
        _hostile(address(g), abi.encodeCall(g.changeDefaultAdminDelay, (uint48(1 days))), "admin-delay");
        vm.warp(block.timestamp + 2 days + 1);
        assertEq(uint256(g.defaultAdminDelay()), tl.getMinDelay(), "equal delays");
    }

    /// @dev The sync task's deadline shape for a scheduled call: preparation + minDelay + 14 days.
    function _houseDeadline() internal view returns (uint64) {
        return uint64(block.timestamp + tl.getMinDelay() + 14 days);
    }

    function _pending() internal view returns (address _who, uint48 _sched) {
        (_who, _sched) = g.pendingDefaultAdmin();
    }

    function _accept() internal {
        vm.prank(attacker);
        g.acceptDefaultAdminTransfer();
    }

    function _expectAcceptTooEarly(uint48 sched_) internal {
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminDelay.selector, sched_)
        );
        g.acceptDefaultAdminTransfer();
    }

    function _expectDead(bytes memory data_, bytes32 pred_, bytes32 salt_, uint64 dl_) internal {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, dl_));
        tl.execute(address(g), 0, data_, pred_, salt_);
    }

    /// @dev The hostile begin (bare: the attacker gives its loaded gun no deadline) and the honest chained cancel
    ///      WRAPPED in `executeBefore` with the house deadline, both scheduled now.
    function _beginAndWrappedChainedCancel()
        internal
        returns (bytes32 _bid, bytes32 _cid, bytes memory _cancelW, uint64 _dl)
    {
        _bid = _scheduleOn(tl, p2, p2Pk, address(g), beginData, NONE, "begin");
        _dl = _houseDeadline();
        _cancelW = _wrap(_dl, cancelBare);
        _cid = _scheduleOn(tl, p1, p1Pk, address(g), _cancelW, _bid, "chained-cancel");
    }

    /*//////////////////////////////////////////////////////////////
          1. A WRAPPED CHAINED CANCEL IS WAITED OUT (AT THE FLOORS)
    //////////////////////////////////////////////////////////////*/

    /// @dev G16a-1. At the floors (G14g-2 reached): the hostile begin is Ready and never expires; the honest
    ///      chained cancel carries the sync's `executeBefore` deadline. The attacker lands the begin one second
    ///      after that deadline: the chained cancel reverts `DeadlinePassed`, the honest side is back to an
    ///      UNCHAINED fresh cancel, which at equal delays is G14c-3's one-second edge and then the builder's order.
    ///      Where §7.5 promised "wins at any admin delay, whenever the attacker lands it", the wrapped cancel loses
    ///      the seat on the attacker's order.
    function test_1_a_wrapped_chained_cancel_is_waited_out_and_the_seat_is_lost_at_the_floors() public {
        _equalise();
        (bytes32 _bid, bytes32 _cid, bytes memory _cancelW, uint64 _dl) = _beginAndWrappedChainedCancel();
        vm.warp(uint256(_dl) + 1);
        assertTrue(tl.isOperationReady(_bid), "a Ready begin never expires: the loaded gun");
        assertTrue(tl.isOperationReady(_cid), "the chained cancel is Ready too, but its wrapper is dead");
        // The attacker lands the begin now.
        _executeOn(tl, address(g), beginData, NONE, "begin");
        uint256 _tb = block.timestamp;
        (address _who, uint48 _sched) = _pending();
        assertEq(_who, attacker, "the hand-over is pending");
        assertEq(uint256(_sched), _tb + 1 days, "acceptable one day after the begin landed");
        // The chained cancel, executable at last, is dead.
        _expectDead(_cancelW, _bid, "chained-cancel", _dl);
        // The honest reflex, a fresh UNCHAINED cancel in the block the begin landed: Ready at the schedule's
        // own second, one second of exclusive executability, then the order inside the block.
        bytes32 _fid = _scheduleOn(tl, p1, p1Pk, address(g), cancelBare, NONE, "fresh-cancel");
        vm.warp(_tb + 1 days);
        assertTrue(tl.isOperationReady(_fid), "the fresh cancel is Ready at exactly T_b + 1 day");
        _expectAcceptTooEarly(_sched);
        vm.warp(_tb + 1 days + 1);
        _accept();
        assertEq(g.defaultAdmin(), attacker, "the attacker's order: the seat is lost");
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, address(tl), bytes32(0))
        );
        tl.execute(address(g), 0, cancelBare, NONE, "fresh-cancel");
        assertEq(token.balanceOf(address(curatorSafe)), CUSTODY, "an admin alone moves no custody");
    }

    /*//////////////////////////////////////////////////////////////
        2. ... AND AT THE DEFAULTS THE MARGIN SHRINKS TO A - D (ONE DAY)
    //////////////////////////////////////////////////////////////*/

    /// @dev G16a-1 at the deploy defaults (minDelay 2 d, admin delay 3 d): the waited-out wrapped cancel leaves
    ///      the honest side V2-10's unchained property, a reaction window of exactly `adminDelay - minDelay`
    ///      (one day) from the moment the attacker lands the begin, which is the attacker's moment. A fresh cancel
    ///      scheduled one day after the begin is Ready in the schedule's second (honest edge); one second later
    ///      both are executable in the same second and the order inside the block decides.
    function test_2_at_the_defaults_the_waited_out_cancel_leaves_a_one_day_reaction_window() public {
        (bytes32 _bid, , bytes memory _cancelW, uint64 _dl) = _beginAndWrappedChainedCancel();
        vm.warp(uint256(_dl) + 1);
        _executeOn(tl, address(g), beginData, NONE, "begin");
        uint256 _tb = block.timestamp;
        (, uint48 _sched) = _pending();
        assertEq(uint256(_sched), _tb + ADMIN_DELAY);
        _expectDead(_cancelW, _bid, "chained-cancel", _dl);
        uint256 _snap = vm.snapshotState();
        // Reaction exactly A - D after the begin: the cancel is Ready in the schedule's second, the acceptance
        // opens one second later.
        uint256 _window = uint256(ADMIN_DELAY) - MIN_DELAY;
        assertEq(_window, 1 days, "the reaction window at the defaults");
        vm.warp(_tb + _window);
        bytes32 _fid = _scheduleOn(tl, p1, p1Pk, address(g), cancelBare, NONE, "fresh-cancel");
        vm.warp(_tb + ADMIN_DELAY);
        assertTrue(tl.isOperationReady(_fid), "Ready at exactly the schedule second");
        _expectAcceptTooEarly(_sched);
        _executeOn(tl, address(g), cancelBare, NONE, "fresh-cancel");
        (address _who, ) = _pending();
        assertEq(_who, address(0), "cancelled on the honest edge");
        // Reaction one second later than A - D: both executable in the same second, the attacker's order shown.
        vm.revertToState(_snap);
        vm.warp(_tb + _window + 1);
        bytes32 _late = _scheduleOn(tl, p1, p1Pk, address(g), cancelBare, NONE, "late-cancel");
        vm.warp(_tb + ADMIN_DELAY + 1);
        assertTrue(tl.isOperationReady(_late), "both executable in the same second");
        _accept();
        assertEq(g.defaultAdmin(), attacker, "one second late: the builder's order, here the attacker's");
    }

    /*//////////////////////////////////////////////////////////////
               3. THE DEFUSAL: FIRE THE PAIR YOURSELF, IN TIME
    //////////////////////////////////////////////////////////////*/

    /// @dev The honest side need not wait for the attacker: once both are Ready, anyone lands the begin AND the
    ///      chained cancel in one transaction (the pair reverts as one if the cancel fails), inside the wrapper's
    ///      deadline. The loaded begin is spent, nothing is pending, the attacker's acceptance has nothing to
    ///      accept. (Only valid while nothing hostile is chained behind the cancel: test 4.)
    function test_3_anyone_fires_the_begin_and_the_chained_cancel_as_one_before_the_deadline() public {
        _equalise();
        (bytes32 _bid, bytes32 _cid, bytes memory _cancelW, uint64 _dl) = _beginAndWrappedChainedCancel();
        vm.warp(block.timestamp + tl.getMinDelay());
        assertTrue(tl.isOperationReady(_bid) && tl.isOperationReady(_cid), "both Ready, the wrapper alive");
        assertLe(block.timestamp, uint256(_dl));
        vm.prank(stranger);
        pair.fire(tl, address(g), beginData, "begin", _cancelW, _bid, "chained-cancel");
        (address _who, ) = _pending();
        assertEq(_who, address(0), "begun and cancelled in one transaction: the gun is spent");
        assertTrue(tl.isOperationDone(_bid) && tl.isOperationDone(_cid), "both Done");
        vm.warp(block.timestamp + 2 days);
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlInvalidDefaultAdmin.selector, attacker)
        );
        g.acceptDefaultAdminTransfer();
        assertEq(g.defaultAdmin(), address(tl), "the timelock keeps the seat");
        _pairIsAtomic();
    }

    /// @dev Past the deadline the same pair reverts as a whole and the begin is NOT landed by the attempt.
    function _pairIsAtomic() internal {
        bytes32 _bid2 = _scheduleOn(tl, p2, p2Pk, address(g), beginData, NONE, "begin-2");
        uint64 _dl2 = _houseDeadline();
        bytes memory _cancelW2 = _wrap(_dl2, cancelBare);
        _scheduleOn(tl, p1, p1Pk, address(g), _cancelW2, _bid2, "chained-cancel-2");
        vm.warp(uint256(_dl2) + 1);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, _dl2));
        pair.fire(tl, address(g), beginData, "begin-2", _cancelW2, _bid2, "chained-cancel-2");
        assertTrue(tl.isOperationReady(_bid2), "the begin was not landed by the failed pair");
        (address _who, ) = _pending();
        assertEq(_who, address(0));
    }

    /*//////////////////////////////////////////////////////////////
       4. THE LADDER: A RE-BEGIN CHAINED BEHIND THE HONEST CANCEL
    //////////////////////////////////////////////////////////////*/

    /// @dev G16a-2. The attacker reads the queue too: it chains a second begin behind the HONEST cancel
    ///      (`predecessor` = the cancel's id). Firing the three in one block (begin, cancel, re-begin) leaves the
    ///      hand-over pending with no cancel behind it: a chained cancel protects only against the operation it
    ///      names. The honest answer is a cancel chained behind the LAST hostile operation, scheduled within the
    ///      admin delay of seeing it, and the eviction that ends the ladder (one round; the evicted proposer's
    ///      queue outlives it, so the last rung still needs its cancel).
    function test_4_a_re_begin_chained_behind_the_honest_cancel_re_arms_the_handover_until_the_last_rung_is_cancelled() public {
        bytes32 _bid = _scheduleOn(tl, p2, p2Pk, address(g), beginData, NONE, "begin");
        bytes32 _cid = _scheduleOn(tl, p1, p1Pk, address(g), cancelBare, _bid, "chained-cancel");
        bytes32 _bid2 = _scheduleOn(tl, p2, p2Pk, address(g), beginData, _cid, "begin-2"); // the rung appears
        uint256 _t0 = block.timestamp;
        uint256 _snap = vm.snapshotState();
        // B: the honest cancel behind the LAST rung, scheduled as the rung appeared, lands in the same block.
        _scheduleOn(tl, p1, p1Pk, address(g), cancelBare, _bid2, "chained-cancel-2");
        vm.warp(_t0 + MIN_DELAY);
        _fireLadder(_bid, _cid);
        _executeOn(tl, address(g), cancelBare, _bid2, "chained-cancel-2");
        (address _who, ) = _pending();
        assertEq(_who, address(0), "the cancel behind the last rung wins in the same block");
        // A: without it, the ladder re-arms the hand-over in the block the chained cancel landed.
        vm.revertToState(_snap);
        vm.warp(_t0 + MIN_DELAY);
        _fireLadder(_bid, _cid);
        uint48 _sched;
        (_who, _sched) = _pending();
        assertEq(_who, attacker, "re-armed in the same block the chained cancel landed");
        assertEq(uint256(_sched), block.timestamp + ADMIN_DELAY);
        _evictAndCancel(_sched);
    }

    function _fireLadder(bytes32 bid_, bytes32 cid_) internal {
        _executeOn(tl, address(g), beginData, NONE, "begin");
        _executeOn(tl, address(g), cancelBare, bid_, "chained-cancel");
        _executeOn(tl, address(g), beginData, cid_, "begin-2");
    }

    /// @dev The eviction (one round) and a fresh cancel scheduled at once, inside A - D at the defaults.
    function _evictAndCancel(uint48 sched_) internal {
        bytes memory _evict = abi.encodeCall(IAccessControl.revokeRole, (tl.PROPOSER_ROLE(), address(p2)));
        _scheduleOn(tl, p1, p1Pk, address(tl), _evict, NONE, "evict");
        bytes32 _cid3 = _scheduleOn(tl, p1, p1Pk, address(g), cancelBare, NONE, "fresh-cancel");
        vm.warp(block.timestamp + MIN_DELAY);
        _executeOn(tl, address(tl), _evict, NONE, "evict");
        assertFalse(tl.hasRole(tl.PROPOSER_ROLE(), address(p2)), "evicted in one round");
        assertTrue(tl.isOperationReady(_cid3));
        _expectAcceptTooEarly(sched_);
        _executeOn(tl, address(g), cancelBare, NONE, "fresh-cancel");
        (address _who, ) = _pending();
        assertEq(_who, address(0), "cancelled a day before the acceptance opened (A - D at the defaults)");
        bytes memory _again = abi.encodeCall(
            tl.schedule,
            (address(g), 0, beginData, NONE, bytes32("begin-3"), tl.getMinDelay())
        );
        vm.expectRevert(bytes("GS013"));
        _exec(p2, p2Pk, address(tl), 0, _again, Operation.Call);
        assertEq(g.defaultAdmin(), address(tl));
        assertEq(token.balanceOf(address(curatorSafe)), CUSTODY, "no custody moved");
    }

    /*//////////////////////////////////////////////////////////////
       6. THE OPEN EXECUTOR INTO AN OPERATION THAT NOW REVERTS (RAIL)
    //////////////////////////////////////////////////////////////*/

    /// @dev The brief's second item. The only way a scheduled operation meets the new `Unauthorized` is a
    ///      TARGET that is a Safe whose handler is this guard (the proposer's own choice): the timelock itself is
    ///      never read as forwarding, so a wrapped admin call to the guard lands. A hostile proposer's reverting
    ///      operation stays Ready for ever (only the veto clears it) and blocks nothing but what is chained
    ///      behind it: the honest sync's operation, scheduled next to it, executes; the sync task's queue print
    ///      and `--allow-pending` are the nuisance it costs.
    function test_6_an_operation_into_a_forwarding_safe_reverts_unauthorized_stays_ready_and_blocks_nothing_else() public {
        (ISafe _c, uint256 _cPk) = _newSafe("council-safe-fwd");
        _adminCall(abi.encodeCall(IAccessControl.grantRole, (g.COUNCIL_ROLE(), address(_c))), "council");
        _exec(_c, _cPk, address(_c), 0, abi.encodeWithSelector(0xf08a0323, address(g)), Operation.Call); // setFallbackHandler(guard)
        // The hostile proposer schedules a call INTO that Safe: it forwards to the guard with itself as caller.
        bytes memory _lock = _wrap(uint64(block.timestamp + 30 days), abi.encodeCall(g.lockdown, (address(curatorSafe))));
        bytes32 _hid = _scheduleOn(tl, p2, p2Pk, address(_c), _lock, NONE, "into-the-safe");
        // The honest proposer's own widening, wrapped, scheduled next to it (`--allow-pending`).
        bytes memory _widen = _wrap(
            uint64(block.timestamp + MIN_DELAY + 14 days),
            abi.encodeCall(g.allowFunction, (address(curatorSafe), address(protocol), MockProtocol.deposit.selector, false, _noRules()))
        );
        bytes32 _wid = _scheduleOn(tl, p1, p1Pk, address(g), _widen, NONE, "widen");
        vm.warp(block.timestamp + MIN_DELAY);
        vm.prank(stranger);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        tl.execute(address(_c), 0, _lock, NONE, "into-the-safe");
        assertTrue(tl.isOperationReady(_hid), "an always-reverting operation stays Ready");
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Enforced), "nothing ran");
        _executeOn(tl, address(g), _widen, NONE, "widen");
        assertTrue(tl.isOperationDone(_wid), "the honest operation next to it executes");
        (bool _allowed, , ) = g.functionPermission(address(curatorSafe), address(protocol), MockProtocol.deposit.selector);
        assertTrue(_allowed);
        // The same call from the council Safe as ITSELF is refused too (the rail reads the slot, G14b-4), and
        // served once it repairs its own handler: the refusal is the Safe's own doing, never a stranger's.
        vm.expectRevert(bytes("GS013"));
        _exec(_c, _cPk, address(g), 0, _lock, Operation.Call);
        _exec(_c, _cPk, address(_c), 0, abi.encodeWithSelector(0xf08a0323, address(0)), Operation.Call);
        assertTrue(_exec(_c, _cPk, address(g), 0, _lock, Operation.Call), "served after the repair");
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
    }

    /*//////////////////////////////////////////////////////////////
        7. A GUARDIAN KEY (THE ONE SINGLE-KEY INSIDER) CANNOT STALL A HAND-OVER
    //////////////////////////////////////////////////////////////*/

    /// @dev The brief's third item from the single-key insider's side: the hand-over predicate reads state the
    ///      council writes (G9c-1, held) and the admin writes; a deployment-wide guardian can only narrow, and no
    ///      narrowing of the pending admin's address (`lockdown`, `lockdownAndRevoke`, `revokeAllApprovals`, the
    ///      three `(safe, target, false)` setters, `revokeTarget`, a forbidden unwrapper hash) makes
    ///      `AdminIsGuarded` fire: the successor accepts. A lockdown of the pending admin's address only holds the
    ///      ADMIN's own `enforce` / `bypass` / `approveTransaction` for that address a day, which nobody needs.
    function test_7_a_deployment_wide_guardian_cannot_stall_a_handover_to_a_successor_timelock() public {
        CuratorGuardTimelock _tlB = _newTimelock(1 days);
        address _bot = makeAddr("guardian-bot");
        _adminCall(abi.encodeCall(g.setDeploymentGuardian, (_bot, true)), "bot");
        _adminCall(_wrap(uint64(block.timestamp + 30 days), abi.encodeCall(g.beginDefaultAdminTransfer, (address(_tlB)))), "begin");
        bytes memory _accept = abi.encodeCall(g.acceptDefaultAdminTransfer, ());
        bytes32 _aid = _scheduleOn(_tlB, p1, p1Pk, address(g), _accept, NONE, "accept");
        vm.startPrank(_bot);
        g.lockdown(address(_tlB));
        g.lockdownAndRevoke(address(_tlB));
        g.revokeAllApprovals(address(_tlB));
        g.setModuleAllowed(address(_tlB), address(protocol), false);
        g.setNativeTransferAllowed(address(_tlB), address(protocol), false);
        g.setMultiSendUnwrapper(address(_tlB), address(protocol), false);
        g.revokeTarget(address(_tlB), address(protocol));
        g.setUnwrapperCodehash(0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939, false); // v1.4.1 CallOnly
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.setGuardian(address(_tlB), stranger, true); // widening: not a guardian's
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.enforce(address(_tlB));
        vm.stopPrank();
        assertEq(g.lockedAt(address(_tlB)), uint64(block.timestamp), "the lockdown of the address is recorded");
        vm.warp(block.timestamp + ADMIN_DELAY + 1);
        assertTrue(_tlB.isOperationReady(_aid));
        _executeOn(_tlB, address(g), _accept, NONE, "accept");
        assertEq(g.defaultAdmin(), address(_tlB), "accepted: nothing a guardian writes is read by the predicate");
        assertFalse(g.isUnwrapperCodehash(0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939), "its one deployment-wide lever: batching off until re-allowed");
    }

    /*//////////////////////////////////////////////////////////////
         5. THE BARE CHAINED CANCEL (THE DOCS' SHAPE) IS NOT WAITED OUT
    //////////////////////////////////////////////////////////////*/

    /// @dev Control for G16a-1: the same wait against a BARE chained cancel changes nothing; the cancel lands in
    ///      the block the begin lands, at the floors, whenever the attacker lands it (G14g test 2 at five days).
    function test_5_control_a_bare_chained_cancel_survives_the_same_wait() public {
        _equalise();
        bytes32 _bid = _scheduleOn(tl, p2, p2Pk, address(g), beginData, NONE, "begin");
        _scheduleOn(tl, p1, p1Pk, address(g), cancelBare, _bid, "chained-cancel");
        vm.warp(block.timestamp + 60 days);
        _executeOn(tl, address(g), beginData, NONE, "begin");
        _executeOn(tl, address(g), cancelBare, _bid, "chained-cancel");
        (address _who, ) = _pending();
        assertEq(_who, address(0), "cancelled in the begin's block after a 60-day wait");
        assertEq(g.defaultAdmin(), address(tl));
    }
}
