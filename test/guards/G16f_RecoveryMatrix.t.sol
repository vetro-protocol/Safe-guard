// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {MultiSendCallOnly} from "safe-contracts-v1.4.1/contracts/libraries/MultiSendCallOnly.sol";
import {console} from "forge-std/console.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G16fBase} from "test/guards/G16f_Base.sol";

/// @title Round 16, reviewer g16f: LIVENESS AND RECOVERY AT THE FLOOR. Every recovery path's duration, measured in
///        chain time on g9c's production topology (real Safe v1.4.1 proxies behind every principal, a real
///        `CuratorGuardTimelock`) at the live timelock delay D (`G16F_MIN_DELAY`: 86400 = the floor, 172800 = the
///        deploy default), with C = `LOCKDOWN_COOLDOWN` = 1 day and A = the admin-transfer delay = 3 days. Each test
///        asserts the closed-form bound and prints a `G16F-ROW` line for the matrix.
contract G16f_RecoveryMatrixTest is G16fBase {
    uint256 internal constant C = 1 days;
    address internal rogue = makeAddr("rogue-guardian");
    address internal rogueGlobal = makeAddr("rogue-deployment-guardian");
    address internal newCouncil = makeAddr("new-council");
    address internal attacker = makeAddr("attacker");

    function _D() internal view returns (uint256) {
        return tl.getMinDelay();
    }

    function _modeIs(CuratorGuardPolicy.Mode m_) internal view {
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(m_), "mode");
    }

    function _cooldownErr() internal view returns (bytes memory) {
        return abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(curatorSafe));
    }

    function _lift() internal view returns (bytes memory) {
        return abi.encodeCall(g.enforce, (address(curatorSafe)));
    }

    function _setG(address who_, bool on_) internal view returns (bytes memory) {
        return abi.encodeCall(g.setGuardian, (address(curatorSafe), who_, on_));
    }

    function _lock(address who_) internal {
        vm.prank(who_);
        g.lockdown(address(curatorSafe));
    }

    function _noCouncil() internal {
        g = _newGuard(address(tl), address(0));
        _configureCurator();
    }

    /// @dev A hostile proposer (p2) lands one call at the live delay; the veto sleeps.
    function _hostile(address target_, bytes memory data_, bytes32 salt_) internal {
        _scheduleOn(tl, p2, p2Pk, target_, data_, NONE, salt_);
        vm.warp(block.timestamp + _D());
        _executeOn(tl, target_, data_, NONE, salt_);
    }

    function _row(string memory id_, uint256 seconds_) internal view {
        console.log("G16F-ROW D=%s | %s | %s s", _D(), id_, seconds_);
    }

    /*//////////////////////////////////////////////////////////////
                    M1-M4: LIFTS, LOOPS AND SWARMS
    //////////////////////////////////////////////////////////////*/

    /// @dev M1. One guardian lockdown, no council, the admin's lift scheduled in the lockdown's block: it lands
    ///      max(D, C + 1 s) after the lockdown (the cooldown's edge is inclusive: at the floor D == C, so the lift
    ///      is held in its own Ready second and lands one second later).
    function test_M1_admin_lift_after_one_lockdown_no_council() public {
        _noCouncil();
        _adminCall(_setG(rogue, true), "rogue");
        uint256 _L = block.timestamp;
        _lock(rogue);
        bytes32 _id = _schedule(p1, p1Pk, address(g), _lift(), NONE, "lift");
        vm.warp(_L + _D());
        assertTrue(tl.isOperationReady(_id), "Ready at L + D");
        if (_D() <= C) {
            vm.expectRevert(_cooldownErr());
            _execute(address(g), _lift(), NONE, "lift");
            vm.warp(_L + C + 1);
        }
        _execute(address(g), _lift(), NONE, "lift");
        _modeIs(CuratorGuardPolicy.Mode.Enforced);
        uint256 _dt = block.timestamp - _L;
        assertEq(_dt, _D() > C ? _D() : C + 1, "lift = max(D, C + 1 s)");
        _row("M1 admin lift after one lockdown, no council", _dt);
    }

    /// @dev M2. A per-Safe key that re-locks until the very second its removal lands (same block, ahead of it):
    ///      the removal as its own operation, the lift chained behind it (docs 6): D + C + 1 s from the first lockdown.
    function test_M2_relock_loop_no_council_removal_chained_ahead_of_the_lift() public {
        _noCouncil();
        _adminCall(_setG(rogue, true), "rogue");
        uint256 _T0 = block.timestamp;
        _lock(rogue);
        bytes32 _rid = _schedule(p1, p1Pk, address(g), _setG(rogue, false), NONE, "remove");
        bytes memory _w = _wrap(uint64(_T0 + _D() + C + 1 days), _lift());
        _schedule(p1, p1Pk, address(g), _w, _rid, "lift");
        vm.warp(_T0 + _D());
        _lock(rogue); // the last re-lock: the removal's own second, ahead of it in the block
        uint256 _last = block.timestamp;
        _execute(address(g), _setG(rogue, false), NONE, "remove"); // never held by the cooldown
        vm.prank(rogue);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.lockdown(address(curatorSafe));
        vm.expectRevert(_cooldownErr());
        _execute(address(g), _w, _rid, "lift");
        vm.warp(_last + C);
        vm.expectRevert(_cooldownErr()); // the inclusive edge
        _execute(address(g), _w, _rid, "lift");
        vm.warp(_last + C + 1);
        _execute(address(g), _w, _rid, "lift");
        assertTrue(_settle(), "settlement resumes");
        uint256 _dt = block.timestamp - _T0;
        assertEq(_dt, _D() + C + 1, "re-lock loop bound = D + C + 1 s");
        _row("M2 re-lock loop, no council, removal chained ahead of the lift", _dt);
    }

    /// @dev M3. A seated council removes the key and lifts in the lockdown's own block, at any delay.
    function test_M3_council_lift_is_immediate_whatever_the_delay() public {
        _configureCurator();
        _adminCall(_setG(rogue, true), "rogue");
        uint256 _L = block.timestamp;
        _lock(rogue);
        vm.startPrank(council);
        g.setGuardian(address(curatorSafe), rogue, false);
        g.enforce(address(curatorSafe));
        vm.stopPrank();
        assertTrue(_settle());
        _row("M3 council lift (same block)", block.timestamp - _L);
    }

    /// @dev M4. A hostile council's deployment-wide swarm (G13f-2), evicted by the admin with NO successor council
    ///      and one key missed to a dropped log: eviction + K-1 removals in one round (the lift chained behind), the
    ///      missed key re-locks at Ready and until its own removal lands: 2D + C + 1 s in all. (A single re-lock at
    ///      Ready alone, the G13f drill's shape, is max(2D, D + C + 1 s): at the floor one second more than the
    ///      drill's "minDelay + cooldown" warp, which is why that drill fails by one second at 86,400.)
    function test_M4_swarm_eviction_without_a_successor_council_one_key_missed() public {
        _configureCurator();
        uint256 _k = 8;
        address[] memory _keys = new address[](_k);
        vm.startPrank(council);
        for (uint256 i; i < _k; ++i) {
            _keys[i] = address(uint160(0xDEAD0000 + i));
            g.setDeploymentGuardian(_keys[i], true);
        }
        g.lockdown(address(curatorSafe));
        vm.stopPrank();
        uint256 _T0 = block.timestamp;
        bytes[] memory _d = new bytes[](_k);
        _d[0] = abi.encodeCall(IAccessControl.revokeRole, (g.COUNCIL_ROLE(), council));
        for (uint256 i; i + 1 < _k; ++i) _d[1 + i] = abi.encodeCall(g.setDeploymentGuardian, (_keys[i], false));
        address[] memory _t = _guardTargets(_k);
        bytes32 _bid = _scheduleBatch(p1, p1Pk, _t, _d, NONE, "evict");
        bytes memory _w = _wrap(uint64(_T0 + 2 * _D() + C + 2 days), _lift());
        _schedule(p1, p1Pk, address(g), _w, _bid, "lift");
        vm.warp(_T0 + _D());
        _lock(_keys[_k - 1]); // the missed key, at Ready, ahead of the batch
        _executeBatch(_t, _d, NONE, "evict");
        vm.expectRevert(_cooldownErr());
        _execute(address(g), _w, _bid, "lift");
        bytes memory _rm = abi.encodeCall(g.setDeploymentGuardian, (_keys[_k - 1], false));
        _schedule(p1, p1Pk, address(g), _rm, NONE, "rm-last"); // learned from its own lockdown
        vm.warp(block.timestamp + _D());
        _lock(_keys[_k - 1]); // re-locks until its removal lands
        uint256 _last = block.timestamp;
        _execute(address(g), _rm, NONE, "rm-last");
        vm.warp(_last + C);
        vm.expectRevert(_cooldownErr());
        _execute(address(g), _w, _bid, "lift");
        vm.warp(_last + C + 1);
        _execute(address(g), _w, _bid, "lift");
        assertTrue(_settle());
        uint256 _dt = block.timestamp - _T0;
        assertEq(_dt, 2 * _D() + C + 1, "swarm, one key missed, no council = 2D + C + 1 s");
        _row("M4 swarm eviction, no successor council, one key missed and re-locking", _dt);
    }

    /// @dev M4b. The same swarm with a successor council seated in the eviction batch: the missed key costs nothing
    ///      (G14g test 3); the whole recovery is one round D.
    function test_M4b_swarm_eviction_with_a_successor_council_is_one_round() public {
        _configureCurator();
        vm.startPrank(council);
        g.setDeploymentGuardian(rogueGlobal, true);
        g.lockdown(address(curatorSafe));
        vm.stopPrank();
        uint256 _T0 = block.timestamp;
        bytes[] memory _d = new bytes[](2);
        _d[0] = abi.encodeCall(IAccessControl.revokeRole, (g.COUNCIL_ROLE(), council));
        _d[1] = abi.encodeCall(IAccessControl.grantRole, (g.COUNCIL_ROLE(), newCouncil));
        _adminBatch(_d, "evict"); // the missed key is rogueGlobal: nobody removed it
        _lock(rogueGlobal); // re-locks at Ready
        vm.startPrank(newCouncil);
        g.setDeploymentGuardian(rogueGlobal, false);
        g.enforce(address(curatorSafe));
        vm.stopPrank();
        assertTrue(_settle());
        uint256 _dt = block.timestamp - _T0;
        assertEq(_dt, _D(), "one round");
        _row("M4b swarm eviction with a successor council seated in the batch", _dt);
    }

    /*//////////////////////////////////////////////////////////////
                    M5: THE FLOOD AND THE PROPOSER'S QUEUE
    //////////////////////////////////////////////////////////////*/

    /// @dev M5. A flooding proposer's ids are all Ready D after scheduling and never expire; the veto cancels a
    ///      Waiting and a Ready id alike; the proposer's eviction lands in the same round and clears nothing of its
    ///      queue (G10c-4): at the floor the veto's triage window per id is one day, at the default two.
    function test_M5_flood_matures_in_D_and_outlives_the_proposers_eviction() public {
        _configureCurator();
        uint256 _n = 32;
        bytes32[] memory _ids = new bytes32[](_n);
        bytes memory _junk = abi.encodeCall(g.enforce, (address(curatorSafe)));
        uint256 _T0 = block.timestamp;
        for (uint256 i; i < _n; ++i) _ids[i] = _schedule(p2, p2Pk, address(g), _junk, NONE, bytes32(i + 1));
        _cancel(_ids[0]); // Waiting: cancellable
        bytes memory _evict = abi.encodeCall(IAccessControl.revokeRole, (tl.PROPOSER_ROLE(), address(p2)));
        _schedule(p1, p1Pk, address(tl), _evict, NONE, "evict");
        vm.warp(_T0 + _D());
        for (uint256 i = 1; i < _n; ++i) assertTrue(tl.isOperationReady(_ids[i]), "Ready at T0 + D");
        _execute(address(tl), _evict, NONE, "evict");
        assertFalse(tl.hasRole(tl.PROPOSER_ROLE(), address(p2)), "evicted in the same round");
        assertTrue(tl.isOperationReady(_ids[2]), "its queue outlives it");
        _cancel(_ids[1]); // Ready: still cancellable
        assertFalse(tl.isOperationPending(_ids[1]));
        vm.warp(block.timestamp + 365 days);
        assertTrue(tl.isOperationReady(_ids[2]), "never expires");
        _row("M5 flood: every id Ready after (veto triage window per id)", _D());
    }

    /*//////////////////////////////////////////////////////////////
                    M6-M7: HAND-OVERS AND THE ADMIN DELAY
    //////////////////////////////////////////////////////////////*/

    /// @dev The honest hand-over to a fresh successor timelock at delay `succ_`: begin (D), then the acceptance,
    ///      schedulable on the successor the moment the begin lands, executable from max(D', A + 1 s) after it.
    function _handover(uint256 succ_) internal returns (uint256 _dt) {
        CuratorGuardTimelock _tlB = _newTimelock(succ_);
        uint256 _T0 = block.timestamp;
        _adminCall(abi.encodeCall(g.beginDefaultAdminTransfer, (address(_tlB))), "begin");
        uint256 _Tb = block.timestamp;
        (, uint48 _sched) = g.pendingDefaultAdmin();
        assertEq(uint256(_sched), _Tb + ADMIN_DELAY, "schedule = T_b + A");
        bytes memory _acc = abi.encodeCall(g.acceptDefaultAdminTransfer, ());
        _scheduleOn(_tlB, p1, p1Pk, address(g), _acc, NONE, "acc");
        uint256 _at = _Tb + (succ_ > ADMIN_DELAY + 1 ? succ_ : ADMIN_DELAY + 1);
        vm.warp(_at - 1);
        vm.expectRevert();
        _executeOn(_tlB, address(g), _acc, NONE, "acc");
        vm.warp(_at);
        _executeOn(_tlB, address(g), _acc, NONE, "acc");
        assertEq(g.defaultAdmin(), address(_tlB), "accepted");
        assertLe(block.timestamp, uint256(_sched) + 30 days, "inside the acceptance window");
        _dt = block.timestamp - _T0;
    }

    function test_M6a_handover_to_a_successor_at_the_floor() public {
        _configureCurator();
        uint256 _dt = _handover(1 days);
        assertEq(_dt, _D() + ADMIN_DELAY + 1, "D + A + 1 s");
        _row("M6a hand-over, successor timelock at 1 d", _dt);
    }

    function test_M6b_handover_to_a_successor_at_the_cap() public {
        _configureCurator();
        uint256 _dt = _handover(30 days);
        assertEq(_dt, _D() + 30 days, "D + D' (the successor's own delay dominates)");
        _row("M6b hand-over, successor timelock at 30 d", _dt);
    }

    /// @dev M7. A hostile proposer with the veto asleep lowers the ADMIN delay alone (one operation; the timelock
    ///      delay untouched; the round-14 drill moved both knobs). (b) The unchained honest rollback, scheduled in
    ///      the block the change landed, undoes it only while now <= effect time = T1 + (A - 1 d): at the 48 h
    ///      default that is the Ready second alone (A - 1 d == D), at the floor a day. (a) Once the one-day admin
    ///      delay is live, the unchained cancel of a hostile begin is Ready at T_b + D while the acceptance opens at
    ///      T_b + 1 d + 1 s: at the default the attacker wins by 86,399 s with no race at all; at the floor the two
    ///      meet at one second (G14g-2). The cancel CHAINED behind the begin (docs 7.5) wins in both cases
    ///      (`G14g_HeldChain2` test 2, re-run here at both delays).
    function test_M7_one_knob_lowering_the_admin_delay_alone() public {
        _configureCurator();
        _hostile(address(g), abi.encodeCall(g.changeDefaultAdminDelay, (uint48(1 days))), "adm");
        uint256 _T1 = block.timestamp;
        (, uint48 _effect) = g.pendingDefaultAdminDelay();
        assertEq(uint256(_effect), _T1 + (ADMIN_DELAY - 1 days), "effect = T1 + (A - 1 d)");
        bytes memory _rb = abi.encodeCall(g.rollbackDefaultAdminDelay, ());
        bytes32 _rbid = _schedule(p1, p1Pk, address(g), _rb, NONE, "rb");
        uint256 _snap = vm.snapshotState();
        vm.warp(_T1 + _D());
        assertTrue(tl.isOperationReady(_rbid));
        _execute(address(g), _rb, NONE, "rb");
        vm.warp(uint256(_effect) + 1);
        if (_T1 + _D() <= _effect) {
            assertEq(g.defaultAdminDelay(), ADMIN_DELAY, "rolled back in time: the delay stays 3 d");
            _row("M7b unchained rollback window of a hostile changeDefaultAdminDelay(1 d), inclusive", _effect - (_T1 + _D()) + 1);
        } else {
            assertEq(g.defaultAdminDelay(), 1 days, "the rollback landed after the effect: a no-op");
            _row("M7b unchained rollback window of a hostile changeDefaultAdminDelay(1 d)", 0);
        }
        vm.revertToState(_snap);
        vm.warp(uint256(_effect) + 1);
        assertEq(g.defaultAdminDelay(), 1 days, "the one-day admin delay is live");
        _hostile(address(g), abi.encodeCall(g.beginDefaultAdminTransfer, (attacker)), "begin");
        uint256 _Tb = block.timestamp;
        (, uint48 _sched) = g.pendingDefaultAdmin();
        assertEq(uint256(_sched), _Tb + 1 days);
        bytes32 _cid = _schedule(p1, p1Pk, address(g), abi.encodeCall(g.cancelDefaultAdminTransfer, ()), NONE, "cancel");
        vm.warp(_Tb + 1 days + 1); // the acceptance opens
        bool _cancelReady = tl.isOperationReady(_cid);
        vm.prank(attacker);
        g.acceptDefaultAdminTransfer();
        assertEq(g.defaultAdmin(), attacker, "the seat is taken");
        if (_D() > 1 days) {
            assertFalse(_cancelReady, "at the default the unchained cancel is not even Ready: no race");
            _row("M7a acceptance opens this long BEFORE the unchained cancel is Ready", _D() - 1 days - 1);
        } else {
            assertTrue(_cancelReady, "at the floor: the one-second edge, lost to block order here");
            _row("M7a acceptance opens this long BEFORE the unchained cancel is Ready (edge)", 0);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    M8-M11: NARROWINGS THAT ARE NOT LOCKDOWNS
    //////////////////////////////////////////////////////////////*/

    /// @dev M8. A rogue per-Safe guardian revoking the policy's one function on every round: the re-allow is an
    ///      admin widening, held by no cooldown, chained behind the key's removal: one round D, no extra second.
    function test_M8_narrowing_loop_by_a_rogue_guardian_costs_one_round() public {
        _noCouncil();
        _adminCall(_setG(rogue, true), "rogue");
        uint256 _T0 = block.timestamp;
        vm.prank(rogue);
        g.revokeFunction(address(curatorSafe), address(protocol), MockProtocol.settleDeposit.selector);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.settleDeposit.selector));
        _settle();
        bytes32 _rid = _schedule(p1, p1Pk, address(g), _setG(rogue, false), NONE, "rm");
        bytes memory _allow = abi.encodeCall(g.allowFunction, (address(curatorSafe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules()));
        _schedule(p1, p1Pk, address(g), _allow, _rid, "allow");
        vm.warp(_T0 + _D());
        vm.prank(rogue);
        g.revokeFunction(address(curatorSafe), address(protocol), MockProtocol.settleDeposit.selector); // the last revoke, ahead
        _execute(address(g), _setG(rogue, false), NONE, "rm");
        _execute(address(g), _allow, _rid, "allow");
        assertTrue(_settle());
        uint256 _dt = block.timestamp - _T0;
        assertEq(_dt, _D(), "one round, no cooldown");
        _row("M8 re-allow after a guardian's revoke loop (removal chained ahead)", _dt);
    }

    /// @dev M9. A rogue DEPLOYMENT-wide guardian forbids a canonical unwrapper hash (every Safe's batching off):
    ///      a seated council re-allows at once; without one the admin re-allows in D behind the key's removal.
    function test_M9_global_unwrapper_ban_by_a_rogue_deployment_guardian() public {
        _noCouncil();
        MultiSendCallOnly _ms = new MultiSendCallOnly();
        bytes32 _h = address(_ms).codehash;
        g.seedCodehash(_h); // a canonical build, as the real guard seeds the three deployments
        _adminCall(abi.encodeCall(g.setMultiSendUnwrapper, (address(curatorSafe), address(_ms), true)), "ms");
        _adminCall(abi.encodeCall(g.setDeploymentGuardian, (rogueGlobal, true)), "rg");
        bytes memory _inner = abi.encodeCall(MockProtocol.settleDeposit, (1));
        bytes memory _batch = abi.encodeWithSelector(MultiSendCallOnly.multiSend.selector, abi.encodePacked(uint8(0), address(protocol), uint256(0), _inner.length, _inner));
        assertTrue(_exec(curatorSafe, curatorPk, address(_ms), 0, _batch, Operation.DelegateCall), "batching works");
        uint256 _T0 = block.timestamp;
        vm.prank(rogueGlobal);
        g.setUnwrapperCodehash(_h, false);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.UnwrapperCodehashNotAllowed.selector, _h));
        _exec(curatorSafe, curatorPk, address(_ms), 0, _batch, Operation.DelegateCall);
        assertTrue(_settle(), "plain calls still pass: a narrowing, never a freeze");
        bytes32 _rid = _schedule(p1, p1Pk, address(g), abi.encodeCall(g.setDeploymentGuardian, (rogueGlobal, false)), NONE, "rm");
        bytes memory _re = abi.encodeCall(g.setUnwrapperCodehash, (_h, true));
        _schedule(p1, p1Pk, address(g), _re, _rid, "re");
        vm.warp(_T0 + _D());
        _execute(address(g), abi.encodeCall(g.setDeploymentGuardian, (rogueGlobal, false)), NONE, "rm");
        _execute(address(g), _re, _rid, "re");
        assertTrue(_exec(curatorSafe, curatorPk, address(_ms), 0, _batch, Operation.DelegateCall), "batching back");
        _row("M9 global unwrapper ban undone by the admin (no council)", block.timestamp - _T0);
    }

    /// @dev M10. The admin's 180-day window (the valve while a replacement guard is prepared) is ended by one
    ///      guardian key's lockdown at once, and the admin's re-open is a lift: D + C + 1 s behind the key's removal.
    function test_M10_a_guardian_lockdown_ends_an_admin_window_and_the_reopen_is_held() public {
        _noCouncil();
        _adminCall(_setG(rogue, true), "rogue");
        _adminCall(_wrap(uint64(block.timestamp + 15 days), abi.encodeCall(g.bypass, (address(curatorSafe), uint64(180 days)))), "win");
        _modeIs(CuratorGuardPolicy.Mode.Bypass);
        uint256 _L = block.timestamp;
        _lock(rogue);
        _modeIs(CuratorGuardPolicy.Mode.Lockdown);
        bytes32 _rid = _schedule(p1, p1Pk, address(g), _setG(rogue, false), NONE, "rm");
        bytes memory _w = _wrap(uint64(_L + 15 days), abi.encodeCall(g.bypass, (address(curatorSafe), uint64(180 days))));
        _schedule(p1, p1Pk, address(g), _w, _rid, "win2");
        vm.warp(_L + _D());
        _lock(rogue);
        uint256 _last = block.timestamp;
        _execute(address(g), _setG(rogue, false), NONE, "rm");
        vm.expectRevert(_cooldownErr());
        _execute(address(g), _w, _rid, "win2");
        vm.warp(_last + C + 1);
        _execute(address(g), _w, _rid, "win2");
        _modeIs(CuratorGuardPolicy.Mode.Bypass);
        uint256 _dt = block.timestamp - _L;
        assertEq(_dt, _D() + C + 1);
        _row("M10 admin window re-opened after a guardian's lockdown (no council)", _dt);
    }

    /// @dev M11. A council window voids the admin's standing approvals (epoch bump); the re-issue is a timelock
    ///      round and is refused while any window is open (`SafeInBypass`): with an honest council that closes
    ///      the window it is D; with a hostile council renewing 7-day windows it is the eviction round first.
    function test_M11_standing_approvals_voided_by_a_council_window_cost_one_round_to_reissue() public {
        _configureCurator();
        bytes memory _pause = abi.encodeCall(MockProtocol.wrap, ());
        bytes memory _approve = abi.encodeCall(g.approveTransaction, (address(curatorSafe), address(0), address(protocol), 0, _pause, Operation.Call, uint64(180 days)));
        _adminCall(_approve, "approve");
        bytes32 _aid = g.computeApprovalId(address(curatorSafe), address(0), address(protocol), 0, _pause, Operation.Call);
        assertGt(g.approvalExpiry(_aid), 0, "standing approval live");
        uint256 _T0 = block.timestamp;
        vm.prank(council);
        g.bypass(address(curatorSafe), 1 hours);
        assertEq(g.approvalExpiry(_aid), 0, "voided by the window's epoch bump");
        _schedule(p1, p1Pk, address(g), _approve, NONE, "re-approve");
        vm.warp(_T0 + 30 minutes);
        // (a hostile council keeps the window open: the re-issue is refused while it is)
        vm.prank(council);
        g.bypass(address(curatorSafe), 7 days);
        vm.warp(_T0 + _D());
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.SafeInBypass.selector, address(curatorSafe)));
        _execute(address(g), _approve, NONE, "re-approve");
        // an honest council closes it: the operation stays Ready and lands
        vm.prank(council);
        g.enforce(address(curatorSafe));
        _execute(address(g), _approve, NONE, "re-approve");
        assertGt(g.approvalExpiry(g.computeApprovalId(address(curatorSafe), address(0), address(protocol), 0, _pause, Operation.Call)), 0, "re-issued");
        _row("M11 standing approval re-issued after a council window (council closes it)", block.timestamp - _T0);
    }

    /*//////////////////////////////////////////////////////////////
                    M12: THE MINIMAL BRICK SET
    //////////////////////////////////////////////////////////////*/

    /// @dev M12. A hostile (or lost) veto plus ONE locker key is a permanent freeze without a council: every lift is
    ///      an admin operation the veto cancels; the approval exit is an admin operation too. With a council seated
    ///      the same two keys freeze nothing: the council lifts and removes the locker in one block, and the veto
    ///      has no say on the fast lane.
    function test_M12a_veto_plus_one_locker_is_permanent_without_a_council() public {
        _noCouncil();
        _adminCall(_setG(rogue, true), "rogue");
        _lock(rogue);
        _cancel(_schedule(p1, p1Pk, address(g), _lift(), NONE, "lift")); // the hostile (or lost) veto
        _cancel(_schedule(p1, p1Pk, address(g), _setG(rogue, false), NONE, "rm"));
        bytes memory _ap = abi.encodeCall(g.approveTransaction, (address(curatorSafe), address(0), address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call, uint64(3 days)));
        _cancel(_schedule(p1, p1Pk, address(g), _ap, NONE, "ap"));
        vm.warp(block.timestamp + 365 days);
        _modeIs(CuratorGuardPolicy.Mode.Lockdown);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(curatorSafe)));
        _settle();
        _row("M12a veto + one locker, no council: still frozen after a year (permanent)", 365 days);
    }

    /// @dev The same two keys against a seated council: the council lifts and removes the locker in one block, and
    ///      the veto has no say on the fast lane.
    function test_M12b_veto_plus_one_locker_freezes_nothing_against_a_seated_council() public {
        _configureCurator();
        _adminCall(_setG(rogue, true), "rogue");
        uint256 _L = block.timestamp;
        _lock(rogue);
        _cancel(_schedule(p1, p1Pk, address(g), _lift(), NONE, "lift"));
        vm.startPrank(council);
        g.setGuardian(address(curatorSafe), rogue, false);
        g.enforce(address(curatorSafe));
        vm.stopPrank();
        assertTrue(_settle());
        _row("M12b veto + one locker against a seated council", block.timestamp - _L);
    }
}
