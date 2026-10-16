// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {G9cBase} from "test/guards/G9c_Base.sol";
import {TestERC20} from "test/mocks/TestERC20.sol";

/// @title Round 13, reviewer g13g (the reviewer's adversary): every HELD item treated as live and chained.
/// @dev   The production topology of `G9cBase` (real Safe v1.4.1 proxies behind the curator, two proposers
///        and the veto; a real `CuratorGuardTimelock` at 2 days; an EOA council). The attacker holds one
///        proposer Safe (p2), the veto is asleep, and the chain is: the delay lowered to the floor (a day
///        since the round-13 follow-up; the hour it would have preferred is refused at proposal),
///        a hostile council granted at that delay, the self-seat (G10a-2: a hand-over to the guard itself),
///        the stall (G9c-1: a plant and a window on the honest successor), the forged reports (G9a-1 through a
///        forwarded `executeBefore`, and G10a-1 through a direct post-hook on an uninstalled guard), and the
///        unrailed acceptance (G9c-3). Without curator keys the chain moves no custody and the honest side
///        recovers in one round at the SAME lowered delay. With curator keys the cheapest path to custody is
///        the documented one and needs none of the held items: a council window plus the quorum.
contract G13g_HeldChainTest is G9cBase {
    bytes32 internal constant TX_CHECKED = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");
    bytes32 internal constant FORGED = keccak256("no Safe transaction ever carried this hash");

    TestERC20 internal token;
    address internal attacker = makeAddr("attacker");
    address internal hostileCouncil = makeAddr("hostile-council");
    address internal newCouncil = makeAddr("new-council");
    address internal plant = makeAddr("planted-guardian");
    uint256 internal constant CUSTODY = 1_000_000e6;

    function setUp() public override {
        super.setUp();
        _configureCurator();
        token = new TestERC20("USD Coin", "USDC");
        token.mint(address(curatorSafe), CUSTODY);
    }

    function _reportsNaming(Vm.Log[] memory logs_, address safe_) internal view returns (uint256 _n) {
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter != address(g) || logs_[i].topics[0] != TX_CHECKED) continue;
            if (logs_[i].topics[1] == bytes32(uint256(uint160(safe_)))) ++_n;
        }
    }

    /// @dev Step 1 of the chain: an hour is refused when proposed (MIN_DELAY_FLOOR = 1 days, applied after
    ///      round 13), so the hostile proposer lowers the delay to the floor itself, a day.
    function _lowerToTheFloor() internal {
        uint256 _live = tl.getMinDelay();
        bytes memory _hour = abi.encodeCall(
            tl.schedule,
            (address(tl), 0, abi.encodeCall(tl.updateDelay, (1 hours)), NONE, bytes32("hour"), _live)
        );
        vm.expectRevert(bytes("GS013"));
        _exec(p2, p2Pk, address(tl), 0, _hour, Operation.Call);
        _hostile(address(tl), abi.encodeCall(tl.updateDelay, (1 days)), "floor");
        assertEq(tl.getMinDelay(), 1 days, "every later operation is a one-day race, never less");
    }

    /// @dev G9a-1 (applied after round 13): a forwarded `executeBefore` on a Safe whose handler is the guard
    ///      is refused before it re-dispatches anything.
    function _forwardedExecuteBeforeIsRefused(address safe_) internal {
        vm.prank(attacker);
        (bool _ok, bytes memory _ret) = safe_.call(
            _wrap(uint64(block.timestamp + 1 hours), abi.encodeCall(g.checkAfterExecution, (FORGED, true)))
        );
        assertFalse(_ok, "G9a-1 (applied after round 13): the forwarded executeBefore is refused");
        assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector);
    }

    /// @dev A hostile proposer schedules one call at the LIVE minimum delay and the sleeping veto lets it land.
    function _hostile(address target_, bytes memory data_, bytes32 salt_) internal {
        _scheduleOn(tl, p2, p2Pk, target_, data_, NONE, salt_);
        vm.warp(block.timestamp + tl.getMinDelay());
        _executeOn(tl, target_, data_, NONE, salt_);
    }

    /// @dev The honest proposer schedules one batch at the live delay; anyone executes it. Returns the
    ///      chain time the round took.
    function _honestBatch(bytes[] memory payloads_, bytes32 salt_) internal returns (uint256) {
        uint256 _t0 = block.timestamp;
        _exec(p1, p1Pk, address(tl), 0, _scheduleBatchCall(payloads_, salt_), Operation.Call);
        vm.warp(block.timestamp + tl.getMinDelay());
        _executeBatch(_guardTargets(payloads_.length), payloads_, NONE, salt_);
        return block.timestamp - _t0;
    }

    /// @dev `scheduleBatch` calldata for guard-targeted payloads at the live minimum delay (kept apart from
    ///      `_honestBatch` so the legacy codegen stays within the stack limit).
    function _scheduleBatchCall(bytes[] memory payloads_, bytes32 salt_) internal view returns (bytes memory) {
        uint256[] memory _v = new uint256[](payloads_.length);
        return abi.encodeCall(tl.scheduleBatch, (_guardTargets(payloads_.length), _v, payloads_, NONE, salt_, tl.getMinDelay()));
    }

    function test_the_chain_of_held_items_moves_no_custody_and_is_undone_in_one_round_at_the_lowered_delay() public {
        bytes32 _councilRole = g.COUNCIL_ROLE();

        // 1. The floor: the hostile proposer would lower the delay to an hour, which the timelock refuses when
        //    proposed (MIN_DELAY_FLOOR = 1 days, applied after round 13); it lowers it to the floor, a day, and
        //    the veto sleeps through the two-day delay of that operation.
        _lowerToTheFloor();

        // 2. A hostile council seat, one day later.
        _hostile(address(g), abi.encodeCall(IAccessControl.grantRole, (_councilRole, hostileCouncil)), "council");
        assertTrue(g.hasRole(_councilRole, hostileCouncil));

        // 3. The self-seat (G10a-2): a hand-over to the guard itself is accepted and nobody can ever accept it.
        _hostile(address(g), abi.encodeCall(g.beginDefaultAdminTransfer, (address(g))), "self-seat");
        (address _pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, address(g), "the guard is its own pending admin");

        // 4. The hostile council opens its 7-day window on the curator Safe: the honest curator keeps settling
        //    (reported as Bypass); nothing a stranger does moves the Safe (every Safe transaction needs the quorum).
        uint256 _windowOpened = block.timestamp;
        vm.prank(hostileCouncil);
        g.bypass(address(curatorSafe), 7 days);
        assertTrue(_settle(), "honest settlement passes inside the hostile window");
        // Even a colluding quorum cannot turn the window into a handler swap or a guard removal (council limits).
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, bytes4(0xf08a0323)));
        _exec(curatorSafe, curatorPk, address(curatorSafe), 0, abi.encodeWithSignature("setFallbackHandler(address)", address(g)), Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, ISafe.setGuard.selector));
        _exec(curatorSafe, curatorPk, address(curatorSafe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call);

        // 5. The forged reports (G9a-1, G10a-1) need a Safe whose handler is the guard or a window on an
        //    uninstalled guard: the attacker can only ever produce them for a Safe it owns, never the curator's.
        (ISafe _sAtt, uint256 _pkAtt) = _newSafe("attacker-safe");
        _exec(_sAtt, _pkAtt, address(_sAtt), 0, abi.encodeWithSignature("setFallbackHandler(address)", address(g)), Operation.Call);
        vm.prank(hostileCouncil);
        g.bypass(address(_sAtt), 7 days); // a window on the attacker's own Safe
        vm.recordLogs();
        _forwardedExecuteBeforeIsRefused(address(_sAtt));
        assertTrue(_exec(_sAtt, _pkAtt, address(g), 0, abi.encodeCall(g.checkAfterExecution, (FORGED, true)), Operation.Call), "G10a-1: the direct post-hook on an uninstalled guard reports too");
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_reportsNaming(_logs, address(_sAtt)), 1, "one forged report left (G10a-1, held), naming the attacker's own Safe");
        assertEq(_reportsNaming(_logs, address(curatorSafe)), 0, "none can name the curator Safe");
        // The curator Safe's own forwarding does nothing: it has no handler (the state the policy requires).
        vm.recordLogs();
        vm.prank(attacker);
        (bool _ok, ) = address(curatorSafe).call(_wrap(uint64(block.timestamp + 1 hours), abi.encodeCall(g.checkAfterExecution, (FORGED, true))));
        _ok; // a call into a Safe without a handler simply returns
        assertEq(_reportsNaming(vm.getRecordedLogs(), address(curatorSafe)), 0, "no handler, no forwarding, no report");

        // 6. The stall (G9c-1) on the honest succession: the honest proposer first has to clear the self-seat,
        //    then begins the hand-over to a fresh timelock; the hostile council plants on the successor.
        // The successor runs at the floor too (a one-day timelock), so every step below is one round of one day.
        CuratorGuardTimelock _tl2 = _newTimelock(1 days);
        bytes[] memory _begin = new bytes[](2);
        _begin[0] = abi.encodeCall(g.cancelDefaultAdminTransfer, ());
        _begin[1] = abi.encodeCall(g.beginDefaultAdminTransfer, (address(_tl2)));
        _honestBatch(_begin, "begin");
        (, uint48 _sched) = g.pendingDefaultAdmin();
        vm.startPrank(hostileCouncil);
        g.setGuardian(address(_tl2), plant, true);
        g.bypass(address(_tl2), 7 days);
        vm.stopPrank();
        bytes memory _accept = abi.encodeCall(g.acceptDefaultAdminTransfer, ());
        _scheduleOn(_tl2, p1, p1Pk, address(g), _accept, NONE, "accept");
        vm.warp(block.timestamp + 1 days);
        // The hand-over predicate runs before OpenZeppelin's delay check: the stall shows at once.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, address(_tl2)));
        _executeOn(_tl2, address(g), _accept, NONE, "accept");
        // G9c-3 (applied after round 13): the acceptance refuses a forwarded caller; here the successor is a
        // timelock, which forwards nothing anyway, and a stranger calling it directly is OpenZeppelin's refusal.
        vm.prank(attacker);
        vm.expectRevert();
        g.acceptDefaultAdminTransfer();

        // 7. The honest recovery, ONE batch at the lowered delay: evict the hostile council, seat a new one,
        //    clear the plant and the windows, void every approval of the curator Safe.
        bytes[] memory _evict = new bytes[](6);
        _evict[0] = abi.encodeCall(IAccessControl.revokeRole, (_councilRole, hostileCouncil));
        _evict[1] = abi.encodeCall(IAccessControl.grantRole, (_councilRole, newCouncil));
        _evict[2] = abi.encodeCall(g.setGuardian, (address(_tl2), plant, false));
        _evict[3] = abi.encodeCall(g.lockdown, (address(_tl2)));
        _evict[4] = abi.encodeCall(g.lockdownAndRevoke, (address(curatorSafe)));
        _evict[5] = abi.encodeCall(g.lockdown, (address(_sAtt)));
        uint256 _elapsed = _honestBatch(_evict, "evict");
        assertEq(_elapsed, 1 days, "the lowered floor cuts both ways: the eviction lands in one day");
        assertFalse(g.hasRole(_councilRole, hostileCouncil));
        // The new council is never held back by the cooldown: settlement resumes at once under the policy.
        vm.prank(newCouncil);
        g.enforce(address(curatorSafe));
        assertTrue(_settle(), "policy settlement resumes");
        // The hostile window on the curator Safe lived three honest rounds at the floor: three days.
        assertEq(block.timestamp - _windowOpened, 3 days, "the hostile window was closed in three one-day rounds");
        // The hand-over completes once the admin delay has passed, inside its 30-day window.
        if (block.timestamp < uint256(_sched) + 1) vm.warp(uint256(_sched) + 1);
        _executeOn(_tl2, address(g), _accept, NONE, "accept");
        assertEq(g.defaultAdmin(), address(_tl2));

        // 8. Custody: untouched by the whole chain.
        assertEq(token.balanceOf(address(curatorSafe)), CUSTODY, "no custody moved without curator keys");
        assertEq(token.balanceOf(attacker), 0);
    }

    /// @dev The cheapest path to custody needs none of the held items: two key sets the design trusts.
    function test_the_cheapest_path_to_custody_is_a_council_window_plus_the_curator_quorum_in_one_block() public {
        bytes memory _drain = abi.encodeCall(token.transfer, (attacker, CUSTODY));
        // Under the policy the transfer is refused: the quorum alone takes nothing from the Safe.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(token), token.transfer.selector));
        _exec(curatorSafe, curatorPk, address(token), 0, _drain, Operation.Call);
        // With the council's keys: a one-hour window, no timelock, no veto, one block.
        vm.prank(council);
        g.bypass(address(curatorSafe), 1 hours);
        assertTrue(_exec(curatorSafe, curatorPk, address(token), 0, _drain, Operation.Call), "the documented trust: the council is fully trusted for funds");
        assertEq(token.balanceOf(attacker), CUSTODY);
        assertEq(token.balanceOf(address(curatorSafe)), 0);
    }
}
