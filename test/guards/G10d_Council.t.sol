// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardHarness} from "test/guards/CuratorGuardTestBase.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {G10dBase} from "test/guards/G10d_Base.sol";

/// @title G10d_Council: a compromised council key against the production topology
/// @notice Round 10, reviewer g10d. The council is an EOA whose key the attacker holds; the curator's
///         quorum is honest unless a test says otherwise. What it can take (nothing without the quorum),
///         what it can break (liveness, for as long as it holds the role), and what stops it.
contract G10d_CouncilTest is G10dBase {
    function setUp() public override {
        super.setUp();
        _configureCurator();
    }

    /// @dev Approvals, a 7-day window, every responder stripped: still no custody without the quorum. The
    ///      council must also choose between an approval and a window (a window voids approvals). With the
    ///      quorum colluding, the window is the drain: the documented "fully trusted for funds".
    function test_compromised_council_alone_moves_no_custody() public {
        uint256 _custody = _balance();
        bytes memory _drain = abi.encodeWithSelector(TRANSFER, stranger, _custody);
        vm.startPrank(council);
        bytes32 _id = g.approveTransaction(address(curatorSafe), address(0), address(token), 0, _drain, Operation.Call, 7 days);
        assertGt(g.approvalExpiry(_id), 0, "a venue call the council may approve: a drain");
        g.setGuardian(address(curatorSafe), guardian, false);
        g.setDeploymentGuardian(bot, false);
        g.bypass(address(curatorSafe), 7 days);
        vm.stopPrank();
        assertEq(g.approvalExpiry(_id), 0, "the window voided the council's own approval");
        assertEq(g.guardians(address(curatorSafe)).length, 0);
        assertFalse(g.hasRole(g.GUARDIAN_ROLE(), bot));

        // Neither the council's operator nor anyone else can execute a Safe transaction.
        _strangerCannotMoveCustody();
        vm.prank(council);
        (bool _ok, bytes memory _r) = address(curatorSafe).call(
            abi.encodeCall(ISafe.execTransaction, (address(token), 0, _drain, Operation.Call, 0, 0, 0, address(0), payable(address(0)), ""))
        );
        assertFalse(_ok);
        assertEq(_reason(_r), "GS020");
        assertEq(_balance(), _custody);

        // The honest curator keeps settling inside the window; nobody but the admin (after minDelay) can
        // close it now that the responders are gone.
        assertTrue(_settle());
        vm.prank(guardian);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.lockdown(address(curatorSafe));
        // With the quorum colluding the council window carries the drain (a venue call passes unchecked).
        assertTrue(_curatorExec(address(token), 0, _drain, Operation.Call));
        assertEq(token.balanceOf(stranger), _custody, "council + quorum: the documented trust");
    }

    /// @dev Section 7.6 step 2 (replace the guard) against a council that does not cooperate: it keeps a
    ///      window open or re-locks one second before every admin operation matures, so the admin's
    ///      approval of `setGuard(new)` is `SafeInBypass` / `LockdownCooldown` for as long as it holds the
    ///      role, and an eviction BUNDLED with the lift and the approval (the shape section 6 forbids) can
    ///      never execute: its own revoke is inside the reverted batch. Evicted as its OWN operation the
    ///      council is out at minDelay whatever it does, the new council restores settlement at once, and
    ///      the chained lift + approval lands one cooldown later: minDelay + 1 day after its last act.
    function test_hostile_council_stalls_the_guard_swap_only_until_evicted_then_one_cooldown() public {
        _prepareSwap();
        uint256 _t0 = block.timestamp;

        // t0: the hostile council opens a window; the admin schedules the naive approval and the bundled shape.
        vm.prank(council);
        g.bypass(address(curatorSafe), 7 days);
        _schedule(p1, p1Pk, address(g), approveSwap, NONE, "naive");
        _scheduleShape(BUNDLED, NONE, "bundled");

        // t0 + 1 day: the runbook's shape, the eviction on its own, the lift and the approval chained behind it.
        vm.warp(_t0 + 1 days);
        bytes32 _idB = _scheduleShape(EVICT, NONE, "evict");
        _scheduleShape(LIFT_SWAP, _idB, "lift+swap");

        // t0 + 2 days: the council's last act one second before the first operations mature.
        vm.warp(_t0 + MIN_DELAY - 1);
        vm.prank(council);
        g.lockdown(address(curatorSafe));
        vm.warp(_t0 + MIN_DELAY);
        vm.prank(stranger);
        vm.expectRevert(_cooldown());
        tl.execute(address(g), 0, approveSwap, NONE, "naive");
        _expectShapeCooldown(BUNDLED, NONE, "bundled");
        assertTrue(g.hasRole(g.COUNCIL_ROLE(), council), "the bundled eviction never happened");

        // t0 + 3 days: the council re-locks a second before the next maturity: the bundled shape is dead again,
        // for ever while the council holds the role. The eviction on its own lands.
        vm.warp(_t0 + MIN_DELAY + 1 days - 1);
        vm.prank(council);
        g.lockdown(address(curatorSafe));
        vm.warp(_t0 + MIN_DELAY + 1 days);
        _expectShapeCooldown(BUNDLED, NONE, "bundled");
        _executeShape(EVICT, NONE, "evict");
        assertFalse(g.hasRole(g.COUNCIL_ROLE(), council));
        assertTrue(g.hasRole(g.COUNCIL_ROLE(), council2));
        vm.prank(council);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.lockdown(address(curatorSafe));

        // The new council is not held back by the cooldown: settlement resumes at once. The admin's lift and
        // approval are: one cooldown after the old council's last lockdown.
        vm.prank(council2);
        g.enforce(address(curatorSafe));
        assertTrue(_settle());
        _expectShapeCooldown(LIFT_SWAP, _idB, "lift+swap");
        vm.warp(_t0 + MIN_DELAY + 2 days);
        _executeShape(LIFT_SWAP, _idB, "lift+swap");

        // The signers execute the swap: minDelay + one cooldown after the hostile council's last act.
        assertTrue(_curatorExec(address(curatorSafe), 0, swapData, Operation.Call));
        assertEq(_guardOf(curatorSafe), address(next));
    }

    uint8 internal constant BUNDLED = 0;
    uint8 internal constant EVICT = 1;
    uint8 internal constant LIFT_SWAP = 2;

    CuratorGuardHarness internal next;
    bytes internal swapData;
    bytes internal approveSwap;
    bytes internal evictCall;
    bytes internal liftCall;

    function _prepareSwap() internal {
        next = _newGuard(address(tl), council2);
        swapData = abi.encodeCall(ISafe.setGuard, (address(next)));
        approveSwap = abi.encodeCall(
            g.approveTransaction,
            (address(curatorSafe), address(0), address(curatorSafe), 0, swapData, Operation.Call, uint64(7 days))
        );
        evictCall = abi.encodeCall(g.revokeRole, (g.COUNCIL_ROLE(), council));
        liftCall = abi.encodeCall(g.enforce, (address(curatorSafe)));
    }

    function _shape(uint8 shape_) internal view returns (address[] memory _t, bytes[] memory _p) {
        if (shape_ == BUNDLED) {
            _t = _guardTargets(3);
            _p = new bytes[](3);
            _p[0] = evictCall;
            _p[1] = liftCall;
            _p[2] = approveSwap;
        } else if (shape_ == EVICT) {
            _t = _guardTargets(2);
            _p = new bytes[](2);
            _p[0] = evictCall;
            _p[1] = abi.encodeCall(g.grantRole, (g.COUNCIL_ROLE(), council2));
        } else {
            _t = _guardTargets(2);
            _p = new bytes[](2);
            _p[0] = liftCall;
            _p[1] = approveSwap;
        }
    }

    function _scheduleShape(uint8 shape_, bytes32 pred_, bytes32 salt_) internal returns (bytes32) {
        (address[] memory _t, bytes[] memory _p) = _shape(shape_);
        return _scheduleBatch(p1, p1Pk, _t, _p, pred_, salt_);
    }

    function _executeShape(uint8 shape_, bytes32 pred_, bytes32 salt_) internal {
        (address[] memory _t, bytes[] memory _p) = _shape(shape_);
        _executeBatch(_t, _p, pred_, salt_);
    }

    function _expectShapeCooldown(uint8 shape_, bytes32 pred_, bytes32 salt_) internal {
        (address[] memory _t, bytes[] memory _p) = _shape(shape_);
        vm.prank(stranger);
        vm.expectRevert(_cooldown());
        tl.executeBatch(_t, _values(_t.length), _p, pred_, salt_);
    }

    function _cooldown() internal view returns (bytes memory) {
        return abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(curatorSafe));
    }

    /// @dev What the council can never do, by approval, by window or directly: weaken the Safe (guard,
    ///      modules, a handler, a single-key threshold, a delegatecall), widen the policy, touch the roles,
    ///      or reach the timelock.
    function test_compromised_council_cannot_weaken_the_safe_widen_the_policy_or_reach_the_timelock() public {
        address _s = address(curatorSafe);
        bytes32 _role = g.COUNCIL_ROLE();
        vm.startPrank(council);
        _councilCannotApprove(_s, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call);
        _councilCannotApprove(_s, abi.encodeCall(ISafe.enableModule, (stranger)), Operation.Call);
        _councilCannotApprove(_s, abi.encodeWithSignature("setFallbackHandler(address)", stranger), Operation.Call);
        _councilCannotApprove(_s, abi.encodeCall(ISafe.addOwnerWithThreshold, (stranger, 1)), Operation.Call);
        _councilCannotApprove(address(protocol), "", Operation.DelegateCall);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.allowFunction(_s, address(token), TRANSFER, false, _noRules());
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.setRequiredFallbackHandler(_s, address(0), false);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.setMultiSendUnwrapper(_s, address(protocol), true);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, council, bytes32(0)));
        g.grantRole(_role, stranger);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, council, bytes32(0)));
        g.beginDefaultAdminTransfer(stranger);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, council, tl.PROPOSER_ROLE()));
        tl.schedule(address(g), 0, abi.encodeCall(g.enforce, (_s)), NONE, "x", MIN_DELAY);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, council, tl.CANCELLER_ROLE()));
        tl.cancel(bytes32(uint256(1)));
        vm.stopPrank();
    }

    function _councilCannotApprove(address to_, bytes memory data_, Operation op_) internal {
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, _selectorOf(data_), op_));
        g.approveTransaction(address(curatorSafe), address(0), to_, 0, data_, op_, 1 days);
    }
}
