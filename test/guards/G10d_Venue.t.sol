// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IAccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/IAccessControlDefaultAdminRules.sol";
import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G10dSigner, HostileVenue, SimDriver} from "test/guards/G10d_Base.sol";

/// @title G10d_Venue: an allowlisted venue turns hostile during the curator's transaction
/// @notice Round 10, reviewer g10d. Real Safe v1.4.1 (1-of-1 signer models the quorum), the guard
///         Enforced, `venue.poke(uint256)` allowlisted. Every test is one thing the venue tries while
///         the Safe's call into it is in flight: re-entering the Safe with a leaked signed transaction,
///         forging the guard's hooks, running the hooks inside `simulateAndRevert` as the Safe, using the
///         guard's role surface, reconfiguring the Safe, and taking its allowance (the one thing it can).
contract G10d_VenueTest is CuratorGuardTestBase, G10dSigner {
    bytes4 internal constant APPROVE = 0x095ea7b3;
    bytes4 internal constant TRANSFER = 0xa9059cbb;
    bytes4 internal constant TRANSFER_FROM = 0x23b872dd;

    HostileVenue internal venue;
    SimDriver internal driver;

    function setUp() public override {
        super.setUp();
        _enforce();
        venue = new HostileVenue();
        driver = new SimDriver();
        vm.deal(address(venue), 1 ether);
        _allow(address(venue), HostileVenue.poke.selector);
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
    }

    function _poke() internal returns (bool) {
        return _execSafeTx(address(venue), 0, abi.encodeCall(HostileVenue.poke, (1)), Operation.Call);
    }

    function _settle(uint256 n_) internal pure returns (bytes memory) {
        return abi.encodeCall(MockProtocol.settleDeposit, (n_));
    }

    /*//////////////////////////////////////////////////////////////
                  REENTRANCY INTO THE SAFE (SIGNED TRANSACTIONS)
    //////////////////////////////////////////////////////////////*/

    /// @dev A transaction the signers signed for the NEXT nonce sits in the Transaction Service, so a
    ///      hostile venue can hold it. Nested inside the venue call it is refused (`NestedExecution`), the
    ///      venue swallows the revert, the outer transaction completes and is reported exactly once. The
    ///      leaked signature stays valid afterwards, for anyone (the documented lift-time card).
    function test_venue_nesting_a_leaked_signed_transaction_is_refused_and_the_outer_reports_once() public {
        uint256 _nonce = _nonceOf(safe);
        bytes memory _leaked = _signedExecCalldata(safe, signerPk, _nonce + 1, address(protocol), 0, _settle(7), Operation.Call);
        venue.queueCall(address(safe), 0, _leaked);

        vm.recordLogs();
        assertTrue(_poke());
        (uint256 _n, uint8 _outcome, ) = _reports(vm.getRecordedLogs(), address(guard));
        assertEq(_n, 1, "one report");
        assertEq(_outcome, uint8(CuratorGuard.Outcome.Policy));
        assertFalse(venue.ok(0));
        assertEq(venue.selectorOf(0), CuratorGuard.NestedExecution.selector);
        assertEq(protocol.calls(), 0, "the leaked transaction never executed");
        assertEq(_nonceOf(safe), _nonce + 1, "the nested frame's nonce bump was undone");

        // After the outer transaction the leaked signature is executable by anyone: the policy admits it.
        vm.prank(attacker);
        (bool _ok, ) = address(safe).call(_leaked);
        assertTrue(_ok);
        assertEq(protocol.calls(), 1);
    }

    /// @dev The same nesting during an APPROVED execution of the venue call (the sentinel is in the slot):
    ///      refused, and the approval is spent exactly once, for the outer execution.
    function test_venue_nesting_during_an_approved_execution_is_refused_and_the_approval_is_spent_once() public {
        bytes memory _runQueue = abi.encodeCall(HostileVenue.runQueue, ());
        bytes32 _id = _approve(address(venue), 0, _runQueue, Operation.Call); // `runQueue` is not allowlisted
        uint256 _nonce = _nonceOf(safe);
        venue.queueCall(address(safe), 0, _signedExecCalldata(safe, signerPk, _nonce + 1, address(protocol), 0, _settle(7), Operation.Call));

        vm.recordLogs();
        assertTrue(_execSafeTx(address(venue), 0, _runQueue, Operation.Call));
        (uint256 _n, uint8 _outcome, ) = _reports(vm.getRecordedLogs(), address(guard));
        assertEq(_n, 1);
        assertEq(_outcome, uint8(CuratorGuard.Outcome.Approval));
        assertEq(venue.selectorOf(0), CuratorGuard.NestedExecution.selector);
        assertEq(protocol.calls(), 0);
        assertEq(guard.approvalExpiry(_id), 0, "consumed once");
    }

    /// @dev Inside a COUNCIL window nothing is recorded, so nesting goes undetected (documented): the nested
    ///      venue call executes, and the nested guard removal is held to the council's limits like any
    ///      owner-signed call of the window.
    function test_venue_nesting_inside_a_council_window_executes_under_the_councils_limits() public {
        vm.prank(council);
        guard.bypass(address(safe), 1 days);
        uint256 _nonce = _nonceOf(safe);
        venue.queueCall(address(safe), 0, _signedExecCalldata(safe, signerPk, _nonce + 1, address(protocol), 0, _settle(7), Operation.Call));
        venue.queueCall(
            address(safe),
            0,
            _signedExecCalldata(safe, signerPk, _nonce + 2, address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call)
        );

        vm.recordLogs();
        assertTrue(_poke());
        assertTrue(venue.ok(0), "nested venue call executed inside the window");
        assertEq(protocol.calls(), 1);
        assertFalse(venue.ok(1));
        assertEq(venue.selectorOf(1), CuratorGuard.CouncilBypassLimit.selector, "nested guard removal refused");
        assertEq(_installedGuard(), address(guard));
        (uint256 _n, uint8 _outcome, ) = _reports(vm.getRecordedLogs(), address(guard));
        assertEq(_n, 2, "inner and outer each reported");
        assertEq(_outcome, uint8(CuratorGuard.Outcome.Bypass));
    }

    /*//////////////////////////////////////////////////////////////
                      CALLING BACK INTO THE GUARD
    //////////////////////////////////////////////////////////////*/

    /// @dev The venue claims to be a Safe with this guard installed (`getStorageAt`) and drives the hooks,
    ///      then every role entry, `executeBefore`, the admin transfer and `grantRole`: no state moves, the
    ///      Safe's live approval is untouched, and the outer transaction is reported once as Policy.
    function test_venue_calling_back_into_the_guard_gets_no_state_and_no_report() public {
        venue.setSlot(GUARD_SLOT, _word(address(guard))); // "installed"
        bytes32 _id = _approve(address(protocol), 0, _settle(9), Operation.Call);
        uint64 _expiry = guard.approvalExpiry(_id);
        address _s = address(safe);
        bytes memory _lockdown = abi.encodeCall(guard.lockdown, (_s));

        venue.queueCall(address(guard), 0, abi.encodeCall(guard.checkAfterExecution, (bytes32("forged"), true)));
        venue.queueCall(
            address(guard),
            0,
            abi.encodeCall(
                guard.checkTransaction,
                (address(protocol), 0, _settle(9), Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(venue))
            )
        );
        venue.queueCall(address(guard), 0, _lockdown);
        venue.queueCall(address(guard), 0, abi.encodeCall(guard.revokeAllApprovals, (_s)));
        venue.queueCall(address(guard), 0, abi.encodeCall(guard.bypass, (_s, uint64(1 hours))));
        venue.queueCall(
            address(guard),
            0,
            abi.encodeCall(guard.approveTransaction, (_s, address(0), address(protocol), 0, _settle(1), Operation.Call, uint64(1 hours)))
        );
        venue.queueCall(address(guard), 0, abi.encodeCall(guard.allowFunction, (_s, address(token), TRANSFER, false, _noRules())));
        venue.queueCall(address(guard), 0, abi.encodeCall(guard.setGuardian, (_s, address(venue), true)));
        venue.queueCall(address(guard), 0, abi.encodeCall(guard.executeBefore, (uint64(block.timestamp + 1), _lockdown)));
        venue.queueCall(address(guard), 0, abi.encodeCall(guard.acceptDefaultAdminTransfer, ()));
        venue.queueCall(address(guard), 0, abi.encodeCall(guard.beginDefaultAdminTransfer, (address(venue))));
        venue.queueCall(address(guard), 0, abi.encodeCall(guard.grantRole, (guard.COUNCIL_ROLE(), address(venue))));

        vm.recordLogs();
        assertTrue(_poke());
        (uint256 _n, uint8 _outcome, ) = _reports(vm.getRecordedLogs(), address(guard));
        assertEq(_n, 1, "exactly one report");
        assertEq(_outcome, uint8(CuratorGuard.Outcome.Policy));
        assertEq(venue.count(), 12);
        for (uint256 i; i < 12; ++i) assertFalse(venue.ok(i), "every callback refused");
        assertEq(venue.selectorOf(0), CuratorGuard.MissingSnapshot.selector, "post-hook: the venue's own slot is empty");
        assertEq(venue.selectorOf(1), CuratorGuard.SafeLockedDown.selector, "pre-hook: an unconfigured 'Safe', the real Safe's approval unreachable");
        for (uint256 i = 2; i < 9; ++i) assertEq(venue.selectorOf(i), CuratorGuardPolicy.Unauthorized.selector, "role surface");
        assertEq(venue.selectorOf(9), IAccessControlDefaultAdminRules.AccessControlInvalidDefaultAdmin.selector);
        assertEq(venue.selectorOf(10), IAccessControl.AccessControlUnauthorizedAccount.selector);
        assertEq(venue.selectorOf(11), IAccessControl.AccessControlUnauthorizedAccount.selector);
        assertEq(uint8(guard.mode(_s)), uint8(CuratorGuardPolicy.Mode.Enforced));
        assertEq(guard.approvalExpiry(_id), _expiry, "the Safe's approval untouched");
        assertFalse(guard.isGuardian(_s, address(venue)));
        assertFalse(_isAllowed(_s, address(token), TRANSFER));
    }

    /// @dev `simulateAndRevert` lets anyone run code AS the Safe, in a frame that always reverts. A venue
    ///      that forges the post-hook there sees it pass (the digest is equal, the slot is cleared, a report
    ///      is emitted), and the frame's revert undoes all of it, transient storage included: the real
    ///      post-hook still finds its snapshot and the transaction is reported once, under its real hash.
    function test_venue_forging_a_report_through_simulateAndRevert_is_undone_with_the_frame() public {
        bytes memory _payload = abi.encodeCall(SimDriver.forgePostHook, (address(guard), bytes32("forged")));
        venue.queueCall(address(safe), 0, abi.encodeWithSignature("simulateAndRevert(address,bytes)", address(driver), _payload));

        SafeTx memory _t = SafeTx(address(venue), 0, abi.encodeCall(HostileVenue.poke, (1)), Operation.Call, 0, 0, address(0), address(0));
        bytes32 _realHash = _txHash(_t);
        vm.recordLogs();
        assertTrue(_execSafeTxParams(_t));
        // The transaction passed: the real post-hook found its snapshot, so the frame's clear was undone.
        // Foundry's log recorder also captures the log of the reverted frame (the EVM discards it with the
        // frame): count by hash, one report under the real hash, one forged one from inside the frame.
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_reportsWithHash(_logs, _realHash), 1, "one report under the real safeTxHash");
        assertEq(_reportsWithHash(_logs, bytes32("forged")), 1, "the forged one lived only inside the reverted frame");
        assertFalse(venue.ok(0), "simulateAndRevert always reverts");
        assertEq(uint256(bytes32(venue.ret(0))), 1, "inside the frame the forged post-hook passed");
        // And the next transaction starts from a clean slot: no stale snapshot, no NestedExecution.
        venue.reset();
        assertTrue(_poke());
    }

    function _reportsWithHash(Vm.Log[] memory logs_, bytes32 hash_) internal view returns (uint256 _n) {
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter == address(guard) && logs_[i].topics.length == 4 && logs_[i].topics[0] == REPORT_SIG && logs_[i].topics[2] == hash_) ++_n;
        }
    }

    /*//////////////////////////////////////////////////////////////
                       RECONFIGURING THE SAFE DIRECTLY
    //////////////////////////////////////////////////////////////*/

    /// @dev Everything on the Safe that would weaken it is self-authorised, owner-only or module-only: a
    ///      venue, however hostile, is none of those. Sending it ETH is the one thing that lands.
    function test_venue_cannot_reconfigure_the_safe() public {
        venue.queueCall(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))));
        venue.queueCall(address(safe), 0, abi.encodeCall(ISafe.enableModule, (address(venue))));
        venue.queueCall(address(safe), 0, abi.encodeWithSignature("setFallbackHandler(address)", address(venue)));
        venue.queueCall(address(safe), 0, abi.encodeWithSignature("approveHash(bytes32)", bytes32(uint256(1))));
        venue.queueCall(
            address(safe),
            0,
            abi.encodeCall(ISafe.execTransactionFromModule, (address(token), 0, abi.encodeWithSelector(TRANSFER, attacker, 1), Operation.Call))
        );
        venue.queueCall(address(safe), 1 wei, "");

        uint256 _before = address(safe).balance;
        assertTrue(_poke());
        assertEq(_reason(venue.ret(0)), "GS031");
        assertEq(_reason(venue.ret(1)), "GS031");
        assertEq(_reason(venue.ret(2)), "GS031");
        assertEq(_reason(venue.ret(3)), "GS030");
        assertEq(_reason(venue.ret(4)), "GS104");
        assertTrue(venue.ok(5));
        assertEq(address(safe).balance, _before + 1 wei);
        assertEq(_installedGuard(), address(guard));
        assertEq(uint256(bytes32(safe.getStorageAt(uint256(FALLBACK_SLOT), 1))), 0);
        assertEq(token.balanceOf(attacker), 0);
    }

    /*//////////////////////////////////////////////////////////////
               WHAT A HOSTILE VENUE TAKES: ITS ALLOWANCE
    //////////////////////////////////////////////////////////////*/

    /// @dev The allowance IS the custody: with the live `approve(vault, max)` a hostile venue (an upgraded
    ///      implementation, a backdoor) takes everything in one allowlisted call, reported as Policy. A
    ///      per-settlement cap on `approve`'s amount word (`LessThanOrEqual` on word 1, which the engine
    ///      and the lint accept today) bounds the take to one cap per curator approval, and refuses the
    ///      max approval the Safe's history shows. Evidence for a policy option, not a guard defect.
    function test_residual_a_hostile_venue_takes_exactly_its_allowance_and_a_capped_approve_bounds_it() public {
        // The live state: an unbounded allowance to the venue.
        vm.prank(address(safe));
        token.approve(address(venue), type(uint256).max);
        uint256 _custody = token.balanceOf(address(safe));
        venue.queueCall(address(token), 0, abi.encodeWithSelector(TRANSFER_FROM, address(safe), attacker, _custody));
        vm.recordLogs();
        assertTrue(_poke());
        (uint256 _n, uint8 _outcome, ) = _reports(vm.getRecordedLogs(), address(guard));
        assertEq(_n, 1);
        assertEq(_outcome, uint8(CuratorGuard.Outcome.Policy), "the guard saw an allowlisted call");
        assertTrue(venue.ok(0));
        assertEq(token.balanceOf(attacker), _custody, "the whole custody left");
        assertEq(token.balanceOf(address(safe)), 0);

        // The capped variant: `approve` bound to the venue AND to an amount.
        uint256 _cap = 10_000e6;
        token.mint(address(safe), 1_000_000e6);
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](2);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0);
        _rules[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 1, bytes32(_cap));
        _allowWithRules(address(token), APPROVE, _rules);
        bytes32[] memory _v = new bytes32[](1);
        _v[0] = _word(address(venue));
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(token), APPROVE, 0, _v);

        assertTrue(_execSafeTx(address(token), 0, abi.encodeWithSelector(APPROVE, address(venue), 0), Operation.Call), "reset");
        assertTrue(_execSafeTx(address(token), 0, abi.encodeWithSelector(APPROVE, address(venue), _cap), Operation.Call), "one settlement's worth");
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(token), APPROVE, uint16(1), bytes32(_cap + 1))
        );
        _execSafeTx(address(token), 0, abi.encodeWithSelector(APPROVE, address(venue), _cap + 1), Operation.Call);
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(token), APPROVE, uint16(1), bytes32(type(uint256).max))
        );
        _execSafeTx(address(token), 0, abi.encodeWithSelector(APPROVE, address(venue), type(uint256).max), Operation.Call);

        venue.reset();
        venue.queueCall(address(token), 0, abi.encodeWithSelector(TRANSFER_FROM, address(safe), attacker, 1_000_000e6));
        venue.queueCall(address(token), 0, abi.encodeWithSelector(TRANSFER_FROM, address(safe), attacker, _cap));
        assertTrue(_poke());
        assertFalse(venue.ok(0), "more than the cap: refused by the token");
        assertTrue(venue.ok(1));
        assertEq(token.balanceOf(address(safe)), 1_000_000e6 - _cap, "the take is bounded by one cap");
    }
}
