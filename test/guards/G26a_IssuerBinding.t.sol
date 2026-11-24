// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";

import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

/// @title Quantstamp GUARD-1 (review G26): a one-shot approval is bound to the account that issued it.
/// @dev Owner path on the real Safe v1.4.1 build. An approval is void from the moment its issuer loses the
///      role it issued with (`revokeRole`, `renounceRole`, the outgoing admin at the hand-over's acceptance),
///      on the hook, the dry run and the view alike; a re-grant or a hand-back revives nothing; nobody
///      else's approval moves. The record is two slots (`_approvals`, slot 7) and the per-account revocation
///      count sits in slot 9. The module path is `G26a_IssuerBindingV150Test` below.
contract G26a_IssuerBindingTest is CuratorGuardTestBase {
    bytes32 internal COUNCIL;
    uint256 internal constant APPROVALS_SLOT = 7;
    uint256 internal constant REVOCATIONS_SLOT = 9;

    address internal council2 = makeAddr("council-2");
    address internal next = makeAddr("next-admin");

    function setUp() public override {
        super.setUp();
        COUNCIL = guard.COUNCIL_ROLE();
    }

    function _settle(uint256 n_) internal pure returns (bytes memory) {
        return abi.encodeCall(MockProtocol.settleDeposit, (n_));
    }

    function _revokeCouncil(address who_) internal {
        vm.prank(vetro);
        guard.revokeRole(COUNCIL, who_);
    }

    function _grantCouncil(address who_) internal {
        vm.prank(vetro);
        guard.grantRole(COUNCIL, who_);
    }

    function _slot1(bytes32 id_) internal view returns (bytes32) {
        return vm.load(address(guard), keccak256(abi.encode(id_, APPROVALS_SLOT)));
    }

    /// @dev Raw second slot of the record: issuer (low 160 bits) and the issuer's count at issue (high 96).
    function _slot2(bytes32 id_) internal view returns (address _issuer, uint96 _gen) {
        uint256 _w = uint256(vm.load(address(guard), bytes32(uint256(keccak256(abi.encode(id_, APPROVALS_SLOT))) + 1)));
        _issuer = address(uint160(_w));
        _gen = uint96(_w >> 160);
    }

    function _countSlot(address a_) internal pure returns (bytes32) {
        return keccak256(abi.encode(a_, REVOCATIONS_SLOT));
    }

    function _count(address a_) internal view returns (uint256) {
        return uint256(vm.load(address(guard), _countSlot(a_)));
    }

    function _lockedDown() internal view returns (bytes memory) {
        return abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe));
    }

    function _handover(address from_, address to_) internal {
        vm.prank(from_);
        guard.beginDefaultAdminTransfer(to_);
        vm.warp(block.timestamp + 1);
        vm.prank(to_);
        guard.acceptDefaultAdminTransfer();
        assertEq(guard.defaultAdmin(), to_, "hand-over landed");
    }

    /// @dev The view reads 0 and the dry run and the hook refuse with the same error.
    function _assertVoid(bytes32 id_, address to_, bytes memory data_) internal {
        assertEq(guard.approvalExpiry(id_), 0, "view: void");
        vm.expectRevert(_lockedDown());
        guard.validateTransaction(address(safe), to_, 0, data_, Operation.Call);
        vm.expectRevert(_lockedDown());
        _execSafeTx(to_, 0, data_, Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
                    THE COUNCIL: revokeRole / renounceRole
    //////////////////////////////////////////////////////////////*/

    /// @dev The finding's council half: live before, void in the block of the revocation on the view, the dry
    ///      run and the hook; a refusal writes nothing. The event names the issuer in an indexed topic.
    function test_council_approval_is_void_after_revokeRole_on_view_dry_run_and_hook() public {
        bytes memory _d = _settle(1);
        vm.recordLogs();
        bytes32 _id = _councilApprove(address(protocol), 0, _d, Operation.Call);
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_logs.length, 1, "one log");
        assertEq(_logs[0].topics.length, 4, "three indexed fields");
        assertEq(_logs[0].topics[0], keccak256("TransactionApproved(address,bytes32,address,address,address,uint256,bytes,uint8,uint64,uint32)"));
        assertEq(_logs[0].topics[3], bytes32(uint256(uint160(council))), "topic 3: the issuer");
        uint64 _expiry = guard.approvalExpiry(_id);
        assertGt(_expiry, 0, "live before");
        guard.validateTransaction(address(safe), address(protocol), 0, _d, Operation.Call);
        (address _issuer, uint96 _gen) = _slot2(_id);
        assertEq(_issuer, council, "issuer recorded");
        assertEq(_gen, 0, "count at issue recorded");
        bytes32 _first = _slot1(_id);

        _revokeCouncil(council);
        assertEq(_count(council), 1, "count moved once");
        _assertVoid(_id, address(protocol), _d);
        assertEq(_slot1(_id), _first, "the refusals wrote nothing");
        (_issuer, _gen) = _slot2(_id);
        assertEq(_issuer, council);
        assertEq(_gen, 0);
        vm.warp(uint256(_expiry) + 1);
        assertEq(guard.approvalExpiry(_id), 0, "view: still 0 past the expiry (a void record never reports its expiry)");
    }

    function test_council_approval_is_void_after_renounceRole() public {
        bytes memory _d = _settle(2);
        bytes32 _id = _councilApprove(address(protocol), 0, _d, Operation.Call);
        vm.prank(council);
        guard.renounceRole(COUNCIL, council);
        _assertVoid(_id, address(protocol), _d);
        assertEq(_count(council), 1, "count moved once");
    }

    /// @dev The `hasRole(role, issuer)` check the audit recommends, taken literally, would revive the record
    ///      at the re-grant; the count does not.
    function test_a_regrant_revives_nothing_and_the_members_new_approvals_work() public {
        bytes memory _old = _settle(3);
        bytes32 _idOld = _councilApprove(address(protocol), 0, _old, Operation.Call);
        _revokeCouncil(council);
        _grantCouncil(council);
        assertTrue(guard.hasRole(COUNCIL, council), "re-granted");
        assertEq(_count(council), 1, "a grant does not move the count");
        _assertVoid(_idOld, address(protocol), _old);
        // a new approval carries the current count and is consumed
        bytes memory _new = _settle(33);
        bytes32 _idNew = _councilApprove(address(protocol), 0, _new, Operation.Call);
        (, uint96 _gen) = _slot2(_idNew);
        assertEq(_gen, 1, "the current count");
        assertTrue(_execSafeTx(address(protocol), 0, _new, Operation.Call), "consumed");
        assertEq(protocol.lastAmount(), 33);
        // a second loss of the role voids the second generation too (the count is not a flag)
        bytes32 _idOld2 = _councilApprove(address(protocol), 0, _old, Operation.Call);
        assertEq(_idOld2, _idOld, "re-approved under the same id");
        assertGt(guard.approvalExpiry(_idOld), 0, "live again: re-issued by a live issuer");
        _revokeCouncil(council);
        _grantCouncil(council);
        assertEq(_count(council), 2);
        _assertVoid(_idOld, address(protocol), _old);
        // another issuer's re-approval takes the void record over, stored count included (1 -> the admin's 0)
        (, _gen) = _slot2(_idOld);
        assertEq(_gen, 1, "before the take-over: the member's count at issue");
        assertEq(_approve(address(protocol), 0, _old, Operation.Call), _idOld);
        address _issuer;
        (_issuer, _gen) = _slot2(_idOld);
        assertEq(_issuer, vetro, "the record is the caller's");
        assertEq(_gen, 0, "with the caller's count");
        assertTrue(_execSafeTx(address(protocol), 0, _old, Operation.Call), "and is consumed");
    }

    /// @dev Docs section 4: a void record is absent, not a veto. An allowlisted payload under it runs on the
    ///      policy lane (outcome `Policy`, no `ApprovalConsumed`), as after an expiry, on the dry run and the
    ///      hook; the record is not spent.
    function test_a_void_approval_over_an_allowlisted_payload_leaves_the_policy_lane_open() public {
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        _enforce();
        bytes memory _d = _settle(9);
        bytes32 _id = _councilApprove(address(protocol), 0, _d, Operation.Call);
        _revokeCouncil(council);
        assertEq(guard.approvalExpiry(_id), 0, "void");
        bytes32 _first = _slot1(_id);
        assertGt(uint256(_first), 0, "still stored");
        guard.validateTransaction(address(safe), address(protocol), 0, _d, Operation.Call);
        vm.recordLogs();
        assertTrue(_execSafeTx(address(protocol), 0, _d, Operation.Call), "the policy lane passes it");
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        uint256 _reports;
        for (uint256 i; i < _logs.length; ++i) {
            if (_logs[i].emitter != address(guard)) continue;
            assertTrue(_logs[i].topics[0] != CuratorGuardPolicy.ApprovalConsumed.selector, "nothing consumed");
            if (_logs[i].topics[0] != CuratorGuard.TransactionChecked.selector) continue;
            ++_reports;
            assertEq(uint256(_logs[i].topics[3]), uint256(CuratorGuard.Outcome.Policy), "outcome: Policy");
        }
        assertEq(_reports, 1, "one report");
        assertEq(protocol.lastAmount(), 9);
        assertEq(_slot1(_id), _first, "the void record is not spent");
        (address _issuer, uint96 _gen) = _slot2(_id);
        assertEq(_issuer, council, "nor rewritten: its issuer");
        assertEq(_gen, 0, "nor rewritten: its count");
        assertEq(guard.approvalExpiry(_id), 0, "still void");
    }

    /*//////////////////////////////////////////////////////////////
                        NO COLLATERAL VOIDING
    //////////////////////////////////////////////////////////////*/

    function test_a_revocation_leaves_every_other_issuers_approvals_alone() public {
        _grantCouncil(council2);
        bytes memory _a = _settle(4);
        bytes memory _b = _settle(44);
        bytes memory _c = _settle(444);
        bytes32 _idA = _councilApprove(address(protocol), 0, _a, Operation.Call);
        vm.prank(council2);
        bytes32 _idB = guard.approveTransaction(address(safe), address(0), address(protocol), 0, _b, Operation.Call, 1 days);
        bytes32 _idC = _approve(address(protocol), 0, _c, Operation.Call); // the admin's
        _revokeCouncil(council);
        assertEq(_count(council2), 0, "the other member's count");
        assertEq(_count(vetro), 0, "the revoking admin's count");
        assertEq(guard.approvalExpiry(_idA), 0, "the revoked member's: void");
        assertGt(guard.approvalExpiry(_idB), 0, "the other member's: live");
        assertGt(guard.approvalExpiry(_idC), 0, "the admin's: live");
        assertTrue(_execSafeTx(address(protocol), 0, _b, Operation.Call));
        assertTrue(_execSafeTx(address(protocol), 0, _c, Operation.Call));
    }

    /// @dev Only the loss of a role an approval can be issued with counts: `GUARDIAN_ROLE` issues nothing, and
    ///      a revocation or renunciation of a role the account does not hold is a no-op.
    function test_a_guardian_role_loss_and_a_noop_revocation_void_nothing() public {
        vm.prank(vetro);
        guard.setDeploymentGuardian(council, true);
        bytes memory _c = _settle(5);
        bytes memory _a = _settle(55);
        bytes32 _idC = _councilApprove(address(protocol), 0, _c, Operation.Call);
        bytes32 _idA = _approve(address(protocol), 0, _a, Operation.Call);
        vm.prank(vetro);
        guard.setDeploymentGuardian(council, false);
        assertFalse(guard.hasRole(guard.GUARDIAN_ROLE(), council), "guardian role gone");
        vm.prank(council);
        guard.renounceRole(bytes32(0), council); // a no-op: the council was never the admin
        vm.prank(vetro);
        guard.revokeRole(COUNCIL, vetro); // a no-op: the admin was never a council member
        assertEq(_count(council), 0, "the member's count did not move");
        assertEq(_count(vetro), 0, "the admin's count did not move");
        assertGt(guard.approvalExpiry(_idC), 0, "the member's approval: live");
        assertGt(guard.approvalExpiry(_idA), 0, "the admin's approval: live");
        assertTrue(_execSafeTx(address(protocol), 0, _c, Operation.Call));
        assertTrue(_execSafeTx(address(protocol), 0, _a, Operation.Call));
    }

    /*//////////////////////////////////////////////////////////////
                    THE ADMIN: THE AUDIT'S EXPLOIT SCENARIO
    //////////////////////////////////////////////////////////////*/

    /// @dev The admin approves `setGuard(0)`; admin control transfers; the owners can no longer use the old
    ///      approval. The successor's re-issue takes the same id; a hand-back revives nothing.
    function test_admin_setGuard0_approval_is_void_after_the_handover_and_a_handback_revives_nothing() public {
        bytes memory _removeGuard = abi.encodeCall(ISafe.setGuard, (address(0)));
        bytes memory _d = _settle(6);
        bytes32 _idRemove = _approve(address(safe), 0, _removeGuard, Operation.Call);
        bytes32 _id = _approve(address(protocol), 0, _d, Operation.Call);
        guard.validateTransaction(address(safe), address(safe), 0, _removeGuard, Operation.Call); // usable before
        _handover(vetro, next);
        _assertVoid(_idRemove, address(safe), _removeGuard);
        _assertVoid(_id, address(protocol), _d);
        assertEq(_installedGuard(), address(guard), "the guard is still installed");
        assertEq(_count(vetro), 1, "the outgoing admin's count moved");
        assertEq(_count(next), 0, "the incoming admin's did not");
        // the new admin re-issues under the same id: the record is now its own
        vm.prank(next);
        assertEq(guard.approveTransaction(address(safe), address(0), address(protocol), 0, _d, Operation.Call, 1 days), _id);
        (address _issuer, uint96 _gen) = _slot2(_id);
        assertEq(_issuer, next);
        assertEq(_gen, 0);
        assertTrue(_execSafeTx(address(protocol), 0, _d, Operation.Call), "the successor's re-issue is consumed");
        // hand back: the first admin's old approval stays void, its new ones work
        _handover(next, vetro);
        assertEq(_count(vetro), 1, "a return does not move the count");
        _assertVoid(_idRemove, address(safe), _removeGuard);
        assertEq(_installedGuard(), address(guard));
        _approve(address(protocol), 0, _d, Operation.Call);
        assertTrue(_execSafeTx(address(protocol), 0, _d, Operation.Call));
    }

    /*//////////////////////////////////////////////////////////////
                            RECORD SHAPE
    //////////////////////////////////////////////////////////////*/

    /// @dev Consumption and `revokeApproval` clear both slots; a void record stays revocable by a guardian.
    function test_consumption_and_revokeApproval_clear_both_slots_of_the_record() public {
        _addGuardian(guardian);
        bytes memory _a = _settle(7);
        bytes memory _b = _settle(77);
        bytes32 _idA = _councilApprove(address(protocol), 0, _a, Operation.Call);
        bytes32 _idB = _councilApprove(address(protocol), 0, _b, Operation.Call);
        (address _issuer, uint96 _gen) = _slot2(_idA);
        assertEq(_issuer, council, "before the consumption: the second slot is written");
        assertTrue(_execSafeTx(address(protocol), 0, _a, Operation.Call));
        assertEq(_slot1(_idA), bytes32(0), "consumed: first slot");
        (_issuer, _gen) = _slot2(_idA);
        assertEq(_issuer, address(0), "consumed: second slot");
        _revokeCouncil(council);
        _grantCouncil(council);
        bytes32 _idC = _councilApprove(address(protocol), 0, _a, Operation.Call); // count 1 in the second slot
        _revokeCouncil(council); // B (count 0) and C (count 1) are void records now
        (_issuer, _gen) = _slot2(_idC);
        assertEq(_issuer, council, "before the revocation: second slot, issuer");
        assertEq(_gen, 1, "before the revocation: second slot, count");
        vm.prank(guardian);
        vm.expectEmit(true, true, false, true, address(guard));
        emit CuratorGuardPolicy.ApprovalRevoked(address(safe), _idC);
        guard.revokeApproval(_idC);
        assertEq(_slot1(_idC), bytes32(0), "revoked: first slot");
        (_issuer, _gen) = _slot2(_idC);
        assertEq(_issuer, address(0), "revoked: second slot, issuer");
        assertEq(_gen, 0, "revoked: second slot, count");
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ApprovalNotFound.selector, _idC));
        guard.revokeApproval(_idC);
        assertGt(uint256(_slot1(_idB)), 0, "another void record is untouched");
    }

    /// @dev The record keeps 96 bits of the full-word count. A count at 2^96 (unreachable: every step needs a
    ///      grant or a hand-over first) fails closed: that account's new approval is void from issue on the
    ///      view and the hooks, and no role revocation or hand-over is ever blocked by the count.
    function test_a_count_at_2_pow_96_fails_closed_and_blocks_no_revocation() public {
        vm.store(address(guard), _countSlot(council), bytes32(uint256(1) << 96));
        bytes memory _d = _settle(8);
        bytes32 _id = _councilApprove(address(protocol), 0, _d, Operation.Call);
        (address _issuer, uint96 _gen) = _slot2(_id);
        assertEq(_issuer, council);
        assertEq(_gen, 0, "the count truncated to 96 bits");
        _assertVoid(_id, address(protocol), _d);
        _revokeCouncil(council);
        assertEq(_count(council), (uint256(1) << 96) + 1, "the revocation landed");
        assertFalse(guard.hasRole(COUNCIL, council));
        vm.store(address(guard), _countSlot(vetro), bytes32(uint256(1) << 96));
        _handover(vetro, next);
        assertEq(_count(vetro), (uint256(1) << 96) + 1, "the hand-over landed");
    }
}

contract G26aModule {
    function exec(ISafe safe_, address to_, uint256 value_, bytes calldata data_, Operation op_) external returns (bool) {
        return safe_.execTransactionFromModule(to_, value_, data_, op_);
    }
}

/// @dev Module path on the real Safe v1.5.0 build with the guard installed as transaction guard and module
///      guard (the finding's module scenario): no owner signature is involved in the execution.
contract G26a_IssuerBindingV150Test is SafeTxHelper {
    CuratorGuard internal guard;
    G26aModule internal module;
    MockProtocol internal protocol;
    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal attacker = makeAddr("attacker");

    function setUp() public {
        vm.warp(1_700_000_000);
        address _curator;
        (_curator, signerPk) = makeAddrAndKey("curator");
        Safe150 _singleton = new Safe150();
        SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = _curator;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        safe = ISafe(address(_proxy));
        guard = new CuratorGuardHarness(0, vetro, council);
        CuratorGuardHarness(address(guard)).seedSafe(address(safe));
        module = new G26aModule();
        protocol = new MockProtocol();
        vm.startPrank(address(safe));
        safe.enableModule(address(module));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        vm.stopPrank();
        vm.startPrank(vetro);
        guard.enforce(address(safe));
        guard.setModuleAllowed(address(safe), address(module), true);
        vm.stopPrank();
    }

    function test_module_approval_is_void_after_the_councils_revocation_on_hook_and_dry_run() public {
        bytes memory _d = abi.encodeCall(MockProtocol.deposit, (1, attacker));
        bytes memory _refused = abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector);
        vm.recordLogs();
        vm.prank(council);
        bytes32 _id = guard.approveTransaction(address(safe), address(module), address(protocol), 0, _d, Operation.Call, 1 days);
        guard.validateModuleTransaction(address(safe), address(module), address(protocol), 0, _d, Operation.Call); // live
        bytes32 _role = guard.COUNCIL_ROLE();
        vm.prank(vetro);
        guard.revokeRole(_role, council);
        assertEq(guard.approvalExpiry(_id), 0, "view: void");
        vm.expectRevert(_refused);
        guard.validateModuleTransaction(address(safe), address(module), address(protocol), 0, _d, Operation.Call);
        vm.expectRevert(_refused);
        module.exec(safe, address(protocol), 0, _d, Operation.Call);
        assertEq(protocol.calls(), 0, "nothing executed");
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_logs[0].topics.length, 4, "three indexed fields");
        assertEq(_logs[0].topics[3], bytes32(uint256(uint160(council))), "topic 3: the issuer, not the module");
    }

    /// @dev Control: the same approval is consumed by the module while its issuer holds the role.
    function test_module_approval_of_a_seated_council_is_consumed() public {
        bytes memory _d = abi.encodeCall(MockProtocol.deposit, (3, attacker));
        vm.prank(council);
        guard.approveTransaction(address(safe), address(module), address(protocol), 0, _d, Operation.Call, 1 days);
        assertTrue(module.exec(safe, address(protocol), 0, _d, Operation.Call));
        assertEq(protocol.lastAmount(), 3);
    }
}
