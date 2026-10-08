// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";
import {SafeMigration} from "safe-contracts-v1.5.0/contracts/libraries/SafeMigration.sol";
import {MultiSendCallOnly} from "safe-contracts-v1.4.1/contracts/libraries/MultiSendCallOnly.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

/// @dev A venue with a dynamic `bytes` argument (what the tail-hash rule binds).
contract PayloadVenue {
    bytes32 public lastHash;
    uint256 public lastDeadline;

    function execute(uint256 deadline_, bytes calldata payload_) external {
        lastDeadline = deadline_;
        lastHash = keccak256(payload_);
    }
}

/// @dev Accepts any calldata (a library that is not a batch build).
contract Sink {
    fallback() external payable {}
}

/// @dev Minimal v1.5.0 module: whoever calls `exec` makes the Safe execute the payload.
contract Round8Module {
    function exec(ISafe safe_, address to_, uint256 value_, bytes calldata data_, Operation op_) external returns (bool) {
        return safe_.execTransactionFromModule(to_, value_, data_, op_);
    }
}

/// @dev Round 8 (docs/curator-guard.md section 13.2, V2-83…): the behaviours the twenty-angle campaign
///      changed, each pinned by a test that fails on the previous code.
contract CuratorGuardRound8Test is CuratorGuardTestBase {
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;
    bytes4 internal constant DEPOSIT = MockProtocol.deposit.selector;
    bytes4 internal constant TRANSFER = IERC20.transfer.selector;

    function _settle(uint256 n_) internal pure returns (bytes memory) {
        return abi.encodeCall(MockProtocol.settleDeposit, (n_));
    }

    /*//////////////////////////////////////////////////////////////
               R8I-1: AN APPROVED BATCH IS DECODED AT USE
    //////////////////////////////////////////////////////////////*/

    /// @dev A tail cut inside the value word of an approved batch: the canonical builds would execute
    ///      `shown << 8k` wei, so the approval lane refuses the payload (`MalformedMultiSend`) live and
    ///      in the dry run, and the approval is kept.
    function test_approved_truncated_batch_is_refused_at_use_and_the_approval_kept() public {
        bytes memory _packed = _entry(attacker, 1, "");
        bytes memory _cut = new bytes(45); // op(1) | to(20) | value cut after its first 24 bytes
        for (uint256 i; i < 45; ++i) _cut[i] = _packed[i];
        bytes memory _batch = _multiSendCalldata(_cut);
        _seedCodehash(address(multiSendCallOnly).codehash); // the fixture build stands in for a canonical one
        bytes32 _id = _approve(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        guard.validateTransaction(address(safe), address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        _execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
        assertGt(guard.approvalExpiry(_id), 0, "approval kept");
        assertEq(attacker.balance, 0, "nothing moved");
    }

    /// @dev Canonical approved batches keep working in `Lockdown`, with self-calls, unlisted targets and
    ///      value, through a registered or an UNREGISTERED canonical build; an entry addressed to the
    ///      guard is refused; a delegatecall into non-canonical code stays unparsed.
    function test_canonical_approved_batches_keep_working_and_cannot_address_the_guard() public {
        MultiSendCallOnly _unregistered = new MultiSendCallOnly();
        _seedCodehash(address(_unregistered).codehash); // canonical, never registered for this Safe
        bytes memory _batch = _multiSendCalldata(
            abi.encodePacked(
                _entry(address(safe), 0, abi.encodeWithSignature("changeThreshold(uint256)", 1)),
                _entry(attacker, 1 ether, ""),
                _entry(address(protocol), 0, _settle(7))
            )
        );
        _approve(address(_unregistered), 0, _batch, Operation.DelegateCall);
        assertTrue(_execSafeTx(address(_unregistered), 0, _batch, Operation.DelegateCall));
        assertEq(attacker.balance, 1 ether);
        assertEq(protocol.lastAmount(), 7);

        bytes memory _forge = _multiSendCalldata(
            _entry(address(guard), 0, abi.encodeCall(guard.checkAfterExecution, (bytes32("forged"), true)))
        );
        bytes32 _id = _approve(address(_unregistered), 0, _forge, Operation.DelegateCall);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, guard.checkAfterExecution.selector));
        _execSafeTx(address(_unregistered), 0, _forge, Operation.DelegateCall);
        assertGt(guard.approvalExpiry(_id), 0, "approval kept");

        // Non-canonical code (a plain library) is not a batch: whatever its calldata, it stays unparsed.
        Sink _lib = new Sink();
        bytes memory _raw = _multiSendCalldata(_cutBytes(_batch, 50));
        _approve(address(_lib), 0, _raw, Operation.DelegateCall);
        assertTrue(_execSafeTx(address(_lib), 0, _raw, Operation.DelegateCall), "unparsed, executed as approved");
    }

    function _cutBytes(bytes memory b_, uint256 n_) internal pure returns (bytes memory _out) {
        _out = new bytes(n_);
        for (uint256 i; i < n_; ++i) _out[i] = b_[i];
    }

    /*//////////////////////////////////////////////////////////////
          R8D-2 / R8D-3: APPROVAL TARGETS AND THE DELEGATECALL CODE PIN
    //////////////////////////////////////////////////////////////*/

    /// @dev An approved delegatecall binds the CODE at `to` when issued: once the code differs the id
    ///      differs, so the approval is void (and `computeApprovalId` says so).
    function test_approved_delegatecall_is_void_once_the_code_at_the_target_changed() public {
        bytes memory _data = hex"deadbeef";
        bytes32 _id = _approve(address(multiSendCallOnly), 0, _data, Operation.DelegateCall);
        assertEq(_id, guard.computeApprovalId(address(safe), address(0), address(multiSendCallOnly), 0, _data, Operation.DelegateCall));
        vm.etch(address(multiSendCallOnly), address(protocol).code);
        assertTrue(
            _id != guard.computeApprovalId(address(safe), address(0), address(multiSendCallOnly), 0, _data, Operation.DelegateCall),
            "a different code, a different id"
        );
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(multiSendCallOnly), 0, _data, Operation.DelegateCall);
        assertGt(guard.approvalExpiry(_id), 0, "the old approval is dead, not spent");
        // A plain call carries no pin: the id ignores the code.
        bytes32 _call = guard.computeApprovalId(address(safe), address(0), attacker, 0, _data, Operation.Call);
        vm.etch(attacker, address(protocol).code);
        assertEq(_call, guard.computeApprovalId(address(safe), address(0), attacker, 0, _data, Operation.Call));
    }

    /// @dev What an approval may address: never an account without code with calldata or as a
    ///      delegatecall, never a delegatecall into EIP-7702 delegated code (`0xef`), never the guard;
    ///      a plain value transfer to a key stays approvable; the executor is never the Safe or the guard.
    function test_approval_targets_are_checked_when_issued() public {
        vm.startPrank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, attacker));
        guard.approveTransaction(address(safe), address(0), attacker, 0, hex"deadbeef", Operation.Call, 1 days);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, attacker));
        guard.approveTransaction(address(safe), address(0), attacker, 0, "", Operation.DelegateCall, 1 days);
        address _delegated = makeAddr("delegated");
        vm.etch(_delegated, abi.encodePacked(hex"ef0100", address(protocol))); // EIP-7702 delegation designator
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, _delegated));
        guard.approveTransaction(address(safe), address(0), _delegated, 0, hex"deadbeef", Operation.DelegateCall, 1 days);
        bytes32 _ok = guard.approveTransaction(address(safe), address(0), _delegated, 0, hex"deadbeef", Operation.Call, 1 days);
        assertGt(guard.approvalExpiry(_ok), 0, "a plain call into delegated code is approvable");
        bytes32 _transfer = guard.approveTransaction(address(safe), address(0), attacker, 1 ether, "", Operation.Call, 1 days);
        assertGt(guard.approvalExpiry(_transfer), 0, "a value transfer to a key is approvable");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(safe)));
        guard.approveTransaction(address(safe), address(safe), address(protocol), 0, _settle(1), Operation.Call, 1 days);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(guard)));
        guard.approveTransaction(address(safe), address(guard), address(protocol), 0, _settle(1), Operation.Call, 1 days);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                R8G-1 / R8G-2: THE SAFE IS PINNED BY CODE HASH
    //////////////////////////////////////////////////////////////*/

    /// @dev A Safe whose proxy or singleton code this guard does not know is refused on the policy path
    ///      (pre-hook, post-hook, dry run), while approvals and windows keep working for it.
    function test_unknown_safe_code_is_refused_on_the_policy_path_only() public {
        CuratorGuardHarness _fresh = new CuratorGuardHarness(0, vetro, council); // nothing seeded
        vm.startPrank(vetro);
        _fresh.enforce(address(safe));
        _fresh.allowFunction(address(safe), address(protocol), SETTLE, false, _noRules());
        vm.stopPrank();
        bytes memory _err = abi.encodeWithSelector(CuratorGuard.SafeNotSupported.selector, address(safe));
        vm.expectRevert(_err);
        _fresh.validateTransaction(address(safe), address(protocol), 0, _settle(1), Operation.Call);
        // A guard that is not in the Safe's slot answers no hook at all (V2-88); install the fresh one.
        vm.prank(address(safe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardNotInstalled.selector, address(safe)));
        _fresh.checkTransaction(address(protocol), 0, _settle(1), Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0));
        vm.store(address(safe), GUARD_SLOT, bytes32(uint256(uint160(address(_fresh)))));
        vm.prank(address(safe));
        vm.expectRevert(_err);
        _fresh.checkTransaction(address(protocol), 0, _settle(1), Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0));
        // The post-hook of a policy transaction re-reads the configuration: an in-context singleton swap
        // to unknown code is caught there too (approved transactions never read it).
        _fresh.seedSafe(address(safe));
        vm.prank(address(safe));
        _fresh.checkTransaction(address(protocol), 0, _settle(1), Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0));
        address _singleton = address(uint160(uint256(vm.load(address(safe), bytes32(0)))));
        vm.store(address(safe), bytes32(0), bytes32(uint256(uint160(address(protocol)))));
        vm.prank(address(safe));
        vm.expectRevert(_err);
        _fresh.checkAfterExecution(bytes32(0), true);
        vm.store(address(safe), bytes32(0), bytes32(uint256(uint160(_singleton))));
        // Approvals and windows do not read the configuration.
        CuratorGuardHarness _unseeded = new CuratorGuardHarness(0, vetro, council);
        vm.store(address(safe), GUARD_SLOT, bytes32(uint256(uint160(address(_unseeded)))));
        vm.prank(vetro);
        _unseeded.approveTransaction(address(safe), address(0), address(protocol), 0, _settle(2), Operation.Call, 1 days);
        vm.prank(address(safe));
        _unseeded.checkTransaction(address(protocol), 0, _settle(2), Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0));
        vm.prank(address(safe));
        _unseeded.checkAfterExecution(bytes32(0), true);
        vm.prank(vetro);
        _unseeded.bypass(address(safe), 1 days);
        _unseeded.validateTransaction(address(safe), address(protocol), 0, _settle(1), Operation.Call);
        vm.store(address(safe), GUARD_SLOT, bytes32(uint256(uint160(address(guard)))));
    }

    /// @dev V2-88: a replacement guard is inert until the Safe adopts it, and a retired one from the swap
    ///      on (per path); the dry run still answers, so the pre-swap checklist can simulate against it.
    function test_a_guard_answers_hooks_only_where_it_is_installed() public {
        CuratorGuardHarness _next = new CuratorGuardHarness(0, vetro, council);
        _next.seedSafe(address(safe));
        vm.startPrank(vetro);
        _next.enforce(address(safe));
        _next.allowFunction(address(safe), address(protocol), SETTLE, false, _noRules());
        bytes32 _staged = _next.approveTransaction(address(safe), address(0), attacker, 1 ether, "", Operation.Call, 1 days);
        vm.stopPrank();
        _next.validateTransaction(address(safe), address(protocol), 0, _settle(1), Operation.Call);
        bytes memory _err = abi.encodeWithSelector(CuratorGuard.GuardNotInstalled.selector, address(safe));
        vm.prank(address(safe));
        vm.expectRevert(_err);
        _next.checkTransaction(attacker, 1 ether, "", Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0));
        assertGt(_next.approvalExpiry(_staged), 0, "a pre-staged approval cannot be spent before adoption");
        // The swap (approved on the installed guard) adopts it; the retired guard answers nothing after.
        bytes memory _swap = abi.encodeCall(ISafe.setGuard, (address(_next)));
        _approve(address(safe), 0, _swap, Operation.Call);
        assertTrue(_execSafeTx(address(safe), 0, _swap, Operation.Call));
        assertTrue(_execSafeTx(address(protocol), 0, _settle(1), Operation.Call), "the replacement enforces");
        vm.prank(address(safe));
        vm.expectRevert(_err);
        guard.checkTransaction(address(protocol), 0, _settle(1), Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0));
    }

    /// @dev `masterCopy()` must answer exactly one word: a proxy that forwards it (empty success, a
    ///      revert, two words) is not a `SafeProxy` and is refused the same way.
    function test_masterCopy_must_answer_one_word() public {
        bytes memory _err = abi.encodeWithSelector(CuratorGuard.SafeNotSupported.selector, address(safe));
        _enforce();
        _allow(address(protocol), SETTLE);
        bytes memory _code = address(safe).code;
        vm.mockCall(address(safe), abi.encodeWithSelector(_H().masterCopySelector()), "");
        vm.expectRevert(_err);
        guard.validateTransaction(address(safe), address(protocol), 0, _settle(1), Operation.Call);
        vm.mockCall(address(safe), abi.encodeWithSelector(_H().masterCopySelector()), abi.encode(uint256(1), uint256(2)));
        vm.expectRevert(_err);
        guard.validateTransaction(address(safe), address(protocol), 0, _settle(1), Operation.Call);
        vm.mockCallRevert(address(safe), abi.encodeWithSelector(_H().masterCopySelector()), "nope");
        vm.expectRevert(_err);
        guard.validateTransaction(address(safe), address(protocol), 0, _settle(1), Operation.Call);
        vm.clearMockedCalls();
        assertEq(address(safe).code, _code);
        guard.validateTransaction(address(safe), address(protocol), 0, _settle(1), Operation.Call);
    }

    /// @dev A module linked on a v1.4.1 Safe (no module hook exists) stops the policy path with
    ///      `ModuleNotHooked` until the council-approved `disableModule` lands; the dry run agrees.
    function test_a_linked_module_this_guard_does_not_hook_stops_the_policy_path() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        assertTrue(_execSafeTx(address(protocol), 0, _settle(1), Operation.Call));
        bytes memory _enable = abi.encodeCall(ISafe.enableModule, (attacker));
        _approve(address(safe), 0, _enable, Operation.Call);
        assertTrue(_execSafeTx(address(safe), 0, _enable, Operation.Call), "approved enableModule lands");
        bytes memory _err = abi.encodeWithSelector(CuratorGuard.ModuleNotHooked.selector, attacker);
        vm.expectRevert(_err);
        _execSafeTx(address(protocol), 0, _settle(2), Operation.Call);
        vm.expectRevert(_err);
        guard.validateTransaction(address(safe), address(protocol), 0, _settle(2), Operation.Call);
        bytes memory _disable = abi.encodeWithSignature("disableModule(address,address)", address(1), attacker);
        _councilApprove(address(safe), 0, _disable, Operation.Call);
        assertTrue(_execSafeTx(address(safe), 0, _disable, Operation.Call), "council lane: disableModule");
        assertTrue(_execSafeTx(address(protocol), 0, _settle(3), Operation.Call), "policy traffic resumes");
    }

    /*//////////////////////////////////////////////////////////////
                  R8H-1: THE GUARD AS A FALLBACK HANDLER
    //////////////////////////////////////////////////////////////*/

    /// @dev With the guard in the Safe's fallback-handler slot, `FallbackManager` forwards every unknown
    ///      selector to it with the Safe as caller, for ANY caller, and the forwarded length is the
    ///      caller's choice: no approval is spent while the slot holds the guard and an after-hook is
    ///      exactly 68 bytes, so a stranger can neither burn an approval nor forge a report (R8H-1,
    ///      R8Q-2). Driven through the Safe's real fallback.
    function test_forwarded_hook_calls_are_refused() public {
        bytes32 _id = _approve(address(protocol), 0, _settle(1), Operation.Call);
        bytes memory _pre = abi.encodeCall(
            guard.checkTransaction,
            (address(protocol), 0, _settle(1), Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0))
        );
        // Through the Safe's real fallback (the guard in the handler slot), not a pranked call with
        // 20 bytes appended: the check is on the slot, because the forwarded length is the caller's choice.
        vm.prank(address(safe));
        (bool _ok, bytes memory _ret) = address(safe).call(abi.encodeWithSignature("setFallbackHandler(address)", address(guard)));
        assertTrue(_ok);
        vm.prank(attacker);
        (_ok, _ret) = address(safe).call(_pre);
        assertFalse(_ok);
        assertEq(_ret, abi.encodeWithSelector(CuratorGuard.ForwardedHookCall.selector));
        vm.prank(attacker);
        (_ok, _ret) = address(safe).call(abi.encodePacked(_pre, bytes12(0)));
        assertFalse(_ok);
        assertEq(_ret, abi.encodeWithSelector(CuratorGuard.ForwardedHookCall.selector));
        assertGt(guard.approvalExpiry(_id), 0, "approval untouched");
        bytes memory _post = abi.encodeCall(guard.checkAfterExecution, (bytes32("forged"), true));
        vm.prank(attacker);
        (_ok, _ret) = address(safe).call(_post);
        assertFalse(_ok);
        assertEq(_ret, abi.encodeWithSelector(CuratorGuard.ForwardedHookCall.selector));
        vm.prank(attacker);
        (_ok, _ret) = address(safe).call(abi.encodePacked(_post, bytes12(0)));
        assertFalse(_ok);
        assertEq(_ret, abi.encodeWithSelector(CuratorGuard.ForwardedHookCall.selector));
        // The genuine shape works again once the handler is anything but the guard.
        vm.prank(address(safe));
        (_ok, ) = address(safe).call(abi.encodeWithSignature("setFallbackHandler(address)", address(0)));
        assertTrue(_ok);
        assertTrue(_execSafeTx(address(protocol), 0, _settle(1), Operation.Call));
        assertEq(guard.approvalExpiry(_id), 0, "consumed by the genuine execution");
    }

    /*//////////////////////////////////////////////////////////////
                 R8E: ROLE-GRANT RAILS, DELAY FLOOR, ACCEPTANCE WINDOW
    //////////////////////////////////////////////////////////////*/

    function test_role_grants_have_the_guards_input_rails() public {
        bytes32 _councilRole = guard.COUNCIL_ROLE();
        bytes32 _guardianRole = guard.GUARDIAN_ROLE();
        _enforce(); // the fixture Safe is configured (a policy exists: targets are added below)
        _allow(address(protocol), SETTLE);
        vm.startPrank(vetro);
        vm.expectRevert(CuratorGuardPolicy.AddressIsNull.selector);
        guard.grantRole(_councilRole, address(0));
        vm.expectRevert(CuratorGuardPolicy.AddressIsNull.selector);
        guard.grantRole(_guardianRole, address(0));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, vetro));
        guard.grantRole(_councilRole, vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, address(safe)));
        guard.grantRole(_councilRole, address(safe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, address(safe)));
        guard.setDeploymentGuardian(address(safe), true);
        // Only admin-written state counts for a grant: a council-written mode or per-Safe guardian on the
        // successor does not block it (a rogue council cannot veto its replacement)…
        address _successor = makeAddr("successor");
        vm.stopPrank();
        vm.startPrank(council);
        guard.enforce(_successor);
        guard.setGuardian(_successor, guardian, true);
        vm.stopPrank();
        vm.prank(vetro);
        guard.grantRole(_councilRole, _successor);
        assertTrue(guard.hasRole(_councilRole, _successor));
        // …while the admin transfer still refuses it (the admin must be exempt from nothing it wrote).
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, _successor));
        guard.beginDefaultAdminTransfer(_successor);
        // The constructor refuses `council == admin` through the same rail.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, vetro));
        new CuratorGuardHarness(0, vetro, vetro);
    }

    function test_admin_delay_has_a_floor_and_a_pending_admin_expires() public {
        vm.startPrank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminDelayTooLong.selector, uint48(3)));
        guard.changeDefaultAdminDelay(3);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminDelayTooLong.selector, uint48(0)));
        guard.changeDefaultAdminDelay(0);
        guard.changeDefaultAdminDelay(1 days);
        address _successor = makeAddr("successor");
        guard.beginDefaultAdminTransfer(_successor);
        vm.stopPrank();
        (, uint48 _schedule) = guard.pendingDefaultAdmin();
        vm.warp(uint256(_schedule) + _H().maxAdminDelay() + 1);
        vm.prank(_successor);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, uint64(_schedule)));
        guard.acceptDefaultAdminTransfer();
        // Re-armed by beginning again; accepted inside the window.
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(_successor);
        (, _schedule) = guard.pendingDefaultAdmin();
        vm.warp(uint256(_schedule) + _H().maxAdminDelay());
        vm.prank(_successor);
        guard.acceptDefaultAdminTransfer();
        assertEq(guard.defaultAdmin(), _successor);
    }

    /*//////////////////////////////////////////////////////////////
                R8A: RULE PAIRING, TAIL HASH, CODELESS TARGETS
    //////////////////////////////////////////////////////////////*/

    function test_a_floor_needs_a_real_ceiling() public {
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](2);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.GreaterThanOrEqual, 0, bytes32(uint256(100)));
        _rules[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 0, bytes32(type(uint256).max));
        vm.startPrank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidRule.selector, 0));
        guard.allowFunction(address(safe), address(protocol), SETTLE, false, _rules);
        _rules[1].value = bytes32(uint256(5)); // below the floor: a dead function
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidRule.selector, 0));
        guard.allowFunction(address(safe), address(protocol), SETTLE, false, _rules);
        _rules[1].value = bytes32(uint256(200));
        guard.allowFunction(address(safe), address(protocol), SETTLE, false, _rules);
        guard.enforce(address(safe));
        vm.stopPrank();
        assertTrue(_execSafeTx(address(protocol), 0, _settle(150), Operation.Call));
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(protocol), SETTLE, uint16(0), bytes32(uint256(201)))
        );
        _execSafeTx(address(protocol), 0, _settle(201), Operation.Call);
    }

    /// @dev `TAIL_FLAG`: the rule binds the hash of the calldata from that word to its end, which pins a
    ///      dynamic payload exactly (re-encodings and trailing bytes are different hashes); static words
    ///      before it keep their own rules and `OneOf` composes.
    function test_tail_hash_rule_binds_a_dynamic_payload() public {
        PayloadVenue _venue = new PayloadVenue();
        bytes memory _good = abi.encodeCall(PayloadVenue.execute, (1000, hex"c0ffee"));
        bytes memory _bad = abi.encodeCall(PayloadVenue.execute, (1000, hex"c0ffef"));
        uint16 _tail = 1 | _H().tailFlag();
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](2);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 0, bytes32(uint256(2000)));
        _rules[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualTo, _tail, _tailHash(_good, 1));
        _allowWithRules(address(_venue), PayloadVenue.execute.selector, _rules);
        _enforce();
        assertTrue(_execSafeTx(address(_venue), 0, _good, Operation.Call));
        assertEq(_venue.lastHash(), keccak256(hex"c0ffee"));
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(_venue), PayloadVenue.execute.selector, _tail, _tailHash(_bad, 1))
        );
        _execSafeTx(address(_venue), 0, _bad, Operation.Call);
        bytes memory _trailing = abi.encodePacked(_good, hex"00");
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(_venue), PayloadVenue.execute.selector, _tail, _tailHash(_trailing, 1))
        );
        _execSafeTx(address(_venue), 0, _trailing, Operation.Call);
        bytes memory _late = abi.encodeCall(PayloadVenue.execute, (3000, hex"c0ffee"));
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(_venue), PayloadVenue.execute.selector, uint16(0), bytes32(uint256(3000)))
        );
        _execSafeTx(address(_venue), 0, _late, Operation.Call);
        // `OneOf` over tail hashes: a guardian-trimmable set of reviewed payloads.
        _rules[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, _tail, 0);
        _allowWithRules(address(_venue), PayloadVenue.execute.selector, _rules);
        bytes32[] memory _set = new bytes32[](2);
        _set[0] = _tailHash(_good, 1);
        _set[1] = _tailHash(_bad, 1);
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(_venue), PayloadVenue.execute.selector, _tail, _set);
        assertTrue(_execSafeTx(address(_venue), 0, _bad, Operation.Call));
        vm.prank(council);
        guard.removeAllowedValues(address(safe), address(_venue), PayloadVenue.execute.selector, _tail, _set);
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(_venue), PayloadVenue.execute.selector, _tail, _tailHash(_good, 1))
        );
        _execSafeTx(address(_venue), 0, _good, Operation.Call);
        // A payload shorter than the flagged word is out of range, like any missing word.
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamOutOfRange.selector, address(_venue), PayloadVenue.execute.selector, _tail)
        );
        _execSafeTx(address(_venue), 0, abi.encodePacked(PayloadVenue.execute.selector, uint256(1)), Operation.Call);
    }

    function _tailHash(bytes memory data_, uint256 word_) internal pure returns (bytes32 _h) {
        uint256 _start = 4 + 32 * word_;
        bytes memory _tail = new bytes(data_.length - _start);
        for (uint256 i; i < _tail.length; ++i) _tail[i] = data_[_start + i];
        _h = keccak256(_tail);
    }

    /// @dev A function call to an account without code is refused at call time (live and dry run); a
    ///      plain value transfer to a key keeps working, and the target becomes callable once deployed.
    function test_calldata_to_a_codeless_target_is_refused_at_call_time() public {
        address _future = makeAddr("future");
        _allow(_future, SETTLE);
        _enforce();
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.NotAContract.selector, _future));
        _execSafeTx(_future, 0, _settle(1), Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.NotAContract.selector, _future));
        guard.validateTransaction(address(safe), _future, 0, _settle(1), Operation.Call);
        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), _future, true);
        assertTrue(_execSafeTx(_future, 1 ether, "", Operation.Call), "a transfer to a key is a native-lane call");
        vm.etch(_future, address(protocol).code);
        assertTrue(_execSafeTx(_future, 0, _settle(1), Operation.Call), "callable once deployed");
    }

    /*//////////////////////////////////////////////////////////////
                     R8F: CAPS AND GENERATION-KEYED SETS
    //////////////////////////////////////////////////////////////*/

    function test_selector_and_guardian_caps() public {
        uint256 _max = _H().maxSelectors();
        vm.startPrank(vetro);
        for (uint256 i; i < _max; ++i) {
            guard.allowFunction(address(safe), address(protocol), bytes4(uint32(i + 1)), false, _noRules());
        }
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.TooManyValues.selector, _max));
        guard.allowFunction(address(safe), address(protocol), bytes4(uint32(_max + 1)), false, _noRules());
        // Re-allowing an existing selector is not a new one.
        guard.allowFunction(address(safe), address(protocol), bytes4(uint32(1)), true, _noRules());
        uint256 _maxGuardians = _H().maxGuardians();
        for (uint256 i; i < _maxGuardians; ++i) {
            guard.setGuardian(address(safe), address(uint160(0x10000 + i)), true);
        }
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.TooManyValues.selector, _maxGuardians));
        guard.setGuardian(address(safe), address(uint160(0x20000)), true);
        guard.setGuardian(address(safe), address(uint160(0x10000)), false);
        guard.setGuardian(address(safe), address(uint160(0x20000)), true);
        vm.stopPrank();
    }

    /// @dev Revocation abandons the `OneOf` sets in O(1): no per-member event, the view reads empty, the
    ///      old members never re-activate, and `revokeTarget` at the caps fits in a block.
    function test_revocation_abandons_value_sets_without_iterating() public {
        _allowWithRules(address(token), IERC20.approve.selector, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        bytes32[] memory _values = new bytes32[](_H().maxAllowedValues());
        for (uint256 i; i < _values.length; ++i) _values[i] = bytes32(i + 1);
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(token), IERC20.approve.selector, 0, _values);
        vm.recordLogs();
        uint256 _gas = gasleft();
        vm.prank(guardian);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.revokeFunction(address(safe), address(token), IERC20.approve.selector);
        vm.prank(council);
        guard.revokeFunction(address(safe), address(token), IERC20.approve.selector);
        assertLt(_gas - gasleft(), 150_000, "O(rules), not O(members)");
        assertEq(vm.getRecordedLogs().length, 1, "one FunctionRevoked, no AllowedValueRemoved");
        assertEq(guard.allowedValues(address(safe), address(token), IERC20.approve.selector, 0).length, 0);
        _allowWithRules(address(token), IERC20.approve.selector, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        assertEq(guard.allowedValues(address(safe), address(token), IERC20.approve.selector, 0).length, 0, "fresh generation");
        _enforce();
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(token), IERC20.approve.selector, uint16(0), bytes32(uint256(1)))
        );
        _execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (address(1), 1)), Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
                R8B / R8I: COUNCIL WINDOW REFUNDS, UNWRAPPER HASHES
    //////////////////////////////////////////////////////////////*/

    function test_council_window_refuses_gas_refunds() public {
        vm.prank(council);
        guard.bypass(address(safe), 1 days);
        vm.txGasPrice(1);
        vm.expectRevert(CuratorGuard.GasRefundNotAllowed.selector);
        _execSafeTxWithRefund(address(protocol), 0, _settle(1), Operation.Call, 1, address(0), attacker);
        assertTrue(_execSafeTx(address(protocol), 0, _settle(1), Operation.Call));
    }

    function test_forbidding_a_non_seeded_unwrapper_hash_is_refused() public {
        bytes32 _typo = keccak256("typo");
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.UnwrapperCodehashNotAllowed.selector, _typo));
        guard.setUnwrapperCodehash(_typo, false);
        bytes32 _seeded = _H().codehashV141();
        vm.prank(council);
        guard.setUnwrapperCodehash(_seeded, false);
        assertFalse(guard.isUnwrapperCodehash(_seeded));
        vm.prank(council);
        guard.setUnwrapperCodehash(_seeded, true);
        assertTrue(guard.isUnwrapperCodehash(_seeded));
    }

    /// @dev R8G-4 (runbook interlock, section 7.5): a singleton migration is approved as ONE `MultiSend`
    ///      batch that ends with the re-install of both guards. The re-installs run on the NEW singleton,
    ///      which asks its own ERC-165 question, so the migration and both guard slots land together (an
    ///      incompatible release would revert the whole batch). `setModuleGuard` executed BEFORE the
    ///      migration is a silent success on v1.4.1 with no handler: it spends the approval and sets nothing.
    function test_singleton_migration_is_one_batch_ending_with_the_reinstall() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        Safe150 _singleton150 = new Safe150();
        _H().seedSafeCodehash(address(_singleton150).codehash); // the fixture's locally compiled v1.5.0 build
        SafeMigration _migration = new SafeMigration(address(_singleton150), address(_singleton150), address(protocol));
        bytes32 _moduleGuardSlot = _H().moduleGuardStorageSlot();
        // The trap: the self-call alone, before the migration.
        bytes memory _early = abi.encodeCall(ISafe.setModuleGuard, (address(guard)));
        bytes32 _spent = _approve(address(safe), 0, _early, Operation.Call);
        assertTrue(_execSafeTx(address(safe), 0, _early, Operation.Call), "unknown selector, no handler: silent success");
        assertEq(guard.approvalExpiry(_spent), 0, "approval spent");
        assertEq(vm.load(address(safe), _moduleGuardSlot), bytes32(0), "nothing set");
        // The recipe.
        bytes memory _migrate = abi.encodeCall(SafeMigration.migrateSingleton, ());
        bytes memory _batch = abi.encodeWithSelector(
            multiSend.multiSend.selector,
            abi.encodePacked(
                abi.encodePacked(uint8(1), address(_migration), uint256(0), _migrate.length, _migrate),
                _entry(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(guard)))),
                _entry(address(safe), 0, abi.encodeCall(ISafe.setModuleGuard, (address(guard))))
            )
        );
        _approve(address(multiSend), 0, _batch, Operation.DelegateCall);
        assertTrue(_execSafeTx(address(multiSend), 0, _batch, Operation.DelegateCall));
        assertEq(address(uint160(uint256(vm.load(address(safe), bytes32(0))))), address(_singleton150), "migrated");
        assertEq(_installedGuard(), address(guard));
        assertEq(address(uint160(uint256(vm.load(address(safe), _moduleGuardSlot)))), address(guard), "module path hooked");
        assertTrue(_execSafeTx(address(protocol), 0, _settle(9), Operation.Call), "policy traffic on the new singleton");
        assertEq(protocol.lastAmount(), 9);
    }

    /// @dev R8N-2 / S-2: a guardian is never the zero address, the Safe or the guard itself (a dead seat).
    function test_the_guard_is_never_a_guardian() public {
        vm.startPrank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(guard)));
        guard.setGuardian(address(safe), address(guard), true);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(safe)));
        guard.setGuardian(address(safe), address(safe), true);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(0)));
        guard.setGuardian(address(safe), address(0), true);
        vm.stopPrank();
    }

    /// @dev The transient slot is the literal `safe << 8 | path`: the two paths of one Safe and two
    ///      Safes never share a slot (the nesting check still fires on the same path).
    function test_transient_slots_stay_distinct_per_safe_and_path() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        vm.prank(address(safe));
        guard.checkTransaction(address(protocol), 0, _settle(1), Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0));
        vm.prank(address(safe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.NestedExecution.selector, address(safe)));
        guard.checkTransaction(address(protocol), 0, _settle(1), Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0));
        vm.prank(address(safe));
        guard.checkAfterExecution(bytes32(0), true);
    }
}

/// @dev R8G-2 on Safe v1.5.0: a linked module is fine while this guard is the module guard.
contract CuratorGuardRound8ModuleTest is SafeTxHelper {
    CuratorGuardHarness internal guard;
    Round8Module internal module;
    MockProtocol internal protocol;
    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal curator;

    function setUp() public {
        vm.warp(1_700_000_000);
        (curator, signerPk) = makeAddrAndKey("curator");
        Safe150 _singleton = new Safe150();
        SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        safe = ISafe(address(_proxy));
        guard = new CuratorGuardHarness(0, vetro, council);
        guard.seedSafe(address(safe));
        module = new Round8Module();
        protocol = new MockProtocol();
        vm.startPrank(address(safe));
        safe.enableModule(address(module));
        safe.setGuard(address(guard));
        vm.stopPrank();
        vm.startPrank(vetro);
        guard.enforce(address(safe));
        guard.allowFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules());
        guard.setModuleAllowed(address(safe), address(module), true);
        vm.stopPrank();
    }

    function _noRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _rules) {}

    function test_v150_linked_module_needs_this_guard_as_module_guard() public {
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ModuleNotHooked.selector, address(module)));
        _execSafeTx(address(protocol), 0, _settle, Operation.Call);
        // `setModuleGuard(guard)` is admin-approved (a self-call); the approval lane never reads the configuration.
        bytes memory _hook = abi.encodeCall(ISafe.setModuleGuard, (address(guard)));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(safe), 0, _hook, Operation.Call, 1 days);
        assertTrue(_execSafeTx(address(safe), 0, _hook, Operation.Call));
        assertTrue(_execSafeTx(address(protocol), 0, _settle, Operation.Call), "hooked: policy traffic resumes");
        assertTrue(module.exec(safe, address(protocol), 0, _settle, Operation.Call), "the module path runs under the hook");
        // Another module guard (not this one) counts as unhooked again.
        bytes memory _other = abi.encodeCall(ISafe.setModuleGuard, (address(0)));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(safe), 0, _other, Operation.Call, 1 days);
        assertTrue(_execSafeTx(address(safe), 0, _other, Operation.Call));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ModuleNotHooked.selector, address(module)));
        guard.validateTransaction(address(safe), address(protocol), 0, _settle, Operation.Call);
    }
}

/// @dev R8M-2: pins the suite lacked (a variant that ended the cooldown when the locking key was removed
///      passed every repository test while reopening V2-55): removing the locker, by the admin or the
///      council, does not end the cooldown; a lockdown of a locked Safe restarts it; a lockdown of an
///      unconfigured Safe starts it.
contract CuratorGuardRound8CooldownTest is CuratorGuardTestBase {
    address internal rogue = makeAddr("rogue");

    function setUp() public override {
        super.setUp();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        _enforce();
        _addGuardian(rogue);
        vm.prank(vetro);
        guard.setDeploymentGuardian(guardian, true);
    }

    function test_removing_the_locker_does_not_end_the_cooldown() public {
        vm.prank(rogue);
        guard.lockdown(address(safe));
        vm.warp(block.timestamp + 1 hours);
        bytes memory _cooldown = abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(safe));
        // Admin removal, bundled with a lift (the honest rotation shape): the lift is still refused.
        vm.startPrank(vetro);
        guard.setGuardian(address(safe), rogue, false);
        vm.expectRevert(_cooldown);
        guard.enforce(address(safe));
        vm.stopPrank();
        // Council removal of a deployment-wide locker: same.
        vm.prank(guardian);
        guard.lockdown(address(safe));
        vm.prank(council);
        guard.setDeploymentGuardian(guardian, false);
        vm.prank(vetro);
        vm.expectRevert(_cooldown);
        guard.approveTransaction(
            address(safe), address(0), address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call, 1 days
        );
    }

    function test_a_lockdown_of_a_locked_safe_restarts_the_cooldown() public {
        vm.prank(rogue);
        guard.lockdown(address(safe));
        uint64 _t0 = uint64(block.timestamp);
        vm.warp(_t0 + 1 days); // last second of the first cooldown
        vm.prank(rogue);
        guard.lockdown(address(safe));
        assertEq(guard.lockedAt(address(safe)), _t0 + 1 days);
        vm.warp(_t0 + 1 days + 1);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(safe)));
        guard.enforce(address(safe));
    }

    function test_a_lockdown_of_an_unconfigured_safe_starts_the_cooldown() public {
        address _fresh = makeAddr("fresh-safe");
        assertEq(guard.lockedAt(_fresh), 0);
        vm.prank(guardian);
        guard.lockdown(_fresh);
        assertEq(guard.lockedAt(_fresh), uint64(block.timestamp));
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, _fresh));
        guard.enforce(_fresh);
    }
}
