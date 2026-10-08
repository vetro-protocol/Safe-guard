// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @title Round 11 (g11c): the admin and narrowing operations at every cap against the per-transaction
///        gas limit (EIP-7825: 16,777,216 since Fusaka; the sync task refuses a batch above 12M).
/// @dev   g10f measured the HOOKS at the caps (rules, batch entries, owners); this suite measures what
///        the guard's own mutators cost at the caps, cold (`vm.cool` on the guard before each call):
///        `addAllowedValues` / `removeAllowedValues` / `clearAllowedValues` at 128 members, a re-allow
///        that drops one, two (the lint's 256-per-function cap) and sixteen (the on-chain shape) full
///        sets, a target at 32 selectors x 16 rules (`allowFunctions`, `revokeTarget`), 32 guardians,
///        and a shipped-policy-shaped initial sync as one timelock batch with its per-call overhead.
contract CuratorGuardG11cCapsTest is CuratorGuardTestBase {
    uint256 internal constant TX_GAS_CAP = 16_777_216; // EIP-7825
    uint256 internal constant SYNC_REFUSE = 12_000_000; // tasks/curator-guard.ts BATCH_GAS_REFUSE
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;
    bytes internal settleData;

    function setUp() public override {
        super.setUp();
        settleData = abi.encodeCall(MockProtocol.settleDeposit, (1));
        _enforce();
    }

    function _members(uint256 n_, uint256 seed_) internal pure returns (bytes32[] memory _m) {
        _m = new bytes32[](n_);
        for (uint256 i; i < n_; ++i) _m[i] = bytes32(seed_ + i + 1);
    }

    function _oneOfRules(uint16 n_) internal pure returns (CuratorGuardPolicy.ParamRule[] memory _rules) {
        _rules = new CuratorGuardPolicy.ParamRule[](n_);
        for (uint16 w; w < n_; ++w) _rules[w] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, w, 0);
    }

    /// @dev A function with `n_` OneOf rules, each set filled to the cap.
    function _fillSets(uint16 n_) internal {
        vm.prank(vetro);
        guard.allowFunction(address(safe), address(protocol), SETTLE, false, _oneOfRules(n_));
        for (uint16 w; w < n_; ++w) {
            vm.prank(vetro);
            guard.addAllowedValues(address(safe), address(protocol), SETTLE, w, _members(128, uint256(w) * 1000));
        }
    }

    function _coldCall(address from_, bytes memory data_) internal returns (uint256 _gas) {
        vm.cool(address(guard));
        vm.prank(from_);
        _gas = gasleft();
        (bool _ok, bytes memory _ret) = address(guard).call(data_);
        _gas -= gasleft();
        if (!_ok) {
            assembly ("memory-safe") {
                revert(add(_ret, 0x20), mload(_ret))
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                           ONEOF SETS AT THE CAP
    //////////////////////////////////////////////////////////////*/

    function test_oneOf_set_operations_at_128_members_cold() public {
        vm.prank(vetro);
        guard.allowFunction(address(safe), address(protocol), SETTLE, false, _oneOfRules(1));
        uint256 _add = _coldCall(vetro, abi.encodeCall(guard.addAllowedValues, (address(safe), address(protocol), SETTLE, 0, _members(128, 0))));
        emit log_named_uint("addAllowedValues, 128 fresh members, cold", _add);
        emit log_named_uint("  task heuristic 60k + 48k x 128", 60_000 + 48_000 * 128);
        uint256 _remove = _coldCall(vetro, abi.encodeCall(guard.removeAllowedValues, (address(safe), address(protocol), SETTLE, 0, _members(128, 0))));
        emit log_named_uint("removeAllowedValues, 128 members, cold (pre-refund)", _remove);
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(protocol), SETTLE, 0, _members(128, 0));
        uint256 _clear = _coldCall(vetro, abi.encodeCall(guard.clearAllowedValues, (address(safe), address(protocol), SETTLE, 0)));
        emit log_named_uint("clearAllowedValues, 128 members, cold (pre-refund)", _clear);
        emit log_named_uint("  => per member", _clear / 128);
        assertLt(_add, TX_GAS_CAP);
        assertLt(_clear, SYNC_REFUSE);
        // The 129th member is refused after the inserts: the whole call reverts.
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(protocol), SETTLE, 0, _members(128, 0));
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.TooManyValues.selector, 129));
        guard.addAllowedValues(address(safe), address(protocol), SETTLE, 0, _members(1, 5000));
    }

    /// @dev A re-allow that drops `k` full sets clears `128 k` members in ONE call: one set (what the
    ///      `MAX_ALLOWED_VALUES` NatSpec promises), two (the lint's joint cap of 256 per function) and
    ///      sixteen (the on-chain shape nothing but the lint prevents) against the transaction cap.
    function test_reallow_dropping_full_sets_against_the_transaction_cap() public {
        uint256 _snap = vm.snapshotState();
        _fillSets(1);
        uint256 _one = _coldCall(vetro, abi.encodeCall(guard.allowFunction, (address(safe), address(protocol), SETTLE, false, _noRules())));
        assertTrue(vm.revertToState(_snap));
        _fillSets(2);
        uint256 _two = _coldCall(vetro, abi.encodeCall(guard.allowFunction, (address(safe), address(protocol), SETTLE, false, _noRules())));
        assertTrue(vm.revertToState(_snap));
        _fillSets(16);
        uint256 _sixteen = _coldCall(vetro, abi.encodeCall(guard.allowFunction, (address(safe), address(protocol), SETTLE, false, _noRules())));
        assertTrue(vm.revertToState(_snap));
        emit log_named_uint("re-allow dropping 1 set of 128 (the NatSpec case), cold", _one);
        emit log_named_uint("re-allow dropping 2 sets of 128 (lint cap 256 / function), cold", _two);
        emit log_named_uint("re-allow dropping 16 sets of 128 (on-chain cap 2048 members), cold", _sixteen);
        emit log_named_uint("  EIP-7825 transaction cap", TX_GAS_CAP);
        assertLt(_one, SYNC_REFUSE, "one set: executable, under the sync gate");
        assertLt(_two, SYNC_REFUSE, "lint cap: executable, under the sync gate");
        assertGt(_sixteen, TX_GAS_CAP, "the on-chain shape cannot execute in one transaction");
        // The escape hatches: sixteen separate `clearAllowedValues` (narrowing, any responder), then the
        // re-allow; or `revokeFunction` (abandons every set in O(1)) and a fresh allow.
        _fillSets(16);
        uint256 _worst;
        for (uint16 w; w < 16; ++w) {
            uint256 _g = _coldCall(council, abi.encodeCall(guard.clearAllowedValues, (address(safe), address(protocol), SETTLE, w)));
            if (_g > _worst) _worst = _g;
        }
        uint256 _after = _coldCall(vetro, abi.encodeCall(guard.allowFunction, (address(safe), address(protocol), SETTLE, false, _noRules())));
        emit log_named_uint("  escape 1: worst single clearAllowedValues of the sixteen", _worst);
        emit log_named_uint("  escape 1: the re-allow once the sets are empty", _after);
        assertLt(_worst, SYNC_REFUSE);
        assertTrue(vm.revertToState(_snap));
        _fillSets(16);
        uint256 _revoke = _coldCall(council, abi.encodeCall(guard.revokeFunction, (address(safe), address(protocol), SETTLE)));
        uint256 _fresh = _coldCall(vetro, abi.encodeCall(guard.allowFunction, (address(safe), address(protocol), SETTLE, false, _noRules())));
        emit log_named_uint("  escape 2: revokeFunction with sixteen full sets (O(1))", _revoke);
        emit log_named_uint("  escape 2: the fresh allow", _fresh);
        assertLt(_revoke, 200_000);
    }

    /*//////////////////////////////////////////////////////////////
                              TARGET AT THE CAP
    //////////////////////////////////////////////////////////////*/

    /// @dev 32 selectors x 16 rules on one target in one `allowFunctions` (each rule is two fresh
    ///      storage slots: the cap shape exceeds one transaction and must be split over syncs, which
    ///      the task's 12M gate enforces); one `allowFunction` with 16 rules; `revokeTarget` deletes
    ///      the 32 records (each with 16 rules); `lockdownAndRevoke` is O(1).
    function test_target_at_32_selectors_x_16_rules() public {
        CuratorGuardPolicy.FunctionSpec[] memory _specs = new CuratorGuardPolicy.FunctionSpec[](32);
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](16);
        for (uint16 w; w < 16; ++w) _rules[w] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualTo, w, bytes32(uint256(w)));
        for (uint256 i; i < 32; ++i) _specs[i] = CuratorGuardPolicy.FunctionSpec(address(protocol), bytes4(uint32(0x1000 + i)), false, _rules);
        uint256 _snap = vm.snapshotState();
        uint256 _one = _coldCall(vetro, abi.encodeCall(guard.allowFunction, (address(safe), address(protocol), bytes4(uint32(0x1000)), false, _rules)));
        assertTrue(vm.revertToState(_snap));
        uint256 _allow = _coldCall(vetro, abi.encodeCall(guard.allowFunctions, (address(safe), _specs)));
        emit log_named_uint("allowFunction: one selector with 16 rules, cold", _one);
        emit log_named_uint("allowFunctions: 32 selectors x 16 rules on one target, cold", _allow);
        emit log_named_uint("  EIP-7825 transaction cap", TX_GAS_CAP);
        assertLt(_one, SYNC_REFUSE, "one function at MAX_RULES fits");
        assertGt(_allow, TX_GAS_CAP, "the per-target cap shape does not fit in one transaction: split over syncs");
        // The 33rd selector is refused.
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.TooManyValues.selector, 32));
        guard.allowFunction(address(safe), address(protocol), bytes4(uint32(0x2000)), false, _noRules());
        uint256 _revoke = _coldCall(council, abi.encodeCall(guard.revokeTarget, (address(safe), address(protocol))));
        emit log_named_uint("revokeTarget: 32 functions x 16 rules, cold (pre-refund)", _revoke);
        assertEq(guard.targets(address(safe)).length, 0);
        vm.prank(vetro);
        guard.allowFunctions(address(safe), _specs);
        uint256 _lock = _coldCall(council, abi.encodeCall(guard.lockdownAndRevoke, (address(safe))));
        emit log_named_uint("lockdownAndRevoke (O(1) whatever the policy), cold", _lock);
        assertLt(_revoke, SYNC_REFUSE, "revokeTarget at the cap fits under the sync gate");
        assertLt(_lock, 100_000);
    }

    /*//////////////////////////////////////////////////////////////
                              32 GUARDIANS
    //////////////////////////////////////////////////////////////*/

    /// @dev Guardians are never read by the hooks: with 32 of them both hooks cost exactly what they
    ///      cost with none; the 33rd seat is refused.
    function test_32_guardians_do_not_touch_the_hooks() public {
        _allow(address(protocol), SETTLE);
        (uint256 _pre0, uint256 _post0) = _hookGas();
        for (uint256 i; i < 32; ++i) _addGuardian(makeAddr(string.concat("guardian-", vm.toString(i))));
        assertEq(guard.guardians(address(safe)).length, 32);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.TooManyValues.selector, 32));
        guard.setGuardian(address(safe), makeAddr("guardian-33"), true);
        (uint256 _pre32, uint256 _post32) = _hookGas();
        emit log_named_uint("pre-hook, 0 guardians (warm)", _pre0);
        emit log_named_uint("pre-hook, 32 guardians (warm)", _pre32);
        emit log_named_uint("after-hook, 0 guardians", _post0);
        emit log_named_uint("after-hook, 32 guardians", _post32);
        assertEq(_pre0, _pre32, "guardians never read by the pre-hook");
        assertEq(_post0, _post32, "guardians never read by the after-hook");
        // A guardian's own actions at the cap are O(1): lockdown and a single revoke.
        address _last = makeAddr("guardian-31");
        uint256 _g = _coldCall(_last, abi.encodeCall(guard.lockdown, (address(safe))));
        emit log_named_uint("lockdown by the 32nd guardian, cold", _g);
        assertLt(_g, 60_000);
    }

    function _hookGas() internal returns (uint256 _pre, uint256 _post) {
        vm.prank(address(safe));
        guard.checkTransaction(address(protocol), 0, settleData, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", curator);
        vm.prank(address(safe));
        guard.checkAfterExecution(bytes32(0), true);
        vm.prank(address(safe));
        _pre = gasleft();
        guard.checkTransaction(address(protocol), 0, settleData, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", curator);
        _pre -= gasleft();
        vm.prank(address(safe));
        _post = gasleft();
        guard.checkAfterExecution(bytes32(0), true);
        _post -= gasleft();
    }

    /*//////////////////////////////////////////////////////////////
                      A SYNC BATCH THROUGH THE TIMELOCK
    //////////////////////////////////////////////////////////////*/

    /// @dev The shipped policy's initial sync as one `executeBatch` (30 `allowFunction`, 5
    ///      `addAllowedValues` of one member, 3 unwrappers, the handler requirement, `enforce`: 40 calls,
    ///      each wrapped in `executeBefore`) through a real `CuratorGuardTimelock`, cold, against the
    ///      caps; and the per-call cost of the wrapper and the timelock loop.
    function test_initial_sync_of_the_shipped_policy_shape_as_one_timelock_batch() public {
        address[] memory _p = new address[](1);
        _p[0] = makeAddr("proposer");
        address[] memory _c = new address[](1);
        _c[0] = makeAddr("veto");
        CuratorGuardTimelock _tl = new CuratorGuardTimelock(2 days, _p, _c);
        CuratorGuard _g = new CuratorGuardHarness(0, address(_tl), council);
        CuratorGuardHarness(address(_g)).seedSafe(address(safe));
        CuratorGuardHarness(address(_g)).seedCodehash(address(multiSendCallOnly).codehash);
        address _safe = address(safe);
        bytes[] memory _payloads = new bytes[](40);
        uint256 _n;
        uint64 _deadline = uint64(block.timestamp + 16 days);
        for (uint256 v; v < 5; ++v) {
            address _vault = address(uint160(0x500000 + v));
            vm.etch(_vault, address(protocol).code);
            for (uint256 s; s < 5; ++s) {
                _payloads[_n++] = abi.encodeCall(_g.executeBefore, (_deadline, abi.encodeCall(_g.allowFunction, (_safe, _vault, bytes4(uint32(0x3000 + s)), false, _noRules()))));
            }
            address _asset = address(uint160(0x600000 + v));
            vm.etch(_asset, address(token).code);
            _payloads[_n++] = abi.encodeCall(_g.executeBefore, (_deadline, abi.encodeCall(_g.allowFunction, (_safe, _asset, IERC20.approve.selector, false, _oneOfRules(1)))));
            _payloads[_n++] = abi.encodeCall(_g.executeBefore, (_deadline, abi.encodeCall(_g.addAllowedValues, (_safe, _asset, IERC20.approve.selector, 0, _members(1, v)))));
        }
        for (uint256 u; u < 3; ++u) {
            address _unwrapper = address(uint160(0x700000 + u));
            vm.etch(_unwrapper, address(multiSendCallOnly).code);
            _payloads[_n++] = abi.encodeCall(_g.executeBefore, (_deadline, abi.encodeCall(_g.setMultiSendUnwrapper, (_safe, _unwrapper, true))));
        }
        _payloads[_n++] = abi.encodeCall(_g.executeBefore, (_deadline, abi.encodeCall(_g.setRequiredFallbackHandler, (_safe, address(0), true))));
        _payloads[_n++] = abi.encodeCall(_g.executeBefore, (_deadline, abi.encodeCall(_g.enforce, (_safe))));
        assertEq(_n, 40);
        address[] memory _targets = new address[](40);
        uint256[] memory _values = new uint256[](40);
        for (uint256 i; i < 40; ++i) _targets[i] = address(_g);
        vm.prank(_p[0]);
        _tl.scheduleBatch(_targets, _values, _payloads, bytes32(0), bytes32("sync"), 2 days);
        vm.warp(block.timestamp + 2 days);
        vm.cool(address(_g));
        vm.cool(address(_tl));
        uint256 _gas = gasleft();
        _tl.executeBatch(_targets, _values, _payloads, bytes32(0), bytes32("sync"));
        _gas -= gasleft();
        emit log_named_uint("initial sync of the shipped policy shape, 40 wrapped calls, executeBatch, cold", _gas);
        assertEq(_g.targets(_safe).length, 10);
        assertEq(uint8(_g.mode(_safe)), uint8(CuratorGuardPolicy.Mode.Enforced));
        assertLt(_gas, SYNC_REFUSE);
        // Per-call overhead of the wrapper and the loop: the same 40 calls made directly, cold.
        CuratorGuard _direct = new CuratorGuardHarness(0, vetro, council);
        CuratorGuardHarness(address(_direct)).seedSafe(address(safe));
        CuratorGuardHarness(address(_direct)).seedCodehash(address(multiSendCallOnly).codehash);
        vm.cool(address(_direct));
        uint256 _sum;
        for (uint256 i; i < 40; ++i) {
            (, bytes memory _inner) = abi.decode(_slice(_payloads[i]), (uint64, bytes));
            vm.prank(vetro);
            uint256 _one = gasleft();
            (bool _ok, ) = address(_direct).call(_inner);
            _one -= gasleft();
            assertTrue(_ok);
            _sum += _one;
        }
        emit log_named_uint("the same 40 calls made directly by the admin, cold", _sum);
        emit log_named_uint("  => wrapper + timelock overhead per call", (_gas - _sum) / 40);
    }

    function _slice(bytes memory wrapped_) internal pure returns (bytes memory _args) {
        _args = new bytes(wrapped_.length - 4);
        for (uint256 i; i < _args.length; ++i) _args[i] = wrapped_[i + 4];
    }

    /*//////////////////////////////////////////////////////////////
                         DEEP BATCHES THROUGH THE SAFE
    //////////////////////////////////////////////////////////////*/

    /// @dev Entries per settlement batch that fit in one transaction through the real Safe: the whole
    ///      `execTransaction` (calldata, hooks, the venue) measured at 10 and 100 entries, the slope
    ///      extrapolated to the EIP-7825 cap.
    function test_batch_entries_that_fit_in_one_transaction() public {
        _allow(address(protocol), SETTLE);
        _registerUnwrapper(address(multiSendCallOnly));
        uint256 _g10 = _execBatch(10);
        uint256 _g100 = _execBatch(100);
        uint256 _slope = (_g100 - _g10) / 90;
        uint256 _fit = 100 + (TX_GAS_CAP - _g100) / _slope;
        emit log_named_uint("execTransaction, settlement batch of 10 entries (warm)", _g10);
        emit log_named_uint("execTransaction, settlement batch of 100 entries (warm)", _g100);
        emit log_named_uint("  => per entry (hook + venue + calldata)", _slope);
        emit log_named_uint("  => entries that fit under 16,777,216", _fit);
        assertGt(_fit, 500);
    }

    function _execBatch(uint256 n_) internal returns (uint256 _gas) {
        bytes memory _packed;
        for (uint256 i; i < n_; ++i) _packed = abi.encodePacked(_packed, _entry(address(protocol), 0, settleData));
        bytes memory _data = _multiSendCalldata(_packed);
        _execSafeTx(address(multiSendCallOnly), 0, _data, Operation.DelegateCall); // warm
        _gas = gasleft();
        _execSafeTx(address(multiSendCallOnly), 0, _data, Operation.DelegateCall);
        _gas -= gasleft();
    }
}
