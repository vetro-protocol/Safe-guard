// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, CuratorGuardHarness, MockProtocol, Reverter} from "test/guards/CuratorGuardTestBase.sol";

/// @dev Succeeds after consuming every unit of gas it was given but a few hundred: the worst venue
///      for the after-hook, which then lives on the 1/64 the Safe kept back (EIP-150) plus 2,500.
contract GreedyVenue {
    uint256 public lastGasAtEntry;

    fallback() external payable {
        lastGasAtEntry = gasleft();
        while (gasleft() > 300) {}
    }
}

/// @title Round 11 (g11c): the gas an EXECUTOR must supply to `execTransaction`, measured, not estimated.
/// @dev   The Safe runs the pre-hook, then `GS010` (`gasleft() >= max(64/63 * safeTxGas, safeTxGas +
///        2500) + 500`), then the inner call with `gasleft() - 2500` (whatever `safeTxGas` says, since
///        `gasPrice` must be 0 under the guard), then the events and the after-hook on what is left.
///        The floor of each shape is found by binary search over the outer call's gas, every probe
///        from one state snapshot with the touched accounts cooled (a real transaction starts cold),
///        and monotonicity is asserted (success at the floor, failure one unit below). Compared
///        against the same Safe without a guard: the guard's share of the floor.
contract CuratorGuardG11cExecutorFloorTest is CuratorGuardTestBase {
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;
    address internal singleton;
    GreedyVenue internal greedy;
    Reverter internal reverter;
    bytes internal settleData;

    function setUp() public override {
        super.setUp();
        settleData = abi.encodeCall(MockProtocol.settleDeposit, (1));
        (, bytes memory _r) = address(safe).staticcall(abi.encodeWithSelector(0xa619486e));
        singleton = abi.decode(_r, (address));
        greedy = new GreedyVenue();
        reverter = new Reverter();
        _enforce();
        _allow(address(protocol), SETTLE);
        _allow(address(greedy), bytes4(0x12345678));
        _allow(address(reverter), bytes4(0x12345678));
        _allowWithRules(address(token), IERC20.approve.selector, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        bytes32[] memory _members = new bytes32[](1);
        _members[0] = _word(address(protocol));
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(token), IERC20.approve.selector, 0, _members);
        _registerUnwrapper(address(multiSendCallOnly));
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    function _cool() internal {
        vm.cool(address(safe));
        vm.cool(singleton);
        vm.cool(address(guard));
        vm.cool(address(protocol));
        vm.cool(address(token));
        vm.cool(address(multiSendCallOnly));
        vm.cool(address(greedy));
        vm.cool(address(reverter));
    }

    function _execData(SafeTx memory t_) internal view returns (bytes memory) {
        return
            abi.encodeCall(
                ISafe.execTransaction,
                (t_.to, t_.value, t_.data, t_.op, t_.safeTxGas, 0, t_.gasPrice, t_.gasToken, payable(t_.refundReceiver), _sign(_txHash(t_)))
            );
    }

    /// @dev One probe: the Safe transaction with exactly `gas_` on the outer call, from a cold state.
    function _try(bytes memory data_, uint256 gas_) internal returns (bool _ok) {
        _cool();
        (_ok, ) = address(safe).call{gas: gas_}(data_);
    }

    /// @dev Smallest outer gas at which the transaction succeeds; asserts failure one unit below and
    ///      success at `hi_` to start with. Every probe is rolled back.
    function _floor(SafeTx memory t_, uint256 hi_) internal returns (uint256) {
        bytes memory _data = _execData(t_);
        uint256 _snap = vm.snapshotState();
        require(_try(_data, hi_), "does not succeed at the search ceiling");
        assertTrue(vm.revertToState(_snap));
        uint256 _lo = 21_000;
        uint256 _hi = hi_;
        while (_lo + 1 < _hi) {
            uint256 _mid = (_lo + _hi) / 2;
            bool _ok = _try(_data, _mid);
            assertTrue(vm.revertToState(_snap));
            if (_ok) _hi = _mid;
            else _lo = _mid;
        }
        assertFalse(_try(_data, _hi - 1), "monotone: fails one unit below the floor");
        assertTrue(vm.revertToState(_snap));
        assertTrue(_try(_data, _hi), "succeeds at the floor");
        assertTrue(vm.revertToState(_snap));
        return _hi;
    }

    function _tx(address to_, bytes memory data_, Operation op_, uint256 safeTxGas_) internal pure returns (SafeTx memory) {
        return SafeTx(to_, 0, data_, op_, safeTxGas_, 0, address(0), address(0));
    }

    /// @dev The same Safe shape without a guard (the reference floor).
    function _unguardedSafe() internal returns (ISafe) {
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        vm.deal(address(_proxy), 1 ether);
        token.mint(address(_proxy), 1_000e6);
        return ISafe(address(_proxy));
    }

    /*//////////////////////////////////////////////////////////////
                                  FLOORS
    //////////////////////////////////////////////////////////////*/

    /// @dev The three shapes the curator sends, guarded and unguarded, `safeTxGas == 0`, cold.
    function test_executor_floor_of_the_policy_shapes_cold() public {
        bytes memory _approve = abi.encodeCall(IERC20.approve, (address(protocol), 1));
        bytes memory _batch = _multiSendCalldata(abi.encodePacked(_entry(address(protocol), 0, settleData), _entry(address(protocol), 0, settleData)));
        uint256 _plain = _floor(_tx(address(protocol), settleData, Operation.Call, 0), 400_000);
        uint256 _oneOf = _floor(_tx(address(token), _approve, Operation.Call, 0), 400_000);
        uint256 _batchFloor = _floor(_tx(address(multiSendCallOnly), _batch, Operation.DelegateCall, 0), 400_000);

        ISafe _guarded = safe;
        safe = _unguardedSafe();
        uint256 _plainRef = _floor(_tx(address(protocol), settleData, Operation.Call, 0), 400_000);
        uint256 _oneOfRef = _floor(_tx(address(token), _approve, Operation.Call, 0), 400_000);
        uint256 _batchRef = _floor(_tx(address(multiSendCallOnly), _batch, Operation.DelegateCall, 0), 400_000);
        safe = _guarded;

        emit log_named_uint("floor: plain allowlisted call, guarded (1 owner, cold)", _plain);
        emit log_named_uint("floor: plain call, unguarded", _plainRef);
        emit log_named_uint("  => guard's share", _plain - _plainRef);
        emit log_named_uint("floor: approve with OneOf, guarded", _oneOf);
        emit log_named_uint("floor: approve, unguarded", _oneOfRef);
        emit log_named_uint("  => guard's share", _oneOf - _oneOfRef);
        emit log_named_uint("floor: settlement batch (2 entries), guarded", _batchFloor);
        emit log_named_uint("floor: batch, unguarded", _batchRef);
        emit log_named_uint("  => guard's share", _batchFloor - _batchRef);
        assertLt(_plain - _plainRef, 110_000, "guard's share of the floor, plain");
        assertLt(_batchFloor - _batchRef, 130_000, "guard's share of the floor, batch");
    }

    /// @dev The approval path spends a storage record (SSTORE to zero, refunded only at the end of the
    ///      transaction) and writes the transient sentinel: its floor against the policy path's.
    function test_executor_floor_of_the_approval_and_window_paths_cold() public {
        bytes memory _self = abi.encodeCall(ISafe.setGuard, (address(guard))); // a self-call only an approval or window admits
        _approve(address(safe), 0, _self, Operation.Call);
        uint256 _approvalFloor = _floor(_tx(address(safe), _self, Operation.Call, 0), 400_000);
        emit log_named_uint("floor: approved self-call (SSTORE spend + sentinel), cold", _approvalFloor);
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        uint256 _councilFloor = _floor(_tx(address(protocol), settleData, Operation.Call, 0), 400_000);
        emit log_named_uint("floor: plain call inside a council window, cold", _councilFloor);
        vm.prank(vetro);
        guard.enforce(address(safe));
        vm.prank(vetro);
        guard.bypass(address(safe), 1 hours);
        uint256 _adminFloor = _floor(_tx(address(protocol), settleData, Operation.Call, 0), 400_000);
        emit log_named_uint("floor: plain call inside an admin window, cold", _adminFloor);
        assertLt(_councilFloor, _approvalFloor + 50_000);
    }

    /// @dev `safeTxGas != 0` under the guard (`gasPrice == 0`): the inner call still receives
    ///      `gasleft() - 2500`; `safeTxGas` only sets the GS010 floor checked AFTER the pre-hook, so the
    ///      executor's floor grows by the pre-hook plus `max(64/63 * S, S + 2500) + 500`.
    function test_executor_floor_with_safeTxGas_is_the_GS010_floor_after_the_pre_hook() public {
        uint256 _zero = _floor(_tx(address(protocol), settleData, Operation.Call, 0), 400_000);
        uint256 _s100k = _floor(_tx(address(protocol), settleData, Operation.Call, 100_000), 600_000);
        uint256 _s1m = _floor(_tx(address(protocol), settleData, Operation.Call, 1_000_000), 2_000_000);
        emit log_named_uint("floor: safeTxGas = 0", _zero);
        emit log_named_uint("floor: safeTxGas = 100k (GS010: S + 2500 + 500)", _s100k);
        emit log_named_uint("floor: safeTxGas = 1M (GS010: 64/63 * S + 500)", _s1m);
        // GS010 is checked after the pre-hook ran: the floor exceeds the formula by at least the pre-hook.
        assertGt(_s100k, uint256(100_000 + 3_000 + 20_000), "pre-hook on top of GS010");
        uint256 _gs010 = (uint256(1_000_000) * 64) / 63 + 500;
        assertGt(_s1m, _gs010 + 20_000, "pre-hook on top of GS010");
        assertLt(_s1m, _gs010 + 120_000, "nothing else on top");
    }

    /// @dev A venue that consumes everything it is given but succeeds: the after-hook runs on the 1/64
    ///      the Safe kept back, so the floor is about 64x the after-hook (plus the events). Measured on
    ///      the one-owner fixture; the live Safe's five owners raise the after-hook, hence the floor.
    function test_executor_floor_of_a_greedy_venue_is_64x_the_after_hook() public {
        bytes memory _data = abi.encodeWithSelector(0x12345678);
        uint256 _floorGreedy = _floor(_tx(address(greedy), _data, Operation.Call, 0), 4_000_000);
        emit log_named_uint("floor: greedy venue (consumes all but 300), safeTxGas = 0, 1 owner", _floorGreedy);
        // At the floor the venue saw nearly everything: the executor cannot bound it under the guard.
        bytes memory _exec = _execData(_tx(address(greedy), _data, Operation.Call, 0));
        uint256 _snap = vm.snapshotState();
        assertTrue(_try(_exec, _floorGreedy));
        uint256 _seen = greedy.lastGasAtEntry();
        assertTrue(vm.revertToState(_snap));
        emit log_named_uint("  gas the venue received at the floor", _seen);
        assertGt(_seen, (_floorGreedy * 9) / 10, "the venue received nearly all of it");
        // A non-zero safeTxGas does not bound the venue either (gasPrice is 0, so the inner call still
        // gets `gasleft() - 2500`): the floor is max(GS010 floor, the 64x rule), and the venue again
        // receives nearly all of it.
        uint256 _floorGreedyS = _floor(_tx(address(greedy), _data, Operation.Call, 1_000_000), 6_000_000);
        emit log_named_uint("floor: greedy venue, safeTxGas = 1M (GS010 floor 1,016,373 does not bind)", _floorGreedyS);
        _exec = _execData(_tx(address(greedy), _data, Operation.Call, 1_000_000));
        _snap = vm.snapshotState();
        assertTrue(_try(_exec, _floorGreedyS));
        uint256 _seenS = greedy.lastGasAtEntry();
        assertTrue(vm.revertToState(_snap));
        emit log_named_uint("  gas the venue received at that floor", _seenS);
        assertGt(_seenS, 1_000_000, "safeTxGas never bounds the venue under the guard");
        assertGt(_floorGreedyS + 1_000, _floorGreedy, "the 64x rule binds in both cases");
        // Direct after-hook cost for the ratio.
        vm.prank(address(safe));
        guard.checkTransaction(address(protocol), 0, settleData, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", curator);
        vm.prank(address(safe));
        uint256 _g = gasleft();
        guard.checkAfterExecution(bytes32(0), true);
        _g -= gasleft();
        emit log_named_uint("  after-hook (direct, warm, 1 owner)", _g);
        emit log_named_uint("  => floor / after-hook", _floorGreedy / _g);
        assertGt(_floorGreedy, 40 * _g);
        assertLt(_floorGreedy, 100 * _g);
    }

    /// @dev Failure semantics under a non-zero `safeTxGas`: an inner revert is tolerated by the Safe
    ///      (`ExecutionFailure`) and the policy path reports it; an approved execution that fails
    ///      reverts the whole transaction (`ApprovedExecutionFailed`) and keeps the approval. With
    ///      `safeTxGas == 0` the Safe itself reverts (`GS013`) before the after-hook.
    function test_failure_semantics_with_and_without_safeTxGas() public {
        bytes memory _data = abi.encodeWithSelector(0x12345678);
        vm.expectRevert(bytes("GS013"));
        _execSafeTx(address(reverter), 0, _data, Operation.Call);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(safe), _txHash(_tx(address(reverter), _data, Operation.Call, 50_000)), 0, CuratorGuard.Outcome.Policy);
        assertFalse(_execSafeTxWithGas(address(reverter), 0, _data, Operation.Call, 50_000), "tolerated: ExecutionFailure");
        bytes32 _id = _approve(address(reverter), 0, _data, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ApprovedExecutionFailed.selector, address(safe)));
        _execSafeTxWithGas(address(reverter), 0, _data, Operation.Call, 50_000);
        assertGt(guard.approvalExpiry(_id), 0, "approval kept");
    }

    /// @dev The owner count at which a greedy venue's 64x floor crosses EIP-7825's 16,777,216 is far
    ///      beyond any custody Safe: the after-hook slope per owner (g10f: about 545) puts it near 440
    ///      owners. Pinned by measuring the after-hook with 50 owners and extrapolating.
    function test_greedy_floor_crosses_the_transaction_cap_only_at_hundreds_of_owners() public {
        while (safe.getOwners().length < 50) {
            address _owner = makeAddr(string.concat("o", vm.toString(safe.getOwners().length)));
            vm.prank(address(safe));
            safe.addOwnerWithThreshold(_owner, 1);
        }
        vm.prank(address(safe));
        guard.checkTransaction(address(protocol), 0, settleData, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", curator);
        vm.prank(address(safe));
        uint256 _g = gasleft();
        guard.checkAfterExecution(bytes32(0), true);
        _g -= gasleft();
        emit log_named_uint("after-hook, 50 owners, warm", _g);
        uint256 _ownersAtCap = 50 + ((16_777_216 / 64 - _g) * 49) / (_g - 17_000);
        emit log_named_uint("  => owners at which 64 x after-hook exceeds 16,777,216 (extrapolated)", _ownersAtCap);
        assertGt(_ownersAtCap, 200);
    }
}
