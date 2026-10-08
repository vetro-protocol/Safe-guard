// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @title Gas profile of the guard (documents the per-transaction overhead; bounds catch regressions)
contract CuratorGuardGasTest is CuratorGuardTestBase {
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;

    function _unguardedSafe(uint256 owners_) internal returns (ISafe) {
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        address[] memory _owners = new address[](owners_);
        _owners[0] = curator;
        for (uint256 i = 1; i < owners_; ++i) _owners[i] = makeAddr(string.concat("o", vm.toString(i)));
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        _H().seedSafe(address(_proxy)); // seeded: the guard pins canonical Safe code (V2-85)
        return ISafe(address(_proxy));
    }

    function _measure(address to_, bytes memory data_, Operation op_) internal returns (uint256 _gas) {
        _gas = gasleft();
        _execSafeTx(to_, 0, data_, op_);
        _gas -= gasleft();
    }

    function test_gas_overhead_of_the_guard_per_transaction() public {
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        // Unguarded reference (1 owner), warm it up first so both measurements are "second call".
        ISafe _guarded = safe;
        safe = _unguardedSafe(1);
        _measure(address(protocol), _settle, Operation.Call);
        uint256 _ref1 = _measure(address(protocol), _settle, Operation.Call);

        safe = _guarded;
        _enforce();
        _allow(address(protocol), SETTLE);
        _measure(address(protocol), _settle, Operation.Call);
        uint256 _g1 = _measure(address(protocol), _settle, Operation.Call);
        emit log_named_uint("execTransaction, 1 owner, no guard", _ref1);
        emit log_named_uint("execTransaction, 1 owner, guard Enforced (no rules)", _g1);
        emit log_named_uint("  => guard overhead (1 owner)", _g1 - _ref1);
        assertLt(_g1 - _ref1, 80_000, "guard overhead regression");

        // Direct hook costs (pranked as the Safe), split pre / post / dry-run.
        vm.prank(address(safe));
        uint256 _gas = gasleft();
        guard.checkTransaction(address(protocol), 0, _settle, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", curator);
        _gas -= gasleft();
        emit log_named_uint("checkTransaction (snapshot + validate)", _gas);
        vm.prank(address(safe));
        _gas = gasleft();
        guard.checkAfterExecution(bytes32(0), true);
        _gas -= gasleft();
        emit log_named_uint("checkAfterExecution (digest recompute)", _gas);
        _gas = gasleft();
        guard.validateTransaction(address(safe), address(protocol), 0, _settle, Operation.Call);
        _gas -= gasleft();
        emit log_named_uint("validateTransaction (validate only, no snapshot)", _gas);

        // Approval path (no snapshot at all).
        _approve(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (2)), Operation.Call);
        uint256 _ga = _measure(address(protocol), abi.encodeCall(MockProtocol.settleDeposit, (2)), Operation.Call);
        emit log_named_uint("execTransaction via approval", _ga);

        // Bypass (nothing but the approval lookup).
        vm.prank(vetro);
        guard.bypass(address(safe), 1 days);
        uint256 _gb = _measure(address(protocol), _settle, Operation.Call);
        emit log_named_uint("execTransaction in Bypass", _gb);
    }

    function test_gas_overhead_scales_with_owner_count() public {
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        uint256[3] memory _counts = [uint256(1), 3, 7];
        for (uint256 i; i < 3; ++i) {
            safe = _unguardedSafe(_counts[i]);
            _measure(address(protocol), _settle, Operation.Call);
            uint256 _ref = _measure(address(protocol), _settle, Operation.Call);
            vm.prank(address(safe));
            safe.setGuard(address(guard));
            vm.startPrank(vetro);
            guard.enforce(address(safe));
            guard.allowFunction(address(safe), address(protocol), SETTLE, false, _noRules());
            vm.stopPrank();
            _measure(address(protocol), _settle, Operation.Call);
            uint256 _g = _measure(address(protocol), _settle, Operation.Call);
            emit log_named_uint(string.concat("owners=", vm.toString(_counts[i]), " guard overhead"), _g - _ref);
        }
    }
}
