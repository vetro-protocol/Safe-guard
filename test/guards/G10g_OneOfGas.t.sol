// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @dev g10g evidence test: the per-member cost of iterating a committed `OneOf` set, which the
///      `FunctionPermission.generation` NatSpec puts at "about 14k gas each on committed storage"
///      (`clearAllowedValues` and a re-allow that drops the `OneOf` rule iterate; `revokeFunction` does not).
contract CuratorGuardG10gOneOfGas is CuratorGuardTestBase {
    uint16 internal constant WORD = 1;

    function _oneOfRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _rules) {
        _rules = new CuratorGuardPolicy.ParamRule[](1);
        _rules[0] = CuratorGuardPolicy.ParamRule({kind: CuratorGuardPolicy.RuleKind.OneOf, wordIndex: WORD, value: 0});
    }

    function _seed(uint256 n_) internal {
        _allowWithRules(address(protocol), MockProtocol.deposit.selector, _oneOfRules());
        bytes32[] memory _values = new bytes32[](n_);
        for (uint256 i; i < n_; ++i) _values[i] = bytes32(uint256(0x1000 + i));
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(protocol), MockProtocol.deposit.selector, WORD, _values);
        assertEq(guard.allowedValues(address(safe), address(protocol), MockProtocol.deposit.selector, WORD).length, n_);
    }

    function test_g10g_clearAllowedValues_cost_per_member() public {
        _seed(32);
        vm.prank(vetro);
        uint256 _before = gasleft();
        guard.clearAllowedValues(address(safe), address(protocol), MockProtocol.deposit.selector, WORD);
        uint256 _used = _before - gasleft();
        emit log_named_uint("clearAllowedValues, 32 members, total gas", _used);
        emit log_named_uint("per member", _used / 32);
        assertEq(guard.allowedValues(address(safe), address(protocol), MockProtocol.deposit.selector, WORD).length, 0);
    }

    function test_g10g_reallow_dropping_the_oneOf_rule_cost_per_member() public {
        _seed(32);
        vm.prank(vetro);
        uint256 _before = gasleft();
        guard.allowFunction(address(safe), address(protocol), MockProtocol.deposit.selector, false, _noRules());
        uint256 _used = _before - gasleft();
        emit log_named_uint("re-allow without the OneOf rule, 32 members, total gas", _used);
        emit log_named_uint("per member", _used / 32);
    }

    function test_g10g_revokeFunction_does_not_iterate() public {
        _seed(32);
        vm.prank(vetro);
        uint256 _before = gasleft();
        guard.revokeFunction(address(safe), address(protocol), MockProtocol.deposit.selector);
        uint256 _used = _before - gasleft();
        emit log_named_uint("revokeFunction with 32 members, total gas", _used);
        assertLt(_used, 100_000);
    }
}
