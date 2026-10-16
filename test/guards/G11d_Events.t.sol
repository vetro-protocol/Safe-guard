// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardHarness, CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @title Round 11 (g11d): the six events no suite asserted.
/// @notice Docs section 7.7 tells an indexer how to apply `AllowedValueAdded` / `AllowedValueRemoved`,
///         `FunctionRevoked`, `ModuleUpdated`, `RequiredFallbackHandlerUpdated` and
///         `UnwrapperCodehashUpdated`; before this suite none of the six was asserted with its payload
///         by any test (`G11d_Traceability` fails without it). Every test passes on the shipped code.
contract G11dEventsTest is CuratorGuardTestBase {
    bytes32 internal constant ADDED_SIG = keccak256("AllowedValueAdded(address,address,bytes4,uint16,bytes32)");
    bytes32 internal constant REMOVED_SIG = keccak256("AllowedValueRemoved(address,address,bytes4,uint16,bytes32)");
    bytes32 internal constant ALLOWED_SIG = keccak256("FunctionAllowed(address,address,bytes4,bool,(uint8,uint16,bytes32)[])");
    bytes32 internal constant REVOKED_SIG = keccak256("FunctionRevoked(address,address,bytes4)");
    bytes32 internal constant CODEHASH_SIG = keccak256("UnwrapperCodehashUpdated(bytes32,bool)");

    bytes4 internal constant DEPOSIT = MockProtocol.deposit.selector;
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;
    bytes4 internal constant WRAP = MockProtocol.wrap.selector;

    bytes32 internal A = bytes32(uint256(0xA1));
    bytes32 internal B = bytes32(uint256(0xB2));
    bytes32 internal C = bytes32(uint256(0xC3));

    function _oneOfOnWord1() internal {
        _allowWithRules(address(protocol), DEPOSIT, _rule(CuratorGuardPolicy.RuleKind.OneOf, 1, 0));
    }

    function _add(bytes32[] memory values_) internal {
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(protocol), DEPOSIT, 1, values_);
    }

    function _two(bytes32 x_, bytes32 y_) internal pure returns (bytes32[] memory _v) {
        _v = new bytes32[](2);
        _v[0] = x_;
        _v[1] = y_;
    }

    function _logsWith(Vm.Log[] memory logs_, bytes32 sig_) internal pure returns (uint256 _n) {
        for (uint256 i; i < logs_.length; ++i) if (logs_[i].topics[0] == sig_) ++_n;
    }

    /// @dev 7.7: "apply `AllowedValueAdded/Removed` in log order". One event per member that joins the set,
    ///      carrying the Safe, target, selector (topics), word index and value; a member already present
    ///      emits nothing.
    function test_AllowedValueAdded_once_per_new_member_and_nothing_for_a_duplicate() public {
        _oneOfOnWord1();
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuardPolicy.AllowedValueAdded(address(safe), address(protocol), DEPOSIT, 1, A);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuardPolicy.AllowedValueAdded(address(safe), address(protocol), DEPOSIT, 1, B);
        _add(_two(A, B));

        vm.recordLogs();
        _add(_two(A, C)); // A is a duplicate
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_logs.length, 1, "one event for the one new member");
        assertEq(_logs[0].topics[0], ADDED_SIG);
        (uint16 _word, bytes32 _value) = abi.decode(_logs[0].data, (uint16, bytes32));
        assertEq(_word, 1);
        assertEq(_value, C);
    }

    /// @dev One `AllowedValueRemoved` per member that leaves the set on `removeAllowedValues` (a non-member
    ///      is skipped silently) and on `clearAllowedValues` (every member).
    function test_AllowedValueRemoved_per_member_on_remove_and_clear_and_silent_for_a_non_member() public {
        _oneOfOnWord1();
        _add(_two(A, B));
        bytes32[] memory _c = new bytes32[](1);
        _c[0] = C;
        _add(_c);

        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuardPolicy.AllowedValueRemoved(address(safe), address(protocol), DEPOSIT, 1, A);
        vm.recordLogs();
        vm.prank(council);
        guard.removeAllowedValues(address(safe), address(protocol), DEPOSIT, 1, _two(A, bytes32(uint256(0xDEAD))));
        assertEq(vm.getRecordedLogs().length, 1, "the non-member is silent");

        vm.recordLogs();
        vm.prank(council);
        guard.clearAllowedValues(address(safe), address(protocol), DEPOSIT, 1);
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_logs.length, 2, "one per remaining member");
        bool _sawB;
        bool _sawC;
        for (uint256 i; i < _logs.length; ++i) {
            assertEq(_logs[i].topics[0], REMOVED_SIG);
            assertEq(_logs[i].topics[1], bytes32(uint256(uint160(address(safe)))));
            assertEq(_logs[i].topics[2], bytes32(uint256(uint160(address(protocol)))));
            assertEq(_logs[i].topics[3], bytes32(DEPOSIT));
            (uint16 _word, bytes32 _value) = abi.decode(_logs[i].data, (uint16, bytes32));
            assertEq(_word, 1);
            if (_value == B) _sawB = true;
            if (_value == C) _sawC = true;
        }
        assertTrue(_sawB && _sawC, "B and C removed");
        assertEq(guard.allowedValues(address(safe), address(protocol), DEPOSIT, 1).length, 0);
    }

    /// @dev 7.7: "`FunctionAllowed` REPLACES the rules, but a `OneOf` set persists while a `OneOf` rule on
    ///      its word is kept": a re-allow that drops the rule emits one `AllowedValueRemoved` per member
    ///      BEFORE its `FunctionAllowed`, so an indexer applying logs in order ends with an empty set.
    function test_a_reallow_that_drops_the_OneOf_rule_removes_every_member_before_FunctionAllowed() public {
        _oneOfOnWord1();
        _add(_two(A, B));
        vm.recordLogs();
        _allowWithRules(address(protocol), DEPOSIT, _rule(CuratorGuardPolicy.RuleKind.EqualToSafe, 1, 0));
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_logs.length, 3, "two removals and the allow");
        assertEq(_logs[0].topics[0], REMOVED_SIG);
        assertEq(_logs[1].topics[0], REMOVED_SIG);
        assertEq(_logs[2].topics[0], ALLOWED_SIG, "FunctionAllowed last");
        (, bytes32 _first) = abi.decode(_logs[0].data, (uint16, bytes32));
        (, bytes32 _second) = abi.decode(_logs[1].data, (uint16, bytes32));
        assertTrue((_first == A && _second == B) || (_first == B && _second == A), "both members named");
        assertEq(guard.allowedValues(address(safe), address(protocol), DEPOSIT, 1).length, 0);
    }

    /// @dev 7.7: "`FunctionRevoked` drops every `OneOf` set of the function at once: no per-member
    ///      `AllowedValueRemoved` follows". The event names the Safe, target and selector; `revokeTarget`
    ///      emits one per selector it revokes and nothing for a function already gone.
    function test_FunctionRevoked_payload_and_one_per_selector_on_revokeTarget() public {
        _oneOfOnWord1();
        _add(_two(A, B));
        _allow(address(protocol), SETTLE);
        _allow(address(protocol), WRAP);

        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuardPolicy.FunctionRevoked(address(safe), address(protocol), DEPOSIT);
        vm.recordLogs();
        vm.prank(council);
        guard.revokeFunction(address(safe), address(protocol), DEPOSIT);
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_logs.length, 1, "no per-member removal");
        assertEq(_logs[0].topics[0], REVOKED_SIG);

        vm.recordLogs();
        vm.prank(council);
        guard.revokeTarget(address(safe), address(protocol));
        _logs = vm.getRecordedLogs();
        assertEq(_logs.length, 2, "one FunctionRevoked per remaining selector");
        bool _sawSettle;
        bool _sawWrap;
        for (uint256 i; i < _logs.length; ++i) {
            assertEq(_logs[i].topics[0], REVOKED_SIG);
            assertEq(_logs[i].topics[1], bytes32(uint256(uint160(address(safe)))));
            assertEq(_logs[i].topics[2], bytes32(uint256(uint160(address(protocol)))));
            if (_logs[i].topics[3] == bytes32(SETTLE)) _sawSettle = true;
            if (_logs[i].topics[3] == bytes32(WRAP)) _sawWrap = true;
        }
        assertTrue(_sawSettle && _sawWrap, "both selectors named");
        assertEq(guard.targets(address(safe)).length, 0);
    }

    /// @dev 7.7: "`MultiSendUnwrapperUpdated` and `ModuleUpdated` (emitted only when the set changed)".
    function test_ModuleUpdated_only_on_change_in_both_directions() public {
        address _module = makeAddr("module");
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuardPolicy.ModuleUpdated(address(safe), _module, true);
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), _module, true);

        vm.recordLogs();
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), _module, true);
        assertEq(vm.getRecordedLogs().length, 0, "no-op allow is silent");

        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuardPolicy.ModuleUpdated(address(safe), _module, false);
        vm.prank(council);
        guard.setModuleAllowed(address(safe), _module, false);

        vm.recordLogs();
        vm.prank(council);
        guard.setModuleAllowed(address(safe), _module, false);
        assertEq(vm.getRecordedLogs().length, 0, "no-op forbid is silent");
        assertEq(guard.modules(address(safe)).length, 0);
    }

    /// @dev `RequiredFallbackHandlerUpdated` carries the handler and the flag, in the setter's order.
    function test_RequiredFallbackHandlerUpdated_carries_the_handler_and_the_flag() public {
        address _handler = makeAddr("tokenCallbackHandler");
        vm.etch(_handler, hex"00");
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuardPolicy.RequiredFallbackHandlerUpdated(address(safe), _handler, true);
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(safe), _handler, true);
        (address _h, bool _e) = guard.requiredFallbackHandler(address(safe));
        assertEq(_h, _handler);
        assertTrue(_e);

        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuardPolicy.RequiredFallbackHandlerUpdated(address(safe), address(0), false);
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(safe), address(0), false);
    }

    /// @dev 7.7: "`UnwrapperCodehashUpdated` (only ever for one of the three seeded hashes)": the constructor
    ///      reports the three canonical hashes as allowed, a council forbid and re-allow report the hash
    ///      and the new state, and a hash outside the seeded set reverts before any event.
    function test_UnwrapperCodehashUpdated_at_construction_and_on_forbid_and_reallow() public {
        vm.recordLogs();
        CuratorGuardHarness _fresh = new CuratorGuardHarness(0, vetro, council);
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        bytes32[3] memory _seeded = [_fresh.codehashV130(), _fresh.codehashV141(), _fresh.codehashV150()];
        uint256 _seen;
        for (uint256 i; i < _logs.length; ++i) {
            if (_logs[i].topics[0] != CODEHASH_SIG) continue;
            assertEq(_logs[i].emitter, address(_fresh));
            assertEq(_logs[i].topics[1], _seeded[_seen], "seeded in constant order");
            assertTrue(abi.decode(_logs[i].data, (bool)), "allowed at construction");
            ++_seen;
        }
        assertEq(_seen, 3, "three seeded hashes reported");

        vm.expectEmit(true, true, true, true, address(_fresh));
        emit CuratorGuardPolicy.UnwrapperCodehashUpdated(_seeded[1], false);
        vm.prank(council);
        _fresh.setUnwrapperCodehash(_seeded[1], false);
        assertFalse(_fresh.isUnwrapperCodehash(_seeded[1]));

        vm.expectEmit(true, true, true, true, address(_fresh));
        emit CuratorGuardPolicy.UnwrapperCodehashUpdated(_seeded[1], true);
        vm.prank(council);
        _fresh.setUnwrapperCodehash(_seeded[1], true);
        assertTrue(_fresh.isUnwrapperCodehash(_seeded[1]));

        bytes32 _foreign = keccak256("not a MultiSendCallOnly build");
        vm.recordLogs();
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.UnwrapperCodehashNotAllowed.selector, _foreign));
        _fresh.setUnwrapperCodehash(_foreign, false);
        assertEq(vm.getRecordedLogs().length, 0, "nothing logged for a foreign hash");
    }
}
