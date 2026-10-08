// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IAccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/IAccessControlDefaultAdminRules.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";

import {CuratorGuardHarness, CuratorGuardTestBase, MockProtocol, MaliciousMultiSend, Reverter} from "test/guards/CuratorGuardTestBase.sol";

/// @title CuratorGuard unit tests (real Safe v1.4.1, owner-signed path)
contract CuratorGuardTest is CuratorGuardTestBase {
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;
    bytes4 internal constant DEPOSIT = MockProtocol.deposit.selector;
    bytes4 internal constant WRAP = MockProtocol.wrap.selector;
    bytes4 internal constant APPROVE = IERC20.approve.selector;
    bytes4 internal constant TRANSFER = IERC20.transfer.selector;

    /*//////////////////////////////////////////////////////////////
                         INSTALL / INTROSPECTION
    //////////////////////////////////////////////////////////////*/

    function test_erc165_ids_match_safe_releases() public view {
        assertTrue(guard.supportsInterface(0xe6d7a83a), "Guard / ITransactionGuard");
        assertTrue(guard.supportsInterface(0x58401ed8), "IModuleGuard");
        assertTrue(guard.supportsInterface(0x01ffc9a7), "IERC165");
        assertFalse(guard.supportsInterface(0xffffffff));
        assertFalse(guard.supportsInterface(0x12345678));
    }

    function test_constants_match_safe_sources() public {
        CuratorGuardHarness _h = new CuratorGuardHarness(0, vetro, council);
        assertEq(_h.guardStorageSlot(), keccak256("guard_manager.guard.address"));
        assertEq(_h.moduleGuardStorageSlot(), keccak256("module_manager.module_guard.address"));
        assertEq(_h.fallbackHandlerStorageSlot(), keccak256("fallback_manager.handler.address"));
        assertEq(_h.modulesHeadSlot(), keccak256(abi.encode(address(1), uint256(1))));
        assertEq(_h.multiSendSelector(), bytes4(keccak256("multiSend(bytes)")));
        assertEq(_h.masterCopySelector(), bytes4(keccak256("masterCopy()")));
        assertEq(GUARD_SLOT, _h.guardStorageSlot());
        assertEq(FALLBACK_SLOT, _h.fallbackHandlerStorageSlot());
        assertEq(MODULES_HEAD_SLOT, _h.modulesHeadSlot());
    }

    function test_local_tx_hash_matches_safe() public view {
        SafeTx memory _t = SafeTx(address(protocol), 1, hex"deadbeef", Operation.DelegateCall, 5, 2, address(3), address(4));
        bytes32 _expected = safe.getTransactionHash(
            _t.to,
            _t.value,
            _t.data,
            _t.op,
            _t.safeTxGas,
            0,
            _t.gasPrice,
            _t.gasToken,
            _t.refundReceiver,
            safe.nonce()
        );
        assertEq(_txHash(_t), _expected, "local EIP-712 hash == Safe.getTransactionHash");
    }

    function test_owner_is_vetro_and_default_mode_is_lockdown() public view {
        assertEq(guard.owner(), vetro);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        assertEq(uint8(guard.mode(attacker)), uint8(CuratorGuardPolicy.Mode.Lockdown));
    }

    /*//////////////////////////////////////////////////////////////
                              MODES
    //////////////////////////////////////////////////////////////*/

    function test_lockdown_rejects_everything_by_default() public {
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
    }

    function test_enforced_allows_allowlisted_function() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (42)), Operation.Call));
        assertEq(protocol.lastAmount(), 42);
    }

    function test_enforced_rejects_unlisted_selector_on_listed_target() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), DEPOSIT));
        _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (1, address(safe))), Operation.Call);
    }

    function test_enforced_rejects_unlisted_target() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(token), TRANSFER));
        _execSafeTx(address(token), 0, abi.encodeCall(IERC20.transfer, (attacker, 1)), Operation.Call);
    }

    function test_bypass_makes_guard_inert_including_guard_removal() public {
        vm.prank(vetro);
        guard.bypass(address(safe), 1 days);
        assertTrue(_execSafeTx(address(token), 0, abi.encodeCall(IERC20.transfer, (attacker, 1)), Operation.Call));
        assertEq(token.balanceOf(attacker), 1);
        // Post-check is skipped in Bypass: the Safe may remove the guard.
        assertTrue(_execSafeTx(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call));
        assertEq(_installedGuard(), address(0));
    }

    function test_lockdown_after_enforced_freezes_curator() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        vm.prank(vetro);
        guard.lockdown(address(safe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
                      SELF-CALLS: SAFE ADMIN SURFACE
    //////////////////////////////////////////////////////////////*/

    function test_self_calls_are_rejected_even_if_allowlisted_elsewhere() public {
        _enforce();
        bytes[] memory _payloads = new bytes[](6);
        _payloads[0] = abi.encodeCall(ISafe.setGuard, (address(0)));
        _payloads[1] = abi.encodeCall(ISafe.enableModule, (attacker));
        _payloads[2] = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", attacker, 1);
        _payloads[3] = abi.encodeWithSignature("swapOwner(address,address,address)", address(1), curator, attacker);
        _payloads[4] = abi.encodeWithSignature("changeThreshold(uint256)", 1);
        _payloads[5] = abi.encodeWithSignature("setFallbackHandler(address)", attacker);
        for (uint256 i; i < _payloads.length; ++i) {
            bytes4 _selector = bytes4(_payloads[i]);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, _selector));
            _execSafeTx(address(safe), 0, _payloads[i], Operation.Call);
        }
        assertEq(_installedGuard(), address(guard), "guard intact");
        assertFalse(safe.isModuleEnabled(attacker));
        assertEq(safe.getOwners().length, 1);
    }

    /// @dev Safe{Wallet}'s "Reject transaction" is an empty, zero-value self-call: it burns the nonce,
    ///      lands in `receive()` and changes no state, so the policy lets exactly that through. Any value
    ///      on it, or Lockdown, still refuses it.
    function test_safe_wallet_rejection_self_call_passes_but_value_or_lockdown_do_not() public {
        _enforce();
        uint256 _nonce = safe.nonce();
        assertTrue(_execSafeTx(address(safe), 0, "", Operation.Call), "Safe{Wallet} reject");
        assertEq(safe.nonce(), _nonce + 1);
        assertEq(_installedGuard(), address(guard));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, bytes4(0)));
        _execSafeTx(address(safe), 1, "", Operation.Call);
        vm.prank(vetro);
        guard.lockdown(address(safe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(safe), 0, "", Operation.Call);
    }

    function test_cannot_allowlist_the_safe_itself() public {
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(safe)));
        guard.allowFunction(address(safe), address(safe), ISafe.setGuard.selector, false, _noRules());
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(safe)));
        guard.setNativeTransferAllowed(address(safe), address(safe), true);
    }

    /*//////////////////////////////////////////////////////////////
                              GAS REFUNDS
    //////////////////////////////////////////////////////////////*/

    function test_gas_refund_in_erc20_is_rejected() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        vm.expectRevert(CuratorGuard.GasRefundNotAllowed.selector);
        _execSafeTxWithRefund(
            address(protocol),
            0,
            abi.encodeCall(MockProtocol.settleDeposit, (1)),
            Operation.Call,
            1e12,
            address(token),
            attacker
        );
    }

    function test_gas_refund_in_native_is_rejected() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        vm.expectRevert(CuratorGuard.GasRefundNotAllowed.selector);
        _execSafeTxWithRefund(
            address(protocol),
            0,
            abi.encodeCall(MockProtocol.settleDeposit, (1)),
            Operation.Call,
            1,
            address(0),
            attacker
        );
    }

    function test_gas_refund_is_rejected_even_with_an_approval() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, uint64(1 days));
        vm.expectRevert(CuratorGuard.GasRefundNotAllowed.selector);
        _execSafeTxWithRefund(address(protocol), 0, _data, Operation.Call, 1, address(token), attacker);
    }

    /*//////////////////////////////////////////////////////////////
                           DELEGATECALL / MULTISEND
    //////////////////////////////////////////////////////////////*/

    function test_delegatecall_to_unregistered_target_is_rejected() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        bytes memory _batch = _multiSendCalldata(_entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1))));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.DelegateCallNotAllowed.selector, address(multiSendCallOnly)));
        _execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
    }

    function test_multisend_batch_of_allowed_calls_passes() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        _allow(address(protocol), DEPOSIT);
        _registerMultiSend();
        bytes memory _batch = _multiSendCalldata(
            abi.encodePacked(
                _entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (7))),
                _entry(address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (9, address(safe))))
            )
        );
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall));
        assertEq(protocol.calls(), 2);
        assertEq(protocol.lastAmount(), 9);
        assertEq(_installedGuard(), address(guard));
    }

    function test_multisend_rejects_batch_with_one_unlisted_entry() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        _registerMultiSend();
        bytes memory _batch = _multiSendCalldata(
            abi.encodePacked(
                _entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (7))),
                _entry(address(token), 0, abi.encodeCall(IERC20.transfer, (attacker, 1)))
            )
        );
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(token), TRANSFER));
        _execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
        assertEq(protocol.calls(), 0, "atomic: nothing executed");
    }

    function test_multisend_rejects_inner_self_call() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        _registerMultiSend();
        bytes memory _batch = _multiSendCalldata(
            abi.encodePacked(
                _entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (7))),
                _entry(address(safe), 0, abi.encodeCall(ISafe.enableModule, (attacker)))
            )
        );
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, ISafe.enableModule.selector));
        _execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
        assertFalse(safe.isModuleEnabled(attacker));
    }

    function test_multisend_rejects_delegatecall_entries_even_on_plain_multisend() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        // Owner mistake: registering the non-CallOnly MultiSend. The parser still refuses op=1 entries.
        _registerUnwrapper(address(multiSend));
        bytes memory _batch = _multiSendCalldata(_entryDelegate(address(new MaliciousMultiSend(GUARD_SLOT, 0)), hex"deadbeef"));
        vm.expectRevert(CuratorGuard.MultiSendDelegateCallEntry.selector);
        _execSafeTx(address(multiSend), 0, _batch, Operation.DelegateCall);
    }

    function test_multisend_rejects_value_on_delegatecall() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        _registerMultiSend();
        bytes memory _batch = _multiSendCalldata(_entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (7))));
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ValueNotAllowed.selector, address(multiSendCallOnly), bytes4(0x8d80ff0a))
        );
        _execSafeTx(address(multiSendCallOnly), 1, _batch, Operation.DelegateCall);
    }

    function test_multisend_rejects_wrong_selector() public {
        _enforce();
        _registerMultiSend();
        bytes memory _bad = abi.encodeWithSelector(bytes4(0x12345678), _entry(address(protocol), 0, ""));
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        _execSafeTx(address(multiSendCallOnly), 0, _bad, Operation.DelegateCall);
    }

    function test_multisend_rejects_non_canonical_head_offset() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        _registerMultiSend();
        bytes memory _packed = _entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (7)));
        // Hand-rolled encoding with the bytes head offset pointing 32 bytes further; a lax parser
        // would check different bytes than MultiSend executes.
        bytes memory _bad = abi.encodePacked(
            bytes4(0x8d80ff0a),
            uint256(0x40),
            uint256(0),
            uint256(_packed.length),
            _packed,
            new bytes((32 - (_packed.length % 32)) % 32)
        );
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        _execSafeTx(address(multiSendCallOnly), 0, _bad, Operation.DelegateCall);
    }

    /// @dev Offset word 0x40 with an otherwise length-consistent encoding: without the offset
    ///      check the guard would validate entries from byte 68 while the Safe's `MultiSend`
    ///      would decode the `bytes` from byte 4 + 0x40 — a different payload.
    function test_multisend_rejects_non_canonical_head_offset_with_consistent_length() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        _registerMultiSend();
        bytes memory _packed = _entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (7)));
        bytes memory _bad = abi.encodePacked(
            bytes4(0x8d80ff0a),
            uint256(0x40),
            uint256(_packed.length),
            _packed,
            new bytes((32 - (_packed.length % 32)) % 32)
        );
        assertEq(_bad.length, 68 + ((_packed.length + 31) / 32) * 32, "length-consistent");
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        _execSafeTx(address(multiSendCallOnly), 0, _bad, Operation.DelegateCall);
    }

    function test_multisend_rejects_trailing_bytes() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        _registerMultiSend();
        bytes memory _ok = _multiSendCalldata(_entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (7))));
        bytes memory _bad = abi.encodePacked(_ok, new bytes(32));
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        _execSafeTx(address(multiSendCallOnly), 0, _bad, Operation.DelegateCall);
    }

    function test_multisend_rejects_empty_batch() public {
        _enforce();
        _registerMultiSend();
        vm.expectRevert(CuratorGuard.EmptyMultiSend.selector);
        _execSafeTx(address(multiSendCallOnly), 0, _multiSendCalldata(""), Operation.DelegateCall);
    }

    function test_multisend_rejects_truncated_entry() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        _registerMultiSend();
        // Declared data length (64) exceeds the bytes actually present (36).
        bytes memory _packed = abi.encodePacked(
            uint8(0),
            address(protocol),
            uint256(0),
            uint256(64),
            abi.encodeCall(MockProtocol.settleDeposit, (7))
        );
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        _execSafeTx(address(multiSendCallOnly), 0, _multiSendCalldata(_packed), Operation.DelegateCall);
    }

    function test_multisend_rejects_truncated_header() public {
        _enforce();
        _registerMultiSend();
        bytes memory _packed = abi.encodePacked(uint8(0), address(protocol), uint256(0)); // missing data length
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        _execSafeTx(address(multiSendCallOnly), 0, _multiSendCalldata(_packed), Operation.DelegateCall);
    }

    function test_multisend_inner_value_requires_permission() public {
        _enforce();
        _allow(address(protocol), WRAP);
        _registerMultiSend();
        bytes memory _batch = _multiSendCalldata(_entry(address(protocol), 1 ether, abi.encodeCall(MockProtocol.wrap, ())));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ValueNotAllowed.selector, address(protocol), WRAP));
        _execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);

        vm.prank(vetro);
        guard.allowFunction(address(safe), address(protocol), WRAP, true, _noRules());
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall));
        assertEq(protocol.lastValue(), 1 ether);
    }

    function test_multisend_inner_native_transfer_requires_permission() public {
        _enforce();
        _registerMultiSend();
        bytes memory _batch = _multiSendCalldata(_entry(address(protocol), 1 ether, ""));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.NativeTransferNotAllowed.selector, address(protocol)));
        _execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);

        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), address(protocol), true);
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall));
        assertEq(address(protocol).balance, 1 ether);
    }

    function testFuzz_multisend_accepts_any_number_of_allowed_entries(uint8 count_) public {
        uint256 _n = bound(count_, 1, 12);
        _enforce();
        _allow(address(protocol), SETTLE);
        _registerMultiSend();
        bytes memory _packed;
        for (uint256 i; i < _n; ++i) {
            _packed = abi.encodePacked(_packed, _entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (i))));
        }
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _multiSendCalldata(_packed), Operation.DelegateCall));
        assertEq(protocol.calls(), _n);
    }

    /*//////////////////////////////////////////////////////////////
                             PARAMETER RULES
    //////////////////////////////////////////////////////////////*/

    function test_rule_equalToSafe_pins_receiver() public {
        _enforce();
        _allowWithRules(address(protocol), DEPOSIT, _rule(CuratorGuardPolicy.RuleKind.EqualToSafe, 1, 0));
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (5, address(safe))), Operation.Call));
        assertEq(protocol.lastReceiver(), address(safe));

        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(protocol), DEPOSIT, uint16(1), _word(attacker))
        );
        _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (5, attacker)), Operation.Call);
    }

    function test_rule_oneOf_scopes_approve_spender() public {
        _enforce();
        _allowWithRules(address(token), APPROVE, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        // Empty set: fails closed.
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(token), APPROVE, uint16(0), _word(address(protocol)))
        );
        _execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (address(protocol), 1e6)), Operation.Call);

        bytes32[] memory _spenders = new bytes32[](1);
        _spenders[0] = _word(address(protocol));
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(token), APPROVE, 0, _spenders);

        assertTrue(_execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (address(protocol), 1e6)), Operation.Call));
        assertEq(token.allowance(address(safe), address(protocol)), 1e6);

        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(token), APPROVE, uint16(0), _word(attacker))
        );
        _execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (attacker, type(uint256).max)), Operation.Call);
    }

    function test_rule_equalTo_and_bounds() public {
        _enforce();
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](3);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualTo, 0, _word(address(protocol)));
        _rules[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 1, bytes32(uint256(100)));
        _rules[2] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.GreaterThanOrEqual, 1, bytes32(uint256(10)));
        _allowWithRules(address(token), APPROVE, _rules);

        assertTrue(_execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (address(protocol), 100)), Operation.Call));
        assertTrue(_execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (address(protocol), 10)), Operation.Call));

        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(token), APPROVE, uint16(1), bytes32(uint256(101)))
        );
        _execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (address(protocol), 101)), Operation.Call);

        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(token), APPROVE, uint16(1), bytes32(uint256(9)))
        );
        _execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (address(protocol), 9)), Operation.Call);

        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(token), APPROVE, uint16(0), _word(attacker))
        );
        _execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (attacker, 50)), Operation.Call);
    }

    function test_rule_fails_closed_on_short_calldata() public {
        _enforce();
        _allowWithRules(address(protocol), DEPOSIT, _rule(CuratorGuardPolicy.RuleKind.EqualToSafe, 1, 0));
        bytes memory _short = abi.encodePacked(DEPOSIT, uint256(5)); // receiver word missing
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamOutOfRange.selector, address(protocol), DEPOSIT, uint16(1)));
        _execSafeTx(address(protocol), 0, _short, Operation.Call);
    }

    function test_rule_rejects_dirty_upper_bits_in_address_word() public {
        _enforce();
        _allowWithRules(address(protocol), DEPOSIT, _rule(CuratorGuardPolicy.RuleKind.EqualToSafe, 1, 0));
        bytes32 _dirty = bytes32((uint256(1) << 160) | uint256(uint160(address(safe))));
        bytes memory _data = abi.encodePacked(DEPOSIT, uint256(5), _dirty);
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(protocol), DEPOSIT, uint16(1), _dirty)
        );
        _execSafeTx(address(protocol), 0, _data, Operation.Call);
    }

    function testFuzz_rule_lessThanOrEqual_boundary(uint256 cap_, uint256 amount_) public {
        _enforce();
        _allowWithRules(address(token), APPROVE, _rule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 1, bytes32(cap_)));
        bytes memory _data = abi.encodeCall(IERC20.approve, (address(protocol), amount_));
        if (amount_ > cap_) {
            vm.expectRevert(
                abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(token), APPROVE, uint16(1), bytes32(amount_))
            );
        }
        _execSafeTx(address(token), 0, _data, Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
                        NATIVE VALUE / EMPTY CALLDATA
    //////////////////////////////////////////////////////////////*/

    function test_native_transfer_requires_explicit_permission() public {
        _enforce();
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.NativeTransferNotAllowed.selector, attacker));
        _execSafeTx(attacker, 1 ether, "", Operation.Call);
        // Zero-value empty calls need it too (fallback functions can carry logic).
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.NativeTransferNotAllowed.selector, address(protocol)));
        _execSafeTx(address(protocol), 0, "", Operation.Call);

        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), address(protocol), true);
        assertTrue(_execSafeTx(address(protocol), 1 ether, "", Operation.Call));
        assertEq(protocol.lastValue(), 1 ether);
    }

    function test_value_on_function_requires_allowValue() public {
        _enforce();
        _allow(address(protocol), WRAP);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ValueNotAllowed.selector, address(protocol), WRAP));
        _execSafeTx(address(protocol), 1 ether, abi.encodeCall(MockProtocol.wrap, ()), Operation.Call);

        vm.prank(vetro);
        guard.allowFunction(address(safe), address(protocol), WRAP, true, _noRules());
        assertTrue(_execSafeTx(address(protocol), 1 ether, abi.encodeCall(MockProtocol.wrap, ()), Operation.Call));
        assertEq(protocol.lastValue(), 1 ether);
    }

    function test_short_calldata_is_rejected() public {
        _enforce();
        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), address(protocol), true);
        vm.expectRevert(CuratorGuard.MalformedCalldata.selector);
        _execSafeTx(address(protocol), 0, hex"aabbcc", Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
                          ONE-SHOT APPROVALS
    //////////////////////////////////////////////////////////////*/

    function test_approval_authorises_guard_migration_and_is_consumed() public {
        _enforce();
        CuratorGuard _next = new CuratorGuard(0, vetro, council);
        bytes memory _data = abi.encodeCall(ISafe.setGuard, (address(_next)));
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(safe),
            0,
            _data,
            Operation.Call,
            uint64(1 days)
        );
        assertEq(_id, guard.computeApprovalId(address(safe), address(0), address(safe), 0, _data, Operation.Call));
        assertEq(guard.approvalExpiry(_id), uint64(block.timestamp) + 1 days);

        assertTrue(_execSafeTx(address(safe), 0, _data, Operation.Call));
        assertEq(_installedGuard(), address(_next), "migrated");
        assertEq(guard.approvalExpiry(_id), 0, "consumed");
    }

    function test_approval_is_single_use() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, uint64(1 days));
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, _data, Operation.Call);
    }

    function test_approval_passes_under_lockdown() public {
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, uint64(1 days));
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call));
        assertEq(protocol.lastAmount(), 1);
    }

    function test_expired_approval_is_ignored() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, uint64(1 hours));
        vm.warp(block.timestamp + 1 hours + 1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, _data, Operation.Call);
    }

    function test_approval_ttl_is_capped_per_role() public {
        uint64 _adminCap = _H().maxAdminApprovalTtl();
        uint64 _councilCap = _H().maxCouncilApprovalTtl();
        assertEq(_adminCap, 180 days);
        assertEq(_councilCap, 7 days);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, _adminCap + 1));
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, "", Operation.Call, _adminCap + 1);
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(protocol), 0, "", Operation.Call, _adminCap);
        assertEq(guard.approvalExpiry(_id), uint64(block.timestamp) + _adminCap, "absolute expiry = now + ttl");

        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, _councilCap + 1));
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, "", Operation.Call, _councilCap + 1);
        vm.prank(council);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, "", Operation.Call, _councilCap);
    }

    function test_approval_rejects_zero_ttl() public {
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, uint64(0)));
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, "", Operation.Call, 0);
    }

    function test_approval_is_bound_to_exact_payload_and_safe() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.startPrank(vetro);
        guard.approveTransaction(attacker, address(0), address(protocol), 0, _data, Operation.Call, uint64(1 days)); // other safe
        guard.approveTransaction(address(safe), address(0), address(protocol), 1, _data, Operation.Call, uint64(1 days)); // other value
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.DelegateCall, uint64(1 days)); // other op
        guard.approveTransaction(address(safe), attacker, address(protocol), 0, _data, Operation.Call, uint64(1 days)); // other executor (a module)
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, _data, Operation.Call);
    }

    function test_guardian_can_revoke_approval() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.startPrank(vetro);
        guard.setGuardian(address(safe), guardian, true);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(protocol),
            0,
            _data,
            Operation.Call,
            uint64(1 days)
        );
        vm.stopPrank();
        vm.prank(guardian);
        guard.revokeApproval(_id);
        assertEq(guard.approvalExpiry(_id), 0);
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ApprovalNotFound.selector, _id));
        guard.revokeApproval(_id);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, _data, Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
                            POST-EXECUTION CHECK
    //////////////////////////////////////////////////////////////*/

    function test_post_check_reverts_if_guard_was_wiped_during_execution() public {
        _assertMaliciousWriteIsCaught(GUARD_SLOT, bytes32(0));
        assertEq(_installedGuard(), address(guard), "whole Safe tx reverted");
    }

    function test_post_check_reverts_if_a_module_was_linked_during_execution() public {
        _assertMaliciousWriteIsCaught(MODULES_HEAD_SLOT, _word(attacker));
        assertFalse(safe.isModuleEnabled(attacker));
    }

    function test_post_check_reverts_if_fallback_handler_changed_during_execution() public {
        _assertMaliciousWriteIsCaught(FALLBACK_SLOT, _word(attacker));
    }

    function test_post_check_reverts_if_threshold_changed_during_execution() public {
        _assertMaliciousWriteIsCaught(bytes32(uint256(4)), bytes32(uint256(7)));
        assertEq(safe.getThreshold(), 1);
    }

    /// @dev Swapping the singleton for an EOA breaks the proxy for the rest of the transaction: the
    ///      post-check's reads through the Safe return no data and the whole Safe transaction still
    ///      reverts (fail closed), just not with the typed error.
    function test_post_check_reverts_if_singleton_changed_during_execution() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        MaliciousMultiSend _evil = new MaliciousMultiSend(bytes32(uint256(0)), _word(attacker));
        _registerUnwrapper(address(_evil));
        bytes memory _batch = _multiSendCalldata(_entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (7))));
        bytes32 _singletonBefore = vm.load(address(safe), bytes32(uint256(0)));
        vm.expectRevert();
        _execSafeTx(address(_evil), 0, _batch, Operation.DelegateCall);
        assertEq(vm.load(address(safe), bytes32(uint256(0))), _singletonBefore, "singleton intact");
        assertEq(protocol.calls(), 0, "nothing executed");
    }

    /// @dev Registers a storage-writing "unwrapper" (owner mistake) and shows the configuration
    ///      snapshot reverts the whole Safe transaction.
    function _assertMaliciousWriteIsCaught(bytes32 slot_, bytes32 value_) internal {
        _enforce();
        _allow(address(protocol), SETTLE);
        MaliciousMultiSend _evil = new MaliciousMultiSend(slot_, value_);
        _registerUnwrapper(address(_evil));
        bytes memory _batch = _multiSendCalldata(_entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (7))));
        bytes32 _before = vm.load(address(safe), slot_);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(safe)));
        _execSafeTx(address(_evil), 0, _batch, Operation.DelegateCall);
        assertEq(vm.load(address(safe), slot_), _before, "slot intact");
        assertEq(protocol.calls(), 0, "nothing executed");
    }

    function test_post_check_hooks_cannot_be_abused_by_strangers() public {
        // A stranger calling the hooks directly has no effect on any policy.
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.MissingSnapshot.selector, attacker));
        guard.checkAfterExecution(bytes32(0), true);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
    }

    /*//////////////////////////////////////////////////////////////
                           ROLES & ADMIN GUARDS
    //////////////////////////////////////////////////////////////*/

    function test_guardian_can_only_narrow() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        vm.prank(vetro);
        guard.setGuardian(address(safe), guardian, true);
        assertTrue(guard.isGuardian(address(safe), guardian));

        vm.startPrank(guardian);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.allowFunction(address(safe), address(protocol), DEPOSIT, false, _noRules());
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.bypass(address(safe), 1 days);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.setNativeTransferAllowed(address(safe), address(protocol), true);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.setMultiSendUnwrapper(address(safe), address(multiSendCallOnly), true);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.setModuleAllowed(address(safe), attacker, true);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, "", Operation.Call, uint64(1));
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.setGuardian(address(safe), attacker, true);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.setRequiredFallbackHandler(address(safe), address(0), false);

        guard.revokeFunction(address(safe), address(protocol), SETTLE);
        assertFalse(_isAllowed(address(safe), address(protocol), SETTLE));
        guard.setNativeTransferAllowed(address(safe), address(protocol), false);
        guard.setMultiSendUnwrapper(address(safe), address(multiSendCallOnly), false);
        guard.setModuleAllowed(address(safe), attacker, false);
        guard.revokeAllApprovals(address(safe));
        guard.lockdown(address(safe));
        vm.stopPrank();
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        assertEq(guard.approvalEpoch(address(safe)), 1);
    }

    function test_strangers_cannot_touch_policy() public {
        vm.startPrank(attacker);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.lockdown(address(safe));
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.revokeFunction(address(safe), address(protocol), SETTLE);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.allowFunction(address(safe), address(protocol), SETTLE, false, _noRules());
        vm.stopPrank();
    }

    function test_admin_transfer_is_two_step_and_can_never_target_zero() public {
        vm.prank(vetro);
        vm.expectRevert(CuratorGuardPolicy.AdminCannotBeZero.selector);
        guard.beginDefaultAdminTransfer(address(0));

        address _next = makeAddr("vetro-2");
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(_next);
        assertEq(guard.owner(), vetro, "still vetro until accepted");
        assertEq(guard.defaultAdmin(), vetro);
        vm.warp(block.timestamp + 1); // delay 0 in tests: accept must land in a later block
        vm.prank(_next);
        guard.acceptDefaultAdminTransfer();
        assertEq(guard.owner(), _next);
        assertFalse(guard.hasRole(guard.DEFAULT_ADMIN_ROLE(), vetro), "exactly one admin at a time");

        // The library refuses direct grants of the admin role and renouncing it outside a transfer.
        bytes32 _adminRole = guard.DEFAULT_ADMIN_ROLE();
        vm.prank(_next);
        vm.expectRevert(abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminRules.selector));
        guard.grantRole(_adminRole, vetro);
        vm.prank(_next);
        vm.expectRevert(abi.encodeWithSelector(IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminDelay.selector, uint48(0)));
        guard.renounceRole(_adminRole, _next);
    }

    function test_config_validation() public {
        vm.startPrank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(0)));
        guard.allowFunction(address(safe), address(0), SETTLE, false, _noRules());
        vm.expectRevert(CuratorGuardPolicy.AddressIsNull.selector);
        guard.allowFunction(address(0), address(protocol), SETTLE, false, _noRules());
        vm.expectRevert(CuratorGuardPolicy.AddressIsNull.selector);
        guard.enforce(address(0));

        CuratorGuardPolicy.ParamRule[] memory _tooMany = new CuratorGuardPolicy.ParamRule[](17);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.TooManyRules.selector, 17));
        guard.allowFunction(address(safe), address(protocol), SETTLE, false, _tooMany);

        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidRule.selector, 0));
        guard.allowFunction(address(safe), address(protocol), SETTLE, false, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, bytes32(uint256(1))));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidRule.selector, 0));
        guard.allowFunction(address(safe), address(protocol), SETTLE, false, _rule(CuratorGuardPolicy.RuleKind.EqualToSafe, 0, bytes32(uint256(1))));

        // An account without code hashes to `0` / `keccak256("")`, neither of which can ever be seeded.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.UnwrapperCodehashNotAllowed.selector, attacker.codehash));
        guard.setMultiSendUnwrapper(address(safe), attacker, true);
        // Code that is not an allowed `MultiSendCallOnly` build is rejected even though it is a contract.
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuardPolicy.UnwrapperCodehashNotAllowed.selector, address(multiSendCallOnly).codehash)
        );
        guard.setMultiSendUnwrapper(address(safe), address(multiSendCallOnly), true);

        // The guard itself and the Safe are never valid targets or unwrappers.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(guard)));
        guard.allowFunction(address(safe), address(guard), CuratorGuardPolicy.lockdown.selector, false, _noRules());
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(guard)));
        guard.setNativeTransferAllowed(address(safe), address(guard), true);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(guard)));
        guard.setMultiSendUnwrapper(address(safe), address(guard), true);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(safe)));
        guard.setMultiSendUnwrapper(address(safe), address(safe), true);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(0)));
        guard.setMultiSendUnwrapper(address(safe), address(0), false);

        // A lower bound alone is fail-open: it must be paired with an upper bound on the same word.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.UnboundedLowerBound.selector, 0));
        guard.allowFunction(address(safe), address(token), APPROVE, false, _rule(CuratorGuardPolicy.RuleKind.GreaterThanOrEqual, 1, bytes32(uint256(1))));
        CuratorGuardPolicy.ParamRule[] memory _mismatched = new CuratorGuardPolicy.ParamRule[](2);
        _mismatched[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.GreaterThanOrEqual, 1, bytes32(uint256(1)));
        _mismatched[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 0, bytes32(uint256(1)));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.UnboundedLowerBound.selector, 0));
        guard.allowFunction(address(safe), address(token), APPROVE, false, _mismatched);

        // Values can only be added under a live OneOf rule.
        bytes32[] memory _values = new bytes32[](1);
        _values[0] = _word(attacker);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.NoOneOfRule.selector, uint16(0)));
        guard.addAllowedValues(address(safe), address(token), APPROVE, 0, _values);
        vm.stopPrank();
    }

    function test_oneOf_set_is_capped() public {
        _enforce();
        _allowWithRules(address(token), APPROVE, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        bytes32[] memory _values = new bytes32[](_H().maxAllowedValues() + 1);
        for (uint256 i; i < _values.length; ++i) _values[i] = bytes32(i + 1);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.TooManyValues.selector, _values.length));
        guard.addAllowedValues(address(safe), address(token), APPROVE, 0, _values);
    }

    function test_guard_is_never_a_valid_call_target_at_runtime() public {
        _enforce();
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, CuratorGuardPolicy.lockdown.selector));
        _execSafeTx(address(guard), 0, abi.encodeCall(CuratorGuardPolicy.lockdown, (address(safe))), Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, bytes4(0)));
        _execSafeTx(address(guard), 0, "", Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
                  ROUND-3 REGRESSIONS: UNWRAPPER CODE PINNING
    //////////////////////////////////////////////////////////////*/

    /// @dev Only the canonical `MultiSendCallOnly` hashes seeded at deployment can ever be allowed on a
    ///      real guard: a locally compiled build (different metadata) is refused even to the admin, so a
    ///      trojaned "MultiSendCallOnly" can never become a delegatecall target. The test fixture seeds
    ///      local builds through `CuratorGuardHarness` instead.
    function test_canonical_multisend_call_only_hashes_are_pre_allowed_and_the_set_is_fixed() public {
        assertTrue(guard.isUnwrapperCodehash(_H().codehashV130()));
        assertTrue(guard.isUnwrapperCodehash(_H().codehashV141()));
        assertTrue(guard.isUnwrapperCodehash(_H().codehashV150()));
        assertFalse(guard.isUnwrapperCodehash(address(multiSendCallOnly).codehash), "local build is not canonical");
        assertFalse(guard.isUnwrapperCodehash(bytes32(0)));

        CuratorGuard _real = new CuratorGuard(0, vetro, council);
        bytes32 _local = address(multiSendCallOnly).codehash;
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.UnwrapperCodehashNotAllowed.selector, _local));
        _real.setUnwrapperCodehash(_local, true);
        // A seeded hash can be forbidden by a deployment-wide guardian and re-allowed by the admin.
        bytes32 _v141 = _H().codehashV141();
        vm.prank(vetro);
        _real.setUnwrapperCodehash(_v141, false);
        assertFalse(_real.isUnwrapperCodehash(_v141));
        vm.prank(vetro);
        _real.setUnwrapperCodehash(_v141, true);
        assertTrue(_real.isUnwrapperCodehash(_v141));
    }

    /// @dev Forbidding a code hash (guardian-capable) disables every unwrapper that carries it, even
    ///      if it stays registered: the hash is re-checked on every delegatecall.
    function test_unwrapper_code_hash_is_rechecked_at_runtime() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        _registerMultiSend();
        bytes memory _batch = _multiSendCalldata(_entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1))));
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall));

        // Forbidding a hash is deployment-wide, so it takes a deployment-wide guardian (or council / admin);
        // a per-Safe guardian is refused.
        vm.prank(vetro);
        guard.setGuardian(address(safe), guardian, true);
        vm.prank(guardian);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.setUnwrapperCodehash(address(multiSendCallOnly).codehash, false);
        bytes32 _guardianRole = guard.GUARDIAN_ROLE();
        vm.prank(vetro);
        guard.grantRole(_guardianRole, guardian);
        vm.prank(guardian);
        guard.setUnwrapperCodehash(address(multiSendCallOnly).codehash, false);
        assertTrue(_contains(guard.multiSendUnwrappers(address(safe)), address(multiSendCallOnly)), "still registered");
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuardPolicy.UnwrapperCodehashNotAllowed.selector, address(multiSendCallOnly).codehash)
        );
        _execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuardPolicy.UnwrapperCodehashNotAllowed.selector, address(multiSendCallOnly).codehash)
        );
        guard.validateTransaction(address(safe), address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);

        // Guardians can only forbid; allowing a hash is admin-only.
        vm.prank(guardian);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.setUnwrapperCodehash(address(multiSendCallOnly).codehash, true);
    }

    /// @dev A storage-writing "unwrapper" can never be registered on a real guard: its hash is not
    ///      canonical and the canonical set is fixed at deployment, so neither the registration nor the
    ///      hash can be allowed, by anyone. The snapshot tests exercise the digest through the harness.
    function test_storage_writing_unwrapper_can_never_be_registered_on_a_real_guard() public {
        MaliciousMultiSend _evil = new MaliciousMultiSend(MODULES_HEAD_SLOT, _word(attacker));
        CuratorGuard _real = new CuratorGuard(0, vetro, council);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.UnwrapperCodehashNotAllowed.selector, address(_evil).codehash));
        _real.setUnwrapperCodehash(address(_evil).codehash, true);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.UnwrapperCodehashNotAllowed.selector, address(_evil).codehash));
        _real.setMultiSendUnwrapper(address(safe), address(_evil), true);
    }

    /*//////////////////////////////////////////////////////////////
                     ROUND-1 REGRESSIONS: RULE / SET LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    function test_stale_oneOf_set_is_cleared_when_the_rule_is_dropped() public {
        _enforce();
        _allowWithRules(address(token), APPROVE, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        bytes32[] memory _spenders = new bytes32[](1);
        _spenders[0] = _word(attacker);
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(token), APPROVE, 0, _spenders);
        assertEq(guard.allowedValues(address(safe), address(token), APPROVE, 0).length, 1);

        // Tighten to a different rule (no OneOf on word 0): the set must not survive dormant.
        _allowWithRules(address(token), APPROVE, _rule(CuratorGuardPolicy.RuleKind.EqualTo, 0, _word(address(protocol))));
        assertEq(guard.allowedValues(address(safe), address(token), APPROVE, 0).length, 0, "set cleared with its rule");

        // Re-introducing OneOf starts empty: the old spender is not resurrected.
        _allowWithRules(address(token), APPROVE, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(token), APPROVE, uint16(0), _word(attacker))
        );
        _execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (attacker, 1)), Operation.Call);
    }

    function test_oneOf_set_is_preserved_while_the_rule_is_kept() public {
        _enforce();
        _allowWithRules(address(token), APPROVE, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        bytes32[] memory _spenders = new bytes32[](1);
        _spenders[0] = _word(address(protocol));
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(token), APPROVE, 0, _spenders);
        // Re-allow with the same OneOf plus an amount cap: the spender set survives.
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](2);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0);
        _rules[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 1, bytes32(uint256(1e6)));
        _allowWithRules(address(token), APPROVE, _rules);
        assertEq(guard.allowedValues(address(safe), address(token), APPROVE, 0).length, 1);
        assertTrue(_execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (address(protocol), 1e6)), Operation.Call));
    }

    function test_bounded_range_rejects_dirty_high_bits_and_negative_ints() public {
        _enforce();
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](2);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.GreaterThanOrEqual, 1, bytes32(uint256(10)));
        _rules[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 1, bytes32(uint256(type(uint128).max)));
        _allowWithRules(address(token), APPROVE, _rules);
        assertTrue(_execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (address(protocol), 10)), Operation.Call));

        bytes32 _dirty = bytes32((uint256(1) << 200) | 7); // decodes to 7 on an ABI-coder-v1 callee
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(token), APPROVE, uint16(1), _dirty));
        _execSafeTx(address(token), 0, abi.encodePacked(APPROVE, _word(address(protocol)), _dirty), Operation.Call);

        bytes32 _negative = bytes32(type(uint256).max); // int256(-1)
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(token), APPROVE, uint16(1), _negative));
        _execSafeTx(address(token), 0, abi.encodePacked(APPROVE, _word(address(protocol)), _negative), Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
                    ROUND-1 REGRESSIONS: APPROVAL LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    /// @dev No live approval ever coexists with `Bypass`: opening a window voids every outstanding
    ///      approval, none can be issued while it is open, and what executed unconsumed inside the
    ///      window cannot replay once enforcement resumes.
    function test_bypass_voids_approvals_and_refuses_new_ones_so_nothing_replays() public {
        bytes memory _data = abi.encodeCall(IERC20.transfer, (attacker, 5));
        bytes32 _id = _approve(address(token), 0, _data, Operation.Call);
        vm.prank(vetro);
        vm.expectEmit(true, false, false, true);
        emit CuratorGuardPolicy.ApprovalsRevoked(address(safe), 1);
        guard.bypass(address(safe), 1 days);
        assertEq(guard.approvalExpiry(_id), 0, "voided when the window opened");
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Bypass));
        (uint64 _until, ) = guard.bypassWindow(address(safe));
        assertEq(_until, uint64(block.timestamp + 1 days));

        assertTrue(_execSafeTx(address(token), 0, _data, Operation.Call), "inert: anything passes");
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.SafeInBypass.selector, address(safe)));
        guard.approveTransaction(address(safe), address(0), address(token), 0, _data, Operation.Call, uint64(1 days));
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.SafeInBypass.selector, address(safe)));
        guard.approveTransaction(address(safe), address(0), address(token), 0, _data, Operation.Call, uint64(1 days));

        _enforce();
        (_until, ) = guard.bypassWindow(address(safe));
        assertEq(_until, 0);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(token), TRANSFER));
        _execSafeTx(address(token), 0, _data, Operation.Call);
        assertEq(token.balanceOf(attacker), 5, "executed exactly once");
    }

    /// @dev A failed approved execution reverts the whole Safe transaction whatever `safeTxGas` says:
    ///      with `safeTxGas == 0` (and the gas-refund path closed) the Safe reverts it itself (GS013),
    ///      otherwise it reports `success == false` and the post-hook reverts (`ApprovedExecutionFailed`).
    ///      A consumed approval can therefore never be lost to a failed run and the guard needs no
    ///      restore-on-failure state (round 8, R8D-1: the pre-check no longer demands `safeTxGas == 0`).
    function test_approved_execution_failure_reverts_whole_whatever_safeTxGas() public {
        Reverter _reverter = new Reverter();
        bytes memory _data = hex"deadbeef";
        bytes32 _id = _approve(address(_reverter), 0, _data, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ApprovedExecutionFailed.selector, address(safe)));
        _execSafeTxWithGas(address(_reverter), 0, _data, Operation.Call, 100_000);
        assertGt(guard.approvalExpiry(_id), 0, "approval untouched by the reverted attempt");
        vm.expectRevert(bytes("GS013"));
        _execSafeTx(address(_reverter), 0, _data, Operation.Call);
        assertGt(guard.approvalExpiry(_id), 0, "approval untouched by the reverted execution");
        // A policy-path transaction is free to use safeTxGas (success is irrelevant to the policy).
        _enforce();
        _allow(address(protocol), SETTLE);
        assertTrue(_execSafeTxWithGas(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call, 100_000));
    }

    function test_revokeAllApprovals_voids_every_outstanding_approval() public {
        bytes memory _a = abi.encodeCall(MockProtocol.settleDeposit, (1));
        bytes memory _b = abi.encodeCall(MockProtocol.settleDeposit, (2));
        bytes32 _idA = _approve(address(protocol), 0, _a, Operation.Call);
        _approve(address(protocol), 0, _b, Operation.Call);
        vm.prank(vetro);
        guard.setGuardian(address(safe), guardian, true);
        vm.prank(guardian);
        guard.revokeAllApprovals(address(safe));
        assertEq(guard.approvalEpoch(address(safe)), 1);
        assertNotEq(guard.computeApprovalId(address(safe), address(0), address(protocol), 0, _a, Operation.Call), _idA);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, _a, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, _b, Operation.Call);
        // Approvals issued after the bump work.
        _approve(address(protocol), 0, _a, Operation.Call);
        assertTrue(_execSafeTx(address(protocol), 0, _a, Operation.Call));
    }

    function test_owner_safe_is_never_constrained_so_self_install_cannot_deadlock() public {
        CuratorGuard _ownedBySafe = new CuratorGuard(0, address(safe), address(0));
        bytes memory _install = abi.encodeCall(ISafe.setGuard, (address(_ownedBySafe)));
        _approve(address(safe), 0, _install, Operation.Call);
        assertTrue(_execSafeTx(address(safe), 0, _install, Operation.Call));
        assertEq(_installedGuard(), address(_ownedBySafe));
        // Unconfigured (Lockdown) for everyone else, but the owner Safe passes anything…
        assertTrue(_execSafeTx(address(token), 0, abi.encodeCall(IERC20.transfer, (attacker, 1)), Operation.Call));
        // …including removing the guard again.
        assertTrue(_execSafeTx(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call));
        assertEq(_installedGuard(), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                  ROUND-1 REGRESSIONS: FALLBACK HANDLER POLICY
    //////////////////////////////////////////////////////////////*/

    function test_required_fallback_handler_is_enforced_before_the_policy() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        // The fixture Safe has no handler: requiring address(0) is satisfied.
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(safe), address(0), true);
        assertTrue(_execSafeTx(address(protocol), 0, _settle, Operation.Call));

        // Requiring a different handler keeps policy traffic flowing while the Safe has NO handler (nothing
        // signs, nothing is forwarded: always acceptable, round 8 R8H-2)…
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(safe), attacker, true);
        assertTrue(_execSafeTx(address(protocol), 0, _settle, Operation.Call));
        // …but a handler the policy does not name freezes it until the Safe matches…
        address _other = makeAddr("otherHandler");
        bytes memory _setOther = abi.encodeWithSignature("setFallbackHandler(address)", _other);
        _approve(address(safe), 0, _setOther, Operation.Call);
        assertTrue(_execSafeTx(address(safe), 0, _setOther, Operation.Call));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FallbackHandlerNotAllowed.selector, _other));
        _execSafeTx(address(protocol), 0, _settle, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FallbackHandlerNotAllowed.selector, _other));
        guard.validateTransaction(address(safe), address(protocol), 0, _settle, Operation.Call);

        // …which happens through an approved self-call, after which traffic resumes.
        bytes memory _setHandler = abi.encodeWithSignature("setFallbackHandler(address)", attacker);
        _approve(address(safe), 0, _setHandler, Operation.Call);
        assertTrue(_execSafeTx(address(safe), 0, _setHandler, Operation.Call));
        assertTrue(_execSafeTx(address(protocol), 0, _settle, Operation.Call));
        // The required handler is never the Safe itself nor the guard (a handler forwards hook calls).
        vm.startPrank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(safe)));
        guard.setRequiredFallbackHandler(address(safe), address(safe), true);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(guard)));
        guard.setRequiredFallbackHandler(address(safe), address(guard), true);
        vm.stopPrank();

        // Disabling enforcement restores the previous behaviour.
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(safe), address(0), false);
        (address _handler, bool _enforce) = guard.requiredFallbackHandler(address(safe));
        assertFalse(_enforce);
        assertEq(_handler, address(0));
        assertTrue(_execSafeTx(address(protocol), 0, _settle, Operation.Call));
    }

    /*//////////////////////////////////////////////////////////////
                        REVOCATION & VIEW SURFACE
    //////////////////////////////////////////////////////////////*/

    function test_revokeFunction_clears_oneOf_sets_and_prunes_target() public {
        _enforce();
        _allowWithRules(address(token), APPROVE, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        bytes32[] memory _spenders = new bytes32[](2);
        _spenders[0] = _word(address(protocol));
        _spenders[1] = _word(attacker);
        vm.prank(vetro);
        guard.addAllowedValues(address(safe), address(token), APPROVE, 0, _spenders);
        assertEq(guard.allowedValues(address(safe), address(token), APPROVE, 0).length, 2);
        assertEq(guard.targets(address(safe)).length, 1);
        assertEq(guard.selectors(address(safe), address(token)).length, 1);

        vm.prank(vetro);
        guard.revokeFunction(address(safe), address(token), APPROVE);
        assertEq(guard.allowedValues(address(safe), address(token), APPROVE, 0).length, 0, "stale set cleared");
        assertEq(guard.targets(address(safe)).length, 0, "target pruned");
        (bool _allowed, , CuratorGuardPolicy.ParamRule[] memory _rules) = guard.functionPermission(address(safe), address(token), APPROVE);
        assertFalse(_allowed);
        assertEq(_rules.length, 0);

        // Re-allowing with the same OneOf rule starts from an empty set: fails closed.
        _allowWithRules(address(token), APPROVE, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(token), APPROVE, uint16(0), _word(attacker))
        );
        _execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (attacker, 1)), Operation.Call);
    }

    function test_revokeTarget_removes_everything_for_target() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        _allow(address(protocol), DEPOSIT);
        vm.startPrank(vetro);
        guard.setNativeTransferAllowed(address(safe), address(protocol), true);
        assertEq(guard.selectors(address(safe), address(protocol)).length, 2);
        guard.revokeTarget(address(safe), address(protocol));
        vm.stopPrank();
        assertEq(guard.selectors(address(safe), address(protocol)).length, 0);
        assertFalse(guard.isNativeTransferAllowed(address(safe), address(protocol)));
        assertEq(guard.targets(address(safe)).length, 0);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), SETTLE));
        _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
    }

    function test_allowFunctions_batch_and_views() public {
        CuratorGuardPolicy.FunctionSpec[] memory _specs = new CuratorGuardPolicy.FunctionSpec[](2);
        _specs[0] = CuratorGuardPolicy.FunctionSpec(address(protocol), SETTLE, false, _noRules());
        _specs[1] = CuratorGuardPolicy.FunctionSpec(address(token), APPROVE, false, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        vm.prank(vetro);
        guard.allowFunctions(address(safe), _specs);
        assertTrue(_isAllowed(address(safe), address(protocol), SETTLE));
        assertTrue(_isAllowed(address(safe), address(token), APPROVE));
        assertEq(guard.targets(address(safe)).length, 2);
        (bool _allowed, bool _allowValue, CuratorGuardPolicy.ParamRule[] memory _rules) = guard.functionPermission(
            address(safe),
            address(token),
            APPROVE
        );
        assertTrue(_allowed);
        assertFalse(_allowValue);
        assertEq(_rules.length, 1);
        assertEq(uint8(_rules[0].kind), uint8(CuratorGuardPolicy.RuleKind.OneOf));
    }

    function test_validateTransaction_mirrors_live_check() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        guard.validateTransaction(address(safe), address(protocol), 0, _data, Operation.Call);

        _enforce();
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), SETTLE));
        guard.validateTransaction(address(safe), address(protocol), 0, _data, Operation.Call);

        _allow(address(protocol), SETTLE);
        guard.validateTransaction(address(safe), address(protocol), 0, _data, Operation.Call);

        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, ISafe.setGuard.selector));
        guard.validateTransaction(address(safe), address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call);

        // Approvals are honoured but not consumed by the dry run.
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(safe),
            0,
            abi.encodeCall(ISafe.setGuard, (address(0))),
            Operation.Call,
            uint64(1 hours)
        );
        guard.validateTransaction(address(safe), address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call);
        assertGt(guard.approvalExpiry(_id), 0);
    }

    /*//////////////////////////////////////////////////////////////
                        LAGOON-SHAPED SCENARIO
    //////////////////////////////////////////////////////////////*/

    /// @dev The policy a Vetro Lagoon Safe needs: approve the vault as spender, settle, and nothing
    ///      that moves assets elsewhere.
    function test_lagoon_shaped_policy() public {
        _enforce();
        _registerMultiSend();
        CuratorGuardPolicy.FunctionSpec[] memory _specs = new CuratorGuardPolicy.FunctionSpec[](2);
        _specs[0] = CuratorGuardPolicy.FunctionSpec(address(protocol), SETTLE, false, _noRules());
        _specs[1] = CuratorGuardPolicy.FunctionSpec(address(token), APPROVE, false, _rule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0));
        bytes32[] memory _spenders = new bytes32[](1);
        _spenders[0] = _word(address(protocol));
        vm.startPrank(vetro);
        guard.allowFunctions(address(safe), _specs);
        guard.addAllowedValues(address(safe), address(token), APPROVE, 0, _spenders);
        vm.stopPrank();

        // Curator batch: approve vault + settle.
        bytes memory _batch = _multiSendCalldata(
            abi.encodePacked(
                _entry(address(token), 0, abi.encodeCall(IERC20.approve, (address(protocol), 500e6))),
                _entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1_000e6)))
            )
        );
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall));
        assertEq(token.allowance(address(safe), address(protocol)), 500e6);
        assertEq(protocol.lastAmount(), 1_000e6);

        // Exfiltration attempts.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(token), TRANSFER));
        _execSafeTx(address(token), 0, abi.encodeCall(IERC20.transfer, (attacker, 1)), Operation.Call);
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(token), APPROVE, uint16(0), _word(attacker))
        );
        _execSafeTx(address(token), 0, abi.encodeCall(IERC20.approve, (attacker, 1)), Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.NativeTransferNotAllowed.selector, attacker));
        _execSafeTx(attacker, 1 ether, "", Operation.Call);
        assertEq(token.balanceOf(address(safe)), 1_000_000e6);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _registerMultiSend() internal {
        _registerUnwrapper(address(multiSendCallOnly));
    }
}
