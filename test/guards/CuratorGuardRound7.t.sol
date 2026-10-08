// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, CuratorGuardTestBase, MaliciousMultiSend, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

/// @dev Round 7 (docs/curator-guard.md section 13.2, V2-76): the tests the mutation campaign found
///      missing. Each one kills a mutant that survived the suite: a one-byte-short council payload
///      typed instead of a bare revert, the canonical 36-byte `setFallbackHandler(0)`, a partial
///      selector self-call on the policy path, the admin acting on itself as a Safe, and a tightened
///      expectation for a singleton swapped mid-transaction.
contract CuratorGuardRound7Test is CuratorGuardTestBase {
    bytes4 internal constant ADD_OWNER = bytes4(keccak256("addOwnerWithThreshold(address,uint256)"));
    bytes4 internal constant REMOVE_OWNER = bytes4(keccak256("removeOwner(address,address,uint256)"));
    bytes4 internal constant SWAP_OWNER = bytes4(keccak256("swapOwner(address,address,address)"));
    bytes4 internal constant CHANGE_THRESHOLD = bytes4(keccak256("changeThreshold(uint256)"));
    bytes4 internal constant SET_FALLBACK_HANDLER = bytes4(keccak256("setFallbackHandler(address)"));

    /// @dev Kills P36: an owner-management payload one byte short of its threshold (or owner) word is
    ///      typed for the council everywhere (approval, window, dry run), never a calldata-slice panic.
    function test_owner_management_payload_one_byte_short_is_typed_for_the_council() public {
        bytes[4] memory _short = [
            abi.encodePacked(CHANGE_THRESHOLD, bytes31(0)), // 35 bytes: threshold word (4:36) cut short
            abi.encodePacked(ADD_OWNER, _word(attacker), bytes31(0)), // 67 bytes: threshold word (36:68) cut short
            abi.encodePacked(REMOVE_OWNER, _word(address(0x1)), _word(curator), bytes31(0)), // 99 bytes: threshold word (68:100)
            abi.encodePacked(SWAP_OWNER, _word(address(0x1)), _word(curator), bytes31(0)) // 99 bytes: new-owner word (68:100)
        ];
        for (uint256 i; i < _short.length; ++i) {
            bytes4 _sel = bytes4(_short[i]);
            vm.prank(council);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, _sel, Operation.Call));
            guard.approveTransaction(address(safe), address(0), address(safe), 0, _short[i], Operation.Call, 1 days);
        }
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        for (uint256 i; i < _short.length; ++i) {
            bytes4 _sel = bytes4(_short[i]);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, _sel));
            guard.validateTransaction(address(safe), address(safe), 0, _short[i], Operation.Call);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, _sel));
            _execSafeTx(address(safe), 0, _short[i], Operation.Call);
        }
    }

    /// @dev Kills P27: `setFallbackHandler(0)` is accepted on the council lane only in its canonical
    ///      36-byte form; a longer payload (trailing bytes the Safe's decoder would ignore) is refused.
    function test_council_setFallbackHandler_zero_must_be_the_canonical_36_bytes() public {
        bytes memory _canonical = abi.encodeWithSelector(SET_FALLBACK_HANDLER, address(0));
        assertEq(_canonical.length, 36);
        assertGt(guard.approvalExpiry(_councilApprove(address(safe), 0, _canonical, Operation.Call)), 0, "canonical form");
        bytes[2] memory _long = [
            abi.encodePacked(_canonical, bytes1(0)), // 37 bytes
            abi.encodePacked(_canonical, bytes32(0)) // 68 bytes: a second zero word
        ];
        for (uint256 i; i < _long.length; ++i) {
            vm.prank(council);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, SET_FALLBACK_HANDLER, Operation.Call));
            guard.approveTransaction(address(safe), address(0), address(safe), 0, _long[i], Operation.Call, 1 days);
            assertGt(guard.approvalExpiry(_approve(address(safe), 0, _long[i], Operation.Call)), 0, "admin may");
        }
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        for (uint256 i; i < _long.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, SET_FALLBACK_HANDLER));
            guard.validateTransaction(address(safe), address(safe), 0, _long[i], Operation.Call);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, SET_FALLBACK_HANDLER));
            _execSafeTx(address(safe), 0, _long[i], Operation.Call);
        }
        guard.validateTransaction(address(safe), address(safe), 0, _canonical, Operation.Call);
    }

    /// @dev Kills G53: the policy's one self-call exception is the EMPTY zero-value call; a self-call
    ///      carrying one to three bytes (no selector) is `SelfCallNotAllowed(0)` live and in the dry run.
    function test_policy_refuses_a_self_call_with_a_partial_selector() public {
        _enforce();
        bytes[3] memory _short = [bytes(hex"00"), bytes(hex"0d58"), bytes(hex"e19a9d")];
        for (uint256 i; i < _short.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, bytes4(0)));
            _execSafeTx(address(safe), 0, _short[i], Operation.Call);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, bytes4(0)));
            guard.validateTransaction(address(safe), address(safe), 0, _short[i], Operation.Call);
        }
        // The exception itself still holds.
        assertTrue(_execSafeTx(address(safe), 0, "", Operation.Call), "Safe{Wallet} reject");
    }

    /// @dev Kills P70: "no role holder can act on itself as a Safe" includes the admin. The admin may
    ///      not `enforce`, open a window or approve for ITSELF (a stale self-configuration would become
    ///      live the day the role moves on), while any other Safe is unaffected.
    function test_the_admin_cannot_authorize_itself_as_a_safe_either() public {
        address _other = makeAddr("other-safe");
        vm.startPrank(vetro);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.enforce(vetro);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.bypass(vetro, 1 hours);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.approveTransaction(vetro, address(0), address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call, 1 days);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.executeBefore(uint64(block.timestamp), abi.encodeCall(guard.enforce, (vetro)));
        guard.enforce(_other);
        guard.enforce(address(safe));
        vm.stopPrank();
        assertEq(uint8(guard.mode(vetro)), uint8(CuratorGuardPolicy.Mode.Lockdown), "the admin carries no configuration");
        (uint64 _until, ) = guard.bypassWindow(vetro);
        assertEq(_until, 0);
        assertEq(uint8(guard.mode(_other)), uint8(CuratorGuardPolicy.Mode.Enforced));
    }

    function test_singleton_swapped_to_an_eoa_mid_transaction_is_typed_SafeConfigUnreadable() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        MaliciousMultiSend _evil = new MaliciousMultiSend(bytes32(uint256(0)), _word(attacker));
        _registerUnwrapper(address(_evil));
        bytes memory _batch = _multiSendCalldata(_entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (7))));
        bytes32 _singletonBefore = vm.load(address(safe), bytes32(uint256(0)));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeNotSupported.selector, address(safe))); // the Safe code pin answers first (V2-85)
        _execSafeTx(address(_evil), 0, _batch, Operation.DelegateCall);
        assertEq(vm.load(address(safe), bytes32(uint256(0))), _singletonBefore, "singleton intact");
        assertEq(protocol.calls(), 0, "nothing executed");
    }
}

/// @dev Minimal Safe module (same shape as `CuratorGuardModule.t.sol`'s `DummyModule`).
contract Round7Module {
    function exec(ISafe safe_, address to_, uint256 value_, bytes calldata data_, Operation op_) external returns (bool) {
        return safe_.execTransactionFromModule(to_, value_, data_, op_);
    }
}

/// @dev Round 7 (V2-76): mutation-campaign killers on the v1.5.0 module path.
contract CuratorGuardRound7ModuleTest is SafeTxHelper {
    CuratorGuard internal guard;
    Round7Module internal module;
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
        CuratorGuardHarness(address(guard)).seedSafe(address(safe)); // locally compiled Safe build: seeded, the guard pins canonical Safe code (V2-85)
        module = new Round7Module();
        protocol = new MockProtocol();
        vm.startPrank(address(safe));
        safe.enableModule(address(module));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        vm.stopPrank();
        vm.prank(vetro);
        guard.enforce(address(safe));
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(module), true);
    }

    /// @dev Kills G70: `ApprovalConsumed` names the executor that consumed the approval, the module
    ///      on the module path (monitors tell an owner-signed one-off from an automation key by it).
    function test_ApprovalConsumed_on_the_module_path_names_the_module() public {
        bytes memory _data = abi.encodeCall(MockProtocol.deposit, (1, curator));
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(module), address(protocol), 0, _data, Operation.Call, 1 hours);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuardPolicy.ApprovalConsumed(address(safe), _id, address(module));
        assertTrue(module.exec(safe, address(protocol), 0, _data, Operation.Call));
        assertEq(guard.approvalExpiry(_id), 0, "consumed");
    }
}
