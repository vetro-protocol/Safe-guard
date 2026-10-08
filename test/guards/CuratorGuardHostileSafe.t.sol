// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {ISafeModuleGuard, ISafeTransactionGuard, Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {StrangersBase} from "test/guards/CuratorGuardStrangersBase.sol";

/// @dev The hostile "Safe". The hooks first ask the caller's
///      `getStorageAt` for its guard slot (V2-88) and the policy path is pinned to genuine Safe code
///      (V2-85), so this contract claims "installed" and then only ever reaches the approval and
///      window paths. Every `getStorageAt` re-enters the guard with whatever the test programmed.
contract HostileSafe {
    enum Reenter {
        None,
        PreHook,
        PostHook,
        ModulePreHook,
        LockdownSibling,
        RevokeSiblingApproval,
        DryRunSibling,
        ExecuteBeforeLockdown
    }

    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 internal constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    CuratorGuard public guard;
    address public sibling;
    bytes32 public siblingApproval;
    Reenter public reenter;
    bool public sane;
    bool public installed;
    address public moduleOfThis;

    constructor(CuratorGuard guard_, address sibling_, address moduleOfThis_) {
        guard = guard_;
        sibling = sibling_;
        moduleOfThis = moduleOfThis_;
    }

    function set(Reenter r_, bool sane_, bool installed_, bytes32 siblingApproval_) external {
        reenter = r_;
        sane = sane_;
        installed = installed_;
        siblingApproval = siblingApproval_;
    }

    /// @dev Nothing here may write storage (the views run under the guard's STATICCALL): the result is
    ///      signalled by the SHAPE of the answer (well-formed only when the re-entrant call succeeded).
    function _reentrantCallSucceeded() internal returns (bool) {
        Reenter _r = reenter;
        if (_r == Reenter.None) return true;
        bytes memory _call;
        if (_r == Reenter.PreHook) {
            _call = abi.encodeCall(
                ISafeTransactionGuard.checkTransaction,
                (sibling, 0, "", Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(this))
            );
        } else if (_r == Reenter.PostHook) {
            _call = abi.encodeCall(ISafeTransactionGuard.checkAfterExecution, (bytes32(uint256(1)), true));
        } else if (_r == Reenter.ModulePreHook) {
            _call = abi.encodeCall(ISafeModuleGuard.checkModuleTransaction, (sibling, 0, "", Operation.Call, moduleOfThis));
        } else if (_r == Reenter.LockdownSibling) {
            _call = abi.encodeCall(CuratorGuardPolicy.lockdown, (sibling));
        } else if (_r == Reenter.RevokeSiblingApproval) {
            _call = abi.encodeCall(CuratorGuardPolicy.revokeApproval, (siblingApproval));
        } else if (_r == Reenter.DryRunSibling) {
            _call = abi.encodeCall(CuratorGuard.validateTransaction, (sibling, sibling, 0, "", Operation.Call));
        } else {
            _call = abi.encodeCall(CuratorGuardPolicy.executeBefore, (type(uint64).max, abi.encodeCall(CuratorGuardPolicy.lockdown, (sibling))));
        }
        (bool _ok, ) = address(guard).call{gas: 300_000}(_call);
        return _ok;
    }

    function masterCopy() external pure returns (bytes32) {
        return keccak256("garbage");
    }

    function getOwners() external view returns (address[] memory _owners) {
        _owners = new address[](1);
        _owners[0] = address(0xbeef);
    }

    function getStorageAt(uint256 slot_, uint256 words_) external returns (bytes memory _ret) {
        if (!sane || !_reentrantCallSucceeded()) {
            assembly {
                mstore(0, 0xdeadbeef)
                return(0x1b, 5) // five raw bytes: no ABI shape at all
            }
        }
        _ret = new bytes(32 * words_);
        if (installed && (slot_ == uint256(GUARD_SLOT) || slot_ == uint256(MODULE_GUARD_SLOT))) {
            address _g = address(guard);
            assembly {
                mstore(add(_ret, 0x20), _g)
            }
        }
    }

    function call(bytes calldata data_) external returns (bool _ok, bytes memory _ret) {
        (_ok, _ret) = address(guard).call(data_);
    }

    receive() external payable {}
}

contract Donor {
    constructor(address payable to_) payable {
        selfdestruct(to_);
    }
}

contract CuratorGuardHostileSafeTest is StrangersBase {
    HostileSafe internal hostile;
    bytes32 internal approvalA;
    bytes32 internal ownApproval;

    function setUp() public override {
        super.setUp();
        hostile = new HostileSafe(guard, address(safe), attacker);
        approvalA = _approve(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (7)), Operation.Call);
        // The admin configures the hostile contract as if it were a Safe (the worst case): a policy, a
        // module, approvals on both paths, and (through the council) a guardian seat on A.
        vm.startPrank(vetro);
        guard.enforce(address(hostile));
        guard.allowFunction(address(hostile), address(protocol), SETTLE, false, _noRules());
        guard.setModuleAllowed(address(hostile), attacker, true);
        ownApproval = guard.approveTransaction(address(hostile), address(0), address(safe), 0, "", Operation.Call, 1 days);
        guard.approveTransaction(address(hostile), attacker, address(safe), 0, "", Operation.Call, 1 days);
        vm.stopPrank();
        vm.prank(council);
        guard.setGuardian(address(safe), address(hostile), true);
    }

    function _pre(address to_, bytes memory data_) internal view returns (bytes memory) {
        return
            abi.encodeCall(
                ISafeTransactionGuard.checkTransaction,
                (to_, 0, data_, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", attacker)
            );
    }

    function _settle() internal pure returns (bytes memory) {
        return abi.encodeCall(MockProtocol.settleDeposit, (1));
    }

    /// @dev A non-Safe contract never reaches the policy path, whatever it answers and
    ///      whatever the admin configured for it: not installed, unreadable, or not a supported Safe.
    function test_a_non_safe_never_reaches_the_policy_path() public {
        bytes32 _a = _state(guard, address(safe));
        hostile.set(HostileSafe.Reenter.None, true, false, 0);
        (bool _ok, bytes memory _ret) = hostile.call(_pre(address(protocol), _settle()));
        assertFalse(_ok);
        assertEq(bytes4(_ret), CuratorGuard.GuardNotInstalled.selector, "claims no guard slot: not installed");
        hostile.set(HostileSafe.Reenter.None, false, true, 0);
        (_ok, _ret) = hostile.call(_pre(address(protocol), _settle()));
        assertFalse(_ok);
        assertEq(bytes4(_ret), CuratorGuard.SafeConfigUnreadable.selector, "garbage storage answers: unreadable");
        hostile.set(HostileSafe.Reenter.None, true, true, 0);
        (_ok, _ret) = hostile.call(_pre(address(protocol), _settle()));
        assertFalse(_ok);
        assertEq(bytes4(_ret), CuratorGuard.SafeNotSupported.selector, "claims installed: still not a pinned Safe");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeNotSupported.selector, address(hostile)));
        guard.validateTransaction(address(hostile), address(protocol), 0, _settle(), Operation.Call);
        assertEq(_state(guard, address(safe)), _a, "A untouched");
    }

    /// @dev Re-entrancy from the one read the hooks make before anything else (`getStorageAt` for
    ///      the guard slot): it runs under STATICCALL, so a hook (which must write) and any narrowing
    ///      call, even one the contract is entitled to as a guardian of A, fail there; the view then
    ///      answers garbage and the pre-hook says `SafeConfigUnreadable`. A dry run of the sibling
    ///      answers and changes nothing.
    function test_reentrancy_from_the_installed_read_is_static_and_cannot_reach_a_sibling() public {
        bytes32 _a = _state(guard, address(safe));
        HostileSafe.Reenter[7] memory _kinds = [
            HostileSafe.Reenter.PreHook,
            HostileSafe.Reenter.PostHook,
            HostileSafe.Reenter.ModulePreHook,
            HostileSafe.Reenter.LockdownSibling,
            HostileSafe.Reenter.RevokeSiblingApproval,
            HostileSafe.Reenter.ExecuteBeforeLockdown,
            HostileSafe.Reenter.DryRunSibling
        ];
        for (uint256 i; i < _kinds.length; ++i) {
            hostile.set(_kinds[i], true, true, approvalA);
            // The hostile contract's OWN approved payload: the path that reads nothing but storage slots.
            (bool _ok, bytes memory _ret) = hostile.call(_pre(address(safe), ""));
            if (_kinds[i] == HostileSafe.Reenter.DryRunSibling) {
                assertTrue(_ok, "a view inside the read is fine; the hostile contract spends its own approval");
                (_ok, ) = hostile.call(abi.encodeCall(ISafeTransactionGuard.checkAfterExecution, (bytes32(0), true)));
                assertTrue(_ok);
            } else {
                assertFalse(_ok, "pre-hook refused");
                assertEq(bytes4(_ret), CuratorGuard.SafeConfigUnreadable.selector, "typed as unreadable");
                assertGt(guard.approvalExpiry(ownApproval), 0, "its own approval is not even spent");
            }
            assertEq(_state(guard, address(safe)), _a, "A untouched");
            assertGt(guard.approvalExpiry(approvalA), 0, "A's approval intact");
        }
    }

    /// @dev Between the hooks the hostile contract is just a caller: it only drives its own slot
    ///      (nesting refused, after-hook without pre-hook refused), while a sibling executes freely.
    function test_direct_hook_calls_only_move_the_callers_own_slot() public {
        hostile.set(HostileSafe.Reenter.None, true, true, 0);
        (bool _ok, bytes memory _ret) = hostile.call(abi.encodeCall(ISafeTransactionGuard.checkAfterExecution, (bytes32(0), true)));
        assertFalse(_ok);
        assertEq(bytes4(_ret), CuratorGuard.MissingSnapshot.selector, "post without pre");
        (_ok, ) = hostile.call(_pre(address(safe), ""));
        assertTrue(_ok, "pre (its own approval)");
        (_ok, _ret) = hostile.call(_pre(address(safe), ""));
        assertFalse(_ok);
        assertEq(bytes4(_ret), CuratorGuard.NestedExecution.selector, "pre twice");
        assertTrue(_execSafeTx(address(protocol), 0, _settle(), Operation.Call), "A executes while hostile is in flight");
        (_ok, ) = hostile.call(abi.encodeCall(ISafeTransactionGuard.checkAfterExecution, (bytes32(0), true)));
        assertTrue(_ok, "post clears");
        (_ok, _ret) = hostile.call(abi.encodeCall(ISafeTransactionGuard.checkAfterExecution, (bytes32(0), true)));
        assertFalse(_ok);
        assertEq(bytes4(_ret), CuratorGuard.MissingSnapshot.selector, "post twice");
    }

    function test_reports_are_bound_to_msg_sender() public {
        hostile.set(HostileSafe.Reenter.None, true, true, 0);
        vm.recordLogs();
        (bool _ok, ) = hostile.call(abi.encodeCall(ISafeTransactionGuard.checkAfterExecution, (keccak256("forged-for-A"), true)));
        assertFalse(_ok);
        assertEq(_guardLogs(vm.getRecordedLogs(), CuratorGuard.TransactionChecked.selector), 0, "no report");
        vm.prank(council);
        guard.bypass(address(hostile), 1 hours);
        vm.recordLogs();
        (_ok, ) = hostile.call(abi.encodeCall(ISafeTransactionGuard.checkAfterExecution, (keccak256("forged-for-A"), true)));
        assertTrue(_ok);
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_guardLogs(_logs, CuratorGuard.TransactionChecked.selector), 1, "one report");
        assertEq(address(uint160(uint256(_logs[0].topics[1]))), address(hostile), "about itself, never about A");
    }

    function test_forced_ether_and_tokens_are_stuck_and_inert() public {
        vm.deal(address(this), 10 ether);
        (bool _sent, ) = address(guard).call{value: 1 ether}("");
        assertFalse(_sent, "no receive: a plain transfer reverts");
        new Donor{value: 1 ether}(payable(address(guard)));
        assertEq(address(guard).balance, 1 ether, "forced in");
        token.mint(address(guard), 5e6);
        assertTrue(_execSafeTx(address(protocol), 0, _settle(), Operation.Call), "hooks unaffected");
    }

    function test_late_post_hook_after_a_completed_transaction_is_missing_snapshot() public {
        assertTrue(_execSafeTx(address(protocol), 0, _settle(), Operation.Call));
        vm.prank(address(safe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.MissingSnapshot.selector, address(safe)));
        guard.checkAfterExecution(bytes32(0), true);
    }
}
