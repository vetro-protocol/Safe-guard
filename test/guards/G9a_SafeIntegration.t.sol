// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";
import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @dev Delegatecalled in the Safe's context through `simulateAndRevert`: calls both hooks as the Safe.
contract HookDriver {
    function drive(address guard_, address to_, bytes calldata data_, bytes32 hash_) external {
        CuratorGuard(guard_).checkTransaction(
            to_, 0, data_, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", msg.sender
        );
        CuratorGuard(guard_).checkAfterExecution(hash_, true);
    }
}

/// @dev Records how much gas the inner call actually received.
contract GasMeter {
    uint256 public seen;

    function probe() external {
        seen = gasleft();
    }
}

/// @dev A fallback handler that strips the 20 appended caller bytes and re-issues the call to the guard
///      at its canonical length, from ITS OWN address.
contract StrippingForwarder {
    address internal immutable guard;

    constructor(address guard_) {
        guard = guard_;
    }

    fallback() external {
        bytes memory _inner = msg.data[:msg.data.length - 20];
        (bool _ok, bytes memory _ret) = guard.call(_inner);
        if (!_ok) {
            assembly {
                revert(add(_ret, 0x20), mload(_ret))
            }
        }
    }
}

/// @title G9a (round 9): Safe-integration properties checked against the vendored v1.4.1 sources and
///        pinned here (what was tried and could not be broken).
contract G9a_SafeIntegrationTest is CuratorGuardTestBase {
    bytes32 internal constant REPORT_SIG = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");

    /// @dev `StorageAccessible.simulateAndRevert` lets anyone run code in the Safe's context, so anyone
    ///      can drive both hooks with the Safe as `msg.sender`; the frame always reverts, so the approval
    ///      it consumed, the transient sentinel it wrote and the report it emitted are all undone.
    function test_simulateAndRevert_can_drive_both_hooks_as_the_safe_but_nothing_survives() public {
        _enforce();
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (7));
        bytes32 _id = _approve(address(protocol), 0, _settle, Operation.Call);
        HookDriver _driver = new HookDriver();
        bytes memory _payload = abi.encodeCall(HookDriver.drive, (address(guard), address(protocol), _settle, keccak256("x")));

        vm.prank(attacker);
        (bool _ok, bytes memory _ret) = address(safe).call(
            abi.encodeWithSignature("simulateAndRevert(address,bytes)", address(_driver), _payload)
        );
        assertFalse(_ok, "simulateAndRevert always reverts");
        // revert data: success word, response length, response. success == 1: both hooks passed inside
        // (the approval was consumed and a report emitted IN THAT FRAME; the frame's revert discards both.
        // Foundry's log recorder keeps logs of reverted frames, so the state is what is asserted here).
        assertEq(uint256(bytes32(_ret)), 1, "the hooks ran as the Safe inside the frame");
        assertGt(guard.approvalExpiry(_id), 0, "approval intact");
        // The transient slot is clean: the genuine approved execution runs (no NestedExecution).
        assertTrue(_execSafeTx(address(protocol), 0, _settle, Operation.Call));
        assertEq(guard.approvalExpiry(_id), 0, "now consumed, once");
    }

    /// @dev Safe v1.4.1 `execTransaction`: with `gasPrice == 0` the inner call receives `gasleft() - 2500`
    ///      (less the EIP-150 retention), whatever `safeTxGas` says; `safeTxGas` is only a FLOOR, checked
    ///      after the pre-hook (GS010). So the guard's gas-refund refusal also means no venue can be
    ///      gas-capped by the signers, and the 64x post-hook floor of docs section 6 follows.
    function test_safeTxGas_is_a_floor_not_a_cap_when_gasPrice_is_zero() public {
        _enforce();
        GasMeter _meter = new GasMeter();
        _allow(address(_meter), GasMeter.probe.selector);
        bytes memory _probe = abi.encodeCall(GasMeter.probe, ());
        assertTrue(_execSafeTxWithGas(address(_meter), 0, _probe, Operation.Call, 50_000));
        assertGt(_meter.seen(), 50_000 * 10, "the inner call got far more than safeTxGas");
        // The floor: a safeTxGas the transaction cannot cover is GS010, raised AFTER the pre-hook ran.
        vm.expectRevert(bytes("GS010"));
        _execSafeTxWithGas(address(_meter), 0, _probe, Operation.Call, uint256(1) << 200);
    }

    /// @dev Reports are keyed by the caller: a handler that strips the appended bytes and re-issues the
    ///      after-hook at 68 bytes is itself the caller, so the report (and the slot) are the handler's,
    ///      never the Safe's.
    function test_a_stripping_handler_cannot_report_for_the_safe() public {
        _enforce();
        StrippingForwarder _forwarder = new StrippingForwarder(address(guard));
        vm.prank(address(safe));
        (bool _ok, ) = address(safe).call(abi.encodeWithSignature("setFallbackHandler(address)", address(_forwarder)));
        assertTrue(_ok);
        vm.prank(attacker);
        bytes memory _ret;
        (_ok, _ret) = address(safe).call(abi.encodeCall(guard.checkAfterExecution, (keccak256("x"), true)));
        assertFalse(_ok);
        assertEq(_ret, abi.encodeWithSelector(CuratorGuard.MissingSnapshot.selector, address(_forwarder)));
    }

    /// @dev The install batch of the runbook (section 7.4), `[setFallbackHandler(0), setGuard(guard)]` as one
    ///      `MultiSendCallOnly` delegatecall: `execTransaction` caches `getGuard()` (zero) before the
    ///      batch, so the freshly installed guard gets no after-hook for the installing transaction and
    ///      the unconfigured Safe is not refused `SafeLockedDown` for it; the very next transaction is.
    function test_install_batch_is_not_post_checked_by_the_guard_it_installs() public {
        address _singleton = abi.decode(_raw(address(safe), abi.encodeWithSelector(0xa619486e)), (address));
        SafeProxy _proxy = new SafeProxy(_singleton);
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(protocol), address(0), 0, payable(address(0)));
        CuratorGuard _fresh = new CuratorGuardHarness(0, vetro, council);
        CuratorGuardHarness(address(_fresh)).seedSafe(address(_proxy));
        ISafe _main = safe;
        safe = ISafe(address(_proxy));

        bytes memory _batch = _multiSendCalldata(
            abi.encodePacked(
                _entry(address(_proxy), 0, abi.encodeWithSignature("setFallbackHandler(address)", address(0))),
                _entry(address(_proxy), 0, abi.encodeCall(ISafe.setGuard, (address(_fresh))))
            )
        );
        vm.recordLogs();
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall), "install batch runs");
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        for (uint256 i; i < _logs.length; ++i) assertTrue(_logs[i].emitter != address(_fresh), "no hook ran on the new guard");
        assertEq(_installedGuard(), address(_fresh));
        assertEq(uint256(bytes32(safe.getStorageAt(uint256(FALLBACK_SLOT), 1))), 0, "handler removed");
        // From the next transaction on the unconfigured Safe is fail-closed.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(_proxy)));
        _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
        safe = _main;
    }

    function _raw(address target_, bytes memory call_) internal view returns (bytes memory _ret) {
        bool _ok;
        (_ok, _ret) = target_.staticcall(call_);
        assertTrue(_ok);
    }
}
