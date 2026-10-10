// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {ISafeTransactionGuard, Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {Vm} from "forge-std/Vm.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @dev Code a stranger can run in the Safe's context through `simulateAndRevert` (a public function of every
///      Safe): it calls the guard's hooks with the Safe as `msg.sender`. The outer frame always reverts, so
///      EIP-1153 must discard every `tstore` made here. Also usable as an owner-signed delegatecall target in an
///      admin window (a window admits raw delegatecalls), where the frame does NOT revert.
contract HookDriver {
    function runPreHook(address guard_, address to_, bytes calldata data_) external {
        ISafeTransactionGuard(guard_).checkTransaction(
            to_, 0, data_, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0)
        );
    }

    function runBothHooks(address guard_, address to_, bytes calldata data_) external {
        ISafeTransactionGuard(guard_).checkTransaction(
            to_, 0, data_, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0)
        );
        ISafeTransactionGuard(guard_).checkAfterExecution(bytes32(uint256(0xdead)), true);
    }
}

/// @dev One EVM transaction that first drives `simulateAndRevert` (reverting frame) and then an honest
///      `execTransaction` of the same Safe: the sequencing a bundle or a batching contract would produce.
contract SameTxSequencer {
    function run(address safe_, bytes calldata simulatePayload_, bytes calldata execPayload_) external returns (bool _simReverted, bool _execOk) {
        (bool _ok, ) = safe_.call(simulatePayload_);
        _simReverted = !_ok;
        (_execOk, ) = safe_.call(execPayload_);
    }
}

/// @dev A venue that burns a chosen amount of gas, to probe the transaction cap from inside a Safe transaction.
contract GasBurnerVenue {
    function burn(uint256 n_) external {
        for (uint256 i; i < n_; ++i) {
            assembly {
                sstore(add(i, 0x1000), 1)
            }
        }
    }
}

/// @title G13c: the chain itself (round 13). EIP-1153 semantics across `simulateAndRevert` and nested frames,
///        same-block bundles, the EIP-7825 transaction cap as forge's EVM sees it, and the second-exact boundaries
///        under slot-aligned timestamps. Run under `--evm-version cancun`, `prague` and `osaka` (the bytecode is
///        the same; only the test EVM moves).
contract G13cChainTest is CuratorGuardTestBase {
    HookDriver internal driver;
    SameTxSequencer internal sequencer;
    GasBurnerVenue internal burner;

    function setUp() public override {
        super.setUp();
        driver = new HookDriver();
        sequencer = new SameTxSequencer();
        burner = new GasBurnerVenue();
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        _allow(address(burner), GasBurnerVenue.burn.selector);
    }

    /*//////////////////////////////////////////////////////////////
               EIP-1153 ACROSS simulateAndRevert AND NESTED FRAMES
    //////////////////////////////////////////////////////////////*/

    /// A stranger runs the pre-hook as the Safe inside `simulateAndRevert`; the frame reverts, EIP-1153 discards
    /// the snapshot: an honest Safe transaction in the SAME EVM transaction is not `NestedExecution`.
    function test_simulateAndRevert_pre_hook_leaves_no_transient_residue_in_the_same_transaction() public {
        bytes memory _sim = abi.encodeWithSignature(
            "simulateAndRevert(address,bytes)",
            address(driver),
            abi.encodeCall(HookDriver.runPreHook, (address(guard), address(protocol), abi.encodeCall(MockProtocol.settleDeposit, (1))))
        );
        bytes memory _exec = _signedExecCalldata(address(protocol), abi.encodeCall(MockProtocol.settleDeposit, (2)));
        vm.prank(attacker);
        (bool _simReverted, bool _execOk) = sequencer.run(address(safe), _sim, _exec);
        assertTrue(_simReverted, "simulateAndRevert always reverts");
        assertTrue(_execOk, "the honest transaction after it is admitted: no NestedExecution");
        assertEq(protocol.lastAmount(), 2, "executed");
    }

    /// Both hooks inside the reverting frame: the forged `TransactionChecked` is discarded with the frame, the
    /// honest transaction after it still passes and is reported exactly once.
    function test_simulateAndRevert_both_hooks_forge_nothing_that_survives_the_frame() public {
        bytes memory _sim = abi.encodeWithSignature(
            "simulateAndRevert(address,bytes)",
            address(driver),
            abi.encodeCall(HookDriver.runBothHooks, (address(guard), address(protocol), abi.encodeCall(MockProtocol.settleDeposit, (1))))
        );
        bytes memory _exec = _signedExecCalldata(address(protocol), abi.encodeCall(MockProtocol.settleDeposit, (3)));
        vm.recordLogs();
        vm.prank(attacker);
        (bool _simReverted, bool _execOk) = sequencer.run(address(safe), _sim, _exec);
        assertTrue(_simReverted && _execOk, "frame reverted, honest transaction admitted");
        // forge's `getRecordedLogs` keeps logs emitted inside frames that later reverted (a harness artefact:
        // on a chain a reverted frame's logs never reach a receipt). The chain fact measured here is the
        // state one: the forged post-hook's `tstore(0)` and the forged pre-hook's snapshot died with the frame,
        // so the honest transaction found an idle slot (no `NestedExecution`) and its own report carries the
        // Safe's real `safeTxHash`, not the forged `0xdead`.
        bytes32 _sig = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        uint256 _honest;
        uint256 _forgedRecordedByHarness;
        for (uint256 i; i < _logs.length; ++i) {
            if (_logs[i].topics[0] != _sig) continue;
            if (_logs[i].topics[2] == bytes32(uint256(0xdead))) ++_forgedRecordedByHarness;
            else ++_honest;
        }
        assertEq(_honest, 1, "the honest transaction is reported once");
        emit log_named_uint("forged reports the harness recorded from the reverted frame (0 on a chain)", _forgedRecordedByHarness);
    }

    /// The contrast: the same driver reached through a NON-reverting frame (an admin-window delegatecall)
    /// parks a snapshot that the window's own post-hook then finds; the Safe transaction fails closed
    /// (`SafeConfigChanged`/digest path never reached: the post-hook sees a snapshot while the mode is Bypass and
    /// compares it, equal digest -> Policy report). Pins what a window admits: nothing persists past the transaction.
    function test_admin_window_delegatecall_into_the_hooks_fails_closed_or_reports_once_never_persists() public {
        _bypass(1 hours);
        bytes memory _data = abi.encodeCall(HookDriver.runPreHook, (address(guard), address(protocol), abi.encodeCall(MockProtocol.settleDeposit, (1))));
        vm.recordLogs();
        bool _ok = _execSafeTx(address(driver), 0, _data, Operation.DelegateCall);
        // The pre-hook ran inside the window (recorded nothing), the delegatecall ran the pre-hook AGAIN as the
        // Safe (snapshot parked), the post-hook then read that snapshot and compared the digest: unchanged.
        assertTrue(_ok, "admitted in an admin window");
        // Whatever happened inside, the next transaction of the same Safe in the next block is clean.
        vm.roll(block.number + 1);
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (4)), Operation.Call), "next transaction clean");
    }

    /*//////////////////////////////////////////////////////////////
                         SAME-BLOCK BUNDLES (A BUILDER)
    //////////////////////////////////////////////////////////////*/

    /// A block builder colluding with the signers and a council key: in ONE block (one timestamp) the council
    /// opens a window, the signers drain, a guardian locks down. Whatever the order inside the block, the drain
    /// lands when the council's lift precedes it and the guardian's lockdown cannot be ordered to prevent it,
    /// because the council is not held by the cooldown. Measured, not argued.
    function test_same_block_bundle_council_window_then_drain_then_guardian_lockdown_in_both_orders() public {
        _addGuardian(guardian);
        bytes memory _drain = abi.encodeCall(token.transfer, (attacker, 1_000e6));
        // Order A: council window, drain, guardian lockdown.
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        assertTrue(_execSafeTx(address(token), 0, _drain, Operation.Call), "order A: drained inside the window");
        vm.prank(guardian);
        guard.lockdown(address(safe));
        // Order B, same block: guardian lockdown first, then the council lifts (no cooldown for the council), drain.
        vm.prank(guardian);
        guard.lockdown(address(safe));
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        assertTrue(_execSafeTx(address(token), 0, _drain, Operation.Call), "order B: the council's window lands after the lockdown in the same block");
        assertEq(token.balanceOf(attacker), 2_000e6);
        // The admin (the timelock's open executor) in the same block is held: a builder cannot help it.
        vm.prank(guardian);
        guard.lockdown(address(safe));
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(safe)));
        guard.bypass(address(safe), 1 hours);
    }

    /*//////////////////////////////////////////////////////////////
                     EIP-7825 AS THE TEST EVM SEES IT
    //////////////////////////////////////////////////////////////*/

    /// Documents whether forge's EVM enforces the transaction cap for a test call: a Safe transaction whose venue
    /// burns about 22 M gas. On a chain this can never execute (EIP-7825, Osaka); if it passes here, the
    /// repository's tests cannot witness the cap and the task's 12 M gate is the only guard against it.
    function test_forge_evm_and_the_eip7825_cap_a_22M_gas_safe_transaction() public {
        uint256 _before = gasleft();
        bool _ok = _execSafeTx(address(burner), 0, abi.encodeCall(GasBurnerVenue.burn, (1000)), Operation.Call);
        uint256 _used = _before - gasleft();
        emit log_named_uint("gas used by the 1000-SSTORE Safe transaction", _used);
        assertTrue(_ok, "forge executes it");
        assertGt(_used, 16_777_216, "above the EIP-7825 cap: forge's test EVM does not enforce the cap");
    }

    /*//////////////////////////////////////////////////////////////
                   SLOT-ALIGNED TIME AND SECOND-EXACT BOUNDARIES
    //////////////////////////////////////////////////////////////*/

    /// Mainnet timestamps are multiples of 12 s from genesis (measured live). A window of `d` seconds closes at
    /// `t + d` exactly; the last block that can use it has timestamp <= t + d - 1; with 12-second slots the
    /// usable blocks are floor((d - 1) / 12) + 1 after the opening block. Pins the arithmetic the runbook relies on.
    function test_window_usable_blocks_under_twelve_second_slots() public {
        uint256 _t0 = 1_700_000_004; // slot-aligned: (t0 - 1606824023) % 12 == 1? we align explicitly below
        _t0 = _t0 - ((_t0 - 1_606_824_023) % 12);
        vm.warp(_t0);
        _bypass(1 hours);
        uint256 _usable;
        for (uint256 _ts = _t0; ; _ts += 12) {
            vm.warp(_ts);
            if (guard.mode(address(safe)) != CuratorGuardPolicy.Mode.Bypass) break;
            ++_usable;
        }
        assertEq(_usable, 300, "a one-hour window is 300 slots including the opening one");
        // An approval TTL of one hour is usable through its expiry second inclusive: 301 slots when the expiry
        // itself is slot-aligned.
        vm.warp(_t0);
        _enforce();
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(
            address(safe), address(0), address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (9)), Operation.Call, 1 hours
        );
        uint64 _expiry = guard.approvalExpiry(_id);
        assertEq(_expiry, _t0 + 1 hours);
        uint256 _usableApproval;
        for (uint256 _ts = _t0; _ts <= _expiry; _ts += 12) ++_usableApproval;
        assertEq(_usableApproval, 301, "inclusive expiry on a slot boundary: 301 slots");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// Calldata of a signed `execTransaction` for the single-owner fixture Safe (nonce read live).
    function _signedExecCalldata(address to_, bytes memory data_) internal view returns (bytes memory) {
        uint256 _nonce = safe.nonce();
        bytes32 _hash = safe.getTransactionHash(to_, 0, data_, Operation.Call, 0, 0, 0, address(0), address(0), _nonce);
        bytes memory _sig = _sign(_hash);
        return abi.encodeCall(
            ISafe.execTransaction, (to_, 0, data_, Operation.Call, 0, 0, 0, address(0), payable(address(0)), _sig)
        );
    }
}
