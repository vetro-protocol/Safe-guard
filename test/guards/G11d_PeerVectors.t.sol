// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";
import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, CuratorGuardTestBase, MockProtocol, Reverter} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

/// @dev A venue that takes any selector (and plain value) through its `fallback`, and records it.
contract G11dFallbackVenue {
    uint256 public hits;
    uint256 public lastLength;
    bytes4 public lastSelector;
    uint256 public lastValue;

    fallback() external payable {
        ++hits;
        lastLength = msg.data.length;
        lastSelector = msg.data.length >= 4 ? bytes4(msg.data[:4]) : bytes4(0);
        lastValue = msg.value;
    }

    receive() external payable {
        ++hits;
        lastLength = 0;
        lastValue = msg.value;
    }
}

/// @dev An allowlisted venue that is also a per-Safe guardian: poked inside a batch, it locks the Safe down.
contract G11dGuardianVenue {
    CuratorGuard internal immutable guard;
    address internal immutable safe;

    constructor(CuratorGuard guard_, address safe_) {
        guard = guard_;
        safe = safe_;
    }

    function poke(uint256) external {
        guard.lockdown(safe);
    }
}

/// @dev Executes an arbitrary pre-encoded call and keeps the revert data (a venue nesting the Safe).
contract G11dNester {
    bytes public lastError;

    function run(address target_, bytes calldata call_) external returns (bool ok) {
        bytes memory _ret;
        (ok, _ret) = target_.call(call_);
        if (!ok) lastError = _ret;
    }
}

/// @dev Runs several Safe transactions one after the other inside ONE EVM transaction (not nested).
contract G11dSequencer {
    function run(address safe_, bytes[] calldata calls_) external returns (bool[] memory _results) {
        _results = new bool[](calls_.length);
        for (uint256 i; i < calls_.length; ++i) {
            (bool _ok, bytes memory _ret) = safe_.call(calls_[i]);
            require(_ok, "execTransaction reverted");
            _results[i] = abi.decode(_ret, (bool));
        }
    }
}

/// @dev Minimal Safe module (v1.5.0 fixture).
contract G11dModule {
    function exec(ISafe safe_, address to_, uint256 value_, bytes calldata data_, Operation op_) external returns (bool) {
        return safe_.execTransactionFromModule(to_, value_, data_, op_);
    }
}

/// @dev The Gnosis Pay shape: a role holder whose `getStorageAt` REVERTS with data shaped exactly like a
///      Safe's answer naming `answer` (96 bytes: offset, length, the word). A forwarding probe that
///      ignored the `staticcall` success flag would take it for a Safe forwarding to `answer`.
contract G11dShapedRevertHolder {
    address internal immutable answer;

    constructor(address answer_) {
        answer = answer_;
    }

    function getStorageAt(uint256, uint256) external view returns (bytes memory) {
        bytes memory _shaped = abi.encode(abi.encodePacked(bytes32(uint256(uint160(answer)))));
        assembly {
            revert(add(_shaped, 0x20), mload(_shaped))
        }
    }

    function lockdown(CuratorGuard guard_, address safe_) external {
        guard_.lockdown(safe_);
    }

    function schedule(CuratorGuardTimelock timelock_, address target_, bytes calldata data_) external {
        timelock_.schedule(target_, 0, data_, bytes32(0), bytes32(0), timelock_.getMinDelay());
    }
}

/// @dev A Safe look-alike whose `masterCopy()` REVERTS with 32 bytes naming itself (a seeded hash), and
///      answers the configuration views healthily otherwise.
contract G11dShapedRevertSafe {
    address internal immutable owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function masterCopy() external view returns (address) {
        bytes memory _shaped = abi.encode(address(this));
        assembly {
            revert(add(_shaped, 0x20), mload(_shaped))
        }
    }

    function getOwners() external view returns (address[] memory _owners) {
        _owners = new address[](1);
        _owners[0] = owner;
    }

    function getStorageAt(uint256, uint256 length_) external pure returns (bytes memory) {
        return new bytes(32 * length_);
    }
}

/// @title Round 11 (g11d): the peers' published failure modes as vectors (Safe v1.4.1 fixture).
/// @notice Policy Engine README edge list (1-3-byte calldata, value to `address(0)` through fallback
///         selectors, targets with fallback functions, batch entries against pre-batch state),
///         HatsSignerGate Sherlock #41 (nested `execTransaction`) and #52 (recomputed versus snapshot),
///         the OLAS stuck lock on `success == false`, and the Gnosis Pay `staticcall` success check.
///         Every test passes on the shipped code; the cross-references name the earlier pins.
contract G11dPeerVectorsTest is CuratorGuardTestBase {
    bytes32 internal constant CHECKED_SIG = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");
    bytes32 internal constant MODE_SIG = keccak256("ModeUpdated(address,uint8,uint64,bool)");
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;
    bytes4 internal constant SEL = 0x11223344;
    bytes4 internal constant OTHER = 0x55667788;

    /*//////////////////////////////////////////////////////////////
                         POLICY ENGINE README EDGES
    //////////////////////////////////////////////////////////////*/

    /// @dev 1, 2 and 3 bytes of calldata are `MalformedCalldata` on the policy path, at top level and as a
    ///      batch entry, live and in the dry run; inside a council window they reach the venue's fallback
    ///      unchanged (cross-reference: `CuratorGuard.t.sol` short calldata, `G10b_AbiEdges`).
    function test_pe_one_to_three_bytes_of_calldata_are_malformed_on_the_policy_path_and_pass_only_inside_a_window() public {
        G11dFallbackVenue _venue = new G11dFallbackVenue();
        _enforce();
        _allow(address(_venue), SEL);
        _registerUnwrapper(address(multiSendCallOnly));
        for (uint256 _len = 1; _len <= 3; ++_len) {
            bytes memory _data = new bytes(_len);
            for (uint256 i; i < _len; ++i) _data[i] = 0xab;
            vm.expectRevert(CuratorGuard.MalformedCalldata.selector);
            _execSafeTx(address(_venue), 0, _data, Operation.Call);
            vm.expectRevert(CuratorGuard.MalformedCalldata.selector);
            _execSafeTx(address(multiSendCallOnly), 0, _multiSendCalldata(_entry(address(_venue), 0, _data)), Operation.DelegateCall);
            vm.expectRevert(CuratorGuard.MalformedCalldata.selector);
            guard.validateTransaction(address(safe), address(_venue), 0, _data, Operation.Call);
        }
        assertEq(_venue.hits(), 0);

        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        for (uint256 _len = 1; _len <= 3; ++_len) {
            bytes memory _data = new bytes(_len);
            assertTrue(_execSafeTx(address(_venue), 0, _data, Operation.Call), "a window passes the bytes through");
            assertEq(_venue.lastLength(), _len);
        }
        assertEq(_venue.hits(), 3);
    }

    /// @dev `address(0)` can neither be allowlisted (a function or the native lane: `InvalidTarget`) nor
    ///      reached on the policy path with value, with or without a selector, at top level or as a batch
    ///      entry (cross-reference: `CuratorGuardV2.t.sol` zero-`to` entry).
    function test_pe_the_zero_address_is_never_a_target_and_never_receives_value() public {
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(0)));
        guard.allowFunction(address(safe), address(0), SEL, true, _noRules());
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, address(0)));
        guard.setNativeTransferAllowed(address(safe), address(0), true);

        _enforce();
        _registerUnwrapper(address(multiSendCallOnly));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.NativeTransferNotAllowed.selector, address(0)));
        _execSafeTx(address(0), 1 wei, "", Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(0), SEL));
        _execSafeTx(address(0), 1 wei, abi.encodePacked(SEL), Operation.Call);
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        _execSafeTx(address(multiSendCallOnly), 0, _multiSendCalldata(_entry(address(0), 1 wei, "")), Operation.DelegateCall);
        assertEq(address(0).balance, 0);
    }

    /// @dev A target with a `fallback` is keyed by the selector BYTES, never by what it implements: the
    ///      allowed selector passes although the fallback takes it, an unlisted one is refused although the
    ///      fallback would take it too, and value needs `allowValue` either way (section 5: "allowlisting a
    ///      selector is necessary, not sufficient").
    function test_pe_a_target_with_a_fallback_is_keyed_by_selector_bytes_not_by_what_it_implements() public {
        G11dFallbackVenue _venue = new G11dFallbackVenue();
        _enforce();
        _allow(address(_venue), SEL);
        assertTrue(_execSafeTx(address(_venue), 0, abi.encodePacked(SEL, uint256(7)), Operation.Call));
        assertEq(_venue.lastSelector(), SEL);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(_venue), OTHER));
        _execSafeTx(address(_venue), 0, abi.encodePacked(OTHER), Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ValueNotAllowed.selector, address(_venue), SEL));
        _execSafeTx(address(_venue), 1 wei, abi.encodePacked(SEL), Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.NativeTransferNotAllowed.selector, address(_venue)));
        _execSafeTx(address(_venue), 1 wei, "", Operation.Call);
        assertEq(_venue.hits(), 1);
    }

    /// @dev Batch entries are checked against the PRE-batch guard state and the Safe's configuration digest
    ///      decides the post-hook: a `lockdown` landing in the middle of a batch (through a venue that holds
    ///      a guardian seat) does not stop the entries already admitted; the batch completes, is reported
    ///      `Policy`, and the NEXT transaction is `SafeLockedDown`. Pinned as the current behaviour: the mode
    ///      is not part of the digest (documented nowhere in so many words; see the g11d matrix).
    function test_pe_a_lockdown_landing_mid_batch_does_not_stop_the_batch_the_next_transaction_is_refused() public {
        G11dGuardianVenue _venue = new G11dGuardianVenue(guard, address(safe));
        _enforce();
        _allow(address(_venue), G11dGuardianVenue.poke.selector);
        _allow(address(protocol), SETTLE);
        _addGuardian(address(_venue));
        _registerUnwrapper(address(multiSendCallOnly));
        bytes memory _batch = _multiSendCalldata(
            abi.encodePacked(
                _entry(address(_venue), 0, abi.encodeCall(G11dGuardianVenue.poke, (1))),
                _entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (5)))
            )
        );
        vm.recordLogs();
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall), "the batch completes");
        assertEq(protocol.lastAmount(), 5, "the entry after the lockdown still ran");
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        uint256 _modes;
        uint256 _reports;
        for (uint256 i; i < _logs.length; ++i) {
            if (_logs[i].topics[0] == MODE_SIG) ++_modes;
            if (_logs[i].topics[0] == CHECKED_SIG) {
                ++_reports;
                assertEq(uint256(_logs[i].topics[3]), uint256(CuratorGuard.Outcome.Policy));
            }
        }
        assertEq(_modes, 1, "the lockdown landed inside the batch");
        assertEq(_reports, 1, "reported once, as Policy");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (6)), Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
                          HATSSIGNERGATE #52 AND #41
    //////////////////////////////////////////////////////////////*/

    /// @dev HSG #52 (signers removed owners and lowered the threshold in one multicall because the
    ///      post-hook recomputed the threshold from the live owner count): the council's floor is checked
    ///      on each entry's PAYLOAD word, never recomputed, so a batch that shrinks a 1-of-4 to a 2-of-2
    ///      passes inside a council window (owner rotation is unchecked there by design, 7.7) while any
    ///      entry whose threshold word is 1 refuses the whole batch (cross-reference:
    ///      `CuratorGuardRobustness` council owner management never below two).
    function test_hsg52_the_council_floor_is_checked_on_each_payload_word_never_recomputed() public {
        _enforce();
        address _o2 = makeAddr("o2");
        address _o3 = makeAddr("o3");
        address _o4 = makeAddr("o4");
        address[3] memory _new = [_o2, _o3, _o4];
        for (uint256 i; i < 3; ++i) {
            bytes memory _add = abi.encodeCall(ISafe.addOwnerWithThreshold, (_new[i], 1));
            _approve(address(safe), 0, _add, Operation.Call); // admin approvals: the council could not add at threshold 1
            assertTrue(_execSafeTx(address(safe), 0, _add, Operation.Call));
        }
        assertEq(safe.getOwners().length, 4);
        _registerUnwrapper(address(multiSendCallOnly));
        vm.prank(council);
        guard.bypass(address(safe), 1 days);

        bytes memory _bad = _multiSendCalldata(
            abi.encodePacked(
                _entry(address(safe), 0, abi.encodeWithSignature("changeThreshold(uint256)", 2)),
                _entry(address(safe), 0, abi.encodeWithSignature("removeOwner(address,address,uint256)", address(1), _o4, 1))
            )
        );
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, bytes4(keccak256("removeOwner(address,address,uint256)"))));
        _execSafeTx(address(multiSendCallOnly), 0, _bad, Operation.DelegateCall);

        bytes memory _shrink = _multiSendCalldata(
            abi.encodePacked(
                _entry(address(safe), 0, abi.encodeWithSignature("changeThreshold(uint256)", 2)),
                _entry(address(safe), 0, abi.encodeWithSignature("removeOwner(address,address,uint256)", address(1), _o4, 2)),
                _entry(address(safe), 0, abi.encodeWithSignature("removeOwner(address,address,uint256)", address(1), _o3, 2))
            )
        );
        vm.recordLogs();
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _shrink, Operation.DelegateCall), "2-of-2 reached in one batch");
        assertEq(safe.getOwners().length, 2);
        assertEq(safe.getThreshold(), 2);
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        for (uint256 i; i < _logs.length; ++i) {
            if (_logs[i].topics[0] == CHECKED_SIG) assertEq(uint256(_logs[i].topics[3]), uint256(CuratorGuard.Outcome.Bypass));
        }
    }

    function _execCalldata(address to_, bytes memory data_, uint256 safeTxGas_, uint256 nonce_) internal view returns (bytes memory) {
        SafeTx memory _t = SafeTx(to_, 0, data_, Operation.Call, safeTxGas_, 0, address(0), address(0));
        bytes32 _domainSeparator = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, address(safe)));
        bytes32 _hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), _domainSeparator, _safeTxHash(_t, nonce_)));
        return
            abi.encodeCall(
                ISafe.execTransaction,
                (to_, 0, data_, Operation.Call, safeTxGas_, 0, 0, address(0), payable(address(0)), _sign(_hash))
            );
    }

    /// @dev HSG #41 (a nested `execTransaction` overwrote the snapshot so the outer post-check compared
    ///      against the updated configuration): here the nested transaction is refused by rule 1 BEFORE any
    ///      policy check, so a nested `setGuard(0)` fails as `NestedExecution`, not as `SelfCallNotAllowed`;
    ///      the venue swallows it, the outer snapshot is intact and the transaction is reported once
    ///      (cross-reference: `CuratorGuardRound2` nested tests, `G10d_Venue` leaked signed transaction).
    function test_hsg41_a_nested_same_safe_transaction_is_refused_before_any_policy_check() public {
        _enforce();
        G11dNester _nester = new G11dNester();
        _allow(address(_nester), G11dNester.run.selector);
        uint256 _nonce = safe.nonce();
        bytes memory _inner = _execCalldata(address(safe), abi.encodeCall(ISafe.setGuard, (address(0))), 0, _nonce + 1);
        vm.recordLogs();
        assertTrue(_execSafeTx(address(_nester), 0, abi.encodeCall(G11dNester.run, (address(safe), _inner)), Operation.Call));
        assertEq(_nester.lastError(), abi.encodeWithSelector(CuratorGuard.NestedExecution.selector, address(safe)));
        assertEq(_installedGuard(), address(guard), "guard still installed");
        assertEq(safe.nonce(), _nonce + 1, "the inner never ran");
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        uint256 _reports;
        for (uint256 i; i < _logs.length; ++i) if (_logs[i].topics[0] == CHECKED_SIG) ++_reports;
        assertEq(_reports, 1, "exactly one report");
    }

    /*//////////////////////////////////////////////////////////////
                           OLAS: STUCK LOCK ON FAILURE
    //////////////////////////////////////////////////////////////*/

    /// @dev OLAS (`_locked = 2; if (!success) return;` left the lock set for ever): the guard's slot is
    ///      transient and cleared before anything else in the post-hook, so a failing policy execution
    ///      with `safeTxGas != 0` (`success == false`, the post-hook runs) leaves nothing behind and the next
    ///      Safe transaction in the SAME EVM transaction passes and is reported (cross-reference:
    ///      `CuratorGuardRobustness` failed policy execution still reported; `CuratorGuardRound2`
    ///      sequential transactions).
    function test_olas_a_failed_execution_leaves_no_stuck_state_the_next_transaction_in_the_same_evm_transaction_passes() public {
        _enforce();
        Reverter _reverter = new Reverter();
        _allow(address(_reverter), 0xdeadbeef);
        _allow(address(protocol), SETTLE);
        uint256 _nonce = safe.nonce();
        bytes[] memory _calls = new bytes[](2);
        _calls[0] = _execCalldata(address(_reverter), hex"deadbeef", 100_000, _nonce);
        _calls[1] = _execCalldata(address(protocol), abi.encodeCall(MockProtocol.settleDeposit, (9)), 0, _nonce + 1);
        G11dSequencer _sequencer = new G11dSequencer();
        vm.recordLogs();
        bool[] memory _results = _sequencer.run(address(safe), _calls);
        assertFalse(_results[0], "the first inner call failed (success == false)");
        assertTrue(_results[1], "the second transaction passed");
        assertEq(protocol.lastAmount(), 9);
        assertEq(safe.nonce(), _nonce + 2);
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        uint256 _reports;
        for (uint256 i; i < _logs.length; ++i) if (_logs[i].topics[0] == CHECKED_SIG) ++_reports;
        assertEq(_reports, 2, "both transactions reported");
    }

    /*//////////////////////////////////////////////////////////////
                    GNOSIS PAY: THE STATICCALL SUCCESS CHECK
    //////////////////////////////////////////////////////////////*/

    /// @dev Gnosis Pay (a contract-signature check read the return data of a `staticcall` without checking
    ///      `success`, so a revert carrying the magic value passed): the guard's forwarding probe reads the
    ///      success flag, so a council member whose `getStorageAt` reverts with a Safe-shaped answer naming
    ///      the guard is NOT taken for a forwarding Safe and keeps its role (cross-reference:
    ///      `CuratorGuardRobustness` `OwnersRevertWellShaped` / `StorageRevertWellSized` for `_read`).
    function test_gnosispay_the_guards_forwarding_probe_treats_a_well_shaped_revert_as_no_answer() public {
        G11dShapedRevertHolder _holder = new G11dShapedRevertHolder(address(guard));
        bytes32 _role = guard.COUNCIL_ROLE();
        vm.prank(vetro);
        guard.grantRole(_role, address(_holder));
        _enforce();
        _holder.lockdown(guard, address(safe));
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown), "the role is honoured");
    }

    /// @dev The timelock's probe likewise: a proposer Safe look-alike whose `getStorageAt` reverts with a
    ///      Safe-shaped answer naming the timelock can still schedule.
    function test_gnosispay_the_timelocks_forwarding_probe_treats_a_well_shaped_revert_as_no_answer() public {
        address _predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        G11dShapedRevertHolder _proposer = new G11dShapedRevertHolder(_predicted);
        address[] memory _proposers = new address[](1);
        _proposers[0] = address(_proposer);
        address[] memory _cancellers = new address[](1);
        _cancellers[0] = makeAddr("veto");
        CuratorGuardTimelock _timelock = new CuratorGuardTimelock(2 days, _proposers, _cancellers);
        assertEq(address(_timelock), _predicted, "address predicted");
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        _proposer.schedule(_timelock, address(protocol), _data);
        assertTrue(_timelock.isOperationPending(_timelock.hashOperation(address(protocol), 0, _data, bytes32(0), bytes32(0))));
    }

    /// @dev The `masterCopy()` probe of the configuration digest: a look-alike whose `masterCopy()` reverts
    ///      with 32 bytes naming a seeded singleton is `SafeNotSupported`, in the dry run as in the hook
    ///      (without the success check it would read as a canonical Safe and reach the policy).
    function test_gnosispay_the_masterCopy_probe_treats_a_well_shaped_revert_as_no_answer() public {
        G11dShapedRevertSafe _lookalike = new G11dShapedRevertSafe(curator);
        _H().seedSafeCodehash(address(_lookalike).codehash);
        vm.prank(vetro);
        guard.enforce(address(_lookalike));
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeNotSupported.selector, address(_lookalike)));
        guard.validateTransaction(address(_lookalike), address(protocol), 0, _data, Operation.Call);
    }
}

/// @title Round 11 (g11d): HSG #41 across the two paths (real Safe v1.5.0).
/// @notice The owner-signed and module paths keep separate transient slots, so a nested APPROVED module
///         transaction that rewrites the configuration inside an outer policy transaction is caught by
///         the OUTER owner-path snapshot: the whole transaction reverts `SafeConfigChanged`, the approval
///         consumption and the owner change roll back (the mirror image of `G9f_Mutation`'s module-path
///         digest test).
contract G11dCrossPathTest is SafeTxHelper {
    CuratorGuard internal guard;
    G11dModule internal module;
    G11dNester internal nester;
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
        CuratorGuardHarness(address(guard)).seedSafe(address(safe));
        module = new G11dModule();
        nester = new G11dNester();
        vm.startPrank(address(safe));
        safe.enableModule(address(module));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        vm.stopPrank();
        vm.startPrank(vetro);
        guard.enforce(address(safe));
        guard.setModuleAllowed(address(safe), address(module), true);
        CuratorGuardPolicy.ParamRule[] memory _none;
        guard.allowFunction(address(safe), address(nester), G11dNester.run.selector, false, _none);
        vm.stopPrank();
    }

    function test_hsg41_a_nested_approved_module_write_is_caught_by_the_outer_owner_snapshot() public {
        address _newOwner = makeAddr("newOwner");
        bytes memory _addOwner = abi.encodeCall(ISafe.addOwnerWithThreshold, (_newOwner, 1));
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(module), address(safe), 0, _addOwner, Operation.Call, 1 days);
        bytes memory _inner = abi.encodeCall(G11dModule.exec, (safe, address(safe), 0, _addOwner, Operation.Call));
        bytes memory _outer = abi.encodeCall(G11dNester.run, (address(module), _inner));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(safe)));
        _execSafeTx(address(nester), 0, _outer, Operation.Call);
        assertEq(safe.getOwners().length, 1, "the owner change rolled back with the outer transaction");
        assertGt(guard.approvalExpiry(_id), 0, "the module approval was not spent");

        // The same module write on its own (no outer policy transaction) lands: the approval is what it is for.
        assertTrue(module.exec(safe, address(safe), 0, _addOwner, Operation.Call));
        assertEq(safe.getOwners().length, 2);
        assertEq(guard.approvalExpiry(_id), 0, "consumed");
    }
}
