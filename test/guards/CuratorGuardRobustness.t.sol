// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {FallbackManager} from "safe-contracts-v1.4.1/contracts/base/FallbackManager.sol";
import {ModuleManager} from "safe-contracts-v1.4.1/contracts/base/ModuleManager.sol";
import {OwnerManager} from "safe-contracts-v1.4.1/contracts/base/OwnerManager.sol";
import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {FallbackManager as FallbackManager150} from "safe-contracts-v1.5.0/contracts/base/FallbackManager.sol";
import {ModuleManager as ModuleManager150} from "safe-contracts-v1.5.0/contracts/base/ModuleManager.sol";
import {OwnerManager as OwnerManager150} from "safe-contracts-v1.5.0/contracts/base/OwnerManager.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";
import {stdError} from "forge-std/StdError.sol";
import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, CuratorGuardTestBase, MaliciousMultiSend, MockProtocol, Reverter} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

/// @dev A Safe look-alike whose configuration views can be made to misbehave in every way the guard
///      must survive without a bare `Panic`: `getOwners()` panicking (what `OwnerManager.getOwners`
///      does when the owner list is longer than `ownerCount`), reverting, or answering a malformed
///      array; `getStorageAt` reverting, answering too few / too many words, or nothing at all.
contract DegradedSafe {
    enum Fault {
        None,
        OwnersPanic,
        OwnersRevert,
        OwnersBadCount,
        OwnersUnpadded,
        StorageRevert,
        StorageShort,
        StorageLong,
        StorageEmpty,
        OwnersTrailingByte, // 97 bytes: count consistent with the words, not word-aligned
        OwnersUndercount, // claims one owner, ships two words
        OwnersRevertWellShaped, // reverts, with a well-formed array as the revert data
        StorageRevertWellSized, // reverts, with data of exactly the expected length
        OwnersSingleWord // a bare 32-byte word (a `bool` / `address` answer): below the array's minimum
    }

    Fault public fault;
    address internal immutable owner;
    mapping(uint256 slot => bytes32) public slots;

    constructor(address owner_) {
        owner = owner_;
    }

    function setFault(Fault fault_) external {
        fault = fault_;
    }

    function setSlot(uint256 slot_, bytes32 value_) external {
        slots[slot_] = value_;
    }

    /// @dev Answers the proxy question with slot 0 when set, else with itself (the harness seeds the
    ///      mock's own code hash, which every `DegradedSafe` instance shares).
    function masterCopy() external view returns (address) {
        address _singleton = address(uint160(uint256(slots[0])));
        return _singleton == address(0) ? address(this) : _singleton;
    }

    function getOwners() external view returns (address[] memory _owners) {
        Fault _f = fault;
        if (_f == Fault.OwnersRevert) revert("owners");
        if (_f == Fault.OwnersBadCount) {
            assembly {
                let p := mload(0x40)
                mstore(p, 0x20)
                mstore(add(p, 0x20), 5) // claims five owners
                mstore(add(p, 0x40), 1) // ships one
                return(p, 0x60)
            }
        }
        if (_f == Fault.OwnersUnpadded) {
            assembly {
                let p := mload(0x40)
                mstore(p, 0x20)
                mstore(add(p, 0x20), 1)
                mstore(add(p, 0x40), 1)
                return(p, 0x5f) // 95 bytes
            }
        }
        if (_f == Fault.OwnersTrailingByte) {
            assembly {
                let p := mload(0x40)
                mstore(p, 0x20)
                mstore(add(p, 0x20), 1)
                mstore(add(p, 0x40), 1)
                return(p, 0x61) // 97 bytes
            }
        }
        if (_f == Fault.OwnersUndercount) {
            assembly {
                let p := mload(0x40)
                mstore(p, 0x20)
                mstore(add(p, 0x20), 1) // claims one
                mstore(add(p, 0x40), 1)
                mstore(add(p, 0x60), 2) // ships two
                return(p, 0x80)
            }
        }
        if (_f == Fault.OwnersRevertWellShaped) {
            assembly {
                let p := mload(0x40)
                mstore(p, 0x20)
                mstore(add(p, 0x20), 1)
                mstore(add(p, 0x40), 1)
                revert(p, 0x60)
            }
        }
        if (_f == Fault.OwnersSingleWord) {
            assembly {
                let p := mload(0x40)
                mstore(p, 1)
                return(p, 0x20)
            }
        }
        _owners = new address[](_f == Fault.OwnersPanic ? 0 : 1);
        _owners[0] = owner; // Panic(0x32) on the empty array, exactly like `OwnerManager.getOwners`
    }

    function getStorageAt(uint256 offset_, uint256 length_) external view returns (bytes memory _out) {
        Fault _f = fault;
        if (_f == Fault.StorageRevert) revert("storage");
        if (_f == Fault.StorageEmpty) {
            assembly {
                return(0, 0)
            }
        }
        if (_f == Fault.StorageRevertWellSized) {
            bytes memory _encoded = abi.encode(new bytes(32 * length_)); // the shape of a healthy answer
            assembly {
                revert(add(_encoded, 0x20), mload(_encoded))
            }
        }
        uint256 _words = length_;
        if (_f == Fault.StorageShort) _words = length_ - 1;
        if (_f == Fault.StorageLong) _words = length_ + 1;
        _out = new bytes(32 * _words);
        for (uint256 i; i < _words; ++i) {
            bytes32 _v = slots[offset_ + i];
            assembly {
                mstore(add(add(_out, 0x20), mul(i, 0x20)), _v)
            }
        }
    }
}

/// @dev An allowlisted venue that is also an ENABLED MODULE of a Safe v1.4.1 (whose module path has no
///      hook): when poked inside a policy transaction it rewrites one Safe storage slot through a
///      module delegatecall, so the post-hook finds the configuration changed, or unreadable.
contract CorruptingModuleVenue {
    ISafe internal immutable safe;
    address internal writer;

    constructor(ISafe safe_) {
        safe = safe_;
    }

    function arm(address writer_) external {
        writer = writer_;
    }

    function poke() external {
        if (writer == address(0)) return;
        require(
            safe.execTransactionFromModule(writer, 0, abi.encodeWithSelector(MaliciousMultiSend.multiSend.selector, ""), Operation.DelegateCall),
            "module call failed"
        );
    }
}

/// @dev A stateful fallback handler in the style of Safe v1.5.0 `ExtensibleFallbackHandler`: a Safe
///      self-call with a selector the Safe does not implement lands here with the Safe as `msg.sender`
///      (`FallbackManager` forwards every unknown selector), which such handlers treat as "only self".
contract StatefulHandler {
    mapping(address safe => bool) public armed;

    fallback() external {
        if (msg.data.length >= 4 && bytes4(msg.data) == 0x12345678) armed[msg.sender] = true;
    }
}

/// @title IMPROVEMENTS_V2.md items 8, 9 and 12 on the v1.4.1 fixture: `SafeConfigUnreadable` and the
///        Cancun probe, `lockdownAndRevoke`, `TransactionChecked`; plus the round-4 review findings.
contract CuratorGuardRobustnessTest is CuratorGuardTestBase {
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;
    /// @dev `SafeStorage.ownerCount`.
    uint256 internal constant OWNER_COUNT_SLOT = 3;
    uint8 internal constant PATH_OWNER = 0;
    uint8 internal constant PATH_MODULE = 1;

    address internal globalGuardian = makeAddr("global-guardian");

    DegradedSafe internal degraded;

    function setUp() public override {
        super.setUp();
        degraded = new DegradedSafe(curator);
        _H().seedSafe(address(degraded)); // seeded: the guard pins canonical Safe code (V2-85)
        degraded.setSlot(uint256(GUARD_SLOT), bytes32(uint256(uint160(address(guard))))); // the look-alike has the guard installed (the hooks answer only a Safe that installed it, V2-88)
        vm.startPrank(vetro);
        guard.setDeploymentGuardian(globalGuardian, true);
        guard.enforce(address(degraded));
        guard.allowFunction(address(degraded), address(protocol), SETTLE, false, _noRules());
        vm.stopPrank();
    }

    function _settle(uint256 n_) internal pure returns (bytes memory) {
        return abi.encodeCall(MockProtocol.settleDeposit, (n_));
    }

    function _tx(address to_, bytes memory data_) internal pure returns (SafeTx memory) {
        return SafeTx(to_, 0, data_, Operation.Call, 0, 0, address(0), address(0));
    }

    function _preHookAs(address safe_, address to_, bytes memory data_) internal {
        vm.prank(safe_);
        guard.checkTransaction(to_, 0, data_, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0));
    }

    function _postHookAs(address safe_, bytes32 hash_, bool success_) internal {
        vm.prank(safe_);
        guard.checkAfterExecution(hash_, success_);
    }

    /// @dev `TransactionChecked` logs emitted by the guard among `logs_`.
    function _reported(Vm.Log[] memory logs_) internal view returns (Vm.Log[] memory _out) {
        uint256 _n;
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter == address(guard) && logs_[i].topics[0] == CuratorGuard.TransactionChecked.selector) ++_n;
        }
        _out = new Vm.Log[](_n);
        _n = 0;
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter == address(guard) && logs_[i].topics[0] == CuratorGuard.TransactionChecked.selector) {
                _out[_n++] = logs_[i];
            }
        }
    }

    function _assertReported(Vm.Log memory log_, address safe_, bytes32 hash_, uint8 path_, CuratorGuard.Outcome outcome_) internal pure {
        assertEq(log_.topics[1], bytes32(uint256(uint160(safe_))), "safe topic");
        assertEq(log_.topics[2], hash_, "txHash topic");
        assertEq(log_.topics[3], bytes32(uint256(outcome_)), "outcome topic");
        assertEq(log_.data, abi.encode(path_), "path");
    }

    /*//////////////////////////////////////////////////////////////
                 ITEM 8: SafeConfigUnreadable (no bubbled Panic)
    //////////////////////////////////////////////////////////////*/

    /// @dev Every fault of the Safe's configuration views, in the pre-hook and in the dry run, is the
    ///      typed error; the healthy look-alike passes both hooks as a control.
    function test_every_configuration_read_fault_is_SafeConfigUnreadable_in_pre_hook_and_dry_run() public {
        bytes memory _data = _settle(1);
        bytes memory _err = abi.encodeWithSelector(CuratorGuard.SafeConfigUnreadable.selector, address(degraded));
        for (uint8 f = uint8(DegradedSafe.Fault.OwnersPanic); f <= uint8(type(DegradedSafe.Fault).max); ++f) {
            degraded.setFault(DegradedSafe.Fault(f));
            vm.prank(address(degraded));
            vm.expectRevert(_err);
            guard.checkTransaction(address(protocol), 0, _data, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0));
            vm.expectRevert(_err);
            guard.validateTransaction(address(degraded), address(protocol), 0, _data, Operation.Call);
        }
        degraded.setFault(DegradedSafe.Fault.None);
        guard.validateTransaction(address(degraded), address(protocol), 0, _data, Operation.Call);
        _preHookAs(address(degraded), address(protocol), _data);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(degraded), bytes32("h"), PATH_OWNER, CuratorGuard.Outcome.Policy);
        _postHookAs(address(degraded), bytes32("h"), true);
    }

    /// @dev The premise of the fault model: a real Safe whose owner list is longer than `ownerCount`
    ///      panics in `getOwners()` with index-out-of-bounds.
    function test_premise_a_real_safe_with_a_short_owner_count_panics_in_getOwners() public {
        vm.store(address(safe), bytes32(OWNER_COUNT_SLOT), bytes32(0));
        vm.expectRevert(stdError.indexOOBError);
        safe.getOwners();
    }

    /// @dev On the real Safe: a corrupted owner count makes every policy transaction fail with the typed
    ///      error (pre-hook and dry run alike, with or without a handler requirement), while the two
    ///      recovery paths that never read the configuration, an approval and a Bypass window, still
    ///      work; once the count is consistent again the policy path is back.
    function test_real_safe_with_an_inconsistent_owner_count_is_unreadable_and_recoverable() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        bytes memory _data = _settle(1);
        bytes memory _err = abi.encodeWithSelector(CuratorGuard.SafeConfigUnreadable.selector, address(safe));
        vm.store(address(safe), bytes32(OWNER_COUNT_SLOT), bytes32(0));

        vm.expectRevert(_err);
        _execSafeTx(address(protocol), 0, _data, Operation.Call);
        vm.expectRevert(_err);
        guard.validateTransaction(address(safe), address(protocol), 0, _data, Operation.Call);
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(safe), address(0), true);
        vm.expectRevert(_err);
        guard.validateTransaction(address(safe), address(protocol), 0, _data, Operation.Call);
        vm.expectRevert(_err);
        _execSafeTx(address(protocol), 0, _data, Operation.Call);

        // Recovery 1: an approval (council or admin) reads nothing of the Safe.
        _councilApprove(address(protocol), 0, _settle(2), Operation.Call);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(safe), _txHash(_tx(address(protocol), _settle(2))), PATH_OWNER, CuratorGuard.Outcome.Approval);
        assertTrue(_execSafeTx(address(protocol), 0, _settle(2), Operation.Call), "approval path");
        assertEq(protocol.lastAmount(), 2);
        // Recovery 2: a council window (its limits read calldata only), then an admin window.
        vm.prank(council);
        guard.bypass(address(safe), 2 hours);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(safe), _txHash(_tx(address(protocol), _settle(3))), PATH_OWNER, CuratorGuard.Outcome.Bypass);
        assertTrue(_execSafeTx(address(protocol), 0, _settle(3), Operation.Call), "council window");
        _bypass(2 hours);
        assertTrue(_execSafeTx(address(protocol), 0, _settle(4), Operation.Call), "admin window");
        assertEq(protocol.lastAmount(), 4);

        // Back to a consistent Safe: the policy path works again, handler requirement included.
        _enforce();
        vm.store(address(safe), bytes32(OWNER_COUNT_SLOT), bytes32(uint256(1)));
        guard.validateTransaction(address(safe), address(protocol), 0, _data, Operation.Call);
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call), "policy path restored");
    }

    /// @dev The post-hook read is wrapped too: a configuration that becomes unreadable DURING a policy
    ///      transaction (a v1.4.1 module rewriting `ownerCount` through its unhooked path) reverts the
    ///      whole Safe transaction with the typed error, and a readable-but-changed configuration with
    ///      `SafeConfigChanged`; the write is rolled back either way and the slot left clean.
    function test_configuration_turning_unreadable_mid_transaction_is_typed_and_rolled_back() public {
        // An enabled v1.4.1 module is refused by the policy path (`ModuleNotHooked`, V2-86), so the in-context
        // write comes from a seeded storage-writing "unwrapper" as in the other snapshot tests.
        _enforce();
        _allow(address(protocol), SETTLE);
        bytes memory _batch = _multiSendCalldata(_entry(address(protocol), 0, _settle(1)));
        MaliciousMultiSend _shorter = new MaliciousMultiSend(bytes32(OWNER_COUNT_SLOT), bytes32(0)); // shorter count: panic
        _registerUnwrapper(address(_shorter));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigUnreadable.selector, address(safe)));
        _execSafeTx(address(_shorter), 0, _batch, Operation.DelegateCall);
        assertEq(uint256(vm.load(address(safe), bytes32(OWNER_COUNT_SLOT))), 1, "write rolled back");

        MaliciousMultiSend _longer = new MaliciousMultiSend(bytes32(OWNER_COUNT_SLOT), bytes32(uint256(2))); // longer count: readable, changed
        _registerUnwrapper(address(_longer));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(safe)));
        _execSafeTx(address(_longer), 0, _batch, Operation.DelegateCall);
        assertEq(uint256(vm.load(address(safe), bytes32(OWNER_COUNT_SLOT))), 1, "write rolled back");
    }

    /// @dev Direct post-hook: a healthy snapshot followed by an unreadable configuration.
    function test_post_hook_alone_surfaces_SafeConfigUnreadable() public {
        _preHookAs(address(degraded), address(protocol), _settle(1));
        degraded.setFault(DegradedSafe.Fault.OwnersPanic);
        vm.prank(address(degraded));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigUnreadable.selector, address(degraded)));
        guard.checkAfterExecution(bytes32(0), true);
    }

    /// @dev An account without code (a typo'd `safe` in an `eth_call`) is unreadable, not an empty revert.
    function test_dry_run_against_an_account_without_code_is_SafeConfigUnreadable() public {
        address _eoa = makeAddr("not-a-safe");
        vm.startPrank(vetro);
        guard.enforce(_eoa);
        guard.allowFunction(_eoa, address(protocol), SETTLE, false, _noRules());
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeNotSupported.selector, _eoa)); // the Safe code pin answers first (V2-85)
        guard.validateTransaction(_eoa, address(protocol), 0, _settle(1), Operation.Call);
    }

    /// @dev The handler word is read as an address (high bits masked), as the decoded read did before;
    ///      the digest still covers the full word.
    function test_fallback_handler_word_is_masked_to_an_address() public {
        address _handler = makeAddr("handler");
        uint256 _slot = uint256(_H().fallbackHandlerStorageSlot());
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(degraded), _handler, true);
        degraded.setSlot(_slot, bytes32(uint256(uint160(_handler)) | (uint256(1) << 200)));
        guard.validateTransaction(address(degraded), address(protocol), 0, _settle(1), Operation.Call);
        _preHookAs(address(degraded), address(protocol), _settle(1));
        degraded.setSlot(_slot, bytes32(uint256(uint160(_handler)))); // same address, clean word: a changed digest
        vm.prank(address(degraded));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(degraded)));
        guard.checkAfterExecution(bytes32(0), true);
        degraded.setSlot(_slot, bytes32(uint256(uint160(makeAddr("other")))));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FallbackHandlerNotAllowed.selector, makeAddr("other")));
        guard.validateTransaction(address(degraded), address(protocol), 0, _settle(1), Operation.Call);
    }

    /// @dev The digest keeps telling apart every component it covers when read through the raw views:
    ///      owner list, owner count, threshold, modules head, fallback handler, guard, module guard.
    function test_digest_still_covers_every_component() public {
        uint256[5] memory _slots = [
            OWNER_COUNT_SLOT,
            uint256(4), // threshold
            uint256(_H().modulesHeadSlot()),
            uint256(_H().fallbackHandlerStorageSlot()),
            uint256(_H().guardStorageSlot())
        ];
        // The singleton is covered through `masterCopy()` (slot 0 of the look-alike): a twin of the mock
        // carries the same (seeded) code hash, so only the digest tells the two apart.
        DegradedSafe _twin = new DegradedSafe(curator);
        _preHookAs(address(degraded), address(protocol), _settle(1));
        degraded.setSlot(0, bytes32(uint256(uint160(address(_twin)))));
        vm.prank(address(degraded));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(degraded)));
        guard.checkAfterExecution(bytes32(0), true);
        degraded.setSlot(0, bytes32(0));
        _postHookAs(address(degraded), bytes32(0), true);
        for (uint256 i; i < _slots.length; ++i) {
            _preHookAs(address(degraded), address(protocol), _settle(1));
            degraded.setSlot(_slots[i], bytes32(uint256(0xBEEF + i)));
            vm.prank(address(degraded));
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(degraded)));
            guard.checkAfterExecution(bytes32(0), true);
            // A reverted post-hook leaves the snapshot in the slot (as it would inside one Safe
            // transaction); restore the slot's value and let a passing post-hook clear it.
            degraded.setSlot(_slots[i], i == 4 ? bytes32(uint256(uint160(address(guard)))) : bytes32(0)); // keep the guard installed (V2-88)
            _postHookAs(address(degraded), bytes32(0), true);
        }
        _preHookAs(address(degraded), address(protocol), _settle(1));
        degraded.setSlot(uint256(_H().moduleGuardStorageSlot()), bytes32(uint256(1)));
        vm.prank(address(degraded));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(degraded)));
        guard.checkAfterExecution(bytes32(0), true);
        degraded.setSlot(uint256(_H().moduleGuardStorageSlot()), bytes32(0));
        _postHookAs(address(degraded), bytes32(0), true);
        // The owner list itself (a different owner, same count) is covered through `getOwners()`.
        DegradedSafe _other = new DegradedSafe(attacker);
        _H().seedSafe(address(_other)); // seeded: the guard pins canonical Safe code (V2-85)
        _other.setSlot(uint256(GUARD_SLOT), bytes32(uint256(uint160(address(guard))))); // installed (V2-88)
        vm.startPrank(vetro);
        guard.enforce(address(_other));
        guard.allowFunction(address(_other), address(protocol), SETTLE, false, _noRules());
        vm.stopPrank();
        _preHookAs(address(_other), address(protocol), _settle(1));
        vm.etch(address(_other), address(degraded).code); // same storage layout, owner now `curator`
        vm.prank(address(_other));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(_other)));
        guard.checkAfterExecution(bytes32(0), true);
    }

    /// @dev The constructor carries the EIP-1153 probe and nothing else from Cancun: exactly one `tload`
    ///      and one `tstore` opcode, and no `mcopy`, in the constructor part of the creation code (the
    ///      bytes before the runtime; linear sweep that skips PUSH data), so the pre-Cancun profile
    ///      (`FOUNDRY_PROFILE=precancun forge test`, deployment fails on a Shanghai EVM) fails because of
    ///      the probe. Here the same creation code deploys on Cancun through a raw `create`.
    function test_constructor_carries_the_transient_storage_probe_and_deploys_on_cancun() public {
        bytes memory _creation = type(CuratorGuard).creationCode;
        uint256 _constructorLength = _runtimeOffset(_creation, type(CuratorGuard).runtimeCode);
        assertGt(_constructorLength, 0);
        (uint256 _tload, uint256 _tstore, uint256 _mcopy) = _scan(_creation, _constructorLength);
        assertEq(_tload, 1, "one tload in the constructor");
        assertEq(_tstore, 1, "one tstore in the constructor");
        assertEq(_mcopy, 0, "no other Cancun opcode in the constructor");

        bytes memory _init = abi.encodePacked(_creation, abi.encode(uint48(0), vetro, council));
        address _deployed;
        assembly {
            _deployed := create(0, add(_init, 0x20), mload(_init))
        }
        assertTrue(_deployed != address(0), "deploys on Cancun");
        assertEq(CuratorGuard(_deployed).defaultAdmin(), vetro);
        assertTrue(CuratorGuard(_deployed).hasRole(CuratorGuard(_deployed).COUNCIL_ROLE(), council));
    }

    /// @dev Offset of the runtime object inside the creation code (solc appends it right after the
    ///      constructor code, possibly followed by a data section), by hash comparison.
    function _runtimeOffset(bytes memory creation_, bytes memory runtime_) internal pure returns (uint256) {
        bytes32 _want = keccak256(runtime_);
        uint256 _len = runtime_.length;
        for (uint256 _off = creation_.length - _len; ; --_off) {
            bytes32 _h;
            assembly ("memory-safe") {
                _h := keccak256(add(add(creation_, 0x20), _off), _len)
            }
            if (_h == _want) return _off;
            if (_off == 0) break;
        }
        revert("runtime object not found inside the creation code");
    }

    function _scan(bytes memory code_, uint256 end_) internal pure returns (uint256 _tload, uint256 _tstore, uint256 _mcopy) {
        uint256 i;
        while (i < end_) {
            uint8 _op = uint8(code_[i]);
            if (_op == 0x5c) ++_tload;
            else if (_op == 0x5d) ++_tstore;
            else if (_op == 0x5e) ++_mcopy;
            if (_op >= 0x60 && _op <= 0x7f) i += _op - 0x5f; // skip PUSH1..PUSH32 immediates
            ++i;
        }
    }

    /*//////////////////////////////////////////////////////////////
                        ITEM 9: lockdownAndRevoke
    //////////////////////////////////////////////////////////////*/

    /// @dev Admin, council, a per-Safe guardian and a deployment-wide guardian may; a stranger and a
    ///      guardian of another Safe may not; the zero Safe is refused.
    function test_lockdownAndRevoke_role_matrix() public {
        _addGuardian(guardian);
        address _otherSafe = makeAddr("other-safe");
        address _otherGuardian = makeAddr("other-guardian");
        vm.prank(vetro);
        guard.setGuardian(_otherSafe, _otherGuardian, true);

        address[4] memory _may = [vetro, council, guardian, globalGuardian];
        for (uint256 i; i < _may.length; ++i) {
            vm.prank(council); // the council lifts at once; the admin waits out the cooldown
            guard.enforce(address(safe));
            bytes32 _id = _councilApprove(address(protocol), 0, _settle(i), Operation.Call);
            uint32 _epoch = guard.approvalEpoch(address(safe));
            vm.prank(_may[i]);
            guard.lockdownAndRevoke(address(safe));
            assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown), "mode");
            assertEq(guard.approvalEpoch(address(safe)), _epoch + 1, "epoch");
            assertEq(guard.approvalExpiry(_id), 0, "approval dead");
        }
        address[2] memory _mayNot = [attacker, _otherGuardian];
        for (uint256 i; i < _mayNot.length; ++i) {
            vm.prank(_mayNot[i]);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.lockdownAndRevoke(address(safe));
        }
        vm.prank(vetro);
        vm.expectRevert(CuratorGuardPolicy.AddressIsNull.selector);
        guard.lockdownAndRevoke(address(0));
        // A per-Safe guardian of THIS Safe cannot touch the other one.
        vm.prank(guardian);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.lockdownAndRevoke(_otherSafe);
    }

    function test_lockdownAndRevoke_from_a_bypass_window_and_its_events() public {
        _addGuardian(guardian);
        vm.prank(council);
        guard.bypass(address(safe), 1 days);
        (uint64 _until, bool _councilWindow) = guard.bypassWindow(address(safe));
        assertGt(_until, 0);
        assertTrue(_councilWindow);
        uint32 _epoch = guard.approvalEpoch(address(safe));

        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuardPolicy.ModeUpdated(address(safe), CuratorGuardPolicy.Mode.Lockdown, 0, false);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuardPolicy.ApprovalsRevoked(address(safe), _epoch + 1);
        vm.prank(guardian);
        guard.lockdownAndRevoke(address(safe));

        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        (_until, _councilWindow) = guard.bypassWindow(address(safe));
        assertEq(_until, 0);
        assertFalse(_councilWindow);
        assertEq(guard.approvalEpoch(address(safe)), _epoch + 1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, _settle(1), Operation.Call);
    }

    /// @dev The approved payload survives `lockdown` and dies with `lockdownAndRevoke` (the live hook
    ///      refuses it with `SafeLockedDown`, exactly as an unapproved one); re-approval in the new epoch
    ///      works, and `enforce` lifts the lockdown as usual.
    function test_lockdownAndRevoke_kills_what_lockdown_alone_lets_through() public {
        _addGuardian(guardian);
        _enforce();
        bytes memory _data = _settle(7);
        bytes32 _id = _approve(address(protocol), 0, _data, Operation.Call);
        vm.prank(guardian);
        guard.lockdown(address(safe));
        guard.validateTransaction(address(safe), address(protocol), 0, _data, Operation.Call); // approval still live
        vm.prank(guardian);
        guard.lockdownAndRevoke(address(safe));
        assertEq(guard.approvalExpiry(_id), 0);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        guard.validateTransaction(address(safe), address(protocol), 0, _data, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, _data, Operation.Call);
        assertEq(protocol.calls(), 0);

        bytes32 _fresh = _councilApprove(address(protocol), 0, _data, Operation.Call);
        assertTrue(_fresh != _id, "new epoch, new id");
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call), "fresh approval under lockdown");
        vm.prank(council);
        guard.enforce(address(safe));
        _allow(address(protocol), SETTLE);
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call), "policy path after the lift");
    }

    /// @dev Idempotent on an already locked Safe (still bumps the epoch, so it is the right reflex even
    ///      when a `lockdown` already ran), and never touches another Safe's state.
    function test_lockdownAndRevoke_is_idempotent_and_scoped_to_the_safe() public {
        address _other = makeAddr("other-safe");
        vm.startPrank(vetro);
        guard.enforce(_other);
        guard.approveTransaction(_other, address(0), address(protocol), 0, _settle(1), Operation.Call, 1 days);
        vm.stopPrank();
        uint32 _otherEpoch = guard.approvalEpoch(_other);
        vm.prank(council);
        guard.lockdownAndRevoke(address(safe));
        vm.prank(council);
        guard.lockdownAndRevoke(address(safe));
        assertEq(guard.approvalEpoch(address(safe)), 2);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        assertEq(guard.approvalEpoch(_other), _otherEpoch, "other Safe untouched");
        assertEq(uint8(guard.mode(_other)), uint8(CuratorGuardPolicy.Mode.Enforced), "other Safe untouched");
    }

    /// @dev Through `executeBefore` (a timelocked incident response that nobody executed in time dies).
    function test_lockdownAndRevoke_through_executeBefore() public {
        _enforce();
        bytes memory _call = abi.encodeCall(guard.lockdownAndRevoke, (address(safe)));
        vm.prank(attacker);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.executeBefore(uint64(block.timestamp + 1), _call);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, uint64(block.timestamp - 1)));
        guard.executeBefore(uint64(block.timestamp - 1), _call);
        vm.prank(vetro);
        guard.executeBefore(uint64(block.timestamp), _call);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        assertEq(guard.approvalEpoch(address(safe)), 1);
    }

    /*//////////////////////////////////////////////////////////////
                      ITEM 12: TransactionChecked
    //////////////////////////////////////////////////////////////*/

    /// @dev Owner path, policy outcome: the event carries the Safe, the Safe's own `safeTxHash`, path 0.
    function test_policy_transaction_is_reported_with_its_safeTxHash() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        SafeTx memory _t = _tx(address(protocol), _settle(1));
        bytes32 _hash = _txHash(_t);
        assertEq(_hash, safe.getTransactionHash(_t.to, 0, _t.data, Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()));
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(safe), _hash, PATH_OWNER, CuratorGuard.Outcome.Policy);
        assertTrue(_execSafeTxParams(_t));
        // The next transaction has a different nonce, so a different hash.
        bytes32 _next = _txHash(_t);
        assertTrue(_next != _hash);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(safe), _next, PATH_OWNER, CuratorGuard.Outcome.Policy);
        assertTrue(_execSafeTxParams(_t));
    }

    /// @dev Approval outcome, preceded by `ApprovalConsumed` in the same transaction (pre-hook first).
    function test_approved_transaction_is_reported_as_Approval_after_ApprovalConsumed() public {
        bytes memory _data = abi.encodeCall(ISafe.addOwnerWithThreshold, (attacker, 1));
        bytes32 _id = _approve(address(safe), 0, _data, Operation.Call);
        bytes32 _hash = _txHash(_tx(address(safe), _data));
        vm.recordLogs();
        assertTrue(_execSafeTx(address(safe), 0, _data, Operation.Call));
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        uint256 _consumedAt = type(uint256).max;
        uint256 _reportedAt = type(uint256).max;
        for (uint256 i; i < _logs.length; ++i) {
            if (_logs[i].emitter != address(guard)) continue;
            if (_logs[i].topics[0] == CuratorGuardPolicy.ApprovalConsumed.selector) {
                assertEq(_logs[i].topics[2], _id);
                _consumedAt = i;
            }
            if (_logs[i].topics[0] == CuratorGuard.TransactionChecked.selector) {
                _assertReported(_logs[i], address(safe), _hash, PATH_OWNER, CuratorGuard.Outcome.Approval);
                _reportedAt = i;
            }
        }
        assertTrue(_consumedAt < _reportedAt, "ApprovalConsumed before TransactionChecked");
        assertEq(_reported(_logs).length, 1, "exactly one report");
        assertTrue(_contains(safe.getOwners(), attacker));
    }

    /// @dev Bypass outcome for both an admin window (nothing checked) and a council window (allowlist).
    function test_bypass_transactions_are_reported_as_Bypass() public {
        _bypass(1 days);
        bytes memory _data = abi.encodeCall(MockProtocol.deposit, (1, attacker)); // not allowlisted
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(safe), _txHash(_tx(address(protocol), _data)), PATH_OWNER, CuratorGuard.Outcome.Bypass);
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call));
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(safe), _txHash(_tx(address(protocol), _data)), PATH_OWNER, CuratorGuard.Outcome.Bypass);
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call));
        // The window's last second still reports Bypass; one second later nothing passes at all.
        (uint64 _until, ) = guard.bypassWindow(address(safe));
        vm.warp(_until - 1);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(safe), _txHash(_tx(address(protocol), _data)), PATH_OWNER, CuratorGuard.Outcome.Bypass);
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call));
        vm.warp(_until);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, _data, Operation.Call);
    }

    /// @dev The admin's own transactions are neither checked nor reported, on either path.
    function test_admin_transactions_are_silent() public {
        bytes memory _data = _settle(1);
        vm.recordLogs();
        _preHookAs(vetro, address(protocol), _data);
        _postHookAs(vetro, bytes32("admin"), true);
        vm.prank(vetro);
        guard.checkModuleTransaction(address(protocol), 0, _data, Operation.Call, attacker);
        vm.prank(vetro);
        guard.checkAfterModuleExecution(bytes32("admin"), false);
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        assertEq(_reported(_logs).length, 0, "admin is silent");
        assertEq(_logs.length, 0, "no event at all");
    }

    /// @dev One Safe transaction, one report, however many calls the batch carries.
    function test_a_multisend_batch_is_reported_once() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        _registerUnwrapper(address(multiSendCallOnly));
        bytes memory _batch = _multiSendCalldata(
            abi.encodePacked(_entry(address(protocol), 0, _settle(1)), _entry(address(protocol), 0, _settle(2)), _entry(address(protocol), 0, _settle(3)))
        );
        SafeTx memory _t = SafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall, 0, 0, address(0), address(0));
        bytes32 _hash = _txHash(_t);
        vm.recordLogs();
        assertTrue(_execSafeTxParams(_t));
        Vm.Log[] memory _r = _reported(vm.getRecordedLogs());
        assertEq(_r.length, 1);
        _assertReported(_r[0], address(safe), _hash, PATH_OWNER, CuratorGuard.Outcome.Policy);
        assertEq(protocol.calls(), 3);
    }

    /// @dev A policy transaction whose inner call failed (`safeTxGas != 0`, the Safe reports
    ///      `success == false` and emits `ExecutionFailure`) is still reported: the guard reports
    ///      checks, not outcomes of the venue call. Pair it with the Safe's own events.
    function test_failed_policy_execution_is_still_reported() public {
        Reverter _reverter = new Reverter();
        _enforce();
        _allow(address(_reverter), bytes4(0x12345678));
        SafeTx memory _t = SafeTx(address(_reverter), 0, abi.encodeWithSelector(0x12345678), Operation.Call, 100_000, 0, address(0), address(0));
        bytes32 _hash = _txHash(_t);
        vm.recordLogs();
        assertFalse(_execSafeTxParams(_t), "inner call failed");
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        Vm.Log[] memory _r = _reported(_logs);
        assertEq(_r.length, 1);
        _assertReported(_r[0], address(safe), _hash, PATH_OWNER, CuratorGuard.Outcome.Policy);
        bool _failureEvent;
        for (uint256 i; i < _logs.length; ++i) {
            if (_logs[i].emitter == address(safe) && _logs[i].topics[0] == keccak256("ExecutionFailure(bytes32,uint256)")) {
                assertEq(_logs[i].topics[1], _hash);
                _failureEvent = true;
            }
        }
        assertTrue(_failureEvent, "Safe emitted ExecutionFailure with the same hash");
    }

    /// @dev Safe{Wallet}'s rejection (empty zero-value self-call) is a policy transaction like any other.
    function test_rejection_self_call_is_reported_as_Policy() public {
        _enforce();
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(safe), _txHash(_tx(address(safe), "")), PATH_OWNER, CuratorGuard.Outcome.Policy);
        assertTrue(_execSafeTx(address(safe), 0, "", Operation.Call));
    }

    /// @dev Nothing is reported when either hook reverts (a refused transaction leaves no trace in the
    ///      guard's logs), including the post-hook reverts. Foundry's log recorder keeps logs emitted
    ///      inside frames that later revert, so this also pins that the event is the post-hook's LAST
    ///      statement (never even transiently emitted before a revert).
    function test_refused_transactions_are_not_reported() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        vm.recordLogs();
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector));
        _execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (1, attacker)), Operation.Call);
        // Post-hook revert: a configuration write mid-transaction (unwrapper stand-in rewriting the guard slot).
        MaliciousMultiSend _evil = new MaliciousMultiSend(_H().guardStorageSlot(), bytes32(0));
        _registerUnwrapper(address(_evil));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(safe)));
        _execSafeTx(address(_evil), 0, _multiSendCalldata(_entry(address(protocol), 0, _settle(1))), Operation.DelegateCall);
        assertEq(_reported(vm.getRecordedLogs()).length, 0);
    }

    /// @dev Direct hook calls pin the outcome encoding for each state the post-hook can find in the slot.
    function test_outcome_encoding_per_slot_state() public {
        bytes memory _data = _settle(1);
        // Policy: snapshot in the slot.
        _preHookAs(address(degraded), address(protocol), _data);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(degraded), bytes32("p"), PATH_OWNER, CuratorGuard.Outcome.Policy);
        _postHookAs(address(degraded), bytes32("p"), true);
        assertEq(uint8(CuratorGuard.Outcome.Policy), 0);
        // Approval: sentinel in the slot.
        vm.prank(vetro);
        guard.approveTransaction(address(degraded), address(0), address(protocol), 0, _data, Operation.Call, 1 days);
        _preHookAs(address(degraded), address(protocol), _data);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(degraded), bytes32("a"), PATH_OWNER, CuratorGuard.Outcome.Approval);
        _postHookAs(address(degraded), bytes32("a"), true);
        assertEq(uint8(CuratorGuard.Outcome.Approval), 1);
        // Bypass: empty slot inside a window.
        vm.prank(vetro);
        guard.bypass(address(degraded), 1 hours);
        _preHookAs(address(degraded), address(protocol), _data);
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(degraded), bytes32("b"), PATH_OWNER, CuratorGuard.Outcome.Bypass);
        _postHookAs(address(degraded), bytes32("b"), true);
        assertEq(uint8(CuratorGuard.Outcome.Bypass), 2);
        // Empty slot outside a window: MissingSnapshot, no report.
        vm.prank(vetro);
        guard.enforce(address(degraded));
        vm.prank(address(degraded));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.MissingSnapshot.selector, address(degraded)));
        guard.checkAfterExecution(bytes32("m"), true);
        // Sentinel with a failed execution: ApprovedExecutionFailed, no report (inside one Safe
        // transaction the revert also rolls the consumption back: module suite).
        vm.prank(vetro);
        guard.approveTransaction(address(degraded), address(0), address(protocol), 0, _data, Operation.Call, 1 days);
        _preHookAs(address(degraded), address(protocol), _data);
        vm.prank(address(degraded));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ApprovedExecutionFailed.selector, address(degraded)));
        guard.checkAfterExecution(bytes32("f"), false);
    }

    /// @dev The post-hook judges an empty slot by the EFFECTIVE mode: once the window expired it is
    ///      `MissingSnapshot`, never a `Bypass` report (only observable through a direct call, the Safe's
    ///      own pre-hook refuses first).
    function test_post_hook_with_an_empty_slot_after_the_window_expired_is_MissingSnapshot() public {
        _bypass(1 hours);
        (uint64 _until, ) = guard.bypassWindow(address(safe));
        vm.warp(_until);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        vm.prank(address(safe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.MissingSnapshot.selector, address(safe)));
        guard.checkAfterExecution(bytes32("stale"), true);
    }

    /// @dev The event ABI monitors index by (docs §7.7) is pinned by signature, not only by the
    ///      compiler-derived selector the other tests use.
    function test_event_signatures_are_pinned() public pure {
        assertEq(CuratorGuard.TransactionChecked.selector, keccak256("TransactionChecked(address,bytes32,uint8,uint8)"));
        assertEq(CuratorGuardPolicy.ApprovalsRevoked.selector, keccak256("ApprovalsRevoked(address,uint32)"));
        assertEq(CuratorGuardPolicy.ModeUpdated.selector, keccak256("ModeUpdated(address,uint8,uint64,bool)"));
        assertEq(CuratorGuardPolicy.ApprovalConsumed.selector, keccak256("ApprovalConsumed(address,bytes32,address)"));
    }
}

/// @title Round-4 review findings on the v1.4.1 fixture.
contract CuratorGuardRound4FindingsTest is CuratorGuardTestBase {
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;
    uint8 internal constant PATH_OWNER = 0;
    bytes4 internal constant ADD_OWNER = bytes4(keccak256("addOwnerWithThreshold(address,uint256)"));
    bytes4 internal constant REMOVE_OWNER = bytes4(keccak256("removeOwner(address,address,uint256)"));
    bytes4 internal constant SWAP_OWNER = bytes4(keccak256("swapOwner(address,address,address)"));
    bytes4 internal constant CHANGE_THRESHOLD = bytes4(keccak256("changeThreshold(uint256)"));
    bytes4 internal constant DISABLE_MODULE = bytes4(keccak256("disableModule(address,address)"));
    bytes4 internal constant SET_FALLBACK_HANDLER = bytes4(keccak256("setFallbackHandler(address)"));
    bytes4 internal constant APPROVE_HASH = bytes4(keccak256("approveHash(bytes32)"));
    bytes4 internal constant SETUP =
        bytes4(keccak256("setup(address[],uint256,address,bytes,address,address,uint256,address)"));

    DegradedSafe internal degraded;

    function setUp() public override {
        super.setUp();
        degraded = new DegradedSafe(curator);
        _H().seedSafe(address(degraded)); // seeded: the guard pins canonical Safe code (V2-85)
        degraded.setSlot(uint256(GUARD_SLOT), bytes32(uint256(uint160(address(guard))))); // the look-alike has the guard installed (the hooks answer only a Safe that installed it, V2-88)
        vm.startPrank(vetro);
        guard.enforce(address(degraded));
        guard.allowFunction(address(degraded), address(protocol), SETTLE, false, _noRules());
        vm.stopPrank();
    }

    function _settle(uint256 n_) internal pure returns (bytes memory) {
        return abi.encodeCall(MockProtocol.settleDeposit, (n_));
    }

    function _reported(Vm.Log[] memory logs_) internal view returns (Vm.Log[] memory _out) {
        uint256 _n;
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter == address(guard) && logs_[i].topics[0] == CuratorGuard.TransactionChecked.selector) ++_n;
        }
        _out = new Vm.Log[](_n);
        _n = 0;
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter == address(guard) && logs_[i].topics[0] == CuratorGuard.TransactionChecked.selector) {
                _out[_n++] = logs_[i];
            }
        }
    }

    /// @dev Mutation survivor Y02: the dry run reads the configuration (and checks a handler requirement)
    ///      BEFORE the policy, like the live pre-check, so an unreadable Safe or a wrong handler is what
    ///      gets reported even for a payload the policy would refuse anyway.
    function test_dry_run_reads_the_configuration_before_the_policy_like_the_live_hook() public {
        bytes memory _denied = abi.encodeCall(MockProtocol.deposit, (1, attacker)); // not allowlisted
        bytes memory _err = abi.encodeWithSelector(CuratorGuard.SafeConfigUnreadable.selector, address(degraded));
        degraded.setFault(DegradedSafe.Fault.OwnersPanic);
        vm.expectRevert(_err);
        guard.validateTransaction(address(degraded), address(protocol), 0, _denied, Operation.Call);
        vm.prank(address(degraded));
        vm.expectRevert(_err);
        guard.checkTransaction(address(protocol), 0, _denied, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0));
        degraded.setFault(DegradedSafe.Fault.None);
        address _handler = makeAddr("handler");
        address _wrong = makeAddr("wrongHandler");
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(degraded), _handler, true);
        degraded.setSlot(uint256(_H().fallbackHandlerStorageSlot()), bytes32(uint256(uint160(_wrong))));
        bytes memory _handlerErr = abi.encodeWithSelector(CuratorGuard.FallbackHandlerNotAllowed.selector, _wrong);
        vm.expectRevert(_handlerErr);
        guard.validateTransaction(address(degraded), address(protocol), 0, _denied, Operation.Call);
        vm.prank(address(degraded));
        vm.expectRevert(_handlerErr);
        guard.checkTransaction(address(protocol), 0, _denied, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0));
        degraded.setSlot(uint256(_H().fallbackHandlerStorageSlot()), bytes32(uint256(uint160(_handler))));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector));
        guard.validateTransaction(address(degraded), address(protocol), 0, _denied, Operation.Call);
    }

    /// @dev R1D-1: the guard is never a call target from a guarded Safe, inside an ADMIN window too (a
    ///      plain call into the post-hook could otherwise forge a `TransactionChecked`); the dry run
    ///      agrees. Everything else stays unchecked in an admin window.
    function test_admin_window_never_lets_the_safe_call_the_guard() public {
        _bypass(1 days);
        bytes memory _forge = abi.encodeCall(guard.checkAfterExecution, (bytes32("forged"), true));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, guard.checkAfterExecution.selector));
        _execSafeTx(address(guard), 0, _forge, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, guard.checkAfterExecution.selector));
        guard.validateTransaction(address(safe), address(guard), 0, _forge, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, bytes4(0)));
        _execSafeTx(address(guard), 0, "", Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, guard.checkAfterExecution.selector));
        _execSafeTx(address(guard), 0, _forge, Operation.DelegateCall); // whatever the operation
        // Still inert otherwise: a non-allowlisted call, a weakening self-call, a raw delegatecall.
        vm.recordLogs();
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (1, attacker)), Operation.Call));
        assertTrue(_execSafeTx(address(safe), 0, abi.encodeCall(ISafe.enableModule, (attacker)), Operation.Call));
        assertTrue(_execSafeTx(address(multiSend), 0, _multiSendCalldata(_entry(address(protocol), 0, _settle(1))), Operation.DelegateCall));
        assertEq(_reported(vm.getRecordedLogs()).length, 3, "one report per transaction");
    }

    /// @dev Documented residual of R1D-1: an admin window decodes nothing, so a batch entry (or any
    ///      delegatecalled code) can still reach the post-hook and add a `Bypass` report under an
    ///      arbitrary hash. Reports inside an admin window are therefore not authoritative; the window
    ///      itself (`ModeUpdated`) is what monitors act on. Outside a window the same batch is refused.
    function test_admin_window_batch_entry_can_still_add_a_bypass_report_documented_residual() public {
        _bypass(1 days);
        _registerUnwrapper(address(multiSendCallOnly));
        bytes memory _batch = _multiSendCalldata(
            _entry(address(guard), 0, abi.encodeCall(guard.checkAfterExecution, (bytes32("forged"), true)))
        );
        vm.recordLogs();
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall));
        Vm.Log[] memory _r = _reported(vm.getRecordedLogs());
        assertEq(_r.length, 2, "forged + genuine");
        assertEq(_r[0].topics[2], bytes32("forged"));
        assertEq(_r[0].topics[3], bytes32(uint256(CuratorGuard.Outcome.Bypass)), "a forged report can only claim Bypass");
        assertEq(_r[0].data, abi.encode(PATH_OWNER));
        _enforce();
        vm.recordLogs();
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, guard.checkAfterExecution.selector));
        _execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
        assertEq(_reported(vm.getRecordedLogs()).length, 0);
    }

    /// @dev R1D-2: council self-calls are an ALLOWLIST (owner management, `disableModule`,
    ///      `setFallbackHandler(0)`, the empty rejection call) for approvals and council windows alike;
    ///      every other selector addressed to the Safe, implemented or not, is admin-only.
    function test_council_self_calls_are_an_allowlist() public {
        (address _x, uint256 _xPk) = makeAddrAndKey("x");
        (address _y, uint256 _yPk) = makeAddrAndKey("y");
        address _z = makeAddr("z");
        bytes[7] memory _allowed = [
            abi.encodeCall(ISafe.addOwnerWithThreshold, (_x, 2)),
            abi.encodeWithSelector(REMOVE_OWNER, address(0x1), _x, 2),
            abi.encodeWithSelector(SWAP_OWNER, address(0x1), _x, _y),
            abi.encodeWithSelector(CHANGE_THRESHOLD, 2),
            abi.encodeWithSelector(DISABLE_MODULE, address(0x1), attacker),
            abi.encodeWithSelector(SET_FALLBACK_HANDLER, address(0)),
            bytes("")
        ];
        for (uint256 i; i < _allowed.length; ++i) {
            assertGt(guard.approvalExpiry(_councilApprove(address(safe), 0, _allowed[i], Operation.Call)), 0, "council may approve");
        }
        bytes[13] memory _denied = [
            abi.encodeCall(ISafe.setGuard, (address(0))),
            abi.encodeCall(ISafe.setModuleGuard, (address(0))),
            abi.encodeCall(ISafe.enableModule, (attacker)),
            abi.encodeWithSelector(SET_FALLBACK_HANDLER, attacker),
            abi.encodeWithSelector(APPROVE_HASH, bytes32(0)),
            abi.encodeWithSelector(bytes4(0xdeadbeef)), // not implemented by the Safe: fallback handler
            abi.encodeWithSelector(SETUP),
            hex"0d58", // shorter than a selector
            abi.encodeCall(ISafe.addOwnerWithThreshold, (_x, 1)), // a single-key custody Safe: admin-only
            abi.encodeWithSelector(REMOVE_OWNER, address(0x1), _x, 1),
            abi.encodeWithSelector(CHANGE_THRESHOLD, 1),
            abi.encodeWithSelector(CHANGE_THRESHOLD, 0),
            abi.encodeWithSelector(CHANGE_THRESHOLD) // threshold argument missing
        ];
        for (uint256 i; i < _denied.length; ++i) {
            bytes4 _sel = _denied[i].length >= 4 ? bytes4(_denied[i]) : bytes4(0);
            vm.prank(council);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, _sel, Operation.Call));
            guard.approveTransaction(address(safe), address(0), address(safe), 0, _denied[i], Operation.Call, 1 days);
            vm.prank(vetro);
            guard.approveTransaction(address(safe), address(0), address(safe), 0, _denied[i], Operation.Call, 1 days); // admin may
        }
        // Inside a council window: the same partition, live and in the dry run.
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        for (uint256 i; i < _denied.length; ++i) {
            bytes4 _sel = _denied[i].length >= 4 ? bytes4(_denied[i]) : bytes4(0);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, _sel));
            _execSafeTx(address(safe), 0, _denied[i], Operation.Call);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, _sel));
            guard.validateTransaction(address(safe), address(safe), 0, _denied[i], Operation.Call);
        }
        for (uint256 i; i < _allowed.length; ++i) {
            guard.validateTransaction(address(safe), address(safe), 0, _allowed[i], Operation.Call);
        }
        // Executed for real inside the window, from the 1-of-1 fixture: add x (threshold 2, one
        // signature still suffices for that one), then with two signatures add z, remove z, keep the
        // threshold, swap x for y, disable a module, reset the handler, reject.
        vm.prank(address(safe));
        safe.enableModule(attacker);
        assertTrue(_execSafeTx(address(safe), 0, _allowed[0], Operation.Call), "addOwnerWithThreshold(x, 2)");
        assertEq(safe.getThreshold(), 2);
        assertTrue(_execSafeTx2(address(safe), abi.encodeCall(ISafe.addOwnerWithThreshold, (_z, 2)), _xPk, signerPk), "add z");
        assertTrue(_execSafeTx2(address(safe), abi.encodeWithSelector(REMOVE_OWNER, address(0x1), _z, 2), _xPk, signerPk), "remove z");
        assertTrue(_execSafeTx2(address(safe), _allowed[3], _xPk, signerPk), "changeThreshold(2)");
        assertTrue(_execSafeTx2(address(safe), _allowed[2], _xPk, signerPk), "swapOwner(x -> y)");
        assertTrue(_execSafeTx2(address(safe), _allowed[4], _yPk, signerPk), "disableModule");
        assertTrue(_execSafeTx2(address(safe), _allowed[5], _yPk, signerPk), "setFallbackHandler(0)");
        assertTrue(_execSafeTx2(address(safe), "", _yPk, signerPk), "rejection");
        assertFalse(safe.isModuleEnabled(attacker));
        assertEq(safe.getOwners().length, 2);
        assertEq(safe.getOwners()[0], _y);
        assertEq(safe.getOwners()[1], curator);
        assertEq(safe.getThreshold(), 2);
    }

    /// @dev Two-signature `execTransaction` (signatures sorted by signer address, as the Safe requires).
    function _execSafeTx2(address to_, bytes memory data_, uint256 pkA_, uint256 pkB_) internal returns (bool) {
        bytes32 _hash = _txHash(SafeTx(to_, 0, data_, Operation.Call, 0, 0, address(0), address(0)));
        bytes memory _sigs = vm.addr(pkA_) < vm.addr(pkB_)
            ? bytes.concat(_sigOf(pkA_, _hash), _sigOf(pkB_, _hash))
            : bytes.concat(_sigOf(pkB_, _hash), _sigOf(pkA_, _hash));
        return safe.execTransaction(to_, 0, data_, Operation.Call, 0, 0, 0, address(0), payable(address(0)), _sigs);
    }

    function _sigOf(uint256 pk_, bytes32 hash_) internal pure returns (bytes memory) {
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(pk_, hash_);
        return abi.encodePacked(_r, _s, _v);
    }

    /// @dev R2-D F-2: council owner management never sets a threshold below 2 (approval, window and dry
    ///      run), and the admin still may (through the timelock).
    function test_council_owner_management_never_sets_a_threshold_below_two() public {
        assertEq(_H().minCouncilThreshold(), 2);
        bytes[3] memory _singleKey = [
            abi.encodeCall(ISafe.addOwnerWithThreshold, (attacker, 1)),
            abi.encodeWithSelector(REMOVE_OWNER, address(0x1), curator, 1),
            abi.encodeWithSelector(CHANGE_THRESHOLD, 1)
        ];
        for (uint256 i; i < _singleKey.length; ++i) {
            bytes4 _sel = bytes4(_singleKey[i]);
            vm.prank(council);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, _sel, Operation.Call));
            guard.approveTransaction(address(safe), address(0), address(safe), 0, _singleKey[i], Operation.Call, 1 days);
            assertGt(guard.approvalExpiry(_approve(address(safe), 0, _singleKey[i], Operation.Call)), 0, "admin may");
        }
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        for (uint256 i; i < _singleKey.length; ++i) {
            bytes4 _sel = bytes4(_singleKey[i]);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, _sel));
            guard.validateTransaction(address(safe), address(safe), 0, _singleKey[i], Operation.Call);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, _sel));
            _execSafeTx(address(safe), 0, _singleKey[i], Operation.Call);
        }
        guard.validateTransaction(address(safe), address(safe), 0, abi.encodeWithSelector(CHANGE_THRESHOLD, 2), Operation.Call);
        guard.validateTransaction(address(safe), address(safe), 0, abi.encodeWithSelector(CHANGE_THRESHOLD, type(uint256).max), Operation.Call);
    }

    /// @dev R2-D F-4: approval `ttl` has a one-hour floor (a `7` typed for seven days would be dead on
    ///      arrival after the timelock); the caps are unchanged.
    function test_approval_ttl_has_a_one_hour_floor() public {
        assertEq(_H().minApprovalTtl(), 1 hours);
        bytes memory _data = _settle(1);
        uint64[3] memory _short = [uint64(0), 1, 1 hours - 1];
        for (uint256 i; i < _short.length; ++i) {
            vm.prank(vetro);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, _short[i]));
            guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, _short[i]);
            vm.prank(council);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, _short[i]));
            guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, _short[i]);
        }
        vm.prank(council);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, 1 hours);
        assertEq(guard.approvalExpiry(_id), uint64(block.timestamp) + 1 hours);
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, uint64(7 days + 1)));
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, 7 days + 1);
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, 180 days);
    }

    /// @dev R2-B F-4: short `setFallbackHandler` payloads are typed for the council (approval, window,
    ///      dry run), never a calldata-slice `Panic`.
    function test_short_setFallbackHandler_payload_is_typed_for_the_council() public {
        bytes[3] memory _short = [
            abi.encodeWithSelector(SET_FALLBACK_HANDLER), // selector only
            abi.encodePacked(SET_FALLBACK_HANDLER, bytes16(0)), // 20 bytes
            abi.encodePacked(SET_FALLBACK_HANDLER, bytes31(0)) // 35 bytes
        ];
        for (uint256 i; i < _short.length; ++i) {
            vm.prank(council);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, SET_FALLBACK_HANDLER, Operation.Call));
            guard.approveTransaction(address(safe), address(0), address(safe), 0, _short[i], Operation.Call, 1 days);
        }
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        for (uint256 i; i < _short.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, SET_FALLBACK_HANDLER));
            guard.validateTransaction(address(safe), address(safe), 0, _short[i], Operation.Call);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, SET_FALLBACK_HANDLER));
            _execSafeTx(address(safe), 0, _short[i], Operation.Call);
        }
    }

    /// @dev R1D-2, the vector: with a stateful fallback handler installed, a Safe self-call with a
    ///      selector the Safe does not implement reaches the handler with the Safe as caller. The council
    ///      can authorise it neither by approval nor inside its window; the admin can.
    function test_council_cannot_reach_a_stateful_fallback_handler_through_the_safe() public {
        StatefulHandler _handler = new StatefulHandler();
        vm.prank(address(safe));
        FallbackManager(payable(address(safe))).setFallbackHandler(address(_handler));
        bytes memory _arm = abi.encodeWithSelector(bytes4(0x12345678));
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, bytes4(0x12345678), Operation.Call));
        guard.approveTransaction(address(safe), address(0), address(safe), 0, _arm, Operation.Call, 1 days);
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, bytes4(0x12345678)));
        _execSafeTx(address(safe), 0, _arm, Operation.Call);
        assertFalse(_handler.armed(address(safe)));
        _enforce();
        _approve(address(safe), 0, _arm, Operation.Call);
        assertTrue(_execSafeTx(address(safe), 0, _arm, Operation.Call));
        assertTrue(_handler.armed(address(safe)), "admin-only");
    }

    /// @dev R2A-1: a handler also answers a DIRECT call from the Safe (the Safe is `msg.sender` either
    ///      way). The policy's required handler therefore counts as part of the Safe for the council:
    ///      unreachable by approval, inside a window, and in the dry run, whatever the selector. A
    ///      handler the policy does not name is a venue call for the council (documented residual: a
    ///      non-zero handler the policy tolerates must be stateless or absent).
    function test_council_cannot_reach_the_policys_required_handler_directly() public {
        StatefulHandler _handler = new StatefulHandler();
        vm.prank(address(safe));
        FallbackManager(payable(address(safe))).setFallbackHandler(address(_handler));
        bytes memory _arm = abi.encodeWithSelector(bytes4(0x12345678));
        // Not named by the policy: a venue call (residual).
        bytes32 _id = _councilApprove(address(_handler), 0, _arm, Operation.Call);
        assertGt(guard.approvalExpiry(_id), 0);
        // Named by the policy: part of the Safe.
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(safe), address(_handler), true);
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, bytes4(0x12345678), Operation.Call));
        guard.approveTransaction(address(safe), address(0), address(_handler), 0, _arm, Operation.Call, 1 days);
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, bytes4(0), Operation.Call));
        guard.approveTransaction(address(safe), address(0), address(_handler), 0, "", Operation.Call, 1 days);
        vm.prank(council);
        guard.bypass(address(safe), 1 hours); // voids the earlier council approval too
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, bytes4(0x12345678)));
        guard.validateTransaction(address(safe), address(_handler), 0, _arm, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, bytes4(0x12345678)));
        _execSafeTx(address(_handler), 0, _arm, Operation.Call);
        _registerUnwrapper(address(multiSendCallOnly));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, bytes4(0x12345678)));
        _execSafeTx(address(multiSendCallOnly), 0, _multiSendCalldata(_entry(address(_handler), 0, _arm)), Operation.DelegateCall);
        assertFalse(_handler.armed(address(safe)));
        // The admin may, and an admin window is inert.
        _enforce();
        _approve(address(_handler), 0, _arm, Operation.Call);
        assertTrue(_execSafeTx(address(_handler), 0, _arm, Operation.Call));
        assertTrue(_handler.armed(address(safe)));
    }

    /// @dev The council allowlist selectors are the Safe's own, in v1.4.1 and v1.5.0 alike.
    function test_council_allowlist_selectors_are_the_safes() public pure {
        assertEq(ADD_OWNER, bytes4(0x0d582f13));
        assertEq(REMOVE_OWNER, bytes4(0xf8dc5dd9));
        assertEq(SWAP_OWNER, bytes4(0xe318b52b));
        assertEq(CHANGE_THRESHOLD, bytes4(0x694e80c3));
        assertEq(DISABLE_MODULE, bytes4(0xe009cfde));
        assertEq(SET_FALLBACK_HANDLER, bytes4(0xf08a0323));
        assertEq(OwnerManager.addOwnerWithThreshold.selector, ADD_OWNER);
        assertEq(OwnerManager.removeOwner.selector, REMOVE_OWNER);
        assertEq(OwnerManager.swapOwner.selector, SWAP_OWNER);
        assertEq(OwnerManager.changeThreshold.selector, CHANGE_THRESHOLD);
        assertEq(ModuleManager.disableModule.selector, DISABLE_MODULE);
        assertEq(FallbackManager.setFallbackHandler.selector, SET_FALLBACK_HANDLER);
        assertEq(OwnerManager150.addOwnerWithThreshold.selector, ADD_OWNER);
        assertEq(OwnerManager150.removeOwner.selector, REMOVE_OWNER);
        assertEq(OwnerManager150.swapOwner.selector, SWAP_OWNER);
        assertEq(OwnerManager150.changeThreshold.selector, CHANGE_THRESHOLD);
        assertEq(ModuleManager150.disableModule.selector, DISABLE_MODULE);
        assertEq(FallbackManager150.setFallbackHandler.selector, SET_FALLBACK_HANDLER);
        assertEq(Safe.approveHash.selector, APPROVE_HASH);
        assertEq(Safe.setup.selector, SETUP);
        assertEq(Safe150.setup.selector, SETUP);
    }

    /// @dev The guard's own selector constants equal the pinned ones.
    function test_guard_selector_constants_are_pinned() public view {
        assertEq(_H().safeAddOwnerWithThreshold(), ADD_OWNER);
        assertEq(_H().safeRemoveOwner(), REMOVE_OWNER);
        assertEq(_H().safeSwapOwner(), SWAP_OWNER);
        assertEq(_H().safeChangeThreshold(), CHANGE_THRESHOLD);
        assertEq(_H().safeDisableModule(), DISABLE_MODULE);
        assertEq(_H().safeSetFallbackHandler(), SET_FALLBACK_HANDLER);
    }

    /// @dev R1D-3: a Safe that was given the council role by mistake cannot unlock, approve or open a
    ///      window for ITSELF; it keeps those powers over other Safes and its narrowing powers.
    function test_a_safe_holding_the_council_role_cannot_authorize_itself() public {
        address _other = makeAddr("other-safe");
        bytes32 _role = guard.COUNCIL_ROLE();
        vm.prank(vetro);
        guard.grantRole(_role, address(safe));
        vm.startPrank(address(safe));
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.enforce(address(safe));
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.bypass(address(safe), 1 hours);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _settle(1), Operation.Call, 1 days);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.executeBefore(uint64(block.timestamp), abi.encodeCall(guard.enforce, (address(safe))));
        guard.enforce(_other);
        guard.approveTransaction(_other, address(0), address(protocol), 0, _settle(1), Operation.Call, 1 days);
        guard.lockdownAndRevoke(address(safe));
        vm.stopPrank();
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        assertEq(uint8(guard.mode(_other)), uint8(CuratorGuardPolicy.Mode.Enforced));
        vm.warp(block.timestamp + _H().lockdownCooldown() + 1); // the admin waits out the lockdown cooldown
        _enforce(); // the admin is never a guarded Safe, so the self-rule never touches it
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Enforced));
    }

    /// @dev Round 5, R3D-2: after any lockdown the ADMIN may not enforce, open a window or approve for
    ///      that Safe for a day (its actions come out of a public timelock queue, scheduled before the
    ///      incident and executable by anyone); the council acts at once; other Safes, widenings and
    ///      guardian management are not held back.
    function test_admin_lifts_windows_and_approvals_wait_a_day_after_any_lockdown() public {
        assertEq(_H().lockdownCooldown(), 1 days);
        _addGuardian(guardian);
        address _other = makeAddr("other-safe");
        bytes memory _err = abi.encodeWithSelector(CuratorGuardPolicy.LockdownCooldown.selector, address(safe));
        // No lockdown yet: no cooldown.
        _enforce();
        address[3] memory _lockers = [guardian, council, vetro]; // whoever locks, the admin waits
        for (uint256 i; i < _lockers.length; ++i) {
            vm.prank(_lockers[i]);
            if (i == 0) guard.lockdownAndRevoke(address(safe));
            else guard.lockdown(address(safe));
            uint256 _lockedAt = block.timestamp;
            assertEq(_H().lockedAt(address(safe)), _lockedAt);
            vm.startPrank(vetro);
            vm.expectRevert(_err);
            guard.enforce(address(safe));
            vm.expectRevert(_err);
            guard.bypass(address(safe), 1 days);
            vm.expectRevert(_err);
            guard.approveTransaction(address(safe), address(0), address(protocol), 0, _settle(1), Operation.Call, 1 days);
            vm.expectRevert(_err);
            guard.executeBefore(uint64(block.timestamp + 1), abi.encodeCall(guard.enforce, (address(safe))));
            // Not held back: widenings, guardian management, another Safe.
            guard.allowFunction(address(safe), address(protocol), SETTLE, false, _noRules());
            guard.setGuardian(address(safe), makeAddr("another-guardian"), true);
            guard.enforce(_other);
            guard.approveTransaction(_other, address(0), address(protocol), 0, _settle(1), Operation.Call, 1 days);
            vm.stopPrank();
            // The last second of the day is still inside; the next one is out.
            vm.warp(_lockedAt + 1 days);
            vm.prank(vetro);
            vm.expectRevert(_err);
            guard.enforce(address(safe));
            vm.warp(_lockedAt + 1 days + 1);
            _enforce();
            _approve(address(protocol), 0, _settle(i), Operation.Call);
            _bypass(1 hours);
            _enforce();
        }
        // The council is never held back.
        vm.prank(guardian);
        guard.lockdown(address(safe));
        vm.startPrank(council);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _settle(9), Operation.Call, 1 days);
        guard.enforce(address(safe));
        guard.bypass(address(safe), 1 hours);
        vm.stopPrank();
    }

    /// @dev Round 5, R3C-1 / R3A F-2: a new owner the council brings in must be a plain key. An account
    ///      with code (the guard itself, a venue, a Safe, an EIP-7702 delegated EOA) can be a seat that
    ///      never signs, or one that accepts any signature; either defeats the threshold, so such owners
    ///      are admin-only, for approvals and council windows alike.
    function test_council_cannot_bring_in_an_owner_with_code() public {
        address _eoa = makeAddr("eoa-owner");
        address _delegated = makeAddr("delegated-eoa");
        vm.etch(_delegated, abi.encodePacked(hex"ef0100", address(protocol))); // EIP-7702 designator
        address[4] memory _withCode = [address(guard), address(protocol), address(multiSendCallOnly), _delegated];
        for (uint256 i; i < _withCode.length; ++i) {
            bytes memory _add = abi.encodeCall(ISafe.addOwnerWithThreshold, (_withCode[i], 2));
            bytes memory _swap = abi.encodeWithSelector(SWAP_OWNER, address(0x1), curator, _withCode[i]);
            vm.prank(council);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, ADD_OWNER, Operation.Call));
            guard.approveTransaction(address(safe), address(0), address(safe), 0, _add, Operation.Call, 1 days);
            vm.prank(council);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, SWAP_OWNER, Operation.Call));
            guard.approveTransaction(address(safe), address(0), address(safe), 0, _swap, Operation.Call, 1 days);
            assertGt(guard.approvalExpiry(_approve(address(safe), 0, _add, Operation.Call)), 0, "admin may");
            assertGt(guard.approvalExpiry(_approve(address(safe), 0, _swap, Operation.Call)), 0, "admin may");
        }
        // A plain key is fine on both selectors; a swap payload without its third word is refused.
        assertGt(guard.approvalExpiry(_councilApprove(address(safe), 0, abi.encodeCall(ISafe.addOwnerWithThreshold, (_eoa, 2)), Operation.Call)), 0);
        assertGt(guard.approvalExpiry(_councilApprove(address(safe), 0, abi.encodeWithSelector(SWAP_OWNER, address(0x1), curator, _eoa), Operation.Call)), 0);
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, SWAP_OWNER, Operation.Call));
        guard.approveTransaction(address(safe), address(0), address(safe), 0, abi.encodeWithSelector(SWAP_OWNER, address(0x1), curator), Operation.Call, 1 days);
        // Inside a council window: the same, live and in the dry run.
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        for (uint256 i; i < _withCode.length; ++i) {
            bytes memory _add = abi.encodeCall(ISafe.addOwnerWithThreshold, (_withCode[i], 2));
            bytes memory _swap = abi.encodeWithSelector(SWAP_OWNER, address(0x1), curator, _withCode[i]);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, ADD_OWNER));
            guard.validateTransaction(address(safe), address(safe), 0, _add, Operation.Call);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, ADD_OWNER));
            _execSafeTx(address(safe), 0, _add, Operation.Call);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, SWAP_OWNER));
            guard.validateTransaction(address(safe), address(safe), 0, _swap, Operation.Call);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, SWAP_OWNER));
            _execSafeTx(address(safe), 0, _swap, Operation.Call);
        }
        assertTrue(_execSafeTx(address(safe), 0, abi.encodeWithSelector(SWAP_OWNER, address(0x1), curator, _eoa), Operation.Call), "plain key");
        assertEq(safe.getOwners()[0], _eoa);
    }

    /// @dev R1D-7: an absurd declared `multiSend` payload length is `MalformedMultiSend`, not a `Panic`
    ///      from the padding arithmetic.
    function test_absurd_multisend_length_is_malformed_not_a_panic() public {
        _enforce();
        _registerUnwrapper(address(multiSendCallOnly));
        bytes memory _data = abi.encodePacked(bytes4(0x8d80ff0a), uint256(0x20), type(uint256).max, bytes32(0));
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        guard.validateTransaction(address(safe), address(multiSendCallOnly), 0, _data, Operation.DelegateCall);
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        _execSafeTx(address(multiSendCallOnly), 0, _data, Operation.DelegateCall);
        bytes memory _overshoot = abi.encodePacked(bytes4(0x8d80ff0a), uint256(0x20), type(uint256).max - 30, bytes32(0));
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        guard.validateTransaction(address(safe), address(multiSendCallOnly), 0, _overshoot, Operation.DelegateCall);
    }
}

/// @title Items 8, 9 and 12 on the module path (real Safe v1.5.0 with `setModuleGuard`).
contract CuratorGuardRobustnessModuleTest is SafeTxHelper {
    CuratorGuard internal guard;
    ModuleStub internal module;
    MockProtocol internal protocol;
    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal guardian = makeAddr("guardian");
    address internal attacker = makeAddr("attacker");
    address internal curator;
    uint8 internal constant PATH_MODULE = 1;
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;

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
        module = new ModuleStub();
        protocol = new MockProtocol();
        vm.startPrank(address(safe));
        safe.enableModule(address(module));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        vm.stopPrank();
        vm.startPrank(vetro);
        guard.enforce(address(safe));
        guard.allowFunction(address(safe), address(protocol), SETTLE, false, _noRules());
        guard.setModuleAllowed(address(safe), address(module), true);
        guard.setGuardian(address(safe), guardian, true);
        vm.stopPrank();
    }

    function _noRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _rules) {}

    function _moduleHash(address module_, address to_, uint256 value_, bytes memory data_, Operation op_) internal view returns (bytes32) {
        return keccak256(abi.encode(address(safe), module_, to_, value_, keccak256(data_), op_));
    }

    function _reported(Vm.Log[] memory logs_) internal view returns (uint256 _n, Vm.Log memory _last) {
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter == address(guard) && logs_[i].topics[0] == CuratorGuard.TransactionChecked.selector) {
                ++_n;
                _last = logs_[i];
            }
        }
    }

    /// @dev `checkModuleTransaction` returns the documented payload hash, which the Safe echoes into the
    ///      post-hook and the guard into the event (path 1).
    function test_module_pre_hook_returns_the_payload_hash_reported_by_the_post_hook() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (5));
        bytes32 _expected = _moduleHash(address(module), address(protocol), 0, _data, Operation.Call);
        vm.prank(address(safe));
        bytes32 _returned = guard.checkModuleTransaction(address(protocol), 0, _data, Operation.Call, address(module));
        assertEq(_returned, _expected, "payload hash");
        vm.prank(address(safe));
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(safe), _expected, PATH_MODULE, CuratorGuard.Outcome.Policy);
        guard.checkAfterModuleExecution(_returned, true);
        // Distinct for a different module, value, data, operation or target: the guard's own answers,
        // taken inside an admin window (nothing is recorded there, so the pre-hook can be called again).
        vm.startPrank(vetro);
        guard.bypass(address(safe), 1 hours);
        guard.setModuleAllowed(address(safe), attacker, true); // the allowlist holds inside a window too
        vm.stopPrank();
        bytes32[5] memory _variants;
        vm.startPrank(address(safe));
        _variants[0] = guard.checkModuleTransaction(address(protocol), 0, _data, Operation.Call, attacker);
        _variants[1] = guard.checkModuleTransaction(address(protocol), 1, _data, Operation.Call, address(module));
        _variants[2] = guard.checkModuleTransaction(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (6)), Operation.Call, address(module));
        _variants[3] = guard.checkModuleTransaction(address(protocol), 0, _data, Operation.DelegateCall, address(module));
        _variants[4] = guard.checkModuleTransaction(attacker, 0, _data, Operation.Call, address(module));
        assertEq(guard.checkModuleTransaction(address(protocol), 0, _data, Operation.Call, address(module)), _expected, "same payload, same hash");
        vm.stopPrank();
        for (uint256 i; i < 5; ++i) {
            assertTrue(_variants[i] != _expected, "variant differs");
            for (uint256 j = i + 1; j < 5; ++j) assertTrue(_variants[i] != _variants[j], "variants pairwise distinct");
        }
    }

    /// @dev R2-B F-1: inside an ADMIN window a module must not reach the guard either (a forged
    ///      `checkAfterModuleExecution` would add a Bypass report under an arbitrary hash), live and in
    ///      the dry run; everything else stays unchecked there for an ALLOWLISTED module, while a module
    ///      off the allowlist stays out in every mode (round 8, R8R-1).
    function test_admin_window_never_lets_a_module_call_the_guard() public {
        vm.prank(vetro);
        guard.bypass(address(safe), 1 days);
        bytes memory _forge = abi.encodeCall(guard.checkAfterModuleExecution, (bytes32("forged"), true));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, guard.checkAfterModuleExecution.selector));
        module.exec(safe, address(guard), 0, _forge, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, guard.checkAfterModuleExecution.selector));
        guard.validateModuleTransaction(address(safe), address(module), address(guard), 0, _forge, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, bytes4(0)));
        module.exec(safe, address(guard), 0, "", Operation.Call);
        vm.recordLogs();
        assertTrue(module.exec(safe, address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (1, attacker)), Operation.Call));
        assertTrue(module.exec(safe, address(safe), 0, abi.encodeCall(ISafe.enableModule, (attacker)), Operation.Call));
        (uint256 _n, ) = _reported(vm.getRecordedLogs());
        assertEq(_n, 2, "one genuine report per module transaction, no forged one");
        // A guardian's `setModuleAllowed(false)` is a complete switch, inside the admin window too.
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(module), false);
        bytes memory _deposit = abi.encodeCall(MockProtocol.deposit, (1, attacker));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module)));
        module.exec(safe, address(protocol), 0, _deposit, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module)));
        guard.validateModuleTransaction(address(safe), address(module), address(protocol), 0, _deposit, Operation.Call);
    }

    /// @dev Through the real v1.5.0 module path: Policy, Approval (bound to the module) and Bypass, each
    ///      reported exactly once with path 1 and the payload hash; a refused module transaction is not.
    function test_module_transactions_are_reported_per_outcome() public {
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.recordLogs();
        assertTrue(module.exec(safe, address(protocol), 0, _settle, Operation.Call));
        (uint256 _n, Vm.Log memory _l) = _reported(vm.getRecordedLogs());
        assertEq(_n, 1);
        assertEq(_l.topics[1], bytes32(uint256(uint160(address(safe)))));
        assertEq(_l.topics[2], _moduleHash(address(module), address(protocol), 0, _settle, Operation.Call));
        assertEq(_l.topics[3], bytes32(uint256(CuratorGuard.Outcome.Policy)));
        assertEq(_l.data, abi.encode(PATH_MODULE));

        bytes memory _deposit = abi.encodeCall(MockProtocol.deposit, (1, attacker));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(module), address(protocol), 0, _deposit, Operation.Call, 1 days);
        vm.recordLogs();
        assertTrue(module.exec(safe, address(protocol), 0, _deposit, Operation.Call));
        (_n, _l) = _reported(vm.getRecordedLogs());
        assertEq(_n, 1);
        assertEq(_l.topics[2], _moduleHash(address(module), address(protocol), 0, _deposit, Operation.Call));
        assertEq(_l.topics[3], bytes32(uint256(CuratorGuard.Outcome.Approval)));
        assertEq(_l.data, abi.encode(PATH_MODULE));

        // A COUNCIL window holds the module path to the policy (V2-66): the allowed payload passes and is
        // reported as Policy, the other one is refused; an ADMIN window is inert and reports Bypass.
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        vm.recordLogs();
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector));
        module.exec(safe, address(protocol), 0, _deposit, Operation.Call);
        assertTrue(module.exec(safe, address(protocol), 0, _settle, Operation.Call));
        (_n, _l) = _reported(vm.getRecordedLogs());
        assertEq(_n, 1);
        assertEq(_l.topics[2], _moduleHash(address(module), address(protocol), 0, _settle, Operation.Call));
        assertEq(_l.topics[3], bytes32(uint256(CuratorGuard.Outcome.Policy)));
        assertEq(_l.data, abi.encode(PATH_MODULE));
        vm.prank(vetro);
        guard.bypass(address(safe), 1 hours);
        vm.recordLogs();
        assertTrue(module.exec(safe, address(protocol), 0, _deposit, Operation.Call));
        (_n, _l) = _reported(vm.getRecordedLogs());
        assertEq(_n, 1);
        assertEq(_l.topics[3], bytes32(uint256(CuratorGuard.Outcome.Bypass)));
        assertEq(_l.data, abi.encode(PATH_MODULE));

        vm.prank(vetro);
        guard.enforce(address(safe));
        vm.recordLogs();
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector));
        module.exec(safe, address(protocol), 0, _deposit, Operation.Call);
        (_n, ) = _reported(vm.getRecordedLogs());
        assertEq(_n, 0, "refused: not reported");
    }

    /// @dev A failed approved module execution reverts the module transaction (`ApprovedExecutionFailed`),
    ///      reports nothing and keeps the approval; the retry is then reported as Approval.
    function test_failed_approved_module_execution_reports_nothing_and_keeps_the_approval() public {
        Reverter _reverter = new Reverter();
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (9));
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(module), address(_reverter), 0, _data, Operation.Call, 1 days);
        vm.recordLogs();
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ApprovedExecutionFailed.selector, address(safe)));
        module.exec(safe, address(_reverter), 0, _data, Operation.Call);
        (uint256 _n, ) = _reported(vm.getRecordedLogs());
        assertEq(_n, 0);
        assertGt(guard.approvalExpiry(_id), 0, "approval kept");
        vm.etch(address(_reverter), address(protocol).code); // the venue is fixed: the retry passes
        vm.recordLogs();
        assertTrue(module.exec(safe, address(_reverter), 0, _data, Operation.Call));
        (_n, ) = _reported(vm.getRecordedLogs());
        assertEq(_n, 1);
        assertEq(guard.approvalExpiry(_id), 0, "consumed");
    }

    /// @dev Owner and module paths of the same Safe report independently in one EVM transaction.
    function test_owner_and_module_paths_report_independently() public {
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.recordLogs();
        assertTrue(module.exec(safe, address(protocol), 0, _settle, Operation.Call));
        assertTrue(_execSafeTx(address(protocol), 0, _settle, Operation.Call));
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        (uint256 _n, ) = _reported(_logs);
        assertEq(_n, 2);
        uint256 _paths;
        for (uint256 i; i < _logs.length; ++i) {
            if (_logs[i].emitter == address(guard) && _logs[i].topics[0] == CuratorGuard.TransactionChecked.selector) {
                uint8 _path = abi.decode(_logs[i].data, (uint8));
                _paths |= 1 << _path;
            }
        }
        assertEq(_paths, 3, "one report per path");
    }

    /// @dev `lockdownAndRevoke` by a guardian kills a module-bound approval and locks the module path.
    function test_lockdownAndRevoke_covers_module_bound_approvals() public {
        bytes memory _deposit = abi.encodeCall(MockProtocol.deposit, (1, attacker));
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(module), address(protocol), 0, _deposit, Operation.Call, 1 days);
        vm.prank(guardian);
        guard.lockdownAndRevoke(address(safe));
        assertEq(guard.approvalExpiry(_id), 0);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        module.exec(safe, address(protocol), 0, _deposit, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        module.exec(safe, address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
    }

    /// @dev R1D-4: a council window keeps the module allowlist in force (an enabled module that a
    ///      guardian revoked does not regain power inside the window). Round 6 (V2-66): it keeps the
    ///      POLICY in force for modules as well: a window is opened for the signers, a module needs no
    ///      owner signature. An admin window is inert for an allowlisted module only (round 8, R8R-1).
    function test_council_window_keeps_the_module_allowlist() public {
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        bytes memory _deposit = abi.encodeCall(MockProtocol.deposit, (1, attacker));
        vm.prank(guardian);
        guard.setModuleAllowed(address(safe), address(module), false);
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module)));
        module.exec(safe, address(protocol), 0, _settle, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module)));
        guard.validateModuleTransaction(address(safe), address(module), address(protocol), 0, _settle, Operation.Call);
        assertTrue(_execSafeTx(address(protocol), 0, _deposit, Operation.Call), "owner path relaxed");
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(module), true);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector));
        module.exec(safe, address(protocol), 0, _deposit, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector));
        guard.validateModuleTransaction(address(safe), address(module), address(protocol), 0, _deposit, Operation.Call);
        assertTrue(module.exec(safe, address(protocol), 0, _settle, Operation.Call), "allowlisted module, policy-allowed call");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, ISafe.setGuard.selector));
        module.exec(safe, address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call);
        // The configuration snapshot is taken on that path too: a module that changes the Safe's
        // configuration inside a council window is caught by the post-hook like under Enforced.
        vm.prank(guardian);
        guard.setModuleAllowed(address(safe), address(module), false);
        vm.prank(vetro);
        guard.bypass(address(safe), 1 hours);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module)));
        module.exec(safe, address(protocol), 0, _deposit, Operation.Call);
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(module), true);
        assertTrue(module.exec(safe, address(protocol), 0, _deposit, Operation.Call), "admin window inert for an allowlisted module");
    }

    /// @dev The module-path dry run reads the configuration where the live pre-check does: an
    ///      unreadable v1.5.0 Safe (owner count below the list) is typed on both.
    function test_unreadable_configuration_on_the_module_path() public {
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.store(address(safe), bytes32(uint256(3)), bytes32(0));
        bytes memory _err = abi.encodeWithSelector(CuratorGuard.SafeConfigUnreadable.selector, address(safe));
        vm.expectRevert(_err);
        guard.validateModuleTransaction(address(safe), address(module), address(protocol), 0, _settle, Operation.Call);
        vm.expectRevert(_err);
        module.exec(safe, address(protocol), 0, _settle, Operation.Call);
        vm.store(address(safe), bytes32(uint256(3)), bytes32(uint256(1)));
        guard.validateModuleTransaction(address(safe), address(module), address(protocol), 0, _settle, Operation.Call);
        assertTrue(module.exec(safe, address(protocol), 0, _settle, Operation.Call));
    }
}

/// @dev Minimal Safe module: whoever calls `exec` makes the Safe execute the payload.
contract ModuleStub {
    function exec(ISafe safe_, address to_, uint256 value_, bytes calldata data_, Operation op_) external returns (bool) {
        return safe_.execTransactionFromModule(to_, value_, data_, op_);
    }
}
