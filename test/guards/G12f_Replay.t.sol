// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Test.sol";

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

/// @dev Records every call it receives (as g10b's book): `(target, sender, value, data)` hashed, in order.
contract G12fBook {
    bytes32[] public entries;

    function record(address target_, address sender_, uint256 value_, bytes calldata data_) external {
        entries.push(keccak256(abi.encode(target_, sender_, value_, data_)));
    }

    function digest() external view returns (bytes32) {
        return keccak256(abi.encodePacked(entries));
    }

    function reset() external {
        delete entries;
    }
}

contract G12fRecorder {
    G12fBook internal immutable book;

    constructor(G12fBook book_) {
        book = book_;
    }

    fallback() external payable {
        book.record(address(this), msg.sender, msg.value, msg.data);
    }

    receive() external payable {
        book.record(address(this), msg.sender, msg.value, "");
    }
}

/// @title Round 12 (g12f): replay of the differential fuzz's exported vectors on forge's EVM.
/// @notice The fuzz (review-scratch/g12f/fuzz: random policies through the real lint, the real `curator-guard-sync`
///         and the guard on hardhat's EVM) exported, for the cap-sized policies, the on-chain policy the sync wrote
///         and every vector with the model's verdict (docs section 4, steps 10-11) and the calls the Safe must
///         make. This suite rebuilds the same fixture here (the canonical Safe v1.4.1 singleton and proxy code at
///         their mainnet addresses, the curator Safe's address, the canonical `MultiSendCallOnly` v1.4.1, the
///         recorders and the guard at the addresses hardhat's account 0 deployed them to) and replays everything
///         against the dry run and the live hooks through genuine `execTransaction`s: a second EVM (revm) agreeing
///         with the first (ethereumjs) on every verdict and every executed call.
contract G12fReplayTest is SafeTxHelper {
    struct ValueSet {
        address target;
        bytes4 selector;
        uint16 wordIndex;
        bytes32[] values;
    }

    struct Vec {
        bytes32 callsHash;
        bytes data;
        bytes expect;
        address module;
        uint8 op;
        address to;
        uint256 value;
    }

    address internal constant ACCOUNT0 = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266; // hardhat account 0 (the deployer)
    address internal constant SAFE = 0x1b534a8543212F5957168D83311A41E0Ea1cfe48;
    address internal constant SINGLETON = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    address internal constant MSCO141 = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;
    address internal constant DELEGATED = 0x7702000000000000000000000000000000000001;
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    CuratorGuard internal guard;
    G12fBook internal book;
    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal curator;
    address[8] internal R;

    function setUp() public {
        if (block.timestamp < 1_700_000_000) vm.warp(1_700_000_000);
        (curator, signerPk) = makeAddrAndKey("curator");
        vm.etch(SINGLETON, vm.parseBytes(vm.trim(vm.readFile("test/guards/vectors-g12f/codes/safe-1.4.1-singleton.hex"))));
        vm.etch(SAFE, vm.parseBytes(vm.trim(vm.readFile("test/guards/vectors-g12f/codes/safe-proxy-1.4.1-curator.hex"))));
        vm.store(SAFE, bytes32(0), bytes32(uint256(uint160(SINGLETON))));
        vm.etch(MSCO141, vm.parseBytes(vm.readFile("test/guards/vectors/multisend-callonly-v141.hex")));
        book = new G12fBook();
        G12fRecorder _rec = new G12fRecorder(book);
        for (uint256 i; i < 8; ++i) {
            R[i] = vm.computeCreateAddress(ACCOUNT0, 1 + i);
            vm.etch(R[i], address(_rec).code); // the immutable book address is baked into the runtime
        }
        vm.etch(DELEGATED, abi.encodePacked(hex"ef0100", R[0]));
        // the guard at the address hardhat's account 0 deployed it to (nonce 9): the vectors name it
        vm.setNonce(ACCOUNT0, 9);
        vm.prank(ACCOUNT0);
        guard = new CuratorGuard(0, vetro, council);
        assertEq(address(guard), vm.computeCreateAddress(ACCOUNT0, 9), "guard address");
        // the real Safe behind the canonical code, one owner, no handler
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe(payable(SAFE)).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        safe = ISafe(SAFE);
        vm.deal(SAFE, 100 ether);
        _execSafeTx(SAFE, 0, abi.encodeCall(ISafe.setGuard, (address(guard))), Operation.Call);
        assertEq(address(uint160(uint256(bytes32(safe.getStorageAt(uint256(GUARD_SLOT), 1))))), address(guard), "installed");
        assertTrue(guard.isUnwrapperCodehash(MSCO141.codehash), "canonical unwrapper code");
    }

    // One test per exported file: forge's memory is never freed inside a test, and nine 400-500 KB files with
    // their decoded vectors in one frame exhaust the per-test gas limit through memory expansion.
    function test_replay_caps_p0_rules16_ceilings() public { _replayFile(0); }
    function test_replay_caps_p1_rules16_mixed_kinds() public { _replayFile(1); }
    function test_replay_caps_p2_oneof_128_plus_128() public { _replayFile(2); }
    function test_replay_caps_p3_members_1024_per_target() public { _replayFile(3); }
    function test_replay_caps_p4_functions32_guardians32() public { _replayFile(4); }
    function test_replay_caps_p5_tails() public { _replayFile(5); }
    function test_replay_caps_p6_wide_head_2000_words() public { _replayFile(6); }
    function test_replay_caps_p7_value_boundaries() public { _replayFile(7); }
    function test_replay_caps_p8_vetro_shape_banded() public { _replayFile(8); }

    function _replayFile(uint256 n_) internal {
        string memory _file = string.concat("test/guards/vectors-g12f/policies-caps-p-", vm.toString(n_), ".json");
        assertTrue(vm.isFile(_file), "vectors file present");
        string memory _json = vm.readFile(_file);
        _applySpecs(vm.parseJsonBytes(_json, ".specs"));
        _applySets(vm.parseJsonBytes(_json, ".sets"));
        _applyLists(vm.parseJsonBytes(_json, ".native"), vm.parseJsonBytes(_json, ".unwrappers"));
        bytes[] memory _blobs = abi.decode(vm.parseJson(_json, ".vectors"), (bytes[]));
        uint256 _accepted;
        for (uint256 i; i < _blobs.length; ++i) {
            if (_replay(_blobs[i], string.concat("policy ", vm.toString(n_), " vector ", vm.toString(i)))) ++_accepted;
        }
        console2.log("policy", n_, "vectors", _blobs.length);
        console2.log("accepted and executed live", _accepted);
        assertGt(_blobs.length, 30, "vectors present");
    }

    /// @dev One vector: the dry run's revert data equals the oracle's; an accepted one executes through the Safe and
    ///      the Safe makes exactly the recorded calls. Returns whether it was accepted.
    function _replay(bytes memory blob_, string memory label_) internal returns (bool) {
        Vec memory v = _vec(blob_);
        assertEq(_dry(v.to, v.value, v.data, v.op), v.expect, label_);
        if (v.expect.length != 0) return false;
        book.reset();
        assertTrue(_execSafeTx(v.to, v.value, v.data, Operation(v.op)), string.concat(label_, " live"));
        assertEq(book.digest(), v.callsHash, string.concat(label_, " calls"));
        return true;
    }

    /// @dev The driver encodes the seven fields as a flat tuple (no outer offset word), as g10b's oracle did.
    function _vec(bytes memory blob_) internal pure returns (Vec memory) {
        (bytes32 _h, bytes memory _d, bytes memory _e, address _m, uint8 _op, address _to, uint256 _val) =
            abi.decode(blob_, (bytes32, bytes, bytes, address, uint8, address, uint256));
        return Vec(_h, _d, _e, _m, _op, _to, _val);
    }

    /// @dev The on-chain policy as the sync wrote it (read back on hardhat), applied here as the admin; one blob
    ///      per part, each decoded in its own frame (the legacy codegen's stack).
    function _applySpecs(bytes memory blob_) internal {
        CuratorGuardPolicy.FunctionSpec[] memory _specs = abi.decode(blob_, (CuratorGuardPolicy.FunctionSpec[]));
        vm.prank(vetro);
        guard.allowFunctions(SAFE, _specs);
    }

    function _applySets(bytes memory blob_) internal {
        ValueSet[] memory _sets = abi.decode(blob_, (ValueSet[]));
        vm.startPrank(vetro);
        for (uint256 i; i < _sets.length; ++i) {
            guard.addAllowedValues(SAFE, _sets[i].target, _sets[i].selector, _sets[i].wordIndex, _sets[i].values);
        }
        vm.stopPrank();
    }

    function _applyLists(bytes memory native_, bytes memory unwrappers_) internal {
        address[] memory _native = abi.decode(native_, (address[]));
        address[] memory _unwrappers = abi.decode(unwrappers_, (address[]));
        vm.startPrank(vetro);
        for (uint256 i; i < _native.length; ++i) guard.setNativeTransferAllowed(SAFE, _native[i], true);
        for (uint256 i; i < _unwrappers.length; ++i) guard.setMultiSendUnwrapper(SAFE, _unwrappers[i], true);
        guard.enforce(SAFE);
        vm.stopPrank();
    }

    function _dry(address to_, uint256 value_, bytes memory data_, uint8 op_) internal view returns (bytes memory) {
        try guard.validateTransaction(SAFE, to_, value_, data_, Operation(op_)) {
            return "";
        } catch (bytes memory _err) {
            return _err;
        }
    }
}
