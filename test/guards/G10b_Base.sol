// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {MultiSendCallOnly} from "safe-contracts-v1.4.1/contracts/libraries/MultiSendCallOnly.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase} from "test/guards/CuratorGuardTestBase.sol";

/// @dev Records every call it receives: `(target, sender, value, data)` hashed per call, in order.
contract G10bLogBook {
    bytes32[] public entries;

    function record(address target_, address sender_, uint256 value_, bytes calldata data_) external {
        entries.push(keccak256(abi.encode(target_, sender_, value_, data_)));
    }

    function count() external view returns (uint256) {
        return entries.length;
    }

    /// @dev One hash over the whole sequence, what the oracle predicts as `callsHash`.
    function digest() external view returns (bytes32) {
        return keccak256(abi.encodePacked(entries));
    }

    function reset() external {
        delete entries;
    }
}

contract G10bRecorder {
    G10bLogBook internal immutable book;

    constructor(G10bLogBook book_) {
        book = book_;
    }

    fallback() external payable {
        book.record(address(this), msg.sender, msg.value, msg.data);
    }

    receive() external payable {
        book.record(address(this), msg.sender, msg.value, "");
    }
}

/// @title G10b fixture: the policy the oracle (`gen.mjs`, kept with the round-10 review material) models.
/// @dev Addresses are deterministic (same deployer, same creation order); the vectors file carries them
///      and `_assertFixture` refuses to run against a fixture that moved.
abstract contract G10bBase is CuratorGuardTestBase {
    G10bLogBook internal book;
    G10bRecorder internal A;
    G10bRecorder internal B;
    G10bRecorder internal C;
    G10bRecorder internal H; // the policy's named fallback handler (enforce = false)
    address internal D = makeAddr("g10b-D"); // allowlisted, no code
    address internal E = makeAddr("g10b-E"); // nothing allowed, no code
    address internal M = makeAddr("g10b-M"); // allowlisted module
    address internal M2 = makeAddr("g10b-M2"); // module off the allowlist
    MultiSendCallOnly internal U2; // same code as the registered unwrapper, not registered
    address internal constant CAN130 = 0x0000000000000000000000000000000000013000;
    address internal constant CAN141 = 0x0000000000000000000000000000000000014100;
    address internal constant CAN150 = 0x0000000000000000000000000000000000015000;

    bytes4 internal constant F0 = bytes4(keccak256("f0()"));
    bytes4 internal constant F1 = bytes4(keccak256("f1(uint256)"));
    bytes4 internal constant F2 = bytes4(keccak256("f2(uint256,address,int256)"));
    bytes4 internal constant F3 = bytes4(keccak256("f3(address,address)"));
    bytes4 internal constant F4 = bytes4(keccak256("f4(uint256,bytes)"));
    bytes4 internal constant F5 = bytes4(keccak256("f5(bytes)"));
    bytes4 internal constant F6 = bytes4(keccak256("f6(uint256,uint256,uint256,uint256)"));
    bytes4 internal constant F7 = bytes4(keccak256("f7(uint256,uint256,bytes)"));
    bytes4 internal constant F8 = bytes4(keccak256("f8(bool)"));
    uint16 internal constant TAIL = 0x8000;

    // The reviewed tails the tail rules bind: canonical encodings (offset, length, padded payload), no
    // address inside (so the oracle's hashes do not depend on the fixture addresses).
    bytes internal constant T4 =
        abi.encode(uint256(0x40), uint256(8), bytes32(0xdeadbeef01020304000000000000000000000000000000000000000000000000)); // f4(uint256 n, bytes p): tail from word 1
    bytes internal constant T5A =
        abi.encode(uint256(0x20), uint256(2), bytes32(0xcafe000000000000000000000000000000000000000000000000000000000000));
    bytes internal constant T5B =
        abi.encode(
            uint256(0x20),
            uint256(33),
            bytes32(0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20),
            bytes32(0x2100000000000000000000000000000000000000000000000000000000000000)
        );
    bytes internal constant T7 =
        abi.encode(uint256(0x60), uint256(2), bytes32(0xbeef000000000000000000000000000000000000000000000000000000000000)); // f7(uint256,uint256,bytes): tail from word 2

    function setUp() public virtual override {
        super.setUp();
        book = new G10bLogBook();
        A = new G10bRecorder(book);
        B = new G10bRecorder(book);
        C = new G10bRecorder(book);
        H = new G10bRecorder(book);
        U2 = new MultiSendCallOnly();
        vm.etch(CAN130, vm.parseBytes(vm.readFile("test/guards/vectors/multisend-callonly-v130.hex")));
        vm.etch(CAN141, vm.parseBytes(vm.readFile("test/guards/vectors/multisend-callonly-v141.hex")));
        vm.etch(CAN150, vm.parseBytes(vm.readFile("test/guards/vectors/multisend-callonly-v150.hex")));
        assertTrue(guard.isUnwrapperCodehash(CAN130.codehash) && guard.isUnwrapperCodehash(CAN141.codehash) && guard.isUnwrapperCodehash(CAN150.codehash), "canonical code seeded");

        _enforce();
        _registerUnwrapper(address(multiSendCallOnly));
        vm.startPrank(vetro);
        guard.setMultiSendUnwrapper(address(safe), CAN130, true);
        guard.setMultiSendUnwrapper(address(safe), CAN141, true);
        guard.setMultiSendUnwrapper(address(safe), CAN150, true);
        guard.setModuleAllowed(address(safe), M, true);
        guard.setRequiredFallbackHandler(address(safe), address(H), false);
        guard.setNativeTransferAllowed(address(safe), address(B), true);
        guard.setNativeTransferAllowed(address(safe), address(C), true);
        // A
        guard.allowFunction(address(safe), address(A), F0, false, _noRules());
        guard.allowFunction(address(safe), address(A), F1, true, _noRules());
        CuratorGuardPolicy.ParamRule[] memory r = new CuratorGuardPolicy.ParamRule[](4);
        r[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.GreaterThanOrEqual, 0, bytes32(uint256(10)));
        r[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 0, bytes32(uint256(1_000_000)));
        r[2] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, 1, 0);
        r[3] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualTo, 2, bytes32(uint256(7)));
        guard.allowFunction(address(safe), address(A), F2, false, r);
        bytes32[] memory v = new bytes32[](3);
        v[0] = _word(address(A));
        v[1] = _word(address(B));
        v[2] = _word(address(safe));
        guard.addAllowedValues(address(safe), address(A), F2, 1, v);
        r = new CuratorGuardPolicy.ParamRule[](2);
        r[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualToSafe, 0, 0);
        r[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualToSafe, 1, 0);
        guard.allowFunction(address(safe), address(A), F3, false, r);
        r = new CuratorGuardPolicy.ParamRule[](2);
        r[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualTo, 0, bytes32(uint256(5)));
        r[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualTo, 1 | TAIL, keccak256(T4));
        guard.allowFunction(address(safe), address(A), F4, false, r);
        r = new CuratorGuardPolicy.ParamRule[](1);
        r[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, 0 | TAIL, 0);
        guard.allowFunction(address(safe), address(A), F5, false, r);
        v = new bytes32[](2);
        v[0] = keccak256(T5A);
        v[1] = keccak256(T5B);
        guard.addAllowedValues(address(safe), address(A), F5, 0 | TAIL, v);
        r = new CuratorGuardPolicy.ParamRule[](1);
        r[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualTo, 3, bytes32(uint256(0x11)));
        guard.allowFunction(address(safe), address(A), F6, false, r);
        r = new CuratorGuardPolicy.ParamRule[](1);
        r[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, 2 | TAIL, 0);
        guard.allowFunction(address(safe), address(A), F7, false, r);
        v = new bytes32[](1);
        v[0] = keccak256(T7);
        guard.addAllowedValues(address(safe), address(A), F7, 2 | TAIL, v);
        r = new CuratorGuardPolicy.ParamRule[](1);
        r[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 0, bytes32(uint256(1)));
        guard.allowFunction(address(safe), address(A), F8, false, r);
        // B, D, H
        guard.allowFunction(address(safe), address(B), F0, false, _noRules());
        guard.allowFunction(address(safe), D, F0, false, _noRules());
        guard.allowFunction(address(safe), address(H), F0, false, _noRules());
        vm.stopPrank();
    }

    function _fixtureHash() internal view returns (bytes32) {
        bytes32 _a = keccak256(abi.encode(address(safe), address(guard), address(A), address(B), address(C), address(H), D, E));
        bytes32 _b = keccak256(abi.encode(M, M2, address(multiSendCallOnly), address(U2), address(multiSend), CAN130, CAN141, CAN150));
        return keccak256(abi.encode(_a, _b, curator, keccak256(T4), keccak256(T5A), keccak256(T5B), keccak256(T7)));
    }
}
