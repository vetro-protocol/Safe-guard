// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test} from "forge-std/Test.sol";

/// Review g12a (the operator and the supply chain): the runtime bytecode the toolchain produces for the two
/// deployed contracts is pinned to the reviewed build. The CBOR metadata tail is stripped, so a comment-only
/// change passes while a change of code, of a compiler setting or of a library the contracts inherit
/// (the OpenZeppelin contracts package locked in package-lock.json) fails. CI's hardhat/foundry parity step compares the
/// two toolchains with each other, never with the reviewed build, and the deploy script deploys whatever the
/// local `node_modules` compiles to: a dependency bump merged on the default branch would otherwise move the
/// audited bytecode silently. Re-pin the two constants only together with the review of the change that moved
/// them (the sizes are the ones docs section 10 and the README quote).
contract G12a_BuildPin is Test {
    uint256 internal constant GUARD_RUNTIME_BYTES = 23_267;
    uint256 internal constant TIMELOCK_RUNTIME_BYTES = 8_204;
    // keccak256 of the runtime code without its CBOR tail: CuratorGuard (sha256 e0366b24...; 7b7cc641... before the
    // zero-target approval rail of G17a-3, +18 B, applied at the owner's decision after round 21) and
    // CuratorGuardTimelock (sha256 a43ecad6...) as built with the masked handler-word rails (G16d-1a/1b, +9 B each,
    // applied after round 18) on top of the round-13 follow-up (G9a-1, G9a-3/G9c-3 and MIN_DELAY_FLOOR = 1 days
    // applied on top of 830824e) with OpenZeppelin contracts 5.2.0, solc 0.8.25, 10 runs, cancun. The previous
    // pins: d878077 (the round-13 follow-up build, rounds 14-18): 23,240 / 8,195 bytes, keccak c8e0a908... /
    // b7790f42...; 830824e: 23,224 / 8,191 bytes, keccak b3ac8167... / 745ff0ea...
    bytes32 internal constant GUARD_STRIPPED_KECCAK = 0x3bfe33c8e8c7a8e4edbe454efb7efaef22182ba362b8b824ccc0610c763bea8d;
    bytes32 internal constant TIMELOCK_STRIPPED_KECCAK = 0x8a69e72c4ff2fbc0189b1ff3f6a7e74c239bcc3c3394a3fe158e952a02da786c;

    function test_guard_runtime_is_the_reviewed_build() public view {
        bytes memory _code = vm.getDeployedCode("CuratorGuard.sol:CuratorGuard");
        assertEq(_code.length, GUARD_RUNTIME_BYTES, "CuratorGuard runtime size moved");
        assertEq(
            keccak256(_stripMetadata(_code)),
            GUARD_STRIPPED_KECCAK,
            "CuratorGuard runtime (metadata stripped) is not the reviewed build"
        );
    }

    /// The settlement-deadline helper (`contracts/helpers/SettlementDeadline.sol`) is deployed only at the
    /// owner's decision, but its runtime is pinned here too so the audit prompt can name one hash for it and a
    /// dependency bump cannot move it unnoticed (review G16g-3).
    function test_settlement_deadline_helper_runtime_is_the_reviewed_build() public view {
        bytes memory _code = vm.getDeployedCode("SettlementDeadline.sol:SettlementDeadline");
        assertEq(_code.length, 177, "SettlementDeadline runtime size moved");
        assertEq(
            keccak256(_stripMetadata(_code)),
            0x15af8250614030304774190ed0be0d8c81749013f26a5157cf600a390d5396fd,
            "SettlementDeadline runtime (metadata stripped) is not the reviewed build"
        );
    }

    function test_timelock_runtime_is_the_reviewed_build() public view {
        bytes memory _code = vm.getDeployedCode("CuratorGuardTimelock.sol:CuratorGuardTimelock");
        assertEq(_code.length, TIMELOCK_RUNTIME_BYTES, "CuratorGuardTimelock runtime size moved");
        assertEq(
            keccak256(_stripMetadata(_code)),
            TIMELOCK_STRIPPED_KECCAK,
            "CuratorGuardTimelock runtime (metadata stripped) is not the reviewed build"
        );
    }

    /// Runtime code without its CBOR metadata tail: the last two bytes give the tail's length.
    function _stripMetadata(bytes memory _code) internal pure returns (bytes memory _out) {
        uint256 _n = _code.length;
        uint256 _tail = ((uint256(uint8(_code[_n - 2])) << 8) | uint256(uint8(_code[_n - 1]))) + 2;
        _out = new bytes(_n - _tail);
        for (uint256 _i; _i < _out.length; ++_i) _out[_i] = _code[_i];
    }
}
