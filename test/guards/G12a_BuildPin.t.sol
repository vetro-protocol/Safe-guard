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
    uint256 internal constant GUARD_RUNTIME_BYTES = 23_240;
    uint256 internal constant TIMELOCK_RUNTIME_BYTES = 8_195;
    // keccak256 of the runtime code without its CBOR tail: CuratorGuard (sha256 2ef656ec...) and
    // CuratorGuardTimelock (sha256 90bb0171...) as built from the round-13 follow-up commit (G9a-1, G9a-3/G9c-3
    // and MIN_DELAY_FLOOR = 1 days applied on top of 830824e) with OpenZeppelin contracts 5.2.0, solc 0.8.25,
    // 10 runs, cancun. The previous pins (830824e): 23,224 / 8,191 bytes, keccak b3ac8167... / 745ff0ea...
    bytes32 internal constant GUARD_STRIPPED_KECCAK = 0xc8e0a9082376e985eec95d4185d178c1a667832b0990852bef052ca40d8d70a6;
    bytes32 internal constant TIMELOCK_STRIPPED_KECCAK = 0xb7790f427d7dfc79e8c3b417a283f7baf39f498403f5a33cdd68e40aab8528aa;

    function test_guard_runtime_is_the_reviewed_build() public view {
        bytes memory _code = vm.getDeployedCode("CuratorGuard.sol:CuratorGuard");
        assertEq(_code.length, GUARD_RUNTIME_BYTES, "CuratorGuard runtime size moved");
        assertEq(
            keccak256(_stripMetadata(_code)),
            GUARD_STRIPPED_KECCAK,
            "CuratorGuard runtime (metadata stripped) is not the reviewed build"
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
