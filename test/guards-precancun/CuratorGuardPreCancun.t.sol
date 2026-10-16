// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test} from "forge-std/Test.sol";

/// @dev Trivial control contract: deploys on any EVM.
contract Plain {
    uint256 public x = 1;
}

/// @title The guard refuses to deploy on a pre-Cancun EVM (v2 robustness item: the constructor's EIP-1153 probe)
/// @notice Runs under `FOUNDRY_PROFILE=precancun` (EVM version Shanghai, compiled without any Cancun
///         opcode). The guard's creation code is the Cancun build the `guards` profile produced
///         (`out-guards/`): its constructor probes EIP-1153 with a `tload` / `tstore` pair, so the raw
///         `create` must fail here while the same bytes deploy under the `guards` profile
///         (`test_constructor_carries_the_transient_storage_probe_and_deploys_on_cancun`). Without the
///         probe a guard deployed on such a chain would brick the first Safe that installs it: every
///         hook, `setGuard(0)` included, would hit the invalid opcode.
contract CuratorGuardPreCancunTest is Test {
    function test_guard_deployment_fails_on_a_shanghai_evm_while_a_plain_contract_deploys() public {
        // A Cancun profile that compiled this directory would deploy the guard: the check is only
        // meaningful without transient storage (the default profile compiles `test/guards/` only).
        if (_hasTransientStorage()) {
            vm.skip(true);
            return;
        }
        new Plain(); // the EVM itself works
        string memory _artifact = "out-guards/CuratorGuard.sol/CuratorGuard.json";
        assertTrue(vm.isFile(_artifact), "run `forge build` first (this test deploys that build)");
        string memory _json = vm.readFile(_artifact);
        bytes memory _creation = vm.parseJsonBytes(_json, ".bytecode.object");
        assertGt(_creation.length, 20_000, "creation code read from the guards build");
        assertEq(vm.parseJsonString(_json, ".metadata.settings.evmVersion"), "cancun", "a Cancun build of the guard");
        bytes memory _init = abi.encodePacked(_creation, abi.encode(uint48(0), address(0xA11CE), address(0)));
        uint256 _gasBefore = gasleft();
        address _deployed;
        uint256 _returnDataSize;
        assembly {
            _deployed := create(0, add(_init, 0x20), mload(_init))
            _returnDataSize := returndatasize()
        }
        uint256 _gasUsed = _gasBefore - gasleft();
        assertEq(_deployed, address(0), "a pre-Cancun EVM must refuse the guard at deployment");
        // Attribution: an invalid opcode halts without return data and burns the whole forwarded gas
        // (63/64); a constructor `revert` would leave data and refund. The exact opcode shape (one
        // `tload`, one `tstore`, no `mcopy`) is pinned by the census test in the guards profile.
        assertEq(_returnDataSize, 0, "an invalid opcode leaves no revert data");
        assertGt(_gasUsed, (_gasBefore / 64) * 60, "an invalid opcode burns the forwarded gas");
    }

    /// @dev `create` of `PUSH0 TLOAD POP STOP`: deploys (an empty account) only where EIP-1153 exists.
    function _hasTransientStorage() internal returns (bool) {
        bytes memory _probe = hex"5f5c5000";
        address _a;
        assembly {
            _a := create(0, add(_probe, 0x20), mload(_probe))
        }
        return _a != address(0);
    }
}
