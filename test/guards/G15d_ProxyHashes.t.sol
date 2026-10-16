// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test} from "forge-std/Test.sol";

import {G9fHarness} from "test/guards/G9fBase.sol";

/// @title Review g15d: the three seeded Safe PROXY code hashes pinned offline, like the six singleton hashes
///        (`G9f_Mutation.test_seeded_safe_singleton_hashes_match_safe_deployments`).
/// @dev   `safe-deployments` carries no proxy bytecode (a proxy is what the canonical factory creates), so the
///        round-9 pin of the proxy hashes is the fork suite `G9f_SafeCodehashes.e2e` only: a one-nibble error in
///        the v1.3.0 `GnosisSafeProxy` hash (mutant g9f-P68) survives the unit suite. The vectors under
///        `test/guards/vectors/safe-proxy-v1{30,41,50}.creation.hex` are each canonical factory's
///        `proxyCreationCode()` read from mainnet at block 26,164,162 (GnosisSafeProxyFactory 1.3.0
///        0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2, SafeProxyFactory 1.4.1 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67,
///        SafeProxyFactory 1.5.0 0x14F2982D601c9458F93bd70B218933A6f8165e7b, the addresses `safe-deployments`
///        lists as canonical); a proxy deployed from each here has the runtime every canonical proxy has.
contract G15dProxyHashesTest is Test {
    function test_seeded_safe_proxy_hashes_match_the_canonical_factories() public {
        G9fHarness _h = new G9fHarness(0, makeAddr("vetro"), makeAddr("council"));
        string[3] memory _files = ["safe-proxy-v130.creation.hex", "safe-proxy-v141.creation.hex", "safe-proxy-v150.creation.hex"];
        for (uint256 i; i < 3; ++i) {
            bytes memory _creation = vm.parseBytes(vm.readFile(string.concat("test/guards/vectors/", _files[i])));
            assertGt(_creation.length, 100, "vector read");
            // the proxy constructor takes the singleton (any non-zero address) as its one argument
            bytes memory _init = abi.encodePacked(_creation, abi.encode(address(0x1234)));
            address _proxy;
            assembly ("memory-safe") {
                _proxy := create(0, add(_init, 0x20), mload(_init))
            }
            assertTrue(_proxy != address(0), "proxy deployed");
            assertTrue(_h.isSafeCodehash(_proxy.codehash), string.concat("proxy hash pinned: ", _files[i]));
        }
        assertFalse(_h.isSafeCodehash(keccak256("")));
    }
}
