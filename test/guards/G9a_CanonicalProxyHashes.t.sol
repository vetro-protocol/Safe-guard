// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Test.sol";

/// @title G9a (round 9): the three proxy runtime hashes the guard pins (`_safeCodehashes`) are the
///        runtime code of a proxy created from the CANONICAL factories' `proxyCreationCode()` on
///        mainnet (safe-deployments carries no proxy code hash, and no unit test pins these literals).
///        Fork test: skipped without `ETHEREUM_FORK_NODE_URL`; forks at `ETHEREUM_FORK_BLOCK_NUMBER`
///        when set (the CI pin), at the head otherwise, like every other fork suite (review P1c-1).
contract G9a_CanonicalProxyHashesTest is Test {
    function _deployFrom(address factory_, address singleton_) internal returns (address _proxy) {
        (bool _ok, bytes memory _ret) = factory_.staticcall(abi.encodeWithSignature("proxyCreationCode()"));
        assertTrue(_ok, "factory answers proxyCreationCode()");
        bytes memory _code = abi.decode(_ret, (bytes));
        bytes memory _init = abi.encodePacked(_code, abi.encode(singleton_));
        assembly ("memory-safe") {
            _proxy := create(0, add(_init, 0x20), mload(_init))
        }
        assertTrue(_proxy != address(0), "proxy deployed");
    }

    function test_fork_canonical_proxy_runtime_hashes_match_the_pinned_literals() public {
        if (bytes(vm.envOr("ETHEREUM_FORK_NODE_URL", string(""))).length == 0) {
            vm.skip(true); // reported as skipped, never as a silent pass
            return;
        }
        uint256 _blockNumber = vm.envOr("ETHEREUM_FORK_BLOCK_NUMBER", uint256(0));
        if (_blockNumber > 0) vm.createSelectFork("ethereum", _blockNumber);
        else vm.createSelectFork("ethereum");
        assertEq(block.chainid, 1, "ETHEREUM_FORK_NODE_URL is not Ethereum mainnet");
        // safe-deployments canonical factories and singletons.
        assertEq(
            _deployFrom(0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2, 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552).codehash,
            0xb89c1b3bdf2cf8827818646bce9a8f6e372885f8c55e5c07acbd307cb133b000,
            "GnosisSafeProxy 1.3.0"
        );
        assertEq(
            _deployFrom(0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67, 0x41675C099F32341bf84BFc5382aF534df5C7461a).codehash,
            0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c,
            "SafeProxy 1.4.1"
        );
        assertEq(
            _deployFrom(0x14F2982D601c9458F93bd70B218933A6f8165e7b, 0xFf51A5898e281Db6DfC7855790607438dF2ca44b).codehash,
            0x4e381985ca68b3e5d27b4425fa581c19cf33146d3f887a3cfca96f55528ea46f,
            "SafeProxy 1.5.0"
        );
        // And the live curator Safe is a 1.4.1 proxy in front of the 1.4.1 singleton.
        assertEq(
            0x1b534a8543212F5957168D83311A41E0Ea1cfe48.codehash,
            0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c,
            "curator Safe proxy"
        );
    }
}
