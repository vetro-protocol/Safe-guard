// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test} from "forge-std/Test.sol";

import {G9fHarness} from "test/guards/G9fBase.sol";

interface IProxyFactory {
    function proxyCreationCode() external pure returns (bytes memory);
}

/// @title Round 9 (g9f, fork): the nine canonical Safe code hashes the guard fixes at deployment,
///        against Ethereum mainnet. Requires `ETHEREUM_FORK_NODE_URL`.
/// @dev The repository pins the three `MultiSendCallOnly` hashes against the safe-deployments package
///      and exercises the live curator Safe (a v1.4.1 proxy + L1 singleton) on the fork; the other
///      seven hashes (both proxies of v1.3.0 / v1.5.0, the L2 singletons, the v1.3.0 / v1.5.0 L1
///      singletons) were pinned by no test. Here: every canonical singleton's live code hashes to a
///      pinned value, and a proxy created from each canonical factory's `proxyCreationCode()` hashes to
///      a pinned value (the proxy runtime does not depend on the singleton it is created with).
contract CuratorGuardG9fSafeCodehashesE2E_EthereumTest is Test {
    address internal constant CURATOR_SAFE = 0x1b534a8543212F5957168D83311A41E0Ea1cfe48;

    function setUp() public {
        uint256 _blockNumber = vm.envOr("ETHEREUM_FORK_BLOCK_NUMBER", uint256(0));
        if (_blockNumber > 0) vm.createSelectFork("ethereum", _blockNumber);
        else vm.createSelectFork("ethereum");
        assertEq(block.chainid, 1, "ETHEREUM_FORK_NODE_URL is not Ethereum mainnet");
    }

    function test_every_canonical_singleton_and_proxy_hash_is_pinned_on_mainnet() public {
        G9fHarness _h = new G9fHarness(0, makeAddr("admin"), address(0));
        address[6] memory _singletons = [
            0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552, // GnosisSafe 1.3.0
            0x3E5c63644E683549055b9Be8653de26E0B4CD36E, // GnosisSafeL2 1.3.0
            0x41675C099F32341bf84BFc5382aF534df5C7461a, // Safe 1.4.1
            0x29fcB43b46531BcA003ddC8FCB67FFE91900C762, // SafeL2 1.4.1
            0xFf51A5898e281Db6DfC7855790607438dF2ca44b, // Safe 1.5.0
            0xEdd160fEBBD92E350D4D398fb636302fccd67C7e // SafeL2 1.5.0
        ];
        string[6] memory _files = [
            "v1.3.0/gnosis_safe.json",
            "v1.3.0/gnosis_safe_l2.json",
            "v1.4.1/safe.json",
            "v1.4.1/safe_l2.json",
            "v1.5.0/safe.json",
            "v1.5.0/safe_l2.json"
        ];
        bytes32[6] memory _seen;
        for (uint256 i; i < 6; ++i) {
            assertGt(_singletons[i].code.length, 0, string.concat("deployed: ", _files[i]));
            bytes32 _live = _singletons[i].codehash;
            string memory _json = vm.readFile(string.concat("node_modules/@safe-global/safe-deployments/dist/assets/", _files[i]));
            assertEq(_live, vm.parseJsonBytes32(_json, ".deployments.canonical.codeHash"), string.concat("package == chain: ", _files[i]));
            assertTrue(_h.isSafeCodehash(_live), string.concat("pinned: ", _files[i]));
            for (uint256 j; j < i; ++j) assertTrue(_seen[j] != _live, "six distinct singleton hashes");
            _seen[i] = _live;
        }
        address[3] memory _factories = [
            0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2, // GnosisSafeProxyFactory 1.3.0
            0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67, // SafeProxyFactory 1.4.1
            0x14F2982D601c9458F93bd70B218933A6f8165e7b // SafeProxyFactory 1.5.0
        ];
        bytes32[3] memory _proxyHashes;
        for (uint256 i; i < 3; ++i) {
            assertGt(_factories[i].code.length, 0, "factory deployed");
            bytes memory _init = abi.encodePacked(IProxyFactory(_factories[i]).proxyCreationCode(), abi.encode(_singletons[2 * i]));
            address _proxy;
            assembly {
                _proxy := create(0, add(_init, 0x20), mload(_init))
            }
            assertTrue(_proxy != address(0), "proxy deployed from the canonical creation code");
            _proxyHashes[i] = _proxy.codehash;
            assertTrue(_h.isSafeCodehash(_proxyHashes[i]), "proxy hash pinned");
            for (uint256 j; j < i; ++j) assertTrue(_proxyHashes[j] != _proxyHashes[i], "three distinct proxy hashes");
            for (uint256 j; j < 6; ++j) assertTrue(_seen[j] != _proxyHashes[i], "a proxy is never a singleton");
            // The runtime does not depend on the singleton argument.
            _init = abi.encodePacked(IProxyFactory(_factories[i]).proxyCreationCode(), abi.encode(_singletons[2 * i + 1]));
            address _proxy2;
            assembly {
                _proxy2 := create(0, add(_init, 0x20), mload(_init))
            }
            assertEq(_proxy2.codehash, _proxyHashes[i], "same runtime for the L2 singleton");
        }
        // The live curator Safe is a v1.4.1 factory proxy in front of the v1.4.1 L1 singleton.
        assertEq(CURATOR_SAFE.codehash, _proxyHashes[1], "the curator Safe's proxy code");
        (, bytes memory _master) = CURATOR_SAFE.staticcall(abi.encodeWithSelector(0xa619486e));
        assertEq(abi.decode(_master, (address)), _singletons[2], "the curator Safe's singleton");
    }
}
