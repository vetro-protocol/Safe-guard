// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuardHarness} from "test/guards/CuratorGuardTestBase.sol";

/// @dev Review round 9, reviewer g9f: the repository harness plus two read-only probes the fuzz and
///      invariant suites need: the configuration digest as the hooks compute it, and the Safe
///      code-hash allowlist (no getter on the guard: the set is fixed at deployment).
contract G9fHarness is CuratorGuardHarness {
    constructor(uint48 adminDelay_, address admin_, address council_) CuratorGuardHarness(adminDelay_, admin_, council_) {}

    function configDigest(address safe_) external view returns (bytes32 _digest, address _handler, address _unhooked) {
        return _configDigest(safe_);
    }

    function isSafeCodehash(bytes32 codehash_) external view returns (bool) {
        return _safeCodehashes[codehash_];
    }
}

/// @dev Accepts any call (a venue whose ABI the policy never has to match).
contract G9fSink {
    uint256 public calls;

    fallback() external payable {
        ++calls;
    }

    receive() external payable {
        ++calls;
    }
}
