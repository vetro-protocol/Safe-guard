// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuardHarness} from "test/guards/CuratorGuardTestBase.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";

/// @dev Review round 10, reviewer g10a (state machine and invariants): the repository harness plus two
///      read-only probes the reference-model invariants need: the RAW mode of a Safe (the views only
///      answer the effective one) and the transient slot of `(safe, path)` as the hooks key it.
contract G10aHarness is CuratorGuardHarness {
    constructor(uint48 adminDelay_, address admin_, address council_) CuratorGuardHarness(adminDelay_, admin_, council_) {}

    function rawMode(address safe_) external view returns (CuratorGuardPolicy.Mode) {
        return _policies[safe_].mode;
    }

    /// @dev The literal key of `CuratorGuard._stateKey` (`safe << 8 | path`), read with `tload`.
    function tslot(address safe_, uint8 path_) external view returns (bytes32 _value) {
        bytes32 _key = bytes32((uint256(uint160(safe_)) << 8) | path_);
        assembly ("memory-safe") {
            _value := tload(_key)
        }
    }

    function configDigest(address safe_) external view returns (bytes32 _digest, address _handler, address _unhooked) {
        return _configDigest(safe_);
    }
}
