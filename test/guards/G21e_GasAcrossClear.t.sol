// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {console2} from "forge-std/console2.sol";
import {Test} from "forge-std/Test.sol";
import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase} from "test/guards/CuratorGuardTestBase.sol";

/// @dev A slot that is set in one transaction and cleared in another, with `gasleft()` sampled by the PARENT frame
///      before and after the child call that clears it: on an EVM where a clear refills gas visible to `GAS`, the
///      parent sees more gas after the call than before.
contract G21eClearer {
    uint256 public slot;

    function set() external {
        slot = 1;
    }

    function clear() external {
        slot = 0;
    }
}

contract G21eParent {
    function measure(G21eClearer c_) external returns (uint256 _before, uint256 _after) {
        _before = gasleft();
        c_.clear();
        _after = gasleft();
    }
}

/// @title G21e: `gasleft()` across a child call that clears storage, and Safe's `execTransaction` on such a call.
contract G21e_GasAcrossClearTest is CuratorGuardTestBase {
    G21eClearer internal clearer;
    G21eParent internal parent;

    function setUp() public override {
        super.setUp();
        clearer = new G21eClearer();
        parent = new G21eParent();
        clearer.set();
    }

    function test_Q1_gasleft_across_a_child_call_that_clears_a_slot() public {
        (uint256 _b, uint256 _a) = parent.measure(clearer);
        console2.log("Q1 parent gasleft before the clearing call:", _b);
        console2.log("Q1 parent gasleft after the clearing call: ", _a);
        if (_a > _b) console2.log("Q1 GAS ROSE across the child call by", _a - _b);
        else console2.log("Q1 gas consumed by the child call:", _b - _a);
    }

    /// Safe v1.4.1: `gasUsed = gasUsed.sub(gasleft())` right after the inner call (GnosisSafeMath, a bare require).
    function test_Q2_safe_v141_execTransaction_of_a_storage_clearing_call() public {
        _enforce();
        _allow(address(clearer), G21eClearer.clear.selector);
        bool _ok = _execSafeTx(address(clearer), 0, abi.encodeCall(G21eClearer.clear, ()), Operation.Call);
        console2.log("Q2 v1.4.1 execTransaction of a clearing call returned:", _ok);
        assertTrue(_ok, "v1.4.1 execTransaction survives a clearing inner call");
    }

    /// Safe v1.5.0: the same accounting on the v1.5.0 build (an admin Safe, no guard in the way).
    function test_Q3_safe_v150_execTransaction_of_a_storage_clearing_call() public {
        Safe150 _singleton = new Safe150();
        SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        safe = ISafe(address(_proxy));
        bool _ok = _execSafeTx(address(clearer), 0, abi.encodeCall(G21eClearer.clear, ()), Operation.Call);
        console2.log("Q3 v1.5.0 execTransaction of a clearing call returned:", _ok);
        assertTrue(_ok, "v1.5.0 execTransaction survives a clearing inner call");
    }
}
