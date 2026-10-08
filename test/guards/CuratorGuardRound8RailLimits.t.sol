// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase} from "test/guards/CuratorGuardTestBase.sol";

/// @title Limits of the role-surface rail (variant V2), probed adversarially.
contract CuratorGuardRound8RailLimitsTest is CuratorGuardTestBase {
    ISafe internal councilSafe;

    function setUp() public override {
        super.setUp();
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = makeAddr("council-owner");
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        councilSafe = ISafe(address(_proxy));
        bytes32 _role = guard.COUNCIL_ROLE();
        vm.startPrank(vetro);
        guard.enforce(address(safe));
        guard.grantRole(_role, address(councilSafe));
        vm.stopPrank();
        vm.prank(address(councilSafe));
        (bool _ok, ) = address(councilSafe).call(abi.encodeWithSignature("setFallbackHandler(address)", address(guard)));
        assertTrue(_ok);
    }

    /// @dev 63/64 starvation: the probe (`getStorageAt` on the caller) is lenient, so a caller that
    ///      starves it would be let through. Sweep the gas given to the forwarded call: whenever the probe
    ///      runs out of gas, what is left (1/64) cannot pay for the role function's first SSTORE, so no
    ///      gas budget yields a state change.
    function test_gas_starvation_of_the_probe_never_yields_a_state_change() public {
        bytes memory _call = abi.encodeCall(guard.bypass, (address(safe), uint64(7 days)));
        uint256 _successes;
        vm.startPrank(attacker);
        for (uint256 g = 3_000; g <= 200_000; g += 137) {
            (bool _ok, ) = address(councilSafe).call{gas: g}(_call);
            if (_ok) ++_successes;
            assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Enforced), "never opened");
        }
        vm.stopPrank();
        assertEq(_successes, 0, "no gas budget gets a forwarded stranger through");
    }

    /// @dev With the `renounceRole` and `_checkRole` overrides (variant V2c) the library's own role
    ///      surface is closed to a forwarded stranger too: the Safe cannot be made to drop its role, and
    ///      (were the admin ever a Safe with the same mistake) no grant, revocation or admin transfer.
    function test_a_forwarded_stranger_cannot_make_the_safe_renounce_its_role() public {
        bytes32 _role = guard.COUNCIL_ROLE();
        vm.prank(attacker);
        (bool _ok, bytes memory _ret) = address(councilSafe).call(abi.encodeCall(guard.renounceRole, (_role, address(councilSafe))));
        assertFalse(_ok, "renounce refused");
        assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector);
        assertTrue(guard.hasRole(_role, address(councilSafe)), "role kept");
        vm.prank(attacker);
        (_ok, _ret) = address(councilSafe).call(abi.encodeCall(guard.grantRole, (_role, attacker)));
        assertFalse(_ok);
        assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector, "library surface: refused before the role lookup");
        // An ordinary holder renounces as before.
        vm.prank(council);
        guard.renounceRole(_role, council);
        assertFalse(guard.hasRole(_role, council));
    }
}
