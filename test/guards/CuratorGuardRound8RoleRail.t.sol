// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";
import {CompatibilityFallbackHandler} from "safe-contracts-v1.4.1/contracts/handler/CompatibilityFallbackHandler.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @title Round 8 (V2-100): no role for a caller that is a
///        Safe with this guard in its fallback-handler slot.
contract CuratorGuardRound8RoleRailTest is CuratorGuardTestBase {
    ISafe internal councilSafe;
    ISafe internal guardianSafe;

    function setUp() public override {
        super.setUp();
        councilSafe = _plainSafe();
        guardianSafe = _plainSafe();
        bytes32 _role = guard.COUNCIL_ROLE();
        vm.startPrank(vetro);
        guard.enforce(address(safe));
        guard.grantRole(_role, address(councilSafe));
        guard.setDeploymentGuardian(address(guardianSafe), true);
        vm.stopPrank();
    }

    function _plainSafe() internal returns (ISafe) {
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = makeAddr("some-owner");
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        return ISafe(address(_proxy));
    }

    function _handler(ISafe safe_, address handler_) internal {
        vm.prank(address(safe_));
        (bool _ok, ) = address(safe_).call(abi.encodeWithSignature("setFallbackHandler(address)", handler_));
        assertTrue(_ok);
    }

    function test_forwarded_strangers_get_no_role() public {
        _handler(councilSafe, address(guard));
        _handler(guardianSafe, address(guard));
        bytes[6] memory _calls = [
            abi.encodeCall(guard.bypass, (address(safe), uint64(7 days))),
            abi.encodeCall(guard.enforce, (address(safe))),
            abi.encodeCall(guard.approveTransaction, (address(safe), address(0), address(protocol), 0, hex"12345678", Operation.Call, uint64(1 days))),
            abi.encodeCall(guard.setGuardian, (address(safe), attacker, true)),
            abi.encodeCall(guard.setDeploymentGuardian, (attacker, true)),
            abi.encodeCall(guard.lockdown, (address(safe)))
        ];
        vm.startPrank(attacker);
        for (uint256 i; i < _calls.length; ++i) {
            for (uint256 pad; pad < 33; pad += 4) {
                (bool _ok, bytes memory _ret) = address(councilSafe).call(abi.encodePacked(_calls[i], new bytes(pad)));
                assertFalse(_ok, "council lane closed to a forwarded stranger");
                assertEq(bytes4(_ret), CuratorGuardPolicy.Unauthorized.selector);
            }
        }
        (bool _ok2, bytes memory _ret2) = address(guardianSafe).call(abi.encodeCall(guard.lockdownAndRevoke, (address(safe))));
        assertFalse(_ok2, "guardian seat closed to a forwarded stranger");
        assertEq(bytes4(_ret2), CuratorGuardPolicy.Unauthorized.selector);
        (_ok2, ) = address(guardianSafe).call(abi.encodeCall(guard.setUnwrapperCodehash, (_H().codehashV141(), false)));
        assertFalse(_ok2);
        vm.stopPrank();
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Enforced), "nothing moved");
        // The council Safe itself is refused too while its handler is the guard (its own genuine call is
        // indistinguishable from a forwarded one); it repairs its handler with a Safe transaction of its
        // own (it is not guarded) and is the council again.
        vm.prank(address(councilSafe));
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.lockdown(address(safe));
        _handler(councilSafe, address(0));
        vm.prank(address(councilSafe));
        guard.lockdown(address(safe));
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
    }

    /// @dev Every ordinary role holder is unaffected: EOAs, a Safe with no handler, a Safe with the
    ///      canonical handler, a `TimelockController` admin (answers no `getStorageAt`).
    function test_ordinary_role_holders_are_unaffected() public {
        vm.prank(council); // an EOA council
        guard.lockdown(address(safe));
        vm.prank(address(councilSafe)); // a Safe, no handler
        guard.enforce(address(safe));
        _handler(councilSafe, address(new CompatibilityFallbackHandler()));
        vm.prank(address(councilSafe)); // a Safe, canonical handler
        guard.bypass(address(safe), 1 hours);
        vm.prank(address(guardianSafe));
        guard.lockdown(address(safe));

        address[] memory _p = new address[](2);
        _p[0] = makeAddr("p1");
        _p[1] = makeAddr("p2");
        address[] memory _c = new address[](1);
        _c[0] = makeAddr("veto");
        CuratorGuardTimelock _tl = new CuratorGuardTimelock(2 days, _p, _c);
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(address(_tl));
        vm.warp(block.timestamp + 2 days);
        vm.prank(address(_tl));
        guard.acceptDefaultAdminTransfer();
        vm.prank(address(_tl)); // the timelock admin
        guard.allowFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules());
        (bool _allowed, , ) = guard.functionPermission(address(safe), address(protocol), MockProtocol.settleDeposit.selector);
        assertTrue(_allowed);
    }
}
