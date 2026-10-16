// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

/// @title Round 16, reviewer g16b: the module path (real Safe v1.5.0, the guard in both slots) reads every clock
///        edge in the same second as the owner path: an admin window's last second and first closed second, and a
///        module-bound approval's inclusive expiry, probed on both paths at the same `block.timestamp`.
contract G16b_ModulePathEdgesTest is SafeTxHelper {
    CuratorGuard internal guard;
    MockProtocol internal protocol;
    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal module = makeAddr("module");
    address internal curator;

    function setUp() public {
        vm.warp(1_700_000_000);
        (curator, signerPk) = makeAddrAndKey("curator");
        Safe150 _singleton = new Safe150();
        SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        safe = ISafe(address(_proxy));
        guard = new CuratorGuardHarness(0, vetro, council);
        CuratorGuardHarness(address(guard)).seedSafe(address(safe));
        protocol = new MockProtocol();
        vm.startPrank(address(safe));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        safe.enableModule(module);
        vm.stopPrank();
        vm.startPrank(vetro);
        guard.setModuleAllowed(address(safe), module, true);
        guard.enforce(address(safe));
        vm.stopPrank();
    }

    function _settle() internal pure returns (bytes memory) {
        return abi.encodeCall(MockProtocol.settleDeposit, (1));
    }

    function _module() internal returns (bool _ok) {
        vm.prank(module);
        _ok = safe.execTransactionFromModule(address(protocol), 0, _settle(), Operation.Call);
    }

    /// @dev An admin window opened at t is open through t + d - 1 on both paths and closed (Lockdown) at t + d on both.
    function test_an_admin_window_closes_in_the_same_second_on_both_paths() public {
        vm.prank(vetro);
        guard.bypass(address(safe), 1 hours);
        uint256 _t = block.timestamp;
        vm.warp(_t + 1 hours - 1);
        assertTrue(_module(), "module path: inert admin window, last second");
        assertTrue(_execSafeTx(address(protocol), 0, _settle(), Operation.Call), "owner path: same second");
        vm.warp(_t + 1 hours);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown), "closed at t + d");
        vm.prank(module);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        safe.execTransactionFromModule(address(protocol), 0, _settle(), Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, _settle(), Operation.Call);
    }

    /// @dev A council approval bound to the module (ttl one hour) is usable through t + ttl inclusive and refused at
    ///      t + ttl + 1; the owner-path twin of the same payload behaves alike at the same seconds.
    function test_a_module_bound_approval_expires_in_the_same_second_as_an_owner_bound_one() public {
        vm.startPrank(council);
        guard.approveTransaction(address(safe), module, address(protocol), 0, _settle(), Operation.Call, 1 hours);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _settle(), Operation.Call, 1 hours);
        vm.stopPrank();
        uint256 _t = block.timestamp;
        uint256 _snap = vm.snapshotState();
        vm.warp(_t + 1 hours);
        assertTrue(_module(), "module path: approval usable at t + ttl (inclusive)");
        assertTrue(_execSafeTx(address(protocol), 0, _settle(), Operation.Call), "owner path: same second");
        vm.revertToState(_snap);
        vm.warp(_t + 1 hours + 1);
        vm.prank(module);
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.settleDeposit.selector)
        );
        safe.execTransactionFromModule(address(protocol), 0, _settle(), Operation.Call);
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.settleDeposit.selector)
        );
        _execSafeTx(address(protocol), 0, _settle(), Operation.Call);
    }
}
