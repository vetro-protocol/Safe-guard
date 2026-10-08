// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {Test} from "forge-std/Test.sol";

import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";

/// @title Round 8 (V2-100), the timelock side: a proposer or veto Safe whose fallback handler is the
///        timelock no longer makes scheduling / cancelling public; ordinary holders are unaffected.
contract CuratorGuardRound8TimelockRailTest is Test {
    ISafe internal proposerSafe;
    ISafe internal vetoSafe;
    address internal p2 = makeAddr("second-proposer");
    address internal attacker = makeAddr("attacker");
    CuratorGuardTimelock internal tl;
    bytes internal data = abi.encodeWithSignature("updateDelay(uint256)", 3 days);

    function setUp() public {
        vm.warp(1_700_000_000);
        proposerSafe = _plainSafe();
        vetoSafe = _plainSafe();
        address[] memory _p = new address[](2);
        _p[0] = address(proposerSafe);
        _p[1] = p2;
        address[] memory _c = new address[](1);
        _c[0] = address(vetoSafe);
        tl = new CuratorGuardTimelock(2 days, _p, _c);
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

    function test_forwarded_strangers_can_neither_schedule_nor_cancel() public {
        _handler(proposerSafe, address(tl));
        _handler(vetoSafe, address(tl));
        bytes memory _schedule = abi.encodeCall(TimelockController.schedule, (address(tl), 0, data, bytes32(0), bytes32(uint256(1)), 2 days));
        vm.prank(attacker);
        (bool _ok, bytes memory _ret) = address(proposerSafe).call(_schedule);
        assertFalse(_ok);
        assertEq(_ret, abi.encodeWithSelector(CuratorGuardTimelock.ForwardedCall.selector, address(proposerSafe)));
        // An honest operation by the second proposer cannot be cancelled by a stranger through the veto Safe.
        vm.prank(p2);
        tl.schedule(address(tl), 0, data, bytes32(0), bytes32(uint256(2)), 2 days);
        bytes32 _id = tl.hashOperation(address(tl), 0, data, bytes32(0), bytes32(uint256(2)));
        vm.prank(attacker);
        (_ok, _ret) = address(vetoSafe).call(abi.encodeCall(TimelockController.cancel, (_id)));
        assertFalse(_ok);
        assertEq(_ret, abi.encodeWithSelector(CuratorGuardTimelock.ForwardedCall.selector, address(vetoSafe)));
        assertTrue(tl.isOperationPending(_id));
        // Nor can a stranger make the proposer Safe drop its role (two proposers: the last-holder rail
        // alone would not stop it).
        vm.prank(attacker);
        (_ok, _ret) = address(proposerSafe).call(abi.encodeWithSignature("renounceRole(bytes32,address)", tl.PROPOSER_ROLE(), address(proposerSafe)));
        assertFalse(_ok);
        assertEq(_ret, abi.encodeWithSelector(CuratorGuardTimelock.ForwardedCall.selector, address(proposerSafe)));
        assertEq(tl.proposerCount(), 2);
        // The Safes repair their own handler (they are not guarded) and hold their roles again.
        _handler(vetoSafe, address(0));
        vm.prank(address(vetoSafe));
        tl.cancel(_id);
        assertFalse(tl.isOperation(_id));
    }

    function test_ordinary_holders_and_the_self_administration_are_unaffected() public {
        vm.prank(address(proposerSafe)); // a Safe, no handler
        tl.schedule(address(tl), 0, data, bytes32(0), bytes32(uint256(3)), 2 days);
        vm.prank(p2); // an EOA
        tl.schedule(address(tl), 0, abi.encodeWithSignature("updateDelay(uint256)", 4 days), bytes32(0), bytes32(uint256(4)), 2 days);
        vm.warp(block.timestamp + 2 days);
        vm.prank(attacker); // open executor; the timelock then calls itself (self-administration)
        tl.execute(address(tl), 0, data, bytes32(0), bytes32(uint256(3)));
        assertEq(tl.getMinDelay(), 3 days);
        bytes memory _grant = abi.encodeWithSignature("grantRole(bytes32,address)", tl.PROPOSER_ROLE(), makeAddr("third-proposer"));
        vm.prank(p2);
        tl.schedule(address(tl), 0, _grant, bytes32(0), bytes32(uint256(5)), 3 days);
        vm.warp(block.timestamp + 3 days);
        tl.execute(address(tl), 0, _grant, bytes32(0), bytes32(uint256(5)));
        assertEq(tl.proposerCount(), 3);
    }
}
