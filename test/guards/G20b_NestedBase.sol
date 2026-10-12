// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Test.sol";

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";
import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";

/// @dev Review round 20, reviewer g20b: round 19's contract-level fact (G19g-1 / G19c-2) as a property. A nested
///      `executeBefore(d1, executeBefore(d2, call))` is a delegatecall to self at every level, so `msg.sender` is the
///      outer caller at every level: the forwarded-caller rail (`_refuseForwarded`, masked to 160 bits since G16d-1)
///      runs FIRST at the outer level and again at every inner level and inside the inner call's own role check,
///      each time on the same caller's handler slot; then the deadlines are checked outermost first; then `call`
///      runs with the CALLER's role (never with the guard's or the timelock's). Hence the nested form executes
///      `call` as the admin exactly when the caller IS the admin, is not forwarded, and both deadlines are
///      unexpired; the refusal names the first rail that fires (`Unauthorized`, then `DeadlinePassed(d1)`, then
///      `DeadlinePassed(d2)`, then the inner call's own error), and nothing observable moves on a refusal.
///
///      Fixture: the PRODUCTION guard (no harness: `executeBefore` and `bypass` read nothing of the Safe's
///      configuration), real Safe v1.4.1 or v1.5.0 proxies from `lib/` (one singleton per fixture, `_mk` picks
///      the build): `adm` is the guard's admin (its handler word is the symbolic input of every check), `cR` holds
///      the council seat, `s` is the guarded Safe the inner call acts on (unconfigured: `Lockdown`, no cooldown
///      running). The inner call is `bypass(s, 180 days)`: the ADMIN's cap (the council's is 7 days), the
///      custody-relevant effect of G19g-1 (the guard inert for the Safe for half a year). Every address is a literal.
abstract contract G20bNestedBase is Test {
    CuratorGuard internal guard;
    ISafe internal adm; // the guard's admin
    ISafe internal cR; // council seat
    ISafe internal s; // the guarded Safe
    address internal singleton;

    address internal constant COUNCIL = address(0xC0C11); // the constructor's council (an EOA, unused)
    address internal constant STRANGER = address(0x5712A);
    address internal constant OWNER = address(0x0B0B);
    uint256 internal constant T0 = 1_800_000_000;
    uint48 internal constant ADMIN_DELAY = 1 days;
    uint64 internal constant DUR = 180 days; // MAX_ADMIN_BYPASS
    bytes32 internal constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    /// @dev `getStorageAt(uint256,uint256)`: the rail's probe.
    bytes4 internal constant GET_STORAGE_AT = 0x5624b25b;

    function _mk(address owner_) internal virtual returns (ISafe);

    function _owner() internal virtual returns (address) {
        return OWNER;
    }

    function setUp() public virtual {
        vm.warp(T0);
        adm = _mk(_owner());
        cR = _mk(_owner());
        s = _mk(_owner());
        guard = new CuratorGuard(ADMIN_DELAY, address(adm), COUNCIL);
        vm.prank(address(s));
        s.setGuard(address(guard));
        bytes32 _C = guard.COUNCIL_ROLE(); // read first: a prank is spent by the next call, a view included
        vm.prank(address(adm));
        guard.grantRole(_C, address(cR));
    }

    function _safe141(address owner_) internal returns (ISafe _safe) {
        if (singleton == address(0)) singleton = address(new Safe());
        SafeProxy _proxy = new SafeProxy(singleton);
        address[] memory _owners = new address[](1);
        _owners[0] = owner_;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        _safe = ISafe(address(_proxy));
    }

    function _safe150(address owner_) internal returns (ISafe _safe) {
        if (singleton == address(0)) singleton = address(new Safe150());
        SafeProxy150 _proxy = new SafeProxy150(singleton);
        address[] memory _owners = new address[](1);
        _owners[0] = owner_;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        _safe = ISafe(address(_proxy));
    }

    /*//////////////////////////////////////////////////////////////
                          THE WORD AND THE CALLS
    //////////////////////////////////////////////////////////////*/

    /// @dev What the EVM forwards to: the low 160 bits of the word.
    function _low(bytes32 w_) internal pure returns (address) {
        return address(uint160(uint256(w_)));
    }

    function _inner() internal view returns (bytes memory) {
        return abi.encodeCall(guard.bypass, (address(s), DUR));
    }

    function _wrap(uint64 d_, bytes memory c_) internal view returns (bytes memory) {
        return abi.encodeCall(guard.executeBefore, (d_, c_));
    }

    function _single(uint64 d_) internal view returns (bytes memory) {
        return _wrap(d_, _inner());
    }

    function _nested2(uint64 d1_, uint64 d2_) internal view returns (bytes memory) {
        return _wrap(d1_, _wrap(d2_, _inner()));
    }

    function _nested3(uint64 d1_, uint64 d2_, uint64 d3_) internal view returns (bytes memory) {
        return _wrap(d1_, _wrap(d2_, _wrap(d3_, _inner())));
    }

    /*//////////////////////////////////////////////////////////////
                      EVERYTHING AN OBSERVER CAN READ
    //////////////////////////////////////////////////////////////*/

    function _digest() internal view returns (bytes32) {
        (uint64 _u, bool _c) = guard.bypassWindow(address(s));
        return keccak256(abi.encode(guard.mode(address(s)), _u, _c, guard.lockedAt(address(s)), guard.approvalEpoch(address(s)), guard.hasRole(guard.COUNCIL_ROLE(), address(cR)), guard.defaultAdmin(), adm.nonce(), cR.nonce(), s.nonce()));
    }

    /*//////////////////////////////////////////////////////////////
                               THE VERDICTS
    //////////////////////////////////////////////////////////////*/

    function _isUnauthorized(bool ok_, bytes memory ret_) internal pure returns (bool) {
        return !ok_ && ret_.length == 4 && bytes4(ret_) == CuratorGuardPolicy.Unauthorized.selector;
    }

    function _isDeadlinePassed(bool ok_, bytes memory ret_, uint64 d_) internal pure returns (bool) {
        return !ok_ && keccak256(ret_) == keccak256(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, d_));
    }

    function _isInvalidDuration(bool ok_, bytes memory ret_) internal pure returns (bool) {
        return !ok_ && keccak256(ret_) == keccak256(abi.encodeWithSelector(CuratorGuardPolicy.InvalidDuration.selector, DUR));
    }

    /// @dev Served as the admin: a 180-day ADMIN window on `s` (`councilBypass == false`).
    function _servedAsAdmin(bool ok_) internal view returns (bool) {
        if (!ok_) return false;
        (uint64 _u, bool _c) = guard.bypassWindow(address(s));
        return guard.mode(address(s)) == CuratorGuardPolicy.Mode.Bypass && _u == uint64(block.timestamp) + DUR && !_c;
    }

    /// @dev The admin Safe's verdict on the nested form: the rail first (for EVERY pair of deadlines, expired ones
    ///      included), then d1, then d2, then served as the admin; nothing moves on a refusal.
    function _assertAdminVerdict(bytes32 w_, uint64 d1_, uint64 d2_, bool ok_, bytes memory ret_, bool moved_) internal view {
        if (_low(w_) == address(guard)) {
            assert(_isUnauthorized(ok_, ret_));
            assert(!moved_);
        } else if (block.timestamp > d1_) {
            assert(_isDeadlinePassed(ok_, ret_, d1_));
            assert(!moved_);
        } else if (block.timestamp > d2_) {
            assert(_isDeadlinePassed(ok_, ret_, d2_));
            assert(!moved_);
        } else {
            assert(_servedAsAdmin(ok_));
            assert(moved_);
        }
    }

    /*//////////////////////////////////////////////////////////////
                               THE ROUTES
    //////////////////////////////////////////////////////////////*/

    /// @dev DIRECT: the role Safe calls the guard itself (its own transaction) with the word in its slot.
    function _direct(ISafe who_, bytes32 w_, bytes memory c_) internal returns (bool _ok, bytes memory _ret, bool _moved) {
        vm.store(address(who_), FALLBACK_SLOT, w_);
        bytes32 _b = _digest();
        vm.prank(address(who_));
        (_ok, _ret) = address(guard).call(c_);
        _moved = _digest() != _b;
    }

    /// @dev FORWARDED: a stranger calls the role Safe; its fallback forwards to the word's low 160 bits with the
    ///      Safe as `msg.sender` (and the stranger's 20 bytes appended).
    function _forwarded(ISafe who_, bytes32 w_, bytes memory c_) internal returns (bool _ok, bytes memory _ret, bool _moved) {
        vm.store(address(who_), FALLBACK_SLOT, w_);
        bytes32 _b = _digest();
        vm.prank(STRANGER);
        (_ok, _ret) = address(who_).call(c_);
        _moved = _digest() != _b;
    }

    /// @dev An EOA caller (no slot to read: the rail passes).
    function _eoa(address who_, bytes memory c_) internal returns (bool _ok, bytes memory _ret, bool _moved) {
        bytes32 _b = _digest();
        vm.prank(who_);
        (_ok, _ret) = address(guard).call(c_);
        _moved = _digest() != _b;
    }
}
