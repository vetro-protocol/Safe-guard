// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Test.sol";

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";
import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @dev Review round 18, reviewer g18b, adopted with G16d-1 applied: the rails compare the handler word's low 160
///      bits (the EVM masks a call target the same way), so a word with dirty high bits that still forwards to the
///      guard or the timelock is refused for EVERY value of the high bits. The fixture is the PRODUCTION `CuratorGuard`
///      and `CuratorGuardTimelock` (no harness) with real Safe v1.4.1 and v1.5.0 proxies from `lib/` as the
///      role holders: `c141` holds the guard's council seat, `a150` is the guard's pending admin, `p141` is
///      a proposer of the timelock, `v150` its canceller; `s` is a guarded Safe with a policy and a council
///      window (the state `executeBefore(enforce)` acts on). The handler slot of a role Safe is planted with
///      `(h << 160) | this` for a fuzzed `h` (sampled over the 96-bit values in the tree; the proof over
///      every value is review material, reviews g18b and g19b): `FallbackManager` forwards every unknown
///      selector to `call(gas(), sload(slot), ...)`, which the EVM masks to 160 bits, so the word forwards to
///      the guard (or the timelock) for EVERY `h`; before G16d-1 the rails compared the RAW word with
///      `address()` and read such a word as not forwarding (the round-16 finding, proven in round 18). Every address is a literal (the suite is shared with its symbolic twin in the review material, where the engine must not model `vm.addr`).
abstract contract G16dDirtyBase is Test {
    CuratorGuard internal guard;
    CuratorGuardTimelock internal tl;
    ISafe internal c141; // council seat on the guard, Safe v1.4.1
    ISafe internal a150; // pending admin of the guard, Safe v1.5.0
    ISafe internal p141; // proposer of the timelock, Safe v1.4.1
    ISafe internal v150; // canceller of the timelock, Safe v1.5.0
    ISafe internal s; // the guarded Safe: a policy, a council window
    MockProtocol internal venue;

    address internal constant VETRO = address(0xA11CE);
    address internal constant COUNCIL = address(0xC0C11);
    address internal constant STRANGER = address(0x5712A);
    address internal constant OWNER = address(0x0B0B);
    address internal constant P2 = address(0x9002); // the timelock's second proposer, an EOA
    address internal constant OTHER = address(0xBEEF); // a handler word that names nobody in particular
    uint256 internal constant T0 = 1_800_000_000;
    uint48 internal constant ADMIN_DELAY = 1 days;
    bytes32 internal constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    bytes32 internal constant SALT = keccak256("g16d");

    function setUp() public virtual {
        vm.warp(T0);
        guard = new CuratorGuard(ADMIN_DELAY, VETRO, COUNCIL);
        c141 = _safe141(OWNER);
        p141 = _safe141(OWNER);
        s = _safe141(OWNER);
        a150 = _safe150(OWNER);
        v150 = _safe150(OWNER);
        venue = new MockProtocol();
        address[] memory _p = new address[](2);
        _p[0] = address(p141);
        _p[1] = P2;
        address[] memory _c = new address[](1);
        _c[0] = address(v150);
        tl = new CuratorGuardTimelock(1 days, _p, _c);

        vm.startPrank(VETRO);
        guard.grantRole(guard.COUNCIL_ROLE(), address(c141));
        guard.allowFunction(address(s), address(venue), MockProtocol.settleDeposit.selector, false, _noRules());
        guard.beginDefaultAdminTransfer(address(a150));
        vm.stopPrank();
        vm.prank(COUNCIL);
        guard.bypass(address(s), 2 days);
    }

    function _safe141(address owner_) internal returns (ISafe _safe) {
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = owner_;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        _safe = ISafe(address(_proxy));
    }

    function _safe150(address owner_) internal returns (ISafe _safe) {
        Safe150 _singleton = new Safe150();
        SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = owner_;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        _safe = ISafe(address(_proxy));
    }

    function _noRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory) {}

    /*//////////////////////////////////////////////////////////////
                              THE WORD
    //////////////////////////////////////////////////////////////*/

    /// @dev The handler word whose low 160 bits are `low_` and whose high 96 bits are `h_`.
    function _wordOf(address low_, uint96 h_) internal pure returns (bytes32) {
        return bytes32((uint256(h_) << 160) | uint256(uint160(low_)));
    }

    /// @dev Plant the word in the Safe's handler slot (a role Safe is unguarded, so its own quorum can do
    ///      this with a storage-writing delegatecall: `G16d_DirtyWord.t.sol` does it through the real
    ///      `execTransaction`; here the slot is written directly).
    function _plant(ISafe safe_, address low_, uint96 h_) internal {
        vm.store(address(safe_), FALLBACK_SLOT, _wordOf(low_, h_));
    }

    /// @dev The slot as the Safe answers it to the rails' probe (`getStorageAt(slot, 1)`).
    function _word(ISafe safe_) internal view returns (bytes32) {
        return bytes32(safe_.getStorageAt(uint256(FALLBACK_SLOT), 1));
    }

    /// @dev What the EVM forwards to: the low 160 bits of the word.
    function _forwardsTo(ISafe safe_) internal view returns (address) {
        return address(uint160(uint256(_word(safe_))));
    }

    /*//////////////////////////////////////////////////////////////
          THE CALLS (encoded before any prank: a prank is spent by the next call, a view included)
    //////////////////////////////////////////////////////////////*/

    function _wrapEnforce(uint64 dl_) internal view returns (bytes memory) {
        return abi.encodeCall(guard.executeBefore, (dl_, abi.encodeCall(guard.enforce, (address(s)))));
    }

    function _accept() internal view returns (bytes memory) {
        return abi.encodeCall(guard.acceptDefaultAdminTransfer, ());
    }

    function _lockdownS() internal view returns (bytes memory) {
        return abi.encodeCall(guard.lockdown, (address(s)));
    }

    function _opData() internal view returns (bytes memory) {
        return abi.encodeCall(guard.enforce, (address(s)));
    }

    function _opId() internal view returns (bytes32) {
        return tl.hashOperation(address(guard), 0, _opData(), bytes32(0), SALT);
    }

    function _schedule() internal view returns (bytes memory) {
        return abi.encodeCall(tl.schedule, (address(guard), 0, _opData(), bytes32(0), SALT, 1 days));
    }

    function _cancel() internal view returns (bytes memory) {
        return abi.encodeCall(tl.cancel, (_opId()));
    }

    function _renounceProposer(ISafe who_) internal view returns (bytes memory) {
        return abi.encodeCall(tl.renounceRole, (tl.PROPOSER_ROLE(), address(who_)));
    }

    /*//////////////////////////////////////////////////////////////
                 EVERYTHING AN OBSERVER CAN READ (three frames)
    //////////////////////////////////////////////////////////////*/

    function _dA() internal view returns (bytes32) {
        (address _p, uint48 _sch) = guard.pendingDefaultAdmin();
        (uint64 _u, bool _cb) = guard.bypassWindow(address(s));
        return keccak256(abi.encode(guard.defaultAdmin(), _p, _sch, guard.mode(address(s)), _u, _cb, guard.lockedAt(address(s))));
    }

    function _dB() internal view returns (bytes32) {
        bytes32 _C = guard.COUNCIL_ROLE();
        bytes32 _P = tl.PROPOSER_ROLE();
        bytes32 _K = tl.CANCELLER_ROLE();
        return keccak256(abi.encode(guard.hasRole(_C, address(c141)), guard.hasRole(_C, STRANGER), tl.proposerCount(), tl.cancellerCount(), tl.hasRole(_P, address(p141)), tl.hasRole(_K, address(v150)), tl.hasRole(_P, STRANGER), tl.hasRole(_K, STRANGER)));
    }

    function _dC() internal view returns (bytes32) {
        return keccak256(abi.encode(c141.nonce(), a150.nonce(), p141.nonce(), v150.nonce(), s.nonce(), tl.isOperation(_opId()), tl.isOperationPending(_opId())));
    }

    function _digest() internal view returns (bytes32) {
        return keccak256(abi.encode(_dA(), _dB(), _dC()));
    }

    /*//////////////////////////////////////////////////////////////
                           THE TWO RAILS' REFUSALS
    //////////////////////////////////////////////////////////////*/

    function _isUnauthorized(bool ok_, bytes memory ret_) internal pure returns (bool) {
        return !ok_ && ret_.length == 4 && bytes4(ret_) == CuratorGuardPolicy.Unauthorized.selector;
    }

    function _isForwardedCall(bool ok_, bytes memory ret_, address who_) internal pure returns (bool) {
        return !ok_ && keccak256(ret_) == keccak256(abi.encodeWithSelector(CuratorGuardTimelock.ForwardedCall.selector, who_));
    }
}
