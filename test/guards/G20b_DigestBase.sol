// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Test.sol";

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";
import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";
import {CompatibilityFallbackHandler} from "safe-contracts-v1.4.1/contracts/handler/CompatibilityFallbackHandler.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @dev Review round 20, reviewer g20b: the digest's BYTE-EXACTNESS (g19e's G19e-3) as a property. The pre-hook of
///      the policy path reads the Safe's fallback-handler word, MASKS it for the handler requirement (`_checkHandler`:
///      the low 160 bits must be the required handler, or zero) and hashes it RAW into the configuration snapshot;
///      the post-hook hashes the slot again and refuses `SafeConfigChanged` on any difference. So a change of the
///      word's high bits alone between the hooks is `SafeConfigChanged`, a clean-to-clean (any same-bytes) no-op is
///      served, and a word is admitted at the pre-hook exactly by its low bits whatever its high bits.
///
///      Fixture: the harness guard (the production hooks; the harness only seeds the code hashes of the locally
///      compiled Safe build, which the deployed guard pins at deployment: V2-85), a real Safe v1.4.1 or v1.5.0
///      proxy `s` with the guard installed by a pranked self-call, `Enforced`, one allowed function on a venue, the
///      handler requirement ON naming a real `CompatibilityFallbackHandler` `H` (the shipped shape, as g19e's suite).
///      The hooks are driven directly with the Safe as `msg.sender` (the only thing they look at); every address is
///      a literal. Collision-freedom of `keccak256` over the snapshot is the engine's axiom, as in every digest check.
abstract contract G20bDigestBase is Test {
    CuratorGuardHarness internal guard;
    ISafe internal s;
    MockProtocol internal venue;
    CompatibilityFallbackHandler internal H;
    address internal singleton;

    address internal constant VETRO = address(0xA11CE);
    address internal constant COUNCIL = address(0xC0C11);
    address internal constant OWNER = address(0x0B0B);
    uint256 internal constant T0 = 1_800_000_000;
    bytes32 internal constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    bytes internal settle;

    function _mk(address owner_) internal virtual returns (ISafe);

    function setUp() public virtual {
        vm.warp(T0);
        s = _mk(OWNER);
        guard = new CuratorGuardHarness(0, VETRO, COUNCIL);
        guard.seedSafe(address(s));
        vm.prank(address(s));
        s.setGuard(address(guard));
        venue = new MockProtocol();
        H = new CompatibilityFallbackHandler();
        settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.startPrank(VETRO);
        guard.allowFunction(address(s), address(venue), MockProtocol.settleDeposit.selector, false, _noRules());
        guard.setRequiredFallbackHandler(address(s), address(H), true);
        guard.enforce(address(s));
        vm.stopPrank();
        // the clean required word, as `setup(..., H, ...)` or an approved `setFallbackHandler(H)` leaves it
        _plant(_clean(address(H)));
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

    function _noRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory) {}

    /*//////////////////////////////////////////////////////////////
                           THE WORD AND THE HOOKS
    //////////////////////////////////////////////////////////////*/

    function _low(bytes32 w_) internal pure returns (address) {
        return address(uint160(uint256(w_)));
    }

    function _clean(address a_) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a_)));
    }

    function _w(address low_, uint96 h_) internal pure returns (bytes32) {
        return bytes32((uint256(h_) << 160) | uint256(uint160(low_)));
    }

    function _plant(bytes32 w_) internal {
        vm.store(address(s), FALLBACK_SLOT, w_);
    }

    function _word() internal view returns (bytes32) {
        return bytes32(s.getStorageAt(uint256(FALLBACK_SLOT), 1));
    }

    /// @dev The live pre-hook on the policy path, as the Safe, no gas refund.
    function _pre() internal returns (bool _ok, bytes memory _ret) {
        bytes memory _c = abi.encodeCall(guard.checkTransaction, (address(venue), 0, settle, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", OWNER));
        vm.prank(address(s));
        (_ok, _ret) = address(guard).call(_c);
    }

    /// @dev The live post-hook, as the Safe (the canonical 68 bytes).
    function _post() internal returns (bool _ok, bytes memory _ret) {
        bytes memory _c = abi.encodeCall(guard.checkAfterExecution, (bytes32(uint256(0x1234)), true));
        vm.prank(address(s));
        (_ok, _ret) = address(guard).call(_c);
    }

    function _isSafeConfigChanged(bool ok_, bytes memory ret_) internal view returns (bool) {
        return !ok_ && keccak256(ret_) == keccak256(abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(s)));
    }

    function _isHandlerNotAllowed(bool ok_, bytes memory ret_, address h_) internal pure returns (bool) {
        return !ok_ && keccak256(ret_) == keccak256(abi.encodeWithSelector(CuratorGuard.FallbackHandlerNotAllowed.selector, h_));
    }

    function _isGuardNotInstalled(bool ok_, bytes memory ret_) internal view returns (bool) {
        return !ok_ && keccak256(ret_) == keccak256(abi.encodeWithSelector(CuratorGuard.GuardNotInstalled.selector, address(s)));
    }

    /// @dev The pre-hook admits a word by its LOW bits: the required handler or none.
    function _admittedLow(bytes32 w_) internal view returns (bool) {
        address _l = _low(w_);
        return _l == address(H) || _l == address(0);
    }
}
