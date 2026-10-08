// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";
import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeMigration} from "safe-contracts-v1.5.0/contracts/libraries/SafeMigration.sol";
import {CompatibilityFallbackHandler as CFH150} from "safe-contracts-v1.5.0/contracts/handler/CompatibilityFallbackHandler.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {ISafeTransactionGuard, Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @dev A "migration library" that is NOT the canonical one: the same selector and payload bytes as
///      `SafeMigration.migrateSingleton()`, writing slot 0 to whatever its deployer chose.
contract LookAlikeMigration {
    address public immutable TARGET;

    constructor(address target_) {
        TARGET = target_;
    }

    function migrateSingleton() external {
        address _t = TARGET;
        assembly {
            sstore(0, _t)
        }
    }
}

/// @dev What sits behind the proxy after a hostile migration: anything, callable by anyone, with no Safe
///      transaction, no hook and no guard event.
contract EvilSingleton {
    function drain(address token_, address to_) external {
        IERC20(token_).transfer(to_, IERC20(token_).balanceOf(address(this)));
    }
}

/// @dev A hypothetical later Safe release whose `setGuard` asks a NEW ERC-165 id for its transaction guard
///      (the convention Safe followed when it introduced the module guard in v1.5.0). Same storage layout.
contract FutureSingletonNewId {
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    function setGuard(address guard_) external {
        require(msg.sender == address(this), "GS031");
        if (guard_ != address(0)) {
            (bool _ok, bytes memory _r) = guard_.staticcall(abi.encodeWithSelector(0x01ffc9a7, bytes4(0x12345678)));
            require(_ok && _r.length == 32 && abi.decode(_r, (bool)), "GS300");
        }
        assembly {
            sstore(GUARD_SLOT, guard_)
        }
    }
}

/// @dev A hypothetical later Safe release that keeps the interface id `0xe6d7a83a` yet calls a pre-hook this
///      guard never had, and, when `RENAME_POST` is set, a new post-hook too. `run` is a reduced
///      `execTransaction` (no signatures: the PoC is about the hooks, not about authorisation).
contract FutureSingletonNewHook {
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bool public immutable RENAME_POST;

    constructor(bool renamePost_) {
        RENAME_POST = renamePost_;
    }

    function run(address to_, bytes calldata data_) external returns (bool _ok) {
        address _guard;
        assembly {
            _guard := sload(GUARD_SLOT)
        }
        (bool _pre, bytes memory _r) = _guard.call(abi.encodeWithSignature("checkTransactionV2(address,bytes)", to_, data_));
        if (!_pre) {
            assembly {
                revert(add(_r, 0x20), mload(_r))
            }
        }
        (_ok, ) = to_.call(data_);
        bytes memory _postCall = RENAME_POST
            ? abi.encodeWithSignature("checkAfterExecutionV2(bool)", _ok)
            : abi.encodeWithSelector(ISafeTransactionGuard.checkAfterExecution.selector, bytes32(0), _ok);
        (bool _post, bytes memory _r2) = _guard.call(_postCall);
        if (!_post) {
            assembly {
                revert(add(_r2, 0x20), mload(_r2))
            }
        }
    }
}

/// @dev The survey's "fallback stance" variant: Safe's example guards keep a non-reverting `fallback()`.
contract CuratorGuardWithFallback is CuratorGuardHarness {
    constructor(uint48 adminDelay_, address admin_, address council_) CuratorGuardHarness(adminDelay_, admin_, council_) {}

    fallback() external {}
}

interface ISafeFallback {
    function setFallbackHandler(address handler) external;
}

/// @title G11f: Safe migrations under the guard (round 11, upgrades / migrations / future EVMs)
/// @notice Real Safe v1.4.1 fixture, the vendored v1.5.0 singleton, migration library and fallback handler.
contract G11fMigrationTest is CuratorGuardTestBase {
    bytes32 internal constant SAFE_MSG_TYPEHASH = 0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca;
    function _migrateCall() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SafeMigration.migrateSingleton.selector);
    }

    function _settle(uint256 n_) internal pure returns (bytes memory) {
        return abi.encodeCall(MockProtocol.settleDeposit, (n_));
    }

    function _singleton() internal view returns (address) {
        return address(uint160(uint256(vm.load(address(safe), bytes32(0)))));
    }

    function _handler() internal view returns (address) {
        return address(uint160(uint256(vm.load(address(safe), FALLBACK_SLOT))));
    }

    function _run(address to_, bytes memory data_) internal returns (bool _ok) {
        (_ok, ) = address(safe).call(abi.encodeCall(FutureSingletonNewHook.run, (to_, data_)));
    }

    /// @dev The library's handler-reinstalling entry point (the "one transaction" upgrade shape), approved
    ///      as the runbook says never to: the migration lands, the 1.5.0 `CompatibilityFallbackHandler` is
    ///      back in the slot, policy traffic stops (`FallbackHandlerNotAllowed`) and, until the council's
    ///      `setFallbackHandler(0)`, the Safe answers EIP-1271 for its signers with no Safe transaction.
    function test_G11f_migrateWithFallbackHandler_reinstalls_a_signature_capable_handler() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(safe), address(0), true); // the shipped policy's requirement
        Safe150 _s150 = new Safe150();
        _H().seedSafeCodehash(address(_s150).codehash);
        CFH150 _cfh = new CFH150();
        SafeMigration _migration = new SafeMigration(address(_s150), address(_s150), address(_cfh));

        bytes memory _call = abi.encodeCall(SafeMigration.migrateWithFallbackHandler, ());
        _approve(address(_migration), 0, _call, Operation.DelegateCall);
        assertTrue(_execSafeTx(address(_migration), 0, _call, Operation.DelegateCall), "the approved migration lands");
        assertEq(_singleton(), address(_s150), "migrated to v1.5.0");
        assertEq(_handler(), address(_cfh), "the signature-capable handler is back");

        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FallbackHandlerNotAllowed.selector, address(_cfh)));
        _execSafeTx(address(protocol), 0, _settle(1), Operation.Call);

        // EIP-1271 through the Safe, answered by the handler: a signer's off-chain signature authorises
        // anything a 1271-aware token accepts (`permit`, `transferWithAuthorization`), zero Safe transactions.
        bytes32 _digest = keccak256("permit digest");
        bytes32 _safeMsgHash = keccak256(abi.encode(SAFE_MSG_TYPEHASH, keccak256(abi.encode(_digest))));
        bytes32 _domain = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, address(safe)));
        bytes memory _sig = _sign(keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), _domain, _safeMsgHash)));
        (bool _ok, bytes memory _ret) = address(safe).staticcall(abi.encodeWithSelector(0x1626ba7e, _digest, _sig));
        assertTrue(_ok && _ret.length == 32 && bytes4(_ret) == bytes4(0x1626ba7e), "the 1271 door is open");

        // The council's repair: approve setFallbackHandler(0); policy traffic resumes on v1.5.0.
        bytes memory _reset = abi.encodeCall(ISafeFallback.setFallbackHandler, (address(0)));
        _councilApprove(address(safe), 0, _reset, Operation.Call);
        assertTrue(_execSafeTx(address(safe), 0, _reset, Operation.Call));
        assertEq(_handler(), address(0));
        assertTrue(_execSafeTx(address(protocol), 0, _settle(2), Operation.Call), "policy traffic on v1.5.0");
    }

    /// @dev The migration approval is the one admin action whose CONTENT, not its shape, decides custody:
    ///      the approval pins the delegatecall target's code hash, and a look-alike library satisfies its own
    ///      pin. Nothing on-chain, in the runbook (no canonical address is named) or in `verify --op` (the
    ///      payload is printed as hex) tells the canonical library from this one.
    function test_G11f_a_look_alike_migration_library_approved_as_the_migration_takes_custody() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        EvilSingleton _evil = new EvilSingleton();
        LookAlikeMigration _fake = new LookAlikeMigration(address(_evil));

        _approve(address(_fake), 0, _migrateCall(), Operation.DelegateCall);
        assertTrue(_execSafeTx(address(_fake), 0, _migrateCall(), Operation.DelegateCall), "approved: InvalidTarget does not fire (code, not 0xef)");
        assertEq(_singleton(), address(_evil), "slot 0 is the attacker's code");

        uint256 _custody = token.balanceOf(address(safe));
        vm.prank(attacker);
        EvilSingleton(address(safe)).drain(address(token), attacker);
        assertEq(token.balanceOf(attacker), _custody, "custody gone with no Safe transaction");
        assertEq(token.balanceOf(address(safe)), 0);

        // The guard learns of it only from the next policy transaction, which cannot run any more.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeNotSupported.selector, address(safe)));
        guard.validateTransaction(address(safe), address(protocol), 0, _settle(1), Operation.Call);
    }

    /// @dev The runbook's one-batch recipe against a release that asks a NEW interface id: the re-install
    ///      entry reverts GS300 inside the batch, the whole Safe transaction reverts (GS013, `safeTxGas` 0),
    ///      slot 0 is untouched and the approval is kept. Fail-closed, as section 7.5 says.
    function test_G11f_the_recipe_to_a_release_with_a_new_interface_id_fails_closed() public {
        _enforce();
        FutureSingletonNewId _future = new FutureSingletonNewId();
        SafeMigration _migration = new SafeMigration(address(_future), address(_future), address(protocol));
        bytes memory _batch = abi.encodeWithSelector(
            multiSend.multiSend.selector,
            abi.encodePacked(
                abi.encodePacked(uint8(1), address(_migration), uint256(0), _migrateCall().length, _migrateCall()),
                _entry(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(guard)))),
                _entry(address(safe), 0, abi.encodeCall(ISafe.setModuleGuard, (address(guard))))
            )
        );
        bytes32 _id = _approve(address(multiSend), 0, _batch, Operation.DelegateCall);
        address _before = _singleton();
        vm.expectRevert("GS013");
        _execSafeTx(address(multiSend), 0, _batch, Operation.DelegateCall);
        assertEq(_singleton(), _before, "the Safe stayed where it was");
        assertGt(guard.approvalExpiry(_id), 0, "the approval is kept");
    }

    /// @dev The trap the recipe cannot close: a release that KEEPS the id but calls a new pre-hook (the recipe's
    ///      re-install asks the ERC-165 question, which such a release answers with yes; only the pinned-release
    ///      rule of 7.5 excludes it). Migrated to, with the shipped guard every later execution reverts inside
    ///      the pre-hook call, approvals and windows included: bricked.
    function test_G11f_migration_alone_to_a_same_id_release_with_a_new_hook_bricks_the_safe_exits_included() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        FutureSingletonNewHook _future = new FutureSingletonNewHook(false);
        SafeMigration _migration = new SafeMigration(address(_future), address(_future), address(protocol));
        _approve(address(_migration), 0, _migrateCall(), Operation.DelegateCall);
        assertTrue(_execSafeTx(address(_migration), 0, _migrateCall(), Operation.DelegateCall), "the old release runs the migration's own post-hook");
        assertEq(_singleton(), address(_future));
        assertFalse(_run(address(protocol), _settle(1)), "policy path: the unknown pre-hook reverts");
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        assertFalse(_run(address(protocol), _settle(1)), "a live window is no exit: the pre-hook call reverts before anything is read");
        vm.prank(council);
        guard.enforce(address(safe));
        _approve(address(protocol), 0, _settle(1), Operation.Call);
        assertFalse(_run(address(protocol), _settle(1)), "an approval is no exit either: bricked");
    }

    /// @dev The survey's non-reverting `fallback()`: the unknown pre-hook "passes", but as long as the release
    ///      still calls the OLD post-hook that one reverts `MissingSnapshot` outside a window (fail-closed),
    ///      and a window is a working exit.
    function test_G11f_with_a_fallback_the_old_post_hook_still_fails_closed_and_a_window_is_the_exit() public {
        CuratorGuardWithFallback _gf = _freshSafeWithFallbackGuard(_singleton());
        FutureSingletonNewHook _future = new FutureSingletonNewHook(false);
        _migrateAlone(_gf, address(_future));
        assertFalse(_run(address(protocol), _settle(2)), "fallback pre-hook passes, the old post-hook reverts MissingSnapshot");
        vm.prank(council);
        _gf.bypass(address(safe), 1 hours);
        assertTrue(_run(address(protocol), _settle(2)), "inside a window the old post-hook reports Bypass: the window is an exit");
        assertEq(protocol.lastAmount(), 2);
    }

    /// @dev Both hooks renamed: with the fallback the Safe is alive and unguarded (the brick traded for fail-open).
    function test_G11f_with_a_fallback_and_both_hooks_renamed_the_safe_is_alive_and_unguarded() public {
        CuratorGuardWithFallback _gf = _freshSafeWithFallbackGuard(_singleton());
        FutureSingletonNewHook _future = new FutureSingletonNewHook(true);
        _migrateAlone(_gf, address(_future));
        uint256 _custody = token.balanceOf(address(safe));
        assertTrue(_run(address(token), abi.encodeCall(IERC20.transfer, (attacker, _custody))), "nothing is checked any more");
        assertEq(token.balanceOf(attacker), _custody, "alive and unguarded");
    }

    /// @dev A new v1.4.1 Safe (same singleton as the fixture's) with the same curator key, a synced guard
    ///      WITH a fallback installed through a genuine `setGuard`; `token` funded again.
    function _freshSafeWithFallbackGuard(address singleton141_) internal returns (CuratorGuardWithFallback _gf) {
        SafeProxy _proxy = new SafeProxy(singleton141_);
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        safe = ISafe(address(_proxy));
        token.mint(address(safe), 1_000_000e6);
        _gf = new CuratorGuardWithFallback(0, vetro, council);
        _gf.seedSafe(address(safe));
        vm.startPrank(vetro);
        _gf.enforce(address(safe));
        _gf.allowFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules());
        vm.stopPrank();
        _execSafeTx(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(_gf))), Operation.Call);
        assertEq(_installedGuard(), address(_gf));
    }

    /// @dev An admin approval on `guard_` of a bare `migrateSingleton()` delegatecall to `singleton_`, executed.
    function _migrateAlone(CuratorGuard guard_, address singleton_) internal {
        SafeMigration _migration = new SafeMigration(singleton_, singleton_, address(protocol));
        vm.prank(vetro);
        guard_.approveTransaction(address(safe), address(0), address(_migration), 0, _migrateCall(), Operation.DelegateCall, 1 days);
        assertTrue(_execSafeTx(address(_migration), 0, _migrateCall(), Operation.DelegateCall));
        assertEq(_singleton(), singleton_, "migrated alone");
    }
}
