// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {G20bDigestBase} from "test/guards/G20b_DigestBase.sol";

/// @dev The concrete twin of `G20b_SymDigest.t.sol` under `forge test` (2,048 runs in the driver), with the one thing
///      the symbolic suite does not watch: the served post-hook emits exactly one `TransactionChecked`. X5 to X7 are
///      not that suite's: they pin the installed-slot check, which reads the guard word's low 160 bits since
///      Quantstamp GUARD-4 (the symbolic X5 pinned the full-word compare).
abstract contract G20bDigestFoundryBase is G20bDigestBase {
    bytes32 internal constant REPORT_SIG = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");
    bytes32 internal constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;
    address internal constant MODULE = address(0x30D);

    function _reports(Vm.Log[] memory logs_) internal view returns (uint256 _n) {
        for (uint256 i; i < logs_.length; ++i) if (logs_[i].emitter == address(guard) && logs_[i].topics[0] == REPORT_SIG) ++_n;
    }

    function testFuzz_X1_the_pre_hook_admits_a_word_by_its_low_bits(bytes32 w) public {
        _plant(w);
        (bool _ok, bytes memory _ret) = _pre();
        if (_admittedLow(w)) assertTrue(_ok, "admitted by the low bits");
        else assertTrue(_isHandlerNotAllowed(_ok, _ret, _low(w)), "FallbackHandlerNotAllowed(low bits)");
    }

    function testFuzz_X2_the_post_hook_is_byte_exact(uint96 h1, bool zeroLow, bytes32 w2) public {
        bytes32 _w1 = _w(zeroLow ? address(0) : address(H), h1);
        _plant(_w1);
        (bool _ok, ) = _pre();
        assertTrue(_ok);
        _plant(w2);
        vm.recordLogs();
        (bool _ok2, bytes memory _ret) = _post();
        if (w2 == _w1) {
            assertTrue(_ok2, "same bytes: served");
            assertEq(_reports(vm.getRecordedLogs()), 1, "one report");
        } else {
            assertTrue(_isSafeConfigChanged(_ok2, _ret), "SafeConfigChanged");
        }
    }

    function testFuzz_X3_the_high_bits_alone_between_the_hooks(uint96 h1, uint96 h2) public {
        _plant(_w(address(H), h1));
        (bool _ok, ) = _pre();
        assertTrue(_ok);
        _plant(_w(address(H), h2));
        vm.recordLogs();
        (bool _ok2, bytes memory _ret) = _post();
        if (h1 == h2) {
            assertTrue(_ok2, "served");
            assertEq(_reports(vm.getRecordedLogs()), 1, "one report");
        } else {
            assertTrue(_isSafeConfigChanged(_ok2, _ret), "SafeConfigChanged");
        }
    }

    function test_X4_a_clean_to_clean_no_op_is_served_with_one_report() public {
        (bool _ok, ) = _pre();
        assertTrue(_ok);
        _plant(_clean(address(H)));
        vm.recordLogs();
        (bool _ok2, ) = _post();
        assertTrue(_ok2);
        assertEq(_reports(vm.getRecordedLogs()), 1);
    }

    function test_X4b_the_high_bits_alone_dirtied_between_the_hooks_is_SafeConfigChanged() public {
        (bool _ok, ) = _pre();
        assertTrue(_ok);
        _plant(_w(address(H), 0xdead));
        (bool _ok2, bytes memory _ret) = _post();
        assertTrue(_isSafeConfigChanged(_ok2, _ret), "dirtied");
    }

    function test_X4c_the_high_bits_alone_cleaned_between_the_hooks_is_SafeConfigChanged() public {
        _plant(_w(address(H), 0xbeef));
        (bool _ok, ) = _pre();
        assertTrue(_ok, "a dirty required word is admitted (masked read)");
        _plant(_clean(address(H)));
        (bool _ok2, bytes memory _ret) = _post();
        assertTrue(_isSafeConfigChanged(_ok2, _ret), "cleaned");
    }

    /// @dev The installed-slot check reads the low 160 bits, as the Safe reads its guard (Quantstamp GUARD-4):
    ///      a guard word whose low bits name this guard is admitted whatever its high bits (X5b and X6 hold the
    ///      control: a word whose low bits name another account is `GuardNotInstalled`).
    function testFuzz_X5_a_dirty_guard_word_is_admitted_by_its_low_160_bits(uint96 h) public {
        vm.store(address(s), GUARD_SLOT, _w(address(guard), h));
        (bool _ok, ) = _pre();
        assertTrue(_ok, "a dirty guard word naming this guard is admitted (masked read)");
    }

    /// @dev X5 at the edges of the mask: the lowest and the highest bit above the address, every high bit, and the
    ///      low 96 bits of this guard's own address repeated above it are admitted (and served by the post-hook); a
    ///      word one bit off inside the low 160 bits (the highest and the lowest), a word that carries this guard in
    ///      its HIGH 160 bits only, an empty address under dirty high bits and the Safe's own address are
    ///      `GuardNotInstalled`.
    function test_X5b_the_mask_is_exactly_160_bits_wide() public {
        uint256 _g = uint256(uint160(address(guard)));
        uint96[4] memory _hs = [uint96(1), uint96(1) << 95, type(uint96).max, uint96(_g)];
        for (uint256 i; i < _hs.length; ++i) {
            vm.store(address(s), GUARD_SLOT, _w(address(guard), _hs[i]));
            (bool _ok, ) = _pre();
            assertTrue(_ok, "admitted by the low 160 bits");
            (_ok, ) = _post();
            assertTrue(_ok, "same bytes: served");
        }
        bytes32[5] memory _others = [bytes32(_g ^ (1 << 159)), bytes32(_g ^ 1), bytes32(_g << 96), _w(address(0), type(uint96).max), _clean(address(s))];
        for (uint256 i; i < _others.length; ++i) {
            vm.store(address(s), GUARD_SLOT, _others[i]);
            (bool _ok, bytes memory _ret) = _pre();
            assertTrue(_isGuardNotInstalled(_ok, _ret), "GuardNotInstalled");
        }
    }

    /// @dev The control of X5 as a property: the pre-hook answers a guard word EXACTLY by its low 160 bits. Any
    ///      word whose low bits name another account (or none) is `GuardNotInstalled`, whatever its high bits.
    function testFuzz_X6_a_guard_word_naming_another_account_is_GuardNotInstalled(uint96 h, address low) public {
        vm.assume(low != address(guard));
        vm.store(address(s), GUARD_SLOT, _w(low, h));
        (bool _ok, bytes memory _ret) = _pre();
        assertTrue(_isGuardNotInstalled(_ok, _ret), "GuardNotInstalled");
    }

    /// @dev X5 and X6 on the module path, whose installed-slot check reads the MODULE-guard slot (the hook is driven
    ///      directly, as the Safe; no module is linked, so the policy lane's `ModuleNotHooked` rail has nothing to
    ///      refuse). The transaction-guard slot is emptied first: the installed-slot check of this path does not
    ///      read it.
    function testFuzz_X7_the_module_hook_reads_the_module_guard_word_by_its_low_160_bits(uint96 h, address low, bool named) public {
        if (named) low = address(guard);
        else vm.assume(low != address(guard));
        vm.prank(VETRO);
        guard.setModuleAllowed(address(s), MODULE, true);
        vm.store(address(s), GUARD_SLOT, bytes32(0));
        vm.store(address(s), MODULE_GUARD_SLOT, _w(low, h));
        bytes memory _c = abi.encodeCall(guard.checkModuleTransaction, (address(venue), 0, settle, Operation.Call, MODULE));
        vm.prank(address(s));
        (bool _ok, bytes memory _ret) = address(guard).call(_c);
        if (named) assertTrue(_ok, "a dirty module-guard word naming this guard is admitted (masked read)");
        else assertTrue(_isGuardNotInstalled(_ok, _ret), "GuardNotInstalled");
    }
}

contract G20b_Digest141Test is G20bDigestFoundryBase {
    function _mk(address owner_) internal override returns (ISafe) {
        return _safe141(owner_);
    }
}

contract G20b_Digest150Test is G20bDigestFoundryBase {
    function _mk(address owner_) internal override returns (ISafe) {
        return _safe150(owner_);
    }
}
