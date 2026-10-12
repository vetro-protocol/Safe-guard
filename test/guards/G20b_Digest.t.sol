// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {G20bDigestBase} from "test/guards/G20b_DigestBase.sol";

/// @dev The concrete twin of `G20b_SymDigest.t.sol` under `forge test` (2,048 runs in the driver), with the one thing
///      the symbolic suite does not watch: the served post-hook emits exactly one `TransactionChecked`.
abstract contract G20bDigestFoundryBase is G20bDigestBase {
    bytes32 internal constant REPORT_SIG = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");

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

    function testFuzz_X5_a_dirty_guard_word_is_GuardNotInstalled(uint96 h) public {
        vm.store(address(s), GUARD_SLOT, _w(address(guard), h));
        (bool _ok, bytes memory _ret) = _pre();
        if (h == 0) assertTrue(_ok);
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
