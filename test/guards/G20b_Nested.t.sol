// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {G20bNestedBase} from "test/guards/G20b_NestedBase.sol";

/// @dev The concrete twin of `G20b_SymNested.t.sol` under `forge test`: the verdict function fuzzed (2,048 runs in the
///      driver), and what the symbolic suite cannot observe: the rail RE-FIRES AT EVERY LEVEL, counted as the
///      `getStorageAt(handler slot, 1)` probes the guard sends the caller (`vm.expectCall` with a count): k levels of
///      `executeBefore` plus the inner call's own role check make k + 1 probes on a served call, and a forwarding
///      word is stopped by the FIRST probe (one probe, whatever the deadlines). Also the real route: the admin Safe's
///      owner SIGNS the nested wrap and `execTransaction` delivers it.
abstract contract G20bNestedFoundryBase is G20bNestedBase {
    uint256 internal constant KEY = 0xB0B0B0B;

    function _owner() internal override returns (address) {
        return vm.addr(KEY);
    }

    function _probe() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(GET_STORAGE_AT, FALLBACK_SLOT, 1);
    }

    function _clean(address a_) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a_)));
    }

    function _dirty(address a_, uint96 h_) internal pure returns (bytes32) {
        return bytes32((uint256(h_) << 160) | uint256(uint160(a_)));
    }

    /// the verdict function, fuzzed over a random word and both deadlines
    function testFuzz_D2_verdict(bytes32 w, uint64 d1, uint64 d2) public {
        (bool _ok, bytes memory _ret, bool _moved) = _direct(adm, w, _nested2(d1, d2));
        _assertAdminVerdict(w, d1, d2, _ok, _ret, _moved);
    }

    /// a word naming the guard, every high-bit value, every pair of deadlines: refused at the first probe
    function testFuzz_D2_a_word_naming_the_guard_is_refused_by_the_first_probe(uint96 h, uint64 d1, uint64 d2) public {
        vm.expectCall(address(adm), _probe(), 1);
        (bool _ok, bytes memory _ret, bool _moved) = _direct(adm, _dirty(address(guard), h), _nested2(d1, d2));
        assertTrue(_isUnauthorized(_ok, _ret), "Unauthorized");
        assertFalse(_moved, "nothing moved");
    }

    function testFuzz_F2_forwarded_naming_the_guard_is_refused_by_the_first_probe(uint96 h, uint64 d1, uint64 d2) public {
        vm.expectCall(address(adm), _probe(), 1);
        (bool _ok, bytes memory _ret, bool _moved) = _forwarded(adm, _dirty(address(guard), h), _nested2(d1, d2));
        assertTrue(_isUnauthorized(_ok, _ret), "Unauthorized through the fallback");
        assertFalse(_moved, "nothing moved");
    }

    /// served: three probes (level 1, level 2, the inner `bypass`'s role check)
    function test_served_nested_wrap_probes_the_caller_three_times() public {
        vm.expectCall(address(adm), _probe(), 3);
        (bool _ok, , bool _moved) = _direct(adm, _clean(address(0)), _nested2(uint64(T0 + 1), uint64(T0)));
        assertTrue(_servedAsAdmin(_ok), "served as the admin: a 180-day admin window");
        assertTrue(_moved);
    }

    /// depth 3 served: four probes
    function test_served_triple_wrap_probes_the_caller_four_times() public {
        vm.expectCall(address(adm), _probe(), 4);
        (bool _ok, , ) = _direct(adm, _clean(address(0)), _nested3(uint64(T0 + 7), uint64(T0 + 3), uint64(T0)));
        assertTrue(_servedAsAdmin(_ok));
    }

    /// the inner deadline expired: two probes (both levels' rails ran), then DeadlinePassed(d2), nothing moved
    function test_inner_deadline_expired_after_two_probes() public {
        vm.expectCall(address(adm), _probe(), 2);
        (bool _ok, bytes memory _ret, bool _moved) = _direct(adm, _clean(address(0)), _nested2(uint64(T0 + 1), uint64(T0 - 1)));
        assertTrue(_isDeadlinePassed(_ok, _ret, uint64(T0 - 1)), "DeadlinePassed(d2)");
        assertFalse(_moved);
    }

    /// the outer deadline expired: one probe, DeadlinePassed(d1)
    function test_outer_deadline_expired_after_one_probe() public {
        vm.expectCall(address(adm), _probe(), 1);
        (bool _ok, bytes memory _ret, bool _moved) = _direct(adm, _clean(address(0)), _nested2(uint64(T0 - 1), uint64(T0 + 1)));
        assertTrue(_isDeadlinePassed(_ok, _ret, uint64(T0 - 1)), "DeadlinePassed(d1)");
        assertFalse(_moved);
    }

    /// the council's own role inside the nesting, never the admin's
    function testFuzz_C2_the_council_runs_the_inner_call_with_its_own_cap(uint96 h, uint64 d1, uint64 d2) public {
        vm.assume(d1 >= T0 && d2 >= T0);
        (bool _ok, bytes memory _ret, bool _moved) = _direct(cR, _dirty(address(0), h), _nested2(d1, d2));
        assertTrue(_isInvalidDuration(_ok, _ret), "InvalidDuration(180 days): the council's cap");
        assertFalse(_moved);
    }

    /// the real route: the admin Safe's owner signs the nested wrap; `execTransaction` delivers it to the guard
    function _signed(bytes memory c_) internal view returns (bytes memory) {
        bytes32 _h = adm.getTransactionHash(address(guard), 0, c_, Operation.Call, 0, 0, 0, address(0), address(0), adm.nonce());
        (uint8 _v, bytes32 _r, bytes32 _sg) = vm.sign(KEY, _h);
        return abi.encodePacked(_r, _sg, _v);
    }

    function _exec(bytes memory c_, bytes memory sig_) internal returns (bool) {
        return adm.execTransaction(address(guard), 0, c_, Operation.Call, 0, 0, 0, address(0), payable(address(0)), sig_);
    }

    function test_signed_execTransaction_delivers_the_nested_wrap_as_the_admin() public {
        bytes memory _c = _nested2(uint64(T0 + 1 days), uint64(T0 + 1));
        bytes memory _sig = _signed(_c);
        vm.expectCall(address(adm), _probe(), 3);
        assertTrue(_exec(_c, _sig), "the Safe reports success");
        assertTrue(_servedAsAdmin(true), "a 180-day admin window on s");
    }

    /// the self-forwarding word (excluded from the symbolic F2): the EVM's depth / gas end it, nothing moves
    function test_self_forwarding_word_ends_with_nothing_moved() public {
        (, , bool _moved) = _forwarded(adm, _clean(address(adm)), _nested2(uint64(T0 + 1), uint64(T0 + 1)));
        assertFalse(_moved);
        assertEq(uint8(guard.mode(address(s))), uint8(CuratorGuardPolicy.Mode.Lockdown));
    }
}

contract G20b_Nested141Test is G20bNestedFoundryBase {
    function _mk(address owner_) internal override returns (ISafe) {
        return _safe141(owner_);
    }
}

contract G20b_Nested150Test is G20bNestedFoundryBase {
    function _mk(address owner_) internal override returns (ISafe) {
        return _safe150(owner_);
    }
}
