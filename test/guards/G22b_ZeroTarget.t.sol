// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G22bZeroTargetBase} from "test/guards/G22b_ZeroTargetBase.sol";

/*//////////////////////////////////////////////////////////////
   THE FORGE TWIN of G22b_SymZeroTarget: the same checks, concrete and fuzzed (2,048 runs under the drivers), on
   both Safe builds; the behavioural pin of the +18-byte rail (G17a-3), which the tree otherwise pins by its
   build hash alone (review G22b-1).
//////////////////////////////////////////////////////////////*/
abstract contract G22bZeroTargetFuzz is G22bZeroTargetBase {
    function _shape(uint8 i_) internal pure returns (bytes memory) {
        if (i_ == 0) return "";
        if (i_ == 1) return hex"deadbeef";
        if (i_ == 2) return abi.encodeCall(MockProtocol.settleDeposit, (1));
        return hex"0102";
    }

    /// @dev Z1a: every seat, both operations, four shapes, two values: refused as the rail says, no approval.
    function test_Z1a_every_seat_is_refused_on_both_operations() public {
        for (uint8 w; w < N_SEATS; ++w) {
            for (uint8 s; s < 4; ++s) {
                _Z1(_seat(w), _req(address(0), 0, _shape(s), false, TTL));
                _Z1(_seat(w), _req(address(0), 1 ether, _shape(s), true, TTL));
                _Z1(_seat(w), _req(MODULE, 1, _shape(s), false, 7 days));
            }
        }
    }

    function testFuzz_Z1a_admin_and_council_get_InvalidTarget_zero_first(bool council, address executor, uint256 value, bytes calldata data, bool dc, uint64 ttl) public {
        _Z1(council ? COUNCIL : VETRO, _req(executor, value, data, dc, ttl));
    }

    function testFuzz_Z1b_any_other_address_gets_Unauthorized(address caller, uint256 value, bytes calldata data, bool dc) public {
        vm.assume(caller != VETRO && caller != COUNCIL);
        _Z1(caller, _req(address(0), value, data, dc, TTL));
    }

    function test_Z1c_wrapped_in_executeBefore() public {
        _Z1c(false, uint64(block.timestamp), _req(address(0), 1 ether, "", false, TTL));
        _Z1c(true, uint64(block.timestamp + 1), _req(address(0), 0, hex"deadbeef", true, TTL));
        _Z1c(false, uint64(block.timestamp - 1), _req(address(0), 1 ether, "", false, TTL)); // the deadline first
    }

    function testFuzz_Z1c_wrapped(bool council, uint64 deadline, uint256 value, bytes calldata data, bool dc) public {
        _Z1c(council, deadline, _req(address(0), value, data, dc, TTL));
    }

    function test_Z1d_through_the_timelock_as_the_admin() public {
        _Z1d(_req(address(0), 1 ether, "", false, TTL), true);
    }

    function testFuzz_Z1d_through_the_timelock(address executor, uint256 value, bytes calldata data, bool dc, uint64 ttl) public {
        _Z1d(_req(executor, value, data, dc, ttl), true);
    }

    /// @dev Z2: the table, every class x four shapes x two values x both operations.
    function test_Z2_the_lanes_agree_on_every_class() public {
        for (uint8 c; c < N_CLASSES; ++c) {
            for (uint8 s; s < 4; ++s) {
                _Z2(c, 0, _shape(s), false);
                _Z2(c, 1 ether, _shape(s), false);
                _Z2(c, 0, _shape(s), true);
            }
        }
    }

    function testFuzz_Z2_the_lanes_agree(uint8 c, uint256 value, bytes calldata data, bool dc) public {
        _Z2(c % N_CLASSES, value, data, dc);
    }

    /// @dev Z2, the library with a WELL-FORMED batch: admitted by both lanes when its entries are, refused by both
    ///      (the guard as an entry target) when they are not.
    function test_Z2_a_canonical_library_with_a_well_formed_batch() public {
        bytes memory _entry = abi.encodeCall(MockProtocol.settleDeposit, (1));
        bytes memory _good = abi.encodeWithSelector(MULTISEND, abi.encodePacked(uint8(0), address(venue), uint256(0), _entry.length, _entry));
        Verdicts memory _v;
        _native(_v, LIB, 0, _good, Operation.DelegateCall);
        _approval(_v, LIB, 0, _good, Operation.DelegateCall);
        assertTrue(_v.setOk && _v.n && _v.i && _v.u, "a well-formed policy batch is admitted by both lanes");
        bytes memory _bad = abi.encodeWithSelector(MULTISEND, abi.encodePacked(uint8(0), address(guard), uint256(0), _entry.length, _entry));
        Verdicts memory _w;
        _native(_w, LIB, 0, _bad, Operation.DelegateCall);
        _approval(_w, LIB, 0, _bad, Operation.DelegateCall);
        assertTrue(!_w.n && bytes4(_w.nr) == CuratorGuard.GuardCallNotAllowed.selector, "native: the guard as an entry");
        assertTrue(_w.i && !_w.u, "approval: issued, never usable with the guard as an entry");
    }

    /// @dev The canonical v1.4.1 runtime itself (keccak ecd5bd14…), admitted through the constructor's seeding alone:
    ///      both lanes, the well-formed batch and the zero-target entry.
    function test_Z2_the_canonical_runtime_through_the_constructors_seeding() public {
        vm.etch(CANON, MSCO_V141);
        assertEq(CANON.codehash, 0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939, "the canonical hash");
        assertTrue(guard.isUnwrapperCodehash(CANON.codehash), "seeded by the constructor");
        bytes memory _entry = abi.encodeCall(MockProtocol.settleDeposit, (1));
        bytes memory _good = abi.encodeWithSelector(MULTISEND, abi.encodePacked(uint8(0), address(venue), uint256(0), _entry.length, _entry));
        Verdicts memory _v;
        _native(_v, CANON, 0, _good, Operation.DelegateCall);
        _approval(_v, CANON, 0, _good, Operation.DelegateCall);
        assertTrue(_v.setOk && _v.n && _v.i && _v.u, "both lanes admit the canonical library's well-formed batch");
        bytes memory _zero = abi.encodeWithSelector(MULTISEND, abi.encodePacked(uint8(0), address(0), uint256(1 ether), _entry.length, _entry));
        Verdicts memory _w;
        _native(_w, CANON, 0, _zero, Operation.DelegateCall);
        _approval(_w, CANON, 0, _zero, Operation.DelegateCall);
        assertTrue(_w.setOk && !_w.n && bytes4(_w.nr) == CuratorGuard.MalformedMultiSend.selector, "native: the zero entry");
        assertTrue(_w.i && !_w.u, "approval: issued, never usable with a zero entry");
    }

    function test_Z3_a_zero_target_batch_entry_is_never_usable_in_either_lane() public {
        _Z3(0, "");
        _Z3(1 ether, "");
        _Z3(0, hex"deadbeef");
    }

    function testFuzz_Z3_zero_entry(uint256 value, bytes calldata entry) public {
        _Z3(value, entry);
    }

    function test_Z4_no_setter_admits_the_zero_target() public {
        for (uint8 w; w < 5; ++w) _Z4(w, 0xdeadbeef, true);
    }

    function testFuzz_Z4_setters(uint8 which, bytes4 sel, bool flag) public {
        _Z4(which, sel, flag);
    }
}

contract G22b_ZeroTarget141Test is G22bZeroTargetFuzz {
    function _mk(address owner_) internal override returns (ISafe) {
        return _safe141(owner_);
    }
}

contract G22b_ZeroTarget150Test is G22bZeroTargetFuzz {
    function _mk(address owner_) internal override returns (ISafe) {
        return _safe150(owner_);
    }
}
