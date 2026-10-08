// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @title Round 9 (g9f): the strict `multiSend(bytes)` decoder in the two modes the repository's
///        differential fuzz leaves out, the council window (`ENTRY_COUNCIL`) and an approved batch
///        (`ENTRY_APPROVED`), plus the canonical-encoding identity every mode shares.
/// @dev Reference, from docs section 4: a batch is accepted only when it is the canonical ABI encoding
///      of `multiSend(bytes)` (standard decoding followed by re-encoding gives the same bytes), holds at
///      least one entry, every entry is a plain call to a non-zero address whose declared length fits;
///      in a council window every entry must in addition keep off the guard and, when it addresses the
///      Safe, be on the council's self-call allowlist (section 4, "council"); an approved batch keeps
///      every entry off the guard and checks nothing else.
contract CuratorGuardG9fMultiSendFuzzTest is CuratorGuardTestBase {
    bytes4 internal constant ADD_OWNER = 0x0d582f13;
    bytes4 internal constant REMOVE_OWNER = 0xf8dc5dd9;
    bytes4 internal constant SWAP_OWNER = 0xe318b52b;
    bytes4 internal constant CHANGE_THRESHOLD = 0x694e80c3;
    bytes4 internal constant DISABLE_MODULE = 0xe009cfde;
    bytes4 internal constant SET_FALLBACK_HANDLER = 0xf08a0323;

    address internal key = makeAddr("plain-key");

    function setUp() public override {
        super.setUp();
        _registerUnwrapper(address(multiSendCallOnly));
    }

    /*//////////////////////////////////////////////////////////////
                                REFERENCE
    //////////////////////////////////////////////////////////////*/

    struct Entry {
        address to;
        uint256 value;
        bytes data;
    }

    function decodeBytes(bytes calldata tail_) external pure returns (bytes memory) {
        return abi.decode(tail_, (bytes));
    }

    /// @dev Docs section 4: selector, head offset `0x20`, `calldata.length == 68 + ceil32(length)`
    ///      (the padding bytes themselves are not inspected: see `test_non_zero_padding_bytes_are_inert`),
    ///      then MultiSend's packed loop (op 0, non-zero `to`, length fits), at least one entry.
    function _reference(bytes memory payload_) internal view returns (bool _ok, Entry[] memory _entries) {
        if (payload_.length < 68 || bytes4(payload_) != 0x8d80ff0a) return (false, _entries);
        if (_word(payload_, 4) != bytes32(uint256(0x20))) return (false, _entries);
        uint256 _len = uint256(_word(payload_, 36));
        if (_len > payload_.length || payload_.length != 68 + ((_len + 31) / 32) * 32) return (false, _entries);
        bytes memory _tail = new bytes(payload_.length - 4);
        for (uint256 j; j < _tail.length; ++j) _tail[j] = payload_[j + 4];
        bytes memory _tx;
        try this.decodeBytes(_tail) returns (bytes memory _d) {
            _tx = _d;
        } catch {
            return (false, _entries);
        }
        if (_tx.length != _len) return (false, _entries);
        Entry[] memory _buf = new Entry[](64);
        uint256 _n;
        uint256 i;
        while (i < _tx.length) {
            if (_tx.length - i < 85) return (false, _entries);
            uint8 _op = uint8(_tx[i]);
            address _to;
            uint256 _value;
            uint256 _len;
            assembly {
                _to := shr(96, mload(add(add(_tx, 0x20), add(i, 1))))
                _value := mload(add(add(_tx, 0x20), add(i, 21)))
                _len := mload(add(add(_tx, 0x20), add(i, 53)))
            }
            if (_op != 0 || _to == address(0) || _len > _tx.length - i - 85) return (false, _entries);
            bytes memory _data = new bytes(_len);
            for (uint256 k; k < _len; ++k) _data[k] = _tx[i + 85 + k];
            _buf[_n++] = Entry(_to, _value, _data);
            i += 85 + _len;
        }
        _entries = new Entry[](_n);
        for (uint256 k; k < _n; ++k) _entries[k] = _buf[k];
        _ok = _n > 0;
    }

    /// @dev Section 4 "council": the self-calls the council may authorise, by payload.
    function _councilAllowsSelfCall(bytes memory d_) internal view returns (bool) {
        if (d_.length == 0) return true;
        if (d_.length < 4) return false;
        bytes4 _sel = bytes4(d_);
        if (_sel == SET_FALLBACK_HANDLER) return d_.length == 36 && _word(d_, 4) == bytes32(0);
        if (_sel == DISABLE_MODULE) return true;
        if (_sel == SWAP_OWNER) return d_.length >= 100 && _plainKey(_word(d_, 68));
        if (_sel == CHANGE_THRESHOLD) return d_.length >= 36 && uint256(_word(d_, 4)) >= 2;
        if (_sel == ADD_OWNER) return d_.length >= 68 && uint256(_word(d_, 36)) >= 2 && _plainKey(_word(d_, 4));
        if (_sel == REMOVE_OWNER) return d_.length >= 100 && uint256(_word(d_, 68)) >= 2;
        return false;
    }

    function _plainKey(bytes32 w_) internal view returns (bool) {
        address _a = address(uint160(uint256(w_)));
        return uint160(_a) > 0xffff && _a.code.length == 0;
    }

    function _word(bytes memory d_, uint256 at_) internal pure returns (bytes32 _w) {
        assembly {
            _w := mload(add(add(d_, 0x20), at_))
        }
    }

    /*//////////////////////////////////////////////////////////////
                                GENERATOR
    //////////////////////////////////////////////////////////////*/

    function _rand(uint256 seed_, uint256 salt_) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(seed_, salt_)));
    }

    /// @dev Entries aimed at a venue, the Safe (self-call payloads on both sides of the council
    ///      allowlist, well-formed and short), the guard and a key; some with value.
    function _randomBatch(uint256 seed_) internal view returns (bytes memory _packed) {
        uint256 _n = 1 + _rand(seed_, 0) % 4;
        for (uint256 i; i < _n; ++i) {
            uint256 _r = _rand(seed_, i + 1);
            uint256 _kind = _r % 12;
            address _to;
            bytes memory _data;
            if (_kind < 3) {
                _to = address(protocol);
                _data = abi.encodeCall(MockProtocol.settleDeposit, (_r >> 8));
            } else if (_kind == 3) {
                _to = address(guard);
                _data = abi.encodeCall(CuratorGuardPolicy.lockdown, (address(safe)));
            } else if (_kind == 4) {
                _to = attacker;
                _data = "";
            } else {
                _to = address(safe);
                _data = _selfCallPayload(_r >> 8);
            }
            uint256 _value = (_r >> 200) % 5 == 0 ? (_r >> 208) % 1e9 : 0;
            _packed = abi.encodePacked(_packed, _entry(_to, _value, _data));
        }
    }

    function _selfCallPayload(uint256 r_) internal view returns (bytes memory) {
        uint256 _k = r_ % 14;
        if (_k == 0) return "";
        if (_k == 1) return abi.encodeWithSelector(ADD_OWNER, key, uint256(2));
        if (_k == 2) return abi.encodeWithSelector(ADD_OWNER, key, uint256(1));
        if (_k == 3) return abi.encodeWithSelector(ADD_OWNER, address(protocol), uint256(2));
        if (_k == 4) return abi.encodeWithSelector(CHANGE_THRESHOLD, uint256(2 + (r_ >> 8) % 3));
        if (_k == 5) return abi.encodeWithSelector(CHANGE_THRESHOLD, uint256((r_ >> 8) % 2));
        if (_k == 6) return abi.encodeWithSelector(SET_FALLBACK_HANDLER, address(0));
        if (_k == 7) return abi.encodeWithSelector(SET_FALLBACK_HANDLER, attacker);
        if (_k == 8) return abi.encodeWithSelector(DISABLE_MODULE, address(1), attacker);
        if (_k == 9) return abi.encodeWithSelector(SWAP_OWNER, address(1), curator, key);
        if (_k == 10) return abi.encodeWithSelector(SWAP_OWNER, address(1), curator, address(0x4));
        if (_k == 11) return abi.encodeCall(ISafe.setGuard, (address(0)));
        if (_k == 12) return abi.encodePacked(ADD_OWNER, bytes32(uint256(uint160(key))), bytes31(0)); // one byte short
        return hex"0d58";
    }

    function _corrupt(bytes memory payload_, uint256 seed_) internal pure returns (bytes memory) {
        uint256 _mode = seed_ % 10 < 5 ? 0 : 1 + (seed_ % 10) % 4;
        if (_mode == 0 || payload_.length == 0) return payload_;
        if (_mode == 1) {
            uint256 _i = (seed_ >> 8) % payload_.length;
            payload_[_i] = bytes1(uint8(payload_[_i]) ^ uint8(1 << ((seed_ >> 16) % 8)));
            return payload_;
        }
        if (_mode == 2) {
            uint256 _newLen = (seed_ >> 8) % payload_.length;
            assembly {
                mstore(payload_, _newLen)
            }
            return payload_;
        }
        if (_mode == 3) return abi.encodePacked(payload_, new bytes(1 + (seed_ >> 8) % 40));
        if (payload_.length >= 68) {
            uint256 _v = (seed_ >> 8) % (payload_.length * 2);
            assembly {
                mstore(add(payload_, 68), _v)
            }
        }
        return payload_;
    }

    function _dryRun(bytes memory payload_) internal view returns (bool _ok, bytes memory _err) {
        try guard.validateTransaction(address(safe), address(multiSendCallOnly), 0, payload_, Operation.DelegateCall) {
            _ok = true;
        } catch (bytes memory _e) {
            _err = _e;
        }
    }

    /*//////////////////////////////////////////////////////////////
                                  FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @dev Council window: accepted iff canonical and every entry is off the guard and, when a
    ///      self-call, on the council's allowlist. The live hook agrees with the dry run.
    /// forge-config: default.fuzz.runs = 2000
    function testFuzz_council_window_batches_match_the_reference(uint256 seed_) public {
        vm.prank(council);
        guard.bypass(address(safe), 1 days);
        bytes memory _payload = _corrupt(_multiSendCalldata(_randomBatch(seed_)), _rand(seed_, 999));
        (bool _canonical, Entry[] memory _entries) = _reference(_payload);
        bool _expected = _canonical;
        for (uint256 i; _expected && i < _entries.length; ++i) {
            if (_entries[i].to == address(guard)) _expected = false;
            else if (_entries[i].to == address(safe)) _expected = _councilAllowsSelfCall(_entries[i].data);
        }
        (bool _ok, bytes memory _err) = _dryRun(_payload);
        assertEq(_ok, _expected, "council window: dry run == reference");
        if (_ok) {
            if (_totalValue(_entries) > address(safe).balance) return; // GS013 on balance, not a policy matter
            uint256 _ownersBefore = safe.getOwners().length;
            bool _changesOwners = _touchesOwners(_entries);
            try this.execBatch(_payload) returns (bool _live) {
                assertTrue(_live, "live hook passes what the dry run passes");
            } catch (bytes memory _e) {
                // The Safe itself may refuse the inner calls (GS013: an owner op on a wrong list, a
                // threshold above the owner count, a module that is not enabled); never the guard.
                assertEq(_e, abi.encodeWithSignature("Error(string)", "GS013"), "only the Safe's GS013, never a guard error");
            }
            if (!_changesOwners) assertEq(safe.getOwners().length, _ownersBefore);
        } else {
            vm.expectRevert(_err);
            _execSafeTx(address(multiSendCallOnly), 0, _payload, Operation.DelegateCall);
        }
    }

    /// @dev Approved batch (admin approval of the delegatecall into the canonical build): accepted iff
    ///      canonical and no entry addresses the guard; self-calls and strangers are the approval's business.
    /// forge-config: default.fuzz.runs = 2000
    function testFuzz_approved_batches_match_the_reference(uint256 seed_) public {
        bytes memory _payload = _corrupt(_multiSendCalldata(_randomBatch(seed_)), _rand(seed_, 999));
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(multiSendCallOnly), 0, _payload, Operation.DelegateCall, 1 days);
        (bool _canonical, Entry[] memory _entries) = _reference(_payload);
        bool _expected = _canonical;
        for (uint256 i; _expected && i < _entries.length; ++i) if (_entries[i].to == address(guard)) _expected = false;
        (bool _ok, bytes memory _err) = _dryRun(_payload);
        assertEq(_ok, _expected, "approved batch: dry run == reference");
        assertGt(guard.approvalExpiry(_id), 0, "the dry run never spends the approval");
        if (!_ok) {
            vm.expectRevert(_err);
            _execSafeTx(address(multiSendCallOnly), 0, _payload, Operation.DelegateCall);
            assertGt(guard.approvalExpiry(_id), 0, "a refused batch keeps its approval");
            // Refused for a reason the decoder names, never the policy.
            bytes4 _sel = bytes4(_err);
            assertTrue(
                _sel == CuratorGuard.MalformedMultiSend.selector ||
                    _sel == CuratorGuard.EmptyMultiSend.selector ||
                    _sel == CuratorGuard.MultiSendDelegateCallEntry.selector ||
                    _sel == CuratorGuard.GuardCallNotAllowed.selector,
                "decoder error"
            );
        }
    }

    /// @dev External so the live execution can be caught (the Safe bubbles the guard's error).
    function execBatch(bytes memory payload_) external returns (bool) {
        return _execSafeTx(address(multiSendCallOnly), 0, payload_, Operation.DelegateCall);
    }

    function _totalValue(Entry[] memory e_) internal pure returns (uint256 _v) {
        for (uint256 i; i < e_.length; ++i) _v += e_[i].value;
    }

    function _touchesOwners(Entry[] memory e_) internal view returns (bool) {
        for (uint256 i; i < e_.length; ++i) {
            if (e_[i].to == address(safe) && e_[i].data.length >= 4) {
                bytes4 _s = bytes4(e_[i].data);
                if (_s == ADD_OWNER || _s == REMOVE_OWNER || _s == SWAP_OWNER) return true;
            }
        }
        return false;
    }

    /// @dev Observation (Info): the decoder checks the padded LENGTH, not the padding bytes, so up to 31
    ///      non-zero bytes can ride inside the ABI padding of an accepted batch. `MultiSendCallOnly` reads
    ///      `length` bytes and never looks at them, so they are inert; a strictly canonical ABI encoding
    ///      would be refused by a decoder that re-encodes. Pinned so a change is a conscious one.
    function test_non_zero_padding_bytes_are_inert() public {
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        bytes memory _packed = _entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (7))); // 121 bytes
        bytes memory _batch = _multiSendCalldata(_packed);
        assertEq(_batch.length, 68 + 128, "seven padding bytes");
        for (uint256 i = 68 + _packed.length; i < _batch.length; ++i) _batch[i] = 0xff;
        guard.validateTransaction(address(safe), address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall));
        assertEq(protocol.lastAmount(), 7, "the padding changed nothing");
        // One byte more than the padding allows is a trailing byte, refused.
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        guard.validateTransaction(address(safe), address(multiSendCallOnly), 0, abi.encodePacked(_batch, bytes1(0xff)), Operation.DelegateCall);
    }

    /// @dev Sanity: the generator reaches the accept branch often enough in both modes.
    function test_generator_reaches_accepted_batches_in_both_modes() public {
        uint256 _accepted;
        vm.prank(council);
        guard.bypass(address(safe), 1 days);
        for (uint256 s; s < 200; ++s) {
            (bool _ok, ) = _dryRun(_corrupt(_multiSendCalldata(_randomBatch(s)), _rand(s, 999)));
            if (_ok) ++_accepted;
        }
        emit log_named_uint("council window: accepted out of 200", _accepted);
        assertGt(_accepted, 10);
    }
}
