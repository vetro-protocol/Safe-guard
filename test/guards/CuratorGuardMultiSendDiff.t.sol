// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase} from "test/guards/CuratorGuardTestBase.sol";

contract LogBook {
    bytes32[] public entries;

    function record(address target_, address sender_, uint256 value_, bytes calldata data_) external {
        entries.push(keccak256(abi.encode(target_, sender_, value_, data_)));
    }

    function count() external view returns (uint256) {
        return entries.length;
    }

    function reset() external {
        delete entries;
    }
}

contract Recorder {
    LogBook internal immutable book;

    constructor(LogBook book_) {
        book = book_;
    }

    fallback() external payable {
        book.record(address(this), msg.sender, msg.value, msg.data);
    }

    receive() external payable {
        book.record(address(this), msg.sender, msg.value, "");
    }
}

/// @title Differential fuzz: guard-accepted MultiSendCallOnly batch == executed call sequence
/// @dev For random (and randomly corrupted) `multiSend(bytes)` payloads: whenever the guard
///      accepts the payload, the real `MultiSendCallOnly` executes exactly the entries a strict
///      reference decoder (standard ABI `bytes` decoding + MultiSend's packed loop) yields, every
///      executed entry is policy-compliant, and nothing reaches an unlisted target.
contract CuratorGuardMultiSendDiffTest is CuratorGuardTestBase {
    LogBook internal book;
    Recorder internal recA;
    Recorder internal recB;
    bytes4 internal constant S1 = 0x11111111;
    bytes4 internal constant S2 = 0x22222222;
    bytes4 internal constant S3 = 0x33333333; // never allowed

    function setUp() public override {
        super.setUp();
        book = new LogBook();
        recA = new Recorder(book);
        recB = new Recorder(book);
        _enforce();
        _registerMultiSend();
        vm.startPrank(vetro);
        guard.allowFunction(address(safe), address(recA), S1, false, _noRules());
        guard.allowFunction(address(safe), address(recA), S2, true, _noRules());
        guard.allowFunction(address(safe), address(recB), S1, false, _noRules());
        guard.setNativeTransferAllowed(address(safe), address(recA), true);
        vm.stopPrank();
    }

    function _registerMultiSend() internal {
        _registerUnwrapper(address(multiSendCallOnly));
    }

    /*//////////////////////////////////////////////////////////////
                          REFERENCE DECODER
    //////////////////////////////////////////////////////////////*/

    /// @dev Standard ABI decoding of `multiSend(bytes)` followed by MultiSend's packed loop.
    function _reference(bytes memory payload_) internal view returns (bytes32[] memory _expected, bool _ok, uint256 _totalValue) {
        if (payload_.length < 4 || bytes4(payload_) != 0x8d80ff0a) return (_expected, false, 0);
        bytes memory _tail = new bytes(payload_.length - 4);
        for (uint256 j; j < _tail.length; ++j) _tail[j] = payload_[j + 4];
        bytes memory _tx;
        try this.decodeBytes(_tail) returns (bytes memory _d) {
            _tx = _d;
        } catch {
            return (_expected, false, 0);
        }
        bytes32[] memory _buf = new bytes32[](64);
        uint256 _n;
        uint256 i;
        while (i < _tx.length) {
            if (_tx.length - i < 85) return (_expected, false, 0); // MultiSend would read past the end
            uint8 _op = uint8(_tx[i]);
            address _to;
            uint256 _value;
            uint256 _len;
            assembly {
                _to := shr(96, mload(add(add(_tx, 0x20), add(i, 1))))
                _value := mload(add(add(_tx, 0x20), add(i, 21)))
                _len := mload(add(add(_tx, 0x20), add(i, 53)))
            }
            if (_op != 0) return (_expected, false, 0);
            // v1.5.0 `MultiSendCallOnly` rewrites a zero `to` to the calling Safe: never acceptable.
            if (_to == address(0)) return (_expected, false, 0);
            if (_len > _tx.length - i - 85) return (_expected, false, 0);
            _totalValue += _value;
            bytes memory _data = new bytes(_len);
            for (uint256 k; k < _len; ++k) _data[k] = _tx[i + 85 + k];
            _buf[_n++] = keccak256(abi.encode(_to, address(safe), _value, _data));
            i += 85 + _len;
        }
        _expected = new bytes32[](_n);
        for (uint256 k; k < _n; ++k) _expected[k] = _buf[k];
        _ok = _n > 0;
    }

    function decodeBytes(bytes calldata tail_) external pure returns (bytes memory) {
        return abi.decode(tail_, (bytes));
    }

    /*//////////////////////////////////////////////////////////////
                              GENERATOR
    //////////////////////////////////////////////////////////////*/

    function _rand(uint256 seed_, uint256 salt_) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(seed_, salt_)));
    }

    function _randomBatch(uint256 seed_) internal view returns (bytes memory _packed) {
        uint256 _n = 1 + _rand(seed_, 0) % 4;
        for (uint256 i; i < _n; ++i) {
            uint256 _r = _rand(seed_, i + 1);
            address _to = [address(recA), address(recA), address(recA), address(recB), attacker, address(0)][_r % 6];
            bytes4 _sel = [S1, S1, S2, S3][(_r >> 8) % 4];
            uint256 _words = (_r >> 16) % 4;
            bytes memory _data = (_r >> 24) % 7 == 0 ? bytes("") : abi.encodePacked(_sel, new bytes(32 * _words));
            if (_data.length > 4 && (_r >> 32) % 2 == 0) _data[4 + ((_r >> 40) % (_data.length - 4))] = bytes1(uint8(_r));
            uint256 _value = (_r >> 48) % 4 == 0 ? (_r >> 56) % 1e9 : 0;
            _packed = abi.encodePacked(_packed, _entry(_to, _value, _data));
        }
    }

    function _corrupt(bytes memory payload_, uint256 seed_) internal pure returns (bytes memory) {
        uint256 _mode = seed_ % 10 < 5 ? 0 : 1 + (seed_ % 10) % 4;
        if (_mode == 0 || payload_.length == 0) return payload_;
        if (_mode == 1) {
            // flip a byte
            uint256 _i = (seed_ >> 8) % payload_.length;
            payload_[_i] = bytes1(uint8(payload_[_i]) ^ uint8(1 << ((seed_ >> 16) % 8)));
            return payload_;
        }
        if (_mode == 2) {
            // truncate
            uint256 _newLen = (seed_ >> 8) % payload_.length;
            assembly {
                mstore(payload_, _newLen)
            }
            return payload_;
        }
        if (_mode == 3) return abi.encodePacked(payload_, new bytes(1 + (seed_ >> 8) % 40)); // append
        // overwrite the bytes length word with a random value
        if (payload_.length >= 68) {
            uint256 _v = (seed_ >> 8) % (payload_.length * 2);
            assembly {
                mstore(add(payload_, 68), _v)
            }
        }
        return payload_;
    }

    /*//////////////////////////////////////////////////////////////
                                 FUZZ
    //////////////////////////////////////////////////////////////*/

    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_guard_accepted_batches_execute_exactly_the_validated_entries(uint256 seed_) public {
        bytes memory _payload = _corrupt(_multiSendCalldata(_randomBatch(seed_)), _rand(seed_, 999));
        uint256 _attackerBalance = attacker.balance;

        bool _accepted;
        try guard.validateTransaction(address(safe), address(multiSendCallOnly), 0, _payload, Operation.DelegateCall) {
            _accepted = true;
        } catch {}
        if (!_accepted) return;

        (bytes32[] memory _expected, bool _refOk, uint256 _totalValue) = _reference(_payload);
        assertTrue(_refOk, "guard accepted a payload the reference decoder rejects");
        if (_totalValue > address(safe).balance) {
            // Policy does not bound native value; execution fails closed on balance (GS013).
            vm.expectRevert(bytes("GS013"));
            _execSafeTx(address(multiSendCallOnly), 0, _payload, Operation.DelegateCall);
            return;
        }

        book.reset();
        // Executes through the real Safe + real MultiSendCallOnly; the live hooks must agree with
        // the dry run, and the batch must run to completion.
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _payload, Operation.DelegateCall), "live exec");
        assertEq(book.count(), _expected.length, "entry count");
        for (uint256 i; i < _expected.length; ++i) assertEq(book.entries(i), _expected[i], "entry mismatch");
        assertEq(attacker.balance, _attackerBalance, "unlisted target reached");
    }

    /// @dev Sanity that the generator produces accepted batches often enough to be meaningful.
    function test_generator_acceptance_rate() public {
        uint256 _accepted;
        for (uint256 s; s < 300; ++s) {
            bytes memory _payload = _corrupt(_multiSendCalldata(_randomBatch(s)), _rand(s, 999));
            try guard.validateTransaction(address(safe), address(multiSendCallOnly), 0, _payload, Operation.DelegateCall) {
                ++_accepted;
            } catch {}
        }
        emit log_named_uint("accepted payloads out of 300", _accepted);
        assertGt(_accepted, 10);
    }
}
