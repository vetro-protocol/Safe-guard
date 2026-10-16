// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {MultiSendCallOnly} from "safe-contracts-v1.4.1/contracts/libraries/MultiSendCallOnly.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {Vm} from "forge-std/Vm.sol";
import {G9cBase} from "test/guards/G9c_Base.sol";

/// @dev Review g15c (the change-impact matrix): how many of a proposer's flood operations (G13f-1) the veto Safe
///      can cancel in ONE MultiSendCallOnly transaction, against the EIP-7825 transaction gas cap of
///      16,777,216 that docs section 7.2 names since G13c-1. Measured on g9c's production topology (real Safe
///      v1.4.1 proxies, a real CuratorGuardTimelock).
contract G15c_CancelGasTest is G9cBase {
    MultiSendCallOnly internal ms;

    function setUp() public override {
        super.setUp();
        ms = new MultiSendCallOnly();
    }

    function _flood(uint256 n_) internal returns (bytes32[] memory _ids) {
        _ids = new bytes32[](n_);
        bytes memory _junk = abi.encodeCall(g.enforce, (address(curatorSafe)));
        for (uint256 i; i < n_; ++i) _ids[i] = _schedule(p1, p1Pk, address(g), _junk, NONE, bytes32(i + 1));
    }

    /// @dev One allocation, linear in `ids_` (a `bytes.concat` loop would be quadratic in the TEST frame and
    ///      pollute the measurement with the test's own memory expansion).
    function _pack(bytes32[] memory ids_) internal view returns (bytes memory _packed) {
        uint256 _entry = 1 + 20 + 32 + 32 + 36;
        _packed = new bytes(ids_.length * _entry);
        bytes4 _sel = tl.cancel.selector;
        address _t = address(tl);
        for (uint256 i; i < ids_.length; ++i) {
            bytes memory _e = abi.encodePacked(uint8(0), _t, uint256(0), uint256(36), _sel, ids_[i]);
            uint256 _off = i * _entry;
            for (uint256 j; j < _entry; ++j) _packed[_off + j] = _e[j];
        }
    }

    /// @dev The gas of the `execTransaction` call itself (`vm.lastCallGas`, the last external call the helper
    ///      makes) plus the transaction's intrinsic gas (21,000 and the calldata's 16 / 4 per byte): what a real
    ///      transaction's gas limit must cover, which EIP-7825 caps at 16,777,216.
    function _cancelBatchGas(bytes32[] memory ids_) internal returns (uint256 _used) {
        bytes memory _data = abi.encodeCall(ms.multiSend, (_pack(ids_)));
        bool _ok = _exec(veto, vetoPk, address(ms), 0, _data, Operation.DelegateCall);
        Vm.Gas memory _g = vm.lastCallGas();
        assertTrue(_ok, "batched cancel landed");
        for (uint256 i; i < ids_.length; ++i) assertFalse(tl.isOperationPending(ids_[i]), "cancelled");
        // Intrinsic gas of the execTransaction calldata: the packed entries dominate; the rest (selector, nine
        // head words, the signature) is about 500 bytes.
        uint256 _nonzero;
        uint256 _zero;
        for (uint256 i; i < _data.length; ++i) if (_data[i] == 0) ++_zero; else ++_nonzero;
        _used = _g.gasTotalUsed + 21_000 + 16 * (_nonzero + 500) + 4 * _zero;
    }

    function test_g15c_cancel_batch_gas_against_the_transaction_cap() public {
        _configureCurator();
        uint256[7] memory _sizes = [uint256(1), 50, 150, 400, 800, 1600, 3200];
        uint256 _cap = 16_777_216;
        uint256 _lastUnder;
        uint256 _lastUnderGas;
        uint256 _firstOver;
        uint256 _firstOverGas;
        for (uint256 k; k < _sizes.length; ++k) {
            bytes32[] memory _ids = _flood(_sizes[k]);
            uint256 _gas = _cancelBatchGas(_ids);
            emit log_named_uint(string.concat("cancels in one MultiSendCallOnly: ", vm.toString(_sizes[k]), " -> gas"), _gas);
            if (_gas <= _cap) {
                _lastUnder = _sizes[k];
                _lastUnderGas = _gas;
            } else if (_firstOver == 0) {
                _firstOver = _sizes[k];
                _firstOverGas = _gas;
            }
        }
        // Linear interpolation between the last batch under the cap and the first above it.
        uint256 _fit = _lastUnder + ((_cap - _lastUnderGas) * (_firstOver - _lastUnder)) / (_firstOverGas - _lastUnderGas);
        emit log_named_uint("cancels that fit under EIP-7825 (16,777,216) in ONE transaction, interpolated", _fit);
        emit log_named_uint("marginal gas per cancel between the two largest batches", (_firstOverGas - _lastUnderGas) / (_firstOver - _lastUnder));
        assertGt(_firstOver, 0, "a flood of 3200 exceeds the transaction cap in one batch");
        assertLt(_fit, 4000, "a flood larger than this needs several veto transactions");
    }
}
