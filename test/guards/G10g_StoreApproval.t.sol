// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";

/// @dev g10g evidence test: how many storage writes `approveTransaction` executes (the `_storeApproval`
///      NatSpec claims one `sstore` for the packed record with the member-wise form), with a control
///      showing that `vm.accesses` reports repeated writes to one slot separately.
contract CuratorGuardG10gStoreApproval is CuratorGuardTestBase {
    function test_g10g_count_storage_writes_of_approveTransaction() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.record();
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, 1 days);
        (, bytes32[] memory _writes) = vm.accesses(address(guard));
        emit log_named_uint("storage writes executed by approveTransaction", _writes.length);
        for (uint256 i; i < _writes.length; ++i) emit log_named_bytes32("  slot", _writes[i]);
        assertGt(uint256(guard.approvalExpiry(_id)), 0);
    }

    /// @dev Control: `revokeFunction` deletes the permission record (one write of its packed slot) and then
    ///      writes `generation` into the same slot; a recording that keeps duplicates lists that slot twice.
    function test_g10g_control_duplicate_writes_are_recorded() public {
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        vm.record();
        vm.prank(vetro);
        guard.revokeFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector);
        (, bytes32[] memory _writes) = vm.accesses(address(guard));
        emit log_named_uint("storage writes executed by revokeFunction", _writes.length);
        uint256 _dupes;
        for (uint256 i; i < _writes.length; ++i) {
            for (uint256 j = i + 1; j < _writes.length; ++j) if (_writes[i] == _writes[j]) ++_dupes;
        }
        emit log_named_uint("repeated (slot) pairs among them", _dupes);
        assertGt(_dupes, 0, "duplicates are recorded");
    }
}
