// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G11dModule} from "test/guards/G11d_PeerVectors.t.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

/// @dev A venue that reverts with a guard error selector of its own making (naming the caller).
contract G11dGuardShapedReverter {
    function poke() external view {
        bytes memory _data = abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, msg.sender);
        assembly {
            revert(add(_data, 0x20), mload(_data))
        }
    }
}

/// @title Round 11 (g11d): documented behaviours and limitations no suite pinned (Safe v1.4.1).
contract G11dPinsTest is CuratorGuardTestBase {
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;

    /// @dev Section 6 "Snapshot scope" and 7.3: the digest covers the modules HEAD; an entry planted directly
    ///      in the `modules` mapping (an old delegatecall, a `setup` initializer) is invisible to every view
    ///      and to the digest, the policy path keeps running next to it, and on v1.3.0 / v1.4.1 (no module
    ///      hook) the planted module executes unguarded, `setGuard(0)` included. Pinned as the documented
    ///      limitation the pre-install log checks of 7.3 exist for.
    function test_snapshot_scope_a_module_entry_planted_behind_the_head_is_invisible_and_unguarded_on_v141() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        G11dModule _planted = new G11dModule();
        // `modules[planted] = SENTINEL` without touching `modules[SENTINEL]` (the head): mapping slot 1.
        vm.store(address(safe), keccak256(abi.encode(address(_planted), uint256(1))), bytes32(uint256(1)));
        assertTrue(safe.isModuleEnabled(address(_planted)), "the Safe honours the planted entry");
        (address[] memory _listed, ) = safe.getModulesPaginated(address(1), 10);
        assertEq(_listed.length, 0, "the list view shows nothing");

        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call), "policy path unaffected");
        assertTrue(_planted.exec(safe, address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call), "unguarded module path");
        assertEq(_installedGuard(), address(0), "the guard is gone, silently");
    }

    /// @dev Section 6 "Seats with code": the Safe counts an owner's ECDSA signature whether or not the owner
    ///      address carries code, and nothing in the hooks reads owner code, so an owner that acquires code
    ///      after it was vetted keeps signing policy transactions (the 7.7 alert is the control).
    function test_seats_with_code_an_owner_that_acquires_code_after_vetting_still_signs_through_the_policy() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        vm.etch(curator, hex"60006000fd"); // a contract at the owner's address (a counterfactual deployment)
        assertGt(curator.code.length, 0);
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (2)), Operation.Call));
        assertEq(protocol.lastAmount(), 2);
    }
}

/// @title Round 11 (g11d): two runbook claims on Safe v1.5.0 no suite pinned.
contract G11dPinsV150Test is SafeTxHelper {
    CuratorGuard internal guard;
    MockProtocol internal protocol;
    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal curator;

    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 internal constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    function setUp() public {
        vm.warp(1_700_000_000);
        (curator, signerPk) = makeAddrAndKey("curator");
        Safe150 _singleton = new Safe150();
        SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        safe = ISafe(address(_proxy));
        guard = new CuratorGuardHarness(0, vetro, council);
        CuratorGuardHarness(address(guard)).seedSafe(address(safe));
        protocol = new MockProtocol();
        vm.startPrank(address(safe));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        vm.stopPrank();
        vm.prank(vetro);
        guard.enforce(address(safe));
    }

    function _slot(bytes32 slot_) internal view returns (address) {
        return address(uint160(uint256(bytes32(safe.getStorageAt(uint256(slot_), 1)))));
    }

    /// @dev 7.8: "On Safe v1.5.0 a venue's revert data is bubbled unchanged and can carry a guard error selector
    ///      although the guard passed the transaction: confirm with `validateTransaction` or a trace."
    function test_v150_bubbles_a_venues_guard_shaped_revert_although_the_guard_passed() public {
        G11dGuardShapedReverter _venue = new G11dGuardShapedReverter();
        CuratorGuardPolicy.ParamRule[] memory _none;
        vm.prank(vetro);
        guard.allowFunction(address(safe), address(_venue), G11dGuardShapedReverter.poke.selector, false, _none);
        bytes memory _data = abi.encodeCall(G11dGuardShapedReverter.poke, ());
        guard.validateTransaction(address(safe), address(_venue), 0, _data, Operation.Call); // the guard passes it
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(_venue), 0, _data, Operation.Call); // the Safe bubbles the venue's bytes
        assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Enforced), "the Safe was never locked down");
    }

    /// @dev 7.5 "Replace the guard" on v1.5.0: "the swap is TWO slots, and each self-call is checked by whichever
    ///      guard sits in the transaction-guard slot at that moment": with `setGuard(new)` executed first and
    ///      alone, the `setModuleGuard(new)` that follows is checked by the NEW guard (here unconfigured, so
    ///      `SafeLockedDown`), an approval of it on the old guard is a stray, and the module path stays on the
    ///      old guard until an approval on the new one lands.
    function test_v150_swap_executed_slot_by_slot_leaves_the_second_self_call_to_the_new_guard() public {
        CuratorGuard _next = new CuratorGuardHarness(0, vetro, council);
        CuratorGuardHarness(address(_next)).seedSafe(address(safe));
        bytes memory _setGuard = abi.encodeCall(ISafe.setGuard, (address(_next)));
        bytes memory _setModuleGuard = abi.encodeCall(ISafe.setModuleGuard, (address(_next)));
        vm.startPrank(vetro);
        guard.approveTransaction(address(safe), address(0), address(safe), 0, _setGuard, Operation.Call, 1 days);
        bytes32 _stray = guard.approveTransaction(address(safe), address(0), address(safe), 0, _setModuleGuard, Operation.Call, 1 days);
        vm.stopPrank();
        assertTrue(_execSafeTx(address(safe), 0, _setGuard, Operation.Call));
        assertEq(_slot(GUARD_SLOT), address(_next));
        assertEq(_slot(MODULE_GUARD_SLOT), address(guard), "module path still on the old guard");

        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(safe), 0, _setModuleGuard, Operation.Call); // checked by `_next`, which is in Lockdown
        assertGt(guard.approvalExpiry(_stray), 0, "the approval on the old guard is a stray nobody can use");

        vm.prank(vetro);
        _next.approveTransaction(address(safe), address(0), address(safe), 0, _setModuleGuard, Operation.Call, 1 days);
        assertTrue(_execSafeTx(address(safe), 0, _setModuleGuard, Operation.Call));
        assertEq(_slot(MODULE_GUARD_SLOT), address(_next), "both slots moved");
    }
}
