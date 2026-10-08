// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

/// @dev A venue that happens to expose the Safe's `setGuard(address)` selector (0xe19a9dd9).
contract GuardSelectorVenue {
    address public last;

    function setGuard(address a_) external {
        last = a_;
    }
}

contract PassThroughModule {
    function exec(ISafe safe_, address to_, uint256 value_, bytes calldata data_, Operation op_) external returns (bool) {
        return safe_.execTransactionFromModule(to_, value_, data_, op_);
    }
}

/// @title Mutation killers (review round 2 of v2): each test was verified to kill at least one
///        otherwise surviving mutant of the v2 logic (docs/curator-guard.md §13.2, V2-27).
contract CuratorGuardMutationTest is CuratorGuardTestBase {
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;

    /// @dev M42: the LIVE hook (not only the dry run) accepts an approval at exactly its expiry.
    function test_live_hook_accepts_approval_at_exactly_its_expiry() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        uint64 _ttl = 1 hours;
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, _ttl);
        uint64 _expiry = guard.approvalExpiry(_id);
        assertEq(_expiry, uint64(block.timestamp) + _ttl);
        vm.warp(_expiry); // exactly the expiry second
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call), "live hook at expiry");
        assertEq(guard.approvalExpiry(_id), 0, "consumed");
        // One second after its expiry a fresh approval is dead on the live hook too.
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, _ttl);
        vm.warp(block.timestamp + _ttl + 1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, _data, Operation.Call);
    }

    /// @dev M28 / M29 / M71: every term of `AdminIsGuarded` on its own.
    function test_admin_is_guarded_for_each_configured_component_alone() public {
        address _a = makeAddr("safe-a"); // Lockdown, nothing but ONE allowed function
        vm.prank(vetro);
        guard.allowFunction(_a, address(protocol), SETTLE, false, _noRules());
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, _a));
        guard.beginDefaultAdminTransfer(_a);
        address _b = makeAddr("safe-b"); // nothing but a native-transfer permission
        vm.prank(vetro);
        guard.setNativeTransferAllowed(_b, address(protocol), true);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, _b));
        guard.beginDefaultAdminTransfer(_b);
        address _c = makeAddr("safe-c"); // nothing but a fallback-handler requirement
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(_c, address(0), true);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, _c));
        guard.beginDefaultAdminTransfer(_c);
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(_c, address(0), false); // switched off again: unconfigured
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(_c);
        (address _pending, ) = guard.pendingDefaultAdmin();
        assertEq(_pending, _c);
        address _d = makeAddr("safe-d"); // nothing but a (then expired) Bypass window
        vm.prank(council);
        guard.bypass(_d, 1 days);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, _d));
        guard.beginDefaultAdminTransfer(_d);
        // Round 6 (V2-72): the EFFECTIVE mode is read. An expired window is forensics, not a
        // configuration: the council cannot keep the hand-over blocked after its window ran out.
        vm.warp(block.timestamp + 2 days);
        assertEq(uint8(guard.mode(_d)), uint8(CuratorGuardPolicy.Mode.Lockdown));
        (uint64 _until, bool _byCouncil) = guard.bypassWindow(_d);
        assertTrue(_until != 0 && _byCouncil, "the raw window is still readable");
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(_d);
        (_pending, ) = guard.pendingDefaultAdmin();
        assertEq(_pending, _d);
        // A LIVE window still refuses, and an explicit lockdown clears it.
        address _e = makeAddr("safe-e");
        vm.prank(council);
        guard.bypass(_e, 1 days);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, _e));
        guard.beginDefaultAdminTransfer(_e);
        vm.prank(council);
        guard.lockdown(_e);
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(_e);
    }

    /// @dev M33 / M34: the policy numbers are pinned next to each other.
    function test_caps_are_pinned() public view {
        assertEq(_H().maxCouncilBypass(), 7 days);
        assertEq(_H().maxCouncilApprovalTtl(), 7 days);
        assertEq(_H().maxAdminBypass(), 180 days);
        assertEq(_H().maxAdminApprovalTtl(), 180 days);
        assertEq(_H().maxAdminDelay(), 30 days);
        assertEq(_H().minBypass(), 1 hours);
        assertEq(_H().maxRules(), 16);
        assertEq(_H().maxAllowedValues(), 128);
        assertEq(_H().maxSelectors(), 32);
        assertEq(_H().maxGuardians(), 32);
        assertEq(_H().minAdminDelay(), 1 days);
        assertEq(_H().tailFlag(), 0x8000);
        assertLt(_H().maxCouncilBypass(), _H().maxAdminBypass());
        assertLt(_H().maxCouncilApprovalTtl(), _H().maxAdminApprovalTtl());
    }

    /// @dev M18: the council denylist is a SELF-call denylist; the same selectors on another contract
    ///      are an ordinary venue call, approvable by the council and allowed inside its window.
    function test_council_denylist_only_covers_self_calls() public {
        GuardSelectorVenue _venue = new GuardSelectorVenue();
        bytes memory _data = abi.encodeWithSelector(ISafe.setGuard.selector, attacker);
        bytes32 _id = _councilApprove(address(_venue), 0, _data, Operation.Call);
        assertGt(guard.approvalExpiry(_id), 0, "council may approve setGuard on a non-Safe target");
        assertTrue(_execSafeTx(address(_venue), 0, _data, Operation.Call));
        assertEq(_venue.last(), attacker);
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        assertTrue(_execSafeTx(address(_venue), 0, _data, Operation.Call));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, ISafe.setGuard.selector));
        _execSafeTx(address(safe), 0, _data, Operation.Call);
    }

    /// @dev M65 / M31: removal event pinned, idempotent removal silent; `revokeAllApprovals` emits the
    ///      new epoch from every narrower.
    function test_guardian_removal_and_revokeAll_events() public {
        vm.prank(vetro);
        guard.setGuardian(address(safe), guardian, true);
        vm.prank(vetro);
        vm.expectEmit(true, true, false, true, address(guard));
        emit CuratorGuardPolicy.GuardianUpdated(address(safe), guardian, false);
        guard.setGuardian(address(safe), guardian, false);
        vm.recordLogs();
        vm.prank(vetro);
        guard.setGuardian(address(safe), guardian, false);
        assertEq(vm.getRecordedLogs().length, 0, "removing a non-guardian emits nothing");

        vm.prank(vetro);
        guard.setGuardian(address(safe), guardian, true);
        vm.prank(guardian);
        vm.expectEmit(true, false, false, true, address(guard));
        emit CuratorGuardPolicy.ApprovalsRevoked(address(safe), 1);
        guard.revokeAllApprovals(address(safe));
        vm.prank(council);
        vm.expectEmit(true, false, false, true, address(guard));
        emit CuratorGuardPolicy.ApprovalsRevoked(address(safe), 2);
        guard.revokeAllApprovals(address(safe));
    }

    /// @dev M67 / M68: the three seeded literals equal the safe-deployments package (offline oracle),
    ///      and are pre-allowed.
    function test_seeded_codehashes_match_safe_deployments() public view {
        string[3] memory _versions = ["v1.3.0", "v1.4.1", "v1.5.0"];
        bytes32[3] memory _constants = [_H().codehashV130(), _H().codehashV141(), _H().codehashV150()];
        for (uint256 i; i < 3; ++i) {
            string memory _json = vm.readFile(
                string.concat("node_modules/@safe-global/safe-deployments/dist/assets/", _versions[i], "/multi_send_call_only.json")
            );
            bytes32 _expected = vm.parseJsonBytes32(_json, ".deployments.canonical.codeHash");
            assertEq(_constants[i], _expected, string.concat("MultiSendCallOnly ", _versions[i], " runtime hash"));
            assertTrue(guard.isUnwrapperCodehash(_expected), "pre-allowed at deployment");
        }
    }

    /// @dev M69 / M70: zero-address edges of the v2 entry points.
    function test_bypass_and_setDeploymentGuardian_reject_the_zero_address() public {
        vm.prank(vetro);
        vm.expectRevert(CuratorGuardPolicy.AddressIsNull.selector);
        guard.bypass(address(0), 1 days);
        vm.prank(council);
        vm.expectRevert(CuratorGuardPolicy.AddressIsNull.selector);
        guard.setDeploymentGuardian(address(0), true);
        assertFalse(guard.hasRole(guard.GUARDIAN_ROLE(), address(0)));
    }

    /// @dev M77: the council-window denylist does not depend on `value` (nor on the callee rejecting
    ///      value): the guard, not GS013, stops a value-carrying self-call.
    function test_council_window_denylist_ignores_value() public {
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, ISafe.setGuard.selector));
        _execSafeTx(address(safe), 1, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call);
    }

    /// @dev Dry run / live hook agreement inside a council window, delegatecall limit included.
    function test_dry_run_models_the_council_window_delegatecall_limit() public {
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        bytes memory _batch = _multiSendCalldata(_entry(address(protocol), 0, hex"deadbeef"));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.DelegateCallNotAllowed.selector, address(multiSend)));
        _execSafeTx(address(multiSend), 0, _batch, Operation.DelegateCall);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.DelegateCallNotAllowed.selector, address(multiSend)));
        guard.validateTransaction(address(safe), address(multiSend), 0, _batch, Operation.DelegateCall);
    }
}

/// @title M72: the council-window denylist holds on the Safe v1.5.0 module path too.
contract CuratorGuardMutationModuleTest is SafeTxHelper {
    CuratorGuard internal guard;
    PassThroughModule internal module;
    MockProtocol internal protocol;
    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal attacker = makeAddr("attacker");
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 internal constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    function setUp() public {
        vm.warp(1_700_000_000);
        address _curator;
        (_curator, signerPk) = makeAddrAndKey("curator");
        Safe150 _singleton = new Safe150();
        SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = _curator;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        safe = ISafe(address(_proxy));
        guard = new CuratorGuardHarness(0, vetro, council);
        CuratorGuardHarness(address(guard)).seedSafe(address(safe)); // locally compiled Safe build: seeded, the guard pins canonical Safe code (V2-85)
        module = new PassThroughModule();
        protocol = new MockProtocol();
        vm.startPrank(address(safe));
        safe.enableModule(address(module));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        vm.stopPrank();
        vm.prank(vetro);
        guard.enforce(address(safe));
    }

    function test_council_window_denylist_holds_on_the_module_path() public {
        vm.prank(council);
        guard.bypass(address(safe), 1 days);
        // The module allowlist stays in force inside a council window (round 4, R1D-4): an unlisted
        // module is refused, live and in the dry run. Round 6 (V2-66): an allowlisted module stays under
        // the POLICY inside a council window (the window relaxes the owner-signed path only), so it
        // reaches an allowed venue call and nothing else.
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module)));
        module.exec(safe, address(protocol), 0, _settle, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module)));
        guard.validateModuleTransaction(address(safe), address(module), address(protocol), 0, _settle, Operation.Call);
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(module), true);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.settleDeposit.selector));
        module.exec(safe, address(protocol), 0, _settle, Operation.Call);
        vm.prank(vetro);
        guard.allowFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector, false, new CuratorGuardPolicy.ParamRule[](0));
        assertTrue(module.exec(safe, address(protocol), 0, _settle, Operation.Call));
        bytes[4] memory _denied = [
            abi.encodeCall(ISafe.setGuard, (address(0))),
            abi.encodeCall(ISafe.setModuleGuard, (address(0))),
            abi.encodeCall(ISafe.enableModule, (attacker)),
            abi.encodeWithSelector(0xf08a0323, attacker)
        ];
        for (uint256 i; i < 4; ++i) {
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, bytes4(_denied[i])));
            module.exec(safe, address(safe), 0, _denied[i], Operation.Call);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, bytes4(_denied[i])));
            guard.validateModuleTransaction(address(safe), address(module), address(safe), 0, _denied[i], Operation.Call);
        }
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.DelegateCallNotAllowed.selector, attacker));
        module.exec(safe, attacker, 0, "", Operation.DelegateCall);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, guard.lockdown.selector));
        module.exec(safe, address(guard), 0, abi.encodeCall(guard.lockdown, (address(safe))), Operation.Call);
        assertEq(address(uint160(uint256(bytes32(safe.getStorageAt(uint256(GUARD_SLOT), 1))))), address(guard));
        assertEq(address(uint160(uint256(bytes32(safe.getStorageAt(uint256(MODULE_GUARD_SLOT), 1))))), address(guard));
        // The owner-signed path of the same council window is relaxed to the council's limits.
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, ISafe.setGuard.selector));
        _execSafeTx(address(safe), 0, _denied[0], Operation.Call);
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (1, attacker)), Operation.Call), "unlisted venue call, owner path");
        // An admin window is inert for an allowlisted module, never for one off the allowlist (round 8,
        // R8R-1: a guardian's `setModuleAllowed(false)` holds in every mode).
        vm.prank(vetro);
        guard.bypass(address(safe), 1 days);
        assertTrue(module.exec(safe, address(safe), 0, _denied[2], Operation.Call), "allowlisted module, admin window: unchecked");
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(module), false);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module)));
        module.exec(safe, address(protocol), 0, _settle, Operation.Call);
    }
}
