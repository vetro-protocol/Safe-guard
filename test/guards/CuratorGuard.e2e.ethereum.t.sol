// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {ILagoonVaultV06} from "contracts/interfaces/lagoon/ILagoonVaultV06.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

/// @dev Lagoon v0.6.0 Safe/owner surface exercised here.
interface ILagoonAdmin {
    function updateNewTotalAssets(uint256 newTotalAssets) external;
    function settleDeposit(uint256 newTotalAssets) external;
    function updateSafe(address newSafe) external;
    function securityCouncilUpdateTotalAssets(uint256 newTotalAssets) external;
}

/// @title CuratorGuard mainnet fork test against the live Vetro Lagoon curator Safe
/// @notice Installs the guard on the real Safe (v1.4.1), applies the policy from
///         `policies/curator-guard/vetro-lagoon.ethereum.json`, replays the exact batch shape the
///         Safe executed on mainnet (NAV update + settle through MultiSendCallOnly v1.4.1), and
///         shows the drains the policy stops. Requires `ETHEREUM_FORK_NODE_URL`.
contract CuratorGuardE2E_EthereumTest is SafeTxHelper {
    address internal constant SAFE = 0x1b534a8543212F5957168D83311A41E0Ea1cfe48;
    address internal constant MULTISEND_CALL_ONLY_141 = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;
    address internal constant MULTISEND_141 = 0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526;
    address internal constant VAULT_USDC = 0x131CcfDFfeD712885aAc31445d351E6b62656679;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 internal constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    address internal constant COMPATIBILITY_FALLBACK_HANDLER_141 = 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99;

    CuratorGuard internal guard;
    address internal vetro = makeAddr("vetro");

    address internal council = makeAddr("council");
    address internal guardian = makeAddr("guardian");
    address internal attacker = makeAddr("attacker");
    address internal signer;

    function setUp() public {
        safe = ISafe(SAFE);
        uint256 _blockNumber = vm.envOr("ETHEREUM_FORK_BLOCK_NUMBER", uint256(0));
        if (_blockNumber > 0) vm.createSelectFork("ethereum", _blockNumber);
        else vm.createSelectFork("ethereum");
        // Never a silent green: the fork must be Ethereum mainnet with the curator Safe deployed (a
        // secret pointing at another chain or a pre-deployment block fails instead of skipping).
        assertEq(block.chainid, 1, "ETHEREUM_FORK_NODE_URL is not Ethereum mainnet");
        assertGt(SAFE.code.length, 0, "the curator Safe has no code at this block");
        assertEq(keccak256(bytes(safe.VERSION())), keccak256("1.4.1"), "safe version");
        (address[] memory _modules, ) = safe.getModulesPaginated(address(0x1), 10);
        assertEq(_modules.length, 0, "pre-install: no modules");
        assertEq(_guardSlot(), address(0), "pre-install: no guard");

        guard = new CuratorGuard(0, vetro, council);
        _applyPolicyFromJson("policies/curator-guard/vetro-lagoon.ethereum.json");
        vm.prank(vetro);
        guard.setGuardian(SAFE, guardian, true);

        // Give the test a 1-of-N key (the only pranked step), then install exactly as the runbook's
        // §7.4 batch does: handler removal and `setGuard` in ONE genuine `MultiSendCallOnly`
        // `execTransaction`, signed by that key (before the guard is installed it needs no approval).
        (signer, signerPk) = makeAddrAndKey("test-signer");
        vm.prank(SAFE);
        safe.addOwnerWithThreshold(signer, 1);
        bytes memory _install = abi.encodeWithSelector(
            0x8d80ff0a,
            abi.encodePacked(
                _entry(SAFE, abi.encodeWithSignature("setFallbackHandler(address)", address(0))),
                _entry(SAFE, abi.encodeCall(ISafe.setGuard, (address(guard))))
            )
        );
        assertTrue(_exec(MULTISEND_CALL_ONLY_141, 0, _install, Operation.DelegateCall), "install batch");
        assertEq(_guardSlot(), address(guard), "installed");
        assertEq(uint256(bytes32(safe.getStorageAt(uint256(FALLBACK_SLOT), 1))), 0, "handler removed");
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Mainnet nonce 29/30 shape: `updateNewTotalAssets` + settle in one MultiSendCallOnly batch.
    function test_curator_can_still_update_nav_and_settle_in_a_batch() public {
        vm.warp(block.timestamp + 1 hours);
        uint256 _nav = ILagoonVaultV06(VAULT_USDC).totalAssets();
        bytes memory _batch = abi.encodeWithSelector(
            0x8d80ff0a,
            abi.encodePacked(
                _entry(VAULT_USDC, abi.encodeCall(ILagoonAdmin.updateNewTotalAssets, (_nav))),
                _entry(VAULT_USDC, abi.encodeCall(ILagoonAdmin.settleDeposit, (_nav)))
            )
        );
        // Reported once, under the live Safe's own `safeTxHash` (what Safe{Wallet} / the Transaction
        // Service show for this transaction).
        bytes32 _hash = _txHash(SafeTx(MULTISEND_CALL_ONLY_141, 0, _batch, Operation.DelegateCall, 0, 0, address(0), address(0)));
        assertEq(
            _hash,
            safe.getTransactionHash(MULTISEND_CALL_ONLY_141, 0, _batch, Operation.DelegateCall, 0, 0, 0, address(0), address(0), safe.nonce())
        );
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(SAFE, _hash, 0, CuratorGuard.Outcome.Policy);
        assertTrue(_exec(MULTISEND_CALL_ONLY_141, 0, _batch, Operation.DelegateCall));
        assertEq(ILagoonVaultV06(VAULT_USDC).totalAssets(), _nav);
        assertEq(_guardSlot(), address(guard));
    }

    function test_curator_can_approve_only_the_matching_vault() public {
        assertTrue(_exec(USDC, 0, abi.encodeCall(IERC20.approve, (VAULT_USDC, type(uint256).max)), Operation.Call));
        assertEq(IERC20(USDC).allowance(SAFE, VAULT_USDC), type(uint256).max);

        vm.expectRevert(
            abi.encodeWithSelector(
                CuratorGuard.ParamRuleViolated.selector,
                USDC,
                IERC20.approve.selector,
                uint16(0),
                bytes32(uint256(uint160(attacker)))
            )
        );
        _exec(USDC, 0, abi.encodeCall(IERC20.approve, (attacker, type(uint256).max)), Operation.Call);
    }

    function test_drains_and_admin_escapes_are_blocked() public {
        uint256 _balance = IERC20(USDC).balanceOf(SAFE);

        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, USDC, IERC20.transfer.selector));
        _exec(USDC, 0, abi.encodeCall(IERC20.transfer, (attacker, 1)), Operation.Call);

        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, ISafe.setGuard.selector));
        _exec(SAFE, 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call);

        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, ISafe.enableModule.selector));
        _exec(SAFE, 0, abi.encodeCall(ISafe.enableModule, (attacker)), Operation.Call);

        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, VAULT_USDC, ILagoonAdmin.updateSafe.selector)
        );
        _exec(VAULT_USDC, 0, abi.encodeCall(ILagoonAdmin.updateSafe, (attacker)), Operation.Call);

        vm.expectRevert(
            abi.encodeWithSelector(
                CuratorGuard.FunctionNotAllowed.selector,
                VAULT_USDC,
                ILagoonAdmin.securityCouncilUpdateTotalAssets.selector
            )
        );
        _exec(VAULT_USDC, 0, abi.encodeCall(ILagoonAdmin.securityCouncilUpdateTotalAssets, (1)), Operation.Call);

        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.DelegateCallNotAllowed.selector, MULTISEND_141));
        _exec(MULTISEND_141, 0, abi.encodeWithSelector(0x8d80ff0a, _entry(USDC, "")), Operation.DelegateCall);

        vm.expectRevert(CuratorGuard.GasRefundNotAllowed.selector);
        _execWithRefund(USDC, abi.encodeCall(IERC20.approve, (VAULT_USDC, 1)), 1e12, USDC, attacker);

        assertEq(IERC20(USDC).balanceOf(SAFE), _balance);
        assertEq(_guardSlot(), address(guard));
    }

    function test_guardian_lockdown_council_lift_and_council_approval_for_owner_management() public {
        vm.prank(guardian);
        guard.lockdown(SAFE);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, SAFE));
        _exec(USDC, 0, abi.encodeCall(IERC20.approve, (VAULT_USDC, 1)), Operation.Call);
        // The council lifts it on the fast lane; the guardian could not.
        vm.prank(guardian);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.enforce(SAFE);
        vm.prank(council);
        guard.enforce(SAFE);
        assertTrue(_exec(USDC, 0, abi.encodeCall(IERC20.approve, (VAULT_USDC, 1)), Operation.Call));

        // The one admin action the Safe has needed so far, now gated by a council approval. The new owner
        // must be a plain key: the council cannot bring in an account with code, and on mainnet even
        // Foundry's well-known test addresses carry code (their keys are public, anyone can delegate
        // them), so the test clears it.
        address _newOwner = makeAddr("e2e-new-owner");
        vm.etch(_newOwner, "");
        bytes memory _data = abi.encodeCall(ISafe.addOwnerWithThreshold, (_newOwner, 2));
        vm.prank(council);
        guard.approveTransaction(SAFE, address(0), SAFE, 0, _data, Operation.Call, uint64(1 days));
        // Signer / approval compromise: a guardian's `lockdownAndRevoke` freezes the Safe AND voids the standing
        // approval in one transaction, so the approved payload no longer runs either.
        vm.prank(guardian);
        guard.lockdownAndRevoke(SAFE);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, SAFE));
        _exec(SAFE, 0, _data, Operation.Call);
        vm.prank(council);
        guard.enforce(SAFE);
        vm.prank(council);
        guard.approveTransaction(SAFE, address(0), SAFE, 0, _data, Operation.Call, uint64(1 days));
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(
            SAFE,
            _txHash(SafeTx(SAFE, 0, _data, Operation.Call, 0, 0, address(0), address(0))),
            0,
            CuratorGuard.Outcome.Approval
        );
        assertTrue(_exec(SAFE, 0, _data, Operation.Call));
        assertEq(safe.getThreshold(), 2);
        assertEq(_guardSlot(), address(guard));
    }

    /// @dev On the deployed 0.7.6 singleton an owner list longer than `ownerCount` makes `getOwners()`
    ///      hit `INVALID`: every unit of forwarded gas is burned and no data is returned, and the guard
    ///      still answers `SafeConfigUnreadable` (the 0.8.25 fixture build panics cheaply instead).
    function test_unreadable_live_safe_burns_the_forwarded_gas_but_is_typed() public {
        bytes32 _count = vm.load(SAFE, bytes32(uint256(3)));
        assertGt(uint256(_count), 1);
        vm.store(SAFE, bytes32(uint256(3)), bytes32(uint256(_count) - 1));
        uint256 _gas = gasleft();
        (bool _ok, bytes memory _ret) = SAFE.staticcall{gas: 200_000}(abi.encodeWithSignature("getOwners()"));
        uint256 _used = _gas - gasleft();
        assertFalse(_ok, "the read fails");
        assertEq(_ret.length, 0, "INVALID leaves no data");
        assertGt(_used, 190_000, "all forwarded gas burned");
        bytes memory _call = abi.encodeCall(IERC20.approve, (VAULT_USDC, 1));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigUnreadable.selector, SAFE));
        guard.validateTransaction(SAFE, USDC, 0, _call, Operation.Call);
        vm.store(SAFE, bytes32(uint256(3)), _count);
        guard.validateTransaction(SAFE, USDC, 0, _call, Operation.Call);
    }

    /// @dev The live Safe ran the canonical `CompatibilityFallbackHandler` (EIP-1271) until the install
    ///      batch removed it. Putting it back (a mistake, or an attempt to re-open the off-chain permit
    ///      path) freezes policy traffic; the council cannot approve another handler, but it can approve
    ///      the reset to zero that fixes the install-ordering mistake.
    function test_fallback_handler_requirement_on_the_live_safe() public {
        // Without a handler the Safe no longer answers `isValidSignature`: USDC's permit /
        // transferWithAuthorization can no longer be authorised off-chain by the signers.
        (bool _ok, bytes memory _ret) = SAFE.staticcall(abi.encodeWithSignature("isValidSignature(bytes32,bytes)", bytes32(0), ""));
        assertTrue(_ok && _ret.length == 0, "no 1271 answer after install");

        bytes memory _reinstall = abi.encodeWithSignature("setFallbackHandler(address)", COMPATIBILITY_FALLBACK_HANDLER_141);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, bytes4(_reinstall)));
        _exec(SAFE, 0, _reinstall, Operation.Call);
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, bytes4(_reinstall), Operation.Call));
        guard.approveTransaction(SAFE, address(0), SAFE, 0, _reinstall, Operation.Call, uint64(1 days));

        // Simulate the handler coming back anyway (an admin-approved mistake): every policy transaction
        // reverts until it is gone again, and only the admin can approve the removal.
        vm.prank(SAFE);
        (bool _reinstalled, ) = SAFE.call(_reinstall);
        assertTrue(_reinstalled);
        address _handler = address(uint160(uint256(bytes32(safe.getStorageAt(uint256(FALLBACK_SLOT), 1)))));
        assertEq(_handler, COMPATIBILITY_FALLBACK_HANDLER_141);
        bytes memory _approveVault = abi.encodeCall(IERC20.approve, (VAULT_USDC, 1));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FallbackHandlerNotAllowed.selector, _handler));
        _exec(USDC, 0, _approveVault, Operation.Call);
        // Resetting the handler to zero never weakens the Safe: the COUNCIL fixes it on the fast lane.
        bytes memory _removeHandler = abi.encodeWithSignature("setFallbackHandler(address)", address(0));
        vm.prank(council);
        guard.approveTransaction(SAFE, address(0), SAFE, 0, _removeHandler, Operation.Call, uint64(1 days));
        assertTrue(_exec(SAFE, 0, _removeHandler, Operation.Call));
        assertEq(uint256(bytes32(safe.getStorageAt(uint256(FALLBACK_SLOT), 1))), 0);
        assertTrue(_exec(USDC, 0, _approveVault, Operation.Call));
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Mirrors `tasks/curator-guard.ts`: functions (+ OneOf values), unwrappers, mode last.
    function _applyPolicyFromJson(string memory path_) internal {
        string memory _json = vm.readFile(path_);
        assertEq(vm.parseJsonAddress(_json, ".safe"), SAFE, "policy safe");
        vm.startPrank(vetro);
        address[] memory _unwrappers = vm.parseJsonAddressArray(_json, ".multiSendUnwrappers");
        for (uint256 i; i < _unwrappers.length; ++i) guard.setMultiSendUnwrapper(SAFE, _unwrappers[i], true);

        for (uint256 i; ; ++i) {
            string memory _base = string.concat(".functions[", vm.toString(i), "]");
            if (!vm.keyExistsJson(_json, string.concat(_base, ".target"))) break;
            address _target = vm.parseJsonAddress(_json, string.concat(_base, ".target"));
            bytes4 _selector = bytes4(keccak256(bytes(vm.parseJsonString(_json, string.concat(_base, ".signature")))));
            bool _allowValue = vm.keyExistsJson(_json, string.concat(_base, ".allowValue")) &&
                vm.parseJsonBool(_json, string.concat(_base, ".allowValue"));
            CuratorGuardPolicy.ParamRule[] memory _rules = _parseRules(_json, _base);
            guard.allowFunction(SAFE, _target, _selector, _allowValue, _rules);
            _addOneOfValues(_json, _base, _target, _selector);
        }
        // The remaining keys, applied as `curator-guard-sync` applies them (empty lists asserted so a
        // future policy edit fails here instead of silently diverging from the task).
        address[] memory _guardians = vm.parseJsonAddressArray(_json, ".guardians");
        for (uint256 i; i < _guardians.length; ++i) guard.setGuardian(SAFE, _guardians[i], true);
        assertEq(vm.parseJsonAddressArray(_json, ".modules").length, 0, "fixture: modules");
        assertEq(vm.parseJsonAddressArray(_json, ".nativeTransfers").length, 0, "fixture: nativeTransfers");
        guard.setRequiredFallbackHandler(
            SAFE,
            vm.parseJsonAddress(_json, ".requiredFallbackHandler.handler"),
            vm.parseJsonBool(_json, ".requiredFallbackHandler.enforce")
        );
        string memory _mode = vm.parseJsonString(_json, ".mode");
        assertEq(keccak256(bytes(_mode)), keccak256("Enforced"), "policy mode");
        guard.enforce(SAFE);
        vm.stopPrank();
    }

    function _parseRules(
        string memory json_,
        string memory base_
    ) internal view returns (CuratorGuardPolicy.ParamRule[] memory _rules) {
        uint256 _count;
        while (vm.keyExistsJson(json_, string.concat(base_, ".rules[", vm.toString(_count), "]"))) ++_count;
        _rules = new CuratorGuardPolicy.ParamRule[](_count);
        for (uint256 j; j < _count; ++j) {
            string memory _r = string.concat(base_, ".rules[", vm.toString(j), "]");
            bytes32 _kind = keccak256(bytes(vm.parseJsonString(json_, string.concat(_r, ".kind"))));
            uint16 _wordIndex = uint16(vm.parseJsonUint(json_, string.concat(_r, ".wordIndex")));
            if (_kind == keccak256("OneOf")) {
                _rules[j] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, _wordIndex, 0);
            } else if (_kind == keccak256("EqualToSafe")) {
                _rules[j] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualToSafe, _wordIndex, 0);
            } else {
                revert("rule kind not supported by this fixture");
            }
        }
    }

    /// @dev Values can only be added once the function carries its `OneOf` rule (allow first).
    function _addOneOfValues(string memory json_, string memory base_, address target_, bytes4 selector_) internal {
        for (uint256 j; vm.keyExistsJson(json_, string.concat(base_, ".rules[", vm.toString(j), "]")); ++j) {
            string memory _r = string.concat(base_, ".rules[", vm.toString(j), "]");
            if (keccak256(bytes(vm.parseJsonString(json_, string.concat(_r, ".kind")))) != keccak256("OneOf")) continue;
            uint16 _wordIndex = uint16(vm.parseJsonUint(json_, string.concat(_r, ".wordIndex")));
            address[] memory _values = vm.parseJsonAddressArray(json_, string.concat(_r, ".values"));
            bytes32[] memory _words = new bytes32[](_values.length);
            for (uint256 k; k < _values.length; ++k) _words[k] = bytes32(uint256(uint160(_values[k])));
            guard.addAllowedValues(SAFE, target_, selector_, _wordIndex, _words);
        }
    }

    function _guardSlot() internal view returns (address) {
        return address(uint160(uint256(bytes32(safe.getStorageAt(uint256(GUARD_SLOT), 1)))));
    }

    function _entry(address to_, bytes memory data_) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to_, uint256(0), data_.length, data_);
    }

    function _exec(address to_, uint256 value_, bytes memory data_, Operation op_) internal returns (bool) {
        return _execSafeTx(to_, value_, data_, op_);
    }

    function _execWithRefund(
        address to_,
        bytes memory data_,
        uint256 gasPrice_,
        address gasToken_,
        address refundReceiver_
    ) internal returns (bool) {
        return _execSafeTxWithRefund(to_, 0, data_, Operation.Call, gasPrice_, gasToken_, refundReceiver_);
    }
}
