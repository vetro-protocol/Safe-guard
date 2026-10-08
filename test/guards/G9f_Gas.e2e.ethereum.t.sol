// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {ILagoonVaultV06} from "contracts/interfaces/lagoon/ILagoonVaultV06.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

interface IG9fLagoonAdmin {
    function updateNewTotalAssets(uint256 newTotalAssets) external;
    function settleDeposit(uint256 newTotalAssets) external;
}

/// @title Round 9 (g9f, fork): gas per hook on the SHIPPED policy, on the live curator Safe.
/// @dev `CuratorGuardGas.t.sol` measures a mock policy (no rules, one owner). Here the policy file is
///      applied to the live Safe (its four owners plus the test key, `OneOf` rules on `approve`, three
///      registered unwrappers), the guard is installed through the runbook's batch, and every hook is
///      measured: the pre-hook and after-hook called directly (cold, then warm), and whole
///      `execTransaction`s before and after the install for the NAV update, the settlement batch and
///      the `approve`. Numbers are logged; the assertions are loose ceilings against regressions.
contract CuratorGuardG9fGasE2E_EthereumTest is SafeTxHelper {
    address internal constant SAFE = 0x1b534a8543212F5957168D83311A41E0Ea1cfe48;
    address internal constant MULTISEND_CALL_ONLY_141 = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;
    address internal constant VAULT_USDC = 0x131CcfDFfeD712885aAc31445d351E6b62656679;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    CuratorGuard internal guard;
    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal signer;

    function setUp() public {
        safe = ISafe(SAFE);
        uint256 _blockNumber = vm.envOr("ETHEREUM_FORK_BLOCK_NUMBER", uint256(0));
        if (_blockNumber > 0) vm.createSelectFork("ethereum", _blockNumber);
        else vm.createSelectFork("ethereum");
        assertEq(block.chainid, 1, "ETHEREUM_FORK_NODE_URL is not Ethereum mainnet");
        assertEq(keccak256(bytes(safe.VERSION())), keccak256("1.4.1"), "safe version");
        assertEq(uint256(bytes32(safe.getStorageAt(uint256(GUARD_SLOT), 1))), 0, "pre-install: no guard");
        guard = new CuratorGuard(0, vetro, council);
        _applyPolicyFromJson("policies/curator-guard/vetro-lagoon.ethereum.json");
        (signer, signerPk) = makeAddrAndKey("test-signer");
        vm.prank(SAFE);
        safe.addOwnerWithThreshold(signer, 1);
    }

    function _install() internal {
        bytes memory _installBatch = abi.encodeWithSelector(
            0x8d80ff0a,
            abi.encodePacked(
                _entry(SAFE, abi.encodeWithSignature("setFallbackHandler(address)", address(0))),
                _entry(SAFE, abi.encodeCall(ISafe.setGuard, (address(guard))))
            )
        );
        assertTrue(_execSafeTx(MULTISEND_CALL_ONLY_141, 0, _installBatch, Operation.DelegateCall), "install batch");
    }

    function _measureExec(address to_, bytes memory data_, Operation op_) internal returns (uint256 _gas) {
        _gas = gasleft();
        assertTrue(_execSafeTx(to_, 0, data_, op_));
        _gas -= gasleft();
    }

    function _preHook(address to_, bytes memory data_, Operation op_) internal returns (uint256 _gas) {
        vm.prank(SAFE);
        _gas = gasleft();
        guard.checkTransaction(to_, 0, data_, op_, 0, 0, 0, address(0), payable(address(0)), "", signer);
        _gas -= gasleft();
    }

    function _postHook() internal returns (uint256 _gas) {
        vm.prank(SAFE);
        _gas = gasleft();
        guard.checkAfterExecution(bytes32(0), true);
        _gas -= gasleft();
    }

    bytes internal updateData;
    bytes internal batchData;
    bytes internal approveData;

    function _payloads() internal {
        vm.warp(block.timestamp + 1 hours);
        uint256 _nav = ILagoonVaultV06(VAULT_USDC).totalAssets();
        updateData = abi.encodeCall(IG9fLagoonAdmin.updateNewTotalAssets, (_nav));
        batchData = abi.encodeWithSelector(
            0x8d80ff0a,
            abi.encodePacked(_entry(VAULT_USDC, updateData), _entry(VAULT_USDC, abi.encodeCall(IG9fLagoonAdmin.settleDeposit, (_nav))))
        );
        approveData = abi.encodeCall(IERC20.approve, (VAULT_USDC, type(uint256).max));
    }

    /// @dev The hooks called directly on the shipped policy: cold (first touch of the policy's storage
    ///      in this transaction), then warm, for the three shapes the curator sends.
    function test_direct_hooks_cold_and_warm_on_the_shipped_policy() public {
        _payloads();
        _install();
        uint256 _preCold = _preHook(VAULT_USDC, updateData, Operation.Call);
        uint256 _postCold = _postHook();
        uint256 _preWarm = _preHook(VAULT_USDC, updateData, Operation.Call);
        uint256 _postWarm = _postHook();
        emit log_named_uint("pre-hook updateNewTotalAssets, cold", _preCold);
        emit log_named_uint("pre-hook updateNewTotalAssets, warm", _preWarm);
        emit log_named_uint("after-hook, cold", _postCold);
        emit log_named_uint("after-hook, warm", _postWarm);
        _preCold = _preHook(MULTISEND_CALL_ONLY_141, batchData, Operation.DelegateCall);
        _postHook();
        _preWarm = _preHook(MULTISEND_CALL_ONLY_141, batchData, Operation.DelegateCall);
        _postHook();
        emit log_named_uint("pre-hook settlement batch (2 entries), cold", _preCold);
        emit log_named_uint("pre-hook settlement batch (2 entries), warm", _preWarm);
        assertLt(_preCold, 200_000, "pre-hook ceiling, batch, cold");
        _preCold = _preHook(USDC, approveData, Operation.Call);
        _postHook();
        _preWarm = _preHook(USDC, approveData, Operation.Call);
        _postHook();
        emit log_named_uint("pre-hook approve(vault, max) with OneOf, cold", _preCold);
        emit log_named_uint("pre-hook approve(vault, max) with OneOf, warm", _preWarm);
        uint256 _dry = gasleft();
        guard.validateTransaction(SAFE, VAULT_USDC, 0, updateData, Operation.Call);
        _dry -= gasleft();
        emit log_named_uint("validateTransaction updateNewTotalAssets (dry run, warm)", _dry);
        assertLt(_postCold, 60_000, "after-hook ceiling, cold");
    }

    /// @dev Whole `execTransaction`s, warm, before and after the install: the overhead on the live Safe.
    function test_execTransaction_overhead_on_the_shipped_policy() public {
        _payloads();
        _measureExec(USDC, approveData, Operation.Call);
        uint256 _refApprove = _measureExec(USDC, approveData, Operation.Call);
        _measureExec(VAULT_USDC, updateData, Operation.Call);
        uint256 _refUpdate = _measureExec(VAULT_USDC, updateData, Operation.Call);
        _measureExec(MULTISEND_CALL_ONLY_141, batchData, Operation.DelegateCall);
        uint256 _refBatch = _measureExec(MULTISEND_CALL_ONLY_141, batchData, Operation.DelegateCall);
        _install();
        _measureExec(USDC, approveData, Operation.Call);
        uint256 _g = _measureExec(USDC, approveData, Operation.Call);
        emit log_named_uint("execTransaction approve: unguarded", _refApprove);
        emit log_named_uint("execTransaction approve: guarded (policy, OneOf rule)", _g);
        emit log_named_uint("  => overhead approve", _g - _refApprove);
        _measureExec(VAULT_USDC, updateData, Operation.Call);
        _g = _measureExec(VAULT_USDC, updateData, Operation.Call);
        emit log_named_uint("execTransaction updateNewTotalAssets: unguarded", _refUpdate);
        emit log_named_uint("execTransaction updateNewTotalAssets: guarded (policy)", _g);
        emit log_named_uint("  => overhead updateNewTotalAssets", _g - _refUpdate);
        _measureExec(MULTISEND_CALL_ONLY_141, batchData, Operation.DelegateCall);
        _g = _measureExec(MULTISEND_CALL_ONLY_141, batchData, Operation.DelegateCall);
        emit log_named_uint("execTransaction settlement batch: unguarded", _refBatch);
        emit log_named_uint("execTransaction settlement batch: guarded (policy)", _g);
        emit log_named_uint("  => overhead batch", _g - _refBatch);
        assertLt(_g - _refBatch, 150_000, "batch overhead ceiling");
    }

    /// @dev The two exits: a council approval and a council window, on the live Safe.
    function test_exit_paths_on_the_shipped_policy() public {
        _payloads();
        _measureExec(VAULT_USDC, updateData, Operation.Call);
        uint256 _ref = _measureExec(VAULT_USDC, updateData, Operation.Call);
        _install();
        vm.prank(council);
        guard.approveTransaction(SAFE, address(0), VAULT_USDC, 0, updateData, Operation.Call, 1 days);
        uint256 _g = _measureExec(VAULT_USDC, updateData, Operation.Call);
        emit log_named_uint("execTransaction updateNewTotalAssets: unguarded", _ref);
        emit log_named_uint("execTransaction updateNewTotalAssets: guarded (council approval)", _g);
        emit log_named_uint("  => overhead approval path", _g - _ref);
        vm.prank(council);
        guard.bypass(SAFE, 1 hours);
        _measureExec(VAULT_USDC, updateData, Operation.Call);
        _g = _measureExec(VAULT_USDC, updateData, Operation.Call);
        emit log_named_uint("execTransaction updateNewTotalAssets: guarded (council window, warm)", _g);
        emit log_named_uint("  => overhead window path", _g - _ref);
    }

    /*//////////////////////////////////////////////////////////////
                    HELPERS (mirror the repository's e2e fixture)
    //////////////////////////////////////////////////////////////*/

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
        address[] memory _guardians = vm.parseJsonAddressArray(_json, ".guardians");
        for (uint256 i; i < _guardians.length; ++i) guard.setGuardian(SAFE, _guardians[i], true);
        guard.setRequiredFallbackHandler(
            SAFE,
            vm.parseJsonAddress(_json, ".requiredFallbackHandler.handler"),
            vm.parseJsonBool(_json, ".requiredFallbackHandler.enforce")
        );
        guard.enforce(SAFE);
        vm.stopPrank();
    }

    function _parseRules(string memory json_, string memory base_) internal view returns (CuratorGuardPolicy.ParamRule[] memory _rules) {
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

    function _entry(address to_, bytes memory data_) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to_, uint256(0), data_.length, data_);
    }
}
