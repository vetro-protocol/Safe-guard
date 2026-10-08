// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {ILagoonVaultV06} from "contracts/interfaces/lagoon/ILagoonVaultV06.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

interface IG11cLagoonAdmin {
    function updateNewTotalAssets(uint256 newTotalAssets) external;
    function settleDeposit(uint256 newTotalAssets) external;
}

/// @title Round 11 (g11c, fork): the executor's gas floor on the LIVE curator Safe with the shipped policy.
/// @dev   The policy file applied as `curator-guard-sync` would, the guard installed through the
///        runbook's batch, then for each shape the curator sends the smallest outer gas at which
///        `execTransaction` succeeds, by binary search from one snapshot with the touched accounts
///        cooled: before the install (the reference) and after it (the guard's share). These are the
///        numbers Safe{Wallet}'s `eth_estimateGas` must find; `G9f_Gas.e2e` measured the hooks alone.
contract CuratorGuardG11cExecutorFloorE2E_EthereumTest is SafeTxHelper {
    address internal constant SAFE = 0x1b534a8543212F5957168D83311A41E0Ea1cfe48;
    address internal constant SINGLETON_141 = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    address internal constant MULTISEND_CALL_ONLY_141 = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;
    address internal constant VAULT_USDC = 0x131CcfDFfeD712885aAc31445d351E6b62656679;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 internal constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    CuratorGuard internal guard;
    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal signer;
    address internal vaultImpl;
    address internal usdcImpl;
    bytes internal updateData;
    bytes internal batchData;
    bytes internal approveData;

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
        vaultImpl = address(uint160(uint256(vm.load(VAULT_USDC, IMPL_SLOT))));
        usdcImpl = address(uint160(uint256(vm.load(USDC, IMPL_SLOT))));
        vm.warp(block.timestamp + 1 hours);
        uint256 _nav = ILagoonVaultV06(VAULT_USDC).totalAssets();
        updateData = abi.encodeCall(IG11cLagoonAdmin.updateNewTotalAssets, (_nav));
        batchData = abi.encodeWithSelector(
            0x8d80ff0a,
            abi.encodePacked(_entry(VAULT_USDC, updateData), _entry(VAULT_USDC, abi.encodeCall(IG11cLagoonAdmin.settleDeposit, (_nav))))
        );
        approveData = abi.encodeCall(IERC20.approve, (VAULT_USDC, type(uint256).max));
    }

    function _entry(address to_, bytes memory data_) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to_, uint256(0), data_.length, data_);
    }

    /// @dev The repository policy file as the sync task applies it.
    function _applyPolicyFromJson(string memory path_) internal {
        string memory _json = vm.readFile(path_);
        vm.startPrank(vetro);
        address[] memory _unwrappers = vm.parseJsonAddressArray(_json, ".multiSendUnwrappers");
        for (uint256 i; i < _unwrappers.length; ++i) guard.setMultiSendUnwrapper(SAFE, _unwrappers[i], true);
        for (uint256 i; ; ++i) {
            string memory _base = string.concat(".functions[", vm.toString(i), "]");
            if (!vm.keyExistsJson(_json, string.concat(_base, ".target"))) break;
            address _target = vm.parseJsonAddress(_json, string.concat(_base, ".target"));
            bytes4 _selector = bytes4(keccak256(bytes(vm.parseJsonString(_json, string.concat(_base, ".signature")))));
            uint256 _ruleCount;
            while (vm.keyExistsJson(_json, string.concat(_base, ".rules[", vm.toString(_ruleCount), "]"))) ++_ruleCount;
            CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](_ruleCount);
            for (uint256 j; j < _ruleCount; ++j) {
                string memory _r = string.concat(_base, ".rules[", vm.toString(j), "]");
                _rules[j] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, uint16(vm.parseJsonUint(_json, string.concat(_r, ".wordIndex"))), 0);
            }
            guard.allowFunction(SAFE, _target, _selector, false, _rules);
            for (uint256 j; j < _ruleCount; ++j) {
                string memory _r = string.concat(_base, ".rules[", vm.toString(j), "]");
                address[] memory _values = vm.parseJsonAddressArray(_json, string.concat(_r, ".values"));
                bytes32[] memory _words = new bytes32[](_values.length);
                for (uint256 k; k < _values.length; ++k) _words[k] = bytes32(uint256(uint160(_values[k])));
                guard.addAllowedValues(SAFE, _target, _selector, _rules[j].wordIndex, _words);
            }
        }
        guard.setRequiredFallbackHandler(SAFE, vm.parseJsonAddress(_json, ".requiredFallbackHandler.handler"), vm.parseJsonBool(_json, ".requiredFallbackHandler.enforce"));
        guard.enforce(SAFE);
        vm.stopPrank();
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
        assertEq(address(uint160(uint256(bytes32(safe.getStorageAt(uint256(GUARD_SLOT), 1))))), address(guard));
    }

    function _cool() internal {
        vm.cool(SAFE);
        vm.cool(SINGLETON_141);
        vm.cool(address(guard));
        vm.cool(VAULT_USDC);
        vm.cool(vaultImpl);
        vm.cool(USDC);
        vm.cool(usdcImpl);
        vm.cool(MULTISEND_CALL_ONLY_141);
    }

    function _execData(SafeTx memory t_) internal view returns (bytes memory) {
        return
            abi.encodeCall(
                ISafe.execTransaction,
                (t_.to, t_.value, t_.data, t_.op, t_.safeTxGas, 0, t_.gasPrice, t_.gasToken, payable(t_.refundReceiver), _sign(_txHash(t_)))
            );
    }

    function _try(bytes memory data_, uint256 gas_) internal returns (bool _ok) {
        _cool();
        (_ok, ) = address(safe).call{gas: gas_}(data_);
    }

    function _floor(address to_, bytes memory data_, Operation op_) internal returns (uint256) {
        bytes memory _data = _execData(SafeTx(to_, 0, data_, op_, 0, 0, address(0), address(0)));
        uint256 _snap = vm.snapshotState();
        require(_try(_data, 1_500_000), "does not succeed at the search ceiling");
        assertTrue(vm.revertToState(_snap));
        uint256 _lo = 21_000;
        uint256 _hi = 1_500_000;
        while (_lo + 1 < _hi) {
            uint256 _mid = (_lo + _hi) / 2;
            bool _ok = _try(_data, _mid);
            assertTrue(vm.revertToState(_snap));
            if (_ok) _hi = _mid;
            else _lo = _mid;
        }
        assertFalse(_try(_data, _hi - 1), "monotone: fails one unit below the floor");
        assertTrue(vm.revertToState(_snap));
        assertTrue(_try(_data, _hi), "succeeds at the floor");
        assertTrue(vm.revertToState(_snap));
        return _hi;
    }

    /// @dev Floors on the live Safe (five owners after the test key), cold, before and after the install.
    function test_executor_floors_on_the_live_safe_before_and_after_the_install() public {
        uint256 _refUpdate = _floor(VAULT_USDC, updateData, Operation.Call);
        uint256 _refBatch = _floor(MULTISEND_CALL_ONLY_141, batchData, Operation.DelegateCall);
        uint256 _refApprove = _floor(USDC, approveData, Operation.Call);
        _install();
        uint256 _update = _floor(VAULT_USDC, updateData, Operation.Call);
        uint256 _batch = _floor(MULTISEND_CALL_ONLY_141, batchData, Operation.DelegateCall);
        uint256 _approve = _floor(USDC, approveData, Operation.Call);
        emit log_named_uint("live Safe, block", block.number);
        emit log_named_uint("floor: updateNewTotalAssets, unguarded, cold", _refUpdate);
        emit log_named_uint("floor: updateNewTotalAssets, guarded, cold", _update);
        emit log_named_uint("  => guard's share", _update - _refUpdate);
        emit log_named_uint("floor: settlement batch (update + settleDeposit), unguarded, cold", _refBatch);
        emit log_named_uint("floor: settlement batch, guarded, cold", _batch);
        emit log_named_uint("  => guard's share", _batch - _refBatch);
        emit log_named_uint("floor: approve(vault, max) with OneOf, unguarded, cold", _refApprove);
        emit log_named_uint("floor: approve, guarded, cold", _approve);
        emit log_named_uint("  => guard's share", _approve - _refApprove);
        assertLt(_update - _refUpdate, 150_000, "guard's share of the floor on the live Safe");
        assertLt(_batch - _refBatch, 170_000);
        assertLt(_approve - _refApprove, 150_000);
    }
}
