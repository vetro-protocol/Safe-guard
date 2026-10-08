// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {G10dSigner, HostileVaultLogic, HostileVenue, IERC20Like} from "test/guards/G10d_Base.sol";

interface IDelayProxyAdmin {
    function owner() external view returns (address);

    function newImplementation() external view returns (address);

    function implementationUpdateTime() external view returns (uint256);

    function delay() external view returns (uint256);

    function submitImplementation(address implementation) external;
}

interface ILagoonVaultProxy {
    function REGISTRY() external view returns (address);
}

interface ILogicRegistry {
    function owner() external view returns (address);

    function canUseLogic(address current, address next) external view returns (bool);
}

/// @title G10d_Fork: a hostile Lagoon vault implementation against the shipped policy on the LIVE Safe
/// @notice Round 10, reviewer g10d, on a mainnet fork of the Vetro curator Safe with the shipped policy
///         shape installed through the runbook's section 7.4 batch. Who can change the five vaults' code
///         (read live), what a hostile implementation takes under the allowlisted selectors (the allowance,
///         which is at max on all five assets), what it cannot do from inside the call (reentrancy into the
///         real 0.7.6 Safe and into the guard), and what a per-settlement allowance cap would bound.
///         Requires `ETHEREUM_FORK_NODE_URL`.
contract G10d_ForkTest is G10dSigner {
    address internal constant SAFE = 0x1b534a8543212F5957168D83311A41E0Ea1cfe48;
    address internal constant MULTISEND_CALL_ONLY_141 = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;
    address internal constant REGISTRY_OWNER = 0x9A408Dc07820d810331A17da5E3a737fA2540d4B;

    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address internal constant WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;
    address internal constant CBBTC = 0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf;
    address internal constant HEMIBTC = 0x06ea695B91700071B161A434fED42D1DcbAD9f00;
    address internal constant VAULT_USDC = 0x131CcfDFfeD712885aAc31445d351E6b62656679;
    address internal constant VAULT_USDT = 0xE7FaE53e32B09028db4Ca8Ff7E4fF0574367eDba;
    address internal constant VAULT_WBTC = 0x1a9b5c9845c2685923215779c6Ec288bD5090e90;
    address internal constant VAULT_CBBTC = 0x110B1F3cD409Ef5A7b354AA1667c19998E1b6340;
    address internal constant VAULT_HEMIBTC = 0x26A6179247420B6e8036DBdeF48fD74d1E57fdc3;

    bytes32 internal constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 internal constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    bytes32 internal constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    bytes4 internal constant APPROVE = 0x095ea7b3;
    bytes4 internal constant UPDATE_NAV = 0xbcd1bf34; // updateNewTotalAssets(uint256)
    bytes4 internal constant SETTLE_DEPOSIT = 0xd24ca58a; // settleDeposit(uint256)
    bytes4 internal constant SETTLE_REDEEM = 0xa627df66; // settleRedeem(uint256)
    // The DelayProxyAdmin's REAL selectors (verified against the Sourcify source of the live admin, round 10).
    bytes4 internal constant SUBMIT_IMPL = 0x657081b3; // submitImplementation(address)
    bytes4 internal constant UPGRADE_AND_CALL = 0x9623609d; // upgradeAndCall(address,address,bytes)
    bytes4 internal constant SUBMIT_DELAY = 0x432efade; // submitDelay(uint256)
    bytes4 internal constant TRANSFER_OWNERSHIP = 0xf2fde38b; // transferOwnership(address)

    CuratorGuard internal guard;
    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal attacker = makeAddr("attacker");
    address internal stranger = makeAddr("stranger");
    address internal signer;
    address internal impl;

    function setUp() public {
        safe = ISafe(SAFE);
        if (bytes(vm.envOr("ETHEREUM_FORK_NODE_URL", string(""))).length == 0) {
            vm.skip(true);
            return;
        }
        uint256 _blockNumber = vm.envOr("ETHEREUM_FORK_BLOCK_NUMBER", uint256(0));
        if (_blockNumber > 0) vm.createSelectFork("ethereum", _blockNumber);
        else vm.createSelectFork("ethereum");
        assertEq(block.chainid, 1, "ETHEREUM_FORK_NODE_URL is not Ethereum mainnet");
        assertEq(keccak256(bytes(safe.VERSION())), keccak256("1.4.1"), "safe version");
        impl = _implOf(VAULT_USDC);

        guard = new CuratorGuard(0, vetro, council);
        _applyShippedPolicyShape();

        // The runbook's 7.4 install: a 1-of-N signer, then handler removal + setGuard in one genuine batch.
        (signer, signerPk) = makeAddrAndKey("g10d-signer");
        vm.prank(SAFE);
        safe.addOwnerWithThreshold(signer, 1);
        bytes memory _install = abi.encodeWithSelector(
            0x8d80ff0a,
            abi.encodePacked(
                _entry(SAFE, abi.encodeWithSignature("setFallbackHandler(address)", address(0))),
                _entry(SAFE, abi.encodeCall(ISafe.setGuard, (address(guard))))
            )
        );
        assertTrue(_execSafeTx(MULTISEND_CALL_ONLY_141, 0, _install, Operation.DelegateCall), "install");
        assertEq(address(uint160(uint256(bytes32(safe.getStorageAt(uint256(GUARD_SLOT), 1))))), address(guard));
        assertEq(uint256(bytes32(safe.getStorageAt(uint256(FALLBACK_SLOT), 1))), 0, "handler removed");
    }

    /*//////////////////////////////////////////////////////////////
               WHO CAN CHANGE THE VENUES' CODE (LIVE FACTS)
    //////////////////////////////////////////////////////////////*/

    /// @dev All five vaults run one implementation behind a `LagoonVaultProxy` whose ONLY upgrade path is
    ///      `upgradeToAndCall` from its `DelayProxyAdmin` (owner: the curator Safe, 1-day delay, nothing
    ///      pending), gated by Lagoon's registry, which can only whitelist, never push. The guard refuses
    ///      every selector of the admin from the Safe (the real ones: g9d pinned two that do not exist on
    ///      it), a stranger is not its owner, and the registry owner cannot upgrade a vault. The allowance
    ///      to each vault is at max: that is what a hostile implementation would take.
    function test_live_the_vaults_code_moves_only_through_the_safes_own_proxy_admin() public {
        address[5] memory _vaults = [VAULT_USDC, VAULT_USDT, VAULT_WBTC, VAULT_CBBTC, VAULT_HEMIBTC];
        address[5] memory _assets = [USDC, USDT, WBTC, CBBTC, HEMIBTC];
        address _registry = ILagoonVaultProxy(VAULT_USDC).REGISTRY();
        assertEq(ILogicRegistry(_registry).owner(), REGISTRY_OWNER, "registry owned by Lagoon");
        assertFalse(ILogicRegistry(_registry).canUseLogic(impl, attacker), "the registry gates");
        for (uint256 i; i < 5; ++i) {
            assertEq(_implOf(_vaults[i]), impl, "one implementation");
            assertEq(ILagoonVaultProxy(_vaults[i]).REGISTRY(), _registry);
            IDelayProxyAdmin _admin = IDelayProxyAdmin(address(uint160(uint256(vm.load(_vaults[i], ADMIN_SLOT)))));
            assertEq(_admin.owner(), SAFE, "the Safe owns the proxy admin");
            assertEq(_admin.newImplementation(), address(0), "nothing pending");
            assertEq(_admin.implementationUpdateTime(), type(uint256).max);
            assertEq(_admin.delay(), 1 days);
            assertGe(IERC20Like(_assets[i]).allowance(SAFE, _vaults[i]), 1 << 255, "allowance at max");
            // From the Safe, the admin's real surface is refused whatever the selector.
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(_admin), SUBMIT_IMPL));
            _execSafeTx(address(_admin), 0, abi.encodeWithSelector(SUBMIT_IMPL, attacker), Operation.Call);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(_admin), UPGRADE_AND_CALL));
            _execSafeTx(address(_admin), 0, abi.encodeWithSelector(UPGRADE_AND_CALL, _vaults[i], attacker, ""), Operation.Call);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(_admin), TRANSFER_OWNERSHIP));
            _execSafeTx(address(_admin), 0, abi.encodeWithSelector(TRANSFER_OWNERSHIP, attacker), Operation.Call);
            vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(_admin), SUBMIT_DELAY));
            _execSafeTx(address(_admin), 0, abi.encodeWithSelector(SUBMIT_DELAY, uint256(1 days)), Operation.Call);
            // A stranger is not the admin's owner.
            vm.prank(stranger);
            vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
            _admin.submitImplementation(attacker);
            // The registry owner is not the proxy's admin: its `upgradeToAndCall` is forwarded to the logic and does nothing.
            vm.prank(REGISTRY_OWNER);
            (bool _ok, ) = _vaults[i].call(abi.encodeWithSignature("upgradeToAndCall(address,bytes)", attacker, ""));
            assertFalse(_ok);
            assertEq(_implOf(_vaults[i]), impl, "unchanged");
        }
    }

    /*//////////////////////////////////////////////////////////////
                 A HOSTILE IMPLEMENTATION UNDER THE POLICY
    //////////////////////////////////////////////////////////////*/

    /// @dev The implementation turned hostile (an upgrade the Safe's own admin landed, or a backdoor in the
    ///      deployed logic): the allowlisted, unconstrained `updateNewTotalAssets` takes the Safe's whole
    ///      USDC balance through the max allowance, reported as Policy. From inside the call it can do
    ///      nothing else: a leaked signed transaction nested into the real 0.7.6 Safe is `NestedExecution`,
    ///      a forged post-hook `MissingSnapshot`, a role call `Unauthorized`, a direct `setGuard` GS031.
    function test_hostile_vault_implementation_takes_the_whole_allowance_through_an_allowlisted_call() public {
        HostileVenue _brain = new HostileVenue();
        vm.etch(impl, address(new HostileVaultLogic(USDC, SAFE, attacker, _brain)).code);
        uint256 _custody = IERC20Like(USDC).balanceOf(SAFE);
        assertGt(_custody, 0, "the live Safe holds USDC");
        uint256 _nonce = _nonceOf(safe);
        _brain.queueCall(address(safe), 0, _signedExecCalldata(safe, signerPk, _nonce + 1, VAULT_USDC, 0, abi.encodeWithSelector(SETTLE_DEPOSIT, 0), Operation.Call));
        _brain.queueCall(address(guard), 0, abi.encodeCall(guard.checkAfterExecution, (bytes32("forged"), true)));
        _brain.queueCall(address(guard), 0, abi.encodeCall(guard.lockdown, (SAFE)));
        _brain.queueCall(SAFE, 0, abi.encodeCall(ISafe.setGuard, (address(0))));

        vm.recordLogs();
        assertTrue(_execSafeTx(VAULT_USDC, 0, abi.encodeWithSelector(UPDATE_NAV, uint256(1)), Operation.Call));
        (uint256 _n, uint8 _outcome, ) = _reports(vm.getRecordedLogs(), address(guard));
        assertEq(_n, 1);
        assertEq(_outcome, uint8(CuratorGuard.Outcome.Policy), "an allowlisted call, as far as the guard can see");
        assertEq(IERC20Like(USDC).balanceOf(attacker), _custody, "the whole balance left through the allowance");
        assertEq(IERC20Like(USDC).balanceOf(SAFE), 0);
        assertEq(_brain.count(), 4);
        assertEq(_brain.selectorOf(0), CuratorGuard.NestedExecution.selector);
        assertEq(_brain.selectorOf(1), CuratorGuard.MissingSnapshot.selector);
        assertEq(_brain.selectorOf(2), CuratorGuardPolicy.Unauthorized.selector);
        assertEq(_reason(_brain.ret(3)), "GS031");
        assertEq(address(uint160(uint256(bytes32(safe.getStorageAt(uint256(GUARD_SLOT), 1))))), address(guard));
        assertEq(_nonceOf(safe), _nonce + 1);
    }

    /// @dev The same hostile implementation against a policy whose `approve` is bound to the vault AND to a
    ///      per-settlement amount, after the live max allowance is reset: the take is one cap. The policy
    ///      engine and the lint accept the rule today; the cost is one `approve` per `settleRedeem`.
    function test_a_per_settlement_allowance_cap_bounds_what_a_hostile_implementation_takes() public {
        uint256 _cap = 500_000; // 0.5 USDC against a live balance of about 1 USDC
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](2);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0);
        _rules[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 1, bytes32(_cap));
        vm.startPrank(vetro);
        guard.allowFunction(SAFE, USDC, APPROVE, false, _rules);
        bytes32[] memory _v = new bytes32[](1);
        _v[0] = bytes32(uint256(uint160(VAULT_USDC)));
        guard.addAllowedValues(SAFE, USDC, APPROVE, 0, _v);
        vm.stopPrank();

        assertTrue(_execSafeTx(USDC, 0, abi.encodeWithSelector(APPROVE, VAULT_USDC, 0), Operation.Call), "reset the live max allowance");
        assertTrue(_execSafeTx(USDC, 0, abi.encodeWithSelector(APPROVE, VAULT_USDC, _cap), Operation.Call), "one settlement's worth");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, USDC, APPROVE, uint16(1), bytes32(type(uint256).max)));
        _execSafeTx(USDC, 0, abi.encodeWithSelector(APPROVE, VAULT_USDC, type(uint256).max), Operation.Call);

        uint256 _custody = IERC20Like(USDC).balanceOf(SAFE);
        assertGt(_custody, _cap);
        vm.etch(impl, address(new HostileVaultLogic(USDC, SAFE, attacker, HostileVenue(payable(address(0))))).code);
        assertTrue(_execSafeTx(VAULT_USDC, 0, abi.encodeWithSelector(UPDATE_NAV, uint256(1)), Operation.Call));
        assertEq(IERC20Like(USDC).balanceOf(attacker), _cap, "the take is one cap");
        assertEq(IERC20Like(USDC).balanceOf(SAFE), _custody - _cap);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _implOf(address proxy_) internal view returns (address) {
        return address(uint160(uint256(vm.load(proxy_, IMPL_SLOT))));
    }

    /// @dev The shipped shape for USDC and its vault, the handler requirement of zero, Enforced.
    function _applyShippedPolicyShape() internal {
        vm.startPrank(vetro);
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](1);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0);
        guard.allowFunction(SAFE, USDC, APPROVE, false, _rules);
        bytes32[] memory _v = new bytes32[](1);
        _v[0] = bytes32(uint256(uint160(VAULT_USDC)));
        guard.addAllowedValues(SAFE, USDC, APPROVE, 0, _v);
        guard.allowFunction(SAFE, VAULT_USDC, UPDATE_NAV, false, _noRules());
        guard.allowFunction(SAFE, VAULT_USDC, SETTLE_DEPOSIT, false, _noRules());
        guard.allowFunction(SAFE, VAULT_USDC, SETTLE_REDEEM, false, _noRules());
        guard.setRequiredFallbackHandler(SAFE, address(0), true);
        guard.enforce(SAFE);
        vm.stopPrank();
    }

    function _noRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _r) {}

    function _entry(address to_, bytes memory data_) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to_, uint256(0), data_.length, data_);
    }
}
