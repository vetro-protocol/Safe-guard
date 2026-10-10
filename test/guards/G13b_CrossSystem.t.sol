// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

interface IERC20Like {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

interface ILagoonV06 {
    function requestDeposit(uint256 assets, address controller, address owner) external payable returns (uint256);
    function deposit(uint256 assets, address receiver) external returns (uint256);
    function claimableDepositRequest(uint256 requestId, address controller) external view returns (uint256);
    function totalAssets() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function isAllowed(address account) external view returns (bool);
}

interface IFeeRegistry {
    function owner() external view returns (address);
    function protocolFeeReceiver() external view returns (address);
    function protocolRate() external view returns (uint256);
    function updateDefaultRate(uint16 rate) external;
}

/// @dev A contract whose `isSanctioned` reverts: stands in for a broken external sanctions list or a
///      registry proxy upgraded to reverting logic (both are keys OUTSIDE the curator Safe and the guard).
contract RevertingOracle {
    function isSanctioned(address) external pure returns (bool) {
        revert("down");
    }
}

/// @title G13b_CrossSystem: THE CROSS-SYSTEM ADVERSARY
/// @notice Round 13, reviewer g13b. The attacker never touches the guard; it acts through Lagoon. The guard
///         admits exactly the shipped policy's calls; a Lagoon-side action (a key OUTSIDE the curator Safe
///         and outside the guard's admin) then turns a guard-admitted transaction into a denial or changes
///         its economics, with the guard blind to it. A mainnet fork of the live Vetro curator Safe
///         (v1.4.1, 2-of-4), the shipped USDC shape installed through the §7.4 batch, genuine
///         `execTransaction`s, the live v0.6.0 vault. Requires `ETHEREUM_FORK_NODE_URL`.
contract G13b_CrossSystemTest is SafeTxHelper {
    address internal constant SAFE = 0x1b534a8543212F5957168D83311A41E0Ea1cfe48;
    address internal constant MSCO141 = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant VAULT_USDC = 0x131CcfDFfeD712885aAc31445d351E6b62656679;
    address internal constant FEE_REGISTRY = 0x6dA4D1859bA1d02D095D2246142CdAd52233e27C;

    bytes32 internal constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    // hopper.storage.Whitelistable: +0 isWhitelisted, +1 accessMode, +2 isBlacklisted, +3 externalSanctionList.
    uint256 internal constant WL_BASE = 0x083cc98ab296d1a1f01854b5f7a2f47df4425a56ba7b35f7faa3a336067e4800;

    bytes4 internal constant UPDATE_NAV = 0xbcd1bf34;
    bytes4 internal constant SETTLE_DEPOSIT = 0xd24ca58a;
    bytes4 internal constant CLAIM_SHARES = 0xf15be6f9; // claimSharesOnBehalf(address[])

    CuratorGuard internal guard;
    ILagoonV06 internal vault = ILagoonV06(VAULT_USDC);
    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal strategy = makeAddr("strategy-stand-in"); // a controller the vault admits (blacklist mode)
    address internal signer;

    function setUp() public {
        safe = ISafe(SAFE);
        if (bytes(vm.envOr("ETHEREUM_FORK_NODE_URL", string(""))).length == 0) {
            vm.skip(true);
            return;
        }
        uint256 _b = vm.envOr("ETHEREUM_FORK_BLOCK_NUMBER", uint256(0));
        if (_b > 0) vm.createSelectFork("ethereum", _b);
        else vm.createSelectFork("ethereum");
        assertEq(block.chainid, 1, "not mainnet");

        guard = new CuratorGuard(0, vetro, council);
        vm.startPrank(vetro);
        CuratorGuardPolicy.ParamRule[] memory _none;
        guard.allowFunction(SAFE, VAULT_USDC, UPDATE_NAV, false, _none);
        guard.allowFunction(SAFE, VAULT_USDC, SETTLE_DEPOSIT, false, _none);
        guard.allowFunction(SAFE, VAULT_USDC, CLAIM_SHARES, false, _none);
        guard.setRequiredFallbackHandler(SAFE, address(0), true);
        guard.enforce(SAFE);
        vm.stopPrank();

        (signer, signerPk) = makeAddrAndKey("g13b-signer");
        vm.prank(SAFE);
        safe.addOwnerWithThreshold(signer, 1);
        bytes memory _install = abi.encodeWithSelector(
            0x8d80ff0a,
            abi.encodePacked(
                _entry(SAFE, abi.encodeWithSignature("setFallbackHandler(address)", address(0))),
                _entry(SAFE, abi.encodeCall(ISafe.setGuard, (address(guard))))
            )
        );
        assertTrue(_execSafeTx(MSCO141, 0, _install, Operation.DelegateCall), "install");
        assertEq(address(uint160(uint256(bytes32(safe.getStorageAt(uint256(GUARD_SLOT), 1))))), address(guard));
    }

    /// @dev A guard-admitted `claimSharesOnBehalf([strategy])` is the policy entry that moves the Vesper
    ///      strategy's settled deposit into shares. A Lagoon-side action nobody at Vetro signed — a reverting
    ///      external sanctions oracle in the vault's `hopper.storage.Whitelistable` slot, or the registry
    ///      proxy broken — makes `isAllowed` revert, so the guard admits the call and it reverts inside
    ///      Lagoon: the strategy's position is frozen (claims, user redeems and the keeper's report all pass
    ///      through `isAllowed`), and the curator cannot repair it. The guard's events show nothing (the
    ///      transaction reverts whole). Only Lagoon (the sanctions oracle / the registry key) can lift it.
    function test_G13b1_a_lagoon_sanctions_or_registry_break_bricks_a_guard_admitted_claim() public {
        // A funded strategy position: the stranger (strategy stand-in) has a settled, claimable deposit.
        deal(USDC, strategy, 100_000e6);
        vm.startPrank(strategy);
        IERC20Like(USDC).approve(VAULT_USDC, 100_000e6);
        vault.requestDeposit(100_000e6, strategy, strategy);
        vm.stopPrank();
        assertTrue(_mark(vault.totalAssets()), "mark");
        assertTrue(_settle(vault.totalAssets()), "settle: the deposit lands, claimable to the strategy");
        assertGt(vault.claimableDepositRequest(0, strategy), 0, "claimable");

        // Guard-admitted claim works today.
        address[] memory _who = new address[](1);
        _who[0] = strategy;
        uint256 _snap = vm.snapshot();
        assertTrue(_execSafeTx(VAULT_USDC, 0, abi.encodeWithSelector(CLAIM_SHARES, _who), Operation.Call), "claim ok");
        assertGt(vault.balanceOf(strategy), 0, "shares to the strategy");
        vm.revertTo(_snap);

        // Lagoon-side action: a reverting external sanctions oracle (whitelistManager's call; or a broken
        // registry proxy — both outside the curator Safe and the guard). `isAllowed` now reverts.
        address _oracle = address(new RevertingOracle());
        vm.store(VAULT_USDC, bytes32(WL_BASE + 3), bytes32(uint256(uint160(_oracle))));
        vm.expectRevert(); // isAllowed reverts inside Lagoon; the Safe surfaces it (GS013 at safeTxGas 0)
        vault.isAllowed(strategy);

        // The SAME guard-admitted claim now reverts whole; the guard emitted nothing, custody is frozen.
        vm.expectRevert(bytes("GS013"));
        _execSafeTx(VAULT_USDC, 0, abi.encodeWithSelector(CLAIM_SHARES, _who), Operation.Call);

        // Only Lagoon can lift it; the curator's policy traffic cannot.
        vm.store(VAULT_USDC, bytes32(WL_BASE + 3), bytes32(uint256(0)));
        assertTrue(_execSafeTx(VAULT_USDC, 0, abi.encodeWithSelector(CLAIM_SHARES, _who), Operation.Call), "repaired");
    }

    /// @dev The Lagoon fee registry (an upgradeable proxy owned by Lagoon's key, `0x9A40…d4B`, which is also
    ///      the `protocolFeeReceiver`) sets, with no Vetro or curator consent, the protocol's cut of every
    ///      manager fee the Vetro manager earns through its guard-admitted settlements. Lagoon raises it up
    ///      to `MAX_PROTOCOL_RATE` (30 %) on its own. The curator Safe and the guard are blind to it; the
    ///      guard's "Vetro gains no custody power" does not bound what the surrounding protocol takes from a
    ///      guard-admitted transaction.
    function test_G13b2_lagoon_sets_its_protocol_cut_of_every_guard_admitted_settlement() public {
        IFeeRegistry _reg = IFeeRegistry(FEE_REGISTRY);
        address _owner = _reg.owner();
        uint256 _before = _reg.protocolRate(); // protocolRate(msg.sender==this)=default; read vault's below
        emit log_named_address("registry owner (Lagoon; also protocolFeeReceiver)", _owner);
        emit log_named_address("protocolFeeReceiver", _reg.protocolFeeReceiver());
        emit log_named_uint("protocol rate before (bps)", _before);

        // A single Lagoon-side call, no Vetro signature, raises the protocol cut to the 30 % cap.
        vm.prank(_owner);
        _reg.updateDefaultRate(5000); // above MAX_PROTOCOL_RATE; FeeLib.protocolRate clamps to 3000
        uint256 _after = _reg.protocolRate();
        emit log_named_uint("protocol rate after one Lagoon call (bps, clamped)", _after);
        assertGt(_after, _before, "Lagoon raised its cut unilaterally");
        assertEq(_after, 5000, "registry stores the raw rate; the vault clamps at use to 3000");
        // The protocol fee receiver is Lagoon's own key, always allowed and never blacklistable.
        assertTrue(vault.isAllowed(_reg.protocolFeeReceiver()), "the receiver is always allowed");
    }

    function _mark(uint256 n_) internal returns (bool) {
        return _execSafeTx(VAULT_USDC, 0, abi.encodeWithSelector(UPDATE_NAV, n_), Operation.Call);
    }

    function _settle(uint256 n_) internal returns (bool) {
        return _execSafeTx(VAULT_USDC, 0, abi.encodeWithSelector(SETTLE_DEPOSIT, n_), Operation.Call);
    }

    function _entry(address to_, bytes memory data_) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to_, uint256(0), data_.length, data_);
    }
}
