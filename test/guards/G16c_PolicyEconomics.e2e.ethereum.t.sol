// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {SettlementDeadline} from "contracts/helpers/SettlementDeadline.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";
import {FakeDeadlineAlwaysPass, KillSwitchDeadline} from "test/guards/G16c_Helpers.sol";

interface IERC20Min {
    function balanceOf(address) external view returns (uint256);

    function approve(address, uint256) external returns (bool);
}

interface IVaultV06 {
    function requestDeposit(uint256 assets, address controller, address owner) external returns (uint256);

    function deposit(uint256 assets, address receiver, address controller) external returns (uint256);

    function requestRedeem(uint256 shares, address controller, address owner) external returns (uint256);

    function redeem(uint256 shares, address receiver, address controller) external returns (uint256);

    function totalAssets() external view returns (uint256);

    function totalSupply() external view returns (uint256);

    function balanceOf(address) external view returns (uint256);

    function convertToAssets(uint256 shares) external view returns (uint256);

    function maxCap() external view returns (uint256);

    function updateMaxCap(uint256) external;
}

/// @title G16c: THE ECONOMIC AND POLICY ADVERSARY OF THE FINAL POLICY, on a mainnet fork of the live curator Safe
/// @notice Round 16, reviewer g16c. The shipped policy plus the round-13 additions (the banded-entry gate, the
///         settlement-deadline helper) priced against capital and against a policy-file reviewer. The guard is deployed
///         fresh with the shipped shape and installed through the runbook's 7.4 batch by a 1-of-N signer the test adds
///         (the live owners' keys are unknown); the USDC vault is funded by a stand-in holder `vesper` that plays the
///         strategy's position; the WBTC vault is the live EMPTY one (totalAssets() == 0 at the fork block).
///         Requires `ETHEREUM_FORK_NODE_URL` (archive) and `ETHEREUM_FORK_BLOCK_NUMBER`.
contract G16c_PolicyEconomicsTest is SafeTxHelper {
    address internal constant SAFE = 0x1b534a8543212F5957168D83311A41E0Ea1cfe48;
    address internal constant MSCO141 = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;
    address internal constant VAULT_USDC = 0x131CcfDFfeD712885aAc31445d351E6b62656679;
    address internal constant VAULT_WBTC = 0x1a9b5c9845c2685923215779c6Ec288bD5090e90;

    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes4 internal constant APPROVE = 0x095ea7b3;
    bytes4 internal constant UPDATE_NAV = 0xbcd1bf34; // updateNewTotalAssets(uint256)
    bytes4 internal constant SETTLE_DEPOSIT = 0xd24ca58a; // settleDeposit(uint256)
    bytes4 internal constant SETTLE_REDEEM = 0xa627df66; // settleRedeem(uint256)

    uint256 internal constant ONE_USDC = 1e6;
    uint256 internal constant ONE_BTC = 1e8;

    CuratorGuard internal guard;
    IVaultV06 internal vault = IVaultV06(VAULT_USDC);
    IVaultV06 internal btcVault = IVaultV06(VAULT_WBTC);
    IERC20Min internal usdc = IERC20Min(USDC);
    IERC20Min internal wbtc = IERC20Min(WBTC);

    address internal vetro = makeAddr("vetro"); // the guard's admin (the timelock in production)
    address internal council = makeAddr("council");
    address internal vesper = makeAddr("vesper"); // stands in for the strategy's position
    address internal colluder = makeAddr("colluder"); // the quorum's accomplice: capital, no keys
    address internal outsider = makeAddr("outsider"); // capital, no keys
    address internal signer;

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

        guard = new CuratorGuard(0, vetro, council);
        _allowVault(VAULT_USDC, USDC);
        _allowVault(VAULT_WBTC, WBTC);
        vm.startPrank(vetro);
        guard.setMultiSendUnwrapper(SAFE, MSCO141, true);
        guard.setRequiredFallbackHandler(SAFE, address(0), true);
        guard.enforce(SAFE);
        vm.stopPrank();

        (signer, signerPk) = makeAddrAndKey("g16c-signer");
        vm.prank(SAFE);
        safe.addOwnerWithThreshold(signer, 1);
        bytes memory _install = _batch(
            abi.encodePacked(
                _entry(SAFE, abi.encodeWithSignature("setFallbackHandler(address)", address(0))),
                _entry(SAFE, abi.encodeCall(ISafe.setGuard, (address(guard))))
            )
        );
        assertTrue(_execSafeTx(MSCO141, 0, _install, Operation.DelegateCall), "install");
        assertEq(address(uint160(uint256(bytes32(safe.getStorageAt(uint256(GUARD_SLOT), 1))))), address(guard));
    }

    /*//////////////////////////////////////////////////////////////
       1. A BAND THE GATE AND THE LINT ADMIT SILENTLY: +-50 % PRICED
    //////////////////////////////////////////////////////////////*/

    /// @dev The sync's first-sync gate admits any band that contains the live NAV and is no wider than it
    ///      (`hi - lo <= totalAssets()`), the lint warns only above a 100x span: a +-50 % band passes both without a
    ///      word. Under it a colluding quorum with an accomplice's capital D runs ONE cycle: mark the floor, settle the
    ///      accomplice's deposit at it, mark the ceiling, settle its redeem at it. The take is the closed form
    ///      (sqrt(1+x) - sqrt(1-x))^2 of NAV at the optimal D = n(sqrt(1-x^2) - (1-x))... measured here, 26.8 % of the
    ///      stand-in strategy's position, against 0.25 % under the +-5 % band of docs section 5 (review G11b-3).
    function test_G16c_1_a_pm50_band_admitted_by_the_gate_leaks_a_quarter_of_nav_per_colluding_cycle() public {
        _fund(VAULT_USDC, USDC, vesper, 1_000_000 * ONE_USDC);
        uint256 n = vault.totalAssets();
        _band(VAULT_USDC, n, 5000); // +-50 %: lo = n/2, hi = 3n/2; width n == totalAssets(): the gate's edge, admitted
        uint256 _lo = (n * 5000) / 10_000;
        uint256 _hi = (n * 15_000) / 10_000;
        assertLe(_hi - _lo, n, "the gate's width rule admits it (hi - lo <= totalAssets())");
        assertLe(_hi, _lo * 100, "the lint's 100x rule stays silent");

        uint256 _before = vault.convertToAssets(vault.balanceOf(vesper));
        uint256 D = (n * 366) / 1000; // the accomplice's capital, near the optimum for x = 0.5
        _settle(VAULT_USDC, _lo, SETTLE_REDEEM); // mark the floor (nothing pending: the mark moves totalAssets)
        _request(VAULT_USDC, USDC, colluder, D);
        _settle(VAULT_USDC, _lo, SETTLE_DEPOSIT); // the accomplice is priced at the floor
        vm.prank(colluder);
        vault.deposit(D, colluder, colluder);
        uint256 _shares = vault.balanceOf(colluder);
        vm.prank(colluder);
        vault.requestRedeem(_shares, colluder, colluder);
        _settle(VAULT_USDC, _hi, SETTLE_REDEEM); // mark the ceiling and pay the accomplice out at it
        vm.prank(colluder);
        vault.redeem(_shares, colluder, colluder);

        uint256 _paid = usdc.balanceOf(colluder);
        uint256 _gain = _paid - D;
        // What is left for the strategy at an honest mark of what remains in custody.
        uint256 _custody = usdc.balanceOf(SAFE);
        _settle(VAULT_USDC, _custody, SETTLE_REDEEM);
        uint256 _after = vault.convertToAssets(vault.balanceOf(vesper));
        emit log_named_uint("NAV before the cycle (USDC, 6 dp)", n);
        emit log_named_uint("accomplice capital D", D);
        emit log_named_uint("accomplice paid out", _paid);
        emit log_named_uint("accomplice gain", _gain);
        emit log_named_uint("gain in bp of NAV", (_gain * 10_000) / n);
        emit log_named_uint("strategy position before", _before);
        emit log_named_uint("strategy position after", _after);
        assertGt(_gain, (n * 25) / 100, "more than a quarter of NAV in one cycle under a +-50 % band");
        assertLt(_after, (_before * 75) / 100, "the strategy lost it");
    }

    /// @dev The control: the same cycle at the optimal capital under the +-5 % band of docs section 5 takes 0.25 %.
    function test_G16c_1b_control_the_pm5_band_leaks_a_quarter_of_a_percent() public {
        _fund(VAULT_USDC, USDC, vesper, 1_000_000 * ONE_USDC);
        uint256 n = vault.totalAssets();
        _band(VAULT_USDC, n, 500);
        uint256 _lo = (n * 9500) / 10_000;
        uint256 _hi = (n * 10_500) / 10_000;
        uint256 D = (n * 4875) / 100_000; // the optimum for x = 0.05
        _settle(VAULT_USDC, _lo, SETTLE_REDEEM);
        _request(VAULT_USDC, USDC, colluder, D);
        _settle(VAULT_USDC, _lo, SETTLE_DEPOSIT);
        vm.prank(colluder);
        vault.deposit(D, colluder, colluder);
        uint256 _shares = vault.balanceOf(colluder);
        vm.prank(colluder);
        vault.requestRedeem(_shares, colluder, colluder);
        _settle(VAULT_USDC, _hi, SETTLE_REDEEM);
        vm.prank(colluder);
        vault.redeem(_shares, colluder, colluder);
        uint256 _gain = usdc.balanceOf(colluder) - D;
        emit log_named_uint("gain in bp of NAV under +-5 %", (_gain * 10_000) / n);
        assertApproxEqAbs((_gain * 10_000) / n, 25, 2, "about 25 bp: x^2 of NAV (review G11b-3)");
    }

    /*//////////////////////////////////////////////////////////////
          2. THE DEADLINE ENTRY: A LOOK-ALIKE BINDS NOTHING
    //////////////////////////////////////////////////////////////*/

    /// @dev The policy entry is `{ target, signature: assertBefore(uint256) }`, a plain call with no rules; nothing
    ///      checks the code behind the target. A helper that dispatches the selector and never reverts lints valid,
    ///      syncs without a warning (measured with the real task on the fork, notes/) and leaves the signers
    ///      believing their confirmed batches expire: the outsider lands the stale batch exactly as in review G13e-1.
    function test_G16c_2_an_always_pass_look_alike_at_the_deadline_entry_lands_a_stale_signed_batch() public {
        _fund(VAULT_USDC, USDC, vesper, 1_000_000 * ONE_USDC);
        uint256 nav0 = vault.totalAssets();
        FakeDeadlineAlwaysPass _fake = new FakeDeadlineAlwaysPass();
        CuratorGuardPolicy.ParamRule[] memory _none;
        vm.prank(vetro);
        guard.allowFunction(SAFE, address(_fake), SettlementDeadline.assertBefore.selector, false, _none);
        _band(VAULT_USDC, nav0, 500);

        uint256 _mark = nav0; // honest when signed
        uint256 _deadline = block.timestamp + 6 hours;
        bytes memory _signed = _signedBatch(
            abi.encodePacked(
                _entry(address(_fake), abi.encodeCall(SettlementDeadline.assertBefore, (_deadline))),
                _entry(VAULT_USDC, abi.encodeWithSelector(UPDATE_NAV, _mark)),
                _entry(VAULT_USDC, abi.encodeWithSelector(SETTLE_DEPOSIT, _mark))
            )
        );
        vm.warp(_deadline + 1 days); // stale by a day
        uint256 _value = (nav0 * 101) / 100; // the curator would mark 1 % higher now
        uint256 _deposit = 30_000 * ONE_USDC;
        _request(VAULT_USDC, USDC, outsider, _deposit);
        vm.prank(outsider);
        (bool _ok, ) = address(safe).call(_signed);
        assertTrue(_ok, "the stale batch lands: the look-alike checked nothing");
        vm.prank(outsider);
        vault.deposit(_deposit, outsider, outsider);
        uint256 _shares = vault.balanceOf(outsider);
        _settle(VAULT_USDC, _value + _deposit, SETTLE_REDEEM);
        uint256 _worth = vault.convertToAssets(_shares);
        emit log_named_uint("outsider gain at a 1 % stale mark (USDC, 6 dp)", _worth - _deposit);
        assertApproxEqAbs(_worth - _deposit, (_deposit * (_value - _mark)) / (_mark + _deposit), 2, "G13e-1's gain");
    }

    /// @dev The control: the real helper kills the same stale batch for every executor (GS013, the nonce kept).
    function test_G16c_2b_control_the_real_helper_kills_the_stale_batch() public {
        _fund(VAULT_USDC, USDC, vesper, 1_000_000 * ONE_USDC);
        uint256 nav0 = vault.totalAssets();
        SettlementDeadline _dl = new SettlementDeadline();
        CuratorGuardPolicy.ParamRule[] memory _none;
        vm.prank(vetro);
        guard.allowFunction(SAFE, address(_dl), SettlementDeadline.assertBefore.selector, false, _none);
        _band(VAULT_USDC, nav0, 500);
        uint256 _deadline = block.timestamp + 6 hours;
        bytes memory _signed = _signedBatch(
            abi.encodePacked(
                _entry(address(_dl), abi.encodeCall(SettlementDeadline.assertBefore, (_deadline))),
                _entry(VAULT_USDC, abi.encodeWithSelector(UPDATE_NAV, nav0)),
                _entry(VAULT_USDC, abi.encodeWithSelector(SETTLE_DEPOSIT, nav0))
            )
        );
        uint256 _nonce = uint256(vm.load(SAFE, bytes32(NONCE_SLOT)));
        vm.warp(_deadline + 1 days);
        vm.prank(outsider);
        (bool _ok, bytes memory _ret) = address(safe).call(_signed);
        assertFalse(_ok, "dead for everyone");
        assertEq(_reason(_ret), "GS013", "the inner call failed");
        assertEq(uint256(vm.load(SAFE, bytes32(NONCE_SLOT))), _nonce, "nonce kept");
    }

    /// @dev A helper with a kill switch: its owner can make every batch carrying the entry revert, and that is all,
    ///      because the entry is the signers' discipline, not the guard's: the same batch without it lands. The
    ///      price of a hostile or broken helper is therefore the deadline protection itself, never settlement.
    function test_G16c_2c_a_kill_switch_helper_costs_the_signers_nothing_but_the_deadline_discipline() public {
        _fund(VAULT_USDC, USDC, vesper, 1_000_000 * ONE_USDC);
        uint256 nav0 = vault.totalAssets();
        vm.prank(outsider);
        KillSwitchDeadline _ks = new KillSwitchDeadline(); // the outsider owns the switch
        CuratorGuardPolicy.ParamRule[] memory _none;
        vm.prank(vetro);
        guard.allowFunction(SAFE, address(_ks), SettlementDeadline.assertBefore.selector, false, _none);
        _band(VAULT_USDC, nav0, 500);
        bytes memory _withEntry = _batch(
            abi.encodePacked(
                _entry(address(_ks), abi.encodeCall(SettlementDeadline.assertBefore, (block.timestamp + 1 hours))),
                _entry(VAULT_USDC, abi.encodeWithSelector(UPDATE_NAV, nav0)),
                _entry(VAULT_USDC, abi.encodeWithSelector(SETTLE_DEPOSIT, nav0))
            )
        );
        assertTrue(_execSafeTx(MSCO141, 0, _withEntry, Operation.DelegateCall), "lands while the switch is off");
        vm.prank(outsider);
        _ks.setHalted(true);
        vm.expectRevert(bytes("GS013"));
        _execSafeTx(MSCO141, 0, _withEntry, Operation.DelegateCall);
        // The signers drop the entry: settlement continues, the deadline protection is gone.
        _settle(VAULT_USDC, nav0, SETTLE_DEPOSIT);
    }

    /*//////////////////////////////////////////////////////////////
         3. A VACUOUS BAND ON AN EMPTY VAULT (THE GATE SKIPS IT)
    //////////////////////////////////////////////////////////////*/

    /// @dev The first-sync gate reads `totalAssets()` and `continue`s when it is zero, the lint stays silent at a
    ///      span of exactly 100x: on the three live BTC vaults (totalAssets() == 0 at the fork block) a band
    ///      [0.01 BTC, 1 BTC] syncs with no flag and no word (measured with the real task, notes/). It then forces the
    ///      honest first mark up to its floor and, once the vault holds 1 BTC, admits a -99 % mark: one cycle with an
    ///      accomplice's 0.01 BTC takes half the position.
    function test_G16c_3_a_vacuous_band_on_the_empty_wbtc_vault_admits_a_minus_99_percent_mark() public {
        assertEq(btcVault.totalAssets(), 0, "the live WBTC vault is empty at the fork block");
        if (btcVault.maxCap() < 2 * ONE_BTC) {
            vm.prank(SAFE);
            btcVault.updateMaxCap(type(uint256).max); // onlySafe; out of policy, a fixture step
        }
        uint256 _lo = ONE_BTC / 100; // 0.01 BTC
        uint256 _hi = ONE_BTC; // 1 BTC: exactly 100x the floor, under the lint's warning line
        _bandAbs(VAULT_WBTC, _lo, _hi);

        // The honest depositor funds 1 BTC; the honest first mark (0: nothing under management yet) is refused.
        _request(VAULT_WBTC, WBTC, vesper, ONE_BTC);
        _expectMarkRefused(VAULT_WBTC, 0);
        _settle(VAULT_WBTC, _lo, SETTLE_DEPOSIT); // the band's floor is the lowest mark the guard admits
        vm.prank(vesper);
        btcVault.deposit(ONE_BTC, vesper, vesper);
        assertEq(wbtc.balanceOf(SAFE), ONE_BTC, "custody: 1 BTC in the Safe");

        // The cycle: mark the floor (-99 % of the real 1 BTC), the accomplice buys in, mark the ceiling, pay it out.
        _settle(VAULT_WBTC, _lo, SETTLE_REDEEM);
        _request(VAULT_WBTC, WBTC, colluder, _lo);
        _settle(VAULT_WBTC, _lo, SETTLE_DEPOSIT);
        vm.prank(colluder);
        btcVault.deposit(_lo, colluder, colluder);
        uint256 _shares = btcVault.balanceOf(colluder);
        vm.prank(colluder);
        btcVault.requestRedeem(_shares, colluder, colluder);
        _settle(VAULT_WBTC, _hi, SETTLE_REDEEM);
        vm.prank(colluder);
        btcVault.redeem(_shares, colluder, colluder);
        uint256 _paid = wbtc.balanceOf(colluder);
        emit log_named_uint("accomplice paid (sat) for 0.01 BTC", _paid);
        assertGt(_paid, (ONE_BTC * 49) / 100, "about half the position for a hundredth of it");
        assertLt(wbtc.balanceOf(SAFE), (ONE_BTC * 52) / 100, "the custody halved");
    }

    /*//////////////////////////////////////////////////////////////
       4. A BAND AHEAD OF THE FUNDING: THE FLAG'S ESCAPE PRICED
    //////////////////////////////////////////////////////////////*/

    /// @dev The gate refuses a band the live NAV does not sit in unless `--allow-unconstrained-nav` is given; the flag
    ///      exists for the unconstrained case and is typed on every sync for the dust vaults today (G11b-6 held). A
    ///      band typed for the EXPECTED funding size and admitted with it brings the funding's first settlement to a
    ///      mark the guard forces: the honest mark (the dust) is refused, the lowest admitted mark values 1 USDC of
    ///      custody at 47,500 USDC, and the 50,000 USDC deposit is settled at that price: the holder of the vault's
    ///      one pre-existing share takes about half of it.
    function test_G16c_4_a_band_typed_for_the_funding_size_forces_a_mis_mark_worth_half_the_deposit() public {
        uint256 _dust = vault.totalAssets();
        assertLt(_dust, 2 * ONE_USDC, "the live USDC vault holds about one USDC");
        assertEq(vault.totalSupply(), 1e18, "one share outstanding");
        uint256 _deposit = 50_000 * ONE_USDC;
        _bandAbs(VAULT_USDC, (_deposit * 95) / 100, (_deposit * 105) / 100); // "the vault will hold 50k"

        _request(VAULT_USDC, USDC, vesper, _deposit);
        _expectMarkRefused(VAULT_USDC, _dust); // the honest mark is refused by the band
        _settle(VAULT_USDC, (_deposit * 95) / 100, SETTLE_DEPOSIT); // the lowest mark the band admits
        vm.prank(vesper);
        vault.deposit(_deposit, vesper, vesper);
        // The honest mark of what the Safe really holds, inside the band now that the deposit joined.
        uint256 _custody = usdc.balanceOf(SAFE);
        _settle(VAULT_USDC, _custody, SETTLE_REDEEM);
        uint256 _vesper = vault.convertToAssets(vault.balanceOf(vesper));
        uint256 _oldShare = vault.convertToAssets(1e18);
        emit log_named_uint("custody (USDC, 6 dp)", _custody);
        emit log_named_uint("the strategy's 50,000 USDC are worth", _vesper);
        emit log_named_uint("the pre-existing one share is worth", _oldShare);
        assertLt(_vesper, (_deposit * 52) / 100, "about half the deposit lost to the mis-mark");
        assertGt(_oldShare, (_deposit * 48) / 100, "taken by whoever holds the one old share");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev The shipped shape for one vault: approve(OneOf vault) on its asset, the mark and both settles free.
    function _allowVault(address vault_, address asset_) internal {
        vm.startPrank(vetro);
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](1);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0);
        guard.allowFunction(SAFE, asset_, APPROVE, false, _rules);
        bytes32[] memory _v = new bytes32[](1);
        _v[0] = bytes32(uint256(uint160(vault_)));
        guard.addAllowedValues(SAFE, asset_, APPROVE, 0, _v);
        CuratorGuardPolicy.ParamRule[] memory _none;
        guard.allowFunction(SAFE, vault_, UPDATE_NAV, false, _none);
        guard.allowFunction(SAFE, vault_, SETTLE_DEPOSIT, false, _none);
        guard.allowFunction(SAFE, vault_, SETTLE_REDEEM, false, _none);
        vm.stopPrank();
    }

    /// @dev A static band of +-`bps_` around `anchor_` on the mark and on both settles (docs section 5, review G11b-2).
    function _band(address vault_, uint256 anchor_, uint256 bps_) internal {
        _bandAbs(vault_, (anchor_ * (10_000 - bps_)) / 10_000, (anchor_ * (10_000 + bps_)) / 10_000);
    }

    function _bandAbs(address vault_, uint256 lo_, uint256 hi_) internal {
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](2);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.GreaterThanOrEqual, 0, bytes32(lo_));
        _rules[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 0, bytes32(hi_));
        vm.startPrank(vetro);
        guard.allowFunction(SAFE, vault_, UPDATE_NAV, false, _rules);
        guard.allowFunction(SAFE, vault_, SETTLE_DEPOSIT, false, _rules);
        guard.allowFunction(SAFE, vault_, SETTLE_REDEEM, false, _rules);
        vm.stopPrank();
    }

    function _settlementBatch(address vault_, uint256 mark_, bytes4 settle_) internal pure returns (bytes memory) {
        return
            _batch(
                abi.encodePacked(
                    _entry(vault_, abi.encodeWithSelector(UPDATE_NAV, mark_)),
                    _entry(vault_, abi.encodeWithSelector(settle_, mark_))
                )
            );
    }

    /// @dev The curator's settlement, executed by its signer.
    function _settle(address vault_, uint256 mark_, bytes4 settle_) internal {
        assertTrue(_execSafeTx(MSCO141, 0, _settlementBatch(vault_, mark_, settle_), Operation.DelegateCall), "settlement");
    }

    /// @dev The mark is refused by the band: the batch reverts in the pre-hook, the nonce is not consumed.
    function _expectMarkRefused(address vault_, uint256 mark_) internal {
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, vault_, UPDATE_NAV, uint16(0), bytes32(mark_))
        );
        _execSafeTx(MSCO141, 0, _settlementBatch(vault_, mark_, SETTLE_REDEEM), Operation.DelegateCall);
    }

    /// @dev The full `execTransaction` calldata of a batch signed at the current nonce: what the signers leave in the
    ///      Transaction Service when they confirm without executing.
    function _signedBatch(bytes memory packed_) internal view returns (bytes memory) {
        SafeTx memory _t = SafeTx(MSCO141, 0, _batch(packed_), Operation.DelegateCall, 0, 0, address(0), address(0));
        return
            abi.encodeCall(
                ISafe.execTransaction,
                (_t.to, _t.value, _t.data, _t.op, 0, 0, 0, address(0), payable(address(0)), _sign(_txHash(_t)))
            );
    }

    /// @dev An async deposit request by `who_` for `amount_` (the asset dealt to it).
    function _request(address vault_, address asset_, address who_, uint256 amount_) internal {
        deal(asset_, who_, IERC20Min(asset_).balanceOf(who_) + amount_);
        vm.startPrank(who_);
        IERC20Min(asset_).approve(vault_, amount_);
        IVaultV06(vault_).requestDeposit(amount_, who_, who_);
        vm.stopPrank();
    }

    /// @dev Request, settle at the live NAV (an honest flat mark), claim.
    function _fund(address vault_, address asset_, address who_, uint256 amount_) internal {
        _request(vault_, asset_, who_, amount_);
        _settle(vault_, IVaultV06(vault_).totalAssets(), SETTLE_DEPOSIT);
        vm.prank(who_);
        IVaultV06(vault_).deposit(amount_, who_, who_);
    }

    /// @dev The string of an `Error(string)` revert, "" otherwise.
    function _reason(bytes memory r_) internal pure returns (string memory) {
        if (r_.length < 68 || bytes4(r_) != 0x08c379a0) return "";
        bytes memory _tail = new bytes(r_.length - 4);
        for (uint256 i; i < _tail.length; ++i) _tail[i] = r_[i + 4];
        return abi.decode(_tail, (string));
    }

    function _batch(bytes memory packed_) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(0x8d80ff0a, packed_);
    }

    function _entry(address to_, bytes memory data_) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to_, uint256(0), data_.length, data_);
    }
}
