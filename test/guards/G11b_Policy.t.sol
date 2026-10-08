// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

interface IERC20Like {
    function balanceOf(address) external view returns (uint256);

    function allowance(address, address) external view returns (uint256);

    function approve(address, uint256) external returns (bool);
}

/// @dev The live Lagoon v0.6.0 surface this suite drives (verified against the Sourcify source of the live logic, round 11).
interface ILagoonV06 {
    function requestDeposit(uint256 assets, address controller, address owner) external payable returns (uint256);

    function deposit(uint256 assets, address receiver) external returns (uint256);

    function requestRedeem(uint256 shares, address controller, address owner) external returns (uint256);

    function redeem(uint256 shares, address receiver, address controller) external returns (uint256);

    function claimableDepositRequest(uint256 requestId, address controller) external view returns (uint256);

    function claimableRedeemRequest(uint256 requestId, address controller) external view returns (uint256);

    function pendingRedeemRequest(uint256 requestId, address controller) external view returns (uint256);

    function totalAssets() external view returns (uint256);

    function totalSupply() external view returns (uint256);

    function balanceOf(address) external view returns (uint256);

    function isCompliant(uint256 currentPps, uint256 nextPps, uint256 timePast) external view returns (bool);

    function securityCouncilUpdateTotalAssets(uint256 newTotalAssets) external;
}

/// @title G11b_Policy: the shipped policy as the attack surface, entry by entry, on the LIVE Safe and vault
/// @notice Round 11, reviewer g11b. A mainnet fork of the Vetro curator Safe (v1.4.1, 2-of-4) with the shipped
///         policy shape for USDC installed through the runbook's 7.4 batch, driven through genuine
///         `execTransaction`s, against the live v0.6.0 vault code. Requires `ETHEREUM_FORK_NODE_URL`.
contract G11b_PolicyTest is SafeTxHelper {
    address internal constant SAFE = 0x1b534a8543212F5957168D83311A41E0Ea1cfe48;
    address internal constant MULTISEND_CALL_ONLY_141 = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address internal constant VAULT_USDC = 0x131CcfDFfeD712885aAc31445d351E6b62656679;
    address internal constant VAULT_USDT = 0xE7FaE53e32B09028db4Ca8Ff7E4fF0574367eDba;

    bytes32 internal constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    // Lagoon ERC-7201 bases (verified source).
    uint256 internal constant ROLES_BASE = 0x7c302ed2c673c3d6b4551cf74a01ee649f887e14fd20d13dbca1b6099534d900;
    uint256 internal constant GUARDRAILS_BASE = 0xd851cf94ad565ef91472fd51daf3f5f2311d4c6801bf4d880e94a7f28b854800;
    uint256 internal constant FEE_BASE = 0xa5292f7ccd85acc1b3080c01f5da9af7799f2c26826bd4d79081d6511780bd00;
    uint256 internal constant ONE_YEAR = 31_556_952; // GuardrailsLib.ONE_YEAR

    bytes4 internal constant APPROVE = 0x095ea7b3;
    bytes4 internal constant UPDATE_NAV = 0xbcd1bf34; // updateNewTotalAssets(uint256)
    bytes4 internal constant SETTLE_DEPOSIT = 0xd24ca58a; // settleDeposit(uint256)
    bytes4 internal constant SETTLE_REDEEM = 0xa627df66; // settleRedeem(uint256)
    bytes4 internal constant CLAIM_SHARES = 0xf15be6f9; // claimSharesOnBehalf(address[])
    bytes4 internal constant CLAIM_ASSETS = 0x26d6c82f; // claimAssetsOnBehalf(address[])
    bytes32 internal constant REPORT_SIG = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");

    CuratorGuard internal guard;
    ILagoonV06 internal vault = ILagoonV06(VAULT_USDC);
    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal stranger = makeAddr("stranger");
    address internal lagoonCouncilKey = makeAddr("lagoon-security-council-at-vetro");
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
        _applyShippedPolicyShape();

        // The runbook's 7.4 install: a 1-of-N signer, then handler removal + setGuard in one genuine batch.
        (signer, signerPk) = makeAddrAndKey("g11b-signer");
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
        G11b-1: THE TWO SETTLE ENTRIES ARE ONE CUSTODY EXIT
    //////////////////////////////////////////////////////////////*/

    /// @dev `settleDeposit` ends with `ERC7540Lib.settleRedeem(msg.sender)` (Vault-v0.6.0.sol:515): with
    ///      `settleRedeem` revoked by a responder, `settleDeposit` still pulls the pending redeem's assets
    ///      out of the Safe through the allowance, reported `Policy` under the settleDeposit selector. The
    ///      claims on behalf, along the way, hand shares and assets to the controller only.
    function test_G11b1_settleDeposit_settles_redeems_so_revoking_settleRedeem_alone_keeps_the_exit_open() public {
        uint256 _n0 = _fundCustody(1_000_000e6);
        uint256 _d = 100_000e6;
        _strangerRequestsDeposit(_d);
        _mark(_n0);
        assertTrue(_settleDeposit(_n0), "honest deposit settlement");
        assertEq(IERC20Like(USDC).balanceOf(SAFE), _n0 + _d, "the deposit landed in the Safe");

        // claimSharesOnBehalf hands the shares to the controller, nobody else.
        address[] memory _who = new address[](1);
        _who[0] = stranger;
        assertTrue(_execSafeTx(VAULT_USDC, 0, abi.encodeWithSelector(CLAIM_SHARES, _who), Operation.Call));
        uint256 _shares = vault.balanceOf(stranger);
        assertGt(_shares, 0, "shares claimed to the stranger");
        assertEq(vault.balanceOf(SAFE), 0, "none to the Safe");

        vm.prank(stranger);
        vault.requestRedeem(_shares, stranger, stranger);

        // A responder narrows the exit, as the §7.5 narrowing vocabulary suggests.
        vm.prank(vetro);
        guard.revokeFunction(SAFE, VAULT_USDC, SETTLE_REDEEM);

        _mark(_n0 + _d);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, VAULT_USDC, SETTLE_REDEEM));
        _settleRedeem(_n0 + _d);

        uint256 _vaultBefore = IERC20Like(USDC).balanceOf(VAULT_USDC);
        vm.recordLogs();
        assertTrue(_settleDeposit(_n0 + _d), "settleDeposit passes the narrowed policy");
        (uint256 _reports, uint8 _outcome) = _reportsOf(vm.getRecordedLogs());
        assertEq(_reports, 1);
        assertEq(_outcome, uint8(CuratorGuard.Outcome.Policy));
        uint256 _pulled = IERC20Like(USDC).balanceOf(VAULT_USDC) - _vaultBefore;
        assertApproxEqRel(_pulled, _d, 1e15, "the redeem settled through settleDeposit: assets left the Safe");
        assertEq(IERC20Like(USDC).balanceOf(SAFE), _n0 + _d - _pulled);
        assertEq(vault.claimableRedeemRequest(0, stranger), _shares, "claimable, no longer pending");

        // claimAssetsOnBehalf pays the controller, nobody else.
        uint256 _before = IERC20Like(USDC).balanceOf(stranger);
        assertTrue(_execSafeTx(VAULT_USDC, 0, abi.encodeWithSelector(CLAIM_ASSETS, _who), Operation.Call));
        assertEq(IERC20Like(USDC).balanceOf(stranger) - _before, _pulled, "assets to the controller");
        assertEq(IERC20Like(USDC).balanceOf(VAULT_USDC), _vaultBefore);
    }

    /*//////////////////////////////////////////////////////////////
        G11b-2: A BAND ON THE MARK ALONE DOES NOT BOUND THE SETTLE
    //////////////////////////////////////////////////////////////*/

    /// @dev Shipped shape plus the §5 / `$comment_nav` band on `updateNewTotalAssets` only. Once the Lagoon
    ///      `securityCouncil` sits outside the Safe (§8 step 2), a mark it places (`securityCouncilUpdateTotalAssets`,
    ///      no guardrail, no guard) is what the settles must repeat (`WrongNewTotalAssets` otherwise), and the
    ///      policy's unbanded settles repeat it at any value: the stranger's redeem is paid at twice the honest NAV.
    function test_G11b2a_shipped_shape_a_mark_placed_outside_the_safe_is_settled_at_any_value() public {
        (uint256 _n1, uint256 _shares) = _strangerHoldsSharesAtHonestNav();
        _bandTheMark(_n1);
        _moveSecurityCouncilToVetro();
        vm.prank(stranger);
        vault.requestRedeem(_shares, stranger, stranger);

        uint256 _bad = 2 * _n1;
        vm.prank(lagoonCouncilKey);
        vault.securityCouncilUpdateTotalAssets(_bad);

        // The band holds on the mark entry ...
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, VAULT_USDC, UPDATE_NAV, uint16(0), bytes32(_bad)));
        _mark(_bad);
        // ... and the settle entry repeats the out-of-band value: custody leaves at 2x NAV.
        uint256 _vaultBefore = IERC20Like(USDC).balanceOf(VAULT_USDC);
        assertTrue(_settleRedeem(_bad), "no rule on the settle");
        uint256 _pulled = IERC20Like(USDC).balanceOf(VAULT_USDC) - _vaultBefore;
        assertApproxEqRel(_pulled, 2 * 100_000e6, 2e15, "paid at twice the honest NAV");
        assertEq(vault.totalAssets(), _bad - _pulled);
    }

    /// @dev The same with the band repeated on both settles (the fix: 0 bytes, today's rule kinds): refused.
    function test_G11b2b_fixed_shape_the_band_on_the_settles_refuses_the_out_of_band_value() public {
        (uint256 _n1, uint256 _shares) = _strangerHoldsSharesAtHonestNav();
        _bandTheMark(_n1);
        _bandTheSettles(_n1);
        _moveSecurityCouncilToVetro();
        vm.prank(stranger);
        vault.requestRedeem(_shares, stranger, stranger);

        uint256 _bad = 2 * _n1;
        vm.prank(lagoonCouncilKey);
        vault.securityCouncilUpdateTotalAssets(_bad);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, VAULT_USDC, SETTLE_REDEEM, uint16(0), bytes32(_bad)));
        _settleRedeem(_bad);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, VAULT_USDC, SETTLE_DEPOSIT, uint16(0), bytes32(_bad)));
        _settleDeposit(_bad);
        // An in-band re-mark by the council unlocks settlement again (safe failure: liveness, not loss).
        vm.prank(lagoonCouncilKey);
        vault.securityCouncilUpdateTotalAssets(_n1);
        assertTrue(_settleRedeem(_n1));
    }

    /*//////////////////////////////////////////////////////////////
        G11b-3: WHAT A STATIC ±x BAND STILL LEAKS, PER CYCLE, IN ONE BLOCK
    //////////////////////////////////////////////////////////////*/

    /// @dev Mark and settles banded at ±5 % of the honest NAV (the `$comment_nav` plan): a stranger's
    ///      deposit of x·NAV at the floor, redeemed at the ceiling, nets about x² of NAV (0.25 %) in one
    ///      block through allowlisted calls; the same cycle with ten times the capital nets less, not more.
    function test_G11b3_a_static_band_leaks_about_x_squared_of_nav_per_cycle_in_one_block() public {
        uint256 _n = _fundCustody(1_000_000e6);
        _bandTheMark(_n);
        _bandTheSettles(_n);
        uint256 _lo = (_n * 95) / 100;
        uint256 _hi = (_n * 105) / 100;

        (uint256 _gainSmall, uint256 _lossSmall) = _cycle(_n / 20, _lo, _hi); // D = x·NAV
        emit log_named_uint("gain with D = 5% of NAV (raw USDC units)", _gainSmall);
        assertEq(_lossSmall, 0);
        assertGt(_gainSmall, (_n * 20) / 10_000, "at least 0.20 % of NAV");
        assertLt(_gainSmall, (_n * 30) / 10_000, "at most 0.30 % of NAV");

        // Ten times the capital: the band is absolute, so the larger deposit dilutes its own mark-up into a loss.
        (uint256 _gainLarge, uint256 _lossLarge) = _cycle(_n / 2, _lo, _hi);
        emit log_named_uint("loss with D = 50% of NAV (raw USDC units)", _lossLarge);
        assertEq(_gainLarge, 0, "capital does not scale the leak");
        assertGt(_lossLarge, 0);
    }

    /*//////////////////////////////////////////////////////////////
        G11b-4: THE GUARDRAIL CONTROL LAPSES A YEAR AFTER THE LAST SETTLEMENT
    //////////////////////////////////////////////////////////////*/

    /// @dev GuardrailsLib.isCompliant scales the move by `ONE_YEAR / timePast` in integer arithmetic (Lagoon
    ///      v0.6.0, verified source): past six months since the last settlement the annualised bound becomes
    ///      a raw bound, past one year it becomes zero and any mark passes. `timePast` is counted from
    ///      `lastFeeTime`, which only a SETTLEMENT (the Safe's call) advances.
    function test_G11b4_lagoon_guardrails_lapse_one_year_after_the_last_settlement() public {
        uint256 _n = _fundCustody(1_000_000e6); // settles now: lastFeeTime = now
        _activateGuardrails(0.2e18, -0.2e18); // +20 % / -20 % per year
        assertFalse(vault.isCompliant(1e6, 2e6, 1 days), "a doubling in a day is refused");
        assertFalse(vault.isCompliant(1e6, 1_200_000, ONE_YEAR / 2), "+20 % at six months is still annualised");
        assertTrue(vault.isCompliant(1e6, 1_200_000, ONE_YEAR / 2 + 1), "+20 % in one mark once the scale is 1");
        assertFalse(vault.isCompliant(1e6, 1_200_001, ONE_YEAR / 2 + 1));
        assertTrue(vault.isCompliant(1e6, 100e6, ONE_YEAR + 1), "a 100x mark passes once the scale is 0");
        assertTrue(vault.isCompliant(1e6, 1, ONE_YEAR + 1), "and a mark to nothing");

        // Live: the policy-allowed mark through the real Safe, guardrails active.
        uint256 _lastFeeTime = uint256(vm.load(VAULT_USDC, bytes32(FEE_BASE + 2)));
        assertEq(_lastFeeTime, block.timestamp);
        vm.warp(_lastFeeTime + 1 days);
        vm.expectRevert(bytes("GS013")); // GuardrailsViolation inside the vault, surfaced by the Safe
        _mark(2 * _n);
        vm.warp(_lastFeeTime + ONE_YEAR + 1);
        assertTrue(_mark(100 * _n), "any mark passes the guardrail after a year without a settlement");
    }

    /*//////////////////////////////////////////////////////////////
        G11b-5: THE COST SIDE OF THE HELD G10d-1 APPROVE CAP
    //////////////////////////////////////////////////////////////*/

    /// @dev Tether refuses a non-zero approve while the allowance is non-zero: under a cap every USDT
    ///      settlement batch carries `approve(vault, 0)` then `approve(vault, C)`, and the live max allowance
    ///      must be reset before the first capped approve lands.
    function test_G11b5a_usdt_needs_a_zero_reset_before_every_capped_approve() public {
        _capApprove(USDT, VAULT_USDT, 1_000_000e6);
        assertGt(IERC20Like(USDT).allowance(SAFE, VAULT_USDT), 0, "live allowance at max");
        vm.expectRevert(bytes("GS013"));
        _execSafeTx(USDT, 0, abi.encodeWithSelector(APPROVE, VAULT_USDT, uint256(100e6)), Operation.Call);
        assertTrue(_execSafeTx(USDT, 0, abi.encodeWithSelector(APPROVE, VAULT_USDT, uint256(0)), Operation.Call));
        assertTrue(_execSafeTx(USDT, 0, abi.encodeWithSelector(APPROVE, VAULT_USDT, uint256(100e6)), Operation.Call));
        vm.expectRevert(bytes("GS013"));
        _execSafeTx(USDT, 0, abi.encodeWithSelector(APPROVE, VAULT_USDT, uint256(200e6)), Operation.Call);
        assertTrue(_execSafeTx(USDT, 0, abi.encodeWithSelector(APPROVE, VAULT_USDT, uint256(0)), Operation.Call));
        assertTrue(_execSafeTx(USDT, 0, abi.encodeWithSelector(APPROVE, VAULT_USDT, uint256(200e6)), Operation.Call));
    }

    /// @dev A pending redeem larger than the cap cannot be settled at all: `settleRedeem` pulls the whole
    ///      batch in one `safeTransferFrom`, so the settlement reverts until the cap is widened (a timelock
    ///      round) or the council approves the larger `approve` one-off.
    function test_G11b5b_a_redeem_batch_above_the_cap_freezes_settlement() public {
        (uint256 _n1, uint256 _shares) = _strangerHoldsSharesAtHonestNav(); // the stranger holds 100k USDC of shares
        _capApprove(USDC, VAULT_USDC, 50_000e6);
        assertTrue(_execSafeTx(USDC, 0, abi.encodeWithSelector(APPROVE, VAULT_USDC, uint256(0)), Operation.Call));
        assertTrue(_execSafeTx(USDC, 0, abi.encodeWithSelector(APPROVE, VAULT_USDC, uint256(50_000e6)), Operation.Call));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, USDC, APPROVE, uint16(1), bytes32(uint256(100_000e6))));
        _execSafeTx(USDC, 0, abi.encodeWithSelector(APPROVE, VAULT_USDC, uint256(100_000e6)), Operation.Call);

        vm.prank(stranger);
        vault.requestRedeem(_shares, stranger, stranger);
        _mark(_n1);
        vm.expectRevert(bytes("GS013")); // SafeERC20: insufficient allowance inside settleRedeem
        _settleRedeem(_n1);
        vm.expectRevert(bytes("GS013")); // and through settleDeposit's redeem leg as well
        _settleDeposit(_n1);
    }

    /*//////////////////////////////////////////////////////////////
                                FLOWS
    //////////////////////////////////////////////////////////////*/

    /// @dev Gives the Safe `amount_` of USDC and marks/settles it honestly: the existing shareholders now own it.
    function _fundCustody(uint256 amount_) internal returns (uint256 _n) {
        deal(USDC, SAFE, amount_);
        _n = amount_;
        assertTrue(_mark(_n), "honest mark");
        assertTrue(_settleDeposit(_n), "honest settle (no pending requests)");
        assertEq(vault.totalAssets(), _n);
    }

    function _strangerRequestsDeposit(uint256 d_) internal {
        deal(USDC, stranger, d_);
        vm.startPrank(stranger);
        IERC20Like(USDC).approve(VAULT_USDC, d_);
        vault.requestDeposit(d_, stranger, stranger);
        vm.stopPrank();
    }

    /// @dev 1,000,000 USDC of custody for the existing holders, then the stranger deposits 100,000 at the
    ///      honest NAV and claims: returns the honest NAV after the deposit and the stranger's shares.
    function _strangerHoldsSharesAtHonestNav() internal returns (uint256 _n1, uint256 _shares) {
        uint256 _n0 = _fundCustody(1_000_000e6);
        _strangerRequestsDeposit(100_000e6);
        assertTrue(_mark(_n0));
        assertTrue(_settleDeposit(_n0));
        uint256 _claimable = vault.claimableDepositRequest(0, stranger); // read before the prank: a view call would consume it
        vm.prank(stranger);
        vault.deposit(_claimable, stranger);
        _shares = vault.balanceOf(stranger);
        _n1 = _n0 + 100_000e6;
        assertEq(vault.totalAssets(), _n1);
        assertEq(IERC20Like(USDC).balanceOf(SAFE), _n1);
    }

    /// @dev One band cycle by the stranger with capital `d_`: deposit at the floor, redeem at the ceiling.
    function _cycle(uint256 d_, uint256 lo_, uint256 hi_) internal returns (uint256 _gain, uint256 _loss) {
        _strangerRequestsDeposit(d_); // `deal` SETS the stranger's balance to d_, so the cycle starts from exactly d_
        assertTrue(_mark(lo_));
        assertTrue(_settleDeposit(lo_));
        uint256 _claimable = vault.claimableDepositRequest(0, stranger);
        vm.startPrank(stranger);
        vault.deposit(_claimable, stranger);
        uint256 _shares = vault.balanceOf(stranger);
        vault.requestRedeem(_shares, stranger, stranger);
        vm.stopPrank();
        assertTrue(_mark(hi_));
        assertTrue(_settleRedeem(hi_));
        uint256 _claimableShares = vault.claimableRedeemRequest(0, stranger);
        vm.prank(stranger);
        vault.redeem(_claimableShares, stranger, stranger);
        uint256 _after = IERC20Like(USDC).balanceOf(stranger);
        if (_after >= d_) _gain = _after - d_;
        else _loss = d_ - _after;
        // Restore the honest book for the next cycle: the custody now equals the Safe's balance.
        uint256 _honest = IERC20Like(USDC).balanceOf(SAFE);
        assertTrue(_mark(_honest > hi_ ? hi_ : _honest));
        assertTrue(_settleDeposit(_honest > hi_ ? hi_ : _honest));
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _mark(uint256 n_) internal returns (bool) {
        return _execSafeTx(VAULT_USDC, 0, abi.encodeWithSelector(UPDATE_NAV, n_), Operation.Call);
    }

    function _settleDeposit(uint256 n_) internal returns (bool) {
        return _execSafeTx(VAULT_USDC, 0, abi.encodeWithSelector(SETTLE_DEPOSIT, n_), Operation.Call);
    }

    function _settleRedeem(uint256 n_) internal returns (bool) {
        return _execSafeTx(VAULT_USDC, 0, abi.encodeWithSelector(SETTLE_REDEEM, n_), Operation.Call);
    }

    function _band(uint256 n_) internal pure returns (CuratorGuardPolicy.ParamRule[] memory _r) {
        _r = new CuratorGuardPolicy.ParamRule[](2);
        _r[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.GreaterThanOrEqual, 0, bytes32((n_ * 95) / 100));
        _r[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 0, bytes32((n_ * 105) / 100));
    }

    function _bandTheMark(uint256 n_) internal {
        vm.prank(vetro);
        guard.allowFunction(SAFE, VAULT_USDC, UPDATE_NAV, false, _band(n_));
    }

    function _bandTheSettles(uint256 n_) internal {
        vm.startPrank(vetro);
        guard.allowFunction(SAFE, VAULT_USDC, SETTLE_DEPOSIT, false, _band(n_));
        guard.allowFunction(SAFE, VAULT_USDC, SETTLE_REDEEM, false, _band(n_));
        vm.stopPrank();
    }

    /// @dev `hopper.storage.Roles` + 5 is `securityCouncil` (verified source; the Safe holds it today).
    function _moveSecurityCouncilToVetro() internal {
        assertEq(address(uint160(uint256(vm.load(VAULT_USDC, bytes32(ROLES_BASE + 5))))), SAFE, "live: the Safe");
        vm.store(VAULT_USDC, bytes32(ROLES_BASE + 5), bytes32(uint256(uint160(lagoonCouncilKey))));
    }

    /// @dev `hopper.storage.GuardrailsManager`: + 0 upperRate, + 1 lowerRate, + 2 activated (all zero live).
    function _activateGuardrails(uint256 upper_, int256 lower_) internal {
        assertEq(uint256(vm.load(VAULT_USDC, bytes32(GUARDRAILS_BASE + 2))), 0, "live: deactivated");
        vm.store(VAULT_USDC, bytes32(GUARDRAILS_BASE), bytes32(upper_));
        vm.store(VAULT_USDC, bytes32(GUARDRAILS_BASE + 1), bytes32(uint256(lower_)));
        vm.store(VAULT_USDC, bytes32(GUARDRAILS_BASE + 2), bytes32(uint256(1)));
    }

    /// @dev The held G10d-1 shape: `approve` bound to the vault and capped on word 1.
    function _capApprove(address token_, address vault_, uint256 cap_) internal {
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](2);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0);
        _rules[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 1, bytes32(cap_));
        vm.startPrank(vetro);
        guard.allowFunction(SAFE, token_, APPROVE, false, _rules);
        bytes32[] memory _v = new bytes32[](1);
        _v[0] = bytes32(uint256(uint160(vault_)));
        guard.addAllowedValues(SAFE, token_, APPROVE, 0, _v);
        vm.stopPrank();
    }

    /// @dev The shipped shape for USDC and its vault (all five selectors), the handler requirement of zero, Enforced.
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
        guard.allowFunction(SAFE, VAULT_USDC, CLAIM_SHARES, false, _noRules());
        guard.allowFunction(SAFE, VAULT_USDC, CLAIM_ASSETS, false, _noRules());
        guard.setRequiredFallbackHandler(SAFE, address(0), true);
        guard.enforce(SAFE);
        vm.stopPrank();
    }

    function _noRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _r) {}

    function _entry(address to_, bytes memory data_) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to_, uint256(0), data_.length, data_);
    }

    function _reportsOf(Vm.Log[] memory logs_) internal view returns (uint256 _n, uint8 _lastOutcome) {
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter == address(guard) && logs_[i].topics.length == 4 && logs_[i].topics[0] == REPORT_SIG) {
                ++_n;
                _lastOutcome = uint8(uint256(logs_[i].topics[3]));
            }
        }
    }
}
