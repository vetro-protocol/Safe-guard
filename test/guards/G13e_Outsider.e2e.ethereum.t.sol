// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {SettlementDeadline} from "contracts/helpers/SettlementDeadline.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";
import {TestERC20} from "test/mocks/TestERC20.sol";

interface IERC20Min {
    function balanceOf(address) external view returns (uint256);

    function approve(address, uint256) external returns (bool);

    function transfer(address, uint256) external returns (bool);
}

/// @dev The live Lagoon v0.6.0 surface this suite drives (verified against the Sourcify source of the
///      implementation `0x6c77…249f`, review g11b).
interface IVaultV06 {
    function requestDeposit(uint256 assets, address controller, address owner) external returns (uint256);

    function deposit(uint256 assets, address receiver, address controller) external returns (uint256);

    function requestRedeem(uint256 shares, address controller, address owner) external returns (uint256);

    function redeem(uint256 shares, address receiver, address controller) external returns (uint256);

    function cancelRequestRedeem(address controller) external;

    function pendingRedeemRequest(uint256 requestId, address controller) external view returns (uint256);

    function claimableRedeemRequest(uint256 requestId, address controller) external view returns (uint256);

    function pendingDepositRequest(uint256 requestId, address controller) external view returns (uint256);

    function claimableDepositRequest(uint256 requestId, address controller) external view returns (uint256);

    function totalAssets() external view returns (uint256);

    function totalSupply() external view returns (uint256);

    function balanceOf(address) external view returns (uint256);

    function transfer(address, uint256) external returns (bool);

    function convertToAssets(uint256 shares) external view returns (uint256);

    function owner() external view returns (address);

    function isAllowed(address) external view returns (bool);

    function updateWhitelistManager(address) external;

    function addToWhitelist(address[] memory) external;

    function switchAccessMode(uint8) external;
}

/// @dev The live `LagoonV06` 6.0.5 proxy (the strategy of the USDC pool): keeper entry and the tracked id.
interface IStrategyMin {
    function requestRedeem(uint256 shares) external returns (uint256);

    function redeemRequestId() external view returns (uint256);
}


/// @title G13e: THE ECONOMIC OUTSIDER WITH NO KEYS, on a mainnet fork of the live curator Safe and USDC vault
/// @notice Round 13, reviewer g13e. Capital only: no owner key, no role, no module. The guard is deployed
///         fresh with the shipped USDC policy shape and installed through the runbook's 7.4 batch by a 1-of-N
///         signer the test adds (the live owners' keys are unknown); the vault is funded by a stand-in holder
///         `vesper` that plays the strategy's position. Requires `ETHEREUM_FORK_NODE_URL` (archive) and
///         `ETHEREUM_FORK_BLOCK_NUMBER`.
contract G13e_OutsiderTest is SafeTxHelper {
    address internal constant SAFE = 0x1b534a8543212F5957168D83311A41E0Ea1cfe48;
    address internal constant MSCO141 = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant VAULT = 0x131CcfDFfeD712885aAc31445d351E6b62656679;
    address internal constant STRAT = 0x099d0Cdd85484B418D1E7375Df894619963D5b94; // Lagoon_Vetro_USDC, 6.0.5
    address internal constant KEEPER = 0xf7364E230EA0e5CC41E6Cd4E2a30A26Ca1850b73;

    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes4 internal constant APPROVE = 0x095ea7b3;
    bytes4 internal constant UPDATE_NAV = 0xbcd1bf34; // updateNewTotalAssets(uint256)
    bytes4 internal constant SETTLE_DEPOSIT = 0xd24ca58a; // settleDeposit(uint256)
    bytes4 internal constant SETTLE_REDEEM = 0xa627df66; // settleRedeem(uint256)
    bytes4 internal constant ONLY_ONE_REQUEST = bytes4(keccak256("OnlyOneRequestAllowed()"));
    bytes4 internal constant INVALID_OPERATOR = bytes4(keccak256("ERC7540InvalidOperator()"));
    bytes4 internal constant NOT_ALLOWED = bytes4(keccak256("AddressNotAllowed(address)"));
    bytes4 internal constant NOT_CANCELABLE = bytes4(keccak256("RequestNotCancelable(uint40)"));

    uint256 internal constant ONE_USDC = 1e6;

    CuratorGuard internal guard;
    IVaultV06 internal vault = IVaultV06(VAULT);
    IERC20Min internal usdc = IERC20Min(USDC);

    address internal vetro = makeAddr("vetro"); // the guard's admin (the timelock in production)
    address internal council = makeAddr("council");
    address internal vesper = makeAddr("vesper"); // stands in for the strategy's position
    address internal outsider = makeAddr("outsider"); // capital, no keys
    address internal signer;

    uint256 internal nav0; // the vault's NAV after the stand-in funding

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
        _applyShippedUsdcShape();

        // 7.4 install: a 1-of-N signer, then handler removal + setGuard in one genuine batch.
        (signer, signerPk) = makeAddrAndKey("g13e-signer");
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

        // The stand-in strategy position: 1,000,000 USDC requested, settled at the live NAV, claimed.
        _fund(vesper, 1_000_000 * ONE_USDC);
        nav0 = vault.totalAssets();
        assertGt(nav0, 1_000_000 * ONE_USDC, "funded");
    }

    /*//////////////////////////////////////////////////////////////
          1. A FULLY SIGNED SETTLEMENT IS AN OPTION ANYONE EXECUTES
    //////////////////////////////////////////////////////////////*/

    /// @dev The curator's second signer confirmed the settlement batch [mark M, settleDeposit(M)] in the
    ///      Transaction Service and nobody executed it (Safe{Wallet} separates "confirm" from "execute"; the
    ///      confirmations, signature bytes included, are public). `execTransaction` has no caller check, so
    ///      the outsider chooses WHEN the signed mark lands: it waits until the mark is stale against the value
    ///      the curator would mark now (V > M), requests a deposit, and executes the batch itself. Its shares
    ///      are priced at the stale M; the next honest mark values them at V. The gain, D·(V−M)/(M+D), comes
    ///      out of the existing holder, the strategy. The band admits every mark here (all within ±5 %).
    function test_G13e_signed_settlement_executed_by_the_outsider_at_a_stale_low_mark() public {
        _band(nav0, 500); // ±5 % around the funded NAV, on the mark and on both settles (the G11b-2 shape)
        uint256 _mark = nav0; // honest when signed
        bytes memory _signed = _signedSettlement(_mark, SETTLE_DEPOSIT); // sits in the queue, unexecuted

        vm.warp(block.timestamp + 1 days);
        uint256 _value = (nav0 * 101) / 100; // what the curator would mark NOW: the signed mark is 1 % stale
        uint256 _deposit = 30_000 * ONE_USDC;
        _request(outsider, _deposit);

        // The outsider lands the curator's own signed transaction from its own key.
        vm.prank(outsider);
        (bool _ok, ) = address(safe).call(_signed);
        assertTrue(_ok, "anyone executes a fully signed Safe transaction");
        vm.prank(outsider);
        vault.deposit(_deposit, outsider, outsider);
        uint256 _shares = vault.balanceOf(outsider);

        // The next honest mark: the true value plus the deposit the Safe received.
        _settle(_value + _deposit, SETTLE_REDEEM);
        uint256 _worth = vault.convertToAssets(_shares);
        uint256 _expected = (_deposit * (_value - _mark)) / (_mark + _deposit);
        emit log_named_uint("outsider deposit (USDC, 6 dp)", _deposit);
        emit log_named_uint("outsider worth at the honest mark", _worth);
        emit log_named_uint("outsider gain", _worth - _deposit);
        emit log_named_uint("expected D*(V-M)/(M+D)", _expected);
        assertGt(_worth, _deposit, "the outsider bought below value");
        assertApproxEqAbs(_worth - _deposit, _expected, 2, "the gain is the stale discount, pro rata");

        // Realised: the outsider redeems at the honest mark and leaves with the gain; the stand-in strategy lost it.
        uint256 _vesperBefore = vault.convertToAssets(vault.balanceOf(vesper));
        vm.prank(outsider);
        vault.requestRedeem(_shares, outsider, outsider);
        _settle(_value + _deposit, SETTLE_REDEEM);
        vm.prank(outsider);
        vault.redeem(_shares, outsider, outsider);
        assertApproxEqAbs(usdc.balanceOf(outsider), _worth, 2, "paid the stale-priced value");
        assertLt(vault.convertToAssets(vault.balanceOf(vesper)), _value, "the strategy's position is below the true value");
        emit log_named_uint("strategy position before the outsider's exit", _vesperBefore);
        emit log_named_uint("strategy position after", vault.convertToAssets(vault.balanceOf(vesper)));
    }

    /// @dev The mirror: a holder escapes a loss. The signed mark M was honest; the custody then loses 1 %
    ///      (here: the Safe's balance), so the honest mark would be 0.99·M. The outsider, already a holder,
    ///      requests a redeem and lands the stale batch itself: it is paid at M, whole; the loss is now
    ///      entirely the strategy's.
    function test_G13e_signed_settlement_executed_by_the_outsider_at_a_stale_high_mark() public {
        _band(nav0, 500);
        uint256 _deposit = 30_000 * ONE_USDC;
        _fund(outsider, _deposit); // the outsider is a holder, settled honestly
        uint256 _shares = vault.balanceOf(outsider);
        uint256 _mark = vault.totalAssets(); // = nav0 + deposit, honest when signed
        bytes memory _signed = _signedSettlement(_mark, SETTLE_DEPOSIT); // settleDeposit also settles redeems

        // Custody loses 1 % (a venue loss); the honest mark is now 0.99·M.
        uint256 _bal = usdc.balanceOf(SAFE);
        deal(USDC, SAFE, (_bal * 99) / 100);
        uint256 _honest = (_mark * 99) / 100;

        vm.prank(outsider);
        vault.requestRedeem(_shares, outsider, outsider);
        vm.prank(outsider);
        (bool _ok, ) = address(safe).call(_signed);
        assertTrue(_ok, "the stale batch lands when the outsider wants it");
        vm.prank(outsider);
        vault.redeem(_shares, outsider, outsider);
        assertApproxEqAbs(usdc.balanceOf(outsider), _deposit, 2, "paid in full at the stale mark");

        // What is left for the strategy at the honest mark of what remains.
        _settle(_honest - _deposit, SETTLE_REDEEM);
        uint256 _vesperWorth = vault.convertToAssets(vault.balanceOf(vesper));
        uint256 _fairShare = (nav0 * 99) / 100; // its pro-rata share of the loss
        emit log_named_uint("strategy worth, fair (pro-rata loss)", _fairShare);
        emit log_named_uint("strategy worth, after the outsider's stale exit", _vesperWorth);
        assertLt(_vesperWorth, _fairShare, "the outsider's share of the loss moved onto the strategy");
        assertApproxEqAbs(_fairShare - _vesperWorth, _deposit / 100, _deposit / 10_000, "about 1 % of the outsider's stake");
    }

    /*//////////////////////////////////////////////////////////////
          2. THE BAND STALL IS FREE FOR THE OUTSIDER ONCE IT IS OUT
    //////////////////////////////////////////////////////////////*/

    /// @dev Review G12c-4 measured the stall from the operator's side. From the outsider's: a position of 6 %
    ///      of NAV, deposited and settled inside the band, makes the next honest mark exceed the ceiling (stall
    ///      1: the outsider's capital waits with everyone else's); after Vetro's re-sync the outsider is paid in
    ///      full and the next honest mark is below the new floor (stall 2: the outsider has left, no fee, no
    ///      loss). Each stall is a timelock round (48 h) and a Vetro signing round.
    function test_G13e_band_stall_after_the_outsiders_exit_costs_the_outsider_nothing() public {
        _band(nav0, 500);
        uint256 _deposit = (nav0 * 6) / 100;
        _fund(outsider, _deposit); // settled at a mark inside the band (the deposit joins the NAV afterwards)
        uint256 _honest = vault.totalAssets();
        assertGt(_honest, (nav0 * 105) / 100, "the honest NAV is now above the ceiling");

        // Stall 1: the honest mark is refused by the band.
        _expectMarkRefused(_honest);

        // Vetro re-syncs the band around the live NAV (a 48 h timelock round in production).
        _band(_honest, 500);
        uint256 _shares = vault.balanceOf(outsider);
        vm.prank(outsider);
        vault.requestRedeem(_shares, outsider, outsider);
        _settle(_honest, SETTLE_REDEEM);
        vm.prank(outsider);
        vault.redeem(_shares, outsider, outsider);
        assertApproxEqAbs(usdc.balanceOf(outsider), _deposit, 2, "the outsider is out, whole");

        // Stall 2: the honest NAV fell below the new floor; the outsider's capital is no longer in the vault.
        uint256 _honest2 = vault.totalAssets();
        assertLt(_honest2, (_honest * 95) / 100, "below the floor");
        _expectMarkRefused(_honest2);
        assertEq(vault.balanceOf(outsider), 0, "nothing of the outsider's left inside");
    }

    /*//////////////////////////////////////////////////////////////
        3. THE DUST REDEEM IN THE STRATEGY'S SLOT AND THE WHITELIST
    //////////////////////////////////////////////////////////////*/

    /// @dev Docs §8 ("Whitelist mode is also a liveness control for the strategies") documents the plant and
    ///      its release by "a real redeem [of] any holder". Verified here on the live vault and the live
    ///      strategy proxy, with what the bullet does not say: (a) the plant costs the outsider one share-wei
    ///      and must be landed before the mark that closes its epoch; (b) a stranger cannot cancel it and the
    ///      keeper's `cancelRequestRedeem` is not an operator either; (c) it survives `switchAccessMode(Whitelist)`
    ///      unchanged while no new plant is possible after the switch; (d) in whitelist mode "any holder" means a
    ///      WHITELISTED holder, so the release is a Vetro action: whitelist a helper that holds shares, have it
    ///      request a redeem worth at least one asset unit, mark and settle.
    function test_G13e_dust_redeem_in_the_strategys_slot_survives_the_whitelist_switch_and_needs_a_whitelisted_release() public {
        // The strategy holds a position (shares moved from the stand-in; public mode admits the transfer).
        uint256 _position = vault.balanceOf(vesper) / 10;
        vm.prank(vesper);
        vault.transfer(STRAT, _position);
        // The outsider holds one USDC worth of shares, settled.
        _fund(outsider, ONE_USDC);

        // (a) The plant: one share-wei, controller = the strategy, landed in the block before the curator's mark.
        vm.prank(outsider);
        vault.requestRedeem(1, STRAT, outsider);
        assertEq(vault.pendingRedeemRequest(0, STRAT), 1, "a request in the strategy's slot");
        assertEq(IStrategyMin(STRAT).redeemRequestId(), 0, "that the strategy did not open");
        _settle(vault.totalAssets(), SETTLE_REDEEM); // the mark closes the epoch; the settle returns without settling
        assertEq(vault.pendingRedeemRequest(0, STRAT), 1, "still pending after a settlement");
        assertEq(vault.claimableRedeemRequest(0, STRAT), 0, "never claimable");

        // The strategy's own redeem is refused from now on.
        vm.prank(KEEPER);
        vm.expectRevert(abi.encodeWithSelector(ONLY_ONE_REQUEST));
        IStrategyMin(STRAT).requestRedeem(_position / 2);

        // (b) Nobody can cancel it: a stranger and the keeper are not the strategy's operators; the epoch is closed.
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(INVALID_OPERATOR));
        vault.cancelRequestRedeem(STRAT);
        vm.prank(KEEPER);
        vm.expectRevert(abi.encodeWithSelector(INVALID_OPERATOR));
        vault.cancelRequestRedeem(STRAT);
        vm.prank(STRAT);
        vm.expectRevert(); // RequestNotCancelable(id): the epoch closed with the mark above
        vault.cancelRequestRedeem(STRAT);

        // (c) Vetro switches to whitelist mode (§8 control 1): the strategy and a helper on the list.
        address _helper = vesper; // a whitelisted holder Vetro controls, holding shares
        address[] memory _list = new address[](2);
        _list[0] = STRAT;
        _list[1] = _helper;
        vm.prank(vault.owner());
        vault.updateWhitelistManager(vetro);
        vm.prank(vetro);
        vault.addToWhitelist(_list);
        vm.prank(vault.owner());
        vault.switchAccessMode(1); // AccessMode.Whitelist
        assertFalse(vault.isAllowed(outsider), "the outsider is out");
        assertEq(vault.pendingRedeemRequest(0, STRAT), 1, "the plant survives the switch");
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(NOT_ALLOWED, outsider));
        vault.requestRedeem(1, STRAT, outsider); // no new plant after the switch
        vm.prank(KEEPER);
        vm.expectRevert(abi.encodeWithSelector(ONLY_ONE_REQUEST));
        IStrategyMin(STRAT).requestRedeem(_position / 2); // the strategy is still blocked

        // A settlement with no other redeem in the batch changes nothing: the batch still converts to zero.
        _settle(vault.totalAssets(), SETTLE_REDEEM);
        assertEq(vault.pendingRedeemRequest(0, STRAT), 1, "a bare settlement does not release it");

        // (d) The release: a whitelisted holder's redeem worth at least one asset unit joins the batch.
        uint256 _release = vault.balanceOf(_helper) / 1000;
        assertGe(vault.convertToAssets(_release), 100, "worth at least the strategy's own floor");
        vm.prank(_helper);
        vault.requestRedeem(_release, _helper, _helper);
        _settle(vault.totalAssets(), SETTLE_REDEEM);
        assertEq(vault.pendingRedeemRequest(0, STRAT), 0, "released with the batch");
        assertEq(vault.claimableRedeemRequest(0, STRAT), 1, "the share-wei is claimable (worth nothing)");
        vm.prank(KEEPER);
        IStrategyMin(STRAT).requestRedeem(_position / 2);
        assertGt(IStrategyMin(STRAT).redeemRequestId(), 0, "the strategy's redeem goes through again");
    }

    /*//////////////////////////////////////////////////////////////
               4. FORCED ETH AND TOKEN DUST CHANGE NOTHING
    //////////////////////////////////////////////////////////////*/

    /// @dev ETH forced into the guard (a `selfdestruct` in a creation transaction, a block reward), into the Safe
    ///      and into a timelock, and a spam token sent to all three: no hook reads a balance, the policy admits
    ///      the settlement as before, and the Safe can move neither the ETH nor the token out.
    function test_G13e_forced_eth_and_token_dust_are_inert() public {
        address[] memory _p = new address[](1);
        _p[0] = makeAddr("proposer");
        address[] memory _c = new address[](1);
        _c[0] = makeAddr("veto");
        CuratorGuardTimelock _tl = new CuratorGuardTimelock(2 days, _p, _c);
        vm.deal(address(guard), 1 ether); // forced: a plain transfer reverts (no receive, no fallback)
        vm.deal(SAFE, 1 ether);
        vm.deal(outsider, 1 ether);
        vm.prank(outsider);
        (bool _sent, ) = address(_tl).call{value: 1}("");
        assertTrue(_sent, "the timelock accepts ETH from anyone (OpenZeppelin receive)");
        vm.prank(outsider);
        (bool _refused, ) = address(guard).call{value: 1}("");
        assertFalse(_refused, "the guard refuses a plain transfer");

        TestERC20 _spam = new TestERC20("SPAM", "SPAM");
        _spam.mint(SAFE, 1e24);
        _spam.mint(address(guard), 1e24);
        _spam.mint(address(_tl), 1e24);

        _settle(vault.totalAssets(), SETTLE_DEPOSIT); // the policy path is unchanged
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.NativeTransferNotAllowed.selector, outsider));
        _execSafeTx(outsider, 1, "", Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(_spam), bytes4(0xa9059cbb)));
        _execSafeTx(address(_spam), 0, abi.encodeWithSelector(0xa9059cbb, outsider, 1), Operation.Call);
        assertEq(address(guard).balance, 1 ether, "stuck, harmless");
    }

    /*//////////////////////////////////////////////////////////////
       2b. THE CYCLE REPEATS AT THE OUTSIDER'S DISCRETION; THE FIX FOR 1
    //////////////////////////////////////////////////////////////*/

    /// @dev One outsider holding just over half the band's width alternates a deposit and a redeem: every
    ///      settlement of its flow pushes the NAV outside the band Vetro just synced, and every re-sync lands
    ///      into the next stall. The curator cannot settle selectively (a batch is a batch), so each of its
    ///      moves is one more timelock round and the vault settles nothing in between. Only whitelist mode
    ///      (docs §8 control 1) ends it.
    function test_G13e_band_cycling_one_outsider_keeps_a_public_vault_out_of_band() public {
        _band(nav0, 500);
        uint256 _deposit = (nav0 * 6) / 100;
        uint256 _stalls;
        for (uint256 i; i < 3; ++i) {
            _fund(outsider, _deposit); // settled under the current band
            uint256 _honest = vault.totalAssets();
            _expectMarkRefused(_honest); // above the ceiling
            ++_stalls;
            _band(_honest, 500); // re-sync (48 h)
            uint256 _shares = vault.balanceOf(outsider);
            vm.prank(outsider);
            vault.requestRedeem(_shares, outsider, outsider);
            _settle(_honest, SETTLE_REDEEM);
            vm.prank(outsider);
            vault.redeem(_shares, outsider, outsider);
            uint256 _honest2 = vault.totalAssets();
            _expectMarkRefused(_honest2); // below the floor
            ++_stalls;
            _band(_honest2, 500); // re-sync (48 h)
        }
        assertEq(_stalls, 6, "six stalls, six timelock rounds, three cycles");
        // `_fund` deals the deposit afresh each cycle: three deposits in, three paid out in full, no fee, no loss.
        assertApproxEqAbs(usdc.balanceOf(outsider), 3 * _deposit, 6, "the outsider's capital is intact after three cycles");
    }

    /// @dev The mitigation for the stale signed settlement: the signers put `assertBefore(deadline)` first in
    ///      every settlement batch (an allowlisted plain call to a stateless helper). Before the deadline the
    ///      batch lands as usual; after it, the batch reverts for every executor (GS013: the inner call failed),
    ///      the nonce is not consumed and nothing the outsider does can revive it.
    function test_G13e_fix_a_settlement_deadline_entry_kills_a_stale_signed_batch() public {
        SettlementDeadline _dl = new SettlementDeadline();
        CuratorGuardPolicy.ParamRule[] memory _none;
        vm.prank(vetro);
        guard.allowFunction(SAFE, address(_dl), SettlementDeadline.assertBefore.selector, false, _none);
        _band(nav0, 500);

        uint256 _mark = nav0;
        uint256 _deadline = block.timestamp + 6 hours;
        bytes memory _data = _batch(
            abi.encodePacked(
                _entry(address(_dl), abi.encodeCall(SettlementDeadline.assertBefore, (_deadline))),
                _entry(VAULT, abi.encodeWithSelector(UPDATE_NAV, _mark)),
                _entry(VAULT, abi.encodeWithSelector(SETTLE_DEPOSIT, _mark))
            )
        );
        SafeTx memory _t = SafeTx(MSCO141, 0, _data, Operation.DelegateCall, 0, 0, address(0), address(0));
        bytes memory _signed = abi.encodeCall(
            ISafe.execTransaction,
            (_t.to, _t.value, _t.data, _t.op, 0, 0, 0, address(0), payable(address(0)), _sign(_txHash(_t)))
        );
        uint256 _nonce = uint256(vm.load(SAFE, bytes32(NONCE_SLOT)));

        vm.warp(_deadline + 1);
        _request(outsider, 30_000 * ONE_USDC);
        vm.prank(outsider);
        (bool _ok, bytes memory _ret) = address(safe).call(_signed);
        assertFalse(_ok, "the stale batch is dead for everyone");
        assertEq(_reason(_ret), "GS013", "the inner call failed: the Safe reverts, the nonce is kept");
        assertEq(uint256(vm.load(SAFE, bytes32(NONCE_SLOT))), _nonce, "nonce free for a fresh settlement");
        assertEq(vault.balanceOf(outsider), 0, "nothing settled");

        // A fresh batch with a live deadline lands as usual (the helper entry costs the batch one plain call).
        uint256 _mark2 = vault.totalAssets();
        bytes memory _fresh = _batch(
            abi.encodePacked(
                _entry(address(_dl), abi.encodeCall(SettlementDeadline.assertBefore, (block.timestamp + 1 hours))),
                _entry(VAULT, abi.encodeWithSelector(UPDATE_NAV, _mark2)),
                _entry(VAULT, abi.encodeWithSelector(SETTLE_DEPOSIT, _mark2))
            )
        );
        assertTrue(_execSafeTx(MSCO141, 0, _fresh, Operation.DelegateCall), "a live deadline settles");
    }

    /// @dev The string of an `Error(string)` revert, "" otherwise.
    function _reason(bytes memory r_) internal pure returns (string memory) {
        if (r_.length < 68 || bytes4(r_) != 0x08c379a0) return "";
        bytes memory _tail = new bytes(r_.length - 4);
        for (uint256 i; i < _tail.length; ++i) _tail[i] = r_[i + 4];
        return abi.decode(_tail, (string));
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev The shipped shape for USDC: approve(OneOf vault), the mark and both settles free, the canonical
    ///      MultiSendCallOnly v1.4.1 registered, handler requirement zero, Enforced.
    function _applyShippedUsdcShape() internal {
        vm.startPrank(vetro);
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](1);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0);
        guard.allowFunction(SAFE, USDC, APPROVE, false, _rules);
        bytes32[] memory _v = new bytes32[](1);
        _v[0] = bytes32(uint256(uint160(VAULT)));
        guard.addAllowedValues(SAFE, USDC, APPROVE, 0, _v);
        CuratorGuardPolicy.ParamRule[] memory _none;
        guard.allowFunction(SAFE, VAULT, UPDATE_NAV, false, _none);
        guard.allowFunction(SAFE, VAULT, SETTLE_DEPOSIT, false, _none);
        guard.allowFunction(SAFE, VAULT, SETTLE_REDEEM, false, _none);
        guard.setMultiSendUnwrapper(SAFE, MSCO141, true);
        guard.setRequiredFallbackHandler(SAFE, address(0), true);
        guard.enforce(SAFE);
        vm.stopPrank();
    }

    /// @dev A static band of ±`bps_` around `anchor_` on the mark and on both settles (docs §5, review G11b-2).
    function _band(uint256 anchor_, uint256 bps_) internal {
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](2);
        _rules[0] = CuratorGuardPolicy.ParamRule(
            CuratorGuardPolicy.RuleKind.GreaterThanOrEqual,
            0,
            bytes32((anchor_ * (10_000 - bps_)) / 10_000)
        );
        _rules[1] = CuratorGuardPolicy.ParamRule(
            CuratorGuardPolicy.RuleKind.LessThanOrEqual,
            0,
            bytes32((anchor_ * (10_000 + bps_)) / 10_000)
        );
        vm.startPrank(vetro);
        guard.allowFunction(SAFE, VAULT, UPDATE_NAV, false, _rules);
        guard.allowFunction(SAFE, VAULT, SETTLE_DEPOSIT, false, _rules);
        guard.allowFunction(SAFE, VAULT, SETTLE_REDEEM, false, _rules);
        vm.stopPrank();
    }

    function _settlementBatch(uint256 mark_, bytes4 settle_) internal pure returns (bytes memory) {
        return
            _batch(
                abi.encodePacked(
                    _entry(VAULT, abi.encodeWithSelector(UPDATE_NAV, mark_)),
                    _entry(VAULT, abi.encodeWithSelector(settle_, mark_))
                )
            );
    }

    /// @dev The curator's settlement, executed by its signer (the honest path).
    function _settle(uint256 mark_, bytes4 settle_) internal {
        assertTrue(_execSafeTx(MSCO141, 0, _settlementBatch(mark_, settle_), Operation.DelegateCall), "settlement");
    }

    /// @dev The mark is refused by the band: the batch reverts in the pre-hook, the nonce is not consumed.
    function _expectMarkRefused(uint256 mark_) internal {
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, VAULT, UPDATE_NAV, uint16(0), bytes32(mark_))
        );
        _execSafeTx(MSCO141, 0, _settlementBatch(mark_, SETTLE_REDEEM), Operation.DelegateCall);
    }

    /// @dev The full `execTransaction` calldata of the settlement batch signed at the current nonce: what the
    ///      signers leave in the Transaction Service when they confirm without executing.
    function _signedSettlement(uint256 mark_, bytes4 settle_) internal view returns (bytes memory) {
        SafeTx memory _t = SafeTx(MSCO141, 0, _settlementBatch(mark_, settle_), Operation.DelegateCall, 0, 0, address(0), address(0));
        return
            abi.encodeCall(
                ISafe.execTransaction,
                (_t.to, _t.value, _t.data, _t.op, 0, 0, 0, address(0), payable(address(0)), _sign(_txHash(_t)))
            );
    }

    /// @dev An async deposit request by `who_` for `amount_` (USDC dealt to it).
    function _request(address who_, uint256 amount_) internal {
        deal(USDC, who_, usdc.balanceOf(who_) + amount_);
        vm.startPrank(who_);
        usdc.approve(VAULT, amount_);
        vault.requestDeposit(amount_, who_, who_);
        vm.stopPrank();
    }

    /// @dev Request, settle at the live NAV (an honest flat mark), claim.
    function _fund(address who_, uint256 amount_) internal {
        _request(who_, amount_);
        _settle(vault.totalAssets(), SETTLE_DEPOSIT);
        vm.prank(who_);
        vault.deposit(amount_, who_, who_);
    }

    function _batch(bytes memory packed_) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(0x8d80ff0a, packed_);
    }

    function _entry(address to_, bytes memory data_) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to_, uint256(0), data_.length, data_);
    }
}
