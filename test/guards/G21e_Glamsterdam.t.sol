// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {console2} from "forge-std/console2.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @dev What the test EVM charges for the primitives the guard's operations are made of. Run the same file under
///      `--evm-version cancun / osaka / amsterdam` (forge >= 1.8 knows `amsterdam`) and under `--isolate` (every
///      top-level call its own transaction, so "cold" and "original value" mean what they mean on a chain).
contract G21ePriceProbe {
    mapping(uint256 => uint256) internal m;

    function sstoreNew(uint256 k_) external returns (uint256 _g) {
        uint256 _a = gasleft();
        m[k_] = 1;
        _g = _a - gasleft();
    }

    function sstoreChange(uint256 k_) external returns (uint256 _g) {
        uint256 _a = gasleft();
        m[k_] = 2;
        _g = _a - gasleft();
    }

    function sstoreClear(uint256 k_) external returns (uint256 _g) {
        uint256 _a = gasleft();
        m[k_] = 0;
        _g = _a - gasleft();
    }

    function sloadCold(uint256 k_) external view returns (uint256 _g) {
        uint256 _a = gasleft();
        uint256 _v = m[k_];
        _g = _a - gasleft();
        _v;
    }

    function extcodesizeCold(address t_) external view returns (uint256 _g) {
        uint256 _a = gasleft();
        uint256 _s = t_.code.length;
        _g = _a - gasleft();
        _s;
    }

    function staticcallCold(address t_) external view returns (uint256 _g) {
        uint256 _a = gasleft();
        (bool _ok, ) = t_.staticcall("");
        _g = _a - gasleft();
        _ok;
    }

    function transientPair() external returns (uint256 _g) {
        uint256 _a = gasleft();
        assembly {
            tstore(7, 1)
            pop(tload(7))
        }
        _g = _a - gasleft();
    }

    function log3() external returns (uint256 _g) {
        uint256 _a = gasleft();
        assembly {
            log3(0, 32, 1, 2, 3)
        }
        _g = _a - gasleft();
    }
}

/// @title G21e: the guard's operations priced by the test EVM (round 21, the environment). Every number is what
///        the EVM the test runs on charges; the file asserts only what must hold on any of them and prints the rest,
///        so the same run under `cancun` (the pinned toolchain), `osaka` (mainnet today) and `amsterdam` (forge 1.8's
///        model of Glamsterdam: EIP-8037 state gas, EIP-8038 access and write prices, EIP-2780, EIP-7976) shows what
///        moves and by how much.
contract G21e_GlamsterdamTest is CuratorGuardTestBase {
    G21ePriceProbe internal probe;
    MockProtocol internal venue2;

    function setUp() public override {
        super.setUp();
        probe = new G21ePriceProbe();
        venue2 = new MockProtocol();
        _enforce();
    }

    /*//////////////////////////////////////////////////////////////
                          P1: THE EVM'S PRICES
    //////////////////////////////////////////////////////////////*/

    function test_P1_primitive_prices_of_this_evm() public {
        uint256 _new = probe.sstoreNew(1);
        vm.store(address(probe), keccak256(abi.encode(uint256(2), uint256(0))), bytes32(uint256(1)));
        uint256 _change = probe.sstoreChange(2);
        vm.store(address(probe), keccak256(abi.encode(uint256(3), uint256(0))), bytes32(uint256(1)));
        uint256 _clear = probe.sstoreClear(3);
        uint256 _sload = probe.sloadCold(4);
        uint256 _ext = probe.extcodesizeCold(address(venue2));
        uint256 _call = probe.staticcallCold(address(multiSendCallOnly));
        uint256 _t = probe.transientPair();
        uint256 _l = probe.log3();
        console2.log("P1 sstore new slot (0->1), cold:", _new);
        console2.log("P1 sstore change (1->2), cold:", _change);
        console2.log("P1 sstore clear (1->0), cold (refund not shown):", _clear);
        console2.log("P1 sload cold:", _sload);
        console2.log("P1 extcodesize cold account:", _ext);
        console2.log("P1 staticcall cold account:", _call);
        console2.log("P1 tstore+tload:", _t);
        console2.log("P1 log3 (32 bytes):", _l);
    }

    /*//////////////////////////////////////////////////////////////
                     P2: THE ADMIN'S WIDENINGS AND NARROWINGS
    //////////////////////////////////////////////////////////////*/

    function _band() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _r) {
        _r = new CuratorGuardPolicy.ParamRule[](2);
        _r[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.GreaterThanOrEqual, 0, bytes32(uint256(90)));
        _r[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 0, bytes32(uint256(110)));
    }

    function _oneOf() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _r) {
        _r = new CuratorGuardPolicy.ParamRule[](1);
        _r[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, 0, bytes32(0));
    }

    function test_P2_widenings_and_narrowings() public {
        address _t = address(venue2);
        vm.startPrank(vetro);
        uint256 _a = gasleft();
        guard.allowFunction(address(safe), _t, MockProtocol.settleDeposit.selector, false, _noRules());
        uint256 _allow0 = _a - gasleft();
        _a = gasleft();
        guard.allowFunction(address(safe), _t, MockProtocol.deposit.selector, false, _band());
        uint256 _allow2 = _a - gasleft();
        _a = gasleft();
        guard.allowFunction(address(safe), _t, MockProtocol.wrap.selector, true, _oneOf());
        uint256 _allowOneOf = _a - gasleft();
        bytes32[] memory _one = new bytes32[](1);
        _one[0] = bytes32(uint256(uint160(address(0xBEEF))));
        _a = gasleft();
        guard.addAllowedValues(address(safe), _t, MockProtocol.wrap.selector, 0, _one);
        uint256 _add1 = _a - gasleft();
        bytes32[] memory _rest = new bytes32[](127);
        for (uint256 i; i < 127; ++i) _rest[i] = bytes32(uint256(0x1000 + i));
        _a = gasleft();
        guard.addAllowedValues(address(safe), _t, MockProtocol.wrap.selector, 0, _rest);
        uint256 _add127 = _a - gasleft();
        // Re-allow with the same rules: a loosening-free re-sync (every slot already set).
        _a = gasleft();
        guard.allowFunction(address(safe), _t, MockProtocol.deposit.selector, false, _band());
        uint256 _reallow2 = _a - gasleft();
        _a = gasleft();
        guard.clearAllowedValues(address(safe), _t, MockProtocol.wrap.selector, 0);
        uint256 _clear128 = _a - gasleft();
        _a = gasleft();
        guard.revokeFunction(address(safe), _t, MockProtocol.deposit.selector);
        uint256 _revoke = _a - gasleft();
        _a = gasleft();
        guard.revokeTarget(address(safe), _t);
        uint256 _revokeTarget = _a - gasleft();
        vm.stopPrank();
        console2.log("P2 allowFunction, fresh target, no rules:", _allow0);
        console2.log("P2 allowFunction, 2nd selector, 2-rule band:", _allow2);
        console2.log("P2 allowFunction, 3rd selector, OneOf:", _allowOneOf);
        console2.log("P2 addAllowedValues, 1 member (first):", _add1);
        console2.log("P2 addAllowedValues, 127 members:", _add127);
        console2.log("P2   per member:", _add127 / 127);
        console2.log("P2 re-allow same band (no slot changes):", _reallow2);
        console2.log("P2 clearAllowedValues, 128 members (pre-refund charge):", _clear128);
        console2.log("P2 revokeFunction (band):", _revoke);
        console2.log("P2 revokeTarget (two left):", _revokeTarget);
        // MAX_ALLOWED_VALUES is sized so one clear fits one transaction under EIP-7825's execution cap.
        assertLt(_clear128 + 21_000, 16_777_216, "a full set's clear fits under the EIP-7825 cap on this EVM");
    }

    /*//////////////////////////////////////////////////////////////
                       P3: THE SAFE'S TRANSACTIONS
    //////////////////////////////////////////////////////////////*/

    function test_P3_the_hooks_and_the_exits() public {
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        bytes memory _call = abi.encodeCall(MockProtocol.settleDeposit, (1));
        uint256 _a = gasleft();
        assertTrue(_execSafeTx(address(protocol), 0, _call, Operation.Call), "policy");
        uint256 _policyCold = _a - gasleft();
        _a = gasleft();
        assertTrue(_execSafeTx(address(protocol), 0, _call, Operation.Call), "policy again");
        uint256 _policyWarm = _a - gasleft();
        // Approval: issue (admin), then consume (one clear of the approval record).
        bytes memory _self = abi.encodeCall(ISafe.setGuard, (address(guard)));
        _a = gasleft();
        _approve(address(safe), 0, _self, Operation.Call);
        uint256 _approve = _a - gasleft();
        _a = gasleft();
        assertTrue(_execSafeTx(address(safe), 0, _self, Operation.Call), "approved");
        uint256 _consume = _a - gasleft();
        // Lockdown (guardian), lift (council): one record each.
        _addGuardian(guardian);
        _a = gasleft();
        vm.prank(guardian);
        guard.lockdown(address(safe));
        uint256 _lockdown = _a - gasleft();
        _a = gasleft();
        vm.prank(council);
        guard.enforce(address(safe));
        uint256 _lift = _a - gasleft();
        console2.log("P3 execTransaction on the policy path, cold:", _policyCold);
        console2.log("P3 execTransaction on the policy path, warm:", _policyWarm);
        console2.log("P3 approveTransaction (admin):", _approve);
        console2.log("P3 execTransaction consuming the approval:", _consume);
        console2.log("P3 lockdown (guardian):", _lockdown);
        console2.log("P3 enforce (council lift):", _lift);
    }

    /*//////////////////////////////////////////////////////////////
                           P4: THE TIMELOCK
    //////////////////////////////////////////////////////////////*/

    function test_P4_the_timelock_schedule_and_execute() public {
        address _proposer = makeAddr("proposer");
        address _veto = makeAddr("veto");
        address[] memory _p = new address[](1);
        _p[0] = _proposer;
        address[] memory _c = new address[](1);
        _c[0] = _veto;
        CuratorGuardTimelock _tl = new CuratorGuardTimelock(1 days, _p, _c);
        // Hand the guard to the timelock the production way: two-step transfer with a zero delay fixture.
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(address(_tl));
        vm.warp(block.timestamp + 1);
        vm.prank(address(_tl));
        guard.acceptDefaultAdminTransfer();
        bytes memory _inner = abi.encodeCall(
            CuratorGuardPolicy.allowFunction,
            (address(safe), address(venue2), MockProtocol.settleDeposit.selector, false, _noRules())
        );
        bytes memory _wrapped = abi.encodeCall(CuratorGuardPolicy.executeBefore, (uint64(block.timestamp + 30 days), _inner));
        bytes32 _salt = keccak256("g21e");
        vm.prank(_proposer);
        uint256 _a = gasleft();
        _tl.schedule(address(guard), 0, _wrapped, bytes32(0), _salt, 1 days);
        uint256 _schedule = _a - gasleft();
        vm.warp(block.timestamp + 1 days);
        _a = gasleft();
        _tl.execute(address(guard), 0, _wrapped, bytes32(0), _salt);
        uint256 _execute = _a - gasleft();
        assertTrue(_isAllowed(address(safe), address(venue2), MockProtocol.settleDeposit.selector), "applied");
        console2.log("P4 schedule (one wrapped allowFunction):", _schedule);
        console2.log("P4 execute (open executor, the wrapper, allowFunction):", _execute);
    }
}
