// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

// Review g17a (the contracts, cold): the module path on the real Safe v1.5.0 build from lib/ (tmpfs copy only).

import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";
import {TestERC20} from "test/mocks/TestERC20.sol";

contract Module {
    function exec(ISafe safe_, address to_, uint256 value_, bytes calldata data_, Operation op_) external returns (bool) {
        return safe_.execTransactionFromModule(to_, value_, data_, op_);
    }
}

contract Arming {
    bool public armed;

    function arm() external {
        armed = true;
    }

    function poke() external view {
        if (!armed) revert("first");
    }
}

contract G17a_ColdV150 is SafeTxHelper {
    CuratorGuard internal guard;
    Module internal module;
    Module internal module2;
    MockProtocol internal protocol;
    TestERC20 internal token;

    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal attacker = makeAddr("attacker");
    address internal curator;

    bytes4 internal constant SWAP_OWNER = 0xe318b52b;

    function setUp() public {
        vm.warp(1_700_000_000);
        (curator, signerPk) = makeAddrAndKey("curator");
        Safe150 _singleton = new Safe150();
        SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        safe = ISafe(address(_proxy));
        vm.deal(address(safe), 10 ether);

        guard = new CuratorGuardHarness(0, vetro, council);
        CuratorGuardHarness(address(guard)).seedSafe(address(safe)); // locally compiled v1.5.0 build
        module = new Module();
        module2 = new Module();
        protocol = new MockProtocol();
        token = new TestERC20("USDC", "USDC");
        token.mint(address(safe), 1_000_000e6);

        vm.startPrank(address(safe)); // pre-guard self-authorized calls (equivalent to execTransactions before install)
        safe.enableModule(address(module));
        safe.enableModule(address(module2));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        vm.stopPrank();

        vm.startPrank(vetro);
        guard.enforce(address(safe));
        guard.allowFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules());
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](1);
        _rules[0] = CuratorGuardPolicy.ParamRule({kind: CuratorGuardPolicy.RuleKind.EqualToSafe, wordIndex: 1, value: 0});
        guard.allowFunction(address(safe), address(protocol), MockProtocol.deposit.selector, false, _rules);
        guard.setModuleAllowed(address(safe), address(module), true); // module2 stays off the allowlist
        vm.stopPrank();
    }

    function _noRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _r) {}

    /*//////////////////////////////////////////////////////////////
          council + an allowlisted module's operator: owner rotation without any curator signature
    //////////////////////////////////////////////////////////////*/

    /// The council's self-call allowlist (owner management) is meant for the fast lane; bound to a module it needs no
    /// owner signature: one council approval per owner seat to swap, executed by whoever drives the module, then a
    /// council window and the council's own keys sign the transfer. Nothing in this chain touches the timelock or the
    /// veto. Reported for comparison with the threat model (section 6).
    function test_council_plus_module_rotate_owners_and_drain_without_a_curator_signature() public {
        (address _councilKey, uint256 _councilPk) = makeAddrAndKey("council-key");
        bytes memory _swap = abi.encodeWithSelector(SWAP_OWNER, address(1), curator, _councilKey);
        vm.prank(council);
        guard.approveTransaction(address(safe), address(module), address(safe), 0, _swap, Operation.Call, 1 hours);
        // the module (any caller of it) executes the approved self-call: no signature, no timelock, no veto
        assertTrue(module.exec(safe, address(safe), 0, _swap, Operation.Call));
        address[] memory _owners = safe.getOwners();
        assertEq(_owners.length, 1);
        assertEq(_owners[0], _councilKey, "the curator seat is now a council key");
        // a council window, and the council's key signs the transfer
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        signerPk = _councilPk;
        uint256 _bal = token.balanceOf(address(safe));
        assertTrue(_execSafeTx(address(token), 0, abi.encodeWithSelector(0xa9059cbb, attacker, _bal), Operation.Call));
        assertEq(token.balanceOf(attacker), _bal, "custody moved: council + module operator, zero curator signatures");
    }

    /// The same approval cannot be used by a module off the allowlist, nor on the owner path, nor by a stranger module.
    function test_module_bound_council_approval_is_bound_to_that_module() public {
        bytes memory _swap = abi.encodeWithSelector(SWAP_OWNER, address(1), curator, attacker);
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module2)));
        guard.approveTransaction(address(safe), address(module2), address(safe), 0, _swap, Operation.Call, 1 hours);
        vm.prank(council);
        guard.approveTransaction(address(safe), address(module), address(safe), 0, _swap, Operation.Call, 1 hours);
        // owner path: the approval is keyed on the module
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, SWAP_OWNER));
        _execSafeTx(address(safe), 0, _swap, Operation.Call);
        // module2 (enabled on the Safe, not allowlisted): refused before any approval lookup, in every mode
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module2)));
        module2.exec(safe, address(safe), 0, _swap, Operation.Call);
        vm.prank(vetro);
        guard.bypass(address(safe), 1 days);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module2)));
        module2.exec(safe, address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
        // a guardian's setModuleAllowed(false) voids the module's approval's effect
        vm.prank(council);
        guard.enforce(address(safe));
        vm.prank(council);
        guard.setModuleAllowed(address(safe), address(module), false);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(module)));
        module.exec(safe, address(safe), 0, _swap, Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
          I8  the module path refuses what the owner path refuses (Enforced)
    //////////////////////////////////////////////////////////////*/

    function test_I8_module_path_matches_owner_path_refusals() public {
        bytes[8] memory _data = [
            abi.encodeCall(ISafe.setGuard, (address(0))),
            abi.encodeCall(guard.lockdown, (address(safe))),
            bytes(""),
            abi.encodeCall(MockProtocol.wrap, ()),
            hex"aabbcc",
            abi.encodeCall(MockProtocol.settleDeposit, (1)),
            abi.encodeCall(MockProtocol.deposit, (1, attacker)),
            bytes("")
        ];
        address[8] memory _to = [address(safe), address(guard), attacker, address(protocol), address(protocol), address(protocol), address(protocol), attacker];
        uint256[8] memory _value = [uint256(0), 0, 0, 0, 0, 1, 0, 1];
        Operation[8] memory _op = [Operation.Call, Operation.Call, Operation.DelegateCall, Operation.Call, Operation.Call, Operation.Call, Operation.Call, Operation.Call];
        bytes[8] memory _err = [
            abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, ISafe.setGuard.selector),
            abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, CuratorGuardPolicy.lockdown.selector),
            abi.encodeWithSelector(CuratorGuard.DelegateCallNotAllowed.selector, attacker),
            abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.wrap.selector),
            abi.encodeWithSelector(CuratorGuard.MalformedCalldata.selector),
            abi.encodeWithSelector(CuratorGuard.ValueNotAllowed.selector, address(protocol), MockProtocol.settleDeposit.selector),
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(protocol), MockProtocol.deposit.selector, uint16(1), bytes32(uint256(uint160(attacker)))),
            abi.encodeWithSelector(CuratorGuard.NativeTransferNotAllowed.selector, attacker)
        ];
        for (uint256 i; i < 8; ++i) {
            vm.expectRevert(_err[i]);
            _execSafeTx(_to[i], _value[i], _data[i], _op[i]);
            vm.expectRevert(_err[i]);
            module.exec(safe, _to[i], _value[i], _data[i], _op[i]);
        }
        // and both accept the same allowed call (two reports, paths 0 and 1)
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (5, address(safe))), Operation.Call));
        assertTrue(module.exec(safe, address(protocol), 0, abi.encodeCall(MockProtocol.deposit, (6, address(safe))), Operation.Call));
        assertEq(protocol.calls(), 2);
    }

    /*//////////////////////////////////////////////////////////////
          approvals on the module path: kept on failure, one use
    //////////////////////////////////////////////////////////////*/

    function test_module_approval_kept_on_failure_spent_once() public {
        Arming _t = new Arming();
        bytes memory _data = abi.encodeCall(Arming.poke, ());
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(module), address(_t), 0, _data, Operation.Call, 1 hours);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ApprovedExecutionFailed.selector, address(safe)));
        module.exec(safe, address(_t), 0, _data, Operation.Call);
        assertGt(guard.approvalExpiry(_id), 0, "kept");
        _t.arm();
        assertTrue(module.exec(safe, address(_t), 0, _data, Operation.Call));
        assertEq(guard.approvalExpiry(_id), 0, "spent");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(_t), Arming.poke.selector));
        module.exec(safe, address(_t), 0, _data, Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
          a council window relaxes the owner path only
    //////////////////////////////////////////////////////////////*/

    function test_council_window_leaves_the_module_path_under_the_policy() public {
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        assertTrue(_execSafeTx(address(protocol), 0, abi.encodeCall(MockProtocol.wrap, ()), Operation.Call));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.wrap.selector));
        module.exec(safe, address(protocol), 0, abi.encodeCall(MockProtocol.wrap, ()), Operation.Call);
        // an admin window relaxes both (the module allowlist and the guard as a top-level target stay)
        vm.prank(council);
        guard.enforce(address(safe));
        vm.prank(vetro);
        guard.bypass(address(safe), 1 hours);
        assertTrue(module.exec(safe, address(protocol), 0, abi.encodeCall(MockProtocol.wrap, ()), Operation.Call));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, CuratorGuardPolicy.lockdown.selector));
        module.exec(safe, address(guard), 0, abi.encodeCall(guard.lockdown, (address(safe))), Operation.Call);
        // ... and in an admin window an allowlisted module may even remove the guard (documented: nothing is checked)
        assertTrue(module.exec(safe, address(safe), 0, abi.encodeCall(ISafe.setModuleGuard, (address(0))), Operation.Call));
    }

    /*//////////////////////////////////////////////////////////////
          the digest on v1.5.0: a module-driven configuration write inside an owner policy transaction
    //////////////////////////////////////////////////////////////*/

    /// A venue that is also an allowlisted module and executes an APPROVED `enableModule` on the module path while an
    /// owner-path policy transaction is in flight: the inner (approved) module transaction lands, the outer post-hook
    /// sees the modules head move and reverts everything (fail closed).
    function test_approved_module_write_inside_policy_tx_fails_closed() public {
        Relay _relay = new Relay(module, safe);
        vm.startPrank(vetro);
        guard.allowFunction(address(safe), address(_relay), Relay.go.selector, false, _noRules());
        bytes memory _enable = abi.encodeCall(ISafe.enableModule, (attacker));
        guard.approveTransaction(address(safe), address(module), address(safe), 0, _enable, Operation.Call, 1 hours);
        vm.stopPrank();
        _relay.set(address(safe), 0, _enable, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(safe)));
        _execSafeTx(address(_relay), 0, abi.encodeCall(Relay.go, ()), Operation.Call);
        assertFalse(safe.isModuleEnabled(attacker));
    }
}

/// @dev An allowlisted "venue" that, when called by the Safe, drives a module transaction of the same Safe.
contract Relay {
    Module internal immutable module;
    ISafe internal immutable safe;
    address internal to;
    uint256 internal value;
    bytes internal data;
    Operation internal op;

    constructor(Module module_, ISafe safe_) {
        module = module_;
        safe = safe_;
    }

    function set(address to_, uint256 value_, bytes calldata data_, Operation op_) external {
        to = to_;
        value = value_;
        data = data_;
        op = op_;
    }

    function go() external {
        require(module.exec(safe, to, value, data, op), "module failed");
    }
}
