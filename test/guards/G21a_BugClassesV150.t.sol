// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

// Review g21a (the contracts, bug classes): the SettlementDeadline helper and the hooks on the real Safe v1.5.0
// build from lib/ (tmpfs copy; never applied).

import {Vm} from "forge-std/Vm.sol";
import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";
import {MultiSendCallOnly as MultiSendCallOnly150} from "safe-contracts-v1.5.0/contracts/libraries/MultiSendCallOnly.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {SettlementDeadline} from "contracts/helpers/SettlementDeadline.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

contract Module {
    function exec(ISafe safe_, address to_, uint256 value_, bytes calldata data_, Operation op_) external returns (bool) {
        return safe_.execTransactionFromModule(to_, value_, data_, op_);
    }
}

contract G21a_BugClassesV150 is SafeTxHelper {
    CuratorGuard internal guard;
    Module internal module;
    MockProtocol internal protocol;
    SettlementDeadline internal deadline;
    MultiSendCallOnly150 internal multiSend;

    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal curator;

    bytes32 internal constant TRANSACTION_CHECKED = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");

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
        CuratorGuardHarness(address(guard)).seedSafe(address(safe));
        module = new Module();
        protocol = new MockProtocol();
        deadline = new SettlementDeadline();
        multiSend = new MultiSendCallOnly150();
        CuratorGuardHarness(address(guard)).seedCodehash(address(multiSend).codehash);

        vm.startPrank(address(safe));
        safe.enableModule(address(module));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        vm.stopPrank();

        vm.startPrank(vetro);
        guard.enforce(address(safe));
        guard.allowFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules());
        guard.allowFunction(address(safe), address(deadline), SettlementDeadline.assertBefore.selector, false, _noRules());
        guard.setModuleAllowed(address(safe), address(module), true);
        guard.setMultiSendUnwrapper(address(safe), address(multiSend), true);
        vm.stopPrank();
    }

    function _noRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _r) {}

    function _nonce() internal view returns (uint256) {
        return uint256(vm.load(address(safe), bytes32(NONCE_SLOT)));
    }

    function _report(Vm.Log[] memory logs_) internal view returns (uint256 _n, uint256 _path, uint256 _outcome) {
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter == address(guard) && logs_[i].topics[0] == TRANSACTION_CHECKED) {
                ++_n;
                _path = abi.decode(logs_[i].data, (uint256));
                _outcome = uint256(logs_[i].topics[3]);
            }
        }
    }

    function _entry(address to_, uint256 value_, bytes memory data_) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to_, value_, data_.length, data_);
    }

    /// @dev Module path, policy: a stale deadline makes `execTransactionFromModule` return false (no revert on
    ///      the module path), the guard still reports `Policy` on path 1 (the report means "passed both hooks").
    function test_V1_helper_under_the_module_path_policy() public {
        uint256 _d = block.timestamp + 600;
        bytes memory _call = abi.encodeCall(SettlementDeadline.assertBefore, (_d));
        vm.warp(_d);
        assertTrue(module.exec(safe, address(deadline), 0, _call, Operation.Call));
        vm.warp(_d + 1);
        vm.recordLogs();
        assertFalse(module.exec(safe, address(deadline), 0, _call, Operation.Call));
        (uint256 _n, uint256 _path, uint256 _outcome) = _report(vm.getRecordedLogs());
        assertEq(_n, 1);
        assertEq(_path, 1);
        assertEq(_outcome, uint256(CuratorGuard.Outcome.Policy));
    }

    /// @dev Module path, approved (module-bound admin approval): a stale deadline reverts the module call with
    ///      `ApprovedExecutionFailed` and keeps the approval; a fresh one is consumed and reported `Approval`.
    function test_V2_helper_under_an_approved_module_transaction() public {
        uint256 _d = block.timestamp + 600;
        bytes memory _call = abi.encodeCall(SettlementDeadline.assertBefore, (_d));
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(module), address(deadline), 0, _call, Operation.Call, 1 days);
        vm.warp(_d + 1);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ApprovedExecutionFailed.selector, address(safe)));
        module.exec(safe, address(deadline), 0, _call, Operation.Call);
        assertGt(guard.approvalExpiry(_id), 0, "approval kept");
        vm.warp(_d);
        vm.recordLogs();
        assertTrue(module.exec(safe, address(deadline), 0, _call, Operation.Call));
        (, uint256 _path, uint256 _outcome) = _report(vm.getRecordedLogs());
        assertEq(_path, 1);
        assertEq(_outcome, uint256(CuratorGuard.Outcome.Approval));
        assertEq(guard.approvalExpiry(_id), 0);
    }

    /// @dev Owner path on v1.5.0 with `safeTxGas == 0`: the Safe bubbles the helper's own reason
    ///      (`SettlementExpired(deadline)`), as a top-level call and as the first entry of a v1.5.0
    ///      `MultiSendCallOnly` batch; the nonce is kept.
    function test_V3_owner_path_bubbles_SettlementExpired_and_keeps_the_nonce() public {
        uint256 _d = block.timestamp + 600;
        bytes memory _call = abi.encodeCall(SettlementDeadline.assertBefore, (_d));
        vm.warp(_d + 1);
        uint256 _n = _nonce();
        vm.expectRevert(abi.encodeWithSelector(SettlementDeadline.SettlementExpired.selector, _d));
        _execSafeTx(address(deadline), 0, _call, Operation.Call);
        bytes memory _batch = abi.encodeWithSelector(
            MultiSendCallOnly150.multiSend.selector,
            abi.encodePacked(_entry(address(deadline), 0, _call), _entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (5))))
        );
        vm.expectRevert(abi.encodeWithSelector(SettlementDeadline.SettlementExpired.selector, _d));
        _execSafeTx(address(multiSend), 0, _batch, Operation.DelegateCall);
        assertEq(_nonce(), _n, "nonce kept");
        assertEq(protocol.calls(), 0);
        vm.warp(_d);
        assertTrue(_execSafeTx(address(multiSend), 0, _batch, Operation.DelegateCall));
        assertEq(protocol.lastAmount(), 5);
        assertEq(_nonce(), _n + 1);
    }

    /// @dev A module venue re-entering the OWNER path of the same Safe while an owner-path policy transaction
    ///      runs: the module path is independent (its own transient slot), held to the policy, reported on its
    ///      own, and the outer configuration digest still matches (nothing of the Safe moved).
    function test_V4_module_transaction_nested_in_an_owner_policy_transaction_is_independent() public {
        NestingVenue _venue = new NestingVenue(safe, module);
        vm.prank(vetro);
        guard.allowFunction(address(safe), address(_venue), NestingVenue.poke.selector, false, _noRules());
        vm.recordLogs();
        assertTrue(_execSafeTx(address(_venue), 0, abi.encodeCall(NestingVenue.poke, (address(protocol), abi.encodeCall(MockProtocol.settleDeposit, (11)))), Operation.Call));
        assertTrue(_venue.innerOk(), "module path allowed inside");
        assertEq(protocol.lastAmount(), 11);
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        uint256 _reports;
        for (uint256 i; i < _logs.length; ++i) if (_logs[i].emitter == address(guard) && _logs[i].topics[0] == TRANSACTION_CHECKED) ++_reports;
        assertEq(_reports, 2, "one report per path");
        // and a self-call through the module inside the owner transaction is refused by the policy (SelfCallNotAllowed)
        _venue.setExpectFailure(true);
        assertTrue(_execSafeTx(address(_venue), 0, abi.encodeCall(NestingVenue.poke, (address(safe), abi.encodeCall(ISafe.setGuard, (address(0))))), Operation.Call));
        assertEq(_venue.innerError(), CuratorGuard.SelfCallNotAllowed.selector);
    }
}

contract NestingVenue {
    ISafe public immutable safe;
    Module public immutable module;
    bool public innerOk;
    bytes4 public innerError;
    bool internal expectFailure;

    constructor(ISafe safe_, Module module_) {
        safe = safe_;
        module = module_;
    }

    function setExpectFailure(bool v_) external {
        expectFailure = v_;
    }

    function poke(address to_, bytes calldata data_) external {
        (bool _ok, bytes memory _ret) = address(module).call(abi.encodeCall(Module.exec, (safe, to_, 0, data_, Operation.Call)));
        if (_ok) {
            innerOk = abi.decode(_ret, (bool));
        } else {
            innerOk = false;
            if (_ret.length >= 4) innerError = bytes4(_ret);
        }
        if (expectFailure) require(!_ok, "expected the module path to refuse");
    }
}
