// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

// Review g22a (the contracts, end to end, fresh): the native lane against the approval lane on every target
// class, the +18-byte zero-target rail of `approveTransaction` on both real builds, and the one place the two
// lanes still disagree: a target whose code vanished between the approval's issue and its use.
// Runs on the real Safe v1.4.1 build (CuratorGuardTestBase) and on the real v1.5.0 build (the subclass).

import {Vm} from "forge-std/Vm.sol";

import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";
import {MultiSendCallOnly} from "safe-contracts-v1.4.1/contracts/libraries/MultiSendCallOnly.sol";
import {MultiSend} from "safe-contracts-v1.4.1/contracts/libraries/MultiSend.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {TestERC20} from "test/mocks/TestERC20.sol";

contract G22a_LanesTest is CuratorGuardTestBase {
    bytes32 internal constant CHECKED = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");

    CuratorGuardTimelock internal timelock;

    function setUp() public virtual override {
        super.setUp();
        address[] memory _p = new address[](1);
        _p[0] = makeAddr("proposer");
        address[] memory _c = new address[](1);
        _c[0] = makeAddr("canceller");
        timelock = new CuratorGuardTimelock(2 days, _p, _c);
    }

    function _designator(address delegate_) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"ef0100", delegate_);
    }

    function _settle(uint256 n_) internal pure returns (bytes memory) {
        return abi.encodeCall(MockProtocol.settleDeposit, (n_));
    }

    /// @dev Number of `TransactionChecked` reports in `logs_` and the outcome of the last one.
    function _reports(Vm.Log[] memory logs_) internal pure returns (uint256 _n, uint8 _outcome) {
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].topics[0] == CHECKED) {
                ++_n;
                _outcome = uint8(uint256(logs_[i].topics[3]));
            }
        }
    }

    function _approveAs(address who_, address to_, uint256 value_, bytes memory data_, Operation op_) internal returns (bytes32) {
        vm.prank(who_);
        return guard.approveTransaction(address(safe), address(0), to_, value_, data_, op_, uint64(1 days));
    }

    function _expectInvalidTarget(address to_) internal {
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, to_));
    }

    /*//////////////////////////////////////////////////////////////
                  A. the one remaining disagreement between the lanes
    //////////////////////////////////////////////////////////////*/

    /// The policy lane checks `to.code.length` at EVERY use (`NotAContract`, "such a target fails closed here
    /// from then on"); the approval lane checks it when the approval is ISSUED only (`_checkApprovalTarget`).
    /// Post-Cancun the only code that can vanish is an EIP-7702 designator, cleared by the EOA's own key: the
    /// approved call then "succeeds" against an account without code, the one-off is spent and reported as
    /// `Approval`, nothing ran. Docs section 4 states the issue-time rail's purpose as "the call would succeed,
    /// spend the one-off and do nothing": that purpose does not survive a delegation cleared after issue.
    function test_A_code_vanished_after_issue_policy_lane_fails_closed_approval_lane_spends_the_one_off() public {
        _enforce();
        address _venue = makeAddr("venue-7702");
        vm.etch(_venue, _designator(address(protocol)));
        assertEq(_venue.code.length, 23, "a designator");

        // both lanes admit the live designator (the policy lane by design: an upgradeable venue, never allowlist one)
        _allow(_venue, MockProtocol.settleDeposit.selector);
        assertTrue(_execSafeTx(_venue, 0, _settle(1), Operation.Call), "policy lane, live designator");
        // the delegate's code ran in the EOA's own storage: `calls` (slot 3) is 1 there
        assertEq(uint256(vm.load(_venue, bytes32(uint256(3)))), 1, "one call landed in the EOA's storage");
        bytes32 _id = _approve(_venue, 0, _settle(2), Operation.Call);
        assertEq(guard.approvalExpiry(_id), uint64(block.timestamp + 1 days), "approval live");

        // the EOA's key clears its delegation
        vm.etch(_venue, "");
        assertEq(_venue.code.length, 0, "the code is gone");

        // policy lane: fail closed at use
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.NotAContract.selector, _venue));
        _execSafeTx(_venue, 0, _settle(1), Operation.Call);
        // dry run of the policy lane agrees
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.NotAContract.selector, _venue));
        guard.validateTransaction(address(safe), _venue, 0, _settle(1), Operation.Call);

        // approval lane: the dry run says "usable", the live hook consumes it, the Safe's call to an account
        // without code succeeds, the transaction is reported `Approval`, nothing executed
        guard.validateTransaction(address(safe), _venue, 0, _settle(2), Operation.Call);
        vm.recordLogs();
        assertTrue(_execSafeTx(_venue, 0, _settle(2), Operation.Call), "approved call to a codeless account succeeds");
        (uint256 _n, uint8 _outcome) = _reports(vm.getRecordedLogs());
        assertEq(_n, 1, "one report");
        assertEq(_outcome, uint8(CuratorGuard.Outcome.Approval), "reported as an approved execution");
        assertEq(guard.approvalExpiry(_id), 0, "the one-off is spent");
        assertEq(uint256(vm.load(_venue, bytes32(uint256(3)))), 1, "nothing ran: the EOA's call counter is still 1");
        assertEq(uint256(vm.load(_venue, bytes32(uint256(0)))), 1, "nothing ran: lastAmount is still the policy lane's 1");
        // a second use is refused on the policy lane again (NotAContract), the one-off is gone for good
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.NotAContract.selector, _venue));
        _execSafeTx(_venue, 0, _settle(2), Operation.Call);
    }

    /// Control: the same approval against a target that keeps its code runs it (what the rail is for).
    function test_A_control_a_plain_contract_target_runs_the_approved_call() public {
        _enforce();
        bytes32 _id = _approve(address(protocol), 0, _settle(7), Operation.Call);
        vm.recordLogs();
        assertTrue(_execSafeTx(address(protocol), 0, _settle(7), Operation.Call));
        (uint256 _n, uint8 _outcome) = _reports(vm.getRecordedLogs());
        assertEq(_n, 1);
        assertEq(_outcome, uint8(CuratorGuard.Outcome.Approval));
        assertEq(protocol.lastAmount(), 7);
        assertEq(guard.approvalExpiry(_id), 0);
    }

    /*//////////////////////////////////////////////////////////////
          B. the native lane and the approval lane on every target class
    //////////////////////////////////////////////////////////////*/

    /// Native lane = `setNativeTransferAllowed` (admin) + an empty-calldata policy call; approval lane = an admin
    /// or council `approveTransaction` with empty calldata. Both must say the same thing for the zero address,
    /// an account without code, an EIP-7702 designator, the guard, the Safe, the timelock and a canonical
    /// `MultiSendCallOnly`. The one class on which they differ (the Safe itself) is the approval lane's purpose.
    function test_B_target_classes_zero_codeless_designator_guard_safe_timelock_library() public {
        _enforce();
        address _eoa = makeAddr("plain-key");
        address _designated = makeAddr("delegated-key");
        vm.etch(_designated, _designator(address(protocol)));

        // the zero address: refused on both lanes (the +18-byte rail, review G17a-3, closes the approval side)
        vm.prank(vetro);
        _expectInvalidTarget(address(0));
        guard.setNativeTransferAllowed(address(safe), address(0), true);
        _expectInvalidTarget(address(0));
        _approveAs(vetro, address(0), 1 ether, "", Operation.Call);
        _expectInvalidTarget(address(0));
        _approveAs(council, address(0), 1 ether, "", Operation.Call);
        _expectInvalidTarget(address(0));
        _approveAs(vetro, address(0), 0, "", Operation.Call);
        // and a policy batch entry to the zero address was always `MalformedMultiSend` (decoder, not the lane)

        // an account without code: a plain transfer is what the native lane is for; the approval lane agrees
        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), _eoa, true);
        assertTrue(_execSafeTx(_eoa, 1 ether, "", Operation.Call), "native lane to a key");
        _approveAs(vetro, _eoa, 1 ether, "", Operation.Call);
        assertTrue(_execSafeTx(_eoa, 1 ether, "", Operation.Call), "approval lane to a key");
        assertEq(_eoa.balance, 2 ether);
        // with calldata: the approval lane refuses at issue, the policy lane at use (NotAContract), nothing runs
        _expectInvalidTarget(_eoa);
        _approveAs(vetro, _eoa, 0, _settle(1), Operation.Call);
        _allow(_eoa, MockProtocol.settleDeposit.selector); // the allowlist entry itself is accepted (counterfactual targets)
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.NotAContract.selector, _eoa));
        _execSafeTx(_eoa, 0, _settle(1), Operation.Call);

        // an EIP-7702 designator: both lanes admit a plain transfer and a call; neither admits a delegatecall
        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), _designated, true);
        assertTrue(_execSafeTx(_designated, 1 ether, "", Operation.Call), "native lane to a designator");
        _approveAs(vetro, _designated, 1 ether, "", Operation.Call);
        assertTrue(_execSafeTx(_designated, 1 ether, "", Operation.Call), "approval lane to a designator");
        _approveAs(vetro, _designated, 0, _settle(3), Operation.Call);
        assertTrue(_execSafeTx(_designated, 0, _settle(3), Operation.Call), "approved call into a designator");
        _expectInvalidTarget(_designated);
        _approveAs(vetro, _designated, 0, _settle(3), Operation.DelegateCall);
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.UnwrapperCodehashNotAllowed.selector, _designated.codehash));
        guard.setMultiSendUnwrapper(address(safe), _designated, true);

        // the guard: refused on both lanes
        vm.prank(vetro);
        _expectInvalidTarget(address(guard));
        guard.setNativeTransferAllowed(address(safe), address(guard), true);
        _expectInvalidTarget(address(guard));
        _approveAs(vetro, address(guard), 0, "", Operation.Call);
        _expectInvalidTarget(address(guard));
        _approveAs(council, address(guard), 0, "", Operation.Call);

        // the Safe: never a policy target (self-calls are what approvals are for); the policy lets exactly the
        // empty zero-value rejection call through, the approval lane admits the empty self-call with value too
        // (harmless: the Safe pays itself)
        vm.prank(vetro);
        _expectInvalidTarget(address(safe));
        guard.setNativeTransferAllowed(address(safe), address(safe), true);
        assertTrue(_execSafeTx(address(safe), 0, "", Operation.Call), "the rejection call on the policy lane");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, bytes4(0)));
        _execSafeTx(address(safe), 1 ether, "", Operation.Call);
        _approveAs(council, address(safe), 1 ether, "", Operation.Call);
        uint256 _before = address(safe).balance;
        assertTrue(_execSafeTx(address(safe), 1 ether, "", Operation.Call), "approved empty self-call with value");
        assertEq(address(safe).balance, _before, "the Safe paid itself");

        // the timelock (a contract with `receive()`): both lanes admit a plain transfer
        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), address(timelock), true);
        assertTrue(_execSafeTx(address(timelock), 1 ether, "", Operation.Call), "native lane to the timelock");
        _approveAs(vetro, address(timelock), 1 ether, "", Operation.Call);
        assertTrue(_execSafeTx(address(timelock), 1 ether, "", Operation.Call), "approval lane to the timelock");
        assertEq(address(timelock).balance, 2 ether);

        // a canonical library (no receive, no fallback): both lanes ADMIT the entry, the library refuses the call
        vm.prank(vetro);
        guard.setNativeTransferAllowed(address(safe), address(multiSendCallOnly), true);
        vm.expectRevert(); // GS013: the Safe reverts on the failed inner call (safeTxGas == 0)
        _execSafeTx(address(multiSendCallOnly), 1 ether, "", Operation.Call);
        bytes32 _id = _approveAs(vetro, address(multiSendCallOnly), 1 ether, "", Operation.Call);
        vm.expectRevert();
        _execSafeTx(address(multiSendCallOnly), 1 ether, "", Operation.Call);
        assertEq(guard.approvalExpiry(_id), uint64(block.timestamp + 1 days), "a failed approved execution keeps the approval");
    }

    /*//////////////////////////////////////////////////////////////
                     C. the +18-byte rail, every shape, both roles
    //////////////////////////////////////////////////////////////*/

    function test_C_zero_target_rail_every_shape() public {
        _enforce();
        bytes memory _data = _settle(1);
        address[2] memory _who = [vetro, council];
        for (uint256 i; i < 2; ++i) {
            // the shape the rail closes: a plain transfer (the other three were already `InvalidTarget` before it:
            // calldata or a delegatecall to an account without code)
            _expectInvalidTarget(address(0));
            _approveAs(_who[i], address(0), 1 ether, "", Operation.Call);
            _expectInvalidTarget(address(0));
            _approveAs(_who[i], address(0), 0, "", Operation.Call);
            _expectInvalidTarget(address(0));
            _approveAs(_who[i], address(0), 0, _data, Operation.Call);
            _expectInvalidTarget(address(0));
            _approveAs(_who[i], address(0), 0, "", Operation.DelegateCall);
        }
        // through the wrapper, as the sync task issues it
        vm.prank(vetro);
        _expectInvalidTarget(address(0));
        guard.executeBefore(
            uint64(block.timestamp),
            abi.encodeCall(guard.approveTransaction, (address(safe), address(0), address(0), 1 ether, "", Operation.Call, uint64(1 days)))
        );
        // the rail precedes the mode and the ttl checks, follows the role check: a stranger is `Unauthorized`
        vm.prank(attacker);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.approveTransaction(address(safe), address(0), address(0), 1 ether, "", Operation.Call, uint64(1 days));
        // and no approval to the zero address can be found live by the hook
        bytes32 _id = guard.computeApprovalId(address(safe), address(0), address(0), 1 ether, "", Operation.Call);
        assertEq(guard.approvalExpiry(_id), 0);
    }
}

/// @dev The same on the real Safe v1.5.0 build.
contract G22a_LanesV150Test is G22a_LanesTest {
    function setUp() public virtual override {
        if (block.timestamp < 1_700_000_000) vm.warp(1_700_000_000);
        (curator, signerPk) = makeAddrAndKey("curator");
        Safe150 _singleton = new Safe150();
        SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        safe = ISafe(address(_proxy));
        vm.deal(address(safe), 10 ether);
        multiSendCallOnly = new MultiSendCallOnly();
        multiSend = new MultiSend();
        guard = new CuratorGuardHarness(0, vetro, council);
        CuratorGuardHarness(address(guard)).seedSafe(address(safe));
        token = new TestERC20("USDC", "USDC");
        protocol = new MockProtocol();
        token.mint(address(safe), 1_000_000e6);
        _execSafeTx(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(guard))), Operation.Call);
        assertEq(_installedGuard(), address(guard), "guard installed (v1.5.0)");
        address[] memory _p = new address[](1);
        _p[0] = makeAddr("proposer");
        address[] memory _c = new address[](1);
        _c[0] = makeAddr("canceller");
        timelock = new CuratorGuardTimelock(2 days, _p, _c);
    }
}
