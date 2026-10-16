// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

/// @dev Round 9, reviewer g9c. The production topology with a REAL Safe v1.4.1 proxy behind every
///      principal: two proposer Safes and one veto Safe on a `CuratorGuardTimelock` (minDelay 2 days),
///      the guard with that timelock as admin (admin-transfer delay 3 days, the deploy default) and an
///      EOA council, and a curator Safe whose one-function policy is applied through the timelock and
///      installed through a genuine `execTransaction(setGuard)`. Every proposer action is a genuine
///      Safe transaction of the proposer Safe, so a guard installed on a proposer by mistake bites.
abstract contract G16fBase is SafeTxHelper {
    uint256 internal MIN_DELAY; // g16f: from G16F_MIN_DELAY (default 2 days)
    uint48 internal constant ADMIN_DELAY = 3 days;
    bytes32 internal constant NONE = bytes32(0);
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    Safe internal singleton;
    CuratorGuardHarness internal g;
    CuratorGuardTimelock internal tl;
    MockProtocol internal protocol;

    address internal council = makeAddr("council");
    address internal stranger = makeAddr("stranger");

    ISafe internal curatorSafe;
    uint256 internal curatorPk;
    ISafe internal p1;
    uint256 internal p1Pk;
    ISafe internal p2;
    uint256 internal p2Pk;
    ISafe internal veto;
    uint256 internal vetoPk;

    function setUp() public virtual {
        vm.warp(1_700_000_000);
        MIN_DELAY = vm.envOr("G16F_MIN_DELAY", uint256(2 days));
        singleton = new Safe();
        (curatorSafe, curatorPk) = _newSafe("curator");
        (p1, p1Pk) = _newSafe("proposer-1");
        (p2, p2Pk) = _newSafe("proposer-2");
        (veto, vetoPk) = _newSafe("veto");
        tl = _newTimelock(MIN_DELAY);
        g = _newGuard(address(tl), council);
        protocol = new MockProtocol();
    }

    function _newTimelock(uint256 minDelay_) internal returns (CuratorGuardTimelock) {
        address[] memory _p = new address[](2);
        _p[0] = address(p1);
        _p[1] = address(p2);
        address[] memory _c = new address[](1);
        _c[0] = address(veto);
        return new CuratorGuardTimelock(minDelay_, _p, _c);
    }

    function _newGuard(address admin_, address council_) internal returns (CuratorGuardHarness _g) {
        _g = new CuratorGuardHarness(ADMIN_DELAY, admin_, council_);
        _g.seedSafe(address(curatorSafe)); // every proxy shares one code hash and the one singleton
    }

    function _newSafe(string memory name_) internal returns (ISafe _safe, uint256 _pk) {
        address _owner;
        (_owner, _pk) = makeAddrAndKey(name_);
        SafeProxy _proxy = new SafeProxy(address(singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = _owner;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        _safe = ISafe(address(_proxy));
        vm.deal(address(_safe), 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                           SAFE TRANSACTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev A Safe transaction of `safe_` signed by its single owner (`safeTxGas = 0`, no refund).
    function _exec(ISafe safe_, uint256 pk_, address to_, uint256 value_, bytes memory data_, Operation op_) internal returns (bool) {
        safe = safe_;
        signerPk = pk_;
        return _execSafeTx(to_, value_, data_, op_);
    }

    function _installOn(ISafe safe_, uint256 pk_) internal {
        _exec(safe_, pk_, address(safe_), 0, abi.encodeCall(ISafe.setGuard, (address(g))), Operation.Call);
        assertEq(_guardOf(safe_), address(g), "guard installed");
    }

    function _guardOf(ISafe safe_) internal view returns (address) {
        return address(uint160(uint256(bytes32(safe_.getStorageAt(uint256(GUARD_SLOT), 1)))));
    }

    /*//////////////////////////////////////////////////////////////
                                TIMELOCK
    //////////////////////////////////////////////////////////////*/

    /// @dev `proposer_` schedules a one-call operation on `tl_` through a genuine Safe transaction.
    function _scheduleOn(
        CuratorGuardTimelock tl_,
        ISafe proposer_,
        uint256 pk_,
        address target_,
        bytes memory data_,
        bytes32 pred_,
        bytes32 salt_
    ) internal returns (bytes32) {
        uint256 _delay = tl_.getMinDelay();
        _exec(proposer_, pk_, address(tl_), 0, abi.encodeCall(tl_.schedule, (target_, 0, data_, pred_, salt_, _delay)), Operation.Call);
        return tl_.hashOperation(target_, 0, data_, pred_, salt_);
    }

    function _schedule(ISafe proposer_, uint256 pk_, address target_, bytes memory data_, bytes32 pred_, bytes32 salt_) internal returns (bytes32) {
        return _scheduleOn(tl, proposer_, pk_, target_, data_, pred_, salt_);
    }

    function _scheduleBatch(
        ISafe proposer_,
        uint256 pk_,
        address[] memory targets_,
        bytes[] memory payloads_,
        bytes32 pred_,
        bytes32 salt_
    ) internal returns (bytes32) {
        uint256[] memory _values = new uint256[](targets_.length);
        _exec(proposer_, pk_, address(tl), 0, abi.encodeCall(tl.scheduleBatch, (targets_, _values, payloads_, pred_, salt_, MIN_DELAY)), Operation.Call);
        return tl.hashOperationBatch(targets_, _values, payloads_, pred_, salt_);
    }

    function _executeOn(CuratorGuardTimelock tl_, address target_, bytes memory data_, bytes32 pred_, bytes32 salt_) internal {
        vm.prank(stranger); // the executor role is open
        tl_.execute(target_, 0, data_, pred_, salt_);
    }

    function _execute(address target_, bytes memory data_, bytes32 pred_, bytes32 salt_) internal {
        _executeOn(tl, target_, data_, pred_, salt_);
    }

    function _executeBatch(address[] memory targets_, bytes[] memory payloads_, bytes32 pred_, bytes32 salt_) internal {
        uint256[] memory _values = new uint256[](targets_.length);
        vm.prank(stranger);
        tl.executeBatch(targets_, _values, payloads_, pred_, salt_);
    }

    function _cancel(bytes32 id_) internal {
        _exec(veto, vetoPk, address(tl), 0, abi.encodeCall(tl.cancel, (id_)), Operation.Call);
    }

    /// @dev One admin call on the guard through the timelock: p1 schedules, the delay passes, anyone executes.
    function _adminCall(bytes memory data_, bytes32 salt_) internal {
        _schedule(p1, p1Pk, address(g), data_, NONE, salt_);
        vm.warp(block.timestamp + MIN_DELAY);
        _execute(address(g), data_, NONE, salt_);
    }

    /// @dev One admin batch on the guard through the timelock.
    function _adminBatch(bytes[] memory payloads_, bytes32 salt_) internal {
        address[] memory _t = _guardTargets(payloads_.length);
        _scheduleBatch(p1, p1Pk, _t, payloads_, NONE, salt_);
        vm.warp(block.timestamp + MIN_DELAY);
        _executeBatch(_t, payloads_, NONE, salt_);
    }

    function _guardTargets(uint256 n_) internal view returns (address[] memory _t) {
        _t = new address[](n_);
        for (uint256 i; i < n_; ++i) _t[i] = address(g);
    }

    /*//////////////////////////////////////////////////////////////
                              CURATOR POLICY
    //////////////////////////////////////////////////////////////*/

    /// @dev The curator Safe's policy (`settleDeposit` on the mock venue, Enforced) applied through the
    ///      timelock, then the guard installed by the curator.
    function _configureCurator() internal {
        bytes[] memory _d = new bytes[](2);
        _d[0] = abi.encodeCall(g.allowFunction, (address(curatorSafe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules()));
        _d[1] = abi.encodeCall(g.enforce, (address(curatorSafe)));
        _adminBatch(_d, "policy");
        _installOn(curatorSafe, curatorPk);
        assertTrue(_settle(), "policy call passes");
    }

    function _settle() internal returns (bool) {
        return _exec(curatorSafe, curatorPk, address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
    }

    function _noRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _rules) {}

    function _wrap(uint64 deadline_, bytes memory call_) internal view returns (bytes memory) {
        return abi.encodeCall(g.executeBefore, (deadline_, call_));
    }
}
