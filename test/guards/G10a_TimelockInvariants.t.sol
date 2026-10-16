// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Test.sol";

import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";

/// @title Round 10 (g10a): the timelock's role machine under scheduled self-calls, against a model of
///        its rails (docs section 4; `CuratorGuardTimelock` header).
/// @dev Universe: two initial proposers, the veto Safe, two outsiders, the zero address and the timelock
///      itself (seven accounts, EOAs stand in for Safes: the forwarded-call probe passes them). Every
///      role change is proposed by a current proposer, waits `getMinDelay()`, is executed by anyone and
///      its verdict compared with the model; a refused one stays `Ready` until the veto cancels it.
///      Invariants: the two counters equal the true holder counts, no account proposes and cancels, the
///      timelock and the zero address never hold a gated role, the executor stays open, the timelock is
///      its only admin, at least one proposer and one canceller remain, the effective delay stays within
///      the clamp whatever `updateDelay` was scheduled.
contract G10aTimelockHandler {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    CuratorGuardTimelock public immutable tl;
    address[7] public universe; // p1, p2, veto, x, y, address(0), the timelock
    bool[7] public isP;
    bool[7] public isC;
    uint256 public nP;
    uint256 public nC;
    uint256 public salt;
    uint256 public mDelay;

    bool public verdictMismatch;
    bytes32 public lastTag;
    uint256 public scheduled;
    uint256 public executed;
    uint256 public refusedAtSchedule;
    uint256 public refusedAtExecute;
    uint256 public cancelled;

    constructor(CuratorGuardTimelock tl_, address p1_, address p2_, address veto_, address x_, address y_, uint256 delay_) {
        tl = tl_;
        universe = [p1_, p2_, veto_, x_, y_, address(0), address(tl_)];
        isP[0] = true;
        isP[1] = true;
        isC[2] = true;
        nP = 2;
        nC = 1;
        mDelay = delay_;
    }

    function _check(bool ok_, bool expected_, bytes32 tag_) internal {
        if (ok_ != expected_) {
            verdictMismatch = true;
            lastTag = tag_;
        }
    }

    function _proposer() internal view returns (address) {
        for (uint256 i; i < 7; ++i) if (isP[i]) return universe[i];
        return address(0);
    }

    function _canceller() internal view returns (address) {
        for (uint256 i; i < 7; ++i) if (isC[i]) return universe[i];
        return address(0);
    }

    /// @dev Schedules `data_` as a self-call, waits the delay and executes; returns the execute verdict.
    ///      A refused execution leaves the operation `Ready`: the veto clears it.
    function _selfCall(bytes memory data_, bytes32 tag_, bool expected_) internal {
        uint256 _delay = tl.getMinDelay();
        bytes32 _salt = bytes32(++salt);
        vm.prank(_proposer());
        tl.schedule(address(tl), 0, data_, bytes32(0), _salt, _delay);
        ++scheduled;
        bytes32 _id = tl.hashOperation(address(tl), 0, data_, bytes32(0), _salt);
        vm.warp(block.timestamp + _delay);
        (bool _ok, ) = address(tl).call(abi.encodeCall(tl.execute, (address(tl), 0, data_, bytes32(0), _salt)));
        _check(_ok, expected_, tag_);
        if (_ok) {
            ++executed;
            if (!tl.isOperationDone(_id)) _check(false, true, "done");
        } else {
            ++refusedAtExecute;
            if (!tl.isOperationReady(_id)) _check(false, true, "ready");
            vm.prank(_canceller());
            tl.cancel(_id);
            ++cancelled;
            if (tl.isOperation(_id)) _check(false, true, "unset");
        }
    }

    function rotate(uint256 seed_) external {
        uint256 _k = seed_ % 8;
        uint256 _a = (seed_ >> 3) % 7;
        address _acct = universe[_a];
        bool _zero = _a == 5;
        bool _self = _a == 6;
        if (_k == 0) {
            bool _exp = !_zero && !_self && !isC[_a];
            _selfCall(abi.encodeCall(tl.grantRole, (tl.PROPOSER_ROLE(), _acct)), "grantP", _exp);
            if (_exp && !isP[_a]) {
                isP[_a] = true;
                ++nP;
            }
        } else if (_k == 1) {
            bool _exp = !(isP[_a] && nP == 1);
            _selfCall(abi.encodeCall(tl.revokeRole, (tl.PROPOSER_ROLE(), _acct)), "revokeP", _exp);
            if (_exp && isP[_a]) {
                isP[_a] = false;
                --nP;
            }
        } else if (_k == 2) {
            bool _exp = !_zero && !_self && !isP[_a];
            _selfCall(abi.encodeCall(tl.grantRole, (tl.CANCELLER_ROLE(), _acct)), "grantC", _exp);
            if (_exp && !isC[_a]) {
                isC[_a] = true;
                ++nC;
            }
        } else if (_k == 3) {
            bool _exp = !(isC[_a] && nC == 1);
            _selfCall(abi.encodeCall(tl.revokeRole, (tl.CANCELLER_ROLE(), _acct)), "revokeC", _exp);
            if (_exp && isC[_a]) {
                isC[_a] = false;
                --nC;
            }
        } else if (_k == 4) {
            _selfCall(abi.encodeCall(tl.grantRole, (tl.EXECUTOR_ROLE(), _acct)), "grantE", true);
        } else if (_k == 5) {
            _selfCall(abi.encodeCall(tl.revokeRole, (tl.EXECUTOR_ROLE(), _acct)), "revokeE", !_zero);
        } else if (_k == 6) {
            _selfCall(abi.encodeCall(tl.grantRole, (tl.DEFAULT_ADMIN_ROLE(), _acct)), "grantAdmin", _self);
        } else {
            _selfCall(abi.encodeCall(tl.revokeRole, (tl.DEFAULT_ADMIN_ROLE(), _acct)), "revokeAdmin", !_self);
        }
    }

    /// @dev `updateDelay` outside the clamp is refused when PROPOSED; inside it executes and moves the
    ///      effective delay.
    function delay(uint256 seed_) external {
        uint256[6] memory _d = [uint256(1 hours), 1 days - 1, 1 days, 7 days, 30 days, 30 days + 1];
        uint256 _new = _d[seed_ % 6];
        bool _inRange = _new >= 1 days && _new <= 30 days;
        bytes memory _data = abi.encodeCall(tl.updateDelay, (_new));
        bytes32 _salt = bytes32(++salt);
        uint256 _delay = tl.getMinDelay();
        vm.prank(_proposer());
        (bool _ok, ) = address(tl).call(abi.encodeCall(tl.schedule, (address(tl), 0, _data, bytes32(0), _salt, _delay)));
        _check(_ok, _inRange, "schedule updateDelay");
        if (!_ok) {
            ++refusedAtSchedule;
            return;
        }
        ++scheduled;
        vm.warp(block.timestamp + _delay);
        tl.execute(address(tl), 0, _data, bytes32(0), _salt);
        ++executed;
        mDelay = _new;
    }

    function time_passes(uint256 seed_) external {
        vm.warp(block.timestamp + 1 + (seed_ % 2 days));
    }
}

contract G10aTimelockInvariantsTest is Test {
    CuratorGuardTimelock internal tl;
    G10aTimelockHandler internal handler;
    address internal p1 = makeAddr("proposer-1");
    address internal p2 = makeAddr("proposer-2");
    address internal veto = makeAddr("veto");
    address internal x = makeAddr("x");
    address internal y = makeAddr("y");

    function setUp() public {
        vm.warp(1_700_000_000);
        address[] memory _p = new address[](2);
        _p[0] = p1;
        _p[1] = p2;
        address[] memory _c = new address[](1);
        _c[0] = veto;
        tl = new CuratorGuardTimelock(1 days, _p, _c);
        handler = new G10aTimelockHandler(tl, p1, p2, veto, x, y, 1 days);
        targetContract(address(handler));
    }

    function invariant_g10a_timelock_verdicts_match_the_rails() public view {
        assertFalse(handler.verdictMismatch(), string(abi.encodePacked("verdict mismatch: ", handler.lastTag())));
    }

    function invariant_g10a_timelock_counts_equal_the_true_holder_sets() public view {
        uint256 _p;
        uint256 _c;
        for (uint256 i; i < 7; ++i) {
            address _a = handler.universe(i);
            bool _isP = tl.hasRole(tl.PROPOSER_ROLE(), _a);
            bool _isC = tl.hasRole(tl.CANCELLER_ROLE(), _a);
            assertEq(_isP, handler.isP(i), "proposer set");
            assertEq(_isC, handler.isC(i), "canceller set");
            assertFalse(_isP && _isC, "a proposer cancels");
            if (_isP) ++_p;
            if (_isC) ++_c;
        }
        assertEq(tl.proposerCount(), _p, "proposerCount");
        assertEq(tl.cancellerCount(), _c, "cancellerCount");
        assertGe(_p, 1, "a proposer remains");
        assertGe(_c, 1, "a canceller remains");
    }

    function invariant_g10a_timelock_fixed_points() public view {
        assertFalse(tl.hasRole(tl.PROPOSER_ROLE(), address(tl)), "self proposer");
        assertFalse(tl.hasRole(tl.CANCELLER_ROLE(), address(tl)), "self canceller");
        assertFalse(tl.hasRole(tl.PROPOSER_ROLE(), address(0)), "zero proposer");
        assertFalse(tl.hasRole(tl.CANCELLER_ROLE(), address(0)), "zero canceller");
        assertTrue(tl.hasRole(tl.EXECUTOR_ROLE(), address(0)), "open executor");
        assertTrue(tl.hasRole(tl.DEFAULT_ADMIN_ROLE(), address(tl)), "self admin");
        for (uint256 i; i < 6; ++i) assertFalse(tl.hasRole(tl.DEFAULT_ADMIN_ROLE(), handler.universe(i)), "a second admin");
        assertGe(tl.getMinDelay(), 1 hours, "delay floor");
        assertLe(tl.getMinDelay(), 30 days, "delay cap");
        assertEq(tl.getMinDelay(), handler.mDelay(), "effective delay is what was scheduled");
    }

    function test_g10a_timelock_handler_is_live() public {
        handler.rotate(0 | (3 << 3)); // grant proposer x
        handler.rotate(1 | (0 << 3)); // revoke proposer p1
        handler.rotate(1 | (1 << 3)); // revoke proposer p2
        handler.rotate(1 | (3 << 3)); // revoke proposer x: refused (last)
        handler.rotate(2 | (4 << 3)); // grant canceller y
        handler.rotate(3 | (2 << 3)); // revoke canceller veto
        handler.rotate(2 | (3 << 3)); // grant canceller x: refused (a proposer)
        handler.rotate(0 | (4 << 3)); // grant proposer y: refused (a canceller)
        handler.rotate(0 | (5 << 3)); // grant proposer zero: refused
        handler.rotate(0 | (6 << 3)); // grant proposer self: refused
        handler.rotate(5 | (5 << 3)); // revoke open executor: refused
        handler.rotate(6 | (3 << 3)); // grant admin x: refused
        handler.rotate(7 | (6 << 3)); // revoke self admin: refused
        handler.delay(0); // 3599: refused at schedule
        handler.delay(3); // 30 days
        handler.delay(4); // 30 days + 1: refused at schedule
        handler.delay(1); // back to 1 hour
        assertFalse(handler.verdictMismatch(), string(abi.encodePacked("verdict mismatch: ", handler.lastTag())));
        assertEq(handler.refusedAtExecute(), 8);
        assertEq(handler.refusedAtSchedule(), 2);
        assertEq(handler.cancelled(), 8);
        invariant_g10a_timelock_counts_equal_the_true_holder_sets();
        invariant_g10a_timelock_fixed_points();
    }
}
