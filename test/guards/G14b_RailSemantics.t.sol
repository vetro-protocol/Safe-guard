// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";
import {console2} from "forge-std/console2.sol";
import {CompatibilityFallbackHandler} from "safe-contracts-v1.4.1/contracts/handler/CompatibilityFallbackHandler.sol";
import {MultiSendCallOnly} from "safe-contracts-v1.4.1/contracts/libraries/MultiSendCallOnly.sol";
import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G9cBase} from "test/guards/G9c_Base.sol";

/// @dev An account that answers EVERY unknown selector with a fixed return built from three words (`len_`
///      bytes of it), and acts on a target as itself through `act`. Shapes the forwarding probe's answer: a
///      Safe v1.3.0+ answers `getStorageAt(slot, 1)` with (0x20, 0x20, word), 96 bytes.
contract G14bAnswer {
    bytes32 internal immutable w0;
    bytes32 internal immutable w1;
    bytes32 internal immutable w2;
    uint256 internal immutable len;

    constructor(bytes32 w0_, bytes32 w1_, bytes32 w2_, uint256 len_) {
        w0 = w0_;
        w1 = w1_;
        w2 = w2_;
        len = len_;
    }

    function act(address target_, bytes calldata call_) external returns (bool _ok, bytes memory _ret) {
        (_ok, _ret) = target_.call(call_);
    }

    fallback() external {
        bytes32 _a = w0;
        bytes32 _b = w1;
        bytes32 _c = w2;
        uint256 _l = len;
        assembly {
            mstore(0x00, _a)
            mstore(0x20, _b)
            mstore(0x40, _c)
            mstore(0x60, 0)
            return(0x00, _l)
        }
    }
}

/// @dev A proxy that relays every unknown call, statically, to `to` and returns its answer verbatim; acts
///      on a target as itself through `act`.
contract G14bForwarder {
    address internal immutable to;

    constructor(address to_) {
        to = to_;
    }

    function act(address target_, bytes calldata call_) external returns (bool _ok, bytes memory _ret) {
        (_ok, _ret) = target_.call(call_);
    }

    fallback() external {
        address _to = to;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let _ok := staticcall(gas(), _to, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(_ok) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
    }
}

/// @dev `CuratorGuardPolicy._isHandlerOf`, verbatim, with the guard's address as a parameter, so the probe's
///      verdict and cost can be measured from a caller's frame.
contract G14bProbe {
    function probe(address account_, address guard_) external view returns (bool _yes, uint256 _gas) {
        bytes32 _slot = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
        uint256 _g0 = gasleft();
        assembly ("memory-safe") {
            let _p := mload(0x40)
            mstore(_p, 0x5624b25b00000000000000000000000000000000000000000000000000000000)
            mstore(add(_p, 0x04), _slot)
            mstore(add(_p, 0x24), 1)
            let _ok := staticcall(gas(), account_, _p, 0x44, _p, 0x60)
            _yes := and(and(_ok, eq(returndatasize(), 0x60)), eq(mload(add(_p, 0x40)), guard_))
        }
        _gas = _g0 - gasleft();
    }
}

/// @title Round 14 (g14b): the semantics of the forwarded-caller rail at its two new entries, `executeBefore`
///        and `_acceptDefaultAdminTransfer` (commit 4892722).
/// @dev   On g9c's production topology: a real Safe v1.4.1 proxy behind every principal, a real
///        `CuratorGuardTimelock` (2 days) as the guard's admin, an EOA council; v1.5.0 builds where named.
///        A: every legitimate caller of the two entries is served. B: every forwarded caller is refused, on
///        both Safe builds. C: the probe itself (answer shapes, another guard instance as handler, the guard's
///        own address, a relaying proxy). D: gas (starvation sweeps, the probe's cost, a 40-call batch).
contract G14b_RailSemanticsTest is G9cBase {
    bytes32 internal constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    bytes32 internal constant FORGED = keccak256("g14b: no Safe transaction ever carried this hash");
    bytes32 internal constant REPORT_SIG = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");
    bytes4 internal constant SET_FALLBACK_HANDLER = 0xf08a0323;

    MultiSendCallOnly internal multiSendCallOnly;
    CompatibilityFallbackHandler internal handler141;
    G14bProbe internal probe;

    function setUp() public override {
        super.setUp();
        _configureCurator();
        multiSendCallOnly = new MultiSendCallOnly();
        handler141 = new CompatibilityFallbackHandler();
        probe = new G14bProbe();
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _handlerOf(address safe_) internal view returns (address) {
        return address(uint160(uint256(bytes32(ISafe(safe_).getStorageAt(uint256(FALLBACK_SLOT), 1)))));
    }

    /// @dev A genuine Safe transaction of an unguarded Safe setting its handler (the Safe implements the
    ///      selector itself, so the slot's content never interferes).
    function _setHandler(ISafe safe_, uint256 pk_, address handler_) internal {
        assertTrue(
            _exec(safe_, pk_, address(safe_), 0, abi.encodeWithSelector(SET_FALLBACK_HANDLER, handler_), Operation.Call),
            "setFallbackHandler"
        );
        assertEq(_handlerOf(address(safe_)), handler_, "handler slot");
    }

    /// @dev The planted state (the premise of every forwarded case), written as the Safe's self-call.
    function _plantHandler(ISafe safe_, address handler_) internal {
        vm.prank(address(safe_));
        (bool _ok, ) = address(safe_).call(abi.encodeWithSelector(SET_FALLBACK_HANDLER, handler_));
        assertTrue(_ok, "plant");
        assertEq(_handlerOf(address(safe_)), handler_, "planted");
    }

    function _wrapped(bytes memory call_) internal view returns (bytes memory) {
        return _wrap(uint64(block.timestamp + 1 hours), call_);
    }

    function _afterHook(bytes32 hash_) internal view returns (bytes memory) {
        return abi.encodeCall(g.checkAfterExecution, (hash_, true));
    }

    function _accept() internal view returns (bytes memory) {
        return abi.encodeCall(g.acceptDefaultAdminTransfer, ());
    }

    function _lock() internal view returns (bytes memory) {
        return abi.encodeCall(g.lockdown, (address(curatorSafe)));
    }

    function _reports(Vm.Log[] memory logs_) internal view returns (uint256 _count) {
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter == address(g) && logs_[i].topics[0] == REPORT_SIG) ++_count;
        }
    }

    function _grantCouncil(address who_, bytes32 salt_) internal {
        _adminCall(abi.encodeCall(g.grantRole, (g.COUNCIL_ROLE(), who_)), salt_);
        assertTrue(g.hasRole(g.COUNCIL_ROLE(), who_), "council granted");
    }

    function _beginTo(address who_, bytes32 salt_) internal {
        _adminCall(_wrap(uint64(block.timestamp + MIN_DELAY + 1 days), abi.encodeCall(g.beginDefaultAdminTransfer, (who_))), salt_);
        (address _pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, who_, "pending admin");
    }

    function _mode() internal view returns (CuratorGuardPolicy.Mode) {
        return g.mode(address(curatorSafe));
    }

    /// @dev A real Safe v1.5.0 (singleton + proxy, 1-of-1), seeded so the policy path knows its code.
    function _newSafe150(string memory name_) internal returns (ISafe _safe, uint256 _pk) {
        address _owner;
        (_owner, _pk) = makeAddrAndKey(name_);
        Safe150 _singleton = new Safe150();
        SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = _owner;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        _safe = ISafe(address(_proxy));
        vm.deal(address(_safe), 1 ether);
        g.seedSafe(address(_safe));
    }

    function _entry(address to_, bytes memory data_) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to_, uint256(0), data_.length, data_);
    }

    function _assertRefused(bool ok_, bytes memory ret_, string memory why_) internal pure {
        assertFalse(ok_, why_);
        assertEq(bytes4(ret_), CuratorGuardPolicy.Unauthorized.selector, why_);
    }

    /*//////////////////////////////////////////////////////////////
                    A. LEGITIMATE CALLERS ARE NOT REFUSED
    //////////////////////////////////////////////////////////////*/

    /// @dev The timelock as the executor of a scheduled, wrapped admin call (the sync's shape; the open
    ///      executor is a stranger). The timelock answers the probe with nothing: no `getStorageAt`, no
    ///      fallback. The deadline is still checked after the rail.
    function test_A1_the_timelock_executing_a_wrapped_admin_call_is_not_refused() public {
        bytes memory _widen = abi.encodeCall(
            g.allowFunction,
            (address(curatorSafe), address(protocol), MockProtocol.deposit.selector, false, _noRules())
        );
        _adminCall(_wrap(uint64(block.timestamp + MIN_DELAY + 1 days), _widen), "a1");
        (bool _allowed, , ) = g.functionPermission(address(curatorSafe), address(protocol), MockProtocol.deposit.selector);
        assertTrue(_allowed, "the wrapped widening landed through the open executor");

        (bool _ok, bytes memory _ret) = address(tl).staticcall(
            abi.encodeWithSelector(ISafe.getStorageAt.selector, uint256(FALLBACK_SLOT), uint256(1))
        );
        assertFalse(_ok, "the timelock has no getStorageAt");
        assertEq(_ret.length, 0, "and no fallback");
        (bool _yes, ) = probe.probe(address(tl), address(g));
        assertFalse(_yes, "the probe reads the timelock as not forwarding");

        uint64 _dead = uint64(block.timestamp + MIN_DELAY - 1);
        bytes memory _late = _wrap(_dead, _widen);
        _schedule(p1, p1Pk, address(g), _late, NONE, "a1-late");
        vm.warp(block.timestamp + MIN_DELAY);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, _dead));
        tl.execute(address(g), 0, _late, NONE, "a1-late");
    }

    /// @dev A council Safe with Safe's own `CompatibilityFallbackHandler` in its handler slot: the probe
    ///      answers that handler, not the guard; wrapped and direct council actions are served.
    function test_A2_a_council_safe_with_a_real_handler_is_not_refused() public {
        (ISafe _c, uint256 _cPk) = _newSafe("council-safe");
        _setHandler(_c, _cPk, address(handler141));
        _grantCouncil(address(_c), "a2");
        (bool _yes, ) = probe.probe(address(_c), address(g));
        assertFalse(_yes, "a Safe-shaped answer naming another handler");

        bytes memory _open = abi.encodeCall(g.bypass, (address(curatorSafe), uint64(2 hours)));
        assertTrue(_exec(_c, _cPk, address(g), 0, _wrapped(_open), Operation.Call), "wrapped bypass");
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Bypass));
        (uint64 _until, bool _byCouncil) = g.bypassWindow(address(curatorSafe));
        assertEq(_until, uint64(block.timestamp + 2 hours));
        assertTrue(_byCouncil);
        assertTrue(_exec(_c, _cPk, address(g), 0, abi.encodeCall(g.enforce, (address(curatorSafe))), Operation.Call), "direct enforce");
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Enforced));
    }

    /// @dev A guardian Safe (per-Safe seat, no handler) wrapping its `lockdown`.
    function test_A3_a_guardian_safe_is_not_refused() public {
        (ISafe _gs, uint256 _gsPk) = _newSafe("guardian-safe");
        _adminCall(abi.encodeCall(g.setGuardian, (address(curatorSafe), address(_gs), true)), "a3");
        assertTrue(_exec(_gs, _gsPk, address(g), 0, _wrapped(_lock()), Operation.Call), "wrapped lockdown");
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Lockdown));
    }

    /// @dev An EOA pending admin accepts directly and through the wrapper (the probe of an account without
    ///      code succeeds with no return data: not forwarded).
    function test_A4_an_eoa_pending_admin_accepts_directly_and_wrapped() public {
        address _eoa = makeAddr("eoa-admin");
        _beginTo(_eoa, "a4");
        vm.warp(block.timestamp + ADMIN_DELAY + 1);
        uint256 _t = block.timestamp;
        uint256 _snap = vm.snapshotState();
        vm.prank(_eoa);
        g.acceptDefaultAdminTransfer();
        assertEq(g.defaultAdmin(), _eoa, "direct");
        vm.revertToState(_snap);
        vm.warp(_t);
        vm.prank(_eoa);
        g.executeBefore(uint64(block.timestamp + 1), _accept());
        assertEq(g.defaultAdmin(), _eoa, "wrapped");
    }

    /// @dev A successor timelock at the new floor (one day) accepts, bare and wrapped (both rails probe
    ///      it, it answers neither). A one-hour successor can no longer be built.
    function test_A5_a_successor_timelock_at_the_new_floor_accepts_bare_and_wrapped() public {
        address[] memory _p = new address[](1);
        _p[0] = address(p1);
        address[] memory _c = new address[](1);
        _c[0] = address(veto);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, uint256(1 hours)));
        new CuratorGuardTimelock(1 hours, _p, _c);

        CuratorGuardTimelock _tlB = _newTimelock(1 days);
        assertEq(_tlB.getMinDelay(), 1 days);
        _beginTo(address(_tlB), "a5");
        uint256 _t = block.timestamp;
        uint256 _snap = vm.snapshotState();

        bytes32 _id = _scheduleOn(_tlB, p1, p1Pk, address(g), _accept(), NONE, "a5-bare");
        vm.warp(block.timestamp + ADMIN_DELAY + 1);
        assertTrue(_tlB.isOperationReady(_id));
        _executeOn(_tlB, address(g), _accept(), NONE, "a5-bare");
        assertEq(g.defaultAdmin(), address(_tlB), "bare acceptance");

        vm.revertToState(_snap);
        vm.warp(_t);
        bytes memory _w = _wrap(uint64(block.timestamp + ADMIN_DELAY + 1 days), _accept());
        _scheduleOn(_tlB, p1, p1Pk, address(g), _w, NONE, "a5-wrapped");
        vm.warp(block.timestamp + ADMIN_DELAY + 1);
        _executeOn(_tlB, address(g), _w, NONE, "a5-wrapped");
        assertEq(g.defaultAdmin(), address(_tlB), "wrapped acceptance");
    }

    /// @dev A Safe pending admin accepts with a real handler; with this guard in its slot it is refused on
    ///      every route (a stranger's forwarded call, the wrapper, and its OWN genuine transaction: the rail
    ///      reads the slot, not the route); the Safe's own `setFallbackHandler` is the repair, then it accepts.
    function test_A6_a_safe_pending_admin_accepts_unless_its_handler_is_this_guard() public {
        (ISafe _dao, uint256 _daoPk) = _newSafe("dao-safe");
        _setHandler(_dao, _daoPk, address(handler141));
        _beginTo(address(_dao), "a6");
        vm.warp(block.timestamp + ADMIN_DELAY + 1);
        uint256 _t = block.timestamp;
        uint256 _snap = vm.snapshotState();
        assertTrue(_exec(_dao, _daoPk, address(g), 0, _accept(), Operation.Call), "accepted with a real handler");
        assertEq(g.defaultAdmin(), address(_dao));

        vm.revertToState(_snap);
        vm.warp(_t);
        _setHandler(_dao, _daoPk, address(g));
        vm.startPrank(stranger);
        (bool _ok, bytes memory _ret) = address(_dao).call(_accept());
        _assertRefused(_ok, _ret, "forwarded acceptance");
        (_ok, _ret) = address(_dao).call(_wrapped(_accept()));
        _assertRefused(_ok, _ret, "forwarded wrapped acceptance");
        vm.stopPrank();
        vm.prank(address(_dao));
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.acceptDefaultAdminTransfer();
        safe = _dao;
        signerPk = _daoPk;
        vm.expectRevert(bytes("GS013"));
        _execSafeTx(address(g), 0, _accept(), Operation.Call);
        assertEq(g.defaultAdmin(), address(tl), "admin unchanged");
        (address _pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, address(_dao), "still pending: the late cancel stays with the admin");

        _setHandler(_dao, _daoPk, address(0));
        assertTrue(_exec(_dao, _daoPk, address(g), 0, _accept(), Operation.Call), "accepted after the repair");
        assertEq(g.defaultAdmin(), address(_dao));
    }

    /// @dev A council Safe's `MultiSendCallOnly` batch (delegatecall) of wrapped calls keeps the Safe as
    ///      the caller of every entry: served. The same library called by an EOA is the caller itself:
    ///      not forwarded, just unauthorised.
    function test_A7_a_multisend_batch_of_wrapped_calls_from_a_council_safe_is_not_refused() public {
        (ISafe _c, uint256 _cPk) = _newSafe("council-safe-batch");
        _grantCouncil(address(_c), "a7");
        address _key = makeAddr("responder");
        bytes memory _packed = abi.encodePacked(
            _entry(address(g), _wrapped(abi.encodeCall(g.bypass, (address(curatorSafe), uint64(2 hours))))),
            _entry(address(g), _wrapped(abi.encodeCall(g.setGuardian, (address(curatorSafe), _key, true))))
        );
        bytes memory _batch = abi.encodeWithSelector(MultiSendCallOnly.multiSend.selector, _packed);
        assertTrue(_exec(_c, _cPk, address(multiSendCallOnly), 0, _batch, Operation.DelegateCall), "batch");
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Bypass));
        assertTrue(g.isGuardian(address(curatorSafe), _key));

        vm.prank(stranger);
        (bool _ok, ) = address(multiSendCallOnly).call(_batch);
        assertFalse(_ok, "the library as the caller holds no role");
        (bool _yes, ) = probe.probe(address(multiSendCallOnly), address(g));
        assertFalse(_yes, "and is not read as forwarding");
    }

    /// @dev `executeBefore(executeBefore(call))`: the delegatecall keeps the caller, both layers probe the
    ///      same account.
    function test_A8_a_nested_executeBefore_keeps_the_caller_and_is_not_refused() public {
        bytes memory _inner = _wrap(uint64(block.timestamp + MIN_DELAY + 2 days), _lock());
        _adminCall(_wrap(uint64(block.timestamp + MIN_DELAY + 1 days), _inner), "a8");
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Lockdown));
    }

    /*//////////////////////////////////////////////////////////////
                      B. FORWARDED CALLERS ARE REFUSED
    //////////////////////////////////////////////////////////////*/

    /// @dev A council Safe whose handler is the guard: wrapped, wrapped with an expired deadline (the rail
    ///      runs first), nested, direct (V2-100): all `Unauthorized`, no window. Its own genuine
    ///      transaction is refused the same way while the slot holds the guard, and served after the repair.
    function test_B1_a_forwarded_council_safe_is_refused_on_executeBefore_before_the_deadline_check() public {
        (ISafe _c, uint256 _cPk) = _newSafe("council-safe-fwd");
        _grantCouncil(address(_c), "b1");
        _setHandler(_c, _cPk, address(g));
        bytes memory _open = abi.encodeCall(g.bypass, (address(curatorSafe), uint64(7 days)));
        vm.startPrank(stranger);
        (bool _ok, bytes memory _ret) = address(_c).call(_wrapped(_open));
        _assertRefused(_ok, _ret, "wrapped");
        (_ok, _ret) = address(_c).call(_wrap(uint64(block.timestamp - 1), _open));
        _assertRefused(_ok, _ret, "expired deadline: the rail before the deadline check");
        (_ok, _ret) = address(_c).call(_wrapped(_wrapped(_open)));
        _assertRefused(_ok, _ret, "nested");
        (_ok, _ret) = address(_c).call(_open);
        _assertRefused(_ok, _ret, "direct (V2-100)");
        vm.stopPrank();
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Enforced), "no window");

        vm.prank(address(_c));
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.executeBefore(uint64(block.timestamp + 1 hours), _open);
        safe = _c;
        signerPk = _cPk;
        vm.expectRevert(bytes("GS013"));
        _execSafeTx(address(g), 0, _wrapped(_open), Operation.Call);

        _setHandler(_c, _cPk, address(0));
        assertTrue(_exec(_c, _cPk, address(g), 0, _wrapped(_open), Operation.Call), "served after the repair");
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Bypass));
    }

    function _forgeAttempt(ISafe safe_) internal returns (uint256 _count) {
        vm.recordLogs();
        vm.startPrank(stranger);
        (bool _ok, bytes memory _ret) = address(safe_).call(_wrapped(_afterHook(FORGED)));
        _assertRefused(_ok, _ret, "owner-path after-hook, wrapped");
        (_ok, _ret) = address(safe_).call(_wrapped(abi.encodeCall(g.checkAfterModuleExecution, (FORGED, true))));
        _assertRefused(_ok, _ret, "module-path after-hook, wrapped");
        (_ok, _ret) = address(safe_).call(_wrapped(_wrapped(_afterHook(FORGED))));
        _assertRefused(_ok, _ret, "nested");
        (_ok, _ret) = address(safe_).call(_afterHook(FORGED));
        assertFalse(_ok, "direct forwarded after-hook");
        assertEq(bytes4(_ret), CuratorGuard.ForwardedHookCall.selector, "88 bytes (V2-89)");
        vm.stopPrank();
        _count = _reports(vm.getRecordedLogs());
    }

    /// @dev The round-9 forgery on both Safe builds: a guarded Safe inside a council window with the guard
    ///      planted in its handler slot. No report on any route, the nonce does not move.
    function test_B2_no_forged_report_through_a_v141_or_a_v150_safe_whose_handler_is_the_guard() public {
        vm.prank(council);
        g.bypass(address(curatorSafe), 2 hours);
        _plantHandler(curatorSafe, address(g));
        uint256 _nonce = curatorSafe.nonce();
        assertEq(_forgeAttempt(curatorSafe), 0, "v1.4.1: no report");
        assertEq(curatorSafe.nonce(), _nonce, "v1.4.1: no Safe transaction");

        (ISafe _s150, uint256 _pk150) = _newSafe150("curator-150");
        _installOn(_s150, _pk150);
        vm.prank(council);
        g.bypass(address(_s150), 2 hours);
        _plantHandler(_s150, address(g));
        (bool _yes, ) = probe.probe(address(_s150), address(g));
        assertTrue(_yes, "v1.5.0 answers the probe like v1.4.1");
        _nonce = _s150.nonce();
        assertEq(_forgeAttempt(_s150), 0, "v1.5.0: no report");
        assertEq(_s150.nonce(), _nonce, "v1.5.0: no Safe transaction");
    }

    /// @dev The hand-over acceptance on v1.5.0: a stranger's forwarded acceptance is refused and the late
    ///      cancel stays; the Safe accepts once it drops the handler.
    function test_B3_a_forwarded_acceptance_through_a_v150_pending_safe_is_refused_until_it_drops_the_handler() public {
        (ISafe _dao, uint256 _pk) = _newSafe150("dao-150");
        _setHandler(_dao, _pk, address(g));
        _beginTo(address(_dao), "b3");
        vm.warp(block.timestamp + ADMIN_DELAY + 1);
        vm.startPrank(stranger);
        (bool _ok, bytes memory _ret) = address(_dao).call(_accept());
        _assertRefused(_ok, _ret, "forwarded acceptance, v1.5.0");
        (_ok, _ret) = address(_dao).call(_wrapped(_accept()));
        _assertRefused(_ok, _ret, "forwarded wrapped acceptance, v1.5.0");
        vm.stopPrank();
        assertEq(g.defaultAdmin(), address(tl));
        (address _pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, address(_dao), "still pending");
        _setHandler(_dao, _pk, address(0));
        assertTrue(_exec(_dao, _pk, address(g), 0, _accept(), Operation.Call));
        assertEq(g.defaultAdmin(), address(_dao));
    }

    /// @dev Order inside `_acceptDefaultAdminTransfer`: the rail, then `AdminIsGuarded`, then the 30-day
    ///      deadline, then OpenZeppelin's checks.
    function test_B4_the_acceptance_rail_runs_before_AdminIsGuarded_and_the_30_day_deadline() public {
        (ISafe _dao, uint256 _pk) = _newSafe("dao-order");
        _beginTo(address(_dao), "b4");
        _grantCouncil(address(_dao), "b4-council");
        _setHandler(_dao, _pk, address(g));
        (, uint48 _schedule) = g.pendingDefaultAdmin();
        vm.warp(uint256(_schedule) + 30 days + 1);

        vm.prank(stranger);
        (bool _ok, bytes memory _ret) = address(_dao).call(_accept());
        _assertRefused(_ok, _ret, "1. the rail");
        _setHandler(_dao, _pk, address(0));
        vm.prank(address(_dao));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, address(_dao)));
        g.acceptDefaultAdminTransfer();
        _adminCall(abi.encodeCall(g.revokeRole, (g.COUNCIL_ROLE(), address(_dao))), "b4-revoke");
        vm.prank(address(_dao));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, uint64(_schedule)));
        g.acceptDefaultAdminTransfer();
        assertEq(g.defaultAdmin(), address(tl));
    }

    /*//////////////////////////////////////////////////////////////
                           C. THE PROBE ITSELF
    //////////////////////////////////////////////////////////////*/

    /// @dev What the probe accepts as "a Safe forwarding to this guard": exactly 96 bytes whose THIRD word is
    ///      this guard's address; the head words are not read. An account that answers so refuses itself at
    ///      every role entry, `executeBefore` and the acceptance included, and nothing else.
    function test_C1_the_probe_takes_only_a_one_word_answer_whose_third_word_is_this_guard() public {
        bytes32 _gw = bytes32(uint256(uint160(address(g))));
        G14bAnswer _s1 = new G14bAnswer(bytes32(uint256(0x20)), bytes32(uint256(0x20)), _gw, 96); // the Safe's shape
        G14bAnswer _s2 = new G14bAnswer(bytes32(0), bytes32(0), _gw, 96); // garbage head, same third word
        G14bAnswer _s3 = new G14bAnswer(bytes32(uint256(0x20)), bytes32(uint256(0x14)), bytes32(bytes20(address(g))), 96); // a 20-byte `bytes`
        G14bAnswer _s4 = new G14bAnswer(bytes32(uint256(0x20)), bytes32(uint256(0x40)), _gw, 128); // two words (G10f's)
        G14bAnswer _s5 = new G14bAnswer(bytes32(uint256(0x20)), bytes32(uint256(0x20)), bytes32(uint256(uint160(address(tl)))), 96); // another address
        _grantCouncil(address(_s1), "c1-1");
        _grantCouncil(address(_s2), "c1-2");
        _grantCouncil(address(_s3), "c1-3");
        _grantCouncil(address(_s4), "c1-4");
        _grantCouncil(address(_s5), "c1-5");

        (bool _ok, bytes memory _ret) = _s1.act(address(g), _lock());
        _assertRefused(_ok, _ret, "s1 direct");
        (_ok, _ret) = _s1.act(address(g), _wrapped(_lock()));
        _assertRefused(_ok, _ret, "s1 wrapped");
        (_ok, _ret) = _s2.act(address(g), _wrapped(_lock()));
        _assertRefused(_ok, _ret, "s2: the head words are not read");
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Enforced));

        (_ok, ) = _s3.act(address(g), _wrapped(_lock()));
        assertTrue(_ok, "s3: a left-aligned 20-byte answer is not the Safe's word");
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Lockdown));
        vm.prank(council);
        g.enforce(address(curatorSafe));
        (_ok, ) = _s4.act(address(g), _wrapped(_lock()));
        assertTrue(_ok, "s4: two words are not a one-word answer");
        vm.prank(council);
        g.enforce(address(curatorSafe));
        (_ok, ) = _s5.act(address(g), _wrapped(_lock()));
        assertTrue(_ok, "s5: another address in the slot");
        vm.prank(council);
        g.enforce(address(curatorSafe));

        // The acceptance: a Safe-shaped imposter as the pending admin refuses itself, the admin keeps the cancel.
        G14bAnswer _s6 = new G14bAnswer(bytes32(uint256(0x20)), bytes32(uint256(0x20)), _gw, 96);
        _beginTo(address(_s6), "c1-6");
        vm.warp(block.timestamp + ADMIN_DELAY + 1);
        (_ok, _ret) = _s6.act(address(g), _accept());
        _assertRefused(_ok, _ret, "s6 acceptance");
        (_ok, _ret) = _s6.act(address(g), _wrapped(_accept()));
        _assertRefused(_ok, _ret, "s6 wrapped acceptance");
        assertEq(g.defaultAdmin(), address(tl));
        _adminCall(abi.encodeCall(g.cancelDefaultAdminTransfer, ()), "c1-cancel");
        (address _pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, address(0), "cancelled");
    }

    /// @dev A Safe whose handler is a DIFFERENT CuratorGuard instance (a replacement before adoption): guard A
    ///      serves it (its slot names B, not A), and whatever a stranger sends it lands on B only, where B's own
    ///      rail refuses it. A never sees a forwarded call from that Safe.
    function test_C2_a_safe_whose_handler_is_another_guard_instance_is_served_by_this_one_and_forwards_nothing_to_it() public {
        CuratorGuardHarness _b = _newGuard(address(tl), council);
        (ISafe _c, uint256 _cPk) = _newSafe("council-safe-b");
        _grantCouncil(address(_c), "c2");
        _setHandler(_c, _cPk, address(_b));
        (bool _yes, ) = probe.probe(address(_c), address(g));
        assertFalse(_yes, "A's probe: the slot names B");
        (_yes, ) = probe.probe(address(_c), address(_b));
        assertTrue(_yes, "B's probe: forwarding");

        assertTrue(_exec(_c, _cPk, address(g), 0, _wrapped(_lock()), Operation.Call), "A serves the council Safe");
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Lockdown));

        bytes memory _enf = _wrapped(abi.encodeCall(g.enforce, (address(curatorSafe))));
        vm.expectCall(address(_b), _enf);
        vm.prank(stranger);
        (bool _ok, bytes memory _ret) = address(_c).call(_enf);
        _assertRefused(_ok, _ret, "lands on B, refused by B's rail");
        vm.prank(stranger);
        (_ok, _ret) = address(_c).call(abi.encodeCall(g.enforce, (address(curatorSafe))));
        _assertRefused(_ok, _ret, "lands on B, refused by B's role rail");
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Lockdown), "A untouched");
        assertEq(_b.lockedAt(address(curatorSafe)), 0, "B wrote nothing");
    }

    /// @dev A proxy that relays `getStorageAt` to a Safe whose handler is the guard refuses itself only; one
    ///      relaying to a Safe with an empty slot is an ordinary caller.
    function test_C3_a_proxy_that_relays_getStorageAt_refuses_only_itself() public {
        (ISafe _fwdSafe, uint256 _fwdPk) = _newSafe("safe-with-guard-handler");
        _setHandler(_fwdSafe, _fwdPk, address(g));
        G14bForwarder _p = new G14bForwarder(address(_fwdSafe));
        G14bForwarder _q = new G14bForwarder(address(curatorSafe));
        _grantCouncil(address(_p), "c3-p");
        _grantCouncil(address(_q), "c3-q");
        (bool _yes, ) = probe.probe(address(_p), address(g));
        assertTrue(_yes, "p relays a forwarding answer");
        (bool _ok, bytes memory _ret) = _p.act(address(g), _lock());
        _assertRefused(_ok, _ret, "p direct");
        (_ok, _ret) = _p.act(address(g), _wrapped(_lock()));
        _assertRefused(_ok, _ret, "p wrapped");
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Enforced));
        (_ok, ) = _q.act(address(g), _wrapped(_lock()));
        assertTrue(_ok, "q served");
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Lockdown));
    }

    /// @dev The guard never reads as a forwarding Safe (no `getStorageAt`, no fallback, no `receive`), and the
    ///      only non-static call it makes is the delegatecall to self, which keeps the caller: a wrapped call
    ///      runs as the admin, never as the guard.
    function test_C4_the_guard_itself_is_neither_forwarding_nor_ever_the_caller() public {
        (bool _ok, bytes memory _ret) = address(g).call(
            abi.encodeWithSelector(ISafe.getStorageAt.selector, uint256(FALLBACK_SLOT), uint256(1))
        );
        assertFalse(_ok, "no getStorageAt");
        assertEq(_ret.length, 0, "no fallback");
        (_ok, ) = address(g).call{value: 1}("");
        assertFalse(_ok, "no receive");
        (bool _yes, ) = probe.probe(address(g), address(g));
        assertFalse(_yes, "the guard's own address is not forwarding");
        _adminCall(_wrap(uint64(block.timestamp + MIN_DELAY + 1 days), _lock()), "c4");
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Lockdown), "the admin, through the wrapper");
    }

    /*//////////////////////////////////////////////////////////////
                                 D. GAS
    //////////////////////////////////////////////////////////////*/

    /// @dev Starvation sweep of the forwarded wrapped after-hook (the forged `Bypass` report): no gas limit
    ///      yields a report; below the limit at which the probe answers, everything dies out of gas. The
    ///      numbers: what the forgery would cost, what the probe costs, the boundary.
    function test_D1_gas_starvation_sweep_of_the_forwarded_wrapped_after_hook_never_reports() public {
        vm.prank(council);
        g.bypass(address(curatorSafe), 2 hours);
        _plantHandler(curatorSafe, address(g));

        vm.prank(address(curatorSafe));
        uint256 _g0 = gasleft();
        g.checkAfterExecution(FORGED, true);
        uint256 _hookCost = _g0 - gasleft();
        (bool _yes, uint256 _probeCost) = probe.probe(address(curatorSafe), address(g));
        assertTrue(_yes);

        bytes memory _call = _wrapped(_afterHook(FORGED));
        vm.recordLogs();
        uint256 _minUnauthorized = type(uint256).max;
        uint256 _maxEmpty;
        uint256 _successes;
        uint256 _other;
        vm.startPrank(stranger);
        for (uint256 _gas = 1_000; _gas <= 200_000; _gas += 37) {
            (bool _ok, bytes memory _ret) = address(curatorSafe).call{gas: _gas}(_call);
            if (_ok) ++_successes;
            else if (_ret.length == 0) _maxEmpty = _gas;
            else if (bytes4(_ret) == CuratorGuardPolicy.Unauthorized.selector) {
                if (_gas < _minUnauthorized) _minUnauthorized = _gas;
            } else ++_other;
        }
        vm.stopPrank();
        assertEq(_successes, 0, "no gas limit gets the wrapped after-hook through");
        assertEq(_other, 0, "only Unauthorized or out of gas");
        assertEq(_reports(vm.getRecordedLogs()), 0, "no report at any gas limit");
        assertLt(_maxEmpty, _minUnauthorized, "monotone: starved below, refused above");
        assertGt(_hookCost, _probeCost, "the forgery costs more than the probe");
        console2.log("D1 after-hook in a window, as the Safe (the forgery's cost)", _hookCost);
        console2.log("D1 probe into the real Safe v1.4.1, warm", _probeCost);
        console2.log("D1 lowest gas limit at which the rail answered Unauthorized", _minUnauthorized);
        console2.log("D1 highest gas limit that died empty", _maxEmpty);
    }

    /// @dev Starvation sweep of the forwarded acceptance through a pending-admin Safe whose handler is the
    ///      guard: the admin never moves; refused or starved.
    function test_D2_gas_starvation_sweep_of_the_forwarded_acceptance_never_accepts() public {
        (ISafe _dao, uint256 _pk) = _newSafe("dao-sweep");
        _setHandler(_dao, _pk, address(g));
        _beginTo(address(_dao), "d2");
        vm.warp(block.timestamp + ADMIN_DELAY + 1);
        uint256 _t = block.timestamp;
        uint256 _snap = vm.snapshotState();
        _setHandler(_dao, _pk, address(0));
        vm.prank(address(_dao));
        uint256 _g0 = gasleft();
        g.acceptDefaultAdminTransfer();
        uint256 _acceptCost = _g0 - gasleft();
        vm.revertToState(_snap);
        vm.warp(_t);
        (bool _yes, uint256 _probeCost) = probe.probe(address(_dao), address(g));
        assertTrue(_yes);

        uint256 _minUnauthorized = type(uint256).max;
        uint256 _maxEmpty;
        uint256 _successes;
        uint256 _other;
        vm.startPrank(stranger);
        for (uint256 _gas = 1_000; _gas <= 200_000; _gas += 37) {
            (bool _ok, bytes memory _ret) = address(_dao).call{gas: _gas}(_accept());
            if (_ok) ++_successes;
            else if (_ret.length == 0) _maxEmpty = _gas;
            else if (bytes4(_ret) == CuratorGuardPolicy.Unauthorized.selector) {
                if (_gas < _minUnauthorized) _minUnauthorized = _gas;
            } else ++_other;
            assertEq(g.defaultAdmin(), address(tl), "admin never moves");
        }
        vm.stopPrank();
        assertEq(_successes, 0);
        assertEq(_other, 0, "only Unauthorized or out of gas");
        assertLt(_maxEmpty, _minUnauthorized);
        assertGt(_acceptCost, _probeCost);
        console2.log("D2 genuine acceptance by the Safe (the hand-over's cost)", _acceptCost);
        console2.log("D2 probe into the pending Safe v1.4.1, warm", _probeCost);
        console2.log("D2 lowest gas limit at which the rail answered Unauthorized", _minUnauthorized);
        console2.log("D2 highest gas limit that died empty", _maxEmpty);
    }

    /// @dev The probe's cost against the timelock (what every wrapped admin call now pays) and a 40-call
    ///      wrapped batch against the same batch of bare calls, both executed through the open executor.
    function test_D3_the_probe_costs_little_per_wrapped_call_against_the_timelock() public {
        tl.getMinDelay(); // warm the timelock, as it is inside an operation it executes
        (bool _yes, uint256 _probeCost) = probe.probe(address(tl), address(g));
        assertFalse(_yes);

        MockProtocol _t2 = new MockProtocol();
        bytes[] memory _wrappedCalls = new bytes[](40);
        bytes[] memory _bareCalls = new bytes[](40);
        for (uint256 i; i < 40; ++i) {
            address _t = i % 2 == 0 ? address(protocol) : address(_t2);
            bytes memory _c = abi.encodeCall(
                g.allowFunction,
                (address(curatorSafe), _t, bytes4(uint32(0x10000000 + uint32(i))), false, _noRules())
            );
            _bareCalls[i] = _c;
            _wrappedCalls[i] = _wrap(uint64(block.timestamp + MIN_DELAY + 10 days), _c);
        }
        address[] memory _targets = _guardTargets(40);
        uint256[] memory _values = new uint256[](40);
        uint256 _t0 = block.timestamp;
        uint256 _snap = vm.snapshotState();

        _scheduleBatch(p1, p1Pk, _targets, _wrappedCalls, NONE, "d3-w");
        vm.warp(block.timestamp + MIN_DELAY);
        vm.prank(stranger);
        uint256 _g0 = gasleft();
        tl.executeBatch(_targets, _values, _wrappedCalls, NONE, "d3-w");
        uint256 _wrappedGas = _g0 - gasleft();
        (bool _allowed, , ) = g.functionPermission(address(curatorSafe), address(_t2), bytes4(uint32(0x10000000 + 39)));
        assertTrue(_allowed, "all 40 landed");

        vm.revertToState(_snap);
        vm.warp(_t0);
        _scheduleBatch(p1, p1Pk, _targets, _bareCalls, NONE, "d3-b");
        vm.warp(block.timestamp + MIN_DELAY);
        vm.prank(stranger);
        _g0 = gasleft();
        tl.executeBatch(_targets, _values, _bareCalls, NONE, "d3-b");
        uint256 _bareGas = _g0 - gasleft();

        console2.log("D3 probe against the timelock, warm", _probeCost);
        console2.log("D3 executeBatch of 40 wrapped allowFunction calls", _wrappedGas);
        console2.log("D3 executeBatch of the same 40 bare calls", _bareGas);
        console2.log("D3 wrapper overhead per call (ABI + delegatecall + probe)", (_wrappedGas - _bareGas) / 40);
        console2.log("D3 the probe's share of the batch (40 x probe)", 40 * _probeCost);
        assertLt(40 * _probeCost, _wrappedGas / 50, "the probe is under 2 % of the batch");
    }
}
