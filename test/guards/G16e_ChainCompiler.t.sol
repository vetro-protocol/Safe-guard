// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";
import {console2} from "forge-std/console2.sol";
import {MultiSendCallOnly} from "safe-contracts-v1.4.1/contracts/libraries/MultiSendCallOnly.sol";

import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G9cBase} from "test/guards/G9c_Base.sol";

/// @dev `CuratorGuardPolicy._isHandlerOf`, verbatim, parameterised, so the probe's verdict and cost can be
///      measured from a caller's frame (g14b's `G14bProbe`).
contract G16eProbe {
    function probe(address account_, address guard_) external view returns (bool _yes, uint256 _gas) {
        bytes32 _slot = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
        uint256 _g0 = gasleft();
        assembly ("memory-safe") {
            let _p := mload(0x40)
            mstore(_p, 0x5624b25b00000000000000000000000000000000000000000000000000000000)
            mstore(add(_p, 0x04), _slot)
            mstore(add(_p, 0x24), 1)
            let _ok := staticcall(gas(), account_, _p, 0x44, _p, 0x60)
            _yes := and(and(_ok, eq(returndatasize(), 0x60)), eq(and(mload(add(_p, 0x40)), 0xffffffffffffffffffffffffffffffffffffffff), guard_))
        }
        _gas = _g0 - gasleft();
    }
}

/// @dev A Safe-shaped account whose handler is the guard (it forwards every unknown selector to it with the
///      caller's 20 bytes appended, exactly as `FallbackManager` does) and whose `getStorageAt` answers like a
///      Safe v1.4.1 (96 bytes, the guard in the third word) AFTER burning `burn` gas: a probe whose internal
///      cost is `burn` gas dearer than today's, i.e. a repricing of what the probe executes (SLOAD, the proxy's
///      DELEGATECALL, the dispatcher) by any amount. If the gas forwarded to it is below `burn` it runs out of
///      gas, as a repriced real Safe would.
contract G16eBurningForwarder {
    address internal immutable handler;
    uint256 public burn;

    constructor(address handler_) {
        handler = handler_;
    }

    function setBurn(uint256 burn_) external {
        burn = burn_;
    }

    function getStorageAt(uint256, uint256) external view returns (bytes memory) {
        uint256 _b = burn;
        uint256 _g = gasleft();
        if (_g <= _b) {
            while (true) {}
        }
        uint256 _stop;
        unchecked {
            _stop = _g - _b;
        }
        while (gasleft() > _stop) {}
        address _h = handler;
        assembly {
            mstore(0, 0x20)
            mstore(0x20, 0x20)
            mstore(0x40, _h)
            return(0, 0x60)
        }
    }

    fallback() external {
        address _h = handler;
        assembly {
            calldatacopy(0, 0, calldatasize())
            mstore(calldatasize(), shl(96, caller()))
            let _ok := call(gas(), _h, 0, 0, add(calldatasize(), 20), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(_ok) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
    }
}

/// @dev Code a stranger runs in a Safe's context through `simulateAndRevert`: it calls the guard with the Safe
///      as `msg.sender` and bubbles the result, so the simulation's revert data carries the inner verdict.
contract G16eDriver {
    function run(address guard_, bytes calldata call_) external returns (bytes memory _ret) {
        bool _ok;
        (_ok, _ret) = guard_.call(call_);
        if (!_ok) {
            assembly {
                revert(add(_ret, 0x20), mload(_ret))
            }
        }
    }
}

/// @title Round 16 (g16e): the chain and the compiler for the new bytecode. The two rails under cold state and
///        under a repriced probe (the 1/64 rule made explicit), EIP-7825 against the largest wrapped batch,
///        `simulateAndRevert` and nested frames at the two new entries, the open executor's gas.
/// @dev   g9c's production topology (real Safe v1.4.1 proxies, a real `CuratorGuardTimelock` at 2 days, an EOA
///        council). Run under `--evm-version cancun`, `prague` and `osaka`: the bytecode is the same build.
contract G16e_ChainCompilerTest is G9cBase {
    bytes32 internal constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    bytes32 internal constant FORGED = keccak256("g16e: no Safe transaction ever carried this hash");
    bytes32 internal constant REPORT_SIG = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");
    bytes4 internal constant SET_FALLBACK_HANDLER = 0xf08a0323;
    uint256 internal constant TX_GAS_CAP = 16_777_216; // EIP-7825
    uint256 internal constant TASK_GATE = 12_000_000; // tasks/curator-guard.ts BATCH_GAS_REFUSE

    MultiSendCallOnly internal msc;
    MockProtocol[8] internal venues;
    G16eProbe internal probe;

    function setUp() public override {
        super.setUp();
        _configureCurator();
        msc = new MultiSendCallOnly();
        for (uint256 i; i < 8; ++i) venues[i] = new MockProtocol();
        probe = new G16eProbe();
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _handlerOf(address safe_) internal view returns (address) {
        return address(uint160(uint256(bytes32(ISafe(safe_).getStorageAt(uint256(FALLBACK_SLOT), 1)))));
    }

    function _setHandler(ISafe safe_, uint256 pk_, address handler_) internal {
        assertTrue(
            _exec(safe_, pk_, address(safe_), 0, abi.encodeWithSelector(SET_FALLBACK_HANDLER, handler_), Operation.Call),
            "setFallbackHandler"
        );
        assertEq(_handlerOf(address(safe_)), handler_, "handler slot");
    }

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

    function _entry(address to_, bytes memory data_) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to_, uint256(0), data_.length, data_);
    }

    function _assertRefused(bool ok_, bytes memory ret_, string memory why_) internal pure {
        assertFalse(ok_, why_);
        assertEq(bytes4(ret_), CuratorGuardPolicy.Unauthorized.selector, why_);
    }

    /// @dev The chain's state for a fresh transaction: the Safe, its singleton, the guard and the timelock cold.
    function _coolAll(address safe_) internal {
        vm.cool(safe_);
        vm.cool(address(singleton));
        vm.cool(address(g));
        vm.cool(address(tl));
    }

    /// @dev `simulateAndRevert`'s revert data: (success, returndatasize, returndata).
    function _simVerdict(bytes memory ret_) internal pure returns (bool _inner) {
        uint256 _s;
        assembly {
            _s := mload(add(ret_, 0x20))
        }
        _inner = _s == 1;
    }

    /*//////////////////////////////////////////////////////////////
          T1 / T2: THE TWO RAILS UNDER COLD STATE (THE CHAIN'S FIRST TOUCH)
    //////////////////////////////////////////////////////////////*/

    /// @dev g14b's D1 from COLD state: every account and slot the forwarded call touches is cold at every gas
    ///      limit (`vm.cool`), as on a chain where the stranger's transaction is the first to touch them. The
    ///      forged `Bypass` report never lands; the only change against the warm sweep is where "out of gas"
    ///      ends and "refused" begins.
    function test_T1_cold_state_sweep_of_the_forwarded_wrapped_after_hook_never_reports() public {
        vm.prank(council);
        g.bypass(address(curatorSafe), 2 hours);
        _plantHandler(curatorSafe, address(g));
        _coolAll(address(curatorSafe));
        (bool _yes, uint256 _probeCold) = probe.probe(address(curatorSafe), address(g));
        assertTrue(_yes, "forwarding");
        (, uint256 _probeWarm) = probe.probe(address(curatorSafe), address(g));

        bytes memory _call = _wrapped(_afterHook(FORGED));
        vm.recordLogs();
        uint256 _minUnauthorized = type(uint256).max;
        uint256 _maxEmpty;
        uint256 _successes;
        uint256 _other;
        for (uint256 _gas = 1_000; _gas <= 200_000; _gas += 37) {
            _coolAll(address(curatorSafe));
            vm.prank(stranger);
            (bool _ok, bytes memory _ret) = address(curatorSafe).call{gas: _gas}(_call);
            if (_ok) ++_successes;
            else if (_ret.length == 0) _maxEmpty = _gas;
            else if (bytes4(_ret) == CuratorGuardPolicy.Unauthorized.selector) {
                if (_gas < _minUnauthorized) _minUnauthorized = _gas;
            } else ++_other;
        }
        console2.log("T1 probe into the real Safe v1.4.1, COLD (account, singleton, slot)", _probeCold);
        console2.log("T1 probe into the real Safe v1.4.1, warm", _probeWarm);
        console2.log("T1 cold: lowest gas limit at which the rail answered Unauthorized", _minUnauthorized);
        console2.log("T1 cold: highest gas limit that died empty", _maxEmpty);
        assertEq(_successes, 0, "no gas limit gets the forwarded wrapped after-hook through from cold state");
        assertEq(_other, 0, "only Unauthorized or out of gas");
        assertEq(_reports(vm.getRecordedLogs()), 0, "no report at any gas limit");
        assertLt(_maxEmpty, _minUnauthorized, "monotone: starved below, refused above");
    }

    /// @dev g14b's D2 from cold state: the forwarded acceptance through a pending-admin Safe whose handler is
    ///      the guard; the admin never moves at any gas limit.
    function test_T2_cold_state_sweep_of_the_forwarded_acceptance_never_accepts() public {
        (ISafe _dao, uint256 _pk) = _newSafe("dao-cold-sweep");
        _setHandler(_dao, _pk, address(g));
        _beginTo(address(_dao), "t2");
        vm.warp(block.timestamp + ADMIN_DELAY + 1);
        uint256 _minUnauthorized = type(uint256).max;
        uint256 _maxEmpty;
        uint256 _successes;
        uint256 _other;
        for (uint256 _gas = 1_000; _gas <= 200_000; _gas += 37) {
            _coolAll(address(_dao));
            vm.prank(stranger);
            (bool _ok, bytes memory _ret) = address(_dao).call{gas: _gas}(_accept());
            if (_ok) ++_successes;
            else if (_ret.length == 0) _maxEmpty = _gas;
            else if (bytes4(_ret) == CuratorGuardPolicy.Unauthorized.selector) {
                if (_gas < _minUnauthorized) _minUnauthorized = _gas;
            } else ++_other;
        }
        assertEq(_successes, 0, "never accepted");
        assertEq(_other, 0, "only Unauthorized or out of gas");
        assertEq(g.defaultAdmin(), address(tl), "admin never moved");
        assertLt(_maxEmpty, _minUnauthorized, "monotone");
        console2.log("T2 cold: lowest gas limit at which the rail answered Unauthorized", _minUnauthorized);
        console2.log("T2 cold: highest gas limit that died empty", _maxEmpty);
        // the genuine acceptance still lands once the handler is dropped (nothing was consumed by the sweep)
        _setHandler(_dao, _pk, address(0));
        assertTrue(_exec(_dao, _pk, address(g), 0, _accept(), Operation.Call), "accepted as itself");
        assertEq(g.defaultAdmin(), address(_dao));
    }

    /*//////////////////////////////////////////////////////////////
             T3: THE 1/64 RULE MADE EXPLICIT: A REPRICED PROBE
    //////////////////////////////////////////////////////////////*/

    bool internal coldSweep;

    function _sweepBurner(G16eBurningForwarder b_, uint256 lo_, uint256 hi_, uint256 step_, bytes memory call_)
        internal
        returns (uint256 _successes, uint256 _first, uint256 _last)
    {
        for (uint256 _gas = lo_; _gas <= hi_; _gas += step_) {
            if (coldSweep) {
                vm.cool(address(b_));
                vm.cool(address(g));
                vm.cool(address(tl));
            }
            vm.prank(stranger);
            (bool _ok, ) = address(b_).call{gas: _gas}(call_);
            if (_ok) {
                if (_successes == 0) _first = _gas;
                _last = _gas;
                ++_successes;
            }
        }
    }

    // sweep parameters and results of `_runBurn` (storage keeps the function shallow on the legacy pipeline)
    uint256 internal edgeLo;
    uint256 internal edgeHi;
    uint256 internal edgeStep;
    uint256 internal rN;
    uint256 internal rFirst;
    uint256 internal rLast;

    function _merge(uint256 n_, uint256 f_, uint256 l_) internal {
        if (n_ == 0) return;
        rN += n_;
        if (f_ < rFirst) rFirst = f_;
        if (l_ > rLast) rLast = l_;
    }

    /// @dev One probe cost. The probe stops running out of gas once the stranger's limit passes about
    ///      64 burn / 63 (its budget); the hook needs a fixed remainder of limit (the window's lower edge L).
    ///      Sweeps: coarse (step 1,009) under min(budget, 250k), where nothing may forge; fine (step 97) around
    ///      the budget's edge while it lies under `edgeHi`; fine (step `edgeStep`) over [`edgeLo`, `edgeHi`]
    ///      once the budget reaches it (the lower edge); a dozen points around a budget above `edgeHi` (the
    ///      upper edge). Results in `rN`, `rFirst`, `rLast`.
    function _runBurn(G16eBurningForwarder b_, uint256 burn_, bytes memory call_) internal {
        b_.setBurn(burn_);
        (rN, rFirst, rLast) = (0, type(uint256).max, 0);
        uint256 _budget = (64 * burn_) / 63;
        (uint256 _below, , ) = _sweepBurner(b_, 1_000, _budget + 3_000 < 250_000 ? _budget + 3_000 : 250_000, 1_009, call_);
        assertEq(_below, 0, "nothing under min(budget, 250k) ever forges");
        if (_budget + 6_000 < edgeHi) {
            (uint256 _n, uint256 _f, uint256 _l) = _sweepBurner(b_, _budget > 7_000 ? _budget - 6_000 : 1_000, _budget + 6_000, 97, call_);
            _merge(_n, _f, _l);
        }
        if (_budget + 6_000 >= edgeLo) {
            (uint256 _n, uint256 _f, uint256 _l) = _sweepBurner(b_, edgeLo, edgeHi, edgeStep, call_);
            _merge(_n, _f, _l);
        }
        if (_budget > edgeHi + 10_000) {
            (uint256 _n, uint256 _f, uint256 _l) = _sweepBurner(b_, _budget - 6_000, _budget + 6_000, 1_009, call_);
            _merge(_n, _f, _l);
        }
        if (rN == 0) rFirst = 0;
        console2.log("T3 burn (extra probe cost)", burn_);
        console2.log("T3   forged reports over the sweeps", rN);
        if (rN != 0) {
            console2.log("T3   window of gas limits: lowest success", rFirst);
            console2.log("T3   window of gas limits: highest success seen", rLast);
        }
    }

    function _newBurner() internal returns (G16eBurningForwarder _b) {
        _b = new G16eBurningForwarder(address(g));
        vm.prank(council);
        g.bypass(address(_b), 2 hours);
    }

    /// @dev Why no repricing within reach opens the rail. In the guard's frame with G gas the probe receives
    ///      63G/64 and, if it runs out, burns all of it; the wrapped hook then gets at most about G/65. A
    ///      forged report needs that remainder to cover the hook's inner cost H while the probe's INTERNAL
    ///      cost P exceeds 63G/64: a window of gas limits exists only if P > ~64 H. Emulated with a
    ///      Safe-shaped forwarder whose `getStorageAt` costs `burn` gas more than a real Safe's. WARM regime
    ///      (the hook's reads already touched in the transaction, the cheapest hook): no gas limit forges a
    ///      report while the probe costs under about 300k gas; from there a window appears whose lower edge
    ///      (about 309k of limit) is fixed by the hook and whose upper edge grows with the probe's cost.
    function test_T3a_warm_the_rail_fails_open_only_if_the_probe_costs_64_times_the_hook() public {
        G16eBurningForwarder _b = _newBurner();
        vm.prank(address(_b));
        g.checkAfterExecution(FORGED, true); // warms the hook's path (the Safe-as-itself report, G10a-1)
        probe.probe(address(curatorSafe), address(g)); // warms the Safe, its singleton and the slot
        (, uint256 _probeWarm) = probe.probe(address(curatorSafe), address(g));
        bytes memory _call = _wrapped(_afterHook(FORGED));
        uint256[7] memory _burns = [uint256(0), 100_000, 200_000, 250_000, 300_000, 450_000, 600_000];
        uint256 _firstBurnWithWindow;
        uint256 _edgeMin = type(uint256).max;
        uint256 _edgeMax;
        vm.recordLogs();
        uint256 _total;
        (edgeLo, edgeHi, edgeStep) = (295_000, 320_000, 97);
        for (uint256 i; i < 7; ++i) {
            _runBurn(_b, _burns[i], _call);
            _total += rN;
            if (rN != 0) {
                if (_firstBurnWithWindow == 0) _firstBurnWithWindow = _burns[i];
                if (rFirst < _edgeMin) _edgeMin = rFirst;
                if (rFirst > _edgeMax) _edgeMax = rFirst;
            }
        }
        // forge's `getRecordedLogs` keeps logs emitted inside frames that later ran out of gas (the harness
        // artefact G13c noted): a report emitted by the inner frame of a call that then starved in the outer
        // frames never reaches a receipt on a chain. The successes are the forgeries; the recorded count is
        // at least that (plus the warming report).
        assertGe(_reports(vm.getRecordedLogs()), _total + 1, "every success is one forged report");
        console2.log("T3a the probe into a real Safe today, warm", _probeWarm);
        console2.log("T3a first burn at which a window appeared", _firstBurnWithWindow);
        console2.log("T3a the window's lower edge across burns (min, max)", _edgeMin, _edgeMax);
        assertEq(_firstBurnWithWindow, 300_000, "no window under 250k extra; a window at 300k");
        assertLe(_edgeMax - _edgeMin, 200, "the lower edge does not move with the probe's cost");
        assertGt(_edgeMin, 300_000, "the hook needs about 309k of limit after a failed probe");
        assertGt(_firstBurnWithWindow, 150 * _probeWarm, "two orders of magnitude above today's warm probe");
    }

    /// @dev The same from COLD state (every account and slot cold at every call, as for the first touch of a
    ///      transaction): the hook's cold reads raise its inner cost, so the lower edge sits higher (about
    ///      560k of limit) and the probe must cost more than about 550k before any window exists.
    function test_T3b_cold_the_threshold_is_higher_still() public {
        G16eBurningForwarder _b = _newBurner();
        _coolAll(address(curatorSafe));
        (, uint256 _probeCold) = probe.probe(address(curatorSafe), address(g));
        bytes memory _call = _wrapped(_afterHook(FORGED));
        coldSweep = true;
        uint256[3] memory _burns = [uint256(450_000), 600_000, 900_000];
        uint256 _firstBurnWithWindow;
        uint256 _edgeMin = type(uint256).max;
        uint256 _edgeMax;
        vm.recordLogs();
        uint256 _total;
        (edgeLo, edgeHi, edgeStep) = (480_000, 640_000, 397);
        for (uint256 i; i < 3; ++i) {
            _runBurn(_b, _burns[i], _call);
            _total += rN;
            if (rN != 0) {
                if (_firstBurnWithWindow == 0) _firstBurnWithWindow = _burns[i];
                if (rFirst < _edgeMin) _edgeMin = rFirst;
                if (rFirst > _edgeMax) _edgeMax = rFirst;
            }
        }
        coldSweep = false;
        assertGe(_reports(vm.getRecordedLogs()), _total, "every success is one forged report (reverted-frame logs are a harness artefact)");
        console2.log("T3b the probe into a real Safe today, cold", _probeCold);
        console2.log("T3b first burn at which a window appeared", _firstBurnWithWindow);
        console2.log("T3b the window's lower edge across burns (min, max)", _edgeMin, _edgeMax);
        assertEq(_firstBurnWithWindow, 600_000, "no window at 450k extra; a window at 600k");
        assertLe(_edgeMax - _edgeMin, 800, "the lower edge does not move with the probe's cost");
        assertGt(_edgeMin, 500_000, "the cold hook needs over 500k of limit after a failed probe");
        assertGt(_firstBurnWithWindow, 50 * _probeCold, "far above today's cold probe");
    }

    /*//////////////////////////////////////////////////////////////
               T4: EIP-7825 AGAINST THE LARGEST WRAPPED BATCH
    //////////////////////////////////////////////////////////////*/

    function _band() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _r) {
        _r = new CuratorGuardPolicy.ParamRule[](2);
        _r[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.GreaterThanOrEqual, 0, bytes32(uint256(950)));
        _r[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 0, bytes32(uint256(1050)));
    }

    function _batch(uint256 n_, bool wrapped_, bool rules_) internal view returns (address[] memory _t, bytes[] memory _p) {
        _t = _guardTargets(n_);
        _p = new bytes[](n_);
        CuratorGuardPolicy.ParamRule[] memory _r = rules_ ? _band() : _noRules();
        uint64 _deadline = uint64(block.timestamp + MIN_DELAY + 10 days);
        for (uint256 i; i < n_; ++i) {
            address _target = address(venues[i % 8]); // at most 32 selectors per target: 15 each at 120 calls
            bytes memory _c = abi.encodeCall(
                g.allowFunction,
                (address(curatorSafe), _target, bytes4(uint32(0x20000000 + uint32(i))), false, _r)
            );
            _p[i] = wrapped_ ? _wrap(_deadline, _c) : _c;
        }
    }

    function _countBytes(bytes memory cd_) internal pure returns (uint256 _nz, uint256 _z) {
        for (uint256 i; i < cd_.length; ++i) if (cd_[i] != 0) ++_nz;
        _z = cd_.length - _nz;
    }

    /// @dev Schedules `(t_, p_)` from the proposer Safe, lands it through the open executor measuring the gas
    ///      of `executeBatch`, counts the calldata, then rewinds (the numbers travel on the stack: a state
    ///      snapshot revert would roll back the test's own storage too).
    function _land(address[] memory t_, bytes[] memory p_, bytes32 salt_) internal returns (uint256 _gas, uint256 _nz, uint256 _z) {
        uint256 _snap = vm.snapshotState();
        uint256 _t0 = block.timestamp;
        _scheduleBatch(p1, p1Pk, t_, p_, NONE, salt_);
        vm.warp(block.timestamp + MIN_DELAY);
        bytes memory _cd = abi.encodeCall(tl.executeBatch, (t_, new uint256[](t_.length), p_, NONE, salt_));
        (_nz, _z) = _countBytes(_cd);
        vm.prank(stranger);
        uint256 _g0 = gasleft();
        (bool _ok, ) = address(tl).call(_cd);
        _gas = _g0 - gasleft();
        assertTrue(_ok, "batch landed");
        vm.revertToState(_snap);
        vm.warp(_t0);
    }

    struct Meas {
        uint256 gas;
        uint256 nz;
        uint256 z;
    }
    /// @dev [wrapped ? 1 : 0][0 = 40 calls, 1 = 120 calls]
    Meas[2][2] internal m;

    function _measureInto(uint256 w_, uint256 k_, uint256 n_, bool rules_) internal {
        (address[] memory _t, bytes[] memory _p) = _batch(n_, w_ == 1, rules_);
        (uint256 _gas, uint256 _nz, uint256 _z) = _land(_t, _p, keccak256(abi.encode(n_, w_, rules_)));
        m[w_][k_] = Meas(_gas, _nz, _z);
    }

    /// @dev Linear model from the two sizes: the marginal gas per call, the largest N whose whole transaction
    ///      (execution + 21,000 + calldata at 16 / 4 per byte) fits under the EIP-7825 cap, and the first N the
    ///      task's 12 M gate refuses (the gate reads the node's estimate, i.e. the whole transaction).
    function _fit(uint256 w_) internal view returns (uint256 _marginal, uint256 _nCap, uint256 _nGate) {
        Meas storage _a = m[w_][0];
        Meas storage _b = m[w_][1];
        _marginal = (_b.gas - _a.gas) / 80;
        uint256 _cdPer = (16 * (_b.nz - _a.nz) + 4 * (_b.z - _a.z)) / 80;
        uint256 _base = 21_000 + 16 * _a.nz + 4 * _a.z + _a.gas;
        _nCap = 40 + (TX_GAS_CAP - _base) / (_marginal + _cdPer);
        _nGate = 40 + (TASK_GATE - _base) / (_marginal + _cdPer) + 1;
    }

    function _reportShape(bool rules_, uint256 probeTl_) internal {
        _measureInto(1, 0, 40, rules_);
        _measureInto(1, 1, 120, rules_);
        _measureInto(0, 0, 40, rules_);
        _measureInto(0, 1, 120, rules_);
        (uint256 _mw, uint256 _capW, uint256 _gateW) = _fit(1);
        (uint256 _mb, uint256 _capB, uint256 _gateB) = _fit(0);
        console2.log(rules_ ? "T4 shape: allowFunction with a 2-rule band" : "T4 shape: allowFunction with no rules");
        console2.log("T4   wrapped: executeBatch gas at 40 / 120 calls", m[1][0].gas, m[1][1].gas);
        console2.log("T4   bare:    executeBatch gas at 40 / 120 calls", m[0][0].gas, m[0][1].gas);
        console2.log("T4   marginal gas per call, wrapped / bare", _mw, _mb);
        console2.log("T4   calldata bytes per wrapped call (nonzero, zero)", (m[1][1].nz - m[1][0].nz) / 80, (m[1][1].z - m[1][0].z) / 80);
        console2.log("T4   largest N under the 16,777,216 cap, wrapped / bare", _capW, _capB);
        console2.log("T4   first N the 12 M gate refuses, wrapped / bare", _gateW, _gateB);
        console2.log("T4   the probe's share at the cap (N x probe against the timelock)", _capW * probeTl_);
        assertGt(_capW, _gateW, "the gate trips well before the cap");
        assertLe(_capB - _capW, 12, "the whole wrapper (ABI, delegatecall, probe, calldata) costs about ten calls of headroom");
        assertLe((_capW * probeTl_) / (_mw + 1), 3, "the probe alone about two calls");
        assertLt(_capW * probeTl_ * 50, TX_GAS_CAP, "the probe is under 2 % of a batch at the cap");
    }

    /// @dev The largest wrapped `executeBatch` of `allowFunction` calls under the EIP-7825 cap, with and without
    ///      the probe (wrapped against bare), for a rule-less entry and a two-rule band entry; the probe's share
    ///      at the cap; where the task's 12 M gate sits against the cap.
    function test_T4_eip7825_headroom_of_the_largest_wrapped_batch() public {
        tl.getMinDelay();
        (, uint256 _probeTl) = probe.probe(address(tl), address(g));
        _reportShape(false, _probeTl);
        _reportShape(true, _probeTl);
        console2.log("T4 probe against the timelock, warm", _probeTl);
    }

    /*//////////////////////////////////////////////////////////////
                 T5: simulateAndRevert AT THE TWO NEW ENTRIES
    //////////////////////////////////////////////////////////////*/

    /// @dev A stranger drives a council Safe's and a pending-admin Safe's `simulateAndRevert` (a public function
    ///      of every Safe, a delegatecall from the Safe's context) into the two entries with the SAFE as
    ///      `msg.sender`: inside the frame the rail passes and the wrapped call succeeds (an oracle anyone has
    ///      through `eth_call` anyway), outside it nothing persists: no window, no admin move, no nonce, no
    ///      transient residue; the genuine acceptance after it still lands.
    function test_T5_simulateAndRevert_at_the_two_entries_persists_nothing() public {
        G16eDriver _d = new G16eDriver();
        (ISafe _c, ) = _newSafe("council-sim");
        _grantCouncil(address(_c), "t5-council");
        bytes memory _open = _wrapped(abi.encodeCall(g.bypass, (address(curatorSafe), uint64(2 hours))));
        bytes memory _sim = abi.encodeWithSignature(
            "simulateAndRevert(address,bytes)",
            address(_d),
            abi.encodeCall(G16eDriver.run, (address(g), _open))
        );
        uint256 _nonce = _c.nonce();
        vm.prank(stranger);
        (bool _ok, bytes memory _ret) = address(_c).call(_sim);
        assertFalse(_ok, "simulateAndRevert always reverts");
        assertTrue(_simVerdict(_ret), "inside the frame the council Safe's wrapped bypass succeeded");
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Enforced), "no window persisted");
        (uint64 _until, ) = g.bypassWindow(address(curatorSafe));
        assertEq(_until, 0, "no window");
        assertEq(_c.nonce(), _nonce, "no Safe transaction");
        assertTrue(_settle(), "the curator's policy transaction after it is clean (no transient residue)");

        (ISafe _dao, uint256 _pk) = _newSafe("dao-sim");
        _beginTo(address(_dao), "t5-dao");
        vm.warp(block.timestamp + ADMIN_DELAY + 1);
        _sim = abi.encodeWithSignature(
            "simulateAndRevert(address,bytes)",
            address(_d),
            abi.encodeCall(G16eDriver.run, (address(g), _accept()))
        );
        vm.prank(stranger);
        (_ok, _ret) = address(_dao).call(_sim);
        assertFalse(_ok);
        assertTrue(_simVerdict(_ret), "inside the frame the pending Safe's acceptance succeeded");
        assertEq(g.defaultAdmin(), address(tl), "the admin did not move");
        (address _pending, ) = g.pendingDefaultAdmin();
        assertEq(_pending, address(_dao), "still pending");
        _sim = abi.encodeWithSignature(
            "simulateAndRevert(address,bytes)",
            address(_d),
            abi.encodeCall(G16eDriver.run, (address(g), _wrapped(_accept())))
        );
        vm.prank(stranger);
        (_ok, _ret) = address(_dao).call(_sim);
        assertFalse(_ok);
        assertTrue(_simVerdict(_ret), "wrapped: the same");
        assertEq(g.defaultAdmin(), address(tl));
        assertTrue(_exec(_dao, _pk, address(g), 0, _accept(), Operation.Call), "the genuine acceptance lands");
        assertEq(g.defaultAdmin(), address(_dao));

        // the guarded Safe's own simulateAndRevert gives a stranger nothing: it holds no role
        _sim = abi.encodeWithSignature(
            "simulateAndRevert(address,bytes)",
            address(_d),
            abi.encodeCall(G16eDriver.run, (address(g), _wrapped(_lock())))
        );
        vm.prank(stranger);
        (_ok, _ret) = address(curatorSafe).call(_sim);
        assertFalse(_ok);
        assertFalse(_simVerdict(_ret), "the curator Safe holds no role: Unauthorized inside the frame");
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Enforced));
    }

    /*//////////////////////////////////////////////////////////////
                    T6: NESTED FRAMES AT THE TWO NEW ENTRIES
    //////////////////////////////////////////////////////////////*/

    /// @dev (a) an EOA pending admin accepts through three nested `executeBefore` frames; (b) a pending-admin
    ///      Safe accepts through a `MultiSendCallOnly` batch whose entry is the wrapped acceptance (the Safe is the
    ///      caller of the entry); (c) through the timelock, an inner `executeBefore` whose deadline passed
    ///      reverts with ITS deadline and the operation stays Ready; (d) the wrapper returns the inner call's
    ///      return data (the council's wrapped approval returns the approval id).
    function test_T6_nested_frames_at_the_two_new_entries() public {
        address _eoa = makeAddr("eoa-admin");
        _beginTo(_eoa, "t6-eoa");
        vm.warp(block.timestamp + ADMIN_DELAY + 1);
        uint64 _d = uint64(block.timestamp + 1 hours);
        vm.prank(_eoa);
        g.executeBefore(_d, _wrap(_d, _wrap(_d, _accept())));
        assertEq(g.defaultAdmin(), _eoa, "accepted through three nested frames");

        // the EOA hands over to a Safe, which accepts through a MultiSendCallOnly batch
        (ISafe _dao, uint256 _pk) = _newSafe("dao-nested");
        vm.prank(_eoa);
        g.beginDefaultAdminTransfer(address(_dao));
        vm.warp(block.timestamp + ADMIN_DELAY + 1);
        bytes memory _ms = abi.encodeCall(MultiSendCallOnly.multiSend, (_entry(address(g), _wrapped(_accept()))));
        assertTrue(_exec(_dao, _pk, address(msc), 0, _ms, Operation.DelegateCall), "batch executed");
        assertEq(g.defaultAdmin(), address(_dao), "accepted through the batch");

        // (c) back to the timelock; an inner deadline in the past bubbles verbatim through the open executor
        vm.prank(address(_dao));
        g.beginDefaultAdminTransfer(address(tl));
        vm.warp(block.timestamp + ADMIN_DELAY + 1);
        vm.prank(address(tl));
        g.acceptDefaultAdminTransfer();
        assertEq(g.defaultAdmin(), address(tl));
        uint64 _past = uint64(block.timestamp + MIN_DELAY - 1);
        bytes memory _op = _wrap(uint64(block.timestamp + MIN_DELAY + 1 days), _wrap(_past, _lock()));
        bytes32 _id = _schedule(p1, p1Pk, address(g), _op, NONE, "t6-c");
        vm.warp(block.timestamp + MIN_DELAY);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, _past));
        tl.execute(address(g), 0, _op, NONE, "t6-c");
        assertTrue(tl.isOperationReady(_id), "still Ready, never Done");
        assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Enforced));

        // (d) return data
        bytes memory _venue = abi.encodeCall(MockProtocol.settleDeposit, (5));
        bytes memory _approve = abi.encodeCall(
            g.approveTransaction,
            (address(curatorSafe), address(0), address(protocol), 0, _venue, Operation.Call, uint64(1 hours))
        );
        vm.prank(council);
        bytes memory _ret = g.executeBefore(uint64(block.timestamp + 1 hours), _approve);
        assertEq(
            abi.decode(_ret, (bytes32)),
            g.computeApprovalId(address(curatorSafe), address(0), address(protocol), 0, _venue, Operation.Call),
            "the wrapper returns the inner return data"
        );
    }

    /*//////////////////////////////////////////////////////////////
               T7: THE OPEN EXECUTOR'S GAS AT A WRAPPED ENTRY
    //////////////////////////////////////////////////////////////*/

    function _sweepExecute(bytes memory op_, bytes32 salt_, bytes32 id_) internal returns (uint256 _first) {
        for (uint256 _gas = 10_000; _gas <= 400_000; _gas += 97) {
            vm.prank(stranger);
            (bool _ok, ) = address(tl).call{gas: _gas}(abi.encodeCall(tl.execute, (address(g), 0, op_, NONE, salt_)));
            if (_ok) {
                assertTrue(tl.isOperationDone(id_), "Done");
                assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Lockdown), "the effect landed");
                return _gas;
            }
            assertTrue(tl.isOperationReady(id_), "a starved execute leaves the operation Ready");
            assertEq(uint8(_mode()), uint8(CuratorGuardPolicy.Mode.Enforced), "and nothing applied");
        }
        revert("never landed");
    }

    /// @dev Anyone may execute a Ready operation with any gas limit: a starved execute either reverts whole
    ///      (the operation stays Ready, nothing applied) or lands whole; there is no limit at which the wrapper
    ///      reports success without its inner effect. The probe moves the first landing limit by about its cost.
    function test_T7_the_open_executor_cannot_starve_a_wrapped_operation_into_a_half_state() public {
        bytes memory _w = _wrap(uint64(block.timestamp + MIN_DELAY + 1 days), _lock());
        bytes32 _idW = _schedule(p1, p1Pk, address(g), _w, NONE, "t7-w");
        bytes32 _idB = _schedule(p1, p1Pk, address(g), _lock(), NONE, "t7-b");
        vm.warp(block.timestamp + MIN_DELAY);
        uint256 _snap = vm.snapshotState();
        uint256 _firstW = _sweepExecute(_w, "t7-w", _idW);
        vm.revertToState(_snap);
        uint256 _firstB = _sweepExecute(_lock(), "t7-b", _idB);
        console2.log("T7 first gas limit at which execute(wrapped lockdown) landed", _firstW);
        console2.log("T7 first gas limit at which execute(bare lockdown) landed", _firstB);
        assertGt(_firstW, _firstB, "the wrapper costs gas");
        assertLt(_firstW - _firstB, 8_000, "a few thousand gas (ABI, the probe, the delegatecall, the 1/64 of each frame)");
    }
}
