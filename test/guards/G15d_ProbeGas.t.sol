// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {Test} from "forge-std/Test.sol";

import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {G9cBase} from "test/guards/G9c_Base.sol";

/// @title Review g15d (mutation testing of the final code): the forwarding probes' gas and answer shape, and the
///        live-delay rail's clamp, pinned where the round-15 campaign found them observed by nothing.
/// @dev   Three mutants of the two `getStorageAt` probes survived the unit suite: the gas each forwards capped at
///        2,300 (guard PR3, timelock TPR3: every test runs with the Safe, its singleton and its handler slot
///        already warm, so a probe that runs out of gas on a COLD handler-slot read, 2,100 gas, never did) and
///        the timelock probe's answer-length check dropped (TPR1: the guard's twin is pinned by `G10f_Pins`, the
///        timelock's copy by nothing). A fourth, the live-delay rail of G10c-1 reading the RAW stored delay
///        instead of the clamped one (LIVE-raw), is unreachable while the constructor and the proposal-time rail
///        keep the raw value inside the clamp; it is pinned here the way the clamp itself is (a planted slot).
contract G15dGuardProbeTest is G9cBase {
    bytes4 internal constant SET_FALLBACK_HANDLER = 0xf08a0323;

    function setUp() public override {
        super.setUp();
        _configureCurator();
    }

    /// @dev PR3: the probe forwards all its gas. A council Safe with this guard in its handler slot is refused
    ///      on its OWN transaction with nothing about it warm. On chain `execTransaction` reads the singleton,
    ///      the nonce, the threshold and the owners, never the handler slot: the probe's SLOAD of it is the
    ///      first of the transaction (cold, 2,100 gas); a probe capped near the warm cost runs out of gas there,
    ///      fails open and serves the Safe. `vm.cool` gives the test the chain's state.
    function test_the_rail_refuses_a_handlerd_council_safe_from_cold_state() public {
        (ISafe _c, uint256 _cPk) = _newSafe("council-safe-cold");
        _adminCall(abi.encodeCall(g.grantRole, (g.COUNCIL_ROLE(), address(_c))), "g15d-council");
        assertTrue(g.hasRole(g.COUNCIL_ROLE(), address(_c)), "council granted");
        assertTrue(
            _exec(_c, _cPk, address(_c), 0, abi.encodeWithSelector(SET_FALLBACK_HANDLER, address(g)), Operation.Call),
            "setFallbackHandler"
        );
        bytes memory _open = abi.encodeCall(g.bypass, (address(curatorSafe), uint64(7 days)));

        // the genuine route: the Safe's own transaction, the Safe, its singleton and every slot cold
        vm.cool(address(_c));
        vm.cool(address(singleton));
        vm.expectRevert(bytes("GS013"));
        _exec(_c, _cPk, address(g), 0, _open, Operation.Call);
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Enforced), "no window (genuine)");

        // the direct route (`msg.sender` is the Safe), cold again
        vm.cool(address(_c));
        vm.cool(address(singleton));
        vm.prank(address(_c));
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        g.bypass(address(curatorSafe), uint64(7 days));
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Enforced), "no window (direct)");

        // control: with the handler dropped the same Safe is served from cold state
        assertTrue(
            _exec(_c, _cPk, address(_c), 0, abi.encodeWithSelector(SET_FALLBACK_HANDLER, address(0)), Operation.Call),
            "repair"
        );
        vm.cool(address(_c));
        vm.cool(address(singleton));
        assertTrue(_exec(_c, _cPk, address(g), 0, _open, Operation.Call), "served after the repair");
        assertEq(uint8(g.mode(address(curatorSafe))), uint8(CuratorGuardPolicy.Mode.Bypass));
    }
}

/// @dev A proposer that answers `getStorageAt` with TWO words whose first is the timelock's address: not a
///      Safe-shaped answer (a Safe answers 96 bytes), so the timelock's probe must not take it for a Safe that
///      forwards. Acts on a target as itself through `act`.
contract G15dTwoWordAnswer {
    address internal timelock;

    function setTimelock(address timelock_) external {
        timelock = timelock_;
    }

    function getStorageAt(uint256, uint256) external view returns (bytes memory) {
        return abi.encodePacked(bytes32(uint256(uint160(timelock))), bytes32(0));
    }

    function act(address target_, bytes calldata call_) external returns (bool _ok, bytes memory _ret) {
        (_ok, _ret) = target_.call(call_);
    }
}

contract G15dTimelockProbeTest is Test {
    ISafe internal proposerSafe;
    ISafe internal vetoSafe;
    Safe internal singleton;
    address internal p2 = makeAddr("second-proposer");
    CuratorGuardTimelock internal tl;
    bytes internal data = abi.encodeWithSignature("updateDelay(uint256)", 3 days);

    function setUp() public {
        vm.warp(1_700_000_000);
        singleton = new Safe();
        proposerSafe = _plainSafe("proposer-owner");
        vetoSafe = _plainSafe("veto-owner");
        tl = _deploy(address(proposerSafe));
    }

    function _deploy(address proposer_) internal returns (CuratorGuardTimelock) {
        address[] memory _p = new address[](2);
        _p[0] = proposer_;
        _p[1] = p2;
        address[] memory _c = new address[](1);
        _c[0] = address(vetoSafe);
        return new CuratorGuardTimelock(2 days, _p, _c);
    }

    function _plainSafe(string memory owner_) internal returns (ISafe) {
        SafeProxy _proxy = new SafeProxy(address(singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = makeAddr(owner_);
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        return ISafe(address(_proxy));
    }

    function _handler(ISafe safe_, address handler_) internal {
        vm.prank(address(safe_));
        (bool _ok, ) = address(safe_).call(abi.encodeWithSignature("setFallbackHandler(address)", handler_));
        assertTrue(_ok, "setFallbackHandler");
    }

    function _id(bytes32 salt_) internal view returns (bytes32) {
        return tl.hashOperation(address(tl), 0, data, bytes32(0), salt_);
    }

    /// @dev TPR3: the timelock's probe forwards all its gas. A proposer Safe with this timelock in its handler
    ///      slot is refused on its own call from cold state (the probe's first read of the slot costs 2,100 gas).
    function test_the_rail_refuses_a_handlerd_proposer_safe_from_cold_state() public {
        _handler(proposerSafe, address(tl));
        vm.cool(address(proposerSafe));
        vm.cool(address(singleton));
        vm.prank(address(proposerSafe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.ForwardedCall.selector, address(proposerSafe)));
        tl.schedule(address(tl), 0, data, bytes32(0), bytes32(uint256(1)), 2 days);
        assertFalse(tl.isOperation(_id(bytes32(uint256(1)))), "nothing scheduled");

        // control: with the handler dropped the Safe schedules from cold state
        _handler(proposerSafe, address(0));
        vm.cool(address(proposerSafe));
        vm.cool(address(singleton));
        vm.prank(address(proposerSafe));
        tl.schedule(address(tl), 0, data, bytes32(0), bytes32(uint256(1)), 2 days);
        assertTrue(tl.isOperationPending(_id(bytes32(uint256(1)))), "scheduled after the repair");
    }

    /// @dev TPR1: the timelock's probe takes a 96-byte answer only (the guard's twin: `G10f_Pins`). A proposer
    ///      whose `getStorageAt` answers two words, the first this timelock, is no forwarding Safe: served.
    function test_the_probe_needs_a_safe_shaped_answer() public {
        G15dTwoWordAnswer _holder = new G15dTwoWordAnswer();
        CuratorGuardTimelock _tl2 = _deploy(address(_holder));
        _holder.setTimelock(address(_tl2));
        bytes32 _salt = bytes32(uint256(2));
        (bool _ok, bytes memory _ret) = _holder.act(
            address(_tl2),
            abi.encodeCall(TimelockController.schedule, (address(_tl2), 0, data, bytes32(0), _salt, 2 days))
        );
        assertTrue(_ok, "a two-word answer is no Safe: the holder is served");
        assertEq(_ret.length, 0);
        assertTrue(_tl2.isOperationPending(_tl2.hashOperation(address(_tl2), 0, data, bytes32(0), _salt)));
    }

    /// @dev LIVE-raw: the live-delay rail (G10c-1) compares with the CLAMPED delay, the one the base contract
    ///      enforces, whatever the raw slot holds (planted as `CuratorGuardRound6` plants it: on chain the
    ///      constructor and the proposal-time rail keep the slot inside the clamp).
    function test_the_live_delay_rail_reads_the_clamped_delay() public {
        bytes32 _slot = bytes32(uint256(2)); // `_minDelay` (forge inspect storage-layout)
        vm.store(address(tl), _slot, bytes32(uint256(48)));
        assertEq(tl.getMinDelay(), 1 days, "floor");
        vm.prank(p2);
        tl.schedule(address(tl), 0, data, bytes32(0), bytes32(uint256(3)), 1 days);
        assertTrue(tl.isOperationPending(_id(bytes32(uint256(3)))), "scheduled at the clamped delay");

        vm.store(address(tl), _slot, bytes32(uint256(172_800_000)));
        assertEq(tl.getMinDelay(), 30 days, "cap");
        vm.prank(p2);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardTimelock.DelayOutOfRange.selector, uint256(31 days)));
        tl.schedule(address(tl), 0, data, bytes32(0), bytes32(uint256(4)), 31 days);
        vm.prank(p2);
        tl.schedule(address(tl), 0, data, bytes32(0), bytes32(uint256(4)), 30 days);
        assertTrue(tl.isOperationPending(_id(bytes32(uint256(4)))), "scheduled at the clamped cap");
    }
}
