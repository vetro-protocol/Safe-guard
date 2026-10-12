// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G16dDirtyBase} from "test/guards/G16d_DirtyWordBase.sol";

/// @dev Records every call it receives: a stand-in for "whatever sits at the low 160 bits of the word".
contract G19aRecorder {
    address public lastSender;
    bytes public lastData;
    uint256 public hits;

    fallback() external {
        lastSender = msg.sender;
        lastData = msg.data;
        ++hits;
    }
}

/// @dev The raw EVM fact, isolated from any Safe: `call(gas(), word, ...)` with a full 256-bit word on the stack.
contract G19aRawCaller {
    function callWord(bytes32 word_, bytes calldata data_) external returns (bool _ok) {
        assembly {
            let _p := mload(0x40)
            calldatacopy(_p, data_.offset, data_.length)
            _ok := call(gas(), word_, 0, _p, data_.length, 0, 0)
        }
    }
}

/// @dev A role holder that is not a Safe: answers `getStorageAt` with whatever bytes it was told (shape attacks on the
///      probe) and acts on a target as itself.
contract G19aShape {
    bytes internal answer;
    bool internal doRevert;

    function set(bytes calldata answer_, bool revert_) external {
        answer = answer_;
        doRevert = revert_;
    }

    function getStorageAt(uint256, uint256) external view returns (bytes memory) {
        if (doRevert) revert("no");
        bytes memory _a = answer;
        assembly {
            return(add(_a, 0x20), mload(_a))
        }
    }

    function act(address target_, bytes calldata call_) external returns (bool _ok, bytes memory _ret) {
        (_ok, _ret) = target_.call(call_);
    }
}

/// @dev Forwards everything to `to` with the caller appended, as `FallbackManager` does, but answers no `getStorageAt`:
///      what an EOA's own EIP-7702 delegation (or a holder's own code) can be.
contract G19aBlindForwarder {
    address internal immutable to;

    constructor(address to_) {
        to = to_;
    }

    fallback() external {
        address _to = to;
        assembly {
            calldatacopy(0, 0, calldatasize())
            mstore(calldatasize(), shl(96, caller()))
            let _ok := call(gas(), _to, 0, 0, add(calldatasize(), 20), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(_ok) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
    }
}

/// @dev `CuratorGuardPolicy._isHandlerOf` with the mask (the tree) and without it (d878077), parameterised, measured
///      from one frame against the same account.
contract G19aProbes {
    bytes32 internal constant SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    function masked(address account_, address guard_) external view returns (bool _yes, uint256 _gas) {
        bytes32 _slot = SLOT;
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

    function raw(address account_, address guard_) external view returns (bool _yes, uint256 _gas) {
        bytes32 _slot = SLOT;
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

/// @title Review g19a: the mask, byte by byte (the attack half). On the PRODUCTION guard and timelock with real Safe v1.4.1
///        and v1.5.0 proxies from `lib/`.
contract G19a_MaskTest is G16dDirtyBase {
    struct GuardFix {
        CuratorGuard g;
        ISafe adm; // the DEFAULT_ADMIN_ROLE holder
        ISafe c; // the council seat
        ISafe gd; // a deployment-wide guardian
        ISafe pa; // the pending admin
    }

    struct TlFix {
        CuratorGuardTimelock t;
        ISafe p; // a proposer (P2 is the other)
        ISafe v; // the canceller
    }

    G19aRecorder internal rec;
    G19aRawCaller internal rawc;
    G19aProbes internal probes;
    GuardFix internal fA; // every role Safe a v1.4.1 build
    GuardFix internal fB; // every role Safe a v1.5.0 build
    TlFix internal lA; // proposer v1.4.1, canceller v1.5.0
    TlFix internal lB; // proposer v1.5.0, canceller v1.4.1
    address[] internal who;
    bytes[] internal data;
    ISafe internal both;
    CuratorGuardTimelock internal tBoth;

    bytes32 internal constant SALT2 = keccak256("g19a-2");
    bytes32 internal constant SALT3 = keccak256("g19a-3");
    bytes32 internal constant SALT4 = keccak256("g19a-4");

    function setUp() public override {
        super.setUp();
        rec = new G19aRecorder();
        rawc = new G19aRawCaller();
        probes = new G19aProbes();
        _guardWithSafes(fA, true);
        _guardWithSafes(fB, false);
        _timelockWithSafes(lA, true);
        _timelockWithSafes(lB, false);
    }

    function _newSafe(bool v141_) internal returns (ISafe) {
        return v141_ ? _safe141(OWNER) : _safe150(OWNER);
    }

    function _guardWithSafes(GuardFix storage f_, bool v141_) internal {
        f_.adm = _newSafe(v141_);
        f_.c = _newSafe(v141_);
        f_.gd = _newSafe(v141_);
        f_.pa = _newSafe(v141_);
        f_.g = new CuratorGuard(ADMIN_DELAY, address(f_.adm), address(f_.c));
        vm.startPrank(address(f_.adm));
        f_.g.setDeploymentGuardian(address(f_.gd), true);
        f_.g.allowFunction(address(s), address(venue), MockProtocol.settleDeposit.selector, false, _noRules());
        f_.g.beginDefaultAdminTransfer(address(f_.pa));
        vm.stopPrank();
    }

    function _timelockWithSafes(TlFix storage l_, bool v141_) internal {
        l_.p = _newSafe(v141_);
        l_.v = _newSafe(!v141_);
        address[] memory _ps = new address[](2);
        _ps[0] = address(l_.p);
        _ps[1] = P2;
        address[] memory _cs = new address[](1);
        _cs[0] = address(l_.v);
        l_.t = new CuratorGuardTimelock(1 days, _ps, _cs);
    }

    function _unauthorized() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(CuratorGuardPolicy.Unauthorized.selector);
    }

    function _forwardedCall(address who_) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(CuratorGuardTimelock.ForwardedCall.selector, who_);
    }

    function _push(address who_, bytes memory data_) internal {
        who.push(who_);
        data.push(data_);
    }

    /// @dev Every route in `who` / `data`, both paths: forwarded (a stranger through the Safe's fallback) and direct (the
    ///      Safe as the caller), must revert with exactly `expected_` (`ForwardedCall(who)` when `expected_` is empty).
    function _refusedOnBothPaths(address contract_, bytes memory expected_) internal {
        for (uint256 i; i < who.length; ++i) {
            bytes memory _exp = expected_.length == 0 ? _forwardedCall(who[i]) : expected_;
            vm.prank(STRANGER);
            (bool _ok, bytes memory _ret) = who[i].call(data[i]);
            assertFalse(_ok, string.concat("forwarded route served ", vm.toString(i)));
            assertEq(keccak256(_ret), keccak256(_exp), string.concat("forwarded route error ", vm.toString(i)));
            vm.prank(who[i]);
            (_ok, _ret) = contract_.call(data[i]);
            assertFalse(_ok, string.concat("direct route served ", vm.toString(i)));
            assertEq(keccak256(_ret), keccak256(_exp), string.concat("direct route error ", vm.toString(i)));
        }
    }

    function _guardDigest(GuardFix storage f_) internal view returns (bytes32) {
        CuratorGuard _g = f_.g;
        bytes32 _d1;
        {
            (address _p, uint48 _sch) = _g.pendingDefaultAdmin();
            (uint64 _u, bool _cb) = _g.bypassWindow(address(s));
            _d1 = keccak256(abi.encode(_g.defaultAdmin(), _p, _sch, _g.defaultAdminDelay(), _g.mode(address(s)), _u, _cb, _g.lockedAt(address(s))));
        }
        bytes32 _d2;
        {
            (address _h, bool _e) = _g.requiredFallbackHandler(address(s));
            _d2 = keccak256(abi.encode(_g.approvalEpoch(address(s)), _g.targets(address(s)).length, _g.selectors(address(s), address(venue)).length, _g.modules(address(s)).length, _g.multiSendUnwrappers(address(s)).length, _g.guardians(address(s)).length, _h, _e));
        }
        bytes32 _d3 = keccak256(abi.encode(_g.hasRole(_g.COUNCIL_ROLE(), address(f_.c)), _g.hasRole(_g.GUARDIAN_ROLE(), address(f_.gd)), _g.hasRole(_g.GUARDIAN_ROLE(), STRANGER), _g.hasRole(_g.COUNCIL_ROLE(), STRANGER), _g.isNativeTransferAllowed(address(s), address(venue))));
        return keccak256(abi.encode(_d1, _d2, _d3));
    }

    function _timelockDigest(TlFix storage l_, bytes32 id_) internal view returns (bytes32) {
        CuratorGuardTimelock _t = l_.t;
        bytes32 _d1 = keccak256(abi.encode(_t.proposerCount(), _t.cancellerCount(), _t.getMinDelay(), _t.isOperationPending(id_), _t.isOperation(id_)));
        bytes32 _d2 = keccak256(abi.encode(_t.hasRole(_t.PROPOSER_ROLE(), address(l_.p)), _t.hasRole(_t.CANCELLER_ROLE(), address(l_.v)), _t.hasRole(_t.PROPOSER_ROLE(), STRANGER), _t.hasRole(_t.CANCELLER_ROLE(), STRANGER), _t.hasRole(_t.PROPOSER_ROLE(), P2)));
        return keccak256(abi.encode(_d1, _d2));
    }

    /*//////////////////////////////////////////////////////////////
                 1. THE EVM FACT THE MASK MIRRORS (CALL TARGET)
    //////////////////////////////////////////////////////////////*/

    /// @dev Yellow Paper, Appendix H.2, CALL (0xf1): the recipient is `t ≡ μs[1] mod 2^160`; revm pops the target with
    ///      `Address::from_word` (the low 20 bytes of the word). A word with any high 96 bits lands at its low 160 bits.
    function testFuzz_1_the_evm_masks_a_call_target_to_its_low_160_bits(uint96 h) public {
        assertTrue(rawc.callWord(_wordOf(address(rec), h), hex"deadbeef"), "call succeeds");
        assertEq(rec.hits(), 1, "landed at the low 160 bits");
        assertEq(rec.lastSender(), address(rawc));
        assertEq(rec.lastData(), hex"deadbeef");
    }

    function test_1b_the_edge_words() public {
        uint96[4] memory _hs = [uint96(0), uint96(1), uint96(1) << 95, type(uint96).max];
        for (uint256 i; i < 4; ++i) {
            assertTrue(rawc.callWord(_wordOf(address(rec), _hs[i]), hex"deadbeef"));
            assertEq(rec.hits(), i + 1);
        }
    }

    /// @dev Both Safe builds: `FallbackManager` does `call(gas(), sload(slot), ...)` on the RAW word; the EVM takes its
    ///      low 160 bits. The probe reads the same slot through `getStorageAt`: for every word, forwards-to == low160(word).
    ///      So an account whose slot's low 160 bits are the guard and that forwards elsewhere cannot exist on a canonical
    ///      singleton, and a Safe whose word forwards to the guard always has the guard in those bits.
    function testFuzz_2_a_safe_forwards_to_the_low_160_bits_of_its_handler_word_on_both_builds(uint96 h) public {
        _plant(c141, address(rec), h);
        _plant(a150, address(rec), h);
        bytes memory _data = abi.encodeWithSelector(bytes4(0x12345678), uint256(7));
        vm.prank(STRANGER);
        (bool _ok, ) = address(c141).call(_data);
        assertTrue(_ok, "v1.4.1 forwards");
        assertEq(rec.hits(), 1);
        assertEq(rec.lastSender(), address(c141), "the Safe is the sender");
        assertEq(rec.lastData(), abi.encodePacked(_data, STRANGER), "the caller's 20 bytes appended");
        vm.prank(STRANGER);
        (_ok, ) = address(a150).call(_data);
        assertTrue(_ok, "v1.5.0 forwards");
        assertEq(rec.hits(), 2);
        assertEq(rec.lastSender(), address(a150));
        assertEq(rec.lastData(), abi.encodePacked(_data, STRANGER));
        assertEq(_word(c141), _wordOf(address(rec), h), "the probe reads the raw word");
        assertEq(_forwardsTo(c141), address(rec), "and forwards-to is its low 160 bits");
        assertEq(_word(a150), _wordOf(address(rec), h));
        assertEq(_forwardsTo(a150), address(rec));
    }

    /*//////////////////////////////////////////////////////////////
                  3. EVERY ROUTE OF THE GUARD'S RAIL, BOTH BUILDS
    //////////////////////////////////////////////////////////////*/

    function _guardRoutesAdmin(GuardFix storage f_) internal {
        CuratorGuard _g = f_.g;
        address _a = address(f_.adm);
        // the library's `onlyRole` entries (`_checkRole`)
        _push(_a, abi.encodeCall(_g.grantRole, (_g.GUARDIAN_ROLE(), STRANGER)));
        _push(_a, abi.encodeCall(_g.revokeRole, (_g.COUNCIL_ROLE(), address(f_.c))));
        _push(_a, abi.encodeCall(_g.beginDefaultAdminTransfer, (STRANGER)));
        _push(_a, abi.encodeCall(_g.cancelDefaultAdminTransfer, ()));
        _push(_a, abi.encodeCall(_g.changeDefaultAdminDelay, (uint48(2 days))));
        _push(_a, abi.encodeCall(_g.rollbackDefaultAdminDelay, ()));
        // `_checkAdmin`
        _push(_a, abi.encodeCall(_g.allowFunction, (address(s), address(venue), MockProtocol.deposit.selector, false, _noRules())));
        _push(_a, abi.encodeCall(_g.setRequiredFallbackHandler, (address(s), address(0), true)));
        _push(_a, abi.encodeCall(_g.setModuleAllowed, (address(s), address(venue), true)));
        _push(_a, abi.encodeCall(_g.setMultiSendUnwrapper, (address(s), address(venue), true)));
        _push(_a, abi.encodeCall(_g.setUnwrapperCodehash, (bytes32(uint256(1)), true)));
        _push(_a, abi.encodeCall(_g.setNativeTransferAllowed, (address(s), address(venue), true)));
        // `_checkAdminOrCouncil(For)`, the re-dispatcher
        _push(_a, abi.encodeCall(_g.setDeploymentGuardian, (STRANGER, true)));
        _push(_a, abi.encodeCall(_g.bypass, (address(s), uint64(1 days))));
        _push(_a, abi.encodeCall(_g.enforce, (address(s))));
        _push(_a, abi.encodeCall(_g.executeBefore, (uint64(block.timestamp + 1), abi.encodeCall(_g.bypass, (address(s), uint64(1 days))))));
    }

    function _guardRoutesCouncilGuardianPending(GuardFix storage f_, bytes32 approvalId_) internal {
        CuratorGuard _g = f_.g;
        address _c = address(f_.c);
        address _gd = address(f_.gd);
        // the council: `_checkAdminOrCouncil(For)`, a narrower, `renounceRole`, the re-dispatcher
        _push(_c, abi.encodeCall(_g.setGuardian, (address(s), STRANGER, true)));
        _push(_c, abi.encodeCall(_g.bypass, (address(s), uint64(1 days))));
        _push(_c, abi.encodeCall(_g.enforce, (address(s))));
        _push(_c, abi.encodeCall(_g.approveTransaction, (address(s), address(0), address(venue), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call, uint64(1 days))));
        _push(_c, abi.encodeCall(_g.lockdown, (address(s))));
        _push(_c, abi.encodeCall(_g.renounceRole, (_g.COUNCIL_ROLE(), _c)));
        _push(_c, abi.encodeCall(_g.executeBefore, (uint64(block.timestamp + 1), abi.encodeCall(_g.enforce, (address(s))))));
        // the guardian: every narrower entry (`_checkNarrower` / `_isGlobalNarrower`), `renounceRole`
        _push(_gd, abi.encodeCall(_g.lockdown, (address(s))));
        _push(_gd, abi.encodeCall(_g.lockdownAndRevoke, (address(s))));
        _push(_gd, abi.encodeCall(_g.revokeFunction, (address(s), address(venue), MockProtocol.settleDeposit.selector)));
        _push(_gd, abi.encodeCall(_g.revokeTarget, (address(s), address(venue))));
        _push(_gd, abi.encodeCall(_g.revokeAllApprovals, (address(s))));
        _push(_gd, abi.encodeCall(_g.revokeApproval, (approvalId_)));
        _push(_gd, abi.encodeCall(_g.renounceRole, (_g.GUARDIAN_ROLE(), _gd)));
        // the pending admin: the acceptance
        _push(address(f_.pa), abi.encodeCall(_g.acceptDefaultAdminTransfer, ()));
    }

    function _everyGuardRouteRefused(GuardFix storage f_, uint96 h_) internal {
        CuratorGuard _g = f_.g;
        // a live approval, issued by the admin Safe before the plant, so `revokeApproval`'s only refusal is the rail
        vm.prank(address(f_.adm));
        bytes32 _id = _g.approveTransaction(address(s), address(0), address(venue), 0, abi.encodeCall(MockProtocol.settleDeposit, (2)), Operation.Call, uint64(2 days));
        // past the admin delay: the acceptance's only refusal is the rail too
        vm.warp(T0 + ADMIN_DELAY + 1);
        _guardRoutesAdmin(f_);
        _guardRoutesCouncilGuardianPending(f_, _id);
        assertEq(who.length, 31, "31 routes");
        _plant(f_.adm, address(_g), h_);
        _plant(f_.c, address(_g), h_);
        _plant(f_.gd, address(_g), h_);
        _plant(f_.pa, address(_g), h_);
        bytes32 _before = _guardDigest(f_);
        _refusedOnBothPaths(address(_g), _unauthorized());
        assertEq(_guardDigest(f_), _before, "nothing moved");
        assertEq(_g.approvalExpiry(_id), uint64(T0 + 2 days), "the approval stands");
        // the control: a word naming another account serves the admin Safe on a direct call
        _plant(f_.adm, OTHER, h_);
        vm.prank(address(f_.adm));
        _g.setDeploymentGuardian(STRANGER, true);
        assertTrue(_g.hasRole(_g.GUARDIAN_ROLE(), STRANGER));
    }

    /// forge-config: default.fuzz.runs = 512
    function testFuzz_3a_every_guard_route_refuses_a_dirty_word_v141_role_safes(uint96 h) public {
        _everyGuardRouteRefused(fA, h);
    }

    /// forge-config: default.fuzz.runs = 512
    function testFuzz_3b_every_guard_route_refuses_a_dirty_word_v150_role_safes(uint96 h) public {
        _everyGuardRouteRefused(fB, h);
    }

    /*//////////////////////////////////////////////////////////////
                4. EVERY ROUTE OF THE TIMELOCK'S RAIL, BOTH BUILDS
    //////////////////////////////////////////////////////////////*/

    function _timelockRoutes(TlFix storage l_, bytes32 id_) internal {
        CuratorGuardTimelock _t = l_.t;
        address _p = address(l_.p);
        address _v = address(l_.v);
        _push(_p, abi.encodeCall(_t.schedule, (address(guard), 0, _opData(), bytes32(0), SALT2, 1 days)));
        {
            address[] memory _ts = new address[](1);
            _ts[0] = address(guard);
            uint256[] memory _vs = new uint256[](1);
            bytes[] memory _ps = new bytes[](1);
            _ps[0] = _opData();
            _push(_p, abi.encodeCall(_t.scheduleBatch, (_ts, _vs, _ps, bytes32(0), SALT3, 1 days)));
        }
        _push(_v, abi.encodeCall(_t.cancel, (id_)));
        _push(_p, abi.encodeCall(_t.renounceRole, (_t.PROPOSER_ROLE(), _p)));
        _push(_v, abi.encodeCall(_t.renounceRole, (_t.CANCELLER_ROLE(), _v)));
        _push(_p, abi.encodeCall(_t.grantRole, (_t.PROPOSER_ROLE(), STRANGER)));
        _push(_v, abi.encodeCall(_t.revokeRole, (_t.PROPOSER_ROLE(), P2)));
        _push(_p, abi.encodeCall(_t.grantRole, (_t.CANCELLER_ROLE(), STRANGER)));
    }

    function _everyTimelockRouteRefused(TlFix storage l_, uint96 h_) internal {
        CuratorGuardTimelock _t = l_.t;
        bytes32 _id = _t.hashOperation(address(guard), 0, _opData(), bytes32(0), SALT);
        vm.prank(P2);
        _t.schedule(address(guard), 0, _opData(), bytes32(0), SALT, 1 days);
        // and one the timelock itself serves once ready (a self-call), for the open-executor route below
        vm.prank(P2);
        _t.schedule(address(_t), 0, abi.encodeCall(_t.updateDelay, (2 days)), bytes32(0), SALT4, 1 days);
        _timelockRoutes(l_, _id);
        assertEq(who.length, 8, "8 routes");
        _plant(l_.p, address(_t), h_);
        _plant(l_.v, address(_t), h_);
        bytes32 _before = _timelockDigest(l_, _id);
        _refusedOnBothPaths(address(_t), "");
        assertEq(_timelockDigest(l_, _id), _before, "nothing moved");
        _noRailRoutes(l_, _id);
    }

    /// @dev `updateDelay` is `onlyTimelock`: no probe, the same refusal for a forwarded stranger and for the Safe itself.
    ///      The open executor is open by design: a stranger through the forwarding proposer Safe executes a ready
    ///      operation exactly as the stranger could directly (no probe, no role, nothing keyed on the Safe).
    function _noRailRoutes(TlFix storage l_, bytes32 id_) internal {
        CuratorGuardTimelock _t = l_.t;
        bytes memory _upd = abi.encodeCall(_t.updateDelay, (2 days));
        bytes memory _exp = abi.encodeWithSelector(bytes4(keccak256("TimelockUnauthorizedCaller(address)")), address(l_.p));
        vm.prank(STRANGER);
        (bool _ok, bytes memory _ret) = address(l_.p).call(_upd);
        assertTrue(!_ok && keccak256(_ret) == keccak256(_exp), "updateDelay forwarded");
        vm.prank(address(l_.p));
        (_ok, _ret) = address(_t).call(_upd);
        assertTrue(!_ok && keccak256(_ret) == keccak256(_exp), "updateDelay direct");
        vm.warp(block.timestamp + 1 days);
        bytes memory _upd2 = abi.encodeCall(_t.updateDelay, (2 days));
        vm.prank(STRANGER);
        (_ok, ) = address(l_.p).call(abi.encodeCall(_t.execute, (address(_t), 0, _upd2, bytes32(0), SALT4)));
        assertTrue(_ok, "execute through the forwarding Safe: open executor");
        assertTrue(_t.isOperationDone(_t.hashOperation(address(_t), 0, _upd2, bytes32(0), SALT4)));
        assertEq(_t.getMinDelay(), 2 days, "the self-call landed with the timelock as the caller");
        assertTrue(_t.isOperationPending(id_), "the other operation still pending (nobody cancelled it)");
        // the control: a word naming another account, the proposer Safe schedules again
        _plant(l_.p, OTHER, 1);
        vm.prank(address(l_.p));
        _t.schedule(address(guard), 0, _opData(), bytes32(0), SALT2, 2 days);
        assertTrue(_t.isOperationPending(_t.hashOperation(address(guard), 0, _opData(), bytes32(0), SALT2)));
    }

    /// forge-config: default.fuzz.runs = 512
    function testFuzz_4a_every_timelock_route_refuses_a_dirty_word_v141_proposer_v150_canceller(uint96 h) public {
        _everyTimelockRouteRefused(lA, h);
    }

    /// forge-config: default.fuzz.runs = 512
    function testFuzz_4b_every_timelock_route_refuses_a_dirty_word_v150_proposer_v141_canceller(uint96 h) public {
        _everyTimelockRouteRefused(lB, h);
    }

    /*//////////////////////////////////////////////////////////////
          5. A WORD NAMING THE OTHER CONTRACT: EACH RAIL BINDS ITSELF
    //////////////////////////////////////////////////////////////*/

    function _bothSeats() internal {
        both = _safe141(OWNER);
        bytes32 _C = guard.COUNCIL_ROLE(); // read before the prank: a view call would consume it
        vm.prank(VETRO);
        guard.grantRole(_C, address(both));
        address[] memory _ps = new address[](2);
        _ps[0] = address(both);
        _ps[1] = P2;
        address[] memory _cs = new address[](1);
        _cs[0] = address(v150);
        tBoth = new CuratorGuardTimelock(1 days, _ps, _cs);
    }

    /// @dev A Safe holding the guard's council seat AND a proposer seat. A word naming the guard: the forwarded `schedule`
    ///      lands at the GUARD (no such selector, no fallback: an empty revert) and never at the timelock, so the
    ///      timelock's rail has nothing to refuse and serves the Safe's own call; the guard's rail refuses both paths.
    function testFuzz_5a_a_word_naming_the_guard_on_a_safe_with_both_seats(uint96 h) public {
        _bothSeats();
        bytes memory _sch = abi.encodeCall(tBoth.schedule, (address(guard), 0, _opData(), bytes32(0), SALT, 1 days));
        bytes memory _enf = abi.encodeCall(guard.enforce, (address(s)));
        _plant(both, address(guard), h);
        vm.prank(STRANGER);
        (bool _ok, bytes memory _ret) = address(both).call(_sch);
        assertTrue(!_ok && _ret.length == 0, "forwarded schedule lands at the guard: no such function");
        vm.prank(STRANGER);
        (_ok, _ret) = address(both).call(_enf);
        assertTrue(_isUnauthorized(_ok, _ret), "forwarded enforce: the guard's rail");
        vm.prank(address(both));
        (_ok, _ret) = address(guard).call(_enf);
        assertTrue(_isUnauthorized(_ok, _ret), "direct enforce: the guard's rail");
        vm.prank(address(both));
        (_ok, ) = address(tBoth).call(_sch);
        assertTrue(_ok, "direct schedule: served, the word does not name the timelock");
        assertTrue(tBoth.isOperationPending(tBoth.hashOperation(address(guard), 0, _opData(), bytes32(0), SALT)));
    }

    /// @dev The mirror image: a word naming the timelock. A rail only ever needs to compare with its own address.
    function testFuzz_5b_a_word_naming_the_timelock_on_a_safe_with_both_seats(uint96 h) public {
        _bothSeats();
        bytes memory _sch = abi.encodeCall(tBoth.schedule, (address(guard), 0, _opData(), bytes32(0), SALT2, 1 days));
        bytes memory _enf = abi.encodeCall(guard.enforce, (address(s)));
        _plant(both, address(tBoth), h);
        vm.prank(STRANGER);
        (bool _ok, bytes memory _ret) = address(both).call(_enf);
        assertTrue(!_ok && _ret.length == 0, "forwarded enforce lands at the timelock: no such function");
        vm.prank(STRANGER);
        (_ok, _ret) = address(both).call(_sch);
        assertTrue(_isForwardedCall(_ok, _ret, address(both)), "forwarded schedule: the timelock's rail");
        vm.prank(address(both));
        (_ok, _ret) = address(tBoth).call(_sch);
        assertTrue(_isForwardedCall(_ok, _ret, address(both)), "direct schedule: the timelock's rail");
        vm.prank(address(both));
        (_ok, ) = address(guard).call(_enf);
        assertTrue(_ok, "direct enforce: served, the word does not name the guard");
        assertEq(uint8(guard.mode(address(s))), uint8(CuratorGuardPolicy.Mode.Enforced));
    }

    /*//////////////////////////////////////////////////////////////
                        6. THE SHAPE OF THE ANSWER
    //////////////////////////////////////////////////////////////*/

    /// @dev A role holder that is not a Safe and answers `getStorageAt` itself. Only a 96-byte answer whose third word's
    ///      low 160 bits are the guard is read as forwarding, for every value of the high bits (and of the two head words:
    ///      the probe does not parse the `bytes` head, a malformed 96-byte answer naming the guard is refused too: it is the
    ///      holder's own answer, fail-closed). Every other length, and a revert, is served.
    function testFuzz_6_the_probe_takes_a_96_byte_answer_only_and_masks_its_third_word(uint96 h, bytes32 head0, bytes32 head1) public {
        G19aShape _sh = new G19aShape();
        bytes32 _C = guard.COUNCIL_ROLE();
        vm.prank(VETRO);
        guard.grantRole(_C, address(_sh));
        bytes memory _rev = abi.encodeCall(guard.revokeAllApprovals, (address(s)));
        bytes32 _w = _wordOf(address(guard), h);
        uint32 _epoch = guard.approvalEpoch(address(s));

        _sh.set(abi.encode(bytes32(uint256(0x20)), bytes32(uint256(0x20)), _w), false);
        (bool _ok, bytes memory _ret) = _sh.act(address(guard), _rev);
        assertTrue(_isUnauthorized(_ok, _ret), "Safe-shaped answer naming the guard: refused");
        _sh.set(abi.encode(head0, head1, _w), false);
        (_ok, _ret) = _sh.act(address(guard), _rev);
        assertTrue(_isUnauthorized(_ok, _ret), "96 bytes, any head words, third word naming the guard: refused");
        assertEq(guard.approvalEpoch(address(s)), _epoch, "nothing moved");

        _sh.set(abi.encode(bytes32(uint256(0x20)), bytes32(uint256(0x20)), _wordOf(OTHER, h)), false);
        (_ok, ) = _sh.act(address(guard), _rev);
        assertTrue(_ok, "third word naming another account: served");
        _sh.set(abi.encode(_w, _w), false); // 64 bytes
        (_ok, ) = _sh.act(address(guard), _rev);
        assertTrue(_ok, "64 bytes: served");
        _sh.set(abi.encode(bytes32(uint256(0x20)), bytes32(uint256(0x40)), _w, _w), false); // 128 bytes
        (_ok, ) = _sh.act(address(guard), _rev);
        assertTrue(_ok, "128 bytes: served");
        _sh.set(abi.encode(_w), false); // 32 bytes
        (_ok, ) = _sh.act(address(guard), _rev);
        assertTrue(_ok, "32 bytes: served");
        _sh.set(abi.encodePacked(bytes32(uint256(0x20)), bytes32(uint256(0x20)), _w, bytes1(0)), false); // 97 bytes
        (_ok, ) = _sh.act(address(guard), _rev);
        assertTrue(_ok, "97 bytes: served");
        _sh.set("", true);
        (_ok, ) = _sh.act(address(guard), _rev);
        assertTrue(_ok, "a revert: served");
        assertEq(guard.approvalEpoch(address(s)), _epoch + 6, "six served calls");
    }

    /*//////////////////////////////////////////////////////////////
                    7. EIP-7702 ACCOUNTS HOLDING A ROLE
    //////////////////////////////////////////////////////////////*/

    function _delegatedSeats() internal returns (address _e, address _e2) {
        _e = vm.addr(0xE0A1);
        _e2 = vm.addr(0xE0A2);
        vm.etch(_e, abi.encodePacked(hex"ef0100", address(new Safe())));
        vm.etch(_e2, abi.encodePacked(hex"ef0100", address(new Safe150())));
        assertEq(_e.code.length, 23, "designator");
        vm.startPrank(VETRO);
        guard.grantRole(guard.COUNCIL_ROLE(), _e);
        guard.grantRole(guard.COUNCIL_ROLE(), _e2);
        vm.stopPrank();
    }

    /// @dev An EOA delegated to a Safe SINGLETON (v1.4.1, v1.5.0) runs the singleton's code over its own storage: it
    ///      forwards like a Safe and answers `getStorageAt` like one, so the rail reads it like a Safe, for every word.
    ///      forge 1.5.1's EVM follows the `0xef0100 || delegate` designator on CALL (G11f).
    function testFuzz_7_an_eip7702_account_delegated_to_a_safe_singleton_is_probed_like_a_safe(uint96 h) public {
        (address _e, address _e2) = _delegatedSeats();
        bytes memory _lock = abi.encodeCall(guard.lockdown, (address(s)));
        bytes32 _w = _wordOf(address(guard), h);
        vm.store(_e, FALLBACK_SLOT, _w);
        vm.store(_e2, FALLBACK_SLOT, _w);
        assertEq(bytes32(ISafe(_e).getStorageAt(uint256(FALLBACK_SLOT), 1)), _w, "answers like a Safe");
        assertEq(bytes32(ISafe(_e2).getStorageAt(uint256(FALLBACK_SLOT), 1)), _w);
        vm.prank(STRANGER);
        (bool _ok, bytes memory _ret) = _e.call(_lock);
        assertTrue(_isUnauthorized(_ok, _ret), "forwarded through the v1.4.1-delegated EOA: refused");
        vm.prank(STRANGER);
        (_ok, _ret) = _e2.call(_lock);
        assertTrue(_isUnauthorized(_ok, _ret), "forwarded through the v1.5.0-delegated EOA: refused");
        vm.prank(_e);
        (_ok, _ret) = address(guard).call(_lock);
        assertTrue(_isUnauthorized(_ok, _ret), "direct while the slot names the guard: refused");
        assertEq(uint8(guard.mode(address(s))), uint8(CuratorGuardPolicy.Mode.Bypass), "nothing moved");
        // the repair: the slot cleared (the account's own storage), served
        vm.store(_e, FALLBACK_SLOT, 0);
        vm.prank(_e);
        guard.lockdown(address(s));
        assertEq(uint8(guard.mode(address(s))), uint8(CuratorGuardPolicy.Mode.Lockdown));
    }

    /// @dev The limit, as for any holder: an EOA that delegates to code that forwards blindly and answers no `getStorageAt`
    ///      is served as itself. That delegation is the EOA's own signed authorization (EIP-7702), as a Safe's custom
    ///      singleton is its quorum's act: the rail refuses a holder's MISCONFIGURATION, not a holder that acts.
    function test_7b_a_blind_delegation_is_the_holders_own_act() public {
        G19aBlindForwarder _f = new G19aBlindForwarder(address(guard));
        address _e = vm.addr(0xE0A3);
        vm.etch(_e, abi.encodePacked(hex"ef0100", address(_f)));
        bytes32 _C = guard.COUNCIL_ROLE();
        vm.prank(VETRO);
        guard.grantRole(_C, _e);
        vm.prank(STRANGER);
        (bool _ok, ) = _e.call(abi.encodeCall(guard.lockdown, (address(s))));
        assertTrue(_ok, "served: the EOA chose code that forwards and does not answer the probe");
        assertEq(uint8(guard.mode(address(s))), uint8(CuratorGuardPolicy.Mode.Lockdown));
    }

    /*//////////////////////////////////////////////////////////////
                   8. THE TIMELOCK ADMINISTERING ITSELF
    //////////////////////////////////////////////////////////////*/

    /// @dev The timelock as the caller of its own `grantRole` (a scheduled self-call anyone executes) and as the guard's
    ///      admin: `_refuseForwarded(timelock)` probes an account that answers no `getStorageAt` (the staticcall fails),
    ///      so it is never read as forwarding, whatever its storage holds at the handler slot.
    function testFuzz_8_the_timelock_administering_itself_is_never_read_as_forwarding(uint96 h) public {
        vm.store(address(tl), FALLBACK_SLOT, _wordOf(address(tl), h));
        bytes memory _grant = abi.encodeCall(tl.grantRole, (tl.PROPOSER_ROLE(), STRANGER));
        vm.prank(P2);
        tl.schedule(address(tl), 0, _grant, bytes32(0), SALT2, 1 days);
        CuratorGuard _g = new CuratorGuard(ADMIN_DELAY, address(tl), COUNCIL);
        bytes memory _allow = abi.encodeCall(_g.allowFunction, (address(s), address(venue), MockProtocol.settleDeposit.selector, false, _noRules()));
        vm.prank(P2);
        tl.schedule(address(_g), 0, _allow, bytes32(0), SALT3, 1 days);
        vm.warp(block.timestamp + 1 days);
        vm.startPrank(STRANGER);
        tl.execute(address(tl), 0, _grant, bytes32(0), SALT2);
        tl.execute(address(_g), 0, _allow, bytes32(0), SALT3);
        vm.stopPrank();
        assertTrue(tl.hasRole(tl.PROPOSER_ROLE(), STRANGER), "the self-administration landed");
        assertEq(_g.targets(address(s)).length, 1, "the admin call from the timelock landed");
    }

    /*//////////////////////////////////////////////////////////////
                                 9. GAS
    //////////////////////////////////////////////////////////////*/

    /// @dev The two probes against the same warm Safe from one frame: the mask's cost is the inserted instructions
    ///      (PUSH1 PUSH1 PUSH1 SHL SUB AND at 3 gas each: 18), and on the dirty word only the masked probe says forwarding.
    function test_9_the_mask_costs_18_gas_per_probe_and_changes_the_verdict_on_a_dirty_word_only() public {
        _plant(c141, address(guard), 0xdead);
        probes.masked(address(c141), address(guard)); // warms the Safe, its singleton and the slot
        (bool _m, uint256 _gm) = probes.masked(address(c141), address(guard));
        (bool _r, uint256 _gr) = probes.raw(address(c141), address(guard));
        assertTrue(_m, "masked: forwarding");
        assertFalse(_r, "raw: not forwarding (d878077 read the dirty word as clean)");
        emit log_named_uint("masked probe, warm", _gm);
        emit log_named_uint("raw probe, warm", _gr);
        emit log_named_uint("delta", _gm - _gr);
        assertEq(_gm - _gr, 18, "the mask's instructions");
        _plant(c141, address(guard), 0);
        (_m, ) = probes.masked(address(c141), address(guard));
        (_r, ) = probes.raw(address(c141), address(guard));
        assertTrue(_m && _r, "the clean word: both agree");
        _plant(c141, OTHER, 0xdead);
        (_m, ) = probes.masked(address(c141), address(guard));
        (_r, ) = probes.raw(address(c141), address(guard));
        assertTrue(!_m && !_r, "another account: both agree");
    }
}
