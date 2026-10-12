// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {G16dDirtyBase} from "test/guards/G16d_DirtyWordBase.sol";

/// @dev The plant a role Safe's own quorum can run: a storage-writing delegatecall (the Safe is unguarded).
contract G16dDirtyWriter {
    function write(bytes32 slot_, bytes32 value_) external {
        assembly {
            sstore(slot_, value_)
        }
    }
}

/// @dev Review round 18, reviewer g18b, adopted with G16d-1 applied: the concrete side of the handler-word mask
///      under `forge test`. The high bits are fuzzed (every value, zero included); the plant is also done the
///      real way, through `execTransaction` with the role Safe's owner signature and a delegatecall, on a
///      v1.4.1 and a v1.5.0 build (the plain `setFallbackHandler(dirtyWord)` self-call is rejected by the
///      ABI decoder, `GS013`; the delegatecall is not).
abstract contract G16dDirtyFoundryBase is G16dDirtyBase {
    uint256 internal constant KEY = 0xB0B0B0B;
    address internal keyed;

    function setUp() public virtual override {
        super.setUp();
        keyed = vm.addr(KEY);
    }

    /// @dev Split in three (the legacy pipeline runs out of stack on the 10-argument calls otherwise).
    function _txHash(ISafe safe_, address to_, bytes memory data_, Operation op_) internal view returns (bytes32) {
        uint256 _n = safe_.nonce();
        return safe_.getTransactionHash(to_, 0, data_, op_, 0, 0, 0, address(0), address(0), _n);
    }

    function _sigOf(bytes32 h_) internal returns (bytes memory) {
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(KEY, h_);
        return abi.encodePacked(_r, _s, _v);
    }

    /// @dev The one external call of the helper (so `vm.expectRevert` binds to `execTransaction`).
    function _execSigned(ISafe safe_, address to_, bytes memory data_, Operation op_, bytes memory sig_) internal returns (bool) {
        return safe_.execTransaction(to_, 0, data_, op_, 0, 0, 0, address(0), payable(address(0)), sig_);
    }

    function _execAs(ISafe safe_, address to_, bytes memory data_, Operation op_) internal returns (bool) {
        bytes memory _sig = _sigOf(_txHash(safe_, to_, data_, op_));
        return _execSigned(safe_, to_, data_, op_, _sig);
    }

    /// @dev Plant through the real Safe: the plain self-call is refused (GS013), the delegatecall lands.
    function _plantForReal(ISafe safe_, address low_, uint96 h_) internal {
        bytes32 _w = _wordOf(low_, h_);
        if (h_ != 0) {
            bytes memory _data = abi.encodeWithSelector(bytes4(0xf08a0323), _w);
            bytes memory _sig = _sigOf(_txHash(safe_, address(safe_), _data, Operation.Call));
            // The ABI decoder refuses the dirty address word with an empty revert; v1.4.1 wraps the failed
            // inner call in `GS013`, v1.5.0 bubbles the inner frame's (empty) revert data instead.
            bool _v150 = keccak256(bytes(safe_.VERSION())) == keccak256("1.5.0");
            if (_v150) vm.expectRevert();
            else vm.expectRevert(bytes("GS013"));
            _execSigned(safe_, address(safe_), _data, Operation.Call, _sig);
            assertEq(_word(safe_), bytes32(0), "the plain self-call planted nothing");
        }
        G16dDirtyWriter _wr = new G16dDirtyWriter();
        assertTrue(_execAs(safe_, address(_wr), abi.encodeCall(G16dDirtyWriter.write, (FALLBACK_SLOT, _w)), Operation.DelegateCall), "delegatecall plant");
        assertEq(_word(safe_), _w, "the word is in the slot");
        assertEq(_forwardsTo(safe_), low_, "the low 160 bits are the target");
    }
}

/// @dev With G16d-1 applied: every word whose low 160 bits are the guard (or the timelock) is refused by its rail,
///      whatever the high bits; the clean word stays refused and a word naming another address is served (the
///      rails bind the TARGET of the forwarding, not the slot's bytes).
contract G16d_DirtyWordMaskedTest is G16dDirtyFoundryBase {
    /// forge-config: default.fuzz.runs = 2048
    function testFuzz_M_every_word_naming_the_guard_or_the_timelock_is_refused_by_its_rail(uint96 h) public {
        _plant(c141, address(guard), h);
        _plant(a150, address(guard), h);
        _plant(p141, address(tl), h);
        _plant(v150, address(tl), h);
        bytes32 _id = _opId();
        bytes memory _sch = _schedule();
        vm.prank(P2);
        (bool _s, ) = address(tl).call(_sch);
        assertTrue(_s);
        bytes32 _b = _digest();
        bytes memory _c = _wrapEnforce(uint64(T0 + 1));
        vm.prank(STRANGER);
        (bool _ok, bytes memory _ret) = address(c141).call(_c);
        assertTrue(_isUnauthorized(_ok, _ret), "executeBefore forwarded");
        vm.prank(address(c141));
        (_ok, _ret) = address(guard).call(_c);
        assertTrue(_isUnauthorized(_ok, _ret), "executeBefore direct");
        _c = _lockdownS();
        vm.prank(STRANGER);
        (_ok, _ret) = address(c141).call(_c);
        assertTrue(_isUnauthorized(_ok, _ret), "lockdown forwarded");
        vm.warp(T0 + ADMIN_DELAY + 1);
        _c = _accept();
        vm.prank(STRANGER);
        (_ok, _ret) = address(a150).call(_c);
        assertTrue(_isUnauthorized(_ok, _ret), "acceptance forwarded");
        vm.prank(address(a150));
        (_ok, _ret) = address(guard).call(_c);
        assertTrue(_isUnauthorized(_ok, _ret), "acceptance direct");
        _c = _renounceProposer(p141);
        vm.prank(STRANGER);
        (_ok, _ret) = address(p141).call(_c);
        assertTrue(_isForwardedCall(_ok, _ret, address(p141)), "renounce forwarded");
        vm.prank(address(p141));
        (_ok, _ret) = address(tl).call(_c);
        assertTrue(_isForwardedCall(_ok, _ret, address(p141)), "renounce direct");
        _c = _cancel();
        vm.prank(STRANGER);
        (_ok, _ret) = address(v150).call(_c);
        assertTrue(_isForwardedCall(_ok, _ret, address(v150)), "cancel forwarded");
        assertEq(_digest(), _b, "nothing moved");
        assertTrue(tl.isOperationPending(_id));
    }

    function test_R_after_a_real_delegatecall_plant_every_route_is_refused() public {
        ISafe _c2 = _safe141(keyed);
        bytes32 _C = guard.COUNCIL_ROLE();
        vm.prank(VETRO);
        guard.grantRole(_C, address(_c2));
        _plantForReal(_c2, address(guard), 0xdead);
        bytes memory _c = _lockdownS();
        vm.prank(STRANGER);
        (bool _ok, bytes memory _ret) = address(_c2).call(_c);
        assertTrue(_isUnauthorized(_ok, _ret), "council lockdown refused");
        ISafe _a2 = _safe150(keyed);
        vm.prank(VETRO);
        guard.beginDefaultAdminTransfer(address(_a2));
        (, uint48 _sch) = guard.pendingDefaultAdmin();
        _plantForReal(_a2, address(guard), 0xbeef);
        vm.warp(uint256(_sch) + 1);
        _c = _accept();
        vm.prank(STRANGER);
        (_ok, _ret) = address(_a2).call(_c);
        assertTrue(_isUnauthorized(_ok, _ret), "acceptance refused");
        assertEq(guard.defaultAdmin(), VETRO);
        ISafe _p2 = _safe141(keyed);
        ISafe _v2 = _safe150(keyed);
        address[] memory _ps = new address[](2);
        _ps[0] = address(_p2);
        _ps[1] = P2;
        address[] memory _cs = new address[](1);
        _cs[0] = address(_v2);
        CuratorGuardTimelock _tl2 = new CuratorGuardTimelock(1 days, _ps, _cs);
        _plantForReal(_p2, address(_tl2), 0xcafe);
        _plantForReal(_v2, address(_tl2), 0xf00d);
        _c = abi.encodeCall(_tl2.schedule, (address(guard), 0, _opData(), bytes32(0), SALT, 1 days));
        vm.prank(STRANGER);
        (_ok, _ret) = address(_p2).call(_c);
        assertTrue(_isForwardedCall(_ok, _ret, address(_p2)), "schedule refused");
        bytes32 _id = _tl2.hashOperation(address(guard), 0, _opData(), bytes32(0), SALT);
        vm.prank(P2);
        _tl2.schedule(address(guard), 0, _opData(), bytes32(0), SALT, 1 days);
        _c = abi.encodeCall(_tl2.cancel, (_id));
        vm.prank(STRANGER);
        (_ok, _ret) = address(_v2).call(_c);
        assertTrue(_isForwardedCall(_ok, _ret, address(_v2)), "cancel refused");
        assertTrue(_tl2.isOperationPending(_id));
    }

    function test_C_the_clean_word_is_refused_and_a_word_naming_another_address_is_served() public {
        _plant(c141, address(guard), 0);
        bytes memory _c = _wrapEnforce(uint64(T0 + 1));
        vm.prank(STRANGER);
        (bool _ok, bytes memory _ret) = address(c141).call(_c);
        assertTrue(_isUnauthorized(_ok, _ret), "clean word: the rail");
        _plant(p141, address(tl), 0);
        _c = _renounceProposer(p141);
        vm.prank(STRANGER);
        (_ok, _ret) = address(p141).call(_c);
        assertTrue(_isForwardedCall(_ok, _ret, address(p141)), "clean word: the timelock's rail");
        _plant(c141, OTHER, 0xabc);
        _c = _wrapEnforce(uint64(T0 + 1));
        vm.prank(address(c141));
        (_ok, ) = address(guard).call(_c);
        assertTrue(_ok, "another address: served");
        assertEq(uint8(guard.mode(address(s))), uint8(CuratorGuardPolicy.Mode.Enforced));
    }
}
