// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G9fHarness} from "test/guards/G9fBase.sol";

/// @title Round 9 (g9f): the configuration digest, fuzzed on the real Safe v1.4.1 fixture.
/// @dev Three properties from docs section 4 ("Post-execution"): (1) the digest equals the hash of the
///      concatenated raw answers of the Safe's own views, in the documented order; (2) any write to a
///      covered component (singleton, owner list, owner count, threshold, modules head, fallback
///      handler, guard, module guard) changes it, for any value, dirty high bits included; (3) a write
///      to the nonce or to an uncovered slot does not. The fixture guard is replaced by the g9f harness
///      (same code plus a read-only probe) so the digest can be read the way the hooks compute it.
contract CuratorGuardG9fDigestFuzzTest is CuratorGuardTestBase {
    bytes32 internal constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;
    address internal constant SENTINEL = address(0x1);
    G9fHarness internal h;
    address internal singleton;
    address internal otherSingleton;

    function setUp() public override {
        super.setUp();
        h = new G9fHarness(0, vetro, council);
        h.seedSafe(address(safe));
        otherSingleton = address(new Safe());
        h.seedSafeCodehash(otherSingleton.codehash);
        singleton = address(uint160(uint256(vm.load(address(safe), bytes32(0)))));
        vm.prank(address(safe));
        safe.setGuard(address(h));
        guard = h;
        _enforce();
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
    }

    function _ownerSlot(address key_) internal pure returns (bytes32) {
        return keccak256(abi.encode(key_, uint256(2)));
    }

    /// @dev The documented concatenation, computed from the Safe's views by the test.
    function _referenceDigest() internal view returns (bytes32) {
        (, bytes memory _master) = address(safe).staticcall(abi.encodeWithSelector(0xa619486e));
        (, bytes memory _owners) = address(safe).staticcall(abi.encodeWithSelector(ISafe.getOwners.selector));
        return
            keccak256(
                abi.encodePacked(
                    bytes32(_master),
                    _raw(3, 2),
                    _owners,
                    _raw(uint256(MODULES_HEAD_SLOT), 1),
                    _raw(uint256(FALLBACK_SLOT), 1),
                    _raw(uint256(GUARD_SLOT), 1),
                    _raw(uint256(MODULE_GUARD_SLOT), 1)
                )
            );
    }

    function _raw(uint256 slot_, uint256 words_) internal view returns (bytes memory _ret) {
        (, _ret) = address(safe).staticcall(abi.encodeWithSelector(ISafe.getStorageAt.selector, slot_, words_));
    }

    function _digest() internal view returns (bytes32 _d) {
        (_d, , ) = h.configDigest(address(safe));
    }

    function test_digest_equals_the_documented_concatenation() public view {
        assertEq(_digest(), _referenceDigest());
    }

    /// forge-config: default.fuzz.runs = 1500
    function testFuzz_digest_changes_with_every_covered_component_and_nothing_else(uint8 which_, bytes32 v_) public {
        bytes32 _before = _digest();
        assertEq(_before, _referenceDigest(), "reference agrees before");
        uint256 _w = which_ % 9;
        bytes32 _slot;
        bytes32 _old;
        bool _covered = true;
        if (_w == 0) {
            // singleton: another seeded build, or the same one (no change expected then)
            _slot = bytes32(0);
            v_ = uint8(v_[31]) % 2 == 0 ? bytes32(uint256(uint160(otherSingleton))) : bytes32(uint256(uint160(singleton)));
        } else if (_w == 1) {
            // owner list: the single owner is replaced by a random key (the count stays 1); the list is
            // SENTINEL -> x -> SENTINEL, so the new owner's own link is written too
            _slot = _ownerSlot(SENTINEL);
            v_ = bytes32(uint256(uint160(uint256(v_))));
            if (v_ == bytes32(uint256(uint160(curator))) || uint256(v_) < 2) v_ = bytes32(uint256(uint160(attacker)));
            vm.store(address(safe), _ownerSlot(address(uint160(uint256(v_)))), bytes32(uint256(uint160(SENTINEL))));
        } else if (_w == 2) {
            // owner count: a larger count reads a zero-padded list (a smaller one panics: out of scope here)
            _slot = bytes32(uint256(3));
            v_ = bytes32(uint256(2 + uint8(v_[31]) % 4));
        } else if (_w == 3) {
            _slot = bytes32(uint256(4)); // threshold, any word
        } else if (_w == 4) {
            // modules head: a non-sentinel head is a linked module; the DIGEST still changes (the
            // ModuleNotHooked rule is the pre-hook's business, read separately)
            _slot = MODULES_HEAD_SLOT;
            if (v_ == bytes32(uint256(1))) v_ = bytes32(uint256(2));
        } else if (_w == 5) {
            _slot = FALLBACK_SLOT; // any word, dirty bits included
        } else if (_w == 6) {
            _slot = GUARD_SLOT;
        } else if (_w == 7) {
            _slot = MODULE_GUARD_SLOT;
        } else {
            _slot = bytes32(uint256(5)); // nonce: out of scope by design
            _covered = false;
        }
        _old = vm.load(address(safe), _slot);
        vm.store(address(safe), _slot, v_);
        bytes32 _after = _digest();
        if (_covered) {
            assertEq(_after != _before, v_ != _old, "covered component: digest moves iff the word moved");
        } else {
            assertEq(_after, _before, "the nonce is outside the digest");
        }
        assertEq(_after, _referenceDigest(), "reference agrees after");
        // Writing the old value back restores the digest exactly (the extra link of case 1 is a dangling
        // mapping entry: invisible to the digest by design, docs section 6 "Snapshot scope").
        vm.store(address(safe), _slot, _old);
        assertEq(_digest(), _before, "deterministic");
    }

    /// @dev The post-hook sees exactly what the digest sees: a covered write between the hooks is
    ///      `SafeConfigChanged`, an uncovered one passes, for a random word.
    /// forge-config: default.fuzz.runs = 300
    function testFuzz_post_hook_follows_the_digest(uint8 which_, bytes32 v_) public {
        uint256 _w = which_ % 5;
        bytes32 _slot = _w == 0 ? bytes32(uint256(4)) : _w == 1 ? FALLBACK_SLOT : _w == 2 ? GUARD_SLOT : _w == 3 ? MODULE_GUARD_SLOT : bytes32(uint256(5));
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.prank(address(safe));
        h.checkTransaction(address(protocol), 0, _data, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", curator);
        bytes32 _old = vm.load(address(safe), _slot);
        vm.store(address(safe), _slot, v_);
        vm.prank(address(safe));
        if (_w != 4 && v_ != _old) vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(safe)));
        h.checkAfterExecution(bytes32(0), true);
        vm.store(address(safe), _slot, _old);
    }
}
