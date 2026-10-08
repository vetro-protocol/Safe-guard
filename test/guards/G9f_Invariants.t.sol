// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {PolicyHandler} from "test/guards/CuratorGuardInvariants.t.sol";
import {G9fHarness} from "test/guards/G9fBase.sol";

/// @title Round 9 (g9f): the repository's policy handler, extended with the ghosts the existing
///        invariant suite does not carry.
/// @dev New actions: a curator execution over a WIDER universe (rule-bearing venue calls with and
///      without value, `approve` with every candidate spender, the rejection self-call, a weakening
///      self-call, a call aimed at the guard) that is first dry-run and then executed through the real
///      Safe, a `MultiSendCallOnly` batch of such entries, a guardian lockdown and a council approval.
///      New ghosts: (1) the dry run and the live hook agree byte for byte (docs section 4: "view
///      replicas of the pre-check"); (2) a batch passes exactly when the mode, the unwrapper
///      registration and every entry's own verdict say so (the documented composition); (3) no curator
///      transaction that passed, whatever its outcome, moved the Safe's configuration digest (the
///      handler's universe has no approved self-call, so the snapshot rule must hold on every success);
///      (4) a lockdown always closes the window, moves `lockedAt` and reads as `Lockdown`; (5) a council
///      approval never lasts longer than `MAX_COUNCIL_APPROVAL_TTL`.
contract G9fHandler is PolicyHandler {
    G9fHarness internal immutable h;

    bool public dryRunDisagreed;
    bool public batchMismatch;
    bool public digestMoved;
    bool public windowNotClosed;
    bool public councilCapBreached;
    uint256 public checkedExecs;
    uint256 public checkedSuccesses;
    uint256 public batchExecs;
    uint256 public batchSuccesses;
    uint256 public lockdownChecks;
    uint256 public capChecks;
    uint256 public venueFailures;
    bytes public lastDryError;
    bytes public lastLiveError;

    constructor(
        G9fHarness guard_,
        address safe_,
        address owner_,
        address council_,
        address guardian_,
        address globalGuardian_,
        address stranger_,
        uint256 curatorPk_,
        address[3] memory targets_,
        address[2] memory unwrappers_
    ) PolicyHandler(guard_, safe_, owner_, council_, guardian_, globalGuardian_, stranger_, curatorPk_, targets_, unwrappers_) {
        h = guard_;
    }

    /*//////////////////////////////////////////////////////////////
                                UNIVERSE
    //////////////////////////////////////////////////////////////*/

    /// @dev One call of the wider universe. None of them is ever an approved payload (approvals cover
    ///      `payloads[0..2]`: `settleDeposit(1)`, `transfer(stranger, 1)` and the empty call to the third
    ///      venue), so an entry's own dry run is its policy verdict.
    function _call(uint256 seed_) internal view returns (address _to, uint256 _value, bytes memory _data) {
        uint256 _k = seed_ % 8;
        uint256 _r = seed_ >> 8;
        if (_k == 0) {
            _to = targets[0];
            _data = abi.encodeCall(MockProtocol.settleDeposit, (2 + (_r % 5)));
        } else if (_k == 1) {
            _to = targets[0];
            _data = abi.encodeCall(MockProtocol.deposit, (_r % 7, _r % 3 == 0 ? stranger : safe));
        } else if (_k == 2) {
            _to = targets[1];
            _data = abi.encodeCall(IERC20.approve, (address(uint160(uint256(values[_r % 4]))), (_r >> 8) % 10));
        } else if (_k == 3) {
            _to = safe; // Safe{Wallet}'s rejection
        } else if (_k == 4) {
            _to = safe;
            _data = abi.encodeWithSignature("changeThreshold(uint256)", uint256(1)); // a weakening self-call (no-op value)
        } else if (_k == 5) {
            _to = address(guard);
            _data = abi.encodeCall(CuratorGuardPolicy.lockdown, (safe));
        } else if (_k == 6) {
            _to = targets[2];
            _data = abi.encodeCall(MockProtocol.settleDeposit, (2 + (_r % 5)));
        } else {
            _to = targets[0];
            _data = abi.encodeCall(MockProtocol.wrap, ());
        }
        if (_k < 3 || _k == 7) _value = (_r >> 16) % 3 == 0 ? 1 : 0;
    }

    function _hashOf(address to_, uint256 value_, bytes memory data_, Operation op_, uint256 nonce_) internal view returns (bytes32) {
        bytes32 _domain = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, safe));
        bytes32 _structHash = keccak256(
            abi.encode(SAFE_TX_TYPEHASH, to_, value_, keccak256(data_), uint8(op_), uint256(0), uint256(0), uint256(0), address(0), address(0), nonce_)
        );
        return keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), _domain, _structHash));
    }

    function _sig(bytes32 hash_) internal view returns (bytes memory) {
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(curatorPk, hash_);
        return abi.encodePacked(_r, _s, _v);
    }

    function _digest() internal view returns (bytes32 _d) {
        (_d, , ) = h.configDigest(safe);
    }

    function _exec(address to_, uint256 value_, bytes memory data_, Operation op_) internal returns (bool _ok, bytes memory _err) {
        bytes memory _s = _sig(_hashOf(to_, value_, data_, op_, ISafe(safe).nonce()));
        try ISafe(safe).execTransaction(to_, value_, data_, op_, 0, 0, 0, address(0), payable(address(0)), _s) returns (bool _r) {
            _ok = _r;
        } catch (bytes memory _e) {
            _err = _e;
        }
    }

    /*//////////////////////////////////////////////////////////////
                             NEW ACTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Dry run, then the real Safe: the two verdicts (and their error bytes) must agree; a success
    ///      must not move the digest; the existing Lockdown / window ghosts are fed as well.
    function g9f_curator_exec_checked(uint256 seed_) external {
        (address _to, uint256 _value, bytes memory _data) = _call(seed_);
        bool _dryOk;
        bytes memory _dryErr;
        try guard.validateTransaction(safe, _to, _value, _data, Operation.Call) {
            _dryOk = true;
        } catch (bytes memory _e) {
            _dryErr = _e;
        }
        CuratorGuardPolicy.Mode _mode = guard.mode(safe);
        bytes32 _before = _digest();
        ++checkedExecs;
        (bool _liveOk, bytes memory _liveErr) = _exec(_to, _value, _data, Operation.Call);
        if (_liveOk) {
            ++checkedSuccesses;
            if (_mode == CuratorGuardPolicy.Mode.Lockdown) lockdownBreached = true; // no approval in this universe
            if (_digest() != _before) digestMoved = true;
        }
        // The dry run replicates the PRE-check: a venue refusing the call (value sent to a non-payable
        // function) is the Safe's GS013 after the guard passed, so it must come with a passing dry run.
        if (!_liveOk && keccak256(_liveErr) == keccak256(abi.encodeWithSignature("Error(string)", "GS013"))) {
            ++venueFailures;
            if (!_dryOk) _disagree(_dryErr, _liveErr);
        } else if (_dryOk != _liveOk || (!_dryOk && keccak256(_dryErr) != keccak256(_liveErr))) {
            _disagree(_dryErr, _liveErr);
        }
        _epochCheck();
    }

    function _disagree(bytes memory dry_, bytes memory live_) internal {
        dryRunDisagreed = true;
        lastDryError = dry_;
        lastLiveError = live_;
    }

    /// @dev A 1-3 entry batch through a registered (or not) unwrapper. Expected verdict, from the docs:
    ///      Lockdown refuses; an admin window checks nothing; a council window needs the registered,
    ///      allowed unwrapper and every entry off the guard and (self-calls) on the council allowlist;
    ///      Enforced needs the registered, allowed unwrapper and every entry's own dry run to pass.
    function g9f_curator_exec_batch(uint256 seed_) external {
        address _unwrapper = unwrappers[seed_ % 2];
        (bytes memory _batch, bool _entriesOk, bool _councilOk, bool _guardEntry) = _buildBatch(seed_);
        bool _expected = _expectedBatch(_unwrapper, _entriesOk, _councilOk, _guardEntry);
        CuratorGuardPolicy.Mode _mode = guard.mode(safe);
        bytes32 _before = _digest();
        ++batchExecs;
        (bool _liveOk, ) = _exec(_unwrapper, 0, _batch, Operation.DelegateCall);
        if (_liveOk) {
            ++batchSuccesses;
            if (_mode == CuratorGuardPolicy.Mode.Lockdown) lockdownBreached = true;
            if (_digest() != _before) digestMoved = true;
        }
        if (_liveOk != _expected) batchMismatch = true;
        _epochCheck();
    }

    /// @dev 1-3 entries of the universe; `entriesOk` is the conjunction of their own dry runs,
    ///      `councilOk` whether every entry keeps off the guard and off weakening self-calls.
    function _buildBatch(uint256 seed_) internal view returns (bytes memory _batch, bool _entriesOk, bool _councilOk, bool _guardEntry) {
        bytes memory _packed;
        _entriesOk = true;
        _councilOk = true;
        uint256 _n = 1 + (seed_ >> 4) % 3;
        for (uint256 i; i < _n; ++i) {
            uint256 _s = uint256(keccak256(abi.encode(seed_, i)));
            if (_s % 8 == 5 && i > 0) _s += 1; // keep the guard entry rare: the first slot only
            (address _to, , bytes memory _data) = _call(_s);
            uint256 _value; // batch entries carry no value: a venue refusing value is the Safe's GS013, not a verdict
            _packed = abi.encodePacked(_packed, uint8(0), _to, _value, _data.length, _data);
            if (_entriesOk && !_dryOk(_to, _value, _data)) _entriesOk = false;
            if (_to == address(guard)) {
                _councilOk = false;
                _guardEntry = true;
            } else if (_to == safe && _data.length != 0) _councilOk = false; // changeThreshold(1): below the council floor
        }
        _batch = abi.encodeWithSelector(bytes4(0x8d80ff0a), _packed);
    }

    function _dryOk(address to_, uint256 value_, bytes memory data_) internal view returns (bool) {
        try guard.validateTransaction(safe, to_, value_, data_, Operation.Call) {
            return true;
        } catch {
            return false;
        }
    }

    /// @dev Docs: Lockdown refuses; an admin window checks nothing (so an entry addressed to the guard
    ///      is not refused by the hook but EXECUTES, and fails as a venue call: the Safe is no guardian
    ///      of itself, so the batch dies on GS013); a council window needs the registered, allowed
    ///      unwrapper and council-clean entries; Enforced needs the registered, allowed unwrapper and
    ///      every entry's own verdict.
    function _expectedBatch(address unwrapper_, bool entriesOk_, bool councilOk_, bool guardEntry_) internal view returns (bool) {
        bool _registered = _has(guard.multiSendUnwrappers(safe), unwrapper_) && guard.isUnwrapperCodehash(unwrapper_.codehash);
        CuratorGuardPolicy.Mode _mode = guard.mode(safe);
        if (_mode == CuratorGuardPolicy.Mode.Enforced) return _registered && entriesOk_;
        if (_mode == CuratorGuardPolicy.Mode.Bypass) {
            (, bool _council) = guard.bypassWindow(safe);
            return _council ? (_registered && councilOk_) : !guardEntry_;
        }
        return false;
    }

    /// @dev A guardian lockdown ends any window at once and starts the cooldown.
    function g9f_guardian_lockdown_closes_the_window() external narrowOnly {
        guard.lockdown(safe);
        ++lockdownChecks;
        (uint64 _until, bool _council) = guard.bypassWindow(safe);
        if (_until != 0 || _council) windowNotClosed = true;
        if (guard.mode(safe) != CuratorGuardPolicy.Mode.Lockdown) windowNotClosed = true;
        if (guard.lockedAt(safe) != uint64(block.timestamp)) windowNotClosed = true;
    }

    /// @dev A council approval is capped at 7 days whatever `ttl` is asked for.
    function g9f_council_approve_checks_the_cap(uint256 seed_) external councilAction {
        if (guard.mode(safe) == CuratorGuardPolicy.Mode.Bypass) return;
        ++capChecks;
        uint256 _p = seed_ % 3;
        uint64 _ttl = uint64(1 hours + (seed_ >> 8) % uint256(7 days - 1 hours));
        bytes32 _id = guard.approveTransaction(safe, address(0), targets[_p], 0, payloads[_p], Operation.Call, _ttl);
        approvedEpoch[_p] = guard.approvalEpoch(safe) + 1;
        if (guard.approvalExpiry(_id) > block.timestamp + 7 days) councilCapBreached = true;
        if (_tryApprove(_p, uint64(7 days + 1 + (seed_ >> 64) % 1000))) councilCapBreached = true;
    }

    function _tryApprove(uint256 p_, uint64 ttl_) internal returns (bool _ok) {
        bytes memory _c = abi.encodeCall(guard.approveTransaction, (safe, address(0), targets[p_], 0, payloads[p_], Operation.Call, ttl_));
        (_ok, ) = address(guard).call(_c);
    }
}

contract CuratorGuardG9fInvariantsTest is CuratorGuardTestBase {
    G9fHandler internal handler;

    function setUp() public override {
        super.setUp();
        // The fixture guard is swapped for the g9f harness (same code plus a digest probe), installed
        // on the Safe the way an admin-window swap would do it.
        G9fHarness _h = new G9fHarness(0, vetro, council);
        _h.seedSafe(address(safe));
        vm.prank(address(safe));
        safe.setGuard(address(_h));
        guard = _h;
        MockProtocol _third = new MockProtocol();
        address _globalGuardian = makeAddr("global-guardian");
        handler = new G9fHandler(
            _h,
            address(safe),
            vetro,
            council,
            guardian,
            _globalGuardian,
            attacker,
            signerPk,
            [address(protocol), address(token), address(_third)],
            [address(multiSendCallOnly), address(multiSend)]
        );
        vm.startPrank(vetro);
        guard.setGuardian(address(safe), guardian, true);
        guard.setDeploymentGuardian(_globalGuardian, true);
        vm.stopPrank();
        _seedCodehash(address(multiSendCallOnly).codehash);
        _seedCodehash(address(multiSend).codehash);
        targetContract(address(handler));
    }

    // The repository's ghosts, carried over so the wider universe feeds them too.
    function invariant_g9f_repository_ghosts_still_hold() public view {
        assertFalse(handler.widened(), "a guardian action widened the policy");
        assertFalse(handler.councilWidened(), "a council action widened the allowlist");
        assertFalse(handler.strangerSucceeded(), "a stranger call succeeded or changed state");
        assertFalse(handler.epochDecreased(), "epoch decreased");
        assertFalse(handler.approvalConsumedInBypass(), "approval consumed inside a window");
        assertFalse(handler.lockdownBreached(), "a transaction succeeded under Lockdown without an approval");
        assertFalse(handler.eventMismatch(), "TransactionChecked missing, duplicated or wrong");
        assertFalse(handler.cooldownBreached(), "an admin lift / window / approval landed inside the cooldown");
        assertEq(guard.approvalEpoch(address(safe)), handler.epochBumps(), "every bump counted");
    }

    /// @dev Docs section 4: `validateTransaction` is a view replica of the pre-check.
    function invariant_g9f_dry_run_agrees_with_the_live_hook() public view {
        assertFalse(handler.dryRunDisagreed(), "dry run and live hook disagreed");
    }

    /// @dev A batch is exactly the conjunction of its entries under the mode's rules.
    function invariant_g9f_batches_compose_from_their_entries() public view {
        assertFalse(handler.batchMismatch(), "a batch verdict differed from the composed one");
    }

    /// @dev Nothing in the universe is an approved self-call: no passed transaction moves the digest.
    function invariant_g9f_passed_transactions_never_move_the_configuration() public view {
        assertFalse(handler.digestMoved(), "a passed transaction changed the Safe's configuration");
    }

    function invariant_g9f_lockdown_closes_windows_and_starts_the_cooldown() public view {
        assertFalse(handler.windowNotClosed(), "a lockdown left a window open or lockedAt stale");
    }

    function invariant_g9f_council_approvals_respect_the_cap() public view {
        assertFalse(handler.councilCapBreached(), "a council approval exceeded 7 days");
    }

    /// @dev Liveness anchor: every new action executes and reaches its interesting branch at least once
    ///      deterministically, so the invariants above cannot hold vacuously.
    function test_g9f_handler_actions_are_live() public {
        handler.owner_allowFunction(0); // targets[0].settleDeposit, no rules
        handler.owner_setMode(1); // enforce
        handler.g9f_curator_exec_checked(1 << 24); // settleDeposit(3), no value: passes
        handler.g9f_curator_exec_checked(0); // settleDeposit(2) with 1 wei: ValueNotAllowed on both
        handler.g9f_curator_exec_checked(3); // rejection self-call: passes
        handler.g9f_curator_exec_checked(4); // changeThreshold(1): refused
        handler.g9f_curator_exec_checked(5); // guard target: refused
        handler.owner_allowFunction(9); // targets[0].settleDeposit with allowValue
        handler.g9f_curator_exec_checked(0); // the guard passes 1 wei, the non-payable venue refuses: GS013
        assertEq(handler.checkedExecs(), 6);
        assertEq(handler.checkedSuccesses(), 2);
        assertEq(handler.venueFailures(), 1, "a GS013 after a passing dry run is agreement");
        assertFalse(handler.dryRunDisagreed(), "agreement");
        assertFalse(handler.digestMoved());
        handler.owner_setUnwrapper(0); // multiSendCallOnly
        handler.g9f_curator_exec_batch(0); // entries of allowed shape
        assertEq(handler.batchExecs(), 1);
        assertFalse(handler.batchMismatch(), "composition");
        handler.council_bypass(0);
        handler.g9f_guardian_lockdown_closes_the_window();
        assertEq(handler.lockdownChecks(), 1);
        assertFalse(handler.windowNotClosed());
        handler.g9f_council_approve_checks_the_cap(1);
        assertEq(handler.capChecks(), 1);
        assertFalse(handler.councilCapBreached());
        assertEq(guard.approvalEpoch(address(safe)), handler.epochBumps());
    }
}
