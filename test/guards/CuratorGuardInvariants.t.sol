// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {CuratorGuardHarness, CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @title Policy handler: admin widens, council runs the fast lane, guardian narrows, stranger tries
///        everything, time passes.
/// @dev Universe: 3 targets x 3 selectors x 2 words x 4 values, 3 native targets, 2 unwrappers,
///      2 modules, 3 approval payloads, mode. `mask()` folds the whole permissive surface into one
///      uint256 so "narrow-only" is `after & ~before == 0`; `allowlistMask()` is the subset the
///      council must never grow (it may change mode and approvals, never the allowlist).
contract PolicyHandler {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    CuratorGuard public immutable guard;
    address public immutable safe;
    address public immutable owner;
    address public immutable council;
    address public immutable guardian;
    address public immutable globalGuardian;
    address public immutable stranger;
    uint256 internal immutable curatorPk;

    /// @dev Bits of `mask()` that describe the allowlist (targets, values, native, unwrappers, modules):
    ///      3 targets x (3 selectors x (allowed + allowValue + 2 words x 4 values) + native) + 2 x 2.
    uint256 internal constant ALLOWLIST_BITS = 3 * (3 * 10 + 1) + 4;

    address[3] public targets;
    bytes4[3] public selectors;
    bytes32[4] public values;
    address[2] public unwrappers;
    address[2] public modules;
    bytes[3] public payloads;

    bool public widened;
    bool public councilWidened;
    bool public strangerSucceeded;
    bool public epochDecreased;
    /// @dev Hook-level ghosts: an approval consumed while the Safe was in Bypass, or a success under
    ///      Lockdown without an approval being consumed.
    bool public approvalConsumedInBypass;
    bool public lockdownBreached;
    /// @dev A passed curator transaction was not reported by exactly one `TransactionChecked` carrying
    ///      the Safe, its `safeTxHash`, the owner path and the outcome the handler predicted.
    bool public eventMismatch;
    /// @dev An admin lift, window or approval succeeded inside the lockdown cooldown.
    bool public cooldownBreached;
    uint256 public cooldownProbes;
    uint256 public curatorExecs;
    uint256 public curatorSuccesses;
    /// @dev Every epoch bump: `revokeAllApprovals` (owner or guardian) and every `bypass` window.
    uint256 public epochBumps;
    uint256 public lastEpoch;
    uint256[3] public approvedEpoch; // epoch at which payload i was last approved (+1), 0 = never
    uint256 public guardianCalls;
    uint256 public ownerCalls;
    uint256 public councilCalls;

    constructor(
        CuratorGuard guard_,
        address safe_,
        address owner_,
        address council_,
        address guardian_,
        address globalGuardian_,
        address stranger_,
        uint256 curatorPk_,
        address[3] memory targets_,
        address[2] memory unwrappers_
    ) {
        guard = guard_;
        safe = safe_;
        owner = owner_;
        council = council_;
        guardian = guardian_;
        globalGuardian = globalGuardian_;
        curatorPk = curatorPk_;
        stranger = stranger_;
        targets = targets_;
        unwrappers = unwrappers_;
        selectors = [MockProtocol.settleDeposit.selector, MockProtocol.deposit.selector, IERC20.approve.selector];
        values = [bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(uint160(safe_))), bytes32(uint256(uint160(stranger_)))];
        modules = [address(0xA11CE), address(0xB0B)];
        payloads[0] = abi.encodeCall(MockProtocol.settleDeposit, (1));
        payloads[1] = abi.encodeCall(IERC20.transfer, (stranger_, 1));
        payloads[2] = "";
    }

    /*//////////////////////////////////////////////////////////////
                              GHOST STATE
    //////////////////////////////////////////////////////////////*/

    function mask() public view returns (uint256 _m) {
        uint256 _bit;
        for (uint256 t; t < 3; ++t) {
            for (uint256 s; s < 3; ++s) {
                (bool _allowed, bool _allowValue, ) = guard.functionPermission(safe, targets[t], selectors[s]);
                if (_allowed) _m |= 1 << _bit;
                ++_bit;
                if (_allowValue) _m |= 1 << _bit;
                ++_bit;
                for (uint16 w; w < 2; ++w) {
                    bytes32[] memory _set = guard.allowedValues(safe, targets[t], selectors[s], w);
                    for (uint256 v; v < 4; ++v) {
                        for (uint256 k; k < _set.length; ++k) {
                            if (_set[k] == values[v]) _m |= 1 << _bit;
                        }
                        ++_bit;
                    }
                }
            }
            if (guard.isNativeTransferAllowed(safe, targets[t])) _m |= 1 << _bit;
            ++_bit;
        }
        for (uint256 u; u < 2; ++u) {
            if (_has(guard.multiSendUnwrappers(safe), unwrappers[u])) _m |= 1 << _bit;
            ++_bit;
            if (_has(guard.modules(safe), modules[u])) _m |= 1 << _bit;
            ++_bit;
        }
        for (uint256 p; p < 3; ++p) {
            if (guard.approvalExpiry(_id(p)) != 0) _m |= 1 << _bit;
            ++_bit;
        }
        CuratorGuardPolicy.Mode _mode = guard.mode(safe);
        if (_mode != CuratorGuardPolicy.Mode.Lockdown) _m |= 1 << _bit;
        ++_bit;
        if (_mode == CuratorGuardPolicy.Mode.Bypass) _m |= 1 << _bit;
        ++_bit;
        // Role surface (a guardian must never be able to grow it): stranger as per-Safe or
        // deployment-wide guardian, stranger as council; a RELAXED handler requirement.
        if (_has(guard.guardians(safe), stranger)) _m |= 1 << _bit;
        ++_bit;
        if (guard.hasRole(guard.GUARDIAN_ROLE(), stranger)) _m |= 1 << _bit;
        ++_bit;
        if (guard.hasRole(guard.COUNCIL_ROLE(), stranger)) _m |= 1 << _bit;
        ++_bit;
        (, bool _enforce) = guard.requiredFallbackHandler(safe);
        if (!_enforce) _m |= 1 << _bit;
        ++_bit;
        require(_bit < 256, "universe too large");
        require(_bit == ALLOWLIST_BITS + 9, "bit layout drifted");
    }

    /// @dev `mask()` minus the approval, mode and role bits (the last 9 bits).
    function allowlistMask() public view returns (uint256) {
        return mask() & ~(uint256(0x1ff) << (ALLOWLIST_BITS));
    }

    function _has(address[] memory list_, address a_) internal pure returns (bool) {
        for (uint256 i; i < list_.length; ++i) if (list_[i] == a_) return true;
        return false;
    }

    function _id(uint256 p_) internal view returns (bytes32) {
        return guard.computeApprovalId(safe, address(0), targets[p_ % 3], 0, payloads[p_], Operation.Call);
    }

    function _epochCheck() internal {
        uint256 _e = guard.approvalEpoch(safe);
        if (_e < lastEpoch) epochDecreased = true;
        lastEpoch = _e;
    }

    modifier narrowOnly() {
        uint256 _before = mask();
        vm.startPrank(guardian);
        _;
        vm.stopPrank();
        uint256 _after = mask();
        if (_after & ~_before != 0) widened = true;
        _epochCheck();
        ++guardianCalls;
    }

    modifier ownerAction() {
        vm.startPrank(owner);
        _;
        vm.stopPrank();
        _epochCheck();
        ++ownerCalls;
    }

    modifier councilAction() {
        uint256 _before = allowlistMask();
        vm.startPrank(council);
        _;
        vm.stopPrank();
        if (allowlistMask() & ~_before != 0) councilWidened = true;
        _epochCheck();
        ++councilCalls;
    }

    /*//////////////////////////////////////////////////////////////
                             OWNER (widen)
    //////////////////////////////////////////////////////////////*/

    function _rules(uint256 seed_) internal view returns (CuratorGuardPolicy.ParamRule[] memory _r) {
        uint256 _kind = seed_ % 5;
        if (_kind == 0) return _r;
        if (_kind == 1) {
            _r = new CuratorGuardPolicy.ParamRule[](1);
            _r[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, uint16(seed_ / 5 % 2), 0);
        } else if (_kind == 2) {
            _r = new CuratorGuardPolicy.ParamRule[](1);
            _r[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 1, bytes32(uint256(1e6)));
        } else if (_kind == 3) {
            _r = new CuratorGuardPolicy.ParamRule[](1);
            _r[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualToSafe, 1, 0);
        } else {
            _r = new CuratorGuardPolicy.ParamRule[](2);
            _r[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.GreaterThanOrEqual, 0, bytes32(uint256(1)));
            _r[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, 0, 0);
        }
    }

    function owner_allowFunction(uint256 seed_) external ownerAction {
        guard.allowFunction(safe, targets[seed_ % 3], selectors[seed_ / 3 % 3], seed_ / 9 % 2 == 1, _rules(seed_ / 18));
    }

    function owner_addValues(uint256 seed_) external ownerAction {
        address _t = targets[seed_ % 3];
        bytes4 _s = selectors[seed_ / 3 % 3];
        uint16 _w = uint16(seed_ / 9 % 2);
        (bool _allowed, , CuratorGuardPolicy.ParamRule[] memory _r) = guard.functionPermission(safe, _t, _s);
        bool _has;
        for (uint256 i; i < _r.length; ++i) {
            if (_r[i].kind == CuratorGuardPolicy.RuleKind.OneOf && _r[i].wordIndex == _w) _has = true;
        }
        if (!_allowed || !_has) return; // would revert NoOneOfRule
        bytes32[] memory _vals = new bytes32[](1 + seed_ / 18 % 3);
        for (uint256 i; i < _vals.length; ++i) _vals[i] = values[(seed_ / 54 + i) % 4];
        guard.addAllowedValues(safe, _t, _s, _w, _vals);
    }

    function owner_setNative(uint256 seed_) external ownerAction {
        guard.setNativeTransferAllowed(safe, targets[seed_ % 3], true);
    }

    function owner_setUnwrapper(uint256 seed_) external ownerAction {
        // A deployment-wide guardian may have forbidden the (seeded) hash meanwhile: the admin re-allows
        // it before registering, exactly as the runbook says.
        guard.setUnwrapperCodehash(unwrappers[seed_ % 2].codehash, true);
        guard.setMultiSendUnwrapper(safe, unwrappers[seed_ % 2], true);
    }

    function owner_setModule(uint256 seed_) external ownerAction {
        guard.setModuleAllowed(safe, modules[seed_ % 2], true);
    }

    /// @dev Inside the cooldown that follows every lockdown the admin's lifts, windows and approvals are
    ///      refused (`LockdownCooldown`); the handler skips them there and probes them separately.
    function _cooling() internal view returns (bool) {
        return block.timestamp <= uint256(CuratorGuardHarness(address(guard)).lockedAt(safe)) + 1 days;
    }

    function owner_setMode(uint256 seed_) external ownerAction {
        uint256 _which = seed_ % 3;
        if (_which == 0) guard.lockdown(safe);
        else if (_cooling()) return;
        else if (_which == 1) guard.enforce(safe);
        else {
            guard.bypass(safe, uint64(1 hours + ((seed_ / 3) % uint256(180 days - 1 hours))));
            ++epochBumps;
        }
    }

    /// @dev During the cooldown every admin lift, window and approval must revert.
    function owner_probes_the_cooldown(uint256 seed_) external ownerAction {
        if (!_cooling()) return;
        ++cooldownProbes;
        bytes[3] memory _calls;
        _calls[0] = abi.encodeCall(guard.enforce, (safe));
        _calls[1] = abi.encodeCall(guard.bypass, (safe, uint64(1 days)));
        _calls[2] = abi.encodeCall(
            guard.approveTransaction,
            (safe, address(0), targets[seed_ % 3], 0, payloads[seed_ % 3], Operation.Call, uint64(1 days))
        );
        for (uint256 i; i < _calls.length; ++i) {
            (bool _ok, ) = address(guard).call(_calls[i]);
            if (_ok) cooldownBreached = true;
        }
    }

    function owner_approve(uint256 seed_) external ownerAction {
        if (_cooling()) return; // refused by design (LockdownCooldown)
        if (guard.mode(safe) == CuratorGuardPolicy.Mode.Bypass) return; // refused by design (SafeInBypass)
        uint256 _p = seed_ % 3;
        guard.approveTransaction(safe, address(0), targets[_p], 0, payloads[_p], Operation.Call, uint64(1 hours + (seed_ % 1000)));
        approvedEpoch[_p] = guard.approvalEpoch(safe) + 1;
    }

    function owner_revokeAll() external ownerAction {
        guard.revokeAllApprovals(safe);
        ++epochBumps;
    }

    function owner_setHandlerRequirement(uint256 seed_) external ownerAction {
        guard.setRequiredFallbackHandler(safe, address(0), seed_ % 2 == 0);
    }

    /*//////////////////////////////////////////////////////////////
                           COUNCIL (fast lane)
    //////////////////////////////////////////////////////////////*/

    function council_enforce() external councilAction {
        guard.enforce(safe);
    }

    function council_lockdown() external councilAction {
        guard.lockdown(safe);
    }

    function council_lockdownAndRevoke() external councilAction {
        guard.lockdownAndRevoke(safe);
        ++epochBumps;
    }

    function council_bypass(uint256 seed_) external councilAction {
        guard.bypass(safe, uint64(1 hours + (seed_ % uint256(7 days - 1 hours))));
        ++epochBumps;
    }

    function council_approve(uint256 seed_) external councilAction {
        if (guard.mode(safe) == CuratorGuardPolicy.Mode.Bypass) return;
        uint256 _p = seed_ % 3;
        guard.approveTransaction(safe, address(0), targets[_p], 0, payloads[_p], Operation.Call, uint64(1 hours + (seed_ % uint256(7 days - 1 hours))));
        approvedEpoch[_p] = guard.approvalEpoch(safe) + 1;
    }

    function council_revokeFunction(uint256 seed_) external councilAction {
        guard.revokeFunction(safe, targets[seed_ % 3], selectors[(seed_ / 3) % 3]);
    }

    function council_revokeAll() external councilAction {
        guard.revokeAllApprovals(safe);
        ++epochBumps;
    }

    function council_setGuardian(uint256 seed_) external councilAction {
        guard.setGuardian(safe, stranger, seed_ % 2 == 0);
    }

    /*//////////////////////////////////////////////////////////////
                        CURATOR (drives the real Safe)
    //////////////////////////////////////////////////////////////*/

    bytes32 internal constant DOMAIN_SEPARATOR_TYPEHASH =
        0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
    bytes32 internal constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    /// @dev Executes one of the three payloads through the genuine `execTransaction` (signed with the
    ///      curator key) and checks the hook-level ghosts: an approval is never consumed inside a
    ///      Bypass window, and nothing succeeds under Lockdown unless an approval was consumed.
    function curator_exec(uint256 seed_) external {
        uint256 _p = seed_ % 3;
        address _to = targets[_p % 3];
        bytes memory _data = payloads[_p];
        bytes32 _id = _id(_p);
        bool _live = guard.approvalExpiry(_id) != 0 && block.timestamp <= guard.approvalExpiry(_id);
        CuratorGuardPolicy.Mode _mode = guard.mode(safe);
        bytes32 _hash = _safeTxHash(_to, _data, ISafe(safe).nonce());
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(curatorPk, _hash);
        ++curatorExecs;
        vm.recordLogs();
        try
            ISafe(safe).execTransaction(_to, 0, _data, Operation.Call, 0, 0, 0, address(0), payable(address(0)), abi.encodePacked(_r, _s, _v))
        returns (bool _ok) {
            if (!_ok) return;
            ++curatorSuccesses;
            bool _consumed = _live && guard.approvalExpiry(_id) == 0;
            if (_consumed && _mode == CuratorGuardPolicy.Mode.Bypass) approvalConsumedInBypass = true;
            if (_mode == CuratorGuardPolicy.Mode.Lockdown && !_consumed) lockdownBreached = true;
            CuratorGuard.Outcome _expected = _consumed
                ? CuratorGuard.Outcome.Approval
                : (_mode == CuratorGuardPolicy.Mode.Bypass ? CuratorGuard.Outcome.Bypass : CuratorGuard.Outcome.Policy);
            _checkReported(_hash, _expected);
        } catch {
            // denied: fine
        }
        _epochCheck();
    }

    /// @dev Exactly one `TransactionChecked(safe, safeTxHash, 0, expected)` from the guard in the logs.
    function _checkReported(bytes32 hash_, CuratorGuard.Outcome expected_) internal {
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        uint256 _n;
        for (uint256 i; i < _logs.length; ++i) {
            if (_logs[i].emitter != address(guard) || _logs[i].topics[0] != CuratorGuard.TransactionChecked.selector) continue;
            ++_n;
            if (
                _logs[i].topics[1] != bytes32(uint256(uint160(safe))) ||
                _logs[i].topics[2] != hash_ ||
                _logs[i].topics[3] != bytes32(uint256(expected_)) ||
                keccak256(_logs[i].data) != keccak256(abi.encode(uint8(0)))
            ) eventMismatch = true;
        }
        if (_n != 1) eventMismatch = true;
    }

    function _safeTxHash(address to_, bytes memory data_, uint256 nonce_) internal view returns (bytes32) {
        bytes32 _domain = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, safe));
        bytes32 _structHash = keccak256(
            abi.encode(SAFE_TX_TYPEHASH, to_, uint256(0), keccak256(data_), uint8(0), uint256(0), uint256(0), uint256(0), address(0), address(0), nonce_)
        );
        return keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), _domain, _structHash));
    }

    /*//////////////////////////////////////////////////////////////
                                  TIME
    //////////////////////////////////////////////////////////////*/

    /// @dev Expiry of approvals and Bypass windows is time-driven, never an actor's doing.
    function time_passes(uint256 seed_) external {
        vm.warp(block.timestamp + 1 + (seed_ % 10 days));
    }

    /*//////////////////////////////////////////////////////////////
                           GUARDIAN (narrow)
    //////////////////////////////////////////////////////////////*/

    function guardian_lockdown() external narrowOnly {
        guard.lockdown(safe);
    }

    function guardian_lockdownAndRevoke() external narrowOnly {
        guard.lockdownAndRevoke(safe);
        ++epochBumps;
    }

    function guardian_revokeFunction(uint256 seed_) external narrowOnly {
        guard.revokeFunction(safe, targets[seed_ % 3], selectors[seed_ / 3 % 3]);
    }

    function guardian_revokeTarget(uint256 seed_) external narrowOnly {
        guard.revokeTarget(safe, targets[seed_ % 3]);
    }

    function guardian_removeValues(uint256 seed_) external narrowOnly {
        bytes32[] memory _vals = new bytes32[](1);
        _vals[0] = values[seed_ / 18 % 4];
        guard.removeAllowedValues(safe, targets[seed_ % 3], selectors[seed_ / 3 % 3], uint16(seed_ / 9 % 2), _vals);
    }

    function guardian_clearValues(uint256 seed_) external narrowOnly {
        guard.clearAllowedValues(safe, targets[seed_ % 3], selectors[seed_ / 3 % 3], uint16(seed_ / 9 % 2));
    }

    function guardian_disableNative(uint256 seed_) external narrowOnly {
        guard.setNativeTransferAllowed(safe, targets[seed_ % 3], false);
    }

    function guardian_disableUnwrapper(uint256 seed_) external narrowOnly {
        guard.setMultiSendUnwrapper(safe, unwrappers[seed_ % 2], false);
    }

    function guardian_disableModule(uint256 seed_) external narrowOnly {
        guard.setModuleAllowed(safe, modules[seed_ % 2], false);
    }

    function guardian_revokeApproval(uint256 seed_) external narrowOnly {
        bytes32 _i = _id(seed_ % 3);
        if (guard.approvalExpiry(_i) == 0) return; // would revert ApprovalNotFound
        guard.revokeApproval(_i);
    }

    /// @dev Attempts at the entry points a per-Safe guardian must not have; `narrowOnly` flags any
    ///      growth of the mask, the low-level calls swallow the expected reverts.
    function guardian_attempts_role_surface(uint256 seed_) external narrowOnly {
        bytes[5] memory _calls;
        _calls[0] = abi.encodeCall(guard.setGuardian, (safe, stranger, true));
        _calls[1] = abi.encodeCall(guard.setDeploymentGuardian, (stranger, true));
        _calls[2] = abi.encodeCall(guard.setRequiredFallbackHandler, (safe, address(0), false));
        _calls[3] = abi.encodeCall(guard.enforce, (safe));
        _calls[4] = abi.encodeCall(
            guard.executeBefore,
            (uint64(block.timestamp + 1), abi.encodeCall(guard.allowFunction, (safe, targets[seed_ % 3], selectors[0], true, _rules(0))))
        );
        for (uint256 i; i < _calls.length; ++i) {
            (bool _ok, ) = address(guard).call(_calls[i]);
            _ok; // reverts expected; any success shows up as a widened mask
        }
    }

    /// @dev The deployment-wide guardian: same narrow-only contract, every Safe.
    function global_guardian_narrows(uint256 seed_) external {
        uint256 _before = mask();
        vm.startPrank(globalGuardian);
        uint256 _which = seed_ % 5;
        if (_which == 0) guard.lockdown(safe);
        else if (_which == 1) guard.revokeFunction(safe, targets[(seed_ / 5) % 3], selectors[(seed_ / 15) % 3]);
        else if (_which == 2) guard.setUnwrapperCodehash(unwrappers[(seed_ / 5) % 2].codehash, false);
        else if (_which == 3) {
            guard.revokeAllApprovals(safe);
            ++epochBumps;
        } else {
            guard.lockdownAndRevoke(safe);
            ++epochBumps;
        }
        (bool _ok, ) = address(guard).call(abi.encodeCall(guard.setGuardian, (safe, stranger, true)));
        _ok;
        vm.stopPrank();
        if (mask() & ~_before != 0) widened = true;
        _epochCheck();
        ++guardianCalls;
    }

    function guardian_revokeAll() external narrowOnly {
        guard.revokeAllApprovals(safe);
        ++epochBumps;
    }

    /*//////////////////////////////////////////////////////////////
                        STRANGER (must all revert)
    //////////////////////////////////////////////////////////////*/

    function stranger_tries(uint256 seed_) external {
        uint256 _before = mask();
        uint256 _epochBefore = guard.approvalEpoch(safe);
        bytes[23] memory _calls;
        _calls[0] = abi.encodeCall(guard.allowFunction, (safe, targets[0], selectors[0], true, _rules(0)));
        CuratorGuardPolicy.FunctionSpec[] memory _specs = new CuratorGuardPolicy.FunctionSpec[](1);
        _specs[0] = CuratorGuardPolicy.FunctionSpec(targets[1], selectors[1], true, _rules(0));
        _calls[1] = abi.encodeCall(guard.allowFunctions, (safe, _specs));
        bytes32[] memory _vals = new bytes32[](1);
        _vals[0] = values[0];
        _calls[2] = abi.encodeCall(guard.addAllowedValues, (safe, targets[0], selectors[0], 0, _vals));
        _calls[3] = abi.encodeCall(guard.setNativeTransferAllowed, (safe, targets[0], seed_ % 2 == 0));
        _calls[4] = abi.encodeCall(guard.setMultiSendUnwrapper, (safe, unwrappers[0], seed_ % 2 == 0));
        _calls[5] = abi.encodeCall(guard.setModuleAllowed, (safe, modules[0], seed_ % 2 == 0));
        _calls[6] = abi.encodeCall(guard.enforce, (safe));
        _calls[7] = abi.encodeCall(guard.lockdown, (safe));
        _calls[8] = abi.encodeCall(guard.approveTransaction, (safe, address(0), targets[0], 0, payloads[0], Operation.Call, uint64(1)));
        _calls[9] = abi.encodeCall(guard.revokeApproval, (_id(0)));
        _calls[10] = abi.encodeCall(guard.revokeAllApprovals, (safe));
        _calls[11] = abi.encodeCall(guard.revokeTarget, (safe, targets[0]));
        _calls[12] = abi.encodeCall(guard.clearAllowedValues, (safe, targets[0], selectors[0], 0));
        _calls[13] = abi.encodeCall(guard.setGuardian, (safe, stranger, true));
        _calls[14] = abi.encodeCall(guard.bypass, (safe, uint64(1 days)));
        _calls[15] = abi.encodeCall(guard.grantRole, (guard.COUNCIL_ROLE(), stranger));
        _calls[16] = abi.encodeCall(guard.beginDefaultAdminTransfer, (stranger));
        _calls[17] = abi.encodeCall(guard.setDeploymentGuardian, (stranger, true));
        _calls[18] = abi.encodeCall(guard.setUnwrapperCodehash, (unwrappers[0].codehash, false));
        _calls[19] = abi.encodeCall(guard.setRequiredFallbackHandler, (safe, address(0), false));
        _calls[20] = abi.encodeCall(guard.changeDefaultAdminDelay, (uint48(1 days)));
        _calls[21] = abi.encodeCall(
            guard.executeBefore,
            (uint64(block.timestamp + 1), abi.encodeCall(guard.allowFunction, (safe, targets[0], selectors[0], true, _rules(0))))
        );
        _calls[22] = abi.encodeCall(guard.lockdownAndRevoke, (safe));
        // `council_setGuardian` may have made the stranger a per-Safe guardian: then its NARROWING calls
        // legitimately succeed, and the check degrades to "never widened".
        bool _isGuardian = guard.isGuardian(safe, stranger);
        vm.startPrank(stranger);
        for (uint256 i; i < _calls.length; ++i) {
            (bool _ok, ) = address(guard).call(_calls[i]);
            if (_ok && !_isGuardian) strangerSucceeded = true;
        }
        vm.stopPrank();
        if (_isGuardian) {
            if (mask() & ~_before != 0) strangerSucceeded = true;
            epochBumps += guard.approvalEpoch(safe) - _epochBefore; // a guardian's revokeAllApprovals / lockdownAndRevoke
        } else if (mask() != _before || guard.approvalEpoch(safe) != _epochBefore) {
            strangerSucceeded = true;
        }
    }
}

/// @title Policy invariants: guardians never widen, strangers never change state, epochs are monotonic,
///        bookkeeping views are consistent, `OneOf` sets never outlive their rule.
contract CuratorGuardInvariantsTest is CuratorGuardTestBase {
    PolicyHandler internal handler;

    function setUp() public override {
        super.setUp();
        MockProtocol _third = new MockProtocol();
        address _globalGuardian = makeAddr("global-guardian");
        handler = new PolicyHandler(
            guard,
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
        // Locally compiled MultiSend builds are not canonical: seed their code through the harness so
        // the handler can register them.
        _seedCodehash(address(multiSendCallOnly).codehash);
        _seedCodehash(address(multiSend).codehash);
        targetContract(address(handler));
    }

    function invariant_guardian_actions_never_widen_the_policy() public view {
        assertFalse(handler.widened(), "a guardian action widened the policy");
    }

    function invariant_strangers_never_change_anything() public view {
        assertFalse(handler.strangerSucceeded(), "a stranger call succeeded or changed state");
    }

    function invariant_approval_epoch_is_monotonic_and_counts_every_bump() public view {
        assertFalse(handler.epochDecreased());
        assertEq(guard.approvalEpoch(address(safe)), handler.epochBumps());
    }

    function invariant_council_actions_never_widen_the_allowlist() public view {
        assertFalse(handler.councilWidened(), "a council action widened the allowlist");
    }

    /// @dev Hook-level: approvals are never consumed inside a Bypass window and Lockdown is never
    ///      breached without one (driven through the genuine `execTransaction`).
    function invariant_hooks_respect_bypass_and_lockdown() public view {
        assertFalse(handler.approvalConsumedInBypass(), "approval consumed inside a Bypass window");
        assertFalse(handler.lockdownBreached(), "a transaction succeeded under Lockdown without an approval");
    }

    /// @dev Every passed curator transaction is reported by exactly one `TransactionChecked` whose
    ///      hash is the Safe's `safeTxHash` and whose outcome matches how it got through.
    function invariant_every_passed_transaction_is_reported_once_with_its_outcome() public view {
        assertFalse(handler.eventMismatch(), "TransactionChecked missing, duplicated or wrong");
    }

    /// @dev No admin lift, window or approval ever lands inside the day that follows a lockdown.
    function invariant_admin_actions_respect_the_lockdown_cooldown() public view {
        assertFalse(handler.cooldownBreached(), "an admin lift / window / approval landed inside the cooldown");
    }

    /// @dev Deterministic liveness anchor for the reporting ghost: the handler's curator path really
    ///      executes and is reported for each outcome, so the fuzz invariant above cannot hold vacuously
    ///      (it would if every curator execution reverted, e.g. after an EIP-712 replica drift).
    function test_handler_curator_path_is_live_and_reported_per_outcome() public {
        handler.owner_allowFunction(0); // targets[0].settleDeposit, no rules
        handler.owner_setMode(1); // enforce
        handler.curator_exec(0); // Policy
        handler.owner_approve(1); // payload 1: token.transfer(stranger, 1)
        handler.curator_exec(1); // Approval
        handler.owner_setMode(2); // a 1 h admin window
        handler.curator_exec(2); // Bypass (empty call to the third venue)
        assertEq(handler.curatorSuccesses(), 3, "three executions passed");
        assertFalse(handler.eventMismatch(), "each reported once with its outcome");
        assertFalse(handler.lockdownBreached());
        assertFalse(handler.approvalConsumedInBypass());
        handler.owner_setMode(0); // lockdown
        handler.curator_exec(0); // refused: not counted, not reported
        assertEq(handler.curatorSuccesses(), 3);
        assertFalse(handler.eventMismatch());
    }

    /// @dev No live approval ever coexists with an open Bypass window.
    function invariant_no_live_approval_during_bypass() public view {
        if (guard.mode(address(safe)) != CuratorGuardPolicy.Mode.Bypass) return;
        for (uint256 p; p < 3; ++p) {
            bytes32 _id = guard.computeApprovalId(address(safe), address(0), handler.targets(p), 0, handler.payloads(p), Operation.Call);
            assertEq(guard.approvalExpiry(_id), 0, "live approval inside a Bypass window");
        }
    }

    /// @dev An expired window reads as Lockdown, never as Bypass or Enforced.
    function invariant_expired_bypass_reads_as_lockdown() public view {
        (uint64 _until, ) = guard.bypassWindow(address(safe));
        if (_until != 0 && block.timestamp >= _until) {
            assertEq(uint8(guard.mode(address(safe))), uint8(CuratorGuardPolicy.Mode.Lockdown));
        }
    }

    function invariant_live_approvals_were_issued_in_the_current_epoch() public view {
        uint256 _epoch = guard.approvalEpoch(address(safe));
        for (uint256 p; p < 3; ++p) {
            bytes32 _id = guard.computeApprovalId(address(safe), address(0), handler.targets(p), 0, handler.payloads(p), Operation.Call);
            if (guard.approvalExpiry(_id) != 0) {
                assertEq(handler.approvedEpoch(p), _epoch + 1, "live approval from an older epoch");
            }
        }
    }

    /// @dev `targets()` / `selectors()` bookkeeping matches the per-function flags.
    function invariant_target_and_selector_views_are_consistent() public view {
        address[] memory _targets = guard.targets(address(safe));
        for (uint256 t; t < 3; ++t) {
            address _t = handler.targets(t);
            uint256 _allowedCount;
            for (uint256 s; s < 3; ++s) {
                if (_isAllowed(address(safe), _t, handler.selectors(s))) ++_allowedCount;
            }
            assertEq(guard.selectors(address(safe), _t).length, _allowedCount, "selectors view");
            bool _listed;
            for (uint256 i; i < _targets.length; ++i) if (_targets[i] == _t) _listed = true;
            bool _shouldBeListed = _allowedCount > 0 || guard.isNativeTransferAllowed(address(safe), _t);
            assertEq(_listed, _shouldBeListed, "targets view");
        }
    }

    /// @dev A `OneOf` set is non-empty only while a live `OneOf` rule references it.
    function invariant_value_sets_never_outlive_their_rule() public view {
        for (uint256 t; t < 3; ++t) {
            for (uint256 s; s < 3; ++s) {
                (bool _allowed, , CuratorGuardPolicy.ParamRule[] memory _rules) = guard.functionPermission(
                    address(safe),
                    handler.targets(t),
                    handler.selectors(s)
                );
                for (uint16 w; w < 2; ++w) {
                    bool _hasRule;
                    for (uint256 i; i < _rules.length; ++i) {
                        if (_rules[i].kind == CuratorGuardPolicy.RuleKind.OneOf && _rules[i].wordIndex == w) _hasRule = true;
                    }
                    uint256 _n = guard.allowedValues(address(safe), handler.targets(t), handler.selectors(s), w).length;
                    if (!_allowed || !_hasRule) assertEq(_n, 0, "dormant OneOf set");
                }
            }
        }
    }
}
