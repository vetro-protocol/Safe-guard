// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";
import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {DummyModule} from "test/guards/CuratorGuardModule.t.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";
import {G10aHarness} from "test/guards/G10aBase.sol";

/// @title Round 10 (g10a): the PER-PATH state machine on a real Safe v1.5.0 (transaction guard and
///        module guard), owner path and module path driven in lockstep with a reference model.
/// @dev Model (docs section 4): the mode record; the module allowlist (two modules, both enabled on the
///      Safe, one of them never allowlisted unless the admin does it); owner-path approvals (executor
///      0) and module-bound approvals (executor = the module) for two payloads; the allowlist bit of
///      `settleDeposit`. Predictions: a module off the allowlist does nothing in any mode; an admin
///      window passes both paths; a council window relaxes the owner path only (the module path stays
///      under the allowlist and the policy); approvals are spent on their own path only; Lockdown
///      refuses everything but a live approval of that path; reports carry the path byte and, on the
///      module path, the payload hash; the dry run agrees with the live module hook; the two transient
///      slots are idle after every transaction.
contract G10aPathHandler {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 internal constant DOMAIN_SEPARATOR_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
    bytes32 internal constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    G10aHarness public immutable guard;
    address public immutable safe;
    uint256 internal immutable pk;
    address public immutable admin;
    address public immutable council;
    address public immutable guardian;
    address public immutable stranger;
    address public immutable venue;
    DummyModule[2] public modules;

    // model
    CuratorGuardPolicy.Mode public mRaw;
    uint64 public mUntil;
    bool public mCouncil;
    uint64 public mLockedAt;
    uint32 public mEpoch;
    bool public mSettle;
    bool[2] public mAllowed;
    uint64[2] public ownerExpiry; // per payload
    uint32[2] public ownerEpochAt;
    uint64[2][2] public moduleExpiry; // [module][payload]
    uint32[2][2] public moduleEpochAt;

    // ghosts
    bool public verdictMismatch;
    bytes32 public lastTag;
    bool public slotDirty;
    bool public reportMismatch;
    bool public dryRunDisagreed;
    uint256 public ownerExecs;
    uint256 public moduleExecs;
    uint256[3] public ownerPassedBy;
    uint256[3] public modulePassedBy;
    uint256 public moduleRefusedOffList;

    constructor(
        G10aHarness guard_,
        address safe_,
        uint256 pk_,
        address admin_,
        address council_,
        address guardian_,
        address stranger_,
        address venue_,
        DummyModule m0_,
        DummyModule m1_
    ) {
        guard = guard_;
        safe = safe_;
        pk = pk_;
        admin = admin_;
        council = council_;
        guardian = guardian_;
        stranger = stranger_;
        venue = venue_;
        modules[0] = m0_;
        modules[1] = m1_;
    }

    /*//////////////////////////////////////////////////////////////
                                 MODEL
    //////////////////////////////////////////////////////////////*/

    function mEffective() public view returns (CuratorGuardPolicy.Mode) {
        if (mRaw == CuratorGuardPolicy.Mode.Bypass && block.timestamp >= mUntil) return CuratorGuardPolicy.Mode.Lockdown;
        return mRaw;
    }

    function _cooling() internal view returns (bool) {
        return block.timestamp <= uint256(mLockedAt) + 1 days;
    }

    function payload(uint256 p_) public view returns (bytes memory) {
        return p_ == 0 ? abi.encodeCall(MockProtocol.settleDeposit, (1)) : abi.encodeCall(MockProtocol.deposit, (1, stranger));
    }

    function _ownerLive(uint256 p_) internal view returns (bool) {
        return ownerExpiry[p_] != 0 && ownerEpochAt[p_] == mEpoch && block.timestamp <= ownerExpiry[p_];
    }

    function _moduleLive(uint256 m_, uint256 p_) internal view returns (bool) {
        return moduleExpiry[m_][p_] != 0 && moduleEpochAt[m_][p_] == mEpoch && block.timestamp <= moduleExpiry[m_][p_];
    }

    function _policyPasses(uint256 p_) internal view returns (bool) {
        return p_ == 0 && mSettle; // `deposit(1, stranger)` is never allowlisted here
    }

    function expectedOwnerExpiry(uint256 p_) external view returns (uint64) {
        return ownerExpiry[p_] != 0 && ownerEpochAt[p_] == mEpoch ? ownerExpiry[p_] : 0;
    }

    function expectedModuleExpiry(uint256 m_, uint256 p_) external view returns (uint64) {
        return moduleExpiry[m_][p_] != 0 && moduleEpochAt[m_][p_] == mEpoch ? moduleExpiry[m_][p_] : 0;
    }

    function ownerId(uint256 p_) public view returns (bytes32) {
        return guard.computeApprovalId(safe, address(0), venue, 0, payload(p_), Operation.Call);
    }

    function moduleId(uint256 m_, uint256 p_) public view returns (bytes32) {
        return guard.computeApprovalId(safe, address(modules[m_]), venue, 0, payload(p_), Operation.Call);
    }

    function _toLockdown() internal {
        mRaw = CuratorGuardPolicy.Mode.Lockdown;
        mUntil = 0;
        mCouncil = false;
        mLockedAt = uint64(block.timestamp);
    }

    function _as(address who_, bytes memory call_) internal returns (bool _ok) {
        vm.prank(who_);
        (_ok, ) = address(guard).call(call_);
    }

    function _check(bool ok_, bool expected_, bytes32 tag_) internal {
        if (ok_ != expected_) {
            verdictMismatch = true;
            lastTag = tag_;
        }
    }

    /*//////////////////////////////////////////////////////////////
                              ROLE ACTIONS
    //////////////////////////////////////////////////////////////*/

    function admin_lockdown() external {
        if (_as(admin, abi.encodeCall(guard.lockdown, (safe)))) _toLockdown();
        else _check(false, true, "admin_lockdown");
    }

    function admin_lockdownAndRevoke() external {
        bool _ok = _as(admin, abi.encodeCall(guard.lockdownAndRevoke, (safe)));
        _check(_ok, true, "admin_lockdownAndRevoke");
        if (_ok) {
            _toLockdown();
            ++mEpoch;
        }
    }

    function admin_enforce() external {
        bool _ok = _as(admin, abi.encodeCall(guard.enforce, (safe)));
        _check(_ok, !_cooling(), "admin_enforce");
        if (_ok) {
            mRaw = CuratorGuardPolicy.Mode.Enforced;
            mUntil = 0;
            mCouncil = false;
        }
    }

    function admin_bypass(uint256 seed_) external {
        uint64 _d = uint64(1 hours + seed_ % uint256(180 days - 1 hours + 1));
        bool _ok = _as(admin, abi.encodeCall(guard.bypass, (safe, _d)));
        _check(_ok, !_cooling(), "admin_bypass");
        if (_ok) {
            mRaw = CuratorGuardPolicy.Mode.Bypass;
            mUntil = uint64(block.timestamp) + _d;
            mCouncil = false;
            ++mEpoch;
        }
    }

    function council_enforce() external {
        bool _ok = _as(council, abi.encodeCall(guard.enforce, (safe)));
        _check(_ok, true, "council_enforce");
        if (_ok) {
            mRaw = CuratorGuardPolicy.Mode.Enforced;
            mUntil = 0;
            mCouncil = false;
        }
    }

    function council_bypass(uint256 seed_) external {
        uint64 _d = uint64(1 hours + seed_ % uint256(7 days - 1 hours + 1));
        bool _ok = _as(council, abi.encodeCall(guard.bypass, (safe, _d)));
        _check(_ok, true, "council_bypass");
        if (_ok) {
            mRaw = CuratorGuardPolicy.Mode.Bypass;
            mUntil = uint64(block.timestamp) + _d;
            mCouncil = true;
            ++mEpoch;
        }
    }

    function guardian_lockdown() external {
        bool _ok = _as(guardian, abi.encodeCall(guard.lockdown, (safe)));
        _check(_ok, true, "guardian_lockdown");
        if (_ok) _toLockdown();
    }

    function admin_allowSettle() external {
        CuratorGuardPolicy.ParamRule[] memory _none;
        bool _ok = _as(admin, abi.encodeCall(guard.allowFunction, (safe, venue, MockProtocol.settleDeposit.selector, false, _none)));
        _check(_ok, true, "admin_allowSettle");
        if (_ok) mSettle = true;
    }

    function guardian_revokeSettle() external {
        bool _ok = _as(guardian, abi.encodeCall(guard.revokeFunction, (safe, venue, MockProtocol.settleDeposit.selector)));
        _check(_ok, true, "guardian_revokeSettle");
        if (_ok) mSettle = false;
    }

    function admin_allowModule(uint256 seed_) external {
        uint256 _m = seed_ % 2;
        bool _ok = _as(admin, abi.encodeCall(guard.setModuleAllowed, (safe, address(modules[_m]), true)));
        _check(_ok, true, "admin_allowModule");
        if (_ok) mAllowed[_m] = true;
    }

    /// @dev A guardian's removal is a complete switch for that key in every mode (V2-94).
    function guardian_disableModule(uint256 seed_) external {
        uint256 _m = seed_ % 2;
        bool _ok = _as(guardian, abi.encodeCall(guard.setModuleAllowed, (safe, address(modules[_m]), false)));
        _check(_ok, true, "guardian_disableModule");
        if (_ok) mAllowed[_m] = false;
    }

    /// @dev Admin approvals bound to the owner path or to a module (allowlisted or not: the admin may).
    function admin_approve(uint256 seed_) external {
        uint256 _p = seed_ % 2;
        uint256 _x = (seed_ >> 1) % 3; // 0 = owner path, 1..2 = module 0..1
        uint64 _ttl = uint64(1 hours + (seed_ >> 3) % 1 days);
        address _executor = _x == 0 ? address(0) : address(modules[_x - 1]);
        bool _expected = !_cooling() && mEffective() != CuratorGuardPolicy.Mode.Bypass;
        bool _ok = _as(admin, abi.encodeCall(guard.approveTransaction, (safe, _executor, venue, 0, payload(_p), Operation.Call, _ttl)));
        _check(_ok, _expected, "admin_approve");
        if (_ok) _recordApproval(_x, _p, _ttl);
    }

    /// @dev A council approval bound to a module needs the module allowlisted when issued.
    function council_approve(uint256 seed_) external {
        uint256 _p = seed_ % 2;
        uint256 _x = (seed_ >> 1) % 3;
        uint64 _ttl = uint64(1 hours + (seed_ >> 3) % 1 days);
        address _executor = _x == 0 ? address(0) : address(modules[_x - 1]);
        bool _expected = mEffective() != CuratorGuardPolicy.Mode.Bypass && (_x == 0 || mAllowed[_x - 1]);
        bool _ok = _as(council, abi.encodeCall(guard.approveTransaction, (safe, _executor, venue, 0, payload(_p), Operation.Call, _ttl)));
        _check(_ok, _expected, "council_approve");
        if (_ok) _recordApproval(_x, _p, _ttl);
    }

    function _recordApproval(uint256 x_, uint256 p_, uint64 ttl_) internal {
        if (x_ == 0) {
            ownerExpiry[p_] = uint64(block.timestamp) + ttl_;
            ownerEpochAt[p_] = mEpoch;
        } else {
            moduleExpiry[x_ - 1][p_] = uint64(block.timestamp) + ttl_;
            moduleEpochAt[x_ - 1][p_] = mEpoch;
        }
    }

    function guardian_revokeAll() external {
        bool _ok = _as(guardian, abi.encodeCall(guard.revokeAllApprovals, (safe)));
        _check(_ok, true, "guardian_revokeAll");
        if (_ok) ++mEpoch;
    }

    /*//////////////////////////////////////////////////////////////
                                 HOOKS
    //////////////////////////////////////////////////////////////*/

    /// @dev Owner path: a window (admin or council) passes a venue call, else a live owner-path
    ///      approval, else Lockdown refuses, else the allowlist. A module-bound approval never counts.
    function curator_exec(uint256 seed_) external {
        uint256 _p = seed_ % 2;
        (bool _expected, CuratorGuard.Outcome _outcome) = _predictOwner(_p);
        ++ownerExecs;
        vm.recordLogs();
        (bool _ok, bytes32 _hash) = _execOwner(payload(_p));
        _check(_ok, _expected, "curator_exec");
        _probeSlots();
        if (_ok) {
            ++ownerPassedBy[uint256(_outcome)];
            if (_outcome == CuratorGuard.Outcome.Approval) ownerExpiry[_p] = 0;
            _checkReported(_hash, 0, _outcome);
        } else {
            vm.getRecordedLogs();
        }
    }

    function _predictOwner(uint256 p_) internal view returns (bool _expected, CuratorGuard.Outcome _outcome) {
        CuratorGuardPolicy.Mode _eff = mEffective();
        if (_eff == CuratorGuardPolicy.Mode.Bypass) return (true, CuratorGuard.Outcome.Bypass);
        if (_ownerLive(p_)) return (true, CuratorGuard.Outcome.Approval);
        if (_eff == CuratorGuardPolicy.Mode.Lockdown) return (false, _outcome);
        return (_policyPasses(p_), CuratorGuard.Outcome.Policy);
    }

    /// @dev Signs with the curator key and executes through the genuine `execTransaction`.
    function _execOwner(bytes memory data_) internal returns (bool _ok, bytes32 _hash) {
        _hash = _safeTxHash(venue, data_, ISafe(safe).nonce());
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(pk, _hash);
        bytes memory _sig = abi.encodePacked(_r, _s, _v);
        try ISafe(safe).execTransaction(venue, 0, data_, Operation.Call, 0, 0, 0, address(0), payable(address(0)), _sig) returns (bool _r_) {
            _ok = _r_;
        } catch {}
    }

    /// @dev Module path: off the allowlist nothing passes in any mode; an ADMIN window passes; a
    ///      council window does NOT relax this path (allowlist and policy as in `Enforced`); a live
    ///      module-bound approval passes and is spent; Lockdown refuses; else the allowlist.
    function module_exec(uint256 seed_) external {
        uint256 _m = seed_ % 2;
        uint256 _p = (seed_ >> 1) % 2;
        (bool _expected, CuratorGuard.Outcome _outcome) = _predictModule(_m, _p);
        (bool _dryOk, bytes32 _dryErr) = _dryModule(_m, _p);
        ++moduleExecs;
        vm.recordLogs();
        (bool _ok, bytes32 _liveErr) = _runModule(_m, _p);
        _check(_ok, _expected, "module_exec");
        // The dry run must agree with the live hook (the module-path replica).
        if (_dryOk != _ok || (!_ok && _dryErr != _liveErr)) dryRunDisagreed = true;
        _probeSlots();
        if (_ok) {
            ++modulePassedBy[uint256(_outcome)];
            if (_outcome == CuratorGuard.Outcome.Approval) moduleExpiry[_m][_p] = 0;
            _checkReported(_moduleHash(_m, _p), 1, _outcome);
        } else {
            if (!mAllowed[_m]) ++moduleRefusedOffList;
            vm.getRecordedLogs();
        }
    }

    function _predictModule(uint256 m_, uint256 p_) internal view returns (bool _expected, CuratorGuard.Outcome _outcome) {
        CuratorGuardPolicy.Mode _eff = mEffective();
        if (!mAllowed[m_]) return (false, _outcome);
        if (_eff == CuratorGuardPolicy.Mode.Bypass && !mCouncil) return (true, CuratorGuard.Outcome.Bypass);
        if (_moduleLive(m_, p_)) return (true, CuratorGuard.Outcome.Approval);
        if (_eff == CuratorGuardPolicy.Mode.Lockdown) return (false, _outcome);
        return (_policyPasses(p_), CuratorGuard.Outcome.Policy); // Enforced, or a council window: the policy
    }

    function _dryModule(uint256 m_, uint256 p_) internal view returns (bool _ok, bytes32 _err) {
        try guard.validateModuleTransaction(safe, address(modules[m_]), venue, 0, payload(p_), Operation.Call) {
            _ok = true;
        } catch (bytes memory _e) {
            _err = keccak256(_e);
        }
    }

    function _runModule(uint256 m_, uint256 p_) internal returns (bool _ok, bytes32 _err) {
        try modules[m_].exec(ISafe(safe), venue, 0, payload(p_), Operation.Call) returns (bool _r_) {
            _ok = _r_;
        } catch (bytes memory _e) {
            _err = keccak256(_e);
        }
    }

    /// @dev The module-path report hash: `keccak256(abi.encode(safe, module, to, value, keccak256(data), operation))`.
    function _moduleHash(uint256 m_, uint256 p_) internal view returns (bytes32) {
        return keccak256(abi.encode(safe, address(modules[m_]), venue, uint256(0), keccak256(payload(p_)), Operation.Call));
    }

    function _probeSlots() internal {
        if (guard.tslot(safe, 0) != 0 || guard.tslot(safe, 1) != 0) slotDirty = true;
    }

    function _checkReported(bytes32 hash_, uint8 path_, CuratorGuard.Outcome expected_) internal {
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        uint256 _n;
        for (uint256 i; i < _logs.length; ++i) {
            if (_logs[i].emitter != address(guard) || _logs[i].topics[0] != CuratorGuard.TransactionChecked.selector) continue;
            ++_n;
            if (
                _logs[i].topics[1] != bytes32(uint256(uint160(safe))) ||
                _logs[i].topics[2] != hash_ ||
                _logs[i].topics[3] != bytes32(uint256(expected_)) ||
                keccak256(_logs[i].data) != keccak256(abi.encode(path_))
            ) reportMismatch = true;
        }
        if (_n != 1) reportMismatch = true;
    }

    function _safeTxHash(address to_, bytes memory data_, uint256 nonce_) internal view returns (bytes32) {
        bytes32 _domain = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, safe));
        bytes32 _structHash = keccak256(
            abi.encode(SAFE_TX_TYPEHASH, to_, uint256(0), keccak256(data_), uint8(0), uint256(0), uint256(0), uint256(0), address(0), address(0), nonce_)
        );
        return keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), _domain, _structHash));
    }

    function time_passes(uint256 seed_) external {
        vm.warp(block.timestamp + 1 + (seed_ % 3 days));
    }
}

contract G10aPathInvariantsTest is SafeTxHelper {
    G10aHarness internal guard;
    G10aPathHandler internal handler;
    DummyModule internal m0;
    DummyModule internal m1;
    MockProtocol internal venue;
    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal guardian = makeAddr("guardian");
    address internal stranger = makeAddr("stranger");
    address internal curator;

    bytes32 internal constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    function setUp() public {
        vm.warp(1_700_000_000);
        (curator, signerPk) = makeAddrAndKey("curator");
        Safe150 _singleton = new Safe150();
        SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        safe = ISafe(address(_proxy));
        guard = new G10aHarness(0, vetro, council);
        guard.seedSafe(address(safe));
        m0 = new DummyModule();
        m1 = new DummyModule();
        venue = new MockProtocol();
        vm.startPrank(address(safe));
        safe.enableModule(address(m0));
        safe.enableModule(address(m1));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        vm.stopPrank();
        assertEq(address(uint160(uint256(bytes32(safe.getStorageAt(uint256(MODULE_GUARD_SLOT), 1))))), address(guard));
        vm.prank(vetro);
        guard.setGuardian(address(safe), guardian, true);
        handler = new G10aPathHandler(guard, address(safe), signerPk, vetro, council, guardian, stranger, address(venue), m0, m1);
        targetContract(address(handler));
    }

    function invariant_g10a_path_verdicts_match_the_model() public view {
        assertFalse(handler.verdictMismatch(), string(abi.encodePacked("verdict mismatch: ", handler.lastTag())));
    }

    function invariant_g10a_path_state_is_the_model_state() public view {
        address _safe = address(safe);
        assertEq(uint8(guard.rawMode(_safe)), uint8(handler.mRaw()), "raw mode");
        (uint64 _until, bool _council) = guard.bypassWindow(_safe);
        assertEq(_until, handler.mUntil(), "window end");
        assertEq(_council, handler.mCouncil(), "window owner");
        assertEq(guard.lockedAt(_safe), handler.mLockedAt(), "lockedAt");
        assertEq(guard.approvalEpoch(_safe), handler.mEpoch(), "epoch");
        for (uint256 p; p < 2; ++p) {
            assertEq(guard.approvalExpiry(handler.ownerId(p)), handler.expectedOwnerExpiry(p), "owner approval");
            for (uint256 m; m < 2; ++m) assertEq(guard.approvalExpiry(handler.moduleId(m, p)), handler.expectedModuleExpiry(m, p), "module approval");
        }
        address[] memory _mods = guard.modules(_safe);
        for (uint256 m; m < 2; ++m) {
            bool _listed;
            for (uint256 i; i < _mods.length; ++i) if (_mods[i] == address(handler.modules(m))) _listed = true;
            assertEq(_listed, handler.mAllowed(m), "module allowlist");
        }
    }

    function invariant_g10a_path_dry_run_agrees_with_the_module_hook() public view {
        assertFalse(handler.dryRunDisagreed(), "validateModuleTransaction disagreed with the live module hook");
    }

    function invariant_g10a_path_reports_and_slots() public view {
        assertFalse(handler.reportMismatch(), "TransactionChecked missing, duplicated or wrong on a path");
        assertFalse(handler.slotDirty(), "a transient slot of either path was left set");
    }

    /// @dev Liveness anchor: both paths pass and are refused in every mode at least once.
    function test_g10a_path_handler_is_live() public {
        handler.admin_allowSettle();
        handler.admin_enforce();
        handler.module_exec(0); // m0 off the allowlist: refused
        handler.admin_allowModule(0);
        handler.module_exec(0); // m0, settle: Policy
        handler.module_exec(2); // m0, deposit: refused by the policy
        handler.curator_exec(0); // owner, settle: Policy
        handler.admin_approve(1 + (1 << 1)); // module 0, payload 1
        handler.module_exec(2); // Approval
        handler.module_exec(2); // spent: refused
        handler.admin_approve(1); // owner path, payload 1
        handler.module_exec(2); // an owner-path approval never spends on the module path
        handler.curator_exec(1); // Approval on the owner path
        handler.council_bypass(0);
        handler.curator_exec(1); // Bypass on the owner path
        handler.module_exec(2); // the council window does not relax the module path: refused
        handler.module_exec(0); // ... but the allowlisted settle still passes under the policy
        handler.guardian_lockdown();
        handler.module_exec(0); // Lockdown
        handler.time_passes(2 days);
        handler.admin_bypass(0);
        handler.module_exec(2); // an admin window passes the module path
        handler.guardian_disableModule(0);
        handler.module_exec(2); // removed by a guardian: refused inside the admin window too
        assertFalse(handler.verdictMismatch(), string(abi.encodePacked("verdict mismatch: ", handler.lastTag())));
        assertEq(handler.modulePassedBy(0), 2);
        assertEq(handler.modulePassedBy(1), 1);
        assertEq(handler.modulePassedBy(2), 1);
        assertEq(handler.ownerPassedBy(0), 1);
        assertEq(handler.ownerPassedBy(1), 1);
        assertEq(handler.ownerPassedBy(2), 1);
        assertEq(handler.moduleRefusedOffList(), 2);
        assertFalse(handler.dryRunDisagreed());
        assertFalse(handler.reportMismatch());
        assertFalse(handler.slotDirty());
        invariant_g10a_path_state_is_the_model_state();
    }
}
