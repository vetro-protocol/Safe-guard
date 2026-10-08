// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";
import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {G10aHarness} from "test/guards/G10aBase.sol";

/// @title Round 10 (g10a): two Safes on ONE guard. Every per-Safe transition names a Safe; the other
///        Safe's whole per-Safe record is a ghost that must never move, whoever acts and however the
///        hooks run; deployment-wide actions move no per-Safe record either.
contract G10aTwoSafeHandler {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 internal constant DOMAIN_SEPARATOR_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
    bytes32 internal constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    G10aHarness public immutable guard;
    address public immutable admin;
    address public immutable council;
    address public immutable globalGuardian;
    address public immutable stranger;
    address public immutable unwrapper;
    address[2] public safes;
    uint256[2] internal pks;
    address[2] public venues;
    address[2] public guardiansOf;

    bool public isolationBroken;
    bytes32 public lastTag;
    bool public crossReport;
    uint256 public actions;
    uint256 public execs;
    uint256 public passes;

    constructor(
        G10aHarness guard_,
        address admin_,
        address council_,
        address globalGuardian_,
        address stranger_,
        address unwrapper_,
        address[2] memory safes_,
        uint256[2] memory pks_,
        address[2] memory venues_,
        address[2] memory guardiansOf_
    ) {
        guard = guard_;
        admin = admin_;
        council = council_;
        globalGuardian = globalGuardian_;
        stranger = stranger_;
        unwrapper = unwrapper_;
        safes = safes_;
        pks = pks_;
        venues = venues_;
        guardiansOf = guardiansOf_;
    }

    /// @dev Everything the guard holds per Safe (deployment-wide state excluded on purpose).
    function fingerprint(uint256 i_) public view returns (bytes32) {
        address _s = safes[i_];
        return keccak256(abi.encode(_modeRecord(_s), _listRecord(_s, i_), _functionRecord(_s)));
    }

    function _modeRecord(address s_) internal view returns (bytes32) {
        (uint64 _until, bool _council) = guard.bypassWindow(s_);
        return keccak256(abi.encode(guard.rawMode(s_), guard.mode(s_), _until, _council, guard.lockedAt(s_), guard.approvalEpoch(s_)));
    }

    function _listRecord(address s_, uint256 i_) internal view returns (bytes32) {
        (address _handler, bool _enforce) = guard.requiredFallbackHandler(s_);
        bytes memory _a = abi.encode(guard.multiSendUnwrappers(s_), guard.modules(s_), guard.guardians(s_), _handler, _enforce);
        bytes memory _b = abi.encode(guard.isNativeTransferAllowed(s_, venues[i_]), guard.approvalExpiry(_id(i_, 0)), guard.approvalExpiry(_id(i_, 1)));
        return keccak256(abi.encode(_a, _b));
    }

    function _functionRecord(address s_) internal view returns (bytes32 _h) {
        address[] memory _targets = guard.targets(s_);
        _h = keccak256(abi.encode(_targets));
        for (uint256 t; t < _targets.length; ++t) {
            (bool _allowed, bool _allowValue, CuratorGuardPolicy.ParamRule[] memory _rules) = guard.functionPermission(s_, _targets[t], MockProtocol.settleDeposit.selector);
            _h = keccak256(abi.encode(_h, guard.selectors(s_, _targets[t]), _allowed, _allowValue, _rules.length));
        }
    }

    function _payload(uint256 p_) internal pure returns (bytes memory) {
        return p_ == 0 ? abi.encodeCall(MockProtocol.settleDeposit, (1)) : abi.encodeCall(MockProtocol.deposit, (1, address(0xBEEF)));
    }

    function _id(uint256 i_, uint256 p_) internal view returns (bytes32) {
        return guard.computeApprovalId(safes[i_], address(0), venues[i_], 0, _payload(p_), Operation.Call);
    }

    /// @dev Runs `call_` as `who_` and flags any change to the OTHER Safe's record.
    function _onSafe(uint256 i_, address who_, bytes memory call_, bytes32 tag_) internal {
        uint256 _o = 1 - i_;
        bytes32 _before = fingerprint(_o);
        vm.prank(who_);
        (bool _ok, ) = address(guard).call(call_);
        _ok;
        ++actions;
        if (fingerprint(_o) != _before) {
            isolationBroken = true;
            lastTag = tag_;
        }
    }

    /// @dev Runs a deployment-wide action and flags any change to EITHER record.
    function _global(address who_, bytes memory call_, bytes32 tag_) internal {
        bytes32 _a = fingerprint(0);
        bytes32 _b = fingerprint(1);
        vm.prank(who_);
        (bool _ok, ) = address(guard).call(call_);
        _ok;
        ++actions;
        if (fingerprint(0) != _a || fingerprint(1) != _b) {
            isolationBroken = true;
            lastTag = tag_;
        }
    }

    function act(uint256 seed_) external {
        uint256 _i = seed_ % 2;
        uint256 _k = (seed_ >> 1) % 20;
        (address _who, bytes memory _call, bytes32 _tag) = _k < 10 ? _buildA(_i, _k, seed_ >> 6) : _buildB(_i, _k, seed_ >> 6);
        if (_k >= 17) _global(_who, _call, _tag);
        else _onSafe(_i, _who, _call, _tag);
    }

    function _buildA(uint256 i_, uint256 k_, uint256 r_) internal view returns (address, bytes memory, bytes32) {
        address _s = safes[i_];
        address _v = venues[i_];
        if (k_ == 0) {
            CuratorGuardPolicy.ParamRule[] memory _none;
            return (admin, abi.encodeCall(guard.allowFunction, (_s, _v, MockProtocol.settleDeposit.selector, false, _none)), "allow");
        }
        if (k_ == 1) return (guardiansOf[i_], abi.encodeCall(guard.revokeFunction, (_s, _v, MockProtocol.settleDeposit.selector)), "revoke");
        if (k_ == 2) return (admin, abi.encodeCall(guard.lockdown, (_s)), "admin lockdown");
        if (k_ == 3) return (council, abi.encodeCall(guard.enforce, (_s)), "council enforce");
        if (k_ == 4) return (council, abi.encodeCall(guard.bypass, (_s, uint64(1 hours + r_ % 6 days))), "council bypass");
        if (k_ == 5) return (admin, abi.encodeCall(guard.bypass, (_s, uint64(1 hours + r_ % 30 days))), "admin bypass");
        if (k_ == 6) return (guardiansOf[i_], abi.encodeCall(guard.lockdownAndRevoke, (_s)), "guardian lockdownAndRevoke");
        if (k_ == 7) return (admin, _approveCall(_s, _v, r_ % 2), "admin approve");
        if (k_ == 8) return (council, _approveCall(_s, _v, r_ % 2), "council approve");
        return (guardiansOf[i_], abi.encodeCall(guard.revokeAllApprovals, (_s)), "guardian revokeAll");
    }

    function _buildB(uint256 i_, uint256 k_, uint256 r_) internal view returns (address, bytes memory, bytes32) {
        address _s = safes[i_];
        address _v = venues[i_];
        if (k_ == 10) return (council, abi.encodeCall(guard.setGuardian, (_s, stranger, r_ % 2 == 0)), "council setGuardian");
        if (k_ == 11) return (admin, abi.encodeCall(guard.setNativeTransferAllowed, (_s, _v, true)), "admin native");
        if (k_ == 12) return (globalGuardian, abi.encodeCall(guard.setNativeTransferAllowed, (_s, _v, false)), "global guardian native off");
        if (k_ == 13) return (admin, abi.encodeCall(guard.setMultiSendUnwrapper, (_s, unwrapper, r_ % 2 == 0)), "admin unwrapper");
        if (k_ == 14) return (admin, abi.encodeCall(guard.setRequiredFallbackHandler, (_s, address(0), r_ % 2 == 0)), "admin handler");
        if (k_ == 15) return (guardiansOf[1 - i_], abi.encodeCall(guard.lockdown, (_s)), "foreign guardian lockdown"); // refused
        if (k_ == 16) return (guardiansOf[1 - i_], abi.encodeCall(guard.revokeAllApprovals, (_s)), "foreign guardian revokeAll"); // refused
        if (k_ == 17) return (globalGuardian, abi.encodeCall(guard.setUnwrapperCodehash, (unwrapper.codehash, false)), "global forbid hash");
        if (k_ == 18) return (council, abi.encodeCall(guard.setUnwrapperCodehash, (unwrapper.codehash, true)), "council re-allow hash");
        return (admin, abi.encodeCall(guard.setDeploymentGuardian, (stranger, r_ % 2 == 0)), "deployment guardian");
    }

    function _approveCall(address s_, address v_, uint256 p_) internal view returns (bytes memory) {
        return abi.encodeCall(guard.approveTransaction, (s_, address(0), v_, 0, _payload(p_), Operation.Call, uint64(1 days)));
    }

    /// @dev A curator transaction of one Safe never moves the other Safe's record and is reported for
    ///      its own Safe only.
    function curator_exec(uint256 seed_) external {
        uint256 _i = seed_ % 2;
        uint256 _o = 1 - _i;
        bytes32 _before = fingerprint(_o);
        ++execs;
        vm.recordLogs();
        if (_execOwner(_i, _payload((seed_ >> 1) % 2))) ++passes;
        Vm.Log[] memory _logs = vm.getRecordedLogs();
        for (uint256 j; j < _logs.length; ++j) {
            if (_logs[j].emitter != address(guard) || _logs[j].topics[0] != CuratorGuard.TransactionChecked.selector) continue;
            if (_logs[j].topics[1] != bytes32(uint256(uint160(safes[_i])))) crossReport = true;
        }
        if (fingerprint(_o) != _before) {
            isolationBroken = true;
            lastTag = "curator exec";
        }
        if (guard.tslot(safes[_o], 0) != 0) isolationBroken = true;
    }

    /// @dev Signs with Safe `i_`'s curator key and executes through its genuine `execTransaction`.
    function _execOwner(uint256 i_, bytes memory data_) internal returns (bool _ok) {
        bytes32 _hash = _safeTxHash(safes[i_], venues[i_], data_, ISafe(safes[i_]).nonce());
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(pks[i_], _hash);
        bytes memory _sig = abi.encodePacked(_r, _s, _v);
        try ISafe(safes[i_]).execTransaction(venues[i_], 0, data_, Operation.Call, 0, 0, 0, address(0), payable(address(0)), _sig) returns (bool _r_) {
            _ok = _r_;
        } catch {}
    }

    function _safeTxHash(address safe_, address to_, bytes memory data_, uint256 nonce_) internal view returns (bytes32) {
        bytes32 _domain = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, safe_));
        bytes32 _structHash = keccak256(
            abi.encode(SAFE_TX_TYPEHASH, to_, uint256(0), keccak256(data_), uint8(0), uint256(0), uint256(0), uint256(0), address(0), address(0), nonce_)
        );
        return keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), _domain, _structHash));
    }

    function time_passes(uint256 seed_) external {
        vm.warp(block.timestamp + 1 + (seed_ % 3 days));
    }
}

contract G10aTwoSafeInvariantsTest is CuratorGuardTestBase {
    G10aHarness internal h;
    G10aTwoSafeHandler internal handler;
    ISafe internal safeB;
    uint256 internal pkB;

    function setUp() public override {
        super.setUp();
        h = new G10aHarness(0, vetro, council);
        h.seedSafe(address(safe));
        vm.prank(address(safe));
        safe.setGuard(address(h));
        guard = h;
        // Safe B: a second real v1.4.1 proxy that installs the same guard.
        address _curatorB;
        (_curatorB, pkB) = makeAddrAndKey("curatorB");
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = _curatorB;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        safeB = ISafe(address(_proxy));
        h.seedSafe(address(safeB));
        vm.prank(address(safeB));
        safeB.setGuard(address(h));
        MockProtocol _venueB = new MockProtocol();
        address _guardianA = makeAddr("guardian-of-A");
        address _guardianB = makeAddr("guardian-of-B");
        address _global = makeAddr("global-guardian");
        _seedCodehash(address(multiSendCallOnly).codehash);
        vm.startPrank(vetro);
        h.setGuardian(address(safe), _guardianA, true);
        h.setGuardian(address(safeB), _guardianB, true);
        h.setDeploymentGuardian(_global, true);
        vm.stopPrank();
        handler = new G10aTwoSafeHandler(
            h,
            vetro,
            council,
            _global,
            attacker,
            address(multiSendCallOnly),
            [address(safe), address(safeB)],
            [signerPk, pkB],
            [address(protocol), address(_venueB)],
            [_guardianA, _guardianB]
        );
        targetContract(address(handler));
    }

    function invariant_g10a_a_safes_record_moves_only_through_calls_that_name_it() public view {
        assertFalse(handler.isolationBroken(), string(abi.encodePacked("isolation broken by: ", handler.lastTag())));
    }

    function invariant_g10a_reports_name_the_executing_safe_only() public view {
        assertFalse(handler.crossReport(), "a report named the other Safe");
    }

    function test_g10a_two_safe_handler_is_live() public {
        for (uint256 k; k < 20; ++k) {
            handler.act(k << 1); // every action kind on Safe A
            handler.act((k << 1) | 1); // and on Safe B
        }
        handler.curator_exec(0);
        handler.curator_exec(1);
        assertEq(handler.actions(), 40);
        assertFalse(handler.isolationBroken(), string(abi.encodePacked("isolation broken by: ", handler.lastTag())));
        assertFalse(handler.crossReport());
    }
}
