// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Test.sol";

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";
import {MultiSendCallOnly} from "safe-contracts-v1.4.1/contracts/libraries/MultiSendCallOnly.sol";
import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @dev Review round 22, reviewer g22b: the zero-target rail of `approveTransaction` (G17a-3, +18 B, the one change
///      of guard code since round 20) as a property, and the two lanes of the guard against each other.
///
///      Z1 (the rail): NO approval whose target is `address(0)` can be issued: by any seat of the fixture (the
///      admin, the council, a per-Safe guardian, the deployment guardian, a stranger, the Safe itself, the guard,
///      the zero sender, an allowlisted module, the timelock), by ANY address (symbolic caller), wrapped in
///      `executeBefore`, or through the timelock as the admin (the production shape); for every value, calldata
///      (lengths 0, 3, 4, 36, 68), operation, executor and ttl; the admin and the council are refused with exactly
///      `InvalidTarget(address(0))` BEFORE any other argument is looked at, everyone else with `Unauthorized`;
///      nothing observable moves; the approval id has no expiry afterwards. Z3: a zero-target BATCH ENTRY in an
///      approved delegatecall into a canonical `MultiSendCallOnly` is issued (the library carries code) but never
///      usable (`MalformedMultiSend` at use, the same decoder and the same reason as the native lane's unwrapper).
///      Z4: no setter of the native lane admits the zero address as a target (`InvalidTarget(0)`).
///
///      Z2 (the lanes agree): for every target class, every value and every calldata shape of the domain, the
///      NATIVE lane (the admin's best-effort allowlisting of the shape on an `Enforced` Safe `sN`, then the dry
///      run `validateTransaction`, the live hook's twin by property 9) and the APPROVAL lane (the admin's
///      `approveTransaction` on a `Lockdown` Safe `sA` whose cooldown has passed, then the dry run of the same
///      payload: issued AND usable) give exactly the verdicts of the oracle `_expect*`, and on every class but
///      the Safe itself, for the shapes both lanes speak of (no calldata, or a selector), the two verdicts are
///      EQUAL on plain calls; on the Safe the approval lane admits what the admin signs and the native lane the
///      empty zero-value rejection call only (the one designed divergence, docs section 4). Classes: the zero
///      address, an account without code, an EIP-7702 delegated EOA (`ef0100 || venue`), the guard, the Safe, the
///      timelock, a canonical-shaped `MultiSendCallOnly` (the lib's v1.4.1 build, its runtime hash seeded as the
///      constructor seeds the canonical three; the forge twin adds the canonical runtime itself, keccak `ecd5bd14…`,
///      etched, through the constructor's own seeding). Fixture: the tree's `CuratorGuardHarness` (the production guard plus code-hash
///      seeding only, as round 20's digest suite: the production build pins the canonical Safe proxy and singleton
///      code and refuses the lib-compiled fixtures with `SafeNotSupported` on every configuration read, which the
///      native lane's dry run makes), the PRODUCTION timelock, a PRODUCTION guard whose admin is the timelock
///      (`gT`, Z1d: no configuration read on that path), real Safe v1.4.1 or v1.5.0 proxies from `lib/` (one
///      singleton per fixture, `_mk` picks the build), EOA seats (the rail is about the target, the
///      forwarded-caller rails are rounds 15-20's property). Every address is a literal.
abstract contract G22bZeroTargetBase is Test {
    CuratorGuardHarness internal guard;
    CuratorGuard internal gT; // the production guard with the timelock as its admin (Z1d)
    CuratorGuardTimelock internal tl;
    ISafe internal sN; // Enforced: the native lane's Safe
    ISafe internal sA; // Lockdown, the admin's cooldown passed: the approval lane's Safe
    MockProtocol internal venue;
    address internal singleton;

    address internal constant VETRO = address(0xA11CE); // the guard's admin (an EOA; the timelock in Z1d)
    address internal constant COUNCIL = address(0xC0C11);
    address internal constant GUARDIAN = address(0x6A4D); // per-Safe guardian of both Safes
    address internal constant DEP_GUARDIAN = address(0xDE96);
    address internal constant STRANGER = address(0x5712A);
    address internal constant MODULE = address(0x0D0D); // allowlisted module of sA
    address internal constant OWNER = address(0x0B0B);
    address internal constant P1 = address(0x9001); // the timelock's proposers and canceller (EOAs)
    address internal constant P2 = address(0x9002);
    address internal constant VETO = address(0x9003);
    address internal constant EOA = address(0xE0A0); // an account without code
    address internal constant DESIG = address(0x7702); // an EIP-7702 delegated EOA: `ef0100 || venue`
    address internal LIB; // a MultiSendCallOnly v1.4.1 (the lib's build), its runtime hash seeded like the canonical three
    address internal constant CANON = address(0x14100); // the canonical v1.4.1 runtime itself (the forge twin, through the constructor's own seeding)
    uint256 internal constant T0 = 1_800_000_000;
    uint64 internal constant TTL = 1 days;
    bytes32 internal constant SALT = keccak256("g22b");
    bytes4 internal constant MULTISEND = 0x8d80ff0a;
    /// @dev `test/guards/vectors/multisend-callonly-v141.hex`, 410 bytes, keccak256 ecd5bd14… (MULTISEND_CALL_ONLY_V141_CODEHASH).
    bytes internal constant MSCO_V141 =
        hex"60806040526004361061001e5760003560e01c80638d80ff0a14610023575b600080fd5b6100dc6004803603602081101561003957600080fd5b810190808035906020019064010000000081111561005657600080fd5b82018360208201111561006857600080fd5b8035906020019184600183028401116401000000008311171561008a57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505091929192905050506100de565b005b805160205b8181101561015f578083015160f81c6001820184015160601c60158301850151603584018601516055850187016000856000811461012857600181146101385761013d565b6000808585888a5af1915061013d565b600080fd5b50600081141561014c57600080fd5b82605501870196505050505050506100e3565b50505056fea26469706673582212208d297bb003abee230b5dfb38774688f37a6fbb97a82a21728e8049b2acb9b73564736f6c63430007060033";

    // target classes
    uint8 internal constant C_ZERO = 0;
    uint8 internal constant C_EOA = 1;
    uint8 internal constant C_DESIG = 2;
    uint8 internal constant C_GUARD = 3;
    uint8 internal constant C_SAFE = 4;
    uint8 internal constant C_TL = 5;
    uint8 internal constant C_LIB = 6;
    uint8 internal constant N_CLASSES = 7;
    uint8 internal constant N_SEATS = 10;

    /// @dev The arguments of one approval request (a memory struct keeps the legacy codegen's stack shallow).
    struct Req {
        address executor;
        uint256 value;
        bytes data;
        bool dc;
        uint64 ttl;
    }

    /// @dev The two lanes' verdicts on one (target, value, data, operation).
    struct Verdicts {
        bool n; // the native lane's dry run
        bytes nr;
        bool setOk; // the native lane's best-effort setter
        bytes setRet;
        bool i; // the approval lane: issued
        bytes ir;
        bool u; // the approval lane: usable (the dry run of the exact payload)
    }

    function _req(address e_, uint256 v_, bytes memory d_, bool dc_, uint64 t_) internal pure returns (Req memory _r) {
        _r.executor = e_;
        _r.value = v_;
        _r.data = d_;
        _r.dc = dc_;
        _r.ttl = t_;
    }

    function _mk(address owner_) internal virtual returns (ISafe);

    function setUp() public virtual {
        vm.warp(T0);
        sN = _mk(OWNER);
        sA = _mk(OWNER);
        guard = new CuratorGuardHarness(1 days, VETRO, COUNCIL);
        guard.seedSafe(address(sN)); // the lib-compiled proxy and singleton (V2-85: the real guard pins the canonical ones)
        guard.seedSafe(address(sA));
        venue = new MockProtocol();
        address[] memory _p = new address[](2);
        _p[0] = P1;
        _p[1] = P2;
        address[] memory _c = new address[](1);
        _c[0] = VETO;
        tl = new CuratorGuardTimelock(1 days, _p, _c);
        gT = new CuratorGuard(1 days, address(tl), COUNCIL);
        vm.etch(DESIG, abi.encodePacked(hex"ef0100", address(venue)));
        LIB = address(new MultiSendCallOnly());
        guard.seedCodehash(LIB.codehash); // halmos 0.3.3 reads the constructor-seeded hash sets as empty (G22b_Diag2 e4/e7/e9): seeded after construction, as every round's fixture
        vm.prank(address(sN));
        sN.setGuard(address(guard));
        vm.prank(address(sA));
        sA.setGuard(address(guard));
        vm.startPrank(VETRO);
        guard.setGuardian(address(sA), GUARDIAN, true);
        guard.setGuardian(address(sN), GUARDIAN, true);
        guard.setDeploymentGuardian(DEP_GUARDIAN, true);
        guard.setModuleAllowed(address(sA), MODULE, true);
        guard.allowFunction(address(sN), address(venue), MockProtocol.settleDeposit.selector, false, _noRules());
        guard.enforce(address(sN));
        guard.lockdown(address(sA)); // lockedAt = T0: the admin's cooldown runs for a day
        vm.stopPrank();
        vm.warp(T0 + 1 days + 1); // the cooldown has passed: the admin may approve on sA again
    }

    function _safe141(address owner_) internal returns (ISafe _safe) {
        if (singleton == address(0)) singleton = address(new Safe());
        SafeProxy _proxy = new SafeProxy(singleton);
        address[] memory _owners = new address[](1);
        _owners[0] = owner_;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        _safe = ISafe(address(_proxy));
    }

    function _safe150(address owner_) internal returns (ISafe _safe) {
        if (singleton == address(0)) singleton = address(new Safe150());
        SafeProxy150 _proxy = new SafeProxy150(singleton);
        address[] memory _owners = new address[](1);
        _owners[0] = owner_;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        _safe = ISafe(address(_proxy));
    }

    function _noRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory) {}

    function _op(bool dc_) internal pure returns (Operation) {
        return dc_ ? Operation.DelegateCall : Operation.Call;
    }

    /// @dev The target of a class, for the lane whose Safe is `s_`.
    function _target(uint8 c_, ISafe s_) internal view returns (address) {
        if (c_ == C_ZERO) return address(0);
        if (c_ == C_EOA) return EOA;
        if (c_ == C_DESIG) return DESIG;
        if (c_ == C_GUARD) return address(guard);
        if (c_ == C_SAFE) return address(s_);
        if (c_ == C_TL) return address(tl);
        return LIB;
    }

    /// @dev The seats of Z1a.
    function _seat(uint8 w_) internal view returns (address) {
        w_ = w_ % N_SEATS;
        if (w_ == 0) return VETRO;
        if (w_ == 1) return COUNCIL;
        if (w_ == 2) return GUARDIAN;
        if (w_ == 3) return DEP_GUARDIAN;
        if (w_ == 4) return STRANGER;
        if (w_ == 5) return address(sA);
        if (w_ == 6) return address(guard);
        if (w_ == 7) return address(0);
        if (w_ == 8) return MODULE;
        return address(tl);
    }

    function _sel(bytes memory d_) internal pure returns (bytes4 _s) {
        assembly ("memory-safe") {
            _s := mload(add(d_, 0x20))
        }
    }

    /// @dev Everything an observer can read of the approval lane's Safe and of the guard's roles (two halves: the
    ///      legacy codegen's stack).
    function _dA() internal view returns (bytes32) {
        (uint64 _u, bool _cb) = guard.bypassWindow(address(sA));
        return keccak256(abi.encode(guard.mode(address(sA)), guard.lockedAt(address(sA)), guard.approvalEpoch(address(sA)), _u, _cb));
    }

    function _dB() internal view returns (bytes32) {
        return keccak256(abi.encode(guard.targets(address(sA)).length, guard.modules(address(sA)).length, guard.isNativeTransferAllowed(address(sA), address(0)), sA.nonce(), guard.defaultAdmin(), guard.hasRole(guard.COUNCIL_ROLE(), COUNCIL)));
    }

    function _digest() internal view returns (bytes32) {
        return keccak256(abi.encode(_dA(), _dB()));
    }

    function _approveCall(address executor_, address to_, uint256 value_, bytes memory data_, Operation op_, uint64 ttl_) internal view returns (bytes memory) {
        return abi.encodeCall(guard.approveTransaction, (address(sA), executor_, to_, value_, data_, op_, ttl_));
    }

    /// @dev The request's approval calldata, on the guard `g_`, with the zero target.
    function _zeroApprove(CuratorGuard g_, Req memory r_) internal view returns (bytes memory) {
        return abi.encodeCall(g_.approveTransaction, (address(sA), r_.executor, address(0), r_.value, r_.data, _op(r_.dc), r_.ttl));
    }

    function _zeroId(CuratorGuard g_, Req memory r_) internal view returns (bytes32) {
        return g_.computeApprovalId(address(sA), r_.executor, address(0), r_.value, r_.data, _op(r_.dc));
    }

    function _isInvalidTarget(bool ok_, bytes memory ret_, address t_) internal pure returns (bool) {
        return !ok_ && keccak256(ret_) == keccak256(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, t_));
    }

    function _isUnauthorized(bool ok_, bytes memory ret_) internal pure returns (bool) {
        return !ok_ && ret_.length == 4 && bytes4(ret_) == CuratorGuardPolicy.Unauthorized.selector;
    }

    function _isDeadlinePassed(bool ok_, bytes memory ret_, uint64 d_) internal pure returns (bool) {
        return !ok_ && keccak256(ret_) == keccak256(abi.encodeWithSelector(CuratorGuardPolicy.DeadlinePassed.selector, d_));
    }

    function _isMalformedMultiSend(bool ok_, bytes memory ret_) internal pure returns (bool) {
        return !ok_ && ret_.length == 4 && bytes4(ret_) == CuratorGuard.MalformedMultiSend.selector;
    }

    /*//////////////////////////////////////////////////////////////
                                THE TWO LANES
    //////////////////////////////////////////////////////////////*/

    /// @dev THE NATIVE LANE on `sN` (Enforced): the admin's best-effort allowlisting of the shape (a native transfer
    ///      for empty calldata, the selector for a function call, the unwrapper for a delegatecall; nothing for a
    ///      1-3 byte payload, which the policy has no shape for), then the dry run.
    function _setterFor(address to_, bytes memory data_, Operation op_) internal view returns (bytes memory) {
        if (op_ == Operation.DelegateCall) return abi.encodeCall(guard.setMultiSendUnwrapper, (address(sN), to_, true));
        if (data_.length == 0) return abi.encodeCall(guard.setNativeTransferAllowed, (address(sN), to_, true));
        if (data_.length >= 4) return abi.encodeCall(guard.allowFunction, (address(sN), to_, _sel(data_), true, _noRules()));
        return "";
    }

    function _native(Verdicts memory v_, address to_, uint256 value_, bytes memory data_, Operation op_) internal {
        bytes memory _set = _setterFor(to_, data_, op_);
        v_.setOk = true;
        if (_set.length != 0) {
            vm.prank(VETRO);
            (v_.setOk, v_.setRet) = address(guard).call(_set);
        }
        (v_.n, v_.nr) = address(guard).call(abi.encodeCall(guard.validateTransaction, (address(sN), to_, value_, data_, op_)));
    }

    /// @dev THE APPROVAL LANE on `sA` (Lockdown): the admin issues, then the dry run of the exact payload (the live
    ///      hook's twin): the approval is usable iff it does not revert.
    function _approval(Verdicts memory v_, address to_, uint256 value_, bytes memory data_, Operation op_) internal {
        vm.prank(VETRO);
        (v_.i, v_.ir) = address(guard).call(_approveCall(address(0), to_, value_, data_, op_, TTL));
        if (!v_.i) return;
        (v_.u, ) = address(guard).call(abi.encodeCall(guard.validateTransaction, (address(sA), to_, value_, data_, op_)));
    }

    /*//////////////////////////////////////////////////////////////
                                 THE ORACLE
    //////////////////////////////////////////////////////////////*/

    /// @dev What the native lane admits: never the zero address nor the guard; on the Safe the rejection call
    ///      only; a value transfer to anything else; a function call (a selector) only to code.
    function _expectNative(uint8 c_, uint256 value_, uint256 len_, bool dc_) internal pure returns (bool) {
        if (dc_) return false; // a delegatecall is only ever the registered unwrapper with a well-formed batch (the concrete twin)
        if (c_ == C_ZERO || c_ == C_GUARD) return false;
        if (c_ == C_SAFE) return value_ == 0 && len_ == 0;
        if (c_ == C_EOA) return len_ == 0;
        return len_ == 0 || len_ >= 4; // DESIG, TL, LIB carry code
    }

    /// @dev What the approval lane issues: never the zero address nor the guard; to an account without code a
    ///      plain value transfer only; to an EIP-7702 designator never a delegatecall; the rest, anything.
    function _expectIssued(uint8 c_, uint256 len_, bool dc_) internal pure returns (bool) {
        if (c_ == C_ZERO || c_ == C_GUARD) return false;
        if (c_ == C_EOA) return len_ == 0 && !dc_;
        if (c_ == C_DESIG) return !dc_;
        return true;
    }

    /// @dev What the approval lane then lets through at use: everything issued, except a delegatecall into a
    ///      canonical library whose payload is no batch (the shapes of the domain: `MalformedMultiSend` or
    ///      `EmptyMultiSend`, the same decoder as the native lane's).
    function _expectUsable(uint8 c_, uint256 len_, bool dc_) internal pure returns (bool) {
        if (!_expectIssued(c_, len_, dc_)) return false;
        if (dc_ && c_ == C_LIB) return false;
        return true;
    }

    /// @dev Z2 for one class: the oracle on both lanes, the exact refusal on the zero address and the guard, and
    ///      the agreement of the lanes.
    function _Z2(uint8 c_, uint256 value_, bytes memory data_, bool dc_) internal {
        Verdicts memory _v;
        _native(_v, _target(c_, sN), value_, data_, _op(dc_));
        _approval(_v, _target(c_, sA), value_, data_, _op(dc_));
        _assertZ2(c_, value_, data_.length, dc_, _v);
    }

    function _assertZ2(uint8 c_, uint256 value_, uint256 len_, bool dc_, Verdicts memory v_) internal view {
        assert(v_.n == _expectNative(c_, value_, len_, dc_));
        assert(v_.i == _expectIssued(c_, len_, dc_));
        assert(v_.u == _expectUsable(c_, len_, dc_));
        if (c_ == C_ZERO) {
            assert(_isInvalidTarget(v_.i, v_.ir, address(0)));
            if (dc_ || len_ == 0 || len_ >= 4) assert(_isInvalidTarget(v_.setOk, v_.setRet, address(0)));
        }
        if (c_ == C_GUARD) assert(_isInvalidTarget(v_.i, v_.ir, address(guard)));
        // the agreement, on plain calls, for the shapes both lanes speak of
        if (!dc_ && (len_ == 0 || len_ >= 4)) {
            if (c_ != C_SAFE) assert(v_.n == v_.u);
            else assert(v_.u && v_.n == (value_ == 0 && len_ == 0));
        }
    }

    /// @dev Z1 for one caller: refused, with the rail's exact error for the admin and the council and
    ///      `Unauthorized` for everyone else, no approval, nothing moved.
    function _Z1(address who_, Req memory r_) internal {
        bytes32 _b = _digest();
        vm.prank(who_);
        (bool _ok, bytes memory _ret) = address(guard).call(_zeroApprove(guard, r_));
        assert(!_ok);
        if (who_ == VETRO || who_ == COUNCIL) assert(_isInvalidTarget(_ok, _ret, address(0)));
        else assert(_isUnauthorized(_ok, _ret));
        assert(guard.approvalExpiry(_zeroId(guard, r_)) == 0);
        assert(_digest() == _b);
    }

    /// @dev Z1c: wrapped in `executeBefore` by the admin or the council: the deadline first, then the rail; never
    ///      an approval.
    function _Z1c(bool council_, uint64 deadline_, Req memory r_) internal {
        bytes memory _inner = _zeroApprove(guard, r_);
        vm.prank(council_ ? COUNCIL : VETRO);
        (bool _ok, bytes memory _ret) = address(guard).call(abi.encodeCall(guard.executeBefore, (deadline_, _inner)));
        assert(!_ok);
        if (block.timestamp > deadline_) assert(_isDeadlinePassed(_ok, _ret, deadline_));
        else assert(_isInvalidTarget(_ok, _ret, address(0)));
        assert(guard.approvalExpiry(_zeroId(guard, r_)) == 0);
    }

    /// @dev Z1d: the production shape: the production guard whose admin is the timelock; a proposer schedules the approval, the
    ///      delay passes, anyone executes: the rail's error bubbles through the timelock, the operation stays
    ///      pending (never Done), no approval exists.
    function _Z1d(Req memory r_, bool exactReason_) internal {
        CuratorGuard _g = gT;
        bytes memory _call = _zeroApprove(_g, r_);
        bytes32 _id = tl.hashOperation(address(_g), 0, _call, bytes32(0), SALT);
        vm.prank(P1);
        tl.schedule(address(_g), 0, _call, bytes32(0), SALT, 1 days);
        vm.warp(block.timestamp + 1 days);
        vm.prank(STRANGER);
        (bool _ok, bytes memory _ret) = address(tl).call(abi.encodeCall(tl.execute, (address(_g), 0, _call, bytes32(0), SALT)));
        assert(!_ok);
        if (exactReason_) assert(_isInvalidTarget(_ok, _ret, address(0))); // the forge twin; halmos 0.3.3 does not carry the bubbled revert data through the timelock's `_execute` (G22b_Diag d1_4)
        assert(tl.isOperationPending(_id) && !tl.isOperationDone(_id));
        assert(_g.approvalExpiry(_zeroId(_g, r_)) == 0);
    }

    /// @dev Z3: a zero-target entry inside a batch: the approval lane issues the delegatecall into the canonical
    ///      library (it carries code) but the dry run refuses it at use with `MalformedMultiSend`; the native lane
    ///      registers the unwrapper and refuses the same batch with the same reason.
    function _Z3(uint256 value_, bytes memory entry_) internal {
        bytes memory _batch = abi.encodeWithSelector(MULTISEND, abi.encodePacked(uint8(0), address(0), value_, entry_.length, entry_));
        Verdicts memory _v;
        _approval(_v, LIB, 0, _batch, Operation.DelegateCall);
        assert(_v.i && !_v.u);
        (bool _ok, bytes memory _ret) = address(guard).call(abi.encodeCall(guard.validateTransaction, (address(sA), LIB, 0, _batch, Operation.DelegateCall)));
        assert(_isMalformedMultiSend(_ok, _ret));
        _native(_v, LIB, 0, _batch, Operation.DelegateCall);
        assert(_v.setOk && _isMalformedMultiSend(_v.n, _v.nr));
    }

    /// @dev Z4: every setter of the native lane refuses the zero address as a target with `InvalidTarget(0)`.
    function _Z4(uint8 which_, bytes4 sel_, bool flag_) internal {
        bytes memory _c;
        which_ = which_ % 5;
        if (which_ == 0) _c = abi.encodeCall(guard.setNativeTransferAllowed, (address(sN), address(0), true));
        else if (which_ == 1) _c = abi.encodeCall(guard.allowFunction, (address(sN), address(0), sel_, flag_, _noRules()));
        else if (which_ == 2) _c = abi.encodeCall(guard.setMultiSendUnwrapper, (address(sN), address(0), true));
        else if (which_ == 3) _c = abi.encodeCall(guard.setModuleAllowed, (address(sN), address(0), true));
        else _c = abi.encodeCall(guard.setGuardian, (address(sN), address(0), true));
        vm.prank(VETRO);
        (bool _ok, bytes memory _ret) = address(guard).call(_c);
        assert(_isInvalidTarget(_ok, _ret, address(0)));
        assert(!guard.isNativeTransferAllowed(address(sN), address(0)) && guard.selectors(address(sN), address(0)).length == 0);
    }
}
