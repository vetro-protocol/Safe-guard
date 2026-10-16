// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Vm.sol";
import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";
import {TestERC20} from "test/mocks/TestERC20.sol";

interface IERC20Like {
    function allowance(address owner, address spender) external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/// @dev Round 10, reviewer g10d (the adversary, second persona). A venue that turned hostile: during
///      the Safe's allowlisted call it runs whatever the test queued (re-entering the Safe, the guard
///      or the timelock) and records each result, and it answers `getStorageAt` like a Safe would, so
///      the guard's "is this a Safe" reads can be probed. `runQueue` is the entry a hostile vault
///      LOGIC calls when it runs inside a proxy and must not write its own storage.
contract HostileVenue {
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    Call[] internal queue;
    bool[] internal oks;
    bytes[] internal rets;
    mapping(uint256 => bytes32) public slots;
    uint256 public pokes;

    function queueCall(address target_, uint256 value_, bytes calldata data_) external {
        queue.push(Call(target_, value_, data_));
    }

    function setSlot(bytes32 slot_, bytes32 word_) external {
        slots[uint256(slot_)] = word_;
    }

    function reset() external {
        delete queue;
        delete oks;
        delete rets;
    }

    function count() external view returns (uint256) {
        return oks.length;
    }

    function ok(uint256 i_) external view returns (bool) {
        return oks[i_];
    }

    function ret(uint256 i_) external view returns (bytes memory) {
        return rets[i_];
    }

    function selectorOf(uint256 i_) external view returns (bytes4) {
        bytes memory _r = rets[i_];
        return _r.length >= 4 ? bytes4(_r) : bytes4(0);
    }

    /// @dev The allowlisted entry point (`poke(uint256)`).
    function poke(uint256) external {
        _run();
    }

    function runQueue() external {
        _run();
    }

    function _run() internal {
        ++pokes;
        uint256 _n = queue.length;
        for (uint256 i; i < _n; ++i) {
            Call storage _c = queue[i];
            (bool _ok, bytes memory _r) = _c.target.call{value: _c.value}(_c.data);
            oks.push(_ok);
            rets.push(_r);
        }
    }

    /// @dev Answers like a Safe's `getStorageAt(offset, 1)`: a `bytes` of one word (96 bytes in all).
    function getStorageAt(uint256 offset_, uint256) external view returns (bytes memory) {
        return abi.encodePacked(slots[offset_]);
    }

    receive() external payable {}
}

/// @dev Delegatecalled in the Safe's own context through `simulateAndRevert`: whatever it calls, the
///      guard sees the SAFE as the caller.
contract SimDriver {
    function forgePostHook(address guard_, bytes32 hash_) external {
        CuratorGuard(guard_).checkAfterExecution(hash_, true);
    }
}

/// @dev A hostile Lagoon vault implementation (what an upgrade through the vault's own proxy admin, or a
///      backdoor in the deployed logic, would run under the allowlisted selectors). Immutables only: it
///      runs in the proxy's storage context. It takes what it can (the Safe's allowance to the vault) and
///      hands the reentrancy probes to its brain.
contract HostileVaultLogic {
    address internal immutable token;
    address internal immutable safe;
    address internal immutable loot;
    HostileVenue internal immutable brain;

    constructor(address token_, address safe_, address loot_, HostileVenue brain_) {
        token = token_;
        safe = safe_;
        loot = loot_;
        brain = brain_;
    }

    /// @dev `updateNewTotalAssets(uint256)`: the selector the policy allows unconstrained.
    function updateNewTotalAssets(uint256) external {
        uint256 _allowance = IERC20Like(token).allowance(safe, address(this));
        uint256 _balance = IERC20Like(token).balanceOf(safe);
        IERC20Like(token).transferFrom(safe, loot, _allowance < _balance ? _allowance : _balance);
        if (address(brain) != address(0)) brain.runQueue();
    }
}

/// @dev Signing and log helpers shared by the unit and the fork suites.
abstract contract G10dSigner is SafeTxHelper {
    bytes32 internal constant REPORT_SIG = keccak256("TransactionChecked(address,bytes32,uint8,uint8)");
    bytes4 internal constant ERROR_STRING = 0x08c379a0;

    function _nonceOf(ISafe safe_) internal view returns (uint256) {
        return uint256(vm.load(address(safe_), bytes32(NONCE_SLOT)));
    }

    /// @dev The full `execTransaction` calldata of `safe_` signed by `pk_` at `nonce_`: what a signer
    ///      quorum leaves in the Transaction Service, and what a hostile venue can therefore hold.
    function _signedExecCalldata(
        ISafe safe_,
        uint256 pk_,
        uint256 nonce_,
        address to_,
        uint256 value_,
        bytes memory data_,
        Operation op_
    ) internal view returns (bytes memory) {
        SafeTx memory _t = SafeTx(to_, value_, data_, op_, 0, 0, address(0), address(0));
        bytes32 _domain = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, address(safe_)));
        bytes32 _hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), _domain, _safeTxHash(_t, nonce_)));
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(pk_, _hash);
        return
            abi.encodeCall(
                ISafe.execTransaction,
                (to_, value_, data_, op_, 0, 0, 0, address(0), payable(address(0)), abi.encodePacked(_r, _s, _v))
            );
    }

    /// @dev `TransactionChecked` reports emitted by `guard_` in `logs_`: how many, the last outcome and hash.
    function _reports(
        Vm.Log[] memory logs_,
        address guard_
    ) internal pure returns (uint256 _n, uint8 _lastOutcome, bytes32 _lastHash) {
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter == guard_ && logs_[i].topics.length == 4 && logs_[i].topics[0] == REPORT_SIG) {
                ++_n;
                _lastOutcome = uint8(uint256(logs_[i].topics[3]));
                _lastHash = logs_[i].topics[2];
            }
        }
    }

    /// @dev The string of an `Error(string)` revert, "" otherwise.
    function _reason(bytes memory r_) internal pure returns (string memory) {
        if (r_.length < 68 || bytes4(r_) != ERROR_STRING) return "";
        bytes memory _tail = new bytes(r_.length - 4);
        for (uint256 i; i < _tail.length; ++i) _tail[i] = r_[i + 4];
        return abi.decode(_tail, (string));
    }

    function _selectorOf(bytes memory r_) internal pure returns (bytes4) {
        return r_.length >= 4 ? bytes4(r_) : bytes4(0);
    }

    /// @dev `cd_` sent to `safe_` must fail with the Safe's own `reason_`.
    function _safeCallFails(ISafe safe_, bytes memory cd_, string memory reason_) internal {
        (bool _ok, bytes memory _r) = address(safe_).call(cd_);
        assertFalse(_ok, "the Safe call must fail");
        assertEq(_reason(_r), reason_, "Safe reason");
    }
}

/// @dev The production topology with a REAL Safe v1.4.1 proxy behind every principal (as g9c built it):
///      two proposer Safes and one veto Safe on a `CuratorGuardTimelock` (minDelay 2 days), the guard with
///      that timelock as admin (admin-transfer delay 3 days) and an EOA council, a per-Safe guardian and a
///      deployment-wide one, and a curator Safe holding the custody token whose one-function policy is
///      applied through the timelock and installed through a genuine `execTransaction(setGuard)`.
abstract contract G10dBase is G10dSigner {
    uint256 internal constant MIN_DELAY = 2 days;
    uint48 internal constant ADMIN_DELAY = 3 days;
    bytes32 internal constant NONE = bytes32(0);
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes4 internal constant TRANSFER = 0xa9059cbb;

    Safe internal singleton;
    CuratorGuardHarness internal g;
    CuratorGuardTimelock internal tl;
    MockProtocol internal protocol;
    TestERC20 internal token;

    address internal council = makeAddr("council");
    address internal council2 = makeAddr("council-2");
    address internal guardian = makeAddr("guardian");
    address internal bot = makeAddr("bot");
    address internal stranger;
    uint256 internal strangerPk;

    ISafe internal curatorSafe;
    uint256 internal curatorPk;
    ISafe internal p1;
    uint256 internal p1Pk;
    ISafe internal p2;
    uint256 internal p2Pk;
    ISafe internal veto;
    uint256 internal vetoPk;

    function setUp() public virtual {
        vm.warp(1_700_000_000);
        (stranger, strangerPk) = makeAddrAndKey("stranger");
        singleton = new Safe();
        (curatorSafe, curatorPk) = _newSafe("curator");
        (p1, p1Pk) = _newSafe("proposer-1");
        (p2, p2Pk) = _newSafe("proposer-2");
        (veto, vetoPk) = _newSafe("veto");
        tl = _newTimelock(MIN_DELAY);
        g = _newGuard(address(tl), council);
        protocol = new MockProtocol();
        token = new TestERC20("USDC", "USDC");
        token.mint(address(curatorSafe), 1_000_000e6);
    }

    function _newTimelock(uint256 minDelay_) internal returns (CuratorGuardTimelock) {
        address[] memory _p = new address[](2);
        _p[0] = address(p1);
        _p[1] = address(p2);
        address[] memory _c = new address[](1);
        _c[0] = address(veto);
        return new CuratorGuardTimelock(minDelay_, _p, _c);
    }

    function _newGuard(address admin_, address council_) internal returns (CuratorGuardHarness _g) {
        _g = new CuratorGuardHarness(ADMIN_DELAY, admin_, council_);
        _g.seedSafe(address(curatorSafe)); // every proxy shares one code hash and the one singleton
    }

    function _newSafe(string memory name_) internal returns (ISafe _safe, uint256 _pk) {
        address _owner;
        (_owner, _pk) = makeAddrAndKey(name_);
        SafeProxy _proxy = new SafeProxy(address(singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = _owner;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        _safe = ISafe(address(_proxy));
        vm.deal(address(_safe), 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                           SAFE TRANSACTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev A Safe transaction of `safe_` signed by its single owner (`safeTxGas = 0`, no refund).
    function _exec(ISafe safe_, uint256 pk_, address to_, uint256 value_, bytes memory data_, Operation op_) internal returns (bool) {
        safe = safe_;
        signerPk = pk_;
        return _execSafeTx(to_, value_, data_, op_);
    }

    function _curatorExec(address to_, uint256 value_, bytes memory data_, Operation op_) internal returns (bool) {
        return _exec(curatorSafe, curatorPk, to_, value_, data_, op_);
    }

    function _installOn(ISafe safe_, uint256 pk_) internal {
        _exec(safe_, pk_, address(safe_), 0, abi.encodeCall(ISafe.setGuard, (address(g))), Operation.Call);
        assertEq(_guardOf(safe_), address(g), "guard installed");
    }

    function _guardOf(ISafe safe_) internal view returns (address) {
        return address(uint160(uint256(bytes32(safe_.getStorageAt(uint256(GUARD_SLOT), 1)))));
    }

    function _balance() internal view returns (uint256) {
        return token.balanceOf(address(curatorSafe));
    }

    /// @dev Every way an account that is not the curator's quorum could try to move the Safe: a transaction
    ///      signed by its own key, one with no signature, a pre-approved hash, the module path.
    function _strangerCannotMoveCustody() internal {
        bytes memory _drain = abi.encodeWithSelector(TRANSFER, stranger, _balance());
        uint256 _nonce = _nonceOf(curatorSafe);
        _safeCallFails(curatorSafe, _signedExecCalldata(curatorSafe, strangerPk, _nonce, address(token), 0, _drain, Operation.Call), "GS026");
        _safeCallFails(
            curatorSafe,
            abi.encodeCall(ISafe.execTransaction, (address(token), 0, _drain, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "")),
            "GS020"
        );
        vm.startPrank(stranger);
        _safeCallFails(curatorSafe, abi.encodeWithSignature("approveHash(bytes32)", bytes32(uint256(1))), "GS030");
        _safeCallFails(curatorSafe, abi.encodeCall(ISafe.execTransactionFromModule, (address(token), 0, _drain, Operation.Call)), "GS104");
        vm.stopPrank();
        assertEq(token.balanceOf(stranger), 0, "nothing moved");
    }

    /*//////////////////////////////////////////////////////////////
                                TIMELOCK
    //////////////////////////////////////////////////////////////*/

    /// @dev `proposer_` schedules a one-call operation through a genuine Safe transaction, at the live delay.
    function _schedule(ISafe proposer_, uint256 pk_, address target_, bytes memory data_, bytes32 pred_, bytes32 salt_) internal returns (bytes32) {
        uint256 _delay = tl.getMinDelay();
        _exec(proposer_, pk_, address(tl), 0, abi.encodeCall(tl.schedule, (target_, 0, data_, pred_, salt_, _delay)), Operation.Call);
        return tl.hashOperation(target_, 0, data_, pred_, salt_);
    }

    function _scheduleBatch(
        ISafe proposer_,
        uint256 pk_,
        address[] memory targets_,
        bytes[] memory payloads_,
        bytes32 pred_,
        bytes32 salt_
    ) internal returns (bytes32) {
        uint256[] memory _values = new uint256[](targets_.length);
        uint256 _delay = tl.getMinDelay();
        _exec(proposer_, pk_, address(tl), 0, abi.encodeCall(tl.scheduleBatch, (targets_, _values, payloads_, pred_, salt_, _delay)), Operation.Call);
        return tl.hashOperationBatch(targets_, _values, payloads_, pred_, salt_);
    }

    function _execute(address target_, bytes memory data_, bytes32 pred_, bytes32 salt_) internal {
        vm.prank(stranger); // the executor role is open
        tl.execute(target_, 0, data_, pred_, salt_);
    }

    function _executeBatch(address[] memory targets_, bytes[] memory payloads_, bytes32 pred_, bytes32 salt_) internal {
        uint256[] memory _values = new uint256[](targets_.length);
        vm.prank(stranger);
        tl.executeBatch(targets_, _values, payloads_, pred_, salt_);
    }

    function _cancel(bytes32 id_) internal {
        _exec(veto, vetoPk, address(tl), 0, abi.encodeCall(tl.cancel, (id_)), Operation.Call);
    }

    /// @dev One admin batch on the guard through the timelock: p1 schedules, the delay passes, anyone executes.
    function _adminBatch(bytes[] memory payloads_, bytes32 salt_) internal {
        address[] memory _t = _guardTargets(payloads_.length);
        _scheduleBatch(p1, p1Pk, _t, payloads_, NONE, salt_);
        vm.warp(block.timestamp + MIN_DELAY);
        _executeBatch(_t, payloads_, NONE, salt_);
    }

    function _guardTargets(uint256 n_) internal view returns (address[] memory _t) {
        _t = new address[](n_);
        for (uint256 i; i < n_; ++i) _t[i] = address(g);
    }

    function _values(uint256 n_) internal pure returns (uint256[] memory _v) {
        _v = new uint256[](n_);
    }

    /// @dev The takeover a compromised proposer schedules: the honest council out, its own key in, and a
    ///      180-day ADMIN window on the curator Safe (an admin window checks nothing, `setGuard(0)` included).
    function _takeover() internal view returns (address[] memory _t, bytes[] memory _p) {
        _t = _guardTargets(3);
        _p = new bytes[](3);
        _p[0] = abi.encodeCall(g.revokeRole, (g.COUNCIL_ROLE(), council));
        _p[1] = abi.encodeCall(g.grantRole, (g.COUNCIL_ROLE(), stranger));
        _p[2] = abi.encodeCall(g.bypass, (address(curatorSafe), uint64(180 days)));
    }

    /*//////////////////////////////////////////////////////////////
                              CURATOR POLICY
    //////////////////////////////////////////////////////////////*/

    /// @dev The curator Safe's policy (`settleDeposit` on the mock venue, a per-Safe and a deployment-wide
    ///      guardian, Enforced) applied through the timelock, then the guard installed by the curator.
    function _configureCurator() internal {
        bytes[] memory _d = new bytes[](4);
        _d[0] = abi.encodeCall(g.allowFunction, (address(curatorSafe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules()));
        _d[1] = abi.encodeCall(g.setGuardian, (address(curatorSafe), guardian, true));
        _d[2] = abi.encodeCall(g.setDeploymentGuardian, (bot, true));
        _d[3] = abi.encodeCall(g.enforce, (address(curatorSafe)));
        _adminBatch(_d, "policy");
        _installOn(curatorSafe, curatorPk);
        assertTrue(_settle(), "policy call passes");
    }

    function _settle() internal returns (bool) {
        return _curatorExec(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1)), Operation.Call);
    }

    function _noRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _rules) {}

    function _word(address a_) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a_)));
    }
}
