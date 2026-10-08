// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";
import {Vm} from "forge-std/Vm.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @dev Round 8, reviewer q: two real Safe v1.4.1 proxies (`safe` = A from the repo fixture, `safeB`)
///      on ONE guard, plus a second, independent guard instance (`otherGuard`) with a third Safe
///      configured on it, so that "a Safe configured on another guard" is a real caller kind.
abstract contract StrangersBase is CuratorGuardTestBase {
    ISafe internal safeB;
    uint256 internal signerPkB;
    address internal curatorB;
    MockProtocol internal protocolB;
    address internal guardianA = makeAddr("guardian-of-A-only");
    address internal guardianB = makeAddr("guardian-of-B-only");

    CuratorGuard internal otherGuard;
    ISafe internal safeC; // configured on `otherGuard`, never on `guard`
    uint256 internal signerPkC;
    address internal curatorC;

    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;
    bytes4 internal constant DEPOSIT = MockProtocol.deposit.selector;

    function setUp() public virtual override {
        super.setUp();
        (curatorB, signerPkB) = makeAddrAndKey("curatorB");
        (curatorC, signerPkC) = makeAddrAndKey("curatorC");
        safeB = _newSafe(curatorB);
        safeC = _newSafe(curatorC);
        protocolB = new MockProtocol();
        vm.deal(address(safeB), 10 ether);
        vm.deal(address(safeC), 10 ether);

        // B installs the SAME guard; A is already installed by the repo fixture.
        _execAs(safeB, signerPkB, address(safeB), 0, abi.encodeCall(ISafe.setGuard, (address(guard))), Operation.Call);
        // C installs a second guard deployment (same admin and council for simplicity).
        otherGuard = new CuratorGuardHarness(0, vetro, council);
        CuratorGuardHarness(address(otherGuard)).seedSafe(address(safeC)); // the guard pins canonical Safe code
        _execAs(safeC, signerPkC, address(safeC), 0, abi.encodeCall(ISafe.setGuard, (address(otherGuard))), Operation.Call);

        vm.startPrank(vetro);
        guard.enforce(address(safe));
        guard.allowFunction(address(safe), address(protocol), SETTLE, false, _noRules());
        guard.setGuardian(address(safe), guardianA, true);
        guard.enforce(address(safeB));
        guard.allowFunction(address(safeB), address(protocolB), SETTLE, false, _noRules());
        guard.setGuardian(address(safeB), guardianB, true);
        otherGuard.enforce(address(safeC));
        otherGuard.allowFunction(address(safeC), address(protocol), SETTLE, false, _noRules());
        vm.stopPrank();
    }

    function _newSafe(address owner_) internal returns (ISafe) {
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = owner_;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        return ISafe(address(_proxy));
    }

    /// @dev `_execSafeTx` for an arbitrary (Safe, signer) pair; the repo helper is bound to `safe`.
    function _execAs(
        ISafe safe_,
        uint256 pk_,
        address to_,
        uint256 value_,
        bytes memory data_,
        Operation op_
    ) internal returns (bool _ok) {
        ISafe _saved = safe;
        uint256 _savedPk = signerPk;
        safe = safe_;
        signerPk = pk_;
        _ok = _execSafeTx(to_, value_, data_, op_);
        safe = _saved;
        signerPk = _savedPk;
    }

    /// @dev Signature for a Safe transaction of `safe_` at its current nonce, so a test can hand it to a
    ///      relayer contract (the executor of `execTransaction` is then NOT the test).
    function _signatureFor(
        ISafe safe_,
        uint256 pk_,
        address to_,
        uint256 value_,
        bytes memory data_,
        Operation op_
    ) internal returns (bytes memory _sig) {
        ISafe _saved = safe;
        uint256 _savedPk = signerPk;
        safe = safe_;
        signerPk = pk_;
        _sig = _sign(_txHash(SafeTx(to_, value_, data_, op_, 0, 0, address(0), address(0))));
        safe = _saved;
        signerPk = _savedPk;
    }

    function _guardLogs(Vm.Log[] memory logs_, bytes32 topic0_) internal view returns (uint256 _n) {
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter == address(guard) && logs_[i].topics[0] == topic0_) ++_n;
        }
    }

    /// @dev One hash over everything the guard reports about `safe_` plus the deployment-wide state,
    ///      so a test can assert "nothing changed for X" after a hostile call.
    function _state(CuratorGuard g_, address safe_) internal view returns (bytes32) {
        bytes memory _acc = abi.encode(
            g_.mode(safe_),
            g_.lockedAt(safe_),
            g_.approvalEpoch(safe_),
            g_.targets(safe_),
            g_.multiSendUnwrappers(safe_),
            g_.modules(safe_),
            g_.guardians(safe_)
        );
        _acc = abi.encode(_acc, _windowAndHandler(g_, safe_), _policyBody(g_, safe_), _global(g_));
        (address _pending, uint48 _schedule) = g_.pendingDefaultAdmin();
        (uint48 _pDelay, uint48 _pSchedule) = g_.pendingDefaultAdminDelay();
        return keccak256(abi.encode(_acc, _pending, _schedule, _pDelay, _pSchedule));
    }

    function _windowAndHandler(CuratorGuard g_, address safe_) internal view returns (bytes memory) {
        (uint64 _until, bool _council) = g_.bypassWindow(safe_);
        (address _handler, bool _enforce) = g_.requiredFallbackHandler(safe_);
        return abi.encode(_until, _council, _handler, _enforce);
    }

    function _policyBody(CuratorGuard g_, address safe_) internal view returns (bytes memory _acc) {
        address[] memory _targets = g_.targets(safe_);
        for (uint256 i; i < _targets.length; ++i) {
            bytes32[] memory _sels = g_.selectors(safe_, _targets[i]);
            _acc = abi.encode(_acc, _targets[i], _sels, g_.isNativeTransferAllowed(safe_, _targets[i]));
            for (uint256 j; j < _sels.length; ++j) _acc = abi.encode(_acc, _function(g_, safe_, _targets[i], bytes4(_sels[j])));
        }
    }

    function _function(CuratorGuard g_, address safe_, address target_, bytes4 selector_) internal view returns (bytes memory _acc) {
        (bool _a, bool _v, CuratorGuardPolicy.ParamRule[] memory _r) = g_.functionPermission(safe_, target_, selector_);
        _acc = abi.encode(_a, _v, _r.length);
        for (uint256 k; k < _r.length; ++k) {
            _acc = abi.encode(_acc, _r[k].kind, _r[k].wordIndex, _r[k].value, g_.allowedValues(safe_, target_, selector_, _r[k].wordIndex));
        }
    }

    function _global(CuratorGuard g_) internal view returns (bytes memory) {
        return
            abi.encode(
                g_.defaultAdmin(),
                g_.defaultAdminDelay(),
                g_.isUnwrapperCodehash(_H().codehashV130()),
                g_.isUnwrapperCodehash(_H().codehashV141()),
                g_.isUnwrapperCodehash(_H().codehashV150()),
                g_.hasRole(g_.COUNCIL_ROLE(), council),
                g_.hasRole(g_.GUARDIAN_ROLE(), guardian)
            );
    }
}
