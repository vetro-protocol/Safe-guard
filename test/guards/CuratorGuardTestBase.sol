// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";
import {MultiSendCallOnly} from "safe-contracts-v1.4.1/contracts/libraries/MultiSendCallOnly.sol";
import {MultiSend} from "safe-contracts-v1.4.1/contracts/libraries/MultiSend.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {TestERC20} from "test/mocks/TestERC20.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

/// @dev Stand-in for any allowlisted venue (a Lagoon vault, an ERC-4626, a lending pool).
contract MockProtocol {
    uint256 public lastAmount;
    address public lastReceiver;
    uint256 public lastValue;
    uint256 public calls;

    function settleDeposit(uint256 newTotalAssets_) external {
        lastAmount = newTotalAssets_;
        ++calls;
    }

    function deposit(uint256 assets_, address receiver_) external returns (uint256) {
        lastAmount = assets_;
        lastReceiver = receiver_;
        ++calls;
        return assets_;
    }

    function wrap() external payable {
        lastValue = msg.value;
        ++calls;
    }

    receive() external payable {
        lastValue = msg.value;
        ++calls;
    }
}

/// @dev What a mis-registered "unwrapper" can do: it runs in the Safe's storage context and may
///      rewrite any slot (guard, modules head, fallback handler, threshold, singleton, …).
contract MaliciousMultiSend {
    bytes32 internal immutable slot;
    bytes32 internal immutable value;

    constructor(bytes32 slot_, bytes32 value_) {
        slot = slot_;
        value = value_;
    }

    function multiSend(bytes memory) external payable {
        bytes32 _slot = slot;
        bytes32 _value = value;
        assembly {
            sstore(_slot, _value)
        }
    }
}

/// @dev Reverts on every call: exercises the `success == false` branch of `execTransaction`.
contract Reverter {
    error Nope();

    fallback() external payable {
        revert Nope();
    }
}

/// @dev Exposes the guard's internal constants so the tests can pin them to Safe's literals, and lets
///      the fixture seed the runtime hash of locally compiled `MultiSendCallOnly` builds (and of the
///      storage-writing "unwrapper" the snapshot tests use as a stand-in for a canonical build that
///      turned out to write storage). On the real guard the seeded set is fixed at deployment.
contract CuratorGuardHarness is CuratorGuard {
    constructor(uint48 adminDelay_, address admin_, address council_) CuratorGuard(adminDelay_, admin_, council_) {}

    function seedCodehash(bytes32 codehash_) external {
        _canonicalCodehashes[codehash_] = true;
        _unwrapperCodehashes[codehash_] = true;
    }

    /// @dev The guard pins canonical Safe proxy and singleton code (V2-85); the fixtures' locally
    ///      compiled (0.8.25) builds are seeded through the harness.
    function seedSafeCodehash(bytes32 codehash_) external {
        _safeCodehashes[codehash_] = true;
    }

    function seedSafe(address safe_) external {
        _safeCodehashes[safe_.codehash] = true;
        (, bytes memory _r) = safe_.staticcall(abi.encodeWithSelector(0xa619486e));
        if (_r.length == 32) _safeCodehashes[abi.decode(_r, (address)).codehash] = true;
    }

    function maxRules() external pure returns (uint256) {
        return MAX_RULES;
    }

    function maxSelectors() external pure returns (uint256) {
        return MAX_SELECTORS;
    }

    function maxGuardians() external pure returns (uint256) {
        return MAX_GUARDIANS;
    }

    function minAdminDelay() external pure returns (uint48) {
        return MIN_ADMIN_DELAY;
    }

    function tailFlag() external pure returns (uint16) {
        return TAIL_FLAG;
    }

    function maxAllowedValues() external pure returns (uint256) {
        return MAX_ALLOWED_VALUES;
    }

    function maxAdminApprovalTtl() external pure returns (uint64) {
        return MAX_ADMIN_APPROVAL_TTL;
    }

    function maxCouncilApprovalTtl() external pure returns (uint64) {
        return MAX_COUNCIL_APPROVAL_TTL;
    }

    function minBypass() external pure returns (uint64) {
        return MIN_BYPASS;
    }

    function maxAdminBypass() external pure returns (uint64) {
        return MAX_ADMIN_BYPASS;
    }

    function maxCouncilBypass() external pure returns (uint64) {
        return MAX_COUNCIL_BYPASS;
    }

    function maxAdminDelay() external pure returns (uint48) {
        return MAX_ADMIN_DELAY;
    }

    function minApprovalTtl() external pure returns (uint64) {
        return MIN_APPROVAL_TTL;
    }

    function minCouncilThreshold() external pure returns (uint256) {
        return MIN_COUNCIL_THRESHOLD;
    }

    function lockdownCooldown() external pure returns (uint64) {
        return LOCKDOWN_COOLDOWN;
    }


    function safeAddOwnerWithThreshold() external pure returns (bytes4) {
        return SAFE_ADD_OWNER_WITH_THRESHOLD;
    }

    function safeRemoveOwner() external pure returns (bytes4) {
        return SAFE_REMOVE_OWNER;
    }

    function safeSwapOwner() external pure returns (bytes4) {
        return SAFE_SWAP_OWNER;
    }

    function safeChangeThreshold() external pure returns (bytes4) {
        return SAFE_CHANGE_THRESHOLD;
    }

    function safeDisableModule() external pure returns (bytes4) {
        return SAFE_DISABLE_MODULE;
    }

    function safeSetFallbackHandler() external pure returns (bytes4) {
        return SAFE_SET_FALLBACK_HANDLER;
    }

    function codehashV130() external pure returns (bytes32) {
        return MULTISEND_CALL_ONLY_V130_CODEHASH;
    }

    function codehashV141() external pure returns (bytes32) {
        return MULTISEND_CALL_ONLY_V141_CODEHASH;
    }

    function codehashV150() external pure returns (bytes32) {
        return MULTISEND_CALL_ONLY_V150_CODEHASH;
    }

    function guardStorageSlot() external pure returns (bytes32) {
        return GUARD_STORAGE_SLOT;
    }

    function moduleGuardStorageSlot() external pure returns (bytes32) {
        return MODULE_GUARD_STORAGE_SLOT;
    }

    function fallbackHandlerStorageSlot() external pure returns (bytes32) {
        return FALLBACK_HANDLER_STORAGE_SLOT;
    }

    function modulesHeadSlot() external pure returns (bytes32) {
        return MODULES_HEAD_SLOT;
    }

    function multiSendSelector() external pure returns (bytes4) {
        return MULTISEND_SELECTOR;
    }

    function masterCopySelector() external pure returns (bytes4) {
        return MASTER_COPY_SELECTOR;
    }
}

/// @title CuratorGuardTestBase
/// @notice Real Safe v1.4.1 (singleton + proxy, 1-of-1 curator signer) with `CuratorGuard`
///         installed through a genuine `execTransaction(setGuard)`. The admin transfer delay is 0 so
///         role hand-overs can be exercised with a one-second warp.
abstract contract CuratorGuardTestBase is SafeTxHelper {
    CuratorGuard internal guard;
    MultiSendCallOnly internal multiSendCallOnly;
    MultiSend internal multiSend;
    TestERC20 internal token;
    MockProtocol internal protocol;

    /// @dev `vetro` holds `DEFAULT_ADMIN_ROLE` (production: the timelock), `council` the fast lane.
    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal guardian = makeAddr("guardian");
    address internal attacker = makeAddr("attacker");
    address internal curator;

    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 internal constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    bytes32 internal constant MODULES_HEAD_SLOT = 0xcc69885fda6bcc1a4ace058b4a62bf5e179ea78fd58a1ccd71c22cc9b688792f;

    function setUp() public virtual {
        // Foundry's default `block.timestamp == 1` collides with TimelockController's `_DONE_TIMESTAMP`
        // and hides off-by-one bugs in absolute warps: run every suite at a realistic time.
        if (block.timestamp < 1_700_000_000) vm.warp(1_700_000_000);
        (curator, signerPk) = makeAddrAndKey("curator");

        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        safe = ISafe(address(_proxy));
        vm.deal(address(safe), 10 ether);

        multiSendCallOnly = new MultiSendCallOnly();
        multiSend = new MultiSend();
        guard = new CuratorGuardHarness(0, vetro, council);
        CuratorGuardHarness(address(guard)).seedSafe(address(safe));
        token = new TestERC20("USDC", "USDC");
        protocol = new MockProtocol();
        token.mint(address(safe), 1_000_000e6);

        // Genuine install path: a Safe self-call executed by the curator before any guard is active.
        _execSafeTx(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(guard))), Operation.Call);
        assertEq(_installedGuard(), address(guard), "guard installed");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _installedGuard() internal view returns (address) {
        return address(uint160(uint256(bytes32(safe.getStorageAt(uint256(GUARD_SLOT), 1)))));
    }

    /// @dev Packed `MultiSend` entry: op(1) | to(20) | value(32) | len(32) | data.
    function _entry(address to_, uint256 value_, bytes memory data_) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to_, value_, data_.length, data_);
    }

    function _entryDelegate(address to_, bytes memory data_) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(1), to_, uint256(0), data_.length, data_);
    }

    function _multiSendCalldata(bytes memory packed_) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(MultiSendCallOnly.multiSend.selector, packed_);
    }

    function _enforce() internal {
        vm.prank(vetro);
        guard.enforce(address(safe));
    }

    function _bypass(uint64 duration_) internal {
        vm.prank(vetro);
        guard.bypass(address(safe), duration_);
    }

    function _addGuardian(address guardian_) internal {
        vm.prank(vetro);
        guard.setGuardian(address(safe), guardian_, true);
    }

    function _allow(address target_, bytes4 selector_) internal {
        vm.prank(vetro);
        guard.allowFunction(address(safe), target_, selector_, false, _noRules());
    }

    function _allowWithRules(address target_, bytes4 selector_, CuratorGuardPolicy.ParamRule[] memory rules_) internal {
        vm.prank(vetro);
        guard.allowFunction(address(safe), target_, selector_, false, rules_);
    }

    function _noRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _rules) {}

    /// @dev Registers `unwrapper_` for the fixture Safe after seeding its runtime code hash through the
    ///      harness (test contracts are compiled locally, so they never carry a canonical
    ///      `MultiSendCallOnly` hash; seeding a storage-writing build models a canonical build that
    ///      turned out to write storage, which is what the snapshot tests exercise).
    function _registerUnwrapper(address unwrapper_) internal {
        _seedCodehash(unwrapper_.codehash);
        vm.prank(vetro);
        guard.setMultiSendUnwrapper(address(safe), unwrapper_, true);
    }

    function _seedCodehash(bytes32 codehash_) internal {
        CuratorGuardHarness(address(guard)).seedCodehash(codehash_);
    }

    /// @dev The fixture guard as its harness (constants and seeding).
    function _H() internal view returns (CuratorGuardHarness) {
        return CuratorGuardHarness(address(guard));
    }

    function _isAllowed(address safe_, address target_, bytes4 selector_) internal view returns (bool) {
        return _isAllowedOn(guard, safe_, target_, selector_);
    }

    function _isAllowedOn(CuratorGuard guard_, address safe_, address target_, bytes4 selector_) internal view returns (bool _allowed) {
        (_allowed, , ) = guard_.functionPermission(safe_, target_, selector_);
    }

    function _contains(address[] memory list_, address a_) internal pure returns (bool) {
        for (uint256 i; i < list_.length; ++i) if (list_[i] == a_) return true;
        return false;
    }

    /// @dev Owner-path approval by the admin (executor = address(0)), 1 day validity.
    function _approve(address to_, uint256 value_, bytes memory data_, Operation op_) internal returns (bytes32) {
        vm.prank(vetro);
        return guard.approveTransaction(address(safe), address(0), to_, value_, data_, op_, uint64(1 days));
    }

    /// @dev Owner-path approval by the council, 1 day validity.
    function _councilApprove(address to_, uint256 value_, bytes memory data_, Operation op_) internal returns (bytes32) {
        vm.prank(council);
        return guard.approveTransaction(address(safe), address(0), to_, value_, data_, op_, uint64(1 days));
    }

    function _rule(
        CuratorGuardPolicy.RuleKind kind_,
        uint16 wordIndex_,
        bytes32 value_
    ) internal pure returns (CuratorGuardPolicy.ParamRule[] memory _rules) {
        _rules = new CuratorGuardPolicy.ParamRule[](1);
        _rules[0] = CuratorGuardPolicy.ParamRule({kind: kind_, wordIndex: wordIndex_, value: value_});
    }

    function _word(address a_) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a_)));
    }
}
