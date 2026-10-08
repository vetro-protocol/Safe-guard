// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";
import {G9fHarness} from "test/guards/G9fBase.sol";

/// @dev A proxy that is NOT a Safe build but answers `masterCopy()` with a canonical singleton and
///      forwards everything else to it: what a custom or re-compiled proxy in front of the real Safe
///      code looks like to the guard's two code-hash terms.
contract G9fForwardingProxy {
    address internal immutable singleton;

    constructor(address singleton_) {
        singleton = singleton_;
    }

    function masterCopy() external view returns (address) {
        return singleton;
    }

    fallback() external payable {
        address _s = singleton;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let _ok := delegatecall(gas(), _s, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(_ok) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
    }

    receive() external payable {}
}

/// @dev Runs one pre-encoded call (used to nest an owner-signed `execTransaction` inside a module one).
contract G9fNester {
    bytes public lastError;

    function run(address target_, bytes calldata call_) external returns (bool ok) {
        bytes memory _ret;
        (ok, _ret) = target_.call(call_);
        if (!ok) lastError = _ret;
    }
}

contract G9fModule {
    function exec(ISafe safe_, address to_, uint256 value_, bytes calldata data_, Operation op_) external returns (bool) {
        return safe_.execTransactionFromModule(to_, value_, data_, op_);
    }
}

/// @title Round 9 (g9f): killers for the mutants that survived the repository suite, and the pins the
///        rule-to-test map found missing (docs sections 4, 6 and 10).
contract CuratorGuardG9fMutationTest is CuratorGuardTestBase {
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;

    function _settle(uint256 n_) internal pure returns (bytes memory) {
        return abi.encodeCall(MockProtocol.settleDeposit, (n_));
    }

    /// @dev M14: the proxy's OWN code is pinned, not only the singleton's. A non-canonical proxy in
    ///      front of a canonical singleton (`masterCopy()` answers one honest word, every view works)
    ///      is `SafeNotSupported` on the policy path; approvals and windows still serve it.
    function test_a_non_canonical_proxy_in_front_of_a_canonical_singleton_is_refused() public {
        address _singleton = address(uint160(uint256(vm.load(address(safe), bytes32(0))))); // seeded by the fixture
        G9fForwardingProxy _proxy = new G9fForwardingProxy(_singleton);
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        (bool _ok, ) = address(_proxy).call(
            abi.encodeWithSignature(
                "setup(address[],uint256,address,bytes,address,address,uint256,address)",
                _owners, 1, address(0), "", address(0), address(0), 0, address(0)
            )
        );
        assertTrue(_ok, "the forwarding proxy is a working Safe");
        vm.prank(address(_proxy));
        ISafe(address(_proxy)).setGuard(address(guard));
        vm.startPrank(vetro);
        guard.enforce(address(_proxy));
        guard.allowFunction(address(_proxy), address(protocol), SETTLE, false, _noRules());
        vm.stopPrank();
        bytes memory _err = abi.encodeWithSelector(CuratorGuard.SafeNotSupported.selector, address(_proxy));
        vm.expectRevert(_err);
        guard.validateTransaction(address(_proxy), address(protocol), 0, _settle(1), Operation.Call);
        vm.prank(address(_proxy));
        vm.expectRevert(_err);
        guard.checkTransaction(address(protocol), 0, _settle(1), Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0));
        // The exits: an approval and a window do not read the configuration.
        vm.prank(vetro);
        guard.approveTransaction(address(_proxy), address(0), address(protocol), 0, _settle(2), Operation.Call, 1 days);
        guard.validateTransaction(address(_proxy), address(protocol), 0, _settle(2), Operation.Call);
        vm.prank(council);
        guard.bypass(address(_proxy), 1 hours);
        guard.validateTransaction(address(_proxy), address(protocol), 0, _settle(1), Operation.Call);
    }

    /// @dev M16: `masterCopy()` must answer exactly one word. A two-word answer whose FIRST word is a
    ///      canonical singleton is still not a `SafeProxy` answer and is refused.
    function test_masterCopy_answering_a_canonical_singleton_in_two_words_is_refused() public {
        _enforce();
        _allow(address(protocol), SETTLE);
        address _singleton = address(uint160(uint256(vm.load(address(safe), bytes32(0)))));
        guard.validateTransaction(address(safe), address(protocol), 0, _settle(1), Operation.Call);
        vm.mockCall(address(safe), abi.encodeWithSelector(_H().masterCopySelector()), abi.encode(_singleton, uint256(1)));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeNotSupported.selector, address(safe)));
        guard.validateTransaction(address(safe), address(protocol), 0, _settle(1), Operation.Call);
        vm.clearMockedCalls();
        guard.validateTransaction(address(safe), address(protocol), 0, _settle(1), Operation.Call);
    }

    /// @dev M08: an approved batch into a canonical `MultiSendCallOnly` build is decoded at use
    ///      "registered or not, forbidden or not" (NatSpec of `_checkApprovalUse`): a build whose hash a
    ///      guardian FORBADE still gets the strict decoder, so a truncated approved payload into it is
    ///      refused with the approval kept.
    function test_approved_batch_into_a_forbidden_canonical_build_is_still_decoded() public {
        bytes32 _hash = address(multiSendCallOnly).codehash;
        _seedCodehash(_hash); // the fixture build stands in for a canonical one
        vm.prank(council);
        guard.setUnwrapperCodehash(_hash, false);
        assertFalse(guard.isUnwrapperCodehash(_hash), "forbidden");
        bytes memory _packed = _entry(attacker, 1 ether, "");
        bytes memory _cut = new bytes(45);
        for (uint256 i; i < 45; ++i) _cut[i] = _packed[i];
        bytes memory _batch = _multiSendCalldata(_cut);
        bytes32 _id = _approve(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        guard.validateTransaction(address(safe), address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
        vm.expectRevert(CuratorGuard.MalformedMultiSend.selector);
        _execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
        assertGt(guard.approvalExpiry(_id), 0, "approval kept");
        assertEq(attacker.balance, 0, "nothing moved");
        // A well-formed approved batch into the forbidden build still runs (the approval decides).
        bytes memory _good = _multiSendCalldata(_entry(address(protocol), 0, _settle(3)));
        _approve(address(multiSendCallOnly), 0, _good, Operation.DelegateCall);
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _good, Operation.DelegateCall));
        assertEq(protocol.lastAmount(), 3);
    }

    /// @dev P30: a Safe configured ONLY through an unwrapper registration counts as guarded for the
    ///      admin transfer and for role grants (`AdminIsGuarded`), like one configured through targets,
    ///      modules, a handler requirement or (transfer only) guardians.
    function test_a_safe_configured_only_through_an_unwrapper_cannot_become_admin_or_a_role_holder() public {
        address _x = makeAddr("unwrapper-only-safe");
        _seedCodehash(address(multiSendCallOnly).codehash);
        vm.prank(vetro);
        guard.setMultiSendUnwrapper(_x, address(multiSendCallOnly), true);
        assertEq(guard.targets(_x).length, 0);
        assertEq(guard.modules(_x).length, 0);
        bytes32 _councilRole = guard.COUNCIL_ROLE();
        vm.startPrank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, _x));
        guard.beginDefaultAdminTransfer(_x);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, _x));
        guard.grantRole(_councilRole, _x);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.AdminIsGuarded.selector, _x));
        guard.setDeploymentGuardian(_x, true);
        // Deregistering it makes the address unconfigured again.
        guard.setMultiSendUnwrapper(_x, address(multiSendCallOnly), false);
        guard.grantRole(_councilRole, _x);
        vm.stopPrank();
        assertTrue(guard.hasRole(_councilRole, _x));
    }

    /*//////////////////////////////////////////////////////////////
              DOCUMENTED CLAIMS WITHOUT A TEST (docs section 4)
    //////////////////////////////////////////////////////////////*/

    /// @dev "Re-approving a payload overwrites its expiry; it never grants a second execution."
    function test_reapproval_overwrites_the_expiry_and_never_grants_a_second_execution() public {
        bytes memory _data = _settle(1);
        bytes32 _id = _approve(address(protocol), 0, _data, Operation.Call);
        uint64 _first = guard.approvalExpiry(_id);
        vm.warp(block.timestamp + 1 hours);
        bytes32 _again = _approve(address(protocol), 0, _data, Operation.Call);
        assertEq(_again, _id, "same id in the same epoch");
        assertEq(guard.approvalExpiry(_id), _first + 1 hours, "expiry overwritten");
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call));
        assertEq(guard.approvalExpiry(_id), 0, "consumed");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, _data, Operation.Call);
    }

    /// @dev "Approvals outlive admin transfers (they are keyed by Safe and epoch, not by who issued them)."
    function test_approvals_outlive_an_admin_transfer() public {
        bytes memory _data = _settle(2);
        bytes32 _id = _approve(address(protocol), 0, _data, Operation.Call);
        address _next = makeAddr("next-admin");
        vm.prank(vetro);
        guard.beginDefaultAdminTransfer(_next);
        vm.warp(block.timestamp + 1);
        vm.prank(_next);
        guard.acceptDefaultAdminTransfer();
        assertEq(guard.defaultAdmin(), _next);
        assertGt(guard.approvalExpiry(_id), 0, "still live under the new admin");
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call), "consumed under the new admin");
        assertEq(protocol.lastAmount(), 2);
        vm.prank(vetro);
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guard.approveTransaction(address(safe), address(0), address(protocol), 0, _data, Operation.Call, 1 days);
    }

    /// @dev "A decommissioned guard keeps its unexpired ones, so `revokeAllApprovals` on decommission":
    ///      an approval issued before an approved `setGuard(0)` is consumable after a re-install.
    function test_a_decommissioned_guard_keeps_its_unexpired_approvals_until_revoked() public {
        bytes memory _data = _settle(3);
        bytes32 _id = _approve(address(protocol), 0, _data, Operation.Call);
        bytes memory _remove = abi.encodeCall(ISafe.setGuard, (address(0)));
        _approve(address(safe), 0, _remove, Operation.Call);
        assertTrue(_execSafeTx(address(safe), 0, _remove, Operation.Call));
        assertEq(_installedGuard(), address(0), "decommissioned");
        assertGt(guard.approvalExpiry(_id), 0, "the approval is still live on the removed guard");
        vm.prank(address(safe));
        safe.setGuard(address(guard)); // a re-install by mistake
        assertTrue(_execSafeTx(address(protocol), 0, _data, Operation.Call), "the old approval revives with the guard");
        // The runbook's step: `lockdownAndRevoke` on the removed guard voids them.
        bytes32 _id2 = _approve(address(protocol), 0, _settle(4), Operation.Call);
        vm.prank(council);
        guard.lockdownAndRevoke(address(safe));
        assertEq(guard.approvalExpiry(_id2), 0);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeLockedDown.selector, address(safe)));
        _execSafeTx(address(protocol), 0, _settle(4), Operation.Call);
    }

    /// @dev "A transaction that itself runs inside a window records nothing, so nesting inside it goes
    ///      undetected (both are unchecked anyway)": pinned as the documented behaviour.
    function test_nesting_inside_an_admin_window_is_undetected_as_documented() public {
        _bypass(1 days);
        G9fNester _nester = new G9fNester();
        uint256 _nonce = safe.nonce();
        SafeTx memory _t = SafeTx(address(protocol), 0, _settle(11), Operation.Call, 0, 0, address(0), address(0));
        bytes32 _domainSeparator = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, address(safe)));
        bytes32 _hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), _domainSeparator, _safeTxHash(_t, _nonce + 1)));
        bytes memory _inner = abi.encodeCall(
            ISafe.execTransaction,
            (address(protocol), 0, _settle(11), Operation.Call, 0, 0, 0, address(0), payable(address(0)), _sign(_hash))
        );
        assertTrue(_execSafeTx(address(_nester), 0, abi.encodeCall(G9fNester.run, (address(safe), _inner)), Operation.Call));
        assertEq(_nester.lastError().length, 0, "the inner transaction was not refused");
        assertEq(safe.nonce(), _nonce + 2, "both ran");
        assertEq(protocol.lastAmount(), 11);
        // Outside the window the same shape is refused (`NestedExecution`), as the suite already pins.
        _enforce();
        _allow(address(protocol), SETTLE);
        _allow(address(_nester), G9fNester.run.selector);
        _hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), _domainSeparator, _safeTxHash(_t, _nonce + 3)));
        _inner = abi.encodeCall(
            ISafe.execTransaction,
            (address(protocol), 0, _settle(11), Operation.Call, 0, 0, 0, address(0), payable(address(0)), _sign(_hash))
        );
        assertTrue(_execSafeTx(address(_nester), 0, abi.encodeCall(G9fNester.run, (address(safe), _inner)), Operation.Call));
        assertEq(bytes4(_nester.lastError()), CuratorGuard.NestedExecution.selector);
        assertEq(safe.nonce(), _nonce + 3, "inner never ran");
    }

    /// @dev Each of the three seeded `MultiSendCallOnly` hashes is CANONICAL (forbiddable by a
    ///      deployment-wide guardian, re-allowable by the council) and pre-allowed; the suite exercised
    ///      the v1.4.1 hash only.
    function test_every_seeded_unwrapper_hash_is_canonical_forbiddable_and_reallowable() public {
        bytes32[3] memory _hashes = [_H().codehashV130(), _H().codehashV141(), _H().codehashV150()];
        vm.prank(vetro);
        guard.setDeploymentGuardian(guardian, true);
        for (uint256 i; i < 3; ++i) {
            assertTrue(guard.isUnwrapperCodehash(_hashes[i]), "pre-allowed");
            vm.prank(guardian);
            guard.setUnwrapperCodehash(_hashes[i], false);
            assertFalse(guard.isUnwrapperCodehash(_hashes[i]), "forbidden by a deployment-wide guardian");
            vm.prank(guardian);
            vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
            guard.setUnwrapperCodehash(_hashes[i], true);
            vm.prank(council);
            guard.setUnwrapperCodehash(_hashes[i], true);
            assertTrue(guard.isUnwrapperCodehash(_hashes[i]), "re-allowed by the council");
        }
    }

    /// @dev The six canonical singleton hashes the guard pins equal the safe-deployments package's
    ///      `codeHash` (offline oracle, like the `MultiSendCallOnly` pin in `CuratorGuardMutation.t.sol`);
    ///      the three proxy hashes are pinned on the fork (`G9f_SafeCodehashes.e2e.ethereum.t.sol`).
    function test_seeded_safe_singleton_hashes_match_safe_deployments() public {
        G9fHarness _h = new G9fHarness(0, vetro, council);
        string[6] memory _files = [
            "v1.3.0/gnosis_safe.json",
            "v1.3.0/gnosis_safe_l2.json",
            "v1.4.1/safe.json",
            "v1.4.1/safe_l2.json",
            "v1.5.0/safe.json",
            "v1.5.0/safe_l2.json"
        ];
        for (uint256 i; i < 6; ++i) {
            string memory _json = vm.readFile(string.concat("node_modules/@safe-global/safe-deployments/dist/assets/", _files[i]));
            bytes32 _expected = vm.parseJsonBytes32(_json, ".deployments.canonical.codeHash");
            assertTrue(_h.isSafeCodehash(_expected), string.concat("singleton hash pinned: ", _files[i]));
        }
        assertFalse(_h.isSafeCodehash(bytes32(0)));
        assertFalse(_h.isSafeCodehash(keccak256("")));
        assertFalse(_h.isSafeCodehash(address(multiSendCallOnly).codehash), "an unrelated contract");
    }
}

/// @title Round 9 (g9f): the module-path post-hook's own digest comparison (docs section 4: "any
///        write ... through any path"), on a real Safe v1.5.0.
contract CuratorGuardG9fModulePathDigestTest is SafeTxHelper {
    CuratorGuard internal guard;
    G9fModule internal module;
    G9fNester internal nester;
    MockProtocol internal protocol;
    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal curator;

    function setUp() public {
        vm.warp(1_700_000_000);
        (curator, signerPk) = makeAddrAndKey("curator");
        Safe150 _singleton = new Safe150();
        SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        safe = ISafe(address(_proxy));
        guard = new CuratorGuardHarness(0, vetro, council);
        CuratorGuardHarness(address(guard)).seedSafe(address(safe));
        module = new G9fModule();
        nester = new G9fNester();
        protocol = new MockProtocol();
        vm.startPrank(address(safe));
        safe.enableModule(address(module));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        vm.stopPrank();
        vm.startPrank(vetro);
        guard.enforce(address(safe));
        guard.setModuleAllowed(address(safe), address(module), true);
        guard.allowFunction(address(safe), address(nester), G9fNester.run.selector, false, new CuratorGuardPolicy.ParamRule[](0));
        vm.stopPrank();
    }

    /// @dev A policy module transaction (slot (safe, 1) holds the digest) whose venue nests an APPROVED
    ///      owner-signed `addOwnerWithThreshold` (slot (safe, 0), sentinel): the inner transaction is
    ///      fine, the outer module post-hook finds the owner list changed and reverts
    ///      `SafeConfigChanged`, rolling back the owner change and the inner approval's consumption.
    function test_module_post_hook_compares_the_digest_and_fails_closed() public {
        address _newOwner = makeAddr("new-owner");
        bytes memory _add = abi.encodeCall(ISafe.addOwnerWithThreshold, (_newOwner, 1));
        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), address(safe), 0, _add, Operation.Call, 1 days);
        SafeTx memory _t = SafeTx(address(safe), 0, _add, Operation.Call, 0, 0, address(0), address(0));
        bytes memory _inner = abi.encodeCall(
            ISafe.execTransaction,
            (address(safe), 0, _add, Operation.Call, 0, 0, 0, address(0), payable(address(0)), _sign(_txHash(_t)))
        );
        bytes memory _outer = abi.encodeCall(G9fNester.run, (address(safe), _inner));
        guard.validateModuleTransaction(address(safe), address(module), address(nester), 0, _outer, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SafeConfigChanged.selector, address(safe)));
        module.exec(safe, address(nester), 0, _outer, Operation.Call);
        assertEq(safe.getOwners().length, 1, "owner change rolled back");
        assertGt(guard.approvalExpiry(_id), 0, "inner approval consumption rolled back");
        assertEq(safe.nonce(), 0, "inner transaction rolled back");
        // The same inner transaction on its own (owner path, approved) lands.
        assertTrue(_execSafeTx(address(safe), 0, _add, Operation.Call));
        assertEq(safe.getOwners().length, 2);
    }
}
