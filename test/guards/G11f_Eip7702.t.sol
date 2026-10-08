// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";
import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";
import {TestERC20} from "test/mocks/TestERC20.sol";

/// @dev What an owner's EIP-7702 delegate can be: code that answers EIP-1271 for anything, under the legacy
///      selector a v1.4.1 Safe asks (`isValidSignature(bytes,bytes)`) and the one v1.5.0 asks
///      (`isValidSignature(bytes32,bytes)`).
contract PermissiveDelegate {
    function isValidSignature(bytes memory, bytes memory) external pure returns (bytes4) {
        return 0x20c13b0b;
    }

    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

/// @dev Another venue implementation, to show the code behind a delegated-EOA target moving.
contract OtherVenue {
    uint256 public hits;

    function settleDeposit(uint256) external {
        hits += 1000;
    }
}

/// @title G11f: EIP-7702 owners and venues under the guard (round 11)
/// @notice Real designator semantics: forge 1.5.1's EVM follows a `0xef0100 || delegate` code on CALL and
///         answers `EXTCODESIZE == 23`, as Prague does. A 3-owner, 2-of-3 Safe; the v1.5.0 variant below.
contract G11fEip7702Test is SafeTxHelper {
    CuratorGuardHarness internal guard;
    MockProtocol internal protocol;
    TestERC20 internal token;

    address internal vetro = makeAddr("vetro");
    address internal council = makeAddr("council");
    address internal attacker = makeAddr("attacker");
    address internal ownerA;
    uint256 internal pkA;
    address internal ownerB;
    uint256 internal pkB;
    address internal ownerC;
    uint256 internal pkC;

    bytes4 internal constant SWAP_OWNER = 0xe318b52b;

    function setUp() public virtual {
        vm.warp(1_700_000_000);
        (ownerA, pkA) = makeAddrAndKey("owner-a");
        (ownerB, pkB) = makeAddrAndKey("owner-b");
        (ownerC, pkC) = makeAddrAndKey("owner-c");
        address[] memory _owners = new address[](3);
        _owners[0] = ownerA;
        _owners[1] = ownerB;
        _owners[2] = ownerC;
        safe = ISafe(_newSafe(_owners, 2));
        guard = new CuratorGuardHarness(0, vetro, council);
        guard.seedSafe(address(safe));
        protocol = new MockProtocol();
        token = new TestERC20("USDC", "USDC");
        token.mint(address(safe), 1_000_000e6);
        vm.prank(address(safe));
        safe.setGuard(address(guard));
        vm.startPrank(vetro);
        guard.enforce(address(safe));
        guard.allowFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules());
        vm.stopPrank();
    }

    function _newSafe(address[] memory owners_, uint256 threshold_) internal virtual returns (address) {
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        Safe(payable(address(_proxy))).setup(owners_, threshold_, address(0), "", address(0), address(0), 0, payable(address(0)));
        return address(_proxy);
    }

    function _noRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _rules) {}

    function _settle(uint256 n_) internal pure returns (bytes memory) {
        return abi.encodeCall(MockProtocol.settleDeposit, (n_));
    }

    function _designator(address delegate_) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"ef0100", delegate_);
    }

    function _tx(address to_, bytes memory data_) internal pure returns (SafeTx memory) {
        return SafeTx(to_, 0, data_, Operation.Call, 0, 0, address(0), address(0));
    }

    function _ecdsa(uint256 pk_, bytes32 hash_) internal pure returns (bytes memory) {
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(pk_, hash_);
        return abi.encodePacked(_r, _s, _v);
    }

    /// @dev A contract-signature head: `r` = the owner, `s` = offset of the dynamic part, `v` = 0.
    function _contractHead(address owner_, uint256 offset_) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(uint256(uint160(owner_))), bytes32(offset_), uint8(0));
    }

    /// @dev Two 65-byte heads in ascending owner order, then the dynamic part.
    function _two(address o1_, bytes memory s1_, address o2_, bytes memory s2_, bytes memory dyn_) internal pure returns (bytes memory) {
        return o1_ < o2_ ? abi.encodePacked(s1_, s2_, dyn_) : abi.encodePacked(s2_, s1_, dyn_);
    }

    function _exec(SafeTx memory t_, bytes memory sigs_) internal returns (bool) {
        return safe.execTransaction(t_.to, t_.value, t_.data, t_.op, t_.safeTxGas, 0, t_.gasPrice, t_.gasToken, payable(t_.refundReceiver), sigs_);
    }

    function _execBC(SafeTx memory t_) internal returns (bool) {
        bytes32 _h = _txHash(t_);
        return _exec(t_, _two(ownerB, _ecdsa(pkB, _h), ownerC, _ecdsa(pkC, _h), ""));
    }

    /// @dev "Owners that acquire code after they were vetted": owner A signs a 7702 authorisation to a
    ///      permissive delegate (phished, or a session-key smart account). From then on anyone the delegate
    ///      accepts holds A's seat for CONTRACT signatures, with no key: one compromised key (B) plus a forged
    ///      contract signature "from" A satisfies the 2-of-3. The guard sees an ordinary policy transaction
    ///      (the owner LIST is unchanged, so the digest is unchanged); what it still bounds is the payload.
    function test_G11f_a_vetted_owner_that_delegates_afterwards_hands_its_seat_to_whoever_its_delegate_accepts() public {
        assertEq(ownerA.code.length, 0, "vetted: no owner has code (section 7.3)");
        PermissiveDelegate _d = new PermissiveDelegate();
        vm.etch(ownerA, _designator(address(_d)));
        assertEq(ownerA.code.length, 23, "EXTCODESIZE 23: the 7.7 'owner acquired code' alert condition");

        SafeTx memory _t = _tx(address(protocol), _settle(7));
        bytes32 _h = _txHash(_t);
        bytes memory _forged = _two(ownerA, _contractHead(ownerA, 130), ownerB, _ecdsa(pkB, _h), abi.encodePacked(uint256(0)));
        vm.expectEmit(true, true, true, true, address(guard));
        emit CuratorGuard.TransactionChecked(address(safe), _h, 0, CuratorGuard.Outcome.Policy);
        assertTrue(_exec(_t, _forged), "2-of-3 satisfied with one key and no key for A");
        assertEq(protocol.lastAmount(), 7);

        SafeTx memory _drain = _tx(address(token), abi.encodeCall(IERC20.transfer, (attacker, 1)));
        bytes32 _h2 = _txHash(_drain);
        bytes memory _forged2 = _two(ownerA, _contractHead(ownerA, 130), ownerB, _ecdsa(pkB, _h2), abi.encodePacked(uint256(0)));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(token), IERC20.transfer.selector));
        _exec(_drain, _forged2);
    }

    /// @dev The survey's item 27 worry ("owners must have no code" would freeze the Safe when one owner
    ///      delegates) does not apply: the guard reads no owner's code, so the honest quorum keeps settling,
    ///      the digest does not move, and the council rotates the delegated seat out for a plain key at once
    ///      (the no-code rule is on the NEW owner only).
    function test_G11f_an_owner_delegation_neither_freezes_the_safe_nor_moves_the_digest_and_the_council_rotates_it_out() public {
        vm.etch(ownerA, _designator(address(new PermissiveDelegate())));
        assertTrue(_execBC(_tx(address(protocol), _settle(1))), "B + C keep settling");

        address _plainKey = makeAddr("replacement-key");
        bytes memory _swap = abi.encodeWithSelector(SWAP_OWNER, address(0x1), ownerA, _plainKey);
        vm.prank(council);
        guard.approveTransaction(address(safe), address(0), address(safe), 0, _swap, Operation.Call, 1 days);
        assertTrue(_execBC(_tx(address(safe), _swap)), "the council's swapOwner executes");
        address[] memory _owners = safe.getOwners();
        assertEq(_owners.length, 3);
        assertEq(_owners[0], _plainKey);
        // And the designator itself is refused as a NEW owner on the council lane (V2-58, real semantics).
        bytes memory _back = abi.encodeWithSelector(SWAP_OWNER, address(0x1), _plainKey, ownerA);
        vm.prank(council);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.CouncilCannotApprove.selector, SWAP_OWNER, Operation.Call));
        guard.approveTransaction(address(safe), address(0), address(safe), 0, _back, Operation.Call, 1 days);
    }

    /// @dev "Targets must carry code" is satisfied by a delegated EOA (23 bytes), whose code its key holder
    ///      re-points at will and can revoke to nothing: a 7702 venue is an upgradeable target with a single
    ///      key as its admin, and `NotAContract`'s "post-Cancun code cannot disappear" no longer holds for it
    ///      (the entry then fails closed). The sync task already warns on `0xef0100` targets.
    function test_G11f_a_delegated_eoa_venue_passes_the_code_check_and_its_code_can_move_or_vanish() public {
        address _venue = makeAddr("venue-eoa");
        vm.etch(_venue, _designator(address(protocol)));
        vm.prank(vetro);
        guard.allowFunction(address(safe), _venue, MockProtocol.settleDeposit.selector, false, _noRules());
        assertTrue(_execBC(_tx(_venue, _settle(3))), "23 bytes of code pass NotAContract");
        assertEq(MockProtocol(payable(_venue)).lastAmount(), 3, "the delegate's code ran in the EOA's context");

        OtherVenue _other = new OtherVenue();
        vm.etch(_venue, _designator(address(_other)));
        assertTrue(_execBC(_tx(_venue, _settle(3))), "same allowlist entry, other code");
        // The storage is the EOA's: `OtherVenue.hits` is slot 0, where `MockProtocol.lastAmount` left 3.
        assertEq(OtherVenue(_venue).hits(), 1003, "other code, same storage");

        vm.etch(_venue, "");
        assertEq(_venue.code.length, 0, "revoked: the code is gone");
        SafeTx memory _t = _tx(_venue, _settle(3));
        bytes memory _sigs = _two(ownerB, _ecdsa(pkB, _txHash(_t)), ownerC, _ecdsa(pkC, _txHash(_t)), "");
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.NotAContract.selector, _venue));
        _exec(_t, _sigs);
    }

    /// @dev Approvals: a delegatecall into a designator is refused when issued (`InvalidTarget`, its code is
    ///      re-pointable), a plain call into one is accepted and runs whatever the delegate is at use (a call
    ///      approval pins no code, as for any upgradeable target).
    function test_G11f_approvals_refuse_a_delegatecall_into_a_designator_and_accept_an_unpinned_call() public {
        address _eoa = makeAddr("delegated");
        vm.etch(_eoa, _designator(address(protocol)));
        vm.prank(vetro);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.InvalidTarget.selector, _eoa));
        guard.approveTransaction(address(safe), address(0), _eoa, 0, _settle(5), Operation.DelegateCall, 1 days);

        vm.prank(vetro);
        bytes32 _id = guard.approveTransaction(address(safe), address(0), _eoa, 0, _settle(5), Operation.Call, 1 days);
        OtherVenue _other = new OtherVenue();
        vm.etch(_eoa, _designator(address(_other))); // re-pointed between approval and use
        assertEq(guard.computeApprovalId(address(safe), address(0), _eoa, 0, _settle(5), Operation.Call), _id, "the id does not move");
        assertTrue(_execBC(_tx(_eoa, _settle(5))), "consumed, running the delegate of the moment");
        assertEq(OtherVenue(_eoa).hits(), 1000);
    }
}

/// @dev The same on Safe v1.5.0 (`isValidSignature(bytes32,bytes)` for contract signatures).
contract G11fEip7702V150Test is G11fEip7702Test {
    function _newSafe(address[] memory owners_, uint256 threshold_) internal override returns (address) {
        Safe150 _singleton = new Safe150();
        SafeProxy150 _proxy = new SafeProxy150(address(_singleton));
        Safe150(payable(address(_proxy))).setup(owners_, threshold_, address(0), "", address(0), address(0), 0, payable(address(0)));
        return address(_proxy);
    }
}
