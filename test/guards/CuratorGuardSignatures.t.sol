// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

/// @dev Legacy EIP-1271 owner (Safe v1.4.1 calls `isValidSignature(bytes,bytes)`, magic 0x20c13b0b).
contract ContractSigner {
    bytes4 internal constant MAGIC = 0x20c13b0b;
    bytes32 public approvedDataHash;

    function approve(bytes32 dataHash_) external {
        approvedDataHash = dataHash_;
    }

    function isValidSignature(bytes memory data_, bytes memory) external view returns (bytes4) {
        return keccak256(data_) == approvedDataHash ? MAGIC : bytes4(0);
    }
}

/// @title Signature shapes through the guard (real Safe v1.4.1, 2-of-3: two EOAs + one contract owner)
contract CuratorGuardSignaturesTest is SafeTxHelper {
    CuratorGuard internal guard;
    MockProtocol internal protocol;
    ContractSigner internal contractOwner;
    address internal vetro = makeAddr("vetro");

    address internal council = makeAddr("council");
    address internal attacker = makeAddr("attacker");
    address internal ownerA;
    uint256 internal pkA;
    address internal ownerB;
    uint256 internal pkB;

    function setUp() public {
        vm.warp(1_700_000_000); // a realistic time: Foundry's default timestamp of 1 sits inside the lockdown cooldown
        (ownerA, pkA) = makeAddrAndKey("owner-a");
        (ownerB, pkB) = makeAddrAndKey("owner-b");
        contractOwner = new ContractSigner();
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        address[] memory _owners = new address[](3);
        _owners[0] = ownerA;
        _owners[1] = ownerB;
        _owners[2] = address(contractOwner);
        Safe(payable(address(_proxy))).setup(_owners, 2, address(0), "", address(0), address(0), 0, payable(address(0)));
        safe = ISafe(address(_proxy));
        guard = new CuratorGuardHarness(0, vetro, council);
        CuratorGuardHarness(address(guard)).seedSafe(address(safe)); // locally compiled Safe build: seeded, the guard pins canonical Safe code (V2-85)
        protocol = new MockProtocol();
        vm.prank(address(safe));
        safe.setGuard(address(guard));
        vm.startPrank(vetro);
        guard.enforce(address(safe));
        guard.allowFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector, false, new CuratorGuardPolicy.ParamRule[](0));
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _hashOf(address to_, bytes memory data_) internal view returns (bytes32) {
        return _txHash(SafeTx(to_, 0, data_, Operation.Call, 0, 0, address(0), address(0)));
    }

    function _txData(address to_, bytes memory data_) internal view returns (bytes memory) {
        uint256 _nonce = uint256(vm.load(address(safe), bytes32(NONCE_SLOT)));
        bytes32 _domainSeparator = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, address(safe)));
        SafeTx memory _t = SafeTx(to_, 0, data_, Operation.Call, 0, 0, address(0), address(0));
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), _domainSeparator, _safeTxHash(_t, _nonce));
    }

    function _ecdsa(uint256 pk_, bytes32 hash_) internal pure returns (bytes memory) {
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(pk_, hash_);
        return abi.encodePacked(_r, _s, _v);
    }

    /// @dev Static part of a contract signature: r = signer, s = offset of the dynamic part, v = 0.
    function _contractSigStatic(address signer_, uint256 offset_) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(uint256(uint160(signer_))), bytes32(offset_), uint8(0));
    }

    /// @dev Pre-validated signature: r = owner, s = 0, v = 1.
    function _preValidated(address owner_) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(uint256(uint160(owner_))), bytes32(0), uint8(1));
    }

    /// @dev Concatenates two 65-byte static parts in ascending owner order.
    function _sorted(address x_, bytes memory sigX_, address y_, bytes memory sigY_) internal pure returns (bytes memory) {
        return x_ < y_ ? abi.encodePacked(sigX_, sigY_) : abi.encodePacked(sigY_, sigX_);
    }

    function _exec(address to_, bytes memory data_, bytes memory signatures_) internal returns (bool) {
        return safe.execTransaction(to_, 0, data_, Operation.Call, 0, 0, 0, address(0), payable(address(0)), signatures_);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    function test_two_eoa_signatures_sorted() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (1));
        bytes32 _h = _hashOf(address(protocol), _data);
        bytes memory _sigs = _sorted(ownerA, _ecdsa(pkA, _h), ownerB, _ecdsa(pkB, _h));
        assertTrue(_exec(address(protocol), _data, _sigs));
        assertEq(protocol.lastAmount(), 1);

        // Denied payload: the guard error surfaces (not a signature error).
        bytes memory _bad = abi.encodeCall(MockProtocol.deposit, (1, attacker));
        _h = _hashOf(address(protocol), _bad);
        _sigs = _sorted(ownerA, _ecdsa(pkA, _h), ownerB, _ecdsa(pkB, _h));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector));
        _exec(address(protocol), _bad, _sigs);
    }

    function test_contract_signature_v0_through_the_guard() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (2));
        bytes32 _h = _hashOf(address(protocol), _data);
        contractOwner.approve(keccak256(_txData(address(protocol), _data)));
        // Static parts: 2 * 65 = 130 bytes; the dynamic part starts at offset 130.
        bytes memory _contractSig = hex"c0ffee";
        bytes memory _static = _sorted(ownerA, _ecdsa(pkA, _h), address(contractOwner), _contractSigStatic(address(contractOwner), 130));
        bytes memory _sigs = abi.encodePacked(_static, bytes32(_contractSig.length), _contractSig);
        assertTrue(_exec(address(protocol), _data, _sigs));
        assertEq(protocol.lastAmount(), 2);

        bytes memory _bad = abi.encodeCall(MockProtocol.deposit, (1, attacker));
        _h = _hashOf(address(protocol), _bad);
        contractOwner.approve(keccak256(_txData(address(protocol), _bad)));
        _static = _sorted(ownerA, _ecdsa(pkA, _h), address(contractOwner), _contractSigStatic(address(contractOwner), 130));
        _sigs = abi.encodePacked(_static, bytes32(_contractSig.length), _contractSig);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector));
        _exec(address(protocol), _bad, _sigs);
    }

    function test_prevalidated_signature_v1_via_approveHash_and_msg_sender() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (3));
        bytes32 _h = _hashOf(address(protocol), _data);
        // Owner B approves the hash on-chain; anyone submits with {B, 0, 1}.
        vm.prank(ownerB);
        (bool _ok, ) = address(safe).call(abi.encodeWithSignature("approveHash(bytes32)", _h));
        assertTrue(_ok);
        bytes memory _sigs = _sorted(ownerA, _ecdsa(pkA, _h), ownerB, _preValidated(ownerB));
        vm.prank(attacker); // relayer
        assertTrue(_exec(address(protocol), _data, _sigs));
        assertEq(protocol.lastAmount(), 3);

        // msg.sender == owner with v == 1 and no approveHash.
        _data = abi.encodeCall(MockProtocol.settleDeposit, (4));
        _h = _hashOf(address(protocol), _data);
        _sigs = _sorted(ownerA, _ecdsa(pkA, _h), ownerB, _preValidated(ownerB));
        vm.prank(ownerB);
        assertTrue(_exec(address(protocol), _data, _sigs));
        assertEq(protocol.lastAmount(), 4);

        // The guard's `msgSender` argument is the relayer, not an owner; policy still applies.
        bytes memory _bad = abi.encodeCall(MockProtocol.deposit, (1, attacker));
        _h = _hashOf(address(protocol), _bad);
        _sigs = _sorted(ownerA, _ecdsa(pkA, _h), ownerB, _preValidated(ownerB));
        vm.prank(ownerB);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector));
        _exec(address(protocol), _bad, _sigs);
    }

    function test_eth_sign_signature_v_gt_30_through_the_guard() public {
        bytes memory _data = abi.encodeCall(MockProtocol.settleDeposit, (5));
        bytes32 _h = _hashOf(address(protocol), _data);
        bytes32 _prefixed = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _h));
        (uint8 _vA, bytes32 _rA, bytes32 _sA) = vm.sign(pkA, _prefixed);
        (uint8 _vB, bytes32 _rB, bytes32 _sB) = vm.sign(pkB, _prefixed);
        bytes memory _sigs = _sorted(
            ownerA,
            abi.encodePacked(_rA, _sA, _vA + 4),
            ownerB,
            abi.encodePacked(_rB, _sB, _vB + 4)
        );
        assertTrue(_exec(address(protocol), _data, _sigs));
        assertEq(protocol.lastAmount(), 5);

        bytes memory _bad = abi.encodeCall(MockProtocol.deposit, (1, attacker));
        _prefixed = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _hashOf(address(protocol), _bad)));
        (_vA, _rA, _sA) = vm.sign(pkA, _prefixed);
        (_vB, _rB, _sB) = vm.sign(pkB, _prefixed);
        _sigs = _sorted(ownerA, abi.encodePacked(_rA, _sA, _vA + 4), ownerB, abi.encodePacked(_rB, _sB, _vB + 4));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(protocol), MockProtocol.deposit.selector));
        _exec(address(protocol), _bad, _sigs);
    }
}
