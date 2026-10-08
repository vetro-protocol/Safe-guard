// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Test.sol";

import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";

/// @title SafeTxHelper
/// @notice Signs and executes Safe transactions with a single EOA signer.
/// @dev    The EIP-712 hash is computed locally (nonce read with `vm.load`) so that the ONLY
///         external call a helper makes is `execTransaction`: `vm.expectRevert` binds to the next
///         external call, and a `getTransactionHash` view in between would swallow it. Parameters
///         travel in a struct so the 10-argument call never hits stack-too-deep on the legacy
///         pipeline (the Safe sources cannot be compiled via-IR).
abstract contract SafeTxHelper is Test {
    struct SafeTx {
        address to;
        uint256 value;
        bytes data;
        Operation op;
        uint256 safeTxGas;
        uint256 gasPrice;
        address gasToken;
        address refundReceiver;
    }

    /// @dev keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"), Safe v1.3.0 → v1.5.0.
    bytes32 internal constant DOMAIN_SEPARATOR_TYPEHASH =
        0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
    /// @dev keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)")
    bytes32 internal constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;
    /// @dev `SafeStorage.nonce`: singleton(0), modules(1), owners(2), ownerCount(3), threshold(4), nonce(5).
    uint256 internal constant NONCE_SLOT = 5;

    ISafe internal safe;
    uint256 internal signerPk;

    function _execSafeTx(address to_, uint256 value_, bytes memory data_, Operation op_) internal returns (bool) {
        return _execSafeTxParams(SafeTx(to_, value_, data_, op_, 0, 0, address(0), address(0)));
    }

    /// @dev `safeTxGas != 0` makes the Safe tolerate a failing inner call (returns `false` instead
    ///      of reverting with GS013).
    function _execSafeTxWithGas(
        address to_,
        uint256 value_,
        bytes memory data_,
        Operation op_,
        uint256 safeTxGas_
    ) internal returns (bool) {
        return _execSafeTxParams(SafeTx(to_, value_, data_, op_, safeTxGas_, 0, address(0), address(0)));
    }

    function _execSafeTxWithRefund(
        address to_,
        uint256 value_,
        bytes memory data_,
        Operation op_,
        uint256 gasPrice_,
        address gasToken_,
        address refundReceiver_
    ) internal returns (bool) {
        return _execSafeTxParams(SafeTx(to_, value_, data_, op_, 0, gasPrice_, gasToken_, refundReceiver_));
    }

    function _execSafeTxParams(SafeTx memory t_) internal returns (bool) {
        bytes memory _signature = _sign(_txHash(t_));
        return
            safe.execTransaction(
                t_.to,
                t_.value,
                t_.data,
                t_.op,
                t_.safeTxGas,
                0,
                t_.gasPrice,
                t_.gasToken,
                payable(t_.refundReceiver),
                _signature
            );
    }

    /// @dev Local replica of `Safe.getTransactionHash` at the Safe's current nonce.
    function _txHash(SafeTx memory t_) internal view returns (bytes32) {
        uint256 _nonce = uint256(vm.load(address(safe), bytes32(NONCE_SLOT)));
        bytes32 _domainSeparator = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, address(safe)));
        return keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), _domainSeparator, _safeTxHash(t_, _nonce)));
    }

    function _safeTxHash(SafeTx memory t_, uint256 nonce_) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    SAFE_TX_TYPEHASH,
                    t_.to,
                    t_.value,
                    keccak256(t_.data),
                    t_.op,
                    t_.safeTxGas,
                    uint256(0),
                    t_.gasPrice,
                    t_.gasToken,
                    t_.refundReceiver,
                    nonce_
                )
            );
    }

    function _sign(bytes32 hash_) internal view returns (bytes memory) {
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(signerPk, hash_);
        return abi.encodePacked(_r, _s, _v);
    }
}
