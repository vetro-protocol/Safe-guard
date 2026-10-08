// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Operation} from "./ISafeGuard.sol";

/// @title ISafe
/// @notice Minimal Safe (v1.3.0+) surface used by the curator guard and its tooling. Verify against
///         `lib/safe-smart-account` (v1.4.1) and `lib/safe-smart-account-v1.5.0` for ground truth.
interface ISafe {
    /// @notice `StorageAccessible.getStorageAt`: reads `length` words starting at storage slot `offset`.
    function getStorageAt(uint256 offset, uint256 length) external view returns (bytes memory);

    /// @notice Self-authorized: the Safe must be `msg.sender` (a Safe transaction, or a module acting on
    ///         its behalf).
    function setGuard(address guard) external;

    /// @notice v1.5.0 only. Self-authorized. On earlier releases the selector is unknown to the Safe and
    ///         answered by its fallback handler: with NO handler the self-call SUCCEEDS and sets nothing,
    ///         so never execute it before the Safe runs v1.5.0, and confirm it by the Safe's own
    ///         `ChangedModuleGuard` event, never by `ExecutionSuccess` alone.
    function setModuleGuard(address moduleGuard) external;

    function enableModule(address module) external;

    function addOwnerWithThreshold(address owner, uint256 _threshold) external;

    function isModuleEnabled(address module) external view returns (bool);

    function getModulesPaginated(address start, uint256 pageSize) external view returns (address[] memory, address);

    function getOwners() external view returns (address[] memory);

    function getThreshold() external view returns (uint256);

    function nonce() external view returns (uint256);

    function VERSION() external view returns (string memory);

    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes32);

    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool success);

    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Operation operation
    ) external returns (bool success);
}
