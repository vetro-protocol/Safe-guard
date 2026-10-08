// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @notice Mirror of Safe's `Enum.Operation`. ABI-encodes as `uint8`; ordering MUST match Safe
///         (`Call = 0`, `DelegateCall = 1`).
enum Operation {
    Call,
    DelegateCall
}

/// @title ISafeTransactionGuard
/// @notice Safe transaction guard hook surface (Safe v1.3.0 `Guard`, v1.4.1 `Guard`, v1.5.0
///         `ITransactionGuard`): identical signatures across releases, interface id `0xe6d7a83a`.
///         Installed on a Safe with `setGuard(guard)`; the Safe calls `checkTransaction` after
///         signature verification and before execution of every `execTransaction`, and
///         `checkAfterExecution` after it, also when the inner call failed (unless `safeTxGas` and
///         `gasPrice` are both zero: then the Safe reverts on failure before the post-hook). Safe
///         v1.4.1+ asks `supportsInterface(0xe6d7a83a)` in `setGuard` and reverts `GS300` on "no"
///         (v1.3.0 stores any address unchecked).
/// @dev    Data location does not affect the ABI. `data` is `calldata` so the guard can slice it
///         without copying; `signatures` is `memory` (one stack slot instead of two) so the
///         11-parameter decoder fits the legacy codegen without via-IR.
interface ISafeTransactionGuard is IERC165 {
    /// @notice Called by the Safe (`msg.sender`) after it verified the signatures of an
    ///         `execTransaction` and before it executes it; a revert refuses the Safe transaction.
    function checkTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external;

    /// @notice Called by the Safe after the execution with its `safeTxHash` and whether the inner call
    ///         succeeded; a revert undoes the whole Safe transaction.
    function checkAfterExecution(bytes32 txHash, bool success) external;
}

/// @title ISafeModuleGuard
/// @notice Safe v1.5.0 module guard hook surface (`IModuleGuard`, interface id `0x58401ed8`).
///         Installed with `setModuleGuard(guard)`; consulted on every `execTransactionFromModule*`.
///         Safe v1.3.0 / v1.4.1 have NO module guard hook: module transactions bypass guards
///         entirely on those releases. `setModuleGuard` asks `supportsInterface(0x58401ed8)` and
///         reverts `GS301` on "no".
interface ISafeModuleGuard is IERC165 {
    /// @notice Called by the Safe (`msg.sender`) before a module transaction executes; the returned hash
    ///         is echoed into `checkAfterModuleExecution`. A revert refuses the module transaction.
    function checkModuleTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        address module
    ) external returns (bytes32 moduleTxHash);

    /// @notice Called by the Safe after the module transaction with the hash the pre-hook returned and
    ///         whether the inner call succeeded; a revert undoes the module transaction.
    function checkAfterModuleExecution(bytes32 txHash, bool success) external;
}
