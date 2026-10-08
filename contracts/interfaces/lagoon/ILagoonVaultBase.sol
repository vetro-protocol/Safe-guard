// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC7540Vault} from "./IERC7540Vault.sol";

/// @title ILagoonVaultBase
/// @notice Shared Lagoon surface across v0.5.x and v0.6.0 vaults — the strategy-facing subset
///         with identical signatures in both release lines, plus `syncRedeem`, declared here
///         though it exists on v0.6.0 only (see its notice).
/// @dev    Version-specific surfaces (whitelist function name, fee struct shape, sync-mode /
///         async-only governance) live in `ILagoonVaultV05` and `ILagoonVaultV06`.
interface ILagoonVaultBase is IERC7540Vault {
    function safe() external view returns (address);

    function paused() external view returns (bool);

    function version() external view returns (string memory);

    /// @notice Freshness signal — true while the last settled NAV is still inside
    ///         `totalAssetsLifespan` (the Safe's `expireTotalAssets()` ends it early). Sync
    ///         deposits gate on this, and on v0.6.0 sync redeems too; async `requestDeposit`
    ///         reverts while it is true on v0.5.x (`OnlySyncDepositAllowed`) and is accepted
    ///         either way on v0.6.0.
    function isTotalAssetsValid() external view returns (bool);

    /// @notice Per-batch settled rate. `convertToAssets(shares, requestId)` reads the price per
    ///         share frozen at the settlement of `requestId`, not the live one. Present in both
    ///         v0.5.x and v0.6.0.
    function convertToAssets(uint256 shares, uint256 requestId) external view returns (uint256);

    /// @notice Synchronous deposit — bypasses the request/settle cycle. Same entry-fee schedule
    ///         as `requestDeposit` (no extra cost). Reverts when the vault's sync gate is closed.
    ///         Present on both v0.5.x and v0.6.0.
    function syncDeposit(uint256 assets, address receiver, address referral) external returns (uint256 shares);

    /// @notice Synchronous redeem — bypasses the request/settle cycle but pays a per-vault
    ///         `haircutRate` (up to 20%) on top of the exit fee. Strategy keepers should treat
    ///         this as an emergency-only path. v0.6.0 only: the function selector does not
    ///         exist on v0.5.x vaults, so callers MUST gate on a version-aware mode check before
    ///         invoking it.
    function syncRedeem(uint256 shares, address receiver, uint256 minimumAssets) external returns (uint256 assets);

    /// @notice Cancels the caller's pending deposit request and returns assets from the
    ///         `pendingSilo`. Reverts with `RequestNotCancelable(requestId)` once the curator's
    ///         next mark (`updateNewTotalAssets`) has closed the epoch. Present on both v0.5.x
    ///         and v0.6.0 with identical signatures.
    function cancelRequestDeposit() external;
}
