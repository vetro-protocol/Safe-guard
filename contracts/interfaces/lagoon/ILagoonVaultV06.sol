// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {ILagoonVaultBase} from "./ILagoonVaultBase.sol";

/// @title ILagoonVaultV06
/// @notice Additions on top of the shared base: the fee rates, the sync-mode enum and getter, the
///         async-only irreversible flag, the deposit cap, the `isAllowed` access check, the
///         redeem cancel, and the two role getters the v0.6.0 source does not expose (see their
///         notices).
interface ILagoonVaultV06 is ILagoonVaultBase {
    /// @notice `Rates` struct — adds entry / exit / haircut on top of v0.5.x.
    struct Rates {
        uint16 managementRate;
        uint16 performanceRate;
        uint16 entryRate;
        uint16 exitRate;
        uint16 haircutRate;
    }

    /// @notice Role that can update totalAssets bypassing guardrails. The v0.6.0 source exposes
    ///         no getter for it: the call reverts on the live vaults (the role sits in the
    ///         `hopper.storage.Roles` slot, see `docs/curator-guard.md` section 8).
    function securityCouncil() external view returns (address);

    /// @notice Role exempt from the `isAllowed` access checks on the claim paths (`_deposit`,
    ///         `_mint`, `_redeem`, `_withdraw`) and on `_requestRedeem`, and from the allowance
    ///         on `transferFrom`; `isAllowed` itself always returns true for it. Does NOT bypass
    ///         `_onlyOperator` on `requestDeposit`. `claimSharesOnBehalf` / `claimAssetsOnBehalf`
    ///         are `onlySafe` in v0.6.0, not super-operator calls. The v0.6.0 source exposes no
    ///         getter for the role either: the call reverts on the live vaults.
    function superOperator() external view returns (address);

    /// @notice Vault-level deposit cap.
    function maxCap() external view returns (uint256);

    /// @notice Irreversible flag — once `activateAsyncOnly()` is pulled, `syncMode` and
    ///         `totalAssetsLifespan` are locked; sync deposit/redeem can never re-enable.
    function isAsyncOnly() external view returns (bool);

    /// @notice Access check: the whitelist or blacklist mode plus the external sanctions list.
    ///         Replaces v0.5.x's `isWhitelisted`.
    function isAllowed(address account) external view returns (bool);

    /// @notice Current `Rates` (Lagoon's `primitives/Struct.sol`) — the only fee-rate getter on
    ///         the vault's ABI; `getSettlement{Entry,Exit}FeeRate` are `ERC7540Lib` functions
    ///         and revert when called on the vault.
    function feeRates() external view returns (Rates memory);

    /// @notice SyncMode enum mirror. Layout MUST match Lagoon's
    ///         `src/v0.6.0/primitives/Enums.sol::SyncMode` ABI ordering.
    enum SyncMode {
        Both,
        SyncDeposit,
        SyncRedeem,
        None
    }

    /// @notice Current sync mode setting. Lagoon's sync gates check it together with
    ///         `isTotalAssetsValid()` (`isAsyncOnly()` keeps the NAV expired for good); its
    ///         state, pause and access checks, and the deposit cap, apply on top.
    function syncMode() external view returns (SyncMode);

    /// @notice Cancels `controller`'s pending redeem request and returns shares from the
    ///         `pendingSilo`. Reverts with `RequestNotCancelable(requestId)` once the curator's
    ///         next mark (`updateNewTotalAssets`) has closed the epoch. v0.5.x has no
    ///         redeem-cancel path.
    function cancelRequestRedeem(address controller) external;
}
