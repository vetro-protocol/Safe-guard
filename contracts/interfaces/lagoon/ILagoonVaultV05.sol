// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {ILagoonVaultBase} from "./ILagoonVaultBase.sol";

/// @title ILagoonVaultV05
/// @notice Lagoon v0.5.x additions on top of the shared base — covers the v0.5.x releases (tags
///         v0.5.0 through v0.5.3), which all build the vault from `src/v0.5.0/`.
/// @dev    `version()` returns `"v0.5.0"` at every v0.5.x tag: the point releases restructured
///         the protocol contracts (`protocol-v1` / `protocol-v2`) and touched the `Silo`
///         (changed at v0.5.1, reverted at v0.5.3), the vault files only in their imports and
///         NatSpec. No tag reports `"v0.5.1"`; `LagoonV05` accepts that string too, for a later
///         point release that might.
/// @dev    v0.5.x has no entry or exit fee: the `Rates` struct holds only management and
///         performance rates, and `SettleData` records no fee rate (v0.6.0's `entryFeeRate` /
///         `exitFeeRate` have no v0.5.x counterpart).
/// @dev    v0.5.x has no `syncRedeem` (redeems are always async), no `isAsyncOnly` trapdoor
///         and no `SyncMode` enum; the NAV gate of a sync deposit is `isTotalAssetsValid()`
///         alone (the state, pause and whitelist checks still apply).
interface ILagoonVaultV05 is ILagoonVaultBase {
    /// @notice Lagoon v0.5.x `Rates` struct from `primitives/Struct.sol`. Only management and
    ///         performance accrue on settle.
    struct Rates {
        uint16 managementRate;
        uint16 performanceRate;
    }

    /// @notice v0.5.x whitelist gate: true for everyone while the whitelist is not activated,
    ///         else for listed accounts (and always for the protocol fee receiver). v0.6.0
    ///         replaces it with the `isAllowed` access check (whitelist or blacklist mode plus
    ///         the external sanctions list).
    function isWhitelisted(address account) external view returns (bool);

    /// @notice Current `Rates` (Lagoon's `primitives/Struct.sol`); until a rate update's cooldown
    ///         has elapsed, the previous rates.
    function feeRates() external view returns (Rates memory);
}
