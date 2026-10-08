// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title IERC7540Vault
/// @notice Minimal ERC-7540 (async ERC-4626) interface: the ERC-4626 views and the ERC-7540
///         request and claim functions the Lagoon strategies are written against (`totalAssets`,
///         `maxDeposit` and `maxWithdraw` are declared but not called by the strategies).
/// @dev    Lagoon's v0.5.x and v0.6.0 vaults implement this. The operator functions and the
///         mint-by-shares and withdraw-by-assets claims, which the strategies do not call, are
///         left out on purpose.
interface IERC7540Vault is IERC20 {
    /*//////////////////////////////////////////////////////////////
                            ERC-4626 SUBSET
    //////////////////////////////////////////////////////////////*/

    function asset() external view returns (address);

    function convertToAssets(uint256 shares) external view returns (uint256 assets);

    function convertToShares(uint256 assets) external view returns (uint256 shares);

    function totalAssets() external view returns (uint256);

    function maxDeposit(address controller) external view returns (uint256);

    /// @notice Asset value of `controller`'s claimable redeem at the rate frozen at its
    ///         settlement (`convertToAssets(shares, redeemId)`: a later NAV move does not change
    ///         it); on v0.6.0 net of the exit fee at the frozen rate. `0` while the vault is
    ///         paused. In a Closed vault with nothing claimable, the controller's share balance
    ///         at the live price instead (on v0.6.0 net of the live exit fee). The strategies do
    ///         not call it.
    function maxWithdraw(address controller) external view returns (uint256);

    /*//////////////////////////////////////////////////////////////
                          7540 — DEPOSIT REQUESTS
    //////////////////////////////////////////////////////////////*/

    /// @return requestId the vault's id for the request; Lagoon returns the current deposit
    ///         epoch id, so calls made in the same epoch share it.
    function requestDeposit(uint256 assets, address controller, address owner) external returns (uint256 requestId);

    function pendingDepositRequest(uint256 requestId, address controller) external view returns (uint256 pendingAssets);

    function claimableDepositRequest(
        uint256 requestId,
        address controller
    ) external view returns (uint256 claimableAssets);

    /// @notice Claim the controller's settled deposit request: the vault transfers the shares
    ///         minted at the settlement to `receiver`, on v0.6.0 net of the entry fee at the rate
    ///         frozen at that settlement. Takes no request id; Lagoon serves
    ///         `lastDepositRequestId[controller]`.
    /// @return shares the vault shares received.
    function deposit(uint256 assets, address receiver, address controller) external returns (uint256 shares);

    /*//////////////////////////////////////////////////////////////
                          7540 — REDEEM REQUESTS
    //////////////////////////////////////////////////////////////*/

    function requestRedeem(uint256 shares, address controller, address owner) external returns (uint256 requestId);

    function pendingRedeemRequest(uint256 requestId, address controller) external view returns (uint256 pendingShares);

    function claimableRedeemRequest(
        uint256 requestId,
        address controller
    ) external view returns (uint256 claimableShares);

    /// @notice Claim the controller's settled redeem request: the vault sends `receiver` the
    ///         assets for `shares` at the rate frozen at the settlement, on v0.6.0 net of the
    ///         exit fee frozen with it. In a Closed Lagoon vault with nothing claimable
    ///         it instead burns `shares` from `controller` at the live price, on v0.6.0 net of
    ///         the live exit fee (see `LagoonBase.closeOutPosition`).
    /// @return assets the amount of underlying received.
    function redeem(uint256 shares, address receiver, address controller) external returns (uint256 assets);
}
