// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

/// @title SettlementDeadline
/// @notice A stateless deadline for Safe batches (review G13e-1). Allowlisted as a plain call with no rules and
///         placed FIRST in every settlement batch by the signers: a batch that nobody executed before its
///         deadline reverts for every executor (a v1.4.1 Safe raises GS013, v1.5.0 bubbles this reason; the nonce is kept), so a fully signed
///         settlement that went stale in the Transaction Service can no longer be landed by an outsider at a
///         mark that is no longer the curator's. Any stateless contract with this shape serves; nothing in the
///         guard changes.
contract SettlementDeadline {
    error SettlementExpired(uint256 deadline);

    function assertBefore(uint256 deadline) external view {
        if (block.timestamp > deadline) revert SettlementExpired(deadline);
    }
}
