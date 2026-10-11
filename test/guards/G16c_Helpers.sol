// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

/// @dev Review g16c: look-alikes of `contracts/helpers/SettlementDeadline.sol` a policy reviewer cannot tell from
///      the real one by the entry `{ target, signature: assertBefore(uint256) }` alone.

/// @dev Dispatches `assertBefore(uint256)` and never reverts: a deadline entry that binds nothing.
contract FakeDeadlineAlwaysPass {
    function assertBefore(uint256) external view {}
}

/// @dev The real check behind an owner's kill switch: the owner can make every batch carrying the entry revert.
contract KillSwitchDeadline {
    error SettlementExpired(uint256 deadline);
    error Halted();

    address public immutable owner;
    bool public halted;

    constructor() {
        owner = msg.sender;
    }

    function setHalted(bool halted_) external {
        require(msg.sender == owner);
        halted = halted_;
    }

    function assertBefore(uint256 deadline) external view {
        if (halted) revert Halted();
        if (block.timestamp > deadline) revert SettlementExpired(deadline);
    }
}

/// @dev A contract with no `assertBefore` at all: a catch-all fallback that returns.
contract NothingButFallback {
    fallback() external {}
}
