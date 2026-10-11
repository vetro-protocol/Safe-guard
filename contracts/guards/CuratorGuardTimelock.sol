// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @title CuratorGuardTimelock
/// @notice The `DEFAULT_ADMIN_ROLE` holder of `CuratorGuard` in production: an OpenZeppelin
///         `TimelockController` with its role topology fixed at construction and guard rails on it.
///         Every widening of a curator policy (and every long approval or long `Bypass`) is a scheduled
///         operation that sits in public for `minDelay` before anyone may execute it; the canceller
///         Safe can stop it in that window. Narrowing never goes through here: it is immediate on the
///         guard (council, guardians).
/// @dev    Topology (docs/curator-guard.md sections 4 and 6):
///         - `proposers_` hold `PROPOSER_ROLE` (in production two Safes, so one lost quorum cannot
///           strand the guard; the contract requires one); `cancellers_` hold `CANCELLER_ROLE` (in
///           production one dedicated veto Safe). Proposing and
///           vetoing are SEPARATED, by the constructor and by `_grantRole` ever after: a canceller can
///           veto its own removal, so a canceller that could also propose would be an unvetoed
///           takeover (strip the council, widen anything, approve `setGuard(0)`) once compromised,
///           while a canceller that cannot propose is at worst a deadlock, and a compromised proposer
///           is cancellable and removable. OpenZeppelin makes every proposer a canceller; this
///           constructor undoes that.
///         - the executor role is open (`address(0)`): no key is needed to land a ready operation;
///         - the timelock administers itself; NO deployer admin (the role set is final at creation,
///           nothing to renounce, nothing a deployer key could have granted in between).
///         Guard rails, enforced on the timelock's own scheduled self-calls and, for the last-holder
///         rail, on a holder's own `renounceRole` too:
///         - `getMinDelay()` is clamped to [`MIN_DELAY_FLOOR`, `MIN_DELAY_CAP`]: an `updateDelay` typed
///           in the wrong unit can neither make widenings instant nor take years to undo; the floor is
///           a day, not an hour: at an hour, a scheduled `updateDelay(1 hours)` would be one vetoable
///           operation that, if missed, shrinks the veto's window on EVERY later operation to an hour,
///           below the time a multisig veto needs to convene (round 13, G13f-3; applied after round 13);
///         - the open executor cannot be revoked (nothing could execute again, the repair included);
///         - the timelock cannot drop its own admin role (the role set would be frozen for good) and
///           never grants it to anyone else (a second admin would manage roles with no delay and no
///           veto): role management stays a scheduled, cancellable self-call;
///         - the last proposer and the last canceller cannot be removed, and neither `address(0)`
///           (which can neither schedule nor cancel) nor the timelock itself (which could only act
///           from inside an operation someone else scheduled: a phantom proposer for the last-holder
///           rail, and as a canceller a veto in every proposer's hands) ever holds a gated role;
///         - a proposer is never granted `CANCELLER_ROLE`, a canceller never `PROPOSER_ROLE`.
///         Proposal-time rails (`schedule` / `scheduleBatch`): three things are refused when the
///         operation is proposed instead of failing or misbehaving after the delay. An operation delay
///         other than the live `getMinDelay()`: an operation id carries neither its proposer nor its
///         delay, so with a longer delay one proposer could take another proposer's exact operation
///         up to 30 days out, leaving the honest schedule to revert and the honest `executeBefore`
///         wrapper dead on arrival, and a unit mistake would park the operation, and the queue, for
///         years. Calldata for a target without code: it would "execute" and be Done with nothing run
///         (`execute` refuses it again). A scheduled `updateDelay` outside the clamp: otherwise it is
///         stored and silently read as the floor or the cap.
///         Not enforced on-chain: the NUMBER of cancellers (a one-batch rotation of the veto Safe
///         holds two for a moment: it grants the new one, then revokes the old); monitoring pages on
///         any `grantRole(CANCELLER_ROLE, …)`. Only a canceller can clear a pending operation, a dead
///         one included, and cancelling a predecessor does not cancel its successor (cancel chained
///         operations as a pair).
contract CuratorGuardTimelock is TimelockController {
    uint256 public constant MIN_DELAY_FLOOR = 1 days;
    uint256 public constant MIN_DELAY_CAP = 30 days;

    error CancellerCannotPropose(address account);
    error ForwardedCall(address safe);
    error DelayOutOfRange(uint256 delay);
    error LastRoleHolder(bytes32 role);
    error NoCanceller();
    error NoProposer();
    error OpenExecutorRequired();
    error ProposerCannotCancel(address account);
    error SelfAdminRequired();
    error SelfHolder(bytes32 role);
    error TargetHasNoCode(address target);
    error ZeroAddressHolder(bytes32 role);

    /// @notice Number of accounts holding `PROPOSER_ROLE` / `CANCELLER_ROLE` (the roles are not
    ///         enumerable in `AccessControl`; kept so the last holder can never be removed).
    uint256 public proposerCount;
    uint256 public cancellerCount;

    /// @param minDelay_ seconds an operation waits before it can execute, within the clamp.
    /// @param proposers_ Safes that schedule operations (at least one; the deploy script wants two).
    /// @param cancellers_ Safes that may cancel a pending operation (at least one, never a proposer).
    constructor(
        uint256 minDelay_,
        address[] memory proposers_,
        address[] memory cancellers_
    ) TimelockController(minDelay_, proposers_, _openExecutor(), address(0)) {
        if (minDelay_ < MIN_DELAY_FLOOR || minDelay_ > MIN_DELAY_CAP) revert DelayOutOfRange(minDelay_);
        if (proposers_.length == 0) revert NoProposer();
        if (cancellers_.length == 0) revert NoCanceller();
        // Grant the cancellers first (none may be a proposer), then strip the proposers of the
        // canceller role OpenZeppelin gave them: the last-holder rail never trips while a configured
        // canceller is in place, and the separation rail of `_grantRole` is bypassed during
        // construction only here, where the constructor restores it before the code exists.
        for (uint256 i; i < cancellers_.length; ++i) {
            if (_contains(proposers_, cancellers_[i])) revert CancellerCannotPropose(cancellers_[i]);
            _grantRole(CANCELLER_ROLE, cancellers_[i]);
        }
        for (uint256 i; i < proposers_.length; ++i) _revokeRole(CANCELLER_ROLE, proposers_[i]);
    }

    /// @inheritdoc TimelockController
    /// @dev Refuses, when the operation is PROPOSED, what would otherwise fail or misbehave late: see
    ///      `_checkScheduled`.
    function schedule(
        address target_,
        uint256 value_,
        bytes calldata data_,
        bytes32 predecessor_,
        bytes32 salt_,
        uint256 delay_
    ) public virtual override onlyRole(PROPOSER_ROLE) {
        _checkScheduled(target_, data_, delay_);
        super.schedule(target_, value_, data_, predecessor_, salt_, delay_);
    }

    /// @inheritdoc TimelockController
    function scheduleBatch(
        address[] calldata targets_,
        uint256[] calldata values_,
        bytes[] calldata payloads_,
        bytes32 predecessor_,
        bytes32 salt_,
        uint256 delay_
    ) public virtual override onlyRole(PROPOSER_ROLE) {
        // A length mismatch is the base contract's error (TimelockInvalidOperationLength).
        if (targets_.length == payloads_.length && targets_.length == values_.length) {
            for (uint256 i; i < targets_.length; ++i) _checkScheduled(targets_[i], payloads_[i], delay_);
        }
        super.scheduleBatch(targets_, values_, payloads_, predecessor_, salt_, delay_);
    }

    /// @dev Proposal-time rails. (1) An operation delay is exactly the live `getMinDelay()` (the base refuses
    ///      a shorter one): a longer one would let a proposer take another proposer's exact operation (same
    ///      id, up to 30 days out), a unit mistake would park the operation for years, and
    ///      near 2^256 `block.timestamp + delay` is a bare `Panic`. (2) A scheduled
    ///      `updateDelay` outside the clamp is refused instead of being stored and silently read as the
    ///      floor or the cap (`updateDelay` can only ever run as a scheduled self-call, so this covers it).
    ///      (3) Calldata for an account without code would "execute" (`_execute` below refuses it too).
    function _checkScheduled(address target_, bytes calldata data_, uint256 delay_) private view {
        if (delay_ > getMinDelay()) revert DelayOutOfRange(delay_);
        if (data_.length != 0 && target_.code.length == 0) revert TargetHasNoCode(target_);
        if (target_ == address(this) && data_.length >= 36 && bytes4(data_[:4]) == this.updateDelay.selector) {
            uint256 _newDelay = uint256(bytes32(data_[4:36]));
            if (_newDelay < MIN_DELAY_FLOOR || _newDelay > MIN_DELAY_CAP) revert DelayOutOfRange(_newDelay);
        }
    }

    /// @dev `Address.verifyCallResult` does not look at the target's code: a call with calldata to an
    ///      account without code succeeds and the operation is Done. Refuse it (the code can be gone, or
    ///      not there yet, between proposal and execution).
    function _execute(address target_, uint256 value_, bytes calldata data_) internal virtual override {
        if (data_.length != 0 && target_.code.length == 0) revert TargetHasNoCode(target_);
        super._execute(target_, value_, data_);
    }

    /// @inheritdoc TimelockController
    /// @dev Clamped: the stored value is what `updateDelay` set, the effective one stays in range.
    function getMinDelay() public view virtual override returns (uint256) {
        uint256 _raw = super.getMinDelay();
        return _raw < MIN_DELAY_FLOOR ? MIN_DELAY_FLOOR : _raw > MIN_DELAY_CAP ? MIN_DELAY_CAP : _raw;
    }

    /// @dev A Safe forwards every selector it does not implement to its fallback handler, for ANY
    ///      caller, with itself as `msg.sender`. A proposer or veto Safe with this timelock in that slot
    ///      would make scheduling, cancelling and renouncing public (no signature, nothing in the Safe's
    ///      queue): no role for such a caller. The probe is `getStorageAt(uint256,uint256)` with
    ///      (`keccak256("fallback_manager.handler.address")`, 1) as a Safe v1.3.0+ answers it; an EOA and
    ///      a contract that is not a Safe (this timelock administering itself) do not answer and pass.
    function _refuseForwarded(address account_) private view {
        bool _forwarded;
        assembly ("memory-safe") {
            let _p := mload(0x40)
            mstore(_p, 0x5624b25b00000000000000000000000000000000000000000000000000000000)
            mstore(add(_p, 0x04), 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5)
            mstore(add(_p, 0x24), 1)
            let _ok := staticcall(gas(), account_, _p, 0x44, _p, 0x60)
            _forwarded := and(and(_ok, eq(returndatasize(), 0x60)), eq(mload(add(_p, 0x40)), address()))
        }
        if (_forwarded) revert ForwardedCall(account_);
    }

    function _checkRole(bytes32 role_, address account_) internal view virtual override {
        _refuseForwarded(account_);
        super._checkRole(role_, account_);
    }

    function renounceRole(bytes32 role_, address callerConfirmation_) public virtual override {
        _refuseForwarded(msg.sender);
        super.renounceRole(role_, callerConfirmation_);
    }

    function _grantRole(bytes32 role_, address account_) internal virtual override returns (bool _granted) {
        // `address(0)` can hold the open executor role only: a gated role granted to it can never be
        // exercised, yet it would count as a holder and defeat the last-holder rail.
        if (account_ == address(0) && role_ != EXECUTOR_ROLE) revert ZeroAddressHolder(role_);
        // The timelock itself can only exercise a gated role from inside an operation someone else
        // scheduled: as a proposer it is a phantom holder for the last-holder rail, as a canceller it
        // hands every proposer a veto (a scheduled self-call `cancel(id)`).
        if (account_ == address(this) && (role_ == PROPOSER_ROLE || role_ == CANCELLER_ROLE)) revert SelfHolder(role_);
        // Role management stays a scheduled, vetoable self-call: the timelock is its only admin.
        if (role_ == DEFAULT_ADMIN_ROLE && account_ != address(this)) revert SelfAdminRequired();
        // Proposing and vetoing stay separated after construction (the base constructor grants both
        // to every proposer and the constructor body above strips the veto again).
        if (address(this).code.length != 0) {
            if (role_ == CANCELLER_ROLE && hasRole(PROPOSER_ROLE, account_)) revert ProposerCannotCancel(account_);
            if (role_ == PROPOSER_ROLE && hasRole(CANCELLER_ROLE, account_)) revert CancellerCannotPropose(account_);
        }
        _granted = super._grantRole(role_, account_);
        if (_granted) {
            if (role_ == PROPOSER_ROLE) ++proposerCount;
            else if (role_ == CANCELLER_ROLE) ++cancellerCount;
        }
    }

    function _revokeRole(bytes32 role_, address account_) internal virtual override returns (bool _revoked) {
        if (role_ == EXECUTOR_ROLE && account_ == address(0)) revert OpenExecutorRequired();
        if (role_ == DEFAULT_ADMIN_ROLE && account_ == address(this)) revert SelfAdminRequired();
        _revoked = super._revokeRole(role_, account_);
        if (_revoked) {
            if (role_ == PROPOSER_ROLE && --proposerCount == 0) revert LastRoleHolder(role_);
            if (role_ == CANCELLER_ROLE && --cancellerCount == 0) revert LastRoleHolder(role_);
        }
    }

    function _contains(address[] memory list_, address account_) private pure returns (bool) {
        for (uint256 i; i < list_.length; ++i) if (list_[i] == account_) return true;
        return false;
    }

    function _openExecutor() private pure returns (address[] memory _executors) {
        _executors = new address[](1);
    }
}
