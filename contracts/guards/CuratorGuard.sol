// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {AccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {ISafe} from "../interfaces/safe/ISafe.sol";
import {ISafeModuleGuard, ISafeTransactionGuard, Operation} from "../interfaces/safe/ISafeGuard.sol";
import {CuratorGuardPolicy} from "./CuratorGuardPolicy.sol";

/// @title CuratorGuard
/// @notice Safe transaction guard (v1.3.0+) and module guard (v1.5.0+) that restricts a
///         curator-operated Safe (e.g. the custody Safe of a Lagoon vault) to an admin-managed,
///         dynamically updatable allowlist of `(contract, function)` pairs. Vetro governance
///         administers the guard through a timelock and a fast council; the curator keeps signing Safe
///         transactions as before, but anything outside the policy reverts inside `execTransaction`.
/// @dev    Pre-execution rules, in evaluation order (the guard's admin is always exempt):
///          1. A nested Safe transaction of the same Safe on the same path is rejected
///             (`NestedExecution`) whenever the outer transaction recorded a snapshot or an approval.
///             The check runs before the Bypass return, so a window opened inside an outer policy
///             transaction cannot be used to nest; an owner-signed transaction that itself runs inside
///             a window records nothing, so nesting inside it goes undetected (the inner transaction
///             is held to the window's own limits like any other). The owner-signed and module paths
///             are independent.
///          2. The Safe's guard slot of this path (transaction guard, module guard) must name this
///             guard (`GuardNotInstalled`): a replacement that is not installed yet and a guard the
///             Safe has moved away from are refused, so neither can spend approvals or use windows
///             when the installed guard lets the Safe call it. The post-hook does not repeat the check
///             (an approved or admin-window `setGuard` moves the slot inside the transaction, and the
///             Safe sends the post-hook to the cached guard), so a post-hook that a Safe calls
///             directly, while it holds a live window on this guard, still emits a `Bypass` report.
///          3. Module path only: the module must be allowlisted, in every mode, approval or not (a
///             guardian's `setModuleAllowed(false)` is a complete switch for that key, inside windows
///             too).
///          4. Effective `Mode.Bypass` (an unexpired window). An ADMIN window checks nothing further
///             on either path, except that the guard itself is never a call target
///             (`GuardCallNotAllowed`, true in every mode), and does not check gas refunds (a window
///             allows any transfer anyway). A COUNCIL window relaxes the owner-signed path only: it
///             refuses what would weaken the Safe, that is any self-call outside the council's
///             allowlist (which holds only owner management with a threshold of at least 2 and new
///             owners without code, `disableModule`, `setFallbackHandler(0)` and the empty rejection
///             call), any call to the policy's required fallback handler
///             (part of the Safe), any delegatecall to anything but a registered `MultiSendCallOnly`
///             (whose entries get the same limits) and a gas refund (a transfer to `refundReceiver`
///             those limits never see); the MODULE path falls through to the rules below unchanged
///             (a module needs no owner signature, and the window is opened for the signers).
///             Approvals cannot exist inside a window (`CuratorGuardPolicy`).
///          5. Gas refunds are rejected (`gasPrice != 0`): `handlePayment` can otherwise pay out
///             the Safe's ERC-20 / native balance to an arbitrary `refundReceiver`.
///          6. An unconsumed, unexpired approval for the exact payload AND execution path
///             (owner-signed, or a specific module; for a delegatecall also the code at the target)
///             passes, is consumed, and skips the policy. An approved delegatecall into canonical
///             `MultiSendCallOnly` code is strictly decoded first (canonical encoding, plain-call
///             entries, none addressed to this guard), and no approval is spent while the Safe's
///             fallback handler is this guard (`ForwardedHookCall`: the Safe would forward anyone's
///             call here with itself as the caller). A failing approved execution reverts the whole
///             Safe transaction, whatever `safeTxGas` says (the Safe's own rule when it is zero, the
///             post-hook's `ApprovedExecutionFailed` otherwise), so the approval is never burnt. This
///             is the only path, outside a window, for Safe self-calls and raw delegatecalls.
///          7. `Mode.Lockdown` (including an expired `Bypass`) rejects.
///          8. The account must be a known Safe proxy in front of a known Safe singleton (runtime code
///             hashes fixed at deployment, `SafeNotSupported`); its critical configuration (singleton
///             as reported by the proxy, modules head, owners, owner count, threshold, fallback
///             handler, guard, module guard) is snapshotted into transient storage; the fallback
///             handler must be none or the policy's required one when a requirement is set; and no
///             module may be linked unless this guard is also the module guard (`ModuleNotHooked`).
///          9. `operation == DelegateCall` is accepted, with no value, only to a registered unwrapper
///             whose runtime code hash is still allowed (`MultiSendCallOnly`); the batch is strictly
///             decoded and every entry is checked as a plain call. Entries whose operation is not a
///             plain call, or addressed to the zero address (which v1.5.0 `MultiSendCallOnly` rewrites
///             to the Safe itself), are rejected.
///         10. A plain call must target neither the Safe itself (no `setGuard`, `enableModule`,
///             `swapOwner`, …; the only exception is the empty zero-value self-call Safe{Wallet} uses
///             to reject a queued transaction) nor this guard. Empty calldata needs the native-transfer
///             permission and calldata shorter than a selector is malformed; otherwise the selector
///             must be allowed on the target, the target must carry code, a non-zero value needs
///             `allowValue`, and every configured parameter rule must hold.
///         Post-execution: the call must be exactly an after-hook's 68 bytes (`ForwardedHookCall`:
///         a call forwarded by a Safe's fallback carries the caller's address where `success` sits),
///         then the single transient slot of `(safe, path)` is read and cleared. An approved
///         execution (the slot holds `APPROVED_SENTINEL`) is done; an empty slot is only legitimate
///         for the admin or an effective `Bypass` (`MissingSnapshot` otherwise); a snapshot must equal
///         the current digest, so any change to the Safe's guard, module guard, modules head, owner
///         list, owner count, threshold, fallback handler or singleton reverts the whole Safe
///         transaction (fail closed).
///         Every transaction that passes both hooks is reported once (`TransactionChecked`: owner or
///         module path, and whether the policy, an approval or a Bypass window let it through); the
///         admin's own transactions are neither checked nor reported.
///         The digest cannot enumerate mappings (a dangling `modules[x]` / `owners[x]` /
///         `approvedHashes` / `signedMessages` entry is invisible to it), which is why unwrapper code
///         is pinned by hash, and only the canonical `MultiSendCallOnly` hashes seeded at deployment
///         can ever be allowed (code that calls the hooks from the Safe's context could otherwise
///         clear the snapshot and take a fresh one of the modified configuration, so the comparison
///         would pass).
/// @dev    Requires EIP-1153 transient storage (Cancun) for the in-flight / snapshot slot; the
///         constructor probes for it so a deployment on a pre-Cancun chain fails instead of bricking
///         the first guarded Safe. The configuration reads go through the Safe's own views. A Safe
///         whose owner list is longer than its owner count (only a storage-writing delegatecall
///         can do that) makes `getOwners()` fail: an index-out-of-bounds write, `Panic(0x32)` on a
///         0.8 build and the gas-consuming `INVALID` opcode on the deployed 0.7.6 singletons. Either
///         way the hook reports `SafeConfigUnreadable`. Such a Safe recovers through an approval or
///         a Bypass window, neither of which reads the owner list: a window reads one slot of the
///         Safe (the guard slot of rule 2), an approval that slot and the fallback-handler slot.
/// @dev    Not covered and documented in `docs/curator-guard.md`: pre-existing allowances and
///         storage planted before install, EIP-1271 signatures while a 1271-capable fallback handler
///         is installed (hence `setRequiredFallbackHandler`), upgradeable targets changing their code
///         underneath an allowlisted selector, and owners that acquire code after they were vetted.
contract CuratorGuard is CuratorGuardPolicy, ISafeTransactionGuard, ISafeModuleGuard {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error ApprovedExecutionFailed(address safe);
    error CouncilBypassLimit(bytes4 selector);
    error DelegateCallNotAllowed(address to);
    error EmptyMultiSend();
    error FallbackHandlerNotAllowed(address handler);
    error ForwardedHookCall();
    error FunctionNotAllowed(address to, bytes4 selector);
    error GasRefundNotAllowed();
    error GuardCallNotAllowed(bytes4 selector);
    error GuardNotInstalled(address safe);
    error MalformedCalldata();
    error MalformedMultiSend();
    error MissingSnapshot(address safe);
    error ModuleNotHooked(address module);
    error MultiSendDelegateCallEntry();
    error NestedExecution(address safe);
    error NativeTransferNotAllowed(address to);
    error ParamOutOfRange(address to, bytes4 selector, uint16 wordIndex);
    error ParamRuleViolated(address to, bytes4 selector, uint16 wordIndex, bytes32 word);
    error SafeConfigChanged(address safe);
    error SafeConfigUnreadable(address safe);
    error SafeLockedDown(address safe);
    error SafeNotSupported(address safe);
    error SelfCallNotAllowed(bytes4 selector);
    error ValueNotAllowed(address to, bytes4 selector);

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @dev Everything the pre-check needs besides the calldata and the Safe (`msg.sender`), packed so
    ///      the legacy codegen keeps the hook within the stack limit. `executor` is `address(0)` on the
    ///      owner-signed path and the module on the module path; `gasPrice` is 0 on the module path.
    struct ExecContext {
        uint8 path;
        address executor;
        address to;
        uint256 value;
        Operation operation;
        uint256 gasPrice;
    }

    /// @notice How a Safe transaction got through the hooks: `Policy` (allowlist evaluated, Safe
    ///         configuration snapshotted and re-verified), `Approval` (a one-shot approval was
    ///         consumed), `Bypass` (inside an unexpired window).
    enum Outcome {
        Policy,
        Approval,
        Bypass
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted by the post-hook, once per Safe transaction that passed (never for a transaction
    ///         whose pre-hook ran as the admin: those are not checked). `path` is `0` for the owner-signed path,
    ///         where `txHash` is the Safe's own `safeTxHash` (unique per execution, nonce included), and
    ///         `1` for the module path, where it is the payload hash `checkModuleTransaction` returned
    ///         (Safe v1.5.0 emits no hash itself; identical module payloads share it, so index module
    ///         executions by log position, not by hash).
    event TransactionChecked(address indexed safe, bytes32 indexed txHash, uint8 path, Outcome indexed outcome);

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    // Internal (no getters) to keep the runtime under the EIP-170 limit; `CuratorGuardHarness` in the
    // tests exposes them so the literals stay pinned to Safe's own hashes.
    /// @dev keccak256("guard_manager.guard.address"), Safe `GuardManager`.
    bytes32 internal constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    /// @dev keccak256("module_manager.module_guard.address"), Safe v1.5.0 `ModuleManager`.
    bytes32 internal constant MODULE_GUARD_STORAGE_SLOT =
        0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;
    /// @dev `modules[SENTINEL_MODULES]`: keccak256(abi.encode(address(1), uint256(1))), `SafeStorage`
    ///      slot 1. Points at the first enabled module (or the sentinel when there is none).
    bytes32 internal constant MODULES_HEAD_SLOT = 0xcc69885fda6bcc1a4ace058b4a62bf5e179ea78fd58a1ccd71c22cc9b688792f;
    /// @dev `multiSend(bytes)`.
    bytes4 internal constant MULTISEND_SELECTOR = 0x8d80ff0a;
    /// @dev `masterCopy()`: answered by `SafeProxy` itself (v1.1.1+), never by the singleton.
    bytes4 internal constant MASTER_COPY_SELECTOR = 0xa619486e;
    /// @dev selector (4) + `bytes` head offset (32) + `bytes` length (32).
    uint256 private constant MULTISEND_HEADER = 68;
    /// @dev operation (1) + to (20) + value (32) + data length (32).
    uint256 private constant MULTISEND_ENTRY_HEADER = 85;
    /// @dev Execution paths; approvals and transient slots are keyed per path.
    uint8 private constant PATH_OWNER = 0;
    uint8 private constant PATH_MODULE = 1;
    /// @dev What `_validateMultiSend` holds every entry of a batch to: the policy, the council-window
    ///      limits, or (an approved batch) only "never this guard".
    uint8 private constant ENTRY_POLICY = 0;
    uint8 private constant ENTRY_COUNCIL = 1;
    uint8 private constant ENTRY_APPROVED = 2;
    /// @dev The transient slot of `(safe, path)` (EIP-1153; `_stateKey`) holds `0` (idle),
    ///      `APPROVED_SENTINEL` (an approved execution is in flight) or the configuration digest
    ///      snapshotted pre-execution (a hash, so it never equals the sentinel in practice).
    bytes32 private constant APPROVED_SENTINEL = bytes32(uint256(1));

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        uint48 adminDelay_,
        address admin_,
        address council_
    ) CuratorGuardPolicy(adminDelay_, admin_, council_) {
        // EIP-1153 probe. Before Cancun `tload` / `tstore` are invalid opcodes: a guard deployed on
        // such a chain would revert every Safe transaction of a guarded Safe, approved ones included,
        // and `setGuard(0)` runs through the very same hooks, so the Safe would be bricked. Fail here,
        // at deployment, instead. The write-back of the loaded value changes nothing and keeps both
        // opcodes in the code (a bare load with an unused result could be optimised away).
        bytes32 _probe = _stateKey(address(0), PATH_OWNER);
        _tstore(_probe, _tload(_probe));
    }

    /*//////////////////////////////////////////////////////////////
                         SAFE TRANSACTION GUARD HOOKS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISafeTransactionGuard
    /// @dev `msg.sender` is the Safe. Unused Safe parameters are deliberately not bound to names.
    function checkTransaction(
        address to_,
        uint256 value_,
        bytes calldata data_,
        Operation operation_,
        uint256 /* safeTxGas */,
        uint256 /* baseGas */,
        uint256 gasPrice_,
        address /* gasToken */,
        address payable /* refundReceiver */,
        bytes memory /* signatures */,
        address /* msgSender */
    ) external override {
        _preCheck(
            ExecContext({
                path: PATH_OWNER,
                executor: address(0),
                to: to_,
                value: value_,
                operation: operation_,
                gasPrice: gasPrice_
            }),
            data_
        );
    }

    /// @inheritdoc ISafeTransactionGuard
    /// @dev `txHash_` is the Safe's `safeTxHash` of the transaction that just ran (reported, not used).
    function checkAfterExecution(bytes32 txHash_, bool success_) external override {
        _afterExecution(msg.sender, PATH_OWNER, txHash_, success_);
    }

    /*//////////////////////////////////////////////////////////////
                           SAFE MODULE GUARD HOOKS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISafeModuleGuard
    /// @dev The module must be allowlisted, approval or not; the payload is then held to the same
    ///      policy as an owner-signed transaction. The Safe echoes the returned hash
    ///      into `checkAfterModuleExecution`, which reports it in `TransactionChecked`: it identifies
    ///      the payload as `keccak256(abi.encode(safe, module, to, value, keccak256(data), operation))`
    ///      (the Safe is folded in so two Safes driven by one module with one payload do not share it).
    function checkModuleTransaction(
        address to_,
        uint256 value_,
        bytes calldata data_,
        Operation operation_,
        address module_
    ) external override returns (bytes32) {
        _preCheck(
            ExecContext({
                path: PATH_MODULE,
                executor: module_,
                to: to_,
                value: value_,
                operation: operation_,
                gasPrice: 0
            }),
            data_
        );
        return keccak256(abi.encode(msg.sender, module_, to_, value_, keccak256(data_), operation_));
    }

    /// @inheritdoc ISafeModuleGuard
    /// @dev `txHash_` is what `checkModuleTransaction` returned for this execution (reported, not used).
    function checkAfterModuleExecution(bytes32 txHash_, bool success_) external override {
        _afterExecution(msg.sender, PATH_MODULE, txHash_, success_);
    }

    /*//////////////////////////////////////////////////////////////
                                 ERC-165
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC-165: the Safe checks `0xe6d7a83a` on `setGuard` (v1.4.1+; v1.3.0 stores any address
    ///         unchecked) and `0x58401ed8` on `setModuleGuard`.
    function supportsInterface(
        bytes4 interfaceId_
    ) public view override(AccessControlDefaultAdminRules, IERC165) returns (bool) {
        return
            interfaceId_ == type(ISafeTransactionGuard).interfaceId ||
            interfaceId_ == type(ISafeModuleGuard).interfaceId ||
            super.supportsInterface(interfaceId_);
    }

    /*//////////////////////////////////////////////////////////////
                             VIEW: DRY RUNS
    //////////////////////////////////////////////////////////////*/

    /// @notice Stateless replica of the `checkTransaction` pre-check for off-chain simulation
    ///         (`eth_call`): reverts with the error the live check would raise, without consuming
    ///         approvals. Assumes `gasPrice == 0`; reads the Safe's configuration through the same
    ///         function as the live pre-check (so `SafeNotSupported`, `SafeConfigUnreadable`,
    ///         `FallbackHandlerNotAllowed` and `ModuleNotHooked` reproduce). Not modelled: the nesting
    ///         check, the installed-slot check (a replacement guard can be simulated before the swap)
    ///         and the post-execution comparison.
    function validateTransaction(
        address safe_,
        address to_,
        uint256 value_,
        bytes calldata data_,
        Operation operation_
    ) external view {
        _dryRun(safe_, PATH_OWNER, address(0), to_, value_, data_, operation_);
    }

    /// @notice `validateTransaction` for the module path (Safe v1.5.0 `setModuleGuard`).
    function validateModuleTransaction(
        address safe_,
        address module_,
        address to_,
        uint256 value_,
        bytes calldata data_,
        Operation operation_
    ) external view {
        _dryRun(safe_, PATH_MODULE, module_, to_, value_, data_, operation_);
    }

    /*//////////////////////////////////////////////////////////////
                            INTERNAL: HOOK LOGIC
    //////////////////////////////////////////////////////////////*/

    /// @dev Shared pre-execution check for both hooks (`msg.sender` is the Safe). See the contract
    ///      NatSpec for the order.
    function _preCheck(ExecContext memory c_, bytes calldata data_) internal {
        if (msg.sender == defaultAdmin()) return;
        SafePolicy storage $ = _policies[msg.sender];
        bytes32 _key = _stateKey(msg.sender, c_.path);
        // One Safe transaction per path at a time: a nested `execTransaction` of the same Safe
        // would share the slot and could hide or consume the outer snapshot or approval. Checked
        // before the Bypass return so a window opened inside an outer policy transaction cannot be
        // used to nest.
        if (_tload(_key) != 0) revert NestedExecution(msg.sender);
        _requireInstalled(msg.sender, c_.path);
        // Before the window and the approval branch: a module off the allowlist can do nothing in any
        // mode, approved or not, so a guardian's `setModuleAllowed(false)` is a complete switch for that
        // key (the read is of this guard's own storage, so it never stands in the way of a window's
        // recovery purpose: the admin allowlists the module it wants to use).
        _checkModule($, c_.path, c_.executor);
        Mode _mode = _effectiveMode($);
        // A window relaxes the owner-signed path. An admin window is otherwise inert; a council window
        // leaves the module path under the policy: a module needs no owner signature, and the window
        // is opened for the signers, not for an automation key.
        if (_mode == Mode.Bypass && _checkWindow($, msg.sender, c_.path, c_.to, data_, c_.operation, c_.gasPrice)) {
            return;
        }
        if (c_.gasPrice != 0) revert GasRefundNotAllowed();
        bytes32 _approvalId = computeApprovalId(msg.sender, c_.executor, c_.to, c_.value, data_, c_.operation);
        uint64 _expiry = _approvals[_approvalId].expiry;
        if (_expiry != 0 && block.timestamp <= _expiry) {
            _checkApprovalUse(msg.sender, c_.to, data_, c_.operation);
            delete _approvals[_approvalId];
            _tstore(_key, APPROVED_SENTINEL);
            emit ApprovalConsumed(msg.sender, _approvalId, c_.executor);
            return;
        }
        if (_mode == Mode.Lockdown) revert SafeLockedDown(msg.sender);
        _snapshotConfig($, msg.sender, _key);
        _validate($, msg.sender, c_.to, c_.value, data_, c_.operation);
    }

    /// @dev Snapshots the Safe's critical configuration into the slot once the policy path's
    ///      requirements on it hold.
    function _snapshotConfig(SafePolicy storage $, address safe_, bytes32 key_) internal {
        _tstore(key_, _checkConfig($, safe_));
    }

    /// @dev Reads the configuration and enforces what the policy path requires of it, for the live
    ///      pre-check and the dry run alike (one function, so the two cannot diverge): the
    ///      fallback-handler requirement, and that no module is linked unless this guard is also the
    ///      Safe's MODULE guard. A linked module this guard does not hook (Safe v1.3.0 / v1.4.1: any
    ///      module; v1.5.0+: `setModuleGuard(guard)` never ran, or the slot points elsewhere) executes
    ///      with no check at all, `setGuard(0)` included: the policy refuses to run next to one
    ///      (`ModuleNotHooked(firstLinkedModule)`), like it refuses to run with a handler it does not
    ///      allow. Approvals and Bypass windows skip this check, so the fix
    ///      (`disableModule`, council lane; `setModuleGuard`, admin lane) stays executable.
    function _checkConfig(SafePolicy storage $, address safe_) internal view returns (bytes32 _digest) {
        address _handler;
        address _unhooked;
        (_digest, _handler, _unhooked) = _configDigest(safe_);
        _checkHandler($, _handler);
        if (_unhooked != address(0)) revert ModuleNotHooked(_unhooked);
    }

    /// @dev No handler is always acceptable (nothing signs, nothing is forwarded); a non-zero one must
    ///      be the handler the policy names. The council's `setFallbackHandler(0)` is therefore a
    ///      complete fast-lane fix for every requirement.
    function _checkHandler(SafePolicy storage $, address handler_) internal view {
        if ($.enforceFallbackHandler && handler_ != address(0) && handler_ != $.requiredFallbackHandler) {
            revert FallbackHandlerNotAllowed(handler_);
        }
    }

    /// @dev Shared post-execution check. Reads and clears the transient slot before anything else so
    ///      no state can leak into a later Safe transaction of the same EVM transaction, then asserts
    ///      the configuration snapshot unless the execution was approved. A failed approved execution
    ///      reverts (the module path, and the owner path when the transaction carries a non-zero
    ///      `safeTxGas`; with `safeTxGas == 0` the Safe reverts before it gets here), which rolls the
    ///      consumption back atomically, so a failed one-off never costs its approval and no restore
    ///      state is needed. Ends with the single `TransactionChecked` of the transaction. Nothing is
    ///      reported for the admin's own transactions: the pre-hook recorded nothing and the account is
    ///      still the admin. A Safe that became the admin during an approved transaction is reported
    ///      once, as `Approval`.
    function _afterExecution(address safe_, uint8 path_, bytes32 txHash_, bool success_) internal {
        // Both after-hooks are exactly `4 + 64` bytes. `FallbackManager` appends the caller's 20 bytes to
        // what it forwards: a forwarded call of that exact length carries them in the low bytes of
        // `success`, which the ABI decoder has already refused as a dirty `bool`. The one way a forwarded
        // call could reach this frame at the canonical length, `executeBefore`'s delegatecall to self,
        // refuses a forwarded caller before it re-dispatches (`CuratorGuardPolicy`, G9a-1).
        if (msg.data.length != 68) revert ForwardedHookCall();
        bytes32 _key = _stateKey(safe_, path_);
        bytes32 _state = _tload(_key);
        _tstore(_key, 0);
        Outcome _outcome; // Outcome.Policy
        if (_state == APPROVED_SENTINEL) {
            if (!success_) revert ApprovedExecutionFailed(safe_);
            _outcome = Outcome.Approval;
        } else if (_state == 0) {
            // The pre-hook recorded nothing: legitimate only for the admin or inside a Bypass window
            // (both evaluated at the same `block.timestamp`, so pre and post agree on the window).
            if (safe_ == defaultAdmin()) return;
            if (_effectiveMode(_policies[safe_]) != Mode.Bypass) revert MissingSnapshot(safe_);
            _outcome = Outcome.Bypass;
        } else {
            (bytes32 _current, , ) = _configDigest(safe_);
            if (_current != _state) revert SafeConfigChanged(safe_);
        }
        emit TransactionChecked(safe_, txHash_, path_, _outcome);
    }

    /// @dev `view` replica of `_preCheck` (no consumption, no snapshot, no nesting check).
    function _dryRun(
        address safe_,
        uint8 path_,
        address executor_,
        address to_,
        uint256 value_,
        bytes calldata data_,
        Operation operation_
    ) internal view {
        if (safe_ == defaultAdmin()) return;
        SafePolicy storage $ = _policies[safe_];
        _checkModule($, path_, executor_);
        Mode _mode = _effectiveMode($);
        if (_mode == Mode.Bypass && _checkWindow($, safe_, path_, to_, data_, operation_, 0)) return;
        uint64 _expiry = _approvals[computeApprovalId(safe_, executor_, to_, value_, data_, operation_)].expiry;
        if (_expiry != 0 && block.timestamp <= _expiry) {
            _checkApprovalUse(safe_, to_, data_, operation_);
            return;
        }
        if (_mode == Mode.Lockdown) revert SafeLockedDown(safe_);
        _checkConfig($, safe_);
        _validate($, safe_, to_, value_, data_, operation_);
    }

    /// @dev Digest over: the singleton as answered by the proxy bytecode itself (`masterCopy()`,
    ///      which `SafeProxy` serves without delegating, so a swapped singleton cannot lie about it),
    ///      owner count + threshold (`SafeStorage` slots 3-4), the owner list, the modules linked-list
    ///      head, the fallback handler, the guard and module guard, read through the Safe's own
    ///      `StorageAccessible` / `OwnerManager` views. The views' raw ABI responses are hashed as
    ///      returned, concatenated (each is shape-checked by `_read`, so no decoder can panic here, and
    ///      the concatenation parses uniquely: a 32-byte singleton, 128 bytes of core slots, an owner
    ///      array whose second word is its own length, then four 96-byte single-slot responses): a Safe
    ///      that cannot answer them reverts `SafeConfigUnreadable` instead of a bare `Panic`.
    ///      Before any of it, the account must be a known Safe proxy in front of a known Safe singleton
    ///      (runtime code hashes fixed at deployment, `_safeCodehashes`): only then do the views, and
    ///      the hooks themselves, mean what this guard assumes. A look-alike, a singleton that forwards
    ///      to replaceable code or is an EIP-7702 delegated account, and a Safe release this guard was
    ///      never reviewed against are refused on the policy path (`SafeNotSupported`; approvals and
    ///      Bypass windows do not come through here, so the exits stay open).
    function _configDigest(
        address safe_
    ) internal view returns (bytes32 _digest, address _handler, address _unhooked) {
        (bool _ok, bytes memory _master) = safe_.staticcall(abi.encodeWithSelector(MASTER_COPY_SELECTOR));
        bytes32 _masterCopy;
        assembly ("memory-safe") {
            _masterCopy := mload(add(_master, 0x20))
        }
        if (
            !_ok ||
            _master.length != 32 ||
            !_safeCodehashes[safe_.codehash] ||
            !_safeCodehashes[address(uint160(uint256(_masterCopy))).codehash]
        ) revert SafeNotSupported(safe_);
        bytes memory _owners = _read(safe_, abi.encodeWithSelector(ISafe.getOwners.selector), 0);
        bytes memory _core = _readStorage(safe_, 3, 2);
        bytes memory _modulesHead = _readStorage(safe_, uint256(MODULES_HEAD_SLOT), 1);
        bytes memory _fallback = _readStorage(safe_, uint256(FALLBACK_HANDLER_STORAGE_SLOT), 1);
        bytes memory _guard = _readStorage(safe_, uint256(GUARD_STORAGE_SLOT), 1);
        bytes memory _moduleGuard = _readStorage(safe_, uint256(MODULE_GUARD_STORAGE_SLOT), 1);
        bytes32 _handlerWord;
        bytes32 _head;
        assembly ("memory-safe") {
            // `bytes` response: offset word, length word, then the slot's value (length checked above).
            _handlerWord := mload(add(_fallback, 0x60))
            // `modules[SENTINEL]` is the sentinel itself (zero before `setup`) while no module is linked.
            // A linked module counts as hooked only when the module-guard slot holds exactly this guard.
            _head := mload(add(_modulesHead, 0x60))
            if or(lt(_head, 2), eq(mload(add(_moduleGuard, 0x60)), address())) {
                _head := 0
            }
        }
        _handler = address(uint160(uint256(_handlerWord)));
        _unhooked = address(uint160(uint256(_head)));
        _digest = keccak256(abi.encodePacked(_masterCopy, _core, _owners, _modulesHead, _fallback, _guard, _moduleGuard));
    }

    /// @dev The pre-hook answers only the Safe whose guard slot of `path_` (transaction guard, module
    ///      guard) names this guard: a replacement that is not installed yet, a guard the Safe has moved
    ///      away from and any account that is not a guarded Safe cannot spend approvals or use windows
    ///      here (`GuardNotInstalled`; an account that cannot answer `getStorageAt` is
    ///      `SafeConfigUnreadable` like every configuration read). Only `getStorageAt` is consulted, so a
    ///      Safe whose OWNER LIST is unreadable (section 7.6 step 4) keeps the approval and window exits.
    ///      Checked before the window and approval branches; not in the post-hook (an approved or
    ///      admin-window `setGuard` moves the slot inside the transaction and the cached guard still gets
    ///      the post-hook; so a post-hook a Safe calls directly, while it holds a live window on this
    ///      guard, still emits a `Bypass` report, see rule 2 of the contract NatSpec) and not in the
    ///      dry runs (the pre-swap checklist simulates against the replacement).
    function _requireInstalled(address safe_, uint8 path_) private view {
        if (_slotWord(safe_, path_ == PATH_OWNER ? GUARD_STORAGE_SLOT : MODULE_GUARD_STORAGE_SLOT) != _self()) {
            revert GuardNotInstalled(safe_);
        }
    }

    function _self() private view returns (bytes32) {
        return bytes32(uint256(uint160(address(this))));
    }

    /// @dev One storage word of the Safe, through its own `getStorageAt`.
    function _slotWord(address safe_, bytes32 slot_) private view returns (bytes32 _word) {
        bytes memory _ret = _readStorage(safe_, uint256(slot_), 1);
        assembly ("memory-safe") {
            _word := mload(add(_ret, 0x60))
        }
    }

    /// @dev `getStorageAt(offset_, words_)` as the Safe answers it (`bytes` of `32 * words_`).
    function _readStorage(address safe_, uint256 offset_, uint256 words_) private view returns (bytes memory) {
        unchecked {
            // words_ is 1 or 2
            return _read(safe_, abi.encodeWithSelector(ISafe.getStorageAt.selector, offset_, words_), 64 + 32 * words_);
        }
    }

    /// @dev `staticcall` into the Safe; every failure surfaces as `SafeConfigUnreadable`: a revert (a
    ///      `Panic`, or on the deployed 0.7.6 singletons an `INVALID` opcode that burns the forwarded
    ///      gas, from `getOwners()` on a Safe whose owner list is longer than its owner count; out of
    ///      gas), an account without code, or a response of the wrong shape. `expectedLength_ == 0`
    ///      accepts a well-formed `address[]` (offset word, count word, `count` words) of any count.
    function _read(address safe_, bytes memory call_, uint256 expectedLength_) private view returns (bytes memory _ret) {
        bool _ok;
        (_ok, _ret) = safe_.staticcall(call_);
        uint256 _length = _ret.length;
        if (expectedLength_ == 0) {
            // The count word is only meaningful once `_length >= 64`, which the conjunction checks first;
            // for a shorter response the load reads past the array and its value is discarded.
            uint256 _count;
            assembly ("memory-safe") {
                _count := mload(add(_ret, 0x40))
            }
            _ok = _ok && _length >= 64 && _length & 31 == 0 && _count == (_length - 64) >> 5;
        } else {
            _ok = _ok && _length == expectedLength_;
        }
        if (!_ok) revert SafeConfigUnreadable(safe_);
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL: VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @dev Policy evaluation for one Safe transaction (delegatecall batch or plain call).
    function _validate(
        SafePolicy storage $,
        address safe_,
        address to_,
        uint256 value_,
        bytes calldata data_,
        Operation operation_
    ) internal view {
        if (operation_ == Operation.DelegateCall) {
            _checkUnwrapper($, to_);
            if (value_ != 0) revert ValueNotAllowed(to_, MULTISEND_SELECTOR);
            _validateMultiSend($, safe_, data_, ENTRY_POLICY);
            return;
        }
        _validateCall($, safe_, to_, value_, data_);
    }

    /// @dev The checks of an open window, shared by the live pre-check and the dry run. Returns
    ///      whether the window handled the transaction: `false` for the module path inside a council
    ///      window, which stays under the policy and the module allowlist (a module needs no owner
    ///      signature; the window is opened for the signers). A council window keeps the Safe's
    ///      security configuration out of reach: every owner-signed call is held to the council's
    ///      limits, and no gas refund (the refund is a transfer the Safe makes to `refundReceiver` that
    ///      those limits never see). An admin window checks nothing further on either path (the
    ///      module allowlist was checked before it), but the guard is never a call target from a
    ///      guarded Safe (a plain call into the post-hook could otherwise forge a report).
    function _checkWindow(
        SafePolicy storage $,
        address safe_,
        uint8 path_,
        address to_,
        bytes calldata data_,
        Operation operation_,
        uint256 gasPrice_
    ) internal view returns (bool) {
        if ($.councilBypass) {
            if (path_ == PATH_MODULE) return false;
            if (gasPrice_ != 0) revert GasRefundNotAllowed();
            _councilBypassCheck($, safe_, to_, data_, operation_);
        } else {
            _denyGuardTarget(to_, data_);
        }
        return true;
    }

    /// @dev Module path only: the module must be allowlisted, in every mode (before the window and the
    ///      approval branch: a module off the allowlist spends no approval and uses no window either).
    function _checkModule(SafePolicy storage $, uint8 path_, address executor_) internal view {
        if (path_ == PATH_MODULE) _checkModuleAllowed($, executor_);
    }

    /// @dev Inside a COUNCIL-opened Bypass window: no policy, but nothing that removes or weakens the
    ///      guard. Delegatecalls only to a registered, hash-pinned `MultiSendCallOnly`, whose entries
    ///      are held to the same self-call allowlist as council approvals (`_councilMaySelfCall`).
    function _councilBypassCheck(
        SafePolicy storage $,
        address safe_,
        address to_,
        bytes calldata data_,
        Operation operation_
    ) internal view {
        if (operation_ == Operation.DelegateCall) {
            _checkUnwrapper($, to_);
            _validateMultiSend($, safe_, data_, ENTRY_COUNCIL);
            return;
        }
        _denyWeakening(safe_, to_, data_, true);
    }

    /// @dev What must hold when a live approval is about to be used, in the hook and in the dry run.
    ///      (1) The Safe's fallback handler is not this guard (below). (2) An approved batch is still a
    ///      batch: a delegatecall whose target carries canonical `MultiSendCallOnly` code (registered or
    ///      not, forbidden or not: the approval decides that) must be the canonical encoding of
    ///      plain-call entries, none of them addressed to this guard. The builds themselves execute
    ///      truncated and non-canonical payloads that decoders display differently (a payload cut `k`
    ///      bytes short inside a value word sends the bytes shown, shifted left by `8k` bits), so without
    ///      this an approval would bind bytes whose meaning depends on the reader. Single-call approvals
    ///      and delegatecalls into any other code stay unparsed (the `setGuard(0)` exit, raw libraries).
    function _checkApprovalUse(address safe_, address to_, bytes calldata data_, Operation operation_) internal view {
        // `FallbackManager` forwards every selector the Safe does not implement to its fallback handler,
        // for ANY caller, with the Safe as `msg.sender`: with this guard in that slot a stranger would
        // consume the approval with nothing executed. The forwarded length is the caller's choice
        // (`calldatasize() + 20`), so no calldata shape tells such a call apart; the slot does. No
        // approval is spent (or reported usable by the dry run) while it holds this guard; a window,
        // which records nothing, stays the way to execute the `setFallbackHandler` repair.
        if (_isHandlerOf(safe_)) revert ForwardedHookCall();
        if (operation_ == Operation.DelegateCall && _canonicalCodehashes[to_.codehash]) {
            _validateMultiSend(_policies[safe_], safe_, data_, ENTRY_APPROVED);
        }
    }

    /// @dev `to` must be a registered unwrapper whose runtime code hash is still allowed.
    function _checkUnwrapper(SafePolicy storage $, address to_) internal view {
        if (!$.multiSendUnwrappers.contains(to_)) revert DelegateCallNotAllowed(to_);
        bytes32 _codehash = to_.codehash;
        if (!_unwrapperCodehashes[_codehash]) revert UnwrapperCodehashNotAllowed(_codehash);
    }

    /// @dev The council-window check for one plain call (top-level or a batch entry): never the guard,
    ///      self-calls only from the council's allowlist (`council_`; an approved batch entry is held to
    ///      the first limit only).
    function _denyWeakening(address safe_, address to_, bytes calldata data_, bool council_) internal view {
        _denyGuardTarget(to_, data_);
        if (council_ && !_councilMaySelfCall(safe_, to_, data_)) revert CouncilBypassLimit(_selectorOf(data_));
    }

    /// @dev The guard is never a call target from a guarded Safe, whatever the mode: its hooks and its
    ///      role surface must never be reachable from a Safe transaction.
    function _denyGuardTarget(address to_, bytes calldata data_) internal view {
        if (to_ == address(this)) revert GuardCallNotAllowed(_selectorOf(data_));
    }

    /// @dev Policy evaluation for one plain call (top-level or a batch entry).
    function _validateCall(
        SafePolicy storage $,
        address safe_,
        address to_,
        uint256 value_,
        bytes calldata data_
    ) internal view {
        bytes4 _selector = _selectorOf(data_);
        if (to_ == safe_) {
            // Safe{Wallet}'s "Reject transaction" is an empty, zero-value self-call that burns the nonce
            // and touches no state (it lands in `receive()`): the one self-call the policy lets through.
            if (value_ == 0 && data_.length == 0) return;
            revert SelfCallNotAllowed(_selector);
        }
        _denyGuardTarget(to_, data_);
        if (data_.length == 0) {
            if (!$.nativeTransferAllowed[to_]) revert NativeTransferNotAllowed(to_);
            return;
        }
        if (data_.length < 4) revert MalformedCalldata();
        FunctionPermission storage _f = $.functions[to_][_selector];
        if (!_f.allowed) revert FunctionNotAllowed(to_, _selector);
        // A function call to an account without code never does what the policy author reviewed (a
        // mistyped target one bit off a venue "succeeds" and keeps the value): fail closed. This costs
        // no liveness: post-Cancun a contract's code cannot disappear, a counterfactual target becomes
        // callable once deployed, and the native lane above is untouched. The one account whose code
        // can go is an EIP-7702 delegated EOA: its 23-byte designator passes this check and vanishes
        // when its key clears the delegation, so such a target fails closed here from then on. It is an
        // upgradeable venue with a single-key admin: never allowlist one.
        if (to_.code.length == 0) revert NotAContract(to_);
        if (value_ != 0 && !_f.allowValue) revert ValueNotAllowed(to_, _selector);
        uint256 _count = _f.rules.length;
        for (uint256 i; i < _count; ++i) {
            _checkRule($, safe_, to_, _selector, data_, _f.rules[i]);
        }
    }

    /// @dev Evaluates one rule against `data_`; fails closed when the word is missing. The rule's
    ///      subject is the static word at `4 + 32 * wordIndex`, or, with `TAIL_FLAG` set in
    ///      `wordIndex`, the hash of everything from that word to the end of the calldata (offsets,
    ///      lengths, contents and any trailing bytes): the one way to bind a dynamic argument, from
    ///      the FIRST dynamic parameter's head word on (a later start leaves an earlier offset free).
    function _checkRule(
        SafePolicy storage $,
        address safe_,
        address to_,
        bytes4 selector_,
        bytes calldata data_,
        ParamRule storage rule_
    ) internal view {
        uint16 _wordIndex = rule_.wordIndex;
        uint256 _start;
        unchecked {
            _start = 4 + 32 * uint256(_wordIndex & ~TAIL_FLAG); // at most 4 + 32 * 32767
            if (data_.length < _start + 32) revert ParamOutOfRange(to_, selector_, _wordIndex);
        }
        bytes32 _word = _wordIndex & TAIL_FLAG != 0 ? keccak256(data_[_start:]) : bytes32(data_[_start:_start + 32]);
        RuleKind _kind = rule_.kind;
        bool _ok;
        if (_kind == RuleKind.EqualToSafe) {
            _ok = _word == bytes32(uint256(uint160(safe_)));
        } else if (_kind == RuleKind.OneOf) {
            _ok = _valueSet($, to_, selector_, _wordIndex).contains(_word);
        } else if (_kind == RuleKind.LessThanOrEqual) {
            _ok = uint256(_word) <= uint256(rule_.value);
        } else if (_kind == RuleKind.GreaterThanOrEqual) {
            // always paired with an upper bound on the same word, see `_validateRules`
            _ok = uint256(_word) >= uint256(rule_.value);
        } else {
            // RuleKind.EqualTo, and the fail-closed default for a kind added later without a branch here
            _ok = _word == rule_.value;
        }
        if (!_ok) revert ParamRuleViolated(to_, selector_, _wordIndex, _word);
    }

    /// @dev Strict `multiSend(bytes)` decoding: the `bytes` head offset must be `0x20`, the calldata
    ///      length must equal the padded encoding exactly, every packed entry must fit inside the
    ///      declared payload and be a plain call. Each entry is validated like a top-level call
    ///      (`ENTRY_POLICY`), held to the council-window limits (`ENTRY_COUNCIL`: never the guard,
    ///      self-calls only from the council's allowlist) or, for an approved batch, only kept off this
    ///      guard (`ENTRY_APPROVED`).
    function _validateMultiSend(SafePolicy storage $, address safe_, bytes calldata data_, uint8 entries_) internal view {
        if (data_.length < MULTISEND_HEADER) revert MalformedMultiSend();
        uint256 _length;
        {
            // The 68 header bytes exist (checked above): three in-bounds calldata reads.
            uint256 _selector;
            uint256 _head;
            assembly ("memory-safe") {
                _selector := shr(224, calldataload(data_.offset))
                _head := calldataload(add(data_.offset, 4))
                _length := calldataload(add(data_.offset, 36))
            }
            if (_selector != uint32(MULTISEND_SELECTOR) || _head != 0x20) revert MalformedMultiSend();
        }
        // `_length > data_.length` first: `_ceil32` of an absurd length would otherwise overflow into a
        // `Panic` instead of the typed error.
        if (_length > data_.length || data_.length != MULTISEND_HEADER + _ceil32(_length)) revert MalformedMultiSend();
        // A non-empty payload holds at least one entry (`_decodeEntry` refuses anything shorter).
        if (_length == 0) revert EmptyMultiSend();
        uint256 _offset = MULTISEND_HEADER;
        uint256 _end;
        unchecked {
            _end = MULTISEND_HEADER + _length; // <= data_.length
        }
        while (_offset < _end) {
            (address _to, uint256 _value, uint256 _dataStart, uint256 _dataLength) = _decodeEntry(data_, _offset, _end);
            unchecked {
                _offset = _dataStart + _dataLength; // <= _end, checked by `_decodeEntry`
            }
            bytes calldata _entryData = data_[_dataStart:_offset];
            if (entries_ == ENTRY_POLICY) _validateCall($, safe_, _to, _value, _entryData);
            else _denyWeakening(safe_, _to, _entryData, entries_ == ENTRY_COUNCIL);
        }
    }

    /// @dev Decodes one packed `MultiSend` entry at `offset_`, bounds-checked against `end_`. A zero
    ///      `to` is rejected: v1.5.0 `MultiSendCallOnly` rewrites it to the calling Safe (a self-call
    ///      the literal comparison in `_validateCall` would not see), v1.3.0 / v1.4.1 would call the
    ///      zero address.
    function _decodeEntry(
        bytes calldata data_,
        uint256 offset_,
        uint256 end_
    ) internal pure returns (address _to, uint256 _value, uint256 _dataStart, uint256 _dataLength) {
        unchecked {
            // Caller's invariant: `offset_ < end_ <= data_.length`.
            if (end_ - offset_ < MULTISEND_ENTRY_HEADER) revert MalformedMultiSend();
            // The 85 header bytes lie inside `data_` (`offset_ + 85 <= end_ <= data_.length`), so three
            // in-bounds calldata reads replace bounds-checked slices: operation (1) | to (20) | value (32)
            // | data length (32).
            uint256 _head;
            assembly ("memory-safe") {
                let _p := add(data_.offset, offset_)
                _head := calldataload(_p)
                _value := calldataload(add(_p, 21))
                _dataLength := calldataload(add(_p, 53))
            }
            if (_head >> 248 != uint8(Operation.Call)) revert MultiSendDelegateCallEntry();
            _to = address(uint160(_head >> 88));
            if (_to == address(0)) revert MalformedMultiSend();
            _dataStart = offset_ + MULTISEND_ENTRY_HEADER;
            if (_dataLength > end_ - _dataStart) revert MalformedMultiSend();
        }
    }

    /// @dev Rounds up to a multiple of 32 (ABI padding of a `bytes` payload).
    function _ceil32(uint256 length_) internal pure returns (uint256) {
        return (length_ + 31) & ~uint256(31);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL: TRANSIENT STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @dev Transient slot of `(safe, path)`: the guard's transient storage holds nothing else, so the
    ///      literal `safe << 8 | path` is unique without hashing.
    function _stateKey(address safe_, uint8 path_) private pure returns (bytes32) {
        return bytes32((uint256(uint160(safe_)) << 8) | path_);
    }

    function _tload(bytes32 key_) private view returns (bytes32 _value) {
        assembly ("memory-safe") {
            _value := tload(key_)
        }
    }

    function _tstore(bytes32 key_, bytes32 value_) private {
        assembly ("memory-safe") {
            tstore(key_, value_)
        }
    }
}
