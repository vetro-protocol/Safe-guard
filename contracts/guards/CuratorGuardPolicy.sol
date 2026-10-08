// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {AccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {Operation} from "../interfaces/safe/ISafeGuard.sol";

/// @title CuratorGuardPolicy
/// @notice Storage, administration and read surface of `CuratorGuard`: a per-Safe allowlist of
///         `(target, selector)` pairs with optional static-parameter rules, plus the one-shot
///         transaction approvals that authorise anything outside the policy.
/// @dev    Roles (OpenZeppelin `AccessControlDefaultAdminRules`):
///          - `DEFAULT_ADMIN_ROLE` ("admin", exactly one account, two-step transfer with a delay; in
///            production `CuratorGuardTimelock`, an OpenZeppelin `TimelockController` fed by Vetro
///            governance): the only role that can WIDEN a policy, approve long-lived transactions, open
///            a long `Bypass` window and administer roles. Transferring the admin to `address(0)` is
///            refused: an adminless guard could never be reconfigured or removed from a Safe (every
///            `setGuard` is a self-call that only the admin's approval or window can authorise). The
///            admin's lifts (`enforce` after a lockdown), windows and approvals come out of a public
///            queue anyone can execute, so they are refused for `LOCKDOWN_COOLDOWN` after every
///            lockdown of the Safe (time for the cancellers to cancel what was queued before the
///            incident). The admin itself is never constrained by the guard (see
///            `CuratorGuard`), so installing the guard on the admin cannot deadlock it; keep the admin a
///            contract that is never a guarded Safe.
///          - `COUNCIL_ROLE` ("council", a fast multisig with no curator keys): lifts a lockdown
///            (`enforce`), issues short approvals (≤ `MAX_COUNCIL_APPROVAL_TTL`) whose Safe self-calls
///            are limited to an allowlist (owner management that never sets a threshold below 2,
///            `disableModule`, `setFallbackHandler(0)`, the empty rejection call; the policy's required
///            fallback handler counts as part of the Safe and is unreachable),
///            opens a short `Bypass` (≤ `MAX_COUNCIL_BYPASS`) that relaxes the owner-signed path only
///            (the same self-call allowlist applies there; the module path stays under the policy and
///            the module allowlist), manages per-Safe and deployment-wide guardians,
///            re-allows a canonical unwrapper hash, and can narrow anything. No role holder can act on
///            itself as a Safe (`enforce`, `bypass`, `approveTransaction` with `safe == msg.sender`).
///          - guardians (warm keys / monitoring bots), per Safe (`setGuardian`) or deployment-wide
///            (`GUARDIAN_ROLE`): can only NARROW a policy (lockdown, revoke, remove values, revoke
///            approvals). They can never widen it.
/// @dev    Policies are keyed by Safe address: `checkTransaction` is called by the Safe itself, so
///         `msg.sender` identifies the policy. One deployment serves any number of Safes.
/// @dev    An unconfigured Safe is in `Mode.Lockdown` (enum default): every transaction is rejected
///         until the admin configures a policy or an approval authorises the transaction. Fail-closed.
///         `Bypass` is always time-boxed and reads as `Lockdown` once it expires.
abstract contract CuratorGuardPolicy is AccessControlDefaultAdminRules {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice `Lockdown`: reject everything except approved transactions (default, and what an
    ///         expired `Bypass` reads as). `Enforced`: evaluate the allowlist. `Bypass`: the policy is
    ///         off for this Safe's owner-signed path until `bypassUntil` (emergency valve; nothing is
    ///         recorded or compared there, and no approval can be issued or consumed). A council-opened
    ///         window still refuses the self-calls outside the council's allowlist on that path and
    ///         leaves the module path entirely under the policy (snapshot, allowlist, post-execution
    ///         comparison, nesting check); an admin window checks nothing on either path but the
    ///         module allowlist and that the guard is never a call target.
    enum Mode {
        Lockdown,
        Enforced,
        Bypass
    }

    /// @notice Rule applied to the 32-byte static word at calldata offset `4 + 32 * wordIndex`.
    ///         `EqualTo`: word == value. `EqualToSafe`: word == the calling Safe (receiver /
    ///         onBehalf pinning). `OneOf`: word ∈ `allowedValues(safe, target, selector, wordIndex)`.
    ///         `LessThanOrEqual` / `GreaterThanOrEqual`: unsigned comparison against `value` over the
    ///         full 256-bit word.
    /// @dev    Only HEAD words are addressable by index. For a dynamic parameter the head word is an
    ///         offset, not the value: do not write word rules against dynamic parameters. With
    ///         `TAIL_FLAG` set in `wordIndex` the rule's subject is instead the hash of the calldata
    ///         from that word to its end (`keccak256(data[4 + 32 * (wordIndex & 0x7fff):])`), which
    ///         binds a dynamic payload exactly (`EqualTo` one reviewed payload, `OneOf` a set of them)
    ///         when the word is the FIRST dynamic parameter's head word: from a later word the offset
    ///         of an earlier dynamic parameter stays outside the hash and the callee reads that
    ///         parameter from wherever the offset points (the tooling refuses such a rule).
    /// @dev    `GreaterThanOrEqual` alone is fail-open (a word with dirty high bits, or a negative
    ///         `intN`, exceeds any floor), so it is only accepted together with an upper bound
    ///         (`LessThanOrEqual`, `EqualTo` or `OneOf`) on the same word.
    enum RuleKind {
        EqualTo,
        EqualToSafe,
        OneOf,
        LessThanOrEqual,
        GreaterThanOrEqual
    }

    struct ParamRule {
        RuleKind kind;
        uint16 wordIndex;
        bytes32 value;
    }

    struct FunctionSpec {
        address target;
        bytes4 selector;
        bool allowValue;
        ParamRule[] rules;
    }

    struct FunctionPermission {
        bool allowed;
        bool allowValue;
        /// @dev Bumped by every revocation and folded into the keys of the function's `OneOf` sets:
        ///      revoking abandons the sets in O(1) instead of iterating their members (about 14k gas
        ///      each on committed storage), and a later re-allow starts from empty sets.
        uint32 generation;
        ParamRule[] rules;
    }

    /// @dev One storage slot. `safe` lets revocation events name the Safe and `epoch` lets views tell
    ///      a stale record from a live one; the id itself already binds
    ///      `(safe, epoch, executor, to, value, data, operation)`.
    struct Approval {
        address safe;
        uint64 expiry;
        uint32 epoch;
    }

    struct SafePolicy {
        Mode mode;
        /// @dev When `enforceFallbackHandler` is set, every non-approved transaction requires the
        ///      Safe's fallback handler to be none or `requiredFallbackHandler` (no handler is always
        ///      acceptable: nothing signs, nothing is forwarded). Used to keep EIP-1271 capable
        ///      handlers (which let signers authorise `permit` / EIP-3009 pulls off-chain, bypassing
        ///      the guard entirely) off the Safe.
        bool enforceFallbackHandler;
        address requiredFallbackHandler;
        /// @dev End of the current `Bypass` window; meaningful only while `mode == Bypass`.
        uint64 bypassUntil;
        /// @dev The current `Bypass` window was opened by the council: the owner-signed path is inert
        ///      for policy purposes but still refuses Safe self-calls outside the council's allowlist
        ///      (the limits of a council approval) and delegatecalls to anything but a registered
        ///      unwrapper; the module path is not relaxed at all.
        bool councilBypass;
        /// @dev Time of the last `lockdown` / `lockdownAndRevoke` (starts `LOCKDOWN_COOLDOWN`).
        uint64 lockedAt;
        EnumerableSet.AddressSet targets;
        mapping(address target => EnumerableSet.Bytes32Set) selectors;
        mapping(address target => mapping(bytes4 selector => FunctionPermission)) functions;
        mapping(address target => bool) nativeTransferAllowed;
        EnumerableSet.AddressSet multiSendUnwrappers;
        EnumerableSet.AddressSet modules;
        EnumerableSet.AddressSet guardians;
        mapping(bytes32 valueSetKey => EnumerableSet.Bytes32Set) allowedValues;
    }

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error AddressIsNull();
    error AdminCannotBeZero();
    error AdminDelayTooLong(uint48 delay);
    error AdminIsGuarded(address account);
    error ApprovalNotFound(bytes32 approvalId);
    error CouncilCannotApprove(bytes4 selector, Operation operation);
    error DeadlinePassed(uint64 deadline);
    error InvalidDuration(uint64 duration);
    error InvalidRule(uint256 index);
    error InvalidTarget(address target);
    error LockdownCooldown(address safe);
    error ModuleNotAllowed(address module);
    error NoOneOfRule(uint16 wordIndex);
    error NotAContract(address account);
    error SafeInBypass(address safe);
    error TooManyRules(uint256 count);
    error TooManyValues(uint256 count);
    error UnboundedLowerBound(uint256 index);
    error Unauthorized();
    error UnwrapperCodehashNotAllowed(bytes32 codehash);

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event AllowedValueAdded(
        address indexed safe,
        address indexed target,
        bytes4 indexed selector,
        uint16 wordIndex,
        bytes32 value
    );
    event AllowedValueRemoved(
        address indexed safe,
        address indexed target,
        bytes4 indexed selector,
        uint16 wordIndex,
        bytes32 value
    );
    event ApprovalConsumed(address indexed safe, bytes32 indexed approvalId, address executor);
    event ApprovalRevoked(address indexed safe, bytes32 indexed approvalId);
    /// @dev Every approval issued for `safe` before `epoch` is void.
    event ApprovalsRevoked(address indexed safe, uint32 epoch);
    event FunctionAllowed(
        address indexed safe,
        address indexed target,
        bytes4 indexed selector,
        bool allowValue,
        ParamRule[] rules
    );
    event FunctionRevoked(address indexed safe, address indexed target, bytes4 indexed selector);
    event GuardianUpdated(address indexed safe, address indexed guardian, bool enabled);
    /// @dev `bypassUntil` is non-zero only for `Mode.Bypass`; `councilBypass` tells a council window
    ///      (owner-signed path relaxed within the council's self-call allowlist and the unwrapper-only
    ///      delegatecall rule; module path under the full policy) from an admin window (nothing checked
    ///      on either path but the module allowlist and that the guard is never a call target).
    event ModeUpdated(address indexed safe, Mode indexed mode, uint64 bypassUntil, bool councilBypass);
    event ModuleUpdated(address indexed safe, address indexed module, bool allowed);
    event MultiSendUnwrapperUpdated(address indexed safe, address indexed multiSend, bool allowed);
    event NativeTransferUpdated(address indexed safe, address indexed target, bool allowed);
    event RequiredFallbackHandlerUpdated(address indexed safe, address handler, bool enforce);
    event UnwrapperCodehashUpdated(bytes32 indexed codehash, bool allowed);
    event TransactionApproved(
        address indexed safe,
        bytes32 indexed approvalId,
        address executor,
        address to,
        uint256 value,
        bytes data,
        Operation operation,
        uint64 expiry,
        uint32 epoch
    );

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Guard generation, for tooling and migrations (the deployed bytecode is what the tooling
    ///         pins; this is what an indexer or a replacement runbook can read).
    uint256 public constant VERSION = 2;
    /// @notice Fast lane: lift lockdowns, short approvals and bypasses, per-Safe guardians, narrowing.
    bytes32 public constant COUNCIL_ROLE = keccak256("COUNCIL_ROLE");
    /// @notice Deployment-wide narrow-only responder (every Safe). Per-Safe guardians: `setGuardian`.
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    // Limits are `internal` (no getters) to keep the runtime under the EIP-170 limit; the test harness
    // exposes them and `tasks/curator-guard.ts` mirrors the ones it needs.
    /// @dev Upper bound on rules per `(target, selector)`; bounds the per-call check cost.
    uint256 internal constant MAX_RULES = 16;
    /// @dev Upper bound on members of one `OneOf` set; keeps `clearAllowedValues` and a re-allow that
    ///      drops a `OneOf` rule (which iterate the set) executable in one block.
    uint256 internal constant MAX_ALLOWED_VALUES = 128;
    /// @dev Upper bound on allowed selectors per target; bounds what `revokeTarget` iterates.
    uint256 internal constant MAX_SELECTORS = 32;
    /// @dev Upper bound on per-Safe guardians: the set is council-managed, and an unbounded one would
    ///      outgrow the `guardians` view and the removal batches of whoever cleans up after a bad council.
    uint256 internal constant MAX_GUARDIANS = 32;
    /// @dev `wordIndex` flag: the rule binds the hash of the calldata tail from that word (`_checkRule`).
    uint16 internal constant TAIL_FLAG = 0x8000;
    /// @dev Longest validity of an admin approval (standing emergency payloads such as `pause()`).
    uint64 internal constant MAX_ADMIN_APPROVAL_TTL = 180 days;
    /// @dev Longest validity of a council approval.
    uint64 internal constant MAX_COUNCIL_APPROVAL_TTL = 7 days;
    /// @dev Shortest `Bypass` window: opening one voids every approval, so a window typed in the wrong
    ///      unit (`7` for 7 days) must not be able to do that for a useless few seconds.
    uint64 internal constant MIN_BYPASS = 1 hours;
    /// @dev Shortest approval validity: a `ttl` typed in the wrong unit (`7` for 7 days) would otherwise
    ///      be issued, sit in a timelock queue and be dead on arrival for every signer.
    uint64 internal constant MIN_APPROVAL_TTL = 1 hours;
    /// @dev Lowest threshold a council-authorised owner-management call may set: a custody Safe must
    ///      never become single-key through the fast lane (a paste error away from one lost key).
    uint256 internal constant MIN_COUNCIL_THRESHOLD = 2;
    /// @dev After a lockdown the admin may not `enforce`, `bypass` or approve for that Safe for this
    ///      long. Admin actions are timelock operations: scheduled before the lockdown, executable by
    ///      anyone, and so runnable in the same transaction as one the signers already signed. The pause
    ///      gives the cancellers a day to cancel them; the council, which acts live, is not held back.
    uint64 internal constant LOCKDOWN_COOLDOWN = 1 days;
    /// @dev Longest `Bypass` window the admin can open (renewable).
    uint64 internal constant MAX_ADMIN_BYPASS = 180 days;
    /// @dev Longest `Bypass` window the council can open.
    uint64 internal constant MAX_COUNCIL_BYPASS = 7 days;
    /// @dev Upper bound on the admin-transfer delay (constructor and `changeDefaultAdminDelay`): a
    ///      typo'd delay could otherwise make the admin hand-over take years (the library applies a
    ///      longer delay after at most 5 days, and lowering it again then waits the difference).
    uint48 internal constant MAX_ADMIN_DELAY = 30 days;
    /// @dev Lower bound for `changeDefaultAdminDelay` (not the constructor: test deployments use 0): a
    ///      delay typed in the wrong unit (`3` for three days) would otherwise leave no time to cancel
    ///      a hand-over that slipped past the veto.
    uint48 internal constant MIN_ADMIN_DELAY = 1 days;
    /// @dev Runtime code hashes of the canonical `MultiSendCallOnly` deployments (safe-deployments
    ///      v1.3.0 `0x40A2…130D`, v1.4.1 `0x9641…02e2`, v1.5.0 `0xA83c…1836`), the only unwrapper code
    ///      that can ever be allowed (`isUnwrapperCodehash` reads the live allowlist).
    bytes32 internal constant MULTISEND_CALL_ONLY_V130_CODEHASH =
        0xa9865ac2d9c7a1591619b188c4d88167b50df6cc0c5327fcbd1c8c75f7c066ad;
    bytes32 internal constant MULTISEND_CALL_ONLY_V141_CODEHASH =
        0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939;
    bytes32 internal constant MULTISEND_CALL_ONLY_V150_CODEHASH =
        0xcdbdcec38d2f1c7d961b0029ff8416b7e86e9974d6f0e9c9580c7d17fcfb6663;

    /// @dev The only Safe self-calls the council may authorise (approvals and council windows): owner
    ///      management (`addOwnerWithThreshold`, `removeOwner`, `swapOwner`, `changeThreshold`),
    ///      `disableModule`, and `setFallbackHandler(address(0))` (checked by payload). Everything else
    ///      addressed to the Safe is admin-only: `setGuard` / `setModuleGuard` (remove or weaken the
    ///      guard), `enableModule` (opens the unguarded v1.3.0 / v1.4.1 module path), any other fallback
    ///      handler (EIP-1271), and every selector the Safe does not implement, which `FallbackManager`
    ///      forwards to the fallback handler with the Safe as the caller (a stateful handler's own
    ///      `onlySelf` surface). An allowlist stays closed when a Safe release adds `authorized` functions.
    bytes4 internal constant SAFE_ADD_OWNER_WITH_THRESHOLD = 0x0d582f13;
    bytes4 internal constant SAFE_REMOVE_OWNER = 0xf8dc5dd9;
    bytes4 internal constant SAFE_SWAP_OWNER = 0xe318b52b;
    bytes4 internal constant SAFE_CHANGE_THRESHOLD = 0x694e80c3;
    bytes4 internal constant SAFE_DISABLE_MODULE = 0xe009cfde;
    bytes4 internal constant SAFE_SET_FALLBACK_HANDLER = 0xf08a0323;

    mapping(address safe => SafePolicy) internal _policies;
    /// @dev Runtime code hashes a delegatecall unwrapper must have, at registration and at every use.
    ///      Only the canonical `MultiSendCallOnly` builds seeded in the constructor can ever be allowed:
    ///      any other code runs in the Safe's storage context, can plant dangling `modules[x]` /
    ///      `owners[x]` entries the configuration digest cannot see, and can even re-arm the hooks to
    ///      launder the digest. A new Safe release therefore means a new guard (approved `setGuard`),
    ///      never a widening of this set. Guardians may forbid a hash; the admin may re-allow a seeded one.
    mapping(bytes32 codehash => bool) internal _unwrapperCodehashes;
    mapping(bytes32 codehash => bool) internal _canonicalCodehashes;
    /// @dev Runtime code hashes of the Safe proxies and singletons this guard supports: the proxy the
    ///      v1.3.0 / v1.4.1 / v1.5.0 factories create and the L1 and L2 singletons of those releases
    ///      (safe-deployments `codeHash`; the proxy hashes follow from the factories' code). Fixed at
    ///      deployment like the unwrapper set: a new Safe release means a new guard.
    mapping(bytes32 codehash => bool) internal _safeCodehashes;
    /// @dev One-shot approvals, keyed by `computeApprovalId`. `expiry == 0` means none.
    mapping(bytes32 approvalId => Approval) internal _approvals;
    /// @dev Folded into every approval id; bumping it voids all outstanding approvals of a Safe.
    ///      Bumped by `revokeAllApprovals` and whenever a `Bypass` window opens.
    mapping(address safe => uint32 epoch) internal _approvalEpochs;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param adminDelay_ delay of the two-step admin transfer (`AccessControlDefaultAdminRules`).
    /// @param admin_ initial admin (production: `CuratorGuardTimelock`). Never a guarded Safe.
    /// @param council_ optional initial council (`address(0)` = none; grant later with `grantRole`);
    ///        never the admin (the admin is exempt from the guard, the council must not be).
    constructor(
        uint48 adminDelay_,
        address admin_,
        address council_
    ) AccessControlDefaultAdminRules(adminDelay_, admin_) {
        if (adminDelay_ > MAX_ADMIN_DELAY) revert AdminDelayTooLong(adminDelay_);
        if (council_ != address(0)) _grantRole(COUNCIL_ROLE, council_); // `_grantRole` refuses the admin
        _safeCodehashes[0xb89c1b3bdf2cf8827818646bce9a8f6e372885f8c55e5c07acbd307cb133b000] = true; // GnosisSafeProxy 1.3.0
        _safeCodehashes[0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c] = true; // SafeProxy 1.4.1
        _safeCodehashes[0x4e381985ca68b3e5d27b4425fa581c19cf33146d3f887a3cfca96f55528ea46f] = true; // SafeProxy 1.5.0
        _safeCodehashes[0xbba688fbdb21ad2bb58bc320638b43d94e7d100f6f3ebaab0a4e4de6304b1c2e] = true; // GnosisSafe 1.3.0
        _safeCodehashes[0x21842597390c4c6e3c1239e434a682b054bd9548eee5e9b1d6a4482731023c0f] = true; // GnosisSafeL2 1.3.0
        _safeCodehashes[0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4] = true; // Safe 1.4.1
        _safeCodehashes[0xb1f926978a0f44a2c0ec8fe822418ae969bd8c3f18d61e5103100339894f81ff] = true; // SafeL2 1.4.1
        _safeCodehashes[0xdda019cbd7c867a533a2a86e5c53434fdc50b13122b5a5ddb4a8df61b31c20f2] = true; // Safe 1.5.0
        _safeCodehashes[0x180193227186ccb85316c94db1f0d156ed932b14712cfaac78901899178572dc] = true; // SafeL2 1.5.0
        _unwrapperCodehashes[MULTISEND_CALL_ONLY_V130_CODEHASH] = true;
        _unwrapperCodehashes[MULTISEND_CALL_ONLY_V141_CODEHASH] = true;
        _unwrapperCodehashes[MULTISEND_CALL_ONLY_V150_CODEHASH] = true;
        _canonicalCodehashes[MULTISEND_CALL_ONLY_V130_CODEHASH] = true;
        _canonicalCodehashes[MULTISEND_CALL_ONLY_V141_CODEHASH] = true;
        _canonicalCodehashes[MULTISEND_CALL_ONLY_V150_CODEHASH] = true;
        emit UnwrapperCodehashUpdated(MULTISEND_CALL_ONLY_V130_CODEHASH, true);
        emit UnwrapperCodehashUpdated(MULTISEND_CALL_ONLY_V141_CODEHASH, true);
        emit UnwrapperCodehashUpdated(MULTISEND_CALL_ONLY_V150_CODEHASH, true);
    }

    /*//////////////////////////////////////////////////////////////
                                  MODE
    //////////////////////////////////////////////////////////////*/

    /// @notice Narrow: freeze `safe_` (admin, council or a guardian of the Safe). Approved
    ///         transactions still pass; `lockdownAndRevoke` voids those too. Either one starts
    ///         `LOCKDOWN_COOLDOWN`, during which no admin lift, window or approval executes.
    function lockdown(address safe_) external {
        _lockdown(safe_);
    }

    /// @notice Narrow: `lockdown` and `revokeAllApprovals` in one transaction (admin, council or a
    ///         guardian of the Safe). For when the signers or a standing approval are the threat: nothing
    ///         runs for `safe_` afterwards, standing approvals included, until the council or admin lifts
    ///         the lockdown or issues a new approval, and no approved payload can slip through between the
    ///         two steps. The default incident response is `lockdown`, which keeps approved one-offs.
    function lockdownAndRevoke(address safe_) external {
        _lockdown(safe_);
        _bumpEpoch(safe_);
    }

    function _lockdown(address safe_) private {
        _nonZero(safe_);
        _checkNarrower(safe_);
        _setMode(safe_, Mode.Lockdown, 0, false);
    }

    /// @notice Evaluate the allowlist for `safe_` (admin or council). Also the way out of a `Bypass`.
    function enforce(address safe_) external {
        _nonZero(safe_);
        _checkAdminOrCouncilFor(safe_);
        _setMode(safe_, Mode.Enforced, 0, false);
    }

    /// @notice Make the guard inert for `safe_` for `duration_` seconds (admin ≤ `MAX_ADMIN_BYPASS`,
    ///         council ≤ `MAX_COUNCIL_BYPASS`): the emergency valve while a replacement guard is
    ///         prepared. Opening a window voids every outstanding approval of the Safe, and none can be
    ///         issued while it is open, so an approval can never be "used" unconsumed inside a window
    ///         and replayed after it. When the window expires the Safe reads as `Lockdown`. A council
    ///         window relaxes the owner-signed path only, within the council's limits; a module
    ///         (no owner signature) stays under the policy and the module allowlist. An admin window
    ///         is inert on both paths, but for the module allowlist and the guard as a call target.
    function bypass(address safe_, uint64 duration_) external {
        _nonZero(safe_);
        bool _admin = _checkAdminOrCouncilFor(safe_);
        if (duration_ < MIN_BYPASS || duration_ > (_admin ? MAX_ADMIN_BYPASS : MAX_COUNCIL_BYPASS)) {
            revert InvalidDuration(duration_);
        }
        _bumpEpoch(safe_);
        unchecked {
            _setMode(safe_, Mode.Bypass, uint64(block.timestamp) + duration_, !_admin); // duration_ <= 180 days
        }
    }

    /// @notice Run one of this contract's own admin/council functions only if `deadline_` has not
    ///         passed, as the caller (`delegatecall` to self keeps `msg.sender`). For operations that
    ///         sit in a timelock queue: a queued `bypass` / `approveTransaction` / widening that nobody
    ///         executed in time is then dead instead of a latent, permissionless action months later.
    function executeBefore(uint64 deadline_, bytes calldata call_) external returns (bytes memory) {
        if (block.timestamp > deadline_) revert DeadlinePassed(deadline_);
        (bool _ok, bytes memory _ret) = address(this).delegatecall(call_);
        if (!_ok) {
            assembly ("memory-safe") {
                revert(add(_ret, 0x20), mload(_ret))
            }
        }
        return _ret;
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN / COUNCIL: ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Grant or revoke the deployment-wide narrow-only `GUARDIAN_ROLE` (admin or council): a
    ///         compromised responder key must be removable on the fast lane, not after the timelock.
    function setDeploymentGuardian(address guardian_, bool enabled_) external {
        _nonZero(guardian_);
        _checkAdminOrCouncil();
        if (enabled_) _grantRole(GUARDIAN_ROLE, guardian_);
        else _revokeRole(GUARDIAN_ROLE, guardian_);
    }

    /// @notice Add or remove a narrow-only guardian for `safe_` (admin or council); at most
    ///         `MAX_GUARDIANS` per Safe, never the zero address, the Safe itself or this guard.
    function setGuardian(address safe_, address guardian_, bool enabled_) external {
        _nonZero(safe_);
        _checkTarget(safe_, guardian_); // never zero, the Safe or this guard (a dead seat)
        _checkAdminOrCouncil();
        EnumerableSet.AddressSet storage _set = _policies[safe_].guardians;
        bool _changed = enabled_ ? _set.add(guardian_) : _set.remove(guardian_);
        if (_set.length() > MAX_GUARDIANS) revert TooManyValues(MAX_GUARDIANS);
        if (_changed) emit GuardianUpdated(safe_, guardian_, enabled_);
    }

    /// @notice Require the Safe's fallback handler to be `handler_` (typically `address(0)`), or none,
    ///         for every non-approved transaction. The canonical `CompatibilityFallbackHandler`
    ///         implements EIP-1271, which lets a signer quorum authorise `permit` /
    ///         `transferWithAuthorization` pulls on 1271-aware tokens (e.g. USDC) without any Safe
    ///         transaction: keep it off. A handler is never the Safe itself nor this guard.
    function setRequiredFallbackHandler(address safe_, address handler_, bool enforce_) external {
        _checkAdmin();
        _nonZero(safe_);
        if (handler_ != address(0)) _checkTarget(safe_, handler_);
        SafePolicy storage $ = _policies[safe_];
        $.requiredFallbackHandler = handler_;
        $.enforceFallbackHandler = enforce_;
        emit RequiredFallbackHandlerUpdated(safe_, handler_, enforce_);
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN: FUNCTION ALLOWLIST
    //////////////////////////////////////////////////////////////*/

    /// @notice Allow `safe_` to call `target_.selector_`. Re-calling REPLACES the rules and the
    ///         `allowValue` flag. A `OneOf` value set is preserved only while a `OneOf` rule on the
    ///         same word is kept; sets of dropped `OneOf` rules are cleared.
    /// @param  allowValue_ permit a non-zero native value on this call (payable functions).
    /// @param  rules_ static-parameter rules, ANDed. `EqualToSafe` / `OneOf` rules must carry
    ///         `value == 0`; `GreaterThanOrEqual` needs an upper bound on the same word.
    function allowFunction(
        address safe_,
        address target_,
        bytes4 selector_,
        bool allowValue_,
        ParamRule[] calldata rules_
    ) external {
        _checkAdmin();
        _allowFunction(safe_, target_, selector_, allowValue_, rules_);
    }

    /// @notice Batch form of `allowFunction`; atomic (one invalid spec reverts the whole batch).
    function allowFunctions(address safe_, FunctionSpec[] calldata specs_) external {
        _checkAdmin();
        uint256 _len = specs_.length;
        for (uint256 i; i < _len; ++i) {
            FunctionSpec calldata _s = specs_[i];
            _allowFunction(safe_, _s.target, _s.selector, _s.allowValue, _s.rules);
        }
    }

    /// @notice Narrow: revoke one function. Its `OneOf` value sets are abandoned at once (no member is
    ///         iterated and no `AllowedValueRemoved` is emitted: a later re-allow starts from empty sets).
    ///         No-op (no event) when the function is not allowed.
    function revokeFunction(address safe_, address target_, bytes4 selector_) external {
        _checkNarrower(safe_);
        _revokeFunction(safe_, target_, selector_);
    }

    /// @notice Narrow: revoke every function (at most `MAX_SELECTORS`) and the native-transfer permission
    ///         of `target_`. A no-op, without events, for a target that carries nothing.
    function revokeTarget(address safe_, address target_) external {
        _checkNarrower(safe_);
        SafePolicy storage $ = _policies[safe_];
        bytes32[] memory _selectors = $.selectors[target_].values();
        uint256 _len = _selectors.length;
        for (uint256 i; i < _len; ++i) {
            _revokeFunction(safe_, target_, bytes4(_selectors[i]));
        }
        if ($.nativeTransferAllowed[target_]) {
            $.nativeTransferAllowed[target_] = false;
            emit NativeTransferUpdated(safe_, target_, false);
        }
        $.targets.remove(target_);
    }

    /// @notice Permit (admin) or forbid (any narrower) empty-calldata calls to `target_`, i.e. plain
    ///         native-token transfers. Also required for zero-value empty calls.
    function setNativeTransferAllowed(address safe_, address target_, bool allowed_) external {
        SafePolicy storage $ = _checkSetter(safe_, target_, allowed_);
        $.nativeTransferAllowed[target_] = allowed_;
        if (allowed_) $.targets.add(target_);
        else _pruneTarget($, target_);
        emit NativeTransferUpdated(safe_, target_, allowed_);
    }

    /// @notice Add members to the `OneOf` set consulted by the rule on `(target_, selector_, wordIndex_)`.
    ///         The function must already carry a `OneOf` rule on that word (allow first, then add
    ///         values). Address members must be encoded as full 32-byte words
    ///         (`bytes32(uint256(uint160(a)))`).
    function addAllowedValues(
        address safe_,
        address target_,
        bytes4 selector_,
        uint16 wordIndex_,
        bytes32[] calldata values_
    ) external {
        _checkAdmin();
        // No function can be allowed for Safe 0 (`_allowFunction`), so a zero `safe_` is `NoOneOfRule`.
        SafePolicy storage $ = _policies[safe_];
        if (!_hasOneOfRule($.functions[target_][selector_], wordIndex_)) revert NoOneOfRule(wordIndex_);
        EnumerableSet.Bytes32Set storage _set = _valueSet($, target_, selector_, wordIndex_);
        uint256 _len = values_.length;
        for (uint256 i; i < _len; ++i) {
            bytes32 _value = values_[i];
            if (_set.add(_value)) emit AllowedValueAdded(safe_, target_, selector_, wordIndex_, _value);
        }
        uint256 _size = _set.length();
        if (_size > MAX_ALLOWED_VALUES) revert TooManyValues(_size);
    }

    /// @notice Narrow: remove members from a `OneOf` set (a value that is not a member is skipped
    ///         silently: a mistyped narrowing never reverts, `lockdown` is the incident primitive).
    function removeAllowedValues(
        address safe_,
        address target_,
        bytes4 selector_,
        uint16 wordIndex_,
        bytes32[] calldata values_
    ) external {
        _checkNarrower(safe_);
        EnumerableSet.Bytes32Set storage _set = _valueSet(_policies[safe_], target_, selector_, wordIndex_);
        uint256 _len = values_.length;
        for (uint256 i; i < _len; ++i) {
            bytes32 _value = values_[i];
            if (_set.remove(_value)) emit AllowedValueRemoved(safe_, target_, selector_, wordIndex_, _value);
        }
    }

    /// @notice Narrow: empty a `OneOf` set.
    function clearAllowedValues(address safe_, address target_, bytes4 selector_, uint16 wordIndex_) external {
        _checkNarrower(safe_);
        _clearAllowedValues(safe_, target_, selector_, wordIndex_);
    }

    /*//////////////////////////////////////////////////////////////
                     ADMIN: DELEGATECALL & MODULE SCOPE
    //////////////////////////////////////////////////////////////*/

    /// @notice Permit (admin) or forbid (any narrower) `delegatecall` into `multiSend_`, whose
    ///         `multiSend(bytes)` payload is unwrapped and every entry checked as a plain call. Only a
    ///         canonical `MultiSendCallOnly` deployment can be registered (runtime hash check here and
    ///         on every use); delegatecall entries inside the batch are rejected regardless.
    function setMultiSendUnwrapper(address safe_, address multiSend_, bool allowed_) external {
        SafePolicy storage $ = _checkSetter(safe_, multiSend_, allowed_);
        bool _changed;
        if (allowed_) {
            // An account without code hashes to `0` or `keccak256("")`, neither of which is seeded.
            bytes32 _codehash = multiSend_.codehash;
            if (!_unwrapperCodehashes[_codehash]) revert UnwrapperCodehashNotAllowed(_codehash);
            _changed = $.multiSendUnwrappers.add(multiSend_);
        } else {
            _changed = $.multiSendUnwrappers.remove(multiSend_);
        }
        if (_changed) emit MultiSendUnwrapperUpdated(safe_, multiSend_, allowed_);
    }

    /// @notice Forbid (admin, council or a deployment-wide guardian) or re-allow (admin or council) a
    ///         runtime code hash for unwrappers, deployment-wide. Only the canonical `MultiSendCallOnly`
    ///         hashes seeded at deployment can ever be allowed (`UnwrapperCodehashNotAllowed`
    ///         otherwise): a new Safe release means a new guard, never a widening of this set, which is
    ///         why re-allowing a seeded hash is a fast-lane action (a leaked responder key must not cost
    ///         batching on every Safe for a timelock delay). Checked again on every delegatecall, so
    ///         forbidding a hash disables already-registered unwrappers that carry it, on every Safe:
    ///         per-Safe guardians cannot. A hash outside the seeded set is refused in both directions:
    ///         forbidding a mistyped one would emit a `UnwrapperCodehashUpdated` for a hash that was
    ///         never allowed, and a responder would believe batching is off.
    function setUnwrapperCodehash(bytes32 codehash_, bool allowed_) external {
        if (allowed_) _checkAdminOrCouncil();
        else _checkGlobalNarrower();
        if (!_canonicalCodehashes[codehash_]) revert UnwrapperCodehashNotAllowed(codehash_);
        _unwrapperCodehashes[codehash_] = allowed_;
        emit UnwrapperCodehashUpdated(codehash_, allowed_);
    }

    /// @notice Permit (admin) or forbid (any narrower) Safe module `module_` to execute through the
    ///         Safe. Only enforced on Safe v1.5.0+ with this guard installed via `setModuleGuard`;
    ///         v1.3.0 / v1.4.1 have no module hook, so keep those Safes module-free (the guard blocks
    ///         `enableModule` self-calls and the configuration check catches other paths) and verify
    ///         `getModulesPaginated` is empty before install.
    function setModuleAllowed(address safe_, address module_, bool allowed_) external {
        SafePolicy storage $ = _checkSetter(safe_, module_, allowed_);
        if (allowed_ ? $.modules.add(module_) : $.modules.remove(module_)) emit ModuleUpdated(safe_, module_, allowed_);
    }

    /*//////////////////////////////////////////////////////////////
                  ADMIN / COUNCIL: ONE-SHOT TRANSACTION APPROVALS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pre-approve ONE execution of the exact `(to_, value_, data_, operation_)` by `safe_`
    ///         through `executor_` (`address(0)` = the owner-signed `execTransaction` path, otherwise
    ///         the Safe module that must drive it), bypassing the policy (and `Lockdown`). Consumed on
    ///         first successful use (a failed execution reverts and keeps it), valid for `ttl_` seconds
    ///         from now: at least `MIN_APPROVAL_TTL`, admin ≤ `MAX_ADMIN_APPROVAL_TTL`, council ≤
    ///         `MAX_COUNCIL_APPROVAL_TTL`. Outside a `Bypass` window this is the only path for Safe
    ///         self-calls (`setGuard`, `swapOwner`, `enableModule`, `setFallbackHandler`, …) and for
    ///         arbitrary delegatecalls. The council may approve neither delegatecalls nor any self-call
    ///         outside its allowlist (owner management with a threshold of at least 2, `disableModule`,
    ///         `setFallbackHandler(0)`, the empty rejection call), nor a call to the policy's required
    ///         fallback handler, and a module-bound council approval must name an allowlisted module
    ///         when issued; at execution EVERY module-bound approval needs the module still allowlisted
    ///         (a guardian removing a module voids its approvals' effect). The gas-refund check is NOT
    ///         bypassed. A failed approved execution reverts the whole Safe transaction and keeps the
    ///         approval, on both paths. An approved delegatecall into a canonical `MultiSendCallOnly` is
    ///         decoded at use (canonical encoding, plain-call entries, none addressed to this guard).
    ///         Re-approving the same payload overwrites the expiry (still one execution). Refused
    ///         while the Safe is in `Bypass`. `to_` must carry code when calldata is sent or on a
    ///         delegatecall (an EIP-7702 delegated account never for a delegatecall), and a
    ///         delegatecall approval is bound to the code at `to_` when it was issued.
    /// @dev    Approved payloads should not nest another `execTransaction` of the same Safe: the
    ///         in-flight marker is a single slot per Safe and path, not a stack (always fails closed).
    function approveTransaction(
        address safe_,
        address executor_,
        address to_,
        uint256 value_,
        bytes calldata data_,
        Operation operation_,
        uint64 ttl_
    ) external returns (bytes32 _approvalId) {
        _nonZero(safe_);
        bool _admin = _checkAdminOrCouncilFor(safe_);
        _checkApprovalTarget(to_, data_.length, operation_);
        // `executor_` names a module: never the Safe itself nor this guard (neither can be allowlisted,
        // so such an approval could never be consumed).
        if (executor_ != address(0)) _checkTarget(safe_, executor_);
        SafePolicy storage $ = _policies[safe_];
        if (_effectiveMode($) == Mode.Bypass) revert SafeInBypass(safe_);
        uint64 _cap = _admin ? MAX_ADMIN_APPROVAL_TTL : MAX_COUNCIL_APPROVAL_TTL;
        if (ttl_ < MIN_APPROVAL_TTL || ttl_ > _cap) revert InvalidDuration(ttl_);
        if (!_admin) {
            _checkCouncilApproval(safe_, to_, data_, operation_);
            // The fast lane never re-arms a module a guardian removed: like a council window, a council
            // approval only reaches a module that is still on the allowlist.
            if (executor_ != address(0)) _checkModuleAllowed($, executor_);
        }
        uint64 _expiry;
        unchecked {
            _expiry = uint64(block.timestamp) + ttl_; // ttl_ <= 180 days: no uint64 overflow
        }
        uint32 _epoch = _approvalEpochs[safe_];
        _approvalId = computeApprovalId(safe_, executor_, to_, value_, data_, operation_);
        _storeApproval(_approvalId, safe_, _expiry, _epoch);
        emit TransactionApproved(safe_, _approvalId, executor_, to_, value_, data_, operation_, _expiry, _epoch);
    }

    /// @notice Narrow: cancel an unconsumed approval (admin, council or a guardian of its Safe).
    function revokeApproval(bytes32 approvalId_) external {
        Approval storage _approval = _approvals[approvalId_];
        if (_approval.expiry == 0) revert ApprovalNotFound(approvalId_);
        address _safe = _approval.safe;
        _checkNarrower(_safe);
        delete _approvals[approvalId_];
        emit ApprovalRevoked(_safe, approvalId_);
    }

    /// @notice Narrow: void every outstanding approval of `safe_` at once (incident response; see
    ///         also `lockdownAndRevoke`).
    function revokeAllApprovals(address safe_) external {
        _nonZero(safe_);
        _checkNarrower(safe_);
        _bumpEpoch(safe_);
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    function allowedValues(
        address safe_,
        address target_,
        bytes4 selector_,
        uint16 wordIndex_
    ) external view returns (bytes32[] memory) {
        return _valueSet(_policies[safe_], target_, selector_, wordIndex_).values();
    }

    function approvalEpoch(address safe_) external view returns (uint32) {
        return _approvalEpochs[safe_];
    }

    /// @notice Expiry of a live approval, `0` if none or if the Safe's approval epoch moved on
    ///         (`revokeAllApprovals`, `bypass`) since it was issued. Compare against `block.timestamp`.
    function approvalExpiry(bytes32 approvalId_) external view returns (uint64) {
        Approval storage _approval = _approvals[approvalId_];
        if (_approval.expiry == 0 || _approval.epoch != _approvalEpochs[_approval.safe]) return 0;
        return _approval.expiry;
    }

    /// @notice End of the last `Bypass` window opened for `safe_` and whether the council opened it.
    ///         `until` stays readable after the window expired (the Safe then reads as `Lockdown` in
    ///         `mode()`), so forensics can see when a window ended; `0` once `enforce` / `lockdown` ran.
    function bypassWindow(address safe_) external view returns (uint64 _until, bool _council) {
        // `_setMode` zeroes both whenever the mode is not `Bypass`.
        SafePolicy storage $ = _policies[safe_];
        return ($.bypassUntil, $.councilBypass);
    }

    /// @notice When `safe_` was last put in `Lockdown` (by anyone); the admin's `enforce` / `bypass` /
    ///         `approveTransaction` for it revert until `LOCKDOWN_COOLDOWN` has passed since then.
    function lockedAt(address safe_) external view returns (uint64) {
        return _policies[safe_].lockedAt;
    }

    function isUnwrapperCodehash(bytes32 codehash_) external view returns (bool) {
        return _unwrapperCodehashes[codehash_];
    }

    /// @notice Approval id for the Safe's CURRENT approval epoch and, for a delegatecall, the CURRENT
    ///         code at `to_`.
    function computeApprovalId(
        address safe_,
        address executor_,
        address to_,
        uint256 value_,
        bytes calldata data_,
        Operation operation_
    ) public view returns (bytes32) {
        // Code that runs in the Safe's context is pinned: an approved delegatecall is void once the
        // code at `to_` differs from what was there when the approval was issued (zero for a call).
        bytes32 _pin;
        assembly ("memory-safe") {
            _pin := mul(operation_, extcodehash(to_))
        }
        return
            keccak256(
                abi.encode(
                    safe_,
                    uint256(_approvalEpochs[safe_]),
                    executor_,
                    to_,
                    value_,
                    keccak256(data_),
                    operation_,
                    _pin
                )
            );
    }

    function functionPermission(
        address safe_,
        address target_,
        bytes4 selector_
    ) external view returns (bool _allowed, bool _allowValue, ParamRule[] memory _rules) {
        FunctionPermission storage _f = _policies[safe_].functions[target_][selector_];
        return (_f.allowed, _f.allowValue, _f.rules);
    }

    /// @notice Per-Safe guardians of `safe_` (deployment-wide guardians hold `GUARDIAN_ROLE` instead).
    function guardians(address safe_) external view returns (address[] memory) {
        return _policies[safe_].guardians.values();
    }

    /// @notice True when `account_` may narrow `safe_`'s policy as a guardian (per-Safe or deployment-wide).
    function isGuardian(address safe_, address account_) external view returns (bool) {
        return hasRole(GUARDIAN_ROLE, account_) || _policies[safe_].guardians.contains(account_);
    }

    function isNativeTransferAllowed(address safe_, address target_) external view returns (bool) {
        return _policies[safe_].nativeTransferAllowed[target_];
    }

    /// @notice EFFECTIVE mode of `safe_`: an expired `Bypass` window reads as `Lockdown`.
    function mode(address safe_) external view returns (Mode) {
        return _effectiveMode(_policies[safe_]);
    }

    function modules(address safe_) external view returns (address[] memory) {
        return _policies[safe_].modules.values();
    }

    function multiSendUnwrappers(address safe_) external view returns (address[] memory) {
        return _policies[safe_].multiSendUnwrappers.values();
    }

    /// @notice Same order as the setter: `(handler, enforce)`.
    function requiredFallbackHandler(address safe_) external view returns (address _handler, bool _enforce) {
        SafePolicy storage $ = _policies[safe_];
        return ($.requiredFallbackHandler, $.enforceFallbackHandler);
    }

    /// @notice Allowed selectors of `target_` for `safe_`, as left-aligned `bytes32` words (the first
    ///         four bytes are the selector; stored that way, returned without conversion to save code).
    function selectors(address safe_, address target_) external view returns (bytes32[] memory) {
        return _policies[safe_].selectors[target_].values();
    }

    /// @notice Targets with at least one allowed selector or a native-transfer permission.
    function targets(address safe_) external view returns (address[] memory) {
        return _policies[safe_].targets.values();
    }

    /*//////////////////////////////////////////////////////////////
                            INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _allowFunction(
        address safe_,
        address target_,
        bytes4 selector_,
        bool allowValue_,
        ParamRule[] calldata rules_
    ) internal {
        _nonZero(safe_);
        _checkTarget(safe_, target_);
        uint256 _count = rules_.length;
        if (_count > MAX_RULES) revert TooManyRules(_count);
        _validateRules(rules_);

        SafePolicy storage $ = _policies[safe_];
        FunctionPermission storage _f = $.functions[target_][selector_];
        // Drop the value sets of `OneOf` rules that the new rule list no longer carries, so a set
        // can never outlive its rule and silently re-activate later.
        uint256 _old = _f.rules.length;
        for (uint256 i; i < _old; ++i) {
            ParamRule storage _r = _f.rules[i];
            if (_r.kind == RuleKind.OneOf && !_hasOneOfRuleIn(rules_, _r.wordIndex)) {
                _clearAllowedValues(safe_, target_, selector_, _r.wordIndex);
            }
        }
        delete _f.rules;
        for (uint256 i; i < _count; ++i) _f.rules.push(rules_[i]);
        _f.allowed = true;
        _f.allowValue = allowValue_;
        EnumerableSet.Bytes32Set storage _selectors = $.selectors[target_];
        _selectors.add(bytes32(selector_));
        if (_selectors.length() > MAX_SELECTORS) revert TooManyValues(MAX_SELECTORS);
        $.targets.add(target_);
        emit FunctionAllowed(safe_, target_, selector_, allowValue_, rules_);
    }

    /// @dev Input rails of every role grant (the library's `grantRole`, `setDeploymentGuardian`, the
    ///      constructor, the admin transfer): never `address(0)` (an `eth_call` without a sender would
    ///      otherwise act as the role), never the admin (exempt from the guard, so it must not also be
    ///      the council), never an account the admin gave an allowlist to (a guarded Safe cannot reach
    ///      the guard, so a role on it is dead: for the council that is a dead fast lane discovered in
    ///      an incident). Only admin-written state is read: a rogue council cannot make the grant of
    ///      its successor revert.
    function _grantRole(bytes32 role_, address account_) internal virtual override returns (bool) {
        _nonZero(account_);
        _requireUnguarded(account_, false);
        return super._grantRole(role_, account_);
    }

    /// @dev Transferring the admin to `address(0)` would leave the guard without any widening or
    ///      removal path forever; refuse it. This also closes the library's renounce path, which needs
    ///      a pending transfer to `address(0)`.
    function _beginDefaultAdminTransfer(address newAdmin_) internal virtual override {
        if (newAdmin_ == address(0)) revert AdminCannotBeZero();
        _requireUnguarded(newAdmin_, true);
        super._beginDefaultAdminTransfer(newAdmin_);
    }

    /// @dev Re-checked at acceptance: the pending admin could have been configured during the delay.
    ///      A pending admin also expires: `executeBefore` bounds when the transfer may BEGIN, this
    ///      bounds when it may be accepted (`MAX_ADMIN_DELAY` after the schedule; a successor timelock
    ///      at the slowest delay still makes it), so an abandoned hand-over cannot be accepted years
    ///      later by keys nobody watches any more. The admin re-arms it by beginning again.
    function _acceptDefaultAdminTransfer() internal virtual override {
        _requireUnguarded(msg.sender, true);
        (, uint48 _schedule) = pendingDefaultAdmin();
        unchecked {
            // uint48 + 30 days: cannot overflow in uint256.
            if (block.timestamp > uint256(_schedule) + MAX_ADMIN_DELAY) revert DeadlinePassed(_schedule);
        }
        super._acceptDefaultAdminTransfer();
    }

    /// @dev The admin is never constrained by the guard: handing the role to a Safe that has a policy
    ///      (a paste error away), or to the council, would make that account exempt from everything,
    ///      including `setGuard(0)`. The EFFECTIVE mode is read: a window that expired is forensics,
    ///      not a configuration (a live one still refuses, until `lockdown(account)` clears it).
    ///      `transfer_`: the admin transfer also refuses the council, a live mode and per-Safe
    ///      guardians (state the council can write); a role grant reads admin-written state only.
    function _requireUnguarded(address account_, bool transfer_) internal view {
        SafePolicy storage $ = _policies[account_];
        if (
            (transfer_ && (_isCouncil(account_) || _effectiveMode($) != Mode.Lockdown || $.guardians.length() != 0)) ||
            _isAdmin(account_) ||
            $.enforceFallbackHandler ||
            $.targets.length() != 0 ||
            $.modules.length() != 0 ||
            $.multiSendUnwrappers.length() != 0
        ) revert AdminIsGuarded(account_);
    }

    /// @dev Bounds the admin-transfer delay both ways: `changeDefaultAdminDelay(86_400_000)`
    ///      (milliseconds by mistake) would otherwise take effect after 5 days and need ~1,000 days to
    ///      undo, and `(3)` (seconds for days) would leave the cancel-in-time property of the hand-over
    ///      with no window at all.
    function _changeDefaultAdminDelay(uint48 newDelay_) internal virtual override {
        if (newDelay_ > MAX_ADMIN_DELAY || newDelay_ < MIN_ADMIN_DELAY) revert AdminDelayTooLong(newDelay_);
        super._changeDefaultAdminDelay(newDelay_);
    }

    /// @dev Member-wise so the legacy codegen writes the packed record with one `sstore` and no
    ///      memory copy (three masked writes otherwise).
    function _storeApproval(bytes32 id_, address safe_, uint64 expiry_, uint32 epoch_) internal {
        Approval storage _a = _approvals[id_];
        _a.safe = safe_;
        _a.expiry = expiry_;
        _a.epoch = epoch_;
    }

    function _bumpEpoch(address safe_) internal {
        uint32 _epoch = ++_approvalEpochs[safe_];
        emit ApprovalsRevoked(safe_, _epoch);
    }

    /// @dev keccak256("fallback_manager.handler.address"), Safe `FallbackManager`.
    bytes32 internal constant FALLBACK_HANDLER_STORAGE_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    /// @dev `FallbackManager` forwards every selector a Safe does not implement to its fallback handler,
    ///      for ANY caller, with the Safe as `msg.sender` (and the caller's 20 bytes appended, a length
    ///      the caller chooses). A Safe with this guard in that slot would hand everything keyed on its
    ///      address to everyone: its hooks if it is guarded, its ROLE if it holds one (the council Safe,
    ///      a guardian Safe). True when `account_` answers `getStorageAt` like a Safe (v1.3.0+) and its
    ///      handler slot holds this guard; an EOA or a contract that is not a Safe (the timelock) is not.
    function _isHandlerOf(address account_) internal view returns (bool _yes) {
        bytes32 _slot = FALLBACK_HANDLER_STORAGE_SLOT;
        assembly ("memory-safe") {
            // getStorageAt(uint256 offset, uint256 length) with (handler slot, 1), built and answered in
            // scratch memory past the free pointer: a `bytes` of one word (offset, length, value).
            let _p := mload(0x40)
            mstore(_p, 0x5624b25b00000000000000000000000000000000000000000000000000000000)
            mstore(add(_p, 0x04), _slot)
            mstore(add(_p, 0x24), 1)
            let _ok := staticcall(gas(), account_, _p, 0x44, _p, 0x60)
            _yes := and(and(_ok, eq(returndatasize(), 0x60)), eq(mload(add(_p, 0x40)), address()))
        }
    }

    /// @dev No role for a caller that may be a forwarded stranger (`_isHandlerOf`).
    function _refuseForwarded() internal view {
        if (_isHandlerOf(msg.sender)) revert Unauthorized();
    }

    /// @dev The library's own role surface gets the same refusal: `onlyRole` (grants, revocations, the
    ///      admin transfer, for an admin that is a Safe) and `renounceRole` (a forwarded stranger must not
    ///      be able to make a Safe drop its role).
    function _checkRole(bytes32 role_, address account_) internal view virtual override {
        _refuseForwarded();
        super._checkRole(role_, account_);
    }

    function renounceRole(bytes32 role_, address account_) public virtual override {
        _refuseForwarded();
        super.renounceRole(role_, account_);
    }

    function _checkAdmin() internal view {
        _refuseForwarded();
        if (!_isAdmin(msg.sender)) revert Unauthorized();
    }

    /// @dev Admin or council; tells the caller which one (the admin gets the longer caps).
    function _checkAdminOrCouncil() internal view returns (bool _admin) {
        _refuseForwarded();
        _admin = _isAdmin(msg.sender);
        if (!_admin && !_isCouncil(msg.sender)) revert Unauthorized();
    }

    /// @dev Admin or council acting on `safe_`, never a Safe on itself: a guarded Safe that was given the
    ///      council role by mistake must not be able to approve, unlock or open a window for itself.
    function _checkAdminOrCouncilFor(address safe_) internal view returns (bool _admin) {
        if (msg.sender == safe_) revert Unauthorized();
        _admin = _checkAdminOrCouncil();
        unchecked {
            // uint64 timestamp + 1 day: cannot overflow in uint256.
            if (_admin && block.timestamp <= uint256(_policies[safe_].lockedAt) + LOCKDOWN_COOLDOWN)
                revert LockdownCooldown(safe_);
        }
    }

    /// @dev Shared by the module path of the hooks and by council approvals.
    function _checkModuleAllowed(SafePolicy storage $, address module_) internal view {
        if (!$.modules.contains(module_)) revert ModuleNotAllowed(module_);
    }

    /// @dev What an approval may address, checked when it is issued. Never this guard. Calldata sent to
    ///      an account without code "succeeds" and does nothing (so does a delegatecall): the one-off
    ///      would be spent, and reported as executed, for nothing. And an approved delegatecall runs
    ///      code in the Safe's context, so that code must be a deployed contract: an EIP-7702 delegated
    ///      EOA (its code starts with `0xef`, which EIP-3541 reserves) can be re-pointed by its key at
    ///      any time, before or after the approval is issued.
    function _checkApprovalTarget(address to_, uint256 dataLength_, Operation operation_) internal view {
        bool _bad;
        assembly ("memory-safe") {
            extcodecopy(to_, 0, 0, 1) // first code byte into scratch space (zero when there is none)
            // no code, with calldata or as a delegatecall; or a delegatecall into 0xef… (EIP-7702)
            _bad := or(
                and(iszero(extcodesize(to_)), or(operation_, iszero(iszero(dataLength_)))),
                and(operation_, eq(byte(0, mload(0)), 0xef))
            )
        }
        if (_bad || to_ == address(this)) revert InvalidTarget(to_);
    }

    /// @dev Council approvals: plain calls only, self-calls only from the council's allowlist.
    function _checkCouncilApproval(
        address safe_,
        address to_,
        bytes calldata data_,
        Operation operation_
    ) internal view {
        if (operation_ != Operation.Call || !_councilMaySelfCall(safe_, to_, data_)) {
            revert CouncilCannotApprove(_selectorOf(data_), operation_);
        }
    }

    /// @dev Calls the council may authorise for `safe_`, by approval or inside its window. The policy's
    ///      required fallback handler counts as part of the Safe (a handler answers Safe calls with the
    ///      Safe as caller, so reaching it directly equals reaching it through the Safe): unreachable
    ///      whatever the selector. Self-calls only from the allowlist (`SAFE_*`): the empty zero-data
    ///      rejection call; `setFallbackHandler` only in its canonical 36-byte zero-argument form (the fix
    ///      for a guard installed before the handler was removed); `swapOwner` and `disableModule`; and
    ///      the owner-management calls that set a threshold (`addOwnerWithThreshold` word 1, `removeOwner`
    ///      word 2, `changeThreshold` word 0) only with a threshold of at least `MIN_COUNCIL_THRESHOLD`;
    ///      a new owner (`addOwnerWithThreshold` word 0, `swapOwner` word 2) only if it has no code.
    ///      Anything shorter than the arguments inspected, or than a selector, is refused
    ///      (`disableModule` is accepted by its selector alone; the Safe rejects a short payload).
    function _councilMaySelfCall(address safe_, address to_, bytes calldata data_) internal view returns (bool) {
        if (to_ != safe_) {
            address _handler = _policies[safe_].requiredFallbackHandler;
            return _handler == address(0) || to_ != _handler;
        }
        if (data_.length == 0) return true;
        if (data_.length < 4) return false;
        bytes4 _selector = bytes4(data_[:4]);
        if (_selector == SAFE_SET_FALLBACK_HANDLER) return data_.length == 36 && bytes32(data_[4:36]) == bytes32(0);
        if (_selector == SAFE_DISABLE_MODULE) return true;
        // A new owner the council brings in must be a plain key: an account with code (this guard, the
        // handler, a Safe, a smart account, an EIP-7702 delegated EOA) can be a seat that never signs or
        // one that accepts any signature, and either defeats the threshold. Such owners are admin-only.
        if (_selector == SAFE_SWAP_OWNER) return data_.length >= 100 && _hasNoCode(data_[68:100]);
        // Byte offset of the threshold argument, 0 for a selector outside the allowlist.
        uint256 _start = _selector == SAFE_CHANGE_THRESHOLD ? 4 : _selector == SAFE_ADD_OWNER_WITH_THRESHOLD
            ? 36
            : _selector == SAFE_REMOVE_OWNER
                ? 68
                : 0;
        unchecked {
            // _start is 4, 36 or 68
            return
                _start != 0 &&
                data_.length >= _start + 32 &&
                uint256(bytes32(data_[_start:_start + 32])) >= MIN_COUNCIL_THRESHOLD &&
                (_start != 36 || _hasNoCode(data_[4:36]));
        }
    }

    /// @dev A precompile has no code, so the no-code rule of `_councilMaySelfCall` would take it for a
    ///      plain key: the identity precompile (0x04) echoes an EIP-1271 query back as the magic value on
    ///      a Safe build without the pre-call code check, so the low address range is refused as well. A
    ///      keyless address stays a dead seat the rule cannot tell apart.
    function _hasNoCode(bytes calldata word_) private view returns (bool) {
        address _account = address(uint160(uint256(bytes32(word_))));
        return uint160(_account) > 0xffff && _account.code.length == 0;
    }

    function _selectorOf(bytes calldata data_) internal pure returns (bytes4) {
        return data_.length >= 4 ? bytes4(data_[:4]) : bytes4(0);
    }

    /// @dev Deployment-wide narrowing: admin, council or a deployment-wide guardian.
    function _checkGlobalNarrower() internal view {
        if (!_isGlobalNarrower()) revert Unauthorized();
    }

    /// @dev Narrowing of `safe_`'s policy: admin, council, a deployment-wide guardian or a guardian of
    ///      that Safe.
    function _checkNarrower(address safe_) internal view {
        if (!_isGlobalNarrower() && !_policies[safe_].guardians.contains(msg.sender)) revert Unauthorized();
    }

    function _isGlobalNarrower() internal view returns (bool) {
        _refuseForwarded();
        return _isAdmin(msg.sender) || _isCouncil(msg.sender) || hasRole(GUARDIAN_ROLE, msg.sender);
    }

    /// @dev A policy target may be neither the zero address, nor the Safe itself (self-calls are
    ///      only ever authorised through approvals), nor this guard (its hooks must never be
    ///      reachable as policy-allowed calls: that would let the Safe consume its own approvals).
    function _checkTarget(address safe_, address target_) internal view {
        if (target_ == address(0) || target_ == safe_ || target_ == address(this)) revert InvalidTarget(target_);
    }

    /// @dev Shared by the `(safe, target, allowed)` setters: the admin widens, any narrower narrows.
    function _checkSetter(address safe_, address target_, bool allowed_) internal view returns (SafePolicy storage) {
        if (allowed_) _checkAdmin();
        else _checkNarrower(safe_);
        _nonZero(safe_);
        _checkTarget(safe_, target_);
        return _policies[safe_];
    }

    function _clearAllowedValues(address safe_, address target_, bytes4 selector_, uint16 wordIndex_) internal {
        EnumerableSet.Bytes32Set storage _set = _valueSet(_policies[safe_], target_, selector_, wordIndex_);
        for (uint256 _n = _set.length(); _n > 0; --_n) {
            bytes32 _value = _set.at(_n - 1);
            _set.remove(_value);
            emit AllowedValueRemoved(safe_, target_, selector_, wordIndex_, _value);
        }
    }

    /// @dev `Bypass` is time-boxed: once the window has passed the Safe is back to fail-closed.
    function _effectiveMode(SafePolicy storage $) internal view returns (Mode) {
        Mode _mode = $.mode;
        if (_mode == Mode.Bypass && block.timestamp >= $.bypassUntil) return Mode.Lockdown;
        return _mode;
    }

    /// @dev `rules` is non-empty only while the function is allowed (`_revokeFunction` deletes the record).
    function _hasOneOfRule(FunctionPermission storage f_, uint16 wordIndex_) internal view returns (bool) {
        uint256 _len = f_.rules.length;
        for (uint256 i; i < _len; ++i) {
            ParamRule storage _r = f_.rules[i];
            if (_r.kind == RuleKind.OneOf && _r.wordIndex == wordIndex_) return true;
        }
        return false;
    }

    function _hasOneOfRuleIn(ParamRule[] calldata rules_, uint16 wordIndex_) internal pure returns (bool) {
        uint256 _len = rules_.length;
        for (uint256 i; i < _len; ++i) {
            ParamRule calldata _r = rules_[i];
            if (_r.kind == RuleKind.OneOf && _r.wordIndex == wordIndex_) return true;
        }
        return false;
    }

    function _isAdmin(address account_) internal view returns (bool) {
        return hasRole(DEFAULT_ADMIN_ROLE, account_);
    }

    function _isCouncil(address account_) internal view returns (bool) {
        return hasRole(COUNCIL_ROLE, account_);
    }

    function _nonZero(address account_) internal pure {
        if (account_ == address(0)) revert AddressIsNull();
    }

    function _pruneTarget(SafePolicy storage $, address target_) internal {
        if ($.selectors[target_].length() == 0 && !$.nativeTransferAllowed[target_]) $.targets.remove(target_);
    }

    function _revokeFunction(address safe_, address target_, bytes4 selector_) internal {
        SafePolicy storage $ = _policies[safe_];
        FunctionPermission storage _f = $.functions[target_][selector_];
        if (!_f.allowed) return;
        // The `OneOf` sets are keyed by the generation: the bump abandons them without iterating.
        uint32 _generation = _f.generation + 1;
        delete $.functions[target_][selector_];
        _f.generation = _generation;
        $.selectors[target_].remove(bytes32(selector_));
        _pruneTarget($, target_);
        emit FunctionRevoked(safe_, target_, selector_);
    }

    function _setMode(address safe_, Mode mode_, uint64 bypassUntil_, bool councilBypass_) internal {
        SafePolicy storage $ = _policies[safe_];
        $.mode = mode_;
        $.bypassUntil = bypassUntil_;
        $.councilBypass = councilBypass_;
        if (mode_ == Mode.Lockdown) $.lockedAt = uint64(block.timestamp);
        emit ModeUpdated(safe_, mode_, bypassUntil_, councilBypass_);
    }

    /// @dev `EqualToSafe` / `OneOf` carry no value; a lower bound must be paired with an upper bound
    ///      (`LessThanOrEqual` / `EqualTo` / `OneOf`) on the same word, otherwise it is fail-open, and
    ///      a `LessThanOrEqual` partner must be a real ceiling: not below the floor (a dead function),
    ///      not `2^256 - 1` (as fail-open as the lone floor).
    function _validateRules(ParamRule[] calldata rules_) internal pure {
        uint256 _count = rules_.length;
        for (uint256 i; i < _count; ++i) {
            ParamRule calldata _r = rules_[i];
            RuleKind _kind = _r.kind;
            if ((_kind == RuleKind.EqualToSafe || _kind == RuleKind.OneOf) && _r.value != 0) revert InvalidRule(i);
            if (_kind == RuleKind.GreaterThanOrEqual) {
                bool _bounded;
                for (uint256 j; j < _count; ++j) {
                    ParamRule calldata _u = rules_[j];
                    if (_u.wordIndex != _r.wordIndex) continue;
                    RuleKind _k = _u.kind;
                    if (_k == RuleKind.LessThanOrEqual) {
                        if (uint256(_u.value) < uint256(_r.value) || ~uint256(_u.value) == 0) revert InvalidRule(i);
                        _bounded = true;
                    } else if (_k == RuleKind.EqualTo || _k == RuleKind.OneOf) {
                        _bounded = true;
                    }
                }
                if (!_bounded) revert UnboundedLowerBound(i);
            }
        }
    }

    /// @dev The `OneOf` set of `(target_, selector_, wordIndex_)` in the function's current generation.
    function _valueSet(
        SafePolicy storage $,
        address target_,
        bytes4 selector_,
        uint16 wordIndex_
    ) internal view returns (EnumerableSet.Bytes32Set storage) {
        return
            $.allowedValues[
                keccak256(abi.encode(target_, selector_, wordIndex_, $.functions[target_][selector_].generation))
            ];
    }
}
