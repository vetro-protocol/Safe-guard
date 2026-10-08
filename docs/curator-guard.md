# CuratorGuard: scoping a Lagoon curator's Safe to a Vetro-managed allowlist

`contracts/guards/CuratorGuard.sol` is a Safe transaction guard (Safe v1.3.0+) and module guard
(Safe v1.5.0+) that restricts what a curator-operated Safe can execute to a per-Safe,
admin-managed allowlist of `(contract, function)` pairs with optional static-parameter rules.
Vetro governance administers the guard through a timelock (widenings) and a fast council (incident
response); the curator keeps signing Safe transactions exactly as today, but anything outside the
policy reverts inside `execTransaction`.

This document is the design rationale, the threat model, the operating runbook and the concrete
policy for the Vetro Lagoon vaults. Read it before touching the guard or a policy file.

- Contracts: `contracts/guards/CuratorGuardPolicy.sol` (storage, admin, views),
  `contracts/guards/CuratorGuard.sol` (Safe hooks, validation), `contracts/interfaces/safe/`.
- Tests: `test/guards/` (real Safe v1.4.1 and v1.5.0 bytecode compiled from
  `lib/safe-smart-account*`), plus the mainnet fork test against the live Vetro Safe.
- Tooling: `deploy/ethereum/guards/00_curator_guard.ts`, `tasks/curator-guard.ts`
  (`curator-guard-sync`), `policies/curator-guard/*.json`.

## 1. Ground truth (Ethereum mainnet, read on 2026-10-04)

| Fact | Value |
|---|---|
| Lagoon vaults (`helpers/address.ts` `Lagoon.vault.Vetro_*`) | USDC `0x131C…6679`, USDT `0xE7Fa…eDba`, WBTC `0x1a9b…0e90`, cbBTC `0x110B…6340`, hemiBTC `0x26A6…fdc3`, all `version() == "v0.6.0"` |
| Custody Safe (`vault.safe()`) of all five | `0x1b534a8543212F5957168D83311A41E0Ea1cfe48` |
| Safe version / owners / threshold | v1.4.1, 4 owners, threshold 2 |
| Safe modules / guard / module guard | none / none / none |
| Safe fallback handler | canonical `CompatibilityFallbackHandler` v1.4.1 (`0xfd07…Ec99`), i.e. EIP-1271 capable (see §6) |
| Vetro governance (`governor()` of every Vetro yield vault and of the `Lagoon_Vetro_*` strategies, also their `feeCollector`) | `0x6649Ddb5c7e52348b73c8bBdD2A1cbA630b7AaEA`, Safe v1.4.1, 3-of-6: the proposed **proposer** of the guard's admin timelock (v1 called it the guard owner) |
| 1271-aware custody assets | USDC (`FiatTokenV2_2`: `permit` and EIP-3009 `transferWithAuthorization` validate contract signatures). cbBTC exposes `permit` / `transferWithAuthorization` but validates ECDSA only (a contract signer is rejected); USDT, WBTC and hemiBTC expose none of them (probed on-chain) |
| Governance Safe owners vs curator Safe owners | the governance Safe is 3-of-6 and **three of its six owners are also owners of the curator Safe** (`0x1F0D…8AC`, `0x9aCa…FFa`, `0xE173…5d3`): three colluding curator keys would meet the proposer quorum, which the v2 deploy script refuses (§6) |
| Lagoon NAV guardrails | `GuardrailsManager` storage is zero on all five vaults (`activated == false`): `updateNewTotalAssets` accepts **any** value today; the curator Safe is also `securityCouncil`, the only role that can activate / configure guardrails |
| Vault fee rates / lifespan / sync | `feeRates() == (0,0,0,0,0)`, `totalAssetsLifespan == 0` (sync deposits never open, NAV always re-proposable), `maxCap == uint256.max`, `allowHighWaterMarkReset == true` |
| Vault proxies | ERC-1967 `LagoonVaultProxy`; each vault's admin is its own `DelayProxyAdmin` (`owner() == the curator Safe`, `delay() == 1 day`, no pending upgrade), gated by Lagoon's `LogicRegistry` (`0x6dA4…27C`, owned by Lagoon `0x9A40…d4B`) |
| `LagoonV06` strategies | `maxLossBps == 0` on all five: a settlement freeze cannot be booked as a loss by the keeper, but neither can a 1-wei rounding deficit, so the keeper's `rebalance` reverts after any real settlement until the cap is raised or the strategy tolerates rounding (§6, §8) |
| Lagoon roles on each vault (`hopper.storage.Roles`) | `owner`, `safe`, `feeReceiver`, `valuationManager`, `securityCouncil` are ALL the Safe; `whitelistManager` and `superOperator` unset (and `superOperator` is **not** locked); `safeLocked = false` |
| Vault access mode | `accessMode == Blacklist` on all five (`isAllowed(0xdEaD) == true`): the vaults are **public**, anyone (the curator included) can deposit alongside the Vesper strategies. Custody held at the time of reading: ≈1 USDC + 2 USDT, nothing else; all five `Lagoon_Vetro_*` strategies have `totalDebtOf == 0` (§12) |
| Safe history (31 executed txs, 2026-05-24 → 2026-06-16) | `updateNewTotalAssets` + `settleDeposit` / `settleRedeem` on the five vaults, `approve(vault, max)` on each asset (spender = the matching vault), `addOwnerWithThreshold` ×3 and `changeThreshold` ×1, three batches via `MultiSendCallOnly` v1.4.1 (`0x9641…02e2`) |

Consequences:

1. The curator (the Safe's signers) currently needs exactly: NAV submission, settlement, asset
   approvals to the vault, and batching. No DeFi venue has been touched from this Safe yet, so the
   initial policy is small and fully verifiable.
2. Because the Safe is also every vault's `owner` and `securityCouncil`, the signers can today
   `updateSafe` (redirect custody), `pause`, `initiateClosing`, `activateAsyncOnly`,
   `transferOwnership`, change roles, and push a NAV that bypasses the guardrails
   (`securityCouncilUpdateTotalAssets`). All of that becomes deny-by-default under the guard.
3. On Safe v1.4.1 a transaction guard is **not** consulted for module transactions (that hook only
   exists in v1.5.0). The Safe has no modules, the guard blocks `enableModule`, and the
   post-execution configuration check reverts any transaction that links a module through another
   path, so the invariant "no modules" is preserved after install. It must be verified before install.
4. A transaction guard sees `execTransaction` only. With the current fallback handler, 2 of the 4
   signers can sign a Safe message off-chain and USDC will honour it as the Safe's EIP-1271
   signature in `permit` / `transferWithAuthorization`: a full USDC drain with zero Safe
   transactions. The guard therefore carries a per-Safe *required fallback handler* and refuses to
   run the policy until the signers execute the Vetro-approved `setFallbackHandler(0)` (§7.3).

## 2. Goal and non-goals

Goal: give Vetro a dynamically updatable, on-chain enforced allowlist of contracts and methods
that the Lagoon curator's Safe may call, so Vetro controls which strategies the vault's assets can
enter, without taking over day-to-day signing.

Non-goals (and why):

- Valuing positions or judging NAV honesty. Lagoon's guardrails + Vetro's `maxLossBps` /
  `reportLoss` in `LagoonBase` handle valuation risk; the guard only scopes execution.
- Replacing the curator's Safe with a Vetro-owned Safe plus a Zodiac Roles module. Possible, but
  it changes who signs; see §3.
- Expressing arbitrary parameter conditions (nested structs, dynamic arrays, cross-parameter
  logic). The rule model covers static head words only, which is what custody-relevant
  parameters (`spender`, `receiver`, `onBehalfOf`, `to`, amounts) are. Anything richer belongs in
  Zodiac Roles v2 or a purpose-built checker, not in this guard.

## 3. Options considered

| Option | Verdict | Why |
|---|---|---|
| **Safe transaction guard with admin-managed allowlist (chosen)** | ✅ | Works on the existing v1.4.1 Safe with the existing signers. Purely subtractive: the guard can block, never initiate, so Vetro gains censorship power but no custody power. Dynamic by construction (the admin writes storage). Cheap, small, auditable. |
| Zodiac Roles Modifier v2 (module) | ❌ for now | Battle-tested and richer (condition trees, allowances, unwrappers), but a module only constrains *module* callers. The curator would have to stop being a Safe owner and act through `execTransactionWithRole`, i.e. Vetro would own the Safe. That is a custody and operations change, not an overlay. Worth revisiting if Vetro ever wants parameter logic beyond static words. **Round 4 (§12) re-opened this verdict**: Roles 2.1.1 on a Vetro-owned Safe is Lagoon's documented curation stack and the better long-run structure whenever Vetro is willing to hold custody power; the guard remains the right primitive only while the curator must own the Safe. See §12.3. |
| Lagoon-level controls only (Vetro takes vault `owner`, locks `updateSafe`) | ❌ alone | Removes the curator's admin powers over the vault but does nothing about what the Safe does with the assets it holds. Complementary, recommended in §8. |
| Custom custody contract replacing the Safe (`updateSafe(newCustody)`) | ❌ | Re-implements a Safe + Roles with none of the tooling or audits; migrating assets out of the current Safe would be a signer-cooperative event anyway. |
| Off-chain monitoring + social recourse | ❌ alone | Detects after the fact; the whole point is prevention. Keep monitoring (guardian role) as a complement. |

Why not upgradeable: a guard with full power to block a Safe is a DoS vector; an upgradeable one
is also a hidden-logic vector toward the curator. The guard is immutable; replacing it is an
explicit, admin-approved `setGuard(newGuard)` the signers execute (§7.5).

## 4. Architecture

```
curator signers ──execTransaction──▶ Safe v1.4.1 ──checkTransaction──▶ CuratorGuard ──reads──▶ policy[safe]
                                        │                                   ▲
                                        └──────── checkAfterExecution ──────┘ (configuration unchanged?)
governance Safe ──schedule──▶ CuratorGuardTimelock (admin) ──allowFunction / approve / bypass──▶ CuratorGuard
council Safe   ──────────────── enforce / lockdown / short approvals / short bypass / setGuardian ──▶ CuratorGuard
guardians      ──────────────── lockdown(AndRevoke) / revoke / removeAllowedValues / revokeApproval ▶ CuratorGuard
```

Roles (OpenZeppelin `AccessControlDefaultAdminRules`; see also IMPROVEMENTS_V2.md item 1):

- **admin** (`DEFAULT_ADMIN_ROLE`, exactly one account, two-step transfer with a delay; in production
  the `CuratorGuardTimelock`, an OpenZeppelin `TimelockController` whose role set is fixed by its
  constructor: two proposer Safes (a deploy-script rule; `helpers/address.ts` still lists one) and
  exactly ONE dedicated veto Safe as canceller, which proposes nothing: the contract refuses a
  canceller that is also a proposer, at construction and on every later `grantRole`. A canceller can
  veto its own removal, so a canceller that could also propose would be an unvetoed takeover once
  compromised (strip the council, widen anything, approve `setGuard(0)`), a veto-only Safe at worst a
  deadlock, and a compromised proposer is cancellable and removable. The executor role is open, there
  is no deployer admin, the council and hot keys hold nothing (deploy-script rules; on-chain only the
  veto and the §7.7 alerts keep it so); the subclass also clamps `getMinDelay()` to [1 h, 30 d],
  refuses to drop the open executor or its own admin role, keeps the last proposer and the last
  canceller, never counts `address(0)` or the timelock itself as a holder of a gated role, never
  grants its admin role to anyone else, and refuses at `schedule` what would fail or misbehave late:
  an operation delay other than the live `getMinDelay()` (an operation id carries neither its proposer
  nor its delay: with a longer one a compromised proposer could take the honest proposer's exact
  operation up to 30 days out, so the honest `scheduleBatch` reverts and the honest wrapper is dead on
  arrival, review G10c-1), calldata for a target without code (which `execute` refuses again)
  and an `updateDelay` outside the clamp): the only role that can **widen** a policy (`allowFunction(s)`,
  `addAllowedValues`, `set…(true)`, re-allowing a seeded unwrapper hash, `setRequiredFallbackHandler`),
  issue approvals of up to 180 days, open a `Bypass` window of up to 180 days in which nothing is
  checked (except that the guard itself is never a call target), and administer roles. Every widening therefore sits in public for the timelock's `minDelay` (48 h by
  default) and can be cancelled by a canceller before it bites; the sync task wraps every scheduled call
  in `executeBefore(deadline, …)` so a batch nobody executed in time is dead rather than a latent,
  permissionless action. For one day after any lockdown of a Safe the admin's `enforce`, `bypass` and
  `approveTransaction` for that Safe revert `LockdownCooldown`: a queued operation was scheduled before
  the incident and anyone may execute it, even in the same transaction as something the signers
  already signed, so the day is the canceller's time to cancel it; the council, which acts live, is
  not held back, and nothing else is: widenings, role grants and guardian removals execute during the
  cooldown, and a council granted during it lifts at once (§6). Transferring the admin to `address(0)` is refused (`AdminCannotBeZero`), as
  is transferring it to an address that carries a policy, or to the council (`AdminIsGuarded`), and
  the admin-transfer delay is capped at 30 days in the constructor and in `changeDefaultAdminDelay`,
  which also has a floor of 1 day (`AdminDelayTooLong`; a delay typed in the wrong unit must leave
  time to cancel a hand-over): an adminless guard could never be reconfigured or
  removed from a Safe, and a guarded Safe that became admin would be exempt from everything. A
  pending admin expires: it must accept within 30 days of the transfer's schedule (`DeadlinePassed`;
  the admin re-arms it by beginning again), so an abandoned hand-over cannot be accepted years later.
  Every role grant (the library's `grantRole`, `setDeploymentGuardian`, the constructor) has the
  guard's input rails: never `address(0)` (`AddressIsNull`), never the admin, never an account the
  admin gave an allowlist to (`AdminIsGuarded`: a guarded Safe cannot reach the guard, so a role on it
  is dead); only admin-written state is read, so a rogue council cannot veto its successor. The admin
  TRANSFER reads more (the council role, a live window and the per-Safe guardians of the pending
  admin), so a council that does not cooperate can stall a hand-over for as long as it holds the role:
  evict it in one batch, `[revokeRole(COUNCIL_ROLE, old), setGuardian(newAdmin, key, false),
  lockdown(newAdmin)]`, then accept inside the 30 days, or begin again (review G9c-1). And no
  role is honoured for a caller that answers as a Safe with THIS guard in its fallback-handler slot
  (`Unauthorized`; the timelock has the same rail for its proposers and its veto, `ForwardedCall`):
  such a Safe forwards anyone's call here with itself as the caller, so its role would be public. The admin
  itself is **never constrained** by the guard: all hooks return early for `msg.sender ==
  defaultAdmin()`, so installing the guard on the admin by mistake cannot deadlock the system. `owner()`
  is kept as a view and returns the admin.
- **council** (`COUNCIL_ROLE`, a fast multisig with **no curator keys**): the time-critical lane.
  `enforce` (lift a lockdown, or leave a `Bypass`), `lockdown`, approvals of at most 7 days whose
  Safe self-calls are limited to an **allowlist** (`CouncilCannotApprove` otherwise): owner management
  (`addOwnerWithThreshold`, `removeOwner`, `swapOwner`, `changeThreshold`; never a threshold below 2,
  and never a new owner that has code: a contract, a Safe or an EIP-7702 delegated EOA can be a seat
  that never signs or one that accepts any signature, so such owners are admin-only), `disableModule`,
  `setFallbackHandler(address(0))` and the empty rejection call; no delegatecalls, and nothing else
  addressed to the Safe (`setGuard`, `setModuleGuard`, `enableModule`, any other handler, and every
  selector the Safe does not implement, which its fallback forwards to the handler with the Safe as
  caller), so the list stays closed when a Safe release adds functions; venue calls such as an
  emergency `pause()` are fine. A `Bypass` window of at least 1 hour (a window typed in the wrong
  unit must not void every approval for nothing) and at most 7 days that turns the policy off but
  keeps the **same allowlist and the module allowlist** in force (`CouncilBypassLimit`,
  `ModuleNotAllowed`; delegatecalls only to a registered `MultiSendCallOnly`, whose entries get the
  allowlist too; no gas refund either: the refund is a transfer to `refundReceiver` those limits
  never see), guardian management (per Safe, at most 32, and deployment-wide), and any narrowing. No role
  holder can act on itself as a Safe (`enforce`, `bypass` and `approveTransaction` revert
  `Unauthorized` when `safe == msg.sender`), so a Safe that was given the council role by mistake
  cannot unlock or approve itself. The policy's required fallback handler counts as part of the Safe
  for the council (unreachable as a call target whatever the selector: a handler answers Safe calls
  with the Safe as caller); a handler the policy does not name is covered by the rule that a non-zero
  handler must be stateless or absent (§6). A compromised council is therefore a 7-day window in which
  the signers may make any call (transfers of custody included) and rotate owners, but it can never
  remove or weaken the guard, and any guardian ends the window at once with `lockdown` (or
  `lockdownAndRevoke`). A council window relaxes the owner-signed path only: a module (no owner
  signature; Safe v1.5.0 module guard) stays under the policy and the module allowlist, and a
  council approval bound to a module names an allowlisted module only, so the fast lane never
  re-arms an automation key a guardian removed. That is a control against a mistaken council: the
  council manages guardians and may remove them, and a council colluding with the signers needs no
  window to last (the first transaction inside one can be the transfer). What bounds a rogue council
  is that it holds no timelock role (neither canceller nor proposer), so it cannot veto or schedule
  its own removal by the admin; the sync task refuses to run while it does.
- **guardians**: narrow-only (`lockdown`; `lockdownAndRevoke` = lockdown plus voiding every standing
  approval in one transaction; revoke function/target, remove `OneOf` values, disable
  unwrapper/module/native transfer, revoke one or all approvals). Per Safe (`setGuardian`) or
  deployment-wide (`GUARDIAN_ROLE`, `setDeploymentGuardian`), both managed by admin or council so a
  compromised responder key is removable on the fast lane. A per-Safe guardian cannot touch another
  Safe nor deployment-wide state (`setUnwrapperCodehash(…, false)` needs admin, council or the
  deployment-wide role; re-allowing a seeded hash is admin or council; a hash outside the seeded set
  is refused in both directions, so a mistyped forbid fails loudly instead of logging a no-op). A
  guardian is never the Safe itself nor the guard, and a module a guardian removed stays out in every
  mode, admin windows included. Meant for monitoring bots and
  on-call responders: a compromised guardian key can freeze Safes, never widen anything. Bots and first responders default to `lockdown` (council-reversible), never `revoke*`: an allowlist
  the bot revoked comes back only through the timelock, and `lockdown` keeps approved one-offs
  executable, pre-staged `pause()` payloads included. `lockdownAndRevoke` is for the case where the
  signers or an outstanding approval are the threat: it also voids every approval; payloads on the
  council's lane (venue calls such as `pause()`, owner management, `disableModule`,
  `setFallbackHandler(0)`) can be re-issued by the council at once as 7-day approvals, admin-only
  payloads (batches, `setGuard`, `setModuleGuard`, `enableModule`, other handlers) only after a
  timelock delay. Guardian keys are **not** timelock cancellers: a canceller can veto every
  admin operation, including its own removal.

One deployment serves any number of Safes: policies are keyed by `msg.sender` of the hooks (the
Safe). An unconfigured Safe is in `Lockdown`, so a Safe that installs the guard before Vetro
configures it is frozen (fail-closed), not open.

Per-Safe policy (`SafePolicy`):

| Field | Meaning |
|---|---|
| `mode` / `bypassUntil` / `councilBypass` | `Lockdown` (default: deny all but approvals), `Enforced` (allowlist), `Bypass` (policy off until `bypassUntil`, emergency only; a council window keeps the council's self-call allowlist, the module allowlist, the unwrapper-only delegatecall rule and the gas-refund refusal, an admin window keeps the guard unreachable as a call target and the module allowlist). A window opened at `t` for `d` seconds (1 h ≤ d ≤ cap) covers `t … t+d-1`; at `t+d` the Safe reads as `Lockdown`, agreed by `mode()`, both hooks and the dry run (approvals, by contrast, are valid through their `expiry` second inclusive). `bypassWindow(safe)` returns the window end and who opened it |
| `enforceFallbackHandler` / `requiredFallbackHandler` | when enforced, non-approved traffic requires the Safe's fallback handler to be NONE or the configured address (use `address(0)`); no handler is always acceptable (nothing signs, nothing is forwarded), so the council's `setFallbackHandler(0)` fixes every requirement. Never the Safe itself nor the guard (`InvalidTarget`) |
| `functions[target][selector]` | `allowed`, `allowValue` (payable), `rules[]` (≤ 16, ANDed); at most 32 selectors per target |
| `allowedValues[(target, selector, wordIndex, generation)]` | membership set (≤ 128 members) for a live `OneOf` rule; cleared when its rule is dropped, abandoned in O(1) when the function is revoked (the function's `generation` is bumped and folded into the key: a re-allow starts from empty sets and revocation never iterates members) |
| `nativeTransferAllowed[target]` | empty-calldata calls (plain ETH transfers, also zero-value) |
| `multiSendUnwrappers` | delegatecall targets whose `multiSend(bytes)` payload is unwrapped; their runtime code hash must be in the deployment-wide allowlist at registration and at every use. The allowlist can only ever contain the canonical `MultiSendCallOnly` v1.3.0 / v1.4.1 / v1.5.0 hashes seeded in the constructor (guardians forbid, the admin re-allows a seeded one; nothing else can be added: a new Safe release means a new guard) |
| `modules` | Safe modules allowed to execute (v1.5.0 module guard path) |
| `guardians` | per-Safe narrow-only responders (≤ 32) |

Rule kinds (`RuleKind`), each against the 32-byte head word at calldata offset `4 + 32·wordIndex`:
`EqualTo(value)`, `EqualToSafe` (word must be the calling Safe), `OneOf` (member of the set),
`LessThanOrEqual(value)`, `GreaterThanOrEqual(value)`. Comparison is on the full 256-bit word, so
a dirty-high-bits address or amount fails `EqualTo` / `OneOf` / `LessThanOrEqual` (an ABI-coder-v2
callee rejects such words; a Solidity abicoder-v1 callee would silently mask them, which is why the
guard never relies on the callee). `GreaterThanOrEqual` alone would be fail-open (any dirty or
negative word exceeds a floor) and is only accepted together with an upper bound on the same word,
and a `LessThanOrEqual` partner must be a real ceiling: not below the floor, not `2^256 - 1`
(`InvalidRule`). With bit 15 of `wordIndex` set (`TAIL_FLAG`) the rule's subject is not the word but
`keccak256(calldata[4 + 32·(wordIndex & 0x7fff):])`, the hash of everything from that word to the end
of the calldata (offsets, lengths, contents, trailing bytes): the one way to bind a dynamic argument
(`EqualTo` pins one reviewed payload, `OneOf` a guardian-trimmable set of them; a re-encoding of the
same logical payload is a different hash and is refused, which is the point). A function call to a
target WITHOUT code is refused at call time (`NotAContract`): a mistyped venue address would otherwise
"succeed" and keep the value; plain transfers (the native lane) are unaffected.

Approvals (`approveTransaction(safe, executor, to, value, data, operation, ttl)`, admin or council):
one execution of the exact payload by the exact path (`executor == address(0)` = owner-signed
`execTransaction`; otherwise the named Safe module), consumed on use, valid for `ttl` seconds from
the moment the call lands (admin ≤ 180 days, council ≤ 7 days; a relative TTL so a timelocked
proposal never reverts for being executed early or late), and void en bloc after
`revokeAllApprovals(safe)` or whenever a `Bypass` window opens (a per-Safe epoch is part of the
approval id; `approvalExpiry` reports `0` for records from an older epoch). Re-approving a payload
overwrites its expiry; it never grants a second execution. Approvals outlive admin transfers (they are
keyed by Safe and epoch, not by who issued them) and a decommissioned guard keeps its unexpired ones,
so `revokeAllApprovals` on decommission (§7.5). What an approval may address is checked when it is
issued (`InvalidTarget`): never the guard itself, never an account without code when calldata is sent
or for a delegatecall (the call would "succeed", spend the one-off and do nothing), never a
delegatecall into EIP-7702 delegated code (its key can re-point it at any time), and a module-bound
approval names a module that is neither the Safe nor the guard. An approved DELEGATECALL is bound to
the code at `to` when it was issued (the code hash is folded into the approval id: once the code
differs, the approval is void). An approved delegatecall into canonical `MultiSendCallOnly` code is
still a batch and is decoded at use with the strict decoder (canonical encoding, plain-call entries,
none addressed to the guard; nothing else is checked): the builds execute truncated and non-canonical
payloads that decoders display differently, so without it an approval would bind bytes whose meaning
depends on the reader. Single-call approvals and delegatecalls into any other code stay unparsed (an
admin-approved delegatecall into NON-canonical code can still address the hooks from the Safe's
context: review such code, not just its calldata). None can be issued while the Safe is in `Bypass`
(`SafeInBypass`): no live approval ever coexists with a `Bypass` window, so nothing that executed
unconsumed inside a window can replay after it. A failed approved execution never costs its
approval, on either path and whatever `safeTxGas` says: with `safeTxGas == 0` the Safe reverts the
whole transaction itself (v1.4.1 says GS013, v1.5.0 bubbles the inner reason; the gas-refund check
closes the other branch of that rule), otherwise it reports `success == false` to the post-hook and
the guard reverts `ApprovedExecutionFailed`, which rolls the consumption back the same way; the guard
needs no restore-on-failure state. An approval that happens to match an allowlisted payload captures
it (the approval branch runs first; the execution is reported as `Approval`). Any role
holder can wrap one of its own calls in `executeBefore(deadline, call)`, which runs it as the caller
only until `deadline`; the sync task does this for every timelocked batch.

Evaluation order in `checkTransaction` / `checkModuleTransaction` (the tests pin it):

1. `msg.sender == defaultAdmin()` → return (the admin is exempt; the exemption is on the Safe that
   calls the hooks: an admin acting as a MODULE of a guarded Safe is under that Safe's policy and
   module allowlist like any module).
2. The transient slot of `(safe, path)` is already set → `NestedExecution`: a Safe transaction of
   the same Safe on the same path is already executing (a nested `execTransaction` reached through
   an allowlisted or approved target). Evaluated before the Bypass return, so a window opened inside
   an outer policy transaction cannot be used to nest; a transaction that itself runs inside a window
   records nothing, so nesting inside it goes undetected (both are unchecked anyway, and a council
   window applies its limits to the inner transaction too). The owner-signed and module paths are
   independent, so an approved owner batch may trigger policy-compliant module transactions.
3. The Safe's guard slot of this path (the transaction-guard slot on the owner path, the module-guard
   slot on the module path) must name this guard → `GuardNotInstalled` otherwise (an account that
   cannot answer `getStorageAt` is `SafeConfigUnreadable`). A replacement guard is therefore inert
   until the Safe adopts it and a retired one from the swap on: neither can spend approvals, use
   windows or emit reports when the installed guard lets the Safe call it. Not checked in the
   post-hook (an approved `setGuard` moves the slot inside the transaction and the Safe calls the
   cached guard) nor in the dry runs (the pre-swap checklist simulates against the replacement).
4. Module path only: the module must be allowlisted (`ModuleNotAllowed`), in EVERY mode, approval or
   not: a guardian's `setModuleAllowed(false)` is a complete switch for that key, inside admin and
   council windows too (the read is of the guard's own storage, so it never stands in the way of a
   window's recovery purpose).
5. Effective `Mode.Bypass` (an unexpired window) → return, nothing recorded. An admin window checks
   nothing further but `GuardCallNotAllowed` for a plain call to the guard itself (a call into the
   post-hook could otherwise forge a `TransactionChecked`; batch entries and delegatecalled code are
   not decoded in an admin window, so reports inside one are not authoritative); a council window
   relaxes the owner-signed path only and there refuses `GasRefundNotAllowed` for a non-zero
   `gasPrice`, `CouncilBypassLimit` for a self-call outside the council's allowlist (anything but
   owner management, `disableModule`, `setFallbackHandler(0)` and the empty rejection call),
   `DelegateCallNotAllowed` for any delegatecall but a registered `MultiSendCallOnly`, whose entries
   get the same limits, and `GuardCallNotAllowed` for the guard itself; the module path of a council
   window continues with the steps below.
6. `gasPrice != 0` → `GasRefundNotAllowed`. Safe's `handlePayment` pays `(gasUsed + baseGas)·gasPrice`
   in `gasToken` to `refundReceiver` from the Safe's balance (`baseGas` is a free word of the signed
   transaction, so the payment is not bounded by the gas actually used; ETH payments are capped at
   `tx.gasprice` per unit, token payments are not): with a non-zero gas price the signers can drain
   any ERC-20 or ETH through the refund path without any call to the token. Approvals do not bypass
   this check.
7. Unconsumed, unexpired approval for `(safe, epoch, executor, to, value, keccak(data), operation,
   code hash of `to` for a delegatecall)` → no approval is spent while the Safe's fallback handler
   is this guard (`ForwardedHookCall`: `FallbackManager` forwards every selector a Safe does not
   implement to its handler, for ANY caller, with the Safe as `msg.sender`, so with the guard in that
   slot a stranger could call `safe.checkTransaction(<approved payload>)` and burn the approval; the
   forwarded length is the caller's choice, so only the slot tells such a call apart); an approved
   delegatecall into canonical `MultiSendCallOnly` code is strictly decoded (`MalformedMultiSend`,
   `EmptyMultiSend`, `MultiSendDelegateCallEntry`, `GuardCallNotAllowed` for an entry addressed to
   the guard); the approval is kept on any of these refusals; then consume it, write the approved
   sentinel into the slot, return.
8. `Mode.Lockdown` (including an expired `Bypass`) → `SafeLockedDown`.
9. The account must be a known Safe: its own code and the code of the singleton its proxy reports
   (`masterCopy()`, exactly one word) must carry one of the runtime code hashes fixed at deployment
   (the proxies of the v1.3.0 / v1.4.1 / v1.5.0 factories, the L1 and L2 singletons of those
   releases) → `SafeNotSupported` otherwise: a look-alike, a singleton that forwards to replaceable
   code, an EIP-7702 delegated account and a Safe release the guard was never reviewed against never
   get a policy transaction (approvals and windows do not read the configuration, so the exits stay
   open; a new Safe release means a new guard, as for the unwrappers). Then snapshot the Safe's
   critical configuration into the slot: that singleton, owner count / threshold from storage slots
   3-4, the owner list, the modules linked-list head, the fallback handler, the guard and
   module-guard slots (read through the Safe's `getStorageAt` / `getOwners`). If a required fallback
   handler is enforced and the live one is neither zero nor the named one →
   `FallbackHandlerNotAllowed`. If a module is linked (the modules head is not the sentinel) and the
   module-guard slot does not hold this guard → `ModuleNotHooked(firstLinkedModule)`: such a module
   executes with no check at all, `setGuard(0)` included (every module on v1.3.0 / v1.4.1; on v1.5.0
   one whose `setModuleGuard(guard)` never ran), so the policy refuses to run next to it until
   `disableModule` (council lane) or `setModuleGuard` (admin lane) lands; both are approvals and
   never read the configuration.
10. `DelegateCall`: `to` must be a registered unwrapper whose runtime code hash is still allowed
   (`UnwrapperCodehashNotAllowed` otherwise), `value == 0`, payload strictly decoded; every entry
   is checked as in step 11; entries with `operation != 0` or `to == address(0)` are rejected (v1.5.0
   `MultiSendCallOnly` rewrites a zero `to` to the calling Safe). Any other delegatecall →
   `DelegateCallNotAllowed`.
11. `Call`: `to == safe` → `SelfCallNotAllowed` (so `setGuard`, `enableModule`, `swapOwner`,
   `changeThreshold`, `setFallbackHandler`, `setModuleGuard` are unreachable except via an
   approval), with one exception: the empty, zero-value self-call Safe{Wallet} uses to reject a queued
   transaction passes (it burns the nonce and lands in `receive()`; the post-check still runs);
   `to == guard` → `GuardCallNotAllowed`. Empty calldata → needs
   `nativeTransferAllowed[to]`. `0 < len < 4` → `MalformedCalldata`. Otherwise
   `functions[to][selector]` must be allowed (`FunctionNotAllowed`), `to` must carry code
   (`NotAContract`), `value > 0` needs `allowValue`, each rule must hold (`ParamOutOfRange` if the
   word is missing, `ParamRuleViolated` otherwise).

Post-execution (`checkAfterExecution` / `checkAfterModuleExecution`), one transient slot per
`(safe, path)` holding `0`, the approved sentinel or the snapshot digest:

- the call must be exactly the 68 bytes of an after-hook (`ForwardedHookCall` otherwise): a call
  forwarded by a Safe's fallback carries the caller's 20 bytes, at that exact length in the low bytes
  of `success`, which the ABI decoder refuses as a dirty `bool`. A report can therefore never be
  forged through a Safe whose fallback handler is the guard;

- read and clear the slot **first**, so nothing can leak into a later Safe transaction of the same
  EVM transaction whatever happens next;
- sentinel (an approved execution) → `ApprovedExecutionFailed` if the Safe reports `success ==
  false` (the module path, and the owner path when the transaction carries a non-zero `safeTxGas`;
  with `safeTxGas == 0` the Safe reverts before the post-hook; the revert rolls the consumption
  back, so a failed one-off never costs its approval), otherwise return: configuration changes are
  what approvals are for;
- `0` → legitimate only for the admin or an effective `Bypass` (pre- and post-hook evaluate the
  window at the same `block.timestamp`, so they always agree); otherwise `MissingSnapshot`. A council
  flip from `Bypass` to `Enforced` inside a curator transaction therefore fails closed, as does an
  admin Safe handing the admin role over inside its own transaction (pre-hook exempt, post-hook no
  longer: do hand-overs from a plain transaction), while a flip into `Bypass` inside a policy
  transaction still gets its configuration compared;
- a digest → recompute the configuration digest and revert `SafeConfigChanged` if it differs from
  the pre-execution snapshot (fail closed). This catches any write to the Safe's guard, module guard,
  modules head, owner list, owner count, threshold, fallback handler or singleton (including a
  swapped singleton that lies in its own views, because `masterCopy()` is answered by the proxy
  bytecode; a singleton swapped to code the guard does not know is `SafeNotSupported` here too). The
  modules coverage is the HEAD slot: complete while the list is empty (which the `ModuleNotHooked`
  rule requires on v1.3.0 / v1.4.1), and on a hooked v1.5.0 Safe an insertion behind the head needs
  self-calls the policy refuses;
- whichever way the transaction got through, the post-hook ends with one
  `TransactionChecked(safe, txHash, path, outcome)`: `path` 0 for the owner-signed path (`txHash` is
  the Safe's own `safeTxHash`, the one Safe{Wallet} and the Transaction Service show) or 1 for the
  module path (`txHash` is the payload hash `checkModuleTransaction` returned,
  `keccak256(abi.encode(safe, module, to, value, keccak256(data), operation))`, since Safe v1.5.0
  emits none for module transactions; a function of the Safe and the payload only, so identical
  module payloads of one Safe share it and module reports are indexed by log position, never by hash); `outcome` is `Policy` (0), `Approval`
  (1) or `Bypass` (2) and is an indexed topic (as is `mode` in `ModeUpdated`), so a bot filters
  "every `Bypass` outcome" server-side; `path` is the event's only data word. A refused
  transaction leaves no event (both hooks revert the whole Safe transaction) and the admin's own
  transactions are neither checked nor reported. The event costs about 2k gas.

The configuration reads go through the Safe's own views (`getOwners()`, `getStorageAt`) as raw ABI
responses, shape-checked and hashed as returned. A Safe that cannot answer them, in the pre-hook, the
post-hook or a dry run, reverts `SafeConfigUnreadable(safe)` instead of a bare `Panic`: in practice a
Safe whose owner list is longer than its `ownerCount` (`OwnerManager.getOwners` then indexes past its
array), which only a storage-writing delegatecall or module can produce (a dry run against an
account without code, or against anything that is not a supported Safe build, is `SafeNotSupported`).
The two paths that never read the configuration, an approval and a Bypass window, keep working on
such a Safe (§7.6); they do read the one guard slot of step 3. The digest cannot enumerate mappings: a dangling `modules[x]` / `owners[x]` /
  `approvedHashes` / `signedMessages` entry is invisible to it, and it is **not a boundary against
  code running in the Safe's context**: such code can call the hooks itself (clearing the slot and
  re-arming a fresh snapshot of the modified configuration) and so launder the digest. Both are why
  unwrapper code is pinned to the canonical `MultiSendCallOnly` hashes seeded at deployment, which
  never write storage and never call the guard, and why that set cannot grow. The digest is
  defence-in-depth against a Safe or `MultiSendCallOnly` bug, not against a mis-registered
  unwrapper (which can no longer exist). The nonce slot is outside the digest.

A nested `execTransaction` of the same Safe on the same path is rejected in the pre-check
(`NestedExecution`, step 2); an intermediary that swallows that revert lets the outer transaction
succeed with the inner one never executed, and the outer approval is consumed exactly once.

`validateTransaction(safe, to, value, data, operation)` and
`validateModuleTransaction(safe, module, …)` are `view` replicas of the pre-check for
simulation (`eth_call`), window limits included; they never consume approvals and model
neither the nested-execution check, nor the installed-slot check (step 3: a replacement guard can be
simulated before the swap), nor the gas-refund check (`gasPrice` is assumed zero), nor the
post-execution comparison, but
they do read the Safe's configuration where the live pre-check snapshots it, so `SafeConfigUnreadable`
, `SafeNotSupported`, `ModuleNotHooked` and `FallbackHandlerNotAllowed` reproduce in simulation
(the live pre-check and the dry run share one function for these). The guard needs EIP-1153 transient storage
(Cancun), available on Ethereum mainnet; its constructor probes for it (`tstore(k, tload(k))`, a
no-op) so a deployment on a pre-Cancun chain fails at `create` instead of producing a guard whose
hooks, `setGuard(0)` included, would hit an invalid opcode and brick the first Safe that installs it
(`FOUNDRY_PROFILE=precancun forge test` demonstrates the refusal on a Shanghai EVM).

Strict `multiSend(bytes)` decoding mirrors Zodiac's `MultiSendUnwrapper`: selector must be
`0x8d80ff0a`, the `bytes` head offset must be `0x20`, `calldata.length` must equal
`68 + ceil32(length)` (no trailing bytes), every packed entry needs 85 header bytes and its
declared data length must fit the payload, empty batches are rejected. A lax parser that trusted
the head offset could be made to check different bytes than `MultiSend` executes. The same decoder
runs on the policy lane (every entry held to the policy), in a council window (every entry held to the
council's limits) and on an approved batch (every entry only kept off the guard). `MultiSendDelegateCallEntry`
is raised for ANY operation byte other than `0` (the builds revert on 2..255 as well).

## 5. Writing policies

Allowlisting a selector is necessary, not sufficient. For every allowed function ask: *which
parameter decides where value ends up, and is it pinned?*

| Venue call | Rule to pin |
|---|---|
| `ERC20.approve(spender, amount)` | `OneOf` on word 0 = the venues that may pull (never unconstrained: `approve(attacker, max)` + `transferFrom` is a full drain). |
| `ERC20.transfer` / `transferFrom` | Do not allowlist. Use a one-shot approval for a deliberate transfer. |
| `ERC4626.deposit(assets, receiver)` / `mint(shares, receiver)` | `EqualToSafe` on word 1. |
| `ERC4626.withdraw(assets, receiver, owner)` / `redeem(shares, receiver, owner)` | `EqualToSafe` on words 1 and 2. |
| Aave v3 `supply(asset, amount, onBehalfOf, ref)` / `withdraw(asset, amount, to)` | `EqualToSafe` on word 2; `OneOf` on word 0 if only some assets are allowed. |
| Morpho Blue `supply(marketParams(5 words), assets, shares, onBehalf, data)` | static struct is inlined: `onBehalf` is word 7, `EqualToSafe`; market pinned with `EqualTo` on words 0–4. |
| Lagoon `settleDeposit(uint256)` / `settleRedeem(uint256)` / `updateNewTotalAssets(uint256)` | a static band on word 0 of `updateNewTotalAssets` (`GreaterThanOrEqual` + `LessThanOrEqual` around the settled NAV; banding that one function suffices, the settles must repeat the proposed value) refuses unit mistakes and caps a single mark, and it is the one NAV control that needs no curator signature. It does not bound a malicious quorum (marks chain inside one block: a ±5 % band still costs about 0.25 % of NAV per cycle) and it must be re-synced with every funding step, or honest settlement stops at the ceiling. The validator demands a band or an explicit `"unconstrained": true`. NAV honesty remains a Lagoon-role question (§8): guardrails bound `updateNewTotalAssets` only once `securityCouncil` has activated them with real bounds, which is not the case on the live vaults. |
| Payable calls (`WETH.deposit()`) | `allowValue: true`; plain ETH sends need `nativeTransfers`. |
| Swaps (routers, aggregators, CowSwap) | Not expressible safely with static words alone (recipient + min-out + path all matter). Prefer a one-shot approval per swap, or Zodiac Roles. Never allowlist `SignMessageLib` delegatecalls: an EIP-1271-signed order can sell the Safe's balance. |

Word rules address head words only. Do not write word rules on dynamic parameters (`bytes`, arrays,
dynamic structs): their head word is an offset. `curator-guard-sync` derives the head layout from
the signature and rejects a word rule on a dynamic word or beyond the head. `address[]`-taking
functions such as Lagoon's `claimSharesOnBehalf(address[])` are fine to allow without rules
because the beneficiaries are the controllers themselves.

A dynamic payload can be bound exactly with a TAIL rule: `{"kind": "EqualTo", "wordIndex": N, "tail":
true, "value": <hash or raw tail bytes>}` binds `keccak256(calldata[4 + 32·N:])`, everything from
head word N to the end of the calldata; `OneOf` with `"values"` binds a set of reviewed payloads that
guardians can trim. N must be the head word of the FIRST dynamic parameter: from there every offset
word is inside the hash, and the static words before it keep their own rules. A later N would leave
the offset word of an earlier dynamic parameter outside the hash, and an ABI decoder reads that
parameter from wherever the offset points (empty, or another parameter's bytes), so the rule would
bind the bytes but not their meaning; the lint refuses it. The value is the 32-byte hash, or the raw
tail bytes, which the tool hashes.
Compute it from the exact calldata the signers will send (`cast keccak $(cast calldata … | cut -c
<11 + 64·N>-)` on the hex after the selector and N words): a re-encoding of the same logical payload
is a different hash and is refused. This is the honest way to allow ONE reviewed batch on a venue
that has its own `multicall` / `execute`, instead of its batch function.

Self-dispatching selectors are refused without `"$allowSensitive": true`: a venue function whose
payload embeds further calls (`multicall(bytes[])` and its variants, `aggregate3`, `execute(address,
uint256,bytes)`, `batch`, ERC-1363 `approveAndCall`, OpenZeppelin 1.x `increaseApproval`) runs them
as the Safe with no selector check and no rule, so allowing one voids every sibling rule and the
selector scoping of that target. `multiSend(bytes)` itself is never a function (as a plain call the
entries run from the library's address, unchecked; with `allowValue` the Safe's ETH goes anywhere),
and a registered unwrapper is never a function or native-transfer target.

Lower bounds need an upper bound on the same word (`GreaterThanOrEqual` + `LessThanOrEqual`,
`EqualTo` or `OneOf`), otherwise the contract rejects the rule; a `LessThanOrEqual` partner below the
floor or equal to `2^256 - 1` is rejected too. `OneOf` values can only be added once the function
carries the `OneOf` rule (allow first, then add values); the sync task orders its calls that way and,
when only a set grows, re-asserts the function's (identical) `allowFunction` ahead of the
`addAllowedValues` in the same batch, so a `revokeFunction` by a responder during the timelock delay
cannot kill the queued batch. Neither the Safe nor the guard can be a target or an unwrapper, and a
target without code is refused when it is called (the task warns at sync time).

Upgradeable targets (proxies) can change their code underneath an allowlisted selector. Treat
"allow a proxy" as "trust its admin", and revoke if the admin changes.

Policies live in `policies/curator-guard/<name>.<chain>.json` and are applied with
`curator-guard-sync` (`curator-guard-lint --policy <file>` runs the same validation offline, without a
network), which diffs the file against on-chain state (functions and rules, `OneOf`
sets, unwrappers, modules, native transfers, the required fallback handler, mode last) and either
applies the resulting admin calls: directly when the signer is the admin (or the admin is
impersonated on a fork), otherwise as ONE `scheduleBatch` on the admin timelock sent by the proposer
Safe (via `helpers/safe.ts`), executed with `--execute` once `minDelay` has passed. The file is the
full desired state: an absent `multiSendUnwrappers` / `modules` / `nativeTransfers` key means
"none", on-chain functions missing from the file are revoked, and `requiredFallbackHandler` and
`guardians` are mandatory (`guardians` are this Safe's narrow-only responders, synced as a full set;
deployment-wide responders hold `GUARDIAN_ROLE` instead). `mode` may only be `Lockdown` or
`Enforced`, and moving a Safe out of `Lockdown` / `Bypass` needs `--allow-unlock`. The validator
is strict (unknown keys, non-boolean flags, missing or non-canonical signatures, selector/signature
mismatch, word rules beyond the head or on dynamic words, unbounded lower bounds, more than 16 rules or
128 `OneOf` members per rule, more than 32 functions per target and more than 32 guardians (contract
caps), more than 256 `OneOf` members per function or 1,024 per target (revocation no longer iterates
members: `revokeFunction` costs about 30-70k gas whatever the sets hold and `revokeTarget` at most 32
of those; the joint caps bound `clearAllowedValues` and a re-allow that drops a `OneOf` rule, which
still iterate at about 14k gas per member on committed storage), unwrappers without code or
with a runtime code hash the guard does not allow, a Safe whose proxy or singleton code is not a
canonical build, a required handler that is the Safe or the guard)
and refuses allowance/transfer-shaped selectors (`approve`, `increaseAllowance`, `transfer`,
`transferFrom`, `safeTransferFrom`, `setApprovalForAll`, `permit`, Permit2 `approve`) without a rule
on each spender / recipient word (word 0; words 0 and 1 for the `transferFrom` shapes and Permit2;
word 1 for `permit`) unless the entry says `"unconstrained": true`. It also refuses duplicate JSON keys (a trailing duplicate would silently
win in `JSON.parse`), empty `OneOf` sets, a zero or self-referencing Safe, and honours optional
`chainId` / `guard` pins. `mode` may only be `Lockdown` or `Enforced` (`Bypass` is an incident action
taken on the guard, never a desired state, and opening it voids approvals by itself).
`--dry-run` prints the diff only.

## 6. Threat model

Assumed: the guard admin (the Vetro timelock and the governance Safe that proposes to it) and the
council are honest and share no signer with the curator Safe (the deploy script refuses otherwise);
guardian keys may be lost or stolen (they can only narrow); the curator's signers may be negligent
or malicious; the Lagoon vault code is as deployed (v0.6.0). That the Safe is a canonical proxy in
front of a canonical singleton is no longer an assumption: the guard checks both runtime code hashes
on the policy path (`SafeNotSupported`). What stays assumed is the Safe's storage BASELINE at install
(a module or owner entry planted directly in a mapping before the guard existed is invisible to every
view, §7.3).

Blocked (all covered by tests in `test/guards/`):

- Calling any contract or selector not on the list; calling the Safe itself (guard removal,
  module enablement, owner/threshold changes, fallback-handler swap) or the guard itself.
- Arbitrary delegatecall (code running in the Safe's storage context), nested delegatecall inside
  a batch, malformed batch encodings, batches with one bad entry (atomic).
- `approve` / `deposit` / `withdraw` to arbitrary counterparties when the matching rule is set
  (spender, receiver and owner words); dirty-bit and negative-integer tricks against bounded rules.
- Gas-refund exfiltration (`gasPrice != 0`).
- Using a one-shot approval twice, after expiry, after `revokeAllApprovals`, on another Safe,
  from the other execution path, with a different value / operation / payload, or through a nested
  `execTransaction` of the same Safe. A failed approved execution gives the approval back.
- Registering any delegatecall target other than a canonical `MultiSendCallOnly` build, and using
  one whose code hash was forbidden after registration.
- Widening the policy from a guardian key or a stranger; deadlocking the owner Safe.
- Changing the Safe's guard, module guard, modules head, owner list, owner count, threshold,
  fallback handler or singleton (even to one that lies in its own views) during a policy
  transaction through any path (configuration snapshot).
- Running the policy while an EIP-1271 capable fallback handler is installed, once the
  requirement is set (`FallbackHandlerNotAllowed`).
- Running the policy on an account that is not a canonical Safe proxy in front of a canonical
  singleton: a look-alike, a singleton that forwards to replaceable code, an EIP-7702 delegated
  singleton or account, a release the guard was never reviewed against (`SafeNotSupported`), or next
  to a linked module the guard does not hook (`ModuleNotHooked`).
- Driving the hooks without a Safe transaction: through the Safe's fallback forwarding (no approval
  is spent and no report emitted that way, `ForwardedHookCall`), or on a guard the Safe does not have
  installed on that path, a replacement before adoption and a retired guard after the swap included
  (`GuardNotInstalled`).
- Using a role through a role-holding Safe's fallback forwarding (the council Safe, a guardian Safe, a
  proposer or veto Safe whose handler is the guard or the timelock).
- A module a guardian removed, in every mode (admin and council windows included).
- An approved batch that is truncated or not canonically encoded, or that addresses the guard; an
  approved delegatecall whose target code changed since the approval; an approval addressed to an
  account without code (with calldata) or, for a delegatecall, to EIP-7702 delegated code.
- A function call to a target without code; a floor whose "ceiling" bounds nothing.
- Granting a guard role to `address(0)`, to the admin or to a configured Safe; a second admin on the
  timelock; the timelock as its own proposer or canceller.

Residual (document, monitor, mitigate outside the guard):

- **Roles and guardians live in the guard instance.** Per-Safe guardians, `GUARDIAN_ROLE` and
  `COUNCIL_ROLE` are state of one guard; a replacement starts with none: sync the policy (which
  carries this Safe's guardian list) against the new guard and re-grant the roles on it before the
  signers switch, otherwise `lockdown` / `revokeAllApprovals` from the responder keys revert. A
  replacement also starts with every seeded unwrapper hash allowed again (a hash forbidden on the old
  guard is not carried over) and with no epoch, approvals or `lockedAt`: the §7.5 checklist compares
  `GUARDIAN_ROLE` members, forbidden hashes, modules and native transfers too.
- **The council is fully trusted for funds.** Seven-day approvals of any venue call plus owner
  rotation plus a seven-day window with the policy off add up to drain capability; what the council
  can never do is remove or weaken the guard, nor veto its own removal: it is deliberately not a
  timelock canceller (a canceller can cancel every admin operation, `revokeRole(COUNCIL_ROLE)`
  included, forever), so the admin removes a compromised council after the timelock delay. Until then
  it can freeze the Safe, re-open windows, strip guardians and stall an admin hand-over (a window, an
  `enforce` or a planted guardian on the pending admin refuses the acceptance until the eviction batch
  of §4 lands): guardians are a control against a
  mistaken council, not a malicious one. Pick its signers accordingly. Its removal batch is
  `[revokeRole(old), grantRole(new), lockdownAndRevoke(safe)]` per Safe and never a lift: what a
  council did in its last hour (a 7-day window it opened, 7-day approvals, a guardian it planted)
  outlives the role, and the new council, which the cooldown does not hold back, clears it at once.
- **The veto Safe is the one trusted veto, and it proposes nothing.** A canceller can cancel its
  own removal. A canceller that could also propose would therefore be, once compromised, an unvetoed
  takeover: it schedules what it likes, nobody can cancel, and after one `minDelay` the council is
  stripped, a hostile council granted, anything widened (reproduced in review, V2-74). A canceller
  that cannot propose is at worst a permanent governance deadlock: no admin operation ever executes
  again, custody stays guarded, settlement continues on the council's lane, and the guard can only
  leave the Safe by a council-approved custody move to a fresh Safe (§7.6). The contract enforces the
  separation (`CancellerCannotPropose` / `ProposerCannotCancel`), the deploy script wants exactly one
  canceller, and a 2-of-3 veto Safe of three distinct governance parties turns even that deadlock
  into a majority decision. A compromised proposer is cancellable and removable. The lockdown
  cooldown protects against STALE honest operations, not against a hostile proposer: a widening, a
  role grant or an approval routed through a freshly granted council all execute during the cooldown,
  so the cancel inside `minDelay` is the control, and bots page the veto Safe on any `CallScheduled`
  that targets the timelock itself, a foreign contract, or carries `grantRole` / `revokeRole` /
  `updateDelay` / `beginDefaultAdminTransfer`, and on `grantRole(CANCELLER_ROLE, …)` in particular
  (the number of cancellers is not enforced on-chain: a rotation needs two for one batch). A guarded
  veto Safe is a veto that cannot be used (`cancel` is a Safe transaction): `ChangedGuard` on it means
  "the veto is gone" until §7.6 step 5 is run.
- **Admin / council key overlap with the curator.** Today's governance Safe is 3-of-6 and three
  of its owners are curator-Safe owners, so with it as proposer three colluding curator keys could
  queue any widening, open a `Bypass` or approve anything. v2 makes this a deployment-time refusal:
  `deploy/ethereum/guards/00_curator_guard.ts` intersects the signer sets of the proposer and the
  council with the curator Safe's (recursively through nested Safes) and aborts on overlap
  (`CURATOR_GUARD_ALLOW_KEY_OVERLAP=1` downgrades it to a warning on forks only). Widenings also sit
  in the timelock for `minDelay`, cancellable by the veto Safe (never the council, never a proposer), and the council can never touch the allowlist
  or the Safe's security configuration, so a compromised fast lane is bounded to 7-day approvals of
  venue calls and owner rotations. A dedicated governance Safe without curator keys must replace
  `curatorGuardProposers` before mainnet (`helpers/address.ts`).
- **NAV marking.** The curator Safe holds `valuationManager` and `securityCouncil`, and Lagoon's
  guardrails are deactivated on the live vaults, so a policy-allowed `updateNewTotalAssets` +
  `settleDeposit` / `settleRedeem` can mark NAV to any value. The guard does not police NAV (§2).
  An inflated mark raises `LagoonBase.tvl()`, but `_rebalance` books profit only up to the
  strategy's idle collateral at report time (`_reportable = min(_profit, idle - payback)`) and
  queues a redeem for the rest, so the pool's price per share is exposed per report only up to
  that idle (credit-line funds the pool just sent included), while the Lagoon-side exposure is the
  strategy's whole share balance, paid out at whatever NAV the curator settles at. Because the
  vaults are public (§1 `accessMode`), a deflated mark lets the curator or a confederate buy in
  cheaply and a later inflated mark lets them redeem against the Safe's custody, all through
  allowlisted calls. Measured on the live USDC vault with the guard installed (round 5): two
  pre-signed allowlisted batches and three public calls take 100 % of a vault's custody in ONE
  Ethereum transaction, with capital that can be flash-borrowed, so no guardian, alert or cooldown
  can react; only on-chain bounds help. The guard is not a NAV control, and until one of the
  Lagoon-side controls below is live every strategy's `debtRatio` stays at zero. Fees are zero today but the Safe, as vault owner,
  may raise the management and performance rates (entry / exit rates can only be lowered after
  initialisation). Mitigation is Lagoon-side (§8): whitelist mode first (it removes the outside
  beneficiary; guardrails alone bound the price-per-share move, so on a public vault a false mark
  still pays an outside depositor in proportion to that depositor's own stake), then `securityCouncil`
  at Vetro with guardrails activated with real bounds, and decide who holds `valuationManager`. Two
  guard-side rule kinds that would bound a mark absolutely and separate it in time from its settle
  were designed and measured in round 8 and are recorded as the first open item of
  IMPROVEMENTS_V2.md §4 (they change how settlement is operated, so they are a decision, not a fix).
- **Settlement is the curator's.** Refusing or delaying settlement (or any Vetro freeze) is
  illiquidity, not loss, for Vesper depositors: pending requests sit in Lagoon's silo or as
  pending shares, `LagoonBase.instantLiquidity()` only promises idle plus already-claimable
  redeems (idle only while the vault is paused), the keeper-side loss cap is `maxLossBps == 0` on
  all five strategies, and `reportLoss` is governor-only. Zero is not an operable setting once a
  position has been through a real settlement: Lagoon's share arithmetic floors both ways, the round
  trip loses at least 1 wei, and `LagoonBase._rebalance` then reverts `LossExceedsCap(1, 0)` on every
  keeper call (claims included) until a gain covers it. Either the strategy gets a rounding
  tolerance (a strategy change, outside this work) or governance sets the smallest cap,
  `setMaxLossBps(1)`; the property that matters, that an operational freeze never books a loss,
  survives both. A lone `updateNewTotalAssets` also closes Lagoon's epoch, after which pending
  requests can be neither cancelled nor claimed until the Safe settles: on any lockdown the keeper
  cancels first, and an approved `pause()` freezes cancellations and settled claims too.
- **Vault pausing latency.** `pause()` / `unpause()` are vault-owner calls (the Safe) and are not
  allowlisted: a guardian `lockdown` stops settlement instantly but does not stop user flows on the
  vault; pausing the vault needs a Vetro approval first. Pre-stage approved `pause()` payloads per
  vault in the incident runbook if that latency matters.
- **EIP-1271 before the handler is removed.** Until the signers execute the approved
  `setFallbackHandler(0)`, the USDC drain path exists regardless of the guard; the requirement
  only freezes policy traffic to force the change. Treat the handler change as part of install,
  not as a follow-up. Tokens added to custody later must be checked for 1271-aware `permit` /
  EIP-3009 before the handler question is reopened (e.g. for a handler that supports ERC-721
  callbacks: use one without `isValidSignature`).
- **On-chain signed messages** (`SignMessageLib` delegatecall) are blocked by the delegatecall
  policy; never register that library as an unwrapper.
- **Pre-existing allowances and modules** at install time are outside the guard's view: enumerate
  and revoke / verify before install (§7.3).
- **Vetro's freeze power.** Any guardian can freeze the Safe (lockdown), which also halts Lagoon
  settlements and therefore Vesper-side redemptions until the council or the admin lifts it
  (`enforce`). This is the intended control, but the curator and depositors should know it exists
  and that lifting it is a fast-lane action, not a timelocked one.
- **Guard liveness.** A guard bug that reverts every transaction bricks the Safe, including
  `setGuard(0)`. Recovery exists and is tested: the approval path is evaluated before any parsing
  (council for owner management and venue calls, admin for `setGuard` / handler / module changes)
  and a time-boxed `Bypass` disables the policy on the owner-signed path (council ≤ 7 days
  immediately, within the council's limits; admin ≤ 180 days through the timelock, which leaves only
  the module allowlist and the guard-as-target refusal in force on both paths); see §7.6. An expired
  window falls back to `Lockdown`, so a forgotten inert guard cannot exist. Two checks precede even
  the approval and window exits and read nothing but this guard's storage and ONE slot of the Safe:
  the installed-slot check and the module allowlist; the approval exit reads one more slot (the
  handler). A Safe whose `getStorageAt` itself is broken (no Safe singleton behaves so) would lose the
  exits; one whose owner list is unreadable keeps them. A Safe whose fallback handler IS the guard
  keeps the window exit only: a council window carries the `setFallbackHandler(0)` repair, approvals
  are refused until it lands.
- **Policy mistakes.** Allowing `transfer`, an unconstrained `approve`, plain `MultiSend`, or a
  target that is itself a generic executor (a router with arbitrary-call features, another Safe's
  `execTransaction`, a venue's own `multicall` / `execute` / `aggregate`: the embedded calls run as
  the Safe, unseen, and void every sibling rule of that target) is a policy error the guard cannot
  detect; the validator refuses the known self-dispatching selectors without a marker and
  `multiSend(bytes)` outright, but the class has no closed list. A function call to an EOA or a
  not-yet-deployed address is refused at call time (`NotAContract`); a plain TRANSFER to a wrong
  address is not. Review every widening against §5.
- **Lagoon roles.** The guard constrains the Safe, not the roles themselves. If Vetro wants the
  curator to be unable to ever exercise `owner` / `securityCouncil` even through a future
  approval, move those roles to Vetro (§8).
- **Council bound and the vaults.** "The council can never weaken the Safe" covers the Safe's own
  configuration and the policy's named fallback handler. It does not cover the contracts the Safe
  controls: every Lagoon `owner` / `safe` function (`updateSafe`, `transferOwnership`,
  `initiateClosing`, `pause`) is a venue call one 7-day council approval away until those roles move
  to Vetro (§8), and on a v1.3.0 / v1.4.1 Safe an enabled module's own admin surface (a module's
  `transferOwnership`) would hand an unguarded executor to a third party, which is why such Safes
  must be module-free at install (§7.3) and why `enableModule` is never approved on them (§7.5).
- **Narrowing cost.** Revoking a function abandons its `OneOf` sets in O(1) (the sets are keyed by
  the function's generation: about 35k gas warm whatever they hold, no per-member event) and
  `revokeTarget` iterates at most 32 selectors, so incident narrowing fits in any block; only
  `clearAllowedValues` and a re-allow that drops a `OneOf` rule still iterate members (about 14k gas
  each on committed storage; the validator caps a policy at 256 members per function and 1,024 per
  target). `lockdown`, `revokeAllApprovals` and `lockdownAndRevoke` are O(1) and remain the
  incident-response primitives; a per-Safe guardian set is capped at 32.
- **Snapshot scope.** The configuration digest reads the singleton from the proxy itself (and
  requires the proxy's and the singleton's code to be canonical builds) and everything else through
  the Safe's views; it cannot enumerate the `modules`, `owners`, `approvedHashes` and
  `signedMessages` mappings, so a dangling entry planted directly in storage is invisible to it, and
  of the modules list it covers the HEAD (complete while the list is empty, which `ModuleNotHooked`
  enforces on v1.3.0 / v1.4.1; behind the head of a hooked v1.5.0 list only refused self-calls can
  insert). The only code that can run in the Safe's context without an approval is a
  registered unwrapper, and unwrapper code is pinned to canonical `MultiSendCallOnly` hashes (which
  never write storage); keep that allowlist untouched. The nonce slot is outside the digest. Two
  mappings can still be written without a guarded transaction, or with one approved library call: any
  single owner sets `approvedHashes` through `approveHash` (in any mode, Lockdown included), and an
  approved `SignMessageLib` delegatecall sets `signedMessages`. Both are dormant while the handler is
  zero, permanent (Safe has no un-sign), survive owner rotation, and become live EIP-1271
  authorisations the day a handler with `isValidSignature` is installed: enumerate the Safe's
  `ApproveHash` / `SignMsg` logs before approving any such handler, ever.
- **Queued admin operations and lockdowns.** A timelock operation is public, executable by anyone
  once ready, and was scheduled before whatever incident follows. The one-day `LockdownCooldown`
  (§4) stops a queued lift, window or approval from being executed atomically with a transaction the
  signers already hold; what nobody cancels during that day becomes executable again. A compromised
  guardian key can extend the pause by re-locking (ONE lockdown inside a chained lift's last day is
  enough: the cooldown then outlives the lift's deadline), until the key is removed: the council does
  that at once in one batch with the lift (`[setGuardian(safe, key, false), enforce(safe)]`, about 80k
  gas through a 2-of-2 Safe) and is never held back; without a council the bound is `minDelay` plus
  a day, and a lift is only safe to queue together with the removal of every key that could re-lock,
  ahead of it in the same cycle. Removing the locker does not end the cooldown it started.
- **Vault code.** The five vault proxies are upgradeable by their `DelayProxyAdmin` (owner: the
  curator Safe; one-day delay; target gated by Lagoon's registry, which today already whitelists a
  v0.5.0 build without guardrails and would accept anything if it ever lost its owner). A submission
  made before install never expires, and `submitImplementation` / `upgradeAndCall` are venue calls on
  the council lane: the pre-install checklist reads the implementation and the pending submission
  (§7.3), those calls are never approved on the council lane (§7.5), and the admin ownership moves to
  Vetro with or before any guardrail activation (§8).
- **Fallback handlers of governance Safes.** A Safe's fallback handler receives every call the Safe
  does not implement, from anyone, with the Safe as caller. A Safe that holds a role must never have
  as its handler a contract on which it holds rights: the guard and the timelock refuse such a caller
  themselves, the deploy script warns on any non-canonical handler of a governance Safe and the sync
  task refuses one that is the guard or the timelock on every run, but the same door opens on any
  OTHER contract a governance Safe has rights on (a token, a vault), which nothing here can see:
  `ChangedFallbackHandler` on a council, proposer, veto or guardian Safe pages (§7.7). ETH or tokens
  sent to the guard are stuck for good (no `receive`, no rescue function, by design) and nothing in
  the guard reads a balance.
- **Safe builds.** The supported set is fixed at deployment: the proxies the v1.3.0 / v1.4.1 /
  v1.5.0 factories create and the L1 and L2 singletons of those releases. A Safe created by the
  v1.1.1 factory, a non-canonical build and every future release are refused on the policy path
  (approvals and windows keep working) until a guard that knows them takes over. A singleton
  MIGRATION under the guard is the one irreversible trap left: an approved `migrateSingleton()` to a
  release whose guard-hook ABI differs would leave every later transaction reverting inside the
  pre-hook call, the exits included. The migration is therefore approved only as ONE batch that ends
  with `setGuard(guard)` (and `setModuleGuard(guard)`): the re-install runs on the NEW singleton,
  which asks its own ERC-165 question, so an incompatible release reverts the whole batch and the
  Safe stays where it was (§7.5).
- **Seats with code.** The Safe counts an owner's signature whether a key, a stored `approveHash` or
  the owner's code produced it, and an owner can acquire code after it was vetted (an EIP-7702
  delegation, a counterfactual address). The council lane refuses a new owner that has code when the
  approval is issued or executed; nothing on-chain enforces "a threshold of KEYS" afterwards (a
  per-Safe key-signatures-only flag was costed at about 430 bytes and is recorded in
  IMPROVEMENTS_V2.md): the §7.7 "owner acquired code" alert is the control, and payloads stay bounded
  by the policy either way.
- **Guard overhead.** Warm, one owner: about 47.6k gas per owner-signed transaction (49.8k with
  three, 54.2k with seven; about 2k of it is the `TransactionChecked` event), measured in `CuratorGuardGas.t.sol` at the deployed optimizer setting; a venue that keeps most of its forwarded gas and still returns success forces a Safe transaction gas limit of about 64 times the post-hook cost (measured between 0.8 M and 1.6 M gas on the live Safe depending on how the venue burns it, growing with the owner count), which Lagoon's settlement functions, returning their unused gas, never do. Cold, on the live 4-owner Safe
  (fork rehearsal, before round 8): about 81k for a single call and 87k for a two-entry batch (≈ 61-67k
  pre-check plus 20k post-check; ≈ +3.5k per extra owner); the approval path ≈ 20k, `Bypass` ≈ 19k.
  Round 8 moved these by what it added and trimmed, measured on the live Safe with the hooks called
  directly and every account cooled first (a method that overstates a real transaction by the
  accesses the Safe has already paid for, but compares like with like): a single policy call 94.3k →
  96.7k, a two-entry batch 106.8k → 103.3k (the decoder is cheaper per entry), the approval path
  19.6k → 29.3k and a window 13.6k → 19.7k. Inside a real `execTransaction` the two new reads cost
  about 2.6k (the installed-slot read, every path) and 2.2k (the handler-slot read, approval path
  only), and the code-hash pin about 1.3k warm. Budget roughly 85-95k gas on top of each curator
  transaction.

## 7. Runbook (Vetro Lagoon Safe)

### 7.1 Deploy

```bash
npx hardhat deploy --network ethereum --tags CuratorGuard
```

Deploys two contracts: `CuratorGuardTimelock` (proposers = `Vetro.curatorGuardProposers`, two
Safes; canceller = `Vetro.curatorGuardCancellers`, exactly one Safe, the trusted veto; executor =
anyone; no deployer admin: the role set is final at creation, nothing to renounce; never the council,
which the script refuses in either list; `minDelay` = `CURATOR_GUARD_TIMELOCK_DELAY`, 48 h by
default, within the contract's [1 h, 30 d]) and `CuratorGuard` with the timelock as admin
(admin-transfer delay `CURATOR_GUARD_ADMIN_DELAY`, 3 days by default, must exceed the timelock
delay) and `Vetro.curatorGuardCouncil` as council. Every topology, principal, overlap and delay check
runs BEFORE the first transaction; the timelock audit and the council-role check run after the
deploys and fail the run. The script **refuses** an empty council on a real network
(`CURATOR_GUARD_ALLOW_NO_COUNCIL=1` to override: without a council every lift of a lockdown is a 48 h
round trip), a single proposer (`CURATOR_GUARD_ALLOW_SINGLE_PROPOSER=1`), a canceller that is also a
proposer (no override: the contract refuses it too), two cancellers
(`CURATOR_GUARD_ALLOW_MULTIPLE_CANCELLERS=1`, rehearsals only), an EOA anywhere, a governance
principal that does not answer as a Safe with a threshold of at least 2 (a read that fails is a
refusal, never a pass; `CURATOR_GUARD_ALLOW_WEAK_GOVERNANCE=1`, rehearsals only; it warns on any
governance Safe whose fallback handler is neither zero nor a canonical `CompatibilityFallbackHandler`:
a handler receives every unknown call with the Safe as caller, so it must never be the guard or the
timelock), a proposer or
canceller the council owns or shares a signer with, and a proposer, canceller or council that shares a
signer with
`Vetro.lagoonCuratorSafe`, recursively through nested Safes (§6); today's governance Safe does, so a
dedicated Safe without curator keys must be configured first (`CURATOR_GUARD_ALLOW_KEY_OVERLAP=1`
downgrades the check to a warning on rehearsals only: a dev node by RPC probe that also reports
chain id 31337 or is declared with `CURATOR_GUARD_FORK=1`, so an RPC endpoint alone cannot downgrade
a refusal; a failed owner read aborts the check instead of passing it). It also refuses fewer
than two proposer Safes (`CURATOR_GUARD_ALLOW_SINGLE_PROPOSER=1` to override): every admin operation
is scheduled by a proposer, so a sole proposer that is guarded by mistake or loses its quorum leaves
the guard unremovable, unwidenable and its admin role untransferable (§7.6 step 5); a timelock delay
under one hour for a fresh timelock (no override: the contract refuses it; the usual symptom of hours
typed as seconds) or above 30 days, and a reused timelock whose live delay differs from the configured
one (`CURATOR_GUARD_ALLOW_SHORT_DELAY=1`); and it runs only against chain 1 or a rehearsal. The
overrides are read from the environment, and so from `.env`, on every run: `KEY_OVERLAP`,
`MULTIPLE_CANCELLERS` and `WEAK_GOVERNANCE` downgrade on rehearsals only, `NO_COUNCIL`,
`SINGLE_PROPOSER` and `SHORT_DELAY` downgrade on real networks too with a loud banner; unset every
`CURATOR_GUARD_ALLOW_*` and `CURATOR_GUARD_FORK` after a rehearsal. It refuses a pre-Cancun chain outright (the
guard needs EIP-1153). After deployment, and for any reused timelock (`CURATOR_GUARD_TIMELOCK`), the
timelock is audited, not trusted: its code must be this repository's build, its delay in range, its
role set, rebuilt from its `RoleGranted` logs and confirmed live with `hasRole`, exactly the expected
one (admin = the timelock only, executor = anyone only, the configured proposers and canceller, the
council nowhere; a holder the scanned logs miss is reported as a scan that starts after the grant),
and its queue empty; a mismatch refuses on a real network. After a fresh deployment the script prints
the `"guard": "<address>"` line to pin in the policy file. A verification failure sets a
non-zero exit code. Both contracts are
non-upgradeable; the script never redeploys an existing artifact (`skipIfAlreadyDeployed`); a
replacement guard is deployed under a new alias, reusing the timelock, with
`CURATOR_GUARD_ALIAS=CuratorGuard_v2 CURATOR_GUARD_TIMELOCK=<timelock> npx hardhat deploy --network
ethereum --tags CuratorGuard`.

### 7.2 Configure the policy BEFORE the Safe installs the guard

```bash
# 0. pin the deployed guard in the file first (the deploy script prints the line); outside rehearsals
#    the task refuses an unpinned file. Run every command from the repository root: the state, batch
#    and manifest files are written to the current directory.
npx hardhat curator-guard-sync --network ethereum --guard <CuratorGuard> \
  --policy policies/curator-guard/vetro-lagoon.ethereum.json --dry-run    # the diff, the queue, the simulation, the ids
npx hardhat curator-guard-sync --network ethereum --guard <CuratorGuard> \
  --policy policies/curator-guard/vetro-lagoon.ethereum.json \
  --proposer <governance Safe>        # ONE scheduleBatch on the timelock, proposed to the governance Safe
# … the Safe signs and executes the proposal, then after minDelay (anyone):
npx hardhat curator-guard-sync --network ethereum --guard <CuratorGuard> \
  --policy policies/curator-guard/vetro-lagoon.ethereum.json --execute
npx hardhat curator-guard-sync --network ethereum --guard <CuratorGuard> \
  --policy policies/curator-guard/vetro-lagoon.ethereum.json --dry-run    # expect "already in sync" and an empty queue
```

A fresh guard needs no flag. Three flags exist for the dangerous cases and must never become a
habit: `--allow-unlock` when an already configured Safe is in `Lockdown` / `Bypass` (an incident
state), `--confirm-revocations` when the diff narrows anything (a deleted line is a revocation), and
`--confirm-loosening` when an already allowed function loses a rule, widens a bound or gains
`allowValue` (the task prints the old and the new rules side by side and names the loosening). A
lift of a lockdown is scheduled as its OWN operation, chained behind the rest with `predecessor`:
the guard holds the admin's lift back for one day after any lockdown (`LOCKDOWN_COOLDOWN`), so a
batch that bundled it with the removal of a key that keeps re-locking could never land; the lift's
window spans the cooldown plus one day (`--unlock-deadline-days`, 1 to 3) instead of fourteen, and
the task prints the `cancel(opId)` calldata to use if a new incident starts while it is queued. At
`--execute` a lift needs `--allow-unlock` again only when the Safe was locked down AFTER the
operation was prepared (a new incident), and a lift the cooldown still holds back is skipped, not
failed, and lands on the next `--execute`.

Every scheduled call is wrapped in `executeBefore(deadline, …)` (`--deadline-days`, 1 to 30, 14 after
`minDelay` by default), so a batch nobody executed in time is dead. Before anything is scheduled every
call is simulated as the admin (dead on arrival is refused, a cooldown is reported with its end) and
the batch's gas is estimated (refused above 12 M, warned above 8 M: one transaction, capped by
EIP-7825). The operation ids, salts, predecessors and deadlines are persisted next to the Safe batch
file (`--execute` re-derives every id from the stored payloads, so a tampered file cannot name an
operation the chain does not hold; `--execute --op <id>` rebuilds an operation from the timelock's
own `CallScheduled` / `CallSalt` logs instead, for a second operator or a lost file, `schedule()`-made
one-call operations included, never touches the state file, and needs `--allow-unlock` for any lift
since the preparation time is unknown there); `--execute`
refuses past the deadline, skips (loudly, with the cancel calldata) an operation that contains a
call the current diff no longer wants (one call per function, so a fast-lane change to one function
never invalidates the rest; the skipped operation stays executable by anyone, so cancel it), and an
identical diff scheduled again gets a fresh id. The state file keeps every operation still in
flight and goes only when all of them are done. `OneOf` growth (a new spender, a new vault) is a
plain widening printed as `+ values`, not a loosening. The state file is keyed by chain and guard,
and a signer manifest (decoded calls, the exact `scheduleBatch` calldata and its hash, every
`hashOperationBatch` input, deadlines as dates) is written next to it on every path, rehearsals
included, for the proposer Safe's signers; a `--dry-run` walks the same path (queue, simulation,
gas, ids, deadlines) and stops before anything is written or sent; `curator-guard-verify --op <id>` gives anyone the same from the chain's logs and says
whether every decoded call is part of the diff the committed file produces right now. Before
scheduling, the task lists every pending operation on the timelock, whatever its target (timelock
self-calls and foreign targets are flagged), and refuses to pile a new one on top without
`--allow-pending`; it fails closed when the timelock's creation block is unknown (deployment record,
`--timelock-block` or `CURATOR_GUARD_TIMELOCK_BLOCK`) or the log scan fails. It also prints a
governance summary (council, guardians, pending admin transfer, standing approvals, forbidden
unwrapper hashes, the cooldown), refuses to run while the council holds a timelock role, checks that
the code at `--guard` is this repository's build and that `policy.guard` is pinned (outside
rehearsals), and says out loud when a function it re-allows was revoked on-chain earlier.
"Configured" mirrors the contract's `AdminIsGuarded` predicate (targets, guardians or a handler
requirement), so a guardian who answered an incident with revocations cannot disarm the gate. Fill
in `guardians` (Vetro's monitoring bot / on-call keys for this Safe) before applying: the file ships
with an empty list, the lint warns, and the sync provisions them. The task also warns when the Safe's live fallback handler differs from the
policy's requirement (§7.3: remove it in the same batch as the install). Then dry-run representative curator transactions
against `validateTransaction` (e.g. with
`cast call <guard> "validateTransaction(address,address,uint256,bytes,uint8)" <safe> <to> 0 <data> 0`),
including a `MultiSendCallOnly` batch copied from the Safe's history. While the live Safe still
carries the 1271-capable handler, every dry run reverts `FallbackHandlerNotAllowed` (allowed and
disallowed calls alike): validate the allowlist with the fork dry-run script, which models the
handler removal, or after install.

### 7.3 Pre-install checks and the fallback handler

- The Safe is a canonical build: `keccak256(eth_getCode(safe))` is one of the three proxy hashes and
  `keccak256(eth_getCode(masterCopy()))` one of the six singleton hashes the guard pins (the sync
  task prints the build and refuses anything else; the guard would answer `SafeNotSupported` on the
  first policy transaction). A Safe behind the v1.1.1 proxy or a custom proxy is not supported:
  migrate custody to a fresh factory-deployed Safe.
- `getModulesPaginated(0x0000…0001, 10)` returns `[]`: the guard refuses policy traffic while a module
  is linked and not hooked (`ModuleNotHooked`), which on v1.3.0 / v1.4.1 means any module. That view
  cannot see an entry PLANTED in the mapping (a `setup` initializer or an old delegatecall can write
  `modules[x]` with nothing pointing at it; such a module works and is invisible): read the Safe's
  `SafeSetup` log (`initializer` must be `0x0`, or the canonical `SafeToL2Setup`) and its history for
  any `operation = 1` to something other than a canonical `MultiSendCallOnly`; when either cannot be
  ruled out, the baseline is a fresh factory-deployed Safe (or v1.5.0 with this guard as module
  guard, where a planted module meets the allowlist).
- Guard slot `0x4a20…34c8` is zero (`getStorageAt(slot, 1)`).
- Enumerate live ERC-20 allowances granted by the Safe: `eth_getLogs` for `Approval(safe, *)` on
  each custody asset from the Safe's creation block (archive RPC or an explorer's approval
  checker), then `allowance(safe, spender)` for every spender seen; revoke any spender the policy
  does not intend (today: exactly the five vaults are expected, each at or near `uint256.max`).
- Owners / threshold are what Vetro expects (today 2-of-4). Note that after install, owner changes
  require a council (or admin) approval.
- **Fallback handler.** The policy enforces `requiredFallbackHandler = 0x0`. Approve
  `setFallbackHandler(0x0000000000000000000000000000000000000000)` (`approveTransaction(safe,
  0x0, safe, 0, data, Call, ttl)`; resetting the handler to zero is the one handler change the council
  may approve, any other handler is admin-only) and have the signers execute it right after `setGuard`
  (or before: the handler change is a self-call either way, and before install it needs no
  approval). Until it lands, every policy transaction reverts `FallbackHandlerNotAllowed`. The
  handler is NEVER the guard itself nor the Safe (the contract refuses both as a requirement; with
  the guard as handler anyone could call the hooks through the Safe: the guard then refuses to spend
  approvals or emit reports, `ForwardedHookCall`, and only a council window carries the repair). Without
  a handler the Safe cannot receive ERC-721 / ERC-1155 via safe-transfer callbacks and does not
  answer `isValidSignature`; neither is needed for Lagoon operations.

Also before install. Per vault: the ERC-1967 implementation slot holds the canonical logic, the
`DelayProxyAdmin` has nothing pending (`newImplementation() == 0`, `implementationUpdateTime() ==
2^256-1`) and the expected `delay()`, and Lagoon's registry has an owner (an ownerless registry accepts
any implementation); the sync task prints every upgradeable target with its implementation and admin.
On the Safe: enumerate the `SignMsg` and `ApproveHash` logs since creation (permanent authorisations
that wake with any signature-capable handler, §6), and check that no owner has code (`eth_getCode`,
EIP-7702 delegations included). With the handler at zero every unknown selector answers success with
empty data, so callbacks that check a return value (ERC-721 / ERC-1155 safe transfers) revert:
withdraw any position a venue would return by safe-transfer first, or require Safe's
`TokenCallbackHandler` (no `isValidSignature`) instead of zero.

### 7.4 Install

The Safe's signers execute `setFallbackHandler(0x0)` and `setGuard(<CuratorGuard>)` (self-calls,
`to = safe`; both fit in one `MultiSendCallOnly` batch, and before the guard is installed they
need no approval). The Safe checks `supportsInterface(0xe6d7a83a)` and stores the guard. From the
next transaction on, the policy is enforced. If the handler change lands after the guard, policy
traffic reverts `FallbackHandlerNotAllowed` until the approved `setFallbackHandler(0x0)`
executes, which also settles nothing in the meantime: do both in one batch. If the trap happened
anyway, the recovery order matters: the council approves the reset (seven-day approval, no timelock)
and the signers execute it; if settlement cannot wait even for that, open a council `bypass` first,
let the signers execute the reset inside the window (allowed there too), then `enforce`. Never issue the
approval while a window is open (`SafeInBypass`) and never open a window after issuing it (the epoch
bump voids it). Verify with `getStorageAt` (guard slot, handler slot) and by simulating one allowed and
one disallowed call through `validateTransaction`. The sync task refuses a Safe that is not a
canonical build and warns when the live handler differs from the requirement, when the Safe has
enabled modules (policy traffic then reverts `ModuleNotHooked`) and when its guard slot already
points at another guard. If the guard was installed before the policy sync executed (§7.2), the Safe sits in
`Lockdown` with an empty allowlist: a council `enforce` is not a fix (every call is then
`FunctionNotAllowed`); open a council `bypass` until the sync lands, and schedule the lift batch
(`--allow-unlock`, one-day execution window) when the proposer Safe can sign the same day.

### 7.5 Day-two operations

- **Add a venue**: edit the policy file (target, selectors, rules per §5), `curator-guard-sync`.
- **Add a venue** is a widening: it goes through the timelock (`minDelay`), is visible to everyone
  as a `CallScheduled` event, and the canceller Safe (never the council) can `cancel` it before it
  executes. Cancel what you do not execute: the `executeBefore` wrapper makes a stale batch dead
  after its deadline, but a cancelled one is cleaner.
- **Remove / emergency**: `lockdown(safe)` (admin, council or a guardian of the Safe) is the default
  response: it freezes the curator immediately, ends any `Bypass` window and keeps approved one-offs
  executable (pre-staged `pause()` payloads, an approved migration); the council reverses it with
  `enforce`. `lockdownAndRevoke(safe)` (same callers) is the response when the signers or a standing
  approval are the threat: it also voids every approval in the same transaction, so nothing at all
  runs for that Safe afterwards; council-issued approvals can be re-issued at once, admin-issued ones
  only after a timelock delay. `revokeTarget` / `revokeFunction` for surgical narrowing. Lift with
  `enforce(safe)` (the council at once; the admin after `minDelay` and never within a day of the last
  lockdown; the sync task schedules it with `--allow-unlock` as its own chained operation). A compromised responder key is removed on the fast lane
  (`setGuardian(safe, key, false)` / `setDeploymentGuardian(key, false)`, council or admin).
- **One-off action outside the policy** (owner change, threshold change, a swap, `initiateClosing`,
  a Lagoon role update): `approveTransaction(safe, executor, to, value, data, operation, ttl)` with
  `executor = 0x0` for the signers (or the module address for a module-driven action) and the exact
  calldata the signers will submit (a batch is approved as one delegatecall payload, admin only),
  `ttl` in seconds, at least one hour (`InvalidDuration` otherwise: `7` typed for seven days would
  be dead on arrival after the timelock; for a timelocked approval the clock starts when anyone
  executes the operation, so give admin approvals days, not hours); the signers execute once. The **council** handles owner
  management (never a threshold below 2, the contract refuses it; never one equal to the owner count,
  one lost key then locks the Safe for good; a new owner must be a plain key: the contract refuses an
  account with code on the council lane, checked when the approval is issued or at execution inside a
  window, and since an address can acquire code later through CREATE2 or an EIP-7702 delegation the
  monitoring rule of §7.7 stays necessary), `disableModule`, `setFallbackHandler(0)` and venue
  one-offs (plain calls only) within 7 days, immediately; the **admin** (timelocked) handles batches
  and any other delegatecall, `setGuard`, `setModuleGuard`, `enableModule` (never on a v1.3.0 /
  v1.4.1 Safe: an enabled module there is unguarded and can remove the guard silently; modules need
  v1.5.0 with `setModuleGuard`), any other fallback handler, and standing payloads of up to 180 days
  (pre-staged `pause()` per vault; a multi-vault emergency is five council approvals and five signing
  rounds, a short council window, or one pre-staged admin batch). `executor` is `0x0` for the
  signers, never the Safe's own address (that binds the approval to the module path and the signers'
  transaction fails on the policy). Approval ids are epoch-bound: an id printed at scheduling time is
  stale once a window or a revocation bumped the epoch, so compute it at execution
  (`computeApprovalId`) or read it from `TransactionApproved`; an approval scheduled before a bump is
  issued, valid, in the new epoch. A delegatecall approval is also bound to the CODE at its target:
  approve after the target is deployed and expect the approval to die if that code changes. The
  target must carry code whenever calldata is sent (`InvalidTarget` when the approval is issued:
  a typo'd address would otherwise "succeed" and spend the one-off), and an approved batch into the
  canonical `MultiSendCallOnly` must be canonically encoded and may not address the guard
  (`MalformedMultiSend` / `GuardCallNotAllowed` at use, approval kept): build batches with the Safe
  tooling, never by hand, and never review one through a decoder alone (the SDK's decoder right-aligns
  a truncated value word and shows 1 wei for a payload that moves 2^64). `safeTxGas` is free: a
  failed approved execution reverts the whole Safe transaction either way (GS013 with
  `safeTxGas = 0`, `ApprovedExecutionFailed` otherwise), so the approval is never lost. Confirm an
  approved Safe self-call by the SAFE's own event (`ChangedGuard`, `ChangedModuleGuard`,
  `ChangedMasterCopy`, `EnabledModule`, …), never by `ExecutionSuccess` plus
  `TransactionChecked(Approval)` alone: with the handler at zero, a selector the current singleton
  does not implement is a silent success that spends the approval.
  `revokeApproval(id)` cancels one unused approval; `revokeAllApprovals(safe)` (admin, council or
  guardian) voids all of them, `lockdownAndRevoke(safe)` does that and freezes the Safe. Approvals are
  refused while the Safe is in `Bypass`.
- **Never on the council lane.** These are venue calls the contract cannot tell from a harmless
  one, and each changes who controls a vault or its code. On a vault: `updateSafe`,
  `transferOwnership`, `renounceOwnership`, `updateSuperOperator`, `updateValuationManager`,
  `updateSecurityCouncil`, `updateWhitelistManager`, `updateFeeReceiver`, `updateRates`,
  `switchAccessMode`, `resetHighWaterMark`, and `updateTotalAssetsLifespan` / `setSyncMode` (they open
  Lagoon's synchronous paths, which pay straight out of the Safe at the last settled NAV). On a
  `DelayProxyAdmin`: `submitImplementation`, `upgradeAndCall`, `submitDelay`, `transferOwnership`,
  `renounceOwnership`. An approved NAV call is a NAV that Vetro co-signed: one settlement per
  approval pair, one-hour TTL, revoke leftovers.
- **Safe upgrade (v1.4.1 → v1.5.0)**: approve ONE batch, as a delegatecall into the canonical
  `MultiSend` (not `CallOnly`: the migration is a delegatecall entry), in this order:
  `[DELEGATECALL SafeMigration.migrateSingleton(), CALL safe.setGuard(guard), CALL
  safe.setModuleGuard(guard)]`. Never `migrateWithFallbackHandler()` (it reinstalls the canonical
  signature-capable handler). The two re-installs run on the NEW singleton, which asks its own
  ERC-165 question about its own hook ABI: a release this guard cannot serve reverts the whole batch
  (GS300 / GS301), the Safe stays where it was and the approval is kept; a compatible one lands the
  migration and both guards in one transaction. Never approve the migration alone (a release with a
  different hook ABI would brick the Safe for good: every later transaction, the exits included,
  reverts inside the pre-hook call) and never `setModuleGuard` before the migration (on v1.4.1 with
  the handler at zero the call is a silent success that spends the approval and sets nothing). The
  target release must be one the guard pins (`SafeNotSupported` on the policy path otherwise: deploy
  the guard that knows it first and name THAT guard in the batch). Check first that no owner is a
  contract relying on legacy EIP-1271 (it becomes a dead seat on v1.5.0), and confirm by
  `ChangedMasterCopy`, `ChangedGuard` and `ChangedModuleGuard`.
- **Fork dry run** of the whole tooling on the production topology: `FORK_NODE_URL=<rpc> npx hardhat
  run scripts/curator-guard-fork-dryrun.ts --network hardhat` deploys the timelock + guard, schedules
  the policy through the timelock as the impersonated proposer, refuses an early execute, warps past
  `minDelay`, executes, re-syncs (expects no drift), models the signers' handler removal + install,
  dry-runs representative curator calls (non-zero exit code on an unexpected allow), and ends with
  an incident drill (a stand-in council locks the Safe down, the lift is scheduled as its own chained
  operation, `curator-guard-verify` decodes it from the logs, a re-lock holds it back, it lands after
  the cooldown). The run exits non-zero until its last line prints "incident drill complete": a
  failing upstream read inside a transaction makes hardhat stop silently, so treat anything without
  that line as failed and use an archive RPC. Against a non-archive upstream (a local anvil fork on a
  free public RPC) also set `FORK_BLOCK_NUMBER` to the upstream head; such a fork keeps its upstream
  for about 15 to 20 minutes. The rehearsal passes only through rehearsal-only downgrades (key
  overlap, a stand-in veto key): it proves the scripted flow, not that the committed address book
  passes the mainnet preflights.
- **After a Safe-batch sync** (the proposer Safe executed `scheduleBatch`), wait `minDelay`, run
  the same command with `--execute` (anyone may execute), then re-run without flags and expect
  "Policy already in sync" AND "no operation pending" (every run prints the timelock's queue,
  whatever the target: a queued role change, window, approval or abandoned batch is executable by
  anyone). The task refuses to start while a stale `safe.batch.tmp.json` exists, and refuses to
  schedule while another operation is still pending on the timelock: cancel what is abandoned.
  `--allow-pending` schedules the NEW diff, which re-includes every unapplied call of a pending sync
  operation and supersedes it: execute the new one and cancel the old one; if the old one is executed
  first, the new one is skipped as "no longer wanted" although anyone can still execute it, so cancel
  it. `--execute` runs a stored operation as long as every call in it is still wanted (extra calls
  caused by a fast-lane change during the delay are picked up by the next sync). Before any lift (`enforce`, by the council or by a queued
  operation) collect the lift-time cards: a fully signed, unexecuted Safe transaction is executable
  by anyone the moment the guard allows it (burn its nonce first, through a council-approved empty
  self-call), and two ready operations for one Safe can be executed by anyone in the harmful order
  (an approval, then a window whose epoch bump voids it), so cancel what is not meant to run.
  Never bundle `lockdownAndRevoke` with an approval or a lift for the same Safe in one operation: the
  lockdown re-arms the cooldown and the batch can never execute.
- **Sync mode / lifespan.** If `totalAssetsLifespan` is ever set above zero (sync deposits), the
  curator needs `expireTotalAssets()` (`0x927b15df`) before re-proposing NAV inside the lifespan:
  add it to the policy at the same time.
- **Committing.** The Safe sources are unstaged git submodules; when committing run
  `git add .gitmodules lib/safe-smart-account lib/safe-smart-account-v1.5.0` so CI checkouts
  (`submodules: recursive`) get them, and `.github/workflows/curator-guard.yml` runs the suites.
- **Replace the guard**: deploy the new guard under a new alias reusing the timelock
  (`CURATOR_GUARD_TIMELOCK=<timelock>`), sync the policy against it (functions, handler requirement,
  per-Safe guardians), check `hasRole(COUNCIL_ROLE, council)` (the deploy script passes the council
  to the constructor; if it is missing, schedule the `grantRole` the script prints), then have the admin approve
  `setGuard(newGuard)` **on the currently installed guard** (approvals live in the guard that will check
  the transaction; one placed on the new guard is a stray to revoke): no task builds that operation,
  so schedule it by hand as a one-call `scheduleBatch([installedGuard], [0],
  [executeBefore(deadline, approveTransaction(safe, 0x0, safe, 0, setGuard(newGuard), Call, ttl))],
  predecessor, salt, minDelay)` from a proposer, or with `schedule(...)` (both decode in
  `curator-guard-verify --op` and run with `--execute --op`; an operation scheduled by hand with
  salt 0 rebuilds too). The post-check tolerates the change only on the approved transaction. Safe
  v1.5.0: the swap is TWO slots, and each self-call is checked by whichever guard sits in the
  transaction-guard slot at that moment, so approve ONE `MultiSendCallOnly` batch
  `[setModuleGuard(newGuard), setGuard(newGuard)]` on the installed guard (with two separate
  approvals and `setGuard` executed first, the second is checked by the NEW guard, its approval on the
  old one is a stray, and the module path stays on the old guard). While that approval is live it is an EXIT from any
  `lockdown` of the installed guard: `lockdown` keeps approvals, so the quorum can execute the swap
  through a lockdown and continue under the replacement, which nobody locked and whose event
  stream nobody watches yet. During a migration responders therefore answer with
  `lockdownAndRevoke` on the installed guard AND `lockdown` on the replacement, the replacement
  stays in `Lockdown` (allowlist synced) until the swap is confirmed and the council then `enforce`s
  it, and bots follow the Safe's `ChangedGuard` and `ChangedModuleGuard` and watch both guards. A
  guard answers its hooks only on the path where the Safe has it installed (`GuardNotInstalled`
  otherwise), so a replacement is inert until the swap and the old guard from the swap on; still do
  not pre-stage approvals on a replacement before it is installed (defence in depth, and an approval's
  clock runs from the moment it is issued). **Pre-swap checklist, before the approval is scheduled**
  (one paste error here stops settlement: an unsynced guard is `Lockdown`, has no unwrapper and no
  per-Safe guardians; with the council role on it, a constructor argument, a council `bypass` restores
  settlement at once but only as plain calls, `updateNewTotalAssets` and `settleDeposit` sent
  separately, since the batch needs the unwrapper the sync registers; otherwise the vaults wait for the
  timelocked sync or for an admin approval of `setGuard(back)`): `newGuard.mode(safe) == Enforced`, `targets(safe)` non-empty,
  `hasRole(COUNCIL_ROLE, council)`, `hasRole(GUARDIAN_ROLE, bot)` for every deployment-wide responder,
  `guardians(safe)`, `modules(safe)`, the native-transfer targets and `requiredFallbackHandler(safe)`
  as in the file, `isUnwrapperCodehash(h)` equal on both guards for the three canonical hashes (a
  hash forbidden on the old guard is allowed again on a fresh one), `validateTransaction` passes for
  a real settle payload (the dry run works before adoption; the live hooks do not). After the swap:
  the guard slot (and on v1.5.0 the module-guard slot `0xb104…9947`) holds the new guard, then
  `lockdownAndRevoke` on the old guard.
- **Remove the guard** (decommission): the admin approves `setGuard(0)` (the council cannot); then
  `lockdownAndRevoke` on the removed guard so a re-install by mistake is fail-closed and cannot revive
  unexpired approvals.
- **Admin hand-over (timelock → new timelock or DAO executor)**: the current admin schedules
  `beginDefaultAdminTransfer(newAdmin)` (refused for `address(0)`, for the council and for any address
  that carries a policy: `AdminIsGuarded`); after `defaultAdminDelay` (3 days; between 1 and 30 days
  once changed) the new admin calls `acceptDefaultAdminTransfer` (itself a scheduled operation when
  the new admin is a timelock; the predicate is re-checked at acceptance) within 30 days of the
  schedule (`DeadlinePassed` afterwards: begin again); `cancelDefaultAdminTransfer` aborts a pending
  hand-over. A council can hold the acceptance back for as long as it holds the role (§4): evict it in
  one batch and accept inside the 30 days, or begin again. Roles, policies and live approvals survive the hand-over; the proposers and cancellers of
  the old timelock do not carry over. A successor timelock brings its QUEUE with it: an operation
  scheduled on it before it is the admin matures with no power and becomes executable by anyone in
  the block of the acceptance (an `approveTransaction(setGuard(0))` scheduled months earlier removes
  the guard with no delay anyone could use). Prefer a FRESH `CuratorGuardTimelock` as successor;
  otherwise read its `CallScheduled` / `Cancelled` / `CallExecuted` logs since creation and have its
  canceller cancel everything pending before the hand-over begins, and again before acceptance. Keep
  `defaultAdminDelay` above the timelock's `minDelay`: raise the guard's admin delay BEFORE raising
  `minDelay` to or above it, or a hand-over that slipped past the veto is accepted before the
  scheduled cancel is ready.
- **Council / proposer / guardian rotation**: `grantRole` / `revokeRole` of `COUNCIL_ROLE` are
  timelocked admin operations; a council NEVER gets a timelock role (`CANCELLER_ROLE` or
  `PROPOSER_ROLE`: it could veto or schedule its own removal, and the sync task refuses to run while
  it holds one). A council replacement is `[revokeRole(old), grantRole(new), lockdownAndRevoke(safe)]`
  per Safe, never bundled with a lift (§6). A guard role is never granted to `address(0)`, to the
  admin or to an address the admin configured as a Safe (`AddressIsNull` / `AdminIsGuarded`: paste the
  council Safe, not the curator Safe). Proposer and canceller changes and `updateDelay` are
  scheduled self-calls of the timelock: grant the successor first, then revoke (the contract keeps
  the last proposer and the last canceller, refuses to drop the open executor or its own admin role,
  never grants that admin role to anyone else nor a gated role to itself, clamps `getMinDelay()` to
  [1 h, 30 d] and refuses an `updateDelay` outside that range, an operation delay other than the live
  `getMinDelay()` and calldata for a target without code when they are PROPOSED, so a value typed in the wrong unit or
  an address typed wrong fails at `schedule`, not after the delay; a proposer is never granted the
  veto and the veto never the proposer role,
  so a rotation of the veto Safe is `[grantRole(CANCELLER_ROLE, new), revokeRole(CANCELLER_ROLE,
  old)]` in one batch, which the old veto can cancel: its consent is part of the design; a full
  rotation is one batch of the three grants followed by the three revokes). Only the veto Safe can
  clear a pending operation, a dead one included (an always-reverting operation stays Ready for
  ever), and cancelling a predecessor does not cancel its successor: cancel chained operations as a
  pair, or a proposer re-schedules the identical predecessor and the successor fires. Keep
  exactly one canceller; the count is not enforced on-chain, so page on any
  `grantRole(CANCELLER_ROLE, …)`. Deployment-wide guardians:
  `setDeploymentGuardian(key, true | false)` by admin or council (never managed by policy files);
  per-Safe guardians: the policy file (a key the council added on the fast lane must be added to the
  file before the next sync, or that sync strips it: the task warns). Owner changes the council
  approves are order-sensitive and point-in-time: `changeThreshold` then `removeOwner` is not
  `removeOwner` then `changeThreshold`, a codeless address can be a dead seat or a typo and no guard
  power reopens an N-of-N Safe, so the council approves one owner change at a time and requires a
  signature from every new owner key first; the no-code rule is checked when the approval is issued
  or at execution inside a window, and an address can acquire code later, so the monitoring rule of
  §7.7 stays the control.
- **Removing a module** (Safe v1.5.0 automation): a guardian's `setModuleAllowed(safe, module,
  false)` is a complete switch for that key in every mode, admin and council windows included: the
  module can neither make policy calls nor spend an approval bound to it, council- or admin-issued,
  until it is allowed again (approvals are kept, not voided, and come back with the allowlisting:
  revoke them too if the key is gone for good, and `disableModule` it on the Safe through a council
  approval). A council window opened on a locked Safe lets ALLOWLISTED modules run under the policy
  for its duration: when the automation is the suspect, remove it from the allowlist first.
- **Vesper keepers during a lockdown**: `rebalance` keeps working (`requestRedeem` is try/catch,
  `instantLiquidity` is idle plus claimable), but it may still `requestDeposit` idle into a vault whose
  curator cannot settle; pause keeper rebalances or `cancelDeposit` for the duration, and set the pool
  debt ratio to zero if the freeze is expected to last.
- **Fork rehearsals**: a local anvil fork on a free public RPC loses its upstream state window after
  ~25 minutes (archive reads then fail with HTTP 403); restart the fork right before a rehearsal or use
  an archive RPC.

### 7.6 Recovery when the guard misbehaves

1. `bypass(safe, duration)`: the council immediately for up to 7 days, the admin through the
   timelock for up to 180 days (wrap it in `executeBefore`). Opening the window voids every
   outstanding approval (epoch bump), none can be issued while it is open, and the policy is off for
   that Safe (no snapshot). A council window still refuses every self-call outside the council's
   allowlist (owner management, `disableModule`, `setFallbackHandler(0)`, the empty rejection call),
   any delegatecall but a registered `MultiSendCallOnly`, a gas refund, any module outside the
   allowlist, and on the module path the policy itself (a council window relaxes the owner-signed
   path only); an admin window checks nothing further on either path but the module allowlist (the
   guard itself stays unreachable as a call target; allowlist, in the same timelock batch, the
   module the recovery needs). Curator operations resume immediately. When the window expires the Safe reads as `Lockdown`: renew
   (`bypass` again) or `enforce` before that. A council `bypass` issued while an admin window is open
   replaces it with a (shorter, limited) council window: coordinate, or the council's call interrupts
   an admin-window guard swap.
2. Prepare the fix (new guard), configure it, and have the signers execute `setGuard(newGuard)`:
   inside an admin window no approval is needed. A council window can never carry the swap (the
   council cannot weaken the Safe, and no approval can be issued while any window is open), so the
   path is: schedule the admin approval of `setGuard(newGuard)` on the timelock while the council
   window keeps the curator working, then `enforce` and execute the approval, or let the admin open
   its own window. Afterwards `lockdownAndRevoke` the old guard, so a re-install by mistake is
   fail-closed and cannot revive unexpired approvals.
3. If only one transaction is affected, prefer an approval over Bypass. Leaving Bypass is
   `enforce(safe)` (council or admin); approvals can be issued again from that moment.
4. `SafeConfigUnreadable(safe)` on every policy transaction (and in `validateTransaction`): the Safe's
   own `getOwners()` / `getStorageAt` no longer answer, in practice an owner list longer than
   `ownerCount` after a storage-writing delegatecall or module (nothing the policy allows can do that;
   a Safe migration or a Safe bug could). The Safe is not frozen: approvals and Bypass windows never
   read the configuration, so the curator keeps settling through a council window or per-transaction
   approvals while the repair is prepared. The repair itself is a storage write (the Safe's own owner
   functions move the count and the list together, so they cannot re-align them): an admin-approved
   delegatecall into a one-off fixer (a generic one that walks the owner list and writes its length,
   not a hard-coded count), or a Safe migration, both through the timelock. Windows and approvals are
   exclusive (`SafeInBypass`), so the order is: a council window keeps settling (any call passes there,
   the signers are trusted for its duration; when they should stay constrained, use council approvals
   of the plain `updateNewTotalAssets` and `settleDeposit` calls instead, one Safe transaction each,
   since the council cannot approve the `MultiSendCallOnly` batch), schedule the admin approval of the
   fixer while the window is open, `enforce` right before executing it (executing the timelock
   operation while the window is open reverts `SafeInBypass`; the operation stays executable until its
   `executeBefore` deadline; policy traffic reverts `SafeConfigUnreadable` from the `enforce` on),
   signers run the fixer, verify with `validateTransaction`. Expect Safe{Wallet} and the Transaction Service to fail to load
   such a Safe (both call `getOwners()`): collect signatures and send `execTransaction` by CLI. Before
   any of that, rule out plain gas starvation: a read that runs out of its 63/64 gas share surfaces as
   `SafeConfigUnreadable` too; if an `eth_call` of `getOwners()` succeeds, the Safe is fine and the
   transaction only needs a higher gas limit. On the live Safe (the deployed singletons, v1.3.0 to
   v1.5.0, are solc 0.7.6 builds) the failing owner read hits the `INVALID` opcode and burns all the
   gas it was given, so every failed policy attempt costs the transaction's whole gas limit: diagnose
   with `eth_call` / `validateTransaction`, do not retry blindly.
   An `ownerCount` LARGER than the list is readable (the array is zero-padded) and passes for a small
   excess; a count corrupted to the tens of thousands fails the policy hook WITHOUT data (the guard's
   copies of the megabyte answer run out of gas) and the approval and window exits hold as before;
   the shorter count is unreadable.
5. A proposer Safe that cannot propose: it installed this guard on itself by mistake (unconfigured,
   so `Lockdown`), or it lost its quorum. With a guarded proposer the council opens a window on it,
   the proposer schedules `executeBefore(deadline, approveTransaction(proposer, 0, proposer, 0,
   setGuard(0), Call, ttl))` from inside the window (a venue call), the delay passes, the council
   runs `enforce` (executing while the window is open reverts `SafeInBypass`; the operation stays
   executable), the operation executes and the proposer's signers run the approved `setGuard(0)`.
   With a SECOND proposer no window is needed: it schedules the same approval, and the guarded
   proposer's signers execute `setGuard(0)` once it lands. Without a second proposer and without a
   council, or with a sole proposer that lost its keys, nothing can
   ever be scheduled again: the guard stays as it is forever (no removal, no widening, no admin
   hand-over). Hence two proposer Safes (§7.1) and a `ChangedGuard` alert on every proposer and
   council Safe (§7.7).
6. `SafeNotSupported(safe)`: the Safe's proxy or singleton code is not a build this guard pins (a
   migration to a newer release, a non-canonical Safe, a singleton swapped in context). Approvals and
   windows keep working. If the Safe was migrated on purpose, deploy a guard that knows the release
   and swap to it (admin approval of `setGuard`, or an admin window meanwhile); if not, treat it as an
   incident: `lockdown`, then find what moved slot 0.
7. `ModuleNotHooked(module)`: a module is linked that this guard does not hook. v1.3.0 / v1.4.1: a
   council approval of `disableModule(prev, module)` (the first module's `prev` is the sentinel
   `0x…01`). v1.5.0: an admin approval of `setModuleGuard(guard)`, or the council's `disableModule`.
8. `GuardNotInstalled(safe)`: the hook was called on a guard that is not in the Safe's slot for that
   path. Seen by the signers only when a v1.5.0 swap moved one slot and not the other (the module
   path is then still on the old guard): finish the swap (§7.5), do not retire the old guard before
   both slots moved.

### 7.7 Monitoring

Index `TransactionChecked(safe, txHash, path, outcome)` emitted by the guard (filter on the emitter:
a venue can emit an event with the same signature): exactly one per Safe transaction that passed
both hooks (owner path: `txHash` is the `safeTxHash`, so it joins directly with the Safe's
`ExecutionSuccess` / `ExecutionFailure` and with the Transaction Service; module path: the payload
hash `keccak256(abi.encode(safe, module, to, value, keccak256(data), operation))`), `outcome`
`Policy` / `Approval` / `Bypass`. `safe`, `txHash` and `outcome` are topics (`topics = [sig, safe, null, 2]`
filters every `Bypass` report server-side; `ModeUpdated` likewise carries `mode` as a topic), `path`
is the data word. Log adjacency: on the owner path the report is the log immediately AFTER the
Safe's `ExecutionSuccess` / `ExecutionFailure` of the same hash (which is also where `success`
lives: the report does not carry it); on the module path it is the log immediately BEFORE
`ExecutionFromModuleSuccess` / `ExecutionFromModuleFailure(module)`. On the module path the hash is a payload hash, not unique per execution
(identical module payloads share it, and v1.5.0's `ExecutionFromModuleSuccess` /
`ExecutionFromModuleFailure` carry no hash): join and count module reports by log position inside the
transaction, never by hash. Inside an admin-opened window batch entries and delegatecalled code are not
decoded, so a `Bypass` report seen there is not authoritative; `ModeUpdated` is the signal. Alert
when a Safe sees more than two council windows (`ModeUpdated` with `Bypass` and `councilBypass`) in
thirty days: windows renew without bound and every renewal voids the admin's standing approvals. Count
`Policy` outcomes against the expected settlement cadence, alert on every
`Bypass` outcome (and on a `Policy` outcome paired with `ExecutionFailure`: a venue call that failed
under `safeTxGas != 0`), and treat an `Approval` outcome as the consumption of the matching
`ApprovalConsumed`. Then `FunctionAllowed` (carries the full rule list; it REPLACES the rules, but a
`OneOf` set persists while a `OneOf` rule on its word is kept: apply `AllowedValueAdded/Removed` in
log order and never reset a set on `FunctionAllowed`), `FunctionRevoked` (drops every `OneOf` set of
the function at once: no per-member `AllowedValueRemoved` follows, so an indexer clears them here),
`AllowedValueAdded/Removed`, `NativeTransferUpdated`, `ModeUpdated` (carries the Bypass window end; it
may repeat the current mode, and its order relative to `ApprovalsRevoked` differs between `bypass`
and `lockdownAndRevoke`; the admin's cooldown ends one day after the block timestamp of the last
`ModeUpdated(safe, Lockdown)`, whatever mode logs follow),
`RequiredFallbackHandlerUpdated`, `TransactionApproved` (carries the full calldata, the absolute
expiry and the epoch), `ApprovalConsumed`, `ApprovalRevoked` (it may name a record that was already
void or expired: the live set is what `approvalExpiry` reports), `ApprovalsRevoked` (also emitted by
every `bypass` and by `lockdownAndRevoke`), `MultiSendUnwrapperUpdated` and `ModuleUpdated` (emitted
only when the set changed), `UnwrapperCodehashUpdated` (only ever for one of the three seeded hashes;
on `false` the response is ONE council batch `[setUnwrapperCodehash(h, true),
setDeploymentGuardian(key, false)]`, and a pending registration needs no rescheduling after it),
`GuardianUpdated` (per Safe), `RoleGranted` / `RoleRevoked` (council and deployment-wide guardians),
`DefaultAdminTransferScheduled` / `DefaultAdminTransferCanceled` / `DefaultAdminDelayChangeScheduled` /
`DefaultAdminDelayChangeCanceled` / `RoleAdminChanged`, on the timelock `CallScheduled` / `CallSalt` /
`CallExecuted` / `Cancelled` / `MinDelayChange` (it reports the RAW argument: the effective delay is
`getMinDelay()`, clamped to [1 h, 30 d]) / `RoleGranted` (a new proposer or canceller; page the
canceller on any `CallScheduled` whose target is the timelock itself or a foreign contract, or whose
payload carries `grantRole` / `revokeRole` / `updateDelay` / `beginDefaultAdminTransfer`: queued role
grants are not held back by the cooldown, so after a lockdown review and cancel them too), on the
Safe `ChangedFallbackHandler` (also on every council, proposer, veto and guardian Safe: a handler
that is the guard or the timelock would make that Safe's role public, §6),
`RoleRevoked` (a proposer or the veto losing its role), on the
Safe `ChangedGuard` and `ChangedModuleGuard` (on the curator Safe, and on every proposer, veto and
council Safe: a guarded proposer cannot schedule anything and a guarded veto cannot cancel, §7.6
step 5; after a v1.5.0 swap both must name the new guard), `ChangedMasterCopy`, `EnabledModule`
(on a v1.3.0 / v1.4.1 Safe an enabled module is
unguarded, whatever approved it), `AddedOwner`/`RemovedOwner`, `ChangedThreshold`,
`ExecutionSuccess`/`ExecutionFailure`, and on each vault's
`DelayProxyAdmin` the upgrade submission event plus `LogicRegistry` ownership changes (a
registry without an owner accepts any implementation). On the Safe also `SignMsg` and `ApproveHash`
(permanent, dormant authorisations, §6) and any owner acquiring code. On a v1.3.0 Safe the
configuration events carry their address in `data`, not in a topic (same signature hash): decode from
`data` when `topics.length == 1`. On each vault:
`NewTotalAssetsUpdated` without `TotalAssetsUpdated` in the same transaction (an epoch closed and left
unsettled), `RatesUpdated`, `SafeUpdated`, `ValuationManagerUpdated`, `SecurityCouncilUpdated`,
`SuperOperatorUpdated`, `WhitelistManagerUpdated`, `FeeReceiverUpdated`, `OwnershipTransferStarted` /
`OwnershipTransferred`, `GuardrailsUpdated` / `GuardrailsStatusUpdated`, `AccessModeUpdated`,
`TotalAssetsLifespanUpdated`, `SyncModeUpdated`, `Paused` / `Unpaused`, `StateUpdated`; each must sit
in a transaction that also carries the guard's `TransactionChecked` for the curator Safe, otherwise a
role has left the Safe: `lockdown` and page. Key every alert on receipts, never on simulations
(`simulateAndRevert` lets anyone run the hooks as the Safe in a frame that always reverts). Send
guardian and council incident transactions through a private relay: a `lockdown` in the public
mempool is visible to the signers it is aimed at. After any lockdown, cancel the queued lifts,
windows and approvals that should not survive it within the one-day cooldown. Alert on any widening and on any
`Bypass`. A guardian bot that calls `lockdown` (or `lockdownAndRevoke` when standing approvals are
part of the threat) on an unexpected widening of `approve` spenders or on a Safe owner-set change is
cheap and effective. Correlate
`ApprovalConsumed` with the Safe's `ExecutionSuccess` before treating a one-off as done. During a
Bypass window also watch `AddedOwner` / `RemovedOwner` / `ChangedThreshold`: owner rotation is
unchecked there by design.

**Reconstructing a Safe's policy from views**: `targets(safe)` → `selectors(safe, target)` (left-aligned
`bytes32` words) → `functionPermission(safe, target, selector)` → `allowedValues(safe, target, selector,
wordIndex)` for every `OneOf` rule (pass the stored `wordIndex`, tail flag included; the view reads
the function's current generation); `isNativeTransferAllowed(safe, target)` per target;
`multiSendUnwrappers(safe)`, `modules(safe)`, `guardians(safe)`, `requiredFallbackHandler(safe)`,
`mode(safe)` / `bypassWindow(safe)` / `lockedAt(safe)`, `approvalEpoch(safe)`,
`isUnwrapperCodehash(hash)`, `isGuardian(safe, account)`, `VERSION()` (2). Live approvals and role members are not enumerable on-chain: index
`TransactionApproved` / `ApprovalConsumed` / `ApprovalRevoked` / `ApprovalsRevoked` and
`RoleGranted` / `RoleRevoked`.

### 7.8 What the curator's signers will see

| Revert | Meaning | Who fixes it |
|---|---|---|
| `SafeLockedDown` | the Safe is in `Lockdown` (incident, fresh guard, or an expired `Bypass`) | council `enforce`, or an approval for the one transaction |
| `FunctionNotAllowed` / `ValueNotAllowed` / `NativeTransferNotAllowed` | target, selector, native value or plain transfer not in the policy | policy change through the timelock, or a council / admin approval |
| `ParamRuleViolated` / `ParamOutOfRange` | an argument outside its rule (e.g. `approve` to a spender other than the vault), or calldata too short for a rule | fix the payload; or a policy change |
| `SelfCallNotAllowed` | a Safe self-call (owner rotation, threshold, guard, modules, handler) | council approval (owner management, `disableModule`, `setFallbackHandler(0)`), admin approval (`setGuard`, `setModuleGuard`, `enableModule`, any other handler) |
| `GuardCallNotAllowed` | the Safe addressed the guard itself, at top level or as a batch entry (an approved canonical batch included) | nothing: the guard can never be a target, not even by approval (`InvalidTarget` at top level); remove that entry |
| `DelegateCallNotAllowed` / `UnwrapperCodehashNotAllowed` / `MultiSendDelegateCallEntry` / `MalformedMultiSend` / `EmptyMultiSend` | a delegatecall to anything but the canonical `MultiSendCallOnly`, a forbidden build, an entry whose operation byte is not `0` (a delegatecall entry, or any other value), a non-canonical encoding (wrong head offset, trailing bytes, an entry cut short, a zero `to`) or an empty batch; an APPROVED batch must be canonically encoded too | use the Safe{Wallet} batch builder (plain calls only); council / admin re-allow a forbidden canonical hash |
| `FallbackHandlerNotAllowed` | the Safe has a fallback handler that is not the one the policy names (none is always fine; install-ordering trap, §7.3) | council approves `setFallbackHandler(0)`, signers execute |
| `GasRefundNotAllowed` | "Safe pays" / relayer gas mode (also refused inside a council window) | sign with `gasPrice = 0` |
| `CouncilBypassLimit` (inside a council window) | a self-call outside the council's allowlist (anything but owner management, `disableModule`, `setFallbackHandler(0)`) | council `enforce` first (or let the window lapse), then an admin approval through the timelock (approvals are refused while any window is open: schedule during the window, `enforce`, then execute), or the admin replaces the window with its own |
| `ModuleNotAllowed` (any mode, windows included) | a module the policy does not allow | admin `setModuleAllowed` (timelocked) |
| `NotAContract` | an allowlisted function call to a target that has no code (a typo'd or not-yet-deployed venue) | fix the address; a counterfactual venue becomes callable once deployed |
| `SafeNotSupported` | the Safe's proxy or singleton code is not a build the guard pins | ask Vetro (§7.6 step 6): approvals and windows still work |
| `ModuleNotHooked` | a module is linked on the Safe that the guard does not hook | council approval of `disableModule` (v1.5.0: or admin approval of `setModuleGuard(guard)`), §7.6 step 7 |
| `GuardNotInstalled` | a hook reached a guard that is not in the Safe's slot for that path (a half-finished v1.5.0 swap) | finish the swap (§7.6 step 8) |
| `ForwardedHookCall` | the Safe's fallback handler is the guard itself: no approval is spent and no report emitted while it is (anyone could otherwise drive the hooks through the Safe) | a council window, `setFallbackHandler(0)` inside it, `enforce`, then re-issue the approvals the window voided |
| `LockdownCooldown` (admin operations only) | the admin tried to enforce, open a window or approve within a day of a lockdown of that Safe | wait out the day, or the council acts now; cancel queued operations that should not survive the incident |
| `SafeConfigUnreadable` with an unusually low gas limit | a configuration read starved of gas (it gets 63/64 of what is left) is reported as unreadable rather than as out of gas | re-estimate / raise the gas limit; an `eth_call` of the Safe's `getOwners()` succeeding tells the two apart |
| `NestedExecution` / `MissingSnapshot` / `SafeConfigChanged` / `ApprovedExecutionFailed` | a nested same-Safe transaction, a role action inside the curator's transaction, a configuration write during a policy transaction, a failed approved execution (a module's, or the signers' when the transaction carries `safeTxGas != 0`; the approval is kept) | structural: split the transaction, fix the payload and retry, or ask Vetro |
| `FailedCall()` (from the timelock's `execute`) | a scheduled call reverted WITHOUT data: an unknown selector, malformed arguments, an enum out of range, or value sent to a non-payable function | re-build the operation from the ABI; the batch error carries no call index, so simulate the calls one by one |
| `SafeConfigUnreadable` | the Safe's own `getOwners()` / `getStorageAt` cannot be read (owner list and owner count out of step after a storage-writing delegatecall; a dry run against a `safe` address that is not a supported Safe is `SafeNotSupported`) | ask Vetro (§7.6 step 4): approvals and Bypass windows still work meanwhile; on the live Safe (solc 0.7.6 singleton) the failing owner read burns all the gas it was given, so a failed attempt costs the whole gas limit: diagnose with `eth_call` / `validateTransaction`, do not retry blindly |

Safe{Wallet}'s Tenderly simulation runs with the guard slot zeroed, so "Simulation successful" says
nothing about the guard; the executor's "Cannot estimate" with one of the reverts above is the real
signal. On Safe v1.5.0 a venue's revert data is bubbled unchanged and can carry a guard error
selector although the guard passed the transaction: confirm with `validateTransaction` or a trace.
USDT refuses `approve` from a non-zero allowance (the live one is `uint256.max`): approve zero first,
both steps are allowed. Rejecting a queued transaction (the empty self-call) works in `Enforced` and inside a window;
under `Lockdown` it is refused like everything else and needs a council approval of the empty
self-call. Off-chain signatures (CowSwap,
Permit2, SIWE) and ERC-721 / ERC-1155 receipts do not, because the fallback handler is removed.

## 8. Complementary Lagoon-level hardening (recommended, outside the guard)

> **Round 4 (§12) consensus: these are go-live preconditions, not complements.** Eight of the
> twenty lenses rated the Lagoon role moves and guardrail activation as the single highest-leverage
> control in the stack, ahead of the guard itself: until they are done the allowlisted
> `updateNewTotalAssets` is unbounded, the vaults are public, and `pause` / `updateSafe` /
> `updateSuperOperator` / fee changes are one approval or one Bypass away from the curator. Two
> reviewers also argued against `lockUpdateSafe()` while a third party is custodian (it is the only
> Lagoon-native lever to re-home future settlement custody); see §12.6.

The guard constrains what the Safe executes; it cannot change who holds Lagoon's roles. Today
the curator Safe holds all of them, so these moves decide how much the curator can do through
*allowed* calls. Verify them by storage, not by getters: the live v0.6.0 vaults answer neither
`securityCouncil()` nor `superOperator()` (the repository's `ILagoonVaultV06` declares both; they
revert on-chain). The roles live in the ERC-7201 slot `hopper.storage.Roles`
(`0x7c302ed2c673c3d6b4551cf74a01ee649f887e14fd20d13dbca1b6099534d900`, read with `cast storage`
at base + 0 `whitelistManager`, + 1 `feeReceiver`, + 2 `safe`, + 4 `valuationManager`, + 5
`securityCouncil`, + 6 `superOperator`; confirm the offsets against the verified source before
relying on them) and the guardrails in `hopper.storage.GuardrailsManager`
(`0xd851cf94ad565ef91472fd51daf3f5f2311d4c6801bf4d880e94a7f28b854800`, base + 0 … + 2, all zero
today). Read on the fork on 2026-10-05: every role is the curator Safe except `whitelistManager`
and `superOperator` (zero), guardrails off, `isAllowed(0xdEaD) == true` (public vaults), vault
`owner` and the five `DelayProxyAdmin` owners the curator Safe, strategies with zero debt and
`maxLossBps == 0`: every item below is still open. The sync task's unconstrained-NAV gate
(`--allow-unconstrained-nav`, §7.2) is the only tooling-side tie to this list: it refuses an
unconstrained `updateNewTotalAssets` on a vault whose `totalAssets()` is not zero.

- **`securityCouncil` → Vetro governance, then activate guardrails.** `securityCouncil` is the only
  role that can `updateActivated(true)` / `updateGuardrails((uint256 upperRate, int256 lowerRate))`
  and the only one that can push a NAV past them (`securityCouncilUpdateTotalAssets`). With the role at Vetro
  and guardrails activated with real bounds, the policy-allowed `updateNewTotalAssets` is bounded
  per settlement interval; without this, "guardrails bound NAV" is not true for these vaults.
- **`owner` → Vetro governance (two-step).** Removes pause / unpause, `initiateClosing`,
  `activateAsyncOnly`, role rotation, `updateSafe` and fee-rate changes from the curator, independent
  of any future approval. Keep `safe` as is; call `lockUpdateSafe()` once custody is final.
- **`valuationManager`**: decide explicitly. Leaving it with the curator means NAV honesty rests
  on guardrails + monitoring; moving it to a Vetro-run valuation process removes the curator's
  NAV discretion entirely (settlement still needs the Safe).
- **Proxy admin.** Each vault's `DelayProxyAdmin` is owned by the curator Safe (1-day delay,
  implementations gated by Lagoon's registry). Upgrades are blocked by the guard today (the admin
  is not an allowlisted target) but would ride on any future approval; consider moving the admin
  ownership to Vetro and re-verify the registry before approving any upgrade. Lagoon's registry
  already whitelists its default v0.5.0 logic as a target: a downgrade keeps the allowlisted
  selectors but drops guardrails and the security council, so the admin ownership must move to Vetro
  with or before guardrail activation, never after. After any Lagoon implementation change, run
  the Lagoon fork suite against the new code before the keeper reports again. The strategies'
  starved-call rule (§8 "Strategy upgrade") judges a vault call starved when it reverts without data
  or hands back less than an eighth (12.5%) of the gas on hand before it; the second test's premise rests
  on the depth of Lagoon's call chain and on no gas-capped or swallowed inner call on the path. The
  EVM retains 1/64 of the gas at each call, so a call that runs out of gas n frames below the rule's
  gas capture hands back at most 1 - (63/64)^n of it: under the eighth through eight frames, above
  it from nine. On v0.6.0 the asset and share transfers sit up to seven frames below the capture,
  within that bound. One path is deeper: in blacklist mode, the live mode, a claimed deposit's share
  transfer also consults the access check, which reads the fee registry through its proxy, ten
  frames in all. There the bound alone does not hold (14.6%) and the rule holds by measurement: the
  frames above spend most of the gas before the deep frames are entered. (In whitelist mode the
  claim's deepest call is the registry read of its own access check, eight frames, within the
  bound.) Scanned in 8- and 16-gas steps across the limits on both Vetro vaults (forks of blocks
  26,142,291-26,142,481), a starved deposit claim handed back at most 7.64% of the gas against the
  rule's 12.5%, and no sampled limit landed the sweep or the report with the deposit unclaimed. The
  V06 fork suite scans the deposit claim's report, sweep and handed-back fraction at every run
  outside the vault's sync-deposit window (which a zero `totalAssetsLifespan` keeps shut today). A
  deeper or thriftier chain in a new implementation could change that: the suite will say so.
- **Order of the NAV controls** (round 5, verified against the deployed v0.6.0 source). (1) Whitelist
  mode with `whitelistManager` at Vetro and only the five strategies whitelisted, then
  `lockSuperOperator()` while it is unset: it removes the outside beneficiary of a false mark (an
  outsider can neither enter nor exit), though a false mark can still short-pay a redeem and strand
  the difference in the Safe. Keep the Safe itself off the whitelist (`claim…OnBehalf` then revert, so
  drop those two policy entries; the strategies claim for themselves) and set the manager and the
  list before `switchAccessMode`. (2) Guardrails on, with `securityCouncil` at Vetro: a second
  proposal in the block of a settlement reverts and per-update moves are bounded. (3) Proxy-admin
  ownership with (2). (4) `setSyncMode(None)` (or `activateAsyncOnly()`): today only
  `totalAssetsLifespan == 0` keeps the synchronous paths closed. Until (1) is live every
  `debtRatio` stays at zero. (2) alone is NOT a substitute on a public vault (round 8, read from the
  live implementation's bytecode: the guardrail compares the price of one share at the current and
  the proposed NAV over the elapsed time, so it is a bound RELATIVE to the vault's own NAV): what a
  false mark then pays an outside depositor is the allowed move times the depositor's OWN stake
  (rate × interval × deposit, with `maxCap` unbounded today), not a fraction of custody; reproduced
  with a ±5 % relative bound and a deposit of ten times custody, one cycle took 499,999 of 1,000,000
  USDC. Whitelist mode removes the outside stake; guardrails then bound what a false mark can shift
  between the whitelisted strategies. A NAV band in the guard policy (§5) is defence in depth, not a
  substitute: a static band is independent of the attacker's capital (about x² of NAV per cycle at
  ±x) but stalls at every funding step, and cycles chain inside one transaction.
- **Whitelist mode is also a liveness control for the strategies** (control (1) above). On a public
  vault any holder can open a request with a strategy as `controller`
  (`requestRedeem(1, strategy, holder)`); after the next mark that share-wei sits alone in a closed
  epoch, Lagoon never settles it, nobody can cancel it, and every later redeem of the strategy reverts
  `OnlyOneRequestAllowed` (the keeper's report emits `VaultActionSkipped`), so the pool's withdrawals
  cannot be queued until a real redeem joins a later batch (any holder's: on a fork a
  1e18-share request by a third holder settled the 1-wei one with the next batch; reproduced on
  the live vaults in the strategy-fix review, 2026-10-05/06; a settled stranger request for the
  strategy likewise blocks
  `closeOutPosition` once the vault is Closed, and only the Safe's `claimAssetsOnBehalf` clears
  it, a call that reverts `AddressNotAllowed` once the Safe is off the whitelist, so run the four
  reads below before the switch as well). After the switch and before any `debtRatio` is
  raised, the vault's `pendingRedeemRequest`, `claimableRedeemRequest`, `pendingDepositRequest`
  and `claimableDepositRequest` for `(0, strategy)` must all read 0. Monitor
  `vault.pendingRedeemRequest(0, strategy) != 0 && strategy.redeemRequestId() == 0` (a request in
  the strategy's slot that the strategy did not open) and alert on
  `VaultActionSkipped(requestRedeem, OnlyOneRequestAllowed)`.
- `maxLossBps`: zero is not operable after a real settlement (§6). Set it to 1 (the smallest cap), or
  give `LagoonBase._rebalance` a rounding tolerance, and keep using `reportLoss` deliberately so a
  settlement freeze stays illiquidity rather than a booked loss. An exit fee is a loss to the
  strategy at the claim report (2% of a withdrawal of a fifth of the debt is 40 bp of it), so a
  fee-bearing vault, should one ever be funded, needs the cap sized to the fee rate times the
  largest withdrawal share; the five live vaults charge none and Lagoon only lets the rate decrease.
- **Strategy upgrade.** The five `Lagoon_Vetro_*` proxies run `LagoonV06` 6.0.5 while the tree is
  newer. On the live code `tvl()`, `balances()` and `instantLiquidity()` revert while a settled
  request waits to be claimed (the vault has no `getSettlement…FeeRate`), a profit report reverts
  `InsufficientBalance` when the pool has credit on offer, and the rounding remainder of a
  booked profit is queued as a redeem that Lagoon never settles, which blocks the pool's next
  withdrawal on a flat NAV (all three measured on forks in the strategy-fix review, 2026-10-05/06).
  Upgrade all five before any `debtRatio` is raised. The flow was rehearsed end to end on private
  forks in that review (three times, the last one with the final tree on all five assets); the
  runbook, in order:
  1. Preflight reads on all five proxies: implementation slot `0x4089…0669` (USDC, USDT) or
     `0x100C…A09b` (BTC), `VERSION()` 6.0.5, `governor()` and `feeCollector()` both the governance
     Safe, `maxLossBps()` 0, `depositRequestId()` and `redeemRequestId()` 0, `pool.totalDebtOf` and
     `tvl()` 0, on each pool `getStrategyConfig(strategy)` either ACTIVE with `debtRatio` 0 or, since
     the removal of 2026-10-06, inactive (`(false, 0, 0, 0, 0)`: then step 5 expects five re-adds at
     0), and on each vault `pendingRedeemRequest`, `claimableRedeemRequest`, `pendingDepositRequest`,
     `claimableDepositRequest` for `(0, strategy)` all 0. `.env`:
     `ETHEREUM_NODE_URL`, `PRIVATE_KEY` whose address is `DEPLOYER` (the address of
     `DEPLOYER_PRIVATE_KEY` too: `helpers/safe.ts` signs the Safe proposal with it), `SAFE_API_KEY`,
     `ETHERSCAN_API_KEY`; the deployer needs about 5.0M gas of ETH for the implementation
     (4,981,327 measured for this tree's build on a fork).
  2. `npx hardhat compile && THRESHOLD_PCT=96 ./scripts/check-contract-sizes.sh` (LagoonV06
     22,744 B, LagoonV05 20,602 B with this change, the starved-call rule included; the gate is
     23,592 B).
  3. `RECORDS=Lagoon_Vetro_USDC,Lagoon_Vetro_WBTC npx hardhat run scripts/seed-oz-validations.ts`,
     after the last `hardhat clean` (`clean` wipes `cache/validations.json`; later recompiles keep the
     seeded entries). The flow's `validateUpgrade` (`helpers/deploy.ts`) must find the live 6.0.5
     builds in that cache; they were compiled for `paris` and the tree targets `cancun`, so a fresh
     compile never records them and the deploy stops, before anything is sent, at "The requested
     contract was not found" until the cache is seeded. The script recompiles the recorded solc inputs
     of the two live builds through Hardhat's compile subtask (about 16 s with the tree already
     compiled; on a clean tree `hardhat run` compiles everything first: 30 s on the review machine,
     longer on a slow one) and writes only the validations cache and Hardhat's own solidity-files
     cache.
  4. Fork dry-run (CLAUDE.md, "Fork dry-run workflow") with `safe` appended to the tags
     (`./scripts/next-deployment-on-fork.sh ethereum <the five tags>,safe`: without it the queued
     Safe calls stay in `safe.batch.tmp.json`, nothing is executed on the fork and the proxies stay
     on 6.0.5) and a `FORK_NODE_URL` whose string contains `eth-mainnet` (hardhat.config.ts derives
     the `localhost` chain id from it; any other URL configures chain id 31337 and the deploy aborts
     with HH101 against a mainnet fork): expect five "Validation successful", one
     `LagoonV06_Implementation` deployment, the same batch as step 5 (ten calls today) and
     "1 impersonated Safe group(s) executed", then the step 6 reads on the fork. Use a fresh fork
     node per run: anvil keeps an impersonated account in `eth_accounts` until it stops, so a second
     run on the same anvil after a `safe` flush finds a signer for the governance Safe, executes the
     five upgrades directly (no "no signer" lines) and queues only the five re-adds; Hardhat's node
     lists its local accounts only and keeps the shape on a re-run.
  5. Mainnet: `npx hardhat deploy --network ethereum --tags
     Lagoon_Vetro_USDC,Lagoon_Vetro_USDT,Lagoon_Vetro_WBTC,Lagoon_Vetro_cbBTC,Lagoon_Vetro_hemiBTC,safe`.
     Expect five validations, one implementation deployment from the deployer, "no signer" for the
     governance Safe five times, Merkl and `addStrategy` steps skipped, and one batch of exactly five
     `upgradeToAndCall(impl, 0x)` to the five proxies proposed to the governance Safe through
     `MultiSendCallOnly`, nothing else (in particular no `updateFeeCollector`: the deploy scripts pin
     the live collector). That shape holds only while every strategy is ACTIVE in its pool: on
     2026-10-06 (tx `0x4499e699…c529`, block 26,134,004) the owner removed all five from their pools,
     and for an inactive strategy the script's idempotent `addStrategy` fires again, in the SAME
     batch, with the script's `debtRatio`: 0 in all five scripts since 2026-10-06 (`01_vetro_usdt`
     through the helper's default). Before that USDC and hemiBTC passed 1000, and a fork rehearsal
     showed what that does: hemiBTC was re-added at 10% and the first keeper report moved 10% of the
     pool to the strategy, while the USDC call reverts `InvalidDebtRatio` because that pool is at
     100% (so are USDT and WBTC), which makes the whole `MultiSendCallOnly` batch revert. Either
     re-add the five with `debtRatio` 0 before the upgrade, or expect exactly TEN calls, per strategy
     `upgradeToAndCall(impl, 0x)` to the proxy then `addStrategy(strategy, 0)` to its pool (rehearsed
     on a fork of block 26,135,045 with the current tree: 10 calls, nothing else), and reject any
     other `debtRatio` or any other call. If the removal is meant to stand, do not run the flow
     with `safe` (it proposes the re-adds): run the five tags WITHOUT `safe`, which deploys the
     implementation, rewrites the records and leaves the ten calls in `safe.batch.tmp.json` without
     proposing them; delete the five `addStrategy` entries from that file and propose the five
     `upgradeToAndCall` (`npx hardhat deploy --network ethereum --tags safe` proposes what the file
     holds, or enter them in the Safe UI), then delete the file. Signers check every call of the
     batch, not only `impl`: `to` is one of the five proxies (the `deployments/ethereum/
     Lagoon_Vetro_*` records) or, for an `addStrategy`, the `pool()` of the proxy upgraded by the
     call before it;
     `upgradeToAndCall` carries `impl` equal to `deployments/ethereum/LagoonV06_Implementation.json`
     and Etherscan's artifact match (the on-chain code differs from the artifact only in the UUPS
     immutable, its own address, at two offsets) and an EMPTY `data` argument (a non-empty payload
     runs as the proxy during the upgrade); `addStrategy(strategy, 0)` names that proxy and the
     ratio 0; `value` 0 and operation Call everywhere (`MultiSendCallOnly`); and the Safe nonce is
     the next one. Do not re-run with `safe` before the Safe has executed: a re-run keys on the
     proxies' implementation slots and would propose the whole batch again (the ten calls today).
  6. After execution: implementation slot and `VERSION()` on all five, request ids 0, the vault reads
     of step 1 still 0, `requestRedeem(1)` from a keeper reverts `UnsettleableRedeem(1)`
     (`0xc4f4bd31`); a re-run of step 5 prints "reusing" five times with no batch once the five are
     active again, but while the removal stands it queues five `addStrategy(strategy, 0)` again (and
     with `safe` would propose them): re-run the five tags without `safe` there and delete
     `safe.batch.tmp.json`. Only then commit
     the 11 rewritten `deployments/ethereum/Lagoon*` records together with the new
     `deployments/ethereum/solcInputs/<hash>.json` (the seeder of the NEXT upgrade reads it); the
     tree ships `VERSION()` 6.0.7 (bumped in `Strategy.sol` and `package.json` with this change, so every
     strategy built from it reports 6.0.7; the live proxies answer 6.0.5 until the batch executes), and
     `create-release` runs after the deployment, the owner's step.
     The upgrade also carries everything merged on `main` since 6.0.5, visibly `toggleMerklOperator(address)`
     replaced by `setMerklOperator(address,bool)` and its event `MerklOperatorToggled(address)` by
     `MerklOperatorUpdated(address,bool)` (PR #374), and the fix itself adds the getter
     `MIN_AUTO_REDEEM_ASSETS()` and the errors
     `UnsettleableRedeem(uint256)` and `VaultCallFailed(bytes4)`, nothing else: keeper tooling that
     still calls the old selector or watches the old event fails after the batch, and a keeper that
     decodes a report's revert needs the new error ABI; update both in the same change.
  After the upgrade `_rebalance` leaves a redeem worth less than `MIN_AUTO_REDEEM_ASSETS` (100 raw
  asset units) in the vault and the keeper's `requestRedeem` reverts `UnsettleableRedeem` on shares
  worth zero assets: an excess debt below that floor is redeemed by hand or waits for a larger need.
  The floor is a compile-time constant, readable on the upgraded strategies as
  `MIN_AUTO_REDEEM_ASSETS()` (selector `0x0ea45d86`); read it per strategy instead of hardcoding 100,
  a later implementation may change it. On the live 6.0.5 code the call reverts with EMPTY revert
  data (ethers v6: code `CALL_EXCEPTION`; "missing revert data", or "no data present; likely
  require(false) occurred" when the node returns `data` `0x`), so a monitor gates the read on
  `VERSION()` ("6.0.5" has no getter) or treats that revert as "not upgraded yet" and skips the floor
  check. Monitor a need that stays deferred with no request of the strategy's own, read right after
  a LANDED keeper report (a report that reverted, `LossExceedsCap` for one, leaves the state in
  place: alert on the revert and do not evaluate the signature on it; between reports a withdrawal
  raises `excessDebt`, which the next report queues normally):
  `need = pool.excessDebt(strategy) + max(tvl() - totalDebtOf(strategy), 0)` and
  `gap = max(need - asset.balanceOf(strategy), 0)`, saturating (in a loss `tvl() < totalDebtOf` and
  the plain subtraction underflows; the idle on hand is what the next report pays back, so after a
  manual `processAllClaimable` the gross formula fires for nothing), while `redeemRequestId() == 0`
  (a request the strategy tracks, pending or claimable, is the one legitimate silence; the vault
  reads below are diagnostics, not preconditions). A `gap` below the fee-adjusted floor,
  `ceil(MIN_AUTO_REDEEM_ASSETS() * 10_000 / (10_000 - feeRates().exitRate))` (100 at the live rate
  of 0; 103 on both Vetro vaults with the 2% cap written into storage: the floor applies to the
  settle value of the sized shares, net of the fee shares), is the ordinary deferral. A `gap` at or
  above it after a landed report is never dust; it has one of six causes, each with its own read:
  the position is still a pending deposit (`depositRequestId() != 0`: no shares to redeem, clears
  after the settlement; measured on the live USDC vault: the claim report that follows a funding
  can leave a 1-unit deposit request behind, the likely mechanism being the claimed shares valuing
  one unit below the debt, booked as a loss inside `maxLossBps` 1 and re-lent by the pool; it holds
  the vault's deposit slot: a credit draw inside its own epoch joins it, one after the curator's
  next mark is skipped `VaultActionSkipped(requestDeposit, OnlyOneRequestAllowed())` and sits
  idle, until that settlement, both measured on the live USDC vault); the vault is paused
  (`isVaultPaused()`: the report only
  flushes idle and
  emits nothing); the vault is not Open (`VaultActionSkipped(requestRedeem, NotOpen(state))`:
  `NotOpen(1)` is Closing, wait for the Safe's `close()`, `closeOutPosition` reverts until then
  (`Panic(0x11)`, no settled request to take the shares from); `NotOpen(2)` is Closed and the
  remedy is, in this order, the strategy's `debtRatio` to 0, then `closeOutPosition`, then the
  report pays everything back: with the ratio still above 0 the report after `closeOutPosition`
  requests the surplus idle into the Closed vault again (measured: 45,304 USDC back into its silo),
  where only `cancelDeposit` recovers it. The vault has no state getter; it emits
  `StateUpdated(uint8)` (1 at `initiateClosing`, 2 at `close`), and an `eth_call` of
  `requestRedeem(1, strategy, strategy)` with `from` the strategy reverts `NotOpen(1|2)`: use one
  of those when the redeem side has nothing to report, since a Closed vault's pending deposit
  (`depositRequestId() != 0`) otherwise looks like the first cause and never settles; the deposit
  side has no such gate on
  v0.6.0: a funding report into a Closing vault still requests the deposit, which `close()` settles
  into shares that `closeOutPosition` sweeps, measured on both Vetro vaults, and a funding report
  into a CLOSED vault still requests it too, into a silo no settlement will ever reach:
  `cancelDeposit` returns the whole amount at any later time while the vault is not paused, the
  request staying in its epoch, measured on all five and shown by the V06 fork suite at every run
  outside the vault's
  sync-deposit window (which a zero `totalAssetsLifespan` keeps shut today); keep the ratio at 0
  once the curator closes); the strategy is off the
  vault's
  whitelist (`isStrategyAllowedInVault()` false, an EMPTY revert of that read being the
  sanctions-list case further down, and `VaultActionSkipped(requestRedeem,
  AddressNotAllowed(strategy))`, or, while a claimable waits, `VaultActionSkipped(
  processClaimableRedeems, AddressNotAllowed(strategy))` alone: the unswept claimable blocks the
  request path, `instantLiquidity()` still counts it and a pool withdrawal that needs it reverts
  `AddressNotAllowed`; the whitelist manager lists it again); a stranger's request holds the slot
  (`VaultActionSkipped(requestRedeem, OnlyOneRequestAllowed())` with `pendingRedeemRequest(0,
  strategy) != 0`: the signature above; one worth assets clears at the next settlement and the
  strategy's own request goes through after it, measured; a dust one only when another holder's
  real redeem joins the batch, see the whitelist control above); or the vault reports an exit rate
  at or above 100%
  (`feeRates().exitRate >= 10_000`, impossible on Lagoon, which caps the rate at 2% at
  initialization and on every update and only lets it fall: such a vault is treated as settling
  nothing, the report lands and queues no redeem where the fix without this guard reverted with
  Panic(0x11), and `requestRedeem` reverts `UnsettleableRedeem`). The signature is redeem-side: a
  refused DEPOSIT leaves `gap` at 0 (the drawn funds sit idle, `tvl()` counts them, the debt equals
  them; measured for every deposit-side refusal above). Its signature is idle after a landed
  report, `asset.balanceOf(strategy)` above dust while `depositRequestId()` is 0, no sync window is
  open (`isAsyncDepositEnabled()` true) and `claimableDepositRequest(0, strategy)` is 0; the landed
  `VaultActionSkipped(requestDeposit | syncDeposit, reason)` names the cause
  (`AddressNotAllowed`, `OnlyOneRequestAllowed`, the token's string or `FailedInnerCall()`), a
  paused vault leaves the idle with no event. Alert on every landed `VaultActionSkipped`: the gap
  formula alone misses this
  side and a refused claim while the strategy's own id is set. A vault call starved of gas inside
  a report's try/catch is a failed report, not a silent one, from this upgrade on. A wrapped call
  counts as starved when it reverted without data, or when it handed back less than an eighth of the
  gas on hand before it: Lagoon itself out of gas, or the token transfer inside it, whose empty revert
  OpenZeppelin's `Address.functionCall` types as `FailedInnerCall()`. A refusal is neither: every
  refusal Lagoon's own code raises on the strategy's path is a typed error that costs little gas (3k
  to 78k measured from the strategy's seat on the five Vetro vaults, `MaxCapReached` the dearest),
  and so is the asset token's own refusal, a string on USDC and cbBTC, a custom error on hemiBTC, a
  bare `require` on USDT and WBTC that OpenZeppelin types as that same `FailedInnerCall()`. A LANDED
  skip with that reason is therefore a token refusal, the token paused or the sender blacklisted,
  from this upgrade on, never a starved call. A starved call makes the report revert
  `VaultCallFailed(selector)` instead of landing with a skip, so a keeper's `eth_estimateGas` can no
  longer settle on a limit at which the call starves. A refusal reached with barely enough gas fails
  the same way; the retry with more gas skips it (at the estimate every refusal measured on the live
  USDC vault, `NotOpen`, `AddressNotAllowed` on both sides, `OnlyOneRequestAllowed`, a refused
  pre-sweep, landed with its typed skip; a dear refusal, 28k-53k gas, puts the estimate 3k-6k gas
  above the limit at which it completes, which a keeper that estimates never sees). On the live
  6.0.5 code the estimate can
  and does settle there (measured on the live USDC vault at block 26,136,162: estimate 276,790
  while the report that lands the deposit uses 338,433 and needs a limit of 363,551, so a limit
  copied from that receipt lands the starved report too; 268,338 against 330,861 used on the tree
  before this rule; the deposit then sat idle while `tvl()` counted it and `need` stayed 0, the
  skip's reason
  empty; the sync-deposit route and the 1-unit request after a claim settle the same way, the
  latter with a `FailedInnerCall()` reason): until the upgrade, send `rebalance()` with an explicit
  gas limit and alert on a skip whose reason is empty or `FailedInnerCall()`. From the upgrade on
  the estimate lands the request (USDC funding report 355,990 against 330,990 in the receipt: the
  difference is the refund the receipt nets out, not a margin to trim; sync route 382,203 with the
  1-unit post-claim request still pending, 301,987 once it is settled; claim report 450,618) and a
  report that reverts `VaultCallFailed(selector)` (`0x6a895b15`, the selector naming the wrapped
  call) was sent with a gas limit below the need: it is not a vault refusal and it changed nothing,
  re-estimate and resend instead of retrying the same limit (a limit above the band where the call
  starves but still below the need fails with empty revert data instead). A report that reverts
  `VaultCallFailed` at a fresh estimate is the alert: no call on Lagoon did that at the latest
  block, so the vault or its token now keeps most of the gas it is given, or a contract on Lagoon's
  path reverted without data (the three cases measured are below). Triage in this order. (1) Resend
  once at the estimate plus 10%, or at 3M: a report that lands then was estimated into the refusal
  band (the Nethermind case below) and its skip names the cause. (2)
  `VaultCallFailed(requestDeposit)` or `(syncDeposit)` at every limit on the USDT vault: read
  `USDT.allowance(strategy, vault)`; below the amount it is the Tether case below, remedy
  `approveToken(type(uint256).max)` (a failed report there burns almost the whole limit, 2.79M of 3M
  measured, so do not retry blindly). (3) `VaultCallFailed` at every limit on any vault: read
  `isStrategyAllowedInVault()`. An EMPTY revert is the sanctions-list case below, which the
  whitelist manager repairs (`setExternalSanctionsList`), unless the list is unset (`cast storage
  <vault>` at the `hopper.storage.Whitelistable` slot `0x083c…4800` + 3 reads zero) and `cast call
  <feeRegistry> 'protocolFeeReceiver()'` reverts (the registry sits at `hopper.storage.Roles` + 3,
  `0x6da4…e27c` on the five vaults today, an upgradeable proxy of Lagoon's). Then Lagoon's protocol
  fee registry, which the access check of every v0.6.0 vault reads first on every request and claim,
  is broken; the signature is the sanctions-list one (every report `VaultCallFailed(selector)` at
  every limit, the read reverting empty, a manual `requestDeposit` reverting empty; measured on a
  fork of the live USDC vault; a registry reverting with data is skipped typed), the whitelist
  manager cannot repair it, only Lagoon can: escalate. (4) None of these: a call on Lagoon's path
  now starves at a sane limit; stop the keeper and escalate. The estimate itself failing with EMPTY
  data on USDT (with the token's string on USDC) before any skip is none of these: Tether or
  FiatToken refused the pool's own transfer (to the strategy with credit on offer, from it at a
  payback), the token paused or the pool or the strategy blacklisted, Tether checking the sender of
  a `transfer` and the `_from` of a `transferFrom`, FiatToken every party (read `paused()`, then
  `isBlackListed` / `isBlacklisted` for the pool and for the strategy), outside the wrapped calls
  and at every limit, measured on both vaults. Which node answers
  the estimate matters. On the 6.0.5 code anvil returns the lowest landing its search finds
  (276,790; starved landings exist a few hundred gas lower too) and
  Hardhat's node its first probe, the full run's `gasUsed` (338,433), both inside the window where the
  deposit starves, so a fork dry-run that copies the fork's estimate reproduces the silent state;
  geth, erigon, reth and Nethermind 2.x start their search at `gasUsed - 1`, try the gross gas times
  64/63 first and bisect downwards, which landed the deposit for the same report (366,357) only
  because its refund (19,900) is smaller than the work that follows the call: a report refunding
  more than that puts the window in their range too (measured on a model with a 67k refund). From
  the upgrade on every estimator returns at least the need, at most 1.5% above it (funding report:
  geth family 358,796, Hardhat 356,202, anvil 355,990; ethers, viem and web3.js pass the node's number
  through unchanged): send at the estimate or above, never a limit derived from a receipt. One
  exception: a node whose estimator counts a revert as success unless some frame ran out of gas
  (Nethermind before 1.35, October 2025) can estimate a report whose vault call is a dear refusal
  about 1.6k gas short, inside the band where the refusal completes but the rule fails it (measured
  on the live USDC vault in whitelist mode: 195,063 against 196,666 needed, `VaultCallFailed` at the
  estimate, the same answer on every retry); a keeper on such a node adds a margin (10% suffices) or
  estimates elsewhere. A keeper that pre-flights with `eth_call` at a fixed limit sees the same
  `VaultCallFailed` below the need and must raise the limit, not skip the report. Three cases
  measured on the forked vaults are not starvation but fail that way too, none of them a revert of
  the vault's own code: Tether's `assert`, a sanctions list and the fee registry. Tether checks the
  allowance in `transferFrom` with a Solidity 0.4 `assert`, which consumes all the gas the token
  frame was given, so on the USDT vault an allowance below the amount (only a keeper's
  `approveToken` can cause it: the deploy approval is unlimited and Tether never decrements an
  unlimited one) reverts `VaultCallFailed(requestDeposit)`, or `(syncDeposit)`, at EVERY limit, the
  fresh estimate included, until `approveToken(type(uint256).max)` (the approval passes through
  zero; `forceApprove` does that); on USDC, cbBTC, WBTC and hemiBTC the same shortfall is a cheap
  typed revert and the report lands with the skip. A contract Lagoon's access check consults can
  revert without data, or have no code: the external sanctions list `isAllowed` calls once the
  whitelist manager has set one (the five vaults have neither a sanctions list nor a whitelist
  manager today) bubbles an empty revert through Lagoon, and every report fails
  `VaultCallFailed(selector)` until the curator repairs it (the vault refuses every user then; an
  oracle that reverts with data is skipped typed); so does Lagoon's protocol fee registry, which the
  same check reads first (`protocolFeeReceiver()`, on v0.5.0 as well), until Lagoon repairs it
  (triage step 3). The 6.0.5 code landed all three with an empty-reason or `FailedInnerCall()` skip.
  With credit on offer a token refusal
  does not reach the wrapped call at all: the pool's own credit-line transfer meets it first and the
  pool's SafeERC20 (OpenZeppelin 5.3) bubbles the token's revert as it is, so the report reverts
  before any vault call, at every limit and in the estimate itself, with the token's string on USDC
  and cbBTC (`Pausable: paused`, `Blacklistable: account is blacklisted`) and with EMPTY data on
  WBTC and USDT, whose bare `require` carries none (measured on the five live proxies with the
  current tree). An empty revert at a fresh estimate on the WBTC or USDT pool is therefore the asset
  paused or, on USDT, the pool or the strategy blacklisted, to check before anything else; the
  landed `VaultActionSkipped(requestDeposit, ...)` face
  of a token refusal needs the idle already on hand when the report runs. Three states neither
  signature shows: if `tvl()` itself reverts (Panic 0x11) the signature cannot be computed, which is
  the view limit below (a settled request waiting to be claimed at a rate above 100%): read
  `claimableRedeemRequest(0, strategy)`, `claimableDepositRequest(0, strategy)` and `feeRates()`,
  and let the next report or a manual `processAllClaimable(0, 0)` clear it; and a request of the
  strategy's own left pending across a settlement (`redeemRequestId() != 0` and
  `convertToAssets(pendingRedeemRequest(0, strategy)) == 0` at the live price, judging the shares
  net of the fee shares, `ceil(pending * exitRate / 10_000)`, as `settleRedeem` does, should the
  vault ever charge an exit fee; or `feeRates().exitRate >= 10_000` while it is pending: at exactly
  100% the settlement returns without settling a request that is worth something) is stranded:
  Lagoon never settles it alone, no event is emitted (the strategy does not retry while its own
  request is pending) and `excessDebt` stays owed; the manual path below the floor or a fall of more
  than 99% on the auto path puts it there, and it clears when the share price recovers, another
  holder's redeem joins a later batch (`cancelRedeem` works only inside its epoch) or, at such a
  rate, the owner lowers it; and a deposit request a stranger opened naming the strategy as
  controller (ERC-7540 binds the owner only; nothing stops it on a vault in blacklist mode) once
  the curator has settled it: `claimableDepositRequest(0, strategy) != 0` with
  `depositRequestId() == 0`. The strategy tracks no id, its pre-sweep claims nothing, and
  `_rebalance` does not attempt the async request while a claimable deposit of its own controller
  waits, so a funding report lands with the idle on hand, no `DepositRequested` and no
  `VaultActionSkipped`, `need` and `gap` at 0 (the idle covers the debt), report after report,
  until a keeper's `requestDeposit(idle)`: Lagoon claims the stranger's shares to the strategy
  inside it and takes the request (measured on the five live proxies with the current tree at the
  real estimate, 1,000 raw units from a stranger, and on Tulipa v0.5.0 at the pin; the 6.0.5 code
  behaves the same; only the Safe's `claimSharesOnBehalf` or that manual request clears the
  claimable, the stranger cannot claim for a controller it is not; the sync route is not gated and
  deposits regardless). So alert on idle left on hand after a landed report whose receipt carries
  neither a request, a sync, nor a skip, and read `claimableDepositRequest(0, strategy)` first.
  That guard
  covers the request path only: with a settled request waiting to be claimed, a rate above 100%
  (exit, for a redeem; entry, for a deposit) makes `tvl()`, `balances()` and `instantLiquidity()`
  revert until the claim; the report itself still lands, because it claims first and Lagoon prices
  a claim at the rate frozen at its settlement (measured on the live vaults), and a manual
  `processAllClaimable` clears it the same way. At exactly 100% nothing underflows: the views value
  the claimable at zero, a settlement returns without settling, and the sync paths (`instantRedeem`,
  `closeOutPosition` in a Closed vault) burn the shares for nothing unless their floor argument is
  non-zero, so never pass 0 there on a vault whose rate reads out of range. A loss above
  `maxLossBps` makes the report revert `LossExceedsCap` and leaves the state in place: alert on the
  revert, not on the signature.
  The funding preconditions above (whitelist mode and the vault reads, `setMaxLossBps(1)` on all five
  by the governor, not inside the `upgradeToAndCall` data, guardrails with `securityCouncil` at Vetro)
  stay in force: every `debtRatio` is 0 until they are met. On a fork, `update-debt-ratio` prints
  "executed" for a reverted `updateDebtRatio` as well (measured: status 0 on a pool at 100%, exit
  0), so read `getStrategyConfig` after it.

## 9. The Vetro Lagoon policy (`policies/curator-guard/vetro-lagoon.ethereum.json`)

Allowed:

- On each of the five vaults: `updateNewTotalAssets(uint256)` (the Safe is `valuationManager`;
  the guardrail-checked NAV path), `settleDeposit(uint256)`, `settleRedeem(uint256)`,
  `claimSharesOnBehalf(address[])`, `claimAssetsOnBehalf(address[])`.
- On each asset (USDC, USDT, WBTC, cbBTC, hemiBTC): `approve(address,uint256)` with
  `OneOf(spender) = { the matching vault }`. Settlement pulls assets from the Safe with
  `safeTransferFrom(safe, …)`, so this allowance is required and is the only one.
- Delegatecall unwrapping through the three canonical `MultiSendCallOnly` builds (v1.3.0
  `0x40A2…130D`, v1.4.1 `0x9641…02e2`, the one the Safe has been using, and v1.5.0 `0xA83c…1836`).
- The file pins `chainId` 1 and marks the five `updateNewTotalAssets` entries `unconstrained` only
  because the vaults are unfunded: a NAV band or the Lagoon-side controls of §8 come before any
  funding. The sync task enforces the dependency: an unconstrained NAV entry on a vault whose
  `totalAssets()` is not zero is refused unless `--allow-unconstrained-nav` is given knowingly (the
  live vaults hold about 1 USDC of dust, so the first mainnet sync needs the flag or a band). The
  file ships without a `guard` pin and is therefore not deployable as shipped: pin the address the
  deploy script prints right after deployment (§7.2).
- Required fallback handler `0x0`, enforced (see §7.3); the Safe's narrow-only guardians as listed
  in the file (deployment-wide guardians hold `GUARDIAN_ROLE` instead). `mode` is `Enforced`; the
  file can never request `Bypass`.

Caveats: `updateNewTotalAssets` is unbounded until §8's guardrail step is done; `expireTotalAssets`
must be added if `totalAssetsLifespan` is ever raised above zero (§7.5).

Deliberately not allowed (use `approveTransaction` case by case; the council approves owner
management and venue one-offs within 7 days, the admin everything else):

- Safe admin (`addOwnerWithThreshold`, `changeThreshold`, `swapOwner`: council; `setGuard`,
  `setModuleGuard`, `enableModule`, `setFallbackHandler`: admin only).
- Lagoon owner/safe admin: `updateSafe`, `lockUpdateSafe`, `transferOwnership`,
  `updateValuationManager`, `updateWhitelistManager`, `updateFeeReceiver`, `updateSecurityCouncil`,
  `updateSuperOperator`, `updateRates` (fees), `switchAccessMode`, `pause`, `unpause`,
  `initiateClosing`, `close`, `activateAsyncOnly`, `setSyncMode`, `updateMaxCap`,
  `updateTotalAssetsLifespan`, `resetHighWaterMark`, `expireTotalAssets`,
  `securityCouncilUpdateTotalAssets` (bypasses guardrails), `updateName/Symbol`, and the vaults'
  `DelayProxyAdmin` upgrade functions.
- Any token `transfer`, any swap, any DeFi venue (none in use yet; add per §5 when the curator's
  strategy set is agreed).

## 10. Test coverage

`FOUNDRY_PROFILE=guards forge test` (26 test files plus three helpers, 32 test contracts, 350 unit
tests plus 6 fork tests against the live Safe; one more file, contract and test under
`FOUNDRY_PROFILE=precancun forge test`, which needs a Shanghai EVM; the default profile recompiles the whole via-IR tree for ~25 minutes, the
`guards` profile only the guard tree; the fork suite needs
`ETHEREUM_FORK_NODE_URL` and a pristine fork block, CI pins one through `.github/actions/fork-blocks`
and runs `forge t --mc CuratorGuard`):

- `CuratorGuard.t.sol`: real Safe v1.4.1 proxy with a curator EOA signer; genuine
  `execTransaction(setGuard)` install; ERC-165 ids and every storage-slot constant pinned to the
  literal values Safe uses; the local EIP-712 hash equals `getTransactionHash`; lockdown default;
  enforced allow/deny; every self-call selector; guard-as-target; gas-refund rejection; delegatecall
  denial; `MultiSendCallOnly` batches (allowed, one bad entry, inner self-call, delegatecall entry on
  plain `MultiSend`, value on delegatecall, wrong selector, non-canonical head offset with and
  without a consistent length, trailing bytes, empty / truncated batches, inner value and native
  permissions, fuzzed entry counts); every rule kind including short calldata, dirty address words,
  bounded ranges against dirty / negative words (`LessThanOrEqual` fuzzed); native transfers;
  approvals (migration, single use, under lockdown, relative TTL and per-role caps, exact binding
  incl. executor, revocation, bulk revocation, a failed approved execution reverting the whole
  transaction whatever `safeTxGas` says: GS013 with zero, `ApprovedExecutionFailed` otherwise);
  configuration snapshot against a malicious unwrapper rewriting the guard, modules head, fallback
  handler, threshold and singleton; unwrapper code-hash pinning (canonical hashes pre-allowed,
  non-canonical code rejected at registration, re-checked at runtime, guardian can forbid);
  `Bypass` voids approvals and refuses new ones so nothing replays; admin exemption (a guard whose
  admin is the Safe never deadlocks); two-step admin transfer that can never target zero; required
  fallback handler; guardian narrow-only semantics; config validation; `OneOf` set lifecycle and
  cap; views and dry runs; a Lagoon-shaped end-to-end policy.
- `CuratorGuardRound2.t.sol` (the round-2 mutation killers): approvals bind the exact calldata and
  are valid at exactly their expiry, a failed approved attempt keeps the approval until a successful
  retry, the transient slot is cleared between sequential transactions, nested `execTransaction` of
  the same Safe is rejected (`NestedExecution`) under both an approved and a policy outer
  transaction, `Bypass` skips every check, stale approval records read dead after
  `revokeAllApprovals` and can be cleaned; ERC-4626 withdraw-shaped rules pin receiver and owner
  words; access control on every widening and narrowing entry point for guardians and strangers
  (role grants and admin transfer included); zero-address guards; `allowFunctions` atomicity;
  `OneOf` at the cap and isolated
  per `(selector, word)`; rule replacement; events pinned with `expectEmit`; evaluation order;
  an allowlisted venue re-entering the hooks; a Safe accepting the admin role mid-flight (through a
  Bypass window, since the guard can never be an approval target); two guarded Safes nested;
  owner-list swap, module guard, singleton swap to a working singleton, a singleton that lies in
  `getStorageAt` (caught through `masterCopy()`) and owner-count writes caught by the snapshot; the
  nonce slot documented as out of scope.
- `CuratorGuardV2.t.sol` (IMPROVEMENTS_V2.md items 1-5): the role matrix (admin widens; council,
  both guardian kinds and strangers cannot; council fast lane; guardians narrow only, the per-Safe
  one scoped to its Safe and unable to touch deployment-wide state; `revokeApproval` scoped to the
  approval's Safe); council approval limits (`setGuard`, `setModuleGuard`, `enableModule`,
  `setFallbackHandler`, any delegatecall refused) against admin approvals of the same payloads; approval
  events with absolute expiry and epoch, validity at exactly the expiry; guard never an approval
  target; `Bypass` caps per role, expiry reading and behaving as `Lockdown`, inclusive last second
  agreed by pre- and post-hook, `ModeUpdated` carrying the window; a council flip into `Bypass`
  inside a policy transaction leaving no stale slot and the reverse flip failing closed; approved
  then policy execution in one EVM transaction; zero-`to` MultiSend entry rejected; and the
  production topology with a real `CuratorGuardTimelock` as admin (two proposers, one canceller, no
  deployer admin; widening waits for `minDelay`, early execute refused, the canceller Safe cancels,
  proposer cannot bypass the timelock,
  council and guardians stay immediate, relative approval TTL survives a 40-day-late execution, the
  guard's own admin-transfer delay).
- `CuratorGuardSignatures.t.sol`: 2-of-3 Safe with sorted EOA signatures, a contract signer
  (`v == 0`), pre-validated signatures (`v == 1`, via `approveHash` and via `msg.sender`) and
  `eth_sign` (`v > 30`): each shape passes an allowed payload through the guard and surfaces the
  guard's typed error on a denied one.
- `CuratorGuardEip1271.t.sol`: real `CompatibilityFallbackHandler` v1.4.1 + a USDC-shaped
  1271-aware token: the zero-transaction drain with the handler installed, the required-handler
  policy freezing traffic until the approved `setFallbackHandler(0)` lands, the closed permit path.
- `CuratorGuardModule.t.sol`: real Safe v1.5.0 with `setGuard` + `setModuleGuard`; module
  allowlist; executor-bound approvals in both directions; a failed approved module execution reverts
  and keeps its approval (no restore state); a module transaction nested inside an approved owner transaction;
  module guard without the transaction guard; owner snapshot surviving a later module-path
  snapshot; in-flight state per path, an outer failure rolling back the inner consumption;
  `ModuleNotAllowed` before `SafeLockedDown`; `validateModuleTransaction`.
- `CuratorGuardMultiSendDiff.t.sol`: differential fuzz (3,000 runs, random and corrupted
  payloads): whenever the guard accepts a `multiSend(bytes)` payload, a strict reference decoder
  agrees and the real `MultiSendCallOnly` executes exactly the validated entries.
- `CuratorGuardInvariants.t.sol`: handler-driven invariants (admin widens, council runs the fast
  lane, per-Safe and deployment-wide guardians narrow, strangers try 23 entry points, a curator drives
  the genuine `execTransaction`, time passes): guardians never widen (role surface included), council
  actions never grow the allowlist, strangers never change state, the approval epoch is monotonic and
  counts every bump (bulk revocations, `lockdownAndRevoke` and Bypass windows), live approvals belong
  to the current epoch, no live approval coexists with a Bypass window, no approval is consumed inside a
  window and Lockdown is never breached without one, an expired window reads as `Lockdown`, every
  passed curator transaction is reported by exactly one `TransactionChecked` carrying its `safeTxHash`
  and the outcome the handler predicted, bookkeeping views are consistent, `OneOf` sets never outlive
  their rule.
- `CuratorGuardMutation.t.sol`: the round-2 mutation killers (live-hook expiry boundary, every
  `AdminIsGuarded` term alone, pinned caps and seeded code hashes against the safe-deployments
  package, self-call scoping of the council limits, value-carrying denied self-calls, zero-address
  edges, dry-run / live agreement for the council window's delegatecall limit) and the council-window
  limits, module allowlist included, on the Safe v1.5.0 module path.
- `CuratorGuardRound6.t.sol`: the timelock's constructor topology and rails (proposer / veto
  separation, zero-address refusal, delay clamp at both edges on the raw slot, open executor and self admin kept,
  last holders kept, counters unmoved by no-op revokes, a compromised proposer removable and a
  compromised veto only a deadlock), the council lane's precompile exclusion, the constructor's
  `council == admin` refusal, the `lockedAt` view, the effective-mode admin hand-over, council
  approvals bound to allowlisted modules.
- `CuratorGuardRound7.t.sol`: the mutation campaign's killers (a one-byte-short council payload
  typed, the canonical 36-byte `setFallbackHandler(0)`, a partial-selector self-call refused on the
  policy path, the admin refused on itself as a Safe, a singleton swapped mid-transaction typed,
  `ApprovalConsumed` naming the module on the module path).
- `CuratorGuardRobustness.t.sol` (IMPROVEMENTS_V2.md items 8, 9, 12; v1.4.1 fixture plus a v1.5.0
  module fixture): a configurable Safe look-alike whose configuration views panic, revert, answer a
  malformed owner array, or answer too few / too many / no storage words, each surfacing as
  `SafeConfigUnreadable` in the pre-hook and the dry run (the healthy one passes as a control); the
  premise on the 0.8.25 build of the real Safe (`ownerCount` below the list panics `getOwners()` with
  index-out-of-bounds; the deployed 0.7.6 singletons hit `INVALID` instead and burn the forwarded gas,
  same typed error, asserted on the fork),
  the typed error on the real Safe with recovery through a council approval, a council window and an
  admin window, and the policy path back once consistent; a v1.4.1 module turning the configuration
  unreadable mid-transaction (typed, rolled back) versus readable-but-changed (`SafeConfigChanged`);
  the post-hook alone; a dry run against an account without code; handler word masking; every digest
  component (owner list, owner count, threshold, modules head, handler, guard, module guard) still
  caught through the raw reads; the constructor's EIP-1153 probe (exactly one `tload` and `tstore`, no
  `mcopy`, in the constructor part of the creation code, found by locating the runtime object by hash,
  and the same creation code deploying through a raw `create`); `lockdownAndRevoke` (role matrix with
  a stranger and a foreign guardian refused, events in order, window closure, idempotence and scoping,
  through `executeBefore`, and the approved payload that `lockdown` alone lets through dying); and
  `TransactionChecked` (safeTxHash pinned against `getTransactionHash`, Approval after
  `ApprovalConsumed`, Bypass for admin and council windows up to the window's last second, admin
  silent on both paths, one report per MultiSend batch, a failed `safeTxGas != 0` execution still
  reported next to the Safe's `ExecutionFailure`, the rejection self-call, refused transactions
  unreported, the outcome encoding per slot state; on v1.5.0: the module payload hash returned by the
  pre-hook and echoed by the post-hook, Policy / Approval / Bypass per outcome, a failed approved
  module execution reporting nothing and keeping its approval, owner and module paths reporting
  independently, `lockdownAndRevoke` covering module-bound approvals, the unreadable configuration on
  the module path and its dry run, council and admin windows both keeping the module allowlist). Its second test contract (`CuratorGuardRound4FindingsTest`) holds the round-4 review
  findings (§13.2): dry-run error precedence
  equal to the live hook, the guard unreachable from a Safe inside an admin window (and the documented
  batch-entry residual), the council self-call allowlist for approvals and windows executed for real
  (add / swap / remove owner, threshold, `disableModule`, handler reset, rejection) with the denied
  shapes (`setGuard`, `setModuleGuard`, `enableModule`, another handler, `approveHash`, `setup`, an
  unimplemented selector, a 2-byte payload), the stateful-fallback-handler vector closed for the
  council and open to the admin, the selectors pinned to Safe v1.4.1 and v1.5.0, a Safe holding the
  council role unable to authorise itself, and the typed error for an absurd `multiSend` length; and
  the round-5 hardenings: the one-day admin cooldown after any lockdown (lifts, windows, approvals,
  through `executeBefore`, boundary second, other Safes and widenings unaffected, the council never
  held back; `CuratorGuardV2.t.sol` replays it through a real timelock with a queued lift, window and
  approval; the invariant suite probes it on every run) and the council's new-owner rule (the guard
  itself, a venue, a Safe-like contract and an EIP-7702 designator refused for `addOwnerWithThreshold`
  and `swapOwner`, approvals and windows, live and dry run; a plain key accepted).
- `test/guards-precancun/CuratorGuardPreCancun.t.sol` (`FOUNDRY_PROFILE=precancun`, EVM version
  Shanghai, compiled without Cancun opcodes): reads the guard's Cancun creation code from
  `out-guards/` and shows that a raw `create` fails on a pre-Cancun EVM while a plain contract deploys;
  it skips itself wherever transient storage exists (a `PUSH0 TLOAD POP STOP` probe), so the default
  profile, which compiles this directory too, is unaffected.
- `CuratorGuardGas.t.sol`: per-transaction overhead, bounded at 80k gas (47.6k measured with one
  owner, of which about 2k is the `TransactionChecked` event).
- `CuratorGuardRound8.t.sol` (round 8, §13.2 V2-83…): an approved truncated batch refused at use with
  the approval kept, canonical approved batches (self-calls, value, an unregistered canonical build)
  still working and unable to address the guard; the delegatecall code pin and the approval-target
  checks (codeless, EIP-7702 designator, executor); the Safe code pin on the pre-hook, the post-hook and
  the dry run with approvals and windows unaffected, `masterCopy()` answering anything but one word;
  `ModuleNotHooked` on v1.4.1 and, in a second contract, on a real v1.5.0 Safe until
  `setModuleGuard(guard)` lands; a guard answering hooks only where it is installed (replacement and
  retired guard); forwarded hook calls through the Safe's real fallback; role-grant rails, the admin
  delay floor and the pending-admin expiry; the floor pairing, the tail-hash rule (`EqualTo` and
  `OneOf`, trailing byte, short payload) and the code check on call targets; selector and guardian
  caps and O(1) revocation (no per-member event, a fresh generation); the council window's refund
  refusal; a non-seeded hash refused in both directions; the one-batch singleton migration with the
  `setModuleGuard`-before-migration trap; the guard never a guardian; and, in a third contract, the
  cooldown pins (removing the locker does not end it, a re-lock restarts it, an unconfigured Safe
  starts it).
- `CuratorGuardRound8Forwarded.t.sol`, `CuratorGuardRound8RoleRail.t.sol`,
  `CuratorGuardRound8RailLimits.t.sol`: no padding (0 to 63 bytes) gets a forwarded hook call through,
  the window exit stays open with the guard as handler, other handlers do not trip the check, the
  parked-snapshot residual; a council or guardian Safe with the guard as handler gives a stranger no
  role (v1.4.1 and the library's own `onlyRole` / `renounceRole`), ordinary holders unaffected, gas
  starvation of the probe never yielding a state change.
- `CuratorGuardRound8Timelock.t.sol`, `CuratorGuardRound8TimelockRail.t.sol`: the timelock never
  holds a gated role (by construction or grant, through a batch or a nested `execute`), no second
  admin, a full rotation of both proposers and the veto in one batch, the proposal-time rails behind
  the proposer check and the base's length check, `execute` refusing a target whose code is gone, the
  inclusive edges of `updateDelay`; a proposer or veto Safe with the timelock as handler gives a
  stranger neither `schedule` nor `cancel`.
- `CuratorGuardStrangers.t.sol`, `CuratorGuardCrossSafe.t.sol`, `CuratorGuardHostileSafe.t.sol`,
  `CuratorGuardRolesAsCallers.t.sol`, `CuratorGuardTimelockSurface.t.sol` (on
  `CuratorGuardStrangersBase.sol`): every state-changing selector of the ABI (pinned against the
  compiler's method identifiers) called by an EOA, `address(0)`, a contract, a contract under
  construction, an unconfigured Safe, a Safe configured on another guard, another guard instance, a
  sibling Safe and a sibling's guardian, directly and wrapped in `executeBefore`, changing nothing;
  isolation between Safes sharing one guard (lockdown, cooldown, epoch, `OneOf` sets, approvals,
  nested and sequential Safe transactions, one Safe as the other's target, module or EIP-1271 owner,
  the Safe-bound module report hash); a hostile "Safe" that re-enters from its configuration reads;
  role holders as hook callers; the timelock's public surface.
- `CuratorGuard.e2e.ethereum.t.sol` (fork): applies the whole policy file to the live Vetro Safe
  (functions, `OneOf` values, unwrappers, guardians, handler requirement; empty lists asserted),
  installs through the runbook's §7.4 batch (handler removal + `setGuard` in one genuine
  `MultiSendCallOnly` `execTransaction`), replays the exact batch shape the Safe executed on mainnet,
  shows the drains and admin escapes the policy stops, guardian lockdown + council lift + council
  approval of owner management with a `lockdownAndRevoke` drill in between (the approved payload dies
  with the lockdown), `TransactionChecked` under the live Safe's own `safeTxHash` for the settlement
  batch (Policy) and the approved owner change (Approval), and the handler requirement (a re-installed
  handler freezes traffic, the council cannot approve handler changes, the admin can).

- Round 9 (g9f) additions, `test/guards/G9f_*.t.sol` on a shared `G9fBase.sol` (a harness with a
  digest probe and a code-hash probe): `G9f_RuleFuzz` (every rule kind, the tail flag, missing and
  dirty words, the ANDed order, fuzzed against a reference and agreed by the dry run and the live hook;
  the rule-shape validation fuzzed the same way), `G9f_MultiSendFuzz` (the strict decoder in the council
  window and on an approved batch, against a reference; the inert non-zero padding pinned),
  `G9f_DigestFuzz` (the digest equals the documented concatenation, moves with every covered word and
  nothing else, the post-hook follows it), `G9f_Invariants` (the repository handler over a wider universe
  with five new ghosts: dry-run / live agreement, batch composition, no passed transaction moves the
  digest, a lockdown closes the window, the council cap), `G9f_Mutation` (killers for the five
  unit-visible survivors of the round-9 campaign of 151 hand-written mutants, the module-path digest
  comparison, the four approval claims of section 4 that had no test, the six singleton hashes against
  the safe-deployments package) and two
  fork suites: `G9f_SafeCodehashes.e2e` (all nine canonical proxy and singleton hashes against mainnet)
  and `G9f_Gas.e2e` (the hooks on the shipped policy and the live Safe). `FOUNDRY_PROFILE=guards_deep`
  runs the invariant suites at 1,024 runs x 50 depth without leaving the guard tree.

`forge coverage` cannot run over these suites (the vendored Safe sources are not via-IR
compatible, which `--ir-minimum` requires), and `FOUNDRY_PROFILE=guards forge build --sizes` exits
non-zero only because the test-only `PolicyHandler` (invariant harness) exceeds the EIP-170 limit; the
deployed contracts are checked by `scripts/check-contract-sizes.sh` on hardhat artifacts. Instead, round 2 ran a 71-mutant campaign against the
guard contracts in a scratch harness (not kept in-tree): every non-equivalent mutant is killed by
the suite above. Round 3 rehearsed the whole runbook on a mainnet fork through real
`execTransaction` calls signed by the live Safe's own owner set.

## 11. Review log

Historical (v1): the test names and the `owner` terminology in this section are as of v1; the v2 renames
(admin / council / guardians, `enforce` / `bypass`, relative TTLs) are in §13.

Three adversarial review rounds were run on the implementation before hand-off. Each round used
independent reviewers with distinct lenses; every finding was reproduced (Foundry PoC) before it
was accepted, then fixed with a regression test. Severity follows the usual
Critical / High / Medium / Low / Informational scale.

### Round 1: contract-level (Safe integration; calldata & rules; access control & state)

| # | Sev. | Finding | Resolution |
|---|---|---|---|
| R1-1 | High | With the canonical `CompatibilityFallbackHandler`, a signer quorum can sign a Safe message off-chain and USDC honours it as the Safe's EIP-1271 signature in `permit` / `transferWithAuthorization`: full USDC drain with zero Safe transactions, never seen by the guard. The earlier doc wrongly claimed spender scoping covered this (these paths need no allowance). | Per-Safe `requiredFallbackHandler` (enforced): the policy refuses to run until the handler equals the configured value (`0x0`); approved `setFallbackHandler(0)` is the install step; snapshot also catches in-tx handler changes. Tests: `CuratorGuardEip1271.t.sol` (drain demonstrated against the real handler, then closed), fork test against the live handler. Runbook §7.3, policy file. |
| R1-2 | Medium | `GreaterThanOrEqual` alone is fail-open: a word with dirty high bits (masked by ABI-coder-v1 / Vyper callees) or a negative `intN` exceeds any floor. | Lower bounds are rejected at config time unless an upper bound (`LessThanOrEqual` / `EqualTo` / `OneOf`) exists on the same word; sync task mirrors the check. Test: `test_bounded_range_rejects_dirty_high_bits_and_negative_ints`. |
| R1-3 | Low | `OneOf` value sets survived rule replacement and revocation (dormant sets re-activated when a `OneOf` rule returned); values could be added before any rule existed. | `allowFunction` clears the sets of dropped `OneOf` rules; `addAllowedValues` requires a live `OneOf` rule; sync task and fork fixture order calls accordingly. Tests: `test_stale_oneOf_set_is_cleared_when_the_rule_is_dropped`, `test_oneOf_set_is_preserved_while_the_rule_is_kept`. |
| R1-4 | Low | Installing the guard on the guard-owner Safe deadlocked everything irreversibly (admin calls are themselves guarded). | All hooks exempt `msg.sender == owner()`. Test: `test_owner_safe_is_never_constrained_so_self_install_cannot_deadlock`. |
| R1-5 | Low | Approvals were not consumed in `Bypass` (one approval, two executions across a Bypass window); no bulk revocation for incident response. | Approvals are consumed in `Bypass`; per-Safe approval epoch + `revokeAllApprovals` (owner or guardian). Tests: `test_approval_is_consumed_in_bypass_and_cannot_replay_afterwards`, `test_revokeAllApprovals_voids_every_outstanding_approval`. |
| R1-6 | Low | An approval was consumed (and `ApprovalConsumed` emitted) even when the Safe reported `success == false` (`safeTxGas != 0`). | In-flight approvals live in transient storage and are restored on failure (`ApprovalRestored`); runbook says to sign approved transactions with `safeTxGas = 0`. Tests: `test_approval_is_restored_when_the_approved_execution_fails`, module variant. |
| R1-7 | Low | `FunctionAllowed` carried only a rule count, so rule weakening was invisible to monitors. | Event carries the full rule list; `TransactionApproved` carries the full calldata. |
| R1-8 | Info | The guard itself (and the Safe) were accepted as targets / unwrappers; an allowlisted `guard.checkTransaction` entry could burn approvals and disable the post-check. | `InvalidTarget` at config time, `GuardCallNotAllowed` at runtime. Tests in `test_config_validation`, `test_guard_is_never_a_valid_call_target_at_runtime`. |
| R1-9 | Info | Approvals were path-agnostic: an allowlisted module could spend an approval meant for the signers. | Approval id binds `executor` (`0x0` = signers, else the module). Tests: `test_approvals_are_bound_to_their_execution_path`, `test_module_bound_approval_does_not_require_the_module_allowlist`. |
| R1-10 | Info | A module transaction inside an approved owner transaction cleared the single in-flight flag early (fail-closed, but an approved migration batch could not contain module calls). | Separate transient in-flight / snapshot slots per execution path. Test: `test_module_transaction_nested_in_an_approved_owner_transaction`. |
| R1-11 | Info | The post-check only verified the guard slot; a mis-registered delegatecall target could still link a module, swap owners / threshold / handler / singleton. The doc overstated the check. | Pre/post configuration snapshot (singleton, owner count, threshold, owner list, modules head, fallback handler, guard, module guard) in transient storage; any change reverts `SafeConfigChanged`. Tests per slot in `CuratorGuard.t.sol`. |
| R1-12 | Info | Unbounded `OneOf` sets could make `revokeFunction` exceed the block gas limit. | `MAX_ALLOWED_VALUES = 128`; `lockdown` / `revokeAllApprovals` stay O(1). Test: `test_oneOf_set_is_capped`. |
| R1-13 | Info | Event / view nits: `revokeFunction` emitted for never-allowed functions, `setMultiSendUnwrapper(…, 0x0, false)` accepted, `ApprovalRevoked` had no Safe, re-approval silently overwrote expiry. | No-op revoke is silent; zero unwrapper rejected; approvals store their Safe; semantics documented. |
| R1-14 | Info | No dry run for the module path. | `validateModuleTransaction`. |
| R1-15 | Info | Tooling did not validate `wordIndex` against the signature (a rule on a non-existent or dynamic word is both a DoS and trivially satisfiable by padding). | `curator-guard-sync` derives the head layout and rejects such rules. |
| R1-16 | Info | Doc wording on nested `execTransaction` ("fails closed") was imprecise. | Reworded: unsupported, never opens. |

Round 1 also confirmed as sound (with differential fuzzing, in a scratch harness, against the
real `MultiSendCallOnly` compiled with solc 0.8.25 and with the mainnet artifact's solc 0.7.6): decoder equivalence, hook ordering / TOCTOU, gas-refund gating,
self-call coverage, ERC-165 / slot constants, approval binding, role separation, `Ownable2Step`
behaviour, data-model consistency, and liveness of the recovery paths.

### Round 2: cross-cutting (Lagoon operations & systemic; tooling & config; tests & code quality)

| # | Sev. | Finding | Resolution |
|---|---|---|---|
| R2-1 | High (governance) | The proposed guard owner Safe (`0x6649…`, 3-of-6) shares three owners with the curator Safe: three colluding curator keys meet the owner quorum and could widen or bypass the policy. | Not fixable in code. Documented prominently (§1, §6, `helpers/address.ts`) as a decision to take before deployment: different owner Safe, higher threshold / non-curator signer, or a widening timelock. |
| R2-2 | Medium (doc/policy) | The doc and policy claimed Lagoon's guardrails bound `updateNewTotalAssets`; on the live vaults guardrails are deactivated and the curator holds `securityCouncil`, so NAV is unbounded through allowed calls. | Corrected (§1, §5, §6, §9); §8 now spells out `securityCouncil` → Vetro + guardrail activation, the `valuationManager` decision, proxy-admin ownership. |
| R2-3 | Medium (logic) | A nested `execTransaction` of the same Safe inside an approved payload shared the in-flight slot: a failing inner transaction restored the outer approval, letting the approved payload run twice; a benign nested one smuggled a snapshot. | `_preCheck` reverts `NestedExecution` when an in-flight or snapshot slot is already set for `(safe, path)`; the post-check clears the snapshot so sequential transactions still work. Tests: `test_nested_execTransaction_inside_an_approved_payload_is_rejected`, `test_sequential_execTransactions_in_one_transaction_are_allowed`. |
| R2-4 | Medium (tooling) | The policy validator ignored unknown keys and string booleans: a `rule`/`rules` typo produced an unconstrained `approve`, a `requireFallbackHandler` typo silently dropped the handler requirement, `"enforce": "false"` applied `true`. | Strict schema (allowed keys per level, typed booleans/ints, decimal-string numbers), `requiredFallbackHandler` mandatory, allowance-shaped selectors need a word-0 rule unless `unconstrained`, contract limits mirrored (16 rules, 128 values, targets ≠ Safe/guard, unwrappers must have code), `--allow-bypass`. Eleven malformed policies verified rejected. |
| R2-5 | Medium (tooling) | Selectors were `keccak(raw string)`: parameter names or `uint` aliases produced garbage selectors, and an explicit `selector` was never cross-checked. | Canonical `FunctionFragment` signature required; `selector` must agree. |
| R2-6 | Medium (CI) | Submodule gitlinks were unstaged, so a fresh CI checkout would miss the Safe sources and break every Foundry workflow. | Documented in §7.5 (`git add .gitmodules lib/safe-smart-account lib/safe-smart-account-v1.5.0` when committing); left unstaged deliberately until the green light. |
| R2-7 | Medium (deploy) | hardhat-deploy would redeploy the immutable guard on any bytecode/metadata drift and repoint the artifact. | `skipIfAlreadyDeployed: true`; replacement guards use a new alias. |
| R2-8 | Low | 35 of 71 mutants survived the round-1 suite, including dropping the calldata hash from the approval id, dropping `onlyOwner` on `allowFunctions` / `addAllowedValues`, dropping the owner list / module-guard slot from the digest, never clearing the in-flight marker, and keying `OneOf` sets without selector/word. | Round-2 suites added (`CuratorGuardRound2`, `Signatures`, `Invariants`, `MultiSendDiff`, `Gas`, module-path tests); re-running the campaign kills every non-equivalent mutant. |
| R2-9 | Low | Absent-key semantics of the policy file were asymmetric; JSON numbers could lose precision; the EOA execution path logged "executed" before confirmation; the dry-run script exited 0 on a wrongly allowed call; Etherscan verification was attempted on fork networks; `safe.batch.tmp.json` was not ignored and a stale file could be merged. | All fixed in the task, scripts and `.gitignore`. |
| R2-10 | Low | No CI workflow exercised the guard suites. | `.github/workflows/curator-guard.yml` on the repo's pattern (`forge t --mc CuratorGuard`). |
| R2-11 | Low | Emergency `pause()` needs a Vetro approval; `expireTotalAssets` becomes necessary if `totalAssetsLifespan` is raised; the vault proxies' admin is the curator Safe's `DelayProxyAdmin`. | Documented (§6, §7.5, §8, §7.7 monitoring). |
| R2-12 | Low | Approvals had no maximum lifetime; access checks ran after argument validation in two setters; `_fallbackHandler` duplicated a read; transient keys re-hashed a string literal per call; NatSpec gaps; two unused `ISafe` members; a wrong pre-existing comment in `ILagoonVaultV06`. | `MAX_APPROVAL_TTL = 30 days`; access checks first; namespaces precomputed; NatSpec added; interface trimmed; comment fixed (the `OneOf` cap is still checked after the insert loop, which is correct because the revert rolls the inserts back). |
| R2-13 | Info | Doc wording: "Vesper governance Safe", "tests pin the order" (now true), e2e fixture rule-kind limits, sync-list omissions. | Fixed. |

Round 2 also confirmed: every policy selector and vault/asset pairing against the deployed
Lagoon implementation and on-chain `asset()`; the settlement allowance model (`settleRedeem` /
`close` pull via `safeTransferFrom(safe, …)`, so the matching vault is the only spender needed);
`claimSharesOnBehalf` / `claimAssetsOnBehalf` never redirect value; the diff/ordering semantics of
the sync task across a 7-step policy evolution; `tsc` / `eslint` clean on the new files; hardhat
and foundry both compile the guard on the legacy pipeline (19.8 kB / 18.7 kB runtime, within the
size gate); test fidelity of the local EIP-712 hashing for v1.4.1 and v1.5.0.

### Round 3: final verification (fresh contract re-review; doc-vs-code audit; runbook rehearsal on a mainnet fork)

| # | Sev. | Finding | Resolution |
|---|---|---|---|
| R3-1 | Medium | The configuration digest reads the modules linked-list head and the owner list, so a delegatecall target that writes a dangling `modules[x]` (or `owners[x]`) mapping entry directly is invisible to it: an invisible, permanent module backdoor on v1.4.1 (reproduced). Precondition: an owner-registered unwrapper that is not `MultiSendCallOnly`. | Unwrapper code is pinned by hash: `setUnwrapperCodehash` (owner allows, guardian forbids), pre-seeded with the canonical `MultiSendCallOnly` v1.3.0 / v1.4.1 runtime hashes, checked at registration and on every delegatecall. The sync task pre-flights it. Tests: `test_canonical_multisend_call_only_hashes_are_pre_allowed`, `test_unwrapper_code_hash_is_rechecked_at_runtime`, `test_storage_writing_unwrapper_cannot_be_registered_without_a_codehash_mistake`. Doc §4/§6 now state the digest's mapping blind spot. |
| R3-2 | Low | `Bypass` skipped the nested-execution check but still consumed and restored approvals: a nested failing inner transaction could restore the outer, already-executing approval (reproduced). | `Bypass` is fully inert (no approval bookkeeping); `curator-guard-sync` voids all approvals when a Safe enters or leaves `Bypass`, runbook §7.6 says so. Tests: `test_bypass_is_inert_for_approvals_and_revokeAllApprovals_prevents_replay`, `test_bypass_leaves_approvals_untouched_and_skips_the_refund_check`. |
| R3-3 | Low | A swapped singleton that forwards to the real one but lies in `getStorageAt` about slot 0 passed the digest (reproduced). | The digest also reads `masterCopy()`, which `SafeProxy` answers from the proxy bytecode without delegating. Test: `test_post_check_catches_a_lying_singleton_through_masterCopy`. |
| R3-4 | Medium (ops) | The runbook never provisioned guardians; guardians are per deployment, so after a guard replacement the responder keys' `lockdown` / `revokeAllApprovals` reverted `Unauthorized` (reproduced on the fork). | `guardians` is a mandatory, fully-synced key of the policy file; §7.2 / §7.5 require syncing the replacement guard before switching; the shipped file has an empty list to fill before go-live. |
| R3-5 | Medium (ops) | The monitoring list missed `NativeTransferUpdated` (a widening), `OwnershipTransferred`, Safe `ChangedThreshold` and `ExecutionFailure` (needed to pair with `ApprovalRestored`). | §7.7 completed (also `UnwrapperCodehashUpdated`, `ExecutionSuccess`). |
| R3-6 | Low | Only the in-flight half of the nested-execution check had a test; `approvalExpiry` reported stale (pre-`revokeAllApprovals`) records as live; the deploy script could not produce the replacement alias §7.5 promised. | Snapshot-half test added (`test_nested_execTransaction_inside_a_policy_transaction_is_rejected`); approvals store their epoch and `approvalExpiry` returns `0` for stale ones; `CURATOR_GUARD_ALIAS` env for the deploy script. |
| R3-7 | Low (doc) | Stale or over-stated statements: the §4 nesting mechanism described the pre-R2-3 behaviour and the evaluation order omitted the nested check; "Vyper masks dirty bits" (Vyper clamps and reverts); `instantLiquidity()` "idle only"; `updateGuardrails` signature; the `eth_sign` suite claimed a typed-error assertion it lacked; "all covered" for withdraw-shaped rules; entry/exit fees cannot be raised; validator checks were presented as unconditional although selector-only entries bypassed them; the §9 not-allowed list omitted `updateRates` and friends; gas numbers were warm-state only; the §7.2 dry run reverts on the live handler; which guard an approval must be placed on; how to enumerate allowances; cbBTC does expose a (ECDSA-only) permit. | All corrected in the text; `signature` is now mandatory in the policy file so every entry gets the head-layout and allowance-shape checks; the `eth_sign` test asserts the typed error; a withdraw-shaped rule test was added; cold gas numbers from the rehearsal are quoted. |
| R3-8 | Info | Process claims (mutation campaign, malformed-policy fixtures, 0.7.6 differential build, 7-step policy evolution) are not reproducible from the tree; the Safe history facts rely on the Transaction Service (archive logs are not available on free RPCs); the e2e fork suite needs a pristine block. | Marked as scratch-harness results in §10 / §11; CI pins the fork block. |

Round 3 also confirmed closure of every contract-side round-1 and round-2 item (fresh re-review with
PoCs for each regression hypothesis, none reproduced except R3-1 … R3-3), and that the runbook
executes as written on a mainnet fork through genuine `execTransaction` calls with the live
Safe's owner set: deploy, sync, one-batch handler removal + install, every §6 block with its
documented error, dry runs matching live behaviour at every stage, approvals with `safeTxGas = 0`
and restoration with `safeTxGas != 0`, guardian lockdown and bulk revoke, Bypass recovery,
replacement and removal. Open before go-live (decisions, not code): the guard-owner quorum overlap
(§6), the Lagoon role moves and guardrail activation (§8), and the guardian key list (§9).

## 12. Design review: is this the best way to onboard a third-party curator? (Round 4, 2026-10-04)

Rounds 1–3 asked "is the implementation correct?". Round 4 asked a different question: **is a
Safe transaction guard on the curator's own Safe the best possible way for the collective owners
of Vetro to place and modify guardrails on a third-party curator running a Lagoon vault?** Twenty
independent reviewers each took one lens and scored the proposal 1–5 on four axes: **A** security
and on-chain auditability, **B** robustness, **C** fit for a future in which a decentralised Vetro
governance controls the guardrails, **D** curator friction (an existing Lagoon curator should not
have to change workflow or tooling). Each reviewer also had to answer "is there a better
alternative, and under what conditions?". Most re-ran the 151 guard tests against a mainnet fork
(blocks 26,121,976–26,122,002), several wrote scratch PoCs (kept under the session scratchpad,
not in the tree), and five did web research on Lagoon, Safe, Zodiac and peer protocols. No
repository code was changed in this round; the doc corrections it produced are listed in §12.7.

### 12.1 Scores

| # | Lens | A | B | C | D | Better alternative? |
|---|---|---|---|---|---|---|
| L1 | Zodiac Roles v2 as the alternative | 4 | 3 | 4 | 4 | No today; Roles 2.1.1 once Vetro accepts custody, swaps, automation or a Roles-native curator |
| L2 | Custody and ownership models | 3 | 3 | 3 | 4 | Yes: keep the code, change the topology (fresh Vetro-created Safes; Roles if the curator is Roles-native) |
| L3 | Lagoon-native controls | 3 | 3 | 3 | 3 | Yes: Lagoon role moves are mandatory in every variant; Roles preferable unless Vetro wants no custody power |
| L4 | Safe{Wallet} UI and signer tooling | 4 | 4 | 3 | 2 | No, conditional on three UX fixes before install |
| L5 | Real curator workflows and venues | 4 | 3 | 2 | 2 | Yes: Vetro-owned Roles (hybrid acceptable) for any active curator |
| L6 | Decentralised-governance future | 4 | 3 | 2 | 3 | Yes: keep the engine, replace the single-owner authority layer before deployment |
| L7 | Fresh line-by-line audit | 4 | 4 | 3 | 3 | No, under the stated constraints; owner overlap must be resolved first |
| L8 | Attack tree: malicious 2-of-4 curator | 4 | 3 | 2 | 4 | No single substitute; layered design conditional on Lagoon moves and a clean owner |
| L9 | Attack tree: non-curator positions | 3 | 4 | 2 | 4 | Yes: timelocked owner, per-Safe guardians, pre-staged approvals; "should not ship" with the current owner |
| L10 | On-chain auditability and observability | 4 | 4 | 3 | 4 | No; with the event additions it matches or beats Roles on transparency |
| L11 | Robustness, liveness, failure modes | 4 | 3 | 2 | 3 | No, conditional on an operator role and tooling gates; not yet fit for a DAO owner |
| L12 | Evolution, migration, scale | 4 | 4 | 3 | 4 | No (UUPS or a policy registry are worse at this scale) |
| L13 | Operations and change management | 4 | 3 | 3 | 3 | No, under the constraint; three P0 process gaps before any external curator |
| L14 | Verification adequacy | 4 | 3 | 4 | 4 | Same stack, different verification architecture (coverage, Halmos, mutation in-tree) |
| L15 | Code quality and minimalism | 4 | 4 | 3 | 4 | Same architecture, leaner shape (≈750 lines, ≈45 selectors) |
| L16 | Economics and incentives | 4 | 3 | 3 | 4 | No single alternative; the guard alone is not the best design (caps, roles, fees dominate) |
| L17 | Industry practice | 3 | 3 | 2 | 4→2 | Yes: capital owner owns the Safe, manager is a Roles member (ENS/karpatkey, Spectra, Lagoon docs) |
| L18 | Lagoon future-proofing, shared Safe | 4 | 3 | 3 | 4 | Yes: one Safe per vault; Roles on Vetro-owned Safes unless the curator must own custody |
| L19 | Tooling and operator experience | 4 | 3 | 3 | 3 | No to replacing the abstraction; yes to layering artefacts and commands on it |
| L20 | Devil's advocate synthesis | 3 | 3 | 3 | 4 | Not the best possible; best-feasible under a self-imposed constraint that is free to drop today |
| | **Mean** | **3.75** | **3.30** | **2.80** | **3.50** | 10 "keep, conditional" / 10 "better structure exists, conditional" |

Reading the table: the guard scores well on what it was built for (A, D for a Safe-signer
curator) and poorly on the axis it was not designed around (C). The D column splits by curator
profile: for a curator whose signers use Safe{Wallet} directly it is a zero-change overlay; for a
curator who already runs Zodiac Roles and Pilot (L5's on-chain sweep found 18 of the 30
Safe-custodied mainnet Lagoon vaults run Roles) the guard is the foreign object and Roles would be
the zero-change option.

### 12.2 Consensus verdict

1. **The guard engine is sound.** The fresh audit (L7) and the adversarial lenses (L8, L9, L11)
   found no new Critical, High or Medium contract finding. Every new contract item is Low or
   Informational (§12.4, C1–C4). Round 1–3 closures held under re-review; two reviewers
   explicitly refuted their own replay hypotheses against the approval-restore path.
2. **The risk is in the structure around the guard, and it is the same four facts in almost every
   report.** (i) The proposed guard owner shares three keys with the curator Safe, so "owner
   honest, curator malicious" is not a real threat model today (L1, L2, L7, L8, L9, L13, L16, L17,
   L20). (ii) The curator Safe is also the vault owner, security council and valuation manager,
   guardrails are off and the vaults are public, so the dominant economic path (NAV marking
   against the Safe's own custody) never passes through the guard (L3, L8, L16, L17, L18, L20).
   (iii) A single owner with instant, total power is operationally unsafe once that owner is a
   DAO or a timelock: lifting a lockdown, one-shot approvals and curator key rotation all inherit
   governance latency (L6, L9, L11, L13, L17). (iv) Guarding a pre-existing shared Safe is what
   creates the install hazards (handler removal, allowance archaeology) and the shared blast radius
   across five vaults (L2, L18, L20).
3. **The proposal is the best feasible design under its own constraint, not the best possible
   design for the question asked.** The constraint "the curator keeps its Safe and signers; Vetro
   gets a veto but no custody power" was chosen in §3 and is reasonable if the curator must own
   custody as a liability boundary. But it is a choice, it costs about three dollars of custody and
   five `updateSafe` calls to drop today, and half the lenses concluded that Lagoon's own documented
   pattern (a Vetro-owned Safe with the curator as a Zodiac Roles 2.1.1 member) is the better
   long-run structure on A, B and C, tying or losing only on D for a Safe-signer curator. The
   other half concluded the guard should stay, every one of them conditional on the P0 list below.
4. **The order of operations is wrong as documented.** §8 (Lagoon role moves, guardrails, access
   mode) is the highest-leverage, zero-code control and must precede any TVL regardless of which
   execution-scoping design is chosen. Rounds 1–3 treated it as complementary; Round 4 treats it as
   a precondition (§8 note).

### 12.3 Decision matrix

Scores are the synthesis of the twenty reports, 1–5 with 5 best; cost 5 = cheapest, time 5 =
fastest. D is given for two curator profiles: a plain Safe-signer curator / a Roles-and-Pilot
native curator. "Hardening package" = the P0 items of §12.4.

| Option | A | B | C | D | Cost | Time | Right when |
|---|---|---|---|---|---|---|---|
| 1. Proposal as-is: guard on the shared 2-of-4 Safe, owner = governance Safe `0x6649…` | 3 | 3 | 2 | 4 / 2 | 5 | 5 | Never as-is: P0-1 and P0-2 are open |
| 2. Proposal + hardening package, still on the existing shared Safe | 4 | 4 | 4 | 3 / 2 | 3 | 3 | The curator must own custody and the mandate is settlement plus direct lending |
| 3. Proposal + hardening package on fresh per-vault Safes (v1.5.0, handler 0 and guard set at genesis, owned 1-of-1 by the curator's own Safe) | 4 | 4 | 4 | 3 / 2 | 3 | 3 | As 2, plus per-vault isolation and a clean install. **Recommended form of "keep the guard"** |
| 4. Vetro-owned Safe(s) + Zodiac Roles 2.1.1; curator Safe and bots as role members; Lagoon roles to Vetro | 4 | 4 | 5 | 2 / 5 | 4 | 4 | Vetro accepts custody power; the curator needs swaps, routers, CoW or keepers, or is Roles-native. **Recommended default once that acceptance exists** |
| 5. Hybrid: guard for the human-signed path, Roles module for bots (v1.5.0 module guard, or Roles owner = Vetro) | 4 | 3 | 4 | 3 / 4 | 2 | 2 | Automation is needed before a Roles migration; dissolves into 4 over time |
| 6. Lagoon role moves + guardrails + whitelist mode + Vesper `debtRatio` caps, no execution scoping | 2 | 5 | 5 | 5 / 5 | 5 | 5 | Always as the first step; sufficient alone only at test-scale TVL |
| 7. Merkle-manager (BoringVault style) or custom allocator module | 4 | 3 | 4 | 1 / 1 | 1 | 1 | Bot curators only; abandons Safe tooling |
| 8. Do nothing beyond caps | 1 | 5 | 5 | 5 / 5 | 5 | 5 | Only if the vaults are treated as external counterparties like any other venue |

What each alternative buys and what must be true:

- **Option 4 (Roles on a Vetro-owned Safe).** Removes the whole `execTransaction` attack surface
  the guard exists to police (no handler requirement, no refund check, no config digest, no nested
  execution check, no v1.4.1 module blind spot), adds condition trees, allowances, calldata
  unwrapping (Bundler3, EVC, multicall) and CoW via the stateless `OrderSigner`, and comes with the
  Roles app, subgraph and Pilot, i.e. standard DAO-treasury tooling. Vetro inherits the Lagoon
  roles with the Safe. Conditions: mastercopy 2.1.1 only (2.1.0 had the June 2026 ERC-1271
  issue); EOA or handler-less contract members; the Roles owner must be a quorum with no curator
  keys (the overlap in P0-1 makes Roles *worse* than the guard, because it hands those keys
  custody instead of policy); local call planning rather than the hosted Zodiac API. Cost: a
  cooperative owner swap or fresh Safes plus `updateSafe`, and the curator re-tools to
  `execTransactionWithRole` / Pilot (Lagoon's documented workflow). What it loses versus the guard:
  "Vetro can only censor, never take" becomes "Vetro can take", which matters only once non-Vetro
  depositors exist; and a Roles bug cannot brick the Safe whereas a guard bug can.
- **Option 3 (guard on fresh per-vault Safes).** Keeps every guard property, removes the install
  hazards (handler 0 and guard from genesis, no allowance archaeology), gives per-vault lockdown and
  policy, polices the module path (v1.5.0 `setModuleGuard`), and keeps curator key rotation on the
  curator's own Safe instead of in Vetro's approval queue (one nested-Safe hop, natively supported
  by Safe{Wallet}). Conditions: the hardening package, an external audit before TVL, and
  documented migration triggers to Option 4.
- **Option 6 (Lagoon-side only).** Dominant first move in every scenario. Insufficient alone
  against venue misuse or hidden theft under a compliant NAV curve, but `debtRatio` bounds Vesper's
  loss to `debtRatio × pool TVL` exactly as for every other external vault strategy in this repo.

### 12.4 Findings by priority

Numbering: **P0** = decide or do before any TVL; **P1** = do before an external curator is
onboarded; **P2** = backlog. Contract items are tagged C, tooling T, verification V, operations O.

**P0 (decisions and preconditions, whichever option is chosen)**

- **P0-1 Guard-owner quorum.** Three of the four curator signers are three of the six owners of
  the proposed guard-owner Safe (threshold 3). Nine lenses independently rated this the weakest
  link; two said the design should not ship with it. Fix in topology: a dedicated guardrails Safe
  with no curator keys (later a timelock or DAO executor), curator Safes containing only curator
  keys, a deploy-time preflight that intersects `getOwners()` recursively and refuses, and
  guardian alerts on `AddedOwner` / `SwapOwner` on both Safes (L1, L2, L7, L8, L9, L13, L16, L17,
  L20).
- **P0-2 Lagoon role moves, guardrails, access mode.** Two-step vault `owner` → Vetro timelock;
  `securityCouncil` → a *fast* Vetro council (guardrail exceptions and a legitimate −5 %/day move
  need it within hours); `feeReceiver` off the guarded Safe; the five `DelayProxyAdmin` ownerships
  → Vetro; `lockSuperOperator()` while it is zero (an unlocked `superOperator` can redeem any
  holder's shares, the Vesper strategies included, to a receiver of its choice); `whitelistManager`
  → Vetro, whitelist exactly the five `Lagoon_Vetro_*` strategies, `switchAccessMode(Whitelist)`;
  `updateActivated(true)` with real bounds per asset; decide `valuationManager` explicitly (an
  on-chain provider is enough while custody is idle). Guardrail cadence caveats to document:
  proposing NAV in the same block as the last settlement panics on division by zero, and after
  more than 365 days without settlement the annualised scale is zero so any mark passes; three of
  the five vaults have never settled with assets (L3, L8, L16, L17, L18, L20). The guard already
  denies `updateActivated` / `updateGuardrails` / `securityCouncilUpdateTotalAssets`, so guardrails
  can be switched on through two one-shot approvals today and the curator cannot undo them while
  the guard holds (L8). Do **not** `lockUpdateSafe()` while a third party is custodian (§12.6).
- **P0-3 Authority layer (C7).** Replace the single owner with three powers before any
  non-fast owner holds the guard: `ADMIN` (widening, Bypass, ownership; sits behind a 24–72 h
  timelock), `COUNCIL` (fast, no curator keys: `Lockdown → Enforced`, approvals for Safe owner
  management and `pause()`, time-boxed Bypass of ≤ 7 days that auto-reverts to Lockdown),
  `GUARDIAN` (narrow only, scoped per Safe, optionally time-boxed lockdown that the council must
  confirm). Approvals take a relative TTL capped per role (a DAO proposal with an absolute expiry
  reverts if executed early or late). `FunctionSpec` becomes self-contained (OneOf values included)
  so a proposal is desired state, not a diff that a guardian action during the vote can break.
  OZ `AccessControlDefaultAdminRules` is already available (L6, L7, L9, L11, L13, L17).
- **P0-4 Guardians and incident tooling (O).** The shipped policy has `guardians: []`, so day-one
  lockdown is a 3-of-6 Safe transaction; there is no approve, lockdown, revoke, validate or watch
  command and no on-call definition. Validator should refuse `Enforced` with no guardians on
  chain 1 (L13, L19, L11).
- **P0-5 External audit and reproducible evidence (V).** No external review exists; the mutation
  campaign, malformed-policy fixtures and 0.7.6 differential build are scratch-only. Estimate from
  L14: two senior auditors × two weeks plus three days of fix review (≈ 4–5 person-weeks) over
  `contracts/guards`, `contracts/interfaces/safe`, `tasks/curator-guard.ts`, the deploy script,
  the policy file and the runbook; follow with a bounty whose scope is guard + policy + owner-Safe
  configuration (L1, L3, L7, L14, L17, L20).
- **P0-6 Custody topology decision.** Choose between Option 3 and Option 4 now, while custody is
  dust and all five strategies carry zero debt; every month of TVL makes either migration harder.
  Either way, one Safe per vault: Lagoon's valuation rule ("a valuation must exclusively reflect
  the positions held by the curating address") is unmeetable with five vaults behind one commingled
  Safe, `settleRedeem` checks and pulls against the Safe's *total* balance, and a lockdown or
  incident on one vault freezes all five (L2, L18, L20).
- **P0-7 Curator-profile check (D).** Before committing to the guard, obtain the candidate
  curator's existing permission set or transaction history and replay it through
  `validateTransaction` on a fork. Swaps and routed execution (CoW `setPreSignature`, Odos, 1inch,
  Paraswap, LI.FI, Enso, Bundler3, EVC `batch`, UniversalRouter) are 20–65 % of an active
  curator's operations and are not expressible in static head words; one-shot approvals cannot
  substitute because quotes expire in minutes while a 3-of-6 Safe takes hours. Handler 0 removes
  CoW, Permit2 signatures, SIWE logins and ERC-721/1155 receipts. There is no keeper path on
  v1.4.1, so every settlement needs two humans (L5, L17, L4, L1). For a settlement-plus-direct-
  lending mandate none of this bites; for anything else it is the migration trigger to Option 4.

**P1 contract changes with cross-lens consensus (decision-independent, small)**

- **C1** Allow `to == safe && value == 0 && data.length == 0` before the self-call check:
  Safe{Wallet}'s "Reject transaction" is exactly that empty self-call and is blocked today, so a
  queued transaction that becomes invalid pins the nonce until Vetro approves the rejection (L4,
  L11; both reproduced).
- **C2** `_decodeEntry` rejects `to == address(0)`: v1.5.0 `MultiSendCallOnly` maps a zero `to`
  to the caller, so a zero entry is a self-call the literal comparison misses (closed today only
  by `_checkTarget`); then pre-seed the v1.5.0 hash `0xcdbdcec3…6663` (`0xA83c…1836`, verified
  live) so a Safe upgrade does not break batching until two unlogged owner calls land (L7, L11,
  L12).
- **C3** `approveTransaction` rejects `to == address(this)`: an approved payload aimed at the
  guard's own hooks burns other approvals on the module path (L7).
- **C4** `_afterExecution` clears both transient slots before any early return: an owner-Safe
  atomic ownership hand-off reverts `MissingSnapshot`, and a Bypass flip inside a policy
  transaction leaves a stale snapshot that false-positives `NestedExecution` later in the same EVM
  transaction (L7; both reproduced, both need an owner action inside the curator's execution).
- **C5** Observability: `TransactionChecked(safe, txHash, path, outcome)` in the post-hook (≈ 2k
  gas), `policyNonce[safe]` bumped by every mutator with `PolicyUpdated`, `codehash` in
  `MultiSendUnwrapperUpdated`, `epoch` in `TransactionApproved` / `ApprovalRestored` (and restore
  with the stored epoch), a component bitmask in `SafeConfigChanged`, a `getPolicy(safe)` view,
  `expectEmit` on every event plus an event-replay test (L10, L12, L6).
- **C6** Per-Safe guardian sets with an optional global set; a guardian key today can lock down
  every Safe on the deployment and disable batching for all of them (L6, L9, L12).
- **C8** Optional per-target version or code-hash pin (`TargetVersionChanged` instead of silently
  running an upgraded or rolled-back Lagoon implementation under the same selectors), an optional
  `maxValue` per payable function, and either an `ExitOnly` mode or exit functions that guardians
  cannot revoke, so narrowing never strands Vesper depositors (L18, L12, L7, L16, L6).
- **C11** Constructor `tload` probe (fails at deploy, not at first transaction, on a non-Cancun
  chain), typed `SafeConfigUnreadable` instead of a bubbled panic when `getOwners()` /
  `getStorageAt` revert on a degraded Safe, and a joint cap on `OneOf` members per function
  (16 × 128 costs ≈ 8.8 M gas to replace or revoke) (L11, L7).

**P1 contract changes that depend on the option chosen**

- **C9** Expressiveness escape hatch (only if the guard stays and venues expand): generalise the
  code-hash-pinned delegatecall mechanism to stateless targets with function rules (CoW
  `OrderSigner` is all-static, so `receiver == safe`, token `OneOf` and `validDuration ≤` are
  already expressible), and add a pluggable immutable `IChecker(target, selector)` for Bundler3 /
  Pendle `TokenInput` / EVC `batch` style payloads. This is the Roles `Custom` condition in ≈ 200
  lines; without it the first swap is the migration trigger (L1, L5, L17).
- **C10** Minimalism pass (L15, if the guard stays and is re-audited anyway): drop the module path
  until a v1.5.0 Safe exists, drop the dry-run views in favour of `eth_call{from: safe}` on the
  hooks, burn approvals on consume instead of restore-on-failure, trim the digest to `masterCopy`
  plus four single-word reads, drop the per-Safe unwrapper set (code hash is sufficient), key
  `OneOf` sets by a per-function nonce, drop `GreaterThanOrEqual` and native-transfer permission,
  extract the strict `multiSend` decoder into a pure library. Expected ≈ 750 lines, ≈ 45
  selectors, ≈ 25k warm overhead. Several items conflict with other lenses; see §12.6.

**P1 tooling**

- **T1** `curator-guard-sync --dry-run --out <dir>` writes a Safe Transaction Builder JSON
  (decodes in Safe{Wallet} without Etherscan), a Governor-shaped `{targets, values, calldatas,
  description}`, a human-readable table, and `policyHash = keccak(canonical expanded JSON)`; set
  the Safe Transaction Service `origin` to the policy path, hash and commit; add
  `--verify-proposal <safeTxHash>` that asserts byte-equality with the local diff. Signers today
  see `allowFunctions(30)` as 6.3 kB of nested tuples with raw selectors and enum integers (L4,
  L6, L9, L12, L13, L19).
- **T2** Validator: strict JSON parser that rejects duplicate keys (a trailing duplicate
  `functions` or `mode` silently wins today), mandatory `chainId` / `guard` / `schemaVersion`
  asserted against the network and `supportsInterface(0xe6d7a83a)`, semantic lint for `approve`
  entries (spender must be an allowlisted vault whose `asset()` is the token and `safe()` is the
  Safe), "every static `address` head word needs a rule or `unconstrained`" instead of the
  exact-signature allowance list (eight value-moving signatures slipped past it), fatal
  `getCode == 0x`, no empty `OneOf` sets, warn when a guardian is the Safe or one of its owners
  (L19, L9, L6, L12).
- **T3** Commands: `curator-guard-approve --safe-tx-hash` (pulls the pending proposal, prints
  `approvalId`, exact `approveTransaction` calldata, the matching `revokeApproval`, `safeTxGas =
  0` instructions, queues to the owner), `curator-guard-validate` (decodes MultiSend entries, calls
  `validateTransaction`, names the policy line that denied), `curator-guard-export` (chain → policy
  JSON + hash, diff against the file), `curator-guard-watch` (reference guardian bot over the §7.7
  events plus `ApprovalConsumed` without `ExecutionSuccess`), `lockdown` / `revoke`; gate
  `Lockdown → Enforced` behind `--allow-unlock` and revocations behind `--confirm-revocations`
  (L4, L11, L13, L19).
- **T4** Rehearse the real path: the fork dry-run should execute the exact owner-Safe
  `execTransaction` batch (impersonated owners) rather than per-call impersonation, which is the
  only path never exercised; support `txServiceUrl` override and a raw-calldata fallback (api-kit
  4.1.0 has no Hemi mapping; a Transaction Service outage leaves a stale batch file) (L19, L11).
- **T5** Deployment-level configuration (`guardians`, `unwrapperCodehashes`, expected modules) in
  `policies/curator-guard/<chain>.deployment.json`, multi-policy sync in one owner batch, chunked
  `allowFunctions` (≈ 125k gas per spec), per-chain deploy scripts and registry entries (L12, L1).
- **T6** CI: path filter must include `tasks/`, `helpers/safe.ts`, `scripts/`, `deploy/ethereum/
  guards/`; run eslint, tsc, the validator and `--dry-run` against a pinned fork for every policy
  file; nightly drift job; the Solidity e2e should consume the tool's exported batch instead of
  re-interpreting the JSON with a second parser that ignores handler, guardians, modules and
  native transfers (L13, L14, L19).
- **T7** Deploy: hard-fail on owner / curator key intersection, fatal Etherscan + Sourcify
  verification, deterministic CREATE2, pre-install assertions on `owner()`, `pendingOwner()` and
  runtime code hash, aligned optimizer runs between forge (200) and hardhat (1000) or a CI check
  that the deployed bytecode matches the tested one (L9, L2, L10).
- **T8** Documents: signer briefing (Safe{Wallet}'s Tenderly simulation overrides the guard slot
  to zero, so "Simulation successful" is meaningless under a guard and the only in-app signal is
  "Cannot estimate" with undecoded revert data; Reject semantics; no dapp signatures or NFT
  receipts; never choose "Safe pays" gas mode; `safeTxGas = 0`), a curator-facing onboarding page
  (allowed table, error names, what now needs Vetro, venue request template and SLA, signer
  rotation, lockdown notification), an incident runbook with lift criteria and drills, and an
  agreement checklist (custody, veto and freeze rights, NAV responsibility, settlement-delay
  liability, off-boarding) (L4, L13).

**P1 verification (L14, L7, L20)**

- **V1** Compile-free Safe fixtures: commit the canonical runtime bytecode of the v1.4.1 / v1.5.0
  singleton, proxy, `MultiSendCallOnly` and handler and `vm.etch` them in the test base. This
  makes `forge coverage --ir-minimum` work on the guard (it dies in the Safe sources today),
  closes the 0.7.6-versus-0.8.25 fidelity gap, and turns the tautological constant tests into
  real assertions. Gate ≥ 95 % line / 90 % branch on `contracts/guards`.
- **V2** Halmos in-tree: six custody properties already prove sub-second (single-use, restore on
  failure, in-flight cleared, `_ceil32`, exact binding on `to` and `value`); add per-function
  "guardian never widens" (the whole-ABI version times out), decoder equivalence with concrete
  offsets, owner exemption, epoch bump voids every id. Nightly, `--solver z3`.
- **V3** Hook-driving invariant handler (the current handlers never call the hooks and never
  warp): sign and execute through the real Safe across approved / policy / nested / module paths
  with ghost invariants (consumed approvals never re-fire without `ApprovalRestored`; no success
  with `to == safe` or a disallowed selector; digest unchanged after every success).
- **V4** Bidirectional differential fuzz (`guardAccepts ⇔ referenceAccepts ∧ canonical ∧
  allEntriesAllowed`), ≥ 50 % acceptance, second oracle (0.7.6 artifact, Zodiac
  `MultiSendUnwrapper` if licence-compatible).
- **V5** Mutation in-tree (gambit config, nightly, committed kill list), fuzz seed in CI,
  `invariant_deep` wired to a schedule, `slither.config.json` with triage (102 detectors run
  clean above Low today), policy-compiler property tests with the eleven malformed fixtures
  committed.
- **V6** Fork suite: dedicated archive-pinned block, `vm.skip` when the URL is absent or the guard
  is already installed, one test through the live owner set's real `execTransaction`.

**P1 Vesper and Lagoon operations (L16, L8, L18, L3, L11)**

- Fund through `update-debt-ratio` in steps; keep `maxLossBps == 0` while a freeze is possible;
  have the keeper read the guard's `mode(vault.safe())` and stop queueing deposits under
  lockdown; alert when a redeem request is pending beyond one settlement cycle, when no curator
  execution has happened for N days, and when `settleRedeem` silently no-ops.
- Decide compensation: fees are zero everywhere and fee shares are minted to the guarded Safe,
  which the policy cannot redeem or transfer, so a third-party curator has no sanctioned way to
  realise fees today; move `feeReceiver` out of the guarded Safe and set a non-zero Vesper
  `performanceFee` so monitoring has a budget.
- Either `activateAsyncOnly()` on all five vaults or allowlist `expireTotalAssets()`: raising
  `totalAssetsLifespan` (one approval away) otherwise traps NAV updates.
- Pre-approve `pause()` per vault (30-day TTL means a monthly renewal owner is needed until C7
  lands); approve single calls, never MultiSend batches; send `lockdown` and `revokeAllApprovals`
  together through a private relay.
- Upgrade runbook: watch `LogicAdded` on the registry and `ImplementationUpdateSubmited` on each
  admin, approve `upgradeAndCall` only in a batch that re-syncs the policy after the strategy
  suite passed against the new implementation on a fork (every Lagoon minor has changed ABI;
  `canUseLogic` ignores the source version so a storage-incompatible downgrade is permitted).

**P2 (backlog)**

Event hygiene (no-op setters emit; `ApprovalRevoked` for stale epochs), `wordIndex`
legibility and venue templates, `schemaVersion`, multi-chain address registry entries, size
headroom for a v2 (≈ 4.4 kB left), §3 rationale rewrite (the real argument for immutability is
bilateral consent plus verified bytecode, not DoS), 1.5.0 migration sequence in §7.5, post-check
gas headroom note (`safeTxGas = 0` with an adaptive callee), MEV exposure of 30-day public
approval calldata once swaps exist, Safe v1.3.0 compatibility test, canonical hashes on OP / Base
/ Hemi, EIP-7702-delegated EOAs as targets.

### 12.5 Recommendation

1. **Do the option-independent work first, this week, while custody is ≈ $3 and debt is zero:**
   P0-2 (Lagoon role moves, guardrails on, whitelist mode, superOperator lock, proxy admins,
   feeReceiver), P0-1 (a guard-owner quorum with no curator keys), one fresh Safe per vault, and
   the Vesper-side caps and alerts. None of this is guard code.
2. **Then decide P0-6 with one question: does Vetro want the power to act on custody without the
   curator's cooperation?** If yes (or if the candidate curator is Roles-native, needs swaps,
   routers, CoW or keepers), go to Option 4: Zodiac Roles 2.1.1 on the Vetro-owned per-vault
   Safes, curator Safe and bots as members, DeFi-Kit presets, widening behind the same timelock,
   narrowing instant. The guard then has no job; the policy file can be compiled to Roles
   permissions so the review work is not lost. If no, go to Option 3: the guard with the
   hardening package (P0-3 role split, C1–C6, C8, C11, T1–T8, V1–V6), installed at genesis on the
   fresh per-vault Safes, externally audited before TVL, with written migration triggers: the
   first venue that needs swaps or dynamic parameters, any automation requirement, custody above
   ≈ $1 M, any non-Vetro depositor, a DAO or timelock taking the owner role, or any Lockdown /
   Bypass incident.
3. **Do not install the guard on the existing shared Safe with the existing owner.** Every
   reviewer who addressed that configuration rated it unshippable (P0-1) or strictly dominated by
   Option 3.

### 12.6 Where reviewers disagreed

- **`lockUpdateSafe()`.** L8 and L20: lock once custody is final. L2 and L3: never lock while a
  third party is custodian, because `updateSafe` is the only Lagoon-native way to re-home future
  settlement custody away from an unresponsive or rogue curator, and a compromised owner using it
  only redirects future deposits. Synthesis: keep it unlocked under a Vetro-held, timelocked owner.
- **`Bypass`.** L15: remove it (approvals already run before any parsing, so liveness does not need
  a third mode and it cost two semantic flips). L7, L11: keep it as the recovery valve for a guard
  bug. Synthesis: keep, but council-only and time-boxed (P0-3).
- **Dry-run views.** L15: drop `validateTransaction` for `eth_call{from: safe}` on the hooks. L4,
  L10, L19: more pre-sign tooling, not less. Synthesis: the view is cheap and already used by
  tooling; keep it and build T3 on it, or drop it only together with the documented `eth_call`
  recipe.
- **Module path and digest scope.** L15: drop the module path and trim the digest (≈ 90 % of the
  per-transaction overhead is defence-in-depth against a double owner mistake). L1, L5: the module
  path is the hybrid-with-Roles bridge on v1.5.0. L7, L9: the digest closed R1-11 / R3-1 / R3-3 and
  should stay. Synthesis: keep the digest; keep the module path only if Option 5 is planned,
  otherwise defer it to a v2.
- **`maxLossBps`.** L16: a small tolerance so routine marks never need governor action. L8, L18
  and §6: keep 0 while a freeze is possible so an operational event never books a loss.
  Synthesis: keep 0; the keeper-griefing case (a 1-wei down-mark) is cheap, visible and reversible.
- **Fallback handler.** L4: v1.5.0 `TokenCallbackHandler` (no `isValidSignature`) as the
  sanctioned alternative when a venue mints NFTs. L5: a scoped EIP-1271 handler (CoW domain only).
  Synthesis: keep 0 until a venue requires callbacks; never Compatibility or Extensible.
- **Is the guard "the best"?** Ten lenses said keep it, ten said a better structure exists; all
  twenty made their answer conditional on P0-1 and P0-2. The split is explained almost entirely by
  whether the reviewer treated "the curator keeps the Safe" as given (§12.2 point 3).

### 12.7 Status after Round 4

- No contract, test, tooling or policy code was changed in this round. The findings above are
  recorded, not applied; C1–C6, C8 and C11 are small and decision-independent and can be applied
  on request together with their regression tests.
- Doc corrections made in this round: §1 gained the `accessMode == Blacklist` row and the
  `superOperator` lock state; §3's Roles row now points here; §6's NAV paragraph no longer
  overstates the pool-pps exposure (profit is booked only up to idle at report time); §8 is
  flagged as go-live preconditions.
- Still uncommitted and unpushed, as before: all guard files, the two Safe submodules (gitlinks
  unstaged), and the modified config files. The anvil fork used by the reviewers has been stopped.

## 13. v2: role split, time-boxed Bypass, approval hardening (2026-10-05)

IMPROVEMENTS_V2.md items 1-5 (and, along the way, items 6 and 7) were implemented after the Round 4
design review, then put through three further review rounds (§13.2); the final state is deployable
from a security standpoint, subject to the non-contract preconditions in §8 and §12. Summary of what changed in the contracts:

| Area | v1 | v2 |
|---|---|---|
| Authority | one `Ownable2Step` owner with instant, total power | `DEFAULT_ADMIN_ROLE` (one account, delayed two-step transfer, never zero) behind an OpenZeppelin `TimelockController` for widenings; `COUNCIL_ROLE` fast lane; per-Safe guardians plus a deployment-wide `GUARDIAN_ROLE` |
| Mode changes | `setMode(safe, mode)` owner-only; `lockdown` owner or guardian | `lockdown` and `lockdownAndRevoke` (any narrower), `enforce` (admin or council), `bypass(safe, duration)` time-boxed (admin ≤ 180 d, council ≤ 7 d); an expired window reads as `Lockdown` |
| Approvals | absolute `expiry` ≤ 30 d; owner only; restored on `success == false`; could target the guard; Bypass inert for them | relative `ttl` (admin ≤ 180 d, council ≤ 7 d); council cannot approve delegatecalls, and its Safe self-calls are limited to an allowlist (owner management, `disableModule`, canonical `setFallbackHandler(0)`, the empty rejection call; round 4); guard never a target; refused during Bypass; every Bypass opening bumps the epoch; `safeTxGas == 0` required on the owner-signed approval path, no restore path (round 8, V2-84: the `safeTxGas` requirement was removed again, the post-hook reverts a failed approved execution on either path; approvals are checked at issue and at use, §4) |
| Transient state | two in-flight slots (id, expiry) + one snapshot slot per `(safe, path)` | one slot per `(safe, path)`: idle / approved sentinel / snapshot digest; cleared first in the post-hook |
| MultiSend | entries with `operation == 1` rejected | plus entries with `to == address(0)` rejected; v1.5.0 `MultiSendCallOnly` hash pre-allowed |
| Deployment | guard with the governance Safe as owner | `CuratorGuardTimelock` + guard; the script refuses a proposer or council sharing a signer with the curator Safe; the constructor refuses pre-Cancun chains |
| Observability | hook reverts only | `TransactionChecked(safe, txHash, path, outcome)` once per passed transaction; `SafeConfigUnreadable` instead of a bubbled `Panic` when the Safe's own views fail |
| The Safe itself (round 8) | any account that answers the views | the proxy and singleton pinned by code hash, the guard installed on the calling path, every linked module hooked, no approval spent and no role honoured through a Safe's fallback forwarding |

### 13.1 What the rounds looked for

Correctness of the role matrix and the council limits; the single-slot state machine under every
interleaving (approved, policy, Bypass, admin, nested, module path, mid-transaction role actions);
the Bypass window boundaries; approval TTL and epoch semantics; MultiSend decoding; integration
with `AccessControlDefaultAdminRules` and `TimelockController`; the tooling's timelock path; test
coverage and robustness of the migrated and new suites; code quality; and footguns, i.e. honest
mistakes by Vetro operators or curator signers that could brick a strategy or vault, strand assets
or lose them.

### 13.2 Review log

#### Round 1 (v2): roles & approvals; hook state machine; integration & operator footguns

Three reviewers, each with scratch Foundry PoCs against the v2 tree (36 PoC tests in total). Every
accepted finding was fixed with a regression test; the suite went from 178 to 190 tests.

| # | Sev. | Finding | Resolution |
|---|---|---|---|
| V2-1 | High (liveness) | Guardian bot keys as timelock `CANCELLER_ROLE` could veto every admin operation forever, including their own removal (reproduced: a canceller cancels `revokeRole(CANCELLER, self)` three times). | Cancellers are the proposer Safe(s) and the council Safe only; the deploy script refuses an EOA canceller and warns when a configured canceller lacks the role; docs §4 / §7 / IMPROVEMENTS_V2.md corrected (guardian keys live in the policy files or `GUARDIAN_ROLE`). |
| V2-2 | Medium | A council-opened `Bypass` window plus cooperating signers removed the guard permanently in one block, so the council denylist was moot and §6's "bounded fast lane" claim false; 7-day windows were renewable without bound. | Council windows keep the self-call denylist in force inside `_preCheck` (`CouncilBypassLimit`; delegatecalls only to a registered `MultiSendCallOnly`, entries held to the same denylist), admin windows stay fully inert (`councilBypass` flag, `bypassWindow` view, `ModeUpdated` carries it). Renewals documented (a guardian `lockdown` ends any window at once). Tests: `test_council_bypass_window_blocks_what_weakens_the_safe_but_nothing_else`, `test_admin_bypass_window_is_fully_inert`. |
| V2-3 | Medium (liveness) | The council could not revoke a compromised deployment-wide `GUARDIAN_ROLE` (admin-only, 48 h), while that key could grief every Safe (lockdowns, codehash forbids, voiding standing approvals). | `setDeploymentGuardian(account, bool)` for admin or council. Test: `test_council_manages_deployment_wide_guardians`. |
| V2-4 | Medium (both A and C) | Queued timelock operations never expire and the executor role is open: a forgotten `bypass` / approval / widening is a latent, permissionless action months later (reproduced: a 180-day `bypass` executed four months after the drill). | `executeBefore(deadline, call)` on the guard (delegatecall to self keeps `msg.sender`); `curator-guard-sync` wraps every scheduled call in it (`--deadline-days`, default 14 after `minDelay`) and refuses `--execute` past the deadline; runbook rule "cancel what you do not execute". Tests: `test_executeBefore_runs_as_the_caller_only_before_the_deadline`, `test_timelocked_bypass_wrapped_with_a_deadline_dies_when_stale`. |
| V2-5 | Medium | Deterministic salt in the sync task: an identical diff (e.g. a second lift of a lockdown) could never be scheduled again (operation id Done forever) and the tool misreported the state. | Salt carries a counter (first unused id); the scheduled operation, salt and deadline are persisted next to the Safe batch file and read back by `--execute`; Done / Waiting / Unset are told apart. |
| V2-6 | Medium | Install-ordering trap: `setGuard` without the handler removal freezes the Safe, and only the admin (48 h) may approve the fix since the council cannot approve handler changes. | The sync task reads the Safe's live handler slot and prints a loud warning when it differs from the requirement; runbook §7.3 / §7.4 emphasise "both in one batch, before install". |
| V2-7 | Medium (liveness) | Council empty by default and a single proposer: every lift is a 48 h round trip and a lost proposer Safe strands the guard forever. | The deploy script refuses an empty council on real networks (`CURATOR_GUARD_ALLOW_NO_COUNCIL=1` to override), takes a list of proposers, and detects fork nodes by RPC probe (`hardhat_metadata` / `anvil_nodeInfo`) instead of the network name. |
| V2-8 | Low | Digest tripwire bypassable by code running as the Safe (a registered non-canonical "unwrapper" can call the hooks itself, clear the slot and re-arm a fresh snapshot of the modified configuration). Precondition: an admin registering a non-canonical hash. | The unwrapper code-hash set is fixed at deployment (v1.3.0 / v1.4.1 / v1.5.0 `MultiSendCallOnly`): guardians may forbid, the admin may re-allow a seeded hash, nothing else can ever be added (a new Safe release means a new guard). Docs §4 no longer present the digest as a boundary against in-context code. Tests: `test_canonical_multisend_call_only_hashes_are_pre_allowed_and_the_set_is_fixed`, `test_storage_writing_unwrapper_can_never_be_registered_on_a_real_guard`; the snapshot tests use a test harness that seeds local builds. |
| V2-9 | Low (liveness) | A failed approved module execution burned the approval (re-approval through the 48 h timelock). | The post-hook reverts `ApprovedExecutionFailed` when an approved execution reports `success == false`, rolling the consumption back atomically (the module path has no `safeTxGas`; the owner path never reaches that state). Tests: `test_failed_approved_module_execution_reverts_and_keeps_the_approval`, `test_in_flight_state_is_kept_per_path`. |
| V2-10 | Low | `ADMIN_DELAY` (1 day) below the timelock delay (48 h): a scheduled `cancelDefaultAdminTransfer` could never land in time. `changeDefaultAdminDelay` with a typo'd value (milliseconds) would take ~1,000 days to undo. | Default admin delay 3 days with a deploy-time warning when it does not exceed the timelock delay; `_changeDefaultAdminDelay` capped at 30 days (`AdminDelayTooLong`). Test: `test_admin_delay_change_is_capped`. |
| V2-11 | Low | Handing the admin role to a Safe that carries a policy (a paste error away) would make it exempt from everything, including `setGuard(0)`. | `_beginDefaultAdminTransfer` refuses an address with a policy, guardians or a handler requirement (`AdminIsGuarded`). Test: `test_guarded_safe_cannot_become_admin_but_an_unconfigured_safe_can`. |
| V2-12 | Info | Nested same-Safe execution after a mid-transaction flip into `Bypass` consumed the outer digest early (the Bypass return preceded the nesting check). | Nesting check moved ahead of the Bypass return. Test: `test_nested_execution_after_a_mid_transaction_bypass_flip_is_rejected`. |
| V2-13 | Info | `setModuleAllowed` accepted the Safe or the guard as a module; `--allow-unlock` would be typed by habit (every runbook command needed it); revocations were silent raw selectors; IMPROVEMENTS_V2.md listed `disableModule` in the council denylist (code denies four selectors: disabling a module is a narrowing); `bypassUntil` NatSpec disagreed with its behaviour after expiry. | `_checkTarget` on modules; `--allow-unlock` only for an already configured Safe; `--confirm-revocations` required when the diff narrows; plan corrected; `bypassWindow(safe)` returns the window end and who opened it. |
| V2-14 | Info (documented) | An approval matching an allowlisted payload captures it (so `safeTxGas != 0` is refused where the policy alone would tolerate it); approvals outlive admin transfers; re-installing a decommissioned guard revives its unexpired approvals; the admin exemption is dormant with a timelock admin but an admin Safe handing over inside its own transaction hits `MissingSnapshot`; v1.5.0 bubbles the inner revert reason where v1.4.1 says GS013. | Documented in §4 / §7; tests `test_approval_matching_an_allowlisted_payload_captures_it`, `test_approved_guard_removal_still_gets_its_post_hook_and_leaves_no_state`, `test_gas_refund_is_rejected_even_with_a_live_approval`. |

Verified sound by the round (with evidence in the reports): no non-admin widening path (every mutator
enumerated, invariants); the council denylist is complete for Safe v1.4.1 / v1.5.0 self-calls that
weaken the guard (`approveHash`, `simulateAndRevert`, `disableModule`, nested `execTransaction` cannot);
TTL caps per role and the epoch binding across Bypass windows, revocations, admin transfers and guard
replacement; Bypass window boundaries consistent across `bypass()`, `mode()`, both hooks and the
dry run; the post-hook can never be skipped once the pre-hook stored (the Safe caches the guard
before the pre-hook); no stale slot across Safe transactions of one EVM transaction; sentinel
collision-safe; digest coverage identical to v1; `GasRefundNotAllowed` precedes the approval branch;
`AccessControlDefaultAdminRules` semantics (role admins, no adminless state, timelock-to-timelock
hand-over); the deploy preflight detects the live three-key overlap on the fork; rejecting zero-`to`
MultiSend entries breaks no legitimate batch; protocol-kit sends `safeTxGas = 0` by default for
v1.3.0+ Safes; a settlement freeze is illiquidity, not loss, on the Vesper side.

#### Round 2 (v2): test adequacy & mutation resistance; tooling & deployment; code quality & doc truth

| # | Sev. | Finding | Resolution |
|---|---|---|---|
| V2-15 | High (process) | After the Round-1 additions the guard's runtime was 24,554 bytes: 22 bytes under EIP-170 and over the repo's own 96 % size gate (`scripts/check-contract-sizes.sh`, hardhat artifacts). | Behaviour-preserving reductions (dry run reuses `_configDigest`; shared `_checkAdminOrCouncil` / `_isGlobalNarrower`; `checkModuleTransaction` returns `bytes32(0)`, the Safe only echoes it to our own post-hook; merged reverts; limits and code-hash constants `internal`, exposed by the test harness; `isModuleAllowed` / `isMultiSendUnwrapper` / `isCanonicalCodehash` views dropped in favour of the list views) and the guard compiled at 100 optimizer runs in both toolchains (`runs_100` foundry restriction, hardhat override, `guards` profile): 23,517 bytes, 1,059 under the limit, size gate green. |
| V2-16 | Medium | The constructor accepted any admin-transfer delay (only `changeDefaultAdminDelay` was capped): `CURATOR_GUARD_ADMIN_DELAY` in milliseconds would have meant an 8-year admin hand-over. | Constructor capped by `MAX_ADMIN_DELAY` (`AdminDelayTooLong`); the deploy script validates the env value before any transaction and reads the live timelock delay for the comparison. |
| V2-17 | Medium | `validateTransaction` ignored the council-window denylist (dry run fail-open while the live check reverted `CouncilBypassLimit`). | Dry run mirrors `_preCheck` inside windows. Test: `test_dry_run_mirrors_the_council_window_denylist`. |
| V2-18 | Medium (tooling) | A queued `enforce` (lift of a lockdown) stayed executable by anyone for the whole 14-day window, so a new incident could be ended silently by whoever executed a stale proposal. | Lifts get a one-day execution window (`--unlock-deadline-days`) and the task prints the `cancel(opId)` calldata; runbook rule "cancel on a new incident". |
| V2-19 | Medium (tooling) | The `--allow-unlock` gate treated "no targets" as "fresh": a guardian who answered an incident with `revokeTarget` on every target disarmed it, and the next routine sync re-allowed everything and lifted the lockdown. | "Configured" mirrors the contract's `AdminIsGuarded` predicate (targets, guardians, handler requirement, Bypass). |
| V2-20 | Medium (tooling) | `--execute` printed the diff of the current file but executed the stored payloads; drift between scheduling and execution was invisible (or reverted with `TimelockInvalidOperationLength`); the state file was unkeyed (one for every chain / guard) and never cleaned on error paths. | `--execute` decodes the stored batch, refuses when the current diff differs from it, reports "already in sync but still queued" with the cancel calldata; the state file is keyed by chain and guard and carries the timelock, policy path and policy hash; a signer manifest with the `hashOperationBatch` inputs is written for the proposer Safe. |
| V2-21 | Medium (deploy) | Re-running the deploy script with a council configured after the first deploy silently did nothing (`skipIfAlreadyDeployed` ignores changed constructor arguments); EOA cancellers were refused only after the timelock deploy; the admin-delay warning compared env values instead of the live timelock. | Pre-transaction validation of every address and delay; the script asserts the council role on the live guard and prints the scheduled `grantRole` otherwise; live `getMinDelay()` drives the delay check (a real network refuses an admin delay at or below it). |
| V2-22 | Low | Validator gaps: duplicate JSON keys (`JSON.parse` keeps the last), no chain / guard pin, `transferFrom`-shaped functions with only a word-0 rule, empty `OneOf` sets, a zero Safe, the Safe among `nativeTransfers`; the guardian-overlap warning called a curator-owner guardian "harmless". | Duplicate-key scanner; optional `chainId` / `guard` pins asserted against the network and `--guard`; per-signature value-word map (incl. `safeTransferFrom`, Permit2 `approve`); empty sets, zero Safe and self-references refused; warning reworded (such a key can void every admin approval). |
| V2-23 | Low | Two TypeScript errors in the task were invisible (hardhat loads tasks in transpile-only mode); CI linted nothing off-chain. | Fixed; the guard workflow lints the tooling and runs the suites under the `guards` profile. |
| V2-24 | Low | `AdminIsGuarded` missed a Safe configured only through modules / unwrappers, and the council itself; `setGuardian(safe, safe)` was accepted; `bypass(safe, 7)` (seven seconds, typed for seven days) voided every approval for nothing; the handler getter answered `(enforce, handler)` while the setter takes `(handler, enforce)`. | Predicate extended (modules, unwrappers, council); a Safe is never its own guardian; one-hour floor on `bypass` (`MIN_BYPASS`); getter order matches the setter. Tests in `CuratorGuardV2.t.sol` ("Round-2 regressions"). |
| V2-25 | Low (ops) | A proposer / canceller / council Safe that installs the guard on itself can no longer propose, cancel or act: with a sole proposer, a permanent brick of governance. | `curator-guard-sync` refuses a policy whose Safe holds `PROPOSER_ROLE` / `CANCELLER_ROLE` on the admin timelock or `COUNCIL_ROLE` on the guard; runbook: list two proposers. |
| V2-27 | Medium (tests) | Mutation campaign (77 hand-written mutants of the v2 logic, 61 killed by the suite as it stood, 14 non-equivalent survivors): the council-window denylist was untested on the module path; the expiry-boundary test checked one second early (it relied on Foundry's `block.timestamp == 1`); the admin-is-guarded terms, the per-role caps, the seeded code-hash literals, the self-call scoping of the council denylist, the zero-address edges of `bypass` / `setDeploymentGuardian`, and value-carrying denied self-calls were never pinned; the differential fuzz never generated a zero `to`; the invariant harness had no deployment-wide guardian, ignored the new entry points and never drove the hooks; the e2e fixture applied neither the handler requirement nor the guardians and installed the guard by prank instead of the runbook batch. | New suite `CuratorGuardMutation.t.sol` (10 killer tests: nine plus the v1.5.0 module-path council-window test, with the safe-deployments package as the oracle for the three hashes); boundary test rewritten against the stored expiry and the live hook; every suite now runs at a realistic timestamp; fuzz pool generates zero `to` and the reference refuses it; invariant harness gained a deployment-wide guardian actor, role bits in the mask, 22 stranger entry points, guardian attempts at the role surface, and a curator that drives the genuine `execTransaction` with hook-level ghosts (no approval consumed inside a window, no success under Lockdown without one); the e2e fixture applies the whole policy file and installs through a genuine §7.4 batch, with council lift and council approvals exercised on the live Safe. |
| V2-26 | Info (docs) | Stale statements: "a failed module execution burns the approval" (it reverts and keeps it), guardian keys as timelock cancellers, `addGuardian` as deployment-wide, the §7.6 guard-swap path during a council window (no approval can be issued inside any window), `NestedExecution` step number, `curatorGuardProposer`, the size comment in `hardhat.config.ts`, `--allow-unlock` on every runbook command. | All corrected. |

Verified by the round: the full hardhat fork rehearsal on the production topology (deploy → schedule
as the proposer Safe → early execute refused → warp → execute → "already in sync" → handler removal +
install → allowed / denied dry runs); the validator rejects twenty malformed policy shapes; the
Safe-batch proposal path reaches the Safe Transaction Service with the right `from`; `isForkNode`
answers false on a public mainnet RPC and true on anvil / hardhat; every policy selector exists on the
live v0.6.0 implementation; `AccessControlDefaultAdminRules` role admins, `executeBefore`'s
delegatecall-to-self (non-payable, `msg.sender` preserved, recursion harmless), `memory-safe` assembly,
CEI, integer widths, the `_canonicalCodehashes` + `_unwrapperCodehashes` pair (a merged status mapping
is larger), and the `ExecContext` struct (now built with named fields).

#### Round 3 (v2, final): fresh line-by-line audit; doc-vs-code audit; operations rehearsal on the fork

The fresh audit found **no Critical, High or Medium contract finding and no regression from the
round-1/2 fixes** (36 mutators × 6 principals access matrix, 19 PoCs). The remaining items are liveness
and operator-side; all were applied. Final: 202 unit tests (12 files, 14 test contracts) + 5 fork
tests green at block 26,123,637; runtime 23,353 bytes at 100 optimizer runs (1,223 under EIP-170, size
gate green); hardhat rehearsal on the production topology green.

| # | Sev. | Finding | Resolution |
|---|---|---|---|
| V2-28 | Low (liveness) | The council could not approve `setFallbackHandler(address(0))`, so the install-ordering trap (guard installed before the handler was removed) was an admin-only, timelock-delayed fix. A reset to zero never weakens the Safe. | `_weakensSafe` exempts a well-formed `setFallbackHandler(address(0))` (council approvals and council windows); any other handler, or a malformed payload, stays denied. Tests: `test_council_may_approve_resetting_the_handler_to_zero_but_nothing_else`, the live-Safe handler test. |
| V2-29 | Low (liveness) | A forbidden canonical unwrapper hash (guardian action) could only be re-allowed by the admin: a leaked responder key meant a 48 h batching outage on every Safe. | Re-allowing a *seeded* hash is admin or council (the set stays fixed). Test: `test_council_may_reallow_a_canonical_hash_after_a_guardian_forbid`. |
| V2-30 | Low | `AdminIsGuarded` was evaluated only when a transfer began; the pending admin could be configured during the delay and still accept. | `_acceptDefaultAdminTransfer` re-runs the predicate (`_requireUnguarded`). Test: `test_pending_admin_configured_during_the_delay_cannot_accept`. |
| V2-31 | Low (ops) | Safe{Wallet}'s "Reject transaction" (empty zero-value self-call) was refused, so a stuck nonce needed an approval. | The policy lets exactly that self-call through (post-check still runs; value or Lockdown still refuse). Plan item 7 done. Test: `test_safe_wallet_rejection_self_call_passes_but_value_or_lockdown_do_not`. |
| V2-32 | Medium (ops) | Nothing stopped approving `setGuard(x)` for an unsynced guard: one paste error freezes every vault for a timelock delay (reproduced on the fork). | Runbook §7.5 pre-swap checklist (mode, targets, council role, guardians, handler, a passing `validateTransaction`); old guard `lockdown` + `revokeAllApprovals` after the swap. |
| V2-33 | Medium (ops) | Guardian narrowing (`revokeTarget`, codehash forbid) is irreversible on the fast lane except through a Bypass; a bot's wrong revocation = a timelock delay without settlement. | Hash re-allow moved to the fast lane (V2-29); runbook: bots answer with `lockdown` (council-reversible), never `revoke*`. |
| V2-34 | Low (tooling) | `--allow-unlock` ignored modules / unwrappers (the contract predicate counts them); the shipped `guardians: []` would strip council-provisioned responders on the next sync without a dedicated warning; an operation whose `scheduleBatch` the proposer Safe signed after the `executeBefore` deadline was reported as "not ready" instead of dead; the task detected forks by network name; the deploy script let an EOA council through on forks only to fail at the canceller grant. | Predicate mirrors the contract; dedicated guardian-strip warning; "dead on arrival, cancel and reschedule" diagnosis; RPC probe for fork detection; EOA council refused everywhere. |
| V2-35 | Info (docs) | Twenty stale statements (v1 `owner` wording in §1/§3, `addGuardian`, guardian cancellers, "inclusive last second", gas figures, "17 entry points", test counts, flag lists, the unwrapper error text, comments in deploy / CI) and missing runbook material (admin hand-over, council / proposer / guardian rotation, decommission, curator-facing reverts, policy reconstruction from views, fork rehearsal expiry, Vesper keepers during a lockdown, council window overriding an admin window). | All corrected or added (§1, §3, §4, §5, §6, §7.3–7.8, §10, §11 banner, §13; task and deploy comments; CI comment; IMPROVEMENTS_V2.md; CLAUDE.md). |

Verified by the round (evidence in the reports): the full access matrix; `executeBefore` (non-payable,
`msg.sender` preserved, recursion and hook payloads harmless); the single-slot state machine with the
final ordering on both paths, re-entrant venues, mid-transaction role actions; approval id / epoch /
TTL semantics; the council denylist against every Safe v1.4.1 / v1.5.0 `authorized` function; the
strict decoder incl. the v1.5.0 zero-`to` rewrite; digest coverage; the three seeded hashes against
live mainnet; interface ids; every §7 command against the task, deploy script and dry-run; and on the
fork: incident drill (guardian lockdown, refused routine syncs with and without revocations, council
lift), council window (settlement passes, weakening self-calls and batch entries refused, approvals
refused inside, expiry to Lockdown), the timelock path (early execute refused, drift / deadline
refusals, fresh salt), approvals by role (`safeTxGas`, gas refund, single use, re-approval, guardian
revocation, `executeBefore` deadline), guard replacement with a reused timelock, the install trap and
its recovery, deploy preflights and idempotence. Residual, documented: an admin-approved batch can
address the hooks from the Safe (burns the Safe's own approvals; the sync tooling must refuse such
payloads); a council window replaces an open admin window; narrowing at the 16×128 caps costs ≈ 8.8 M
gas per function; a non-zero required fallback handler must be stateless.

#### Round 4 (v2): robustness and auditability items 8, 9 and 12 (2026-10-05)

Implemented after the round-3 sign-off, from IMPROVEMENTS_V2.md §2 and §3:

- **Item 8, `SafeConfigUnreadable` + Cancun probe.** `_configDigest` reads the Safe's views through
  one shape-checked `staticcall` helper and hashes the raw ABI responses (owner array: offset word,
  count word, `count` words; storage reads: exactly `64 + 32·words` bytes); a revert, an account
  without code or a malformed answer is `SafeConfigUnreadable(safe)` in the pre-hook, the post-hook and
  the dry runs (which now read the configuration exactly where the live pre-check snapshots it). The
  constructor runs `tstore(k, tload(k))` on the guard's own namespace key (a no-op), so a pre-Cancun
  chain refuses the deployment. Net effect on size: the raw reads replaced six ABI decoders, the
  runtime shrank from 23,353 to 23,145 bytes with everything below included.
- **Item 9, `lockdownAndRevoke(safe)`.** `_nonZero`, `_checkNarrower`, `_setMode(Lockdown)`,
  `_bumpEpoch`; `ModeUpdated` then `ApprovalsRevoked`. Same callers as `lockdown`.
- **Item 12, `TransactionChecked(safe, txHash, path, outcome)`.** Emitted once at the end of
  `_afterExecution` with `Outcome {Policy, Approval, Bypass}`; the admin path stays silent;
  `checkModuleTransaction` now returns `keccak256(abi.encode(module, to, value, keccak256(data),
  operation))` so the module-path event carries a meaningful hash (v2 returned zero to save code).
  About 2k gas per transaction (46.9k total overhead with one owner after round 7, bound 80k).

Tests: `CuratorGuardRobustness.t.sol` (29 tests on both Safe paths at that point, 46 after both review rounds), the `precancun`
profile, three new invariant handler actions plus the `TransactionChecked` ghost
(`invariant_every_passed_transaction_is_reported_once_with_its_outcome`), the stranger list grown to
23 entry points, and two fork assertions on the live Safe. Verification at that point: 232 unit + 5
fork + 1 pre-Cancun tests green, hardhat fork rehearsal green (deploy script, timelock path, install,
dry runs), size gate green at 96 % (23,145 bytes).

Two review rounds followed (correctness, no new vulnerability, coverage and robustness of the new
tests). Round 1 (adversarial contract review of the diff with 17 PoCs, a 60-mutant campaign in a
scratch copy, and a fresh line-by-line audit of both contracts with 38 PoCs; the operations / docs /
tooling reviewer was cut off by a usage limit and re-run after the fixes below) found no Critical,
High or Medium issue in the three items. It found four Low issues in adjacent, pre-existing logic
and five surviving mutants; all were fixed, which moved the runtime to 23,418 bytes (174 under the
gate) and the suite to 241 unit tests:

| # | Sev. | Finding | Resolution |
|---|---|---|---|
| V2-36 | Low | Inside an admin-opened Bypass window a plain call from the Safe to the guard's own post-hook checked nothing and added a forged `TransactionChecked(…, Bypass)` under an arbitrary hash, breaking "once per transaction". | The guard is never a call target from a guarded Safe, in any mode (`GuardCallNotAllowed` in admin windows too, dry run included). Residual, documented in §4 and §7.7: batch entries and delegatecalled code are not decoded in an admin window, so reports inside one are not authoritative; `ModeUpdated` is the signal. Tests: `test_admin_window_never_lets_the_safe_call_the_guard`, `test_admin_window_batch_entry_can_still_add_a_bypass_report_documented_residual`. |
| V2-37 | Low | The council's self-call limit was a denylist of four selectors. A selector the Safe does not implement reaches the fallback handler with the Safe as caller, so with a stateful handler (v1.5.0 `ExtensibleFallbackHandler`) the council could reconfigure signature semantics, and any `authorized` function a future Safe release adds would have been approvable. | Allowlist instead: owner management, `disableModule`, canonical `setFallbackHandler(0)`, the empty rejection call; everything else addressed to the Safe is admin-only, for approvals and council windows alike, on both paths. Tests: `test_council_self_calls_are_an_allowlist`, `test_council_cannot_reach_a_stateful_fallback_handler_through_the_safe`, `test_council_allowlist_selectors_are_the_safes`. |
| V2-38 | Low | Nothing on-chain stopped a Safe that was granted `COUNCIL_ROLE` by mistake from approving, unlocking or opening a window for itself (only tooling and the timelock delay did). | `enforce`, `bypass` and `approveTransaction` refuse `msg.sender == safe` (`Unauthorized`), through `executeBefore` as well; powers over other Safes and narrowing of itself remain. Test: `test_a_safe_holding_the_council_role_cannot_authorize_itself`. |
| V2-39 | Low | A council window switched the module allowlist off: an enabled v1.5.0 module a guardian had revoked regained full power for the window. | The module allowlist stays in force inside council windows (`ModuleNotAllowed`), live and in the dry run; admin windows stay inert. Tests: `test_council_window_keeps_the_module_allowlist`, `test_council_window_denylist_holds_on_the_module_path`. |
| V2-40 | Low (tests) | Five non-equivalent mutants survived the suite: the owner-array padding and exact-count terms of `_read`, ignoring the staticcall success flag when the revert data happens to have the expected shape (owners and storage reads), and the dry run reading the configuration after the policy. | Four new `DegradedSafe` faults (trailing byte, under-count, well-shaped revert data for owners and storage) and a precedence test; the five mutants are killed on re-run. Two further survivors were equivalent (`msg.sender` for `safe_`, hashing any `masterCopy` response). |
| V2-41 | Low (ops) | The pre-Cancun test lived under `test/`, so the default profile would compile and run it on Cancun, where the guard deploys; a deployment on a pre-Cancun chain surfaced the probe as an opaque constructor revert. | The test skips itself where transient storage exists (a `PUSH0 TLOAD POP STOP` `create` probe); the deploy script runs the same probe through `eth_call` and refuses with a plain message. |
| V2-42 | Info | An absurd declared `multiSend` payload length reverted with an arithmetic `Panic` from the padding computation instead of `MalformedMultiSend`. | Length bounded by the calldata length before padding. Test: `test_absurd_multisend_length_is_malformed_not_a_panic`. |
| V2-43 | Info | A configuration read that runs out of its 63/64 gas share surfaces as `SafeConfigUnreadable` with a gas limit far below any estimate (a narrow band, never a pass); NatSpec overstated the nesting check inside a window; the module-path `txHash` is a payload hash, not unique per execution. | Documented (§4, §7.6 step 4, §7.8, event NatSpec: index module reports by log position; an `eth_call` of `getOwners()` succeeding tells starvation apart). |
| V2-44 | Info | Recorded, not changed: the owner-array and storage shape checks are self-consistency only (only Safe code answers, raw bytes are hashed); `uint32` epoch saturation (unreachable); council windows skip the gas-refund check (the window allows any transfer anyway); narrowing at the 16×128 caps may need several transactions (`lockdown` is the primitive); mutators accept `safe == admin` (a dead policy); `revokeTarget` lacks `_nonZero` (a no-op). | None. |
| V2-45 | Low (docs / ops) | The re-run operations review (no contract defect; bytecode byte-identical between hardhat and foundry; the deploy probe verified on the fork) found nineteen wording and runbook items: stale denylist NatSpec (`ModeUpdated`, `_validateMultiSend`) and the §13 summary row; §6 gas figures; §7.7 silent on the module hash not being unique and on admin-window reports; the §7.8 rows for `GuardCallNotAllowed` (no approval exists), `CouncilBypassLimit` (approvals are refused while a window is open) and the codeless-address case; §7.6 step 4 missing the window / approval exclusivity and the Safe{Wallet} caveat; guidance on `lockdown` versus `lockdownAndRevoke` for bots (the latter voids pre-staged admin approvals, which come back only after a timelock delay); the sync task and the policy comment still saying only the admin can approve the handler fix; the replace-guard step asking for a council grant the deploy script already makes; counts and cross-references; the pre-Cancun test's dependence on a prior guards build; CI path filters. | All applied (docs §4, §6, §7.5–§7.8, §10, §13; NatSpec; `tasks/curator-guard.ts`; policy file comment; `CLAUDE.md`; CI paths; the pre-Cancun test asserts the artifact exists and says what to run). |

Round 2 (four fresh reviewers on the round-1 tree: an adversarial contract review with 27 PoCs
including an exhaustive council-allowlist matrix against Safe v1.3.0 / v1.4.1 / v1.5.0; a 93-mutant
campaign over the round-4 code with whole-suite runs, 84 killed, 2 equivalent survivors, 7 real
survivors in four gaps, each with a proven killer test; an operations review with a live-Safe drill of
every runbook claim the changes touch (council allowlist, `lockdown` versus `lockdownAndRevoke` with a
pre-staged `pause()`, council windows with the module allowlist, the unreadable-Safe recovery order,
a guard swap, a decommission); and a footgun / liveness review with 25 PoCs including the full
unreadable-Safe recovery through a real `TimelockController`) found **no Critical or High issue**, one
Medium liveness trap outside the contracts, three Low contract hardenings and a set of test, runbook
and tooling items. Everything was applied; the runtime is 23,527 bytes (65 under the gate; the digest
now hashes the concatenated raw responses, which parse uniquely by construction) and the suite stands
at 250 unit tests (16 test contracts), 6 fork tests and the pre-Cancun test, all green with the hardhat
rehearsal and the size gate:

| # | Sev. | Finding | Resolution |
|---|---|---|---|
| V2-46 | Medium (liveness) | Nothing enforced the "two proposer Safes" rule (`helpers/address.ts` lists one; the deploy script refused only an empty list). A sole proposer that installs this guard on itself by mistake (unconfigured, so `Lockdown`: it can no longer `schedule`) or loses its quorum leaves the guard unremovable, unwidenable and its admin role untransferable for good; with a council there is a recovery recipe (council window, scheduling the approval of `setGuard(0)` as a venue call from inside it, `enforce`, execute), without one it is permanent. | Deploy script refuses fewer than two proposers on real networks (`CURATOR_GUARD_ALLOW_SINGLE_PROPOSER=1` to override) and a timelock delay under one hour (`CURATOR_GUARD_ALLOW_SHORT_DELAY=1`, hours typed as seconds), printing delays in human units; §7.1, §7.6 step 5 (the recipe) and §7.7 (`ChangedGuard` on every proposer and council Safe) written. |
| V2-47 | Low | The council could reach a stateful fallback handler by calling it DIRECTLY (`_councilMaySelfCall` treated every `to != safe` as a venue call, while a handler answers a direct call from the Safe exactly like a forwarded one): with a policy tolerating such a handler, `setDomainVerifier` / `setSafeMethod` would give a compromised council a persistent EIP-1271 backdoor. Not reachable with the shipped policy (`address(0)` enforced). | The policy's required fallback handler counts as part of the Safe for the council: unreachable by approval, inside a window (top level and batch entries) and in the dry run, whatever the selector; a handler the policy does not name stays a venue call (documented residual: a tolerated non-zero handler must be stateless or absent). Test: `test_council_cannot_reach_the_policys_required_handler_directly`. |
| V2-48 | Low | Council owner management had no threshold floor: `removeOwner(…, 1)` or `addOwnerWithThreshold(x, 1)` turns the custody Safe into a single-key Safe through the fast lane, one paste error away from one lost key; a threshold equal to the owner count is a lock-out no guard power can undo. | The council allowlist refuses any owner-management call that sets a threshold below 2 (`addOwnerWithThreshold` word 1, `removeOwner` word 2, `changeThreshold` word 0; a missing argument is refused too), for approvals and windows; the admin may still. The owner-count ceiling is a runbook rule (§7.5). Tests: `test_council_owner_management_never_sets_a_threshold_below_two`, the allowlist test executed with two signers. |
| V2-49 | Low | Approval `ttl` had no floor: `7` (seconds, typed for seven days) was accepted and, after a timelock, dead on arrival; the matching `bypass` floor existed since V2-24. | `MIN_APPROVAL_TTL = 1 hours` (`InvalidDuration` below). Test: `test_approval_ttl_has_a_one_hour_floor`; the suites' one-second approvals moved to one hour. |
| V2-50 | Low (tests) | Seven non-equivalent mutants survived the 93-mutant campaign: the guard-as-target rule on the module path inside an admin window (live and dry run), a single-word `getOwners()` answer, the raw-versus-effective mode in the post-hook's empty-slot branch, and short `setFallbackHandler` payloads; the round-1 campaign also left the event ABI unpinned and the invariant handler's reporting ghost without a liveness anchor, and the pre-Cancun test attributed its failure only together with the census test. | Killer tests added for each (`test_admin_window_never_lets_a_module_call_the_guard`, the `OwnersSingleWord` fault with the fault loop bound to the enum's last member, `test_post_hook_with_an_empty_slot_after_the_window_expired_is_MissingSnapshot`, `test_short_setFallbackHandler_payload_is_typed_for_the_council`, `test_event_signatures_are_pinned`, `test_handler_curator_path_is_live_and_reported_per_outcome`); the pre-Cancun test asserts an empty return and the gas burn of an invalid opcode plus a Cancun build; the module-hash variants now come from the guard; the guard's selector constants are pinned through the harness. |
| V2-51 | Low (docs / ops) | On the deployed Safe singletons (solc 0.7.6, v1.3.0 to v1.5.0) an owner list longer than `ownerCount` makes `getOwners()` hit `INVALID`, burning all forwarded gas: still `SafeConfigUnreadable`, but every failed policy attempt costs the whole gas limit, which the 0.8.25 fixture (a cheap `Panic`) never showed. | NatSpec, §7.6 step 4, §7.8 and §10 say so; fork test `test_unreadable_live_safe_burns_the_forwarded_gas_but_is_typed`. |
| V2-52 | Low (ops / tooling) | Runbook and tooling gaps: the re-issue lane after `lockdownAndRevoke` is decided by the payload, not the issuer; an unsynced replacement guard does have the council (constructor) but no unwrapper, so a window restores plain-call settlement only; the council cannot approve a batch, so an unreadable Safe settles through a window or two plain-call approvals and a timelocked approval executed inside a window reverts `SafeInBypass` (retry after `enforce`); the Safe{Wallet} rejection is refused under `Lockdown`; `enableModule` must never be approved on a v1.3.0 / v1.4.1 Safe; approval ids are epoch-bound; `executor` typed as the Safe binds the approval to the module path; a guard installed before the sync needs a council window, not `enforce`; the policy registered one of three canonical `MultiSendCallOnly` builds; a typo'd non-zero handler requirement freezes traffic for a timelock delay; the sync task did not warn on enabled modules or a foreign guard slot; CI ran no type check. | §4, §6 (council bound versus the vaults, gas floor), §7.4, §7.5, §7.6, §7.7 (emitter filter, window-renewal alert) and §7.8 rewritten; the policy file lists the three canonical unwrappers and carries a corrected comment; the validator requires `"$allowNonZeroHandler": true` and code at a non-zero handler; the task warns on enabled modules and a guard slot pointing elsewhere; CI type-checks the guard tooling and watches the config files; the fork-blocks action documents the pristine-Safe requirement; plan §4 records the approve-task and council-batch ideas. |
| V2-53 | Info | Recorded, not changed: a venue can emit an event with the `TransactionChecked` signature (filter by emitter); council windows renew without bound (alert rule); a delegatecall to the guard's own code inside an admin window is refused like a call (`GuardCallNotAllowed` ignores the operation); the admin-approved batch residual; approvals of a `MultiSendCallOnly` batch stay admin-only (a council window runs such a batch; a cooldown between council windows and a `curator-guard-approve` task are plan §4 items). | None. |

#### Round 5 (v2): malicious counterparties, Lagoon semantics, Safe internals, griefing and timing (2026-10-05)

A third review campaign with new angles, after item 10 was added as a validator rule
(`curator-guard-lint`, 256 `OneOf` members per function and 1,024 per target). Four reviewers: hostile
venues, tokens, modules, contract owners and libraries (26 PoCs, several on the live Safe); the Lagoon
v0.6.0 vault semantics against the deployed, source-verified implementation (11 fork PoCs); Safe
v1.3.0 / v1.4.1 / v1.5.0 internals on vendored and canonical 0.7.6 bytecode (32 PoCs); griefing,
timing, reorg and chain-level edge cases (24 PoCs with measured gas). No way was found for a contract
to move the guard's state, skip a hook, replay an approval or launder the digest, and the Safe-side
ordering assumptions hold on every release (contract-owner signature validation is a static call;
nothing moves after the post-hook). The findings sit around the guard:

| # | Sev. | Finding | Resolution |
|---|---|---|---|
| V2-54 | High (governance liveness) | The council held `CANCELLER_ROLE` on the timelock, so a rogue or compromised council could cancel its own removal and every other admin operation forever, and with `lockdown` freeze every guarded Safe for good; §4 and §6 called a compromised council "recoverable". | The council is never a canceller: the deploy script grants the role only to `Vetro.curatorGuardCancellers`, refuses a list containing the council and refuses (warns on rehearsals) a reused timelock on which the council holds it. Cancellers are the proposer Safes. §4, §6 and §7.1 corrected, including that guardians bound a mistaken council, not a malicious one. |
| V2-55 | Medium | A queued `enforce`, `bypass` or approval was a one-transaction exception to any lockdown: once ready, anyone could execute it atomically with a transaction the signers had already signed, with no block for a guardian or canceller to interpose. | `LOCKDOWN_COOLDOWN`: for one day after every `lockdown` / `lockdownAndRevoke` the admin's `enforce`, `bypass` and `approveTransaction` for that Safe revert `LockdownCooldown` (the council is not held back); the day is the cancellers' time to cancel queued operations, and a lift wrapped with the task's one-day window dies inside it. Tests: `test_admin_lifts_windows_and_approvals_wait_a_day_after_any_lockdown`, `test_queued_admin_actions_wait_out_the_lockdown_cooldown` (real timelock), `invariant_admin_actions_respect_the_lockdown_cooldown`. |
| V2-56 | Critical for funding, documented residual sharpened | NAV marking through the allowlist: `updateNewTotalAssets` + settles let a colluding signer quorum take 100 % of a vault's custody in one transaction with flash-borrowable capital (measured on the live USDC vault with the guard installed). The guard cannot judge a NAV; no guardian or alert can react. | Not a guard defect and not fixable in the guard. §6 states it without softening; §8 gives the verified order of the Lagoon-side controls (whitelist mode with the Safe off the list, guardrails with `securityCouncil` at Vetro, proxy-admin ownership, sync mode off); every `debtRatio` stays at zero until one is live. The validator now demands a NAV band or an explicit `"unconstrained": true` on `updateNewTotalAssets` (a band refuses unit mistakes and caps one mark; it does not bound a malicious quorum), and the shipped file says why its entries are unconstrained. |
| V2-57 | Medium (docs versus strategy code) | The docs told Vetro to keep `maxLossBps` at 0, but with zero the keeper's `rebalance` reverts `LossExceedsCap(1, 0)` after any real settlement (Lagoon's share arithmetic loses at least 1 wei on a round trip); the strategy's own fixtures say production needs a non-zero cap. | §1, §6, §8 corrected: set 1 bp or give `LagoonBase._rebalance` a rounding tolerance. The strategy was not changed in this work. |
| V2-58 | Low | Council owner management could bring in an owner with code: the guard itself or any non-signing contract (a dead seat that can brick the Safe once live signers fall below the threshold), or a smart account / EIP-7702 delegated EOA whose validator accepts anything (the threshold floor becomes nominal). | On the council lane a new owner (`addOwnerWithThreshold` word 0, `swapOwner` word 2) must have no code; such owners are admin-only. Test: `test_council_cannot_bring_in_an_owner_with_code`. On the mainnet fork even Foundry's well-known test addresses carry code, which the rule refused. |
| V2-59 | Medium (tooling) | The deploy script's signer-overlap preflight treated ANY failure of `getOwners()` (rate limit, timeout) as "not a Safe" and passed; a dev-node RPC answer alone downgraded five refusals to warnings; delegated EOAs passed as multisigs. | The owner read fails closed (only an EVM-level answer means "not a Safe"); a rehearsal needs chain id 31337 or `CURATOR_GUARD_FORK=1` on top of the probe, in the deploy script and the task; `0xef0100` accounts count as plain keys. |
| V2-60 | Low (tooling) | An abandoned batch stayed executable by anyone and could resurrect what a later batch corrected; `--execute` refused a ready batch after any honest fast-lane change; nothing warned about upgradeable targets, delegated-EOA targets or the missing `chainId` pin. | The task refuses to schedule next to a pending operation for the guard (`--allow-pending`), lists other pending operations after `--execute`, executes the stored batch while every call in it is still wanted, prints each upgradeable target with implementation and admin, warns on delegated-EOA targets; the policy file pins `chainId` 1. |
| V2-61 | Low (ops / docs) | Vault upgrade state, `SignMsg` / `ApproveHash` history and owner code were outside the pre-install checklist; Safe's `migrateWithFallbackHandler` under an admin approval reinstalls a signature-capable handler; a lone `updateNewTotalAssets` closes Lagoon's epoch and strands pending requests under a lockdown; the registry already whitelists a v0.5.0 downgrade target; only `totalAssetsLifespan == 0` keeps Lagoon's synchronous paths closed; vault-side events and incident-transaction privacy were missing from the monitoring guidance; admin approval TTLs start when a stranger executes the operation. | §6 (snapshot scope, vault code, queued operations), §7.3, §7.5 (never-on-the-council-lane list, Safe upgrade sequence, TTL guidance), §7.6, §7.7 and §7.8 written or corrected. |
| V2-62 | Info | NatSpec: the ERC-165 check on `setGuard` exists from v1.4.1; modules can make the Safe call itself; v1.5.0 emits no hash for module transactions. Gas floor with a gas-keeping venue is 0.8 M to 1.6 M on the live Safe; v1.5.0 bubbles venue revert data that can mimic guard errors; USDT refuses `approve` from a non-zero allowance. | Corrected or documented. |

Room for these changes came from removing duplication (the window checks and the module-allowlist
check are shared by the live hook and the dry run) and from compiling the guard at 10 optimizer runs
in both toolchains: 23,388 bytes, 204 under the gate. Suite: 254 unit tests, 6 fork tests, the
pre-Cancun test.

#### Round 6 (v2): compiler and libraries, stateful fuzzing, tooling attack surface, composition (2026-10-05)

A fourth campaign, again with new angles: solc 0.8.25's known-bug list, OpenZeppelin 5.2.0 and the
refactors of round 5, differentially across seven builds (legacy and via-IR, 10 and 200 runs,
optimiser off; 10,000 short and 2,000 long random operation sequences agree; 18 seeded mutants of the
newest logic detected); a two-Safe stateful fuzz campaign with a reference model (module path,
batches, windows, cooldown, a re-entrant venue; 42,000 handler calls, no violation; 38 of 39 seeded
defects detected); the off-chain tooling as an attack surface (139 crafted policy files, eleven
scripted scenarios against the fork rehearsal, the deploy script's preflights and reruns, the Safe
helper); and the composition of accepted residuals, role powers and the round-5 protections (75
PoCs on the production topology with real Safes for proposers, council and curator). No chain reaches
custody on the live topology without the curator's own quorum, and no guard-level defect above Low
was found; the findings sit in the timelock topology, the tooling and the runbook.

| # | Sev. | Finding | Resolution |
|---|---|---|---|
| V2-63 | High (governance liveness) | OpenZeppelin makes every proposer a canceller, so each of the two REQUIRED proposer Safes could veto its own removal: a compromised one was a permanent veto (no admin operation ever executes again, the guard can never leave the Safe), and with a compromised council it was the permanent freeze of V2-54 moved one level up. A deployer key held the timelock's admin role from creation until a separate `renounceRole`; whatever it granted or queued in between survived unaudited (R6D-3, R6D-6, R6C-04). | `CuratorGuardTimelock` fixes the topology in its constructor: two proposers, exactly ONE canceller Safe (the trusted veto; a proposer without the role is removable), the executor open, no deployer admin. The deploy script refuses two cancellers, dedupes proposers, requires every governance principal to be a Safe with threshold ≥ 2 (a failed read refuses), checks signer overlap pairwise (curator against everyone; the council may not own or share a quorum with a proposer or the canceller), and audits every timelock, reused or fresh, from its own logs (code hash, delay, exact role set, empty queue). §4, §6, §7.1, §7.5; tests `CuratorGuardTimelockTest`. |
| V2-64 | Low (build) | The Foundry restriction `runs_10 = true` named a profile, not a setting, and was silently ignored: under the default profile the guard was built at 200 runs (23,852 bytes, over the gate; the harness over EIP-170), contrary to the comments (R6A-1). The timelock was deployed from a 1000-run build no test ran (R6A-4). | `{ paths = "contracts/guards/CuratorGuard*.sol", optimizer_runs = 10 }`; the Hardhat 10-run override covers the timelock too; `forge config` shows the constraint under both profiles. The two `via_ir_high = true` entries outside the guard have the same slip and are left for the owners of that code. |
| V2-65 | Medium (irreversible) | Three one-operation wedges on the unmodified timelock: `updateDelay` typed in milliseconds (2,000 days, the correction needs the new delay) or as 48 seconds, or `type(uint256).max` (every schedule overflows); `revokeRole(EXECUTOR_ROLE, address(0))` without a named executor (nothing executes again, the repair included); the timelock renouncing its own admin role (the role set frozen for good); both proposers rotating from one bad list (R6D-5, R6D-8). | The subclass clamps `getMinDelay()` to [1 h, 30 d] (the raw value is what the event reports), refuses to revoke the open executor or its own admin role, and keeps the last proposer and the last canceller (role counts maintained in `_grantRole` / `_revokeRole`). Tests for each rail. |
| V2-66 | Low today, Medium with automation | "Council windows keep the module allowlist" kept the list and dropped the policy: an allowlisted module (no owner signature) got every venue call inside a window the council opened for the signers (R6D-11). A council approval could also name a module a guardian had removed from the allowlist (R6B-O1). | A council window relaxes the owner-signed path only: the module path stays under the policy and the module allowlist (admin windows stay inert on both paths); a council approval with a non-zero executor needs an allowlisted module. `_checkWindow` returns whether the window handled the path and `_checkModuleAllowed` is shared with approvals; three tests rewritten, one added. |
| V2-67 | Medium (liveness; introduced by the round-5 cooldown) | A narrower that keeps re-locking vetoed every timelock batch that mixed a lift with anything else, its own removal included (one held-back call reverts the whole atomic batch), and the sync task emitted exactly that batch with a one-day window the cooldown outlived by construction: measured 216 h frozen after three tool rounds at one 27k-gas transaction per round (R6D-1, R6D-12). | The sync task schedules a lift as its own operation chained behind the rest with `predecessor`, with a window of cooldown + 1 to 3 days; every call is simulated as the admin before scheduling (dead on arrival refused, a cooldown reported with its end) and a lift the cooldown still holds back is skipped at `--execute`, not failed; `lockedAt(safe)` is a public view (bots and the task read the cooldown); §6 and §7.5 say the cooldown protects against stale honest operations, not against a hostile proposer, whose control is the cancel inside `minDelay` and the monitoring of role-changing and timelock-self operations (R6D-2, R6A-3). |
| V2-68 | Medium (tooling) | Five ways a sync could differ from what a reviewer read: a signature whose selector collides with a value-moving function under another name passed the validator with no rule (`many_msg_babbage(bytes1)` is `transfer`); an escaped key (`"mode"`) defeated the duplicate-key scanner; two `OneOf` rules on one word flipped every sync; loosened rules printed like first-time additions and no second person could decode a queued operation; `note` was echoed raw (ANSI injection) (R6C-01, R6C-05, R6C-06, R6C-08, R6C-19). | Shape maps keyed by selector, a well-known-signature table (a colliding name is refused), keys must be plain ASCII without escapes, one rule kind per word, a per-function old-to-new rule diff with `--confirm-loosening`, selectors printed everywhere, a signer manifest with decoded calls and the exact `scheduleBatch` calldata, `curator-guard-verify --op` rebuilding an operation from the chain's logs, `note` printable ASCII of at most 200 characters. A lint corpus (`policies/curator-guard/lint-corpus`, run by `scripts/curator-guard-lint-corpus.sh` in CI) pins every rule. |
| V2-69 | Info | "No code" is not "plain key": the identity precompile (0x04) echoes an EIP-1271 query back as the magic value on Safe builds without the pre-call code check (solc ≥ 0.8.10 sources), so the council could have added an accept-all seat there; dead on the canonical 0.7.6 singletons (R6A-2). | The council lane refuses the low address range (`uint160 > 0xffff`) as a new owner; the admin still may. |
| V2-70 | Low (tooling) | `--execute` compared one aggregated `allowFunctions` call, so a guardian revoking ONE wanted function during the delay made the whole reviewed batch "no longer wanted"; the pending scan kept only operations targeting the guard (timelock self-calls and foreign targets, the dangerous ones, were never listed) and failed open on a scan error; the state file was believed verbatim; `--deadline-days 0` or `100000` scheduled dead or 273-year operations; the Safe helper proposed a rehearsal on a dev node under a non-`localhost` name to the production Safe queue, signed by a key that could differ from the named sender (R6D-14, R6C-10, R6C-11, R6C-13, R6C-14). | One `allowFunction` call per function; the scan covers every `CallScheduled` since the timelock's creation block (deployment record, `--timelock-block` or `CURATOR_GUARD_TIMELOCK_BLOCK`; unknown block or failed scan refuses unless `--allow-pending`), decoding guard calls, timelock self-calls and foreign targets; operation ids re-derived from stored payloads, `--op` rebuilds from logs; day arguments bounded (1 to 30, lifts 1 to 3) and deadlines printed as dates; the helper impersonates on any dev node and requires the proposal signer to be the named deployer; the task refuses to propose from an undeclared dev node. |
| V2-71 | Low (tooling) | Lint checked less than the sync: rule values unparsed, checksums unverified, zero / Safe / guard entries and duplicates accepted, `"enforce": false` unmarked, vacuous bounds (`≤ 2^256-1`, `≥ 0`), floor above ceiling, only eight allowance-shaped signatures, ownership / upgrade / role / Safe-management selectors allowed like any venue call; the shared batch file and the manifest lingered after a failed proposal; a batch could exceed the EIP-7825 transaction cap and revert for every executor after the delay (R6C-07, R6C-09, R6C-12, R6C-15, R6C-16, R6C-22, R6C-23). | Type-aware value parsing, mandatory EIP-55, exclusions and duplicate checks for every list, `$allowUnenforcedHandler` and `$allowSensitive` markers, vacuous and contradictory bounds refused, 23 allowance / receiver / controller / operator-shaped signatures, signed-word warnings; the shared batch file is removed on a failed proposal and the manifest at completion; gas estimated (refused above 12 M, warned above 8 M); more proxy patterns (ZeppelinOS, EIP-1822) and a selector-in-code probe; Safe cross-checks fail closed on transport errors; the code at `--guard` must be this build; `policy.guard` required outside rehearsals; a governance summary (roles from logs, pending admin transfer, standing approvals, forbidden hashes, cooldown) on every run; re-allows of revoked functions said out loud. |
| V2-72 | Low | `AdminIsGuarded` read the raw mode: after a council window on the pending admin expired and the council was removed, the acceptance still reverted until `lockdown(newAdmin)` (R6D-10). The constructor accepted the council as admin, which `beginDefaultAdminTransfer` refuses (R6A-6). | The predicate reads the effective mode (a live window still refuses); the constructor refuses `council == admin`. |
| V2-73 | Info (docs, CI) | Seven places still told the operator to make the council a canceller, one of them the rotation instruction of §7.5 (R6D-7, R6C-17); a live `setGuard(newGuard)` approval is an exit from any lockdown onto an unwatched guard (R6D-8); the council's residue outlives its removal (R6D-9); owner rules are order-sensitive and point-in-time (R6D-15); lift-time cards (signed stale Safe transactions, two ready operations) (R6D-13); CI used `npm i`, mutable action tags, `stable` Foundry, no `permissions:`, a `tsc` step that passed when tsc died, an e2e suite that skipped on a wrong-chain secret, and no job ran the tooling (R6C-18). | Docs corrected everywhere (§4, §6, §7.1, §7.5, §7.6, §7.7, `helpers/address.ts`, the deploy script header, `IMPROVEMENTS_V2.md`); the sync task refuses to run while the council holds a timelock role. CI: `npm ci --ignore-scripts`, pinned Foundry, `permissions: contents: read`, abnormal `tsc` exits fail, the e2e suite asserts chain id 1 and the Safe's code, the lint corpus runs, and a second job runs the fork rehearsal (deploy, schedule, execute, install, incident drill) with cached Hardhat artifacts. |

Not changed, recorded: the two `via_ir_high` restrictions outside the guard (V2-64); the
`validateModuleTransaction(safe, address(0), …)` dry run answered by an owner-path approval (no module
is `address(0)`, R6B-O2; closed since by V2-75: the module allowlist is checked first, so the zero
module is `ModuleNotAllowed`); "events only on change" for the four `…Updated(x, false)` setters and a
refusal of shortening re-approvals (R6D-16: monitoring hygiene, bytes); a cooldown on a council
younger than the Safe's last lockdown (R6D-2: the cancel inside `minDelay` is the control). Size
after this round: 23,472 bytes, 120 under the gate, with the `lockedAt` view, the module-path rule
and the precompile exclusion paid for by three unchecked additions of bounded timestamps. Suite:
265 unit tests, 6 fork tests, the pre-Cancun test; the fork rehearsal now ends with an incident
drill (council lockdown, a lift scheduled as a chained operation, `curator-guard-verify` from the
logs, a re-lock holding it back, execution after the cooldown).

#### Round 7 (v2): line-by-line re-audit, mutation campaign, live runbook drill, assumption audit (2026-10-05)

The last of the three extra campaigns: a fresh line-by-line audit of the three contracts after the
round-6 changes (29 PoCs, dispatcher, storage layout and interface pins, OpenZeppelin 5.2.0's
constructor dispatch proven on the vendored source); a mutation campaign against the suite (183
hand-written mutants of the round-5 and round-6 code: 172 killed, 4 equivalent, 7 test gaps closed
by killing tests now in the suite, no surviving mutant that the spec wants); an end-to-end runbook
drill on the mainnet fork with real `execTransaction`s from the curator's quorum (deploy, schedule,
execute, install, settlement, NAV band, lockdown and lift, council owner rotation and window, the
replacement-guard swap, second-operator execution from the logs, the deploy refusals one by one, the
timelock rails through scheduled self-calls; 2 Medium and 1 Medium-process findings on the tooling,
none on the contracts); and an assumption audit of every claim the documentation makes against the
code and the live topology (28 claims corrected, one High on the topology). No contract-level
finding above Low; the High is the governance shape the contracts allowed and the address book
configured.

| # | Sev. | Finding | Resolution |
|---|---|---|---|
| V2-74 | High (governance topology) | "One trusted veto" was instantiated as a proposer that also cancels: a compromised canceller-proposer is an unvetoed TAKEOVER after one `minDelay` (it schedules anything, nobody can cancel; reproduced: the honest council revoked, a hostile council granted, `enforce` and a 7-day window in one batch executed inside the cooldown), not the deadlock §4 / §6 described; `helpers/address.ts` listed the same governance Safe, the one sharing three curator keys, as sole proposer and sole canceller, and the deploy script enforced "one canceller" but not "the canceller proposes nothing" (R7D-1). | Proposing and vetoing are separated by the contract: the constructor refuses a canceller that is a proposer and `_grantRole` refuses either role to a holder of the other ever after (`CancellerCannotPropose` / `ProposerCannotCancel`); `address(0)` is never a holder of a gated role (R7A-1: it would have defeated the last-holder rail). The deploy script refuses a canceller that proposes; the address book ships an EMPTY canceller list with the instruction to create a dedicated veto Safe (ideally a 2-of-3 of three distinct governance parties) and the fork rehearsal uses a stand-in; §4 and §6 now say what a compromised veto can and cannot do. |
| V2-75 | Low today, Medium with automation | A module-bound approval was checked against the module allowlist at ISSUE only: an approval issued while the module was allowlisted was consumed after a guardian removed the module, so "the fast lane never re-arms a removed module" held for new approvals only (R7A-2, R7D-2 / P1-3). | The module allowlist is checked before the approval branch on the module path, live and in the dry run: a module off the allowlist spends no approval, admin- or council-issued (`setModuleAllowed(false)` is a complete switch; approvals are kept and come back with the allowlisting). Zero bytes: a reordering. |
| V2-76 | Low (tests) | Seven mutants survived the suite: the delay clamp's two edges, a counter moved by a revoke of a role not held, a one-byte-short council payload reverting without data instead of the typed error, the admin not refused on itself as a Safe, a partial-selector self-call accepted on the policy path, and `ApprovalConsumed` not pinned on the module path (R7-B). Four more mutants were equivalent (the three `unchecked` blocks and the approval-before-window order, proven). | The killing tests are in `CuratorGuardRound6.t.sol` (timelock) and `CuratorGuardRound7.t.sol` (the rest, plus a tightened expectation for a singleton swapped mid-transaction). Mutation score after them: 179 / 179 non-equivalent mutants. |
| V2-77 | Medium (tooling, rehearsal) | The fork rehearsal could stop silently with exit 0: a failing upstream read inside a transaction makes hardhat's EDR panic and the pending promise never settles, so `catch` is never reached and CI would have been green on a run that stopped at the first deploy (R7C-01). | The script sets a failing exit code first and clears it only by its last line; CI asserts the "incident drill complete" marker too; §7.5 says to treat any run without it as failed. |
| V2-78 | Medium (tooling, operator misled) | Five of the six `CURATOR_GUARD_ALLOW_*` overrides downgraded refusals on REAL networks while the script's header and banner said "rehearsal only" / "they downgrade nothing"; `.env` leftovers from a rehearsal applied on mainnet (a two-canceller timelock was deployed in REAL mode under that banner); a sub-hour delay surfaced as an undecoded constructor revert (R7C-02, R7C-14, R7D-4). | `KEY_OVERLAP`, `MULTIPLE_CANCELLERS` and `WEAK_GOVERNANCE` are rehearsal-only; `NO_COUNCIL`, `SINGLE_PROPOSER` and `SHORT_DELAY` downgrade on real networks with a banner naming them; a sub-hour delay for a fresh timelock is refused outright; §7.1 lists each override and says to unset them after a rehearsal. |
| V2-79 | Medium (tooling, operator misled) | The timelock's queue was listed only when there was something to schedule: the documented check "re-run and expect already in sync" printed nothing while `updateDelay(48)`, role changes, queued windows or approvals or an abandoned batch sat ready (R7C-03). `--dry-run` skipped the pending scan, the simulation, the gas gate and the ids, so the first time an operator saw them was the run that proposed to the Safe service (R7C-09). | Every run prints the queue, whatever the target, before the diff; a dry run walks the whole scheduling path and stops before anything is written or sent, on the direct and the timelock paths alike. |
| V2-80 | Low (tooling) | `--allow-pending` dropped the superseded operation from the state file and `--execute` refused an executable set when the old one landed first (R7C-04); `--execute --op` deleted the state file and manifest of OTHER in-flight operations and let a lift through without `--allow-unlock` when the lockdown fell between preparation and the proposer's signing (R7C-05, R7C-06); `schedule()`-made one-call operations, the natural shape of the `setGuard(newGuard)` approval, failed to rebuild (R7C-07); duplicate `--op` ids executed once then threw a 1970 timestamp (R7C-10); the clock warning printed twice; the selector probe missed selectors with a leading zero byte and probed beacon proxies against the proxy code (R7C-12); the audit misdiagnosed a creation block after the grant (R7C-13); the manifest was written on the production path only (R7C-15). | The state file keeps every in-flight operation and goes when all are done; superseded or drifted operations are skipped loudly with the cancel calldata instead of failing the run; `--op` never touches the file, needs `--allow-unlock` for any lift and accepts one-call operations (`hashOperation`, executed through `execute`); ids are deduplicated; the probe uses solc's shortened PUSH and resolves beacons; the audit names a scan that starts after the grant; the manifest is written on every path. |
| V2-81 | Medium (process, go-live gate) | Nothing tied `"unconstrained": true` on the NAV-marking function to the chain state it is conditioned on: the file could be synced onto a funded vault (R7D-3). The shipped file has no `guard` pin, so the first documented mainnet command was refused, and nothing said to pin (R7C-08). | The sync refuses an unconstrained NAV entry on a vault whose `totalAssets()` is not zero unless `--allow-unconstrained-nav` is given knowingly (the live vaults hold about 1 USDC of dust); the deploy script prints the `"guard"` line to pin and §7.2 starts with it. |
| V2-82 | Info (docs) | 28 claims corrected (R7D Part 1): "cancellable by a proposer Safe", "a time-boxed Bypass disables the guard entirely", "every check before the first transaction", the cooldown's scope in §4, the dry run's gas-refund assumption, `RoleRevoked` missing from the monitoring list, a guarded veto Safe, test counts and gas figures, the `GuardCallNotAllowed` row, `OneOf` growth not a loosening, the rehearsal's downgrades, the live v0.6.0 vaults not answering `securityCouncil()` / `superOperator()` (roles live in the `hopper.storage.Roles` slot: §8 verification uses storage reads). Stale NatSpec after V2-66 in five places; `disableModule` accepted by selector alone; "never for the admin" softened (R7A-3). | Corrected in place; NatSpec rewritten. |

Not changed, recorded: `_requireUnguarded` ignores standing approvals, a dormant handler requirement
and the guard slot (R7A-4; the admin is exempt from the hooks either way); `setDeploymentGuardian`
accepted a guarded Safe (narrowing only, R7D-7; refused since V2-92's `_grantRole` rail, while the per-Safe
`setGuardian` still accepts one: a dead seat either way); an admin-approved batch can forge a path-1
`TransactionChecked` and burn a module-bound approval (R7D-5: a sharpened statement of the
documented batch residual; path-1 reports on a v1.3.0 / v1.4.1 Safe are never authoritative); a
guarded veto Safe is a veto that cannot be used until §7.6 step 5 (R7D-6); the two `via_ir_high`
restrictions outside the guard; CI's `tsc` step treats exit 1 without diagnostics as a crash now but
cannot tell a crash that prints diagnostics (R7D-9); the strategy-side `ILagoonVaultV06` getters
that the live vaults do not implement (outside the guard). Size after this round: guard 23,472 bytes
(unchanged: V2-75 is a reordering), timelock 7,227 bytes, both toolchains identical. Suite: 273 unit
tests, 6 fork tests, the pre-Cancun test; the rehearsal (with the incident drill) exit 0.

#### Round 8 (v2): twenty single-angle contract reviews (2026-10-05)

A fourth extra campaign, contract-level only, with one reviewer per angle: calldata and rules, the
transient-storage state machine, the configuration digest, approvals, access control, gas and
denial of service, the Safe release matrix (v1.3.0 to v1.5.0, the L2 builds, Safe `main`, EIP-7702
accounts, on the deployed 0.7.6 bytecode of every singleton), signatures and the fallback handler,
`MultiSend`, error handling and revert data, events, guard migration, griefing bounds, state-machine
invariants (33 handler actions, 8 planted mutants caught), compiler and assembly output, the Lagoon
NAV path (on the live v0.6.0 implementation bytecode), hostile callers and multi-Safe isolation, the
window / approval / cooldown machine (a 110-cell mutator table and an 80-cell hook table), the public
surface and byte trims, and the timelock with OpenZeppelin's internals. Excluded by request: further
role separation. Every proposal came with a passing PoC and a measured byte cost; the accepted set
was staged, measured and run against the whole suite before it was applied. No Critical or High.
Five Medium findings, all on what an approval or a "Safe" is assumed to be, none on the policy path
of the live Safe as configured.

| # | Sev. | Finding | Resolution |
|---|---|---|---|
| V2-83 | Medium | An approved `MultiSendCallOnly` batch bound bytes, not meaning: the approval lane returned before any parsing, the canonical builds execute truncated and non-canonical payloads (a tail cut inside a value word runs `shown << 8k` wei: the Safe SDK's decoder shows 1 wei for a payload that moves 2^64), a zero `to` is a self-call on v1.5.0, and an approved entry could address the guard's hooks (the documented residual V2-53 / R7D-5) (R8I-1). | An approved delegatecall whose target carries canonical `MultiSendCallOnly` code is decoded at use with the strict decoder in a third mode (canonical encoding, plain-call entries, non-zero `to`, never the guard; nothing else is checked), live and in the dry run, the approval kept on a refusal. Single-call approvals and delegatecalls into other code stay unparsed. The decoder itself reads its headers with in-bounds `calldataload`s (smaller, and a third cheaper per entry). |
| V2-84 | Medium | An approved delegatecall bound the ADDRESS, not the code that would run in the Safe's context (a redeploy, an upgrade or an EIP-7702 re-delegation between approval and use), an approval addressed to an account without code was consumed and reported as done with nothing executed, and a module-bound approval could name the Safe or the guard (R8D-2, R8D-3, R8D-5, J-4). The forced `safeTxGas == 0` on the approval path was redundant since the post-hook reverts on a failed approved execution, and took the signers' only inner-gas floor away (R8D-1). | The code hash of `to` is folded into the approval id for delegatecalls; `approveTransaction` refuses (`InvalidTarget`) an account without code when calldata is sent or for a delegatecall, a delegatecall into `0xef…` delegated code, and an executor that is the Safe or the guard. `SafeTxGasNotAllowed` is gone: a failed approved execution reverts the whole transaction on either path (`ApprovedExecutionFailed` when the Safe reports the failure). |
| V2-85 | Medium | Nothing pinned the Safe's implementation: the digest hashed the VALUE `masterCopy()` returned and tolerated an unreadable one as zero. A canonical proxy in front of a forwarding singleton, an EIP-7702 delegated singleton or account, a proxy that forwards `masterCopy()`, and a future release with another storage layout all read as a Safe through every view the guard, the tooling and the runbook make, while the code behind them could move custody with no Safe transaction, or left the digest silently blind (R8G-1, R8G-3, R8C-1). | The policy path requires the account's code and the code of the singleton its proxy reports (exactly one word) to carry one of nine runtime code hashes fixed at deployment (`SafeNotSupported`); approvals and windows do not read the configuration, so the exits stay open, and a new Safe release means a new guard, as for the unwrappers. The sync task refuses a Safe that is not a canonical build before scheduling anything. The core read shrank to slots 3-4 (slot 0 is what `masterCopy()` answers, slots 1-2 are never written): about 5k gas less per policy transaction. |
| V2-86 | Low | A linked module the guard does not hook was read by the digest on every policy transaction and never acted on: on v1.3.0 / v1.4.1 any module, on v1.5.0 one whose `setModuleGuard(guard)` never ran, executes with no check at all next to a policy that reports everything as fine (R8G-2, R8C-2). | `ModuleNotHooked(firstLinkedModule)` in the configuration check the live pre-hook and the dry run now share (`_checkConfig`: one function, so the two cannot diverge again); the fixes (`disableModule` on the council lane, `setModuleGuard` on the admin lane) are approvals and never read the configuration. |
| V2-87 | Medium (operations) | Two runbook recipes could strand or brick a Safe. An approved `migrateSingleton()` to a release whose guard-hook ABI differs leaves every later transaction reverting inside the pre-hook call, the exits included; `setModuleGuard` executed before the migration on a zero-handler v1.4.1 Safe is a silent success that spends the approval and sets nothing; and on v1.5.0 a guard swap approved as two separate self-calls strands the module path on the old guard when `setGuard` runs first (R8G-4, R8G-2c, R8L-F1, R8L-F2). | §7.5: the migration is approved only as ONE `MultiSend` batch `[migrateSingleton, setGuard(guard), setModuleGuard(guard)]` (the re-installs run on the NEW singleton, whose own ERC-165 question reverts the whole batch for an incompatible release), the v1.5.0 swap as ONE `MultiSendCallOnly` batch, and every approved Safe self-call is confirmed by the Safe's own event. `ISafe.setModuleGuard` documents the silent success. The recipe and the trap are pinned by a test. |
| V2-88 | Low | The hooks answered any account whose policy key they held, so a guard that is not in the Safe's slot (a replacement before adoption, a retired guard after the swap) still spent approvals, honoured windows and emitted reports whenever the installed guard let the Safe call it (the class behind R6D-16) (R8L-F3). | `_requireInstalled`: the pre-hook reads the Safe's guard slot of that path and reverts `GuardNotInstalled` unless it names this guard, before the window and approval branches (not in the post-hook, which the Safe calls on its cached guard after an approved swap, nor in the dry runs, which the pre-swap checklist uses). |
| V2-89 | Low | With the guard as the Safe's fallback handler (a paste error in an approved `setFallbackHandler`, or done before install), `FallbackManager` forwards every unknown selector to it, for any caller, with the Safe as `msg.sender`: a stranger could consume standing approvals and forge `TransactionChecked` with no Safe transaction; `setRequiredFallbackHandler` accepted the guard and the Safe (R8H-1, R8N-1, R8N-6). The first fix staged in this round, a check on the call's length, was itself broken by the last reviewer: the forwarded length is the caller's choice, and twelve bytes of padding restore a canonical one (R8Q-2). | No approval is spent (live or in the dry run) while the Safe's handler slot holds the guard, and an after-hook must be exactly its 68 bytes, where a forwarded call carries the caller's address in `success` and is refused by the decoder (`ForwardedHookCall`); a forwarded pre-hook on the policy path can only park a transient snapshot that dies with the stranger's transaction. A council window carries the `setFallbackHandler(0)` repair. A required handler is never the Safe nor the guard; the validator mirrors it. |
| V2-90 | Low | A non-zero required handler re-opened the install-ordering trap: the requirement was an equality, so a Safe with NO handler was refused, and the one handler change the council may approve (`setFallbackHandler(0)`) froze a working Safe until the timelock (R8H-2). | No handler is always acceptable; a non-zero one must be the handler the policy names. |
| V2-91 | Medium | Incident narrowing cost 3.3 times what the documentation said (about 14k gas per `OneOf` member on committed storage): `revokeTarget` at the validator's caps needed 87 % of the per-transaction gas cap, a validator-compliant target could be un-revocable in one transaction, and at the on-chain caps `revokeFunction` fit in no transaction. The per-Safe guardian set was council-growable without bound (R8F F-1, F-3). | `OneOf` sets are keyed by a per-function generation that every revocation bumps: revocation abandons the sets in O(1) and a re-allow starts empty (no per-member event: indexers clear a function's sets on `FunctionRevoked`). At most 32 selectors per target and 32 guardians per Safe. The task estimates a batch's gas again when it executes it. |
| V2-92 | Low | The library's `grantRole` was the only mutator without the guard's input rails: `address(0)` (an `eth_call` without a sender then acted as the council), the admin (kept a council key after a hand-over), a configured Safe (a dead fast lane discovered in an incident). `changeDefaultAdminDelay` had a cap and no floor, and a pending admin never expired (R8E F-1, F-2, F-6, R8N-3). | `_grantRole` refuses the zero address, the admin and an account the admin gave an allowlist to (admin-written state only, so a rogue council cannot veto its successor); the admin delay has a 1-day floor; a pending admin must accept within 30 days of the schedule. |
| V2-93 | Low | Timelock: the timelock itself could hold `PROPOSER_ROLE` / `CANCELLER_ROLE` (by grant or by construction: a phantom holder that defeats the last-holder rail, and as canceller a veto in every proposer's hands); one scheduled `grantRole(DEFAULT_ADMIN_ROLE, x)` gave `x` undelayed, unvetoable role management; `schedule` accepted a delay typed in the wrong unit (2,000 days, or a `Panic` at the extreme), calldata for a target without code (the operation "executes" and is Done with nothing run) and an `updateDelay` that the clamp then silently read as the 1-hour floor (R8E F-4, F-5, R8J J-3, J-5, J-6, confirmed and refined by R8T). | `SelfHolder`, `SelfAdminRequired` on the grant side, and proposal-time rails on `schedule` / `scheduleBatch` (`DelayOutOfRange`, `TargetHasNoCode`; `execute` refuses a codeless target again), behind the proposer check and the base's length check. A full rotation of both proposers and the veto still works as one batch. |
| V2-94 | Low | "A guardian's `setModuleAllowed(false)` is a complete switch" was false inside an admin window: the window returned before the module check, so a disabled v1.5.0 module regained everything, `setGuard(0)` included, for up to 180 days (R8R-1). | The module allowlist is checked before the window, live and in the dry run (a read of the guard's own storage: no effect on a window's recovery purpose). Zero bytes. |
| V2-95 | Low | Rules: a floor's only partner could bound nothing (`LessThanOrEqual 2^256-1`) or sit below it (a dead function); an allowlisted call to an account without code "succeeded" and kept its value; dynamic arguments could not be bound at all, so a venue's own batch function was all-or-nothing (R8A-1, R8A-5, R8A-4, R8A-2, R8I-2). | The pairing check refuses both ceilings; `NotAContract` at call time; a tail-hash rule (`TAIL_FLAG` in `wordIndex`: the subject is the hash of the calldata from that word on) binds one reviewed payload or a set of them. The validator refuses self-dispatching selectors without a marker, `multiSend(bytes)` as a function and an unwrapper as a target. |
| V2-96 | Low | Smaller contract items: a council window let a gas refund pay `refundReceiver` outside the council's limits (R8B-1); forbidding a mistyped unwrapper hash succeeded, changed nothing and logged a no-op the tooling then reported for ever (R8I-3, R8K K-1); the guard could be registered as its own guardian (R8N-2, R8S S-2); `ModuleUpdated` / `MultiSendUnwrapperUpdated` fired without a change (K-2); bots could not filter reports by outcome or mode (K-4). | Refunds refused in council windows; a hash outside the seeded set is refused in both directions; `setGuardian` uses `_checkTarget`; the two events fire on change only; `outcome` and `mode` are indexed topics (and the build is smaller for it); `VERSION()`. |
| V2-97 | Low (tooling) | A values-only queued batch died on one `revokeFunction` during the delay (`NoOneOfRule`) (R8M-1); `--op` refused an operation scheduled with salt 0, although "no `CallSalt`" means salt 0 (K-8); an empty revert and the timelock's `FailedCall()` printed as a transport error (J-2); the module message claimed a refusal the contract does not make (R8N-4). | The sync re-asserts the identical `allowFunction` ahead of its `addAllowedValues`; salt 0 is tried and verified against the id; `decodeRevert` names both shapes; message corrected. 13 lint-corpus cases added. |
| V2-98 | Info (tests) | The suite did not pin that removing the locking key leaves the cooldown in force (a variant that ended it passed every test while reopening V2-55), nor the migration recipe, nor the admin-window module rule (R8M-2). | Three cooldown pins, the migration test, and `CuratorGuardRound8.t.sol` / `CuratorGuardRound8Timelock.t.sol` for everything above. |
| V2-99 | Info (docs) | Doc truth: §4's evaluation order listed the approval before the module allowlist (stale since V2-75); "whitelist mode OR guardrails" in §8 is not an equivalence (a relative per-share bound pays an outside depositor in proportion to its own stake: reproduced on the live implementation bytecode, R8P-1); the narrowing-cost figures; `MinDelayChange` reports the raw value; a successor timelock brings its queue to a hand-over (R8E F-3); only the veto clears a dead operation and chained operations are cancelled as a pair (R8T T-4); the admin delay must stay above `minDelay` (T-5); v1.3.0 `setGuard` stores any address and emits non-indexed events (R8G-5, R8G-6); a replacement inherits neither `GUARDIAN_ROLE` members nor forbidden hashes (R8L-F4); pre-install storage baseline (R8C-6, R8H-5); a large `ownerCount` excess fails without data (J-7). | Corrected in §4 to §8; NatSpec rewritten. |
| V2-100 | Low | The same forwarding door opened the ROLE surface: a role-holding Safe (the council Safe, a guardian Safe; on the timelock a proposer or the veto Safe) whose fallback handler is the guard (the timelock) handed its role to everyone, with no signature and nothing in the Safe's queue: anyone could call `councilSafe.bypass(custodySafe, 7 days)` (R8Q-3). | No role is honoured for a caller that answers as a Safe with this guard in its handler slot (`Unauthorized`; probed in every role check, the library's `onlyRole` and `renounceRole` included), and the timelock has the same rail (`ForwardedCall`). The sync task refuses such a Safe on every run and the deploy script warns on any non-canonical handler of a governance Safe; `ChangedFallbackHandler` on a governance Safe pages. The door stays open on any OTHER contract a governance Safe has rights on (§6). |
| V2-101 | Info | The module-path report hash was a function of the payload only, so two Safes driven by one module with one payload shared a `txHash` topic (R8Q-1); a "recorded" note of round 6 had been closed by V2-75 without saying so (R8Q-4); the stranger list of the invariant handler missed 11 of 34 mutators (R8Q I-2). | The hash folds the Safe; the note says so; a 40-call stranger matrix over nine caller kinds, the cross-Safe isolation tests and a hostile "Safe" are in the suite (`CuratorGuardStrangers`, `CrossSafe`, `HostileSafe`, `RolesAsCallers`, `TimelockSurface`). |

Trims that paid for the additions, each behaviour-preserving with a differential or the whole suite
behind it: the transient slot is the literal `safe << 8 | path` (no hashing), the configuration
check is one function, the three `set…Allowed` setters share their prologue, the approval record is
written with one `SSTORE`, `ExecContext` no longer carries the Safe, bounded arithmetic is
`unchecked`, array elements are bound once per iteration.

Not changed, recorded: two Lagoon NAV rule kinds designed by this round (`WithinBpsOf` with an
absolute bound and `MinInterval`: +541 bytes as a pair, the first persistent write on the policy
path, settlement in two transactions; they change how the curator operates, so they are the first
open decision of IMPROVEMENTS_V2.md §4, not a fix); a per-Safe key-signatures-only flag (+433, R8H-4);
a gas cap on the configuration reads (a 1,000-owner Safe needs 2.5 M, so any cap is a liveness
cliff; R8C-5 against R8B / R8F); an assembly digest (−617 bytes for a 45-line Yul block in the most
critical read path, R8C-4); via-IR (−975 bytes, but the Safe sources do not compile under it, so
the tested bytes would no longer be the deployed ones, R8O); typed-error fields for responders
(R8J); principal or success fields in events (the receipt carries both, R8K); five rate limits on
windows and lockdowns, two of them unsound (R8M); a whole-policy view (+736) and a terminal
"retired" state (R8L); `allowFunctions` and the other measured trims kept as a byte reserve; a
dead-on-arrival wrapper check and a guard exception for a guarded proposer Safe (R8T); `approveHash`
and `signedMessages` plants (unchanged residual). Pre-existing and unchanged: the admin window
leaves batch entries undecoded, so a report inside one is not authoritative. Size after this round: guard 23,224 bytes (368 under the gate),
timelock 8,187 bytes, both toolchains identical. Suite: 350 unit tests in 32 test contracts, 6 fork
tests, the pre-Cancun test; the lint corpus (31 cases plus the shipped policy); the rehearsal (with
the incident drill) exit 0. Gas: about 47.6k per owner-signed transaction warm with one owner (46.9k
before: the installed-slot read and the code pin cost more than the smaller core read saves on a warm
path).
