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

## 1. Ground truth (Ethereum mainnet, read on 2026-10-04; the two Safes' owner sets re-read on 2026-10-09, review G13b-3)

| Fact | Value |
|---|---|
| Lagoon vaults (`helpers/address.ts` `Lagoon.vault.Vetro_*`) | USDC `0x131C…6679`, USDT `0xE7Fa…eDba`, WBTC `0x1a9b…0e90`, cbBTC `0x110B…6340`, hemiBTC `0x26A6…fdc3`, all `version() == "v0.6.0"` |
| Custody Safe (`vault.safe()`) of all five | `0x1b534a8543212F5957168D83311A41E0Ea1cfe48` |
| Safe version / owners / threshold | v1.4.1, 4 owners, threshold 2 |
| Safe modules / guard / module guard | none / none / none |
| Safe fallback handler | canonical `CompatibilityFallbackHandler` v1.4.1 (`0xfd07…Ec99`), i.e. EIP-1271 capable (see §6) |
| Vetro governance (`governor()` of every Vetro yield vault and of the `Lagoon_Vetro_*` strategies, also their `feeCollector`) | `0x6649Ddb5c7e52348b73c8bBdD2A1cbA630b7AaEA`, Safe v1.4.1, 3-of-6: the proposed **proposer** of the guard's admin timelock (v1 called it the guard owner) |
| 1271-aware custody assets | USDC (`FiatTokenV2_2`: `permit` and EIP-3009 `transferWithAuthorization` validate contract signatures). cbBTC exposes `permit` / `transferWithAuthorization` but validates ECDSA only (a contract signer is rejected); USDT, WBTC and hemiBTC expose none of them (probed on-chain) |
| Who can change the custody assets' code | USDC and cbBTC are proxies whose admin accounts (`0x807a…95d2`, `0x42d9…c2af`) hold no code, i.e. keys, not contracts; USDT is not a proxy but `deprecate(address)` re-targets `approve` and the transfers to new code under the same selectors; WBTC is not a proxy (pausable, no blacklist); hemiBTC is a LayerZero OFT, unverified on Sourcify, whose owner `0x694f…C4e6` (a 171-byte proxy) sets the bridge peers (read on-chain, review G17d-3). The guard's answer is unchanged: allowing a proxy is trusting its admin (§5), and the approve cap bounds a hostile implementation to the allowance |
| Governance Safe owners vs curator Safe owners | the governance Safe is 3-of-6 and **two of its six owners are also owners of the curator Safe** (`0x1F0D…8AC`, `0x9aCa…FFa`; on 2026-10-04 it was three: `0xE173…5d3` was swapped for `0x5cCf…091` at the governance Safe's nonce 42, block 26,151,701, 2026-10-09 01:55 UTC, inside review round 12, review G13b-3 and G13g-3): two shared keys meet the curator 2-of-4 quorum but are one short of the proposer quorum, so curator keys alone no longer meet it; any overlap is still what the v2 deploy script refuses (§6) |
| Lagoon NAV guardrails | `GuardrailsManager` storage is zero on all five vaults (`activated == false`): `updateNewTotalAssets` accepts **any** value today; the curator Safe is also `securityCouncil`, the only role that can activate / configure guardrails |
| Vault fee rates / lifespan / sync | `feeRates() == (0,0,0,0,0)`, `totalAssetsLifespan == 0` (sync deposits never open, NAV always re-proposable), `maxCap == uint256.max`, `allowHighWaterMarkReset == true` |
| Vault proxies | ERC-1967 `LagoonVaultProxy`; each vault's admin is its own `DelayProxyAdmin` (`owner() == the curator Safe`, `delay() == 1 day`, no pending upgrade), gated by Lagoon's protocol registry (`0x6dA4…27C`, owned by Lagoon `0x9A40…d4B`; ONE upgradeable contract: `canUseLogic(proxy, logic)` gates upgrades and `protocolFeeReceiver()` / `protocolRate()` set the protocol's cut, read live on 2026-10-11: it is the "fee registry" of §6 and §8) |
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

- Valuing positions or judging NAV honesty. That is Lagoon's guardrails and Vetro's `maxLossBps` /
  `reportLoss` in `LagoonBase` (§8; neither is live today: guardrails are deactivated on the five
  vaults and `maxLossBps == 0`, §1, §6); the guard only scopes execution.
- Replacing the curator's Safe with a Vetro-owned Safe plus a Zodiac Roles module. Possible, but
  it changes who signs; see §3.
- Expressing arbitrary parameter conditions (nested structs, dynamic arrays, cross-parameter
  logic). The rule model compares static head words, which is what custody-relevant parameters
  (`spender`, `receiver`, `onBehalfOf`, `to`, amounts) are, and binds a dynamic payload only as a
  whole, by the hash of the calldata tail (`"tail": true`, §5; one reviewed payload or a set of
  them), never field by field. Anything richer belongs in Zodiac Roles v2 or a purpose-built
  checker, not in this guard.

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

Roles (OpenZeppelin `AccessControlDefaultAdminRules`; the v2 role split is recorded in §13):

- **admin** (`DEFAULT_ADMIN_ROLE`, exactly one account, two-step transfer with a delay; in production
  the `CuratorGuardTimelock`, an OpenZeppelin `TimelockController` whose role set is fixed by its
  constructor: two proposer Safes (a deploy-script rule; `helpers/address.ts` still lists one) and
  exactly ONE dedicated veto Safe as canceller, which proposes nothing: the contract refuses a
  canceller that is also a proposer, at construction and on every later `grantRole`. A canceller can
  veto its own removal, so a canceller that could also propose would be an unvetoed takeover once
  compromised (strip the council, widen anything, approve `setGuard(0)`), a veto-only Safe at worst a
  deadlock, and a compromised proposer is cancellable and removable. The executor role is open, there
  is no deployer admin, the council and hot keys hold nothing (deploy-script rules; on-chain only the
  veto and the §7.7 alerts keep it so); the subclass also clamps `getMinDelay()` to [1 d, 30 d],
  refuses to drop the open executor or its own admin role, keeps the last proposer and the last
  canceller, never counts `address(0)` or the timelock itself as a holder of a gated role, never
  grants its admin role to anyone else, and refuses at `schedule` what would fail or misbehave late:
  an operation delay other than the live `getMinDelay()` (an operation id carries neither its proposer
  nor its delay: with a longer one a compromised proposer could take the honest proposer's exact
  operation up to 30 days out, so the honest `scheduleBatch` reverts and the honest wrapper is dead on
  arrival, review G10c-1), calldata for a target without code (which `execute` refuses again)
  and an `updateDelay` outside the clamp): the only role that can **widen** a policy (`allowFunction(s)`,
  `addAllowedValues`, `setNativeTransferAllowed` / `setMultiSendUnwrapper` / `setModuleAllowed` with
  `true`, `setRequiredFallbackHandler`; re-allowing a seeded unwrapper hash and seating guardians are
  admin OR council), issue approvals of up to 180 days, open a `Bypass` window of up to 180 days in
  which nothing is checked (except that the guard itself is never a call target and a module must
  still be allowlisted), and administer roles. Every widening therefore sits in public for the timelock's `minDelay` (48 h by
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
  lockdown(newAdmin)]`, then accept inside the 30 days, or begin again (review G9c-1; a key the council
  plants after the batch was prepared survives it and costs one more operation, and a per-Safe guardian
  set the council filled to its 32 makes the admin's own `setGuardian(safe, key, true)` revert
  `TooManyValues` until the batch empties it, review G10c-6). And no
  role is honoured for a caller that answers as a Safe with THIS guard in its fallback-handler slot (the
  slot's low 160 bits, as the EVM masks a call target: a word with dirty high bits still forwards, review G16d-1)
  (`Unauthorized`; the timelock has the same rail for its proposers and its veto, `ForwardedCall`):
  such a Safe forwards anyone's call here with itself as the caller, so its role would be public. The probe
  (the caller's own `getStorageAt`, every remaining gas forwarded) fails OPEN when it runs out of gas, but
  whoever starves it keeps at most 1/64 of the frame's gas for what follows, so a forged report or a
  forwarded acceptance would need the probe's own cost to exceed about 64 times the inner call's: measured,
  a window of gas limits appears only once the probe costs about 300k gas with every read warm, or 560k
  cold, against 1.7k and 5.7k today; no repricing of `SLOAD`, `STATICCALL` or the Safe's dispatcher comes
  within two orders of magnitude of it (review G16e). The admin
  itself is **never constrained** by the guard: all hooks return early for `msg.sender ==
  defaultAdmin()`, so installing the guard on the admin by mistake cannot deadlock the system. `owner()`
  is kept as a view and returns the admin. A few input rails run before the role check, so a stranger
  may be refused `InvalidTarget` (`setGuardian` with the guard as the seat), `AddressIsNull` (a zero
  Safe argument) or `ApprovalNotFound` (`revokeApproval` of an unknown id) rather than `Unauthorized`,
  and `grantRole` / `revokeRole` of the admin role answer every caller with OpenZeppelin's
  `AccessControlEnforcedDefaultAdminRules`: none of these writes state. A per-Safe guardian seat has
  the zero / Safe / guard rail only (`setGuardian(safe, admin, true)` is accepted, a dead seat, while
  `setDeploymentGuardian(admin, true)` is `AdminIsGuarded`), and the timelock accepts a named
  executor next to the open one through a scheduled `grantRole(EXECUTOR_ROLE, …)` (review G12e).
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
  `lockdownAndRevoke`). On a v1.5.0 Safe with a module the signers enabled and the admin allowlisted,
  the rotation needs no signer at all: a module-bound council approval of the Safe's own `swapOwner`
  is executed by whoever drives the module (review G17a-2; the rail that would refuse module-bound
  self-calls is held, because it would also remove the council's signer-free recovery of a Safe whose
  signers are lost). A council window relaxes the owner-signed path only: a module (no owner
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
  admin operation, including its own removal. A council or guardian key can drop its own role at
  once with `renounceRole` (OpenZeppelin; a council that does so leaves the fast lane empty until the
  admin's timelocked `grantRole`), the admin cannot (its renounce path needs a pending transfer to
  `address(0)`, which `AdminCannotBeZero` refuses), and renouncing a role one does not hold is a
  silent no-op (review G12e).

One deployment serves any number of Safes: policies are keyed by `msg.sender` of the hooks (the
Safe). An unconfigured Safe is in `Lockdown`, so a Safe that installs the guard before Vetro
configures it is frozen (fail-closed), not open.

Per-Safe policy (`SafePolicy`):

| Field | Meaning |
|---|---|
| `mode` / `bypassUntil` / `councilBypass` | `Lockdown` (default: deny all but approvals), `Enforced` (allowlist), `Bypass` (policy off until `bypassUntil`, emergency only; a council window keeps the council's self-call allowlist, the module allowlist, the unwrapper-only delegatecall rule and the gas-refund refusal, an admin window keeps the guard unreachable as a call target and the module allowlist). A window opened at `t` for `d` seconds (1 h ≤ d ≤ cap) covers `t … t+d-1`; at `t+d` the Safe reads as `Lockdown`, agreed by `mode()`, both hooks and the dry run (approvals, by contrast, are valid through their `expiry` second inclusive). `bypassWindow(safe)` returns the window end and who opened it |
| `enforceFallbackHandler` / `requiredFallbackHandler` | when enforced, non-approved traffic requires the Safe's fallback handler to be NONE or the configured address (use `address(0)`); no handler is always acceptable (nothing signs, nothing is forwarded), so the council's `setFallbackHandler(0)` fixes every requirement. Never the Safe itself nor the guard (`InvalidTarget`) |
| `functions[target][selector]` | `allowed`, `allowValue` (payable), `rules[]` (≤ 16, ANDed); at most 32 selectors per target |
| `allowedValues[(target, selector, wordIndex, generation)]` | membership set (≤ 128 members) for a live `OneOf` rule; cleared when its rule is dropped (about 12k gas per committed member, 1.6 M for a full set; a re-allow that drops several full sets clears all of them in one call, which the lint's joint cap of 256 members per function keeps inside one transaction, review G11c-1), abandoned in O(1) when the function is revoked (the function's `generation` is bumped and folded into the key: a re-allow starts from empty sets and revocation never iterates members) |
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
   until the Safe adopts it and a retired one from the swap on: neither can spend approvals or use
   windows when the installed guard lets the Safe call it. Not checked in the post-hook (an approved
   `setGuard` moves the slot inside the transaction and the Safe calls the cached guard) nor in the
   dry runs (the pre-swap checklist simulates against the replacement); so a post-hook reached on
   its own by a Safe that holds a live window on a guard it does not have installed still emits a
   `Bypass` report from that guard (a replacement before adoption, through the installed guard's
   admin window; a retired guard until its window ends or `lockdownAndRevoke`): a monitoring
   artefact, never a transaction that guard checked (review G10a-1).
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
   `DelegateCallNotAllowed`. Every entry is checked before the first one executes, against the guard's
   state at that moment: a mode change that lands in the middle of the batch (a venue that holds a
   guardian seat calling `lockdown`) does not stop the entries already admitted; the post-hook compares
   the configuration digest, of which the mode is no part, and the NEXT transaction is refused.
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
  of `success`, which the ABI decoder refuses as a dirty `bool`. A report can therefore not be forged
  through a forwarded hook call, and not through the one re-dispatcher the guard has either:
  `executeBefore` refuses a caller whose fallback handler is this guard (`Unauthorized`) before it
  delegatecalls anything, since the wrapped after-hook would otherwise run at its canonical length
  with the Safe as caller and, inside a window, report any hash (review G9a-1, applied after round
  13; the handler requirement refuses policy traffic from a Safe in that state, §7.3);

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
  self-calls the policy refuses. The one authorized write it cannot see is a REMOVAL behind the head:
  an approved module-path `disableModule(prev, module)` of a module that is not the head, driven by
  a venue inside a policy transaction, unlinks it under a `Policy` report of the outer transaction
  (the same construction against the head module fails closed, `SafeConfigChanged`); a narrowing an
  admin or council approval authorised, never a widening (review G12b-2);
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
| `ERC20.approve(spender, amount)` | `OneOf` on word 0 = the venues that may pull (never unconstrained: `approve(attacker, max)` + `transferFrom` is a full drain). Optionally `LessThanOrEqual` on word 1: the allowance is what a venue that turns hostile (an upgraded implementation, a backdoor) takes in one allowlisted call, so a cap sized to one settlement bounds that take to one cap per curator approval, at the cost of an `approve` entry in every batch that settles a redeem (review G10d-1). |
| `ERC20.transfer` / `transferFrom` | Do not allowlist. Use a one-shot approval for a deliberate transfer. |
| `ERC4626.deposit(assets, receiver)` / `mint(shares, receiver)` | `EqualToSafe` on word 1. |
| `ERC4626.withdraw(assets, receiver, owner)` / `redeem(shares, receiver, owner)` | `EqualToSafe` on words 1 and 2. |
| Aave v3 `supply(asset, amount, onBehalfOf, ref)` / `withdraw(asset, amount, to)` | `EqualToSafe` on word 2; `OneOf` on word 0 if only some assets are allowed. |
| Morpho Blue `supply(marketParams(5 words), assets, shares, onBehalf, data)` | static struct is inlined: `onBehalf` is word 7, `EqualToSafe`; market pinned with `EqualTo` on words 0–4. |
| Lagoon `settleDeposit(uint256)` / `settleRedeem(uint256)` / `updateNewTotalAssets(uint256)` | a static band on word 0 of `updateNewTotalAssets` (`GreaterThanOrEqual` + `LessThanOrEqual` around the settled NAV; band the two settles of that vault with the SAME bounds: a settle repeats whatever mark is pending, `WrongNewTotalAssets` otherwise, and once `securityCouncil` sits outside the Safe (§8) a mark that role places meets no guardrail and, without the band on the settles, no guard either; the lint demands the repetition, review G11b-2) refuses unit mistakes and caps a single mark, and it is the one NAV control that needs no curator signature. It does not bound a malicious quorum (marks chain inside one block: a ±5 % band still costs about 0.25 % of NAV per cycle) and it must be re-synced with every funding step, or honest settlement stops at the ceiling (and at every exit, where the NAV falls below the floor, and on a public vault at every outside deposit or redemption larger than the distance to the nearer bound, half the band: each re-sync is one timelock round; the sync task prints a band that moves in one direction, keeps its relative width and contains the vault's live `totalAssets()` as "shifted" and asks for `--confirm-loosening` only when the band widens or moves away from the live NAV, review G12c; one outsider holding that much alternates a deposit and a redeem so that every re-sync lands into the next stall, at no cost to it, six stalls in three cycles measured, review G13e: never sync a band on a public vault before whitelist mode, §8; note that `totalAssets()` is the curator's last settled mark, so a band that follows it moves by at most the band's width plus whatever the settlements in between moved: a funding step or an exit moves it by the flow itself (+4,668,738 % at the first funding of the USDC vault from dust, printed as the band-move line, review G15a); the file's reviewer, not the flag, judges each move). The validator demands a band or an explicit `"unconstrained": true`; a band is a band only where the NAV sits inside it: the sync task refuses a band's first sync on a vault whose live `totalAssets()` lies outside it or is smaller than the band's width (`[1, 2^256-2]` lints valid, passes the contract and caps nothing) unless `--allow-unconstrained-nav` is given knowingly, and the validator warns offline when the ceiling exceeds 100 times the floor (review G13a-1). An `unconstrained` entry is refused the same way while the vault holds assets OR while a recorded `Lagoon_Vetro_*` strategy routes custody to it (the pool's `debtRatio` / `totalDebt` or the strategy's `tvl()`, read from the address book's `Lagoon.strategy` entries: the curator can mark `totalAssets()` to zero, the pool's accounting it cannot touch; reviews G11b-6, G13g-2, g13e), the strategy figures printed with every refusal, and an empty vault with no Vesper debt behind it passes. On a vault that holds nothing there is no settled NAV to judge a band against and the honest first mark (0) is one no band admits, so the sync refuses a banded or fixed mark on an empty vault until its first settlement (keep the entry `unconstrained` there: the gate admits that while no recorded strategy carries debt or holds assets, and once Vesper custody is pending behind the still-empty vault the first settlement's sync needs `--allow-unconstrained-nav` knowingly, the figures printed; the three live BTC vaults are empty), and a fixed mark (`EqualTo` / `OneOf` on word 0) is judged by its lowest and highest member against the live NAV on every sync, since a set grows by a plain widening the loosening gate never sees (review G16c-2). The band-move line prints the band's edges relative to the live NAV and says when the NAV sits at an edge: a band that keeps the NAV at its floor ratchets by its full width per sync while the ceiling's move alone reads as a modest follow (review G16c-3); and a first band wider than ±10 % is admitted with its price printed, since under ±x a colluding quorum moves about x² of NAV per settlement cycle (26.8 % measured at ±50 %, the gate's edge, against 0.25 % at ±5 %, review G16c). Never type a band for the NAV a flow is EXPECTED to bring: the gate refuses it (the live NAV is outside it) and `--allow-unconstrained-nav` admits it, after which the honest mark is refused and the lowest mark the band admits prices the flow: a band typed for a 50,000 USDC funding of the 1 USDC vault settled that deposit at a 47,500 USDC mark, leaving the deposit worth 25,642 USDC and the vault's one pre-existing share worth 24,359 USDC, measured in review G16c-4; the flag is for the unconstrained case, a band is always synced around the SETTLED NAV and moved after the flow. A settlement the signers confirmed and nobody executed is an option anyone exercises (§6): allowlist the stateless `SettlementDeadline.assertBefore(uint256)` helper (`contracts/helpers/SettlementDeadline.sol`, deployed at funding; a policy entry with no rules) as a plain call and put it first in every settlement batch, so a batch nobody executed before its deadline reverts for every executor (GS013) and its nonce stays free (review G13e-1); the sync refuses that entry unless the code at its target is this repository's `SettlementDeadline` build (metadata excluded, as the guard's own identity check): a look-alike that dispatches the selector and never reverts, a catch-all fallback or a proxy synced with at most a yellow line and bound nothing, measured in review G16c-1 (`"$allowSensitive": true` admits a reviewed foreign helper). NAV honesty remains a Lagoon-role question (§8): guardrails bound `updateNewTotalAssets` only once `securityCouncil` has activated them with real bounds, which is not the case on the live vaults. |
| Payable calls (`WETH.deposit()`) | `allowValue: true`; plain ETH sends need `nativeTransfers`. |
| Swaps (routers, aggregators, CowSwap) | Not expressible safely with static words alone (recipient + min-out + path all matter). Prefer a one-shot approval per swap, or Zodiac Roles. Never allowlist `SignMessageLib` delegatecalls: an EIP-1271-signed order can sell the Safe's balance. |

Word rules address head words only. Do not write word rules on dynamic parameters (`bytes`, arrays,
dynamic structs): their head word is an offset. A `bytesN` parameter (N < 32) sits in the HIGH bytes of
its head word: write its value as the full 32-byte word with the N bytes on the left (`0x12345678` for a
`bytes4` is the word `0x12345678000…000`); a decimal or a right-aligned number is a word no canonical
call carries, and a `LessThanOrEqual` / `GreaterThanOrEqual` on such a word means nothing (the lint
refuses both, review G12f-1). `curator-guard-sync` derives the head layout from
the signature and rejects a word rule on a dynamic word or beyond the head. `address[]`-taking
functions such as Lagoon's `claimSharesOnBehalf(address[])` are fine to allow without rules
because the beneficiaries are the controllers themselves.

A dynamic payload can be bound exactly with a TAIL rule: `{"kind": "EqualTo", "wordIndex": N,
"tail": true, "value": <hash or raw tail bytes>}` binds `keccak256(calldata[4 + 32·N:])`, everything
from head word N to the end of the calldata (inside a batch, to the end of that entry's own
calldata: the hash never reaches the next entry or the padding); `OneOf` with `"values"` binds a set
of reviewed payloads that guardians can trim. N must be the head word of the FIRST dynamic
parameter: from there every offset word is inside the hash, and the static words before it keep
their own rules. A later N would leave the offset word of an earlier dynamic parameter outside the
hash, and an ABI decoder reads that parameter from wherever the offset points (empty, or another
parameter's bytes), so the rule would bind the bytes but not their meaning; the lint refuses it. The
value is the 32-byte hash, or the raw tail bytes, which the tool hashes. Prefer the raw bytes: the
lint checks that they are the canonical encoding of the parameters from word N (decoded with the
signature and re-encoded to the same bytes). A reviewed payload that is NOT canonical binds bytes
but not meaning even from the first dynamic word: its offset can point back into a static word
before N, and a static word without a rule (the lint only warns for unbound `address` words) then
becomes the length or the contents of the dynamic parameter, so the signers change what the venue
decodes without touching the hashed tail (review G10b-1). The 32-byte hash is accepted unchecked,
for a venue that does not decode calldata the standard way.
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
deployment-wide responders hold `GUARDIAN_ROLE` instead). Moving a Safe out of `Lockdown` /
`Bypass` needs `--allow-unlock`. The validator
is strict (unknown keys, non-boolean flags, missing or non-canonical signatures, selector/signature
mismatch, word rules beyond the head or on dynamic words, unbounded lower bounds, more than 16 rules or
128 `OneOf` members per rule, more than 32 functions per target and more than 32 guardians (contract
caps), more than 256 `OneOf` members per function or 1,024 per target (revocation no longer iterates
members: `revokeFunction` costs about 30-70k gas whatever the sets hold and `revokeTarget` at most 32
of those; the joint caps bound `clearAllowedValues` and a re-allow that drops a `OneOf` rule, which
still iterate at about 12k gas per member on committed storage, §4), unwrappers without code or
with a runtime code hash the guard does not allow, a Safe whose proxy or singleton code is not a
canonical build, a required handler that is the Safe or the guard)
and refuses allowance/transfer-shaped selectors (`approve`, `increaseAllowance`, `transfer`,
`transferFrom`, `safeTransferFrom`, `setApprovalForAll`, `permit`, Permit2 `approve`, the ERC-4626 / ERC-7540
receiver shapes and the live Lagoon v0.6.0 vault's own `syncDeposit` / `syncRedeem` / four-argument
`requestDeposit`, review G17d-1) without a rule
on each spender / recipient word (word 0; words 0 and 1 for the `transferFrom` shapes and Permit2;
word 1 for `permit`) unless the entry says `"unconstrained": true`; a `OneOf` set whose bound on the same word no
member satisfies is refused as a dead function (review G17d-2), and so is a ceiling or a floor on an `address` or
`bool` word, or at the full width of a `uintN` word, since it orders nothing (review G17b-3). It also refuses duplicate JSON keys (a trailing duplicate would silently
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
- Widening the policy from a guardian key or a stranger.
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
  is spent that way, `ForwardedHookCall`; `executeBefore` refuses such a caller too, so a forwarded
  hook can no longer be re-dispatched at its canonical length to forge a `Bypass` report inside a
  window, review G9a-1, applied after round 13), or on a guard the Safe does not have
  installed on that path, a replacement before adoption and a retired guard after the swap included
  (`GuardNotInstalled`).
- Using a role through a role-holding Safe's fallback forwarding (the council Safe, a guardian Safe, a
  proposer or veto Safe whose handler is the guard or the timelock), and completing a pending admin
  hand-over through a pending-admin Safe's forwarding (the acceptance is not a role entry and carries
  the same refusal, review G9a-3 / G9c-3, applied after round 13).
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
  included, forever), so the admin removes a compromised council after the timelock delay. With an
  allowlisted module on a v1.5.0 Safe the owner rotation needs no signer either: a module-bound
  approval of the Safe's own `swapOwner` executes through the module (review G17a-2). Until then
  it can freeze the Safe, re-open windows, strip guardians and stall an admin hand-over (a window, an
  `enforce` or a planted guardian on the pending admin refuses the acceptance until the eviction batch
  of §4 lands): guardians are a control against a
  mistaken council, not a malicious one. Pick its signers accordingly. Its removal batch is
  `[revokeRole(old), grantRole(new), lockdownAndRevoke(safe)]` per Safe and never a lift: what a
  council did in its last hour (a 7-day window it opened, 7-day approvals, a guardian it planted)
  outlives the role, and the new council, which the cooldown does not hold back, clears it at once.
  What it NARROWED in that hour (`revokeTarget`, `revokeFunction`, `clearAllowedValues`, an unwrapper
  it de-registered) outlives the role too and the new council cannot restore it: only the timelock
  widens those (a forbidden canonical hash is the one narrowing the new council undoes itself,
  `setUnwrapperCodehash(h, true)`, §7.7), so chain the full re-assertion of the policy file behind the
  rotation (§7.5) or settlement stays frozen for one more `minDelay` after the lift (review G10c-3).
- **A governance Safe can deadlock itself.** The account the hooks exempt is the admin, in production
  the timelock, which is not a Safe (v1's "the owner Safe cannot deadlock itself" rested on that
  exemption and does not carry over). A proposer, veto or council Safe that executes `setGuard(guard)`
  on itself is an unconfigured, `Lockdown` Safe from that block: it can neither schedule, cancel nor
  act, and `setGuard(0)` is an admin approval only a proposer can schedule. The contracts do not
  refuse the install (it is that Safe's own transaction, before any hook runs); the sync task refuses
  a `policy.safe` that holds a timelock or council role, the deploy script wants two proposers, and
  §7.6 step 5 is the recovery: a second proposer schedules the approval of `setGuard(0)` (one
  `minDelay`), or a council window on the stuck Safe lets it schedule its own. With a sole proposer
  and no council it is permanent; custody stays guarded and settlement continues
  (`G9c_ProposerRecovery`, V2-46). Price: that Safe's own quorum, by mistake or by a hostile
  majority; `ChangedGuard` on every governance Safe pages (§7.7).
- **The veto Safe is the one trusted veto, and it proposes nothing.** A canceller can cancel its
  own removal. A canceller that could also propose would therefore be, once compromised, an unvetoed
  takeover: it schedules what it likes, nobody can cancel, and after one `minDelay` the council is
  stripped, a hostile council granted, anything widened (reproduced in review, V2-74). A canceller
  that cannot propose is at worst a permanent governance deadlock: no admin operation ever executes
  again, custody stays guarded, settlement continues on the council's lane, and the guard can only
  leave the Safe by a council-approved custody move to a fresh Safe (§7.6). The contract enforces the
  separation (`CancellerCannotPropose` / `ProposerCannotCancel`), the deploy script wants exactly one
  canceller, and a 2-of-3 veto Safe of three distinct governance parties turns even that deadlock
  into a majority decision. A compromised proposer is cancellable and removable, after one `minDelay`
  and provided every operation it schedules is vetoed as it appears; its queue outlives its removal
  (cancel everything it scheduled, review G10c-4). An operation id carries neither its proposer nor
  its delay, so the timelock pins every operation delay to the live `getMinDelay()`: a proposer that
  schedules the honest proposer's exact operation first only places that operation on time, and can
  neither cancel it (a proposer is never a canceller) nor park it later (every schedule is at the live
  minimum). With any longer delay allowed, as before review G10c-1, it could have parked the honest
  operation, and its own removal, up to 30 days out. A compromised proposer's cheapest levers are two:
  `updateDelay` down to the clamp's floor, vetoable like any operation but, if missed, shrinking the
  veto's window on EVERY later operation to that floor, which is why the floor is a day and not an
  hour (`MIN_DELAY_FLOOR = 1 days`, applied after round 13, review G13f-3); and a flood of bare operations that never expire (the timelock caps
  nothing), which the veto clears in one batched cancel and the sync names as a burst above 20
  pending (review G13f-1). The floor now equals the admin delay's floor (`MIN_ADMIN_DELAY`, a day):
  a proposer that lowers both (two vetoable operations; OpenZeppelin applies the shorter admin delay
  only after the difference has passed) makes an UNCHAINED cancel of a hostile hand-over Ready in the
  same second the acceptance opens, where the old floors left the cancel a 23-hour margin; the BARE cancel
  CHAINED behind the hostile begin (§7.5) wins at any admin delay when it is scheduled within the admin
  delay of the hostile `CallScheduled`, chained or not (review G16b-1; a wrapped one is waited out, and a
  re-begin chained behind the cancel needs a cancel of its own, review G16a-1 / G16a-2), and the sync's governance summary
  prints both delays and warns when the admin delay is not strictly above (review G14g-2). The lockdown
  cooldown protects against STALE honest operations, not against a hostile proposer: a widening, a
  role grant or an approval routed through a freshly granted council all execute during the cooldown,
  so the cancel inside `minDelay` is the control, and bots page the veto Safe on EVERY `CallScheduled`
  whose id the operator's own state file and manifest do not hold: an approval, a window, a widening,
  a guardian change or `changeDefaultAdminDelay` scheduled on the guard are as dangerous as a role
  change and carry none of the selectors a selector list would name (review G10c-2), and the
  timelock's self-calls and `grantRole(CANCELLER_ROLE, …)` page in particular (the number of
  cancellers is not enforced on-chain: a rotation needs two for one batch). A guarded veto Safe is a
  veto that cannot be used (`cancel` is a Safe transaction): `ChangedGuard` on it means "the veto is
  gone" until the council opens a window on it (`cancel` is a plain call to a foreign contract and
  passes there at once, review G10c-5) or §7.6 step 5 is run.
- **Admin / council key overlap with the curator.** Today's governance Safe is 3-of-6 and two
  of its owners are curator-Safe owners (three until one left the governance set between
  2026-10-04 and 2026-10-09, review G13b-3), so with it as proposer the shared curator keys are one
  signature short of queueing any widening, opening a `Bypass` or approving anything; one more
  shared key would close that gap. v2 makes any overlap a deployment-time refusal:
  `deploy/ethereum/guards/00_curator_guard.ts` intersects the signer sets of the proposer and the
  council with the curator Safe's (recursively through nested Safes) and aborts on overlap
  (`CURATOR_GUARD_ALLOW_KEY_OVERLAP=1` downgrades it to a warning on forks only). Widenings also sit
  in the timelock for `minDelay`, cancellable by the veto Safe (never the council, never a proposer), and the council can never touch the allowlist
  or the Safe's security configuration, so a compromised fast lane is bounded to 7-day approvals of
  venue calls and owner rotations. A dedicated governance Safe without curator keys must replace
  `curatorGuardProposers` before mainnet (`helpers/address.ts`). The same governance Safe is
  `governor()` of the five `Lagoon_Vetro_*` strategies and upgrades them directly (UUPS,
  `onlyGovernor`, no timelock): an unguarded power over the pool capital that funds the vaults,
  outside this guard's scope and worth the same delay-and-veto discipline (review G13b-4). Priced
  the same way, that lever is the cheaper one: the two shared keys already ARE the curator quorum
  (2-of-4), so one more governance signature marks the NAV with the Safe and, in the same block,
  upgrades the strategy that holds the depositors' claim, with no delay and no veto anywhere, where
  the proposer lane gives the veto `minDelay`. The deploy preflight intersects the signer sets of
  the proposers, the council and the canceller with the curator Safe's and never the governor's, so
  a dedicated proposer Safe satisfies it and leaves that price unchanged: move the strategies'
  `governor()` off the shared keys (or behind a timelock, §8 "Strategy upgrade") together with the
  proposer, not after it (review G15f-3).
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
  were designed and measured in round 8 and are recorded as an open decision in the round-8
  entry of §13.2 (they change how settlement is operated, so they are a decision, not a fix).
- **Settlement is the curator's.** `settleDeposit` ends by settling the pending redeems as well
  (`Vault-v0.6.0.sol:515`): the two settle entries are ONE custody exit, so a responder that wants to
  stop assets leaving the Safe narrows both, or the target, and a monitor keys on the vault's
  `SettleRedeem` event rather than on the selector (review G11b-1). A settlement the signers confirmed and nobody executed is an option anyone
  can exercise: `execTransaction` has no caller check and the confirmations, signature bytes included,
  are public in the Transaction Service, so an outsider lands the signed mark when it has gone stale:
  a deposit requested before a mark that is now low buys `D·(V−M)/(M+D)` out of the strategy, a
  redeem requested before a mark that is now high (a venue loss after signing) leaves whole and moves
  the loss onto the strategy (291 USDC and 300 USDC on a 30,000 USDC stake at 1 %, measured on the
  live vault; review G13e). The band does not bound it (the stale mark is inside it) and the only
  recall is a race to burn the nonce: execute what you sign, put the deadline entry of §5 first in every
  settlement batch, and page on a curator transaction the Transaction Service shows fully confirmed
  and unexecuted for more than an hour, and on a settlement landed by a `tx.from` that is neither an
  owner nor the known relayer. A `settleRedeem` the Safe cannot cover returns without settling and still
  takes the management and performance fees and resets the guardrail clock (status 1,
  `TransactionChecked(Policy)`, no `SettleRedeem`): alert on a settlement batch with no `SettleRedeem`
  while a redeem is pending (review G12c). Two Lagoon-side keys outside the Safe and the guard sit
  on the admitted path as well: the vault's access check (`isAllowed`) reads the external sanctions
  list the whitelist manager sets and Lagoon's fee registry proxy first, so a reverting list or a
  broken registry makes a guard-admitted `claimSharesOnBehalf` / `claimAssetsOnBehalf` (and every
  user redeem and keeper report) revert whole with no guard event, which only the whitelist manager
  or Lagoon can repair (`test/guards/G13b_CrossSystem.t.sol`, review G13b-1). Refusing or delaying settlement
  (or any Vetro freeze) is illiquidity, not loss, for Vesper depositors: pending requests sit in
  Lagoon's silo or as
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
  vault in the incident runbook if that latency matters, while the Safe is still the vault's owner:
  once `owner` sits at Vetro (§8) such an approval is issued but unusable (the vault refuses the
  curator, `OwnableUnauthorizedAccount`, and the approval survives), and the lever is Vetro's own
  signing round (`pause()` measured at 91,503 gas for a 3-of-6 on a fork; review G12c).
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
  and that lifting it is a fast-lane action, not a timelocked one, while a council is seated; the
  admin's lift lands `minDelay` after the proposer Safe scheduled it (the one-day cooldown ends inside
  the delay for any lockdown placed at or before the schedule) and up to `minDelay` plus the cooldown
  after a RE-LOCK placed just before it is Ready ("Queued admin operations and lockdowns" below;
  measured in review G16b-2). The same freeze, from outside: every custody asset's issuer can pause its token or blacklist
  the Safe (USDC, USDT, cbBTC; WBTC pauses; hemiBTC has an owner), and USDC and cbBTC are upgradeable
  under the allowlisted `approve` selector; none of them can pull from the Safe. Frozen custody, never
  moved custody, and nothing in the guard sees it.
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
  `clearAllowedValues` and a re-allow that drops a `OneOf` rule still iterate members (about 12k gas
  each on committed storage, §4; the validator caps a policy at 256 members per function and 1,024 per
  target). `lockdown`, `revokeAllApprovals` and `lockdownAndRevoke` are O(1) and remain the
  incident-response primitives; a per-Safe guardian set is capped at 32.
- **Snapshot scope.** The configuration digest reads the singleton from the proxy itself (and
  requires the proxy's and the singleton's code to be canonical builds) and everything else through
  the Safe's views; it cannot enumerate the `modules`, `owners`, `approvedHashes` and
  `signedMessages` mappings, so a dangling entry planted directly in storage is invisible to it, and
  of the modules list it covers the HEAD (complete while the list is empty, which `ModuleNotHooked`
  enforces on v1.3.0 / v1.4.1; behind the head of a hooked v1.5.0 list only refused self-calls can
  insert, and only an approved module-path `disableModule` can remove, unseen by the outer digest
  when a venue drives it inside a policy transaction: a narrowing, review G12b-2). The only code that
  can run in the Safe's context without an approval is a
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
  guardian key can extend the pause by re-locking (ONE lockdown in a chained lift's last day, from
  `deadline - 1 day` on with that second included, is enough: the cooldown then outlives the lift's
  deadline; one second earlier the lift still lands in the deadline's own second), until the key is removed: the council does
  that at once in one batch with the lift (`[setGuardian(safe, key, false), enforce(safe)]`, about 80k
  gas through a 2-of-2 Safe) and is never held back; without a council the bound is `minDelay` plus
  a day and one more block (the cooldown's edge is inclusive: a re-lock in the removal's own second
  holds the lift through `lockedAt + 1 day`; at the one-day floor even a single lockdown holds a lift
  scheduled in its block for the lift's own Ready second, so the admin's lift there is a day and a
  second, review G16f-1), and a lift is only safe to queue together with the removal of every key
  that could re-lock, ahead of it in the same cycle. That bound holds only once EVERY re-locking key is gone:
  `GUARDIAN_ROLE` is deployment-wide, uncapped (per-Safe guardians stop at 32) and not enumerable on
  chain, so list it from the guard's `RoleGranted` / `RoleRevoked` logs since its creation block (the
  governance summary does, and refuses an incomplete stream), remove every member in one
  `scheduleBatch` chained ahead of the lift, and page on a burst of `setDeploymentGuardian(…, true)`:
  one key missed to a dropped log re-locks and the cycle restarts (`test/guards/G13f_Liveness.t.sol`,
  review G13f-2). Removing the locker does not end the cooldown it started.
- **Vault code.** The five vault proxies are upgradeable by their `DelayProxyAdmin` (owner: the
  curator Safe; one-day delay; target gated by Lagoon's registry, which today already whitelists a
  v0.5.0 build without guardrails; the registry is itself a `TransparentUpgradeableProxy` under
  Lagoon's own admin, so the gate is whatever Lagoon's keys make it: Lagoon can widen what the Safe
  may upgrade to, never push an upgrade, review g10d). A submission
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
  `ChangedFallbackHandler` on a council, proposer, veto or guardian Safe pages (§7.7). A plain ETH
  transfer to the guard reverts (no `receive`, no `fallback`); ERC-20 tokens sent to it, and ETH forced
  in by `selfdestruct` or as a block reward, are stuck for good (no rescue function, by design) and
  nothing in the guard reads a balance. The timelock, by contrast, accepts ETH and ERC-721 / ERC-1155
  safe transfers from anyone (OpenZeppelin `receive()`, `ERC721Holder`, `ERC1155Holder`); only a
  scheduled operation moves them out.
- **Another chain.** The guard is deployed on Ethereum only (`helpers/address.ts` knows chain 1 and reads
  chain 31337 as Ethereum, so an anvil fork of an L2 at the default chain id would rehearse against the
  Ethereum book; the policy pins `chainId` 1). Measured on 2026-10-09 on Base, Optimism, Hemi and Arbitrum
  (review G13c-3): EIP-1153 is live on all four (an `eth_call` with a transient-storage probe answers), and
  the canonical v1.3.0 / v1.4.1 / v1.5.0 `Safe`, `SafeL2`, proxy factories and `MultiSendCallOnly` sit at
  the mainnet addresses with exactly the hashes this guard pins, so the constructor's probe and every pin
  would hold as is. What changes is the clock the second-exact windows, approvals, cooldown and
  `executeBefore` deadlines read: OP-stack chains (Base, Optimism; Hemi at 12 s) stamp every block
  `parent + block time` whatever the wall clock, so after a sequencer outage the catch-up blocks carry
  past timestamps and a one-hour window can close in minutes of real time; Arbitrum's sequencer sets
  timestamps within 24 h behind and 1 h ahead of its clock and may repeat one; none has a public mempool,
  so a `lockdown` cannot be front-run but can be held by the sequencer up to the forced-inclusion window.
  Before any L2 deployment: an address-book entry for the chain, `policy.chainId` set to it, a rehearsal
  with `anvil --chain-id <that id>`, and the windows re-sized to that chain's clock.
- **Safe builds.** The supported set is fixed at deployment: the proxies the v1.3.0 / v1.4.1 /
  v1.5.0 factories create and the L1 and L2 singletons of those releases. A Safe created by the
  v1.1.1 factory, a non-canonical build and every future release are refused on the policy path
  (approvals and windows keep working) until a guard that knows them takes over. A singleton
  MIGRATION under the guard is the one irreversible trap left: an approved `migrateSingleton()` to a
  release whose guard-hook ABI differs would leave every later transaction reverting inside the
  pre-hook call, the exits included. The migration is therefore approved only as ONE batch that ends
  with `setGuard(guard)` (and `setModuleGuard(guard)`): the re-install runs on the NEW singleton,
  which asks its own ERC-165 question, so an incompatible release reverts the whole batch and the
  Safe stays where it was (§7.5). The guard deliberately has no non-reverting `fallback()` (Safe's
  example guards keep one so that a later release calling a new selector cannot lock the account).
  The brick needs a release that keeps the hook interface id yet calls a new hook, which the recipe's
  re-install cannot see (a same-id release answers the ERC-165 question with yes) and only the
  pinned-release rule above excludes. A fallback would not save a release that still calls the old
  post-hook (`MissingSnapshot` outside a window), and against one that renames both hooks it trades
  the brick for a Safe that is alive and unguarded: the fail-open the June 2026 Gnosis Pay incident
  warns against (review G11f; measured at -6 bytes, the dispatcher's unknown-selector revert becoming
  a stop; not applied).
- **Seats with code.** The Safe counts an owner's signature whether a key, a stored `approveHash` or
  the owner's code produced it, and an owner can acquire code after it was vetted (an EIP-7702
  delegation, a counterfactual address). Under EIP-7702 that code is the 23-byte delegation designator,
  and a delegate that answers EIP-1271 for anything (a phished authorisation, a session-key account)
  hands that seat's CONTRACT signature to anyone: the quorum is then one key short of its threshold on
  v1.4.1 and v1.5.0 alike, the owner list and the digest do not move, and the payload stays bounded by
  the policy (review G11f). The council lane refuses a new owner that has code when the
  approval is issued or executed; nothing on-chain enforces "a threshold of KEYS" afterwards (a
  per-Safe key-signatures-only flag was costed at about 430 bytes and is recorded in the
  round-8 entry of §13.2): the §7.7 "owner acquired code" alert is the control, and payloads stay bounded
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

Commit the two records hardhat-deploy writes, `deployments/ethereum/CuratorGuardTimelock.json` and
`deployments/ethereum/CuratorGuard.json` (they are not ignored; `localhost` and `hardhat` records are): a re-run is
idempotent through them alone (`skipIfAlreadyDeployed` reads the record, never the chain), so a clone without them
deploys a second timelock and guard, a lost guard record re-points `CuratorGuard` to a fresh, uninstalled guard, and a
lost timelock record is read as the recorded guard's admin instead of deploying an orphan (review G20g-2). The
replacement recipe of §7.5 names the timelock explicitly (`CURATOR_GUARD_TIMELOCK`).

Deploys two contracts: `CuratorGuardTimelock` (proposers = `Vetro.curatorGuardProposers`, two
Safes; canceller = `Vetro.curatorGuardCancellers`, exactly one Safe, the trusted veto; executor =
anyone; no deployer admin: the role set is final at creation, nothing to renounce; never the council,
which the script refuses in either list; `minDelay` = `CURATOR_GUARD_TIMELOCK_DELAY`, 48 h by
default, within the contract's [1 d, 30 d]) and `CuratorGuard` with the timelock as admin
(admin-transfer delay `CURATOR_GUARD_ADMIN_DELAY`, 3 days by default, must sit at least a day above
the timelock delay, review G16b-3) and `Vetro.curatorGuardCouncil` as council. Every topology, principal, overlap and delay check
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
under one day for a fresh timelock (no override: the contract refuses it since the round-13 follow-up, G13f-3;
the usual symptom of hours typed as seconds; a testnet guard needs the same one-day timelock, since the floor
is the contract's: rehearsals warp the chain instead, review G16g-3) or above 30 days, and a reused timelock whose live delay differs from the configured
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

A proposer, veto or council Safe created in Safe{Wallet} after 22 September 2026 runs Safe v1.5.0 by
default. The guard and the timelock serve it (the proxy and singleton hashes are pinned, the
forwarded-call probe reads `getStorageAt`), but the Transaction Service proposal path of the sync task
(`helpers/safe.ts`, `@safe-global/protocol-kit` 6.1.2) refuses it before anything is signed: protocol-kit
knows the releases up to v1.4.1 and throws `Invalid Safe version` for any other. Upgrade protocol-kit to
a release that lists v1.5.0 before creating a v1.5.0 proposer Safe, or propose from Safe{Wallet}'s
Transaction Builder (review G11f).

### 7.2 Configure the policy BEFORE the Safe installs the guard

```bash
# 0. pin the deployed guard in the file first (the deploy script prints the line, a top-level "guard" key
#    next to "safe"; the lint and the task refuse a pin that differs from --guard); outside rehearsals
#    the task refuses an unpinned file. Run every command from the repository root: the state, batch
#    and manifest files are written to the current directory.
# 1. on today's chain EVERY run below is refused with "updateNewTotalAssets(uint256) on <vault> is
#    unconstrained while the vault reports totalAssets() = …, with no Vesper debt behind it (…)" (the five NAV
#    entries are `unconstrained` and two vaults hold dust, V2-81; the same gate refuses an unconstrained entry on
#    an EMPTY vault behind which a recorded Lagoon_Vetro_* strategy carries a debtRatio, a totalDebt or a tvl(),
#    reviews G11b-6 and G13g-2, so the flag is about the dust only while every strategy's figures read 0): put a
#    NAV band on the funded entries first (§5, §8), or add
#    --allow-unconstrained-nav to each command below, knowingly (review G11a-2). The same gate refuses
#    a band's FIRST sync when the vault's live totalAssets() sits outside it or the band is wider than
#    +-50 % of it (a band on paper, review G13a-1); a band already on chain moves under the loosening
#    gate (the loosening gate below: anchored and no wider is a shift). A band or a fixed mark on a vault that holds
#    nothing is refused until its first settlement (keep it unconstrained there; --allow-unconstrained-nav admits it
#    too, as a WARNING, and today's dust vaults make that flag habitual: read the warning, review G18d), a fixed EqualTo / OneOf
#    mark is judged by its lowest and highest member on every sync (review G16c-2), and a
#    settlement-deadline entry whose target is not the repository's SettlementDeadline build is refused
#    (review G16c-1).
npx hardhat curator-guard-sync --network ethereum --guard <CuratorGuard> \
  --policy policies/curator-guard/vetro-lagoon.ethereum.json --dry-run    # the diff, the queue, the simulation, the ids (on a fork add --via-timelock, or the dry run shows the impersonated admin's direct calls and no ids)
npx hardhat curator-guard-sync --network ethereum --guard <CuratorGuard> \
  --policy policies/curator-guard/vetro-lagoon.ethereum.json \
  --proposer <governance Safe>        # ONE scheduleBatch on the timelock, proposed to the governance Safe
# … the Safe signs and executes the proposal, then after minDelay (anyone):
npx hardhat curator-guard-sync --network ethereum --guard <CuratorGuard> \
  --policy policies/curator-guard/vetro-lagoon.ethereum.json --execute
npx hardhat curator-guard-sync --network ethereum --guard <CuratorGuard> \
  --policy policies/curator-guard/vetro-lagoon.ethereum.json --dry-run    # expect "already in sync" and an empty queue
```

On a fork (a dev node declared with `CURATOR_GUARD_FORK=1`, or chain 31337) the `--proposer` command
above applies the diff at once as the impersonated timelock and schedules nothing: pass `--via-timelock`
to rehearse schedule → execute as the fork dry-run script of §7.5 does (review G11a-3).

No review round executed the Transaction Service proposal itself (`helpers/safe.ts`) or the deploy script's
Etherscan verification: every rehearsal flushed the batch by impersonation on a fork, as the review's rules
allowed no key. The first real `--proposer` run is therefore the first execution of that path: rehearse it
once with a throwaway Safe and an API key before the first mainnet proposal (review G18g-5).

A fresh guard needs no flag. Six flags gate the dangerous cases and must never become a habit:
`--allow-unconstrained-nav` (step 1 above), `--allow-pending` and `--allow-large-batch` (both below), and
three on the diff itself: `--allow-unlock` when an already configured Safe is in `Lockdown` / `Bypass` (an incident
state), `--confirm-revocations` when the diff narrows anything (a deleted line is a revocation), and
`--confirm-loosening` when an already allowed function loses a rule, widens a bound or gains
`allowValue` (the task prints the old and the new rules side by side and names the loosening; a NAV
band moved to follow the settled NAV, the re-sync of §5, is printed as "shifted" and needs no flag
when it moves in one direction, keeps its relative width (the file's edges are integers, so two raw
units of width are forgiven besides one part in a million: an exit to a dust NAV is a shift too, review G15a-2) and contains the vault's live
`totalAssets()`; a widened band, a dropped bound or a band moved away from the live NAV is a
loosening like any other, review G12c). A first band is judged by the gate again at `--execute`, against the NAV of
that moment: a flow settled on the vault during the delay moves the NAV out of the queued band, the execute is refused
("does not contain") and `--allow-unconstrained-nav` then lands a band the honest mark no longer fits, one more
timelock round (measured, review G16c): settle nothing on a vault between the schedule and the execution of its
first band, or cancel and sync again. A
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
EIP-7825 at 16,777,216 gas; measured: the shipped policy's initial sync is 4.4 M as one batch of 40
wrapped calls (4,393,513 on a fork of block 26,163,301, review G15a); one transaction holds about 179 rule-less
wrapped `allowFunction` entries or about 77 two-rule band entries and the gate refuses the 127th / 55th, the wrapper's
probe being 1 % of a batch at the cap (an Osaka anvil's own estimate, review G16e); a target filled to 32 selectors x 16 rules is 25.7 M in one `allowFunctions` and must be
split over syncs, review G11c-1). The cap is the chain's, not the rehearsal's: a mainnet node (reth 2.7.0, measured
2026-10-09) refuses `eth_estimateGas` above it ("gas required exceeds: 16777216") while `eth_call` still runs a
30 M call to completion; hardhat's in-process network (2.28.6, `osaka` by default) refuses to mine a transaction
above it; anvil 1.5.1 mines a 22 M transaction on every hardfork it offers (`osaka` included) and estimates it at
22 M, and forge's test EVM executes it too, so a batch an anvil rehearsal executed, or `--allow-large-batch`,
proves nothing about the cap: the 12 M gate is the control, and a batch scheduled above the cap is signed,
waits the delay and reverts for every executor (review G13c-1). The operation ids, salts, predecessors and deadlines are persisted next to the Safe batch
file (`--execute` re-derives every id from the stored payloads, so a tampered file cannot name an
operation the chain does not hold; `--execute --op <id>` rebuilds an operation from the timelock's
own `CallScheduled` / `CallSalt` logs instead, for a second operator or a lost file, `schedule()`-made
one-call operations included; an operation that carries calls no sync produces, the hand-scheduled
approvals of §7.5 and §7.6, a role change, a window, runs exactly as named and only behind
`--confirm-sensitive`, after every such call is printed with its tag and the cancel calldata, while
its sync calls still keep the drift check; unwrapped calls and timelock self-calls it never executes;
reached without `--op`, such an operation is named a one-off and pointed at that route or at the
timelock's own `execute` / `executeBatch`, with the cancel calldata as the third option, never
advised as if it were a drifted sync (review G9e-1, G15a-3, G19c-4); it never
touches the state file, and needs `--allow-unlock` for any lift (an `enforce` of a configured Safe,
or a `bypass`) since the preparation time is unknown there); `--execute`
refuses past the deadline, skips (loudly, with the cancel calldata) an operation that contains a
call the current diff no longer wants (one call per function, so a fast-lane change to one function
never invalidates the rest; the skipped operation stays executable by anyone, so cancel it), and an
identical diff scheduled again gets a fresh id. The state file keeps every operation still in
flight and goes only when all of them are done. Every send waits for ONE confirmation (`tx.wait()`), and the
state file is written or removed on that one block, so a reorg can disagree with it; the chain, never the
file, decides (measured on a fork with the real task, review G13c-2): a `scheduleBatch` the chain dropped
leaves the file naming an operation the timelock does not hold: `--execute` skips it as "not scheduled
on-chain" and a plain run prepares a fresh operation (the deadline is recomputed from the chain's clock, so
the id differs; the stale entry is dropped); the Safe transaction re-mined a block later moves the Ready
time by that block and leaves the deadline, fixed at preparation, where it was, and `--execute` waits for
the chain's Ready, not the file's. An `executeBatch` the chain dropped AFTER the task removed the file and
the manifest (every operation read as done on the reorged block) leaves the policy unapplied and the
operation Ready with no file: the plain run lists it with its id and decoded calls, and
`--execute --op <id>` lands it from the logs (`--allow-unlock` as well whenever the batch lifts a lockdown
or a Bypass of a CONFIGURED Safe, as every post-incident sync does; the first sync's `enforce` is the go-live
enable of a fresh Safe and needs no flag, review G14f-5). Mainnet timestamps are slot-aligned (12 s; one missed
slot in 600 measured), so a deadline or expiry second is hit by a block with probability 1/12 and a
one-block reorg moves a receipt by one slot. Rehearse reorgs with `evm_snapshot` / `evm_revert`: anvil
1.5.1's `anvil_reorg` drops the transactions and rewinds balances but leaves the storage of locally
deployed contracts (the timelock's queue, the guard's policy) as the dropped block wrote it (measured).
`OneOf` growth (a new spender, a new vault) is a
plain widening printed as `+ values`, not a loosening. The state file is keyed by chain and guard,
and a signer manifest (decoded calls, the exact `scheduleBatch` calldata and its hash, every
`hashOperationBatch` input, deadlines as dates) is written next to it on every path, rehearsals
included, for the proposer Safe's signers. The manifest, the Safe{Wallet} page and the Transaction
Service proposal all come from the operator's machine, so a signer trusts none of them: before
signing, each signer runs `curator-guard-verify --guard <guard> --policy <file> --manifest <manifest>
[--proposer <Safe>] [--nonce <n>]` on their own clone of the committed file and their own RPC. It
rebuilds everything from the manifest's `scheduleBatch` calldata alone: the operation ids, every
decoded call against the diff the committed file produces right now, the delay against the live
`getMinDelay()`, and the EIP-712 domain hash, message hash and `safeTxHash` of the proposal as
protocol-kit builds it (one operation: a plain call to the timelock; two or more: one
`MultiSendCallOnly` delegatecall), cross-checked with the Safe's own `getTransactionHash`. Sign only
the proposal whose `safeTxHash` is the printed one (Safe{Wallet} shows it in the transaction details;
a hardware wallet shows the domain and message hashes): a proposal with another hash is not the
manifest's transaction, whatever the page decodes (the Bybit shape; review G12a-2). A `--dry-run`
walks the same path (queue, simulation,
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
handler removal (it syncs a copy of the file pinned to the guard it deploys, so the production pin
of step 0 does not stop it; review G11a-1), or after install.

### 7.3 Pre-install checks and the fallback handler

- **The guard the signers are about to install is the one that was reviewed, behind the right admin.**
  The deploy script's audit (§7.1) and `curator-guard-sync`'s build check run on the operator's machine
  and compare the chain with `helpers/address.ts` on that machine: a tampered address book or operator
  audits itself as "expected". The install signers therefore read, from their own node, before signing
  the batch of §7.4: `keccak256(eth_getCode(guard))` and `keccak256(eth_getCode(guard.defaultAdmin()))`
  with their CBOR tails stripped equal the reviewed build (`test/guards/G12a_BuildPin.t.sol`, 23,249 and
  8,204 bytes); `guard.defaultAdmin()` is the timelock named in this runbook and in the policy file's
  `$comment`, `guard.defaultAdminDelay()` is 3 days and `guard.pendingDefaultAdmin()` empty;
  `timelock.getMinDelay()` is 48 h; `timelock.hasRole(PROPOSER_ROLE, p)` for exactly the proposer Safes
  named here (today `0x6649…AaEA`, to be replaced before mainnet, §1), `hasRole(CANCELLER_ROLE, veto)` for
  the one veto Safe named here and nobody else, `hasRole(EXECUTOR_ROLE, address(0))`,
  `hasRole(DEFAULT_ADMIN_ROLE, timelock)` only; `guard.hasRole(COUNCIL_ROLE, council)` for the council
  named here. The addresses the signers compare with are the ones written in this document and in the
  committed policy file at the reviewed commit, never the operator's printout: a guard behind another
  admin can lock the Safe down for good or approve what its admin chooses (review G12a-3).
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
  With the per-settlement cap of §5 in the policy, reset those five to zero in the install batch
  (`approve(vault, 0)`, allowed by the rule) and let the curator approve one settlement's worth before
  each `settleRedeem`: a hostile vault implementation then takes one cap, not the custody (G10d-1).
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
  approvals, `ForwardedHookCall`, `executeBefore` refuses the forwarded caller as well (review G9a-1,
  applied after round 13), and only a council window carries the repair). Without
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
  only after a timelock delay. Escalate to it only on a CONFIRMED live signer compromise (a §7.7 PAGE
  whose replay decodes a guard selector, which required a valid owner quorum): a keyless stranger can
  flood the reverted-`execTransaction` page with `GS0xx` signature-check reverts (review G13d) to
  simulate that incident, and reacting with `lockdownAndRevoke` self-inflicts the freeze AND voids the
  pre-staged `pause()` and migration approvals the incident may need (plain `lockdown` keeps them);
  prefer `lockdown` and `revokeApproval` of the specific suspect record until the compromise is real. `revokeTarget` / `revokeFunction` for surgical narrowing. Lift with
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
  (pre-staged `pause()` per vault while the Safe is still the vault's owner, §8; a multi-vault emergency is five council approvals and five signing
  rounds, a short council window, or one pre-staged admin batch). `executor` is `0x0` for the
  signers, never the Safe's own address nor the guard (`InvalidTarget`: a non-zero executor names a
  Safe module). Approval ids are epoch-bound: an id printed at scheduling time is
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
  `EnabledModule`, …), never by `ExecutionSuccess` plus
  `TransactionChecked(Approval)` alone: with the handler at zero, a selector the current singleton
  does not implement is a silent success that spends the approval. `ChangedMasterCopy` is NOT a Safe
  event: a canonical migration library emits it (`SafeMigration`, `SafeToL2Migration`,
  `SafeToL2Setup`), and an approved delegatecall into any
  other code can rewrite the singleton slot with no event at all (a pinned build keeps the policy
  path running), so after every approved delegatecall confirm the singleton by reading
  `masterCopy()` / slot 0, not by waiting for the event (round 10, G10e-2).
  `revokeApproval(id)` cancels one unused approval; `revokeAllApprovals(safe)` (admin, council or
  guardian) voids all of them, `lockdownAndRevoke(safe)` does that and freezes the Safe. Approvals are
  refused while the Safe is in `Bypass`.
- **Never on the council lane.** These are venue calls the contract cannot tell from a harmless
  one, and each changes who controls a vault or its code (the lint refuses them in a policy file without
  `"$allowSensitive": true` and `curator-guard-verify` names them in a decoded one-off, review G15a-4). On a vault: `updateSafe`,
  `transferOwnership`, `renounceOwnership`, `updateSuperOperator`, `updateValuationManager`,
  `updateSecurityCouncil`, `updateWhitelistManager`, `updateFeeReceiver`, `updateRates`,
  `switchAccessMode`, `resetHighWaterMark`, and `updateTotalAssetsLifespan` / `setSyncMode` (they open
  Lagoon's synchronous paths, which pay straight out of the Safe at the last settled NAV); the `securityCouncil`'s
  `updateActivated` / `updateGuardrails` and the `whitelistManager`'s `addToWhitelist` / `revokeFromWhitelist` /
  `revokeFromBlacklist` / `setExternalSanctionsList` (the §8 controls themselves, review G17d-1); hemiBTC's
  LayerZero `send` (a cross-chain transfer to a receiver no word rule can bind). On a
  `DelayProxyAdmin`: `submitImplementation`, `upgradeAndCall`, `submitDelay`, `updateDelay`, `transferOwnership`,
  `renounceOwnership`. An approved NAV call is a NAV that Vetro co-signed: one settlement per
  approval pair, issued on the council lane with a one-hour TTL (the hour starts when the council
  issues it) or through the timelock with a TTL of days (the clock starts when anyone executes the
  operation, see above), and the leftover revoked (review G13e).
- **Safe upgrade (v1.4.1 → v1.5.0)**: approve ONE batch, as a delegatecall into the canonical
  `MultiSend` (not `CallOnly`: the migration is a delegatecall entry), in this order:
  `[DELEGATECALL SafeMigration.migrateSingleton(), CALL safe.setGuard(guard), CALL
  safe.setModuleGuard(guard)]`. Never `migrateWithFallbackHandler()` (it reinstalls the canonical
  signature-capable handler; it is also the one-transaction upgrade shape a wallet UI is built around, so
  decode any wallet-built upgrade payload before approving it). The entries are what the veto reviews:
  the approval pins the code of `to` (the `MultiSend` build), never what an entry addresses, and a
  look-alike library at another address satisfies its own pin and writes slot 0 to whatever its deployer
  chose, after which anyone moves the custody with no Safe transaction (review G11f). The migration entry
  must address the canonical `SafeMigration` v1.5.0, `0x6439e7ABD8Bb915A5263094784C5CF561c4172AC`
  (runtime code hash `0x52d7…14ea`; its `SAFE_SINGLETON()` `0xFf51…a44b`, `SAFE_L2_SINGLETON()`
  `0xEdd1…C7e` and `SAFE_FALLBACK_HANDLER()` `0x3EfC…77f4` are the 1.5.0 deployments the guard pins),
  and `to` the canonical `MultiSend` v1.4.1 `0x3886…B526` or v1.5.0 `0x2185…7eB7`; `curator-guard-verify
  --op` prints what an approval authorises one level down (self-call, call, delegatecall, and a canonical
  batch entry by entry with the canonical libraries named). The two re-installs run on the NEW singleton, which asks its own
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
  the policy (a copy of the committed file pinned to that fresh guard, written to a per-run directory under
  the system's temp directory so two rehearsals on one host never share a file name, review G16g-3; the
  task refuses a pin that differs from `--guard` on every network, and the committed file carries the
  production pin from §7.2 step 0 on) through the timelock as the impersonated proposer, refuses an early execute, warps past
  `minDelay`, executes, re-syncs (expects no drift), models the signers' handler removal + install,
  dry-runs representative curator calls (non-zero exit code on an unexpected allow), and ends with
  an incident drill (a stand-in council locks the Safe down, the lift is scheduled as its own chained
  operation, `curator-guard-verify` decodes it from the logs, a re-lock holds it back, it lands after
  the cooldown). The run exits non-zero until its last line prints "incident drill complete": a
  failing upstream read inside a transaction makes hardhat stop silently, so treat anything without
  that line as failed and use an archive RPC. Against a non-archive upstream (a local anvil fork on a
  free public RPC) also set `FORK_BLOCK_NUMBER` to the upstream head; such a fork keeps its upstream
  for about 15 to 20 minutes. That anvil must keep the chain id it forks (no `--chain-id 31337`, the flag the README's
  `--network localhost` recipe needs for the task path): hardhat's EDR holds no hardfork history for chain 31337, so the
  in-process fork of such a node dies in the deploy script's EIP-1153 probe with "No known hardfork for execution on
  historical block", a `chains` entry in `hardhat.config.ts` does not cure it (hardhat 2.28.6, measured), and the error
  reads as a pre-Cancun chain; run the two paths against two anvils or an archive RPC (review G18d). The rehearsal passes only through rehearsal-only downgrades (key
  overlap, a stand-in veto key): it proves the scripted flow, not that the committed address book
  passes the mainnet preflights.
- **After a Safe-batch sync** (the proposer Safe executed `scheduleBatch`), wait `minDelay`, run
  the same command with `--execute` (anyone may execute), then re-run with no flag but the one §7.2 step 1 demands
  on today's chain (`--allow-unconstrained-nav` while a funded entry is unconstrained: the NAV gate refuses the plain
  run before it reads the chain, review G18d) and expect
  "Policy already in sync" AND "no operation pending" (every run prints the timelock's queue,
  whatever the target: a queued role change, window, approval or abandoned batch is executable by
  anyone). A queue line without a tag is sync-shaped, not judged: the queue never compares a call with the diff (`verify --op` says "(NOT in the current diff)" and the execute path refuses it; review G19c-5). A line tagged `[NESTED WRAPPER]` wraps a call in `executeBefore` twice: the guard runs it (the delegatecall keeps the caller) and the innermost call, decoded level by level, is what lands; no sync and no recipe wraps twice, `--execute --op` refuses it, so cancel it (review G19c-2, G19g-1). The task refuses to start while a stale `safe.batch.tmp.json` exists, and refuses to
  schedule while another operation is still pending on the timelock: cancel what is abandoned.
  `--allow-pending` schedules the NEW diff, which re-includes every unapplied call of a pending sync
  operation and supersedes it: execute the new one and cancel the old one; if the old one is executed
  first, the new one is skipped as "no longer wanted" although anyone can still execute it, so cancel
  it. `--execute` runs a stored operation as long as every call in it is still wanted (extra calls
  caused by a fast-lane change during the delay are picked up by the next sync). Before any lift (`enforce`, by the council or by a queued
  operation) collect the lift-time cards: a fully signed, unexecuted Safe transaction is executable
  by anyone the moment the guard allows it and at any later moment of the executor's choosing,
  settlement batches included (§6, review G13e; burn its nonce first, through a council-approved empty
  self-call), and two ready operations for one Safe can be executed by anyone in the harmful order
  (an approval, then a window whose epoch bump voids it), so cancel what is not meant to run.
  Never bundle `lockdownAndRevoke` with an approval or a lift for the same Safe in one operation: the
  lockdown re-arms the cooldown and the batch can never execute.
- **Sync mode / lifespan.** If `totalAssetsLifespan` is ever set above zero (sync deposits), the
  curator needs `expireTotalAssets()` (`0x927b15df`) before re-proposing NAV inside the lifespan:
  add it to the policy at the same time.
- **Committing.** The Safe sources are unstaged git submodules; when committing run
  `git add .gitmodules lib/safe-smart-account lib/safe-smart-account-v1.5.0` so CI checkouts
  (`submodules: recursive`) get them, and `.github/workflows/ci.yml` runs the suites.
- **Replace the guard**: deploy the new guard under a new alias reusing the timelock
  (`CURATOR_GUARD_TIMELOCK=<timelock>`), sync the policy against it (functions, handler requirement,
  per-Safe guardians), re-grant the deployment-wide responders on it (`setDeploymentGuardian(key,
  true)` by the council or the admin: `GUARDIAN_ROLE` lives per guard and is not in the file; review
  G11a-5), check `hasRole(COUNCIL_ROLE, council)` (the deploy script passes the council
  to the constructor; if it is missing, schedule the `grantRole` the script prints), then have the admin approve
  `setGuard(newGuard)` **on the currently installed guard** (approvals live in the guard that will check
  the transaction; one placed on the new guard is a stray to revoke): no task builds that operation,
  so schedule it by hand as a one-call `scheduleBatch([installedGuard], [0],
  [executeBefore(deadline, approveTransaction(safe, 0x0, safe, 0, setGuard(newGuard), Call, ttl))],
  predecessor, salt, minDelay)` from a proposer, or with `schedule(...)` (both decode in
  `curator-guard-verify --op`, which gives a one-off its own verdict, and run with
  `--execute --op <id> --confirm-sensitive`, the flag that says the operation was read and is wanted
  as named (review G9e-1); an operation scheduled by hand with salt 0 rebuilds too). The post-check tolerates the change only on the approved transaction. Safe
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
  guard answers its pre-hook only on the path where the Safe has it installed (`GuardNotInstalled`
  otherwise; the post-hook's window report is the exception of §4 step 3), so a replacement is inert
  until the swap and the old guard from the swap on; still do
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
  unexpired approvals. Then retire the policy file: set its `mode` to `Lockdown` (or delete it). The
  removed guard still holds the Safe's policy, so a sync of the file as it stands reads a configured Safe
  in `Lockdown` and asks for `--allow-unlock`, the lift that would undo the fail-closed state; with
  `mode: Lockdown` it answers "already in sync" (the task warns when the Safe's guard slot is empty,
  review G17f-2).
- **Admin hand-over (timelock → new timelock or DAO executor)**: the current admin schedules
  `beginDefaultAdminTransfer(newAdmin)` (refused for `address(0)`, `AdminCannotBeZero`, and for the
  council or any address that carries a policy, `AdminIsGuarded`); after `defaultAdminDelay` (3 days; between 1 and 30 days
  once changed) the new admin calls `acceptDefaultAdminTransfer` (itself a scheduled operation when
  the new admin is a timelock; the predicate is re-checked at acceptance) within 30 days of the
  schedule (`DeadlinePassed` afterwards: begin again); `cancelDefaultAdminTransfer` aborts a pending
  hand-over. A council can hold the acceptance back for as long as it holds the role (§4): evict it in
  one batch and accept inside the 30 days, or begin again. Roles, policies and live approvals survive the hand-over; the proposers and cancellers of
  the old timelock do not carry over. A successor timelock brings its QUEUE with it: an operation
  scheduled on it before it is the admin matures with no power and becomes executable by anyone in
  the block of the acceptance (an `approveTransaction(setGuard(0))` scheduled months earlier removes
  the guard with no delay anyone could use). Prefer a FRESH `CuratorGuardTimelock` as successor (the deploy
  script has no timelock-only path: `CURATOR_GUARD_ALIAS=CuratorGuard_v2 npx hardhat deploy --network ethereum
  --tags CuratorGuard` deploys an audited `CuratorGuard_v2Timelock` with the configured roles and an empty queue,
  next to an unused `CuratorGuard_v2` that is never installed, 7.6 M gas in all; a timelock deployed by hand is
  audited by hand, review G15a-5). Two tooling limits of a hand-over: `curator-guard-verify --op` and the sync's queue
  print read the guard's CURRENT admin's logs, so the successor's queue (its scheduled acceptance, anything it
  brought) is decoded by hand until the acceptance lands (a monitor keyed on one timelock's `CallScheduled` is blind
  to the successor's queue the same way: watch the successor from the begin, review G18d); and the sync's log scans of the GUARD (council,
  guardians, standing approvals, forbidden hashes, revocations) start at the earliest deployment record of the
  admin or the guard, so a hand-deployed successor without a record needs `--timelock-block <the guard's
  creation block>` on every run, or the governance summary omits every grant and approval older than the
  successor and the council canary refuses the run on mainnet (review G15a-1);
  otherwise read its `CallScheduled` / `Cancelled` / `CallExecuted` logs since creation and have its
  canceller cancel everything pending before the hand-over begins, and again before acceptance. Keep
  `defaultAdminDelay` above the timelock's `minDelay`: raise the guard's admin delay BEFORE raising
  `minDelay` to or above it, or a hand-over that slipped past the veto is accepted before the
  scheduled cancel is ready. Answer a hostile `beginDefaultAdminTransfer` with a
  `cancelDefaultAdminTransfer` CHAINED behind it (`predecessor` = the hostile operation id), scheduled
  within `defaultAdminDelay` of the hostile `CallScheduled`: a cancel is Ready `minDelay` after ITS OWN
  `CallScheduled`, so against an attacker that lands the begin the second it is Ready, a cancel scheduled
  r after the hostile one keeps `defaultAdminDelay` minus r, chained or not (chaining lets it be
  scheduled while the begin is still pending and executed in the block the begin lands; `minDelay`
  cancels out): three days at the deploy defaults, one block at r = `defaultAdminDelay`, the attacker's
  seat one second later; an unchained cancel executed before the begin is a no-op (review G16b-1); a scheduled `changeDefaultAdminDelay(1 day)` is in effect two days after it
  lands and makes exactly that unchained cancel a day late at the 48 h default (review G10c-2). Its
  rollback (`rollbackDefaultAdminDelay`, an admin operation) is a queue round too: scheduled UNCHAINED
  in the block the change lands, it is Ready in the very second the shorter delay takes effect at the
  48 h default (`defaultAdminDelay` minus `MIN_ADMIN_DELAY` is 2 d, equal to `minDelay`; from the next
  second it is a no-op and the one-day delay stays until a `changeDefaultAdminDelay(3 days)` lands and
  waits three more days), and keeps a day only at the one-day floor: chain the rollback behind the
  hostile change (`predecessor` = its id) like the cancel, or veto the change inside its own
  `minDelay` (review G16f-2). With
  both floors at a day since the round-13 follow-up, `updateDelay(1 days)` next to
  `changeDefaultAdminDelay(1 days)` makes the two delays EQUAL, which no contract refuses (the deploy
  script's `adminDelay > minDelay` rule is checked at deployment only): a cancel scheduled when the begin lands then keeps
  the Ready second alone (OpenZeppelin accepts strictly after the schedule): on mainnet one whole block,
  since every constant is a multiple of the 12-second slot and block timestamps are slot-aligned, so the
  edge second is a block of its own unless that slot is missed (about one slot in 500); the next second is
  the builder's order inside one block. Every Ready begin the attacker holds in reserve re-opens the
  window and needs a cancel of its own (a cancel executed while nothing is pending is spent for nothing),
  so the veto's one batched cancel of the attacker's queue, at any time before the attacker lands it, is
  the cheaper answer (review G16b-1); the sync's governance summary warns when the live
  delays are not strictly ordered (review G14c-3). Chain the cancel, and chain it BARE: a hostile begin
  carries no deadline and its proposer chooses when to land it, so a chained cancel wrapped in
  `executeBefore` (the shape of every sync call) is waited out and dies `DeadlinePassed` in the block the
  begin finally lands, after which the honest side is back to the unchained cancel, a day behind the
  acceptance at the defaults and the one-second race at the floors (review G16a-1). Nor leave the pair to
  the attacker's timing: once both are Ready, land the begin and the chained cancel yourself in one
  transaction (two `execute` calls from any account, through a `MultiSendCallOnly` batch or a helper
  contract: the pair reverts as one if the cancel fails), after reading the queue's predecessors, because
  a proposer can chain a RE-BEGIN behind your cancel, which fires in the same block and leaves the
  hand-over pending with nothing behind it: chain a cancel behind the LAST hostile operation within the
  admin delay of seeing it, and evict the proposer; its queue outlives it, so the last rung still needs
  its cancel (review G16a-2).
- **Council / proposer / guardian rotation**: `grantRole` / `revokeRole` of `COUNCIL_ROLE` are
  timelocked admin operations; a council NEVER gets a timelock role (`CANCELLER_ROLE` or
  `PROPOSER_ROLE`: it could veto or schedule its own removal, and the sync task refuses to run while
  it holds one). A council replacement is `[revokeRole(old), grantRole(new), lockdownAndRevoke(safe)]`
  per Safe, never bundled with a lift (§6), and chained behind it with `predecessor`, in the same
  cycle, the full re-assertion of the policy file for that Safe: every `allowFunction` and every
  `addAllowedValues` (a revocation empties the `OneOf` sets), built from the file and not from the
  sync task's diff (which reads the chain at preparation and sees nothing to do before the council
  acts): a function the old council revokes at any time before the batch executes comes back with it,
  and the new council's `enforce` restores settlement at once (review G10c-3). A guard role is never
  granted to `address(0)`, to the
  admin or to an address the admin configured as a Safe (`AddressIsNull` / `AdminIsGuarded`: paste the
  council Safe, not the curator Safe). Proposer and canceller changes and `updateDelay` are
  scheduled self-calls of the timelock: grant the successor first, then revoke; revoking a proposer
  leaves its queue in place, so after removing a compromised one cancel every operation it scheduled,
  not only the ones that paged (review G10c-4) (the contract keeps
  the last proposer and the last canceller, refuses to drop the open executor or its own admin role,
  never grants that admin role to anyone else nor a gated role to itself, clamps `getMinDelay()` to
  [1 d, 30 d] and refuses an `updateDelay` outside that range, an operation delay other than the live
  `getMinDelay()` and calldata for a target without code when they are PROPOSED, so a value typed in the wrong unit or
  an address typed wrong fails at `schedule`, not after the delay, and an EXECUTED `updateDelay`, hostile
  or the governance's own, refuses every proposal signed at the old delay (`DelayOutOfRange` above the
  new one, `TimelockInsufficientDelay` below it): re-run `curator-guard-verify --manifest` right before
  the proposer Safe executes, and budget one signing round per delay change (review G16b-5); a proposer is never granted the
  veto and the veto never the proposer role,
  so a rotation of the veto Safe is `[grantRole(CANCELLER_ROLE, new), revokeRole(CANCELLER_ROLE,
  old)]` in one batch, which the old veto can cancel: its consent is part of the design; a full
  rotation is one batch of the three grants followed by the three revokes). Only the veto Safe can
  clear a pending operation, a dead one included (an always-reverting operation stays Ready for
  ever), and cancelling a predecessor does not cancel its successor: cancel chained operations as a
  pair, or a proposer re-schedules the identical predecessor and the successor fires. Keep
  exactly one canceller; the count is not enforced on-chain, so page on any
  `grantRole(CANCELLER_ROLE, …)`. Deployment-wide guardians:
  `setDeploymentGuardian(key, true | false)` by admin or council (never managed by policy files;
  uncapped and not enumerable on chain: after a hostile swarm, list them from the logs with the
  governance summary and remove them all in the batch that carries the lift, review G13f-2);
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
- **Fork rehearsals** need proposer, veto and council Safes without curator keys, which the address
  book does not have yet: create them on the fork through the canonical `SafeProxyFactory` v1.4.1
  (`createProxyWithNonce(singleton, setup(...), salt)`, 2-of-3 of dev keys, the canonical
  `CompatibilityFallbackHandler`) and write them into your copy of `helpers/address.ts`; the deploy
  script then passes every preflight without an override (the fork drill's EOA stand-ins need
  `CURATOR_GUARD_ALLOW_KEY_OVERLAP=1`, and an EOA council is refused everywhere). The curator Safe's
  own transactions are rehearsed with two of its real owners impersonated (`anvil_impersonateAccount`,
  `approveHash`, then `execTransaction` with `v = 1` signatures), which exercises the real signature path.
- **Fork rehearsals**: a local anvil fork on a free public RPC loses its upstream state window after
  about 15 to 20 minutes (archive reads then fail with HTTP 403; the fork dry run above measures the
  same window); restart the fork right before a rehearsal or use an archive RPC.

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
   proposer's signers execute `setGuard(0)` once it lands. A guarded VETO Safe cancels from inside a
   council window at once (`cancel` is a plain call to a foreign contract), before its own exit is
   even scheduled; the exit follows the recipe above. Without a second proposer and without a
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
is the data word. No guard event names its caller: `ModeUpdated`, `GuardianUpdated`, `FunctionRevoked`,
`ApprovalsRevoked` and `TransactionApproved` read the same whether a guardian bot, the council or the
admin acted, and the receipt tells them apart (the timelock's `CallExecuted` for the admin, a
governance Safe's `ExecutionSuccess` for the council, the veto or a proposer, else `tx.from`), so key
every "who did it" alert on receipts, never on `eth_getLogs` alone (review G12d-2). Log adjacency: on the owner path the report is the log immediately AFTER the
Safe's `ExecutionSuccess` / `ExecutionFailure` of the same hash (which is also where `success`
lives: the report does not carry it); on the module path it is the log immediately BEFORE
`ExecutionFromModuleSuccess` / `ExecutionFromModuleFailure(module)`. On the module path the hash is a payload hash, not unique per execution
(identical module payloads share it, and v1.5.0's `ExecutionFromModuleSuccess` /
`ExecutionFromModuleFailure` carry no hash): join and count module reports by log position inside the
transaction, never by hash. Inside an admin-opened window batch entries and delegatecalled code are not
decoded, so a `Bypass` report seen there is not authoritative; `ModeUpdated` is the signal. A report
from a guard that is not in the Safe's guard slot after the transaction is a window artefact of a
guard the Safe does not have installed (§4 step 3), unless that same transaction carries
`ChangedGuard` / `ChangedModuleGuard`: an approved swap or removal moves the slot inside the
transaction and the cached guard still reports it, legitimately (review G12d-4). Alert
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
`RequiredFallbackHandlerUpdated` (emitted on every call, a repeated identical requirement included),
`TransactionApproved` (carries the full calldata, the absolute
expiry and the epoch), `ApprovalConsumed`, `ApprovalRevoked` (it may name a record that was already
void or expired: the live set is what `approvalExpiry` reports), `ApprovalsRevoked` (also emitted by
every `bypass` and by `lockdownAndRevoke`), `MultiSendUnwrapperUpdated` and `ModuleUpdated` (emitted
only when the set changed), `UnwrapperCodehashUpdated` (only ever for one of the three seeded hashes, and on every call, a repeated state included;
on `false` the response is ONE council batch `[setUnwrapperCodehash(h, true),
setDeploymentGuardian(key, false)]`, and a pending registration needs no rescheduling after it),
`GuardianUpdated` (per Safe), `RoleGranted` / `RoleRevoked` (council and deployment-wide guardians, and
the admin role itself at a hand-over's acceptance),
`DefaultAdminTransferScheduled` / `DefaultAdminTransferCanceled` / `DefaultAdminDelayChangeScheduled`
(compare its `newDelay` with the timelock's `getMinDelay()` the moment it is scheduled, not when it
takes effect at `effectSchedule`: the sync's governance summary reads the live `defaultAdminDelay()`
and warns only once the change is in force, review G14c-3 and G15g) /
`DefaultAdminDelayChangeCanceled` (page on it whenever the two delays are not strictly ordered: the cancelled change
was the raise that would have restored the order, and the one-knob rollback of §7.5 lands as exactly this event,
reviews G16f-2 and G18d) / `RoleAdminChanged`, on the timelock `CallScheduled` / `CallSalt` /
`CallExecuted` / `Cancelled` / `MinDelayChange` (page on every one: the veto's window on every later
operation just moved; since the round-13 follow-up a scheduled `updateDelay` outside [1 d, 30 d] is
refused when proposed, so after construction the argument it reports IS the effective `getMinDelay()`,
review G13f-3) / `RoleGranted` (a new proposer or canceller; page the
canceller on EVERY `CallScheduled` (the operator's own view may mark the ids of its state file or
manifest as expected, but both live on the operator's machine, where a compromised operator writes the hostile id: the canceller's
monitor decodes every `CallScheduled` itself, `curator-guard-verify --op`, on its own machine and RPC,
and never reads those files as a filter; review G12a-2), page it as well on a BURST of
`CallScheduled` from one proposer in a short window, known ids or not (a flood of operations that
never expire is itself the incident; the veto clears it in one MultiSend; the sync task names a queue
above 20 pending as a burst and prints at most 50, so a monitor should page at a handful an hour
from one proposer rather than wait for twenty, review G13f-1), and
name the timelock's self-calls, foreign targets, `grantRole` / `revokeRole` / `updateDelay` /
`beginDefaultAdminTransfer` / `cancelDefaultAdminTransfer` / `changeDefaultAdminDelay` / `rollbackDefaultAdminDelay` /
`approveTransaction` / `bypass` / `setRequiredFallbackHandler` / `setModuleAllowed` and every widening as the loudest
(a `cancelDefaultAdminTransfer` wrapped in `executeBefore` is the shape §7.5 forbids, waited out past its deadline,
review G16a-1; a grant, a guardian seat or a hand-over for the guard's OWN address is a dead seat, review G16g-4; an
`approveTransaction` whose target is the zero address is an approved burn of the value, review G17a-3; and the
wrapper's `uint64` deadline is printed raw when no date type holds it, never dropped with the page or the wrapper,
review G17b-1: all four measured in review G18d; and `executeBefore` is unwrapped to a FIXED POINT before any of these names is looked for: a wrapper inside a wrapper hid a 180-day admin window from a one-level decoder as `executeBefore(<deadline>, 0x3280d2ee…)` until `ModeUpdated` opened it, review G19g-1 and G20d): an approval of
the curator Safe's own `setGuard(0)` or a 180-day admin window scheduled on the guard carries none of
the selectors an earlier list named, lands for anyone after `minDelay`, and is exactly what a
compromised proposer schedules (`curator-guard-verify --op` decodes such an operation and tags it
`[ROLE / INCIDENT-SENSITIVE]`; reviews G10c-2 and G10e-3); queued role grants and widenings are not
held back by the cooldown, so after a lockdown review and cancel them too, and after removing a
proposer cancel its whole queue), on the
Safe `ChangedFallbackHandler` (also on every council, proposer, veto and guardian Safe, and on a
pending admin from the block `DefaultAdminTransferScheduled` names it: a handler
that is the guard or the timelock would make that Safe's role public, §6, and on the pending admin it
turns the acceptance into a stranger's call the guard refuses `Unauthorized`, review G9a-3 and G15g),
`RoleRevoked` (a proposer or the veto losing its role), on the
Safe `ChangedGuard` and `ChangedModuleGuard` (on the curator Safe, and on every proposer, veto and
council Safe: a guarded proposer cannot schedule anything and a guarded veto cannot cancel, §7.6
step 5; after a v1.5.0 swap both must name the new guard), `ChangedMasterCopy`, `EnabledModule`
(on a v1.3.0 / v1.4.1 Safe an enabled module is
unguarded, whatever approved it), `AddedOwner`/`RemovedOwner`, `ChangedThreshold`,
`ExecutionSuccess`/`ExecutionFailure`, and on each vault's
`DelayProxyAdmin` the upgrade submission event plus the protocol registry's (`0x6dA4…27C`, §1: also the fee registry) `addLogic` /
`removeLogic` and ownership changes (a
registry without an owner accepts any implementation). On the Safe also `SignMsg` and `ApproveHash`
(permanent, dormant authorisations, §6) and any owner acquiring code (no event anywhere: poll
`eth_getCode` for every owner of the curator and governance Safes, or scan each block's EIP-7702
transactions for an owner as the authority, review G12d-5), and poll the guard, handler and singleton slots of the curator Safe AND of every role Safe as RAW 32-byte words (a delegatecall plants any of them with no event, the Safe forwards to the low 160 bits of a dirty handler word and the rails read the same bits, so `0x…dead‖guard` on a council Safe hands its calls to the masked rail and `0x…dead‖0x0` on the curator Safe passes as a zero handler; a monitor that compares only the low 160 bits of the curator Safe saw neither, review G16d-1 and G20d). On a v1.3.0 Safe the
configuration events carry their address in `data`, not in a topic (same signature hash): decode from
`data` when `topics.length == 1`. On each vault:
`NewTotalAssetsUpdated` without `TotalAssetsUpdated` in the same transaction (an epoch closed and left
unsettled; `TotalAssetsExpirationUpdated` and `HighWaterMarkUpdated` accompany every mark and
settlement: index them with the settlement flow, not as role changes, review G12d-3), `RatesUpdated`, `SafeUpdated`, `ValuationManagerUpdated`, `SecurityCouncilUpdated`,
`SuperOperatorUpdated`, `WhitelistManagerUpdated`, `FeeReceiverUpdated`, `OwnershipTransferStarted` /
`OwnershipTransferred`, `GuardrailsUpdated` / `GuardrailsStatusUpdated`, `AccessModeUpdated`,
`TotalAssetsLifespanUpdated`, `SyncModeUpdated`, `Paused` / `Unpaused`, `StateUpdated`; each must sit
in a transaction that also carries the guard's `TransactionChecked` for the curator Safe, otherwise a
role has left the Safe: `lockdown` and page. Key every alert on receipts, never on simulations
(`simulateAndRevert` lets anyone run the hooks as the Safe in a frame that always reverts: the hooks' transient
writes and the forged `TransactionChecked` die with the frame, measured, review G13c), and re-read a block
whose parent hash moved (a one-block reorg re-mines the same receipt under another block hash, or drops it:
an alert raised on the dropped block is stale, one keyed on the re-mined receipt is a block late). A refused
transaction leaves no guard event, but the signers' attempt does leave a receipt: page on every
reverted `execTransaction` to the curator Safe (status 0; the error selector is in the revert
data of a replay, `eth_call` at that block or a trace, since a receipt carries none); a quorum trying
what the policy refuses is the earliest sign of a compromised signer, and the
guard's events alone never show it. CLASSIFY that revert: the guard is called only AFTER
`checkNSignatures` passes, so a replay that decodes a GUARD selector (`FunctionNotAllowed`,
`ParamRuleViolated`, `SelfCallNotAllowed`, `SafeLockedDown`, …) had a valid owner quorum and is the
compromised-signer PAGE; a replay that decodes a Safe signature-check revert (`GS020` / `GS021` /
`GS022` / `GS025` / `GS026`, raised before the guard runs) needed NO key and is a stranger or a
mis-signed attempt, which anyone can send to the Safe at about 39k gas each to flood this exact rule
(measured, review G13d): rate-limit or WARN those by `tx.from` / reason so a real guard-selector PAGE
is not buried, and never read a `GS0xx` page as a live signer compromise. The guard-selector rule
holds for an `execTransaction` (selector `0x6a761202`) only: a status-0 call to the Safe with any
OTHER calldata never reached `checkNSignatures`, it is a stranger's call through the Safe's fallback
handler, and since the round-13 follow-up the guard refuses it with the same `Unauthorized` (a hook
wrapped in `executeBefore`, review G9a-1) or with `ForwardedHookCall`: no key is implied, it is the
WARN that says the Safe's handler slot holds the guard (§7.8), and a monitor that keys on "guard
selector" alone pages a compromised signer on a keyless stranger (measured, review G15g). A `GS013` is
the guard PASSING (a valid quorum) and the inner call refusing: replay the inner call from the Safe to
name it (`SettlementExpired` from the deadline helper of §5, Lagoon's `WrongNewTotalAssets`) and page
it only when `tx.from` is neither an owner nor the known relayer (§6, review G13e). On a PROPOSER
Safe a `GS013` whose inner call is the timelock's `DelayOutOfRange` or `TargetHasNoCode` is a proposer
probing what the proposal-time rails refuse (a sub-day `updateDelay`, review G13f-3): it leaves no
`CallScheduled` to page on, so page the veto on the receipt (the refusal itself is the signal). Lists rebuilt from `eth_getLogs` (the governance summary's
council, guardians and standing approvals, the timelock's queue) are only as complete as the
provider's answers: a provider that silently truncates or drops logs makes them optimistic, so use an
archive RPC that answers completely and treat "council: none" or "no operation pending" from a public
endpoint as unproven (the task's canaries refuse an incomplete stream, round 10 G10e-1). Send
guardian and council incident transactions through a private relay: a `lockdown` in the public
mempool is visible to the signers it is aimed at. After any lockdown, cancel the queued lifts,
windows and approvals that should not survive it within the one-day cooldown. Alert on any widening and on any
`Bypass`. A guardian bot that calls `lockdown` (or `lockdownAndRevoke` when standing approvals are
part of the threat) on an unexpected widening of `approve` spenders or on a Safe owner-set change is
cheap and effective. Correlate
`ApprovalConsumed` with the Safe's `ExecutionSuccess` before treating a one-off as done. During a
Bypass window also watch `AddedOwner` / `RemovedOwner` / `ChangedThreshold`: owner rotation is
unchecked there by design. On the custody assets themselves index `Transfer(from = safe, …)` and
`Approval(owner = safe, …)` (review G12d-1): custody leaves the Safe honestly in exactly one shape, a
`Transfer` to a vault inside a transaction that carries both that vault's `SettleRedeem` and the
guard's report. A `Transfer` out of the Safe with no report beside it is an EIP-1271 / EIP-3009 pull
through a signature-capable handler, a module on a v1.3.0 / v1.4.1 Safe, or a venue drawing on its
allowance; one WITH the report but without `SettleRedeem` is a venue implementation pulling through
the allowance (reported `Policy`, the whole allowance in one allowlisted call, review G10d-1); and an
`Approval` to a spender that is not a vault, or one with no report beside it, is a window, a stray
approval or the permit path. `lockdown` and page on each; none of them is visible in the guard's or
the vaults' events. On the Safe's own `ApproveHash` book and in the Transaction Service: page on a
curator transaction fully confirmed (a quorum of owners' approvals, on chain or in the Service) and
unexecuted for more than an hour, and on a settlement (`SettleDeposit` / `SettleRedeem` /
`NewTotalAssetsUpdated` beside the report) landed by a `tx.from` that is neither an owner nor the
known relayer: a confirmed batch is an option anyone exercises at a moment of their choosing (§6,
review G13e); the deadline helper's `SettlementExpired` inside a `GS013` is that option expiring as
designed, not a policy refusal.

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
| `MalformedCalldata` | calldata of 1 to 3 bytes: shorter than a selector, yet not the empty calldata of a plain transfer (a truncated payload, or a venue addressed by fewer bytes than a selector), at top level or as a batch entry | fix the payload: a plain transfer is empty calldata, a function call starts with its 4-byte selector (such bytes reach the venue only inside a council or admin window) |
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
| `ForwardedHookCall` (also `Unauthorized` from `executeBefore` and from the hand-over acceptance) | the Safe's fallback handler is the guard itself: no approval is spent while it is (anyone could otherwise drive the hooks through the Safe, directly or wrapped in `executeBefore`, and complete a pending hand-over on its behalf; review G9a-1 and G9a-3, applied after round 13) | on the guarded Safe: a council window, `setFallbackHandler(0)` inside it, `enforce`, then re-issue the approvals the window voided. On a role-holding or pending-admin Safe this guard does not guard (the council, a deployment-wide guardian and a pending admin never are, by the grant and transfer rails; a per-Safe guardian seat has no such rail, so a guarded Safe seated there takes the recipe above): that Safe's own `setFallbackHandler(0)` transaction and nothing else; never a window or `enforce` on a pending admin, since a live window and the `Enforced` mode it leaves refuse the acceptance (`AdminIsGuarded`) until `lockdown(newAdmin)` restores the mode (review G14b-1) |
| `LockdownCooldown` (admin operations only) | the admin tried to enforce, open a window or approve within a day of a lockdown of that Safe | wait out the day, or the council acts now; cancel queued operations that should not survive the incident |
| `SafeConfigUnreadable` with an unusually low gas limit | a configuration read starved of gas (it gets 63/64 of what is left) is reported as unreadable rather than as out of gas | re-estimate / raise the gas limit; an `eth_call` of the Safe's `getOwners()` succeeding tells the two apart |
| `NestedExecution` / `MissingSnapshot` / `SafeConfigChanged` / `ApprovedExecutionFailed` | a nested same-Safe transaction, a role action inside the curator's transaction, a configuration write during a policy transaction, a failed approved execution (a module's, or the signers' when the transaction carries `safeTxGas != 0`; the approval is kept) | structural: split the transaction, fix the payload and retry, or ask Vetro |
| `FailedCall()` (from the timelock's `execute`) | a scheduled call reverted WITHOUT data: an unknown selector, malformed arguments, an enum out of range, or value sent to a non-payable function | re-build the operation from the ABI; the batch error carries no call index, so simulate the calls one by one |
| `SafeConfigUnreadable` | the Safe's own `getOwners()` / `getStorageAt` cannot be read (owner list and owner count out of step after a storage-writing delegatecall; a dry run against a `safe` address that is not a supported Safe is `SafeNotSupported`) | ask Vetro (§7.6 step 4): approvals and Bypass windows still work meanwhile; on the live Safe (solc 0.7.6 singleton) the failing owner read burns all the gas it was given, so a failed attempt costs the whole gas limit: diagnose with `eth_call` / `validateTransaction`, do not retry blindly |
| a status-0 settlement or claim with NO guard error (the guard passed; Lagoon reverted) | the vault's access check `isAllowed` reverted: the external sanctions list or Lagoon's fee registry proxy is broken (review G13b-1); or Lagoon's own refusal (`OnlySafe` after an `updateSafe`, `WrongNewTotalAssets` on a settle that does not repeat the pending mark) | the whitelist manager (`setExternalSanctionsList`) or Lagoon (the registry); nothing in the policy or the guard |

A raw `custom error 0x…` (from `cast call … validateTransaction`, an `eth_call` replay or a trace) is one of
these selectors (`cast sig`): `SafeLockedDown(address)` `0xf31caf41`, `FunctionNotAllowed(address,bytes4)`
`0xdd22d9b6`, `ValueNotAllowed(address,bytes4)` `0x6141c433`, `NativeTransferNotAllowed(address)` `0xc16efa05`,
`ParamRuleViolated(address,bytes4,uint16,bytes32)` `0xdd09e70a` (the last word is the offending argument),
`ParamOutOfRange(address,bytes4,uint16)` `0x179d1ee2`, `MalformedCalldata()` `0x59170bf0`,
`SelfCallNotAllowed(bytes4)` `0x5a3e05ad`, `GuardCallNotAllowed(bytes4)` `0x52b498a9`,
`DelegateCallNotAllowed(address)` `0x5d9179f4`, `UnwrapperCodehashNotAllowed(bytes32)` `0xafd15f82`,
`MultiSendDelegateCallEntry()` `0xf5df277e`, `MalformedMultiSend()` `0xa04af7a6`, `EmptyMultiSend()`
`0x2b14c97a`, `FallbackHandlerNotAllowed(address)` `0xd4ef5ed9`, `GasRefundNotAllowed()` `0x0672e151`,
`CouncilBypassLimit(bytes4)` `0x820007d9`, `ModuleNotAllowed(address)` `0x85682ba1`, `NotAContract(address)`
`0x8a8b41ec`, `SafeNotSupported(address)` `0x8ac2a0f9`, `ModuleNotHooked(address)` `0x42392af2`,
`GuardNotInstalled(address)` `0xd4038cc4`, `ForwardedHookCall()` `0xe2bdff4a`, `Unauthorized()` `0x82b42900`,
`LockdownCooldown(address)` `0x30628f46`, `SafeConfigUnreadable(address)` `0x38cc646a`,
`NestedExecution(address)` `0x4fef49c8`, `MissingSnapshot(address)` `0xb80de7e1`, `SafeConfigChanged(address)`
`0xd2ed3dd7`, `ApprovedExecutionFailed(address)` `0x726e39f3`, `FailedCall()` `0xd6bda275` (review G17f-5).

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
unconstrained `updateNewTotalAssets` on a vault behind which a `Lagoon_Vetro_*` strategy (the address
book's `Lagoon.strategy` entries, `helpers/address.ts`) carries a `debtRatio`, a `totalDebt` (the pool's
accounting, written by governance and the keeper) or a `tvl()`, or whose own `totalAssets()` is not zero:
that number is the curator's mark and stays a trigger because on a public vault custody can be an
outsider's with no Vesper debt behind it (reviews G11b-6, G13g-2, g13e); the strategy figures are printed
with every refusal.

- **`securityCouncil` → Vetro governance, then activate guardrails.** `securityCouncil` is the only
  role that can `updateActivated(true)` / `updateGuardrails((uint256 upperRate, int256 lowerRate))`
  and the only one that can push a NAV past them (`securityCouncilUpdateTotalAssets`). With the role at Vetro
  and guardrails activated with real bounds, the policy-allowed `updateNewTotalAssets` is bounded
  per settlement interval; without this, "guardrails bound NAV" is not true for these vaults.
  The bound is annualised from the LAST SETTLEMENT (`lastFeeTime`, `hopper.storage.FeeManager` + 2,
  advanced only by the Safe's settles) with `ONE_YEAR / timePast` in integer arithmetic, a scale that
  rounds down to 1 once more than half a year has passed and to 0 after a year: from six months
  after the last settlement a +20 %/yr bound admits +20 % in ONE mark, after one year any mark passes
  (measured on the live v0.6.0 code, review G11b-4). The curator decides when settlements happen, so a
  guarded vault needs an alert on `block.timestamp - lastFeeTime` well inside six months, and the §5
  band on the mark and the settles is the bound that does not lapse. Activate only after a fresh
  settlement: the live vaults' last settlement is 2026-06-16, and on a clock that old (integer scale 2
  at 122 days) the +20 %/yr and -10 %/yr bounds admit +10 % and -5 % in ONE mark (measured on a fork
  of block 26,151,235); a NAV-only settlement right after activation resets `lastFeeTime` (review
  G12c).
- **`owner` → Vetro governance (two-step).** Removes pause / unpause, `initiateClosing`,
  `activateAsyncOnly`, role rotation, `updateSafe` and fee-rate changes from the curator, independent
  of any future approval; it also retires the pre-staged `pause()` approvals of §6 / §7.5 (Vetro
  pauses directly from then on). Keep `safe` as is; call `lockUpdateSafe()` once custody is final.
- **`feeReceiver` → off the guarded Safe.** Fee shares minted to the Safe are unrealisable under the
  policy (`requestRedeem` and the share `transfer` are not allowlisted: 49 USDC of shares after one
  30-day cycle at 1 % / 10 % on a 45.7k position, measured on a fork); `updateFeeReceiver` is
  owner-only, so after the owner move it is Vetro's direct call, to be made before any non-zero rate
  (§12.4 recommended it; review G12c). Lagoon's fee registry (`0x6dA4…27C`, owned by Lagoon's
  `0x9A40…d4B`, which is also the `protocolFeeReceiver`) sets the protocol's cut of every manager
  fee a guard-admitted settlement realises, up to `MAX_PROTOCOL_RATE` (30 %) with no Vetro or
  curator consent: size Vetro's own rates knowing Lagoon can raise its share afterwards (review
  G13b-2).
- **`valuationManager`**: decide explicitly. Leaving it with the curator means NAV honesty rests
  on guardrails + monitoring; moving it to a Vetro-run valuation process removes the curator's
  NAV discretion entirely (settlement still needs the Safe).
- **Proxy admin.** Each vault's `DelayProxyAdmin` is owned by the curator Safe (1-day delay,
  implementations gated by Lagoon's registry). Upgrades are blocked by the guard today (the admin
  is not an allowlisted target) but would ride on any future approval; consider moving the admin
  ownership to Vetro and re-verify the registry before approving any upgrade. Lagoon's registry
  already whitelists its default v0.5.0 logic as a target: a downgrade keeps four of the five
  allowlisted selectors (`claimAssetsOnBehalf(address[])`, `0x26d6c82f`, is not dispatched by the
  v0.5.0 default logic `0xE505…DEDf`: that entry reverts in the vault until the policy is re-synced,
  and the sync task's selector probe reports it; read live, review G11f) and drops guardrails and the
  security council, so the admin ownership must move to Vetro
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
  ±x) but stalls at every funding step, every exit and, on a public vault, every outside flow larger
  than the band (each a timelock round: four in one 30-day cycle with one outside depositor,
  measured; review G12c; one outsider holding half the band's width keeps a public vault out of band
  for as long as it likes, free of fee or loss, review G13e), and cycles chain inside one transaction.
- **Whitelist mode is also a liveness control for the strategies** (control (1) above). On a public
  vault any holder can open a request with a strategy as `controller`
  (`requestRedeem(1, strategy, holder)`); after the next mark that share-wei sits alone in a closed
  epoch, Lagoon never settles it, nobody can cancel it, and every later redeem of the strategy reverts
  `OnlyOneRequestAllowed` (the keeper's report emits `VaultActionSkipped`), so the pool's withdrawals
  cannot be queued until a redeem worth at least one asset unit joins a later batch: on a public
  vault any holder's (on a fork a 1e18-share request by a third holder settled the 1-wei one with the
  next batch; reproduced on the live vaults in the strategy-fix review, 2026-10-05/06), after the
  switch only a WHITELISTED holder's, so the release is Vetro's action: whitelist a helper that holds
  shares, have it request a redeem of at least that value, mark and settle. The plant survives
  `switchAccessMode` unchanged and cannot be re-planted after it (`AddressNotAllowed`); nobody cancels
  it (a stranger and the keeper are not the strategy's operators, `ERC7540InvalidOperator`, and its
  epoch closed with the mark); a settlement with no other redeem in the batch leaves it where it is;
  it costs the planter one share-wei and one transaction in the block before the mark (measured on the
  live vault and the live 6.0.5 proxy, review G13e); a settled stranger request for the
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
- **Strategy upgrade** (a `vesper-strategies` procedure: the strategies, their deploy scripts and
  every command of this item live there, not in this repository). The five `Lagoon_Vetro_*` proxies
  run `LagoonV06` 6.0.5 while that tree is newer. On the live code `tvl()`, `balances()` and
  `instantLiquidity()` revert while a settled
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
  funding. The sync task enforces the dependency: an unconstrained NAV entry on a vault behind which a
  `Lagoon_Vetro_*` strategy (the address book's `Lagoon.strategy` entries) carries a `debtRatio`, a
  `totalDebt` or a `tvl()`, or whose own `totalAssets()` is not zero, is refused unless
  `--allow-unconstrained-nav` is given knowingly, the strategy figures printed with the refusal (reviews
  G11b-6 and G13g-2; the
  two live vaults hold dust, about 1 USDC and 2 USDT (§1), so the first mainnet sync needs the flag or a band; a band's
  first sync is checked against the same `totalAssets()`, inside the band and no wider than ±50 % of
  it, so a band that only looks like one is refused the same way, review G13a-1; on an empty vault, where that number is zero, a band or a fixed mark is refused until the first settlement, and a fixed `EqualTo` / `OneOf` mark is judged by its lowest and highest member on every sync, review G16c-2). The
  file ships without a `guard` pin and is therefore not deployable as shipped: pin the address the
  deploy script prints right after deployment (§7.2).
- Required fallback handler `0x0`, enforced (see §7.3); the Safe's narrow-only guardians (the file
  ships with an EMPTY `guardians` list: fill in Vetro's responders before go-live, the lint warns, §7.2;
  deployment-wide guardians hold `GUARDIAN_ROLE` instead). `mode` is `Enforced`; the
  file can never request `Bypass`.

Caveats: `updateNewTotalAssets` is unbounded until §8's guardrail step is done; `settleDeposit` also
settles pending redeems, so the two settle entries are one custody exit (narrow both or the target,
review G11b-1); a NAV band, when one is written, goes on the mark and on both settles (review
G11b-2); the settlement-deadline entry's target must be the repository's `SettlementDeadline` build (the sync
compares the runtime, review G16c-1); `expireTotalAssets` must be added if `totalAssetsLifespan` is ever raised above zero (§7.5).

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

`forge test` (110 test files plus thirteen shared helpers under `test/guards/` after round 19: 143 suites and
2,476 tests without an RPC, and ten of the files are fork suites against the live Safe and vaults (38 tests): the six
`*.e2e.ethereum.t.sol` files need `ETHEREUM_FORK_NODE_URL`
and `G9a_CanonicalProxyHashes`, `G10d_Fork`, `G11b_Policy` and `G13b_CrossSystem` skip without it; one
more file, contract
and test under `FOUNDRY_PROFILE=precancun forge test`, which needs a Shanghai EVM and a prior
`forge build`; in this repository the default profile IS the guard profile and `FOUNDRY_PROFILE=guards`
is kept as an alias; CI pins a pristine fork block through `.github/actions/fork-blocks` and runs
`forge test` in `.github/workflows/ci.yml`):

- `G12a_BuildPin.t.sol`: the runtime bytecode of `CuratorGuard`, `CuratorGuardTimelock` and the
  `SettlementDeadline` helper, metadata stripped, is pinned to the reviewed build (23,249, 8,204 and 177 bytes;
  keccak `a1cc0159…`, `8a69e72c…`, `15af8250…`; the deploy script carries the same two guard and timelock
  pins and refuses to send an artifact that does not hash to them, review G18g-2; the helper's pin is the build the sync compares a
  deadline entry's target against, §5, review G16c-1). CI's toolchain-parity step compares
  hardhat with foundry, never with the reviewed build, and the deploy script deploys whatever the local
  `node_modules` compiles to, so a bump of `@openzeppelin/contracts` (a Dependabot merge, `npm update`)
  would move the deployed bytecode with every check green: the pin fails the suite instead, and is
  re-pinned only together with the review of the change that moved it (review G12a-1).
- Symbolic proofs, outside this repository and outside `forge test` (halmos `check_` suites with z3): round
  12's `G12b_Symbolic` / `G12b_Witness` (an admitted `Enforced` transaction is never a configuration write, an
  approval is spent once by its exact payload on its path, nobody but the admin widens, time only narrows,
  `OneOf` sets never leak into a re-allow, the v1.5.0 module path refuses what the owner path refuses, the dry
  run is the live hook) and round 15's `G15b_Sym*` on the production guard and a one-day timelock (no forwarded
  caller reaches `executeBefore`'s delegatecall or completes an acceptance for any deadline, payload and time;
  a forwarding Safe with any calldata changes nothing; no scheduled `updateDelay` outside [1 day, 30 days] is
  proposed, stored or read; the timelock's role rails at the floor, complete). Each proof ranges over a finite
  address domain and the calldata lengths its driver names, and every symbolic model was replayed concretely.
  They live with the review material (`review-scratch/g12b/`, `review-scratch/g15b/notes/`, each with its
  drivers, settings and verdict lines; the review-material manifest lists them), not in this tree (review
  G15b-1).
- `G12e_Matrix*.t.sol` (generated by `test/guards/matrix/gen_matrix.py`): every external and public function of
  the three contracts called as every caller class in every mode and window state, each cell compared with the
  expectation the documentation decides (or, where it does not, with the code: those cells are tagged `U` in
  the generator and pin behaviour, not design). Regenerate with `python3 test/guards/matrix/gen_matrix.py`,
  copy `test/guards/matrix/out/G12e_*.sol` over the committed suites and delete `out/`: it is inside Foundry's
  test glob and git-ignored, and left in place it runs the matrix twice (review G12e, G14d-2). Fourteen caller
  classes since the handler-word mask landed: class 13 is Safe A with a dirty handler word whose low 160 bits are
  the guard, and must answer exactly as class 12 (the clean word) does (review G16d-1, g17c).
- `G16d_DirtyWord.t.sol` (on `G16d_DirtyWordBase.sol`, review g18b adopted with the mask applied): the production
  guard and timelock with real v1.4.1 and v1.5.0 Safes in the role seats; a handler word whose low 160 bits are the
  guard (or the timelock) is refused by its rail on every route, fuzzed over the high 96 bits (2,048 runs, seeded in
  CI; the proof over every value of the high bits, and over the whole word on every route of both rails, is review
  material: g18b and g19b), the clean word stays refused, a word naming another address is served, and the plant is
  also done the real way (a storage-writing delegatecall through `execTransaction`, since the plain
  `setFallbackHandler` self-call refuses the dirty word).
- `G13b_CrossSystem.t.sol` (fork): a Lagoon-side key outside the Safe and the guard turns a
  guard-admitted claim into a denial (a reverting external sanctions list stored in the live USDC
  vault's `hopper.storage.Whitelistable` slot makes `claimSharesOnBehalf` revert whole, then succeed
  again once cleared), and Lagoon's registry owner raises the protocol's cut of every settlement's
  manager fee on its own (review G13b-1, G13b-2).
- `G13f_Liveness.t.sol`: on g9c's production topology, a proposer floods the timelock with 64
  operations that never expire and are still Ready ten years later; a swarm of 40 deployment-wide
  guardians outlives an eviction that misses one (the admin's lift reverts `LockdownCooldown` until
  the last is removed); `updateDelay(1 hours)` is refused when proposed (`DelayOutOfRange`, `GS013` through
  the proposer's Safe) and the one-day floor keeps the veto a day on every later operation (review G13f-1,
  G13f-2, G13f-3, applied after round 13).
- `G14g_HeldChain2.t.sol`: the chain of held items re-run with the follow-up known: at the floors (the
  timelock's and the admin delay's, both one day, reached by a proposer while the veto sleeps) an UNCHAINED
  honest cancel of a hostile hand-over is a one-second race the awake attacker wins, the CHAINED cancel of
  §7.5 wins at any delay and the eviction lands in one one-day round, and a hostile council's guardian swarm
  costs nothing against a seated council (review G14g-2, G14g-3).
- `G14b_RailSemantics.t.sol` / `G14b_DocsRecipe.t.sol`: the two forwarded-caller rails of the follow-up on
  real Safe v1.4.1 and v1.5.0 builds: every legitimate caller of `executeBefore` and of the hand-over
  acceptance is served (the timelock, a council or guardian Safe with a real handler, an EOA or Safe pending
  admin, a successor timelock at the one-day floor, a council batch, a nested wrapper), every forwarded one is
  refused on every route with no report and no nonce moved, the probe's imposters refuse only themselves, two
  gas sweeps of 5,379 limits find no limit at which the probe fails and the wrapped call still runs, and the
  §7.8 repair of a pending-admin Safe is its own `setFallbackHandler(0)` (review G14b).
- `G14c_Clocks.t.sol`: a real timelock lowered to the one-day floor from its own queue next to a guard whose
  admin delay is lowered to its floor: both reached, the unchained cancel of a hostile hand-over keeps the
  Ready second alone and the next second is the builder's order either way, the chained cancel wins, and the
  cooldown is covered by the delay for any lockdown placed before the schedule (review G14c-3).
- `G16f_RecoveryMatrix.t.sol` (on `G16f_Base.sol`, g9c's fixture reading the timelock delay from
  `G16F_MIN_DELAY`, default two days): every recovery path's chain time asserted as a closed form at the live
  delay D, with C the one-day cooldown and A the three-day admin delay: a single lockdown's admin lift
  max(D, C + 1 s); a re-locking key D + C + 1 s behind its chained removal; a council lift in the same block; a
  deployment-wide swarm 2D + C + 1 s without a successor council and D with one seated in the batch; a flood
  Ready after D and outliving its proposer's eviction; a hand-over D + max(D', A + 1 s) for a successor at D';
  the one-knob `changeDefaultAdminDelay(1 day)` and its unchained rollback window, (A - 1 d) - D + 1 s, one
  second at the 48 h default; a guardian's revoke loop and a deployment guardian's unwrapper ban undone in D;
  an admin window re-opened D + C + 1 s after a guardian's lockdown; a council window's epoch bump re-issued
  in D; a veto plus one locker permanent without a council and nothing against a seated one.
  `G16F_MIN_DELAY=86400 forge test --match-contract G16f_` runs it at the floor (review G16f).
- `G16a_Insider.t.sol`: the insider who read the follow-up, on g9c's topology: a wrapped chained cancel is waited
  out by a bare hostile begin and a bare one survives a 60-day wait, a re-begin chained behind the honest cancel
  re-arms the ladder and the cancel behind the last rung wins, the only scheduled operation the rails refuse is
  one aimed at a forwarding Safe (a corpse), and a deployment-wide guardian cannot stall a hand-over (review
  G16a).
- `G16b_TimeAttack.t.sol` / `G16b_ModulePathEdges.t.sol`: the hand-over reaction law (a cancel scheduled r after
  the hostile scheduling wins iff r is at most the admin delay, chained or not), the inverted delay pair in one
  batch, the decrease wait of a lowered admin delay, a stock of Ready begins, the admin's lift duration at and
  after the cooldown, in-flight proposals across an executed `updateDelay`, and the module path's window and
  approval edges on a real v1.5.0 Safe (review G16b).
- `G16c_PolicyEconomics.e2e.ethereum.t.sol` (fork, with `G16c_Helpers.sol`): the price of a band the gate admits
  (26.8 % of NAV per colluding cycle at ±50 %, 25 bp at ±5 %), a look-alike deadline helper re-opening the
  stale-batch option and the real one killing it, an empty vault's band forcing the first mark to its floor and
  then admitting −99 %, and the flag's escape ahead of a flow costing half a first deposit (review G16c).
- `G15c_CancelGas.t.sol`: the marginal gas of a veto Safe's `cancel` (about 6,607) and the number of cancels one
  transaction holds under the EIP-7825 cap (about 2,600), the figures §6 and §7.7 quote (review G15c-5).
- `G16e_ChainCompiler.t.sol`: the two rails from cold state (two more starvation sweeps, nothing lands) and under a
  repriced probe (a Safe-shaped forwarder whose `getStorageAt` burns a chosen amount: the fail-open window of
  §6 appears only past about 300k gas warm / 560k cold and its lower edge is the hook's, not the probe's), the
  EIP-7825 boundary of a wrapped batch (179 rule-less or 77 banded entries, the 12 M gate at 127 / 55, the probe
  1 %), `simulateAndRevert` and nested frames at the two entries (nothing persists; the inner deadline bubbles
  verbatim and the operation stays Ready), the open executor's gas (a starved execute leaves the operation Ready
  and nothing applied; the wrapper moves the first landing limit by 4,268); byte-identical gas under cancun,
  prague and osaka. `G16e_Cap.s.sol`, kept with the round-16 review material (`review-scratch/g16e/fixes/`), not in
  this tree, schedules the boundary batches on a dev node for the node's own estimate (review G16e).
- `G15d_ProbeGas.t.sol` / `G15d_ProxyHashes.t.sol` / `G15d_HeldPins.t.sol`: the killers of the six mutants the
  warm unit suite could not see (review G15d): the forwarding probes refuse a council Safe whose handler is the
  guard from COLD state (`vm.cool`) on its genuine and its direct route and serve it after the repair, the
  timelock's probe answers only to a Safe-shaped 96-byte answer, the live-delay rail schedules at the clamped
  delay with a planted raw slot; a proxy deployed from each canonical factory's `proxyCreationCode()` (three
  vectors under `test/guards/vectors/`) hashes into the seeded set, offline; and the report of a no-op
  `setNativeTransferAllowed` is pinned as current (to flip with the held G9b-2 if ever applied).

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
- `CuratorGuardV2.t.sol` (the v2 items of §13): the role matrix (admin widens; council,
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
- `CuratorGuardRobustness.t.sol` (the v2 robustness items of §13.2: `SafeConfigUnreadable`,
  `lockdownAndRevoke`, `TransactionChecked`; v1.4.1 fixture plus a v1.5.0
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
  it skips itself wherever transient storage exists (a `PUSH0 TLOAD POP STOP` probe), so a profile that
  compiles this directory on Cancun would be unaffected (the default profile compiles `test/guards/` only).
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
- Round 10 (g10f) additions, `test/guards/G10f_*.t.sol`: `G10f_Gas` (every hook path on the shipped
  policy shape applied to the local fixture, and the worst case of each: 16 rules of every kind, a
  tail-hash rule over 1 KiB to 256 KiB, batches of 10 to 100 entries warm and 50 distinct targets cold,
  4 to 50 owners, a council-window batch of self-calls, an approved batch decoded at use) and
  `G10f_Pins` (killers for the 23 probes that survived the suite as shipped, none a defect: the
  `NativeTransferUpdated` and `MultiSendUnwrapperUpdated` events, `revokeTarget`'s native event, the
  `_checkAdmin` forwarding rail with an admin Safe, the Safe-shaped answer the forwarding probe
  requires, the zero-address rail of `setDeploymentGuardian`, `addAllowedValues` needing a `OneOf`
  rule on that word, a re-allow clearing the set of a moved `OneOf` rule, `targets` pruning, an
  approved single call into canonical code staying unparsed, a role grant never reading the council
  term, and six timelock fall-through arms). `G10f_HeldFixPins` pins the two round-9 rails applied
  after round 13 (G9a-1, G9a-3 / G9c-3; four tests); the pins of the round-9 items that stay held
  (G9c-1, G9b-2) stay with the review material outside this repository.
- The other round-10 suites, all green on the shipped code: `G10a_*` (a reference model of the mode,
  window, cooldown, approval and hand-over machine driven in lockstep with the guard through real Safe
  v1.4.1 / v1.5.0 transactions: 14 invariant functions over four handlers, two Safes on one guard, the
  timelock's counters under scheduled self-calls, and the G10a-1 / G10a-2 PoCs), `G10b_*` (a
  differential corpus of 2,800 calldata vectors generated from section 4 alone, in
  `test/guards/vectors/`, replayed through the dry run, the live hooks on a real Safe and the three
  canonical Safe builds; the ABI edge cases), `G10c_*` (the governance game: id squatting, hostile
  proposer and council, windows; the three `G10c_IdSquat` tests pin the G10c-1 rail: a longer
  delay is refused and a squat at the honest delay is the honest operation; `G10e_Monitoring`'s
  forged-report test flipped with G9a-1 after round 13; the `G10a_Findings` G10a-1 and G10a-2 tests flip
  with those items, review G11d-3), `G10d_*`
  (the second adversary: hostile venue, hostile vault
  implementation on the live Safe, compromised council and proposer), `G10e_Monitoring` (event
  adjacency, uniqueness and ordering) and `G10g_*` (the `OneOf` gas and `_storeApproval` write-count
  measurements behind two NatSpec claims).
- Round 11 additions, all green on the shipped code: `G9a_*` and `G9c_*` (the round-9 Safe-integration and
  governance PoCs adopted on g11d's request: the forwarded `executeBefore` forgery, refused since the round-13 follow-up, and `simulateAndRevert`
  as the Safe, the canonical proxy hashes, the hand-over at the slowest successor delay, the council stall's
  eviction, the rotation residue, the veto-only deadlock, the guarded-proposer recovery of 7.6 step 5),
  `G11b_Policy` (the shipped policy shape on the live Safe: the one custody exit, the settles repeating a
  council mark, the band's leak and the approve cap's cost), `G11c_*` (time boundaries fuzzed at the second,
  the executor's gas floor on the fixture and the live Safe, the caps under committed storage, the lift
  window against the signing round; the 11 exhaustive EIP-150 gas sweeps of `G11c_GasStarvation` need a
  raised gas limit and 31 CPU-minutes and are kept with the round-11 review material, not in-tree), `G11d_*`
  (traceability: every header citation, error and event asserted by some test, the 7.8 table complete; the
  event payloads; the peers' failure modes as vectors: 1-3-byte calldata, `address(0)`, fallback targets,
  pre-batch state, nested `execTransaction`, the OLAS stuck lock, the Gnosis Pay `staticcall` flag),
  `G11f_*` (the one-batch migration against a new-id and a same-id release, a look-alike migration library,
  the replacement swap and rollback, EIP-7702 owners and venues on both releases) and `G11g_Evidence` (the
  claims behind five comment corrections).

`forge coverage` cannot measure the guard contracts: without the optimizer the guard hits "stack too
deep" (the 11-argument `checkTransaction`), and `--ir-minimum` dies in the vendored Safe v1.4.1 sources
(`execTransaction`'s `operation`, "too deep in the stack by 4 slots" under via-IR with the optimizer off; the
v1.5.0 sources and the three guard contracts compile under those settings, but every fixture deploys the
v1.4.1 build, review G17c). Branch coverage is measured by mutation instead (round 10, g10f:
every `if` decision of the three contracts forced each way and every `&&` / `||` operand
neutralised; the branch map is kept with the round-10 review material).
`FOUNDRY_PROFILE=guards forge build --sizes` exits
non-zero only because the test-only `PolicyHandler` (invariant harness) exceeds the EIP-170 limit; the
deployed contracts are checked by `scripts/check-contract-sizes.sh` on hardhat artifacts. Before the round-10 campaign, round 2 ran a 71-mutant campaign against the
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
| R2-4 | Medium (tooling) | The policy validator ignored unknown keys and string booleans: a `rule`/`rules` typo produced an unconstrained `approve`, a `requireFallbackHandler` typo silently dropped the handler requirement, `"enforce": "false"` applied `true`. | Strict schema (allowed keys per level, typed booleans/ints, decimal-string numbers), `requiredFallbackHandler` mandatory, allowance-shaped selectors need a word-0 rule unless `unconstrained`, contract limits mirrored (16 rules, 128 values, targets ≠ Safe/guard, unwrappers must have code), `--allow-bypass` (now `--allow-unlock`). Eleven malformed policies verified rejected. |
| R2-5 | Medium (tooling) | Selectors were `keccak(raw string)`: parameter names or `uint` aliases produced garbage selectors, and an explicit `selector` was never cross-checked. | Canonical `FunctionFragment` signature required; `selector` must agree. |
| R2-6 | Medium (CI) | Submodule gitlinks were unstaged, so a fresh CI checkout would miss the Safe sources and break every Foundry workflow. | Documented in §7.5 (`git add .gitmodules lib/safe-smart-account lib/safe-smart-account-v1.5.0` when committing); left unstaged deliberately until the green light. |
| R2-7 | Medium (deploy) | hardhat-deploy would redeploy the immutable guard on any bytecode/metadata drift and repoint the artifact. | `skipIfAlreadyDeployed: true`; replacement guards use a new alias. |
| R2-8 | Low | 35 of 71 mutants survived the round-1 suite, including dropping the calldata hash from the approval id, dropping `onlyOwner` on `allowFunctions` / `addAllowedValues`, dropping the owner list / module-guard slot from the digest, never clearing the in-flight marker, and keying `OneOf` sets without selector/word. | Round-2 suites added (`CuratorGuardRound2`, `Signatures`, `Invariants`, `MultiSendDiff`, `Gas`, module-path tests); re-running the campaign kills every non-equivalent mutant. |
| R2-9 | Low | Absent-key semantics of the policy file were asymmetric; JSON numbers could lose precision; the EOA execution path logged "executed" before confirmation; the dry-run script exited 0 on a wrongly allowed call; Etherscan verification was attempted on fork networks; `safe.batch.tmp.json` was not ignored and a stale file could be merged. | All fixed in the task, scripts and `.gitignore`. |
| R2-10 | Low | No CI workflow exercised the guard suites. | `.github/workflows/curator-guard.yml` on the repo's pattern (`forge t --mc CuratorGuard`); in this repository the workflow is `.github/workflows/ci.yml` and runs every suite with `forge test`. |
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
  `invariant_deep` (now the `guards_deep` profile) wired to a schedule, `slither.config.json` with triage (102 detectors run
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

IMPROVEMENTS_V2.md (the v2 planning document; it stayed in the vesper-strategies tree the guard was
split from and is not in this repository) items 1-5 (and, along the way, items 6 and 7) were
implemented after the Round 4 design review, then put through three further review rounds (§13.2); the final state is deployable
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
| V2-65 | Medium (irreversible) | Three one-operation wedges on the unmodified timelock: `updateDelay` typed in milliseconds (2,000 days, the correction needs the new delay) or as 48 seconds, or `type(uint256).max` (every schedule overflows); `revokeRole(EXECUTOR_ROLE, address(0))` without a named executor (nothing executes again, the repair included); the timelock renouncing its own admin role (the role set frozen for good); both proposers rotating from one bad list (R6D-5, R6D-8). | The subclass clamps `getMinDelay()` to [1 d, 30 d] (the raw value is what the event reports), refuses to revoke the open executor or its own admin role, and keeps the last proposer and the last canceller (role counts maintained in `_grantRole` / `_revokeRole`). Tests for each rail. |
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

#### Rounds 9 to 11 and the move to this repository (2026-10-08)

Three further campaigns of seven lenses each (Safe integration, the policy engine, roles and time,
the adversary, deployment and tooling, tests and mutation, comments; then the state machine, calldata
edges, governance as a game, a second adversary, incident drills, mutation coverage, a second comment
reading; then an end-to-end runbook rehearsal, the shipped policy against the live vault code, gas
and time boundaries, spec-to-test traceability, the tooling as code, upgrades and future EVMs, a
third comment reading) found no Critical or High. The guard system was then moved into this
repository (`d04e686`), the one contract change of the three rounds was committed (`2c1fc92`: an
operation delay other than the live `getMinDelay()` is refused at `schedule`, review G10c-1, +4
bytes on the timelock, 8,187 to 8,191 bytes) and everything else the rounds produced was ported and
reviewed (`830824e`): comment-only corrections to the three contracts (bytecode identical), the
documentation corrections cited as "review G9…", "G10…" and "G11…" in §4 to §10, the lint and
tooling changes described in §7.2 and §7.5, about 110 adopted tests and 70 lint-corpus cases. Size:
guard 23,224 bytes (368 under the gate), timelock 8,191 bytes, both toolchains identical. Suite: 85
suites and 583 tests without an RPC (580 pass, the three non-e2e fork suites skip), 89 suites and 602
tests with an archive RPC at the pinned block, the pre-Cancun test; the lint corpus (112 cases plus
the shipped policy); the fork rehearsal exit 0.

HELD for the owner's decision at that date (G9a-1, G9a-3 / G9c-3 and the delay floor landed after round
13: see "Round 13 follow-up" below), each with a proof-of-concept test and a measured diff in the review
material kept outside this repository, none applied at that date: `_refuseForwarded()` first in
`executeBefore` (G9a-1, +8 bytes: a stranger forges a `Bypass` report through a Safe whose fallback
handler is the guard; §4, §6, §7.3 and §7.8 name the exception) and the same rail in
`_acceptDefaultAdminTransfer` (G9a-3 / G9c-3, +8 bytes); the hand-over predicate on admin-written
state only (G9c-1, −57 bytes); `NativeTransferUpdated` on change only (G9b-2, +47 bytes); the
post-hook's window report only where the guard is installed (G10a-1, about +40 bytes; §4 step 3
describes the artefact); the guard never its own council, guardian or pending admin (G10a-2, +19
bytes); `MIN_DELAY_FLOOR = 1 days` (+4 bytes on the timelock); the sync task executing hand-scheduled
approvals behind `--confirm-sensitive` (G9e-1; until it lands, the one-offs of §7.5 and §7.6 are
executed with a hand-built `execute`); a fuzz seed in CI (G9f-10); the per-settlement `approve` cap
as a policy option (G10d-1, §5); the unconstrained-NAV sync gate re-based on the strategies' debt
(G11b-6); and the tests that pin the held fixes (G10f-2). The tests of this tree that pin HELD
behaviour as current (§10) flip when an item lands.

#### Round 12 (2026-10-09): the operator and the supply chain, properties proven, go-live economics, monitoring as code, the access matrix, the rule language, the auditor's first day

Seven lenses on `830824e`. No Critical or High; two Medium outside the contracts, both fixed in this
tree: five Dependabot merges had moved the default branch onto OpenZeppelin 5.4.0 and Hardhat 3 with
CI red (the timelock compiles to other bytecode there; `test/guards/G12a_BuildPin.t.sol` now pins
both stripped runtimes, `.github/dependabot.yml` keeps the Solidity dependency off, the CI actions
are pinned by SHA; the default branch itself is the owner's to repair, review G12a-1), and the
proposer Safe's signers had nothing to verify a proposal with that did not come from the operator's
machine (`curator-guard-verify --manifest` rebuilds the operation ids and the EIP-712 `safeTxHash`
from the manifest's calldata alone, §7.2, review G12a-2). Proven with `halmos` over an eight-address
domain: an admitted `Enforced` transaction changes no configuration slot, an approval is spent once
and only by its exact payload on its path, nobody but the admin widens, a window expires on its own
and a lockdown is never lifted by time, `OneOf` sets never leak into a re-allow, the v1.5.0 module
path refuses what the owner path refuses (review g12b; the symbolic suites stay in the review
material). A generated access matrix (13 caller classes x 95 argument shapes x 8 states, 10,453
cells, 0 disagreements with the documentation in the cells it decides, 1,347 cells read from the
code) and a differential fuzz of the rule language (1,209 policies, 43,262 vectors, 0 verdict
mismatches between the lint's stated semantics, the sync and the live hooks) are adopted as
`test/guards/G12e_*` with their generator and `G12f_*` with their replay vectors. Lows, all
applied: the band re-sync no longer trips the loosening gate when it only follows the live NAV
(G12c-1), the dead `pause()` approvals after the §8 owner move (G12c-2), `feeReceiver` off the Safe
before any non-zero rate (G12c-3), the lint refuses the required fallback handler as a policy target
(G12b-1) and a right-aligned value or a bound on a `bytesN` word (G12f-1), the custody-token and
receipt-join rules of §7.7 (G12d-1, G12d-2), the install trust root in §7.3 (G12a-3), the review
log's missing rounds (G12g-4). Size unchanged: guard 23,224 bytes, timelock 8,191 bytes, both
toolchains identical. Suite: 113 suites and 2,237 tests without an RPC (2,234 pass, three fork
suites skip). Residual, outside this repository: the audited commit was not yet on the remote and
the default branch stayed on the broken dependency set at the end of the round.

#### Round 13 (2026-10-09): creative adversarial angles, the final round

Seven personas on the tree of round 12: the patient insider, the cross-system adversary, the chain
itself, the social engineer of the runbook, the economic outsider with no keys, the liveness killer and
the reviewer's adversary. No Critical, High or Medium; the three contracts are unchanged (guard 23,224
bytes, timelock 8,191 bytes). Every finding is a Low or an Info outside the contracts, all applied in
this tree. A NAV band that is present but vacuous (`[1, 2^256-2]` lints valid and skipped the funding
gate, which fired only for `"unconstrained": true`) is now gated at its first sync against the vault's
live `totalAssets()` and warned about offline (G13a-1). Lagoon's access check reads an external
sanctions list and Lagoon's fee registry on the admitted path, so a key outside the Safe and the guard
can turn a guard-admitted claim into a denial, and Lagoon's registry owner sets the protocol's cut of
every settlement's manager fee (G13b-1, G13b-2); the governance Safe swapped one owner during round 12
and now shares two keys with the curator Safe, not three (G13b-3, G13g-3), and upgrades the strategies
directly (G13b-4). The compromised-signer page of §7.7 fired identically on a keyless garbage-signature
revert, and the documented reflex to it voided pre-staged emergency approvals (G13d-1, G13d-2). The
test EVM was two forks behind mainnet, the transaction gas cap is invisible to anvil and forge, reorgs
were undocumented and an L2 deployment would read a different clock (G13c-1 to G13c-4: an `osaka`
profile and CI step, §7.2, §6, §7.7). A proposer can flood the timelock with operations that never
expire, a swarm of uncapped deployment-wide guardians outlives an incomplete eviction, and
`updateDelay(1 hours)` collapses the veto's window on every later operation to one hour (G13f-1 to
G13f-3: the queue print names a burst, §6 and §7.6 the enumeration; the one-day floor stays a held
decision with this round's evidence). A settlement batch the signers confirmed and nobody executed is
an option anyone exercises at a stale mark, and one outsider holding half a band's width keeps a public
vault out of band for free (G13e-1, G13e-4: the `SettlementDeadline` helper of §5, and whitelist mode
before any band on a public vault in §8). The review itself: §5 and §7.2 still described the applied
G12c-1 as pending, the held NAV-gate diff reads deployment records this repository does not have, and
the review log stopped one round early (G13g-1, G13g-2, G13g-4). Chained, every held item executed on
the production topology moves no custody and is undone in one round at the lowered delay
(`G13g_HeldChain`). Adopted suites: `G13b_CrossSystem`, `G13c_Chain`, `G13e_Outsider.e2e`,
`G13f_Liveness`, `G13g_HeldChain` (20 tests, 14 of them on forks of the live vault and Safe). The
cheapest path to custody, every lens agreeing: today, two of the four curator keys, since the guard is
not installed; installed and funded, the council's quorum plus two curator keys in one block, or two
curator keys plus the proposer quorum and a missed veto window. Held for the owner, with the round's
second opinions: G9a-1, G9a-3/G9c-3, G9e-1, G9f-10 and G10f-2 apply (unanimous across rounds 10 to
13); `MIN_DELAY_FLOOR = 1 days` apply (six of six this round); G11b-6 apply only with G13g-2's companion
diff and a `totalAssets()` component kept; the optional cap on deployment-wide guardians (G13f-2b);
G9c-1, G9b-2, G10a-1 and G10a-2 leave; G10d-1 at funding. Residual, outside this repository: the
reviewed tree is uncommitted and the audited commit not on the remote; the ground truth of §1 moves
while a round runs, so re-read it the day the audit prompt goes out.

#### Round 13 follow-up (2026-10-10): two held code decisions applied in one commit

The owner applied two of the held items and nothing else of the contracts changed. G9a-1: `_refuseForwarded()`
is the first statement of `executeBefore`, so the one re-dispatcher the guard has refuses a caller whose
fallback handler is this guard (`Unauthorized`) before it delegatecalls anything; a forwarded after-hook can
no longer be run at its canonical length to forge a `TransactionChecked` inside a window (+8 bytes). G9a-3 /
G9c-3: the same rail is the first statement of `_acceptDefaultAdminTransfer`, behind OpenZeppelin's identity
check, so a stranger cannot complete a hand-over on behalf of a pending-admin Safe whose handler is the guard
and the outgoing admin keeps its late cancel (+8 bytes). G13f-3: `MIN_DELAY_FLOOR` on the timelock is one day
instead of one hour (+4 bytes): the constructor, the proposal-time rail on a scheduled `updateDelay` and the
read-time clamp all move, so a compromised proposer can no longer shrink the veto's window on every later
operation to an hour; the live default delay (48 h) and the admin delay (3 d, strictly above it by the deploy
script's rule) are unchanged. Sizes: guard 23,240 bytes (352 under the gate), timelock 8,195 bytes; the build
pin (`G12a_BuildPin`) asserts the new stripped keccak hashes (`c8e0a908…` / `b7790f42…`; sha256 `2ef656ec…` /
`90bb0171…` in its comment). With the code: the
access-matrix generator's expectations for the two rails and the floor and the six regenerated `G12e_*`
suites (the timelock surface gained a `schedule(updateDelay(1 day))` cell), the round-9 proof-of-concept
suites flipped into pins of the refusal (`G9a_ForwardedExecuteBefore*`, `G9c_Handover`, `G10e_Monitoring`,
`G11g_Evidence`), the held-fix pins for the two rails (`G10f_HeldFixPins`, four tests), and every test that
built or scheduled a one-hour timelock moved to a day (`CuratorGuardRound6`, `CuratorGuardRound8Timelock`,
`CuratorGuardV2`, `G10a_TimelockInvariants`, `G10d_Proposer`, `G10f_Pins`, `G11c_TimeBoundaries`,
`G13f_Liveness`, `G13g_HeldChain`). Still held: G9e-1 (the sync task executing hand-scheduled approvals behind
`--confirm-sensitive`; §7.2 and §7.5 still route those through a hand-built `execute`) and G9f-10 (a fuzz seed in
CI), both "apply" in every round and not in this commit; G9c-1, G9b-2, G10a-1, G10a-2 (leave), with their G10f-2
pins outside the repository; G10d-1 (at funding); G11b-6 with G13g-2 (apply together, keep a `totalAssets()`
component); G13f-2b; and the deployment of the settlement-deadline helper.
Suite after the change: 120 suites, 2,257 tests pass without an RPC (four fork
suites skip), 31 fork tests at a settled head and at the CI pin, the deep invariants 32/32, the corpus 121,
the fork drill complete, the Osaka profile identical. (The first verification run after the change
failed one test, `G10d_Proposer`'s residual of the one-hour lever, flipped before the commit; the second run
is the committed tree's, review G14e-8.)

#### Round 14 (2026-10-10): the follow-up commit under the microscope

Seven lenses on commit `4892722` (the diff and the bytecode, the rails' semantics, the floor and every clock, the
tests of the change, comments and docs, tooling and CI, the adversary of the change). No Critical, High or Medium;
the three contracts are unchanged (guard 23,240 bytes, timelock 8,195 bytes; two NatSpec precisions proven
zero-byte, review G14e-5). Every byte of the delta is accounted for (two 8-byte jump sequences into
`_refuseForwarded`, four widened constants, relocated tags and data offsets; hardhat equals foundry after the
metadata tail; the timelock's creation code also moved by one byte, which the runtime pin does not cover, review
G14a). The rails serve every legitimate caller and refuse every forwarded one on every route, under two gas sweeps
of 5,379 limits each (review G14b); every mutant of the two rails and the floor is killed, one order variant of
the acceptance rail now pinned (review G14d-1); the floor moves its three sites together and every strict ordering
survives, with one new equality: the timelock's floor, the admin delay's floor and the lockdown cooldown are all a
day, so at the floors an UNCHAINED cancel of a hostile hand-over is a one-second race while the CHAINED cancel of
§7.5 wins at any delay (review G14c-3, G14g-2). Lows and Infos, all applied in this tree (0 bytes of guard code):
the deploy script's floor mirror and message with §7.1 and the §10 line (G14a-1, also G14c-1, G14f-1, G14g-1); the
§7.8 repair column for a role-holding or pending-admin Safe (G14b-1); `verify --manifest` prints the time by which
the proposer must execute (G14c-2); the governance summary prints both live delays and warns when they are not
strictly ordered, with §6 and §7.5 (G14c-3); stale sentences in §4, §7.8, §10, §13.2 and the README, the held list
corrected to include G9e-1 and G9f-10 (G14e-2, G14e-3); the generator's D14 text (G14e-4; the documentation table's line citations stay those of 830824e, as its header says); the flipped
suites' titles (G14e-7); `.gitignore` for the generator's `out/` and the regeneration command (G14d-2);
`--execute --op` counts `enforce` as a lift only on a configured Safe, with §7.2 (G14f-5); the first verification
run's failure named (G14e-8). Adopted suites: `G14b_RailSemantics` (19 tests), `G14b_DocsRecipe` (1),
`G14c_Clocks` (5), `G14g_HeldChain2` (3) and one test in `G10f_HeldFixPins`. Suite: 124 suites, 2,286 tests pass
without an RPC (four fork suites skip), 31 fork tests at a settled head and at the CI pin, the pre-Cancun test,
the corpus 121, the fork drill complete, the Osaka profile identical. Held, with the round's second opinions:
G9e-1 and G9f-10 apply (seven of seven, still held by the owner); G9c-1, G9b-2, G10a-1 and G10a-2 leave (seven
of seven); G10d-1 at funding; G11b-6 with G13g-2 and a `totalAssets()` component (seven of seven); G13f-2b leave
until measured (six of seven); the settlement-deadline helper at a public vault's funding. Residual, outside this
repository: the audited commit is not on the remote, the default branch stays on the broken dependency set, and
the repository's workflow has never run with the fork secret set, so no run of it has ever passed (review g15e).

#### Round 15 (2026-10-10): cross-cutting analysis of the whole tree

Seven lenses on the tree of round 14, each cutting across the contracts, the tooling, the policy, the tests,
the docs and the runbook at once. No Critical, High or Medium; the three contracts are unchanged (guard 23,240
bytes, timelock 8,195 bytes). The lifecycle ran end to end on a fork through the deploy script, the three
tasks and the runbook's commands as written, with genuine Safe transactions on the live curator and
governance Safes: every contract step did what the runbook says (G15a). Every property round 12 proved holds
on the final code, and the two rails and the floor are now proofs on the production guard and a one-day
timelock: no forwarded caller reaches `executeBefore`'s delegatecall or completes an acceptance for any
deadline, payload and time; no scheduled `updateDelay` outside [1 day, 30 days] is proposed, stored or read;
the timelock's role rails complete at the floor, which round 12's engine artefact had prevented (G15b). The
change-impact matrix of the 45 changes applied since 830824e (1,081 cells) found six conflicts, none in the
contracts: the held tooling diffs had rotted against the applied tree and were rebased (G15c-1, G15c-2, still
held), the signer-side verify paths silenced the band gate's warnings (G15c-3), and the settlement-deadline
helper's designed `GS013` had no class in §7.7 (G15c-4). 702 mutants of the final code: every mutant of the
rails and the floor killed by the unit suite; six genuine gaps of the warm unit suite (the probes' forwarded
gas, the timelock probe's shape, the live-delay clamp, the v1.3.0 proxy hash offline, the held G9b-2's
observability) now have killers in the tree (G15d). The audit package reproduces to the byte from a fresh
clone, and is not ready to send for reasons outside the tree: the commit is unpublished, the repository has
never held the fork secret so no CI run has ever passed, and the prompt's sentence on the held items was
false as worded (G15e: a corrected prompt and a review-material manifest in the review material). The threat
model re-derived from the code agrees with §6 on every custody and freeze path; §2's rule-model sentence was
stale, §6 listed v1's self-deadlock as blocked, and the two shared keys are priced against the proposer lane
where the undelayed strategy upgrade is the cheaper lever (G15f). Monitoring: §7.7's classify rule had not
caught up with the rails, a proposer probing the floor left no scheduled operation to page on, the G13e pages
lived only in §6, and the two-delay print armed two days late (G15g). Applied, 0 bytes of guard code: the
tooling (the log-scan anchor after a hand-over, the band exemption's slack and rounding, one-off operations
named, sixteen Lagoon and proxy-admin signatures in the sensitive list, the verify paths' warnings, the
`--allow-pending` list cap, the `NAV_FAMILY` exemption scope, the pending admin delay compared), the docs
(§2, §5, §6, §7.2, §7.5, §7.7, §10, this entry), the README, and the adopted suites `G15c_CancelGas`,
`G15d_ProbeGas`, `G15d_ProxyHashes`, `G15d_HeldPins`. Suite: 129 suites, 2,293 tests pass without an RPC, 31
fork tests at a settled head and at the CI pin, precancun, the corpus 121, the drill, the Osaka profile
identical. Still held, unchanged: G9e-1 (now as the rebased G15c-2), G9f-10, G9c-1, G9b-2, G10a-1, G10a-2,
G10d-1, G11b-6 with G13g-2 (now as the rebased G15c-1), G13f-2b, the settlement-deadline deployment.

#### Round 16 (2026-10-10/11): adversarial, with the follow-up known; the last of the three final rounds

Seven adversaries who had read everything, the follow-up included. No Critical, High or Medium; the three
contracts are unchanged. One Low is a contract hardening left to the owner: the forwarded-caller probe compares
the raw 32-byte handler word with the guard's address while the EVM masks the forwarded call target to 160
bits, so a role-holding Safe's own quorum could plant a dirty-high-bits handler word by a storage-writing
delegatecall and hand its role to any stranger (never a forged report, never custody; the tooling already
masks and flags such a handler); masking the word costs 9 bytes in each contract, proven and reproduced
(G16d-1). Everything else applied is zero bytes. The insider who read the follow-up found that the chained
cancel of a hostile hand-over wins only when scheduled bare and behind the last hostile rung (G16a); the time
attacker measured the general law (a cancel scheduled within the admin delay of the hostile scheduling wins,
chained or not), the admin's no-council lift at the delay plus the signing round, and a deploy rule that
accepted a one-second margin in silence (G16b); the economic adversary found that a look-alike deadline helper
synced without a word, that the band gate had two escapes (an empty vault, a fixed-mark set) and that the
band-move print could read as the opposite of what happened, and priced a ±50 % band at 26.8 % of NAV per
colluding cycle (G16c); the multi-guard lens confirmed the rails across instances (G16d); the chain lens
bounded the rails' one gas dependency (a repricing would have to make the probe 64 times dearer than the hook)
and measured the transaction cap at 179 wrapped entries on an Osaka node (G16e); the liveness lens re-ran every
recovery at the floor, found none slower except by the cooldown's inclusive edge, measured the one-knob
rollback window at the deploy defaults, and left a delay-parameterised recovery matrix now run at the floor in
CI (G16f); the reviewer's adversary found the rebased hand-scheduled-approvals diff rotted again, measured the
guardian cap at +181 bytes, and filed six unanimous zero-byte items that had fallen between the lists, four of
which are now in the tree (G16g). Applied: the tooling (the helper's runtime checked against the repository's
artifact, the band gate on empty vaults and fixed-mark sets, the band print around the live NAV with its
per-cycle price, the wrapped-cancel and dead-seat tags, the pending admin delay and a one-day margin in the
ordering checks, the drill's per-run temp directory), the docs (§5, §6, §7.1, §7.2, §7.5, §7.7, §10, this
entry), the README, the CI step for the recovery matrix at the floor, and the adopted suites
`G16a_Insider`, `G16b_TimeAttack`, `G16b_ModulePathEdges`, `G16c_PolicyEconomics.e2e`, `G16e_ChainCompiler`,
`G16f_RecoveryMatrix`. Suite: 134 suites, 2,332 tests pass without an RPC, 38 fork tests at a settled head and
at the CI pin, precancun, the corpus 121, the drill, the Osaka profile identical. Still held: G9e-1 (as the
round-16 rebase), G9f-10, G9c-1, G9b-2, G10a-1, G10a-2, G10d-1, G11b-6 with G13g-2 (as the round-15 rebase),
G13f-2b (+181 bytes, measured), G16d-1 (+9 bytes each, recommended), the settlement-deadline deployment, the
symbolic suites' adoption.

#### After the three final rounds (2026-10-11)

Rounds 14, 15 and 16, 21 reports, all "install as shipped": the follow-up commit is exactly the three
statements it claims, proven on the production contracts, killed under mutation, consistent across every
part of the tree, and attacked from seven more angles without a path to custody or to a frozen governance.
The cheapest path to custody is unchanged since round 5: two curator keys through the NAV mark, today the same
two keys that sit on both Safes. What is left is the owner's: the held list above, the package (publish the
commit, set the fork secret, make the default branch equal, one green run), and the governance moves of §8.

#### Round 17 (2026-10-11): fresh eyes, the first of the two closing rounds

Seven reviewers read the repository cold, before the record: the contracts from the sources alone (g17a),
the tooling as code (g17b), the tests as a system (g17c), the policy and the lint against the live code
(g17d), the documentation as a product (g17e), the runbook as a new operator (g17f) and the adversary with
fresh eyes (g17g). All seven say "install as shipped"; none found a Critical, High or Medium in the contracts,
and the one Critical named (g17g) is the NAV lever the record holds by design. The cold contract reader built
PoCs on the real v1.4.1 and v1.5.0 Safe builds and found the design holds under every attack constructible
from the sources; it made the NatSpec precise (the admin window is a full bypass whose reports are not
authoritative, and it relaxes top-level entries only; comment-only, identity unchanged), named that on a
v1.5.0 Safe with an allowlisted module a module-bound council approval rotates owners with no signer at all
(§4, §6; the +63-byte rail that would refuse it is held, since it would also remove the council's signer-free
recovery of a Safe whose signers are lost), and that an approval of a value to the zero address is accepted
(the tooling now says so wherever an approval is read; the +18-byte rail is held). The tooling reader found two
Medium items in the tooling and zero bytes of guard code: one queued operation with a deadline beyond the year
275760 (a uint64 the proposer chooses) killed the queue print of every sync, `verify --op` and the
post-execute print with a bare RangeError (now printed as the raw number), and the NAV go-live gate read
`totalAssets()` under a catch that treated a rate limit or a timeout as "not a vault" and vanished without a
word (now a transport failure throws, on the sync and on both verify paths); plus a bound on an `address` or
`bool` word that counted as a rule for the allowance table (refused, with a ceiling at a `uintN` word's full
width), the state file's `lifts` and `preparedAt` believed verbatim on `--execute` (re-derived; the earlier of
the file's time and the `CallScheduled` block decides; the Safe checked), a call's value ignored by `verify
--op`, lint markers for the escape hatches, and `.env.example`. The test reader ran CI's exact first step
under the pinned forge 1.5.1 and found `forge test -vvv` fails fifteen tests through a tracer artefact (a call
that reverts with no data is handed an ABI-encoded "call to non-contract address" string whenever traces are
recorded; reproduced by the integrator; the step now runs without traces and re-runs failures with them),
moved the starvation sweeps' logs before their asserts, measured that no lcov exists under any flag (Safe
v1.4.1's `execTransaction` is too deep under `--ir-minimum`) and killed 16 of 16 one-line mutants with the
non-invariant suites alone. The policy reader rebuilt the live implementation from Sourcify byte-identical to
the v0.6.0 sources, re-ran the lint-versus-guard differential on the final tree (2,842 vectors, 997 through
the real Safe, zero mismatches) and closed the tables against the live code: the vault's own receiver-carrying
entry points (`syncDeposit`, `syncRedeem`, the four-argument `requestDeposit`), the council's and the
whitelist manager's levers and `DelayProxyAdmin.updateDelay()` as markers, hemiBTC's LayerZero `send`, and a
`OneOf` set beside a bound none of its members satisfies (refused as a dead function); §1 now says who can
change each custody asset's code. The documentation reader checked every number, hash, selector, slot,
address, cap and command against the tree and the chain (all true; §10's counts and a few contradictions
fixed; a restructuring proposal left for the owner). The new operator took a fresh clone to exit in fourteen
minutes of execution and fixed the five prints and sentences that misled (queued rules read as words, the
empty-guard-slot warning, refusals as one-line errors, the first-band note, §7.2 / §7.8). Applied: the tooling
and docs above, the CI step, the corpus (129 cases), the adopted suites `G17a_Cold` and `G17a_ColdV150`.
Suite: 136 suites, 2,350 tests pass without an RPC, 38 fork tests at a settled head and at the CI
pin, the recovery matrix at the floor, precancun, the drill, the Osaka profile identical; identity 2ef656ec /
90bb0171 unchanged. Still held: G9e-1, G9f-10, G9c-1, G9b-2, G10a-1, G10a-2, G10d-1, G11b-6 with G13g-2,
G13f-2b, G16d-1 (+9 bytes each, recommended by all seven), the settlement-deadline deployment, the symbolic
suites' adoption, and the two new optional rails G17a-2 (+63 bytes, lean leave) and G17a-3 (+18 bytes).

#### Round 18 (2026-10-11): closure, the last round of the series

Seven reviewers checked the record against the tree it describes and the package as an auditor will receive
it: the record reverse-applied against the tree (g18a), the properties re-run with the held handler-word mask
proven on both the shipped and the masked code (g18b), the lint against the guard differentially on the final
lint (g18c), the monitor and every runbook section on a fork (g18d), the audit package on a fresh clone with
every CI step in order and GitHub read (g18e), every held item applied alone and all together on scratch
copies with a decision table (g18f), and the reviewer's adversary auditing round 17's integration and the
series' blind spots (g18g). All seven say "install as shipped"; nothing changed in the contracts (identity
2ef656ec / 90bb0171 / e22116e1 re-derived in both toolchains by three lenses). What the round found was in
the record and the tooling, not the design: three round-16 tooling prints the record counted as applied had
never reached the tree (a verbatim diff of that round carried their removal on its minus side; found by four
lenses independently) and half of a round-17 lint warning had been lost in a hand merge; both are restored,
with the hand-over cancel and the delay rollback now role-sensitive in the queue print. The differential lens
ran 1,716 policies and 43,911 vectors, 17,083 of them through the real Safe, with zero divergences between
the lint, the guard and the dry run, and left four zero-byte refinements (the per-cycle price printed for a
fixed mark set the gate admits, a warning for a settles-only band, the guard refused in every list before a
direct sync sends anything, the restored warning). The package lens found GitHub's `main` to be a different
tree (five Dependabot merges, OpenZeppelin 5.4.0 among them, that the branch does not carry): making it equal
to the reviewed commit must be a force-push, never a merge, and the final prompt says so. The adversary added
the one check that sends the audited bytes (the deploy script now refuses an artifact whose stripped runtime
does not hash to the reviewed pins, measured through the real script on a fork), kept CI's traced rerun red on
a real failure, named the one path no round ever executed (the Transaction Service proposal and the Etherscan
verification; §7.2 now says to rehearse it once with a throwaway Safe), and left a one-page summary for the
auditor. The drill now schedules an operation with the largest uint64 deadline and checks that the prints
survive and the veto cancels it. The held list is unchanged, with every held tooling diff rebased on this tree
and run on a fork, and the decision table measured per item: the handler-word mask costs 9 bytes in each
contract and flips only the two size pins; the whole list applied at once would sit 32 bytes under the gate
with twenty tests flipping, so it is never landed together. Applied: the tooling, deploy script, CI, drill and
docs above, the corpus (130 cases), the helper's NatSpec (v1.5.0 bubbles the reason v1.4.1 reports as GS013),
the monitor variant of the review material. Suite: 136 suites, 2,350 tests pass without an RPC, 38
fork tests at a settled head and at the CI pin, the recovery matrix at the floor, precancun, the drill with
its new step, the Osaka profile identical; identity unchanged. Still held: G9e-1 (as the round-18 rebase),
G9f-10, G9c-1, G9b-2, G10a-1 (as the round-18 rebase), G10a-2, G10d-1, G11b-6 with G13g-2 (as the round-18
rebase), G13f-2b, G16d-1 (+9 bytes each, proven and recommended by every reviewer of rounds 16 to 18), G17a-2,
G17a-3, the settlement-deadline deployment, the symbolic suites' adoption (as the round-18 rebase).

#### After the two closing rounds (2026-10-11)

Rounds 17 and 18, fourteen reports, all "install as shipped": the repository read cold by seven reviewers who
had never seen the record found no path to custody or to a frozen governance that the record did not already
hold, and the closure round found the record true of the tree in everything but four zero-byte prints, now in
place. The three contracts have not changed by a byte since the follow-up commit 4892722. The cheapest path to
custody is still two curator keys through the NAV mark on a funded public vault. What is left is the owner's:
the held list with its decision table, the package (commit this tree, push the branch, force `main` to the
hash, set the fork secret, one green run, send the prompt with the manifest and the one-page summary), the
first rehearsal of the proposal path, and the governance moves of §8.

#### Round 18 follow-up (2026-10-11): four held items applied at the owner's decision

After the rounds 17 and 18 commit was pushed, the owner asked for the recommended held items. Applied: G16d-1
(the forwarded-caller probes of both rails compare the handler word's low 160 bits, as the EVM masks a call
target: +9 bytes in each contract, guard 23,249 bytes and timelock 8,204 bytes, sha256 `7b7cc641…` /
`a43ecad6…`, keccak `a1cc0159…` / `8a69e72c…`; the build pin re-pinned with the diff round 18 measured, the
deploy script's reviewed-build pins moved with it, the NatSpec of both probes says what is compared; g18b's
concrete suite adopted with the masked expectations as `G16d_DirtyWord`, and the access matrix gained a
dirty-word class that must answer exactly as the clean-word class does, which its first regeneration showed
only after the generator's hook mapping learned the new key); G9e-1 F1 (the sync task executes an operation
named with `--op` that carries calls no sync produces, exactly as named, behind `--confirm-sensitive`, and the
queue print tags every such call `[NOT A SYNC CALL]` beside the role-sensitive and round-18 tags; the round-18
rebase, its two hunks under the round-18 help text and the restored tags merged by hand); G11b-6 with G13g-2
(the unconstrained-NAV gate reads the Vesper strategies' debt behind each vault from the address book, keeps a
`totalAssets()` component and the transport rail on every read; the round-18 rebase, clean); G9f-10 (one pinned
fuzz seed on CI's first test step, the Osaka step unseeded). Not applied: G17a-3 (optional), G17a-2, G9c-1,
G9b-2, G10a-1, G10a-2, G13f-2b (leave), the symbolic suites' adoption (the owner's call), the approve cap and
the settlement-deadline deployment (at funding). Suite: 138 suites, 2,448 tests pass without an RPC (the matrix
1,740), 38 fork tests at a settled head and at the CI pin, the recovery matrix at the floor, the seeded step,
precancun, the drill with its debt-gate lines, the Osaka profile identical. Rounds 19 and 20 review this tree.

#### Round 19 (2026-10-11): the four applied held items under the microscope

Seven reviewers took the tree with the owner's four decisions applied: the mask byte by byte (g19a), the
properties with the mask (g19b), the confirm path end to end (g19c), the debt gate (g19d), the matrix and the
adopted suite (g19e), the integration audit (g19f) and the adversary after the mask (g19g). All seven say
"install as shipped"; nothing in the contracts, and the cheapest paths to custody and to a frozen governance
have not moved. The mask is exactly one AND insertion per contract with every jump target shifted by nine
bytes, identical in both toolchains, and holds as a property over every 256-bit handler word on twelve routes
of both rails for both Safe builds, with the unmasked contracts as the witness (0 of 24 there); the dirty-word
matrix class is right in all 760 cells and a mask-removal mutant flips 30 tests. The one Medium was in the
tooling, found by two lenses independently: a doubly wrapped `executeBefore` still executes its inner call as
the admin (the delegatecall to self keeps the caller) while the queue print, `verify --op` and the confirm
print rendered the inner call as opaque bytes under a bare "not a sync call" tag; the decoder now unwraps
level by level, tags the innermost call and the nesting, and the execute path refuses a nested operation.
Applied, all zero bytes of guard code: that fix, a call's value judged on the confirm path, one `lifts`
expression for both execute paths, the debt gate classifying a strategy's reverting read as custody and a
transport failure as a named throw (a Panic on `tvl()` no longer kills every print) with a guard on the
address book's key, the flag's text and §5 / §7.2 naming the debt trigger, two older probe copies brought to
the masked predicate, the generator's and parser's counts, the build pin's lineage comment, the §10 and §7.2
wording, the Osaka profile's comment, and the adopted suites `G19a_Mask` (the EVM-level proof of the mask on
every route), `G19e_DigestDirty` (the raw compares that remain and fail closed: the digest is byte-exact, a
dirty guard or module-guard word is a full stop), `G19g_NestedWrap` and `G19g_CouncilHandler`. The prompt,
the manifest and the one-page summary carry the tree's sizes and counts. Suite: 143 suites, 2,476
tests pass without an RPC, 38 fork tests at a settled head and at the CI pin, the recovery matrix at the
floor, the seeded step, precancun, the drill, the Osaka profile identical; identity unchanged since the mask.
Still held: G17a-3 (optional), G17a-2, G9c-1, G9b-2, G10a-1, G10a-2, G13f-2b (leave), the symbolic suites'
adoption (the owner's call; the proofs of the mask join them in the review material), the approve cap and the
settlement-deadline deployment (at funding).

#### Round 20 (2026-10-12): final closure of the final tree

Seven reviewers closed the series on the tree with the owner's four decisions and round 19's fixes applied: the
record against the tree (g20a), the properties (g20b), the lint against the guard (g20c), the monitor and the
runbook (g20d), the audit package (g20e), the remaining held list applied (g20f) and the reviewer's adversary
last of all (g20g). All seven say "install as shipped"; nothing in the contracts, nothing above Low anywhere,
and every Low is a print, a comment or a sentence. The record is true of the tree: forty-nine applied diffs
reverse-apply or are accounted for hunk by hunk, every pin agrees in both toolchains, the matrix regenerates
byte-identically, every held row's diff applies where the manifest says. The properties of rounds 12 to 19 give
exactly their recorded verdicts, and two new ones hold on both Safe builds: a nested wrapper executes its inner
call as the admin exactly when both deadlines are unexpired and the caller is not forwarded, with the rail
re-firing at every level, and the configuration digest is byte-exact (a change of the handler word's high bits
alone between the hooks is a refused change). The lint-versus-guard differential found zero divergences over
48,624 vectors with 19,086 executed through the real Safe, the sync's emitted calls exactly the eleven of its
set. The monitor caught every incident class and every signature of rounds 16 to 19 and the five new ones, and
the runbook ran as written, the confirm path and the debt gate included. A fresh clone with the working tree
overlaid rebuilt to the pinned bytes and passed every CI step in order under the pinned forge. Each remaining
held item re-measured on this tree flips exactly its documented tests, and the whole list at once would still
sit 32 bytes under the gate with 19 flips, so it is never landed as a set. Applied, all zero bytes of guard
code: the sync's list pre-check no longer claims a contract rule that does not exist (the contract accepts the
admin in every list), the address book is read only when a NAV entry is judged, two prints reworded, the verify
verdict names a hand-built narrowing or a nested wrapper, a sibling guard's operations are decoded rather than
called foreign, the deploy script's re-run uses the recorded guard's admin and never deploys an orphan timelock
(§7.1 says to commit the deployment records), the drill pins the nested wrapper's tags and refusal and the debt
gate's clause, the CI comment counts sixteen traced failures (the dirty-word class added one), the monitor
variant of the review material unwraps to a fixed point and polls every role Safe's raw handler word, §7.5 and
§7.7 name the nested wrapper and the raw-word poll, §10's header carries the tree's counts, and the two forge
twins of the new properties are adopted. Suite: 147 suites, 2,510 tests pass without an RPC, 38 fork
tests at a settled head and at the CI pin, the recovery matrix at the floor, the seeded step, precancun, the
drill, the Osaka profile identical; identity unchanged since the mask.

#### After the twenty rounds (2026-10-12)

Rounds 9 to 20 on this repository, 88 reports, every one since round 9 "install as shipped": one Medium
contract fix landed in round 10, two rails and a one-day floor in the round-13 follow-up, the nine-byte
handler-word mask at the owner's decision after round 18, and nothing else in the bytecode. The three contracts
are the pinned runtimes of §10; everything around them was rehearsed on forks with the review's own toolchain.
The cheapest path to custody is outside the guard by design: two curator keys through the NAV mark on a funded
public vault, which §8 and the sync's gate are built to bound. What remains is the owner's: the held list with
its decision table, the package (commit this tree, name the hash, force `main` to it so the workflow can run, set
the fork secret, one green run, send the prompt with the manifest and the one-page summary), the first rehearsal
of the proposal path, and the governance moves of §8.
