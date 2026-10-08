import fs from "fs";
import chalk from "chalk";
import { FunctionFragment, ParamType, getAddress, isAddress, keccak256, toBeHex, zeroPadValue } from "ethers";
import type { Contract, EventLog, Interface, Log } from "ethers";
import { task } from "hardhat/config";
import type { HardhatRuntimeEnvironment } from "hardhat/types";
import { SAFE_BATCH_TXS_FILE, executeBatchUsingSafe, saveForSafeBatchExecution } from "../helpers/safe";

/// Reconcile a `CuratorGuard` policy for one Safe against a JSON policy file (see
/// policies/curator-guard/*.json and docs/curator-guard.md). Computes the diff between the on-chain
/// policy and the file and applies it as the guard's ADMIN (`DEFAULT_ADMIN_ROLE`):
///
///   - signer == admin (or the admin impersonated on a fork network): the calls are sent directly;
///   - admin == a `TimelockController` (production): every call is wrapped in
///     `executeBefore(deadline, call)` and the batch goes into ONE `scheduleBatch` sent by a proposer
///     (`--proposer`, directly when the signer holds `PROPOSER_ROLE`, otherwise queued as a Safe batch
///     for the proposer Safe). A batch that LIFTS a lockdown / Bypass is split in two operations (the
///     lift alone, chained behind the rest with `predecessor`): the guard holds the admin's lift back
///     for `LOCKDOWN_COOLDOWN` after any lockdown, and bundled with the rest it would take the whole
///     batch down with it. After `minDelay` anyone runs the same command with `--execute`. The salt
///     carries a counter, so a repeated diff schedules a NEW operation; the ones in flight are
///     persisted per chain + guard (next to the Safe batch file) and `--execute` replays exactly them,
///     re-deriving every operation id from the stored payloads (or rebuilding them from the timelock's
///     own `CallScheduled` logs with `--op`), refusing a drifted diff, a passed deadline or an
///     operation the proposer never scheduled.
///
///   npx hardhat curator-guard-sync --network ethereum \
///     --guard 0x... --policy policies/curator-guard/vetro-lagoon.ethereum.json \
///     [--dry-run] [--allow-unlock] [--confirm-revocations] [--confirm-loosening] [--proposer 0x...] \
///     [--execute [--op 0x...]] [--via-timelock] [--deadline-days 14] [--unlock-deadline-days 1] \
///     [--allow-pending] [--allow-large-batch] [--timelock-block N]
///
///   npx hardhat curator-guard-lint --policy <file>          # offline: shape, rules, caps
///   npx hardhat curator-guard-verify --network ethereum --guard 0x... --policy <file> --op 0x...
///                                                           # second pair of eyes on a queued operation
///
/// The file is the full desired state: anything on-chain that the file does not list is revoked.
/// `mode` may only be `Lockdown` or `Enforced`; `Bypass` is an incident action taken directly on the
/// guard by the council or the admin, never part of a desired-state sync. Moving a Safe out of
/// `Lockdown` / `Bypass` needs `--allow-unlock` so a routine widening cannot silently end an incident.
/// The validator is strict (unknown keys, wrong types, non-canonical signatures, selector collisions
/// with well-known functions, unbounded or vacuous bounds, rules on dynamic words, allowance-shaped
/// selectors without a rule all abort) and mirrors the contract-side limits; every call is also
/// simulated as the admin before it is scheduled, so a batch is not signed dead on arrival.

type RuleKind = "EqualTo" | "EqualToSafe" | "OneOf" | "LessThanOrEqual" | "GreaterThanOrEqual";
const RULE_KINDS: RuleKind[] = ["EqualTo", "EqualToSafe", "OneOf", "LessThanOrEqual", "GreaterThanOrEqual"];
const UPPER_BOUND_KINDS: RuleKind[] = ["LessThanOrEqual", "EqualTo", "OneOf"];
const LOWER_BOUND_KINDS: RuleKind[] = ["GreaterThanOrEqual", "EqualTo", "OneOf"];
/// Desired-state modes. The contract also has `Bypass` (enum value 2), which the file may not request.
const MODES = ["Lockdown", "Enforced"] as const;
const CHAIN_MODES = ["Lockdown", "Enforced", "Bypass"] as const;
type Mode = (typeof MODES)[number];

// Mirrors `CuratorGuardPolicy.MAX_RULES` / `MAX_ALLOWED_VALUES` / `MAX_SELECTORS` / `MAX_GUARDIANS` /
// `TAIL_FLAG` / `LOCKDOWN_COOLDOWN`.
const MAX_RULES = 16;
const MAX_ALLOWED_VALUES = 128;
const MAX_SELECTORS = 32;
const MAX_GUARDIANS = 32;
const TAIL_FLAG = 0x8000;
const LOCKDOWN_COOLDOWN = 86_400n;
// Joint caps on `OneOf` members (IMPROVEMENTS_V2.md item 10, enforced here rather than on-chain). Since
// round 8 revocation abandons the sets in O(1) (generation-keyed), but `clearAllowedValues` and a
// re-allow that drops a `OneOf` rule still iterate every member (≈ 4.3k gas each on committed
// storage), so a policy must stay far below a block: 256 per function ≈ 1.1 M gas.
const MAX_ONEOF_MEMBERS_PER_FUNCTION = 256;
const MAX_ONEOF_MEMBERS_PER_TARGET = 1024;
// The canonical `MultiSendCallOnly` selector: the guard decodes a batch only as an UNWRAPPER
// (delegatecall); allowed as a plain-call FUNCTION the inner entries run from the library's address,
// unchecked, and with `allowValue` the Safe's ETH goes anywhere (review R8I-2). Never a function.
const MULTISEND_SELECTOR = "0x8d80ff0a";
// The Safe proxies and singletons the guard supports, by runtime code hash (mirrors
// `CuratorGuardPolicy._safeCodehashes`): a Safe behind other code is refused on the policy path
// (`SafeNotSupported`), so the sync refuses it before anything is scheduled (review R8G-1 / R8C-6).
const SAFE_PROXY_CODEHASHES = new Map<string, string>([
  ["0xb89c1b3bdf2cf8827818646bce9a8f6e372885f8c55e5c07acbd307cb133b000", "GnosisSafeProxy 1.3.0"],
  ["0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c", "SafeProxy 1.4.1"],
  ["0x4e381985ca68b3e5d27b4425fa581c19cf33146d3f887a3cfca96f55528ea46f", "SafeProxy 1.5.0"],
]);
const SAFE_SINGLETON_CODEHASHES = new Map<string, string>([
  ["0xbba688fbdb21ad2bb58bc320638b43d94e7d100f6f3ebaab0a4e4de6304b1c2e", "GnosisSafe 1.3.0"],
  ["0x21842597390c4c6e3c1239e434a682b054bd9548eee5e9b1d6a4482731023c0f", "GnosisSafeL2 1.3.0"],
  ["0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4", "Safe 1.4.1"],
  ["0xb1f926978a0f44a2c0ec8fe822418ae969bd8c3f18d61e5103100339894f81ff", "SafeL2 1.4.1"],
  ["0xdda019cbd7c867a533a2a86e5c53434fdc50b13122b5a5ddb4a8df61b31c20f2", "Safe 1.5.0"],
  ["0x180193227186ccb85316c94db1f0d156ed932b14712cfaac78901899178572dc", "SafeL2 1.5.0"],
]);
// One scheduled batch is one transaction: EIP-7825 caps a transaction at 16,777,216 gas (Fusaka), and
// a batch above it is signed, waits the delay and then reverts for every executor (review R6C-09).
const BATCH_GAS_WARN = 8_000_000n;
const BATCH_GAS_REFUSE = 12_000_000n;
const MAX_NOTE_LENGTH = 200;
const UINT256_MAX = (1n << 256n) - 1n;
const ZERO_HASH = "0x0000000000000000000000000000000000000000000000000000000000000000";
const selectorOfSignature = (signature: string) => FunctionFragment.from(signature).selector;
// Selectors that move or delegate value through static address words (spender, receiver, controller,
// operator); each listed word needs a rule. Keyed by SELECTOR, so a look-alike signature with the same
// 4 bytes (review R6C-01: `many_msg_babbage(bytes1)` == `transfer(address,uint256)`) cannot slip past.
const ALLOWANCE_LIST: [string, number[]][] = [
  ["approve(address,uint256)", [0]],
  ["increaseAllowance(address,uint256)", [0]],
  ["transfer(address,uint256)", [0]],
  ["transferFrom(address,address,uint256)", [0, 1]],
  ["safeTransferFrom(address,address,uint256)", [0, 1]],
  ["safeTransferFrom(address,address,uint256,bytes)", [0, 1]],
  ["safeTransferFrom(address,address,uint256,uint256,bytes)", [0, 1]],
  ["safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)", [0, 1]],
  ["setApprovalForAll(address,bool)", [0]],
  ["approve(address,address,uint160,uint48)", [0, 1]], // Permit2
  ["permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", [1]],
  ["permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)", [1]], // DAI
  ["deposit(uint256,address)", [1]], // ERC-4626 receivers
  ["mint(uint256,address)", [1]],
  ["withdraw(uint256,address,address)", [1, 2]],
  ["redeem(uint256,address,address)", [1, 2]],
  ["requestDeposit(uint256,address,address)", [1, 2]], // ERC-7540 controller / owner
  ["requestRedeem(uint256,address,address)", [1, 2]],
  ["setOperator(address,bool)", [0]],
  ["send(address,uint256,bytes)", [0]], // ERC-777
  ["operatorSend(address,address,uint256,bytes,bytes)", [0, 1]],
  ["authorizeOperator(address)", [0]],
  ["transferAndCall(address,uint256,bytes)", [0]], // ERC-677
  // Review G9e-2: the shapes docs section 5 tells a policy author to pin, and the receiver-carrying
  // siblings of what was already listed, were accepted without a rule.
  ["deposit(uint256,address,address)", [1]], // ERC-7540 (Lagoon): receiver of the claimed shares
  ["mint(uint256,address,address)", [1]],
  ["transferAndCall(address,uint256)", [0]], // ERC-1363
  ["transferFromAndCall(address,address,uint256)", [0, 1]],
  ["transferFromAndCall(address,address,uint256,bytes)", [0, 1]],
  ["transferFrom(address,address,uint160,address)", [0, 1]], // Permit2
  ["supply(address,uint256,address,uint16)", [2]], // Aave v3 onBehalfOf
  ["withdraw(address,uint256,address)", [2]], // Aave v3 to
  ["supply((address,address,address,address,uint256),uint256,uint256,address,bytes)", [7]], // Morpho Blue onBehalf
  ["withdraw((address,address,address,address,uint256),uint256,uint256,address,address)", [8]], // Morpho Blue receiver
  ["withdrawCollateral((address,address,address,address,uint256),uint256,address,address)", [7]],
  ["borrow((address,address,address,address,uint256),uint256,uint256,address,address)", [8]],
];
// Functions that change who controls a contract or what code it runs: never routine curator work.
// Refused unless the entry carries `"$allowSensitive": true`.
const SENSITIVE_LIST = [
  "transferOwnership(address)",
  "renounceOwnership()",
  "upgradeTo(address)",
  "upgradeToAndCall(address,bytes)",
  "changeAdmin(address)",
  "grantRole(bytes32,address)",
  "revokeRole(bytes32,address)",
  "renounceRole(bytes32,address)",
  "setGuard(address)",
  "setModuleGuard(address)",
  "enableModule(address)",
  "disableModule(address,address)",
  "setFallbackHandler(address)",
  "addOwnerWithThreshold(address,uint256)",
  "removeOwner(address,address,uint256)",
  "swapOwner(address,address,address)",
  "changeThreshold(uint256)",
  "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
  "execTransactionFromModule(address,uint256,bytes,uint8)",
  "approveHash(bytes32)",
];
// Functions whose payload EMBEDS further calls that run as the Safe with no selector check and no rule
// (a venue's own batch / multicall / execute, ERC-1363 callbacks): allowing one voids every sibling
// rule and the selector scoping of that target (review R8A-2). The class has no closed list, so this is
// a marker requirement, not a denylist: `"$allowSensitive": true` says the batch venue was reviewed as
// such (prefer ONE reviewed payload bound by a tail-hash rule, see `tail` below).
const SELF_DISPATCH_LIST = [
  "multicall(bytes[])",
  "multicall(uint256,bytes[])",
  "multicall(bool,bytes[])",
  "multicall(bytes32,bytes[])",
  "aggregate((address,bytes)[])",
  "aggregate3((address,bool,bytes)[])",
  "aggregate3Value((address,bool,uint256,bytes)[])",
  "tryAggregate(bool,(address,bytes)[])",
  "blockAndAggregate((address,bytes)[])",
  "execute(address,uint256,bytes)",
  "execute(bytes32,bytes)",
  "executeBatch((address,uint256,bytes)[])",
  "batch(bytes[])",
  "approveAndCall(address,uint256,bytes)",
  "approveAndCall(address,uint256)", // ERC-1363 two-argument form: the spender's onApprovalReceived runs as the Safe
  "increaseApproval(address,uint256)",
];
// Other signatures the diff prints by name and that a look-alike may not shadow.
const OTHER_KNOWN = [
  "updateNewTotalAssets(uint256)",
  "settleDeposit(uint256)",
  "settleRedeem(uint256)",
  "claimSharesOnBehalf(address[])",
  "claimAssetsOnBehalf(address[])",
  "initiateClosing()",
  "close(uint256)",
  "multiSend(bytes)",
];
const ALLOWANCE_SHAPED = new Map<string, number[]>(
  ALLOWANCE_LIST.map(([sig, words]) => [selectorOfSignature(sig), words]),
);
const SENSITIVE = new Set(SENSITIVE_LIST.map(selectorOfSignature));
const SELF_DISPATCH = new Set(SELF_DISPATCH_LIST.map(selectorOfSignature));
/// Well-known signatures by selector: a policy entry whose selector matches one of these under another
/// name is a collision (ground in seconds) and is refused; the diff and the manifest always print the
/// selector next to the name.
const KNOWN_SIGNATURES = new Map<string, string>(
  [...ALLOWANCE_LIST.map(([sig]) => sig), ...SENSITIVE_LIST, ...SELF_DISPATCH_LIST, ...OTHER_KNOWN].map((sig) => [
    selectorOfSignature(sig),
    sig,
  ]),
);
// NAV-shaped functions (the word that carries a vault valuation), keyed by SELECTOR: the validator
// demands a floor and a ceiling on that word, or an explicit `"unconstrained": true`. A static band
// cannot stop a malicious quorum (marks chain), but it refuses unit mistakes, caps a single mark, and is
// the one NAV control that needs no curator signature (docs/curator-guard.md sections 5 and 8).
const BAND_SHAPED = new Map<string, number>([[selectorOfSignature("updateNewTotalAssets(uint256)"), 0]]);
// Storage slots that reveal an upgradeable target (ERC-1967, the ZeppelinOS legacy slot used by USDC
// and cbBTC, EIP-1822).
const PROXY_SLOTS: [string, string][] = [
  ["ERC-1967 implementation", "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"],
  ["ERC-1967 beacon", "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"],
  ["ZeppelinOS implementation", "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"],
  ["EIP-1822 logic", "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"],
];
const ERC1967_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const SAFE_HANDLER_SLOT = "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5";
// Canonical `CompatibilityFallbackHandler` deployments (v1.3.0 canonical and eip155, v1.4.1, v1.5.0),
// lower-cased: what a governance Safe's handler slot may hold besides zero without a warning.
const CANONICAL_SAFE_HANDLERS = new Set([
  "0xf48f2b2d2a534e402487b3ee7c18c33aec0fe5e4",
  "0x017062a1de2fe6b99be3d9d37841fed19f573804",
  "0xfd0732dc9e303f09fcef3a7388ad10a83459ec99",
  "0x3efcbb83a4a7afcb4f68d501e2c2203a38be77f4",
]);
const SAFE_GUARD_SLOT = "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8";
const SENTINEL = "0x0000000000000000000000000000000000000001";

/// `tail`: the rule binds `keccak256(calldata[4 + 32 * wordIndex:])`, the whole tail from that word
/// (`wordIndex` must be the FIRST dynamic parameter's head word, so every offset word is inside the hash)
/// (offsets, lengths, contents, trailing bytes), instead of the word: the one way to pin a dynamic
/// payload (`EqualTo` one hash, `OneOf` a set). `value` / `values` are then 32-byte hashes, or the raw
/// tail bytes (any other hex length), which the tool hashes. On-chain the flag is bit 15 of `wordIndex`.
type PolicyRule = { kind: RuleKind; wordIndex: number; tail?: boolean; value?: string; values?: string[] };
type PolicyFunction = {
  target: string;
  signature: string;
  selector?: string;
  allowValue?: boolean;
  unconstrained?: boolean;
  $allowSensitive?: boolean;
  rules?: PolicyRule[];
  note?: string;
};
type Policy = {
  /// Optional pins: refused when they do not match the network / the --guard argument. `guard` is
  /// REQUIRED outside rehearsals (a sync against the wrong instance is otherwise one typo away).
  chainId?: number;
  guard?: string;
  safe: string;
  mode: Mode;
  requiredFallbackHandler: { handler: string; enforce: boolean };
  /// Required with `true` when `requiredFallbackHandler` enforces a NON-ZERO handler: that re-opens the
  /// EIP-1271 path, so the handler must be stateless, and a typo there freezes every policy transaction.
  $allowNonZeroHandler?: boolean;
  /// Required with `true` when `requiredFallbackHandler.enforce` is false: the EIP-1271 defence is then
  /// off (a permit / EIP-3009 drain needs no Safe transaction at all).
  $allowUnenforcedHandler?: boolean;
  /// Narrow-only responders for THIS Safe (`setGuardian`), synced as a full set. Deployment-wide
  /// guardians hold `GUARDIAN_ROLE` on the guard and are not managed by this file. A replacement
  /// guard starts with none, so re-sync before switching to it.
  guardians: string[];
  multiSendUnwrappers?: string[];
  modules?: string[];
  nativeTransfers?: string[];
  functions: PolicyFunction[];
};

type OnChainRule = { kind: number; wordIndex: number; value: string };
type Call = { description: string; data: string };
type Plan = {
  calls: Call[];
  lifts: boolean;
  revocations: number;
  loosenings: string[];
  currentMode: (typeof CHAIN_MODES)[number];
};

const lower = (a: string) => a.toLowerCase();
const key = (target: string, selector: string) => `${lower(target)}:${lower(selector)}`;
const iso = (unixSeconds: bigint | number) => new Date(Number(unixSeconds) * 1000).toISOString();
const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

/*//////////////////////////////////////////////////////////////
                              TASKS
//////////////////////////////////////////////////////////////*/

task("curator-guard-lint", "Validate a CuratorGuard policy file offline (no network): shape, rules, caps")
  .addParam("policy", "Path to the policy JSON")
  .setAction(async (args) => {
    const { policy, warnings } = loadPolicy(args.policy);
    for (const w of warnings) console.log(chalk.yellow(`warning: ${w}`));
    const targets = new Set(policy.functions.map((f) => lower(f.target)));
    const members = policy.functions.reduce(
      (n, f) => n + (f.rules ?? []).reduce((m, r) => m + (r.kind === "OneOf" ? (r.values ?? []).length : 0), 0),
      0,
    );
    console.log(
      chalk.green(
        `${args.policy}: valid. safe ${policy.safe}, mode ${policy.mode}, ${policy.functions.length} function(s) on ` +
          `${targets.size} target(s), ${members} OneOf member(s), ${policy.guardians.length} guardian(s), ` +
          `${(policy.multiSendUnwrappers ?? []).length} unwrapper(s), ${(policy.modules ?? []).length} module(s), ` +
          `handler ${policy.requiredFallbackHandler.handler} enforce=${policy.requiredFallbackHandler.enforce}`,
      ),
    );
    for (const f of policy.functions) console.log(`  ${selectorOf(f)} ${f.signature} on ${f.target}`);
  });

task("curator-guard-sync", "Reconcile a CuratorGuard policy for a Safe against a JSON policy file")
  .addParam("guard", "CuratorGuard address")
  .addParam("policy", "Path to the policy JSON")
  .addOptionalParam(
    "proposer",
    "Timelock proposer (an EOA signer or a Safe) when the guard admin is a TimelockController",
  )
  .addOptionalParam(
    "deadlineDays",
    "Timelock admin: days (1-30) after minDelay during which a scheduled batch may still be executed (executeBefore wrapper)",
    "14",
  )
  .addOptionalParam(
    "unlockDeadlineDays",
    "Timelock admin: days (1-3) after minDelay AND the lockdown cooldown during which a lift (enforce) may still be executed",
    "1",
  )
  .addOptionalParam(
    "op",
    "With --execute: operation id(s) to execute, comma-separated, rebuilt from the timelock's logs",
  )
  .addOptionalParam(
    "timelockBlock",
    "Block the admin timelock was deployed at (log scans start there; also CURATOR_GUARD_TIMELOCK_BLOCK)",
  )
  .addFlag("dryRun", "Print the diff (and with --execute every check) without sending anything")
  .addFlag("allowUnlock", "Required to move an already configured Safe out of Lockdown / Bypass into Enforced")
  .addFlag(
    "confirmRevocations",
    "Required when the diff revokes functions, values, unwrappers, modules, native transfers or guardians",
  )
  .addFlag(
    "confirmLoosening",
    "Required when an already allowed function loses a rule, widens a bound or gains allowValue",
  )
  .addFlag("execute", "Timelock admin: execute the previously scheduled batch instead of scheduling it")
  .addFlag(
    "allowPending",
    "Timelock admin: schedule although another operation is still pending on the timelock (it stays executable by anyone)",
  )
  .addFlag("allowLargeBatch", "Schedule a batch estimated above 12M gas (split the policy change instead)")
  .addFlag(
    "allowUnconstrainedNav",
    "Sync an unconstrained NAV-marking function on a vault that already holds assets (a colluding quorum can then mark the custody away)",
  )
  .addFlag("viaTimelock", "Fork networks: rehearse schedule -> execute instead of impersonating the admin")
  .setAction(async (args: SyncArgs & { policy: string }, hre: HardhatRuntimeEnvironment) => {
    const { policy, policyText, warnings } = loadPolicy(args.policy);
    for (const w of warnings) console.log(chalk.yellow(`warning: ${w}`));
    const ctx = await guardContext(hre, args.guard, policy, args.timelockBlock);
    if (fs.existsSync(SAFE_BATCH_TXS_FILE)) {
      throw Error(`${SAFE_BATCH_TXS_FILE} exists: flush or delete the stale Safe batch before syncing`);
    }
    await governanceSummary(hre, ctx);
    // The timelock's queue is printed on EVERY run, "already in sync" included: a queued role change,
    // window, approval or abandoned batch is executable by anyone and must never hide behind a quiet
    // routine check (review R7C-03).
    if (ctx.timelock) {
      const queue = await pendingOperations(ctx, await timelockScan(hre, ctx, true));
      if (queue.length) {
        console.log(chalk.yellow(`${queue.length} operation(s) pending on the timelock ${ctx.admin}:`));
        for (const q of queue)
          console.log(chalk.yellow(`  ${q.opId} (scheduled in block ${q.block}): ${q.description}`));
      } else console.log(chalk.blue(`no operation pending on the timelock ${ctx.admin}`));
    }
    const plan = await planDiff(hre, ctx, policy, false, args.allowUnconstrainedNav === true);
    if (!plan.calls.length && !args.execute) {
      console.log(chalk.blue("Policy already in sync; nothing to do."));
      return;
    }
    if (plan.calls.length) {
      console.log(chalk.blue(`${plan.calls.length} admin call(s) to ${ctx.guard} (admin ${ctx.admin}):`));
      for (const c of plan.calls) console.log(`  - ${c.description}`);
    }
    if (!args.execute) {
      // Gates on what gets scheduled; `--execute` re-checks the stored batch against the diff instead.
      if (plan.lifts && !args.allowUnlock) {
        throw Error(
          `the Safe is configured and in ${plan.currentMode} on-chain while the file asks for Enforced: re-run with ` +
            `--allow-unlock if lifting it is intended (never apply a routine policy change during an incident)`,
        );
      }
      // A dry run still walks the whole scheduling path (pending check, simulation, gas, operation
      // ids and deadlines) and stops before anything is written or sent (review R7C-09).
      if (!args.dryRun && plan.revocations > 0 && !args.confirmRevocations) {
        throw Error(
          `${plan.revocations} revocation(s) in the diff (a missing line in the file revokes on-chain permissions): re-run with ` +
            `--confirm-revocations if intended`,
        );
      }
      if (!args.dryRun && plan.loosenings.length && !args.confirmLoosening) {
        throw Error(
          `${plan.loosenings.length} loosening(s) in the diff (an allowed function loses a rule, widens a bound or gains ` +
            `allowValue):\n  ${plan.loosenings.join("\n  ")}\nre-run with --confirm-loosening if intended`,
        );
      }
    }
    await applyAsAdmin(hre, args, ctx, plan, { policyPath: args.policy, policyText });
  });

task(
  "curator-guard-verify",
  "Decode a queued timelock operation from the chain's logs and compare it with the policy file",
)
  .addParam("guard", "CuratorGuard address")
  .addParam("policy", "Path to the policy JSON")
  .addParam("op", "Operation id(s), comma-separated")
  .addOptionalParam("timelockBlock", "Block the admin timelock was deployed at (also CURATOR_GUARD_TIMELOCK_BLOCK)")
  .setAction(
    async (
      args: { guard: string; policy: string; op: string; timelockBlock?: string },
      hre: HardhatRuntimeEnvironment,
    ) => {
      const { policy } = loadPolicy(args.policy);
      const ctx = await guardContext(hre, args.guard, policy, args.timelockBlock);
      if (!ctx.timelock) throw Error(`the guard admin ${ctx.admin} is not a TimelockController`);
      const scan = await timelockScan(hre, ctx, false);
      const plan = await planDiff(hre, ctx, policy, true, true);
      const wanted = new Set(plan.calls.map((c) => c.data));
      let allMatch = true;
      for (const id of args.op.split(",")) {
        const op = await rebuildOperation(ctx, scan, id.trim());
        const ts: bigint = await ctx.timelock.getTimestamp(op.opId);
        console.log(
          chalk.blue(
            `operation ${op.opId}: ${ts === 0n ? "NOT scheduled" : ts === 1n ? "executed" : `ready at ${iso(ts)}`}, ` +
              `predecessor ${op.predecessor}, scheduled in block ${op.block}`,
          ),
        );
        for (const [i, c] of op.calls.entries()) {
          const inner = unwrapExecuteBefore(ctx.guardIface, c.data);
          const guardTarget = lower(c.target) === lower(ctx.guard);
          const stillWanted = guardTarget && inner !== undefined && wanted.has(inner.data);
          allMatch &&= stillWanted;
          console.log(
            `  [${i}] ${describeTimelockCall(ctx, c.target, c.data)}` +
              (guardTarget
                ? stillWanted
                  ? chalk.green("  (in the current diff)")
                  : chalk.red("  (NOT in the current diff)")
                : chalk.red("  (NOT a guard call)")),
          );
        }
      }
      console.log(
        allMatch
          ? chalk.green("every decoded call is part of the diff the committed policy file produces right now")
          : chalk.red(
              "some decoded calls are NOT what the committed policy file would produce right now: do not sign / execute blindly",
            ),
      );
    },
  );

/*//////////////////////////////////////////////////////////////
                         CONTEXT AND SUMMARY
//////////////////////////////////////////////////////////////*/

type Ctx = {
  guard: string;
  safe: string;
  admin: string;
  guardContract: Contract;
  guardIface: Interface;
  timelock: Contract | undefined;
  forkLike: boolean;
  chainId: string;
  blockArg: string | undefined;
};

/// Everything the tasks share: the guard, its admin, pins and the invariants of what may be synced.
async function guardContext(
  hre: HardhatRuntimeEnvironment,
  guardAddress: string,
  policy: Policy,
  blockArg: string | undefined,
): Promise<Ctx> {
  const { ethers } = hre;
  if (!/^0x[0-9a-fA-F]{40}$/.test(guardAddress)) throw Error(`--guard must be an address, got ${guardAddress}`);
  const guard = ethers.getAddress(guardAddress);
  const chainId = await hre.getChainId();
  const forkLike = await isRehearsal(hre);
  if (policy.chainId !== undefined && Number(chainId) !== 31337 && Number(chainId) !== policy.chainId) {
    throw Error(`policy.chainId is ${policy.chainId} but the network reports ${chainId}`);
  }
  if (policy.guard !== undefined && lower(policy.guard) !== lower(guard)) {
    throw Error(`policy.guard is ${policy.guard} but --guard is ${guard}`);
  }
  if (policy.guard === undefined && !forkLike) {
    throw Error("policy.guard is required outside rehearsals: pin the deployed guard address in the file");
  }
  // The build this tooling encodes against must be the code at `--guard` (metadata tail excluded).
  const artifact = await hre.artifacts.readArtifact("CuratorGuard");
  const live = await ethers.provider.getCode(guard);
  if (live === "0x") throw Error(`${guard} has no code`);
  if (stripMetadata(live) !== stripMetadata(artifact.deployedBytecode)) {
    throw Error(
      `the code at ${guard} is not this repository's CuratorGuard build (artifacts/ vs chain): wrong address, wrong network, ` +
        `or a stale compile (npx hardhat compile)`,
    );
  }
  // Typechain may or may not be generated (CI type-checks without it): the plain ethers type.
  const guardContract = (await ethers.getContractAt("CuratorGuard", guard)) as unknown as Contract;
  const guardIface = new ethers.Interface(artifact.abi);
  const safe = ethers.getAddress(policy.safe);
  const admin: string = await guardContract.defaultAdmin();
  if (lower(safe) === lower(guard) || lower(safe) === lower(admin)) {
    throw Error("policy.safe must be neither the guard nor the guard admin (the admin is never constrained)");
  }
  if ((await ethers.provider.getCode(safe)) === "0x") {
    const msg = `policy.safe ${safe} has no code on this network: a policy for a non-existent Safe (typo?)`;
    if (forkLike) console.log(chalk.yellow(`WARNING: ${msg}`));
    else throw Error(msg);
  }
  // A proposer / canceller / council Safe that installs the guard on itself can no longer propose,
  // cancel or act: with a sole proposer that is a permanent brick of governance.
  if (await guardContract.hasRole(await guardContract.COUNCIL_ROLE(), safe))
    throw Error("policy.safe is the council: the council must not be guarded");
  const timelock = await timelockAt(hre, admin);
  if (timelock) {
    for (const role of ["PROPOSER_ROLE", "CANCELLER_ROLE"] as const) {
      if (await timelock.hasRole(await timelock.getFunction(role)(), safe)) {
        throw Error(
          `policy.safe holds ${role} on the admin timelock ${admin}: a governance Safe must never be guarded`,
        );
      }
    }
  }
  return { guard, safe, admin, guardContract, guardIface, timelock, forkLike, chainId, blockArg };
}

/// What a sync does not change but an operator must see: roles, pending admin transfer, standing
/// approvals of this Safe, the cooldown, and the council's timelock roles (the council must never be a
/// canceller or proposer: it could veto or schedule its own removal; review V2-54 / R6D-7).
async function governanceSummary(hre: HardhatRuntimeEnvironment, ctx: Ctx): Promise<void> {
  const { ethers } = hre;
  const g = ctx.guardContract;
  const councilRole: string = await g.COUNCIL_ROLE();
  const guardianRole: string = await g.GUARDIAN_ROLE();
  const [pendingAdmin, pendingSchedule] = await g.pendingDefaultAdmin();
  const now = BigInt((await ethers.provider.getBlock("latest"))!.timestamp);
  const lines: string[] = [`admin ${ctx.admin}${ctx.timelock ? " (TimelockController)" : ""}`];
  if (pendingAdmin !== ethers.ZeroAddress)
    lines.push(chalk.yellow(`PENDING ADMIN TRANSFER to ${pendingAdmin} (acceptable from ${iso(pendingSchedule)})`));
  const from = await creationBlock(hre, ctx);
  const holders = async (role: string): Promise<string[]> => {
    if (from === undefined) return [];
    const out = new Set<string>();
    for (const l of await scanLogs(hre, g, g.filters.RoleGranted(role), from))
      out.add(ethers.getAddress((l as EventLog).args.account));
    const live: string[] = [];
    for (const h of out) if (await g.hasRole(role, h)) live.push(h);
    return live;
  };
  const council = await holders(councilRole);
  const guardians = await holders(guardianRole);
  const unknown = from === undefined ? "(unknown: no log range, pass --timelock-block)" : "none";
  lines.push(`council: ${council.length ? council.join(", ") : unknown}`);
  lines.push(`deployment-wide guardians: ${guardians.length ? guardians.join(", ") : unknown}`);
  const perSafe: string[] = await g.guardians(ctx.safe);
  lines.push(`guardians of ${ctx.safe}: ${perSafe.length ? perSafe.join(", ") : "none"}`);
  // A Safe forwards every call it does not implement to its fallback handler, from ANYONE, with itself
  // as the caller: a role-holding Safe whose handler is the guard (or the timelock) hands its role to
  // everyone (review R8Q-3). The contracts refuse such a caller; this names it before an incident does.
  const principals: [string, string][] = [
    ...council.map((a) => ["council", a] as [string, string]),
    ...guardians.map((a) => ["deployment-wide guardian", a] as [string, string]),
    ...perSafe.map((a) => ["guardian", a] as [string, string]),
  ];
  if (ctx.timelock && from !== undefined) {
    for (const role of ["PROPOSER_ROLE", "CANCELLER_ROLE"] as const) {
      const id: string = await ctx.timelock.getFunction(role)();
      const seen = new Set<string>();
      for (const l of await scanLogs(hre, ctx.timelock, ctx.timelock.filters.RoleGranted(id), from))
        seen.add(ethers.getAddress((l as EventLog).args.account));
      for (const h of seen) if (await ctx.timelock.hasRole(id, h)) principals.push([`timelock ${role}`, h]);
    }
  }
  for (const [label, who] of principals) {
    if ((await ethers.provider.getCode(who)) === "0x" || !(await isSafeContract(hre, who))) continue;
    const raw: string = await (await ethers.getContractAt("ISafe", who)).getStorageAt(SAFE_HANDLER_SLOT, 1);
    const handler = ethers.getAddress("0x" + raw.slice(-40));
    if ([ctx.guard, ctx.admin].some((x) => lower(x) === lower(handler)))
      throw Error(
        `${label} ${who}: its fallback handler is ${handler}. A Safe forwards unknown calls to its handler from anyone, with itself ` +
          `as the caller: its role would be public. Have it execute setFallbackHandler(0) (or the canonical handler) first`,
      );
    if (handler !== ethers.ZeroAddress && !CANONICAL_SAFE_HANDLERS.has(lower(handler)))
      lines.push(chalk.yellow(`WARNING: ${label} ${who} has a non-canonical fallback handler ${handler}`));
  }
  if (ctx.timelock) {
    for (const c of council) {
      for (const role of ["PROPOSER_ROLE", "CANCELLER_ROLE"] as const) {
        if (await ctx.timelock.hasRole(await ctx.timelock.getFunction(role)(), c)) {
          throw Error(
            `the council ${c} holds ${role} on the admin timelock ${ctx.admin}: it could veto or schedule its own removal. ` +
              `Schedule revokeRole(${role}, ${c}) on the timelock from a proposer before any sync (docs section 7.5)`,
          );
        }
      }
    }
  }
  if (from !== undefined) {
    const live: string[] = [];
    for (const l of await scanLogs(hre, g, g.filters.TransactionApproved(ctx.safe), from)) {
      const a = (l as EventLog).args;
      const expiry: bigint = await g.approvalExpiry(a.approvalId);
      if (expiry > now)
        live.push(
          `${a.approvalId} to ${a.to} ${String(a.data).slice(0, 10)} executor ${a.executor} until ${iso(expiry)}`,
        );
    }
    if (live.length) lines.push(chalk.yellow(`STANDING APPROVALS (${live.length}):\n    ${live.join("\n    ")}`));
    const forbidden: string[] = [];
    for (const l of await scanLogs(hre, g, g.filters.UnwrapperCodehashUpdated(), from)) {
      const a = (l as EventLog).args;
      if (!a.allowed && !(await g.isUnwrapperCodehash(a.codehash)) && !forbidden.includes(a.codehash))
        forbidden.push(a.codehash);
    }
    if (forbidden.length)
      lines.push(
        chalk.yellow(`FORBIDDEN unwrapper code hashes: ${forbidden.join(", ")} (batching is off until re-allowed)`),
      );
  }
  const lockedAt: bigint = await g.lockedAt(ctx.safe);
  if (lockedAt !== 0n) {
    const until = lockedAt + LOCKDOWN_COOLDOWN;
    const text = `last lockdown ${iso(lockedAt)}; admin lifts / windows / approvals ${now <= until ? "HELD BACK until" : "free since"} ${iso(until)}`;
    lines.push(now <= until ? chalk.yellow(text) : text);
  }
  console.log(chalk.blue(`governance of ${ctx.guard}:\n  ${lines.join("\n  ")}`));
}

/*//////////////////////////////////////////////////////////////
                               DIFF
//////////////////////////////////////////////////////////////*/

/// The admin calls that take the on-chain policy of `policy.safe` to the file. Pure planning: nothing
/// is sent. `quiet` suppresses the printed diff (verify task).
async function planDiff(
  hre: HardhatRuntimeEnvironment,
  ctx: Ctx,
  policy: Policy,
  quiet = false,
  allowUnconstrainedNav = false,
): Promise<Plan> {
  const { ethers } = hre;
  const guard = ctx.guardContract;
  const iface = ctx.guardIface;
  const safe = ctx.safe;
  const say = (s: string) => {
    if (!quiet) console.log(s);
  };
  const toRule = (r: PolicyRule): OnChainRule => ({
    kind: RULE_KINDS.indexOf(r.kind),
    wordIndex: onChainWordIndex(r),
    value: r.kind === "EqualToSafe" || r.kind === "OneOf" ? ZERO_HASH : ruleWord(r, r.value!),
  });
  const sameRules = (a: OnChainRule[], b: OnChainRule[]) =>
    a.length === b.length &&
    a.every((r, i) => r.kind === b[i].kind && r.wordIndex === b[i].wordIndex && lower(r.value) === lower(b[i].value));
  const ruleText = (r: OnChainRule) =>
    `${RULE_KINDS[r.kind]}@${r.wordIndex & TAIL_FLAG ? `tail${r.wordIndex & ~TAIL_FLAG}` : r.wordIndex}${r.kind === 0 || r.kind === 3 || r.kind === 4 ? `=${wordText(r.value)}` : ""}`;

  const calls: Call[] = [];
  const valueCalls: Call[] = []; // applied after allowFunction: values need their OneOf rule first
  const NARROWING = new Set(["revokeFunction", "removeAllowedValues", "revokeTarget", "clearAllowedValues"]);
  let revocations = 0;
  const loosenings: string[] = [];
  const push = (description: string, fn: string, params: unknown[], list: Call[] = calls) => {
    if (
      NARROWING.has(fn) ||
      (/^set(MultiSendUnwrapper|ModuleAllowed|NativeTransferAllowed|Guardian)$/.test(fn) &&
        params[params.length - 1] === false)
    ) {
      ++revocations;
    }
    list.push({ description, data: iface.encodeFunctionData(fn, params) });
  };

  // --- functions -------------------------------------------------------------------------------
  const desired = new Map<
    string,
    { target: string; selector: string; allowValue: boolean; rules: OnChainRule[]; src: PolicyFunction }
  >();
  const probeCodes = new Map<string, string>(); // target -> code (the implementation's for a proxy) for the selector probe
  for (const f of policy.functions) {
    const target = ethers.getAddress(f.target);
    if (lower(target) === lower(safe) || lower(target) === lower(ctx.guard) || lower(target) === lower(ctx.admin)) {
      throw Error(`${target}: the Safe, the guard and the guard admin can never be policy targets`);
    }
    if (!probeCodes.has(lower(target))) {
      let probeCode = await ethers.provider.getCode(target);
      if (probeCode === "0x") {
        say(
          chalk.yellow(
            `WARNING: target ${target} has no code (EOA or not deployed yet): every call to it is a plain transfer of nothing`,
          ),
        );
      } else if (probeCode.toLowerCase().startsWith("0xef0100")) {
        say(
          chalk.yellow(
            `WARNING: target ${target} is an EIP-7702 delegated EOA: its key holder can change the code behind this ` +
              `allowlist entry at any time. Targets must be contracts.`,
          ),
        );
      } else {
        for (const [label, slot] of PROXY_SLOTS) {
          const impl = await ethers.provider.getStorage(target, slot);
          if (BigInt(impl) === 0n) continue;
          const implAddress = ethers.getAddress("0x" + impl.slice(-40));
          const admin1967 = await ethers.provider.getStorage(target, ERC1967_ADMIN);
          say(
            chalk.yellow(
              `note: target ${target} is an upgradeable proxy (${label} ${implAddress}` +
                (BigInt(admin1967) !== 0n ? `, admin 0x${admin1967.slice(-40)}` : "") +
                `): check who can upgrade it and that no upgrade is pending before install (docs section 7.3)`,
            ),
          );
          if (label === "ERC-1967 beacon") {
            try {
              const beacon = new ethers.Contract(
                implAddress,
                ["function implementation() view returns (address)"],
                ethers.provider,
              );
              probeCode = await ethers.provider.getCode(await beacon.implementation());
            } catch {
              /* an unreadable beacon leaves the proxy's own code for the probe */
            }
          } else probeCode = await ethers.provider.getCode(implAddress);
          break;
        }
      }
      probeCodes.set(lower(target), probeCode);
    }
    const selector = selectorOf(f);
    // A selector the target's code never dispatches is a typo or a collision (the implementation's
    // code for a proxy); heuristic, since the PUSH could sit behind a further delegatecall. solc
    // shortens a selector with leading zero bytes to a smaller PUSH (review R7C-12).
    const code = probeCodes.get(lower(target))!;
    if (code !== "0x" && !lower(code).includes(pushOf(selector))) {
      say(
        chalk.yellow(
          `WARNING: selector ${selector} (${f.signature}) does not occur in the code of ${target}: typo, or a deeper proxy?`,
        ),
      );
    }
    const k = key(target, selector);
    if (desired.has(k)) throw Error(`Duplicate function entry ${f.signature} (${selector}) on ${target}`);
    desired.set(k, { target, selector, allowValue: f.allowValue === true, rules: (f.rules ?? []).map(toRule), src: f });
  }

  // The go-live gate behind `"unconstrained": true` on a NAV-marking function (docs sections 5 and 8):
  // tolerable only while the vault it marks holds nothing a colluding quorum could mark away.
  for (const d of desired.values()) {
    if (!d.src.unconstrained || !BAND_SHAPED.has(d.selector)) continue;
    let assets = 0n;
    try {
      assets = await new ethers.Contract(
        d.target,
        ["function totalAssets() view returns (uint256)"],
        ethers.provider,
      ).totalAssets();
    } catch {
      continue; // not an ERC-4626 vault: nothing to gate on
    }
    if (assets === 0n) continue;
    const msg = `${d.src.signature} on ${d.target} is unconstrained while the vault reports totalAssets() = ${assets}: a colluding curator quorum can mark that custody away (docs section 8); put a NAV band on it, or pass --allow-unconstrained-nav`;
    if (!allowUnconstrainedNav) throw Error(msg);
    say(chalk.red(`WARNING: ${msg}`));
  }

  const onChainTargets: string[] = (await guard.targets(safe)).map((t: string) => ethers.getAddress(t));
  const onChainFunctions = new Map<string, { target: string; selector: string }>();
  for (const target of onChainTargets) {
    const sels: string[] = await guard.selectors(safe, target); // bytes32 words, selector in the first 4 bytes
    for (const w of sels) {
      const s = lower(w).slice(0, 10);
      onChainFunctions.set(key(target, s), { target, selector: s });
    }
  }
  const revokedOnChain = await revokedFunctions(hre, ctx);

  for (const [k, d] of desired) {
    const label = `${d.src.signature} (${d.selector})`;
    const [allowed, allowValue, rawRules] = await guard.functionPermission(safe, d.target, d.selector);
    const rules: OnChainRule[] = rawRules.map((r: [bigint, bigint, string]) => ({
      kind: Number(r[0]),
      wordIndex: Number(r[1]),
      value: r[2],
    }));
    // A values-only change re-asserts the (identical) `allowFunction` ahead of its `addAllowedValues` in
    // the same batch: a `revokeFunction` by any narrower during the delay would otherwise kill the
    // queued batch (`NoOneOfRule`) and cost another delay (review R8M-1). Idempotent: the kept `OneOf`
    // rule keeps its set.
    const unchanged = allowed && allowValue === d.allowValue && sameRules(rules, d.rules);
    let reassert = false;
    if (unchanged) {
      for (const r of d.src.rules ?? []) {
        if (r.kind !== "OneOf") continue;
        const want = (r.values ?? []).map((v) => ruleWord(r, v));
        const have = new Set(
          ((await guard.allowedValues(safe, d.target, d.selector, onChainWordIndex(r))) as string[]).map(lower),
        );
        if (want.some((v) => !have.has(v))) reassert = true;
      }
    }
    if (!unchanged || reassert) {
      // One call per function: `--execute` compares calls one by one, so a fast-lane change to ONE
      // function during the delay never invalidates the others (review R6D-14).
      push(
        `allowFunction ${label} on ${d.target} allowValue=${d.allowValue} rules=[${d.rules.map(ruleText).join(", ")}]`,
        "allowFunction",
        [safe, d.target, d.selector, d.allowValue, d.rules],
      );
      if (unchanged) {
        say(chalk.gray(`= allow   ${label} on ${d.target} (re-asserted ahead of its value changes)`));
      } else if (!allowed) {
        say(chalk.green(`+ allow   ${label} on ${d.target}${d.src.note ? `  // ${d.src.note}` : ""}`));
        const revoked = revokedOnChain.get(k);
        if (revoked)
          say(
            chalk.yellow(
              `  NOTE: this function was REVOKED on-chain in block ${revoked.block} (tx ${revoked.tx}): re-allowing it`,
            ),
          );
      } else {
        // Already allowed: print what changes and whether it loosens.
        const before = `allowValue=${allowValue} [${rules.map(ruleText).join(", ")}]`;
        const after = `allowValue=${d.allowValue} [${d.rules.map(ruleText).join(", ")}]`;
        const why = loosensRules(rules, d.rules, allowValue, d.allowValue);
        say(
          chalk.yellow(
            `~ rules   ${label} on ${d.target}: ${before} -> ${after}${why.length ? chalk.red(`  LOOSENING: ${why.join("; ")}`) : ""}`,
          ),
        );
        if (why.length) loosenings.push(`${label} on ${d.target}: ${why.join("; ")}`);
      }
    }
    for (const r of d.src.rules ?? []) {
      if (r.kind !== "OneOf") continue;
      const word = onChainWordIndex(r);
      const want = new Set((r.values ?? []).map((v) => ruleWord(r, v)));
      const have = new Set(((await guard.allowedValues(safe, d.target, d.selector, word)) as string[]).map(lower));
      const add = [...want].filter((v) => !have.has(v));
      const remove = [...have].filter((v) => !want.has(v));
      if (add.length) {
        push(
          `addAllowedValues ${label}@${d.target} word ${word}: ${add.map(wordText).join(", ")}`,
          "addAllowedValues",
          [safe, d.target, d.selector, word, add],
          valueCalls,
        );
        say(chalk.green(`+ values  ${label} word ${word}: ${add.map(wordText).join(", ")}`));
      }
      if (remove.length) {
        push(
          `removeAllowedValues ${label}@${d.target} word ${word}: ${remove.map(wordText).join(", ")}`,
          "removeAllowedValues",
          [safe, d.target, d.selector, word, remove],
        );
        say(chalk.red(`- values  ${label} word ${word}: ${remove.map(wordText).join(", ")}`));
      }
    }
    onChainFunctions.delete(k);
  }
  calls.push(...valueCalls);
  for (const f of onChainFunctions.values()) {
    const known = KNOWN_SIGNATURES.get(f.selector);
    push(`revokeFunction ${f.selector}${known ? ` (${known})` : ""} on ${f.target}`, "revokeFunction", [
      safe,
      f.target,
      f.selector,
    ]);
    say(chalk.red(`- revoke  ${f.selector}${known ? ` (${known})` : ""} on ${f.target}`));
  }

  // --- sets: unwrappers / modules / native transfers (absent key = empty set) -------------------
  const syncSet = async (label: string, want: string[], have: string[], fn: string) => {
    const w = new Set(want.map(lower));
    const h = new Set(have.map(lower));
    for (const a of w) {
      if (h.has(a)) continue;
      push(`${fn} ${ethers.getAddress(a)} = true`, fn, [safe, ethers.getAddress(a), true]);
      say(chalk.green(`+ ${label} ${a}`));
    }
    for (const a of h) {
      if (w.has(a)) continue;
      push(`${fn} ${ethers.getAddress(a)} = false`, fn, [safe, ethers.getAddress(a), false]);
      say(chalk.red(`- ${label} ${a}`));
    }
  };
  for (const u of policy.multiSendUnwrappers ?? []) {
    const code = await ethers.provider.getCode(u);
    if (code === "0x")
      throw Error(`unwrapper ${u} has no code (the contract rejects it: its code hash is not a canonical build)`);
    const codehash = ethers.keccak256(code);
    if (!(await guard.isUnwrapperCodehash(codehash))) {
      throw Error(
        `unwrapper ${u} runtime code hash ${codehash} is not allowed on the guard: only the canonical MultiSendCallOnly ` +
          `builds seeded at deployment (v1.3.0 / v1.4.1 / v1.5.0) can ever be unwrappers (a forbidden seeded hash is ` +
          `re-allowed by the admin or the council; a newer Safe release means a new guard)`,
      );
    }
  }
  for (const m of policy.modules ?? []) {
    if ((await ethers.provider.getCode(m)) === "0x")
      throw Error(`module ${m} has no code (the contract would accept it: a module is a contract, this is a typo)`);
  }
  await syncSet(
    "unwrap  ",
    policy.multiSendUnwrappers ?? [],
    await guard.multiSendUnwrappers(safe),
    "setMultiSendUnwrapper",
  );
  await syncSet("module  ", policy.modules ?? [], await guard.modules(safe), "setModuleAllowed");
  const nativeHave: string[] = [];
  for (const t of new Set([...onChainTargets, ...(policy.nativeTransfers ?? []).map((a) => ethers.getAddress(a))])) {
    if (await guard.isNativeTransferAllowed(safe, t)) nativeHave.push(t);
  }
  await syncSet("native  ", policy.nativeTransfers ?? [], nativeHave, "setNativeTransferAllowed");

  // --- guardians (per-Safe full set) -----------------------------------------------------------
  let onChainGuardians = 0;
  {
    const want = new Set(policy.guardians.map(lower));
    const have = new Set(((await guard.guardians(safe)) as string[]).map(lower));
    onChainGuardians = have.size;
    const safeOwners = await safeOwnersOf(hre, safe);
    for (const g of want) {
      if (g === lower(safe) || safeOwners.has(g)) {
        say(
          chalk.yellow(
            `warning: guardian ${g} is the Safe or one of its owners: a curator key could then void every admin approval ` +
              `(revokeAllApprovals, e.g. a pending setGuard(newGuard) migration) and freeze its own settlement; check it is intended`,
          ),
        );
      }
      if (have.has(g)) continue;
      push(`setGuardian ${ethers.getAddress(g)} = true`, "setGuardian", [safe, ethers.getAddress(g), true]);
      say(chalk.green(`+ guardian ${g}`));
    }
    for (const g of have) {
      if (want.has(g)) continue;
      push(`setGuardian ${ethers.getAddress(g)} = false`, "setGuardian", [safe, ethers.getAddress(g), false]);
      say(chalk.red(`- guardian ${g}`));
    }
    if (have.size > 0 && want.size === 0) {
      say(
        chalk.yellow(
          `WARNING: the file lists no guardians but ${have.size} are set on-chain (council fast-lane provisioning?): ` +
            `this sync would strip every responder; add them to the file first`,
        ),
      );
    }
  }

  // --- fallback handler requirement (required key) ----------------------------------------------
  {
    const want = policy.requiredFallbackHandler;
    const wantHandler = ethers.getAddress(want.handler);
    if (want.enforce && wantHandler !== ethers.ZeroAddress && (await ethers.provider.getCode(wantHandler)) === "0x") {
      throw Error(
        `requiredFallbackHandler.handler ${wantHandler} has no code on this chain: a typo here freezes every policy ` +
          `transaction (FallbackHandlerNotAllowed) and only a council window keeps settlement alive until the admin corrects it`,
      );
    }
    // The cross-checks below read the Safe; only "not a Safe" is tolerated, a transport error is an
    // error (an RPC hiccup must not silently remove a warning; review R6C-22).
    if ((await ethers.provider.getCode(safe)) !== "0x" && (await isSafeContract(hre, safe))) {
      const safeContract = await ethers.getContractAt("ISafe", safe);
      // The guard pins the Safe's proxy and singleton by runtime code hash (`SafeNotSupported` on the
      // policy path otherwise): a Safe behind other code, a forwarding singleton or a release the guard
      // was never reviewed against never gets a policy transaction (review R8G-1, R8C-6).
      const build = await safeBuildOf(hre, safe);
      if (!build.ok)
        throw Error(`policy.safe ${safe}: ${build.why} (the guard refuses it on the policy path: SafeNotSupported)`);
      say(`Safe build: ${build.why}`);
      if (want.enforce) {
        // Install-ordering trap: once the guard is installed, a handler that differs from the requirement
        // freezes every policy transaction; the fix needs an approval (the council's when the requirement
        // is address(0), the admin's for any other handler).
        const raw: string = await safeContract.getStorageAt(SAFE_HANDLER_SLOT, 1);
        const live = ethers.getAddress("0x" + raw.slice(-40));
        if (lower(live) !== lower(wantHandler)) {
          say(
            chalk.yellow(
              `WARNING: the Safe's fallback handler is ${live} but the policy requires ${want.handler}: the signers must execute ` +
                `setFallbackHandler(${want.handler}) in the SAME batch as setGuard (before install it needs no approval); ` +
                `afterwards the fix needs an approval: the council's (fast lane) when the requirement is address(0), ` +
                `the admin's (timelock delay) for any other handler; all policy traffic reverts meanwhile.`,
            ),
          );
        }
      }
      // Pre-install checks (docs §7.3): enabled modules bypass a v1.3.0 / v1.4.1 guard entirely, and a
      // guard slot already pointing elsewhere means this policy checks nothing until the swap executes.
      const [enabledModules] = await safeContract.getModulesPaginated(SENTINEL, 10);
      if (enabledModules.length > 0) {
        say(
          chalk.yellow(
            `WARNING: the Safe has ${enabledModules.length} enabled module(s): ${enabledModules.join(", ")}. On Safe v1.3.0 / ` +
              `v1.4.1 modules are not guarded (one can remove the guard): disable them before install, and never approve ` +
              `enableModule on such a Safe.`,
          ),
        );
      }
      const guardRaw: string = await safeContract.getStorageAt(SAFE_GUARD_SLOT, 1);
      const liveGuard = ethers.getAddress("0x" + guardRaw.slice(-40));
      if (liveGuard !== ethers.ZeroAddress && lower(liveGuard) !== lower(ctx.guard)) {
        say(
          chalk.yellow(
            `WARNING: the Safe's guard slot holds ${liveGuard}, not ${ctx.guard}: this policy checks nothing until the ` +
              `signers execute the approved setGuard swap (docs §7.5).`,
          ),
        );
      }
    }
    const [handler, enforce] = await guard.requiredFallbackHandler(safe);
    if (enforce !== want.enforce || lower(handler) !== lower(wantHandler)) {
      push(`setRequiredFallbackHandler ${wantHandler} enforce=${want.enforce}`, "setRequiredFallbackHandler", [
        safe,
        wantHandler,
        want.enforce,
      ]);
      say(chalk.yellow(`~ handler ${want.handler} enforce=${want.enforce}`));
      if (enforce && !want.enforce)
        loosenings.push("requiredFallbackHandler.enforce true -> false (the EIP-1271 defence goes off)");
    }
  }

  // --- mode (last; the EFFECTIVE mode: an expired Bypass window reads as Lockdown) --------------
  const currentMode = CHAIN_MODES[Number(await guard.mode(safe))];
  let lifts = false; // an already configured Safe leaving Lockdown / Bypass (short execution window)
  if (currentMode !== policy.mode) {
    if (policy.mode === "Enforced") {
      // A fresh guard is simply being enabled; an already configured Safe sitting in Lockdown / Bypass
      // is an incident state that a routine sync must not end silently. "Configured" mirrors the
      // contract's own `AdminIsGuarded` predicate, so a guardian who answered an incident with
      // revocations cannot disarm the gate (the handler requirement and guardians survive).
      const [, enforceOnChain] = await guard.requiredFallbackHandler(safe);
      lifts =
        onChainTargets.length > 0 ||
        onChainGuardians > 0 ||
        enforceOnChain ||
        currentMode === "Bypass" ||
        ((await guard.modules(safe)) as string[]).length > 0 ||
        ((await guard.multiSendUnwrappers(safe)) as string[]).length > 0;
      push("enforce", "enforce", [safe]);
    } else {
      push("lockdown", "lockdown", [safe]);
    }
    say(chalk.yellow(`~ mode    ${currentMode} -> ${policy.mode}`));
  }
  return { calls, lifts, revocations, loosenings, currentMode };
}

/// Why `after` is weaker than `before` for a function that is already allowed (empty = not weaker).
function loosensRules(
  before: OnChainRule[],
  after: OnChainRule[],
  valueBefore: boolean,
  valueAfter: boolean,
): string[] {
  const why: string[] = [];
  if (!valueBefore && valueAfter) why.push("allowValue switched on");
  for (const b of before) {
    const same = after.find((a) => a.kind === b.kind && a.wordIndex === b.wordIndex);
    if (!same) {
      why.push(`${RULE_KINDS[b.kind]} on word ${b.wordIndex} removed`);
      continue;
    }
    if (b.kind === 3 && BigInt(same.value) > BigInt(b.value)) why.push(`ceiling on word ${b.wordIndex} raised`);
    if (b.kind === 4 && BigInt(same.value) < BigInt(b.value)) why.push(`floor on word ${b.wordIndex} lowered`);
  }
  return why;
}

/// Functions revoked on-chain for this Safe (`FunctionRevoked` logs), so a re-allow is said out loud.
async function revokedFunctions(
  hre: HardhatRuntimeEnvironment,
  ctx: Ctx,
): Promise<Map<string, { block: number; tx: string }>> {
  const out = new Map<string, { block: number; tx: string }>();
  const from = await creationBlock(hre, ctx);
  if (from === undefined) return out;
  for (const l of await scanLogs(hre, ctx.guardContract, ctx.guardContract.filters.FunctionRevoked(ctx.safe), from)) {
    const a = (l as EventLog).args;
    out.set(key(a.target, String(a.selector).slice(0, 10)), { block: l.blockNumber, tx: l.transactionHash });
  }
  return out;
}

/*//////////////////////////////////////////////////////////////
                              APPLY
//////////////////////////////////////////////////////////////*/

type SyncArgs = {
  guard: string;
  proposer?: string;
  execute?: boolean;
  op?: string;
  dryRun?: boolean;
  allowUnlock?: boolean;
  confirmRevocations?: boolean;
  confirmLoosening?: boolean;
  allowPending?: boolean;
  allowLargeBatch?: boolean;
  allowUnconstrainedNav?: boolean;
  viaTimelock?: boolean;
  deadlineDays?: string;
  unlockDeadlineDays?: string;
  timelockBlock?: string;
};
type ScheduledOp = {
  opId: string;
  salt: string;
  predecessor: string;
  deadline: string;
  payloads: string[];
  lifts: boolean;
  /// `single` = scheduled with `schedule()` (hashOperation), `batch` = `scheduleBatch()`; absent = batch.
  kind?: "single" | "batch";
};
type Scheduled = {
  version: 2;
  chainId: string;
  timelock: string;
  guard: string;
  safe: string;
  preparedAt: string;
  operations: ScheduledOp[];
  policyPath: string;
  policyHash: string;
};
type Signer = Awaited<ReturnType<HardhatRuntimeEnvironment["ethers"]["getSigner"]>>;

/// Sends the admin calls: directly when the signer is the admin (or the admin is impersonated on a
/// fork), otherwise through the admin `TimelockController` (schedule, later `--execute`).
async function applyAsAdmin(
  hre: HardhatRuntimeEnvironment,
  args: SyncArgs,
  ctx: Ctx,
  plan: Plan,
  meta: { policyPath: string; policyText: string },
): Promise<void> {
  const { ethers } = hre;
  const { admin, guard, safe, forkLike, chainId } = ctx;
  const calls = plan.calls;
  const [signer] = await ethers.getSigners();
  const signerAddress = signer ? lower(await signer.getAddress()) : undefined;
  const impersonate = async (who: string): Promise<Signer> => {
    await hre.network.provider.send("hardhat_impersonateAccount", [who]);
    await hre.network.provider.send("hardhat_setBalance", [who, "0x3635C9ADC5DEA00000"]);
    return ethers.getSigner(who);
  };
  const sendAll = async (executor: Signer) => {
    if (args.dryRun) {
      console.log(
        chalk.blue(
          `dry run: would send ${calls.length} call(s) directly as ${await executor.getAddress()}; nothing sent`,
        ),
      );
      return;
    }
    // Not atomic across calls: every intermediate state is fail-closed (empty OneOf sets deny, mode
    // is set last) and a re-run resumes from the on-chain state.
    for (const c of calls) {
      const tx = await executor.sendTransaction({ to: guard, data: c.data });
      await tx.wait();
      console.log(chalk.green(`executed: ${c.description} (tx: ${tx.hash})`));
    }
  };

  if (!args.execute && signer && signerAddress === lower(admin)) return sendAll(signer);

  const timelock = ctx.timelock;
  if (!timelock) {
    if (args.execute) throw Error(`the guard admin ${admin} is not a TimelockController: nothing to execute`);
    if (forkLike) {
      console.log(chalk.yellow(`Fork network: impersonating admin ${admin}`));
      return sendAll(await impersonate(admin));
    }
    throw Error(
      `the signer is not the guard admin ${admin} and the admin is not a TimelockController: nothing this task can do`,
    );
  }
  if (forkLike && !args.viaTimelock && !args.execute) {
    console.log(
      chalk.yellow(
        `Fork network: impersonating the timelock admin ${admin} (use --via-timelock to rehearse scheduling)`,
      ),
    );
    return sendAll(await impersonate(admin));
  }

  // --- TimelockController path -------------------------------------------------------------------
  // Every call is wrapped in `executeBefore(deadline, call)` so a batch nobody executed within the
  // window is dead instead of a latent, permissionless action (the executor role is open). A lift
  // (`enforce` on a configured Safe) is its own operation, chained behind the rest with `predecessor`:
  // the guard holds the admin's lift back for `LOCKDOWN_COOLDOWN` after any lockdown, and a batch
  // that bundled it with the removal of the key that keeps re-locking could never land (review R6D-1).
  // The lift's window therefore spans the cooldown plus the short unlock window.
  const minDelay: bigint = await timelock.getMinDelay();
  const latest = (await ethers.provider.getBlock("latest"))!;
  clockSanity(latest.timestamp, forkLike);
  const guardIface = ctx.guardIface;
  const wrap = (list: Call[], deadline: bigint) =>
    list.map((c) => guardIface.encodeFunctionData("executeBefore", [deadline, c.data]));
  const stateFile = `${SAFE_BATCH_TXS_FILE}.timelock.${chainId}.${lower(guard)}.json`;
  const readScheduled = (): Scheduled | undefined => {
    if (!fs.existsSync(stateFile)) return undefined;
    let parsed: unknown;
    try {
      parsed = JSON.parse(fs.readFileSync(stateFile, "utf8"));
    } catch (e: unknown) {
      throw Error(
        `${stateFile} is not valid JSON (${errorText(e)}): delete it, or pass --op <id> to execute from the chain's logs`,
      );
    }
    const s = parsed as Partial<Scheduled>;
    if (s.version !== 2 || !Array.isArray(s.operations))
      throw Error(`${stateFile} has an unknown format: delete it, or pass --op <id>`);
    return s as Scheduled;
  };
  const cancelHint = (opId: string) =>
    `cancel it from the canceller Safe: ${admin} cancel(bytes32) data ${timelock.interface.encodeFunctionData("cancel", [opId])}`;
  // The log scan fails closed when scheduling (an unknown creation block or a failed scan needs
  // --allow-pending); an --execute from the state file tolerates it, one from --op needs the logs.
  const scan = await timelockScan(hre, ctx, args.allowPending === true || (args.execute === true && !args.op));

  if (args.execute) {
    await executeScheduled(
      hre,
      args,
      ctx,
      plan,
      scan,
      readScheduled(),
      stateFile,
      wrap,
      cancelHint,
      signer,
      impersonate,
    );
    return;
  }

  // Any pending operation stays executable by anyone until its deadline and can resurrect what a
  // later batch corrected: refuse to pile a new one on top without an explicit flag.
  const pending = await pendingOperations(ctx, scan);
  const previous = readScheduled();
  for (const op of previous?.operations ?? []) {
    if ((await timelock.getTimestamp(op.opId)) > 1n && !pending.some((p) => p.opId === op.opId)) {
      pending.push({
        opId: op.opId,
        calls: [],
        block: 0,
        predecessor: op.predecessor,
        delay: 0n,
        description: "(from the state file)",
      });
    }
  }
  if (pending.length) {
    const list = pending.map((p) => `  ${p.opId}: ${p.description}\n    ${cancelHint(p.opId)}`).join("\n");
    if (!args.allowPending) {
      throw Error(
        `${pending.length} operation(s) are still pending on the timelock:\n${list}\n` +
          `cancel what is abandoned, or pass --allow-pending to schedule the NEW diff next to them (it re-includes every ` +
          `unapplied call of a pending sync operation and supersedes it: execute the new one, cancel the old one)`,
      );
    }
    console.log(chalk.yellow(`WARNING: scheduling next to ${pending.length} pending operation(s):\n${list}`));
  }

  // Two operations when the batch lifts: everything else first, the lift alone behind it.
  const windowDays = dayArg(args.deadlineDays ?? "14", 1, 30, "--deadline-days");
  const unlockDays = dayArg(args.unlockDeadlineDays ?? "1", 1, 3, "--unlock-deadline-days");
  const enforceData = guardIface.encodeFunctionData("enforce", [safe]);
  const liftIndex = plan.lifts ? calls.findIndex((c) => c.data === enforceData) : -1;
  const groups: { calls: Call[]; deadline: bigint; lifts: boolean }[] = [];
  const body = liftIndex >= 0 ? calls.filter((_, i) => i !== liftIndex) : calls;
  if (body.length)
    groups.push({ calls: body, deadline: BigInt(latest.timestamp) + minDelay + windowDays * 86_400n, lifts: false });
  if (liftIndex >= 0) {
    groups.push({
      calls: [calls[liftIndex]],
      deadline: BigInt(latest.timestamp) + minDelay + LOCKDOWN_COOLDOWN + unlockDays * 86_400n,
      lifts: true,
    });
  }

  // Dead-on-arrival check: every call simulated as the admin against the current state; a batch that
  // reverts after the signers signed it is the failure mode this exists for (review R6C-07 / R6D-1).
  const gas = await simulateAsAdmin(
    hre,
    ctx,
    groups.flatMap((g) => wrap(g.calls, g.deadline)),
  );
  if (gas > BATCH_GAS_REFUSE && !args.allowLargeBatch) {
    throw Error(
      `the batch is estimated at ${gas} gas, above ${BATCH_GAS_REFUSE} (one transaction, EIP-7825 caps it at 16.7M): split the ` +
        `policy change over several syncs, or pass --allow-large-batch`,
    );
  }
  if (gas > BATCH_GAS_WARN) console.log(chalk.yellow(`WARNING: the batch is estimated at ${gas} gas`));

  const policyHash = ethers.keccak256(ethers.toUtf8Bytes(meta.policyText));
  const ops: ScheduledOp[] = [];
  const scheduleCalls: string[] = [];
  let predecessor = ZERO_HASH;
  for (const g of groups) {
    const payloads = wrap(g.calls, g.deadline);
    const targets = payloads.map(() => guard);
    const values = payloads.map(() => 0n);
    const saltFor = (n: number) =>
      ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["string", "address", "bytes[]", "uint256"],
          ["curator-guard-sync", guard, g.calls.map((c) => c.data), n],
        ),
      );
    let counter = 0;
    let salt = saltFor(counter);
    let opId: string = await timelock.hashOperationBatch(targets, values, payloads, predecessor, salt);
    while ((await timelock.getTimestamp(opId)) !== 0n) {
      salt = saltFor(++counter);
      opId = await timelock.hashOperationBatch(targets, values, payloads, predecessor, salt);
    }
    console.log(
      chalk.blue(
        `Timelock ${admin}: operation ${opId} (salt #${counter}, predecessor ${predecessor}), minDelay ${minDelay}s, ` +
          `executeBefore ${iso(g.deadline)} (the window counts from NOW, not from when the proposer Safe signs)`,
      ),
    );
    for (const c of g.calls) console.log(`    ${c.description}`);
    if (g.lifts) {
      console.log(
        chalk.yellow(
          `  this operation LIFTS a lockdown / Bypass: anyone may execute it once ready and the cooldown passed; on a new incident ${cancelHint(opId)}`,
        ),
      );
    }
    ops.push({ opId, salt, predecessor, deadline: g.deadline.toString(), payloads, lifts: g.lifts, kind: "batch" });
    scheduleCalls.push(
      timelock.interface.encodeFunctionData("scheduleBatch", [targets, values, payloads, predecessor, salt, minDelay]),
    );
    predecessor = opId;
  }
  console.log(chalk.blue(`  policy ${meta.policyPath} keccak ${policyHash}`));
  // Earlier operations of this guard that are still in flight stay in the file (an executed or
  // cancelled one drops out), so a later --execute still sees them (review R7C-04).
  const carried: ScheduledOp[] = [];
  for (const op of previous?.operations ?? []) {
    if (!ops.some((o) => o.opId === op.opId) && (await timelock.getTimestamp(op.opId)) > 1n) carried.push(op);
  }
  const stored: Scheduled = {
    version: 2,
    chainId,
    timelock: admin,
    guard,
    safe,
    preparedAt: String(latest.timestamp),
    operations: [...carried, ...ops],
    policyPath: meta.policyPath,
    policyHash,
  };
  // Signers of the proposer Safe see `scheduleBatch(...)` with `executeBefore(deadline, call)` blobs:
  // give them something to verify against (the manifest reproduces every operation id and decodes
  // every call; `curator-guard-verify --op <id>` does the same from the chain's logs). Written on
  // every path, rehearsals included, so an operator has seen one before the real run (review R7C-15).
  const manifest = `${stateFile}.manifest.json`;
  const manifestText = JSON.stringify(
    {
      chainId,
      timelock: admin,
      guard,
      safe,
      proposer: args.proposer ?? signerAddress ?? null,
      preparedAt: iso(latest.timestamp),
      operations: ops.map((op, i) => ({
        ...op,
        deadlineIso: iso(BigInt(op.deadline)),
        targets: op.payloads.map(() => guard),
        values: op.payloads.map(() => "0"),
        decoded: op.payloads.map((p) => describeTimelockCall(ctx, guard, p)),
        scheduleBatchCalldata: scheduleCalls[i],
        scheduleBatchCalldataHash: ethers.keccak256(scheduleCalls[i]),
      })),
      policyPath: meta.policyPath,
      policyHash,
      verify:
        "hashOperationBatch(targets, values, payloads, predecessor, salt) == opId for each operation; npx hardhat curator-guard-verify --op <opId>",
    },
    null,
    2,
  );
  if (args.dryRun) {
    console.log(
      chalk.blue(
        `dry run: would schedule ${ops.length} operation(s) as above (ids and deadlines are recomputed on the real run); nothing written, nothing sent`,
      ),
    );
    return;
  }
  fs.writeFileSync(manifest, manifestText);
  console.log(chalk.blue(`  signer manifest written to ${manifest}`));

  const proposerRole: string = await timelock.PROPOSER_ROLE();
  if (signer && signerAddress && (await timelock.hasRole(proposerRole, signerAddress))) {
    for (const data of scheduleCalls) {
      const tx = await signer.sendTransaction({ to: admin, data });
      await tx.wait();
      console.log(chalk.green(`scheduled (tx: ${tx.hash})`));
    }
    fs.writeFileSync(stateFile, JSON.stringify(stored, null, 2));
    console.log(
      chalk.green(
        `scheduled ${ops.length} operation(s); execute with --execute after ${minDelay}s (state in ${stateFile})`,
      ),
    );
    return;
  }
  if (!args.proposer)
    throw Error(
      "the signer is not a timelock proposer: pass --proposer <address> (a proposer Safe, or an EOA on a fork)",
    );
  const proposer = ethers.getAddress(args.proposer);
  if (!(await timelock.hasRole(proposerRole, proposer)))
    throw Error(`${proposer} does not hold PROPOSER_ROLE on ${admin}`);
  if (forkLike) {
    console.log(chalk.yellow(`Fork network: impersonating proposer ${proposer}`));
    const who = await impersonate(proposer);
    for (const data of scheduleCalls) {
      const tx = await who.sendTransaction({ to: admin, data });
      await tx.wait();
      console.log(chalk.green(`scheduled (tx: ${tx.hash})`));
    }
    fs.writeFileSync(stateFile, JSON.stringify(stored, null, 2));
    console.log(chalk.green(`scheduled ${ops.length} operation(s); warp ${minDelay}s, then --execute`));
    return;
  }
  // A dev node that is not a declared rehearsal never reaches the Safe Transaction Service: the
  // proposal would land in the PRODUCTION queue signed by the key in .env (review R6C-13).
  if (await isForkNode(hre)) {
    throw Error(
      "this node answers dev-node methods but the run is not a declared rehearsal (CURATOR_GUARD_FORK=1): refusing to propose to the Safe service",
    );
  }
  try {
    for (const data of scheduleCalls) await saveForSafeBatchExecution({ from: proposer, to: admin, data, value: "0" });
    await executeBatchUsingSafe(hre);
  } catch (e: unknown) {
    // Nothing of ours may linger in the shared Safe batch file: another task would propose it, merged
    // with its own calls (review R6C-12).
    if (fs.existsSync(SAFE_BATCH_TXS_FILE)) fs.unlinkSync(SAFE_BATCH_TXS_FILE);
    throw e;
  }
  fs.writeFileSync(stateFile, JSON.stringify(stored, null, 2));
  console.log(
    chalk.blue(
      `After the proposer Safe executes scheduleBatch, wait ${minDelay}s, then re-run this command with --execute ` +
        `(anyone may execute; the windows close at ${ops.map((o) => iso(BigInt(o.deadline))).join(" / ")}); finally re-run ` +
        `without flags and expect 'Policy already in sync'.`,
    ),
  );
}

/// `--execute`: replay the stored operations (or the ones named with `--op`, rebuilt from the logs).
async function executeScheduled(
  hre: HardhatRuntimeEnvironment,
  args: SyncArgs,
  ctx: Ctx,
  plan: Plan,
  scan: Scan,
  stored: Scheduled | undefined,
  stateFile: string,
  wrap: (list: Call[], deadline: bigint) => string[],
  cancelHint: (id: string) => string,
  signer: Signer | undefined,
  impersonate: (who: string) => Promise<Signer>,
): Promise<void> {
  const { ethers } = hre;
  const timelock = ctx.timelock!;
  const { admin, guard, safe, chainId, forkLike } = ctx;
  const enforceData = ctx.guardIface.encodeFunctionData("enforce", [safe]);
  type Op = ScheduledOp & { block: number };
  let ops: Op[];
  if (args.op) {
    ops = [];
    const ids = [
      ...new Set(
        args.op
          .split(",")
          .map((id) => lower(id.trim()))
          .filter(Boolean),
      ),
    ];
    for (const id of ids) {
      const op = await rebuildOperation(ctx, scan, id);
      if (op.calls.some((c) => lower(c.target) !== lower(guard)))
        throw Error(`operation ${id} targets something other than the guard: not a sync operation`);
      const deadlines = op.calls.map((c) => unwrapExecuteBefore(ctx.guardIface, c.data)?.deadline);
      if (deadlines.some((d) => d === undefined))
        throw Error(`operation ${id} has a call that is not an executeBefore wrapper: not a sync operation`);
      const deadline = (deadlines as bigint[]).reduce((a, b) => (a < b ? a : b));
      ops.push({
        opId: op.opId,
        salt: op.salt,
        predecessor: op.predecessor,
        deadline: deadline.toString(),
        payloads: op.calls.map((c) => c.data),
        lifts: op.calls.some((c) => unwrapExecuteBefore(ctx.guardIface, c.data)?.data === enforceData),
        kind: op.kind,
        block: op.block,
      });
    }
  } else {
    if (!stored)
      throw Error(
        `${stateFile} not found: schedule first, or pass --op <id> to execute an operation rebuilt from the timelock's logs`,
      );
    if (stored.chainId !== chainId || lower(stored.timelock) !== lower(admin) || lower(stored.guard) !== lower(guard)) {
      throw Error(
        `${stateFile} belongs to chain ${stored.chainId} / timelock ${stored.timelock} / guard ${stored.guard}, not this run`,
      );
    }
    ops = [];
    for (const op of stored.operations) {
      // The file is a convenience cache: the id is re-derived from its payloads, and an id the chain
      // holds proves the chain holds exactly these payloads (review R6C-11).
      const recomputed: string = await timelock.hashOperationBatch(
        op.payloads.map(() => guard),
        op.payloads.map(() => 0n),
        op.payloads,
        op.predecessor,
        op.salt,
      );
      if (recomputed !== op.opId)
        throw Error(
          `${stateFile}: operation ${op.opId} does not hash to its payloads (tampered or corrupt file): delete it and use --op <id>`,
        );
      ops.push({ ...op, block: 0 });
    }
  }
  if (!ops.length) throw Error("nothing to execute");
  const now = BigInt((await ethers.provider.getBlock("latest"))!.timestamp);
  for (const op of ops) {
    console.log(
      chalk.blue(`operation ${op.opId} (predecessor ${op.predecessor}, executeBefore ${iso(BigInt(op.deadline))}):`),
    );
    for (const p of op.payloads) console.log(`    ${describeTimelockCall(ctx, guard, p)}`);
  }
  // Already executed operations of a partially executed set are skipped (a lift held back by the
  // cooldown on the previous run); the rest must still be scheduled and wanted.
  const pendingOps: Op[] = [];
  let unscheduled = 0;
  for (const op of ops) {
    const ts: bigint = await timelock.getTimestamp(op.opId);
    if (ts === 1n) {
      console.log(chalk.blue(`operation ${op.opId} was already executed`));
      continue;
    }
    if (ts === 0n) {
      console.log(
        chalk.yellow(
          `operation ${op.opId} is not scheduled on-chain (cancelled, or the proposer Safe has not executed scheduleBatch yet): skipping`,
        ),
      );
      ++unscheduled;
      continue;
    }
    if (ts > BigInt(op.deadline)) {
      throw Error(
        `operation ${op.opId} is dead on arrival: the proposer scheduled it for ${iso(ts)}, after its executeBefore deadline ` +
          `${iso(BigInt(op.deadline))} (the window counts from when the batch was prepared); ${cancelHint(op.opId)}, then schedule again`,
      );
    }
    pendingOps.push(op);
  }
  if (!pendingOps.length) {
    if (unscheduled) throw Error(`${unscheduled} operation(s) are not scheduled on-chain and none is executable`);
    console.log(chalk.green("every operation was already executed"));
    if (!args.dryRun && !args.op) removeState(stateFile);
    return;
  }
  if (!plan.calls.length) {
    for (const op of pendingOps)
      console.log(
        chalk.yellow(`the policy is already in sync; operation ${op.opId} is still queued: ${cancelHint(op.opId)}`),
      );
    return;
  }
  // Every stored call must still be wanted. Extra calls in the current diff (a fast-lane change during
  // the delay: a council-added guardian, a guardian's revocation) do not invalidate what was reviewed
  // and scheduled; they are picked up by the next sync.
  const lockedAt: bigint = await ctx.guardContract.lockedAt(safe);
  const runnable: Op[] = [];
  for (const op of pendingOps) {
    const wanted = new Set(wrap(plan.calls, BigInt(op.deadline)));
    const stale = op.payloads.filter((p) => !wanted.has(p));
    if (stale.length) {
      // Superseded or drifted: never executed by this task, but still executable by ANYONE until its
      // deadline, so it is named loudly rather than failing the run (review R7C-04).
      console.log(
        chalk.red(
          `NOT executing operation ${op.opId}: ${stale.length} of its call(s) are no longer what the current diff wants (the file or the chain ` +
            `changed since scheduling):\n    ${stale.map((p) => describeTimelockCall(ctx, guard, p)).join("\n    ")}\n  it stays executable by anyone until ${iso(BigInt(op.deadline))}: ${cancelHint(op.opId)}`,
        ),
      );
      continue;
    }
    if (now > BigInt(op.deadline)) {
      console.log(
        chalk.yellow(
          `operation ${op.opId} passed its executeBefore deadline ${iso(BigInt(op.deadline))} (dead): ${cancelHint(op.opId)}`,
        ),
      );
      continue;
    }
    if (op.lifts) {
      // The lift was reviewed with --allow-unlock when it was scheduled; a lockdown that happened AFTER
      // that is a new incident, which this execution must not end silently (review R6C-21). Without
      // the state file the preparation time is unknown, so a lift needs the flag outright (R7C-06).
      if (args.op) {
        if (!args.allowUnlock)
          throw Error(
            `operation ${op.opId} lifts a lockdown / Bypass: with --op the preparation time is unknown, so re-run with --allow-unlock only if the responders agree the incident is over`,
          );
        console.log(chalk.yellow(`WARNING: operation ${op.opId} lifts a lockdown / Bypass (--allow-unlock given)`));
      } else {
        const scheduledAt = BigInt(stored?.preparedAt ?? "0");
        if (lockedAt > scheduledAt) {
          const msg = `the Safe was locked down at ${iso(lockedAt)}, AFTER operation ${op.opId} was prepared (${iso(scheduledAt)}): a new incident`;
          if (!args.allowUnlock)
            throw Error(`${msg}; re-run with --allow-unlock only if the responders agree the incident is over`);
          console.log(chalk.yellow(`WARNING: ${msg}; lifting anyway (--allow-unlock)`));
        }
      }
    }
    runnable.push(op);
  }
  if (!runnable.length) {
    console.log(
      chalk.yellow("nothing executable: every pending operation is superseded, drifted or dead (cancel them)"),
    );
    return;
  }
  const executor = signer ?? (forkLike ? await impersonate(admin) : undefined);
  if (!executor) throw Error("no signer available to execute the timelock batch");
  const from = await executor.getAddress();
  let executed = 0;
  for (const op of runnable) {
    const data =
      op.kind === "single"
        ? timelock.interface.encodeFunctionData("execute", [guard, 0n, op.payloads[0], op.predecessor, op.salt])
        : timelock.interface.encodeFunctionData("executeBatch", [
            op.payloads.map(() => guard),
            op.payloads.map(() => 0n),
            op.payloads,
            op.predecessor,
            op.salt,
          ]);
    if (!(await timelock.isOperationReady(op.opId))) {
      const ts: bigint = await timelock.getTimestamp(op.opId);
      throw Error(`operation ${op.opId} is not ready before ${iso(ts)}`);
    }
    // The whole batch simulated as the executor: a revert is decoded before anything is sent, and the
    // gas is estimated again (the chain moved during the delay: a batch that fit when it was scheduled
    // can exceed the per-transaction cap now; review R8F-2).
    try {
      await ethers.provider.call({ from, to: admin, data });
      const gasNow = await ethers.provider.estimateGas({ from, to: admin, data });
      if (gasNow > BATCH_GAS_REFUSE && !args.allowLargeBatch)
        throw Error(
          `operation ${op.opId} is estimated at ${gasNow} gas now, above ${BATCH_GAS_REFUSE} (EIP-7825 caps a transaction at 16.7M): ` +
            `cancel it and re-sync in smaller batches, or pass --allow-large-batch`,
        );
      if (gasNow > BATCH_GAS_WARN)
        console.log(chalk.yellow(`WARNING: operation ${op.opId} is estimated at ${gasNow} gas now`));
    } catch (e: unknown) {
      const decoded = decodeRevert(ctx, e);
      if (op.lifts && decoded.startsWith("LockdownCooldown")) {
        console.log(
          chalk.yellow(
            `operation ${op.opId} would revert with ${decoded}: the cooldown has not passed; re-run --execute after ${iso(lockedAt + LOCKDOWN_COOLDOWN)}`,
          ),
        );
        break;
      }
      throw Error(`operation ${op.opId} would revert: ${decoded}`);
    }
    if (args.dryRun) {
      console.log(chalk.green(`dry run: operation ${op.opId} is ready, wanted and simulates fine`));
      continue;
    }
    const tx = await executor.sendTransaction({ to: admin, data });
    await tx.wait();
    ++executed;
    console.log(chalk.green(`executed timelock operation ${op.opId} (tx: ${tx.hash})`));
  }
  if (args.dryRun) return;
  // The state file goes only when every operation it lists is done; --op never touches it (R7C-05).
  if (!args.op && stored) {
    let allDone = true;
    for (const op of stored.operations) if ((await timelock.getTimestamp(op.opId)) !== 1n) allDone = false;
    if (allDone) removeState(stateFile);
  }
  for (const other of await pendingOperations(ctx, scan)) {
    if (ops.some((o) => o.opId === other.opId)) continue;
    console.log(
      chalk.yellow(
        `WARNING: operation ${other.opId} is still pending: ${other.description}; if abandoned, ${cancelHint(other.opId)}`,
      ),
    );
  }
  console.log(
    chalk.green(
      `${executed} of ${runnable.length} operation(s) executed; re-run without --execute to verify "already in sync"`,
    ),
  );
}

function removeState(stateFile: string): void {
  for (const f of [stateFile, `${stateFile}.manifest.json`]) if (fs.existsSync(f)) fs.unlinkSync(f);
}

/*//////////////////////////////////////////////////////////////
                        TIMELOCK LOG SCANS
//////////////////////////////////////////////////////////////*/

type ScheduledCall = { target: string; value: bigint; data: string };
type ScanOp = {
  opId: string;
  calls: ScheduledCall[];
  predecessor: string;
  delay: bigint;
  block: number;
  salt?: string;
  kind?: "single" | "batch";
};
type Scan = { from: number | undefined; ops: Map<string, ScanOp> };

/// Every `CallScheduled` of the timelock since its creation block, ALL targets (timelock-self and
/// foreign targets are the dangerous ones; review R6D-14 / R6A-3). Fails closed unless `tolerate`:
/// without a known creation block or on a failed scan the caller must opt in to go on blind.
async function timelockScan(hre: HardhatRuntimeEnvironment, ctx: Ctx, tolerate: boolean): Promise<Scan> {
  const timelock = ctx.timelock;
  const ops = new Map<string, ScanOp>();
  if (!timelock) return { from: undefined, ops };
  const from = await creationBlock(hre, ctx);
  if (from === undefined) {
    const msg = `the creation block of the timelock ${ctx.admin} is unknown (no deployment record): pass --timelock-block <N> or set CURATOR_GUARD_TIMELOCK_BLOCK, otherwise pending operations cannot be listed`;
    if (!tolerate) throw Error(`${msg} (--allow-pending to go on blind)`);
    console.log(chalk.yellow(`WARNING: ${msg}`));
    return { from, ops };
  }
  let logs: (Log | EventLog)[];
  try {
    logs = await scanLogs(hre, timelock, timelock.filters.CallScheduled(), from);
  } catch (e: unknown) {
    const msg = `could not scan the timelock's CallScheduled events (${errorText(e)})`;
    if (!tolerate) throw Error(`${msg}: refusing to schedule blind (--allow-pending to override)`);
    console.log(chalk.yellow(`WARNING: ${msg}`));
    return { from, ops };
  }
  for (const l of logs) {
    const a = (l as EventLog).args;
    const op = ops.get(a.id) ?? {
      opId: a.id,
      calls: [],
      predecessor: a.predecessor,
      delay: a.delay,
      block: l.blockNumber,
    };
    op.calls[Number(a.index)] = { target: a.target, value: a.value, data: a.data };
    ops.set(a.id, op);
  }
  try {
    for (const l of await scanLogs(hre, timelock, timelock.filters.CallSalt(), from)) {
      const a = (l as EventLog).args;
      const op = ops.get(a.id);
      if (op) op.salt = a.salt;
    }
  } catch {
    /* salts are needed for --op only; rebuildOperation says so */
  }
  return { from, ops };
}

async function pendingOperations(ctx: Ctx, scan: Scan): Promise<(ScanOp & { description: string })[]> {
  const out: (ScanOp & { description: string })[] = [];
  for (const op of scan.ops.values()) {
    if (!(await ctx.timelock!.isOperationPending(op.opId))) continue;
    out.push({ ...op, description: op.calls.map((c) => describeTimelockCall(ctx, c.target, c.data)).join(" | ") });
  }
  return out;
}

/// An operation rebuilt from the chain (no state file involved).
async function rebuildOperation(ctx: Ctx, scan: Scan, id: string): Promise<ScanOp & { salt: string }> {
  if (!/^0x[0-9a-fA-F]{64}$/.test(id)) throw Error(`--op ${id} is not an operation id`);
  if (scan.from === undefined)
    throw Error(
      "the timelock's creation block is unknown: pass --timelock-block <N> (or CURATOR_GUARD_TIMELOCK_BLOCK) so the operation can be rebuilt from its logs",
    );
  const op = scan.ops.get(id) ?? scan.ops.get(lower(id));
  if (!op) throw Error(`operation ${id} not found in the timelock's CallScheduled logs since block ${scan.from}`);
  // OpenZeppelin emits `CallSalt` only for a non-zero salt: no event MEANS salt 0 (review R8K-8); the
  // hash check below still decides.
  if (op.salt === undefined) op.salt = ZERO_HASH;
  const timelock = ctx.timelock!;
  // `schedule()` (one call, `hashOperation`) and `scheduleBatch()` (`hashOperationBatch`) hash
  // differently and are executed through different functions (review R7C-07).
  const batchHash: string = await timelock.hashOperationBatch(
    op.calls.map((c) => c.target),
    op.calls.map((c) => c.value),
    op.calls.map((c) => c.data),
    op.predecessor,
    op.salt,
  );
  let kind: "single" | "batch" | undefined = batchHash === op.opId ? "batch" : undefined;
  if (!kind && op.calls.length === 1) {
    const c = op.calls[0];
    const singleHash: string = await timelock.hashOperation(c.target, c.value, c.data, op.predecessor, op.salt);
    if (singleHash === op.opId) kind = "single";
  }
  if (!kind) throw Error(`operation ${id}: the logged calls do not hash to the id (incomplete log scan?)`);
  return { ...op, salt: op.salt, kind };
}

/// Deployment record, explicit block, or unknown.
async function creationBlock(hre: HardhatRuntimeEnvironment, ctx: Ctx): Promise<number | undefined> {
  const explicit = ctx.blockArg ?? process.env.CURATOR_GUARD_TIMELOCK_BLOCK;
  if (explicit !== undefined && explicit !== "") {
    if (!/^\d+$/.test(explicit)) throw Error(`timelock block must be a block number, got ${explicit}`);
    return Number(explicit);
  }
  const all = await hre.deployments.all();
  for (const who of [ctx.admin, ctx.guard]) {
    const d = Object.values(all).find((x) => lower(x.address) === lower(who));
    if (d?.receipt?.blockNumber !== undefined) return Number(d.receipt.blockNumber);
  }
  if (ctx.forkLike) {
    const from = Math.max(0, (await hre.ethers.provider.getBlockNumber()) - 50_000);
    console.log(
      chalk.yellow(
        `note: rehearsal without a deployment record: log scans start at block ${from} (older operations and grants are invisible)`,
      ),
    );
    return from;
  }
  return undefined;
}

/// `queryFilter` in adaptive chunks (public RPCs cap the range), never silently partial.
async function scanLogs(
  hre: HardhatRuntimeEnvironment,
  contract: Contract,
  filter: Parameters<Contract["queryFilter"]>[0],
  from: number,
): Promise<(Log | EventLog)[]> {
  const head = await hre.ethers.provider.getBlockNumber();
  const out: (Log | EventLog)[] = [];
  let chunk = 50_000;
  let a = from;
  while (a <= head) {
    const b = Math.min(head, a + chunk - 1);
    try {
      out.push(...(await contract.queryFilter(filter, a, b)));
      a = b + 1;
    } catch (e: unknown) {
      if (chunk <= 1_000) throw Error(`log scan failed for blocks ${a}-${b}: ${errorText(e)}`);
      chunk = Math.floor(chunk / 4);
    }
  }
  return out;
}

/*//////////////////////////////////////////////////////////////
                    SIMULATION, DECODING, HELPERS
//////////////////////////////////////////////////////////////*/

/// Each wrapped call simulated as the admin; returns the summed gas estimate. Calls that depend on an
/// earlier call of the same batch (`addAllowedValues` before its `allowFunction`: `NoOneOfRule`) are
/// estimated by a heuristic instead.
async function simulateAsAdmin(hre: HardhatRuntimeEnvironment, ctx: Ctx, payloads: string[]): Promise<bigint> {
  const { ethers } = hre;
  let gas = 0n;
  for (const data of payloads) {
    try {
      gas += await ethers.provider.estimateGas({ from: ctx.admin, to: ctx.guard, data });
    } catch (e: unknown) {
      const decoded = decodeRevert(ctx, e);
      if (decoded.startsWith("NoOneOfRule")) {
        const inner = unwrapExecuteBefore(ctx.guardIface, data);
        const members = inner ? Number(ctx.guardIface.decodeFunctionData("addAllowedValues", inner.data)[4].length) : 1;
        gas += 60_000n + 48_000n * BigInt(members);
        continue;
      }
      if (decoded.startsWith("LockdownCooldown")) {
        const lockedAt: bigint = await ctx.guardContract.lockedAt(ctx.safe);
        console.log(
          chalk.yellow(
            `note: ${describeTimelockCall(ctx, ctx.guard, data)} is held back by the lockdown cooldown until ${iso(lockedAt + LOCKDOWN_COOLDOWN)} ` +
              `(before the timelock delay ends, unless the Safe is locked again)`,
          ),
        );
        gas += 80_000n;
        continue;
      }
      throw Error(
        `${describeTimelockCall(ctx, ctx.guard, data)} would revert as the admin right now: ${decoded} (dead on arrival: fix the file or the chain first)`,
      );
    }
  }
  return gas;
}

function decodeRevert(ctx: Ctx, e: unknown): string {
  const err = e as { data?: string; error?: { data?: string }; info?: { error?: { data?: string } }; message?: string };
  const data = err.data ?? err.error?.data ?? err.info?.error?.data;
  if (typeof data === "string" && data.startsWith("0x") && data.length >= 10) {
    for (const iface of [ctx.guardIface, ctx.timelock?.interface]) {
      try {
        const parsed = iface?.parseError(data);
        if (parsed) return `${parsed.name}(${parsed.args.map(String).join(", ")})`;
      } catch {
        /* not this ABI */
      }
    }
    if (data === "0xd6bda275") {
      return "FailedCall() (the timelock's wrapper for a call that reverted WITHOUT data: an unknown selector, malformed arguments, an enum out of range, or value sent to a non-payable function)";
    }
    if (data.length === 10) return `truncated error ${data} (a selector without its arguments)`;
    return `revert data ${data}`;
  }
  if (typeof data === "string" && data.length <= 2)
    return "reverted without data (out of gas, or the target refused the calldata itself: unknown selector, malformed arguments, value to a non-payable function)";
  return errorText(e);
}

function unwrapExecuteBefore(iface: Interface, data: string): { deadline: bigint; data: string } | undefined {
  try {
    const parsed = iface.parseTransaction({ data });
    if (parsed?.name !== "executeBefore") return undefined;
    return { deadline: BigInt(parsed.args[0]), data: parsed.args[1] };
  } catch {
    return undefined;
  }
}

/// Human text for a call scheduled on the timelock, decoded through the guard's ABI (executeBefore
/// unwrapped), the timelock's own ABI (flagged GOVERNANCE), or marked FOREIGN.
function describeTimelockCall(ctx: Ctx, target: string, data: string): string {
  if (lower(target) === lower(ctx.guard)) {
    const inner = unwrapExecuteBefore(ctx.guardIface, data);
    const prefix = inner ? `executeBefore(${iso(inner.deadline)}) ` : "";
    const text = describeGuardCall(ctx.guardIface, inner ? inner.data : data);
    const sensitive =
      /^(grantRole|revokeRole|renounceRole|beginDefaultAdminTransfer|changeDefaultAdminDelay|setDeploymentGuardian|setGuardian|bypass|approveTransaction|enforce)\b/.test(
        text,
      );
    return `${prefix}${text}${sensitive ? "  [ROLE / INCIDENT-SENSITIVE]" : ""}`;
  }
  if (ctx.timelock && lower(target) === lower(ctx.admin)) {
    try {
      const parsed = ctx.timelock.interface.parseTransaction({ data });
      return `TIMELOCK SELF-CALL ${parsed?.name}(${parsed?.args.map(String).join(", ")})  [GOVERNANCE]`;
    } catch {
      return `TIMELOCK SELF-CALL ${data.slice(0, 10)}…  [GOVERNANCE, undecodable]`;
    }
  }
  return `FOREIGN TARGET ${target} data ${data.slice(0, 10)}… (${(data.length - 2) / 2} bytes)`;
}

function describeGuardCall(iface: Interface, data: string): string {
  try {
    const parsed = iface.parseTransaction({ data });
    if (!parsed) return `undecodable ${data.slice(0, 10)}`;
    const args = parsed.args.map((a, i) => {
      const t = parsed.fragment.inputs[i];
      if (t.type === "bytes4")
        return `${a}${KNOWN_SIGNATURES.get(String(a)) ? ` ${KNOWN_SIGNATURES.get(String(a))}` : ""}`;
      if (t.type === "bytes32[]") return `[${(a as string[]).map(wordText).join(", ")}]`;
      if (t.baseType === "array" || t.baseType === "tuple")
        return JSON.stringify(a, (_, v) => (typeof v === "bigint" ? v.toString() : v));
      return String(a);
    });
    return `${parsed.name}(${args.join(", ")})`;
  } catch {
    return `undecodable ${data.slice(0, 10)}`;
  }
}

/// The PUSH solc emits for a 4-byte selector: leading zero bytes are dropped (`PUSH1`..`PUSH4`).
function pushOf(selector: string): string {
  const hex = lower(selector.slice(2)).replace(/^(00)+/, "") || "00";
  return (0x5f + hex.length / 2).toString(16) + hex;
}

function wordText(word: string): string {
  const w = lower(word);
  if (/^0x0{24}[0-9a-f]{40}$/.test(w) && !/^0x0{54}[0-9a-f]{10}$/.test(w)) return "0x" + w.slice(26);
  return BigInt(w).toString();
}

function dayArg(raw: string, min: number, max: number, flag: string): bigint {
  if (!/^\d+$/.test(raw)) throw Error(`${flag} must be an integer number of days (${min}-${max}), got ${raw}`);
  const n = Number(raw);
  if (n < min || n > max) throw Error(`${flag} must be between ${min} and ${max} days, got ${raw}`);
  return BigInt(n);
}

function clockSanity(blockTimestamp: number, forkLike: boolean): void {
  const drift = Math.abs(Date.now() / 1000 - blockTimestamp);
  if (drift > 3600 && !forkLike) {
    console.log(
      chalk.yellow(
        `WARNING: the chain's clock (${iso(blockTimestamp)}) is ${Math.round(drift / 60)} minutes away from this machine's: deadlines are computed from the chain`,
      ),
    );
  }
}

/// Runtime code without its CBOR metadata tail (the last two bytes give the tail's length).
function stripMetadata(code: string): string {
  const hex = lower(code.startsWith("0x") ? code.slice(2) : code);
  if (hex.length < 4) return hex;
  const cborLength = parseInt(hex.slice(-4), 16);
  const total = (cborLength + 2) * 2;
  return total < hex.length ? hex.slice(0, hex.length - total) : hex;
}

async function safeOwnersOf(hre: HardhatRuntimeEnvironment, safe: string): Promise<Set<string>> {
  const out = new Set<string>();
  if ((await hre.ethers.provider.getCode(safe)) === "0x" || !(await isSafeContract(hre, safe))) return out;
  for (const o of (await (await hre.ethers.getContractAt("ISafe", safe)).getOwners()) as string[]) out.add(lower(o));
  return out;
}

/// The Safe's proxy and singleton runtime code against the hashes the guard supports
/// (`SAFE_PROXY_CODEHASHES` / `SAFE_SINGLETON_CODEHASHES`); `masterCopy()` must answer one word.
async function safeBuildOf(hre: HardhatRuntimeEnvironment, safe: string): Promise<{ ok: boolean; why: string }> {
  const { ethers } = hre;
  const proxyHash = ethers.keccak256(await ethers.provider.getCode(safe));
  const proxy = SAFE_PROXY_CODEHASHES.get(proxyHash);
  if (!proxy) return { ok: false, why: `the account's code (${proxyHash}) is not a canonical Safe proxy` };
  let answer: string;
  try {
    answer = await ethers.provider.call({ to: safe, data: "0xa619486e" }); // masterCopy()
  } catch (e: unknown) {
    return { ok: false, why: `masterCopy() reverted (${errorText(e)})` };
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(answer)) return { ok: false, why: `masterCopy() answered ${answer}, not one word` };
  const singleton = ethers.getAddress("0x" + answer.slice(-40));
  const singletonHash = ethers.keccak256(await ethers.provider.getCode(singleton));
  const release = SAFE_SINGLETON_CODEHASHES.get(singletonHash);
  if (!release)
    return { ok: false, why: `the singleton ${singleton} (${singletonHash}) is not a canonical Safe build` };
  return { ok: true, why: `${proxy} in front of ${release} (${singleton})` };
}

/// `true` when `account` answers `getOwners()` like a Safe; `false` on an EVM-level answer that is
/// not one; a transport error is thrown (never "not a Safe").
async function isSafeContract(hre: HardhatRuntimeEnvironment, account: string): Promise<boolean> {
  try {
    const owners: string[] = await (await hre.ethers.getContractAt("ISafe", account)).getOwners();
    return Array.isArray(owners) && owners.length > 0;
  } catch (e: unknown) {
    const code = (e as { code?: string }).code;
    const message = errorText(e);
    if (code === "CALL_EXCEPTION" || code === "BAD_DATA" || /revert|could not decode result data/i.test(message))
      return false;
    throw Error(`could not read ${account} as a Safe (${message}): refusing to continue on a failed read`);
  }
}

/// A rehearsal is a dev node (RPC probe) that ALSO reports chain 31337 or is declared with
/// CURATOR_GUARD_FORK=1 (an anvil fork keeps the forked chain id): the RPC alone decides nothing.
async function isRehearsal(hre: HardhatRuntimeEnvironment): Promise<boolean> {
  if (!(await isForkNode(hre))) return false;
  return Number(await hre.getChainId()) === 31337 || process.env.CURATOR_GUARD_FORK === "1";
}

/// A fork / local dev node answers `hardhat_metadata` (hardhat) or `anvil_nodeInfo` (anvil); a real RPC
/// answers neither. Never trust the network name: `--network localhost` can point at mainnet.
async function isForkNode(hre: HardhatRuntimeEnvironment): Promise<boolean> {
  for (const method of ["hardhat_metadata", "anvil_nodeInfo"]) {
    try {
      await hre.network.provider.send(method, []);
      return true;
    } catch {
      /* not that kind of node */
    }
  }
  return false;
}

/// The admin as a `TimelockController`, or `undefined` when it does not answer `getMinDelay()`.
async function timelockAt(hre: HardhatRuntimeEnvironment, admin: string): Promise<Contract | undefined> {
  const { ethers } = hre;
  if ((await ethers.provider.getCode(admin)) === "0x") return undefined;
  const timelock = (await ethers.getContractAt("CuratorGuardTimelock", admin)) as unknown as Contract;
  try {
    await timelock.getMinDelay();
    return timelock;
  } catch {
    return undefined;
  }
}

/*//////////////////////////////////////////////////////////////
                        POLICY FILE VALIDATION
//////////////////////////////////////////////////////////////*/

function loadPolicy(file: string): { policy: Policy; policyText: string; warnings: string[] } {
  const policyText = fs.readFileSync(file, "utf8");
  rejectDuplicateKeys(policyText, file);
  const policy = JSON.parse(policyText) as Policy;
  const warnings = validatePolicy(policy);
  return { policy, policyText, warnings };
}

/// `JSON.parse` keeps the LAST duplicate key, so a trailing `"mode": "Enforced"` or a second
/// `"functions"` array would silently override what a reviewer read. Refuse duplicates anywhere, and
/// refuse escaped or non-ASCII KEYS outright: `"mode"` is `mode` to `JSON.parse` and a different
/// key to a reader (review R6C-06).
function rejectDuplicateKeys(text: string, where: string): void {
  const stack: { keys: Set<string> | null }[] = [];
  let i = 0;
  const readString = (): { raw: string; escaped: boolean } => {
    // assumes text[i] === '"'
    let out = "";
    let escaped = false;
    ++i;
    while (i < text.length) {
      const c = text[i];
      if (c === "\\") {
        escaped = true;
        out += text.slice(i, i + 2);
        i += 2;
        continue;
      }
      if (c === '"') {
        ++i;
        return { raw: out, escaped };
      }
      out += c;
      ++i;
    }
    throw Error(`${where}: unterminated string`);
  };
  while (i < text.length) {
    const c = text[i];
    if (c === "{") {
      stack.push({ keys: new Set() });
      ++i;
    } else if (c === "[") {
      stack.push({ keys: null });
      ++i;
    } else if (c === "}" || c === "]") {
      stack.pop();
      ++i;
    } else if (c === '"') {
      const { raw, escaped } = readString();
      let j = i;
      while (j < text.length && /\s/.test(text[j])) ++j;
      const top = stack[stack.length - 1];
      if (text[j] === ":" && top && top.keys) {
        if (escaped || !/^[\x20-\x7e]*$/.test(raw))
          throw Error(`${where}: key '${raw}' uses escapes or non-ASCII characters (write keys in plain ASCII)`);
        if (top.keys.has(raw)) throw Error(`${where}: duplicate key '${raw}' (JSON.parse would keep the last one)`);
        top.keys.add(raw);
      }
    } else {
      ++i;
    }
  }
}

/// Canonical selector: the signature must be in canonical ABI form (no parameter names, no `uint`
/// aliases) so the hash the contract sees is the hash the reviewer reads; an explicit `selector`
/// must agree with it; a selector that belongs to a well-known function must carry that function's
/// own signature text.
function selectorOf(f: PolicyFunction): string {
  if (!f.signature) throw Error(`Function entry for ${f.target} needs a canonical signature`);
  const fragment = FunctionFragment.from(f.signature);
  if (fragment.format("sighash") !== f.signature)
    throw Error(`${f.signature}: not canonical, write it as ${fragment.format("sighash")}`);
  if (f.selector && lower(f.selector) !== fragment.selector)
    throw Error(`${f.signature}: selector ${f.selector} does not match ${fragment.selector}`);
  const known = KNOWN_SIGNATURES.get(fragment.selector);
  if (known && known !== f.signature) {
    throw Error(
      `${f.signature}: selector ${fragment.selector} is ${known} (a 4-byte collision: the guard would allow ${known})`,
    );
  }
  return fragment.selector;
}

/// The static type behind each head word of a function's parameters (`undefined` for the OFFSET word
/// of a dynamic parameter, which is never a value): one entry per 32-byte head word.
function headTypes(fragment: FunctionFragment): (string | undefined)[] {
  const isDynamic = (t: ParamType): boolean => {
    if (t.baseType === "string" || t.baseType === "bytes") return true;
    if (t.isArray()) return t.arrayLength === -1 || isDynamic(t.arrayChildren!);
    if (t.isTuple()) return t.components!.some(isDynamic);
    return false;
  };
  const words = (t: ParamType): (string | undefined)[] => {
    if (isDynamic(t)) return [undefined];
    if (t.isArray()) return Array.from({ length: t.arrayLength! }, () => words(t.arrayChildren!)).flat();
    if (t.isTuple()) return t.components!.map(words).flat();
    return [t.type];
  };
  return fragment.inputs.map(words).flat();
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const isAddressString = (v: unknown): v is string => typeof v === "string" && /^0x[0-9a-fA-F]{40}$/.test(v);
const isZeroAddress = (v: string) => /^0x0{40}$/.test(v);

function assertKeys(obj: Record<string, unknown>, allowed: string[], where: string): void {
  for (const k of Object.keys(obj)) {
    if (k.startsWith("$comment")) continue;
    if (!allowed.includes(k)) throw Error(`${where}: unknown key '${k}' (allowed: ${allowed.join(", ")})`);
  }
}

/// EIP-55 is mandatory: a lowercase address carries no checksum at all.
function assertChecksummed(v: string, where: string): void {
  if (getAddress(v) !== v) throw Error(`${where}: address ${v} must be EIP-55 checksummed (${getAddress(v)})`);
}

/// A rule value as the 32-byte word the contract compares, type-aware when the word's type is known:
/// an address word takes a checksummed address (or a number that fits 160 bits), a `uintN` word a value
/// that fits N bits, a `bool` 0 or 1.
/// The `wordIndex` the chain stores: bit 15 set for a tail-hash rule.
const onChainWordIndex = (r: PolicyRule) => (r.tail ? r.wordIndex | TAIL_FLAG : r.wordIndex);

/// A rule's 32-byte word. For a tail rule the value is the hash itself (32-byte hex) or the raw tail
/// bytes (hex of any other length), hashed here.
function ruleWord(r: PolicyRule, v: string): string {
  if (!r.tail) return toWord(v);
  if (!/^0x([0-9a-fA-F]{2})*$/.test(v))
    throw Error(`tail rule value ${v} must be hex (a 32-byte hash, or the raw tail bytes)`);
  return /^0x[0-9a-fA-F]{64}$/.test(v) ? lower(v) : lower(keccak256(v));
}

function toWord(v: string, type?: string): string {
  let word: bigint;
  if (/^\d+$/.test(v)) word = BigInt(v);
  else if (isAddress(v)) {
    assertChecksummed(v, "rule value");
    word = BigInt(getAddress(v));
  } else if (/^0x[0-9a-fA-F]{64}$/.test(v)) word = BigInt(v);
  else throw Error(`Unsupported rule value: ${v} (use a decimal string, a checksummed address or a 32-byte hex word)`);
  if (word > UINT256_MAX) throw Error(`rule value ${v} does not fit 256 bits`);
  if (type) {
    const m = /^uint(\d+)$/.exec(type);
    if (type === "address" && word >> 160n !== 0n) throw Error(`rule value ${v} does not fit an address word`);
    if (type === "bool" && word > 1n) throw Error(`rule value ${v} is not a bool`);
    if (m && word >> BigInt(m[1]) !== 0n) throw Error(`rule value ${v} does not fit ${type}`);
  }
  return lower(zeroPadValue(toBeHex(word), 32));
}

function validatePolicy(p: unknown): string[] {
  const warnings: string[] = [];
  if (!isPlainObject(p)) throw Error("policy must be a JSON object");
  assertKeys(
    p,
    [
      "chainId",
      "guard",
      "safe",
      "mode",
      "requiredFallbackHandler",
      "$allowNonZeroHandler",
      "$allowUnenforcedHandler",
      "guardians",
      "multiSendUnwrappers",
      "modules",
      "nativeTransfers",
      "functions",
    ],
    "policy",
  );
  if (!isAddressString(p.safe) || isZeroAddress(p.safe)) throw Error("policy.safe must be a non-zero address");
  assertChecksummed(p.safe, "policy.safe");
  const safe = p.safe;
  const guard = typeof p.guard === "string" ? p.guard : undefined;
  if (p.chainId !== undefined && !(Number.isInteger(p.chainId) && (p.chainId as number) > 0))
    throw Error("policy.chainId must be a positive integer");
  if (guard !== undefined) {
    if (!isAddressString(guard) || isZeroAddress(guard)) throw Error("policy.guard must be a non-zero address");
    assertChecksummed(guard, "policy.guard");
    if (lower(guard) === lower(safe)) throw Error("policy.guard must not be the Safe");
  } else if (p.guard !== undefined) throw Error("policy.guard must be an address");
  const reserved = (a: string) =>
    isZeroAddress(a) || lower(a) === lower(safe) || (guard !== undefined && lower(a) === lower(guard));
  if (!MODES.includes(p.mode as Mode))
    throw Error(`policy.mode must be one of ${MODES.join(", ")} (Bypass is an incident action, never a desired state)`);
  if (!isPlainObject(p.requiredFallbackHandler))
    throw Error("policy.requiredFallbackHandler is required: { handler, enforce }");
  assertKeys(p.requiredFallbackHandler, ["handler", "enforce"], "policy.requiredFallbackHandler");
  if (!isAddressString(p.requiredFallbackHandler.handler))
    throw Error("requiredFallbackHandler.handler must be an address");
  assertChecksummed(p.requiredFallbackHandler.handler, "requiredFallbackHandler.handler");
  if (!isZeroAddress(p.requiredFallbackHandler.handler) && reserved(p.requiredFallbackHandler.handler))
    throw Error(
      "requiredFallbackHandler.handler is never the Safe itself nor the guard (a handler forwards the hooks)",
    );
  if (typeof p.requiredFallbackHandler.enforce !== "boolean")
    throw Error("requiredFallbackHandler.enforce must be a boolean");
  for (const marker of ["$allowNonZeroHandler", "$allowUnenforcedHandler"] as const) {
    if (p[marker] !== undefined && p[marker] !== true) throw Error(`policy.${marker} must be true when present`);
  }
  if (
    p.requiredFallbackHandler.enforce &&
    !isZeroAddress(p.requiredFallbackHandler.handler) &&
    p.$allowNonZeroHandler !== true
  ) {
    throw Error(
      "requiredFallbackHandler: a non-zero handler re-opens the EIP-1271 path (it must be stateless) and a typo freezes " +
        'every policy transaction; set "$allowNonZeroHandler": true to confirm it is intended',
    );
  }
  if (!p.requiredFallbackHandler.enforce && p.$allowUnenforcedHandler !== true) {
    throw Error(
      'requiredFallbackHandler.enforce is false: the EIP-1271 defence (docs section 4) is then off; set "$allowUnenforcedHandler": true to confirm it is intended',
    );
  }
  if (!Array.isArray(p.guardians) || !p.guardians.every(isAddressString)) {
    throw Error(
      "policy.guardians is required: an array of addresses (may be empty, but incident response needs at least one)",
    );
  }
  const seenGuardians = new Set<string>();
  for (const g of p.guardians) {
    assertChecksummed(g, "policy.guardians");
    if (reserved(g)) throw Error(`policy.guardians: ${g} cannot be a guardian (zero, the Safe or the guard)`);
    if (seenGuardians.has(lower(g))) throw Error(`policy.guardians: ${g} listed twice`);
    seenGuardians.add(lower(g));
  }
  if (p.guardians.length > MAX_GUARDIANS) throw Error(`policy.guardians: at most ${MAX_GUARDIANS} (the contract cap)`);
  if (p.guardians.length === 0 && p.mode === "Enforced")
    warnings.push("no guardian listed: only the council (and the timelock, after its delay) can lock this Safe down");
  for (const listKey of ["multiSendUnwrappers", "modules", "nativeTransfers"] as const) {
    const list = p[listKey];
    if (list === undefined) continue;
    if (!Array.isArray(list) || !list.every(isAddressString))
      throw Error(`policy.${listKey} must be an array of addresses`);
    const dup = new Set<string>();
    for (const a of list) {
      assertChecksummed(a, `policy.${listKey}`);
      if (reserved(a))
        throw Error(`policy.${listKey}: ${a} is refused (zero, the Safe or the guard; the contract rejects it)`);
      if (dup.has(lower(a))) throw Error(`policy.${listKey}: ${a} listed twice`);
      dup.add(lower(a));
    }
  }
  if (!Array.isArray(p.functions)) throw Error("policy.functions must be an array");
  const unwrappers = new Set(((p.multiSendUnwrappers as string[] | undefined) ?? []).map(lower));
  for (const t of (p.nativeTransfers as string[] | undefined) ?? []) {
    if (unwrappers.has(lower(t)))
      throw Error(`policy.nativeTransfers: ${t} is a registered unwrapper; a batch build is never a plain-call target`);
  }
  const membersPerTarget = new Map<string, number>();
  const selectorsPerTarget = new Map<string, number>();
  const entries = new Set<string>();
  for (const f of p.functions as unknown[]) {
    if (!isPlainObject(f)) throw Error("policy.functions entries must be objects");
    assertKeys(
      f,
      ["target", "signature", "selector", "allowValue", "unconstrained", "$allowSensitive", "rules", "note"],
      "function",
    );
    const where = `${(f.signature as string | undefined) ?? "?"} on ${f.target}`;
    if (!isAddressString(f.target)) throw Error(`${where}: target must be an address`);
    assertChecksummed(f.target, where);
    if (reserved(f.target)) throw Error(`${where}: the zero address, the Safe and the guard can never be targets`);
    if (typeof f.signature !== "string")
      throw Error(`${where}: signature (canonical, e.g. "approve(address,uint256)") is required`);
    if (f.selector !== undefined && !(typeof f.selector === "string" && /^0x[0-9a-fA-F]{8}$/.test(f.selector)))
      throw Error(`${where}: selector must be a 4-byte hex string`);
    for (const flag of ["allowValue", "unconstrained"] as const) {
      if (f[flag] !== undefined && typeof f[flag] !== "boolean") throw Error(`${where}: ${flag} must be a boolean`);
    }
    if (f.$allowSensitive !== undefined && f.$allowSensitive !== true)
      throw Error(`${where}: $allowSensitive must be true when present`);
    if (
      f.note !== undefined &&
      (typeof f.note !== "string" || !/^[\x20-\x7e]*$/.test(f.note) || f.note.length > MAX_NOTE_LENGTH)
    ) {
      throw Error(
        `${where}: note must be printable ASCII of at most ${MAX_NOTE_LENGTH} characters (it is echoed to terminals)`,
      );
    }
    const fn = f as unknown as PolicyFunction;
    const selector = selectorOf(fn); // canonical signature / selector agreement / known-selector collision
    const entry = key(fn.target, selector);
    if (entries.has(entry)) throw Error(`${where}: duplicate entry for ${selector} on ${fn.target}`);
    entries.add(entry);
    if (unwrappers.has(lower(fn.target)))
      throw Error(
        `${where}: the target is a registered unwrapper; a batch build is only ever a delegatecall unwrapper`,
      );
    if (selector === MULTISEND_SELECTOR)
      throw Error(
        `${where}: multiSend(bytes) is never a function: as a plain call the entries run from the library, unchecked (register the build as an unwrapper instead)`,
      );
    const perTargetSelectors = (selectorsPerTarget.get(lower(fn.target)) ?? 0) + 1;
    selectorsPerTarget.set(lower(fn.target), perTargetSelectors);
    if (perTargetSelectors > MAX_SELECTORS)
      throw Error(`${fn.target}: more than ${MAX_SELECTORS} functions on one target (the contract cap)`);
    if (SENSITIVE.has(selector) && fn.$allowSensitive !== true) {
      throw Error(
        `${where}: changes ownership, code, roles or the Safe itself: never routine curator work; set "$allowSensitive": true if it is really intended`,
      );
    }
    if (SELF_DISPATCH.has(selector) && fn.$allowSensitive !== true) {
      throw Error(
        `${where}: its payload embeds further calls that run as the Safe with no selector check and no rule (every sibling rule of this ` +
          `target is void once it is allowed): bind ONE reviewed payload with a "tail": true rule, or set "$allowSensitive": true if the whole batch surface is really intended`,
      );
    }
    const rules = fn.rules ?? [];
    if (!Array.isArray(rules)) throw Error(`${where}: rules must be an array`);
    if (rules.length > MAX_RULES) throw Error(`${where}: at most ${MAX_RULES} rules`);
    const types = headTypes(FunctionFragment.from(fn.signature));
    let members = 0;
    const perWord = new Map<number, RuleKind[]>();
    for (const r of rules as unknown[]) {
      if (!isPlainObject(r)) throw Error(`${where}: rules entries must be objects`);
      assertKeys(r, ["kind", "wordIndex", "tail", "value", "values"], `${where} rule`);
      const rule = r as unknown as PolicyRule;
      if (!RULE_KINDS.includes(rule.kind)) throw Error(`${where}: unknown rule kind ${String(rule.kind)}`);
      if (!Number.isInteger(rule.wordIndex) || rule.wordIndex < 0 || rule.wordIndex >= TAIL_FLAG)
        throw Error(`${where}: bad wordIndex`);
      if (rule.tail !== undefined && rule.tail !== true) throw Error(`${where}: tail must be true when present`);
      if (rule.wordIndex >= types.length)
        throw Error(`${where}: rule word ${rule.wordIndex} is beyond the ${types.length} head word(s)`);
      let type = types[rule.wordIndex];
      if (rule.tail) {
        // The hash of the calldata tail from that word: only meaningful from a dynamic parameter's head
        // word on (before it the words are static and have their own rules), with `EqualTo` / `OneOf`.
        if (rule.kind !== "EqualTo" && rule.kind !== "OneOf")
          throw Error(`${where}: a tail rule is EqualTo (one payload) or OneOf (a set of payloads)`);
        const firstDynamic = types.indexOf(undefined);
        if (firstDynamic === -1 || rule.wordIndex < firstDynamic)
          throw Error(
            `${where}: a tail rule starts at the first dynamic parameter's head word (word ${rule.wordIndex} is static; bind it with a word rule)`,
          );
        // Only the FIRST dynamic parameter's head word puts every offset word inside the hash. From a
        // later word the offset of an earlier dynamic parameter is free, and the callee decodes that
        // parameter from wherever the offset points (empty, or another parameter's bytes): the rule
        // would bind the bytes but not their meaning (review G9b-1).
        if (rule.wordIndex > firstDynamic)
          throw Error(
            `${where}: a tail rule must start at the FIRST dynamic parameter's head word (word ${firstDynamic}), not word ${rule.wordIndex}: the offset of parameter ${firstDynamic} would stay outside the hash`,
          );
        type = "bytes32"; // the subject is a hash
      } else if (type === undefined)
        throw Error(
          `${where}: word ${rule.wordIndex} is a dynamic parameter offset, rules cannot bind it (use "tail": true)`,
        );
      const kinds = perWord.get(onChainWordIndex(rule)) ?? [];
      if (kinds.includes(rule.kind))
        throw Error(
          `${where}: two ${rule.kind} rules on word ${rule.wordIndex} (the chain keeps one set / one bound per word)`,
        );
      kinds.push(rule.kind);
      perWord.set(onChainWordIndex(rule), kinds);
      if (/^int\d*$/.test(type))
        warnings.push(
          `${where}: word ${rule.wordIndex} is ${type}; the guard compares words unsigned, a negative value reads as a huge one`,
        );
      if (rule.kind === "OneOf") {
        if (!Array.isArray(rule.values) || !rule.values.every((v) => typeof v === "string"))
          throw Error(`${where}: OneOf needs 'values' (strings)`);
        if (rule.values.length === 0)
          throw Error(`${where}: an empty OneOf set makes the function unusable (it always reverts)`);
        if (rule.values.length > MAX_ALLOWED_VALUES)
          throw Error(`${where}: OneOf set exceeds ${MAX_ALLOWED_VALUES} members (the contract cap)`);
        if (rule.value !== undefined) throw Error(`${where}: OneOf takes 'values', not 'value'`);
        const words = new Set<string>();
        for (const v of rule.values) {
          const w = rule.tail ? ruleWord(rule, v) : toWord(v, type);
          if (words.has(w)) throw Error(`${where}: OneOf member ${v} listed twice`);
          words.add(w);
        }
        members += rule.values.length;
      } else if (rule.kind === "EqualToSafe") {
        if (rule.value !== undefined || rule.values !== undefined) throw Error(`${where}: EqualToSafe takes no value`);
        if (type !== "address")
          throw Error(`${where}: EqualToSafe on word ${rule.wordIndex} which is ${type}, not an address`);
      } else {
        if (typeof rule.value !== "string")
          throw Error(`${where}: ${rule.kind} needs 'value' as a string (decimal, address or 32-byte hex)`);
        if (rule.values !== undefined) throw Error(`${where}: ${rule.kind} takes 'value', not 'values'`);
        const w = BigInt(rule.tail ? ruleWord(rule, rule.value) : toWord(rule.value, type));
        if (rule.kind === "LessThanOrEqual" && w === UINT256_MAX)
          throw Error(`${where}: LessThanOrEqual 2^256-1 on word ${rule.wordIndex} bounds nothing`);
        if (rule.kind === "GreaterThanOrEqual" && w === 0n)
          throw Error(`${where}: GreaterThanOrEqual 0 on word ${rule.wordIndex} bounds nothing`);
      }
    }
    for (const [word, kinds] of perWord) {
      const lo = (rules as PolicyRule[]).find((r) => onChainWordIndex(r) === word && r.kind === "GreaterThanOrEqual");
      const hi = (rules as PolicyRule[]).find((r) => onChainWordIndex(r) === word && r.kind === "LessThanOrEqual");
      if (lo && !kinds.some((k) => UPPER_BOUND_KINDS.includes(k)))
        throw Error(`${where}: GreaterThanOrEqual on word ${word} needs an upper bound on the same word`);
      if (lo && hi && BigInt(toWord(lo.value!)) > BigInt(toWord(hi.value!)))
        throw Error(`${where}: floor above ceiling on word ${word} (the function could never be called)`);
      if (kinds.includes("EqualTo") && kinds.length > 1)
        throw Error(
          `${where}: EqualTo on word ${word} next to another rule on the same word is redundant or contradictory`,
        );
      if (kinds.includes("EqualToSafe") && kinds.includes("OneOf"))
        throw Error(`${where}: EqualToSafe and OneOf on word ${word} together`);
    }
    if (members > MAX_ONEOF_MEMBERS_PER_FUNCTION) {
      throw Error(
        `${where}: ${members} OneOf members across its rules exceed ${MAX_ONEOF_MEMBERS_PER_FUNCTION}: revokeFunction ` +
          `iterates every member (≈ 4.3k gas each), keep incident narrowing far below a block`,
      );
    }
    const targetKey = lower(fn.target);
    const targetMembers = (membersPerTarget.get(targetKey) ?? 0) + members;
    membersPerTarget.set(targetKey, targetMembers);
    if (targetMembers > MAX_ONEOF_MEMBERS_PER_TARGET) {
      throw Error(
        `${fn.target}: ${targetMembers} OneOf members across its functions exceed ${MAX_ONEOF_MEMBERS_PER_TARGET}: ` +
          `revokeTarget iterates every function and member, keep incident narrowing far below a block`,
      );
    }
    // The allowance list is a closed table over an open class (review G9e-2): name every static
    // `address` head word that no rule binds, so a counterparty, receiver or operator word of a venue
    // shape the table does not know is at least read out loud before it is allowed unbound.
    if (!fn.unconstrained) {
      const bound = (i: number) => rules.some((r) => (r as PolicyRule).wordIndex === i && !(r as PolicyRule).tail);
      const unbound = types.map((t, i) => (t === "address" && !bound(i) ? i : -1)).filter((i) => i >= 0);
      if (unbound.length)
        warnings.push(
          `${where}: address word(s) ${unbound.join(", ")} carry no rule: if one is a spender, receiver, owner or operator, ` +
            `bind it (EqualToSafe / OneOf / EqualTo); a token or market address may stay unbound`,
        );
    }
    const bandWord = BAND_SHAPED.get(selector);
    if (bandWord !== undefined && !fn.unconstrained) {
      const kinds = (rules as PolicyRule[]).filter((r) => r.wordIndex === bandWord).map((r) => r.kind);
      if (!kinds.some((k) => UPPER_BOUND_KINDS.includes(k)) || !kinds.some((k) => LOWER_BOUND_KINDS.includes(k))) {
        throw Error(
          `${where}: NAV-shaped function needs a floor and a ceiling on word ${bandWord} (a band around the settled NAV ` +
            `refuses unit mistakes and caps a single mark; re-sync it with every funding step) or "unconstrained": true`,
        );
      }
    }
    const valueWords = ALLOWANCE_SHAPED.get(selector);
    if (valueWords && !fn.unconstrained) {
      for (const w of valueWords) {
        if (!rules.some((r) => (r as PolicyRule).wordIndex === w)) {
          throw Error(
            `${where}: allowance / receiver-shaped function needs a rule on word ${w} (set "unconstrained": true to override)`,
          );
        }
      }
    }
  }
  return warnings;
}
