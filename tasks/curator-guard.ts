import fs from "fs";
import chalk from "chalk";
import {
  AbiCoder,
  FunctionFragment,
  ParamType,
  getAddress,
  getBytes,
  hexlify,
  isAddress,
  concat,
  keccak256,
  solidityPacked,
  toBeHex,
  toUtf8Bytes,
  zeroPadValue,
} from "ethers";
import type { Contract, EventLog, Interface, Log } from "ethers";
import { task } from "hardhat/config";
import { HardhatPluginError } from "hardhat/plugins";
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
// The deploy script's margin of the admin delay above the timelock delay: a cancel scheduled when a hostile
// begin lands keeps `adminDelay - minDelay`, a proposer Safe's signing round at least (review G16b-3).
const ADMIN_DELAY_MARGIN = 86_400n;
// Joint caps on `OneOf` members (a v2 robustness item, enforced here rather than on-chain). Since
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
// Least `executeBefore` window worth having (seconds): the proposer Safe's signing round eats the window
// from the preparation side and a block interval or a cancel latency from the execution side.
const WINDOW_MARGIN = 3_600n;
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
  // Review G17d-1: the live Lagoon v0.6.0 vault's own receiver-carrying entry points (read from the chain): the
  // synchronous lanes mint or pay to `receiver`, the four-argument request names the controller and the owner.
  ["syncDeposit(uint256,address,address)", [1]], // Lagoon v0.6.0: receiver of the shares
  ["syncRedeem(uint256,address,uint256)", [1]], // Lagoon v0.6.0: receiver of the assets
  ["requestDeposit(uint256,address,address,address)", [1, 2]], // Lagoon v0.6.0: controller / owner, with a referral
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
  // Lagoon v0.6.0 role, code and custody levers (docs section 7.5 "Never on the council lane", 8): named in every
  // decode and refused in a policy file without `"$allowSensitive": true` (review G15a-4).
  "updateSafe(address)",
  "lockUpdateSafe()",
  "updateSecurityCouncil(address)",
  "updateSuperOperator(address)",
  "updateValuationManager(address)",
  "updateWhitelistManager(address)",
  "updateFeeReceiver(address)",
  "updateRates((uint16,uint16,uint16,uint16,uint16))",
  "switchAccessMode(uint8)",
  "resetHighWaterMark()",
  "updateTotalAssetsLifespan(uint128)",
  "setSyncMode(uint8)",
  "securityCouncilUpdateTotalAssets(uint256)",
  "submitImplementation(address)",
  "upgradeAndCall(address,address,bytes)",
  "submitDelay(uint256)",
  // Review G17d-1: the remaining live levers of the roles the Safe holds today (`securityCouncil`, `whitelistManager`,
  // the `DelayProxyAdmin`'s apply step): the guardrails and the whitelist are the Lagoon-side controls of docs
  // section 8, so a policy entry that switches or widens them is never routine curator work either.
  "updateActivated(bool)",
  "updateGuardrails((uint256,int256))",
  "addToWhitelist(address[])",
  "revokeFromWhitelist(address[])",
  "revokeFromBlacklist(address[])",
  "setExternalSanctionsList(address)",
  "updateDelay()",
  // hemiBTC is a LayerZero OFT: `send` moves custody to a bytes32 receiver inside a dynamic tuple that no word rule
  // can bind (the unbound-address warning names only the refund address), a transfer in all but name.
  "send((uint32,bytes32,uint256,uint256,bytes,bytes,bytes),(uint256,uint256),address)",
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
  "assertBefore(uint256)", // contracts/helpers/SettlementDeadline.sol (docs section 5, review G13e-1)
  "initiateClosing()",
  "close(uint256)",
  "multiSend(bytes)",
];
const ALLOWANCE_SHAPED = new Map<string, number[]>(
  ALLOWANCE_LIST.map(([sig, words]) => [selectorOfSignature(sig), words]),
);
const SENSITIVE = new Set(SENSITIVE_LIST.map(selectorOfSignature));
/// The settlement-deadline entry: a plain call with no rules whose only substance is the code behind its target
/// (review G16c-1).
const DEADLINE_SELECTOR = selectorOfSignature("assertBefore(uint256)");
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
// The settles of a NAV-shaped target: they repeat the pending mark, so a band on the mark must be repeated on them.
const SETTLE_SIGNATURES = ["settleDeposit(uint256)", "settleRedeem(uint256)"];
/// The mark and its settles: the only functions whose word-0 band follows the vault's live `totalAssets()` (the
/// shift exemption of review G12c-1 reads the anchor for these alone; any other word-0 band moves under the
/// loosening gate, review G15c).
const NAV_FAMILY = new Set<string>([...BAND_SHAPED.keys(), ...SETTLE_SIGNATURES.map(selectorOfSignature)]);
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
// Canonical Safe libraries an approved delegatecall may legitimately address (safe-deployments 1.37.56,
// Ethereum, lower-cased). The approval pins the code of `to`, never what an entry inside a batch addresses,
// so `verify --op` prints an approval's payload one level down and names these (review G11f): a batch into a
// canonical `MultiSend` is unpacked entry by entry, a migration entry is checked against the canonical
// `SafeMigration`, and a delegatecall into anything else is marked as unknown code in the Safe's context.
const CANONICAL_MULTISEND = new Map<string, string>([
  ["0xa238cbeb142c10ef7ad8442c6d1f9e89e07e7761", "MultiSend v1.3.0"],
  ["0x998739bfdaadde7c933b942a68053933098f9eda", "MultiSend v1.3.0 (eip155)"],
  ["0x40a2accbd92bca938b02010e17a5b8929b49130d", "MultiSendCallOnly v1.3.0"],
  ["0xa1dabef33b3b82c7814b6d82a79e50f4ac44102b", "MultiSendCallOnly v1.3.0 (eip155)"],
  ["0x38869bf66a61cf6bdb996a6ae40d5853fd43b526", "MultiSend v1.4.1"],
  ["0x9641d764fc13c8b624c04430c7356c1c7c8102e2", "MultiSendCallOnly v1.4.1"],
  ["0x218543288004cd07832472d464648173c77d7eb7", "MultiSend v1.5.0"],
  ["0xa83c336b20401af773b6219ba5027174338d1836", "MultiSendCallOnly v1.5.0"],
]);
const CANONICAL_MIGRATIONS = new Map<string, string>([
  ["0x526643f69b81b008f46d95cd5ced5ec0edffdac6", "SafeMigration v1.4.1"],
  ["0x6439e7abd8bb915a5263094784c5cf561c4172ac", "SafeMigration v1.5.0"],
]);
const MIGRATION_SIGNATURES = [
  "migrateSingleton()",
  "migrateWithFallbackHandler()",
  "migrateL2Singleton()",
  "migrateL2WithFallbackHandler()",
];
const MIGRATION_NAMES = new Map<string, string>(MIGRATION_SIGNATURES.map((sig) => [selectorOfSignature(sig), sig]));
// The migration library's entry points that put a signature-capable fallback handler back (docs §7.5).
const HANDLER_REINSTALLING = new Set(
  ["migrateWithFallbackHandler()", "migrateL2WithFallbackHandler()"].map(selectorOfSignature),
);

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
/// A chain timestamp as a date. Total: `Date` holds nothing above 8.64e12 s (the year 275760) and an `executeBefore`
/// deadline is a `uint64` read from the timelock's logs, i.e. whatever a proposer scheduled, so a value beyond that is
/// printed as the raw number instead of throwing: one such operation must not take the queue print, `verify --op` and
/// every sync down with a bare RangeError (review G17b-1).
const MAX_DATE_SECONDS = 8_640_000_000_000n;
const iso = (unixSeconds: bigint | number) => {
  const s = BigInt(unixSeconds);
  if (s < 0n || s > MAX_DATE_SECONDS) return `${s}s (not a representable date: beyond the year 275760)`;
  return new Date(Number(s) * 1000).toISOString();
};
const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

/// A refusal the task raises on purpose (`throw Error(...)`: a gate, a missing flag, a stale file) is an answer for the
/// operator, not a crash: hardhat prints a plain `Error` as "An unexpected error occurred:" with a stack trace, and a
/// `HardhatPluginError` as one line. Anything else (a TypeError, an ethers or node error, which carry a `code`) keeps
/// its stack: those are bugs or transport failures (review G17f-3).
async function asOperatorAnswers<T>(f: () => Promise<T>): Promise<T> {
  try {
    return await f();
  } catch (e: unknown) {
    if (e instanceof Error && e.constructor === Error && !("code" in e))
      throw new HardhatPluginError("curator-guard", e.message, e);
    throw e;
  }
}

/*//////////////////////////////////////////////////////////////
                              TASKS
//////////////////////////////////////////////////////////////*/

task("curator-guard-lint", "Validate a CuratorGuard policy file offline (no network): shape, rules, caps")
  .addParam("policy", "Path to the policy JSON")
  .setAction(async (args) =>
    asOperatorAnswers(async () => {
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
      for (const f of policy.functions) {
        // What the rules do not say is read out loud next to the entry: the escape hatches (review G17b-6).
        const flags = [
          f.unconstrained === true && "UNCONSTRAINED",
          f.allowValue === true && "allowValue",
          f.$allowSensitive === true && "$allowSensitive",
        ].filter(Boolean);
        const rules = (f.rules ?? []).length;
        console.log(
          `  ${selectorOf(f)} ${f.signature} on ${f.target} (${rules ? `${rules} rule(s)` : "no rules"})` +
            (flags.length ? chalk.yellow(`  [${flags.join(", ")}]`) : ""),
        );
      }
    }),
  );

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
    "Sync an unconstrained NAV-marking function, or a NAV band at its first sync that does not contain the vault's live totalAssets() or is wider than +-50 % of it, on a vault that already holds assets (a colluding quorum can then mark the custody away); it also admits a band or a fixed mark on a vault that holds nothing (refused otherwise until its first settlement, review G16c-2)",
  )
  .addFlag("viaTimelock", "Fork networks: rehearse schedule -> execute instead of impersonating the admin")
  .setAction(async (args: SyncArgs & { policy: string }, hre: HardhatRuntimeEnvironment) =>
    asOperatorAnswers(async () => {
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
        const scan = await timelockScan(hre, ctx, true);
        const queue = await pendingOperations(ctx, scan);
        if (queue.length) {
          console.log(chalk.yellow(`${queue.length} operation(s) pending on the timelock ${ctx.admin}:`));
          // A flood is itself the incident (review G13f-1): the timelock caps nothing, a bare operation never
          // expires, and every run pays one read per scanned id, so the print is capped and the burst named.
          for (const q of queue.slice(0, QUEUE_PRINT_CAP))
            console.log(chalk.yellow(`  ${q.opId} (scheduled in block ${q.block}): ${q.description}`));
          if (queue.length > QUEUE_PRINT_CAP)
            console.log(
              chalk.yellow(
                `  ... and ${queue.length - QUEUE_PRINT_CAP} more (curator-guard-verify --op <id> decodes any one)`,
              ),
            );
          if (queue.length > QUEUE_FLOOD_WARN)
            console.log(
              chalk.red(
                `WARNING: ${queue.length} pending operations is a burst, not a backlog: a compromised proposer floods the queue with operations that never expire (review G13f-1); page the veto Safe, which cancels the abandoned ids in MultiSend batches (about 2,600 cancels fit under the 16.8 M transaction cap of EIP-7825, measured in review g15c; one batch for any flood seen so far), and remove that proposer`,
              ),
            );
        } else if (scan.degraded) {
          // A tolerated scan that could not list the queue must never read as an empty queue (review P1b-2).
          console.log(
            chalk.yellow(
              `the timelock's queue could NOT be listed (${scan.degraded}): treat it as unknown, never as empty`,
            ),
          );
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
    }),
  );

task(
  "curator-guard-verify",
  "Decode a queued timelock operation from the chain's logs (--op), or a signer manifest's proposal before it is signed (--manifest), and compare it with the policy file",
)
  .addParam("guard", "CuratorGuard address")
  .addParam("policy", "Path to the policy JSON")
  .addOptionalParam("op", "Operation id(s), comma-separated: queued operations, rebuilt from the timelock's logs")
  .addOptionalParam(
    "manifest",
    "A signer manifest written by curator-guard-sync: decode its scheduleBatch calldata against the committed file and print the proposer Safe's EIP-712 hashes to compare with the hardware wallet BEFORE signing",
  )
  .addOptionalParam(
    "proposer",
    "With --manifest: the proposer Safe the proposal is for (default: the manifest's proposer)",
  )
  .addOptionalParam(
    "nonce",
    "With --manifest: the Safe nonce of the proposal (default: the proposer Safe's live nonce())",
  )
  .addOptionalParam("timelockBlock", "Block the admin timelock was deployed at (also CURATOR_GUARD_TIMELOCK_BLOCK)")
  .setAction(
    async (
      args: {
        guard: string;
        policy: string;
        op?: string;
        manifest?: string;
        proposer?: string;
        nonce?: string;
        timelockBlock?: string;
      },
      hre: HardhatRuntimeEnvironment,
    ) =>
      asOperatorAnswers(async () => {
        if (!args.op === !args.manifest) throw Error("pass exactly one of --op <id> or --manifest <file>");
        // The signer's check prints what the lint would tell the operator: a band on paper (the 100x warning,
        // review G13a-1), no guardian, a signed word. Dropped before (review G15c-3).
        const { policy, warnings } = loadPolicy(args.policy);
        for (const w of warnings) console.log(chalk.yellow(`warning: ${w}`));
        const ctx = await guardContext(hre, args.guard, policy, args.timelockBlock);
        if (!ctx.timelock) throw Error(`the guard admin ${ctx.admin} is not a TimelockController`);
        if (args.manifest) {
          await verifyManifest(hre, ctx, policy, args.manifest, args.proposer, args.nonce);
          return;
        }
        const scan = await timelockScan(hre, ctx, false);
        const plan = await planDiff(hre, ctx, policy, true, true);
        const wanted = new Set(plan.calls.map((c) => c.data));
        let allMatch = true;
        let syncShaped = 0;
        let pendingNamed = 0;
        for (const id of args.op!.split(",")) {
          const op = await rebuildOperation(ctx, scan, id.trim());
          const ts: bigint = await ctx.timelock.getTimestamp(op.opId);
          // An executed operation's calls left the diff when they landed: it is not judged against the current
          // diff (the drift verdict would be red by construction; review P1b-7).
          const done = ts === 1n;
          if (!done) ++pendingNamed;
          console.log(
            chalk.blue(
              `operation ${op.opId}: ${ts === 0n ? "NOT scheduled" : ts === 1n ? "executed" : `ready at ${iso(ts)}`}, ` +
                `predecessor ${op.predecessor}, scheduled in block ${op.block}`,
            ),
          );
          for (const [i, c] of op.calls.entries()) {
            const inner = unwrapExecuteBefore(ctx.guardIface, c.data);
            const guardTarget = lower(c.target) === lower(ctx.guard);
            // A value on the call is never what a sync schedules (the `--manifest` path checks it the same way; the guard's
            // `executeBefore` is not payable, so such an operation cannot even execute; review G17b-5).
            const stillWanted = guardTarget && c.value === 0n && inner !== undefined && wanted.has(inner.data);
            if (!done) {
              allMatch &&= stillWanted;
              if (guardTarget && inner !== undefined && SYNC_SELECTORS.has(inner.data.slice(0, 10))) ++syncShaped;
            }
            const [first, ...rest] = describeTimelockCall(ctx, c.target, c.data).split("\n");
            console.log(
              `  [${i}] ${first}` +
                (done
                  ? chalk.blue("  (executed)")
                  : guardTarget
                    ? stillWanted
                      ? chalk.green("  (in the current diff)")
                      : chalk.red("  (NOT in the current diff)")
                    : chalk.red("  (NOT a guard call)")) +
                (c.value !== 0n ? chalk.red(`  value ${c.value}`) : "") +
                rest.map((line) => `\n${line}`).join(""),
            );
          }
        }
        // A sync operation is judged against the diff the committed file produces right now; a one-off
        // (an approval, a window, a role change, a lift: the runbook's own recipes of sections 7.5 and
        // 7.6) never is, so the verdict names it as such instead of calling it drift (review G11a-4).
        if (!pendingNamed) {
          console.log(
            chalk.blue(
              "every operation named is already executed: its calls left the diff when they landed; compare them with the " +
                "signer manifest or the file's history, not with the current diff",
            ),
          );
          return;
        }
        if (!allMatch && syncShaped === 0) {
          console.log(
            chalk.yellow(
              "no decoded call is a policy sync: this is a one-off operation (role / incident-sensitive); compare the decoded " +
                "call with the runbook recipe it came from and with the manifest of whoever scheduled it, never with the policy file",
            ),
          );
          return;
        }
        console.log(
          allMatch
            ? chalk.green("every decoded call is part of the diff the committed policy file produces right now")
            : chalk.red(
                "some decoded calls are NOT what the committed policy file would produce right now: do not sign / execute blindly",
              ),
        );
      }),
  );

type ManifestFile = {
  chainId?: string | number;
  timelock?: string;
  guard?: string;
  proposer?: string | null;
  operations?: { opId?: string; scheduleBatchCalldata?: string }[];
};

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
// Safe v1.3.0+ EIP-712 constants (`Safe.sol`: DOMAIN_SEPARATOR_TYPEHASH, SAFE_TX_TYPEHASH).
const SAFE_DOMAIN_TYPEHASH = keccak256(toUtf8Bytes("EIP712Domain(uint256 chainId,address verifyingContract)"));
const SAFE_TX_TYPEHASH = keccak256(
  toUtf8Bytes(
    "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)",
  ),
);
// The canonical `MultiSendCallOnly` protocol-kit wraps two or more proposed calls in, per Safe release
// (helpers/address.ts `Safe.multiSendCallOnly_*`; the policy file registers the same three).
const MULTISEND_CALL_ONLY: Record<string, string> = {
  "1.3.0": "0x40A2aCCbd92BCA938b02010E17A5b8929b49130D",
  "1.4.1": "0x9641d764fc13c8B624c04430C7356C1C7C8102e2",
  "1.5.0": "0xA83c336B20401Af773B6219BA5027174338D1836",
};

/// The three hashes a signer compares with the hardware wallet (domain hash and message hash on a
/// blind-signing display, `safeTxHash` in Safe{Wallet}'s transaction details), for a proposal with no gas
/// refund (`safeTxGas`, `baseGas`, `gasPrice` 0, `gasToken` and `refundReceiver` zero), as `Safe.sol`
/// v1.3.0+ computes them.
function safeTxHashes(
  chainId: bigint,
  safe: string,
  to: string,
  data: string,
  operation: number,
  nonce: bigint,
): { domain: string; message: string; safeTxHash: string } {
  const coder = AbiCoder.defaultAbiCoder();
  const domain = keccak256(coder.encode(["bytes32", "uint256", "address"], [SAFE_DOMAIN_TYPEHASH, chainId, safe]));
  const message = keccak256(
    coder.encode(
      [
        "bytes32",
        "address",
        "uint256",
        "bytes32",
        "uint8",
        "uint256",
        "uint256",
        "uint256",
        "address",
        "address",
        "uint256",
      ],
      [SAFE_TX_TYPEHASH, to, 0n, keccak256(data), operation, 0n, 0n, 0n, ZERO_ADDRESS, ZERO_ADDRESS, nonce],
    ),
  );
  return { domain, message, safeTxHash: keccak256(concat(["0x1901", domain, message])) };
}

/// `--manifest`: the signer-side check of a proposal BEFORE it is signed. The manifest, the Safe{Wallet} page and
/// the Transaction Service proposal all come from the operator's machine, so a signer trusts none of them:
/// everything is rebuilt from the manifest's `scheduleBatchCalldata` alone, on the signer's own clone of the
/// committed file and their own RPC: the operation id (locally, `keccak256(abi.encode(...))` as OpenZeppelin
/// hashes it), every decoded call against the diff the committed file produces right now, the chain of
/// predecessors, the delay against the live `getMinDelay()`, and the EIP-712 hashes the proposer Safe's signers
/// see on a hardware wallet for the proposal protocol-kit builds (one operation: a plain call to the timelock;
/// two or more: one `MultiSendCallOnly` delegatecall, as `helpers/safe.ts` proposes them). A proposal whose
/// hash is not the one printed is not the manifest's transaction, whatever the page shows (review G12a-2).
async function verifyManifest(
  hre: HardhatRuntimeEnvironment,
  ctx: Ctx,
  policy: Policy,
  file: string,
  proposerArg: string | undefined,
  nonceArg: string | undefined,
): Promise<void> {
  const timelock = ctx.timelock!;
  let m: ManifestFile;
  try {
    m = JSON.parse(fs.readFileSync(file, "utf8")) as ManifestFile;
  } catch (e: unknown) {
    throw Error(`${file} is not a readable manifest (${errorText(e)})`);
  }
  if (!Array.isArray(m.operations) || !m.operations.length) throw Error(`${file}: no operations`);
  if (String(m.chainId) !== String(ctx.chainId))
    throw Error(`${file} was written for chain ${m.chainId}; this network is ${ctx.chainId}`);
  if (lower(String(m.timelock)) !== lower(ctx.admin) || lower(String(m.guard)) !== lower(ctx.guard))
    throw Error(`${file} names timelock ${m.timelock} / guard ${m.guard}, not ${ctx.admin} / ${ctx.guard}`);
  const proposer = proposerArg ?? m.proposer ?? undefined;
  if (!proposer || !isAddress(proposer)) throw Error("pass --proposer <Safe>: the manifest names no proposer Safe");
  const safeAddress = getAddress(proposer);

  const plan = await planDiff(hre, ctx, policy, true, true);
  const wanted = new Set(plan.calls.map((c) => c.data));
  const minDelay: bigint = await timelock.getMinDelay();
  const coder = AbiCoder.defaultAbiCoder();
  let allMatch = true;
  let previousId = ZERO_HASH;
  const calldatas: string[] = [];
  const now = BigInt((await hre.ethers.provider.getBlock("latest"))!.timestamp);
  for (const [i, op] of m.operations.entries()) {
    const calldata = String(op.scheduleBatchCalldata ?? "");
    if (!/^0x[0-9a-fA-F]+$/.test(calldata)) throw Error(`${file}: operation #${i} carries no scheduleBatch calldata`);
    const parsed = timelock.interface.parseTransaction({ data: calldata });
    if (!parsed || (parsed.name !== "scheduleBatch" && parsed.name !== "schedule"))
      throw Error(
        `${file}: operation #${i} is not a schedule / scheduleBatch call (${parsed?.name ?? calldata.slice(0, 10)})`,
      );
    const batch = parsed.name === "scheduleBatch";
    const targets: string[] = batch ? (parsed.args[0] as string[]).map(String) : [String(parsed.args[0])];
    const values: bigint[] = batch ? (parsed.args[1] as bigint[]).map(BigInt) : [BigInt(parsed.args[1])];
    const payloads: string[] = batch ? (parsed.args[2] as string[]).map(String) : [String(parsed.args[2])];
    const predecessor = String(parsed.args[3]);
    const salt = String(parsed.args[4]);
    const delay = BigInt(parsed.args[5]);
    const opId = batch
      ? keccak256(
          coder.encode(
            ["address[]", "uint256[]", "bytes[]", "bytes32", "bytes32"],
            [targets, values, payloads, predecessor, salt],
          ),
        )
      : keccak256(
          coder.encode(
            ["address", "uint256", "bytes", "bytes32", "bytes32"],
            [targets[0], values[0], payloads[0], predecessor, salt],
          ),
        );
    console.log(
      chalk.blue(`operation #${i} ${opId}: ${parsed.name}, delay ${delay}s, predecessor ${predecessor}, salt ${salt}`),
    );
    if (op.opId && lower(String(op.opId)) !== lower(opId)) {
      allMatch = false;
      console.log(chalk.red(`  the manifest says ${op.opId}: its decoded list does not describe this calldata`));
    }
    if (i > 0 && lower(predecessor) !== lower(previousId)) {
      allMatch = false;
      console.log(chalk.red(`  predecessor is not operation #${i - 1}: the chain of operations is not the manifest's`));
    }
    if (delay !== minDelay) {
      allMatch = false;
      console.log(chalk.red(`  delay ${delay}s is not the live getMinDelay() ${minDelay}s (the timelock refuses it)`));
    }
    const scheduledAt: bigint = await timelock.getTimestamp(opId);
    if (scheduledAt !== 0n)
      console.log(
        chalk.yellow(
          `  already on the timelock (${scheduledAt === 1n ? "executed" : `ready at ${iso(scheduledAt)}`}): scheduling it again reverts`,
        ),
      );
    let earliest: bigint | undefined;
    for (const [j, p] of payloads.entries()) {
      const guardTarget = lower(targets[j]) === lower(ctx.guard);
      const inner = unwrapExecuteBefore(ctx.guardIface, p);
      if (inner && (earliest === undefined || inner.deadline < earliest)) earliest = inner.deadline;
      const stillWanted = guardTarget && values[j] === 0n && inner !== undefined && wanted.has(inner.data);
      allMatch &&= stillWanted;
      const [first, ...rest] = describeTimelockCall(ctx, targets[j], p).split("\n");
      console.log(
        `  [${j}] ${first}` +
          (guardTarget
            ? stillWanted
              ? chalk.green("  (in the current diff)")
              : chalk.red("  (NOT in the current diff)")
            : chalk.red("  (NOT a guard call)")) +
          (values[j] !== 0n ? chalk.red(`  value ${values[j]}`) : "") +
          rest.map((line) => `\n${line}`).join(""),
      );
    }
    // The signer is the one whose delay kills the operation: its `executeBefore` deadline was fixed when the
    // operator prepared it, and it is Ready `minDelay` after THIS proposal executes, so a signature that lands
    // later than `deadline - minDelay` schedules a dead operation (the sync prints the same time to the operator;
    // on a one-day timelock a lift's deadline is three days after preparation, review G14c-2). Derived from the
    // calldata, never from a manifest field.
    if (earliest !== undefined) {
      const scheduleBy = earliest - minDelay;
      const line = `  executeBefore ${iso(earliest)}: the proposer Safe must execute this proposal before ${iso(scheduleBy)} (dead on arrival afterwards)`;
      if (now >= scheduleBy) {
        allMatch = false;
        console.log(chalk.red(`${line}: that time has passed, do not sign; ask for a fresh proposal`));
      } else if (scheduleBy - now < WINDOW_MARGIN) {
        console.log(chalk.yellow(`${line}: less than ${WINDOW_MARGIN / 3600n} h left`));
      } else console.log(chalk.blue(line));
    }
    previousId = opId;
    calldatas.push(calldata);
  }

  // What the proposer Safe's signers will be asked to sign: protocol-kit proposes one call directly and two or
  // more as one MultiSendCallOnly delegatecall (helpers/safe.ts).
  const { ethers } = hre;
  const safe = new ethers.Contract(
    safeAddress,
    [
      "function nonce() view returns (uint256)",
      "function VERSION() view returns (string)",
      "function getTransactionHash(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256) view returns (bytes32)",
    ],
    ethers.provider,
  );
  const hasCode = (await ethers.provider.getCode(safeAddress)) !== "0x";
  let nonce: bigint;
  if (nonceArg !== undefined) {
    if (!/^\d+$/.test(nonceArg)) throw Error(`--nonce must be a number, got ${nonceArg}`);
    nonce = BigInt(nonceArg);
  } else if (hasCode) nonce = BigInt(await safe.nonce());
  else throw Error(`${safeAddress} has no code on this network: pass --nonce <n>`);
  let version = "unknown";
  if (hasCode) {
    try {
      version = String(await safe.VERSION());
    } catch {
      /* not a Safe that answers VERSION() */
    }
  }
  let to = ctx.admin;
  let data = calldatas[0];
  let operation = 0;
  if (calldatas.length > 1) {
    const lib = MULTISEND_CALL_ONLY[version];
    if (!lib)
      throw Error(
        `${calldatas.length} operations are proposed as one MultiSendCallOnly batch and Safe v${version} has no canonical ` +
          `MultiSendCallOnly in this table: compare the operations one by one`,
      );
    const packed = concat(
      calldatas.map((d) =>
        solidityPacked(["uint8", "address", "uint256", "uint256", "bytes"], [0, ctx.admin, 0, (d.length - 2) / 2, d]),
      ),
    );
    to = lib;
    data = new ethers.Interface(["function multiSend(bytes)"]).encodeFunctionData("multiSend", [packed]);
    operation = 1;
  }
  const { domain, message, safeTxHash } = safeTxHashes(BigInt(ctx.chainId), safeAddress, to, data, operation, nonce);
  console.log(
    chalk.blue(
      `proposal for Safe ${safeAddress} (v${version}) at nonce ${nonce}: to ${to}, value 0, operation ${
        operation === 0 ? "0 (Call)" : "1 (DelegateCall into MultiSendCallOnly)"
      }, safeTxGas 0, baseGas 0, gasPrice 0, gasToken 0x0, refundReceiver 0x0${nonceArg === undefined ? " (nonce read live: pass --nonce if the Transaction Service assigned another)" : ""}`,
    ),
  );
  console.log(chalk.blue(`  calldata keccak256 ${keccak256(data)} (${(data.length - 2) / 2} bytes)`));
  console.log(chalk.blue(`  EIP-712 domain hash  ${domain}`));
  console.log(chalk.blue(`  EIP-712 message hash ${message}`));
  console.log(chalk.blue(`  safeTxHash           ${safeTxHash}`));
  if (hasCode) {
    try {
      const own: string = await safe.getTransactionHash(
        to,
        0,
        data,
        operation,
        0,
        0,
        0,
        ZERO_ADDRESS,
        ZERO_ADDRESS,
        nonce,
      );
      if (own === safeTxHash) console.log(chalk.green("  the Safe's own getTransactionHash agrees"));
      else {
        allMatch = false;
        console.log(
          chalk.red(`  the Safe's own getTransactionHash answers ${own}: this Safe does not hash like Safe v1.3.0+`),
        );
      }
    } catch (e: unknown) {
      console.log(
        chalk.yellow(`  the Safe did not answer getTransactionHash (${errorText(e)}): compare the hashes above`),
      );
    }
  }
  console.log(
    allMatch
      ? chalk.green(
          "every decoded call is part of the diff the committed policy file produces right now: sign ONLY the proposal whose " +
            "safeTxHash is the one above (Safe{Wallet} shows it in the transaction details; a hardware wallet shows the domain and message hashes)",
        )
      : chalk.red(
          "some decoded calls are NOT what the committed policy file would produce right now, or the manifest does not describe " +
            "its own calldata: do not sign",
        ),
  );
}

/// The guard functions a policy sync emits (every call of `planDiff`); any other guard call is a one-off.
const SYNC_SELECTORS = new Set(
  [
    "allowFunction(address,address,bytes4,bool,(uint8,uint16,bytes32)[])",
    "revokeFunction(address,address,bytes4)",
    "addAllowedValues(address,address,bytes4,uint16,bytes32[])",
    "removeAllowedValues(address,address,bytes4,uint16,bytes32[])",
    "setNativeTransferAllowed(address,address,bool)",
    "setMultiSendUnwrapper(address,address,bool)",
    "setModuleAllowed(address,address,bool)",
    "setGuardian(address,address,bool)",
    "setRequiredFallbackHandler(address,address,bool)",
    "enforce(address)",
    "lockdown(address)",
  ].map(selectorOfSignature),
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
  // The deploy script orders `defaultAdminDelay` strictly above `minDelay` at deployment only; both floors are a
  // day (`MIN_DELAY_FLOOR`, `MIN_ADMIN_DELAY`), so a scheduled `updateDelay` or `changeDefaultAdminDelay` can equalise
  // or invert them later, after which an UNCHAINED `cancelDefaultAdminTransfer` keeps the Ready second alone (a
  // block in twelve) or lands late: say it on every run (docs section 7.5, review G14c-3).
  if (ctx.timelock) {
    const adminDelay: bigint = await g.defaultAdminDelay();
    const minDelay: bigint = await ctx.timelock.getMinDelay();
    // A scheduled `changeDefaultAdminDelay` is in force only from its effect time (OpenZeppelin waits the old delay
    // before a shorter one applies): the live getter says nothing about it for up to five days, during which
    // `rollbackDefaultAdminDelay` could still undo it, so the pending value is compared as well (review G15g-3).
    const [pendingDelay, effectAt]: [bigint, bigint] = await g.pendingDefaultAdminDelay();
    const text = `admin-transfer delay ${adminDelay}s, timelock delay ${minDelay}s`;
    // A cancel scheduled when a hostile begin lands is Ready `minDelay` later and the acceptance opens `adminDelay`
    // later: the honest side keeps the difference, a signing round at least, or chains a cancel within the admin
    // delay of the hostile CallScheduled (review G16b-3; the deploy script keeps a day).
    const order = (delay: bigint, label: string) =>
      delay >= minDelay + ADMIN_DELAY_MARGIN
        ? label
        : chalk.yellow(
            `WARNING: ${label}: ${delay > minDelay ? `only ${delay - minDelay}s apart` : "not strictly ordered"}, so a hand-over that ` +
              `slips past the veto is accepted ${delay > minDelay ? `${delay - minDelay}s after` : delay === minDelay ? "in the block" : "before"} ` +
              `a cancel scheduled when the begin lands is Ready; chain the cancel behind the begin (predecessor) within the admin ` +
              `delay of the begin's CallScheduled, or schedule changeDefaultAdminDelay at least a day above the timelock delay`,
          );
    lines.push(order(adminDelay, text));
    if (effectAt !== 0n)
      lines.push(
        order(
          pendingDelay,
          `PENDING admin-transfer delay ${pendingDelay}s in force from ${iso(effectAt)} (rollbackDefaultAdminDelay undoes it until then: schedule it chained behind the change, an unchained one is Ready in that very second at the 48 h default; review G16f-2), timelock delay ${minDelay}s`,
        ),
      );
  }
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
  // Canaries (review G10e-1): the creation transaction granted the admin role at or after `from`, so a
  // scan that cannot see that grant while the role is held is an incomplete log stream (a provider that
  // silently truncates or drops answers), and every list below would be optimistic: refuse instead.
  if (from !== undefined) {
    const adminRole: string = await g.DEFAULT_ADMIN_ROLE();
    const seenAdmin = (await scanLogs(hre, g, g.filters.RoleGranted(adminRole), from)).some(
      (l) => lower(String((l as EventLog).args.account)) === lower(ctx.admin),
    );
    if (!seenAdmin && (await g.hasRole(adminRole, ctx.admin)))
      throw Error(
        `log stream incomplete: the guard's RoleGranted(DEFAULT_ADMIN_ROLE, ${ctx.admin}) since block ${from} is missing ` +
          `from eth_getLogs although the role is held: the scan starts after the grant (pass the timelock's creation block, ` +
          `not a later one) or the provider truncates or drops logs; either way no list rebuilt from it ` +
          `(council, guardians, approvals, the timelock's queue) can be trusted; use an RPC that answers completely`,
      );
  }
  const council = await holders(councilRole);
  const guardians = await holders(guardianRole);
  // The address book names the council: a configured council the scan does not show while hasRole says
  // it holds the role is the same incomplete stream (review G10e-1), like the deploy script's audit.
  // (loaded at call time: helpers/address imports the hardhat runtime, which a task file cannot at config load)
  const bookCouncil: string =
    ctx.chainId === "1"
      ? ((await import("../helpers/address")).default as typeof import("../helpers/address").default).ethereum.Vetro
          .curatorGuardCouncil
      : "";
  if (
    bookCouncil &&
    !council.some((c) => lower(c) === lower(bookCouncil)) &&
    (await g.hasRole(councilRole, bookCouncil))
  )
    throw Error(
      `log stream incomplete: ${bookCouncil} holds COUNCIL_ROLE but no RoleGranted log was found since block ${from}: ` +
        `the scan starts after the grant (pass the timelock's creation block) or the provider drops logs`,
    );
  const unknown = from === undefined ? "(unknown: no log range, pass --timelock-block)" : "none";
  lines.push(`council: ${council.length ? council.join(", ") : unknown}`);
  lines.push(`deployment-wide guardians: ${guardians.length ? guardians.join(", ") : unknown}`);
  const perSafe: string[] = await g.guardians(ctx.safe);
  lines.push(`guardians of ${ctx.safe}: ${perSafe.length ? perSafe.join(", ") : "none"}`);
  // The contract accepts its own address as council, deployment-wide guardian or pending admin (review
  // G10a-2, held at +19 bytes): a dead seat, since no call ever has the guard as its sender, and a hand-over
  // to it can never be accepted (one wasted timelock round). Named here, at 0 bytes, on every run.
  const selfSeats = [
    ...(council.some((a) => lower(a) === lower(ctx.guard)) ? ["COUNCIL_ROLE"] : []),
    ...(guardians.some((a) => lower(a) === lower(ctx.guard)) ? ["GUARDIAN_ROLE"] : []),
    ...(lower(pendingAdmin) === lower(ctx.guard) ? ["the pending admin"] : []),
  ];
  if (selfSeats.length)
    lines.push(
      chalk.red(
        `WARNING: the guard ${ctx.guard} holds its own seat (${selfSeats.join(", ")}): a dead seat nothing can act from ` +
          `(review G10a-2); schedule revokeRole / setDeploymentGuardian(false) / cancelDefaultAdminTransfer from a proposer`,
      ),
    );
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
    // One line per approval id: a re-approval of the same transaction logs the same id again with a
    // new expiry (review G11e-3).
    const live = new Map<string, string>();
    for (const l of await scanLogs(hre, g, g.filters.TransactionApproved(ctx.safe), from)) {
      const a = (l as EventLog).args;
      const expiry: bigint = await g.approvalExpiry(a.approvalId);
      // The hook honours an approval through its expiry second (`block.timestamp <= expiry`).
      if (expiry >= now)
        live.set(
          String(a.approvalId),
          `${a.approvalId} to ${a.to} ${String(a.data).slice(0, 10)} executor ${a.executor} until ${iso(expiry)}`,
        );
    }
    if (live.size)
      lines.push(chalk.yellow(`STANDING APPROVALS (${live.size}):\n    ${[...live.values()].join("\n    ")}`));
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
  const ruleText = onChainRuleText;

  const calls: Call[] = [];
  const valueCalls: Call[] = []; // applied after allowFunction: values need their OneOf rule first
  // Removals go FIRST: the contract checks `MAX_SELECTORS` per target and `MAX_GUARDIANS` per Safe
  // after the add, so at the cap a rotation (one out, one in) that adds first reverts `TooManyValues`
  // for the whole batch, although the final set fits (review G11e-1). Every intermediate state of
  // the direct path is still fail-closed (fewer permissions, never more).
  const revokeCalls: Call[] = [];
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
  // The lint refuses the guard in a list only when the file pins it (`guard`, optional in a rehearsal); the contract
  // refuses it in every setter (`InvalidTarget`), so without this check a rehearsal's dry run passed and the direct
  // sync reverted mid-way with a raw VM exception, the earlier calls landed (fail-closed: the mode is set last;
  // review G18c-4). Targets were already checked below; the other lists are held to the same rule here.
  for (const [listKey, list] of [
    ["guardians", policy.guardians],
    ["multiSendUnwrappers", policy.multiSendUnwrappers ?? []],
    ["modules", policy.modules ?? []],
    ["nativeTransfers", policy.nativeTransfers ?? []],
    [
      "requiredFallbackHandler",
      isZeroAddress(policy.requiredFallbackHandler.handler) ? [] : [policy.requiredFallbackHandler.handler],
    ],
  ] as [string, string[]][]) {
    for (const a of list) {
      if (lower(a) === lower(ctx.guard) || lower(a) === lower(ctx.admin) || lower(a) === lower(safe))
        throw Error(
          `policy.${listKey}: ${a} is the guard, the guard admin or the Safe itself (the contract refuses it: InvalidTarget)`,
        );
    }
  }
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
    // The settlement-deadline entry (docs section 5, review G13e-1) is a plain call with no rules: nothing but the
    // code behind the target makes it bind. A look-alike that dispatches the selector and never reverts, a contract
    // with a catch-all fallback, a proxy or an address without code lints valid and synced with at most a yellow
    // line, leaving the signers believing their confirmed batches expire (review G16c-1). The target's own runtime
    // must be this repository's `SettlementDeadline` build (metadata tail excluded, as the guard's own identity
    // check), unless the entry says `"$allowSensitive": true` for a reviewed foreign helper.
    if (selector === DEADLINE_SELECTOR && f.$allowSensitive !== true) {
      const helper = await hre.artifacts.readArtifact("SettlementDeadline");
      const own = await ethers.provider.getCode(target);
      if (own === "0x" || stripMetadata(own) !== stripMetadata(helper.deployedBytecode)) {
        throw Error(
          `${f.signature} on ${target}: the code at the target is not this repository's SettlementDeadline build ` +
            `(contracts/helpers/SettlementDeadline.sol): a deadline entry binds nothing unless the stateless helper is what ` +
            `answers it; deploy the repository's helper and pin its address, or set "$allowSensitive": true for a reviewed ` +
            `foreign helper (review G16c-1)`,
        );
      }
    }
    const k = key(target, selector);
    if (desired.has(k)) throw Error(`Duplicate function entry ${f.signature} (${selector}) on ${target}`);
    desired.set(k, { target, selector, allowValue: f.allowValue === true, rules: (f.rules ?? []).map(toRule), src: f });
  }

  // The go-live gate on a NAV-marking function (docs sections 5 and 8): tolerable only while the vault
  // it marks holds nothing a colluding quorum could mark away. An `"unconstrained": true` entry bounds
  // nothing by its own admission and is gated on every sync. A BANDED entry is gated at its FIRST sync
  // (no floor and ceiling on chain yet): a band the live `totalAssets()` does not sit in, or one wider
  // than +-50 % of it, caps nothing either (`[1, 2^256-2]` passes the contract and lints valid) while it
  // reads as a bound in the diff (review G13a-1). A band already on chain moves under the loosening
  // gate instead (`loosensRules`: anchored on the live NAV and no wider is a shift, anything else a
  // loosening).
  for (const d of desired.values()) {
    const bandWord = BAND_SHAPED.get(d.selector);
    if (bandWord === undefined) continue;
    let band: { lo: bigint; hi: bigint } | undefined;
    let fixed = false; // an EqualTo / OneOf mark: judged by its lowest and highest member, on every sync
    if (!d.src.unconstrained) {
      const floor = d.rules.find((r) => r.wordIndex === bandWord && r.kind === 4);
      const ceil = d.rules.find((r) => r.wordIndex === bandWord && r.kind === 3);
      const eq = d.rules.find((r) => r.wordIndex === bandWord && r.kind === 0);
      const oneOf = (d.src.rules ?? []).find((r) => r.wordIndex === bandWord && r.kind === "OneOf" && !r.tail);
      if (floor && ceil) {
        const [allowed, , rawRules] = await guard.functionPermission(safe, d.target, d.selector);
        const has = (k: number) =>
          rawRules.some((r: [bigint, bigint, string]) => Number(r[0]) === k && Number(r[1]) === bandWord);
        if (allowed && has(3) && has(4)) continue; // on chain already: it moves under the loosening gate
        band = { lo: BigInt(floor.value), hi: BigInt(ceil.value) };
      } else if (eq) {
        band = { lo: BigInt(eq.value), hi: BigInt(eq.value) };
        fixed = true;
      } else if (oneOf) {
        // A fixed-mark set read as "tight by construction" to this gate, so a far member ({the dust, 100,000 USDC}
        // on a 1 USDC vault) synced with no flag and no word; a set grows by `addAllowedValues`, a plain widening
        // the loosening gate never sees, so the set is judged on every sync (review G16c-2).
        const words = (oneOf.values ?? []).map((v) => BigInt(ruleWord(oneOf, v)));
        band = { lo: words.reduce((a, b) => (a < b ? a : b)), hi: words.reduce((a, b) => (a > b ? a : b)) };
        fixed = true;
      } else continue;
    }
    let assets = 0n;
    try {
      assets = await new ethers.Contract(
        d.target,
        ["function totalAssets() view returns (uint256)"],
        ethers.provider,
      ).totalAssets();
    } catch (e: unknown) {
      if (isEvmAnswer(e)) continue; // not an ERC-4626 vault: nothing to gate on
      // A transport failure is not an answer: the go-live gate of docs sections 5 and 8 must not vanish on a rate
      // limit or a timeout of this one read (review G17b-2).
      throw Error(
        `could not read totalAssets() of ${d.target} (${errorText(e)}): the NAV gate is not judged on a failed read; use an RPC that answers`,
      );
    }
    const what =
      band === undefined
        ? ""
        : fixed
          ? `a fixed mark set [${band.lo} .. ${band.hi}]`
          : `a band [${band.lo}, ${band.hi}]`;
    let msg: string;
    if (assets === 0n) {
      // Nothing to mark away: an unconstrained mark passes. A band or a fixed mark on an empty vault has no settled
      // NAV to be judged against, and the honest first mark on it (0: nothing under management) is one no band
      // admits (the contract refuses a zero floor); this gate used to skip it, so a vacuous band ([0.01 BTC, 1 BTC]
      // on the empty live BTC vaults) synced with no flag and no word and was never looked at again (review G16c-2).
      if (band === undefined) continue;
      msg = `${d.src.signature} on ${d.target} carries ${what} while the vault reports totalAssets() = 0: there is no settled NAV to band around yet and the honest first mark (0) is one no band admits; keep the entry unconstrained until the first settlement (an unconstrained mark on an empty vault passes this gate), then band around the settled NAV, or pass --allow-unconstrained-nav knowingly (review G16c-2)`;
    } else if (band === undefined) {
      msg = `${d.src.signature} on ${d.target} is unconstrained while the vault reports totalAssets() = ${assets}: a colluding curator quorum can mark that custody away (docs section 8); put a NAV band on it, or pass --allow-unconstrained-nav`;
    } else {
      let shape: string;
      if (band.lo > assets || assets > band.hi) shape = "that does not contain";
      else if (band.hi - band.lo > assets) shape = "wider than +-50 % of";
      else {
        // Admitted. A band is priced by its half-width: a colluding quorum moves about x^2 of NAV per settlement
        // cycle under +-x (0.25 % at +-5 %, docs section 5; 26.8 % at +-50 %, this gate's edge, measured in review
        // G16c), so a wide one is admitted with its price said out loud, whatever `quiet` says.
        const half = assets - band.lo > band.hi - assets ? assets - band.lo : band.hi - assets;
        const halfPct = Number((half * 10_000n) / assets) / 100;
        // A fixed mark set is priced like a band: its lowest and highest member are the marks the quorum may place, so
        // {1, NAV} on a funded vault is the -100 % band in another shape and was admitted without a word while the band
        // of the same edges printed its price (review G18c-2).
        if (halfPct <= 10) {
          // Admitted silently until now: say which NAV the gate judged the band against (review G17f-4).
          const lo = Number(((assets - band.lo) * 10_000n) / assets) / 100;
          const hi = Number(((band.hi - assets) * 10_000n) / assets) / 100;
          say(
            `note: ${d.src.signature} on ${d.target}: ${what} contains the vault's totalAssets() = ${assets} (-${lo} %, +${hi} %)`,
          );
        }
        if (halfPct > 10)
          console.log(
            chalk.yellow(
              `note: ${d.src.signature} on ${d.target}: ${what} is +-${halfPct} % of totalAssets() = ${assets}: ` +
                `a colluding curator quorum can move about ${Math.round(halfPct * halfPct) / 100} % of NAV per settlement cycle under it ` +
                `(0.25 % under the +-5 % band of docs section 5, review G16c-3)`,
            ),
          );
        continue;
      }
      msg = `${d.src.signature} on ${d.target} carries ${what} ${shape} the vault's totalAssets() = ${assets}: a band only on paper caps nothing a colluding curator quorum marks away (docs sections 5 and 8); tighten it around the settled NAV, or pass --allow-unconstrained-nav knowingly (review G13a-1${fixed ? ", G16c-2" : ""})`;
    }
    if (!allowUnconstrainedNav) throw Error(msg);
    // Printed whatever `quiet` says: `curator-guard-verify --op / --manifest` run the plan quietly with the entry
    // admitted, and a signer must see what the operator's flag admitted (review G15c-3).
    console.log(chalk.red(`WARNING: ${msg}`));
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
        // A NAV band (floor + ceiling on word 0 of a NAV-shaped function or of its settles) that moves to
        // follow the vault's live totalAssets() is the re-sync of docs section 5, not a loosening.
        let anchor: bigint | undefined;
        if (
          NAV_FAMILY.has(d.selector) &&
          d.rules.some((r) => r.wordIndex === 0 && r.kind === 3) &&
          d.rules.some((r) => r.wordIndex === 0 && r.kind === 4)
        ) {
          try {
            anchor = await new ethers.Contract(
              d.target,
              ["function totalAssets() view returns (uint256)"],
              ethers.provider,
            ).totalAssets();
          } catch (e: unknown) {
            if (!isEvmAnswer(e))
              throw Error(
                `could not read totalAssets() of ${d.target} (${errorText(e)}): a band shift is not judged on a failed read`,
              );
            anchor = undefined; // not a vault: no exemption
          }
        }
        const { why, shifted } = loosensRules(rules, d.rules, allowValue, d.allowValue, anchor);
        say(
          chalk.yellow(
            `~ rules   ${label} on ${d.target}: ${before} -> ${after}${why.length ? chalk.red(`  LOOSENING: ${why.join("; ")}`) : ""}${shifted.length ? `  (${shifted.join("; ")})` : ""}`,
          ),
        );
        // A shift is exempt from the loosening gate, so the move itself is said out loud: the anchor is the
        // vault's live `totalAssets()`, the curator's own last settled mark, and a band that follows it is a
        // ratchet bounded by the band's width per sync; the reviewer of the file judges the move, not the
        // flag (review G13g-8).
        if (shifted.length && anchor !== undefined) {
          const ceilBefore = rules.find((r) => r.wordIndex === 0 && r.kind === 3);
          const ceilAfter = d.rules.find((r) => r.wordIndex === 0 && r.kind === 3);
          const floorAfter = d.rules.find((r) => r.wordIndex === 0 && r.kind === 4);
          if (ceilBefore && ceilAfter && floorAfter) {
            const from = BigInt(ceilBefore.value);
            const to = BigInt(ceilAfter.value);
            const lo = BigInt(floorAfter.value);
            const bps = from === 0n ? 0n : ((to - from) * 10_000n) / from;
            // The ceiling's move alone read as "following the NAV" for a band that kept the NAV at its FLOOR: "+4.76 %"
            // while the room above the NAV doubled, then "+9.99 %" from the new mark one sync later. The edges
            // relative to the live NAV are what a reviewer needs, and a NAV sitting at an edge is said out loud
            // (review G16c-3).
            const below = ((anchor - lo) * 10_000n) / anchor;
            const above = ((to - anchor) * 10_000n) / anchor;
            say(
              chalk.yellow(
                `          band now [-${Number(below) / 100} %, +${Number(above) / 100} %] around totalAssets() = ${anchor} ` +
                  `(ceiling ${from} -> ${to}, ${bps >= 0n ? "+" : ""}${Number(bps) / 100} %): that number is the curator's last ` +
                  `settled mark; the move is reviewed in the file, never confirmed by a flag`,
              ),
            );
            const width = to - lo;
            if (width > 0n && (anchor - lo <= width / 10n || to - anchor <= width / 10n))
              say(
                chalk.yellow(
                  `          NOTE: the live NAV sits at the band's ${anchor - lo <= width / 10n ? "floor" : "ceiling"}: all of the ` +
                    `band's room is on one side; a band that follows the NAV is centred on it, and one that keeps the NAV at an ` +
                    `edge ratchets by its full width per sync (reviews G13g-8, G16c-3)`,
                ),
              );
          }
        }
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
  for (const f of onChainFunctions.values()) {
    const known = KNOWN_SIGNATURES.get(f.selector);
    push(
      `revokeFunction ${f.selector}${known ? ` (${known})` : ""} on ${f.target}`,
      "revokeFunction",
      [safe, f.target, f.selector],
      revokeCalls,
    );
    say(chalk.red(`- revoke  ${f.selector}${known ? ` (${known})` : ""} on ${f.target}`));
  }
  calls.unshift(...revokeCalls);
  calls.push(...valueCalls);

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
    for (const g of have) {
      if (want.has(g)) continue;
      push(`setGuardian ${ethers.getAddress(g)} = false`, "setGuardian", [safe, ethers.getAddress(g), false]);
      say(chalk.red(`- guardian ${g}`));
    }
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
      } else if (liveGuard === ethers.ZeroAddress && onChainTargets.length > 0) {
        // A configured Safe whose slot is empty was decommissioned (`setGuard(0)` then `lockdownAndRevoke`, §7.5) or
        // never installed: the file's `Enforced` would then ask for `--allow-unlock` and lift a lockdown that keeps a
        // re-install fail-closed. Say what the slot says (review G17f-2).
        say(
          chalk.yellow(
            `WARNING: the Safe's guard slot is EMPTY while this guard holds a policy for it: the guard is not installed ` +
              `(decommissioned, or not yet installed). After a decommission retire the file ("mode": "Lockdown", docs §7.5) ` +
              `rather than lifting the lockdown; before an install sync as usual.`,
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
/// A band (a floor and a ceiling on one word) that MOVES without growing is not weaker: it is the
/// re-sync docs section 5 asks for at every funding step (the settled NAV moved, the band follows).
/// Such a shift is reported as `shifted`, never as a loosening, so the flag that must never become a
/// habit (`--confirm-loosening`) is asked for only when the band widens, a bound goes, a floor falls
/// below the old floor while the ceiling stays, or `allowValue` switches on (review G12c).
function loosensRules(
  before: OnChainRule[],
  after: OnChainRule[],
  valueBefore: boolean,
  valueAfter: boolean,
  anchor?: bigint,
): { why: string[]; shifted: string[] } {
  const why: string[] = [];
  const shifted: string[] = [];
  if (!valueBefore && valueAfter) why.push("allowValue switched on");
  const bandWords = new Set<number>();
  for (const b of before) {
    if (b.kind !== 3 && b.kind !== 4) continue;
    const other = before.find((o) => o.wordIndex === b.wordIndex && o.kind === (b.kind === 3 ? 4 : 3));
    const sameCeil = after.find((a) => a.kind === 3 && a.wordIndex === b.wordIndex);
    const sameFloor = after.find((a) => a.kind === 4 && a.wordIndex === b.wordIndex);
    if (!other || !sameCeil || !sameFloor) continue;
    const ceilBefore = BigInt((b.kind === 3 ? b : other).value);
    const floorBefore = BigInt((b.kind === 4 ? b : other).value);
    const ceilAfter = BigInt(sameCeil.value);
    const floorAfter = BigInt(sameFloor.value);
    const sameDirection =
      (ceilAfter >= ceilBefore && floorAfter >= floorBefore) || (ceilAfter <= ceilBefore && floorAfter <= floorBefore);
    // The width is compared relative to the band's centre (a +-5 % band around a larger NAV is wider in
    // raw units and no looser), with one part in a thousand of the band's own relative width as slack: a
    // band typed in round numbers, or one computed by integer division at a six-decimal NAV, lands a few
    // parts in a million to a few parts in ten thousand off the previous relative width, which a
    // one-in-a-million slack read as a loosening on every honest re-sync (review G15g-4; a +-5 % band may
    // grow to +-5.005 % unflagged, 0.005 % of NAV). The file's edges are integers (n * 95 / 100 and
    // n * 105 / 100 both round), so the new width may also exceed the old by up to two raw units whatever
    // the NAV: forgiven besides the slack, or a band following a NAV below about 2e7 raw units (an exit to
    // dust) reads as a loosening (review G15a-2).
    const widthAfter = ceilAfter - floorAfter > 2n ? ceilAfter - floorAfter - 2n : 0n;
    const notWider =
      widthAfter * (ceilBefore + floorBefore) * 1_000n <=
      (ceilBefore - floorBefore) * (ceilAfter + floorAfter) * 1_001n;
    // Only a band that lands on the vault's live `totalAssets()` (the anchor the caller read) is a
    // re-sync; a band moved away from it is a loosening like any other.
    const anchored = anchor !== undefined && floorAfter <= anchor && anchor <= ceilAfter;
    if (sameDirection && notWider && anchored) bandWords.add(b.wordIndex);
  }
  for (const w of bandWords)
    shifted.push(`band on word ${w} shifted (relative width not grown, the vault's totalAssets() inside)`);
  for (const b of before) {
    const same = after.find((a) => a.kind === b.kind && a.wordIndex === b.wordIndex);
    if (!same) {
      why.push(`${RULE_KINDS[b.kind]} on word ${b.wordIndex} removed`);
      continue;
    }
    if (bandWords.has(b.wordIndex) && (b.kind === 3 || b.kind === 4)) continue;
    if (b.kind === 3 && BigInt(same.value) > BigInt(b.value)) why.push(`ceiling on word ${b.wordIndex} raised`);
    if (b.kind === 4 && BigInt(same.value) < BigInt(b.value)) why.push(`floor on word ${b.wordIndex} lowered`);
  }
  return { why, shifted };
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
  /// When THIS operation was prepared (chain time), so a later schedule that carries it keeps it (review G17b-4).
  preparedAt?: string;
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
    // Capped like the routine queue print (review G13f-1): a flood must not turn the refusal into a dump.
    const list =
      pending
        .slice(0, QUEUE_PRINT_CAP)
        .map((p) => `  ${p.opId}: ${p.description}\n    ${cancelHint(p.opId)}`)
        .join("\n") + (pending.length > QUEUE_PRINT_CAP ? `\n  ... and ${pending.length - QUEUE_PRINT_CAP} more` : "");
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
    // The deadline is fixed now and the operation is Ready `minDelay` after the proposer Safe executes
    // `scheduleBatch`: every hour the signing round takes is an hour less of the window, and a
    // schedule later than `deadline - minDelay` is dead on arrival. Say when, in clock time, the
    // proposer must have executed it (review G9e-5 / G11c).
    const scheduleBy = g.deadline - minDelay;
    console.log(
      chalk.yellow(
        `  the proposer Safe must execute scheduleBatch before ${iso(scheduleBy)} (dead on arrival afterwards); ` +
          `advised: before ${iso(scheduleBy - WINDOW_MARGIN)}, so at least ${WINDOW_MARGIN / 3600n} h of window remain`,
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
    ops.push({
      opId,
      salt,
      predecessor,
      deadline: g.deadline.toString(),
      payloads,
      lifts: g.lifts,
      kind: "batch",
      preparedAt: String(latest.timestamp),
    });
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
        // An `enforce` lifts a lockdown / Bypass only on a CONFIGURED Safe (the plan's predicate); on a fresh
        // Safe it is the go-live enable, which needs no flag when the first sync is replayed by id after a
        // reorg (review G14f-5).
        lifts:
          op.calls.some((c) => unwrapExecuteBefore(ctx.guardIface, c.data)?.data === enforceData) &&
          (await safeIsConfigured(ctx.guardContract, safe)),
        kind: op.kind,
        block: op.block,
      });
    }
  } else {
    if (!stored)
      throw Error(
        `${stateFile} not found: schedule first, or pass --op <id> to execute an operation rebuilt from the timelock's logs`,
      );
    if (
      stored.chainId !== chainId ||
      lower(stored.timelock) !== lower(admin) ||
      lower(stored.guard) !== lower(guard) ||
      lower(String(stored.safe)) !== lower(safe)
    ) {
      // The Safe as well: a guard serves any number of Safes and the file is keyed by chain and guard, so another
      // Safe's operations would otherwise be judged against this Safe's diff and called drifted (review G17b-4).
      throw Error(
        `${stateFile} belongs to chain ${stored.chainId} / timelock ${stored.timelock} / guard ${stored.guard} / Safe ${stored.safe}, not this run`,
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
      ops.push({
        ...op,
        // Never believed from the file: a lift is an `enforce` on a configured Safe, as the `--op` path derives it (the
        // id check above proves the payloads and nothing else; review G17b-4).
        lifts:
          op.payloads.some((p) => unwrapExecuteBefore(ctx.guardIface, p)?.data === enforceData) &&
          (await safeIsConfigured(ctx.guardContract, safe)),
        block: (scan.ops.get(op.opId) ?? scan.ops.get(lower(op.opId)))?.block ?? 0,
      });
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
    // A window shorter than the margin is no window: blocks are 12 s apart and a simulation at `latest`
    // can pass while the transaction lands after the deadline (`DeadlinePassed`, nothing executed).
    const opens = ts > now ? ts : now;
    if (BigInt(op.deadline) - opens < WINDOW_MARGIN) {
      console.log(
        chalk.yellow(
          `WARNING: operation ${op.opId} has less than ${WINDOW_MARGIN / 3600n} h between ${ts > now ? "Ready" : "now"} (${iso(opens)}) and its ` +
            `executeBefore deadline ${iso(BigInt(op.deadline))}: execute at once or ${cancelHint(op.opId)} and schedule again`,
        ),
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
    for (const op of pendingOps) {
      // A hand-scheduled one-off (an approval, a role change, a window) is never a sync operation: this task
      // does not execute it (review G9e-1, held) and must not advise cancelling it (review G15a-3).
      console.log(
        chalk.yellow(
          isOneOff(ctx, op.payloads)
            ? `operation ${op.opId} is not a policy sync (a one-off: see curator-guard-verify --op): this task does not execute it; once Ready, land it with the timelock's own execute / executeBatch, or ${cancelHint(op.opId)}`
            : `the policy is already in sync; operation ${op.opId} is still queued: ${cancelHint(op.opId)}`,
        ),
      );
    }
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
    if (stale.length && isOneOff(ctx, op.payloads)) {
      // A hand-scheduled one-off (an approval, a role change, a window, a hand-over step) is never a sync
      // operation: this task does not execute it (review G9e-1, held) and must not advise cancelling it
      // as a drifted sync (review G15a-3); `curator-guard-verify --op` gives it its own verdict.
      console.log(
        chalk.yellow(
          `operation ${op.opId} is not a policy sync (a one-off: curator-guard-verify --op decodes it): this task does not ` +
            `execute it; once Ready, land it with the timelock's own execute / executeBatch, or ${cancelHint(op.opId)}`,
        ),
      );
      continue;
    }
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
        // The preparation time is the file's word (per operation since review G17b-4, the file-level value for an older
        // file). The chain's own `CallScheduled` block is never tampered and a tampered file can only move this time
        // later, so the EARLIER of the two decides when the scan has the block: the file may make the check stricter,
        // never looser.
        let scheduledAt = BigInt(op.preparedAt ?? stored?.preparedAt ?? "0");
        if (op.block > 0) {
          const scheduledBlock = await ethers.provider.getBlock(op.block);
          if (scheduledBlock && BigInt(scheduledBlock.timestamp) < scheduledAt)
            scheduledAt = BigInt(scheduledBlock.timestamp);
        }
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
  // "Done" is read at ONE confirmation: a reorg that drops the execution afterwards leaves the operation
  // Ready with no file, and `--execute --op <id>` is the way back (review G13c-2), so say the ids out loud.
  if (!args.op && stored) {
    let allDone = true;
    for (const op of stored.operations) if ((await timelock.getTimestamp(op.opId)) !== 1n) allDone = false;
    if (allDone) {
      removeState(stateFile);
      console.log(
        chalk.blue(
          `state file removed (every operation done at block ${await ethers.provider.getBlockNumber()}); if a reorg ` +
            `drops an execution, land it again with --execute --op ${stored.operations.map((o) => o.opId).join(" / --op ")}`,
        ),
      );
    }
  }
  if (scan.degraded)
    console.log(chalk.yellow(`WARNING: other pending operations could NOT be listed (${scan.degraded})`));
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

/// A one-off operation: none of its wrapped calls is a policy mutator (the verify task's own test).
function isOneOff(ctx: Ctx, payloads: string[]): boolean {
  return payloads.every((p) => {
    const inner = unwrapExecuteBefore(ctx.guardIface, p);
    return inner === undefined || !SYNC_SELECTORS.has(inner.data.slice(0, 10));
  });
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
type Scan = {
  from: number | undefined;
  ops: Map<string, ScanOp>;
  /// Set when a tolerated scan could not list the queue (the reason): `ops` is then unknown, never empty.
  degraded?: string;
};

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
    return { from, ops, degraded: msg };
  }
  let logs: (Log | EventLog)[];
  try {
    logs = await scanLogs(hre, timelock, timelock.filters.CallScheduled(), from);
  } catch (e: unknown) {
    const msg = `could not scan the timelock's CallScheduled events (${errorText(e)})`;
    if (!tolerate) throw Error(`${msg}: refusing to schedule blind (--allow-pending to override)`);
    console.log(chalk.yellow(`WARNING: ${msg}`));
    return { from, ops, degraded: msg };
  }
  // Canary (review G10e-1): the timelock's constructor granted itself DEFAULT_ADMIN_ROLE at `from` or
  // later; a scan that cannot see it while the role is held is an incomplete stream, and an empty queue
  // built from it would let a pending operation hide behind "no operation pending".
  try {
    const adminRole: string = await timelock.DEFAULT_ADMIN_ROLE();
    const seenSelf = (await scanLogs(hre, timelock, timelock.filters.RoleGranted(adminRole), from)).some(
      (l) => lower(String((l as EventLog).args.account)) === lower(ctx.admin),
    );
    if (!seenSelf && (await timelock.hasRole(adminRole, ctx.admin))) {
      const msg = `log stream incomplete: the timelock's RoleGranted(DEFAULT_ADMIN_ROLE, ${ctx.admin}) since block ${from} is missing from eth_getLogs although the role is held: the provider truncates or drops logs, so the queue cannot be listed`;
      if (!tolerate) throw Error(`${msg}: refusing to schedule blind (--allow-pending to override)`);
      console.log(chalk.yellow(`WARNING: ${msg}`));
      return { from, ops, degraded: msg };
    }
  } catch (e: unknown) {
    if (!tolerate) throw e;
    console.log(chalk.yellow(`WARNING: ${errorText(e)}`));
    return { from, ops, degraded: errorText(e) };
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

/// "Configured" as the contract's `AdminIsGuarded` predicate reads it and as `planDiff` decides whether an
/// `enforce` is a lift: any policy state on the Safe, or a Bypass window.
async function safeIsConfigured(guard: Contract, safe: string): Promise<boolean> {
  const [, enforceOnChain] = await guard.requiredFallbackHandler(safe);
  const mode = CHAIN_MODES[Number(await guard.mode(safe))];
  return (
    ((await guard.targets(safe)) as string[]).length > 0 ||
    ((await guard.guardians(safe)) as string[]).length > 0 ||
    enforceOnChain === true ||
    mode === "Bypass" ||
    ((await guard.modules(safe)) as string[]).length > 0 ||
    ((await guard.multiSendUnwrappers(safe)) as string[]).length > 0
  );
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
    // After the head every scan is empty and the canary would blame the provider (review G11e-3).
    const head = await hre.ethers.provider.getBlockNumber();
    if (Number(explicit) > head) throw Error(`timelock block ${explicit} is after the chain head ${head}`);
    return Number(explicit);
  }
  // The guard's own logs (council and guardian grants, approvals, forbidden hashes, revocations) start at
  // the guard's creation, which only the FIRST admin timelock precedes: after a hand-over the successor's
  // record starts later than every grant made before it, so the scan takes the earliest record it has
  // (review G15a-1: "council: none" after a hand-over while hasRole said yes).
  const all = await hre.deployments.all();
  let earliest: number | undefined;
  for (const who of [ctx.admin, ctx.guard]) {
    const d = Object.values(all).find((x) => lower(x.address) === lower(who));
    const b = d?.receipt?.blockNumber;
    if (b !== undefined && (earliest === undefined || Number(b) < earliest)) earliest = Number(b);
  }
  if (earliest !== undefined) return earliest;
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

/// The routine queue print shows at most this many pending operations, and above the lower bound it
/// names the burst for what it is (review G13f-1): a proposer floods the timelock at no cost, the veto
/// clears the flood in one batched cancel.
const QUEUE_PRINT_CAP = 50;
const QUEUE_FLOOD_WARN = 20;

/// Above this many logs in one answer the chunk is split and asked again: a provider that silently
/// caps an answer never says so, and the guard's own event volume never fills a chunk this far
/// (review G10e-1, hostile log stream). A single block is always accepted as answered.
const DENSE_CHUNK_LOGS = 1_000;

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
      const got = await contract.queryFilter(filter, a, b);
      if (got.length >= DENSE_CHUNK_LOGS && b > a) {
        chunk = Math.max(1, Math.floor(chunk / 4));
        continue;
      }
      out.push(...got);
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
/// earlier call of the same batch (`addAllowedValues` before its `allowFunction`: `NoOneOfRule`; an add
/// at a set's cap after a removal: `TooManyValues`) are estimated by a heuristic instead.
async function simulateAsAdmin(hre: HardhatRuntimeEnvironment, ctx: Ctx, payloads: string[]): Promise<bigint> {
  const { ethers } = hre;
  let gas = 0n;
  const caps = await cappedSets(ctx, payloads);
  for (const [i, data] of payloads.entries()) {
    try {
      gas += await ethers.provider.estimateGas({ from: ctx.admin, to: ctx.guard, data });
    } catch (e: unknown) {
      const decoded = decodeRevert(ctx, e);
      // The contract checks `MAX_GUARDIANS` / `MAX_SELECTORS` after the add, so a removal earlier in
      // the SAME batch makes room that a call simulated alone cannot see (the batch executes in
      // order; review G11e-1): the running count decides, and the estimate is a heuristic.
      if (decoded.startsWith("TooManyValues") && caps.fitsAt(i)) {
        gas += 150_000n;
        continue;
      }
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

/// Running sizes of the two capped sets (the per-Safe guardians, the selectors of each target) over an
/// ORDERED batch, from the on-chain state: `fitsAt(i)` says whether the set that payload `i` adds to is
/// within its cap once every earlier call of the batch has run (review G11e-1).
async function cappedSets(ctx: Ctx, payloads: string[]): Promise<{ fitsAt: (i: number) => boolean }> {
  const guard = ctx.guardContract;
  const safe = lower(ctx.safe);
  const guardians = new Set(((await guard.guardians(ctx.safe)) as string[]).map(lower));
  const selectors = new Map<string, Set<string>>();
  const sizeAfter: (number | undefined)[] = [];
  const capOf: (number | undefined)[] = [];
  for (const data of payloads) {
    let size: number | undefined;
    let cap: number | undefined;
    const inner = unwrapExecuteBefore(ctx.guardIface, data);
    let name: string | undefined;
    let args: readonly unknown[] = [];
    try {
      const parsed = inner ? ctx.guardIface.parseTransaction({ data: inner.data }) : null;
      name = parsed?.name;
      args = parsed?.args ?? [];
    } catch {
      /* not a guard call: no set touched */
    }
    if (name === "setGuardian" && lower(String(args[0])) === safe) {
      if (args[2]) guardians.add(lower(String(args[1])));
      else guardians.delete(lower(String(args[1])));
      size = guardians.size;
      cap = MAX_GUARDIANS;
    } else if ((name === "allowFunction" || name === "revokeFunction") && lower(String(args[0])) === safe) {
      const target = String(args[1]);
      if (!selectors.has(lower(target))) {
        const live = ((await guard.selectors(ctx.safe, target)) as string[]).map((w) => lower(w).slice(0, 10));
        selectors.set(lower(target), new Set(live));
      }
      const set = selectors.get(lower(target))!;
      if (name === "allowFunction") set.add(lower(String(args[2])));
      else set.delete(lower(String(args[2])));
      size = set.size;
      cap = MAX_SELECTORS;
    }
    sizeAfter.push(size);
    capOf.push(cap);
  }
  return { fitsAt: (i) => sizeAfter[i] !== undefined && sizeAfter[i]! <= capOf[i]! };
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
    // A seat for the guard's own address is a dead seat (review G10a-2): say so where the veto reads the queue.
    const deadSeat = (() => {
      try {
        const parsed = ctx.guardIface.parseTransaction({ data: inner ? inner.data : data });
        if (!parsed) return false;
        const seatOf: Record<string, number> = {
          grantRole: 1,
          setDeploymentGuardian: 0,
          setGuardian: 1,
          beginDefaultAdminTransfer: 0,
        };
        const i = seatOf[parsed.name];
        return i !== undefined && lower(String(parsed.args[i])) === lower(ctx.guard);
      } catch {
        return false;
      }
    })();
    // A cancel of a hand-over and a rollback of an admin-delay change decide the same race as the begin and the change
    // (docs section 7.5, reviews G16a-1 and G16f-2): role-sensitive like them (review G18d-1).
    const sensitive =
      /^(grantRole|revokeRole|renounceRole|beginDefaultAdminTransfer|cancelDefaultAdminTransfer|changeDefaultAdminDelay|rollbackDefaultAdminDelay|setDeploymentGuardian|setGuardian|bypass|approveTransaction|enforce)\b/.test(
        text,
      );
    // A cancel chained behind a hostile begin must be BARE: the begin carries no deadline and its proposer lands
    // it when it likes, so a wrapped cancel is waited out and dies `DeadlinePassed` in the block the begin lands
    // (section 7.5, review G16a-1). Named wherever the call is printed (the queue, --op, --manifest).
    const wrappedCancel = inner !== undefined && /^cancelDefaultAdminTransfer\b/.test(text);
    // The tag belongs on the call's own line: an approval's description continues on further lines with what it
    // authorises (review G11f), and the queue print joins calls with " | " (review P1b-5).
    const [first, ...rest] = text.split("\n");
    const tags =
      (sensitive ? "  [ROLE / INCIDENT-SENSITIVE]" : "") +
      (deadSeat ? "  [DEAD SEAT: the guard itself, review G10a-2]" : "") +
      (wrappedCancel ? "  [WRAPPED CANCEL: can be waited out past its deadline, schedule it bare]" : "");
    return [`${prefix}${first}${tags}`, ...rest].join("\n");
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
      if (t.type === "tuple[]" && t.arrayChildren?.components?.map((c) => c.name).join() === "kind,wordIndex,value")
        return `[${(a as [bigint, bigint, string][])
          .map((r) => onChainRuleText({ kind: Number(r[0]), wordIndex: Number(r[1]), value: r[2] }))
          .join(", ")}]`;
      if (t.baseType === "array" || t.baseType === "tuple")
        return JSON.stringify(a, (_, v) => (typeof v === "bigint" ? v.toString() : v));
      return String(a);
    });
    const text = `${parsed.name}(${args.join(", ")})`;
    if (parsed.name !== "approveTransaction") return text;
    // The content of an approval is the custody (review G11f): say what it authorises, one level down.
    const authorised = describeApprovedPayload(
      String(parsed.args[0]),
      String(parsed.args[2]),
      String(parsed.args[4]),
      BigInt(parsed.args[5]),
    );
    return `${text}\n      authorises ${authorised}`;
  } catch {
    return `undecodable ${data.slice(0, 10)}`;
  }
}

type PackedEntry = { operation: number; to: string; value: bigint; data: string };

/// Unpacks `multiSend(bytes)`: op(1) | to(20) | value(32) | length(32) | data, repeated. `undefined` for
/// anything that does not parse to the end (the contract refuses such a batch at use anyway).
function unpackMultiSend(data: string): PackedEntry[] | undefined {
  try {
    const packed = String(AbiCoder.defaultAbiCoder().decode(["bytes"], "0x" + data.slice(10))[0]);
    const bytes = getBytes(packed);
    const out: PackedEntry[] = [];
    let i = 0;
    while (i < bytes.length) {
      if (i + 85 > bytes.length) return undefined;
      const length = Number(BigInt(hexlify(bytes.slice(i + 53, i + 85))));
      if (i + 85 + length > bytes.length) return undefined;
      out.push({
        operation: bytes[i],
        to: getAddress(hexlify(bytes.slice(i + 1, i + 21))),
        value: BigInt(hexlify(bytes.slice(i + 21, i + 53))),
        data: hexlify(bytes.slice(i + 85, i + 85 + length)),
      });
      i += 85 + length;
    }
    return out;
  } catch {
    return undefined;
  }
}

/// One level of what an approval authorises: a Safe self-call by name, a plain call by selector, a
/// delegatecall by library (a canonical `MultiSend` batch entry by entry, each entry described the same way).
function describeApprovedPayload(safe: string, to: string, data: string, operation: bigint, depth = 0): string {
  const pad = "        " + "  ".repeat(depth);
  const sel = data.length >= 10 ? lower(data.slice(0, 10)) : "0x";
  const name = data.length <= 2 ? "(empty calldata)" : (KNOWN_SIGNATURES.get(sel) ?? MIGRATION_NAMES.get(sel) ?? sel);
  if (operation === 1n) {
    const lib = CANONICAL_MULTISEND.get(lower(to)) ?? CANONICAL_MIGRATIONS.get(lower(to));
    const flags =
      (lib ? "" : "  [UNKNOWN CODE IN THE SAFE'S STORAGE CONTEXT: not a canonical Safe library]") +
      (HANDLER_REINSTALLING.has(sel) ? "  [REINSTALLS A SIGNATURE-CAPABLE FALLBACK HANDLER]" : "") +
      (MIGRATION_NAMES.has(sel) && !CANONICAL_MIGRATIONS.has(lower(to))
        ? "  [MIGRATION SELECTOR ON A NON-CANONICAL LIBRARY]"
        : "");
    const head = `DELEGATECALL ${to} ${lib ? `(${lib}) ` : ""}${name}${flags}`;
    const entries =
      sel === MULTISEND_SELECTOR && CANONICAL_MULTISEND.has(lower(to)) ? unpackMultiSend(data) : undefined;
    if (!entries) return head;
    return [
      head,
      ...entries.map(
        (e, i) =>
          `${pad}#${i} ${e.value !== 0n ? `value ${e.value} ` : ""}${describeApprovedPayload(safe, e.to, e.data, BigInt(e.operation), depth + 1)}`,
      ),
    ].join("\n");
  }
  // Review G17a-3: the guard refuses a codeless approval target only with calldata or on a delegatecall, so an
  // approved transfer of value to the zero address (a paste error) is valid on-chain; say so wherever an approval is read.
  if (isZeroAddress(to)) return `CALL ${to} ${name}  [ZERO TARGET: an approved burn of the value, review G17a-3]`;
  if (lower(to) === lower(safe)) return `SELF-CALL ${name}  [SAFE CONFIGURATION]`;
  return `CALL ${to} ${name}`;
}

/// The PUSH solc emits for a 4-byte selector: leading zero bytes are dropped (`PUSH1`..`PUSH4`).
function pushOf(selector: string): string {
  const hex = lower(selector.slice(2)).replace(/^(00)+/, "") || "00";
  return (0x5f + hex.length / 2).toString(16) + hex;
}

/// `GreaterThanOrEqual@0=952760`, `OneOf@tail2`: one rule as the diff prints it, so the veto reads a queued band in
/// the operator's words and not as a `(kind, wordIndex, bytes32)` tuple (review G17f-1).
function onChainRuleText(r: OnChainRule): string {
  const word = r.wordIndex & TAIL_FLAG ? `tail${r.wordIndex & ~TAIL_FLAG}` : r.wordIndex;
  const value = r.kind === 0 || r.kind === 3 || r.kind === 4 ? `=${wordText(r.value)}` : "";
  return `${RULE_KINDS[r.kind] ?? `kind${r.kind}`}@${word}${value}`;
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

/// `true` when `e` is the EVM's own answer to a call (a revert, or a return the ABI cannot decode: the target does not
/// implement the function), `false` for a transport failure (a timeout, a rate limit, a dropped connection), which is
/// never read as an answer (review G17b-2; the test `isSafeContract` and `timelockAt` apply).
function isEvmAnswer(e: unknown): boolean {
  const code = (e as { code?: string }).code;
  return code === "CALL_EXCEPTION" || code === "BAD_DATA" || /revert|could not decode result data/i.test(errorText(e));
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

/// The admin as a `TimelockController`, or `undefined` when it does not answer `getMinDelay()` (an
/// EVM-level answer); a transport error is thrown, never read as "not a timelock" (the queue, the
/// council's timelock roles and the proposer check would silently drop out of the run; review G11e-3).
async function timelockAt(hre: HardhatRuntimeEnvironment, admin: string): Promise<Contract | undefined> {
  const { ethers } = hre;
  if ((await ethers.provider.getCode(admin)) === "0x") return undefined;
  const timelock = (await ethers.getContractAt("CuratorGuardTimelock", admin)) as unknown as Contract;
  try {
    await timelock.getMinDelay();
    return timelock;
  } catch (e: unknown) {
    const code = (e as { code?: string }).code;
    const message = errorText(e);
    if (code === "CALL_EXCEPTION" || code === "BAD_DATA" || /revert|could not decode result data/i.test(message))
      return undefined;
    throw Error(`could not read ${admin} as a TimelockController (${message}): refusing to continue on a failed read`);
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
  // ethers parses `uint256[0]` and `()` as canonical types; no Solidity contract can declare them, so such an
  // entry would allowlist a selector nothing implements (review G12f-4).
  const parameterList = f.signature.slice(f.signature.indexOf("(") + 1, f.signature.lastIndexOf(")"));
  if (/\[0\]|\(\)/.test(parameterList))
    throw Error(`${f.signature}: a zero-length array or an empty tuple is not a type a contract can implement`);
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

/// A raw tail must be the CANONICAL encoding of the parameters from word `wordIndex` on (review G10b-1): with
/// `wordIndex` zero words in front it must decode as the full parameter list and re-encode to the same bytes.
/// Any other layout binds bytes whose meaning the callee reads differently: an offset that points back into a
/// static word before `wordIndex` makes that word (unbound unless it carries its own rule) the length or the
/// contents of the dynamic parameter, so the signers can change the payload the venue decodes without
/// touching the hashed tail. A venue that does not decode the standard way can still be bound by giving the
/// 32-byte hash itself, which this check does not see.
function assertCanonicalTail(fragment: FunctionFragment, wordIndex: number, raw: string, where: string): void {
  const full = "0x" + "00".repeat(32 * wordIndex) + raw.slice(2);
  let decoded: unknown[];
  try {
    decoded = AbiCoder.defaultAbiCoder().decode(fragment.inputs, full).toArray();
  } catch (e) {
    throw Error(
      `${where}: tail bytes do not decode as ${fragment.format("sighash")} from word ${wordIndex}: ${(e as Error).message} ` +
        `(a \`string\` payload that is not valid UTF-8 cannot be re-encoded here: give its 32-byte hash instead)`,
    );
  }
  if (lower(AbiCoder.defaultAbiCoder().encode(fragment.inputs, decoded)) !== lower(full))
    throw Error(
      `${where}: tail bytes are not the canonical encoding of ${fragment.format("sighash")} from word ${wordIndex} ` +
        `(an offset points elsewhere, or the padding differs): the callee would read a payload the hash does not pin; ` +
        `re-encode the reviewed call, or give the 32-byte hash for a venue that does not decode the standard way`,
    );
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
    // A `bytesN` parameter occupies the HIGH N bytes of its head word (the ABI left-aligns it); a decimal, or a hex
    // word with its bytes on the right, is a word no canonical call ever carries, so the rule is dead (review G12f-1).
    const b = /^bytes(\d+)$/.exec(type);
    if (b && Number(b[1]) < 32 && word !== 0n && (word & ((1n << BigInt(8 * (32 - Number(b[1])))) - 1n)) !== 0n) {
      throw Error(
        `rule value ${v} is not left-aligned for ${type}: the ABI puts the ${b[1]} bytes in the high bytes of the word ` +
          `(write the 32-byte word 0x<${2 * Number(b[1])} hex digits>${"00".repeat(32 - Number(b[1]))}); a number is right-aligned and can never match`,
      );
    }
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
    // The policy's required fallback handler counts as part of the Safe on the council lane (unreachable
    // as a call target: a handler answers calls from the Safe as the Safe's own) but the policy lane has no
    // such notion, so an entry on it would let the signers reach the handler's Safe-only surface (an
    // `ExtensibleFallbackHandler`'s `setSafeMethod`) through an allowlisted call (review G12b-1).
    if (
      !isZeroAddress(p.requiredFallbackHandler.handler) &&
      lower(f.target) === lower(p.requiredFallbackHandler.handler)
    )
      throw Error(
        `${where}: the policy's required fallback handler is part of the Safe (the council lane refuses every call to it); it can never be a policy target`,
      );
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
    const fragment = FunctionFragment.from(fn.signature);
    const types = headTypes(fragment);
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
          `${where}: two ${rule.kind} rules on word ${rule.wordIndex} (redundant: every rule is evaluated and ANDed; a OneOf word has one set)`,
        );
      kinds.push(rule.kind);
      perWord.set(onChainWordIndex(rule), kinds);
      if (/^int\d*$/.test(type))
        warnings.push(
          `${where}: word ${rule.wordIndex} is ${type}; the guard compares words unsigned, a negative value reads as a huge one`,
        );
      // A bound compares the whole word as an unsigned number; on a `bytesN` word (N < 32) that number is the N bytes
      // shifted into the high end, so a ceiling or a floor on it bounds nothing an author means (review G12f-1).
      if (
        /^bytes\d+$/.test(type) &&
        type !== "bytes32" &&
        (rule.kind === "LessThanOrEqual" || rule.kind === "GreaterThanOrEqual")
      )
        throw Error(
          `${where}: ${rule.kind} on word ${rule.wordIndex} which is ${type}: a bound compares the left-aligned word as a number and ` +
            `means nothing for fixed bytes; pin the word with EqualTo or OneOf`,
        );
      // On an `address` word every canonical value sits below 2^160 and on a `bool` word below 2: a ceiling or a floor
      // there admits every honest call while it counts as "a rule on word N" for the allowance table and silences the
      // unbound-address warning (`approve` with `LessThanOrEqual 2^160-1` on the spender linted valid and the guard
      // allowed every spender; review G17b-3).
      if (
        (type === "address" || type === "bool") &&
        (rule.kind === "LessThanOrEqual" || rule.kind === "GreaterThanOrEqual")
      )
        throw Error(
          `${where}: ${rule.kind} on word ${rule.wordIndex} which is ${type}: a bound orders nothing an author means on it; ` +
            `pin the word with EqualTo, EqualToSafe or OneOf`,
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
          if (rule.tail && !/^0x[0-9a-fA-F]{64}$/.test(v)) assertCanonicalTail(fragment, rule.wordIndex, v, where);
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
        if (rule.tail && !/^0x[0-9a-fA-F]{64}$/.test(rule.value))
          assertCanonicalTail(fragment, rule.wordIndex, rule.value, where);
        const w = BigInt(rule.tail ? ruleWord(rule, rule.value) : toWord(rule.value, type));
        // The word's own width: a ceiling at the largest value a `uintN` word carries in a canonical call bounds nothing
        // either (`2^256-1` for an untyped or 256-bit word; review G17b-3).
        const width = /^uint(\d+)$/.exec(type);
        const bits = width ? BigInt(width[1]) : 256n;
        if (rule.kind === "LessThanOrEqual" && w === (1n << bits) - 1n)
          throw Error(`${where}: LessThanOrEqual 2^${bits}-1 on word ${rule.wordIndex} (${type}) bounds nothing`);
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
      // Review G17d-2: a `OneOf` set beside a bound on the same word is a dead function when no member satisfies the
      // bound: the contract accepts the rules and every call reverts `ParamRuleViolated`, which the author discovers
      // at the first refused transaction.
      if (lo || hi) {
        const loW = lo?.value !== undefined ? BigInt(toWord(lo.value)) : 0n;
        const hiW = hi?.value !== undefined ? BigInt(toWord(hi.value)) : UINT256_MAX;
        const inside = (x: bigint) => x >= loW && x <= hiW;
        const set = (rules as PolicyRule[]).find((r) => onChainWordIndex(r) === word && r.kind === "OneOf");
        if (set) {
          const outside = (set.values ?? []).filter((v) => !inside(BigInt(toWord(v))));
          if (outside.length === (set.values ?? []).length)
            throw Error(
              `${where}: no OneOf member on word ${word} satisfies its bounds [${loW}, ${hiW}] (the function could never be called)`,
            );
          if (outside.length)
            warnings.push(
              `${where}: ${outside.length} OneOf member(s) on word ${word} fall outside its bounds [${loW}, ${hiW}] and can never match`,
            );
        }
        // (`EqualToSafe` beside a bound cannot reach here: a bound on an address word is refused above, review G17b-3.)
      }
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
    // A settle's own word-0 band or set is read like the mark's (the settle executes whatever mark is pending, review
    // G11b-2): with no constrained mark on its target to mirror, a settles-only `[1, 2^256-2]` read as banded with no
    // word and no gate (review G18c-3). With a constrained mark the settle repeats it, warned once on the mark below.
    const settleWord =
      bandWord === undefined &&
      NAV_FAMILY.has(selector) &&
      !(p.functions as unknown as PolicyFunction[]).some(
        (m) =>
          lower(m.target) === lower(fn.target) &&
          !m.unconstrained &&
          BAND_SHAPED.has(selectorOfSignature(String(m.signature))),
      )
        ? 0
        : undefined;
    if (bandWord !== undefined && !fn.unconstrained) {
      const kinds = (rules as PolicyRule[]).filter((r) => r.wordIndex === bandWord).map((r) => r.kind);
      if (!kinds.some((k) => UPPER_BOUND_KINDS.includes(k)) || !kinds.some((k) => LOWER_BOUND_KINDS.includes(k))) {
        throw Error(
          `${where}: NAV-shaped function needs a floor and a ceiling on word ${bandWord} (a band around the settled NAV ` +
            `refuses unit mistakes and caps a single mark; re-sync it with every funding step) or "unconstrained": true`,
        );
      }
    }
    const pricedWord = bandWord ?? settleWord;
    if (pricedWord !== undefined && !fn.unconstrained) {
      const bandWord = pricedWord;
      // Offline the live NAV is unknown, but a ceiling more than 100 times the floor is a band only on
      // paper: `[1, 2^256-2]` passes the pairing checks above and the contract's, and caps nothing a NAV
      // band is for. The sync refuses such a band's first sync against the vault's live `totalAssets()`
      // (review G13a-1); the warning keeps a reviewer from reading a floor and a ceiling as a bound.
      const lo = (rules as PolicyRule[]).find(
        (r) => r.wordIndex === bandWord && r.kind === "GreaterThanOrEqual" && !r.tail,
      );
      const hi = (rules as PolicyRule[]).find(
        (r) => r.wordIndex === bandWord && r.kind === "LessThanOrEqual" && !r.tail,
      );
      if (lo?.value !== undefined && hi?.value !== undefined) {
        const loW = BigInt(toWord(lo.value));
        const hiW = BigInt(toWord(hi.value));
        if (hiW > loW * 100n)
          warnings.push(
            `${where}: the NAV band on word ${bandWord} spans [${loW}, ${hiW}], a ceiling more than 100 times the floor: it reads as a band and caps nothing (a NAV band sits around the settled NAV; the sync refuses its first sync unless the vault's live totalAssets() sits inside it and the band is no wider than +-50 % of it, or --allow-unconstrained-nav is given knowingly)`,
          );
      }
      // A fixed mark set (EqualTo / OneOf on the NAV word) with one member far from another is the same band on
      // paper in another shape; the sync judges the set's lowest and highest member against the live NAV on every
      // sync (review G16c-2).
      const fixedWords = (rules as PolicyRule[])
        .filter((r) => r.wordIndex === bandWord && !r.tail && (r.kind === "EqualTo" || r.kind === "OneOf"))
        .flatMap((r) =>
          r.kind === "OneOf" ? (r.values ?? []).map((v) => BigInt(toWord(v))) : [BigInt(toWord(r.value!))],
        );
      if (fixedWords.length) {
        const minW = fixedWords.reduce((a, b) => (a < b ? a : b));
        const maxW = fixedWords.reduce((a, b) => (a > b ? a : b));
        if (maxW > minW * 100n)
          warnings.push(
            `${where}: the fixed NAV mark set on word ${bandWord} spans [${minW}, ${maxW}], a member more than 100 times another: it reads as a fixed mark and caps nothing (the sync judges the set's lowest and highest member against the vault's live totalAssets() on every sync, review G16c-2)`,
          );
      }
    }
    const valueWords = ALLOWANCE_SHAPED.get(selector);
    // The escape hatch is read out loud where every reader of the file's warnings sees it (the lint, the sync and both
    // verify paths print them): an unconstrained allowance-shaped entry lets the Safe name ANY spender, receiver or
    // operator (review G17b-6; the hunk the round-17 merge dropped, review G18c-1).
    if (valueWords && fn.unconstrained)
      warnings.push(
        `${where}: unconstrained on an allowance / receiver-shaped function: the Safe may call it with ANY spender, receiver or operator`,
      );
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
  // A settle repeats whatever mark is pending (`WrongNewTotalAssets` otherwise), a `securityCouncilUpdateTotalAssets`
  // mark included once that role sits outside the Safe (docs section 8): a band on the mark entry alone then
  // bounds nothing the settles cannot pay out. A banded mark needs the same band on both settles of its target
  // (review G11b-2); the settles of an unconstrained mark stay free, as shipped.
  const fns = p.functions as unknown as PolicyFunction[];
  // Every word-0 rule of a function as the chain compares it (kind and value word(s)), in a canonical order. The
  // band-shape check above lets a constrained mark carry a floor + ceiling, an `EqualTo` (a fixed mark) or a
  // `OneOf` set on word 0: the settles must repeat whichever of these it carries, exactly (review P1b-1).
  const navRules = (f: PolicyFunction): string[] =>
    (f.rules ?? [])
      .filter((r) => r.wordIndex === 0 && !r.tail)
      .map((r) =>
        r.kind === "EqualToSafe"
          ? r.kind
          : r.kind === "OneOf"
            ? `${r.kind} {${(r.values ?? [])
                .map((v) => BigInt(ruleWord(r, v)))
                .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
                .join(", ")}}`
            : `${r.kind} ${BigInt(ruleWord(r, r.value!))}`,
      )
      .sort();
  for (const mark of fns) {
    if (!BAND_SHAPED.has(selectorOf(mark)) || mark.unconstrained) continue;
    const want = navRules(mark);
    if (!want.length) continue; // unreachable: a constrained mark carries a floor and a ceiling (checked above)
    for (const sig of SETTLE_SIGNATURES) {
      const settle = fns.find(
        (f) => lower(f.target) === lower(mark.target) && selectorOf(f) === selectorOfSignature(sig),
      );
      if (!settle) continue;
      if (navRules(settle).join("; ") !== want.join("; "))
        throw Error(
          `${sig} on ${mark.target}: must repeat the NAV band of updateNewTotalAssets (${want.join(" + ")} on word 0): ` +
            `the settle repeats whatever mark is pending, a securityCouncil mark included (review G11b-2)`,
        );
    }
  }
  return warnings;
}
