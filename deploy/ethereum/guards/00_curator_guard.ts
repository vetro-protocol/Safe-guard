import chalk from "chalk";
import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { getAddress, keccak256 } from "ethers";
import type { Contract, EventLog, Log } from "ethers";
import Addresses from "../../../helpers/address";

const CONTRACT = "CuratorGuard";
const TIMELOCK_CONTRACT = "CuratorGuardTimelock";
// Deployment alias; set CURATOR_GUARD_ALIAS=CuratorGuard_v2 (etc.) to deploy a replacement guard next
// to the installed one (docs/curator-guard.md section 7.5). The timelock alias follows it.
const ALIAS = process.env.CURATOR_GUARD_ALIAS || CONTRACT;
const TIMELOCK_ALIAS = `${ALIAS}Timelock`;
// A delay typed as "2d" or "48h" threw a bare `SyntaxError: Cannot convert 2d to a BigInt` from the module's load, naming
// no variable (review G21b-12): say which variable, and that the unit is seconds.
function secondsFromEnv(name: string, fallback: bigint): bigint {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  if (!/^\d+$/.test(raw)) throw Error(`${name} must be a whole number of SECONDS (48 h = 172800), got ${raw}`);
  return BigInt(raw);
}
// Widenings sit in public for this long before they can be executed (seconds). 48 h default.
const TIMELOCK_DELAY = secondsFromEnv("CURATOR_GUARD_TIMELOCK_DELAY", 48n * 3600n);
// Delay of the guard's own two-step admin transfer (`AccessControlDefaultAdminRules`). Must sit at least a
// day above the timelock delay (`ADMIN_DELAY_MARGIN`) so a `cancelDefaultAdminTransfer` scheduled when a
// hostile begin lands keeps a signing round before the acceptance opens: 3 days default.
const ADMIN_DELAY = secondsFromEnv("CURATOR_GUARD_ADMIN_DELAY", 3n * 24n * 3600n);
// Reuse an existing timelock (e.g. for a replacement guard) instead of deploying one per alias.
const EXISTING_TIMELOCK = process.env.CURATOR_GUARD_TIMELOCK;
const ZERO = "0x0000000000000000000000000000000000000000";
// The reviewed runtimes, metadata stripped, as `test/guards/G12a_BuildPin.t.sol` pins them (keccak256 of the runtime
// without its CBOR tail; 23,267 and 8,204 bytes: the masked handler-word rails of review G16d-1 and the guard's zero-target approval rail of review G17a-3). The deploy sends whatever the local `node_modules` and solc compiled
// to, and CI's parity step compares hardhat with foundry, never with the pin: this is the one step that must send the
// reviewed bytes, so it checks them itself (review G18g-2). A re-pin is a contract change with a review: move these
// two values together with the test's.
const REVIEWED_RUNTIME_KECCAK: Record<string, string> = {
  [CONTRACT]: "0x3bfe33c8e8c7a8e4edbe454efb7efaef22182ba362b8b824ccc0610c763bea8d",
  [TIMELOCK_CONTRACT]: "0x8a69e72c4ff2fbc0189b1ff3f6a7e74c239bcc3c3394a3fe158e952a02da786c",
};
// Mirrors `CuratorGuardTimelock.MIN_DELAY_FLOOR / MIN_DELAY_CAP` and `CuratorGuardPolicy.MAX_ADMIN_DELAY`
// (the floor is one day since the round-13 follow-up, G13f-3; keep the three in sync with the contracts).
const MIN_DELAY_FLOOR = 86_400n;
const MIN_DELAY_CAP = 30n * 24n * 3600n;
const MAX_ADMIN_DELAY = 30n * 24n * 3600n;
// How far the admin delay must sit above the timelock delay. The ordering exists so that a
// `cancelDefaultAdminTransfer` scheduled when a hostile begin lands is Ready (minDelay later) before the
// acceptance opens (adminDelay later): the honest side keeps adminDelay - minDelay, which must hold a
// proposer Safe's signing round; "above by one second" satisfies the strict rule and keeps nothing
// (review G16b-3). The defaults keep a day.
const ADMIN_DELAY_MARGIN = 86_400n;
const OVERRIDES = [
  "CURATOR_GUARD_ALLOW_KEY_OVERLAP",
  "CURATOR_GUARD_ALLOW_NO_COUNCIL",
  "CURATOR_GUARD_ALLOW_SINGLE_PROPOSER",
  "CURATOR_GUARD_ALLOW_MULTIPLE_CANCELLERS",
  "CURATOR_GUARD_ALLOW_SHORT_DELAY",
  "CURATOR_GUARD_ALLOW_WEAK_GOVERNANCE",
  "CURATOR_GUARD_FORK",
];
// Overrides that never downgrade a refusal on a real network.
const REHEARSAL_ONLY = [
  "CURATOR_GUARD_ALLOW_KEY_OVERLAP",
  "CURATOR_GUARD_ALLOW_MULTIPLE_CANCELLERS",
  "CURATOR_GUARD_ALLOW_WEAK_GOVERNANCE",
];

/// Deploys the (non-upgradeable) `CuratorGuard` behind a `CuratorGuardTimelock`:
///
///   proposer Safes   ──schedule──▶ CuratorGuardTimelock (DEFAULT_ADMIN of the guard) ──▶ CuratorGuard
///   canceller Safe   ──cancel────▶ (ONE Safe: the trusted veto; never the council, never a hot key)
///   council Safe     ─────────── fast lane (enforce, short approvals / bypass, guardians) ──▶
///   guardian keys    ─────────── narrow only (lockdown, revoke) ────────────────────────────▶
///
/// The timelock's roles are fixed by its constructor (no deployer admin, nothing to renounce, the
/// executor role open): `Vetro.curatorGuardProposers` (two Safes, so one lost quorum cannot strand the
/// guard) and `Vetro.curatorGuardCancellers` (exactly one dedicated veto Safe that is NOT a proposer:
/// a canceller can veto its own removal, so a canceller that could also propose would be an unvetoed
/// takeover once compromised, and a second canceller a second permanent veto; the contract itself
/// refuses a canceller that proposes; reviews V2-63 and V2-74). The council is never a canceller or
/// proposer (V2-54).
///
/// Preflight, all before the first transaction: no curator key may reach a proposer, the council or the
/// canceller (recursively through nested Safes; the P0 finding of docs section 12), the council may not
/// own or share a quorum with a proposer or the canceller, every governance principal must be a Safe
/// with a threshold of at least 2, delays within the contract ranges. Overrides, read from the
/// environment (and so from `.env`) on EVERY run: `CURATOR_GUARD_ALLOW_KEY_OVERLAP`,
/// `CURATOR_GUARD_ALLOW_MULTIPLE_CANCELLERS` and `CURATOR_GUARD_ALLOW_WEAK_GOVERNANCE` downgrade a
/// refusal on a FORK rehearsal only (fork = the node answers `hardhat_metadata` / `anvil_nodeInfo` AND
/// reports chain 31337 or CURATOR_GUARD_FORK=1; never a network name); `CURATOR_GUARD_ALLOW_NO_COUNCIL`,
/// `CURATOR_GUARD_ALLOW_SINGLE_PROPOSER` and `CURATOR_GUARD_ALLOW_SHORT_DELAY` downgrade on REAL networks
/// too, with a loud banner: unset them after a rehearsal.
///
/// A reused timelock (CURATOR_GUARD_TIMELOCK) is audited, not trusted: its code must be this
/// repository's build, its delay in range, and its role set, rebuilt from its own logs, exactly the
/// expected one. After every deployment the same audit runs and the queue must be empty.
///
/// The guard does nothing until (1) the admin configures a policy for a Safe and (2) that Safe's
/// signers execute `setGuard(<guard>)`. Apply the policy with the `curator-guard-sync` task BEFORE the
/// Safe installs the guard: an unconfigured Safe is in `Lockdown` and would be frozen on install.
/// See docs/curator-guard.md for the full runbook.
///
///   npx hardhat deploy --network ethereum --tags CuratorGuard
///   CURATOR_GUARD_ALIAS=CuratorGuard_v2 CURATOR_GUARD_TIMELOCK=0x... npx hardhat deploy --network ethereum --tags CuratorGuard
const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployments, getNamedAccounts, ethers } = hre;
  const { deployer } = await getNamedAccounts();
  if (!deployer) throw Error(`The 'deployer' named account wasn't set`);

  const vetro = Addresses.ethereum.Vetro;
  const proposers = dedupe((vetro.curatorGuardProposers || []).filter((p) => p && p !== ZERO));
  const council: string = vetro.curatorGuardCouncil ? ethers.getAddress(vetro.curatorGuardCouncil) : ZERO;
  const cancellers = dedupe((vetro.curatorGuardCancellers || []).filter((c) => c && c !== ZERO));
  const curatorSafe: string = ethers.getAddress(vetro.lagoonCuratorSafe);
  const forkLike = await isRehearsal(hre);
  // `rehearsalOnly` overrides never downgrade on a real network; the others do, loudly (review R7C-02).
  const refuse = (msg: string, override?: string, rehearsalOnly = false) => {
    const overridden = override !== undefined && process.env[override] === "1" && (forkLike || !rehearsalOnly);
    if (forkLike || overridden) {
      console.log(
        chalk.yellow(
          `WARNING${overridden && !forkLike ? ` (OVERRIDE ${override} ACTIVE ON A REAL NETWORK)` : ""}: ${msg}`,
        ),
      );
      return;
    }
    throw Error(
      `${msg}.${override ? ` (${override}=1 to override${rehearsalOnly ? ", on a rehearsal only" : ""})` : ""}`,
    );
  };
  // --- the build ---------------------------------------------------------------------------------
  // Before any preflight: the artifacts about to be deployed must be the reviewed build (a rehearsal of a changed
  // build warns, as every refusal does on a fork; a real network refuses, with no override: re-pin with a review).
  for (const [name, expected] of Object.entries(REVIEWED_RUNTIME_KECCAK)) {
    const stripped = stripMetadata((await hre.artifacts.readArtifact(name)).deployedBytecode);
    const actual = keccak256(`0x${stripped}`);
    if (actual !== expected)
      refuse(
        `${name}: the compiled artifact's stripped runtime (${stripped.length / 2} bytes) hashes to ${actual}, not the reviewed ` +
          `${expected}: this is not the audited build; re-pin it with a review (test/guards/G12a_BuildPin.t.sol and ` +
          `REVIEWED_RUNTIME_KECCAK in this script) before deploying`,
      );
    else
      console.log(
        chalk.green(
          `${name}: the artifact is the reviewed build (${actual.slice(0, 10)}…, ${stripped.length / 2} bytes)`,
        ),
      );
  }
  const active = OVERRIDES.filter((v) => process.env[v] === "1");
  if (active.length) {
    const realEffect = active.filter((v) => !REHEARSAL_ONLY.includes(v));
    console.log(
      chalk.yellow(
        `overrides in effect: ${active.join(", ")}` +
          (forkLike
            ? " (rehearsal: every refusal is a warning here anyway)"
            : realEffect.length
              ? ` (REAL NETWORK: ${realEffect.join(", ")} WILL downgrade refusals; the others are ignored here)`
              : " (real network: ignored, these are rehearsal-only)"),
      ),
    );
  }
  // This script lives in deploy/ethereum: it must only ever run against mainnet or a rehearsal of it.
  const chainId = Number(await hre.getChainId());
  if (chainId !== 1 && !forkLike)
    throw Error(`chain ${chainId} is not Ethereum mainnet and this is not a rehearsal: refusing`);

  // --- preflight: topology ---------------------------------------------------------------------
  if (!proposers.length) throw Error("Vetro.curatorGuardProposers is empty in helpers/address.ts");
  if (!cancellers.length)
    throw Error(
      "Vetro.curatorGuardCancellers is empty in helpers/address.ts: the timelock needs exactly one dedicated veto Safe (never a proposer)",
    );
  // The contract refuses a canceller that proposes (a compromised canceller-proposer would be an
  // unvetoed takeover); say it before spending gas.
  for (const c of cancellers) {
    if (proposers.some((p) => p.toLowerCase() === c.toLowerCase())) {
      throw Error(
        `canceller ${c} is also a proposer: the veto Safe must propose nothing (CuratorGuardTimelock refuses it; docs section 6)`,
      );
    }
  }
  if (council === ZERO) {
    refuse(
      "Vetro.curatorGuardCouncil is empty: no fast lane to lift a lockdown or open a short Bypass (48 h round trips)",
      "CURATOR_GUARD_ALLOW_NO_COUNCIL",
    );
  }
  // Every admin operation is scheduled by a proposer: a sole proposer Safe that installs this guard on
  // itself by mistake (Lockdown, cannot schedule) or loses its quorum leaves the guard unremovable,
  // unwidenable and its admin role untransferable for good (docs §7.6 step 5). Two proposer Safes.
  if (proposers.length < 2) {
    refuse(
      `only ${proposers.length} distinct timelock proposer configured: a frozen or quorum-less sole proposer wedges the guard permanently`,
      "CURATOR_GUARD_ALLOW_SINGLE_PROPOSER",
    );
  }
  // One canceller: with two, each can veto its own removal (review R6D-3).
  if (cancellers.length > 1) {
    refuse(
      `${cancellers.length} canceller Safes configured: a canceller can veto its own removal, so every canceller is a permanent veto; keep exactly one`,
      "CURATOR_GUARD_ALLOW_MULTIPLE_CANCELLERS",
      true,
    );
  }
  // The council must never cancel or propose: it could veto or schedule its own removal (V2-54, R6D-7).
  if (council !== ZERO && [...proposers, ...cancellers].some((a) => a.toLowerCase() === council.toLowerCase())) {
    throw Error(
      "the council must be neither a proposer nor a canceller of the timelock: it could veto or schedule its own removal",
    );
  }
  // Delays typed in the wrong unit: a 48-second timelock makes every widening executable at once; the
  // contract clamps `getMinDelay()` to [1 d, 30 d] and refuses a constructor value outside it.
  // A fresh timelock cannot be constructed below the floor (`DelayOutOfRange`); no override.
  if (TIMELOCK_DELAY < MIN_DELAY_FLOOR && !EXISTING_TIMELOCK) {
    throw Error(
      `CURATOR_GUARD_TIMELOCK_DELAY is ${TIMELOCK_DELAY}s (${human(TIMELOCK_DELAY)}): the contract refuses less than a day (the value is in seconds; 48 h = 172800)`,
    );
  }
  if (TIMELOCK_DELAY > MIN_DELAY_CAP)
    throw Error(
      `CURATOR_GUARD_TIMELOCK_DELAY ${TIMELOCK_DELAY}s (${human(TIMELOCK_DELAY)}) exceeds the contract cap of 30 days`,
    );
  if (ADMIN_DELAY > MAX_ADMIN_DELAY)
    throw Error(`CURATOR_GUARD_ADMIN_DELAY ${ADMIN_DELAY}s exceeds the contract cap of 30 days`);
  if (ADMIN_DELAY < TIMELOCK_DELAY + ADMIN_DELAY_MARGIN) {
    refuse(
      `admin delay ${ADMIN_DELAY}s is less than a day above the timelock delay ${TIMELOCK_DELAY}s: a cancelDefaultAdminTransfer scheduled when a hostile begin lands keeps ${ADMIN_DELAY > TIMELOCK_DELAY ? ADMIN_DELAY - TIMELOCK_DELAY : 0n}s before the acceptance opens, less than a signing round (set CURATOR_GUARD_ADMIN_DELAY at least a day above the timelock delay)`,
      "CURATOR_GUARD_ALLOW_SHORT_DELAY",
    );
  }
  // The guard's constructor probes EIP-1153 (a guard on a pre-Cancun chain would brick the first Safe
  // that installs it) and reverts without a reason: say it in words before spending gas. The probe is
  // `PUSH0 TLOAD POP STOP` run as creation code through eth_call.
  try {
    await ethers.provider.call({ data: "0x5f5c5000" });
  } catch (e: unknown) {
    throw Error(
      `This network has no EIP-1153 transient storage (pre-Cancun EVM, or the RPC refused the creation probe); CuratorGuard cannot run here: ${errorText(e)}`,
    );
  }

  // --- preflight: principals must be real multisigs -------------------------------------------
  // "Has code" is not "is a multisig": every proposer, the council and the canceller must answer as a
  // Safe with a threshold of at least 2 (review R6C-16); a read that fails is a refusal, not a pass.
  const principals: [string, string][] = [
    ...proposers.map((p) => ["proposer", p] as [string, string]),
    ...cancellers.map((c) => ["canceller", c] as [string, string]),
    ...(council !== ZERO ? [["council", council] as [string, string]] : []),
  ];
  for (const [label, who] of principals) {
    const code = await ethers.provider.getCode(who);
    if (isPlainAccount(code)) {
      // An EOA proposer or canceller is tolerated on fork rehearsals only (stand-ins); an EOA council never.
      if (forkLike && label !== "council")
        console.log(chalk.yellow(`WARNING (fork rehearsal only): ${label} ${who} is an EOA`));
      else throw Error(`${label} ${who} is an EOA: proposers, the council and the canceller must be multisigs`);
      continue;
    }
    const shape = await safeShape(hre, who);
    if (!shape) {
      refuse(
        `${label} ${who} has code but does not answer as a Safe (getOwners / getThreshold): governance principals must be Safes`,
        "CURATOR_GUARD_ALLOW_WEAK_GOVERNANCE",
        true,
      );
      continue;
    }
    if (shape.threshold < 2n)
      refuse(
        `${label} ${who} is a ${shape.threshold}-of-${shape.owners.length} Safe: governance Safes need a threshold of at least 2`,
        "CURATOR_GUARD_ALLOW_WEAK_GOVERNANCE",
        true,
      );
    if (shape.modules.length)
      console.log(
        chalk.yellow(
          `WARNING: ${label} ${who} has ${shape.modules.length} enabled module(s) (${shape.modules.join(", ")}): a module is a hidden signer of a governance Safe`,
        ),
      );
    // A Safe forwards every call it does not implement to its fallback handler, from ANYONE, with
    // itself as the caller: a governance Safe whose handler is a contract on which it holds rights (the
    // guard, the timelock) hands those rights to everyone (review R8Q-3). The contracts refuse such a
    // caller and the sync task names it on every run; here anything but zero or the canonical
    // handler is flagged before the role is granted.
    const handler = await safeFallbackHandler(hre, who);
    if (handler !== ZERO && !CANONICAL_SAFE_HANDLERS.has(handler.toLowerCase()))
      console.log(
        chalk.yellow(
          `WARNING: ${label} ${who} has a non-canonical fallback handler ${handler}: a handler receives every unknown call with the Safe as caller; it must never be the guard or the timelock`,
        ),
      );
  }
  const curatorShape = await safeShape(hre, curatorSafe);
  if (!curatorShape)
    refuse(
      `the curator Safe ${curatorSafe} does not answer as a Safe on this network`,
      "CURATOR_GUARD_ALLOW_WEAK_GOVERNANCE",
      true,
    );

  // --- preflight: signer overlap, pairwise ----------------------------------------------------------
  // (1) No curator key may reach a proposer, the council or the canceller (colluding curator keys would
  // control their own guard: docs section 12 P0-1). (2) The council may not own or share a quorum with
  // a proposer or the canceller: through such a Safe it would cancel or schedule its own removal
  // (review R6D-4). (3) Two proposers sharing signers only weaken liveness: a warning.
  const sets = new Map<string, Set<string>>();
  const signersOf = async (who: string) => {
    if (!sets.has(who)) sets.set(who, await signerSet(hre, who));
    return sets.get(who)!;
  };
  const curatorKeys = await signersOf(curatorSafe);
  for (const [label, who] of principals) {
    const overlap = [...(await signersOf(who))].filter((k) => curatorKeys.has(k));
    if (overlap.length) {
      const msg = `${label} ${who} shares ${overlap.length} signer(s) with the curator Safe ${curatorSafe}: ${overlap.join(", ")}`;
      if (process.env.CURATOR_GUARD_ALLOW_KEY_OVERLAP === "1" && forkLike)
        console.log(chalk.yellow(`WARNING (fork rehearsal only): ${msg}`));
      else
        throw Error(
          `${msg}. Refusing to deploy: colluding curator keys would control their own guard (section 12 P0-1).`,
        );
    }
  }
  if (council !== ZERO) {
    const councilKeys = await signersOf(council);
    for (const [label, who] of principals) {
      if (label === "council") continue;
      const keys = await signersOf(who);
      const overlap = [...keys].filter((k) => councilKeys.has(k) || k === council.toLowerCase());
      if (overlap.length) {
        throw Error(
          `${label} ${who} is owned by or shares ${overlap.length} signer(s) with the council ${council} (${overlap.join(", ")}): the council could cancel or schedule its own removal through it`,
        );
      }
    }
  }
  for (let i = 0; i < proposers.length; ++i) {
    for (let j = i + 1; j < proposers.length; ++j) {
      const a = await signersOf(proposers[i]);
      const overlap = [...(await signersOf(proposers[j]))].filter((k) => a.has(k));
      if (overlap.length)
        console.log(
          chalk.yellow(
            `WARNING: proposers ${proposers[i]} and ${proposers[j]} share ${overlap.length} signer(s): one lost or compromised key set weakens both`,
          ),
        );
    }
  }

  // --- timelock (admin of the guard) -----------------------------------------------------------
  // Roles are fixed by the constructor: proposers, cancellers, open executor, self-administered. No
  // deployer admin, nothing to renounce, nothing a deployer key could have granted meanwhile (R6D-6).
  const timelockArgs = [TIMELOCK_DELAY, proposers, cancellers] as const;
  let timelockAddress: string;
  if (EXISTING_TIMELOCK) {
    timelockAddress = ethers.getAddress(EXISTING_TIMELOCK);
    console.log(chalk.blue(`reusing timelock ${timelockAddress} (CURATOR_GUARD_TIMELOCK)`));
  } else if ((await deployments.getOrNull(ALIAS)) && !(await deployments.getOrNull(TIMELOCK_ALIAS))) {
    // A guard record without its timelock record (a re-run after a lost or uncommitted record, review G20g-2): the
    // recorded guard's admin IS its timelock. Deploying another here would be refused by the admin check below only
    // after the deploy was paid for, and would leave the record naming an orphan that holds the proposer roles.
    const recorded = (await deployments.get(ALIAS)).address;
    timelockAddress = ethers.getAddress(await (await ethers.getContractAt(CONTRACT, recorded)).defaultAdmin());
    console.log(
      chalk.blue(
        `${TIMELOCK_ALIAS} record missing: using the admin of the recorded ${ALIAS} ${recorded}, ${timelockAddress} ` +
          `(CURATOR_GUARD_TIMELOCK overrides; restore the record from the chain and commit both)`,
      ),
    );
  } else {
    const timelock = await deployments.deploy(TIMELOCK_ALIAS, {
      contract: TIMELOCK_CONTRACT,
      from: deployer,
      args: [...timelockArgs],
      log: true,
      skipIfAlreadyDeployed: true,
    });
    timelockAddress = timelock.address;
    console.log(
      timelock.newlyDeployed
        ? chalk.green(
            `${TIMELOCK_ALIAS} deployed at ${timelockAddress} (delay ${TIMELOCK_DELAY}s = ${human(TIMELOCK_DELAY)}, proposers ${proposers.join(", ")}, canceller ${cancellers.join(", ")})`,
          )
        : chalk.blue(`${TIMELOCK_ALIAS} already deployed at ${timelockAddress}`),
    );
  }
  // Audited, never trusted: a reused or previously deployed timelock must be this build, in range, and
  // hold exactly the expected roles (review R6C-02).
  const tl = (await ethers.getContractAt(TIMELOCK_CONTRACT, timelockAddress)) as unknown as Contract;
  const artifact = await hre.artifacts.readArtifact(TIMELOCK_CONTRACT);
  if (stripMetadata(await ethers.provider.getCode(timelockAddress)) !== stripMetadata(artifact.deployedBytecode)) {
    throw Error(
      `the code at ${timelockAddress} is not this repository's ${TIMELOCK_CONTRACT} build: refusing to put a guard behind it`,
    );
  }
  const liveMinDelay: bigint = await tl.getMinDelay();
  if (liveMinDelay !== TIMELOCK_DELAY) {
    refuse(
      `timelock ${timelockAddress} has minDelay ${liveMinDelay}s (${human(liveMinDelay)}), not the configured ${TIMELOCK_DELAY}s`,
      "CURATOR_GUARD_ALLOW_SHORT_DELAY",
    );
  }
  if (ADMIN_DELAY < liveMinDelay + ADMIN_DELAY_MARGIN)
    refuse(
      `admin delay ${ADMIN_DELAY}s is less than a day above the live timelock delay ${liveMinDelay}s: a cancelDefaultAdminTransfer scheduled when a hostile begin lands keeps ${ADMIN_DELAY > liveMinDelay ? ADMIN_DELAY - liveMinDelay : 0n}s before the acceptance opens`,
      "CURATOR_GUARD_ALLOW_SHORT_DELAY",
    );
  await auditTimelock(hre, tl, timelockAddress, proposers, cancellers, council, forkLike);

  // --- guard -----------------------------------------------------------------------------------
  // Immutable contract: never redeploy on bytecode/metadata drift (hardhat-deploy would otherwise mint
  // a second, unconfigured guard and repoint the artifact away from the one the Safe installed).
  // A replacement guard (docs/curator-guard.md section 7.5) is a new, versioned alias.
  const guardArgs = [ADMIN_DELAY, timelockAddress, council];
  // A lost or uncommitted guard record (review G22c-4): `skipIfAlreadyDeployed` sees no record and mints a second guard
  // behind the same timelock, then repoints the record at it. Two cheap reads catch the common cases before any gas
  // is spent: the curator Safe's guard slot (an installed guard), and the timelock's queue (a synced, not yet installed
  // guard: every sync targets the guard). Both are read for this repository's build with this timelock as admin.
  if (!(await deployments.getOrNull(ALIAS))) await refuseIfGuardExists(hre, timelockAddress, curatorSafe, forkLike);
  const result = await deployments.deploy(ALIAS, {
    contract: CONTRACT,
    from: deployer,
    args: guardArgs,
    log: true,
    skipIfAlreadyDeployed: true,
  });
  console.log(
    result.newlyDeployed
      ? chalk.green(`${ALIAS} deployed at ${result.address} (admin ${timelockAddress}, council ${council})`)
      : chalk.blue(`${ALIAS} already deployed at ${result.address}`),
  );
  const guard = await ethers.getContractAt(CONTRACT, result.address);
  if ((await guard.defaultAdmin()).toLowerCase() !== timelockAddress.toLowerCase()) {
    throw Error(`${ALIAS} admin is ${await guard.defaultAdmin()}, expected the timelock ${timelockAddress}`);
  }
  if (result.newlyDeployed) {
    console.log(
      chalk.blue(
        `next: pin the guard in the policy file before any sync (the task refuses an unpinned file outside rehearsals):\n` +
          `  "guard": "${result.address}",`,
      ),
    );
  }
  // `skipIfAlreadyDeployed` ignores changed constructor arguments: a council configured after the first
  // deploy is NOT granted. Say so, with the scheduled operation that grants it.
  if (council !== ZERO && !(await guard.hasRole(await guard.COUNCIL_ROLE(), council))) {
    const data = guard.interface.encodeFunctionData("grantRole", [await guard.COUNCIL_ROLE(), council]);
    console.log(
      chalk.yellow(
        `WARNING: ${council} does not hold COUNCIL_ROLE on ${result.address} (guard deployed earlier). Schedule on the timelock from a proposer: target ${result.address} data ${data}`,
      ),
    );
  }
  const liveAdminDelay: bigint = await guard.defaultAdminDelay();
  if (liveAdminDelay !== ADMIN_DELAY)
    console.log(
      chalk.yellow(`WARNING: ${ALIAS} has admin delay ${liveAdminDelay}s, not the configured ${ADMIN_DELAY}s`),
    );

  if (!forkLike) {
    const toVerify: [string, readonly unknown[]][] = [[result.address, guardArgs]];
    if (!EXISTING_TIMELOCK) toVerify.unshift([timelockAddress, [...timelockArgs]]);
    for (const [address, constructorArguments] of toVerify) {
      try {
        await hre.run("verify:verify", { address, constructorArguments });
      } catch (e: unknown) {
        const msg = errorText(e);
        if (/already verified/i.test(msg)) console.log(chalk.blue(`${address} already verified.`));
        else {
          console.log(
            chalk.red(`VERIFICATION FAILED for ${address}; the deployment stands, verify by hand. Reason: ${msg}`),
          );
          process.exitCode = 1;
        }
      }
    }
  }
};

/// A guard of this build with `timelock` as its admin is already installed on the curator Safe, or is the target of an
/// operation this timelock has scheduled: a deploy without its record would mint a second one (review G22c-4).
async function refuseIfGuardExists(
  hre: HardhatRuntimeEnvironment,
  timelock: string,
  curatorSafe: string,
  forkLike: boolean,
): Promise<void> {
  const { ethers } = hre;
  const artifact = await hre.artifacts.readArtifact(CONTRACT);
  const expected = stripMetadata(artifact.deployedBytecode);
  const isOurs = async (candidate: string): Promise<boolean> => {
    if (!/^0x[0-9a-fA-F]{40}$/.test(candidate) || candidate === ZERO) return false;
    if (stripMetadata(await ethers.provider.getCode(candidate)) !== expected) return false;
    try {
      const admin: string = await (await ethers.getContractAt(CONTRACT, candidate)).defaultAdmin();
      return admin.toLowerCase() === timelock.toLowerCase();
    } catch {
      return false;
    }
  };
  const found = new Set<string>();
  const safe = await hre.ethers.getContractAt("ISafe", curatorSafe);
  try {
    const raw: string = await safe.getStorageAt(
      "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8",
      1,
    );
    const slot = ethers.getAddress("0x" + raw.slice(-40));
    if (await isOurs(slot)) found.add(slot);
  } catch {
    /* not a Safe that answers getStorageAt: nothing installed to read */
  }
  const from = await creationBlock(hre, timelock);
  if (from !== undefined) {
    const tl = (await ethers.getContractAt(TIMELOCK_CONTRACT, timelock)) as unknown as Contract;
    const targets = new Set<string>();
    for (const l of await scanLogs(hre, tl, tl.filters.CallScheduled(), from))
      targets.add(String((l as EventLog).args.target));
    for (const t of targets) if (await isOurs(t)) found.add(ethers.getAddress(t));
  }
  if (!found.size) return;
  const msg =
    `${ALIAS} has no deployment record here, but ${[...found].join(", ")} is this build with ${timelock} as its admin ` +
    `(installed on the curator Safe, or the target of a scheduled operation): a deploy now would mint a second guard and ` +
    `repoint the record; restore deployments/<network>/${ALIAS}.json from the chain and commit it (CURATOR_GUARD_ALIAS=... for a replacement guard)`;
  if (forkLike) console.log(chalk.yellow(`WARNING: ${msg}`));
  else throw Error(msg);
}

/// Rebuilds the timelock's role set from its own `RoleGranted` / `RoleRevoked` logs (roles are not
/// enumerable) and compares it with the expected topology: admin = the timelock only, executor = anyone
/// only, proposers and cancellers exactly as configured, the council nowhere; and the queue empty.
async function auditTimelock(
  hre: HardhatRuntimeEnvironment,
  tl: Contract,
  address: string,
  proposers: string[],
  cancellers: string[],
  council: string,
  forkLike: boolean,
): Promise<void> {
  const roles: [string, string][] = [
    ["DEFAULT_ADMIN_ROLE", await tl.DEFAULT_ADMIN_ROLE()],
    ["PROPOSER_ROLE", await tl.PROPOSER_ROLE()],
    ["CANCELLER_ROLE", await tl.CANCELLER_ROLE()],
    ["EXECUTOR_ROLE", await tl.EXECUTOR_ROLE()],
  ];
  const expected = new Map<string, Set<string>>([
    ["DEFAULT_ADMIN_ROLE", new Set([address.toLowerCase()])],
    ["PROPOSER_ROLE", new Set(proposers.map((p) => p.toLowerCase()))],
    ["CANCELLER_ROLE", new Set(cancellers.map((c) => c.toLowerCase()))],
    ["EXECUTOR_ROLE", new Set([ZERO])],
  ]);
  const from = await creationBlock(hre, address);
  const problems: string[] = [];
  if (from === undefined) {
    problems.push(
      `the creation block of ${address} is unknown (no deployment record; set CURATOR_GUARD_TIMELOCK_BLOCK): the role set cannot be rebuilt from logs`,
    );
  } else {
    for (const [name, role] of roles) {
      const seen = new Set<string>();
      for (const l of await scanLogs(hre, tl, tl.filters.RoleGranted(role), from))
        seen.add(String((l as EventLog).args.account).toLowerCase());
      const live = new Set<string>();
      for (const a of seen) if (await tl.hasRole(role, a)) live.add(a);
      const want = expected.get(name)!;
      const extra = [...live].filter((a) => !want.has(a));
      const missing = [...want].filter((a) => !live.has(a));
      if (extra.length) problems.push(`${name}: unexpected holder(s) ${extra.join(", ")}`);
      for (const m of missing) {
        // Held but not in the scanned logs: the scan started after the grant (wrong creation block),
        // which hides every OTHER holder too; held by nobody: a genuine gap.
        if (await tl.hasRole(role, m))
          problems.push(
            `${name}: ${m} holds the role but no RoleGranted log was found from block ${from}: the scan starts after the grant (pass the timelock's creation block), so other holders may be hidden`,
          );
        else problems.push(`${name}: missing holder ${m}`);
      }
    }
    // One CallScheduled log per CALL of an operation: counted by log, a single 40-call sync read as "40 operation(s)"
    // (review G22c-2). Count operation ids.
    const ids = new Set<string>();
    for (const l of await scanLogs(hre, tl, tl.filters.CallScheduled(), from)) ids.add(String((l as EventLog).args.id));
    let pending = 0;
    for (const id of ids) if (await tl.isOperationPending(id)) ++pending;
    if (pending)
      problems.push(
        `${pending} operation(s) are pending in the queue (any target); review and cancel them before a guard goes behind this timelock`,
      );
  }
  if (council !== ZERO) {
    for (const [name, role] of roles) {
      if (name !== "DEFAULT_ADMIN_ROLE" && (await tl.hasRole(role, council)))
        problems.push(`the council ${council} holds ${name}`);
    }
  }
  if (!problems.length) {
    console.log(chalk.green(`timelock ${address} audited: roles as configured, council without roles, queue empty`));
    return;
  }
  const msg = `timelock ${address} does not match the expected topology:\n  - ${problems.join("\n  - ")}`;
  if (forkLike) console.log(chalk.yellow(`WARNING: ${msg}`));
  else throw Error(msg);
}

async function creationBlock(hre: HardhatRuntimeEnvironment, address: string): Promise<number | undefined> {
  const explicit = process.env.CURATOR_GUARD_TIMELOCK_BLOCK;
  if (explicit) {
    // Validated as the sync task does: `Number("abc")` is NaN, every scan is then empty and the audit
    // reports every expected holder as "held without a log" (review G11e-3).
    if (!/^\d+$/.test(explicit)) throw Error(`CURATOR_GUARD_TIMELOCK_BLOCK must be a block number, got ${explicit}`);
    const head = await hre.ethers.provider.getBlockNumber();
    if (Number(explicit) > head)
      throw Error(`CURATOR_GUARD_TIMELOCK_BLOCK ${explicit} is after the chain head ${head}`);
    return Number(explicit);
  }
  const d = Object.values(await hre.deployments.all()).find((x) => x.address.toLowerCase() === address.toLowerCase());
  if (d?.receipt?.blockNumber !== undefined) return Number(d.receipt.blockNumber);
  return undefined;
}

async function scanLogs(
  hre: HardhatRuntimeEnvironment,
  contract: Contract,
  filter: Parameters<Contract["queryFilter"]>[0],
  from: number,
) {
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

/// Seconds as `Xd Yh Zm Ws`, so a delay typed in the wrong unit is visible at a glance.
function human(seconds: bigint): string {
  const d = seconds / 86400n;
  const h = (seconds % 86400n) / 3600n;
  const m = (seconds % 3600n) / 60n;
  const s = seconds % 60n;
  return [d && `${d}d`, h && `${h}h`, m && `${m}m`, (s || seconds === 0n) && `${s}s`].filter(Boolean).join(" ");
}

const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

/// Distinct checksummed addresses (the same Safe twice, in any casing, is one proposer).
function dedupe(list: string[]): string[] {
  const out: string[] = [];
  for (const a of list) {
    const c = getAddress(a);
    if (!out.includes(c)) out.push(c);
  }
  return out;
}

/// Runtime code without its CBOR metadata tail.
function stripMetadata(code: string): string {
  const hex = (code.startsWith("0x") ? code.slice(2) : code).toLowerCase();
  if (hex.length < 4) return hex;
  const total = (parseInt(hex.slice(-4), 16) + 2) * 2;
  return total < hex.length ? hex.slice(0, hex.length - total) : hex;
}

/// An account without code, or an EIP-7702 delegated EOA (code `0xef0100 || delegate`): a single key,
/// whatever it delegates to today.
function isPlainAccount(code: string): boolean {
  return code === "0x" || code.toLowerCase().startsWith("0xef0100");
}

// Canonical `CompatibilityFallbackHandler` deployments (v1.3.0 canonical and eip155, v1.4.1, v1.5.0).
const CANONICAL_SAFE_HANDLERS = new Set([
  "0xf48f2b2d2a534e402487b3ee7c18c33aec0fe5e4",
  "0x017062a1de2fe6b99be3d9d37841fed19f573804",
  "0xfd0732dc9e303f09fcef3a7388ad10a83459ec99",
  "0x3efcbb83a4a7afcb4f68d501e2c2203a38be77f4",
]);

/// The fallback handler of a Safe (`keccak256("fallback_manager.handler.address")`, read through its
/// own `getStorageAt`).
async function safeFallbackHandler(hre: HardhatRuntimeEnvironment, account: string): Promise<string> {
  const safe = await hre.ethers.getContractAt("ISafe", account);
  const raw: string = await safe.getStorageAt("0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5", 1);
  return hre.ethers.getAddress("0x" + raw.slice(-40));
}

/// Owners, threshold and modules of a Safe; `undefined` when the account does not answer as one (an
/// EVM-level answer); a transport error is thrown, never read as "not a Safe".
async function safeShape(
  hre: HardhatRuntimeEnvironment,
  account: string,
): Promise<{ owners: string[]; threshold: bigint; modules: string[] } | undefined> {
  const safe = await hre.ethers.getContractAt("ISafe", account);
  try {
    const owners: string[] = await safe.getOwners();
    const threshold: bigint = await safe.getThreshold();
    if (!owners.length || threshold === 0n) return undefined;
    let modules: string[] = [];
    try {
      [modules] = await safe.getModulesPaginated("0x0000000000000000000000000000000000000001", 10);
    } catch {
      /* v1.3.0 and older answer the same way; a failure here is not a verdict on the Safe */
    }
    return { owners, threshold, modules };
  } catch (e: unknown) {
    const code = (e as { code?: string }).code;
    const message = errorText(e);
    if (code === "CALL_EXCEPTION" || code === "BAD_DATA" || /revert|could not decode result data/i.test(message))
      return undefined;
    throw Error(`could not read ${account} as a Safe (${message}): refusing to judge governance on a failed read`);
  }
}

/// A rehearsal is a dev node (RPC probe) that ALSO reports chain 31337 or is declared with
/// CURATOR_GUARD_FORK=1 (an anvil fork keeps the forked chain id). The RPC endpoint alone must not be
/// able to downgrade the refusals above to warnings on a real network.
async function isRehearsal(hre: HardhatRuntimeEnvironment): Promise<boolean> {
  if (!(await isForkNode(hre))) return false;
  const chainId = Number(await hre.getChainId());
  if (chainId === 31337 || process.env.CURATOR_GUARD_FORK === "1") return true;
  console.log(
    chalk.yellow(
      `NOTE: the RPC answers like a dev node but reports chain ${chainId}: treated as a REAL network (set CURATOR_GUARD_FORK=1 for an anvil-fork rehearsal)`,
    ),
  );
  return false;
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

/// Signers that can act for `account`: the account itself when it is a plain account, otherwise its
/// Safe owners, expanded recursively through nested Safes. Fails closed: a read that does not answer as
/// a Safe for an account WITH code counts the contract as a single principal only when the EVM said so
/// (review R6C-03); nesting deeper than 3 is refused rather than cut off.
async function signerSet(hre: HardhatRuntimeEnvironment, account: string, depth = 0): Promise<Set<string>> {
  const { ethers } = hre;
  const out = new Set<string>();
  const addr = ethers.getAddress(account);
  if (isPlainAccount(await ethers.provider.getCode(addr))) {
    out.add(addr.toLowerCase());
    return out;
  }
  if (depth > 3) throw Error(`${addr}: Safes nested deeper than 3 levels: refusing to judge the signer overlap`);
  const shape = await safeShape(hre, addr);
  if (!shape) {
    out.add(addr.toLowerCase()); // a contract without `getOwners()`: a single principal
    return out;
  }
  for (const o of shape.owners) for (const k of await signerSet(hre, o, depth + 1)) out.add(k);
  return out;
}

func.tags = [CONTRACT];
export default func;
