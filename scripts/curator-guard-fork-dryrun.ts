import fs from "fs";
import os from "os";
import path from "path";
import hre from "hardhat";
import Addresses from "../helpers/address";

/// Fork dry run of the CuratorGuard v2 tooling on the PRODUCTION topology (timelock admin):
///   1. deploy the timelock + guard (the key-overlap preflight is downgraded to a warning on the fork,
///      because today's governance Safe shares signers with the curator Safe);
///   2. schedule the Vetro Lagoon policy through the timelock as the proposer Safe (impersonated);
///   3. warp past `minDelay`, execute the batch, re-sync and expect no drift;
///   4. install the guard on the live curator Safe (handler removal + setGuard, impersonated) and
///      dry-run representative curator calls through `validateTransaction`;
///   5. incident drill: the council locks the Safe down, a lift is scheduled as its own chained
///      operation, `curator-guard-verify` decodes it from the logs, the cooldown holds it back, then it
///      executes.
///
///   FORK_NODE_URL=<mainnet rpc or local anvil fork> npx hardhat run scripts/curator-guard-fork-dryrun.ts --network hardhat
///
/// Against a non-archive upstream (e.g. a local anvil fork backed by a free public RPC) also set
/// FORK_BLOCK_NUMBER to the upstream head, otherwise hardhat forks `latest - 32` and storage reads fail.
/// The run declares itself a rehearsal (CURATOR_GUARD_FORK=1) when the node answers dev methods, so
/// an in-process fork that reports chain id 1 is treated as the rehearsal it is.

const SAFE: string = Addresses.ethereum.Vetro.lagoonCuratorSafe;
const PROPOSER: string = Addresses.ethereum.Vetro.curatorGuardProposers[0];
const VAULT_USDC: string = Addresses.ethereum.Lagoon.vault.Vetro_USDC;
const USDC: string = Addresses.ethereum.USDC;
const POLICY = path.join(__dirname, "..", "policies", "curator-guard", "vetro-lagoon.ethereum.json");

async function main() {
  if (!process.env.FORK_NODE_URL)
    throw Error("FORK_NODE_URL is required: this is a fork rehearsal, never the in-memory chain");
  let dev = false;
  for (const method of ["hardhat_metadata", "anvil_nodeInfo"]) {
    try {
      await hre.network.provider.send(method, []);
      dev = true;
    } catch {
      /* not that kind of node */
    }
  }
  if (!dev) throw Error("the node does not answer dev-node methods: refusing to rehearse against a real network");
  // A failing upstream read inside a transaction makes hardhat's EDR panic and the process exit 0
  // without reaching `catch` (review R7C-01): the exit code is set to failure now and cleared only by
  // the last line of the drill, so a silent stop is never a green run.
  process.exitCode = 1;
  process.env.CURATOR_GUARD_FORK = "1";
  process.env.CURATOR_GUARD_ALLOW_KEY_OVERLAP = "1";
  // No veto Safe in the address book yet: a stand-in key (never a proposer) cancels on this fork.
  if (!Addresses.ethereum.Vetro.curatorGuardCancellers.length) {
    Addresses.ethereum.Vetro.curatorGuardCancellers = [
      hre.ethers.getAddress("0xce70000000000000000000000000000000000ce7"),
    ];
  }
  await hre.run("deploy", { tags: "CuratorGuard" });
  const d = await hre.deployments.get("CuratorGuard");
  const t = await hre.deployments.get("CuratorGuardTimelock");
  const guard = await hre.ethers.getContractAt("CuratorGuard", d.address);
  const timelock = await hre.ethers.getContractAt("CuratorGuardTimelock", t.address);
  console.log(
    "guard:",
    d.address,
    "admin (timelock):",
    await guard.defaultAdmin(),
    "owner() view:",
    await guard.owner(),
  );
  if ((await guard.defaultAdmin()).toLowerCase() !== t.address.toLowerCase()) throw Error("admin is not the timelock");
  // The committed file is pinned to the PRODUCTION guard from section 7.2 step 0 on, and the task
  // refuses a pin that differs from `--guard` on every network. This rehearsal deploys a fresh guard,
  // so it syncs a copy of the file pinned to that guard; everything else in the file is unchanged
  // (review G11a-1).
  const committed = JSON.parse(fs.readFileSync(POLICY, "utf8")) as Record<string, unknown>;
  // A per-run directory: the shared temp directory of a multi-session host must never let one rehearsal's copy
  // be deleted or overwritten by another's (review G16g-3).
  const POLICY_RUN = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), "curator-guard-fork-dryrun-")),
    `policy.${d.address.toLowerCase()}.json`,
  );
  fs.writeFileSync(POLICY_RUN, JSON.stringify({ ...committed, guard: d.address }, null, 2));
  console.log("policy copy for this rehearsal (pinned to the fresh guard):", POLICY_RUN);

  // Every sync here passes `allowUnconstrainedNav`: the live vaults hold dust (about 1 USDC), which the
  // unconstrained-NAV gate refuses on mainnet until a band is set or the flag is given knowingly.
  console.log("--- dry run ---");
  await hre.run("curator-guard-sync", {
    allowUnconstrainedNav: true,
    guard: d.address,
    policy: POLICY_RUN,
    dryRun: true,
  });
  console.log("--- schedule through the timelock (proposer impersonated) ---");
  await hre.run("curator-guard-sync", {
    allowUnconstrainedNav: true,
    guard: d.address,
    policy: POLICY_RUN,
    viaTimelock: true,
    proposer: PROPOSER,
  });
  if ((await guard.targets(SAFE)).length !== 0) throw Error("policy applied before the delay elapsed");
  console.log("--- execute too early must fail ---");
  let earlyFailed = false;
  try {
    await hre.run("curator-guard-sync", {
      allowUnconstrainedNav: true,
      guard: d.address,
      policy: POLICY_RUN,
      execute: true,
    });
  } catch (e: unknown) {
    earlyFailed = true;
    console.log("early execute refused:", (e instanceof Error ? e.message : String(e)).slice(0, 120));
  }
  if (!earlyFailed) throw Error("BUG: the batch executed before minDelay");
  const minDelay = Number(await timelock.getMinDelay());
  await hre.network.provider.send("evm_increaseTime", [minDelay + 1]);
  await hre.network.provider.send("evm_mine", []);
  console.log(`--- warped ${minDelay + 1}s; execute ---`);
  await hre.run("curator-guard-sync", {
    allowUnconstrainedNav: true,
    guard: d.address,
    policy: POLICY_RUN,
    execute: true,
  });
  console.log("--- re-run (expect: already in sync) ---");
  await hre.run("curator-guard-sync", {
    allowUnconstrainedNav: true,
    guard: d.address,
    policy: POLICY_RUN,
    dryRun: true,
  });
  if ((await guard.targets(SAFE)).length === 0) throw Error("policy not applied");
  console.log(
    "mode:",
    await guard.mode(SAFE),
    "targets:",
    (await guard.targets(SAFE)).length,
    "guardians:",
    await guard.guardians(SAFE),
  );

  // The NAV gate on a band that only looks like one (review G13a-1): on a vault that holds anything, a
  // band the live totalAssets() does not sit in, or one wider than +-50 % of it, is refused at its first
  // sync like an unconstrained mark; the flag admits it knowingly. The settles carry the mark's band
  // (the validator demands the repetition).
  console.log("--- band gate: a band on paper is refused at its first sync ---");
  type PolicyFn = { target: string; signature: string; rules?: unknown[]; [k: string]: unknown };
  const policyRun = JSON.parse(fs.readFileSync(POLICY_RUN, "utf8")) as { functions: PolicyFn[] };
  const vaultAbi = ["function totalAssets() view returns (uint256)"];
  let dusty: { target: string; assets: bigint } | undefined;
  for (const f of policyRun.functions) {
    if (f.signature !== "updateNewTotalAssets(uint256)") continue;
    const assets: bigint = await new hre.ethers.Contract(f.target, vaultAbi, hre.ethers.provider).totalAssets();
    if (assets > 0n) {
      dusty = { target: f.target, assets };
      break;
    }
  }
  if (!dusty) {
    console.log("no vault holds assets on this fork: the band gate has nothing to refuse (step skipped)");
  } else {
    const dustyTarget = dusty.target;
    const banded = (lo: bigint, hi: bigint) => ({
      ...policyRun,
      functions: policyRun.functions.map((f) =>
        f.target === dustyTarget &&
        ["updateNewTotalAssets(uint256)", "settleDeposit(uint256)", "settleRedeem(uint256)"].includes(f.signature)
          ? {
              target: f.target,
              signature: f.signature,
              rules: [
                { kind: "GreaterThanOrEqual", wordIndex: 0, value: lo.toString() },
                { kind: "LessThanOrEqual", wordIndex: 0, value: hi.toString() },
              ],
            }
          : f,
      ),
    });
    for (const [label, lo, hi, expect] of [
      ["wider than the NAV", 1n, (1n << 256n) - 2n, "wider than +-50 %"],
      ["away from the NAV", dusty.assets * 2n + 1n, dusty.assets * 3n + 1n, "does not contain"],
    ] as const) {
      const file = `${POLICY_RUN}.${label.replace(/ /g, "-")}.json`;
      fs.writeFileSync(file, JSON.stringify(banded(lo, hi), null, 2));
      let refusedBand = false;
      try {
        await hre.run("curator-guard-sync", { guard: d.address, policy: file, dryRun: true });
      } catch (e: unknown) {
        const m = e instanceof Error ? e.message : String(e);
        refusedBand = m.includes(expect);
        console.log(`band ${label} refused:`, m.slice(0, 140));
      }
      if (!refusedBand) throw Error(`BUG: a band ${label} was not refused at its first sync (expected "${expect}")`);
      await hre.run("curator-guard-sync", {
        allowUnconstrainedNav: true,
        guard: d.address,
        policy: file,
        dryRun: true,
      });
      console.log(`band ${label} admitted with --allow-unconstrained-nav (dry run)`);
      fs.unlinkSync(file);
    }
  }

  // Install step the signers execute on mainnet (approved self-calls): drop the EIP-1271 capable
  // fallback handler, then install the guard. Impersonate the Safe for the fork.
  await hre.network.provider.send("hardhat_impersonateAccount", [SAFE]);
  await hre.network.provider.send("hardhat_setBalance", [SAFE, "0x3635C9ADC5DEA00000"]);
  const safeSigner = await hre.ethers.getSigner(SAFE);
  const safeIface = new hre.ethers.Interface(["function setFallbackHandler(address)", "function setGuard(address)"]);
  await (
    await safeSigner.sendTransaction({
      to: SAFE,
      data: safeIface.encodeFunctionData("setFallbackHandler", [hre.ethers.ZeroAddress]),
    })
  ).wait();
  await (
    await safeSigner.sendTransaction({ to: SAFE, data: safeIface.encodeFunctionData("setGuard", [d.address]) })
  ).wait();
  console.log("fallback handler removed and guard installed on", SAFE);

  const iface = new hre.ethers.Interface([
    "function settleDeposit(uint256)",
    "function transfer(address,uint256)",
    "function approve(address,uint256)",
  ]);
  await guard.validateTransaction(SAFE, VAULT_USDC, 0, iface.encodeFunctionData("settleDeposit", [0]), 0);
  console.log("validate settleDeposit: allowed");
  await guard.validateTransaction(SAFE, USDC, 0, iface.encodeFunctionData("approve", [VAULT_USDC, 1]), 0);
  console.log("validate approve(vault): allowed");
  for (const [label, to, data] of [
    ["transfer(dead)", USDC, iface.encodeFunctionData("transfer", ["0x000000000000000000000000000000000000dEaD", 1])],
    ["approve(dead)", USDC, iface.encodeFunctionData("approve", ["0x000000000000000000000000000000000000dEaD", 1])],
  ] as const) {
    try {
      await guard.validateTransaction(SAFE, to, 0, data, 0);
      console.log(`BUG: ${label} allowed`);
      process.exitCode = 1;
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      console.log(
        `validate ${label}: blocked (${msg.match(/reverted with custom error '([^']*)'/)?.[1] ?? msg.slice(0, 60)})`,
      );
    }
  }

  // --- incident drill: lockdown by the council, lift as a chained operation --------------------
  console.log("--- incident drill ---");
  // No council in the address book yet: a stand-in key (never the proposer, which holds a timelock role
  // the sync task refuses on a council) is granted the role through the timelock, as a rotation would be.
  const council: string =
    Addresses.ethereum.Vetro.curatorGuardCouncil || hre.ethers.getAddress("0xc0c1000000000000000000000000000000000c01");
  const guardAsCouncil = await hre.ethers.getContractAt("CuratorGuard", d.address, await impersonate(council));
  if (!(await guard.hasRole(await guard.COUNCIL_ROLE(), council))) {
    // Grant the stand-in council through the timelock (one scheduled op), as a real rotation would.
    const grant = guard.interface.encodeFunctionData("grantRole", [await guard.COUNCIL_ROLE(), council]);
    const proposer = await impersonate(PROPOSER);
    await (
      await timelock.connect(proposer).getFunction("schedule")(
        d.address,
        0,
        grant,
        hre.ethers.ZeroHash,
        hre.ethers.id("drill"),
        minDelay,
      )
    ).wait();
    await hre.network.provider.send("evm_increaseTime", [minDelay + 1]);
    await hre.network.provider.send("evm_mine", []);
    await (
      await timelock.getFunction("execute")(d.address, 0, grant, hre.ethers.ZeroHash, hre.ethers.id("drill"))
    ).wait();
  }
  await (await guardAsCouncil.lockdown(SAFE)).wait();
  console.log("council locked the Safe down; mode:", await guard.mode(SAFE));
  let refused = false;
  try {
    await hre.run("curator-guard-sync", {
      allowUnconstrainedNav: true,
      guard: d.address,
      policy: POLICY_RUN,
      viaTimelock: true,
      proposer: PROPOSER,
    });
  } catch (e: unknown) {
    refused = true;
    console.log("sync without --allow-unlock refused:", (e instanceof Error ? e.message : String(e)).slice(0, 100));
  }
  if (!refused) throw Error("BUG: a routine sync lifted a lockdown");
  await hre.run("curator-guard-sync", {
    allowUnconstrainedNav: true,
    guard: d.address,
    policy: POLICY_RUN,
    viaTimelock: true,
    proposer: PROPOSER,
    allowUnlock: true,
  });
  const stateFile = `safe.batch.tmp.json.timelock.${await hre.getChainId()}.${d.address.toLowerCase()}.json`;
  const stored = JSON.parse(fs.readFileSync(stateFile, "utf8")) as {
    operations: { opId: string; lifts: boolean; predecessor: string }[];
  };
  const lift = stored.operations.find((o) => o.lifts);
  if (!lift) throw Error("BUG: no lift operation scheduled");
  if (stored.operations.length !== 1)
    throw Error(`expected the lift alone (nothing else to change), got ${stored.operations.length} operations`);
  console.log("--- verify the queued lift from the logs ---");
  await hre.run("curator-guard-verify", { guard: d.address, policy: POLICY_RUN, op: lift.opId });
  // A re-lock by the council one hour before the delay ends: the lift is held back by the cooldown.
  await hre.network.provider.send("evm_increaseTime", [minDelay - 3600]);
  await hre.network.provider.send("evm_mine", []);
  await (await guardAsCouncil.lockdown(SAFE)).wait();
  await hre.network.provider.send("evm_increaseTime", [3601]);
  await hre.network.provider.send("evm_mine", []);
  console.log("--- execute: a NEW lockdown after scheduling must be refused without --allow-unlock ---");
  let held = false;
  try {
    await hre.run("curator-guard-sync", {
      allowUnconstrainedNav: true,
      guard: d.address,
      policy: POLICY_RUN,
      execute: true,
    });
  } catch (e: unknown) {
    held = true;
    console.log("execute refused:", (e instanceof Error ? e.message : String(e)).slice(0, 100));
  }
  if (!held) throw Error("BUG: a lift executed over a newer lockdown without --allow-unlock");
  console.log("--- execute with --allow-unlock: held back by the cooldown, then lands ---");
  await hre.run("curator-guard-sync", {
    allowUnconstrainedNav: true,
    guard: d.address,
    policy: POLICY_RUN,
    execute: true,
    allowUnlock: true,
  });
  if (Number(await guard.mode(SAFE)) !== 0) throw Error("BUG: the lift executed inside the cooldown");
  await hre.network.provider.send("evm_increaseTime", [86_400]);
  await hre.network.provider.send("evm_mine", []);
  await hre.run("curator-guard-sync", {
    allowUnconstrainedNav: true,
    guard: d.address,
    policy: POLICY_RUN,
    execute: true,
    allowUnlock: true,
  });
  if (Number(await guard.mode(SAFE)) !== 1) throw Error("BUG: the lift did not land after the cooldown");
  if (fs.existsSync(stateFile)) throw Error("BUG: state file left behind after a complete execution");
  if (fs.existsSync(`${stateFile}.manifest.json`)) throw Error("BUG: manifest left behind after a complete execution");
  // --- a hostile proposer value in the queue (review G17b-1; pinned in the drill at review G18g-6's request) ---
  // One scheduled operation whose executeBefore deadline is the largest uint64 must take neither the queue print,
  // the dry run nor `verify --op` down: the task prints the raw number and the veto can still decode and cancel it.
  console.log("--- hostile deadline in the queue: the prints survive, the veto cancels ---");
  const hostile = guard.interface.encodeFunctionData("executeBefore", [
    (1n << 64n) - 1n,
    guard.interface.encodeFunctionData("lockdown", [SAFE]),
  ]);
  const hostileSalt = hre.ethers.id("drill-hostile-deadline");
  await (
    await timelock.connect(await impersonate(PROPOSER)).getFunction("schedule")(
      d.address,
      0,
      hostile,
      hre.ethers.ZeroHash,
      hostileSalt,
      minDelay,
    )
  ).wait();
  const hostileId: string = await timelock.hashOperation(d.address, 0, hostile, hre.ethers.ZeroHash, hostileSalt);
  const printed: string[] = [];
  const log = console.log;
  console.log = (...a: unknown[]) => {
    printed.push(a.map(String).join(" "));
    log(...a);
  };
  try {
    await hre.run("curator-guard-sync", {
      allowUnconstrainedNav: true,
      guard: d.address,
      policy: POLICY_RUN,
      dryRun: true,
    });
    await hre.run("curator-guard-verify", { guard: d.address, policy: POLICY_RUN, op: hostileId });
  } finally {
    console.log = log;
  }
  if (!printed.some((l) => l.includes("not a representable date")))
    throw Error("BUG: the queue print did not name the hostile deadline as such (review G17b-1)");
  const canceller = await impersonate(Addresses.ethereum.Vetro.curatorGuardCancellers[0]);
  await (await timelock.connect(canceller).getFunction("cancel")(hostileId)).wait();
  if ((await timelock.getTimestamp(hostileId)) !== 0n)
    throw Error("BUG: the veto could not cancel the hostile operation");
  console.log("hostile deadline printed as the raw number and cancelled by the veto");
  console.log("incident drill complete: mode", await guard.mode(SAFE));
  process.exitCode = 0;
}

async function impersonate(who: string) {
  await hre.network.provider.send("hardhat_impersonateAccount", [who]);
  await hre.network.provider.send("hardhat_setBalance", [who, "0x3635C9ADC5DEA00000"]);
  return hre.ethers.getSigner(who);
}
main().catch((e) => {
  console.error(e);
  process.exit(1);
});
