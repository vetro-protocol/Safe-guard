# Safe Guard (CuratorGuard)

`CuratorGuard` is a Safe **transaction guard and module guard** (Safe v1.3.0 / v1.4.1 / v1.5.0) that allowlists exactly what a Lagoon curator Safe may call. It is a guard, not a module: it never executes anything, it only checks and reverts.

- **Deny by default.** It allowlists `(target, selector)` pairs with on-chain argument rules: `EqualTo`, `EqualToSafe`, `OneOf`, `LessThanOrEqual`, `GreaterThanOrEqual`, and tail-hash rules that bind a dynamic payload exactly.
- **Batches.** `MultiSendCallOnly` batches are unwrapped and each entry is checked (the unwrappers are pinned by code hash).
- **Always refused:**
  - self-calls
  - the guard itself as a target
  - any other delegatecall
  - gas refunds
  - Safe configuration changes: the guard, module guard, modules, owners, threshold, fallback handler and singleton are snapshotted in transient storage and compared after execution
- **Modes:** `Enforced`, `Bypass` (time-boxed) and `Lockdown`, with a cooldown on the admin's lifts. One-shot approvals of an exact payload are supported. A specific fallback handler is required.
- **Roles:**
  - admin = `CuratorGuardTimelock` (OpenZeppelin `TimelockController` with proposer Safes, a veto-only canceller and `executeBefore` deadlines)
  - a council fast lane
  - narrow-only guardians

The design, threat model and runbook are in [docs/curator-guard.md](docs/curator-guard.md). The Vetro policy is [policies/curator-guard/vetro-lagoon.ethereum.json](policies/curator-guard/vetro-lagoon.ethereum.json).

This repository was split out of `vesper-strategies`. The Lagoon strategies the curator Safe serves, and their deploy scripts, stay there.

## Layout

| Path                                                         | Contents                                                                                 |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| `contracts/guards/`                                          | `CuratorGuard`, `CuratorGuardPolicy`, `CuratorGuardTimelock`                             |
| `contracts/interfaces/safe/`, `contracts/interfaces/lagoon/` | Safe and Lagoon interfaces (Lagoon is used by the tests)                                 |
| `test/guards/`                                               | Foundry unit, fuzz, invariant and mutation suites; `*.e2e.ethereum.t.sol`, `G10d_Fork`, `G11b_Policy`, `G11c_ExecutorFloor.e2e`, `G9a_CanonicalProxyHashes` and `G13b_CrossSystem` are fork tests |
| `test/guards-precancun/`                                     | Checks that the guard refuses to deploy on a pre-Cancun EVM                              |
| `policies/curator-guard/`                                    | Policy files and the lint corpus                                                         |
| `deploy/ethereum/guards/`                                    | hardhat-deploy script for the timelock and guard (`--tags CuratorGuard`)                 |
| `tasks/curator-guard.ts`                                     | `curator-guard-sync`, `curator-guard-lint`, `curator-guard-verify`                       |
| `scripts/`                                                   | Fork rehearsal, policy lint corpus, contract-size gate                                   |
| `helpers/`                                                   | Address book (`address.ts`) and Safe batch proposals (`safe.ts`)                         |

## Setup

```bash
git clone --recurse-submodules https://github.com/bloqpriv/Safe-gaurd.git   # or the SSH form with a registered key
cd Safe-gaurd
git checkout <the branch or commit under review>   # a fresh clone lands on main
npm ci --ignore-scripts   # as CI does: nothing in the lockfile needs a lifecycle script to run
cp .env.example .env   # fill in RPCs and keys as needed
```

You need [Foundry](https://book.getfoundry.sh) (CI pins `v1.5.1`) and Node from `.nvmrc`. The submodules are forge-std and the Safe v1.4.1 and v1.5.0 sources, which the tests use as fixtures.

## Test

```bash
forge test --no-match-path '*e2e*'                       # unit suites, no RPC needed (the four non-e2e fork suites report skipped)
ETHEREUM_FORK_BLOCK_NUMBER=25570000 forge test           # everything, needs ETHEREUM_FORK_NODE_URL (archive RPC)
FOUNDRY_PROFILE=guards_deep forge test --mt invariant    # deep invariant search
forge build && FOUNDRY_PROFILE=precancun forge test      # pre-Cancun deployment refusal
FOUNDRY_PROFILE=osaka forge test --no-match-path '*e2e*'   # the unit suites on the EVM mainnet runs today (Osaka)
G16F_MIN_DELAY=86400 forge test --match-contract G16f_     # the recovery matrix at the one-day timelock floor (default: the 48 h deploy delay)
python3 test/guards/matrix/gen_matrix.py && cp test/guards/matrix/out/G12e_*.sol test/guards/ && rm -r test/guards/matrix/out   # regenerate the access matrix after a change of its expectations (never leave out/ in place: it is inside Foundry's test glob)
npm run lint:policies                                    # policy lint corpus
THRESHOLD_PCT=96 npm run sizes                           # EIP-170 size gate (hardhat artifacts)
FORK_NODE_URL=<rpc> FORK_BLOCK_NUMBER=25570000 \
  npx hardhat run scripts/curator-guard-fork-dryrun.ts --network hardhat   # fork rehearsal of the tooling
```

To drive the tasks against an anvil fork you run yourself (`--network localhost`), start it with `--chain-id 31337`
(hardhat refuses any other chain id for that network) and point `LOCALHOST_NODE_URL` at it; `FORK_NODE_URL` is only
the upstream of the in-process `hardhat` network.

The fork block must come before the guard was installed on the Vetro curator Safe (the fork tests assert the Safe has no guard and no modules); without `ETHEREUM_FORK_NODE_URL` the `*.e2e.ethereum` suites fail to resolve the `ethereum` RPC alias and the other fork suites skip.

The guard and its timelock compile at 10 optimizer runs on the legacy pipeline, with `evm_version = cancun`, in both Foundry and Hardhat. CI checks that the two toolchains produce identical runtime bytecode, and `test/guards/G12a_BuildPin.t.sol` pins both runtimes (metadata stripped) to the reviewed build: a dependency or compiler change that moves the bytecode fails `forge test` until it is re-pinned with a review. `@openzeppelin/contracts` is a Solidity dependency of the deployed contracts: treat a bump of it as a contract change (`.github/dependabot.yml` keeps Dependabot off it).

## Deploy

```bash
npx hardhat deploy --network ethereum --tags CuratorGuard
```

Before a mainnet run, fill in the `Vetro.curatorGuard*` roles in `helpers/address.ts`. The script refuses an empty canceller list or council, and a proposer, canceller or council that shares keys with the curator Safe. See docs sections 7.1 to 7.4 for the deploy, the policy sync, the pre-install checks and the install batch (section 8 lists the Lagoon-side preconditions). Use `curator-guard-sync` to schedule policy changes through the timelock.

## CI

`.github/workflows/ci.yml` runs:

- eslint and tsc on the tooling
- the policy lint corpus
- the Foundry suites
- the pre-Cancun check
- a fork rehearsal with the size gate and the toolchain-parity check

The fork jobs need the repository secret `ETHEREUM_FORK_NODE_URL`, set to an archive-capable mainnet RPC.

## Review material

The review record is [docs/curator-guard.md](docs/curator-guard.md) section 13.2. The round reports, the diffs of the
decisions still held (section 13.2 lists them), and the suites that are not in this tree (the `halmos` symbolic
suites of round 12, the differential fuzz of the rule language, the EIP-150 gas sweeps, the mutation campaigns'
results) are kept in the owner's review archive, which the test headers and section 10 call "the review material";
it is supplied to auditors with the audit prompt, together with a manifest of its files.
