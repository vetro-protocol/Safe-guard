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
| `test/guards/`                                               | Foundry unit, fuzz, invariant and mutation suites; `*.e2e.ethereum.t.sol` are fork tests |
| `test/guards-precancun/`                                     | Checks that the guard refuses to deploy on a pre-Cancun EVM                              |
| `policies/curator-guard/`                                    | Policy files and the lint corpus                                                         |
| `deploy/ethereum/guards/`                                    | hardhat-deploy script for the timelock and guard (`--tags CuratorGuard`)                 |
| `tasks/curator-guard.ts`                                     | `curator-guard-sync`, `curator-guard-lint`, `curator-guard-verify`                       |
| `scripts/`                                                   | Fork rehearsal, policy lint corpus, contract-size gate                                   |
| `helpers/`                                                   | Address book (`address.ts`) and Safe batch proposals (`safe.ts`)                         |

## Setup

```bash
git clone --recurse-submodules git@github.com:bloqpriv/Safe-gaurd.git
cd Safe-gaurd
npm ci
cp .env.example .env   # fill in RPCs and keys as needed
```

You need [Foundry](https://book.getfoundry.sh) (CI pins `v1.5.1`) and Node from `.nvmrc`. The submodules are forge-std and the Safe v1.4.1 and v1.5.0 sources, which the tests use as fixtures.

## Test

```bash
forge test --no-match-path '*e2e*'                       # unit suites, no RPC needed
ETHEREUM_FORK_BLOCK_NUMBER=25570000 forge test           # everything, needs ETHEREUM_FORK_NODE_URL (archive RPC)
FOUNDRY_PROFILE=guards_deep forge test --mt invariant    # deep invariant search
forge build && FOUNDRY_PROFILE=precancun forge test      # pre-Cancun deployment refusal
npm run lint:policies                                    # policy lint corpus
THRESHOLD_PCT=96 npm run sizes                           # EIP-170 size gate (hardhat artifacts)
FORK_NODE_URL=<rpc> FORK_BLOCK_NUMBER=25570000 \
  npx hardhat run scripts/curator-guard-fork-dryrun.ts --network hardhat   # fork rehearsal of the tooling
```

The e2e fork block must come before the guard was installed on the Vetro curator Safe (the tests assert the Safe has no guard and no modules).

The guard and its timelock compile at 10 optimizer runs on the legacy pipeline, with `evm_version = cancun`, in both Foundry and Hardhat. CI checks that the two toolchains produce identical runtime bytecode.

## Deploy

```bash
npx hardhat deploy --network ethereum --tags CuratorGuard
```

Before a mainnet run, fill in the `Vetro.curatorGuard*` roles in `helpers/address.ts`. The script refuses an empty canceller list or council, and a proposer, canceller or council that shares keys with the curator Safe. See docs section 8 for the install sequence. Use `curator-guard-sync` to schedule policy changes through the timelock.

## CI

`.github/workflows/ci.yml` runs:

- eslint and tsc on the tooling
- the policy lint corpus
- the Foundry suites
- the pre-Cancun check
- a fork rehearsal with the size gate and the toolchain-parity check

The fork jobs need the repository secret `ETHEREUM_FORK_NODE_URL`, set to an archive-capable mainnet RPC.
