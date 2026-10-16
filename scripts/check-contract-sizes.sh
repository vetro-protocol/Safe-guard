#!/usr/bin/env bash
#
# Fail if any contract's deployed (runtime) bytecode reaches THRESHOLD_PCT of the
# EIP-170 limit (24,576 bytes). Shared by the local pre-push hook and CI so both
# enforce the same rule. Measures hardhat artifacts because hardhat is the
# toolchain that deploys; forge compiles the same contract under different
# settings.
#
#   THRESHOLD_PCT=90 ./scripts/check-contract-sizes.sh   # tighten locally
#
set -euo pipefail

LIMIT=24576                                      # EIP-170 max deployed bytecode
# Several live contracts sit in the 90-95% band; tighten as they shrink.
THRESHOLD_PCT="${THRESHOLD_PCT:-96}"
THRESHOLD=$(( LIMIT * THRESHOLD_PCT / 100 ))

echo "Checking contract sizes against hardhat artifacts (fail at ${THRESHOLD_PCT}% of ${LIMIT}B = ${THRESHOLD}B)…"

npx hardhat compile

# Abstract contracts and interfaces have deployedBytecode "0x" and drop out.
# Tab-separated: runtime  pct  margin  name
violations="$(node -e '
const fs = require("fs");
const path = require("path");
const LIMIT = Number(process.argv[1]);
const THRESHOLD = Number(process.argv[2]);
const rows = [];
(function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p);
    else if (e.name.endsWith(".json") && !e.name.endsWith(".dbg.json")) {
      const a = JSON.parse(fs.readFileSync(p, "utf8"));
      if (!a.deployedBytecode || a.deployedBytecode === "0x") continue;
      const size = (a.deployedBytecode.length - 2) / 2;
      if (size >= THRESHOLD) rows.push({ size, name: a.contractName });
    }
  }
})("artifacts/contracts");
rows.sort((x, y) => y.size - x.size);
for (const r of rows)
  console.log(`${r.size}\t${Math.floor((r.size * 100) / LIMIT)}\t${LIMIT - r.size}\t${r.name}`);
' "$LIMIT" "$THRESHOLD")"

if [ -n "$violations" ]; then
  printf '\n   size    %%    margin  contract\n'
  printf '%s\n' "$violations" | while IFS=$'\t' read -r size pct margin name; do
    printf '  %5sB  %3s%%  %5sB  %s\n' "$size" "$pct" "$margin" "$name"
  done
  printf '\n❌ Contract(s) at or above %s%% of the %sB EIP-170 limit.\n' "$THRESHOLD_PCT" "$LIMIT"
  printf 'The guard contracts compile at 10 optimizer runs without via-IR in both toolchains (the single compiler\n'
  printf 'setting of hardhat.config.ts, foundry.toml); a contract near the gate is measured before code is added (docs section 10).\n'
  exit 1
fi

echo "✅ All contracts under ${THRESHOLD_PCT}% of the ${LIMIT}B limit."
