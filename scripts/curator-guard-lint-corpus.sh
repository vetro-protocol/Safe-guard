#!/usr/bin/env bash
# Runs `curator-guard-lint` over the corpus: every `refuse-*.json` must be refused, every
# `accept-*.json` accepted, and every shipped policy file must be accepted. CI runs this.
set -u
cd "$(dirname "$0")/.."
status=0
for f in policies/curator-guard/lint-corpus/refuse-*.json; do
  if out=$(npx hardhat curator-guard-lint --policy "$f" 2>&1); then
    echo "FAIL: $f was accepted"; status=1
  # A refuse-* case is refused for ITS reason, not for a typo elsewhere in the file: when a
  # `<name>.reason` file sits next to it, that text must occur in the lint's output (review G9e-3).
  # An empty pattern would match anything, so an empty .reason file is a failure (review G11e-2).
  # A refuse-* case without a .reason passes for ANY refusal (a JSON typo, a wrong key): every case names its
  # reason, so a missing file is a failure too (review G21f; `refuse-x.json.reason` is a missing file).
  elif [ ! -f "${f%.json}.reason" ]; then
    echo "FAIL: ${f%.json}.reason is missing (the case would pass for any refusal)"; status=1
  elif [ -z "$(cat "${f%.json}.reason")" ]; then
    echo "FAIL: ${f%.json}.reason is empty (it would match any refusal)"; status=1
  elif [ -f "${f%.json}.reason" ] && ! grep -qF -- "$(cat "${f%.json}.reason")" <<< "$out"; then
    echo "FAIL: $f was refused for another reason: $(echo "$out" | grep -m1 -E '^Error' || echo "$out" | tail -1)"; status=1
  else
    echo "ok: refused $f"
  fi
done
for f in policies/curator-guard/lint-corpus/accept-*.json policies/curator-guard/*.json; do
  if out=$(npx hardhat curator-guard-lint --policy "$f" 2>&1); then
    # An accept-* case may pin a WARNING: when a `<name>.warn` file sits next to it, that text must
    # occur in the lint's output (the lint's warnings are rules too; review G11e).
    if [ -f "${f%.json}.warn" ] && [ -z "$(cat "${f%.json}.warn")" ]; then
      echo "FAIL: ${f%.json}.warn is empty (it would match any output)"; status=1
    elif [ -f "${f%.json}.warn" ] && ! grep -qF -- "$(cat "${f%.json}.warn")" <<< "$out"; then
      echo "FAIL: $f was accepted without the expected warning: $(cat "${f%.json}.warn")"; status=1
    else
      echo "ok: accepted $f"
    fi
  else
    echo "FAIL: $f was refused: $(echo "$out" | tail -1)"; status=1
  fi
done
exit $status
