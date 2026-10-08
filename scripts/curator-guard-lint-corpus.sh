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
  elif [ -f "${f%.json}.reason" ] && ! grep -qF -- "$(cat "${f%.json}.reason")" <<< "$out"; then
    echo "FAIL: $f was refused for another reason: $(echo "$out" | grep -m1 -E '^Error' || echo "$out" | tail -1)"; status=1
  else
    echo "ok: refused $f"
  fi
done
for f in policies/curator-guard/lint-corpus/accept-*.json policies/curator-guard/*.json; do
  if out=$(npx hardhat curator-guard-lint --policy "$f" 2>&1); then
    echo "ok: accepted $f"
  else
    echo "FAIL: $f was refused: $(echo "$out" | tail -1)"; status=1
  fi
done
exit $status
