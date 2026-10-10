#!/usr/bin/env python3
"""Merges expected.json with the `G12E|...` console lines of a `forge test -vv` run into MATRIX.md.

Usage: parse_results.py <forge log> [<forge log> ...] > MATRIX.md
Lines:  G12E|<suite>|<class>|<fn>|<state>|<expErrId>|<gotSelHex>|<flags>|<nLogs>|MATCH|MISMATCH
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EXP = json.load(open(os.path.join(HERE, "out", "expected.json")))

ERR_NAMES = [
    "OK", "EMPTY", "Unauthorized", "AddressIsNull", "AdminCannotBeZero", "AdminDelayTooLong", "AdminIsGuarded",
    "ApprovalNotFound", "CouncilCannotApprove", "DeadlinePassed", "InvalidDuration", "InvalidRule", "InvalidTarget",
    "LockdownCooldown", "ModuleNotAllowed", "NoOneOfRule", "NotAContract", "SafeInBypass", "TooManyRules",
    "TooManyValues", "UnboundedLowerBound", "UnwrapperCodehashNotAllowed", "ApprovedExecutionFailed",
    "CouncilBypassLimit", "DelegateCallNotAllowed", "EmptyMultiSend", "FallbackHandlerNotAllowed",
    "ForwardedHookCall", "FunctionNotAllowed", "GasRefundNotAllowed", "GuardCallNotAllowed", "GuardNotInstalled",
    "MalformedCalldata", "MalformedMultiSend", "MissingSnapshot", "ModuleNotHooked", "MultiSendDelegateCallEntry",
    "NestedExecution", "NativeTransferNotAllowed", "SafeConfigChanged", "SafeConfigUnreadable", "SafeLockedDown",
    "SafeNotSupported", "SelfCallNotAllowed", "ValueNotAllowed", "AccessControlUnauthorizedAccount",
    "AccessControlBadConfirmation", "AccessControlEnforcedDefaultAdminRules", "AccessControlEnforcedDefaultAdminDelay",
    "AccessControlInvalidDefaultAdmin", "TimelockUnexpectedOperationState", "TimelockUnauthorizedCaller",
    "TimelockInsufficientDelay", "TimelockUnexecutedPredecessor", "FailedCall", "CancellerCannotPropose",
    "ForwardedCall", "DelayOutOfRange", "LastRoleHolder", "OpenExecutorRequired", "ProposerCannotCancel",
    "SelfAdminRequired", "SelfHolder", "TargetHasNoCode", "ZeroAddressHolder",
]
SIGS = {
    "Unauthorized": "Unauthorized()", "AddressIsNull": "AddressIsNull()", "AdminCannotBeZero": "AdminCannotBeZero()",
    "AdminDelayTooLong": "AdminDelayTooLong(uint48)", "AdminIsGuarded": "AdminIsGuarded(address)",
    "ApprovalNotFound": "ApprovalNotFound(bytes32)", "CouncilCannotApprove": "CouncilCannotApprove(bytes4,uint8)",
    "DeadlinePassed": "DeadlinePassed(uint64)", "InvalidDuration": "InvalidDuration(uint64)", "InvalidRule": "InvalidRule(uint256)",
    "InvalidTarget": "InvalidTarget(address)", "LockdownCooldown": "LockdownCooldown(address)", "ModuleNotAllowed": "ModuleNotAllowed(address)",
    "NoOneOfRule": "NoOneOfRule(uint16)", "NotAContract": "NotAContract(address)", "SafeInBypass": "SafeInBypass(address)",
    "TooManyRules": "TooManyRules(uint256)", "TooManyValues": "TooManyValues(uint256)", "UnboundedLowerBound": "UnboundedLowerBound(uint256)",
    "UnwrapperCodehashNotAllowed": "UnwrapperCodehashNotAllowed(bytes32)", "ApprovedExecutionFailed": "ApprovedExecutionFailed(address)",
    "CouncilBypassLimit": "CouncilBypassLimit(bytes4)", "DelegateCallNotAllowed": "DelegateCallNotAllowed(address)",
    "EmptyMultiSend": "EmptyMultiSend()", "FallbackHandlerNotAllowed": "FallbackHandlerNotAllowed(address)",
    "ForwardedHookCall": "ForwardedHookCall()", "FunctionNotAllowed": "FunctionNotAllowed(address,bytes4)",
    "GasRefundNotAllowed": "GasRefundNotAllowed()", "GuardCallNotAllowed": "GuardCallNotAllowed(bytes4)",
    "GuardNotInstalled": "GuardNotInstalled(address)", "MalformedCalldata": "MalformedCalldata()", "MalformedMultiSend": "MalformedMultiSend()",
    "MissingSnapshot": "MissingSnapshot(address)", "ModuleNotHooked": "ModuleNotHooked(address)",
    "MultiSendDelegateCallEntry": "MultiSendDelegateCallEntry()", "NestedExecution": "NestedExecution(address)",
    "NativeTransferNotAllowed": "NativeTransferNotAllowed(address)", "SafeConfigChanged": "SafeConfigChanged(address)",
    "SafeConfigUnreadable": "SafeConfigUnreadable(address)", "SafeLockedDown": "SafeLockedDown(address)",
    "SafeNotSupported": "SafeNotSupported(address)", "SelfCallNotAllowed": "SelfCallNotAllowed(bytes4)",
    "ValueNotAllowed": "ValueNotAllowed(address,bytes4)", "AccessControlUnauthorizedAccount": "AccessControlUnauthorizedAccount(address,bytes32)",
    "AccessControlBadConfirmation": "AccessControlBadConfirmation()",
    "AccessControlEnforcedDefaultAdminRules": "AccessControlEnforcedDefaultAdminRules()",
    "AccessControlEnforcedDefaultAdminDelay": "AccessControlEnforcedDefaultAdminDelay(uint48)",
    "AccessControlInvalidDefaultAdmin": "AccessControlInvalidDefaultAdmin(address)",
    "TimelockUnexpectedOperationState": "TimelockUnexpectedOperationState(bytes32,bytes32)",
    "TimelockUnauthorizedCaller": "TimelockUnauthorizedCaller(address)", "TimelockInsufficientDelay": "TimelockInsufficientDelay(uint256,uint256)",
    "TimelockUnexecutedPredecessor": "TimelockUnexecutedPredecessor(bytes32)", "FailedCall": "FailedCall()",
    "CancellerCannotPropose": "CancellerCannotPropose(address)", "ForwardedCall": "ForwardedCall(address)",
    "DelayOutOfRange": "DelayOutOfRange(uint256)", "LastRoleHolder": "LastRoleHolder(bytes32)", "OpenExecutorRequired": "OpenExecutorRequired()",
    "ProposerCannotCancel": "ProposerCannotCancel(address)", "SelfAdminRequired": "SelfAdminRequired()", "SelfHolder": "SelfHolder(bytes32)",
    "TargetHasNoCode": "TargetHasNoCode(address)", "ZeroAddressHolder": "ZeroAddressHolder(bytes32)",
}
SEL = {}
for name, sig in SIGS.items():
    try:
        SEL[subprocess.check_output(["cast", "sig", sig], text=True).strip().lower()] = name
    except Exception:
        pass
SEL["0x00000000"] = "OK"
SEL["0xffffffff"] = "EMPTY"

results = {}
pat = re.compile(r"G12E\|([GHTV])\|(\d+)\|(\d+)\|(\d+)\|(\d+)\|(0x[0-9a-fA-F]{8})\|(\d+)\|(\d+)\|(MATCH|MISMATCH)")
tests = {"pass": 0, "fail": 0}
for path in sys.argv[1:]:
    for line in open(path, errors="replace"):
        m = pat.search(line)
        if m:
            suite, c, f, s, exp, got, flags, n, verdict = m.groups()
            results[(suite, int(c), int(f), int(s))] = dict(exp=int(exp), got=got.lower(), flags=int(flags), n=int(n), verdict=verdict)
        elif line.startswith("[PASS]"):
            tests["pass"] += 1
        elif line.startswith("[FAIL"):
            tests["fail"] += 1

cells = EXP["cells"]
by_key = {(c["suite"], c["c"], c["f"], c["s"]): c for c in cells}
classes = {c["id"]: c for c in EXP["classes"]}
tclasses = {c["id"]: c for c in EXP["tclasses"]}
functions = {f["id"]: f for f in EXP["functions"]}
tfunctions = {f["id"]: f for f in EXP["tfunctions"]}
states = [s["key"] for s in EXP["states"]]
paths = {p["id"]: p for p in EXP["paths"]}
payloads = {p["id"]: p for p in EXP["payloads"]}


def short(err, events):
    if err == "OK":
        return "OK" + ("[" + ",".join(e.split(":")[0] if ":" not in e else e.replace("OutBypass", "Bypass") for e in events) + "]" if events else "[]")
    return err


def mark(cell):
    r = results.get((cell["suite"], cell["c"], cell["f"], cell["s"]))
    und = "U" in cell["doc"].split(",")
    if r is None:
        return "?", und
    if r["verdict"] == "MISMATCH":
        return "!!" + SEL.get(r["got"], r["got"]) + ("" if r["flags"] & 2 else "(events)"), und
    return "", und


out = []
out.append("# G12e access-control matrix (Safe-gaurd 830824e)\n")
out.append("Generated by `matrix/gen_matrix.py`, run with `forge test -j 1 -vv` in `review-scratch/g12e/root`, merged by `matrix/parse_results.py`.")
out.append("Cells: %d expected, %d observed, %d MISMATCH; forge tests: %d passed, %d failed.\n" % (
    len(cells), len(results), sum(1 for r in results.values() if r["verdict"] == "MISMATCH"), tests["pass"], tests["fail"]))
out.append("Legend: a cell is `OK[events]` or the revert's error name; `*` = the documentation does not decide the cell (the expectation is read from the code); `!!X` = the run disagreed and returned X; `?` = no result line. The `doc` column names the deciding passage (see the key at the end). Rows whose eight states agree are written once.\n")
out.append("States: " + "; ".join("S%d %s" % (i, k) for i, k in enumerate(states)) + "\n")

und_list = []
mis_list = []

# ---- guard matrix
out.append("## A. The guard: 13 caller classes x 95 functions x 8 states\n")
for cid in sorted(classes):
    out.append("### Class %d: %s\n" % (cid, classes[cid]["label"]))
    out.append("| # | function | S0 | S1 | S2 | S3 | S4 | S5 | S6 | S7 | doc |")
    out.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for fid in sorted(functions):
        row = []
        docs = set()
        for sid in range(8):
            cell = by_key[("G", cid, fid, sid)]
            m, und = mark(cell)
            txt = short(cell["err"], cell["events"]) + ("*" if und else "") + m
            row.append(txt)
            docs.update(cell["doc"].split(","))
            if und:
                und_list.append(("G", cid, fid, sid, cell))
            if m.startswith("!!"):
                mis_list.append(("G", cid, fid, sid, cell, m))
        docs.discard("U")
        d = ",".join(sorted(docs, key=lambda x: (len(x), x)))
        if len(set(row)) == 1:
            out.append("| %d | `%s` | %s | | | | | | | | %s |" % (fid, functions[fid]["key"], "all: " + row[0], d))
        else:
            out.append("| %d | `%s` | %s | %s |" % (fid, functions[fid]["key"], " | ".join(row), d))
    out.append("")

# ---- hooks through Safe transactions
out.append("## B. The hooks through real Safe transactions: 3 paths x 9 payloads x 8 states\n")
for pid in sorted(paths):
    out.append("### Path %d: %s\n" % (pid, paths[pid]["label"]))
    out.append("| # | payload | S0 | S1 | S2 | S3 | S4 | S5 | S6 | S7 | doc |")
    out.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for kid in sorted(payloads):
        if pid != 0 and kid == 8:
            continue
        row = []
        docs = set()
        for sid in range(8):
            cell = by_key[("H", pid, kid, sid)]
            m, und = mark(cell)
            row.append(short(cell["err"], cell["events"]) + ("*" if und else "") + m)
            docs.update(cell["doc"].split(","))
            if m.startswith("!!"):
                mis_list.append(("H", pid, kid, sid, cell, m))
        docs.discard("U")
        d = ",".join(sorted(docs, key=lambda x: (len(x), x)))
        if len(set(row)) == 1:
            out.append("| %d | %s | %s | | | | | | | | %s |" % (kid, payloads[kid]["key"], "all: " + row[0], d))
        else:
            out.append("| %d | %s | %s | %s |" % (kid, payloads[kid]["key"], " | ".join(row), d))
    out.append("")

# ---- timelock
out.append("## C. The timelock: 9 caller classes x 31 functions\n")
out.append("| # | function | " + " | ".join("C%d %s" % (c, tclasses[c]["key"]) for c in sorted(tclasses)) + " | doc |")
out.append("|---|---|" + "---|" * len(tclasses) + "---|")
for fid in sorted(tfunctions):
    row = []
    docs = set()
    for cid in sorted(tclasses):
        cell = by_key[("T", cid, fid, 0)]
        m, und = mark(cell)
        row.append(short(cell["err"], cell["events"]) + ("*" if und else "") + m)
        docs.update(cell["doc"].split(","))
        if und:
            und_list.append(("T", cid, fid, 0, cell))
        if m.startswith("!!"):
            mis_list.append(("T", cid, fid, 0, cell, m))
    docs.discard("U")
    out.append("| %d | `%s` | %s | %s |" % (fid, tfunctions[fid]["key"], " | ".join(row), ",".join(sorted(docs, key=lambda x: (len(x), x)))))
out.append("\nTimelock classes: " + "; ".join("C%d %s" % (c, tclasses[c]["label"]) for c in sorted(tclasses)) + "\n")

# ---- via timelock
out.append("## D. The admin's cells of S3 through a real CuratorGuardTimelock (scheduled by a proposer, wrapped in executeBefore, executed by a stranger)\n")
out.append("| # | function | expected (= the direct admin cell) | result |")
out.append("|---|---|---|---|")
for fid in sorted(functions):
    if ("V", 0, fid, 3) not in by_key:
        continue
    cell = by_key[("V", 0, fid, 3)]
    r = results.get(("V", 0, fid, 3))
    m, und = mark(cell)
    if r is None and cell["note"] == "" and "send 1 wei" in functions[fid]["key"]:
        continue
    out.append("| %d | `%s` | %s%s | %s |" % (fid, functions[fid]["key"], short(cell["err"], cell["events"]), "*" if und else "", "MISMATCH " + m if m.startswith("!!") else ("not run" if r is None else "match")))
    if m.startswith("!!"):
        mis_list.append(("V", 0, fid, 3, cell, m))
out.append("")

# ---- mismatches and undecided
out.append("## E. Cells where the run disagreed with the documented expectation\n")
if not mis_list:
    out.append("None.\n")
for suite, c, f, s, cell, m in mis_list:
    name = functions[f]["key"] if suite in ("G", "V") else (tfunctions[f]["key"] if suite == "T" else payloads[f]["key"])
    who = classes[c]["key"] if suite in ("G", "V") else (tclasses[c]["key"] if suite == "T" else paths[c]["key"])
    out.append("- %s | %s | `%s` | S%d: expected %s, got %s (doc %s; %s)" % (suite, who, name, s, short(cell["err"], cell["events"]), m[2:], cell["doc"], cell["note"]))
out.append("")
out.append("## F. Cells the documentation does not decide (expectation read from the code), grouped by function\n")
grouped = {}
for suite, c, f, s, cell in und_list:
    key = (suite, f)
    grouped.setdefault(key, []).append((c, s, cell))
for (suite, f), items in sorted(grouped.items()):
    name = functions[f]["key"] if suite == "G" else tfunctions[f]["key"]
    notes = sorted(set(cell["note"] for _, _, cell in items))
    whos = sorted(set(c for c, _, _ in items))
    out.append("- %s `%s` (classes %s; %d cells): %s" % ("guard" if suite == "G" else "timelock", name, ",".join(str(w) for w in whos), len(items), " / ".join(n for n in notes if n)))
out.append("")
out.append("## G. Documentation key\n")
for k, v in EXP["docs"].items():
    out.append("- **%s**: %s" % (k, v))
print("\n".join(out))
