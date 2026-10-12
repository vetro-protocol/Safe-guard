#!/usr/bin/env python3
"""G12e: the access-control matrix generator.

Emits Foundry test files that call EVERY external / public function of CuratorGuard (CuratorGuardPolicy
and the OpenZeppelin role surface included) and CuratorGuardTimelock as every caller class, in every mode
and window state of the guarded Safe, and compare the outcome (success / revert selector) and the guard's
events with an expectation derived from the documentation (docs/curator-guard.md sections 4, 6, 7.5-7.8
and the NatSpec). Where the documentation does not decide a cell the expectation is derived from the code
and the cell is tagged UNDECIDED, so the report can list it.

Outputs (next to this script, under out/; copied into the review root's test/guards by the driver):
  G12e_Matrix.t.sol            the guard matrix: 14 caller classes x 95 functions x 8 states (class 13 the dirty handler word, review G16d-1)
  G12e_MatrixHooks.t.sol       the hooks through real Safe transactions: 3 paths x 9 payloads x 8 states
  G12e_MatrixTimelock.t.sol    the timelock surface: 9 caller classes x 32 functions
  G12e_MatrixViaTimelock.t.sol every admin cell of state S3 executed through a real CuratorGuardTimelock
  G12e_MatrixViews.t.sol       the view and ERC-165 surface for every caller class
  expected.json                every cell's expectation with its documentation reference
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
os.makedirs(OUT, exist_ok=True)

# --------------------------------------------------------------------------------------------------
# Documentation references (docs/curator-guard.md of Safe-gaurd 830824e; line numbers of that revision of the file).
# --------------------------------------------------------------------------------------------------
DOCS = {
    "D1": "S4 L120-125 admin bullet: the only role that can WIDEN (allowFunction(s), addAllowedValues, set*(true), setRequiredFallbackHandler); re-allowing a seeded hash and seating guardians are admin OR council; approvals <= 180 d; Bypass <= 180 d; administer roles",
    "D2": "S4 L128-133: for one day after any lockdown the admin's enforce / bypass / approveTransaction revert LockdownCooldown; the council is not held back; widenings, role grants and guardian removals execute during the cooldown",
    "D3": "S4 L133-140: admin transfer refused for address(0) (AdminCannotBeZero), a policy-carrying address or the council (AdminIsGuarded); delay capped at 30 d with a 1 d floor (AdminDelayTooLong); a pending admin expires 30 d after the schedule (DeadlinePassed)",
    "D4": "S4 L141-144: every role grant has the input rails: never address(0) (AddressIsNull), never the admin, never an account with an allowlist (AdminIsGuarded)",
    "D5": "S4 L151-154: no role is honoured for a caller that answers as a Safe with THIS guard in its fallback-handler slot (Unauthorized); the timelock has the same rail (ForwardedCall)",
    "D6": "S4 L154-157: the admin is never constrained by the guard: all hooks return early for msg.sender == defaultAdmin(); its transactions are neither checked nor reported (L365-366)",
    "D7": "S4 L158-189 council bullet: enforce, lockdown, approvals <= 7 d limited to the self-call allowlist (CouncilCannotApprove; threshold never below 2; no new owner with code), a Bypass of 1 h to 7 d, guardian management (per Safe and deployment-wide), any narrowing; no role holder acts on itself (enforce, bypass, approveTransaction revert Unauthorized when safe == msg.sender)",
    "D8": "S4 L190-208 guardians: narrow-only (lockdown, lockdownAndRevoke, revoke function / target, remove OneOf values, disable unwrapper / module / native transfer, revoke one or all approvals); a per-Safe guardian cannot touch another Safe nor deployment-wide state (setUnwrapperCodehash(false) needs admin, council or the deployment-wide role; re-allowing is admin or council)",
    "D9": "S4 L210-212: an unconfigured Safe is in Lockdown",
    "D10": "S4 L218 mode table: a window opened at t for d covers t..t+d-1; at t+d the Safe reads as Lockdown; approvals are valid through their expiry inclusive",
    "D11": "S4 L243-274 approvals: admin or council; valid ttl seconds; void en bloc whenever a Bypass window opens; InvalidTarget for the guard, a codeless target with calldata, a delegatecall into EIP-7702 code; a module-bound approval names neither the Safe nor the guard; refused while the Safe is in Bypass (SafeInBypass); any role holder can wrap one of its own calls in executeBefore, which runs it as the caller only until the deadline",
    "D12": "S4 L276-363 evaluation order of the hooks (admin exempt; NestedExecution; GuardNotInstalled / SafeConfigUnreadable; ModuleNotAllowed in every mode; the window rules; GasRefundNotAllowed; the approval branch incl. ForwardedHookCall; SafeLockedDown; SafeNotSupported / FallbackHandlerNotAllowed / ModuleNotHooked; the delegatecall and plain-call rules)",
    "D13": "S4 L365-407 post-execution: exactly 68 bytes (ForwardedHookCall); an empty slot is legitimate only for the admin or an effective Bypass (MissingSnapshot otherwise); a digest must match (SafeConfigChanged); one TransactionChecked per passing transaction; nothing for the admin",
    "D14": "S6 Blocked list L559-607: widening from a guardian key or a stranger; role grants to address(0), the admin or a configured Safe; forwarded hook calls spend no approval (ForwardedHookCall) and executeBefore refuses a forwarded caller, so no Bypass report is forged through it (G9a-1, applied after round 13); roles through a role-holding Safe's fallback forwarding",
    "D15": "S7.5 L1067-1077 remove / emergency: lockdown and lockdownAndRevoke by admin, council or a guardian of the Safe; the council lifts at once, the admin after minDelay and never within a day of the last lockdown; setGuardian / setDeploymentGuardian(false) council or admin",
    "D16": "S7.5 L1078-1121 one-off actions: approveTransaction by admin or council, ttl at least one hour (InvalidDuration), executor never the Safe nor the guard (InvalidTarget), target must carry code; revokeApproval; revokeAllApprovals by admin, council or guardian",
    "D17": "S7.5 L1238-1260 hand-over: begin refused for address(0) (AdminCannotBeZero), the council or a policy-carrying address (AdminIsGuarded); the new admin accepts after defaultAdminDelay within 30 days (DeadlinePassed afterwards); cancelDefaultAdminTransfer aborts a pending hand-over",
    "D18": "S7.5 L1260-1292 rotation: grantRole / revokeRole of COUNCIL_ROLE are timelocked admin operations; a role is never granted to address(0), the admin or a configured Safe (AddressIsNull / AdminIsGuarded); deployment-wide guardians by admin or council",
    "D19": "S7.7 L1393-1437 events: ModeUpdated may repeat the current mode; ApprovalsRevoked also on every bypass and lockdownAndRevoke; ApprovalRevoked may name a void record; RequiredFallbackHandlerUpdated and UnwrapperCodehashUpdated on every call; MultiSendUnwrapperUpdated and ModuleUpdated only on a change; RoleGranted / RoleRevoked incl. the admin role at acceptance",
    "D20": "S7.8 signer table L1498-1533: the hook errors and who fixes them",
    "N": "NatSpec of the function (contracts/guards/CuratorGuardPolicy.sol / CuratorGuard.sol / CuratorGuardTimelock.sol)",
    "OZ": "OpenZeppelin 5.2.0 AccessControl / AccessControlDefaultAdminRules / TimelockController sources",
    "T1": "CuratorGuardTimelock header L13-52 and S4 L109-119: proposers schedule, one veto cancels, the executor is open, the timelock administers itself, the rails (ZeroAddressHolder, SelfHolder, SelfAdminRequired, ProposerCannotCancel, CancellerCannotPropose, LastRoleHolder, OpenExecutorRequired, DelayOutOfRange, TargetHasNoCode, ForwardedCall)",
    "U": "UNDECIDED by the documentation: the expectation is read from the code",
}

# --------------------------------------------------------------------------------------------------
# Caller classes of the guard matrix
# --------------------------------------------------------------------------------------------------
CLASSES = [
    dict(id=0, key="ADMIN", label="the admin (EOA holding DEFAULT_ADMIN_ROLE; production: the timelock)", sender="vetro", target="address(g)", eff="vetro", admin=True),
    dict(id=1, key="COUNCIL", label="the council (COUNCIL_ROLE)", sender="council", target="address(g)", eff="council", council=True),
    dict(id=2, key="GUARDIAN_A", label="a per-Safe guardian of Safe A", sender="gA", target="address(g)", eff="gA", gA=True),
    dict(id=3, key="GUARDIAN_D", label="a deployment-wide guardian (GUARDIAN_ROLE)", sender="gD", target="address(g)", eff="gD", gD=True),
    dict(id=4, key="SAFE_A", label="the guarded Safe A itself (v1.4.1, guard installed; pranked)", sender="address(safeA)", target="address(g)", eff="address(safeA)", isA=True, isSafe=True),
    dict(id=5, key="MODULE_ALLOWED", label="an allowlisted module (contract; pranked)", sender="address(MOD)", target="address(g)", eff="address(MOD)", contract=True),
    dict(id=6, key="MODULE_OTHER", label="a module that is not allowlisted (contract; pranked)", sender="address(MODX)", target="address(g)", eff="address(MODX)", contract=True),
    dict(id=7, key="STRANGER", label="a stranger (EOA)", sender="stranger", target="address(g)", eff="stranger", stranger=True),
    dict(id=8, key="ZERO", label="address(0) (an eth_call without a sender)", sender="address(0)", target="address(g)", eff="address(0)", zero=True),
    dict(id=9, key="PENDING_ADMIN", label="the pending admin (hand-over begun, not accepted)", sender="pend", target="address(g)", eff="pend", pending=True),
    dict(id=10, key="FWD_COUNCIL_SAFE", label="a council Safe whose fallback handler is the guard (a stranger calls the Safe, which forwards)", sender="stranger", target="address(councilSafe)", eff="address(councilSafe)", fwd=True, council=True, isSafe=True),
    dict(id=11, key="FWD_SAFE_A", label="Safe A with the guard as fallback handler, handler requirement OFF (a stranger calls the Safe)", sender="stranger", target="address(safeA)", eff="address(safeA)", fwd=True, isA=True, isSafe=True, handlerGuard=True),
    dict(id=12, key="FWD_SAFE_A_REQ", label="Safe A with the guard as fallback handler, handler requirement ON (the shipped shape)", sender="stranger", target="address(safeA)", eff="address(safeA)", fwd=True, isA=True, isSafe=True, handlerGuard=True, req=True),
    # Review G16d-1 (applied after round 18): a handler word whose LOW 160 bits are the guard and whose high 96 bits are
    # dirty still forwards (the EVM masks the call target); every read of the slot masks it the same way, so the class
    # must answer exactly as class 12 does.
    dict(id=13, key="FWD_SAFE_A_REQ_DIRTY", label="Safe A with a DIRTY handler word whose low 160 bits are the guard, handler requirement ON (a stranger calls the Safe; the word forwards, review G16d-1)", sender="stranger", target="address(safeA)", eff="address(safeA)", fwd=True, isA=True, isSafe=True, handlerGuard=True, req=True, dirty=True),
]

STATES = [
    dict(id=0, key="S0_LOCKDOWN_FRESH", mode="LOCKDOWN", cooldown=False, apprLive=True, window=None, warped=0),
    dict(id=1, key="S1_LOCKDOWN_COOLDOWN", mode="LOCKDOWN", cooldown=True, apprLive=True, window=None, warped=0),
    dict(id=2, key="S2_LOCKDOWN_AFTER_COOLDOWN", mode="LOCKDOWN", cooldown=False, apprLive=True, window=None, warped=86401),
    dict(id=3, key="S3_ENFORCED", mode="ENFORCED", cooldown=False, apprLive=True, window=None, warped=0),
    dict(id=4, key="S4_ADMIN_WINDOW", mode="BYPASS", cooldown=False, apprLive=False, window="admin", warped=0),
    dict(id=5, key="S5_COUNCIL_WINDOW", mode="BYPASS", cooldown=False, apprLive=False, window="council", warped=0),
    dict(id=6, key="S6_EXPIRED_WINDOW", mode="LOCKDOWN", cooldown=False, apprLive=False, window=None, warped=3601),
    dict(id=7, key="S7_COUNCIL_WINDOW_IN_COOLDOWN", mode="BYPASS", cooldown=True, apprLive=False, window="council", warped=0),
]

# --------------------------------------------------------------------------------------------------
# Error ids (0 = success, 1 = empty revert) and their Solidity selector expressions
# --------------------------------------------------------------------------------------------------
ERRORS = [
    ("OK", None), ("EMPTY", None),
    ("Unauthorized", "CuratorGuardPolicy.Unauthorized.selector"),
    ("AddressIsNull", "CuratorGuardPolicy.AddressIsNull.selector"),
    ("AdminCannotBeZero", "CuratorGuardPolicy.AdminCannotBeZero.selector"),
    ("AdminDelayTooLong", "CuratorGuardPolicy.AdminDelayTooLong.selector"),
    ("AdminIsGuarded", "CuratorGuardPolicy.AdminIsGuarded.selector"),
    ("ApprovalNotFound", "CuratorGuardPolicy.ApprovalNotFound.selector"),
    ("CouncilCannotApprove", "CuratorGuardPolicy.CouncilCannotApprove.selector"),
    ("DeadlinePassed", "CuratorGuardPolicy.DeadlinePassed.selector"),
    ("InvalidDuration", "CuratorGuardPolicy.InvalidDuration.selector"),
    ("InvalidRule", "CuratorGuardPolicy.InvalidRule.selector"),
    ("InvalidTarget", "CuratorGuardPolicy.InvalidTarget.selector"),
    ("LockdownCooldown", "CuratorGuardPolicy.LockdownCooldown.selector"),
    ("ModuleNotAllowed", "CuratorGuardPolicy.ModuleNotAllowed.selector"),
    ("NoOneOfRule", "CuratorGuardPolicy.NoOneOfRule.selector"),
    ("NotAContract", "CuratorGuardPolicy.NotAContract.selector"),
    ("SafeInBypass", "CuratorGuardPolicy.SafeInBypass.selector"),
    ("TooManyRules", "CuratorGuardPolicy.TooManyRules.selector"),
    ("TooManyValues", "CuratorGuardPolicy.TooManyValues.selector"),
    ("UnboundedLowerBound", "CuratorGuardPolicy.UnboundedLowerBound.selector"),
    ("UnwrapperCodehashNotAllowed", "CuratorGuardPolicy.UnwrapperCodehashNotAllowed.selector"),
    ("ApprovedExecutionFailed", "CuratorGuard.ApprovedExecutionFailed.selector"),
    ("CouncilBypassLimit", "CuratorGuard.CouncilBypassLimit.selector"),
    ("DelegateCallNotAllowed", "CuratorGuard.DelegateCallNotAllowed.selector"),
    ("EmptyMultiSend", "CuratorGuard.EmptyMultiSend.selector"),
    ("FallbackHandlerNotAllowed", "CuratorGuard.FallbackHandlerNotAllowed.selector"),
    ("ForwardedHookCall", "CuratorGuard.ForwardedHookCall.selector"),
    ("FunctionNotAllowed", "CuratorGuard.FunctionNotAllowed.selector"),
    ("GasRefundNotAllowed", "CuratorGuard.GasRefundNotAllowed.selector"),
    ("GuardCallNotAllowed", "CuratorGuard.GuardCallNotAllowed.selector"),
    ("GuardNotInstalled", "CuratorGuard.GuardNotInstalled.selector"),
    ("MalformedCalldata", "CuratorGuard.MalformedCalldata.selector"),
    ("MalformedMultiSend", "CuratorGuard.MalformedMultiSend.selector"),
    ("MissingSnapshot", "CuratorGuard.MissingSnapshot.selector"),
    ("ModuleNotHooked", "CuratorGuard.ModuleNotHooked.selector"),
    ("MultiSendDelegateCallEntry", "CuratorGuard.MultiSendDelegateCallEntry.selector"),
    ("NestedExecution", "CuratorGuard.NestedExecution.selector"),
    ("NativeTransferNotAllowed", "CuratorGuard.NativeTransferNotAllowed.selector"),
    ("SafeConfigChanged", "CuratorGuard.SafeConfigChanged.selector"),
    ("SafeConfigUnreadable", "CuratorGuard.SafeConfigUnreadable.selector"),
    ("SafeLockedDown", "CuratorGuard.SafeLockedDown.selector"),
    ("SafeNotSupported", "CuratorGuard.SafeNotSupported.selector"),
    ("SelfCallNotAllowed", "CuratorGuard.SelfCallNotAllowed.selector"),
    ("ValueNotAllowed", "CuratorGuard.ValueNotAllowed.selector"),
    ("AccessControlUnauthorizedAccount", "IAccessControl.AccessControlUnauthorizedAccount.selector"),
    ("AccessControlBadConfirmation", "IAccessControl.AccessControlBadConfirmation.selector"),
    ("AccessControlEnforcedDefaultAdminRules", "IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminRules.selector"),
    ("AccessControlEnforcedDefaultAdminDelay", "IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminDelay.selector"),
    ("AccessControlInvalidDefaultAdmin", "IAccessControlDefaultAdminRules.AccessControlInvalidDefaultAdmin.selector"),
    ("TimelockUnexpectedOperationState", "TimelockController.TimelockUnexpectedOperationState.selector"),
    ("TimelockUnauthorizedCaller", "TimelockController.TimelockUnauthorizedCaller.selector"),
    ("TimelockInsufficientDelay", "TimelockController.TimelockInsufficientDelay.selector"),
    ("TimelockUnexecutedPredecessor", "TimelockController.TimelockUnexecutedPredecessor.selector"),
    ("FailedCall", "Errors.FailedCall.selector"),
    ("CancellerCannotPropose", "CuratorGuardTimelock.CancellerCannotPropose.selector"),
    ("ForwardedCall", "CuratorGuardTimelock.ForwardedCall.selector"),
    ("DelayOutOfRange", "CuratorGuardTimelock.DelayOutOfRange.selector"),
    ("LastRoleHolder", "CuratorGuardTimelock.LastRoleHolder.selector"),
    ("OpenExecutorRequired", "CuratorGuardTimelock.OpenExecutorRequired.selector"),
    ("ProposerCannotCancel", "CuratorGuardTimelock.ProposerCannotCancel.selector"),
    ("SelfAdminRequired", "CuratorGuardTimelock.SelfAdminRequired.selector"),
    ("SelfHolder", "CuratorGuardTimelock.SelfHolder.selector"),
    ("TargetHasNoCode", "CuratorGuardTimelock.TargetHasNoCode.selector"),
    ("ZeroAddressHolder", "CuratorGuardTimelock.ZeroAddressHolder.selector"),
]
ERR_ID = {name: i for i, (name, _) in enumerate(ERRORS)}

# Event pattern elements: name -> Solidity bytes32 expression. "Evt:Extra" folds one indexed topic.
EVT_SOL = {
    "ModeUpdated": "CuratorGuardPolicy.ModeUpdated.selector",
    "ApprovalsRevoked": "CuratorGuardPolicy.ApprovalsRevoked.selector",
    "ApprovalRevoked": "CuratorGuardPolicy.ApprovalRevoked.selector",
    "ApprovalConsumed": "CuratorGuardPolicy.ApprovalConsumed.selector",
    "TransactionApproved": "CuratorGuardPolicy.TransactionApproved.selector",
    "GuardianUpdated": "CuratorGuardPolicy.GuardianUpdated.selector",
    "RequiredFallbackHandlerUpdated": "CuratorGuardPolicy.RequiredFallbackHandlerUpdated.selector",
    "FunctionAllowed": "CuratorGuardPolicy.FunctionAllowed.selector",
    "FunctionRevoked": "CuratorGuardPolicy.FunctionRevoked.selector",
    "NativeTransferUpdated": "CuratorGuardPolicy.NativeTransferUpdated.selector",
    "AllowedValueAdded": "CuratorGuardPolicy.AllowedValueAdded.selector",
    "AllowedValueRemoved": "CuratorGuardPolicy.AllowedValueRemoved.selector",
    "MultiSendUnwrapperUpdated": "CuratorGuardPolicy.MultiSendUnwrapperUpdated.selector",
    "UnwrapperCodehashUpdated": "CuratorGuardPolicy.UnwrapperCodehashUpdated.selector",
    "ModuleUpdated": "CuratorGuardPolicy.ModuleUpdated.selector",
    "TransactionChecked": "CuratorGuard.TransactionChecked.selector",
    "RoleGranted": "IAccessControl.RoleGranted.selector",
    "RoleRevoked": "IAccessControl.RoleRevoked.selector",
    "DefaultAdminTransferScheduled": "IAccessControlDefaultAdminRules.DefaultAdminTransferScheduled.selector",
    "DefaultAdminTransferCanceled": "IAccessControlDefaultAdminRules.DefaultAdminTransferCanceled.selector",
    "DefaultAdminDelayChangeScheduled": "IAccessControlDefaultAdminRules.DefaultAdminDelayChangeScheduled.selector",
    "DefaultAdminDelayChangeCanceled": "IAccessControlDefaultAdminRules.DefaultAdminDelayChangeCanceled.selector",
    "CallScheduled": "TimelockController.CallScheduled.selector",
    "CallExecuted": "TimelockController.CallExecuted.selector",
    "Cancelled": "TimelockController.Cancelled.selector",
    "MinDelayChange": "TimelockController.MinDelayChange.selector",
    "CallSalt": "TimelockController.CallSalt.selector",
}
EXTRA_SOL = {
    "Lockdown": "bytes32(uint256(CuratorGuardPolicy.Mode.Lockdown))",
    "Enforced": "bytes32(uint256(CuratorGuardPolicy.Mode.Enforced))",
    "Bypass": "bytes32(uint256(CuratorGuardPolicy.Mode.Bypass))",
    "Policy": "bytes32(uint256(CuratorGuard.Outcome.Policy))",
    "Approval": "bytes32(uint256(CuratorGuard.Outcome.Approval))",
    "OutBypass": "bytes32(uint256(CuratorGuard.Outcome.Bypass))",
    "COUNCIL": "keccak256(\"COUNCIL_ROLE\")",
    "GUARDIAN": "keccak256(\"GUARDIAN_ROLE\")",
    "ADMIN": "bytes32(0)",
    "PROPOSER": "keccak256(\"PROPOSER_ROLE\")",
    "CANCELLER": "keccak256(\"CANCELLER_ROLE\")",
    "EXECUTOR": "keccak256(\"EXECUTOR_ROLE\")",
}


def OK(events, doc, note=""):
    return dict(err="OK", events=list(events), doc=doc, note=note)


def R(err, doc, note=""):
    return dict(err=err, events=[], doc=doc, note=note)


# --------------------------------------------------------------------------------------------------
# Gates (the order of checks follows the code; the reference says which document decides the cell)
# --------------------------------------------------------------------------------------------------
def g_admin(c):
    if c.get("fwd"):
        return R("Unauthorized", "D5")
    if not c.get("admin"):
        return R("Unauthorized", "D1,D14")
    return None


def g_admin_or_council(c):
    if c.get("fwd"):
        return R("Unauthorized", "D5")
    if not (c.get("admin") or c.get("council")):
        return R("Unauthorized", "D1,D7")
    return None


def g_admin_or_council_for(c, s, safe):
    """safe in {'A', 'B', 'self', 'zero'}; the Safe argument of the call."""
    if safe == "self" or (safe == "A" and c.get("isA")):
        return R("Unauthorized", "D7", "no role holder acts on itself as a Safe (msg.sender == safe)")
    r = g_admin_or_council(c)
    if r:
        return r
    if c.get("admin") and s["cooldown"]:
        return R("LockdownCooldown", "D2")
    return None


def is_narrower_of(c, safe):
    if c.get("fwd"):
        return False
    if c.get("admin") or c.get("council") or c.get("gD"):
        return True
    if c.get("gA") and safe == "A":
        return True
    return False


def g_narrower(c, safe):
    if c.get("fwd"):
        return R("Unauthorized", "D5")
    if not is_narrower_of(c, safe):
        return R("Unauthorized", "D8,D14,D15")
    return None


def g_global_narrower(c):
    if c.get("fwd"):
        return R("Unauthorized", "D5")
    if not (c.get("admin") or c.get("council") or c.get("gD")):
        return R("Unauthorized", "D8")
    return None


def g_onlyrole_admin(c):
    if c.get("fwd"):
        return R("Unauthorized", "D5")
    if not c.get("admin"):
        return R("AccessControlUnauthorizedAccount", "D1,D18,OZ", "only the admin administers roles; the error name is OpenZeppelin's (not in the docs)")
    return None


def hook_kind(c):
    if c.get("admin"):
        return "admin"
    if c.get("key") == "SAFE_A":
        return "safeA"
    if c.get("key") == "FWD_SAFE_A":
        return "fwdA"
    if c.get("key") in ("FWD_SAFE_A_REQ", "FWD_SAFE_A_REQ_DIRTY"):
        return "fwdAreq"
    if c.get("key") == "FWD_COUNCIL_SAFE":
        return "fwdCouncil"
    return "other"


def in_window(s):
    return s["mode"] == "BYPASS"


def lockdown(s):
    return s["mode"] == "LOCKDOWN"


# --------------------------------------------------------------------------------------------------
# The guard's functions: key, Solidity calldata expression, oracle(class, state)
# --------------------------------------------------------------------------------------------------
F = []


def fn(key, sol, oracle, note="", value=0, target=None):
    F.append(dict(id=len(F), key=key, sol=sol, oracle=oracle, note=note, value=value, target=target))


# --- mode ------------------------------------------------------------------------------------------
fn("lockdown(A)", "abi.encodeCall(g.lockdown, (address(safeA)))",
   lambda c, s: g_narrower(c, "A") or OK(["ModeUpdated:Lockdown"], "D8,D15"))
fn("lockdownAndRevoke(A)", "abi.encodeCall(g.lockdownAndRevoke, (address(safeA)))",
   lambda c, s: g_narrower(c, "A") or OK(["ModeUpdated:Lockdown", "ApprovalsRevoked"], "D8,D15,D19"))
fn("enforce(A)", "abi.encodeCall(g.enforce, (address(safeA)))",
   lambda c, s: g_admin_or_council_for(c, s, "A") or OK(["ModeUpdated:Enforced"], "D1,D2,D7,D15"))
fn("bypass(A, 1 day)", "abi.encodeCall(g.bypass, (address(safeA), uint64(1 days)))",
   lambda c, s: g_admin_or_council_for(c, s, "A") or OK(["ApprovalsRevoked", "ModeUpdated:Bypass"], "D1,D7,D19"))
fn("bypass(A, 30 days)", "abi.encodeCall(g.bypass, (address(safeA), uint64(30 days)))",
   lambda c, s: g_admin_or_council_for(c, s, "A") or (R("InvalidDuration", "D7", "council window at most 7 days") if c.get("council") else OK(["ApprovalsRevoked", "ModeUpdated:Bypass"], "D1")))
fn("bypass(A, 30 minutes)", "abi.encodeCall(g.bypass, (address(safeA), uint64(30 minutes)))",
   lambda c, s: g_admin_or_council_for(c, s, "A") or R("InvalidDuration", "D7,N", "a window of at least 1 hour (MIN_BYPASS)"))
fn("executeBefore(now+30d, lockdown(A))", "abi.encodeCall(g.executeBefore, (uint64(block.timestamp + 30 days), abi.encodeCall(g.lockdown, (address(safeA)))))",
   lambda c, s: g_narrower(c, "A") or OK(["ModeUpdated:Lockdown"], "D11,D8", "executeBefore runs the inner call as the caller"))
fn("executeBefore(now-1, lockdown(A))", "abi.encodeCall(g.executeBefore, (uint64(block.timestamp - 1), abi.encodeCall(g.lockdown, (address(safeA)))))",
   lambda c, s: (R("Unauthorized", "D5", "the forwarded-caller rail runs before the deadline check (G9a-1)") if c.get("fwd") else R("DeadlinePassed", "D11", "only until the deadline, whoever calls")))
# --- guardians / roles -----------------------------------------------------------------------------
fn("setDeploymentGuardian(newKey, true)", "abi.encodeCall(g.setDeploymentGuardian, (newKey, true))",
   lambda c, s: g_admin_or_council(c) or OK(["RoleGranted:GUARDIAN"], "D1,D7,D18"))
fn("setDeploymentGuardian(gD, false)", "abi.encodeCall(g.setDeploymentGuardian, (gD, false))",
   lambda c, s: g_admin_or_council(c) or OK(["RoleRevoked:GUARDIAN"], "D15,D18"))
fn("setDeploymentGuardian(admin, true)", "abi.encodeCall(g.setDeploymentGuardian, (g.defaultAdmin(), true))",
   lambda c, s: g_admin_or_council(c) or R("AdminIsGuarded", "D4", "never the admin"))
fn("setDeploymentGuardian(A, true)", "abi.encodeCall(g.setDeploymentGuardian, (address(safeA), true))",
   lambda c, s: g_admin_or_council(c) or R("AdminIsGuarded", "D4,D14", "never a configured Safe"))
fn("setGuardian(A, newKey, true)", "abi.encodeCall(g.setGuardian, (address(safeA), newKey, true))",
   lambda c, s: g_admin_or_council(c) or OK(["GuardianUpdated"], "D1,D7,D15"))
fn("setGuardian(A, gA, false)", "abi.encodeCall(g.setGuardian, (address(safeA), gA, false))",
   lambda c, s: g_admin_or_council(c) or OK(["GuardianUpdated"], "D15"))
fn("setGuardian(A, admin, true)", "abi.encodeCall(g.setGuardian, (address(safeA), g.defaultAdmin(), true))",
   lambda c, s: g_admin_or_council(c) or OK(["GuardianUpdated"], "U", "per-Safe seats have only the zero / Safe / guard rail (G9b-5 class): the admin is accepted as a per-Safe guardian while setDeploymentGuardian(admin) is AdminIsGuarded"))
fn("setGuardian(A, guard, true)", "abi.encodeCall(g.setGuardian, (address(safeA), address(g), true))",
   lambda c, s: R("InvalidTarget", "N,U", "the target rail runs BEFORE the role check: a stranger is told InvalidTarget, not Unauthorized"))
fn("setRequiredFallbackHandler(A, 0, true)", "abi.encodeCall(g.setRequiredFallbackHandler, (address(safeA), address(0), true))",
   lambda c, s: g_admin(c) or OK(["RequiredFallbackHandlerUpdated"], "D1,D19"))
# --- allowlist ------------------------------------------------------------------------------------
fn("allowFunction(A, P, wrap, value, [])", "abi.encodeCall(g.allowFunction, (address(safeA), address(P), WRAP, true, _noRules()))",
   lambda c, s: g_admin(c) or OK(["FunctionAllowed"], "D1,D14"))
fn("allowFunctions(A, [wrap])", "abi.encodeCall(g.allowFunctions, (address(safeA), _specWrap()))",
   lambda c, s: g_admin(c) or OK(["FunctionAllowed"], "D1,D14"))
fn("revokeFunction(A, P, settle)", "abi.encodeCall(g.revokeFunction, (address(safeA), address(P), SETTLE))",
   lambda c, s: g_narrower(c, "A") or OK(["FunctionRevoked"], "D8,D15"))
fn("revokeTarget(A, P)", "abi.encodeCall(g.revokeTarget, (address(safeA), address(P)))",
   lambda c, s: g_narrower(c, "A") or OK(["FunctionRevoked", "FunctionRevoked"], "D8,D15"))
fn("setNativeTransferAllowed(A, nt2, true)", "abi.encodeCall(g.setNativeTransferAllowed, (address(safeA), nt2, true))",
   lambda c, s: g_admin(c) or OK(["NativeTransferUpdated"], "D1"))
fn("setNativeTransferAllowed(A, nt, false)", "abi.encodeCall(g.setNativeTransferAllowed, (address(safeA), nt, false))",
   lambda c, s: g_narrower(c, "A") or OK(["NativeTransferUpdated"], "D8,N", "emits on every call (NatSpec)"))
fn("addAllowedValues(A, P, deposit, 0, [2])", "abi.encodeCall(g.addAllowedValues, (address(safeA), address(P), DEPOSIT, 0, _vals(2)))",
   lambda c, s: g_admin(c) or OK(["AllowedValueAdded"], "D1"))
fn("removeAllowedValues(A, P, deposit, 0, [1])", "abi.encodeCall(g.removeAllowedValues, (address(safeA), address(P), DEPOSIT, 0, _vals(1)))",
   lambda c, s: g_narrower(c, "A") or OK(["AllowedValueRemoved"], "D8"))
fn("clearAllowedValues(A, P, deposit, 0)", "abi.encodeCall(g.clearAllowedValues, (address(safeA), address(P), DEPOSIT, 0))",
   lambda c, s: g_narrower(c, "A") or OK(["AllowedValueRemoved"], "D8"))
fn("setMultiSendUnwrapper(A, M2, true)", "abi.encodeCall(g.setMultiSendUnwrapper, (address(safeA), address(M2), true))",
   lambda c, s: g_admin(c) or OK(["MultiSendUnwrapperUpdated"], "D1"))
fn("setMultiSendUnwrapper(A, M, false)", "abi.encodeCall(g.setMultiSendUnwrapper, (address(safeA), address(M), false))",
   lambda c, s: g_narrower(c, "A") or OK(["MultiSendUnwrapperUpdated"], "D8"))
fn("setUnwrapperCodehash(h141, true)", "abi.encodeCall(g.setUnwrapperCodehash, (g.codehashV141(), true))",
   lambda c, s: g_admin_or_council(c) or OK(["UnwrapperCodehashUpdated"], "D1,D8"))
fn("setUnwrapperCodehash(h150, false)", "abi.encodeCall(g.setUnwrapperCodehash, (g.codehashV150(), false))",
   lambda c, s: g_global_narrower(c) or OK(["UnwrapperCodehashUpdated"], "D8"))
fn("setModuleAllowed(A, MOD2, true)", "abi.encodeCall(g.setModuleAllowed, (address(safeA), address(MOD2), true))",
   lambda c, s: g_admin(c) or OK(["ModuleUpdated"], "D1"))
fn("setModuleAllowed(A, MOD, false)", "abi.encodeCall(g.setModuleAllowed, (address(safeA), address(MOD), false))",
   lambda c, s: g_narrower(c, "A") or OK(["ModuleUpdated"], "D8"))


# --- approvals ------------------------------------------------------------------------------------
def o_approve(c, s, safe="A", target_bad=None, ttl_bad=None, council_bad=None, module_bad=False, self_safe=False):
    if self_safe and c.get("zero"):
        return R("AddressIsNull", "U", "_nonZero(safe) runs first")
    if self_safe:
        return R("Unauthorized", "D7", "no role holder approves for itself as a Safe")
    r = g_admin_or_council_for(c, s, safe)
    if r:
        return r
    if target_bad:
        return R("InvalidTarget", "D11,D16", target_bad)
    if in_window(s):
        return R("SafeInBypass", "D11", "refused while the Safe is in Bypass")
    if ttl_bad == "long" and c.get("council"):
        return R("InvalidDuration", "D7", "council approvals at most 7 days")
    if ttl_bad == "short":
        return R("InvalidDuration", "D16,N", "ttl at least one hour")
    if council_bad and c.get("council"):
        return R("CouncilCannotApprove", "D7", council_bad)
    if module_bad and c.get("council"):
        return R("ModuleNotAllowed", "D11,N", "a module-bound council approval names an allowlisted module")
    return OK(["TransactionApproved"], "D1,D7,D11,D16")


fn("approveTransaction(A, 0, P, settle(7), 1 day)", "abi.encodeCall(g.approveTransaction, (address(safeA), address(0), address(P), 0, SETTLE7, Operation.Call, uint64(1 days)))",
   lambda c, s: o_approve(c, s))
fn("approveTransaction(A, 0, P, settle(7), 30 days)", "abi.encodeCall(g.approveTransaction, (address(safeA), address(0), address(P), 0, SETTLE7, Operation.Call, uint64(30 days)))",
   lambda c, s: o_approve(c, s, ttl_bad="long"))
fn("approveTransaction(A, 0, P, settle(7), 30 minutes)", "abi.encodeCall(g.approveTransaction, (address(safeA), address(0), address(P), 0, SETTLE7, Operation.Call, uint64(30 minutes)))",
   lambda c, s: o_approve(c, s, ttl_bad="short"))
fn("approveTransaction(A, 0, A, setGuard(0), 1 day)", "abi.encodeCall(g.approveTransaction, (address(safeA), address(0), address(safeA), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call, uint64(1 days)))",
   lambda c, s: o_approve(c, s, council_bad="setGuard is admin-only"))
fn("approveTransaction(A, 0, A, changeThreshold(2), 1 day)", "abi.encodeCall(g.approveTransaction, (address(safeA), address(0), address(safeA), 0, abi.encodeWithSignature(\"changeThreshold(uint256)\", uint256(2)), Operation.Call, uint64(1 days)))",
   lambda c, s: o_approve(c, s))
fn("approveTransaction(A, 0, A, changeThreshold(1), 1 day)", "abi.encodeCall(g.approveTransaction, (address(safeA), address(0), address(safeA), 0, abi.encodeWithSignature(\"changeThreshold(uint256)\", uint256(1)), Operation.Call, uint64(1 days)))",
   lambda c, s: o_approve(c, s, council_bad="never a threshold below 2"))
fn("approveTransaction(caller, 0, P, settle(7), 1 day)", "abi.encodeCall(g.approveTransaction, (_c, address(0), address(P), 0, SETTLE7, Operation.Call, uint64(1 days)))",
   lambda c, s: o_approve(c, s, self_safe=True))
fn("approveTransaction(A, MODX, P, settle(7), 1 day)", "abi.encodeCall(g.approveTransaction, (address(safeA), address(MODX), address(P), 0, SETTLE7, Operation.Call, uint64(1 days)))",
   lambda c, s: o_approve(c, s, module_bad=True))
fn("approveTransaction(A, 0, EOA, 0x12345678, 1 day)", "abi.encodeCall(g.approveTransaction, (address(safeA), address(0), newKey, 0, hex\"12345678\", Operation.Call, uint64(1 days)))",
   lambda c, s: o_approve(c, s, target_bad="never an account without code when calldata is sent"))
fn("approveTransaction(A, 0, guard, lockdown(A), 1 day)", "abi.encodeCall(g.approveTransaction, (address(safeA), address(0), address(g), 0, abi.encodeCall(g.lockdown, (address(safeA))), Operation.Call, uint64(1 days)))",
   lambda c, s: o_approve(c, s, target_bad="never the guard itself"))
fn("revokeApproval(apprA)", "abi.encodeCall(g.revokeApproval, (apprA))",
   lambda c, s: g_narrower(c, "A") or OK(["ApprovalRevoked"], "D16,D19", "a void (epoch-bumped) record is still revocable"))
fn("revokeApproval(apprB)", "abi.encodeCall(g.revokeApproval, (apprB))",
   lambda c, s: g_narrower(c, "B") or OK(["ApprovalRevoked"], "D8,D16"))
fn("revokeApproval(unknown id)", "abi.encodeCall(g.revokeApproval, (bytes32(uint256(0xdead))))",
   lambda c, s: R("ApprovalNotFound", "U", "the existence check runs BEFORE the role check"))
fn("revokeAllApprovals(A)", "abi.encodeCall(g.revokeAllApprovals, (address(safeA)))",
   lambda c, s: g_narrower(c, "A") or OK(["ApprovalsRevoked"], "D8,D16"))
fn("lockdown(caller)", "abi.encodeCall(g.lockdown, (_c))",
   lambda c, s: (R("AddressIsNull", "U", "_nonZero(safe) first") if c.get("zero") else (g_narrower(c, "self") or OK(["ModeUpdated:Lockdown"], "U", "narrowing one's own address is allowed (dead policy); the docs forbid only enforce / bypass / approveTransaction on self"))))
fn("lockdown(B)", "abi.encodeCall(g.lockdown, (address(safeB)))",
   lambda c, s: g_narrower(c, "B") or OK(["ModeUpdated:Lockdown"], "D8,D15"))
# --- OpenZeppelin role surface --------------------------------------------------------------------
fn("grantRole(COUNCIL, newKey)", "abi.encodeCall(g.grantRole, (COUNCIL_ROLE, newKey))",
   lambda c, s: g_onlyrole_admin(c) or OK(["RoleGranted:COUNCIL"], "D1,D18"))
fn("grantRole(GUARDIAN, newKey)", "abi.encodeCall(g.grantRole, (GUARDIAN_ROLE, newKey))",
   lambda c, s: g_onlyrole_admin(c) or OK(["RoleGranted:GUARDIAN"], "D1,D18"))
fn("grantRole(COUNCIL, A)", "abi.encodeCall(g.grantRole, (COUNCIL_ROLE, address(safeA)))",
   lambda c, s: g_onlyrole_admin(c) or R("AdminIsGuarded", "D4,D14,D18"))
fn("grantRole(COUNCIL, admin)", "abi.encodeCall(g.grantRole, (COUNCIL_ROLE, g.defaultAdmin()))",
   lambda c, s: g_onlyrole_admin(c) or R("AdminIsGuarded", "D4,D18"))
fn("grantRole(COUNCIL, 0)", "abi.encodeCall(g.grantRole, (COUNCIL_ROLE, address(0)))",
   lambda c, s: g_onlyrole_admin(c) or R("AddressIsNull", "D4,D18"))
fn("grantRole(DEFAULT_ADMIN, newKey)", "abi.encodeCall(g.grantRole, (bytes32(0), newKey))",
   lambda c, s: R("AccessControlEnforcedDefaultAdminRules", "OZ,U", "OpenZeppelin refuses the admin role in grantRole for EVERY caller, before the role check (the docs say two-step transfer only)"))
fn("revokeRole(COUNCIL, council)", "abi.encodeCall(g.revokeRole, (COUNCIL_ROLE, council))",
   lambda c, s: g_onlyrole_admin(c) or OK(["RoleRevoked:COUNCIL"], "D1,D18"))
fn("revokeRole(GUARDIAN, gD)", "abi.encodeCall(g.revokeRole, (GUARDIAN_ROLE, gD))",
   lambda c, s: g_onlyrole_admin(c) or OK(["RoleRevoked:GUARDIAN"], "D1,D18"))
fn("revokeRole(DEFAULT_ADMIN, admin)", "abi.encodeCall(g.revokeRole, (bytes32(0), g.defaultAdmin()))",
   lambda c, s: R("AccessControlEnforcedDefaultAdminRules", "OZ,U", "as grantRole: refused for every caller before the role check"))


def o_renounce(c, s, role):
    if c.get("fwd"):
        return R("Unauthorized", "D5", "a forwarded stranger must not make a Safe drop its role")
    holds = (role == "COUNCIL" and c.get("council")) or (role == "GUARDIAN" and c.get("gD"))
    if role == "ADMIN" and c.get("admin"):
        return R("AccessControlEnforcedDefaultAdminDelay", "D3,N,OZ", "the renounce path needs a pending transfer to address(0), which AdminCannotBeZero refuses")
    if holds:
        return OK(["RoleRevoked:" + role], "U", "a role holder may renounce its own role (OpenZeppelin); the docs do not say so for the council / guardians")
    return OK([], "U", "renouncing a role one does not hold is a silent no-op (OpenZeppelin)")


fn("renounceRole(COUNCIL, caller)", "abi.encodeCall(g.renounceRole, (COUNCIL_ROLE, _c))", lambda c, s: o_renounce(c, s, "COUNCIL"))
fn("renounceRole(GUARDIAN, caller)", "abi.encodeCall(g.renounceRole, (GUARDIAN_ROLE, _c))", lambda c, s: o_renounce(c, s, "GUARDIAN"))
fn("renounceRole(DEFAULT_ADMIN, caller)", "abi.encodeCall(g.renounceRole, (bytes32(0), _c))", lambda c, s: o_renounce(c, s, "ADMIN"))
fn("renounceRole(COUNCIL, stranger)", "abi.encodeCall(g.renounceRole, (COUNCIL_ROLE, stranger))",
   lambda c, s: (R("Unauthorized", "D5") if c.get("fwd") else (OK([], "U", "the stranger confirms its own address: silent no-op") if c.get("stranger") else R("AccessControlBadConfirmation", "OZ,U", "confirmation must be the caller"))))
fn("beginDefaultAdminTransfer(newKey)", "abi.encodeCall(g.beginDefaultAdminTransfer, (newKey))",
   lambda c, s: g_onlyrole_admin(c) or OK(["DefaultAdminTransferCanceled", "DefaultAdminTransferScheduled"], "D17,OZ", "the pending hand-over to `pend` is implicitly cancelled first (OpenZeppelin)"))
fn("beginDefaultAdminTransfer(0)", "abi.encodeCall(g.beginDefaultAdminTransfer, (address(0)))",
   lambda c, s: g_onlyrole_admin(c) or R("AdminCannotBeZero", "D3,D17"))
fn("beginDefaultAdminTransfer(A)", "abi.encodeCall(g.beginDefaultAdminTransfer, (address(safeA)))",
   lambda c, s: g_onlyrole_admin(c) or R("AdminIsGuarded", "D3,D17"))
fn("beginDefaultAdminTransfer(council)", "abi.encodeCall(g.beginDefaultAdminTransfer, (council))",
   lambda c, s: g_onlyrole_admin(c) or R("AdminIsGuarded", "D3,D17"))
fn("beginDefaultAdminTransfer(guard)", "abi.encodeCall(g.beginDefaultAdminTransfer, (address(g)))",
   lambda c, s: g_onlyrole_admin(c) or OK(["DefaultAdminTransferCanceled", "DefaultAdminTransferScheduled"], "U", "the guard accepts itself as pending admin (G10a-2, held; the docs list zero, the council and a policy-carrying address only)"))
fn("cancelDefaultAdminTransfer()", "abi.encodeCall(g.cancelDefaultAdminTransfer, ())",
   lambda c, s: g_onlyrole_admin(c) or OK(["DefaultAdminTransferCanceled"], "D17"))


def o_accept(c, s):
    # OpenZeppelin's public `acceptDefaultAdminTransfer` checks the caller's identity first; the forwarded-caller
    # rail of `_acceptDefaultAdminTransfer` (G9a-3 / G9c-3, applied after round 13) sits behind it, so only a
    # forwarded Safe that IS the pending admin reaches it (pinned by G9c_Handover and G10f_HeldFixPins).
    if c.get("fwd") and c.get("pending"):
        return R("Unauthorized", "D5", "the acceptance refuses a forwarded caller (G9a-3 / G9c-3, applied after round 13)")
    if c.get("pending"):
        if s["warped"] > 86400:
            return OK(["RoleRevoked:ADMIN", "RoleGranted:ADMIN"], "D17,D19")
        return R("AccessControlEnforcedDefaultAdminDelay", "D17,OZ", "before defaultAdminDelay has passed (error name is OpenZeppelin's)")
    return R("AccessControlInvalidDefaultAdmin", "D17,OZ", "only the pending admin accepts")


fn("acceptDefaultAdminTransfer()", "abi.encodeCall(g.acceptDefaultAdminTransfer, ())", o_accept)
fn("changeDefaultAdminDelay(2 days)", "abi.encodeCall(g.changeDefaultAdminDelay, (uint48(2 days)))",
   lambda c, s: g_onlyrole_admin(c) or OK(["DefaultAdminDelayChangeScheduled"], "D3"))
fn("changeDefaultAdminDelay(31 days)", "abi.encodeCall(g.changeDefaultAdminDelay, (uint48(31 days)))",
   lambda c, s: g_onlyrole_admin(c) or R("AdminDelayTooLong", "D3", "capped at 30 days"))
fn("changeDefaultAdminDelay(1 hour)", "abi.encodeCall(g.changeDefaultAdminDelay, (uint48(1 hours)))",
   lambda c, s: g_onlyrole_admin(c) or R("AdminDelayTooLong", "D3", "floor of 1 day"))
fn("rollbackDefaultAdminDelay()", "abi.encodeCall(g.rollbackDefaultAdminDelay, ())",
   lambda c, s: g_onlyrole_admin(c) or OK([], "U", "nothing pending: a silent no-op"))


# --- hooks, called directly -------------------------------------------------------------------------
def o_pre(c, s, payload):
    """payload in {'allowed', 'approved', 'denied'}."""
    k = hook_kind(c)
    if k == "admin":
        return OK([], "D6", "the admin's hooks return silently")
    if k == "other":
        return R("SafeConfigUnreadable", "D12", "step 3: an account that cannot answer getStorageAt")
    if k == "fwdCouncil":
        return R("GuardNotInstalled", "D12", "step 3: the guard slot of the caller does not name this guard")
    # the guarded Safe A (pranked, or forwarded with the guard as its handler)
    if payload == "approved":
        if in_window(s):
            return OK([], "D12", "step 5: a window records nothing")
        if s["apprLive"]:
            if k in ("fwdA", "fwdAreq"):
                return R("ForwardedHookCall", "D12,D14", "step 7: no approval is spent while the Safe's handler is this guard")
            return OK(["ApprovalConsumed"], "D12", "step 7: the approval is consumed")
        return R("SafeLockedDown", "D11,D12", "the approval was voided by the window's epoch bump; step 8")
    if in_window(s):
        return OK([], "D12", "step 5: admin window checks nothing; council window admits a venue call")
    if lockdown(s):
        return R("SafeLockedDown", "D12,D9", "step 8")
    # Enforced
    if k == "fwdAreq":
        return R("FallbackHandlerNotAllowed", "D12,D20", "step 9: the handler is the guard while the requirement names address(0)")
    if payload == "denied":
        return R("FunctionNotAllowed", "D12,D20", "step 11")
    return OK([], "D12,D14", "steps 9-11 pass; a snapshot is parked (a forwarded pre-hook can only park a transient snapshot, S6)")


def o_post(c, s, via_execute_before=False):
    k = hook_kind(c)
    if k == "admin":
        return OK([], "D6,D13", "nothing is reported for the admin")
    if k in ("fwdCouncil", "fwdA", "fwdAreq") and via_execute_before:
        return R("Unauthorized", "D5,D13", "executeBefore refuses a forwarded caller before it re-dispatches anything (G9a-1, applied after round 13)")
    if k in ("fwdCouncil", "fwdA", "fwdAreq"):
        return R("ForwardedHookCall", "D13", "a forwarded after-hook is not 68 bytes")
    if k in ("safeA", "fwdA", "fwdAreq") and in_window(s):
        return OK(["TransactionChecked:OutBypass"], "D13", "an empty slot is legitimate inside an effective Bypass (G10a-1 note)")
    return R("MissingSnapshot", "D13")


def o_module_pre(c, s):
    k = hook_kind(c)
    if k == "admin":
        return OK([], "D6")
    if k == "other":
        return R("SafeConfigUnreadable", "D12")
    return R("GuardNotInstalled", "D12", "step 3 on the module path: the module-guard slot of a v1.4.1 Safe is empty (before the module allowlist, step 4)")


fn("checkTransaction(P, settle(1), ...)", "abi.encodeCall(g.checkTransaction, (address(P), 0, SETTLE1, Operation.Call, 0, 0, 0, address(0), payable(address(0)), \"\", _c))", lambda c, s: o_pre(c, s, "allowed"))
fn("checkTransaction(P, settle(9) approved, ...)", "abi.encodeCall(g.checkTransaction, (address(P), 0, SETTLE9, Operation.Call, 0, 0, 0, address(0), payable(address(0)), \"\", _c))", lambda c, s: o_pre(c, s, "approved"))
fn("checkTransaction(P, wrap() denied, ...)", "abi.encodeCall(g.checkTransaction, (address(P), 0, abi.encodeCall(MockProtocol.wrap, ()), Operation.Call, 0, 0, 0, address(0), payable(address(0)), \"\", _c))", lambda c, s: o_pre(c, s, "denied"))
fn("checkAfterExecution(h, true)", "abi.encodeCall(g.checkAfterExecution, (bytes32(uint256(0x1234)), true))", lambda c, s: o_post(c, s))
fn("checkModuleTransaction(P, settle(1), MOD)", "abi.encodeCall(g.checkModuleTransaction, (address(P), 0, SETTLE1, Operation.Call, address(MOD)))", o_module_pre)
fn("checkModuleTransaction(P, settle(1), MODX)", "abi.encodeCall(g.checkModuleTransaction, (address(P), 0, SETTLE1, Operation.Call, address(MODX)))", o_module_pre)
fn("checkAfterModuleExecution(h, true)", "abi.encodeCall(g.checkAfterModuleExecution, (bytes32(uint256(0x1234)), true))", lambda c, s: o_post(c, s))
fn("executeBefore(now+30d, checkAfterExecution(h, true))", "abi.encodeCall(g.executeBefore, (uint64(block.timestamp + 30 days), abi.encodeCall(g.checkAfterExecution, (bytes32(uint256(0x1234)), true))))", lambda c, s: o_post(c, s, via_execute_before=True))
fn("executeBefore(now+30d, checkTransaction(P, settle(9) approved))", "abi.encodeCall(g.executeBefore, (uint64(block.timestamp + 30 days), abi.encodeCall(g.checkTransaction, (address(P), 0, SETTLE9, Operation.Call, 0, 0, 0, address(0), payable(address(0)), \"\", _c))))", lambda c, s: (R("Unauthorized", "D5", "executeBefore refuses a forwarded caller first (G9a-1, applied after round 13)") if c.get("fwd") else o_pre(c, s, "approved")))


# --- dry runs (views; the class only matters through the handler state of Safe A) --------------------
def handler_is_guard(c):
    return c.get("handlerGuard") is True


def o_validate(c, s, payload, module=None):
    if module == "MODX":
        return R("ModuleNotAllowed", "D12", "step 4, in every mode")
    if payload == "approved":
        if in_window(s):
            return OK([], "D12")
        if s["apprLive"]:
            if handler_is_guard(c):
                return R("ForwardedHookCall", "D12", "the dry run reports what the hook would do: no approval while the handler is the guard")
            return OK([], "D12", "the dry run never consumes")
        return R("SafeLockedDown", "D11,D12")
    if in_window(s) and (module is None or s["window"] == "admin"):
        return OK([], "D12", "step 5")
    if lockdown(s):
        return R("SafeLockedDown", "D12")
    # Enforced, or the module path inside a council window (held to the policy)
    if c.get("req") and handler_is_guard(c):
        return R("FallbackHandlerNotAllowed", "D12")
    if payload == "denied":
        return R("FunctionNotAllowed", "D12")
    return OK([], "D12")


fn("validateTransaction(A, P, settle(1))", "abi.encodeCall(g.validateTransaction, (address(safeA), address(P), 0, SETTLE1, Operation.Call))", lambda c, s: o_validate(c, s, "allowed"))
fn("validateTransaction(A, P, settle(9) approved)", "abi.encodeCall(g.validateTransaction, (address(safeA), address(P), 0, SETTLE9, Operation.Call))", lambda c, s: o_validate(c, s, "approved"))
fn("validateTransaction(A, P, wrap() denied)", "abi.encodeCall(g.validateTransaction, (address(safeA), address(P), 0, abi.encodeCall(MockProtocol.wrap, ()), Operation.Call))", lambda c, s: o_validate(c, s, "denied"))
fn("validateModuleTransaction(A, MOD, P, settle(1))", "abi.encodeCall(g.validateModuleTransaction, (address(safeA), address(MOD), address(P), 0, SETTLE1, Operation.Call))", lambda c, s: o_validate(c, s, "allowed", module="MOD"))
fn("validateModuleTransaction(A, MODX, P, settle(1))", "abi.encodeCall(g.validateModuleTransaction, (address(safeA), address(MODX), address(P), 0, SETTLE1, Operation.Call))", lambda c, s: o_validate(c, s, "allowed", module="MODX"))
# --- value to the guard, zero Safe arguments --------------------------------------------------------
fn("send 1 wei to the guard (empty calldata)", "bytes(\"\")", lambda c, s: R("EMPTY", "S6 L798", "no receive(): a plain transfer reverts (so ETH is refused, not stuck; only forced ETH is stuck)"), value=1, target="guard")
fn("enforce(0)", "abi.encodeCall(g.enforce, (address(0)))", lambda c, s: R("AddressIsNull", "U", "_nonZero(safe) runs before the role check: every caller sees AddressIsNull"))
fn("lockdown(0)", "abi.encodeCall(g.lockdown, (address(0)))", lambda c, s: R("AddressIsNull", "U", "same ordering"))
fn("revokeFunction(0, P, settle)", "abi.encodeCall(g.revokeFunction, (address(0), address(P), SETTLE))",
   lambda c, s: g_narrower(c, "zero") or OK([], "U", "Safe 0 carries nothing: a silent no-op for a global narrower"))
fn("setGuardian(0, newKey, true)", "abi.encodeCall(g.setGuardian, (address(0), newKey, true))", lambda c, s: R("AddressIsNull", "N,U", "never the zero Safe; before the role check"))
fn("allowFunction(0, P, wrap, value, [])", "abi.encodeCall(g.allowFunction, (address(0), address(P), WRAP, true, _noRules()))",
   lambda c, s: g_admin(c) or R("AddressIsNull", "N,U", "no function can be allowed for Safe 0"))
fn("approveTransaction(0, 0, P, settle(7), 1 day)", "abi.encodeCall(g.approveTransaction, (address(0), address(0), address(P), 0, SETTLE7, Operation.Call, uint64(1 days)))", lambda c, s: R("AddressIsNull", "U", "_nonZero(safe) first"))
fn("setNativeTransferAllowed(0, nt2, true)", "abi.encodeCall(g.setNativeTransferAllowed, (address(0), nt2, true))",
   lambda c, s: g_admin(c) or R("AddressIsNull", "U"))
fn("setNativeTransferAllowed(0, nt, false)", "abi.encodeCall(g.setNativeTransferAllowed, (address(0), nt, false))",
   lambda c, s: g_narrower(c, "zero") or R("AddressIsNull", "U"))

assert len(F) == 95, len(F)

# --------------------------------------------------------------------------------------------------
# Hooks through real Safe transactions: paths x payloads x states
# --------------------------------------------------------------------------------------------------
PATHS = [
    dict(id=0, key="OWNER_A_v141", label="owner-signed path of Safe A (v1.4.1), executed by anyone with the curator's signature"),
    dict(id=1, key="MODULE_B_ALLOWED", label="module path of Safe B (v1.5.0) driven by the allowlisted module"),
    dict(id=2, key="MODULE_B_OTHER", label="module path of Safe B (v1.5.0) driven by a module that is not allowlisted"),
]
PAYLOADS = [
    dict(id=0, key="venue call allowed: P.settleDeposit(1)"),
    dict(id=1, key="venue call not allowed: P.wrap()"),
    dict(id=2, key="self-call: setGuard(0)"),
    dict(id=3, key="empty zero-value self-call (Safe{Wallet} rejection)"),
    dict(id=4, key="call into the guard: lockdown(safe)"),
    dict(id=5, key="delegatecall into the registered MultiSendCallOnly: [settleDeposit(1), settleDeposit(1)]"),
    dict(id=6, key="approved payload: P.settleDeposit(9)"),
    dict(id=7, key="delegatecall into an unregistered MultiSendCallOnly copy"),
    dict(id=8, key="allowed venue call with gasPrice = 1 (refund to the curator)"),
]


def o_hook(path, k, s):
    P_OK = OK(["TransactionChecked:Policy"], "D12,D13")
    B_OK = OK(["TransactionChecked:OutBypass"], "D12,D13")
    A_OK = OK(["ApprovalConsumed", "TransactionChecked:Approval"], "D12,D13")
    if path == 2:
        return R("ModuleNotAllowed", "D12", "step 4: a module off the allowlist does nothing in any mode, windows included")
    if path == 1 and k == 8:
        k = 0  # a module transaction carries no gas price
    council_window_relaxes = in_window(s) and (s["window"] == "admin" or path == 0)
    if k == 8 and not (in_window(s) and s["window"] == "admin" and path == 0):
        return R("GasRefundNotAllowed", "D12", "step 6, also inside a council window and before the Lockdown check")
    if in_window(s) and s["window"] == "admin":
        if k == 4:
            return R("GuardCallNotAllowed", "D12", "the guard is never a call target, admin window included")
        return B_OK
    if in_window(s) and path == 0:  # council window, owner path
        if k == 2:
            return R("CouncilBypassLimit", "D12,D20", "a self-call outside the council's allowlist")
        if k == 4:
            return R("GuardCallNotAllowed", "D12")
        if k == 7:
            return R("DelegateCallNotAllowed", "D12", "delegatecalls only to a registered MultiSendCallOnly")
        return B_OK
    # Lockdown, Enforced, or the module path inside a council window (policy)
    if k == 6 and s["apprLive"] and not in_window(s):
        return A_OK
    if lockdown(s):
        return R("SafeLockedDown", "D12,D9,D20", "step 8" + ("; the approval was voided by the window's epoch bump" if k == 6 else ""))
    if k == 0 or k == 3 or k == 5:
        return P_OK
    if k == 6:
        return OK(["TransactionChecked:Policy"], "D12", "the council window voided the approval; the module path is under the policy, where settleDeposit(9) is allowed")
    if k == 1:
        return R("FunctionNotAllowed", "D12,D20")
    if k == 2:
        return R("SelfCallNotAllowed", "D12,D20")
    if k == 4:
        return R("GuardCallNotAllowed", "D12,D20")
    if k == 7:
        return R("DelegateCallNotAllowed", "D12,D20")
    raise AssertionError((path, k, s))


# --------------------------------------------------------------------------------------------------
# The timelock surface
# --------------------------------------------------------------------------------------------------
TCLASSES = [
    dict(id=0, key="PROPOSER", label="a proposer (EOA)", sender="p1", target="address(tl)", eff="p1", proposer=True),
    dict(id=1, key="CANCELLER", label="the veto Safe's key (canceller, EOA)", sender="veto", target="address(tl)", eff="veto", canceller=True),
    dict(id=2, key="TIMELOCK_SELF", label="the timelock itself (a scheduled self-call; pranked)", sender="address(tl)", target="address(tl)", eff="address(tl)", self=True),
    dict(id=3, key="STRANGER", label="a stranger (EOA)", sender="stranger", target="address(tl)", eff="stranger"),
    dict(id=4, key="ZERO", label="address(0)", sender="address(0)", target="address(tl)", eff="address(0)", zero=True),
    dict(id=5, key="FWD_PROPOSER_SAFE", label="a proposer Safe whose fallback handler is the timelock (forwarded)", sender="stranger", target="address(fwdPropSafe)", eff="address(fwdPropSafe)", fwd=True, proposer=True),
    dict(id=6, key="FWD_CANCELLER_SAFE", label="a canceller Safe whose fallback handler is the timelock (forwarded)", sender="stranger", target="address(fwdCancSafe)", eff="address(fwdCancSafe)", fwd=True, canceller=True),
    dict(id=7, key="GUARD", label="the guard contract (pranked)", sender="address(guard)", target="address(tl)", eff="address(guard)"),
    dict(id=8, key="SAFE_A", label="the guarded Safe A (pranked)", sender="address(safeA)", target="address(tl)", eff="address(safeA)"),
]
TF = []


def tfn(key, sol, oracle, value=0):
    TF.append(dict(id=len(TF), key=key, sol=sol, oracle=oracle, value=value))


def tg_role(c, role):
    if c.get("fwd"):
        return R("ForwardedCall", "D5,T1")
    if role == "PROPOSER" and not c.get("proposer"):
        return R("AccessControlUnauthorizedAccount", "T1,OZ")
    if role == "CANCELLER" and not c.get("canceller"):
        return R("AccessControlUnauthorizedAccount", "T1,OZ")
    if role == "ADMIN" and not c.get("self"):
        return R("AccessControlUnauthorizedAccount", "T1,OZ", "role management is a scheduled self-call: only the timelock itself")
    return None


tfn("schedule(P.settle(1), delay = minDelay)", "abi.encodeCall(tl.schedule, (address(P), 0, SETTLE1, bytes32(0), bytes32(uint256(777)), tl.getMinDelay()))",
    lambda c: tg_role(c, "PROPOSER") or OK(["CallScheduled", "CallSalt"], "T1,OZ", "CallSalt follows for a non-zero salt (OpenZeppelin)"))
tfn("schedule(P.settle(1), delay = 30 days)", "abi.encodeCall(tl.schedule, (address(P), 0, SETTLE1, bytes32(0), bytes32(uint256(778)), uint256(30 days)))",
    lambda c: tg_role(c, "PROPOSER") or R("DelayOutOfRange", "T1", "an operation delay other than the live getMinDelay()"))
tfn("schedule(P.settle(1), delay = minDelay - 1)", "abi.encodeCall(tl.schedule, (address(P), 0, SETTLE1, bytes32(0), bytes32(uint256(779)), tl.getMinDelay() - 1))",
    lambda c: tg_role(c, "PROPOSER") or R("TimelockInsufficientDelay", "T1,OZ", "the base refuses a shorter one"))
tfn("schedule(EOA target with calldata)", "abi.encodeCall(tl.schedule, (newKey, 0, SETTLE1, bytes32(0), bytes32(uint256(780)), tl.getMinDelay()))",
    lambda c: tg_role(c, "PROPOSER") or R("TargetHasNoCode", "T1"))
tfn("schedule(tl.updateDelay(31 days))", "abi.encodeCall(tl.schedule, (address(tl), 0, abi.encodeCall(tl.updateDelay, (uint256(31 days))), bytes32(0), bytes32(uint256(781)), tl.getMinDelay()))",
    lambda c: tg_role(c, "PROPOSER") or R("DelayOutOfRange", "T1", "an updateDelay outside the clamp is refused when proposed"))
tfn("schedule(tl.updateDelay(2 hours))", "abi.encodeCall(tl.schedule, (address(tl), 0, abi.encodeCall(tl.updateDelay, (uint256(2 hours))), bytes32(0), bytes32(uint256(782)), tl.getMinDelay()))",
    lambda c: tg_role(c, "PROPOSER") or R("DelayOutOfRange", "T1", "an updateDelay below the one-day floor is refused when proposed (G13f-3, applied after round 13)"))
tfn("schedule(tl.updateDelay(1 day))", "abi.encodeCall(tl.schedule, (address(tl), 0, abi.encodeCall(tl.updateDelay, (uint256(1 days))), bytes32(0), bytes32(uint256(784)), tl.getMinDelay()))",
    lambda c: tg_role(c, "PROPOSER") or OK(["CallScheduled", "CallSalt"], "T1,OZ", "the floor itself is inside the clamp"))
tfn("scheduleBatch([P.settle(1)], delay = minDelay)", "abi.encodeCall(tl.scheduleBatch, (_one(address(P)), _one(uint256(0)), _one(SETTLE1), bytes32(0), bytes32(uint256(783)), tl.getMinDelay()))",
    lambda c: tg_role(c, "PROPOSER") or OK(["CallScheduled", "CallSalt"], "T1,OZ"))
tfn("execute(ready operation)", "abi.encodeCall(tl.execute, (address(P), 0, SETTLE2, bytes32(0), bytes32(uint256(2))))",
    lambda c: OK(["CallExecuted"], "T1", "the executor role is open: anyone lands a ready operation"))
tfn("execute(waiting operation)", "abi.encodeCall(tl.execute, (address(P), 0, SETTLE4, bytes32(0), bytes32(uint256(4))))",
    lambda c: R("TimelockUnexpectedOperationState", "T1,OZ", "not ready yet"))
tfn("execute(done operation)", "abi.encodeCall(tl.execute, (address(P), 0, SETTLE3, bytes32(0), bytes32(uint256(3))))",
    lambda c: R("TimelockUnexpectedOperationState", "T1,OZ"))
tfn("executeBatch([ready operation])", "abi.encodeCall(tl.executeBatch, (_one(address(P)), _one(uint256(0)), _one(SETTLE5), bytes32(0), bytes32(uint256(5))))",
    lambda c: OK(["CallExecuted"], "T1"))
tfn("cancel(waiting operation)", "abi.encodeCall(tl.cancel, (_opWaiting()))",
    lambda c: tg_role(c, "CANCELLER") or OK(["Cancelled"], "T1"))
tfn("cancel(done operation)", "abi.encodeCall(tl.cancel, (_opDone()))",
    lambda c: tg_role(c, "CANCELLER") or R("TimelockUnexpectedOperationState", "T1,OZ"))
tfn("updateDelay(2 hours)", "abi.encodeCall(tl.updateDelay, (uint256(2 hours)))",
    lambda c: (OK(["MinDelayChange"], "T1") if c.get("self") else R("TimelockUnauthorizedCaller", "T1,OZ", "updateDelay only as a scheduled self-call")))
tfn("grantRole(PROPOSER, newKey)", "abi.encodeCall(tl.grantRole, (PROPOSER_ROLE, newKey))",
    lambda c: tg_role(c, "ADMIN") or OK(["RoleGranted:PROPOSER"], "T1"))
tfn("grantRole(CANCELLER, p1)", "abi.encodeCall(tl.grantRole, (CANCELLER_ROLE, p1))",
    lambda c: tg_role(c, "ADMIN") or R("ProposerCannotCancel", "T1"))
tfn("grantRole(PROPOSER, veto)", "abi.encodeCall(tl.grantRole, (PROPOSER_ROLE, veto))",
    lambda c: tg_role(c, "ADMIN") or R("CancellerCannotPropose", "T1"))
tfn("grantRole(PROPOSER, 0)", "abi.encodeCall(tl.grantRole, (PROPOSER_ROLE, address(0)))",
    lambda c: tg_role(c, "ADMIN") or R("ZeroAddressHolder", "T1"))
tfn("grantRole(PROPOSER, tl)", "abi.encodeCall(tl.grantRole, (PROPOSER_ROLE, address(tl)))",
    lambda c: tg_role(c, "ADMIN") or R("SelfHolder", "T1"))
tfn("grantRole(DEFAULT_ADMIN, newKey)", "abi.encodeCall(tl.grantRole, (bytes32(0), newKey))",
    lambda c: tg_role(c, "ADMIN") or R("SelfAdminRequired", "T1"))
tfn("grantRole(EXECUTOR, newKey)", "abi.encodeCall(tl.grantRole, (EXECUTOR_ROLE, newKey))",
    lambda c: tg_role(c, "ADMIN") or OK(["RoleGranted:EXECUTOR"], "U", "a named executor next to the open one is accepted; the docs only say the executor role is open"))
tfn("revokeRole(EXECUTOR, 0)", "abi.encodeCall(tl.revokeRole, (EXECUTOR_ROLE, address(0)))",
    lambda c: tg_role(c, "ADMIN") or R("OpenExecutorRequired", "T1"))
tfn("revokeRole(DEFAULT_ADMIN, tl)", "abi.encodeCall(tl.revokeRole, (bytes32(0), address(tl)))",
    lambda c: tg_role(c, "ADMIN") or R("SelfAdminRequired", "T1"))
tfn("revokeRole(CANCELLER, veto) [veto is one of two cancellers]", "abi.encodeCall(tl.revokeRole, (CANCELLER_ROLE, veto))",
    lambda c: tg_role(c, "ADMIN") or OK(["RoleRevoked:CANCELLER"], "T1", "two cancellers in this fixture (the forwarded canceller Safe is the other)"))
tfn("revokeRole(PROPOSER, p1)", "abi.encodeCall(tl.revokeRole, (PROPOSER_ROLE, p1))",
    lambda c: tg_role(c, "ADMIN") or OK(["RoleRevoked:PROPOSER"], "T1"))


def to_renounce(c, role):
    if c.get("fwd"):
        return R("ForwardedCall", "D5,T1")
    if role == "PROPOSER" and c.get("proposer"):
        return OK(["RoleRevoked:PROPOSER"], "T1,U", "a proposer may renounce while another remains")
    if role == "CANCELLER" and c.get("canceller"):
        return OK(["RoleRevoked:CANCELLER"], "T1,U", "two cancellers in this fixture")
    if role == "EXECUTOR" and c.get("zero"):
        return R("OpenExecutorRequired", "T1", "the open executor cannot be dropped, not even by address(0) renouncing")
    return OK([], "U", "renouncing a role one does not hold is a silent no-op (OpenZeppelin)")


tfn("renounceRole(PROPOSER, caller)", "abi.encodeCall(tl.renounceRole, (PROPOSER_ROLE, _c))", lambda c: to_renounce(c, "PROPOSER"))
tfn("renounceRole(CANCELLER, caller)", "abi.encodeCall(tl.renounceRole, (CANCELLER_ROLE, _c))", lambda c: to_renounce(c, "CANCELLER"))
tfn("renounceRole(EXECUTOR, caller)", "abi.encodeCall(tl.renounceRole, (EXECUTOR_ROLE, _c))", lambda c: to_renounce(c, "EXECUTOR"))
tfn("send 1 wei (receive)", "bytes(\"\")", lambda c: OK([], "U", "the timelock accepts ETH from anyone (OpenZeppelin receive()); a proposer can schedule it out"), value=1)
tfn("onERC721Received", "abi.encodeCall(tl.onERC721Received, (stranger, stranger, 1, \"\"))", lambda c: OK([], "U", "OpenZeppelin ERC721Holder: answers anyone"))
tfn("onERC1155Received", "abi.encodeCall(tl.onERC1155Received, (stranger, stranger, 1, 1, \"\"))", lambda c: OK([], "U", "OpenZeppelin ERC1155Holder: answers anyone"))
assert len(TF) == 32, len(TF)

# --------------------------------------------------------------------------------------------------
# Expectation tables
# --------------------------------------------------------------------------------------------------
PATTERNS = []
PAT_ID = {}


def pat(events):
    k = tuple(events)
    if k not in PAT_ID:
        PAT_ID[k] = len(PATTERNS)
        PATTERNS.append(k)
    return PAT_ID[k]


expected = dict(docs=DOCS, classes=[dict(id=c["id"], key=c["key"], label=c["label"]) for c in CLASSES],
                states=[dict(id=s["id"], key=s["key"]) for s in STATES],
                functions=[dict(id=f["id"], key=f["key"]) for f in F],
                tclasses=[dict(id=c["id"], key=c["key"], label=c["label"]) for c in TCLASSES],
                tfunctions=[dict(id=f["id"], key=f["key"]) for f in TF],
                paths=PATHS, payloads=PAYLOADS, cells=[])
guard_tables = {}
for c in CLASSES:
    table = []
    for f in F:
        for s in STATES:
            e = f["oracle"](c, s)
            table.append((ERR_ID[e["err"]], pat(e["events"])))
            expected["cells"].append(dict(suite="G", c=c["id"], f=f["id"], s=s["id"], err=e["err"], events=e["events"], doc=e["doc"], note=e["note"]))
    guard_tables[c["id"]] = table
hook_table = []
for p in PATHS:
    for k in PAYLOADS:
        for s in STATES:
            e = o_hook(p["id"], k["id"], s)
            hook_table.append((ERR_ID[e["err"]], pat(e["events"])))
            expected["cells"].append(dict(suite="H", c=p["id"], f=k["id"], s=s["id"], err=e["err"], events=e["events"], doc=e["doc"], note=e["note"]))
tl_tables = {}
for c in TCLASSES:
    table = []
    for f in TF:
        e = f["oracle"](c)
        table.append((ERR_ID[e["err"]], pat(e["events"])))
        expected["cells"].append(dict(suite="T", c=c["id"], f=f["id"], s=0, err=e["err"], events=e["events"], doc=e["doc"], note=e["note"]))
    tl_tables[c["id"]] = table
# the admin cells of S3 through a real timelock (suite V): same oracle as class 0, state 3
via_table = []
for f in F:
    e = f["oracle"](CLASSES[0], STATES[3])
    via_table.append((ERR_ID[e["err"]], pat(e["events"])))
    expected["cells"].append(dict(suite="V", c=0, f=f["id"], s=3, err=e["err"], events=e["events"], doc=e["doc"], note=e["note"]))
expected["patterns"] = [list(p) for p in PATTERNS]
assert len(PATTERNS) < 250

with open(os.path.join(OUT, "expected.json"), "w") as fh:
    json.dump(expected, fh, indent=1)


def hexbytes(table):
    return "".join("%02x%02x" % (a, b) for a, b in table)


# --------------------------------------------------------------------------------------------------
# Solidity emission
# --------------------------------------------------------------------------------------------------
HEADER = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

// GENERATED by test/guards/matrix/gen_matrix.py (review round 12, lens g12e: access control,
// exhaustively). Do not edit by hand: regenerate.

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";
import {MultiSendCallOnly} from "safe-contracts-v1.4.1/contracts/libraries/MultiSendCallOnly.sol";
import {Safe as Safe150} from "safe-contracts-v1.5.0/contracts/Safe.sol";
import {SafeProxy as SafeProxy150} from "safe-contracts-v1.5.0/contracts/proxies/SafeProxy.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IAccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/IAccessControlDefaultAdminRules.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {Errors} from "@openzeppelin/contracts/utils/Errors.sol";
import {Vm} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {CuratorGuardTimelock} from "contracts/guards/CuratorGuardTimelock.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";
"""

BASE_IMPORT = """
import {G12eMatrixBase, G12eModule} from "test/guards/G12e_MatrixBase.sol";
"""


def emit_err_sel():
    lines = ["    function _errSel(uint8 e_) internal pure returns (bytes4) {", "        if (e_ == 0) return bytes4(0);", "        if (e_ == 1) return bytes4(0xffffffff);"]
    for i, (name, sol) in enumerate(ERRORS):
        if sol:
            lines.append("        if (e_ == %d) return %s;" % (i, sol))
    lines.append("        revert(\"unknown error id\");")
    lines.append("    }")
    return "\n".join(lines)


def emit_pattern_hash():
    lines = ["    function _patternHash(uint8 p_) internal pure returns (bytes32 _h) {"]
    for i, p in enumerate(PATTERNS):
        body = []
        for el in p:
            if ":" in el:
                ev, extra = el.split(":")
                body.append("_h = keccak256(abi.encodePacked(_h, %s, %s));" % (EVT_SOL[ev], EXTRA_SOL[extra]))
            else:
                body.append("_h = keccak256(abi.encodePacked(_h, %s));" % EVT_SOL[el])
        lines.append("        if (p_ == %d) { %s return _h; }" % (i, " ".join(body)))
    lines.append("        revert(\"unknown pattern id\");")
    lines.append("    }")
    return "\n".join(lines)


def emit_calldata(funcs, name="_calldata"):
    lines = ["    function %s(uint8 f_, address _c) internal view returns (bytes memory) {" % name]
    for f in funcs:
        lines.append("        if (f_ == %d) return %s;" % (f["id"], f["sol"]))
    lines.append("        revert(\"unknown function id\");")
    lines.append("    }")
    return "\n".join(lines)


BASE_BODY = r'''
/// @dev Minimal Safe module: whoever calls `exec` makes the Safe execute the payload (as in the module suite).
contract G12eModule {
    function exec(ISafe safe_, address to_, uint256 value_, bytes calldata data_, Operation op_) external returns (bool) {
        return safe_.execTransactionFromModule(to_, value_, data_, op_);
    }
}

/// @title G12eMatrixBase: the fixture and the cell runner of the access-control matrix.
/// @dev Real Safe v1.4.1 (A, the guard installed through a genuine execTransaction) and v1.5.0 (B, guard and
///      module guard, two enabled modules), a council Safe whose fallback handler is the guard, a configured
///      policy for A and B, live approvals, a pending admin hand-over. Every cell runs from a state snapshot
///      and is reverted afterwards, so cells never influence each other.
abstract contract G12eMatrixBase is SafeTxHelper {
    CuratorGuardHarness internal guard;
    CuratorGuardHarness internal g; // the guard under test (`guard`, or `guardT` behind a real timelock)
    Safe internal singleton141;
    Safe150 internal singleton150;
    ISafe internal safeA;
    ISafe internal safeB;
    ISafe internal councilSafe;
    MockProtocol internal P;
    MultiSendCallOnly internal M;
    MultiSendCallOnly internal M2;
    G12eModule internal MOD;
    G12eModule internal MODX;
    G12eModule internal MOD2;

    address internal vetro = makeAddr("g12e-admin");
    address internal council = makeAddr("g12e-council");
    address internal gA = makeAddr("g12e-guardian-of-A");
    address internal gD = makeAddr("g12e-deployment-guardian");
    address internal stranger = makeAddr("g12e-stranger");
    address internal pend = makeAddr("g12e-pending-admin");
    address internal newKey = makeAddr("g12e-new-key");
    address internal nt = makeAddr("g12e-native-target");
    address internal nt2 = makeAddr("g12e-native-target-2");
    address internal curatorA;
    address internal curatorB;
    uint256 internal pkA;
    uint256 internal pkB;
    bytes32 internal apprA;
    bytes32 internal apprB;
    uint256 internal T0;

    bytes32 internal constant COUNCIL_ROLE = keccak256("COUNCIL_ROLE");
    bytes32 internal constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 internal constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes4 internal constant SETTLE = MockProtocol.settleDeposit.selector;
    bytes4 internal constant DEPOSIT = MockProtocol.deposit.selector;
    bytes4 internal constant WRAP = MockProtocol.wrap.selector;
    bytes internal SETTLE1 = abi.encodeCall(MockProtocol.settleDeposit, (1));
    bytes internal SETTLE7 = abi.encodeCall(MockProtocol.settleDeposit, (7));
    bytes internal SETTLE9 = abi.encodeCall(MockProtocol.settleDeposit, (9));

    function setUp() public virtual {
        vm.warp(1_700_000_000);
        T0 = block.timestamp;
        (curatorA, pkA) = makeAddrAndKey("g12e-curator-A");
        (curatorB, pkB) = makeAddrAndKey("g12e-curator-B");
        singleton141 = new Safe();
        singleton150 = new Safe150();
        guard = new CuratorGuardHarness(1 days, vetro, council);
        g = guard;
        P = new MockProtocol();
        M = new MultiSendCallOnly();
        M2 = new MultiSendCallOnly();
        MOD = new G12eModule();
        MODX = new G12eModule();
        MOD2 = new G12eModule();
        guard.seedCodehash(address(M).codehash);
        // Safe A: v1.4.1, the guard installed through a genuine owner-signed execTransaction.
        safeA = _newSafe141(curatorA, address(0));
        guard.seedSafe(address(safeA));
        safe = safeA;
        signerPk = pkA;
        _execSafeTx(address(safeA), 0, abi.encodeCall(ISafe.setGuard, (address(guard))), Operation.Call);
        // The council Safe: v1.4.1 with the guard as its fallback handler (the state every rail refuses).
        councilSafe = _newSafe141(makeAddr("g12e-council-safe-owner"), address(guard));
        // Safe B: v1.5.0, two modules enabled, the guard as guard and module guard (self-authorized calls
        // impersonating the Safe, equivalent to pre-guard execTransactions).
        safeB = _newSafe150(curatorB);
        guard.seedSafe(address(safeB));
        vm.startPrank(address(safeB));
        safeB.enableModule(address(MOD));
        safeB.enableModule(address(MODX));
        safeB.setModuleGuard(address(guard));
        safeB.setGuard(address(guard));
        vm.stopPrank();
        vm.deal(address(safeA), 10 ether);
        vm.deal(address(safeB), 10 ether);
        _configure(guard);
        address[9] memory _funded = [vetro, council, gA, gD, stranger, pend, address(MOD), address(MODX), address(0)];
        for (uint256 i; i < _funded.length; ++i) vm.deal(_funded[i], 1 ether);
    }

    /// @dev The policy of A and B, the responders, the approvals and the pending hand-over, on `guard_`
    ///      (whose admin impersonated here is `guard_.defaultAdmin()`).
    function _configure(CuratorGuardHarness guard_) internal {
        address _admin = guard_.defaultAdmin();
        vm.startPrank(_admin);
        guard_.allowFunction(address(safeA), address(P), SETTLE, false, _noRules());
        guard_.allowFunction(address(safeA), address(P), DEPOSIT, false, _oneOf0());
        guard_.addAllowedValues(address(safeA), address(P), DEPOSIT, 0, _vals(1));
        guard_.setNativeTransferAllowed(address(safeA), nt, true);
        guard_.setMultiSendUnwrapper(address(safeA), address(M), true);
        guard_.setModuleAllowed(address(safeA), address(MOD), true);
        guard_.setGuardian(address(safeA), gA, true);
        guard_.setDeploymentGuardian(gD, true);
        guard_.grantRole(COUNCIL_ROLE, address(councilSafe));
        guard_.setUnwrapperCodehash(guard_.codehashV141(), false);
        apprA = guard_.approveTransaction(address(safeA), address(0), address(P), 0, SETTLE9, Operation.Call, uint64(7 days));
        guard_.allowFunction(address(safeB), address(P), SETTLE, false, _noRules());
        guard_.setModuleAllowed(address(safeB), address(MOD), true);
        guard_.setMultiSendUnwrapper(address(safeB), address(M), true);
        apprB = guard_.approveTransaction(address(safeB), address(MOD), address(P), 0, SETTLE9, Operation.Call, uint64(7 days));
        guard_.beginDefaultAdminTransfer(pend);
        vm.stopPrank();
    }

    function _newSafe141(address owner_, address handler_) internal returns (ISafe) {
        SafeProxy _proxy = new SafeProxy(address(singleton141));
        address[] memory _owners = new address[](1);
        _owners[0] = owner_;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", handler_, address(0), 0, payable(address(0)));
        return ISafe(address(_proxy));
    }

    function _newSafe150(address owner_) internal returns (ISafe) {
        SafeProxy150 _proxy = new SafeProxy150(address(singleton150));
        address[] memory _owners = new address[](1);
        _owners[0] = owner_;
        Safe150(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
        return ISafe(address(_proxy));
    }

    /*//////////////////////////////////////////////////////////////
                                STATES
    //////////////////////////////////////////////////////////////*/

    /// @dev S0 fresh Lockdown; S1 Lockdown inside the cooldown; S2 Lockdown after the cooldown (+1 d +1 s);
    ///      S3 Enforced; S4 admin window; S5 council window; S6 expired council window (+1 h +1 s);
    ///      S7 council window opened inside the cooldown. Applied to A and B alike, by the council (never
    ///      held back) except the admin window.
    function _setState(uint8 s_) internal {
        if (s_ == 1 || s_ == 2 || s_ == 7) {
            vm.startPrank(council);
            g.lockdown(address(safeA));
            g.lockdown(address(safeB));
            vm.stopPrank();
        }
        if (s_ == 2) vm.warp(T0 + 1 days + 1);
        if (s_ >= 3 && s_ <= 6) {
            vm.startPrank(council);
            g.enforce(address(safeA));
            g.enforce(address(safeB));
            vm.stopPrank();
        }
        if (s_ == 4) {
            vm.startPrank(g.defaultAdmin());
            g.bypass(address(safeA), uint64(2 days));
            g.bypass(address(safeB), uint64(2 days));
            vm.stopPrank();
        }
        if (s_ == 5 || s_ == 7) {
            vm.startPrank(council);
            g.bypass(address(safeA), uint64(2 days));
            g.bypass(address(safeB), uint64(2 days));
            vm.stopPrank();
        }
        if (s_ == 6) {
            vm.startPrank(council);
            g.bypass(address(safeA), uint64(1 hours));
            g.bypass(address(safeB), uint64(1 hours));
            vm.stopPrank();
            vm.warp(T0 + 1 hours + 1);
        }
    }

    /*//////////////////////////////////////////////////////////////
                             CELL MACHINERY
    //////////////////////////////////////////////////////////////*/

    function _noRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _rules) {}

    function _oneOf0() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _rules) {
        _rules = new CuratorGuardPolicy.ParamRule[](1);
        _rules[0] = CuratorGuardPolicy.ParamRule({kind: CuratorGuardPolicy.RuleKind.OneOf, wordIndex: 0, value: bytes32(0)});
    }

    function _vals(uint256 v_) internal pure returns (bytes32[] memory _v) {
        _v = new bytes32[](1);
        _v[0] = bytes32(v_);
    }

    function _specWrap() internal view returns (CuratorGuardPolicy.FunctionSpec[] memory _specs) {
        _specs = new CuratorGuardPolicy.FunctionSpec[](1);
        _specs[0] = CuratorGuardPolicy.FunctionSpec(address(P), WRAP, true, _noRules());
    }

    function _selOf(bool ok_, bytes memory ret_) internal pure returns (bytes4) {
        if (ok_) return bytes4(0);
        if (ret_.length < 4) return bytes4(0xffffffff);
        return bytes4(ret_);
    }

    /// @dev Running hash of the events `emitter_` emitted, folding the indexed topic the matrix pins:
    ///      ModeUpdated.mode (topic 2), TransactionChecked.outcome (topic 3), RoleGranted / RoleRevoked.role
    ///      (topic 1). The expected pattern is hashed the same way by `_patternHash`.
    function _eventHash(Vm.Log[] memory logs_, address emitter_) internal pure returns (bytes32 _h) {
        for (uint256 i; i < logs_.length; ++i) {
            if (logs_[i].emitter != emitter_) continue;
            bytes32 _t = logs_[i].topics[0];
            if (_t == CuratorGuardPolicy.ModeUpdated.selector) _h = keccak256(abi.encodePacked(_h, _t, logs_[i].topics[2]));
            else if (_t == CuratorGuard.TransactionChecked.selector) _h = keccak256(abi.encodePacked(_h, _t, logs_[i].topics[3]));
            else if (_t == IAccessControl.RoleGranted.selector || _t == IAccessControl.RoleRevoked.selector) _h = keccak256(abi.encodePacked(_h, _t, logs_[i].topics[1]));
            else _h = keccak256(abi.encodePacked(_h, _t));
        }
    }

    function _countFrom(Vm.Log[] memory logs_, address emitter_) internal pure returns (uint256 _n) {
        for (uint256 i; i < logs_.length; ++i) if (logs_[i].emitter == emitter_) ++_n;
    }

    /// @dev Compares one cell's outcome with its expectation. `_flags`: bit 0 the call succeeded, bit 1 the
    ///      events matched (vacuously on a revert), bit 2 MISMATCH.
    function _judge(bool ok_, bytes memory ret_, Vm.Log[] memory logs_, uint8 expErr_, uint8 expPat_, address emitter_) internal pure returns (bytes4 _got, uint8 _flags, uint256 _n) {
        _got = _selOf(ok_, ret_);
        bool _okMatch = (ok_ == (expErr_ == 0)) && (ok_ || _got == _errSel(expErr_));
        bool _evMatch = !ok_ || _eventHash(logs_, emitter_) == _patternHash(expPat_);
        _flags = (ok_ ? 1 : 0) | (_evMatch ? 2 : 0) | (!(_okMatch && _evMatch) ? 4 : 0);
        _n = _countFrom(logs_, emitter_);
    }

    function _log(string memory suite_, uint256 c_, uint256 f_, uint256 s_, uint8 expErr_, bytes4 got_, uint8 flags_, uint256 nLogs_) internal pure {
        string memory _a = string.concat("G12E|", suite_, "|", vm.toString(c_), "|", vm.toString(f_), "|", vm.toString(s_));
        string memory _b = string.concat("|", vm.toString(uint256(expErr_)), "|", vm.toString(abi.encodePacked(got_)), "|", vm.toString(uint256(flags_)), "|", vm.toString(nLogs_));
        console.log(string.concat(_a, _b, (flags_ & 4) != 0 ? "|MISMATCH" : "|MATCH"));
    }

    /// @dev A pre-hook that passed as Safe A leaves a transient snapshot; a post-hook as A clears it (and
    ///      reverts harmlessly when the slot is empty). Called after every cell before the state revert so a
    ///      later hook cell of the same test never sees `NestedExecution` through transient storage.
    function _clearTransient() internal {
        vm.prank(address(safeA));
        (bool _ok, ) = address(g).call(abi.encodeCall(g.checkAfterExecution, (bytes32(0), true)));
        _ok;
    }

__ERRSEL__

__PATTERNHASH__

__CALLDATA__
}
'''

GUARD_CLASS_TEMPLATE = r"""
/// @title Matrix class __ID__: __LABEL__
contract G12e_Matrix_C__ID___Test is G12eMatrixBase {
    uint8 internal constant CLASS_ID = __ID__;

    function _expTable() internal pure returns (bytes memory) {
        return hex"__EXP__";
    }

    function _exp(uint8 f_, uint8 s_) internal pure returns (uint8 _err, uint8 _pat) {
        bytes memory _t = _expTable();
        uint256 _i = (uint256(f_) * 8 + s_) * 2;
        return (uint8(_t[_i]), uint8(_t[_i + 1]));
    }

    function _classSetup() internal {
__CLASSSETUP__
    }

    function _sender(uint8 f_) internal view returns (address) {
        if (__FN_HAS_TARGET_OVERRIDE__) return __OVERRIDE_SENDER__;
        return __SENDER__;
    }

    function _target(uint8 f_) internal view returns (address) {
        if (__FN_HAS_TARGET_OVERRIDE__) return address(g);
        return __TARGET__;
    }

    function _eff() internal view returns (address) {
        return __EFF__;
    }

    function _call(uint8 f_) internal returns (bool _ok, bytes memory _ret) {
        bytes memory _cd = _calldata(f_, _eff());
        vm.recordLogs();
        vm.prank(_sender(f_));
        (_ok, _ret) = _target(f_).call{value: __FN_VALUE__}(_cd);
    }

    function _runCell(uint8 f_, uint8 s_) internal returns (bool) {
        uint256 _snap = vm.snapshotState();
        _classSetup();
        _setState(s_);
        (bool _ok, bytes memory _ret) = _call(f_);
        (uint8 _expErr, uint8 _expPat) = _exp(f_, s_);
        (bytes4 _got, uint8 _flags, uint256 _n) = _judge(_ok, _ret, vm.getRecordedLogs(), _expErr, _expPat, address(g));
        _log("G", CLASS_ID, f_, s_, _expErr, _got, _flags, _n);
        _clearTransient();
        vm.revertToStateAndDelete(_snap);
        vm.warp(T0);
        return (_flags & 4) != 0;
    }

    function _runAll(uint8 f_) internal {
        uint256 _mismatches;
        for (uint8 s; s < 8; ++s) if (_runCell(f_, s)) ++_mismatches;
        assertEq(_mismatches, 0, "cells disagree with the documented expectation");
    }

__TESTS__
}
"""


def class_setup(c):
    lines = []
    if c.get("dirty"):
        lines.append("        vm.store(address(safeA), FALLBACK_SLOT, bytes32((uint256(0xdead) << 160) | uint256(uint160(address(g)))));")
    elif c.get("handlerGuard"):
        lines.append("        vm.store(address(safeA), FALLBACK_SLOT, bytes32(uint256(uint160(address(g)))));")
    if c.get("req"):
        lines.append("        vm.prank(g.defaultAdmin());")
        lines.append("        g.setRequiredFallbackHandler(address(safeA), address(0), true);")
    if not lines:
        lines.append("        // nothing: the class is defined by its sender")
    return "\n".join(lines)


def test_name(prefix, c_id, f):
    safe = "".join(ch if ch.isalnum() else "_" for ch in f["key"])
    while "__" in safe:
        safe = safe.replace("__", "_")
    return "test_%s%02d_f%02d_%s" % (prefix, c_id, f["id"], safe.strip("_"))


value_overrides = [f for f in F if f["value"]]
assert len(value_overrides) == 1
VALUE_FN = value_overrides[0]["id"]


def emit_guard_file():
    base = BASE_BODY.replace("__ERRSEL__", emit_err_sel()).replace("__PATTERNHASH__", emit_pattern_hash()).replace("__CALLDATA__", emit_calldata(F))
    with open(os.path.join(OUT, "G12e_MatrixBase.sol"), "w") as fh:
        fh.write(HEADER + base)
    body = HEADER + BASE_IMPORT
    for c in CLASSES:
        tests = "\n".join("    function %s() public { _runAll(%d); }" % (test_name("c", c["id"], f), f["id"]) for f in F)
        t = GUARD_CLASS_TEMPLATE
        t = t.replace("__ID__", str(c["id"])).replace("__LABEL__", c["label"]).replace("__EXP__", hexbytes(guard_tables[c["id"]]))
        t = t.replace("__CLASSSETUP__", class_setup(c))
        t = t.replace("__FN_HAS_TARGET_OVERRIDE__", "f_ == %d" % VALUE_FN)
        t = t.replace("__OVERRIDE_SENDER__", "stranger" if c.get("fwd") else c["sender"])
        t = t.replace("__SENDER__", c["sender"]).replace("__TARGET__", c["target"]).replace("__EFF__", c["eff"])
        t = t.replace("__FN_VALUE__", "f_ == %d ? 1 : 0" % VALUE_FN)
        t = t.replace("__TESTS__", tests)
        body += t
    with open(os.path.join(OUT, "G12e_Matrix.t.sol"), "w") as fh:
        fh.write(body)


HOOKS_TEMPLATE = r"""
/// @title The hooks through REAL Safe transactions: the owner-signed path of A (v1.4.1) and the module path of
///        B (v1.5.0, an allowlisted module and one that is not), 9 payloads x 8 states each.
contract G12e_MatrixHooks_Test is G12eMatrixBase {
    function _expTable() internal pure returns (bytes memory) {
        return hex"__EXP__";
    }

    function _exp(uint8 p_, uint8 k_, uint8 s_) internal pure returns (uint8 _err, uint8 _pat) {
        bytes memory _t = _expTable();
        uint256 _i = ((uint256(p_) * 9 + k_) * 8 + s_) * 2;
        return (uint8(_t[_i]), uint8(_t[_i + 1]));
    }

    struct Payload {
        address to;
        uint256 value;
        bytes data;
        Operation op;
        uint256 gasPrice;
    }

    function _batch() internal view returns (bytes memory) {
        bytes memory _e = abi.encodePacked(uint8(0), address(P), uint256(0), SETTLE1.length, SETTLE1);
        return abi.encodeWithSelector(MultiSendCallOnly.multiSend.selector, bytes.concat(_e, _e));
    }

    function _payload(uint8 k_, ISafe safe_) internal view returns (Payload memory) {
        if (k_ == 0) return Payload(address(P), 0, SETTLE1, Operation.Call, 0);
        if (k_ == 1) return Payload(address(P), 0, abi.encodeCall(MockProtocol.wrap, ()), Operation.Call, 0);
        if (k_ == 2) return Payload(address(safe_), 0, abi.encodeCall(ISafe.setGuard, (address(0))), Operation.Call, 0);
        if (k_ == 3) return Payload(address(safe_), 0, "", Operation.Call, 0);
        if (k_ == 4) return Payload(address(g), 0, abi.encodeCall(g.lockdown, (address(safe_))), Operation.Call, 0);
        if (k_ == 5) return Payload(address(M), 0, _batch(), Operation.DelegateCall, 0);
        if (k_ == 6) return Payload(address(P), 0, SETTLE9, Operation.Call, 0);
        if (k_ == 7) return Payload(address(M2), 0, _batch(), Operation.DelegateCall, 0);
        if (k_ == 8) return Payload(address(P), 0, SETTLE1, Operation.Call, 1);
        revert("payload");
    }

    /// @dev The owner-signed path: the curator's signature, submitted by anyone.
    function _execOwner(uint8 k_) internal returns (bool _ok, bytes memory _ret) {
        Payload memory _p = _payload(k_, safeA);
        safe = safeA;
        signerPk = pkA;
        SafeTx memory _t = SafeTx(_p.to, _p.value, _p.data, _p.op, 0, _p.gasPrice, address(0), _p.gasPrice != 0 ? curatorA : address(0));
        bytes memory _sig = _sign(_txHash(_t));
        bytes memory _cd = abi.encodeCall(ISafe.execTransaction, (_t.to, _t.value, _t.data, _t.op, 0, 0, _t.gasPrice, address(0), payable(_t.refundReceiver), _sig));
        vm.recordLogs();
        (_ok, _ret) = address(safeA).call(_cd);
    }

    /// @dev The module path of B (v1.5.0): the module calls execTransactionFromModule.
    function _execModule(uint8 p_, uint8 k_) internal returns (bool _ok, bytes memory _ret) {
        Payload memory _p = _payload(k_ == 8 ? 0 : k_, safeB);
        vm.recordLogs();
        vm.prank(p_ == 1 ? address(MOD) : address(MODX));
        (_ok, _ret) = address(safeB).call(abi.encodeCall(ISafe.execTransactionFromModule, (_p.to, _p.value, _p.data, _p.op)));
    }

    function _runCell(uint8 p_, uint8 k_, uint8 s_) internal returns (bool) {
        uint256 _snap = vm.snapshotState();
        _setState(s_);
        (bool _ok, bytes memory _ret) = p_ == 0 ? _execOwner(k_) : _execModule(p_, k_);
        (uint8 _expErr, uint8 _expPat) = _exp(p_, k_, s_);
        (bytes4 _got, uint8 _flags, uint256 _n) = _judge(_ok, _ret, vm.getRecordedLogs(), _expErr, _expPat, address(g));
        _log("H", p_, k_, s_, _expErr, _got, _flags, _n);
        vm.revertToStateAndDelete(_snap);
        vm.warp(T0);
        return (_flags & 4) != 0;
    }

    function _runAll(uint8 p_, uint8 k_) internal {
        uint256 _mismatches;
        for (uint8 s; s < 8; ++s) if (_runCell(p_, k_, s)) ++_mismatches;
        assertEq(_mismatches, 0, "cells disagree with the documented expectation");
    }

__TESTS__
}
"""


def emit_hooks_file():
    tests = []
    for p in PATHS:
        for k in PAYLOADS:
            if p["id"] != 0 and k["id"] == 8:
                continue
            tests.append("    function test_p%d_%s_k%d() public { _runAll(%d, %d); }" % (p["id"], p["key"], k["id"], p["id"], k["id"]))
    body = HEADER + BASE_IMPORT + HOOKS_TEMPLATE.replace("__EXP__", hexbytes(hook_table)).replace("__TESTS__", "\n".join(tests))
    with open(os.path.join(OUT, "G12e_MatrixHooks.t.sol"), "w") as fh:
        fh.write(body)


TL_BASE_TEMPLATE = r'''
/// @title The timelock's surface for every caller class.
abstract contract G12eTimelockBase is G12eMatrixBase {
    CuratorGuardTimelock internal tl;
    ISafe internal fwdPropSafe;
    ISafe internal fwdCancSafe;
    address internal p1 = makeAddr("g12e-proposer-1");
    address internal p2 = makeAddr("g12e-proposer-2");
    address internal veto = makeAddr("g12e-veto");
    bytes32 internal constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 internal constant CANCELLER_ROLE = keccak256("CANCELLER_ROLE");
    bytes32 internal constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes internal SETTLE2 = abi.encodeCall(MockProtocol.settleDeposit, (2));
    bytes internal SETTLE3 = abi.encodeCall(MockProtocol.settleDeposit, (3));
    bytes internal SETTLE4 = abi.encodeCall(MockProtocol.settleDeposit, (4));
    bytes internal SETTLE5 = abi.encodeCall(MockProtocol.settleDeposit, (5));

    function setUp() public virtual override {
        super.setUp();
        // The forwarding Safes need the timelock's address before the timelock knows them: compute it.
        address _tlAddr = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 2);
        fwdPropSafe = _newSafe141(makeAddr("g12e-prop-safe-owner"), _tlAddr);
        fwdCancSafe = _newSafe141(makeAddr("g12e-canc-safe-owner"), _tlAddr);
        address[] memory _p = new address[](3);
        _p[0] = p1;
        _p[1] = p2;
        _p[2] = address(fwdPropSafe);
        address[] memory _c = new address[](2);
        _c[0] = veto;
        _c[1] = address(fwdCancSafe);
        tl = new CuratorGuardTimelock(2 days, _p, _c);
        require(address(tl) == _tlAddr, "timelock address");
        vm.deal(address(tl), 1 ether);
        vm.deal(p1, 1 ether);
        vm.deal(veto, 1 ether);
        vm.deal(address(guard), 1 ether);
        // Operations: 2 (ready), 3 (done), 5 (ready, batch) scheduled now; 4 (waiting) after the warp.
        uint256 _d = tl.getMinDelay();
        vm.startPrank(p1);
        tl.schedule(address(P), 0, SETTLE2, bytes32(0), bytes32(uint256(2)), _d);
        tl.schedule(address(P), 0, SETTLE3, bytes32(0), bytes32(uint256(3)), _d);
        tl.scheduleBatch(_one(address(P)), _one(uint256(0)), _one(SETTLE5), bytes32(0), bytes32(uint256(5)), _d);
        vm.stopPrank();
        vm.warp(block.timestamp + _d);
        T0 = block.timestamp;
        tl.execute(address(P), 0, SETTLE3, bytes32(0), bytes32(uint256(3)));
        vm.prank(p1);
        tl.schedule(address(P), 0, SETTLE4, bytes32(0), bytes32(uint256(4)), _d);
    }

    function _one(address a_) internal pure returns (address[] memory _r) {
        _r = new address[](1);
        _r[0] = a_;
    }

    function _one(uint256 v_) internal pure returns (uint256[] memory _r) {
        _r = new uint256[](1);
        _r[0] = v_;
    }

    function _one(bytes memory b_) internal pure returns (bytes[] memory _r) {
        _r = new bytes[](1);
        _r[0] = b_;
    }

    function _opWaiting() internal view returns (bytes32) {
        return tl.hashOperation(address(P), 0, SETTLE4, bytes32(0), bytes32(uint256(4)));
    }

    function _opDone() internal view returns (bytes32) {
        return tl.hashOperation(address(P), 0, SETTLE3, bytes32(0), bytes32(uint256(3)));
    }
}
'''

TL_CLASS_TEMPLATE = r"""
/// @title Timelock matrix class __ID__: __LABEL__
contract G12e_MatrixTimelock_C__ID___Test is G12eTimelockBase {
    uint8 internal constant CLASS_ID = __ID__;

    function _expTable() internal pure returns (bytes memory) {
        return hex"__EXP__";
    }

    function _exp(uint8 f_) internal pure returns (uint8 _err, uint8 _pat) {
        bytes memory _t = _expTable();
        return (uint8(_t[uint256(f_) * 2]), uint8(_t[uint256(f_) * 2 + 1]));
    }

__CALLDATA__

    function _call(uint8 f_) internal returns (bool _ok, bytes memory _ret) {
        bytes memory _cd = _tcalldata(f_, __EFF__);
        bool _value = f_ == __VALUE_FN__;
        address _to = _value ? address(tl) : __TARGET__;
        address _sender = (_value && __ISFWD__) ? stranger : __SENDER__;
        vm.recordLogs();
        vm.prank(_sender);
        (_ok, _ret) = _to.call{value: _value ? 1 : 0}(_cd);
    }

    function _runCell(uint8 f_) internal returns (bool) {
        uint256 _snap = vm.snapshotState();
        (bool _ok, bytes memory _ret) = _call(f_);
        (uint8 _expErr, uint8 _expPat) = _exp(f_);
        (bytes4 _got, uint8 _flags, uint256 _n) = _judge(_ok, _ret, vm.getRecordedLogs(), _expErr, _expPat, address(tl));
        _log("T", CLASS_ID, f_, 0, _expErr, _got, _flags, _n);
        vm.revertToStateAndDelete(_snap);
        vm.warp(T0);
        return (_flags & 4) != 0;
    }

__TESTS__
}
"""


def emit_timelock_file():
    body = HEADER + BASE_IMPORT + TL_BASE_TEMPLATE
    value_fns = [f for f in TF if f["value"]]
    assert len(value_fns) == 1
    for c in TCLASSES:
        tests = "\n".join("    function %s() public { assertFalse(_runCell(%d), \"cell disagrees with the documented expectation\"); }" % (test_name("t", c["id"], f), f["id"]) for f in TF)
        t = TL_CLASS_TEMPLATE
        t = t.replace("__ID__", str(c["id"])).replace("__LABEL__", c["label"]).replace("__EXP__", hexbytes(tl_tables[c["id"]]))
        t = t.replace("__CALLDATA__", emit_calldata(TF, name="_tcalldata"))
        t = t.replace("__EFF__", c["eff"]).replace("__TARGET__", c["target"]).replace("__SENDER__", c["sender"])
        t = t.replace("__ISFWD__", "true" if c.get("fwd") else "false").replace("__VALUE_FN__", str(value_fns[0]["id"]))
        t = t.replace("__TESTS__", tests)
        body += t
    with open(os.path.join(OUT, "G12e_MatrixTimelock.t.sol"), "w") as fh:
        fh.write(body)


VIA_TEMPLATE = r'''
/// @title Every admin cell of state S3 (Enforced), executed through a REAL CuratorGuardTimelock that is the
///        guard's admin: scheduled by a proposer, wrapped in executeBefore, executed by a stranger after the
///        delay. The outcome and the guard's events must equal the direct admin cell's.
contract G12e_MatrixViaTimelock_Test is G12eTimelockBase {
    CuratorGuardHarness internal guardT;
    CuratorGuardTimelock internal tl3;

    function setUp() public override {
        super.setUp();
        guardT = new CuratorGuardHarness(1 days, address(tl), council);
        guardT.seedCodehash(address(M).codehash);
        guardT.seedSafe(address(safeA));
        guardT.seedSafe(address(safeB));
        g = guardT;
        _configure(guardT); // impersonates the timelock for the setup only; the cells go through the queue
        address[] memory _p = new address[](1);
        _p[0] = p1;
        address[] memory _c = new address[](1);
        _c[0] = veto;
        tl3 = new CuratorGuardTimelock(1 days, _p, _c);
    }

    function _expTable() internal pure returns (bytes memory) {
        return hex"__EXP__";
    }

    function _exp(uint8 f_) internal pure returns (uint8 _err, uint8 _pat) {
        bytes memory _t = _expTable();
        return (uint8(_t[uint256(f_) * 2]), uint8(_t[uint256(f_) * 2 + 1]));
    }

    /// @dev Schedules `executeBefore(deadline, <the admin cell's calldata>)` on the timelock as a proposer,
    ///      waits the delay and executes it as a stranger.
    function _viaQueue(uint8 f_) internal returns (bool _ok, bytes memory _ret) {
        bytes memory _wrapped = abi.encodeCall(guardT.executeBefore, (uint64(block.timestamp + 10 days), _calldata(f_, address(tl))));
        bytes32 _salt = bytes32(uint256(1000 + f_));
        uint256 _d = tl.getMinDelay();
        vm.prank(p1);
        tl.schedule(address(guardT), 0, _wrapped, bytes32(0), _salt, _d);
        vm.warp(block.timestamp + _d);
        vm.recordLogs();
        vm.prank(stranger);
        (_ok, _ret) = address(tl).call(abi.encodeCall(tl.execute, (address(guardT), 0, _wrapped, bytes32(0), _salt)));
    }

    function _runCell(uint8 f_) internal returns (bool) {
        uint256 _snap = vm.snapshotState();
        _setState(3);
        (bool _ok, bytes memory _ret) = _viaQueue(f_);
        (uint8 _expErr, uint8 _expPat) = _exp(f_);
        (bytes4 _got, uint8 _flags, uint256 _n) = _judge(_ok, _ret, vm.getRecordedLogs(), _expErr, _expPat, address(guardT));
        _log("V", 0, f_, 3, _expErr, _got, _flags, _n);
        vm.revertToStateAndDelete(_snap);
        vm.warp(T0);
        return (_flags & 4) != 0;
    }

    /// @dev The hand-over to a second timelock: begin (scheduled on tl), accept (scheduled on tl3) after the
    ///      admin delay, both executed by a stranger: `guardT.defaultAdmin()` moves to tl3.
    function test_v_handover_timelock_to_timelock_through_the_queues() public {
        bytes memory _begin = abi.encodeCall(guardT.beginDefaultAdminTransfer, (address(tl3)));
        uint256 _d = tl.getMinDelay();
        vm.prank(p1);
        tl.schedule(address(guardT), 0, _begin, bytes32(0), bytes32(uint256(4242)), _d);
        vm.warp(block.timestamp + _d);
        vm.prank(stranger);
        tl.execute(address(guardT), 0, _begin, bytes32(0), bytes32(uint256(4242)));
        (address _pending, ) = guardT.pendingDefaultAdmin();
        assertEq(_pending, address(tl3), "pending");
        bytes memory _accept = abi.encodeCall(guardT.acceptDefaultAdminTransfer, ());
        uint256 _d3 = tl3.getMinDelay();
        vm.prank(p1);
        tl3.schedule(address(guardT), 0, _accept, bytes32(0), bytes32(uint256(4243)), _d3);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(stranger);
        tl3.execute(address(guardT), 0, _accept, bytes32(0), bytes32(uint256(4243)));
        assertEq(guardT.defaultAdmin(), address(tl3), "accepted");
        // The old timelock is now a stranger to the guard, the new one is exempt in the hooks.
        vm.prank(address(tl));
        vm.expectRevert(CuratorGuardPolicy.Unauthorized.selector);
        guardT.enforce(address(safeA));
    }

__TESTS__
}
'''


def emit_via_file():
    tests = "\n".join(
        "    function %s() public { assertFalse(_runCell(%d), \"cell disagrees with the direct admin cell\"); }" % (test_name("v", 0, f), f["id"])
        for f in F if not f["value"]
    )
    body = HEADER + BASE_IMPORT + TL_BASE_TEMPLATE + VIA_TEMPLATE.replace("__EXP__", hexbytes(via_table)).replace("__TESTS__", tests)
    with open(os.path.join(OUT, "G12e_MatrixViaTimelock.t.sol"), "w") as fh:
        fh.write(body)


VIEWS_TEMPLATE = r'''
/// @title The view surface and ERC-165 for every caller class (what a stranger can learn: the whole policy).
contract G12e_MatrixViews_Test is G12eTimelockBase {
    function _views() internal view returns (bytes[] memory _c) {
        _c = new bytes[](31);
        uint256 i;
        _c[i++] = abi.encodeCall(g.allowedValues, (address(safeA), address(P), DEPOSIT, 0));
        _c[i++] = abi.encodeCall(g.approvalEpoch, (address(safeA)));
        _c[i++] = abi.encodeCall(g.approvalExpiry, (apprA));
        _c[i++] = abi.encodeCall(g.bypassWindow, (address(safeA)));
        _c[i++] = abi.encodeCall(g.lockedAt, (address(safeA)));
        _c[i++] = abi.encodeCall(g.isUnwrapperCodehash, (g.codehashV141()));
        _c[i++] = abi.encodeCall(g.computeApprovalId, (address(safeA), address(0), address(P), 0, SETTLE9, Operation.Call));
        _c[i++] = abi.encodeCall(g.functionPermission, (address(safeA), address(P), SETTLE));
        _c[i++] = abi.encodeCall(g.guardians, (address(safeA)));
        _c[i++] = abi.encodeCall(g.isGuardian, (address(safeA), gA));
        _c[i++] = abi.encodeCall(g.isNativeTransferAllowed, (address(safeA), nt));
        _c[i++] = abi.encodeCall(g.mode, (address(safeA)));
        _c[i++] = abi.encodeCall(g.modules, (address(safeA)));
        _c[i++] = abi.encodeCall(g.multiSendUnwrappers, (address(safeA)));
        _c[i++] = abi.encodeCall(g.requiredFallbackHandler, (address(safeA)));
        _c[i++] = abi.encodeCall(g.selectors, (address(safeA), address(P)));
        _c[i++] = abi.encodeCall(g.targets, (address(safeA)));
        _c[i++] = abi.encodeWithSignature("VERSION()");
        _c[i++] = abi.encodeWithSignature("COUNCIL_ROLE()");
        _c[i++] = abi.encodeWithSignature("GUARDIAN_ROLE()");
        _c[i++] = abi.encodeWithSignature("DEFAULT_ADMIN_ROLE()");
        _c[i++] = abi.encodeCall(g.hasRole, (COUNCIL_ROLE, council));
        _c[i++] = abi.encodeCall(g.getRoleAdmin, (COUNCIL_ROLE));
        _c[i++] = abi.encodeWithSignature("defaultAdmin()");
        _c[i++] = abi.encodeWithSignature("pendingDefaultAdmin()");
        _c[i++] = abi.encodeWithSignature("defaultAdminDelay()");
        _c[i++] = abi.encodeWithSignature("pendingDefaultAdminDelay()");
        _c[i++] = abi.encodeWithSignature("defaultAdminDelayIncreaseWait()");
        _c[i++] = abi.encodeWithSignature("owner()");
        _c[i++] = abi.encodeCall(g.supportsInterface, (bytes4(0x01ffc9a7)));
        _c[i++] = abi.encodeCall(g.validateTransaction, (address(safeA), address(P), 0, SETTLE1, Operation.Call));
        require(i == 31, "count");
    }

    /// @dev Every view answers every caller class, forwarded Safes included, without a state change.
    function test_views_answer_every_caller_class_without_side_effects() public {
        _setState(3);
        address[11] memory _senders = [vetro, council, gA, gD, address(safeA), address(MOD), stranger, address(0), pend, address(councilSafe), address(tl)];
        bytes[] memory _calls = _views();
        bytes32 _before = keccak256(abi.encode(g.mode(address(safeA)), g.approvalEpoch(address(safeA)), g.targets(address(safeA)), g.guardians(address(safeA)), g.defaultAdmin()));
        for (uint256 k; k < _senders.length; ++k) {
            for (uint256 i; i < _calls.length; ++i) {
                vm.prank(_senders[k]);
                (bool _ok, ) = address(g).call(_calls[i]);
                assertTrue(_ok, "view answers");
            }
        }
        // Through a Safe whose handler is the guard (forwarded): the views answer too.
        for (uint256 i; i < _calls.length; ++i) {
            vm.prank(stranger);
            (bool _ok, ) = address(councilSafe).call(_calls[i]);
            assertTrue(_ok, "forwarded view answers");
        }
        assertEq(keccak256(abi.encode(g.mode(address(safeA)), g.approvalEpoch(address(safeA)), g.targets(address(safeA)), g.guardians(address(safeA)), g.defaultAdmin())), _before, "no side effect");
        console.log("G12E|W|views|31 views x 12 caller classes|MATCH");
    }

    /// @dev ERC-165 of the guard and the timelock; the documentation names the two guard ids only (S4 L1043,
    ///      ISafeGuard NatSpec): the rest of the table is UNDECIDED and recorded.
    function test_erc165_surface() public view {
        assertTrue(g.supportsInterface(0x01ffc9a7), "ERC165");
        assertTrue(g.supportsInterface(0xe6d7a83a), "ISafeTransactionGuard (documented)");
        assertTrue(g.supportsInterface(0x58401ed8), "ISafeModuleGuard (documented)");
        assertTrue(g.supportsInterface(type(IAccessControl).interfaceId), "IAccessControl (undecided)");
        assertTrue(g.supportsInterface(type(IAccessControlDefaultAdminRules).interfaceId), "IAccessControlDefaultAdminRules (undecided)");
        assertFalse(g.supportsInterface(0x8da5cb5b), "IERC5313 owner() is served but not announced (undecided)");
        assertFalse(g.supportsInterface(0xffffffff), "0xffffffff");
        assertFalse(g.supportsInterface(0x12345678), "random");
        assertTrue(tl.supportsInterface(0x01ffc9a7), "timelock ERC165");
        assertTrue(tl.supportsInterface(type(IAccessControl).interfaceId), "timelock IAccessControl");
        assertTrue(tl.supportsInterface(0x4e2312e0), "timelock IERC1155Receiver (OpenZeppelin ERC1155Holder)");
        assertFalse(tl.supportsInterface(0x150b7a02), "timelock IERC721Receiver is served but not announced (OpenZeppelin ERC721Holder)");
        assertFalse(tl.supportsInterface(0xe6d7a83a), "the timelock is no guard");
        console.log("G12E|W|erc165|13 ids|MATCH");
    }
}
'''


def emit_views_file():
    body = HEADER + BASE_IMPORT + TL_BASE_TEMPLATE + VIEWS_TEMPLATE
    with open(os.path.join(OUT, "G12e_MatrixViews.t.sol"), "w") as fh:
        fh.write(body)


if __name__ == "__main__":
    emit_guard_file()
    emit_hooks_file()
    emit_timelock_file()
    emit_via_file()
    emit_views_file()
    n_cells = len(expected["cells"])
    n_und = sum(1 for c in expected["cells"] if "U" in c["doc"].split(","))
    print("functions %d, classes %d, states %d; cells %d (undecided by the docs: %d); patterns %d" % (len(F), len(CLASSES), len(STATES), n_cells, n_und, len(PATTERNS)))
