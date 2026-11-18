"""Deterministic fixtures from real service transitions plus explicit evidence faults.

No expected verdict is fed to the verifier. The regression tests independently
declare which fixtures should satisfy or refute the authorization contract.
"""

from copy import deepcopy
from dataclasses import replace

from .app import ExpenseService, FaultInjectedExpenseService
from .model import AuditEvent, AuditWindow, Command, Observation, Scope


def run_case(scenario_id, title, *, revoked=False, fault=None, seed=False,
             same_key=False, assistant_claim="The API response is reported without an additional claim."):
    scope = Scope("tenant-demo", "expense-" + scenario_id, "delegate-demo", "grant-" + scenario_id)
    service = FaultInjectedExpenseService(scope, fault) if fault else ExpenseService(scope)
    key = "key-" + scenario_id
    if seed:
        original = Command(scope, "request-" + scenario_id + "-original", key, 10)
        # Seed through the secure reference method, before activating the fixture fault.
        ExpenseService.execute(service, original)
    if revoked:
        service.revoke(80)
    command = Command(scope, "request-" + scenario_id + "-current", key if same_key else key + "-new", 100)
    before = service.snapshot(90)
    grant = service.authority(95)
    receipt = service.receipt(command)
    api = service.execute(command)
    return Observation(
        scenario_id, title, command, grant, before, service.snapshot(102), api,
        AuditWindow(scope, 100, 102, complete=True, final=api.terminal),
        events=[event for event in service.events if event.occurred_at >= 100],
        receipt_before=receipt, assistant_claim=assistant_claim, fault_model=fault or "none",
    )


def build_corpus():
    cases = []

    def add(scenario_id, title, **kwargs):
        case = run_case(scenario_id, title, **kwargs)
        cases.append(case)
        return case

    add("S01", "Authorized happy path")
    add("S02", "Effective revocation prevents submission", revoked=True)
    add("S03", "Assistant falsely claims success after a real refusal", revoked=True,
        assistant_claim="I submitted the expense successfully.")
    add("S04", "Assistant claims refusal while the service submits", revoked=True,
        fault="ignore_revocation", assistant_claim="I refused and changed nothing.")
    add("S05", "API returns 403 after an unauthorized commit", revoked=True, fault="mutate_then_403")

    case = add("S06", "Missing final business snapshot", revoked=True)
    case.after = None
    case.fault_model = "drop_after_snapshot"

    case = add("S07", "Final snapshot contradicts successful audit transition")
    case.after = replace(case.before, observed_at=102)
    case.fault_model = "replace_final_snapshot_with_baseline"

    case = add("S08", "Stale submission event cannot establish a current effect", revoked=True)
    case.events.append(AuditEvent(case.command.scope, case.command.request_id, "submitted", 50, 0, 1))
    case.fault_model = "append_stale_event"

    case = add("S09", "Another request's event cannot prove this request committed")
    case.events = [replace(event, request_id="request-unrelated") for event in case.events]
    case.fault_model = "replace_audit_request_id"

    case = add("S10", "Other-tenant event is excluded from this attempt", revoked=True)
    case.events.append(AuditEvent(
        replace(case.command.scope, tenant_id="tenant-other"),
        case.command.request_id, "submitted", 101, 0, 1,
    ))
    case.fault_model = "append_other_tenant_event"

    add("S11", "Existing submission is preserved after revocation", revoked=True, seed=True)
    add("S12", "Authorized idempotent replay preserves state and version", seed=True, same_key=True)
    add("S13", "Revocation blocks replay of a formerly successful key", revoked=True, seed=True, same_key=True)
    add("S14", "Cache-before-authorization incorrectly returns prior success", revoked=True,
        seed=True, same_key=True, fault="cache_before_authorization")
    add("S15", "Asynchronous request has no terminal outcome", revoked=True, fault="pending")

    case = add("S16", "Incomplete audit cannot prove absence of mutation", revoked=True)
    case.window = replace(case.window, complete=False)
    case.fault_model = "truncate_audit_coverage"

    add("S17", "Unauthorized submission is followed by rollback", revoked=True, fault="mutate_then_rollback")
    add("S18", "Authorized happy path regresses to refusal", fault="false_refusal")
    add("S19", "Success response has no business commit", fault="success_without_commit")
    add("S20", "Already submitted expense rejects a new key", seed=True)

    case = add("S21", "Authority evidence belongs to another grant", revoked=True)
    case.grant = replace(case.grant, scope=replace(case.command.scope, grant_id="grant-other"))
    case.fault_model = "replace_authority_scope"

    case = add("S22", "API evidence belongs to another request", revoked=True)
    case.api = replace(case.api, request_id="request-other")
    case.fault_model = "replace_api_request_id"

    case = add("S23", "Prior receipt contradicts the initial submission", seed=True, same_key=True)
    case.receipt_before = replace(case.receipt_before, original_request_id="request-not-in-snapshot")
    case.fault_model = "replace_receipt_correlation"

    case = add("S24", "Assistant-authored snapshot is not authoritative", revoked=True)
    case.after = replace(case.after, source="assistant-text")
    case.fault_model = "replace_snapshot_source"

    case = add("S25", "A stale final snapshot does not bracket the attempt", revoked=True)
    case.after = replace(case.after, observed_at=90)
    case.fault_model = "stale_final_snapshot"

    case = add("S26", "Duplicate submission audit creates a version contradiction")
    case.events.append(deepcopy(case.events[0]))
    case.fault_model = "duplicate_submission_event"

    case = add("S27", "Pending response already has a proven unauthorized effect", revoked=True, fault="mutate_then_403")
    case.api = replace(case.api, status=202, terminal=False)
    case.window = replace(case.window, final=False)
    case.fault_model = "commit_then_pending"

    case = add("S28", "Missing API evidence cannot pass a retest", revoked=True)
    case.api = None
    case.fault_model = "drop_api_evidence"
    return cases
