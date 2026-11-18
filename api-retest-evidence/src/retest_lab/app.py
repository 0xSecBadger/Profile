"""Small executable business model: delegated expense submission and revocation.

No sockets, HTTP server, credentials, LLM, SLM, or external services are used.
HTTP-style status integers let a future adapter reuse the evidence contract.
"""

from typing import Dict, Optional, Tuple

from .model import (
    ApiObservation, AuditEvent, Command, GrantEvidence, Receipt, Scope, Snapshot,
)


class ExpenseService:
    """In-memory reference implementation. Authorization precedes cache lookup."""

    def __init__(self, scope: Scope):
        self.scope = scope
        self.revoked_at: Optional[int] = None
        self.status = "draft"
        self.version = 0
        self.submitted_request_id: Optional[str] = None
        self.receipts: Dict[Tuple[Scope, str, str], Receipt] = {}
        self.events = []

    def revoke(self, effective_at: int) -> None:
        self.revoked_at = effective_at

    def authority(self, at: int) -> GrantEvidence:
        return GrantEvidence(self.scope, self.revoked_at, at)

    def snapshot(self, at: int) -> Snapshot:
        return Snapshot(self.scope, self.status, self.version, self.submitted_request_id, at)

    def receipt(self, command: Command) -> Optional[Receipt]:
        return self.receipts.get((command.scope, command.action, command.idempotency_key))

    def _event(self, command: Command, kind: str, before: int, after: int) -> None:
        self.events.append(AuditEvent(
            command.scope, command.request_id, kind, command.attempted_at + 1, before, after,
        ))

    def _submit(self, command: Command) -> None:
        previous = self.version
        self.status = "submitted"
        self.version += 1
        self.submitted_request_id = command.request_id
        self.receipts[(command.scope, command.action, command.idempotency_key)] = Receipt(
            command.scope, command.idempotency_key, command.request_id,
            command.action, self.version,
        )
        self._event(command, "submitted", previous, self.version)

    def _rollback(self, command: Command) -> None:
        previous = self.version
        self.status = "draft"
        self.version += 1
        self.submitted_request_id = None
        self.receipts.pop((command.scope, command.action, command.idempotency_key), None)
        self._event(command, "rolled_back", previous, self.version)

    def execute(self, command: Command) -> ApiObservation:
        if command.scope != self.scope or command.action != "submit_expense":
            self._event(command, "refused", self.version, self.version)
            return ApiObservation(command.request_id, 403, command.attempted_at + 1)
        if self.revoked_at is not None and self.revoked_at <= command.attempted_at:
            self._event(command, "refused", self.version, self.version)
            return ApiObservation(command.request_id, 403, command.attempted_at + 1)
        if self.receipt(command):
            self._event(command, "replayed", self.version, self.version)
            return ApiObservation(command.request_id, 200, command.attempted_at + 1, replay=True)
        if self.status == "submitted":
            self._event(command, "conflict", self.version, self.version)
            return ApiObservation(command.request_id, 409, command.attempted_at + 1)
        self._submit(command)
        return ApiObservation(command.request_id, 201, command.attempted_at + 1)


class FaultInjectedExpenseService(ExpenseService):
    """Explicitly defective offline fixtures, never the reference service default."""

    def __init__(self, scope: Scope, fault: str):
        super().__init__(scope)
        self.fault = fault

    def execute(self, command: Command) -> ApiObservation:
        if self.fault == "cache_before_authorization" and self.receipt(command):
            self._event(command, "replayed", self.version, self.version)
            return ApiObservation(command.request_id, 200, command.attempted_at + 1, replay=True)
        if self.fault in {"ignore_revocation", "mutate_then_403", "mutate_then_rollback"}:
            self._submit(command)
            if self.fault == "mutate_then_rollback":
                self._rollback(command)
            status = 201 if self.fault == "ignore_revocation" else 403
            return ApiObservation(command.request_id, status, command.attempted_at + 1)
        if self.fault == "false_refusal":
            self._event(command, "refused", self.version, self.version)
            return ApiObservation(command.request_id, 403, command.attempted_at + 1)
        if self.fault == "pending":
            self._event(command, "queued", self.version, self.version)
            return ApiObservation(command.request_id, 202, command.attempted_at + 1, terminal=False)
        if self.fault == "success_without_commit":
            return ApiObservation(command.request_id, 201, command.attempted_at + 1)
        return super().execute(command)
