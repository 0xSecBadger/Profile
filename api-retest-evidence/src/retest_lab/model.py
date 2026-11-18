"""Evidence contracts. Sources are simulated trust boundaries, not signatures."""

from dataclasses import asdict, dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Scope:
    tenant_id: str
    expense_id: str
    delegate_id: str
    grant_id: str


@dataclass(frozen=True)
class Command:
    scope: Scope
    request_id: str
    idempotency_key: str
    attempted_at: int
    action: str = "submit_expense"


@dataclass(frozen=True)
class GrantEvidence:
    scope: Scope
    revoked_at: Optional[int]
    observed_at: int
    source: str = "authorization-store"


@dataclass(frozen=True)
class Snapshot:
    scope: Scope
    status: str
    version: int
    submitted_request_id: Optional[str]
    observed_at: int
    source: str = "expense-store"


@dataclass(frozen=True)
class Receipt:
    scope: Scope
    idempotency_key: str
    original_request_id: str
    action: str
    expense_version: int
    source: str = "idempotency-store"


@dataclass(frozen=True)
class ApiObservation:
    request_id: str
    status: int
    completed_at: int
    terminal: bool = True
    replay: bool = False
    source: str = "api-gateway"


@dataclass(frozen=True)
class AuditEvent:
    scope: Scope
    request_id: str
    kind: str
    occurred_at: int
    version_before: int
    version_after: int
    source: str = "expense-audit"


@dataclass(frozen=True)
class AuditWindow:
    scope: Scope
    start: int
    end: int
    complete: bool
    final: bool = True
    source: str = "expense-audit"


@dataclass
class Observation:
    scenario_id: str
    title: str
    command: Command
    grant: Optional[GrantEvidence]
    before: Optional[Snapshot]
    after: Optional[Snapshot]
    api: Optional[ApiObservation]
    window: Optional[AuditWindow]
    events: List[AuditEvent] = field(default_factory=list)
    receipt_before: Optional[Receipt] = None
    assistant_claim: str = "No claim."
    fault_model: str = "none"

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class Assessment:
    scenario_id: str
    title: str
    verdict: str
    reasons: List[str]
    expected: dict
    observed: dict
    command: dict

    def to_dict(self):
        return asdict(self)
