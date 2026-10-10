"""Report values: what the analysis produces and the renderers print."""

from dataclasses import dataclass
from enum import StrEnum

from unifiwifioptimizer.domain.models import Band


class Severity(StrEnum):
    INFO = "info"
    ADVISORY = "advisory"
    WARNING = "warning"
    ERROR = "error"


class CheckStatus(StrEnum):
    """`INCOMPLETE`: the controller did not send a field the check needs; `NOT_EVALUABLE`: the tool has no
    rule for this case yet (6 GHz detect-only); `NOT_APPLICABLE`: the check does not apply to this subject."""

    PASSED = "passed"
    FAILED = "failed"
    INCOMPLETE = "incomplete"
    NOT_EVALUABLE = "not_evaluable"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True, kw_only=True)
class Finding:
    severity: Severity
    code: str
    message: str
    subject: str
    band: Band | None = None
    ui_path: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class CheckResult:
    code: str
    subject: str
    status: CheckStatus
    detail: str
    expected: str | None = None
    actual: str | None = None
    ui_path: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Recommendation:
    """A concrete setting change; `current == recommended` records a confirmed setting, not a change."""

    code: str
    subject: str
    band: Band | None
    setting: str
    current: int | None
    recommended: int
    reason: str
    ui_path: str | None = None

    @property
    def is_change(self) -> bool:
        return self.current != self.recommended


@dataclass(frozen=True, slots=True, kw_only=True)
class Report:
    site_id: str
    findings: tuple[Finding, ...]
    checks: tuple[CheckResult, ...]
    recommendations: tuple[Recommendation, ...]

    @property
    def has_changes(self) -> bool:
        return any(r.is_change for r in self.recommendations) or any(
            c.status is CheckStatus.FAILED for c in self.checks
        )
