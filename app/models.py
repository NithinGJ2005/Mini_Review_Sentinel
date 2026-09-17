from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Decision(str, Enum):
    APPROVED = "APPROVED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    finding: str
    severity: Severity
    evidence: str
    recommendation: str
    source: str
    confidence: float = 1.0
    decision: str | None = None

    def as_dict(self) -> dict[str, Any]:
        finding_decision = self.decision
        if not finding_decision:
            finding_decision = "REJECTED" if self.severity == Severity.HIGH and self.source.startswith("deterministic") else "REVIEW_REQUIRED"
        return {
            "file": self.file,
            "line": self.line,
            "finding": self.finding,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "decision": finding_decision,
            "source": self.source,
            "confidence": round(self.confidence, 3),
        }


@dataclass
class LLMReview:
    risk: Severity = Severity.LOW
    findings: list[Finding] = field(default_factory=list)
    needs_context: bool = False
    context_questions: list[str] = field(default_factory=list)
    summary: str = ""
    raw: str = ""


@dataclass
class ReviewResult:
    decision: Decision
    findings: list[Finding]
    static_risk: Severity
    llm_risk: Severity
    llm_available: bool
    iterations: int
    review_id: str
    cached: bool = False
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "review_id": self.review_id,
            "cached": self.cached,
            "decision": self.decision.value,
            "static_risk": self.static_risk.value,
            "llm_risk": self.llm_risk.value,
            "llm_available": self.llm_available,
            "iterations": self.iterations,
            "findings": [f.as_dict() for f in self.findings],
            "notes": self.notes,
        }
