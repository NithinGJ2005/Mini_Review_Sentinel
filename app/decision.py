from __future__ import annotations

from .models import Decision, Finding, Severity


def max_risk(findings: list[Finding]) -> Severity:
    if any(f.severity == Severity.HIGH for f in findings):
        return Severity.HIGH
    if any(f.severity == Severity.MEDIUM for f in findings):
        return Severity.MEDIUM
    return Severity.LOW


def resolve(static_findings: list[Finding], llm_findings: list[Finding], llm_available: bool) -> tuple[Decision, Severity, Severity, list[str]]:
    static_risk = max_risk(static_findings)
    llm_risk = max_risk(llm_findings) if llm_available else Severity.LOW
    notes: list[str] = []

    # Deterministic safety-first policy:
    # deterministic HIGH => REJECTED regardless of LLM disagreement.
    if static_risk == Severity.HIGH:
        high_static = [f for f in static_findings if f.severity == Severity.HIGH]
        details = "; ".join(f"'{f.finding}' at {f.file}:{f.line}" for f in high_static) or "security rule"
        notes.append(f"Deterministic HIGH-risk finding is authoritative for rejection ({details}).")
        if llm_available and llm_risk == Severity.LOW:
            notes.append(f"LLM disagreed (reported LOW risk); deterministic rule for {details} wins because evidence is reproducible.")
        return Decision.REJECTED, static_risk, llm_risk, notes

    # If LLM sees a high-risk contextual issue, require human review rather than auto-rejecting.
    if llm_available and llm_risk == Severity.HIGH:
        high_llm = [f for f in llm_findings if f.severity == Severity.HIGH]
        details = "; ".join(f"'{f.finding}' at {f.file}:{f.line}" for f in high_llm) or "contextual concern"
        notes.append(f"LLM HIGH-risk contextual concern triggers human review rather than automatic rejection ({details}).")
        if static_risk == Severity.LOW:
            notes.append(f"Static analysis was LOW, so probabilistic signal ({details}) is escalated conservatively.")
        return Decision.REVIEW_REQUIRED, static_risk, llm_risk, notes

    if static_risk == Severity.MEDIUM or llm_risk == Severity.MEDIUM:
        notes.append("Medium-risk evidence requires human review.")
        return Decision.REVIEW_REQUIRED, static_risk, llm_risk, notes

    if not llm_available:
        notes.append("LLM unavailable; approved only when deterministic analysis finds no high/medium risk.")

    return Decision.APPROVED, static_risk, llm_risk, notes
