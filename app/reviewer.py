from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from pathlib import Path

from .decision import resolve
from .llm import LLMClient
from .models import Decision, Finding, ReviewResult, Severity
from .static_analysis import scan_file

MAX_ITERATIONS = 2
EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    ".env",
    "__pycache__",
    ".pytest_cache",
    "build",
    "dist",
}


def collect_python_files(paths: list[str]) -> list[str]:
    collected: set[str] = set()
    result: list[str] = []

    for path_str in paths:
        p = Path(path_str)
        if not p.exists():
            if path_str not in collected:
                collected.add(path_str)
                result.append(path_str)
            continue

        if p.is_file():
            if any(part in EXCLUDED_DIRS for part in p.parts):
                continue
            canon = str(p)
            if canon not in collected:
                collected.add(canon)
                result.append(canon)
        elif p.is_dir():
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not d.endswith(".egg-info")]
                dirs.sort()
                for file in sorted(files):
                    if file.endswith(".py"):
                        fpath = str(Path(root) / file)
                        if fpath not in collected:
                            collected.add(fpath)
                            result.append(fpath)

    return sorted(result)


def extract_context_keywords(question: str) -> set[str]:
    stop_words = {"the", "and", "for", "where", "what", "how", "defined", "does", "with", "from", "this", "that", "have", "been"}
    keywords: set[str] = set()
    tokens = re.findall(r"[A-Za-z0-9_.]+", question)
    for token in tokens:
        clean = token.strip(".").lower()
        if len(clean) >= 3 and clean not in stop_words:
            keywords.add(clean)
        sub_parts = re.split(r"[_.]", token)
        for part in sub_parts:
            camel_parts = re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?=[A-Z][a-z]|\b)", part)
            for cp in camel_parts:
                cp_lower = cp.lower()
                if len(cp_lower) >= 3 and cp_lower not in stop_words:
                    keywords.add(cp_lower)
    return keywords


def sanitize_source_for_prompt(source: str) -> str:
    sanitized = source.replace("</UNTRUSTED_SOURCE>", "<\\/UNTRUSTED_SOURCE>")
    sanitized = sanitized.replace("<UNTRUSTED_SOURCE>", "<\\UNTRUSTED_SOURCE>")
    sanitized = sanitized.replace("SOURCE_BUNDLE_END", "SOURCE_BUNDLE_\\END")
    sanitized = sanitized.replace("ADDITIONAL_CONTEXT_END", "ADDITIONAL_CONTEXT_\\END")
    return sanitized


class ReviewEngine:
    def __init__(self, llm: LLMClient, db_path: str = "review_history.db"):
        self.llm = llm
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS reviews (review_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")

    @staticmethod
    def review_id(files: list[str], base_dir: Path | None = None) -> str:
        h = hashlib.sha256()
        for file in sorted(files):
            p = Path(file)
            if not p.is_file():
                continue
            try:
                data = p.read_bytes()
            except OSError:
                continue
            rel_name = file
            if base_dir:
                try:
                    rel_name = p.resolve().relative_to(base_dir).as_posix()
                except ValueError:
                    rel_name = file
            h.update(rel_name.encode())
            h.update(b"\0")
            h.update(data)
        return h.hexdigest()[:16]

    def _cached(self, review_id: str) -> ReviewResult | None:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT payload FROM reviews WHERE review_id = ?", (review_id,)).fetchone()
        if not row:
            return None
        data = json.loads(row[0])
        return ReviewResult(
            decision=Decision(data["decision"]),
            findings=[
                Finding(
                    file=f["file"],
                    line=f["line"],
                    finding=f["finding"],
                    severity=Severity(f["severity"]),
                    evidence=f["evidence"],
                    recommendation=f["recommendation"],
                    source=f["source"],
                    confidence=f.get("confidence", 1.0),
                    decision=f.get("decision"),
                )
                for f in data["findings"]
            ],
            static_risk=Severity(data["static_risk"]),
            llm_risk=Severity(data["llm_risk"]),
            llm_available=data["llm_available"],
            iterations=data["iterations"],
            review_id=data["review_id"],
            cached=True,
            notes=data["notes"],
        )

    def _save(self, result: ReviewResult) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT OR REPLACE INTO reviews(review_id, payload) VALUES (?, ?)", (result.review_id, json.dumps(result.as_dict())))

    def review_files(self, files: list[str], base_dir: str | Path | None = None) -> ReviewResult:
        files = collect_python_files(files)
        base_path = Path(base_dir).resolve() if base_dir else None

        def to_rel(fpath: str) -> str:
            if not base_path:
                return fpath
            try:
                return Path(fpath).resolve().relative_to(base_path).as_posix()
            except ValueError:
                return fpath

        rid = self.review_id(files, base_dir=base_path)
        cached = self._cached(rid)
        if cached:
            return cached

        if not files:
            result = ReviewResult(
                decision=Decision.APPROVED,
                findings=[],
                static_risk=Severity.LOW,
                llm_risk=Severity.LOW,
                llm_available=True,
                iterations=0,
                review_id=rid,
                notes=["No Python files to review."],
            )
            self._save(result)
            return result

        static_findings: list[Finding] = []
        analysis_notes: list[str] = []
        source_parts: list[str] = []
        for file in files:
            rel_file = to_rel(file)
            p = Path(file)
            if not p.is_file():
                analysis_notes.append(f"Static analysis skipped {rel_file}: File not found or not a regular file")
                continue
            try:
                source = p.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                analysis_notes.append(f"Static analysis skipped {rel_file}: {exc}")
                continue
            findings, error = scan_file(file)
            if base_path:
                findings = [
                    Finding(
                        file=rel_file,
                        line=f.line,
                        finding=f.finding,
                        severity=f.severity,
                        evidence=f.evidence.replace(str(p), rel_file),
                        recommendation=f.recommendation,
                        source=f.source,
                        confidence=f.confidence,
                        decision=f.decision,
                    )
                    for f in findings
                ]
            static_findings.extend(findings)
            if error:
                analysis_notes.append(error.replace(str(p), rel_file))
            safe_source = sanitize_source_for_prompt(source)
            source_parts.append(f"FILE: {rel_file}\n<UNTRUSTED_SOURCE>\n{safe_source}\n</UNTRUSTED_SOURCE>")

        bundle = "\n\n".join(source_parts)
        llm_findings: list[Finding] = []
        llm_available = True
        iterations = 0
        context = ""
        notes = list(analysis_notes)
        seen_context_requests: set[str] = set()

        while iterations < MAX_ITERATIONS:
            iterations += 1
            try:
                review = self.llm.review(bundle, additional_context=context)
                llm_findings = review.findings
                if base_path:
                    llm_findings = [
                        Finding(
                            file=to_rel(f.file),
                            line=f.line,
                            finding=f.finding,
                            severity=f.severity,
                            evidence=f.evidence,
                            recommendation=f.recommendation,
                            source=f.source,
                            confidence=f.confidence,
                            decision=f.decision,
                        )
                        for f in llm_findings
                    ]
                if review.needs_context and iterations < MAX_ITERATIONS:
                    question_key = "|".join(review.context_questions)
                    if question_key in seen_context_requests:
                        notes.append("Repeated context request blocked by termination guard.")
                        break
                    seen_context_requests.add(question_key)
                    context = self._provide_context(review.context_questions, files, base_dir=base_path)
                    continue
                break
            except Exception as exc:
                llm_available = False
                notes.append(f"LLM review unavailable: {type(exc).__name__}: {exc}")
                break

        decision, static_risk, llm_risk, decision_notes = resolve(static_findings, llm_findings, llm_available)
        notes.extend(decision_notes)
        all_findings = self._merge_findings(static_findings, llm_findings)
        bound_findings = self._bind_finding_decisions(all_findings, decision)
        result = ReviewResult(decision=decision, findings=bound_findings, static_risk=static_risk, llm_risk=llm_risk,
                              llm_available=llm_available, iterations=iterations, review_id=rid, notes=notes)
        self._save(result)
        return result

    @staticmethod
    def _bind_finding_decisions(findings: list[Finding], overall_decision: Decision) -> list[Finding]:
        bound: list[Finding] = []
        for f in findings:
            if overall_decision == Decision.REJECTED:
                f_decision = "REJECTED" if f.severity == Severity.HIGH and f.source.startswith("deterministic") else "REVIEW_REQUIRED"
            elif overall_decision == Decision.REVIEW_REQUIRED:
                f_decision = "REVIEW_REQUIRED"
            else:
                f_decision = "APPROVED"
            bound.append(
                Finding(
                    file=f.file,
                    line=f.line,
                    finding=f.finding,
                    severity=f.severity,
                    evidence=f.evidence,
                    recommendation=f.recommendation,
                    source=f.source,
                    confidence=f.confidence,
                    decision=f_decision,
                )
            )
        return bound

    def _provide_context(self, questions: list[str], files: list[str], base_dir: Path | None = None) -> str:
        # Purposeful bounded context retrieval: only return small relevant slices, no tool execution.
        text = []
        for file in files:
            p = Path(file)
            if not p.is_file():
                continue
            source = p.read_text(encoding="utf-8", errors="replace")
            lines = source.splitlines()
            rel_file = file
            if base_dir:
                try:
                    rel_file = p.resolve().relative_to(base_dir).as_posix()
                except ValueError:
                    rel_file = file
            for q in questions:
                keywords = extract_context_keywords(q)
                if not keywords:
                    continue
                hits = [i for i, line in enumerate(lines) if any(k in line.lower() for k in keywords)]
                for i in hits[:3]:
                    lo, hi = max(0, i - 2), min(len(lines), i + 3)
                    snippet = sanitize_source_for_prompt("\n".join(lines[lo:hi]))
                    text.append(f"{rel_file}:{lo+1}-{hi}\n" + snippet)
        return "\n\n".join(text)[:6000]

    @staticmethod
    def _merge_findings(static: list[Finding], llm: list[Finding]) -> list[Finding]:
        unique: dict[tuple[str, int, str], Finding] = {}
        for f in [*static, *llm]:
            key = (f.file, f.line, f.finding.lower())
            existing = unique.get(key)
            if existing is None or f.confidence > existing.confidence:
                unique[key] = f
        return list(unique.values())
