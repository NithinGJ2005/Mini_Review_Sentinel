from __future__ import annotations

import ast
import re
from pathlib import Path

from .models import Finding, Severity

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Generic API key", re.compile(r"(?i)\b(api[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]")),
    ("Generic secret assignment", re.compile(r"(?i)\b(password|passwd|secret|token)\s*=\s*['\"][^'\"]{12,}['\"]")),
]

SQL_EXEC_METHODS = {"execute", "executemany", "executescript"}


def _line_for_offset(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _is_literal_string(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _const_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def scan_python(file: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(source, filename=file)
    except SyntaxError:
        return []  # analysis failure is non-fatal; caller records it

    # Dangerous eval/exec: deterministic AST check, not a substring search.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            name = node.func.id
            findings.append(
                Finding(
                    file=file,
                    line=node.lineno,
                    finding=f"Dangerous use of {name}()",
                    severity=Severity.HIGH,
                    evidence=f"The call invokes built-in {name}(), which can execute attacker-controlled Python code.",
                    recommendation=f"Avoid {name}(); use a safe parser or a constrained API for the required operation.",
                    source="deterministic:ast",
                )
            )

    # SQL injection: track simple string construction into execute-like calls.
    assignments: dict[str, tuple[ast.AST, int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = (node.value, node.lineno)

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in SQL_EXEC_METHODS:
            if not node.args:
                continue
            query = node.args[0]
            query_node = query
            query_line = getattr(query, "lineno", node.lineno)
            if isinstance(query, ast.Name) and query.id in assignments:
                query_node, query_line = assignments[query.id]

            unsafe = False
            evidence = ""
            if isinstance(query_node, ast.JoinedStr):
                unsafe = True
                evidence = "The SQL query is an f-string containing interpolated expressions before execute()."
            elif isinstance(query_node, ast.BinOp) and isinstance(query_node.op, ast.Add):
                unsafe = True
                evidence = "The SQL query is built by concatenating expressions before execute()."
            elif isinstance(query_node, ast.BinOp) and isinstance(query_node.op, ast.Mod):
                unsafe = True
                evidence = "The SQL query uses '%' string interpolation before execute()."
            elif isinstance(query_node, ast.Call) and isinstance(query_node.func, ast.Attribute) and query_node.func.attr == "format":
                unsafe = True
                evidence = "The SQL query uses str.format() interpolation before execute()."

            if unsafe:
                if query_line != node.lineno:
                    evidence += f" Unsafe query constructed at line {query_line} and executed at line {node.lineno}."
                if len(node.args) >= 2:
                    evidence += " Passing separate parameters does not neutralize dynamic query interpolation."
                findings.append(
                    Finding(
                        file=file,
                        line=query_line,
                        finding="SQL Injection",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        recommendation="Use a parameterized query with placeholders and pass user-controlled values separately.",
                        source="deterministic:ast",
                    )
                )

    # Hard-coded secrets: context-aware regex + AST assignment filtering.
    for line_no, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for label, pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            value_text = line[match.start(): match.end()]
            # Obvious placeholders/examples should not be flagged.
            lowered = value_text.lower()
            placeholders = {
                "your_api_key_here",
                "changeme",
                "example_secret",
                "test_secret",
                "mock_",
                "dummy_",
                "sample_",
                "<api_key>",
                "<secret>",
                "test_key_",
            }
            if any(p in lowered for p in placeholders):
                continue
            findings.append(
                Finding(
                    file=file,
                    line=line_no,
                    finding="Hard-coded secret",
                    severity=Severity.HIGH,
                    evidence=f"{label} appears as a concrete credential-like string in source code.",
                    recommendation="Move the secret to a secure environment/secret manager and rotate it if it was exposed.",
                    source="deterministic:regex",
                )
            )
            break

    # De-duplicate same file/line/finding.
    unique: dict[tuple[str, int, str], Finding] = {}
    for f in findings:
        unique[(f.file, f.line, f.finding)] = f
    return list(unique.values())


def scan_file(file: str) -> tuple[list[Finding], str | None]:
    path = Path(file)
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [], f"Could not read {file}: {exc}"
    if path.suffix == ".py":
        try:
            ast.parse(source, filename=file)
        except SyntaxError as exc:
            return [], f"Python parse failure in {file}: {exc}"
        return scan_python(file, source), None
    return [], None
