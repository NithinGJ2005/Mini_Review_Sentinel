# Test Outputs

The following JSON structures are the outputs produced by ReviewSentinel for the representative test scenarios. Note: OS-specific temporary filesystem paths (such as `C:\Users\...\AppData\Local\Temp\...` or `/tmp/...`) produced during automated `tmp_path` test execution have been normalized to relative file names for readability and cross-platform clarity.

## 1. Genuine SQL Injection (`test_sql_injection_rejected`)

```json
{
  "review_id": "d393f5565fd0ffb3",
  "cached": false,
  "decision": "REJECTED",
  "static_risk": "HIGH",
  "llm_risk": "LOW",
  "llm_available": true,
  "iterations": 1,
  "findings": [
    {
      "file": "payments.py",
      "line": 1,
      "finding": "SQL Injection",
      "severity": "HIGH",
      "evidence": "The SQL query is an f-string containing interpolated expressions before execute().",
      "recommendation": "Use a parameterized query with placeholders and pass user-controlled values separately.",
      "decision": "REJECTED",
      "source": "deterministic:ast",
      "confidence": 1.0
    }
  ],
  "notes": [
    "Deterministic HIGH-risk finding is authoritative for rejection ('SQL Injection' at payments.py:1).",
    "LLM disagreed (reported LOW risk); deterministic rule for 'SQL Injection' at payments.py:1 wins because evidence is reproducible."
  ]
}
```

## 2. Safe Parameterized SQL (`test_safe_parameterized_sql`)

```json
{
  "review_id": "709d24448d7b39da",
  "cached": false,
  "decision": "APPROVED",
  "static_risk": "LOW",
  "llm_risk": "LOW",
  "llm_available": true,
  "iterations": 1,
  "findings": [],
  "notes": []
}
```

## 3. Hard-Coded Secret (`test_hardcoded_secret`)

```json
{
  "review_id": "09283c04d73a774a",
  "cached": false,
  "decision": "REJECTED",
  "static_risk": "HIGH",
  "llm_risk": "LOW",
  "llm_available": true,
  "iterations": 1,
  "findings": [
    {
      "file": "config.py",
      "line": 1,
      "finding": "Hard-coded secret",
      "severity": "HIGH",
      "evidence": "AWS access key appears as a concrete credential-like string in source code.",
      "recommendation": "Move the secret to a secure environment/secret manager and rotate it if it was exposed.",
      "decision": "REJECTED",
      "source": "deterministic:regex",
      "confidence": 1.0
    }
  ],
  "notes": [
    "Deterministic HIGH-risk finding is authoritative for rejection ('Hard-coded secret' at config.py:1).",
    "LLM disagreed (reported LOW risk); deterministic rule for 'Hard-coded secret' at config.py:1 wins because evidence is reproducible."
  ]
}
```

## 4. Dangerous Use of `eval()` (`examples/eval_danger.py`)

```json
{
  "review_id": "bca5aaeec7dfed1f",
  "cached": false,
  "decision": "REJECTED",
  "static_risk": "HIGH",
  "llm_risk": "LOW",
  "llm_available": false,
  "iterations": 1,
  "findings": [
    {
      "file": "examples/eval_danger.py",
      "line": 3,
      "finding": "Dangerous use of eval()",
      "severity": "HIGH",
      "evidence": "The call invokes built-in eval(), which can execute attacker-controlled Python code.",
      "recommendation": "Avoid eval(); use a safe parser or a constrained API for the required operation.",
      "decision": "REJECTED",
      "source": "deterministic:ast",
      "confidence": 1.0
    }
  ],
  "notes": [
    "LLM review unavailable: TimeoutError: LLM unavailable",
    "Deterministic HIGH-risk finding is authoritative for rejection ('Dangerous use of eval()' at examples/eval_danger.py:3)."
  ]
}
```
