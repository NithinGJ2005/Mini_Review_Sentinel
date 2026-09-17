# Design Decisions

## A. Static vs LLM Disagreement

**Simple explanation:**
Deterministic static checks act as the non-negotiable security baseline. When hard evidence in the source code shows a high-risk security flaw, the LLM cannot override it. If the LLM suspects a contextual business-logic problem that static checks missed, a human must review it.

**What happens:**
- Static HIGH + LLM LOW → `REJECTED`
- Static LOW + LLM HIGH → `REVIEW_REQUIRED`

**Why:**
- Deterministic analysis inspects concrete syntax (such as dynamic SQL interpolation or hardcoded secrets). If that vulnerability is physically present in the code, an LLM must not be allowed to talk the system out of observable evidence.
- An LLM can spot subtle business-logic flaws that static rules cannot catch. Because LLM reasoning is probabilistic rather than mathematically proven, its findings escalate to human review instead of triggering automatic rejection.

**Technical note:**
The conflict resolution policy in `resolve()` enforces deterministic checks as an absolute security floor while using the LLM as an advisory detector for broader context.

---

## B. LLM Failure

**Simple explanation:**
If the LLM is unreachable, times out, or encounters network errors, the review does not crash. ReviewSentinel falls back to deterministic static analysis alone so security checks remain dependable.

**What happens:**
- If static analysis finds HIGH risk → `REJECTED`
- If static analysis finds MEDIUM risk → `REVIEW_REQUIRED`
- If static analysis finds NO issues → `APPROVED` (with an explicit note stating the LLM was unavailable)

**Why:**
Security gating should never completely stop simply because an external cloud API is down. Critical security vulnerabilities (`eval()`, SQL injection, hardcoded credentials) can still be caught locally and reliably by static analysis.

**Technical note:**
`ReviewEngine` catches all provider exceptions, records `llm_available = False`, and preserves the note in the final audit trail without losing static findings.

---

## C. LLM Output Validation

**Simple explanation:**
The system never trusts raw text output from an AI model. All model responses must follow a strict, structured JSON schema before being processed.

**What happens:**
- Valid JSON matching our schema → Findings are parsed, bound to decisions, and merged.
- Malformed JSON, markdown chatter, or unexpected values → The parser catches the error, marks the LLM as unavailable, and safely continues with deterministic analysis.

**Why:**
LLMs are non-deterministic and can produce conversational preamble, missing fields, or invalid enum values. Strict schema validation protects the downstream review pipeline from crashing or corrupting review decisions.

**Technical note:**
`parse_llm_payload()` extracts JSON objects even when surrounded by markdown code blocks, validates required keys and `Severity` enums, and raises controlled exceptions on invalid structures.

---

## D. Agent Termination

**Simple explanation:**
The agentic context-gathering loop has strict, hardcoded limits so it can never run indefinitely or consume infinite API tokens.

**What happens:**
- The review loop terminates after at most 2 iterations (`MAX_ITERATIONS = 2`).
- If the model requests the exact same additional context questions, the loop stops immediately.

**Why:**
Without bounds, an autonomous agent loop can get trapped in recursive re-evaluation or cycle through repeated questions. Hardcoded limits guarantee that review execution always finishes quickly.

**Technical note:**
`ReviewEngine` tracks an explicit iteration counter against `MAX_ITERATIONS` and maintains a set of hashed question strings (`seen_context_requests`) to break cyclic requests.

---

## E. False Positives

**Simple explanation:**
ReviewSentinel uses Python Abstract Syntax Tree (AST) analysis rather than naive keyword search. This prevents ordinary, harmless code from being falsely reported as security flaws.

**What happens:**
- Safe method calls like `model.eval()` or `task.execute()` are ignored.
- Parameterized SQL queries are recognized as safe.
- Environment variable lookups are not flagged as hardcoded secrets.

**Why:**
- **Method name collisions**: A naive regex matching `eval(` flags standard library methods like PyTorch's `model.eval()`. AST analysis checks whether `eval()` is a bare built-in function call or an attribute method on an object.
- **SQL parameterization**: The detector inspects the query argument passed to `cursor.execute()`. If the query is constructed using dynamic string formatting (f-strings, `+` concatenation, `%` interpolation, or `.format()`), it is flagged as unsafe. If the query is a static string literal using parameter placeholders (`?` or `%s`) with values passed separately, it is recognized as safe.
- **Secrets vs Environment variables**: Scanners looking for `api_key = ...` often flag `api_key = os.getenv("API_KEY")`. ReviewSentinel requires literal quoted strings and explicitly ignores standard placeholder prefixes (`test_key_`, `mock_`, `dummy_`, `<api_key>`).

**Technical note:**
AST parsing evaluates code structure (`ast.Call`, `ast.JoinedStr`, `ast.Constant`) instead of raw text matches, eliminating common false alarms.

---

## F. One Trade-off: Explicit State Machine vs Multi-Agent Framework

**Simple explanation:**
We chose a small, explicit Python state machine (`MAX_ITERATIONS = 2`) over a complex multi-agent framework (like LangGraph or AutoGen).

**What happens:**
- The review follows an explicit sequence: static scan → initial LLM review → optional bounded context retrieval → final decision.
- There are no background agent negotiations or unpredictable conversational loops.

**Why:**
- **Easy to reason about**: The entire lifecycle is plain Python with clear preconditions and transitions.
- **Guaranteed termination**: Mathematical certainty that the review finishes in at most 2 cycles.
- **Deterministic security decisions**: Security gatekeeping requires reproducible, consistent outcomes.
- **Fast and testable**: No heavy frameworks or background workers, allowing all 40 unit and integration tests to run in seconds without external services.

**Technical note:**
Clean abstractions (`LLMClient`) allow deterministic testing with test doubles (`MockLLM`) that verify every transition without live API keys.

---

## G. Lightweight Repository Acquisition vs GitHub API Integration

**Simple explanation:**
To support Git repositories, ReviewSentinel uses a lightweight local clone command instead of integrating with the GitHub REST API.

**What happens:**
- The repository is cloned into a temporary working directory via `git clone --depth 1`.
- The Python files are discovered and reviewed as local data.
- The temporary directory is completely removed immediately after review finishes.

**Why:**
- **Repository input requirement**: ReviewSentinel evaluates source code files, not pull request metadata, issues, or commit histories.
- **Universal compatibility**: Shallow cloning works across GitHub, GitLab, Bitbucket, and self-hosted Git servers without provider-specific code.
- **Zero authentication overhead**: Does not require setting up GitHub personal access tokens, managing OAuth, or handling API rate limits.
- **Data safety**: The repository remains passive data—no repository code (`setup.py`, `Makefile`, shell scripts) is ever executed.

**Technical note:**
`app/git_repo.py` manages shallow cloning with disabled hooks and disabled prompts, guarantees cleanup on Windows despite read-only packfiles, and translates clone failures into clean errors without tracebacks.
