# Design Decisions

## A. Static vs LLM disagreement

### Static HIGH, LLM LOW

`REJECTED`.

The static rule is deterministic and reproducible. For the three mandatory security checks, an LLM should not be allowed to talk the system out of evidence that is directly observable in the syntax/AST.

### Static LOW, LLM HIGH

`REVIEW_REQUIRED`.

An LLM can notice contextual business-logic problems that a narrow deterministic rule cannot. Because that signal is probabilistic, it escalates to human review instead of causing an automatic rejection.

## B. LLM failure

The review continues with deterministic analysis. If there are no medium/high deterministic findings, the system may approve, but the result records that the LLM was unavailable.

This is a deliberate fail-safe for a small assignment: security checks remain available even when the external dependency is down.

## C. LLM output validation

The provider adapter requires a JSON object. Findings must contain the expected fields and enum values. Malformed JSON or unexpected shapes raise a controlled exception that is converted into an LLM-unavailable path. Raw model text is never directly used as the decision.

## D. Agent termination

`MAX_ITERATIONS = 2` is a hard upper bound. A repeated identical context request is also blocked. Therefore the engine cannot enter an unbounded review/context/re-review loop.

## E. False positives

A difficult false positive is distinguishing harmless occurrences of security-related terms from genuine vulnerabilities. 

### Why AST is superior to raw string/regex scanning
1. **Method name collisions**: Libraries like PyTorch define `model.eval()`, and task runners define `worker.execute(task)`. A naive string or regex scanner matches the keywords `eval(` or `execute(` and triggers false-positive code execution or SQL injection rejections. AST analysis inspects Python syntax tree nodes: it verifies whether `eval()` is a bare built-in function invocation (`ast.Name(id='eval')`) or an attribute call on an object (`ast.Attribute(attr='eval')`), safely allowing domain methods.
2. **SQL structure vs keyword presence**: A query containing the word `SELECT` or `execute` is not vulnerable if it uses parameter placeholders (`?` or `%s`) passed as separate arguments. AST analysis traces whether the query argument into `cursor.execute()` is an expression (`ast.JoinedStr`, `ast.BinOp` with `+` or `%`, `str.format()`) versus a parameterized call (`len(args) >= 2`), eliminating false alarms on safe parameterization.
3. **Environment lookups vs hardcoded secrets**: Scanners matching variable names like `api_key = ...` often flag `api_key = os.environ.get("API_KEY")`. Our regex requires concrete quoted string literals with minimum length thresholds and excludes standard placeholder prefixes (`mock_`, `dummy_`, `sample_`, `<api_key>`, `test_key_`), preventing false alarms on secure configuration patterns.

## F. One trade-off: Explicit State Machine vs Multi-Agent Framework

I deliberately chose a small, explicit Python state machine (`MAX_ITERATIONS = 2` loop inside `ReviewEngine`) over introducing a multi-agent orchestration framework (such as LangGraph or AutoGen).

### Why this simpler solution was chosen:
1. **Easier to reason about**: The review lifecycle follows a transparent sequence: initial review -> optional bounded context retrieval -> re-evaluation -> deterministic decision. Every transition has clear, explicit preconditions in plain Python.
2. **Guaranteed bounded termination**: Multi-agent setups risk complex recursive loops or emergent agent chats. An explicit iteration counter and question deduplication set provide a mathematically provable termination guarantee.
3. **Deterministic control flow for security**: In security gatekeeping, the decision policy must be reproducible. Frameworks with inter-agent negotiation add non-deterministic variability to critical policy enforcement.
4. **Simpler failure modes**: When an LLM API times out or emits malformed output, the state machine catches the exception and immediately falls back to deterministic static analysis without orphaned agent state.
5. **Easier testing and defense**: The state machine operates against clean abstractions (`LLMClient`), allowing comprehensive unit testing with deterministic test doubles (`MockLLM`) that execute in fractions of a second without requiring API keys or heavy dependencies.

The trade-off is giving up general-purpose multi-agent choreography in exchange for a lightweight, robust, highly testable, and defensible architecture suited for this assignment.

## G. Lightweight Repository Acquisition vs GitHub API Integration

Remote Git support was implemented via a lightweight, subprocess-based repository-acquisition layer rather than integrating with the GitHub REST/GraphQL API.

### Why this approach was chosen:
1. **Repository input requirement**: The goal is evaluating repository source code, which only requires obtaining the repository files on disk.
2. **Cloning is sufficient**: Standard shallow cloning (`git clone --depth 1`) retrieves the exact working tree needed for source analysis across any Git host (GitHub, GitLab, Bitbucket, self-hosted), not just GitHub.
3. **No GitHub API authentication required**: Avoids requiring GitHub personal access tokens, OAuth flows, rate limiting constraints, or network API schemas.
4. **Source code focus**: The reviewer evaluates source code AST and semantics, not Git commit metadata, pull request comments, or issues.
5. **Simplicity and testability**: Isolating repository acquisition as an input adapter cleanly decouples source retrieval from review logic. This makes the architecture straightforward to test locally (using local file/git URLs) with zero external network or service dependencies.

