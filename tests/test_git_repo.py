from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import pytest

from app.cli import main
from app.git_repo import (
    GitCloneError,
    GitInvalidUrlError,
    GitRepoNotFoundError,
    GitUnavailableError,
    acquire_repository,
    clone_repository,
    is_git_url,
    safe_rmtree,
    validate_git_url,
)
from app.llm import MockLLM
from app.models import Decision, Severity
from app.reviewer import ReviewEngine, collect_python_files


def base_llm():
    return {"risk": "LOW", "summary": "Clean.", "needs_context": False, "context_questions": [], "findings": []}


def create_local_git_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    repo_dir = tmp_path / "source_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", str(repo_dir)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.email", "test@sentinel.local"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.name", "ReviewSentinel"], check=True, capture_output=True)

    for rel_path, content in files.items():
        file_path = repo_dir / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8")

    subprocess.run(["git", "-C", str(repo_dir), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "initial commit"], check=True, capture_output=True)
    return repo_dir


# =========================================================================
# Test 1 — Local Git-style repository
# =========================================================================
def test_local_git_style_repository(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    # Create .git directory with a Python file inside it
    git_dir = repo_dir / ".git" / "hooks"
    git_dir.mkdir(parents=True)
    (git_dir / "pre-commit.py").write_text("eval(user_input)\n", encoding="utf-8")

    # Create app/ directory with example.py
    app_dir = repo_dir / "app"
    app_dir.mkdir()
    (app_dir / "example.py").write_text("x = 1\n", encoding="utf-8")

    # Create README.md
    (repo_dir / "README.md").write_text("# Test Repo\n", encoding="utf-8")

    # Discover files
    discovered = collect_python_files([str(repo_dir)])

    # Verify: Python files outside .git are analyzed, .git contents are ignored
    assert len(discovered) == 1
    assert discovered[0].replace("\\", "/").endswith("app/example.py")
    assert not any(".git" in f for f in discovered)

    # Review via engine
    engine = ReviewEngine(MockLLM([base_llm()]), db_path=str(tmp_path / "test1.db"))
    result = engine.review_files([str(repo_dir)])

    assert result.decision == Decision.APPROVED
    assert len(result.findings) == 0


# =========================================================================
# Test 2 — Remote Git repository (full flow via file:// URL)
# =========================================================================
def test_remote_git_repository_full_flow(tmp_path):
    # Setup local git repository acting as remote
    source_repo = create_local_git_repo(
        tmp_path,
        {
            "app/example.py": "result = eval(user_input)\n",
            "app/safe.py": "total = 42\n",
            "README.md": "# Sample Project\n",
        },
    )

    file_url = f"file:///{source_repo.resolve().as_posix()}"
    engine = ReviewEngine(MockLLM([base_llm()]), db_path=str(tmp_path / "remote.db"))

    # Verify repository acquisition and review flow
    with acquire_repository(file_url) as (repo_path, base_dir):
        assert repo_path.exists()
        assert base_dir is not None

        py_files = collect_python_files([str(repo_path)])
        assert len(py_files) == 2

        result = engine.review_files(py_files, base_dir=base_dir)

    # Verify final decision is REJECTED due to eval
    assert result.decision == Decision.REJECTED
    assert result.static_risk == Severity.HIGH
    assert len(result.findings) == 1
    # Verify path is relative to repository root, not exposing temp dir
    assert result.findings[0].file == "app/example.py"
    assert result.findings[0].line == 1
    assert "eval" in result.findings[0].finding


# =========================================================================
# Test 3 — Clone failure (controlled errors)
# =========================================================================
def test_clone_failure_invalid_url(monkeypatch, capsys):
    test_args = ["cli.py", "https://invalid_url;bad"]
    monkeypatch.setattr(sys, "argv", test_args)

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "Unable to clone repository: invalid repository URL." in output
    assert "Traceback" not in output


def test_clone_failure_short_invalid_url(monkeypatch, capsys):
    test_args = ["cli.py", "https://"]
    monkeypatch.setattr(sys, "argv", test_args)

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "Unable to clone repository: invalid repository URL." in output
    assert "Traceback" not in output


def test_clone_failure_repo_not_found(monkeypatch, capsys):
    test_args = ["cli.py", "https://github.com/sentinel-nonexistent-org-0000/nonexistent-repo-9999.git"]
    monkeypatch.setattr(sys, "argv", test_args)

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "Unable to clone repository: repository not found or inaccessible." in output
    assert "Traceback" not in output


def test_git_unavailable_controlled_error(monkeypatch, capsys):
    monkeypatch.setattr(shutil, "which", lambda cmd: None if cmd == "git" else shutil.which(cmd))
    test_args = ["cli.py", "https://github.com/user/repo.git"]
    monkeypatch.setattr(sys, "argv", test_args)

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "Git executable was not found. Install Git and try again." in output
    assert "Traceback" not in output


# =========================================================================
# Test 4 — Temporary cleanup on success and failure
# =========================================================================
def test_temporary_clone_cleanup_on_success(tmp_path):
    source_repo = create_local_git_repo(
        tmp_path,
        {"app/main.py": "x = 10\n"},
    )
    file_url = f"file:///{source_repo.resolve().as_posix()}"

    captured_clone_path = None
    with acquire_repository(file_url) as (repo_path, _):
        captured_clone_path = repo_path
        assert captured_clone_path.exists()

    assert captured_clone_path is not None
    assert not captured_clone_path.exists()
    assert not captured_clone_path.parent.exists()


def test_temporary_clone_cleanup_on_failure(tmp_path):
    source_repo = create_local_git_repo(
        tmp_path,
        {"app/main.py": "x = 10\n"},
    )
    file_url = f"file:///{source_repo.resolve().as_posix()}"

    captured_clone_path = None
    try:
        with acquire_repository(file_url) as (repo_path, _):
            captured_clone_path = repo_path
            assert captured_clone_path.exists()
            raise RuntimeError("Simulated failure during analysis")
    except RuntimeError:
        pass

    assert captured_clone_path is not None
    assert not captured_clone_path.exists()
    assert not captured_clone_path.parent.exists()


# =========================================================================
# Test 5 — URL Detection & Branch / Ref Support
# =========================================================================
def test_is_git_url_recognition():
    # Recognized Git URLs
    assert is_git_url("https://github.com/user/repository.git")
    assert is_git_url("https://github.com/user/repository")
    assert is_git_url("http://gitlab.com/user/repo")
    assert is_git_url("git@github.com:user/repository.git")
    assert is_git_url("git@gitlab.com:org/project")
    assert is_git_url("ssh://git@github.com/user/repo.git")
    assert is_git_url("git://github.com/user/repo.git")
    assert is_git_url("file:///path/to/repo")

    # Ordinary local paths (must NOT be recognized as Git URLs)
    assert not is_git_url("file.py")
    assert not is_git_url("examples/payments.py")
    assert not is_git_url("directory/")
    assert not is_git_url(".")
    assert not is_git_url("C:\\path\\to\\file.py")
    assert not is_git_url("C:/path/to/file.py")
    assert not is_git_url("")


def test_branch_ref_checkout(tmp_path):
    source_repo = create_local_git_repo(
        tmp_path,
        {"app/main.py": "x = 1\n"},
    )
    # Create feature branch with a secret
    subprocess.run(["git", "-C", str(source_repo), "checkout", "-b", "feature"], check=True, capture_output=True)
    mock_key = "".join(["AKIA", "1234567890ABCDEF"])
    (source_repo / "app" / "secret.py").write_text(f'api_key = "{mock_key}"\n', encoding="utf-8")
    subprocess.run(["git", "-C", str(source_repo), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(source_repo), "commit", "-m", "add secret on feature branch"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(source_repo), "checkout", "master"], check=True, capture_output=True)

    file_url = f"file:///{source_repo.resolve().as_posix()}"
    engine = ReviewEngine(MockLLM([base_llm()]), db_path=str(tmp_path / "branch.db"))

    # Reviewing with --ref feature must find the secret
    with acquire_repository(file_url, ref="feature") as (repo_path, base_dir):
        py_files = collect_python_files([str(repo_path)])
        assert any("secret.py" in f for f in py_files)
        result = engine.review_files(py_files, base_dir=base_dir)

    assert result.decision == Decision.REJECTED
    assert any(f.finding == "Hard-coded secret" and f.file == "app/secret.py" for f in result.findings)


def test_remote_git_repo_cli_human_output(tmp_path, monkeypatch, capsys):
    source_repo = create_local_git_repo(
        tmp_path,
        {
            "src/payments.py": "result = eval(payload)\n",
        },
    )
    file_url = f"file:///{source_repo.resolve().as_posix()}"
    test_args = ["cli.py", file_url, "--db", str(tmp_path / "cli_test.db")]
    monkeypatch.setattr(sys, "argv", test_args)

    main()

    captured = capsys.readouterr()
    output = captured.out

    # Must contain required fields:
    # File, Line, Finding, Severity, Evidence, Recommendation, Decision
    assert "src/payments.py:1" in output
    assert "Finding: Dangerous use of eval()" in output
    assert "Severity: HIGH" in output
    assert "Evidence:" in output
    assert "Recommendation:" in output
    assert "Decision:\nREJECTED" in output or "Decision: REJECTED" in output
    # Must NOT expose temporary clone directory in output
    assert "review_sentinel_" not in output


def test_remote_git_repo_cli_json_output(tmp_path, monkeypatch, capsys):
    import json

    source_repo = create_local_git_repo(
        tmp_path,
        {
            "src/auth.py": 'query = f"SELECT * FROM users WHERE id = {user_id}"\ncursor.execute(query)\n',
        },
    )
    file_url = f"file:///{source_repo.resolve().as_posix()}"
    test_args = ["cli.py", file_url, "--json", "--db", str(tmp_path / "cli_json.db")]
    monkeypatch.setattr(sys, "argv", test_args)

    main()

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert data["decision"] == "REJECTED"
    assert len(data["findings"]) == 1
    finding = data["findings"][0]
    assert finding["file"] == "src/auth.py"
    assert finding["line"] == 1
    assert finding["finding"] == "SQL Injection"
    assert finding["severity"] == "HIGH"
    assert "query" in finding["evidence"]
    assert "parameterized" in finding["recommendation"]
    assert finding["decision"] == "REJECTED"
    assert "review_sentinel_" not in finding["file"]


def test_clone_subprocess_error_classification(tmp_path, monkeypatch):
    class FakeProcess:
        def __init__(self, returncode, stderr):
            self.returncode = returncode
            self.stderr = stderr
            self.stdout = ""

    # Test authentication failed maps to GitRepoNotFoundError
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: FakeProcess(128, "fatal: Authentication failed for 'https://github.com/user/private.git'"),
    )
    with pytest.raises(GitRepoNotFoundError) as exc_info:
        clone_repository("https://github.com/user/private.git", tmp_path / "dest1")
    assert "repository not found or inaccessible" in str(exc_info.value)

    # Test could not resolve host maps to GitRepoNotFoundError
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: FakeProcess(128, "fatal: unable to access 'https://github.com/': Could not resolve host: github.com"),
    )
    with pytest.raises(GitRepoNotFoundError) as exc_info:
        clone_repository("https://github.com/user/repo.git", tmp_path / "dest2")
    assert "repository not found or inaccessible" in str(exc_info.value)

    # Test invalid repo name maps to GitInvalidUrlError
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: FakeProcess(128, "fatal: 'bad:repo' is not a valid repository name"),
    )
    with pytest.raises(GitInvalidUrlError) as exc_info:
        clone_repository("https://github.com/bad/repo.git", tmp_path / "dest3")
    assert "invalid repository URL" in str(exc_info.value)

