from __future__ import annotations

import argparse
import json
import os
import sys

from .git_repo import (
    GitCloneError,
    GitError,
    GitInvalidUrlError,
    GitRepoNotFoundError,
    GitUnavailableError,
    acquire_repository,
    is_git_url,
)
from .llm import GeminiLLM, UnavailableLLM
from .models import Decision, Severity
from .reviewer import ReviewEngine, collect_python_files


def run_review(py_files: list[str], args: argparse.Namespace, base_dir: str | None = None) -> None:
    if os.getenv("GOOGLE_API_KEY"):
        try:
            llm = GeminiLLM()
        except Exception:
            llm = UnavailableLLM()
    else:
        llm = UnavailableLLM()

    result = ReviewEngine(llm, db_path=args.db).review_files(py_files, base_dir=base_dir)
    if args.json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        print(f"Decision: {result.decision.value}")
        print(f"Static risk: {result.static_risk.value} | LLM risk: {result.llm_risk.value} | Iterations: {result.iterations}")
        for f in result.findings:
            f_decision = f.decision or ("REJECTED" if result.decision == Decision.REJECTED and f.severity == Severity.HIGH else "REVIEW_REQUIRED")
            print(f"\n{f.file}:{f.line}\n\nFinding: {f.finding}\nSeverity: {f.severity.value}\n\nEvidence:\n{f.evidence}\n\nRecommendation:\n{f.recommendation}\n\nDecision:\n{f_decision}")
        if result.notes:
            print("\nNotes:")
            for note in result.notes:
                print(f"- {note}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mini ReviewSentinel - Automated code review for Python files and Git repositories.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Review a single Python file
  python -m app.cli examples/payments.py

  # Review a directory of Python files
  python -m app.cli examples/

  # Review the local repository
  python -m app.cli .

  # Review a remote Git repository (clones into temporary directory, reviews Python source, cleans up)
  python -m app.cli https://github.com/user/repository.git
  python -m app.cli https://github.com/user/repository.git --ref main
""",
    )
    parser.add_argument("files", nargs="+", help="Python files, directories, or Git repository URL to review")
    parser.add_argument("--ref", "--branch", default=None, help="Optional branch, tag, or ref to checkout after cloning")
    parser.add_argument("--db", default="review_history.db")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    # Determine if input is a Git repository URL
    if len(args.files) == 1 and is_git_url(args.files[0]):
        target_url = args.files[0]
        try:
            with acquire_repository(target_url, ref=args.ref) as (repo_path, base_dir):
                py_files = collect_python_files([str(repo_path)])
                run_review(py_files, args, base_dir=str(base_dir) if base_dir else None)
        except GitUnavailableError:
            print("Git executable was not found. Install Git and try again.")
            sys.exit(1)
        except GitInvalidUrlError:
            print("Unable to clone repository: invalid repository URL.")
            sys.exit(1)
        except GitRepoNotFoundError:
            print("Unable to clone repository: repository not found or inaccessible.")
            sys.exit(1)
        except GitCloneError as exc:
            print(str(exc))
            sys.exit(1)
        except Exception as exc:
            print(f"Unable to clone repository: {exc}")
            sys.exit(1)
        return

    # Check for invalid URL passed that didn't match git url schemes
    if len(args.files) == 1 and any(args.files[0].startswith(prefix) for prefix in ("http:/", "https:/", "git@", "ssh:/", "git:/")):
        print("Unable to clone repository: invalid repository URL.")
        sys.exit(1)

    missing = [f for f in args.files if not os.path.exists(f)]
    if missing:
        print(f"Error: File(s) not found: {', '.join(missing)}")
        sys.exit(1)

    py_files = collect_python_files(args.files)
    run_review(py_files, args, base_dir=None)


if __name__ == "__main__":
    main()
