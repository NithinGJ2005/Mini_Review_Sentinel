from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from typing import Generator
from urllib.parse import urlparse


class GitError(Exception):
    """Base exception for Git repository operations."""
    pass


class GitUnavailableError(GitError):
    """Raised when git executable is not found."""
    pass


class GitInvalidUrlError(GitError):
    """Raised when repository URL is invalid."""
    pass


class GitRepoNotFoundError(GitError):
    """Raised when repository does not exist or is inaccessible."""
    pass


class GitCloneError(GitError):
    """Raised when git clone fails due to network or other errors."""
    pass


def is_git_url(target: str) -> bool:
    """
    Determines if the given target string is a Git repository URL
    rather than a local filesystem path.
    """
    if not isinstance(target, str):
        return False
    target = target.strip()
    if not target:
        return False

    # Check for SCP-style SSH Git URL: git@host:user/repo.git or git@host:repo
    if target.startswith("git@") and ":" in target:
        return True

    # Check standard URL schemes
    if target.startswith(("https://", "http://", "git://", "ssh://", "file://")):
        return True

    return False


def validate_git_url(url: str) -> None:
    """
    Validates the structure and character safety of a Git repository URL.
    Raises GitInvalidUrlError if the URL is malformed or contains dangerous shell characters.
    """
    url = url.strip()
    # Reject null bytes or line breaks
    if any(c in url for c in "\0\r\n\t"):
        raise GitInvalidUrlError("Unable to clone repository: invalid repository URL.")

    if url.startswith("file://"):
        # file:// URLs represent local repositories (e.g. in tests or local workflows)
        path_part = url[7:]
        if not path_part.strip("/"):
            raise GitInvalidUrlError("Unable to clone repository: invalid repository URL.")
        return

    # Reject shell injection characters, quotes, and whitespace in remote URLs
    if any(c in url for c in " \"'<>|;$`"):
        raise GitInvalidUrlError("Unable to clone repository: invalid repository URL.")

    if url.startswith("git@"):
        parts = url.split(":", 1)
        if len(parts) != 2:
            raise GitInvalidUrlError("Unable to clone repository: invalid repository URL.")
        host, repo = parts[0][4:], parts[1].strip("/")
        if not host or not repo:
            raise GitInvalidUrlError("Unable to clone repository: invalid repository URL.")
        return

    parsed = urlparse(url)
    if parsed.scheme in ("https", "http", "git", "ssh"):
        if not parsed.netloc:
            raise GitInvalidUrlError("Unable to clone repository: invalid repository URL.")
        # Path should contain at least a repository identifier (e.g. /user/repo or /repo)
        path = parsed.path.strip("/")
        if not path:
            raise GitInvalidUrlError("Unable to clone repository: invalid repository URL.")
        return

    raise GitInvalidUrlError("Unable to clone repository: invalid repository URL.")


def safe_rmtree(path: Path | str) -> None:
    """
    Safely removes a directory tree, handling Windows read-only file attributes
    (commonly placed on .git files/packfiles) so cleanup never fails or leaves files behind.
    """
    target = Path(path)
    if not target.exists():
        return

    def _remove_readonly(func, subpath, _):
        try:
            os.chmod(subpath, stat.S_IWRITE | stat.S_IREAD)
            func(subpath)
        except Exception:
            pass

    try:
        shutil.rmtree(target, onerror=_remove_readonly)
    except Exception:
        shutil.rmtree(target, ignore_errors=True)


def clone_repository(
    url: str,
    dest_dir: Path | str,
    ref: str | None = None,
    timeout_seconds: int = 60,
) -> Path:
    """
    Clones a remote Git repository into dest_dir safely and reliably without executing
    arbitrary repository code.
    """
    git_bin = shutil.which("git")
    if not git_bin:
        raise GitUnavailableError("Git executable was not found. Install Git and try again.")

    validate_git_url(url)

    dest_path = Path(dest_dir)
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    # Disable interactive terminal prompts and credential manager dialogs
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = ""
    env["GCM_INTERACTIVE"] = "never"

    # Assemble clone command:
    # - Disable hooks via core.hooksPath=""
    # - Disable LFS filter processes
    # - Shallow clone (--depth 1) for speed and safety
    cmd = [
        git_bin,
        "-c", "core.hooksPath=",
        "-c", "filter.lfs.smudge=",
        "-c", "filter.lfs.clean=",
        "-c", "filter.lfs.process=",
        "-c", "filter.lfs.required=false",
        "clone",
        "--depth", "1",
    ]
    if ref:
        cmd.extend(["--branch", ref])
    cmd.extend([url, str(dest_path)])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        raise GitCloneError("Unable to clone repository: operation timed out.")
    except OSError as exc:
        raise GitCloneError(f"Unable to clone repository: {exc}")

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stderr_lower = stderr.lower()

        # Check for invalid URL errors from git
        if (
            "is not a valid repository name" in stderr_lower
            or ("protocol" in stderr_lower and "is not supported" in stderr_lower)
            or "malformed url" in stderr_lower
            or "invalid url" in stderr_lower
        ):
            raise GitInvalidUrlError("Unable to clone repository: invalid repository URL.")

        # Check for not found / inaccessible / auth errors
        if (
            "not found" in stderr_lower
            or "does not exist" in stderr_lower
            or "could not resolve host" in stderr_lower
            or "authentication failed" in stderr_lower
            or "permission denied" in stderr_lower
            or "access denied" in stderr_lower
            or "terminal prompts disabled" in stderr_lower
            or "remote branch" in stderr_lower
        ):
            raise GitRepoNotFoundError("Unable to clone repository: repository not found or inaccessible.")

        # Generic clone failure - clean error without traceback
        err_msg = stderr.splitlines()[-1] if stderr else f"exit code {proc.returncode}"
        raise GitCloneError(f"Unable to clone repository: {err_msg}")

    return dest_path


@contextmanager
def acquire_repository(
    target: str,
    ref: str | None = None,
) -> Generator[tuple[Path, Path | None], None, None]:
    """
    Context manager that acquires a target (file, directory, or remote Git repository).
    Yields (path_to_review, base_dir_for_relative_paths).
    If target is a remote Git URL:
      - Creates a temporary directory
      - Clones the repository
      - Yields (clone_path, clone_path)
      - Safely cleans up the temporary directory in finally block
    If target is a local path:
      - Yields (Path(target), None)
    """
    if is_git_url(target):
        temp_dir = tempfile.mkdtemp(prefix="review_sentinel_")
        clone_dest = Path(temp_dir) / "repo"
        try:
            clone_repository(target, clone_dest, ref=ref)
            yield clone_dest, clone_dest
        finally:
            safe_rmtree(temp_dir)
    else:
        yield Path(target), None
