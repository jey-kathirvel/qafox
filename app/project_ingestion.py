"""Safe Git ingestion and isolated job workspace primitives."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


class IngestionRejected(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class GitIngestionResult:
    repository_url: str
    branch: str
    commit_sha: str
    archive_path: Path


def _is_public_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return not any(
        (
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        )
    )


def validate_repository_url(value: str) -> str:
    url = str(value or "").strip()
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise IngestionRejected("Repository URL must use HTTPS.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise IngestionRejected(
            "Repository URL must not contain credentials, query, or fragment data."
        )
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(
                parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM
            )
        }
    except socket.gaierror as exc:
        raise IngestionRejected("Repository host could not be resolved.") from exc
    if not addresses or any(not _is_public_address(item) for item in addresses):
        raise IngestionRejected(
            "Repository host must resolve only to public addresses."
        )
    return url


def validate_branch(value: str) -> str:
    branch = str(value or "main").strip()
    if (
        not branch
        or len(branch) > 200
        or branch.startswith(("-", ".", "/"))
        or branch.endswith((".", "/"))
        or ".." in branch
        or "//" in branch
        or "@{" in branch
        or any(part.endswith(".lock") for part in branch.split("/"))
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", branch)
    ):
        raise IngestionRejected("Default branch name is invalid.")
    return branch


def _safe_git_environment(private_home: Path) -> dict[str, str]:
    environment = {
        key: os.environ[key]
        for key in ("PATH", "SYSTEMROOT", "WINDIR")
        if key in os.environ
    }
    environment.update(
        {
            "HOME": str(private_home),
            "USERPROFILE": str(private_home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "https",
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
    )
    return environment


def _run_git(
    git: str,
    arguments: list[str],
    *,
    cwd: Path,
    home: Path,
    timeout: int,
) -> str:
    try:
        result = subprocess.run(
            [
                git,
                "-c",
                "http.followRedirects=false",
                "-c",
                "core.hooksPath=",
                *arguments,
            ],
            cwd=cwd,
            env=_safe_git_environment(home),
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        raise IngestionRejected("Repository could not be fetched safely.") from exc
    return result.stdout.strip()


def ingest_git_repository(
    repository_url: str,
    branch: str,
    staging_directory: Path,
    *,
    timeout_seconds: int = 180,
    max_repository_bytes: int = 500 * 1024 * 1024,
) -> GitIngestionResult:
    """Fetch one branch and export it without checking out repository files."""
    url = validate_repository_url(repository_url)
    safe_branch = validate_branch(branch)
    git = shutil.which("git")
    if not git:
        raise IngestionRejected("Git is not installed on the ingestion worker.")

    staging_directory.mkdir(parents=True, exist_ok=False)
    os.chmod(staging_directory, 0o700)
    private_home = staging_directory / "git-home"
    bare_repository = staging_directory / "repository.git"
    private_home.mkdir(mode=0o700)

    _run_git(
        git,
        ["init", "--bare", str(bare_repository)],
        cwd=staging_directory,
        home=private_home,
        timeout=timeout_seconds,
    )
    _run_git(
        git,
        [
            "--git-dir",
            str(bare_repository),
            "fetch",
            "--depth=1",
            "--no-tags",
            url,
            f"refs/heads/{safe_branch}",
        ],
        cwd=staging_directory,
        home=private_home,
        timeout=timeout_seconds,
    )
    repository_size = sum(
        item.stat().st_size
        for item in bare_repository.rglob("*")
        if item.is_file()
    )
    if repository_size > max_repository_bytes:
        raise IngestionRejected("Repository exceeds the 500 MB ingestion limit.")

    commit_sha = _run_git(
        git,
        [
            "--git-dir",
            str(bare_repository),
            "rev-parse",
            "FETCH_HEAD^{commit}",
        ],
        cwd=staging_directory,
        home=private_home,
        timeout=timeout_seconds,
    )
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", commit_sha):
        raise IngestionRejected("Repository did not resolve to a valid commit.")

    archive_path = staging_directory / f"repository-{uuid.uuid4().hex}.tar"
    _run_git(
        git,
        [
            "--git-dir",
            str(bare_repository),
            "archive",
            "--format=tar",
            f"--output={archive_path}",
            commit_sha,
        ],
        cwd=staging_directory,
        home=private_home,
        timeout=timeout_seconds,
    )
    if not archive_path.is_file():
        raise IngestionRejected("Repository archive was not created.")
    return GitIngestionResult(
        url, safe_branch, commit_sha.lower(), archive_path
    )


def create_job_workspace(root: Path, job_public_id: str) -> Path:
    canonical_id = str(uuid.UUID(str(job_public_id)))
    workspace = (root / canonical_id).resolve()
    workspace.relative_to(root.resolve())
    workspace.mkdir(parents=True, exist_ok=False)
    os.chmod(workspace, 0o700)
    for name in ("source", "artifacts", "results", "logs"):
        (workspace / name).mkdir(mode=0o700)
    return workspace


def cleanup_job_workspace(root: Path, job_public_id: str) -> bool:
    try:
        canonical_id = str(uuid.UUID(str(job_public_id)))
        workspace = (root / canonical_id).resolve()
        workspace.relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    if workspace.is_dir():
        shutil.rmtree(workspace)
        return True
    return False
