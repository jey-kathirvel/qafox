"""Validated application configuration loaded from the environment."""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable {name} is not set.")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str
    secret_key: str
    smtp_password: str
    domain: str = "qafox.ads-ai.in"
    smtp_host: str = "smtp.hostinger.com"
    smtp_port: int = 465
    smtp_username: str = ""
    smtp_from_email: str = ""
    smtp_from_name: str = "QAFox"
    worker_id: str = "qafox-worker"
    worker_poll_seconds: float = 2.0
    project_root: Path = Path("/opt/qafox/data/projects")
    staging_root: Path = Path("/opt/qafox/data/staging")
    job_workspace_root: Path = Path("/tmp/qafox/jobs")
    git_timeout_seconds: int = 180

    @classmethod
    def from_env(cls) -> "Settings":
        database_url = _required("DATABASE_URL")
        secret_key = _required("QAFOX_SECRET_KEY")
        encoded_password = _required("SMTP_PASSWORD_B64")
        try:
            smtp_password = base64.b64decode(
                encoded_password, validate=True
            ).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError("SMTP_PASSWORD_B64 must contain valid base64 UTF-8.") from exc

        smtp_username = os.getenv("SMTP_USERNAME", "").strip()
        return cls(
            database_url=database_url,
            secret_key=secret_key,
            smtp_password=smtp_password,
            domain=os.getenv("QAFOX_DOMAIN", "qafox.ads-ai.in").strip(),
            smtp_host=os.getenv("SMTP_HOST", "smtp.hostinger.com").strip(),
            smtp_port=int(os.getenv("SMTP_PORT", "465")),
            smtp_username=smtp_username,
            smtp_from_email=os.getenv("SMTP_FROM_EMAIL", smtp_username).strip(),
            smtp_from_name=os.getenv("SMTP_FROM_NAME", "QAFox").strip(),
            worker_id=os.getenv("QAFOX_WORKER_ID", "qafox-worker").strip(),
            worker_poll_seconds=float(os.getenv("QAFOX_WORKER_POLL_SECONDS", "2")),
            project_root=Path(os.getenv("QAFOX_PROJECT_ROOT", "/opt/qafox/data/projects")),
            staging_root=Path(os.getenv("QAFOX_STAGING_ROOT", "/opt/qafox/data/staging")),
            job_workspace_root=Path(os.getenv("QAFOX_JOB_ROOT", "/tmp/qafox/jobs")),
            git_timeout_seconds=int(os.getenv("QAFOX_GIT_TIMEOUT_SECONDS", "180")),
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_env()
