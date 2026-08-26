"""Standalone worker entry point. Uploaded source is never executed here."""

from __future__ import annotations

import logging
import shutil
import time
from pathlib import Path

from sqlalchemy import text
from sqlalchemy import select

from app.config import get_settings
from app.database import SessionLocal
from app.jobs import claim_next_job, complete_job, fail_job
from app.project_ingestion import cleanup_job_workspace, create_job_workspace
from app.quality_models import QualityTestRun
from app.quality_models import (
    PerformanceEndpointMetric, PerformanceTestArtifact, PerformanceTestResult,
    RunStatus, utc_now,
)
from app.performance_testing import execute_k6, parse_k6_summary
from app.security_scanning import SCANNERS, run_security_scanner

LOG = logging.getLogger("qafox.worker")


def _security_job(db, job, workspace: Path, settings) -> None:
    run = db.get(QualityTestRun, job.test_run_id)
    if run is None:
        raise RuntimeError("Quality test run was not found.")
    project = db.execute(
        text(
            """
            SELECT storage_directory FROM projects
            WHERE id = :project_id
              AND owner_user_id = :owner_user_id
              AND deleted_at IS NULL
            """
        ),
        {"project_id": run.project_id, "owner_user_id": run.owner_user_id},
    ).mappings().first()
    if not project:
        raise RuntimeError("Owned project source was not found.")
    project_directory = Path(project["storage_directory"]).resolve()
    expected = (settings.project_root / str(run.owner_user_id)).resolve()
    project_directory.relative_to(expected)
    stored_source = project_directory / "source"
    if not stored_source.is_dir() or any(path.is_symlink() for path in stored_source.rglob("*")):
        raise RuntimeError("Project source workspace is unsafe.")
    isolated_source = workspace / "source"
    shutil.copytree(stored_source, isolated_source, dirs_exist_ok=True)

    requested = (run.configuration or {}).get("security") or {}
    selected = [
        scanner for name, scanner in SCANNERS.items()
        if bool(requested.get(name, requested.get(
            {"semgrep": "sast", "trivy": "dependencies", "gitleaks": "secrets"}[name],
            False,
        )))
    ]
    if not selected:
        raise RuntimeError("Security job has no enabled scanners.")
    statuses = []
    for scanner in selected:
        scan_workspace = workspace / "results" / scanner.name
        scan_run = run_security_scanner(
            db,
            scanner=scanner,
            source=isolated_source,
            workspace=scan_workspace,
            project_id=run.project_id,
            owner_user_id=run.owner_user_id,
            test_run_id=run.id,
        )
        statuses.append(scan_run.status)
    if not statuses or all(status == "UNAVAILABLE" for status in statuses):
        raise RuntimeError("No requested security scanner is installed on this worker.")
    if any(status == "FAILED" for status in statuses):
        raise RuntimeError("One or more security scanners failed.")
    complete_job(db, job.id)


def _performance_job(db, job, workspace: Path) -> None:
    run = db.get(QualityTestRun, job.test_run_id)
    if run is None or run.profile != "performance":
        raise RuntimeError("Performance test run was not found.")
    artifact = db.execute(
        select(PerformanceTestArtifact).where(PerformanceTestArtifact.test_run_id == run.id)
    ).scalar_one_or_none()
    if artifact is None or artifact.owner_user_id != run.owner_user_id:
        raise RuntimeError("Authorized performance artifact was not found.")
    if artifact.authorization_confirmed_by != run.owner_user_id:
        raise RuntimeError("Performance target authorization does not match the run owner.")

    script_path = workspace / "script.js"
    summary_path = workspace / "summary.json"
    script_path.write_text(artifact.script_text, encoding="utf-8")
    run.status = RunStatus.RUNNING.value
    run.progress = 25.0
    db.commit()

    def cancelled() -> bool:
        db.expire(run, ["cancel_requested"])
        return bool(run.cancel_requested)

    execution = execute_k6(
        script_path, summary_path, base_url=artifact.target_url,
        timeout_seconds=int(artifact.configuration_json["timeout_seconds"]),
        should_cancel=cancelled,
    )
    if execution.status == "UNAVAILABLE":
        raise RuntimeError("k6 is not installed on this worker.")
    if execution.status == "CANCELLED":
        now = utc_now()
        run.status = RunStatus.CANCELLED.value
        run.completed_at = now
        job.status = "CANCELLED"
        job.completed_at = now
        db.commit()
        return
    if execution.status != "COMPLETED":
        raise RuntimeError(execution.error_message or "k6 execution failed.")

    run.status = RunStatus.PARSING.value
    run.progress = 85.0
    overall, endpoint_rows = parse_k6_summary(execution.summary, artifact.metric_map_json)
    result = PerformanceTestResult(
        test_run_id=run.id, artifact_id=artifact.id, project_id=run.project_id,
        owner_user_id=run.owner_user_id, status="COMPLETED",
        tool_version=execution.tool_version, raw_summary_json=execution.summary,
        completed_at=utc_now(), **overall,
    )
    db.add(result)
    db.flush()
    for row in endpoint_rows:
        db.add(PerformanceEndpointMetric(
            result_id=result.id, project_id=run.project_id,
            owner_user_id=run.owner_user_id, **row,
        ))
    db.commit()
    complete_job(db, job.id)


def run_once() -> bool:
    settings = get_settings()
    with SessionLocal() as db:
        job = claim_next_job(db, settings.worker_id)
        if job is None:
            return False
        LOG.info("Claimed job %s (%s)", job.public_id, job.job_type)
        try:
            workspace = create_job_workspace(settings.job_workspace_root, job.public_id)
            if job.job_type == "security_scan":
                _security_job(db, job, workspace, settings)
            elif job.job_type == "performance_test":
                _performance_job(db, job, workspace)
            else:
                fail_job(
                    db,
                    job.id,
                    f"No handler is registered for job type {job.job_type}.",
                )
        except RuntimeError as exc:
            LOG.warning("Job %s failed: %s", job.public_id, exc)
            fail_job(db, job.id, str(exc))
        except Exception:
            LOG.exception("Job execution failed for %s", job.public_id)
            fail_job(db, job.id, "Isolated job execution failed.")
        finally:
            cleanup_job_workspace(settings.job_workspace_root, job.public_id)
        return True


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    delay = get_settings().worker_poll_seconds
    while True:
        if not run_once():
            time.sleep(delay)


if __name__ == "__main__":
    main()
