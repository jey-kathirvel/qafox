"""Database-backed job queue boundary used by web and worker processes."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.quality_models import JobStatus, QualityTestRun, RunStatus, WorkerJob, utc_now


def enqueue_quality_run(
    db: Session, *, project_id: int, owner_user_id: int, profile: str,
    configuration: dict, job_type: str = "quality_test",
) -> tuple[QualityTestRun, WorkerJob]:
    run = QualityTestRun(
        project_id=project_id,
        owner_user_id=owner_user_id,
        profile=profile,
        configuration=configuration,
    )
    db.add(run)
    db.flush()
    job = WorkerJob(test_run_id=run.id, job_type=job_type, payload={"run_id": run.id})
    db.add(job)
    db.commit()
    return run, job


def enqueue_security_run(
    db: Session, *, project_id: int, owner_user_id: int,
    scanners: tuple[str, ...] = ("semgrep", "trivy", "gitleaks"),
) -> tuple[QualityTestRun, WorkerJob]:
    return enqueue_quality_run(
        db,
        project_id=project_id,
        owner_user_id=owner_user_id,
        profile="security",
        configuration={"security": {name: True for name in scanners}},
        job_type="security_scan",
    )


def enqueue_performance_run(
    db: Session, *, project_id: int, owner_user_id: int, configuration: dict,
    defer_commit: bool = False,
) -> tuple[QualityTestRun, WorkerJob]:
    if not configuration.get("authorization_confirmed"):
        raise ValueError("Explicit target authorization is required.")
    # UI creation defers commit so the authorization artifact and queue record
    # become visible atomically; a worker cannot claim an artifact-less run.
    run = QualityTestRun(
        project_id=project_id, owner_user_id=owner_user_id,
        profile="performance", configuration=configuration,
    )
    db.add(run)
    db.flush()
    job = WorkerJob(test_run_id=run.id, job_type="performance_test", payload={"run_id": run.id})
    db.add(job)
    db.flush()
    if not defer_commit:
        db.commit()
    return run, job


def request_run_cancellation(db: Session, *, run_id: int, owner_user_id: int) -> bool:
    run = db.get(QualityTestRun, run_id)
    if run is None or run.owner_user_id != owner_user_id:
        return False
    if run.status in {RunStatus.COMPLETED.value, RunStatus.FAILED.value, RunStatus.CANCELLED.value}:
        return False
    run.cancel_requested = True
    job = db.execute(select(WorkerJob).where(WorkerJob.test_run_id == run.id)).scalar_one_or_none()
    if job is not None and job.status == JobStatus.QUEUED.value:
        now = utc_now()
        job.status = JobStatus.CANCELLED.value
        job.completed_at = now
        run.status = RunStatus.CANCELLED.value
        run.completed_at = now
    db.commit()
    return True


def claim_next_job(db: Session, worker_id: str) -> WorkerJob | None:
    statement = (
        select(WorkerJob)
        .where(WorkerJob.status == JobStatus.QUEUED.value)
        .order_by(WorkerJob.created_at, WorkerJob.id)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    job = db.execute(statement).scalar_one_or_none()
    if job is None:
        db.rollback()
        return None
    now = utc_now()
    job.status = JobStatus.RUNNING.value
    job.worker_id = worker_id
    job.started_at = now
    job.heartbeat_at = now
    job.attempts += 1
    run = db.get(QualityTestRun, job.test_run_id)
    if run is not None:
        run.status = RunStatus.PREPARING.value
        run.started_at = run.started_at or now
    db.commit()
    return job


def fail_job(db: Session, job_id: int, message: str) -> None:
    """Fail a claimed job without persisting sensitive exception details."""
    job = db.get(WorkerJob, job_id)
    if job is None:
        return
    now = utc_now()
    job.status = JobStatus.FAILED.value
    job.completed_at = now
    job.error_message = str(message or "Worker execution failed.")[:1000]
    run = db.get(QualityTestRun, job.test_run_id)
    if run is not None:
        run.status = RunStatus.FAILED.value
        run.completed_at = now
    db.commit()


def complete_job(db: Session, job_id: int) -> None:
    job = db.get(WorkerJob, job_id)
    if job is None:
        return
    now = utc_now()
    job.status = JobStatus.COMPLETED.value
    job.completed_at = now
    job.heartbeat_at = now
    run = db.get(QualityTestRun, job.test_run_id)
    if run is not None:
        run.status = RunStatus.COMPLETED.value
        run.progress = 100.0
        run.completed_at = now
    db.commit()
