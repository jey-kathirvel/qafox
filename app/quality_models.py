"""Foundation persistence for universal quality-test executions."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RunStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    PREPARING = "PREPARING"
    ANALYZING = "ANALYZING"
    RUNNING = "RUNNING"
    PARSING = "PARSING"
    AI_ANALYSIS = "AI_ANALYSIS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class JobStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class QualityTestRun(Base):
    __tablename__ = "quality_test_runs"
    __table_args__ = (
        Index("quality_test_runs_project_created_idx", "owner_user_id", "project_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[int] = mapped_column(Integer, nullable=False)
    owner_user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    profile: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default=RunStatus.QUEUED.value)
    progress: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    configuration: Mapped[dict] = mapped_column(JSON, nullable=False)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WorkerJob(Base):
    __tablename__ = "worker_jobs"
    __table_args__ = (
        UniqueConstraint("test_run_id", name="worker_jobs_test_run_key"),
        Index("worker_jobs_claim_idx", "status", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    test_run_id: Mapped[int] = mapped_column(Integer, nullable=False)
    job_type: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default=JobStatus.QUEUED.value)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    worker_id: Mapped[str | None] = mapped_column(String(150))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ProjectSource(Base):
    __tablename__ = "project_sources"
    __table_args__ = (
        UniqueConstraint("project_id", name="project_sources_project_key"),
        Index("project_sources_owner_idx", "owner_user_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(Integer, nullable=False)
    owner_user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    source_type: Mapped[str] = mapped_column(String(20), nullable=False)
    repository_url: Mapped[str | None] = mapped_column(String(1000))
    default_branch: Mapped[str | None] = mapped_column(String(200))
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    authorization_confirmed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    authorization_confirmed_by: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class TechnologyDetectionRun(Base):
    __tablename__ = "technology_detection_runs"
    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "source_sha256",
            "detector_version",
            name="technology_detection_source_key",
        ),
        Index(
            "technology_detection_owner_project_idx",
            "owner_user_id",
            "project_id",
            "created_at",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), unique=True)
    project_id: Mapped[int] = mapped_column(Integer, nullable=False)
    owner_user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    source_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    detector_version: Mapped[str] = mapped_column(String(30), nullable=False)
    primary_language: Mapped[str] = mapped_column(String(100), nullable=False)
    report_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class SecurityScanRun(Base):
    __tablename__ = "security_scan_runs"
    __table_args__ = (
        Index("security_scan_runs_owner_project_idx", "owner_user_id", "project_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), unique=True)
    test_run_id: Mapped[int | None] = mapped_column(Integer)
    project_id: Mapped[int] = mapped_column(Integer, nullable=False)
    owner_user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    scanner: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(100), nullable=False, default="unknown")
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SecurityFindingRecord(Base):
    __tablename__ = "security_findings"
    __table_args__ = (
        UniqueConstraint("scan_run_id", "fingerprint", name="security_findings_scan_fingerprint_key"),
        Index("security_findings_owner_project_idx", "owner_user_id", "project_id", "severity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), unique=True)
    scan_run_id: Mapped[int] = mapped_column(Integer, nullable=False)
    test_run_id: Mapped[int | None] = mapped_column(Integer)
    project_id: Mapped[int] = mapped_column(Integer, nullable=False)
    owner_user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner: Mapped[str] = mapped_column(String(40), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(500), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    category: Mapped[str] = mapped_column(String(200), nullable=False)
    component: Mapped[str] = mapped_column(String(1000), nullable=False)
    source_file: Mapped[str | None] = mapped_column(String(2000))
    source_line: Mapped[int | None] = mapped_column(Integer)
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")
    recommendation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    cwe_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    owasp_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    details_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class PerformanceTestArtifact(Base):
    __tablename__ = "performance_test_artifacts"
    __table_args__ = (
        UniqueConstraint("test_run_id", name="performance_artifacts_test_run_key"),
        Index("performance_artifacts_owner_project_idx", "owner_user_id", "project_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    test_run_id: Mapped[int] = mapped_column(Integer, nullable=False)
    project_id: Mapped[int] = mapped_column(Integer, nullable=False)
    owner_user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    target_url: Mapped[str] = mapped_column(String(2000), nullable=False)
    authorization_confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    authorization_confirmed_by: Mapped[int] = mapped_column(Integer, nullable=False)
    generator_version: Mapped[str] = mapped_column(String(30), nullable=False)
    script_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    script_text: Mapped[str] = mapped_column(Text, nullable=False)
    configuration_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    metric_map_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class PerformanceTestResult(Base):
    __tablename__ = "performance_test_results"
    __table_args__ = (
        UniqueConstraint("test_run_id", name="performance_results_test_run_key"),
        Index("performance_results_owner_project_idx", "owner_user_id", "project_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    test_run_id: Mapped[int] = mapped_column(Integer, nullable=False)
    artifact_id: Mapped[int] = mapped_column(Integer, nullable=False)
    project_id: Mapped[int] = mapped_column(Integer, nullable=False)
    owner_user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(100), nullable=False)
    requests: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    errors: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    requests_per_second: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    duration_avg_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    duration_min_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    duration_max_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    duration_p50_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    duration_p90_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    duration_p95_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    duration_p99_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    data_received_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    data_sent_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    vus_max: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    raw_summary_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PerformanceEndpointMetric(Base):
    __tablename__ = "performance_endpoint_metrics"
    __table_args__ = (
        UniqueConstraint("result_id", "method", "path", name="performance_endpoint_result_route_key"),
        Index("performance_endpoint_owner_project_idx", "owner_user_id", "project_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    result_id: Mapped[int] = mapped_column(Integer, nullable=False)
    project_id: Mapped[int] = mapped_column(Integer, nullable=False)
    owner_user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(2000), nullable=False)
    requests: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    errors: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    duration_avg_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    duration_min_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    duration_max_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    duration_p50_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    duration_p90_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    duration_p95_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    duration_p99_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
