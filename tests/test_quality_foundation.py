import base64
import os
from unittest import TestCase, mock

# The shared database module intentionally validates production configuration
# at import time. Tests provide isolated values before importing it.
os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("QAFOX_SECRET_KEY", "test-secret")
os.environ.setdefault(
    "SMTP_PASSWORD_B64", base64.b64encode(b"test-password").decode()
)

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.database import Base
from app.jobs import claim_next_job, enqueue_quality_run, fail_job
from app.quality_models import JobStatus, QualityTestRun, RunStatus, WorkerJob


class SettingsTests(TestCase):
    def test_loads_and_decodes_required_configuration(self):
        environment = {
            "DATABASE_URL": "sqlite://",
            "QAFOX_SECRET_KEY": "test-secret",
            "SMTP_PASSWORD_B64": base64.b64encode(b"mail-secret").decode(),
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            settings = Settings.from_env()
        self.assertEqual(settings.database_url, "sqlite://")
        self.assertEqual(settings.smtp_password, "mail-secret")

    def test_missing_secret_fails_fast_without_echoing_values(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "DATABASE_URL"):
                Settings.from_env()


class JobQueueTests(TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://")
        Base.metadata.create_all(self.engine)

    def test_web_enqueue_and_worker_claim_are_separate(self):
        with Session(self.engine) as db:
            run, job = enqueue_quality_run(
                db,
                project_id=21,
                owner_user_id=11,
                profile="quick",
                configuration={"security": {"sast": True}},
            )
            run_id, job_id = run.id, job.id

        with Session(self.engine) as db:
            claimed = claim_next_job(db, "worker-test")
            self.assertEqual(claimed.id, job_id)
            self.assertEqual(claimed.status, JobStatus.RUNNING.value)
            self.assertEqual(claimed.attempts, 1)

        with Session(self.engine) as db:
            persisted_run = db.get(QualityTestRun, run_id)
            self.assertEqual(persisted_run.status, RunStatus.PREPARING.value)
            self.assertEqual(
                db.scalars(select(WorkerJob)).one().worker_id,
                "worker-test",
            )

    def test_empty_queue_returns_none(self):
        with Session(self.engine) as db:
            self.assertIsNone(claim_next_job(db, "worker-test"))

    def test_worker_failure_completes_job_and_run(self):
        with Session(self.engine) as db:
            run, job = enqueue_quality_run(
                db,
                project_id=21,
                owner_user_id=11,
                profile="quick",
                configuration={},
            )
            claim_next_job(db, "worker-test")
            fail_job(db, job.id, "safe failure")
            self.assertEqual(db.get(WorkerJob, job.id).status, JobStatus.FAILED.value)
            self.assertEqual(db.get(QualityTestRun, run.id).status, RunStatus.FAILED.value)
