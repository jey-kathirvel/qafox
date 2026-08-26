import base64
import os
import tempfile
from pathlib import Path
from unittest import TestCase, mock

os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("QAFOX_SECRET_KEY", "test-secret")
os.environ.setdefault("SMTP_PASSWORD_B64", base64.b64encode(b"test-password").decode())

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.jobs import enqueue_performance_run, request_run_cancellation
from app.performance_testing import K6Config, execute_k6, generate_k6_script, parse_k6_summary
from app.quality_models import JobStatus, QualityTestRun, RunStatus, WorkerJob


class K6GenerationTests(TestCase):
    def test_generation_is_reproducible_and_read_only_by_default(self):
        routes = [
            {"method": "POST", "path": "/users"},
            {"method": "GET", "path": "/health"},
            {"method": "GET", "path": "/users/{id}"},
            {"method": "HEAD", "path": "/ready"},
        ]
        first = generate_k6_script(routes, K6Config(3, 20, 30))
        second = generate_k6_script(reversed(routes), K6Config(3, 20, 30))
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(first.script, second.script)
        self.assertIn('"/health"', first.script)
        self.assertNotIn('"/users"', first.script)
        self.assertNotIn("https://", first.script)
        self.assertIn("POST /users", first.skipped_routes)
        self.assertIn("GET /users/{id}", first.skipped_routes)

    def test_configuration_bounds_and_empty_routes_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "Virtual users"):
            generate_k6_script([{"method": "GET", "path": "/"}], K6Config(0, 1, 1))
        with self.assertRaisesRegex(ValueError, "No safe"):
            generate_k6_script([{"method": "DELETE", "path": "/records"}])


class K6MetricsTests(TestCase):
    def test_exact_overall_and_endpoint_percentiles_are_parsed(self):
        artifact = generate_k6_script([{"method": "GET", "path": "/health"}])
        mapping = next(iter(artifact.metric_map.values()))
        duration_values = {
            "count": 100, "avg": 12.5, "min": 2, "max": 80,
            "med": 10, "p(90)": 20, "p(95)": 25, "p(99)": 50,
        }
        summary = {"metrics": {
            "http_reqs": {"values": {"count": 100, "rate": 10}},
            "http_req_failed": {"values": {"rate": 0.02, "passes": 98, "fails": 2}},
            "http_req_duration": {"values": duration_values},
            "data_received": {"values": {"count": 2048}},
            "data_sent": {"values": {"count": 512}},
            "vus_max": {"values": {"max": 5}},
            mapping["duration_metric"]: {"values": duration_values},
            mapping["failure_metric"]: {"values": {"rate": 0.02, "passes": 98, "fails": 2}},
        }}
        overall, endpoints = parse_k6_summary(summary, artifact.metric_map)
        self.assertEqual(overall["requests"], 100)
        self.assertEqual(overall["errors"], 2)
        self.assertEqual(overall["duration_p99_ms"], 50)
        self.assertEqual(overall["requests_per_second"], 10)
        self.assertEqual(endpoints[0]["path"], "/health")
        self.assertEqual(endpoints[0]["duration_p95_ms"], 25)

    def test_missing_metrics_object_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "metrics object"):
            parse_k6_summary({}, {})

    @mock.patch("app.performance_testing.shutil.which", return_value=None)
    def test_missing_k6_is_explicitly_unavailable(self, _which):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            result = execute_k6(root / "script.js", root / "summary.json", base_url="https://example.com", timeout_seconds=5)
        self.assertEqual(result.status, "UNAVAILABLE")

    def test_running_process_honors_cancellation(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.communicate.return_value = (None, None)
        process.returncode = -15
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch("app.performance_testing.shutil.which", return_value="k6"), \
             mock.patch("app.performance_testing.subprocess.run") as version, \
             mock.patch("app.performance_testing.subprocess.Popen", return_value=process):
            version.return_value.stdout = "k6 v1"
            root = Path(folder)
            result = execute_k6(
                root / "script.js", root / "summary.json",
                base_url="https://example.com", timeout_seconds=5,
                should_cancel=lambda: True,
            )
        process.terminate.assert_called_once()
        self.assertEqual(result.status, "CANCELLED")

    def test_running_process_honors_hard_timeout(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.communicate.return_value = (None, None)
        process.returncode = -15
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch("app.performance_testing.shutil.which", return_value="k6"), \
             mock.patch("app.performance_testing.subprocess.run") as version, \
             mock.patch("app.performance_testing.subprocess.Popen", return_value=process), \
             mock.patch("app.performance_testing.time.monotonic", side_effect=[0, 6, 6]):
            version.return_value.stdout = "k6 v1"
            root = Path(folder)
            result = execute_k6(
                root / "script.js", root / "summary.json",
                base_url="https://example.com", timeout_seconds=5,
            )
        process.terminate.assert_called_once()
        self.assertEqual(result.status, "FAILED")
        self.assertIn("timeout", result.error_message)


class PerformanceQueueTests(TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://")
        Base.metadata.create_all(self.engine)

    def test_authorization_is_required_before_enqueue(self):
        with Session(self.engine) as db:
            with self.assertRaisesRegex(ValueError, "authorization"):
                enqueue_performance_run(db, project_id=1, owner_user_id=2, configuration={})

    def test_queued_run_can_be_cancelled_by_owner(self):
        with Session(self.engine) as db:
            run, job = enqueue_performance_run(
                db, project_id=1, owner_user_id=2,
                configuration={"authorization_confirmed": True},
            )
            run_id, job_id = run.id, job.id
        with Session(self.engine) as db:
            self.assertFalse(request_run_cancellation(db, run_id=run_id, owner_user_id=999))
            self.assertTrue(request_run_cancellation(db, run_id=run_id, owner_user_id=2))
        with Session(self.engine) as db:
            self.assertEqual(db.get(QualityTestRun, run_id).status, RunStatus.CANCELLED.value)
            self.assertEqual(db.get(WorkerJob, job_id).status, JobStatus.CANCELLED.value)
