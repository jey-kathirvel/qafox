import base64
import json
import os
from pathlib import Path
from unittest import TestCase, mock

os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("QAFOX_SECRET_KEY", "test-secret")
os.environ.setdefault("SMTP_PASSWORD_B64", base64.b64encode(b"test-password").decode())

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database import Base
from app.quality_models import SecurityFindingRecord, SecurityScanRun
from app.security_scanning import (
    GitleaksScanner,
    ScannerOutput,
    SemgrepScanner,
    TrivyScanner,
    run_security_scanner,
    safe_source_file,
)


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "scanner_results"


def payload(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class SemgrepIntegrationTests(TestCase):
    def test_normalizes_sast_metadata_and_evidence(self):
        finding = SemgrepScanner().parse(payload("semgrep.json"))[0]
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.source_file, "app/search.py")
        self.assertEqual(finding.source_line, 42)
        self.assertEqual(finding.cwe, ("CWE-89",))
        self.assertIn("A03:2021", finding.owasp[0])
        self.assertEqual(len(finding.fingerprint), 64)
        self.assertEqual(
            safe_source_file("C:/worker/jobs/123/source/app/search.py"),
            "app/search.py",
        )

    def test_command_disables_metrics_and_repository_gitignore(self):
        command = SemgrepScanner().command("semgrep", Path("source"), Path("result.json"))
        self.assertIn("--metrics", command)
        self.assertIn("off", command)
        self.assertIn("--no-git-ignore", command)


class TrivyIntegrationTests(TestCase):
    def test_normalizes_vulnerability_and_misconfiguration(self):
        findings = TrivyScanner().parse(payload("trivy.json"))
        vulnerability = next(item for item in findings if item.category == "Dependency Vulnerability")
        configuration = next(item for item in findings if item.category == "Configuration")
        self.assertEqual(vulnerability.severity, "CRITICAL")
        self.assertEqual(vulnerability.details["installed_version"], "1.0.0")
        self.assertEqual(vulnerability.details["fixed_version"], "1.0.1")
        self.assertEqual(configuration.source_line, 1)


class GitleaksIntegrationTests(TestCase):
    def test_secret_values_are_never_in_normalized_finding(self):
        raw = (FIXTURES / "gitleaks.json").read_text(encoding="utf-8")
        finding = GitleaksScanner().parse(json.loads(raw))[0]
        serialized = json.dumps(finding.details) + finding.evidence + finding.description
        self.assertEqual(finding.evidence, "********")
        self.assertNotIn("super-secret-value", serialized)

    def test_command_requires_redaction_and_avoids_git_history(self):
        command = GitleaksScanner().command("gitleaks", Path("source"), Path("result.json"))
        self.assertIn("--redact", command)
        self.assertIn("--no-git", command)


class SecurityPersistenceTests(TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://")
        Base.metadata.create_all(self.engine)

    def test_missing_binary_is_recorded_as_unavailable_not_clean(self):
        with Session(self.engine) as db, mock.patch("shutil.which", return_value=None):
            run = run_security_scanner(
                db, scanner=SemgrepScanner(), source=Path("."), workspace=Path(".scanner-test"),
                project_id=21, owner_user_id=11,
            )
            self.assertEqual(run.status, "UNAVAILABLE")
        self.assertEqual(
            Session(self.engine).scalars(select(SecurityScanRun)).one().status,
            "UNAVAILABLE",
        )

    def test_redacted_findings_round_trip_with_owner_scope_columns(self):
        finding = GitleaksScanner().parse(payload("gitleaks.json"))[0]
        scanner = mock.Mock()
        scanner.name = "gitleaks"
        scanner.execute.return_value = ScannerOutput("gitleaks", "8.20.0", (finding,))
        with Session(self.engine) as db:
            run = run_security_scanner(
                db, scanner=scanner, source=Path("."), workspace=Path(".scanner-test"),
                project_id=21, owner_user_id=11, test_run_id=31,
            )
            self.assertEqual(run.status, "COMPLETED")
        with Session(self.engine) as db:
            row = db.scalars(select(SecurityFindingRecord)).one()
            self.assertEqual(row.owner_user_id, 11)
            self.assertEqual(row.evidence, "********")
            self.assertNotIn("super-secret-value", json.dumps(row.details_json))


class SecurityUiAndQueueTests(TestCase):
    def test_security_page_and_queue_are_owner_scoped_and_csrf_protected(self):
        source = Path("app/security_routes.py").read_text(encoding="utf-8")
        self.assertIn('@router.get("/projects/{public_id}/security")', source)
        self.assertIn('@router.post("/projects/{public_id}/security/run")', source)
        self.assertIn("AND owner_user_id = :owner_user_id", source)
        self.assertIn("csrf_valid(request, csrf)", source)

    def test_security_enqueue_uses_dedicated_worker_job_type(self):
        from app.jobs import enqueue_security_run
        from app.quality_models import WorkerJob

        engine = create_engine("sqlite://")
        Base.metadata.create_all(engine)
        with Session(engine) as db:
            run, job = enqueue_security_run(db, project_id=21, owner_user_id=11)
            self.assertEqual(job.job_type, "security_scan")
            self.assertTrue(run.configuration["security"]["semgrep"])
        with Session(engine) as db:
            self.assertEqual(db.scalars(select(WorkerJob)).one().job_type, "security_scan")
