import base64
import os
import tempfile
from pathlib import Path
from unittest import TestCase

os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("QAFOX_SECRET_KEY", "test-secret")
os.environ.setdefault(
    "SMTP_PASSWORD_B64", base64.b64encode(b"test-password").decode()
)

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database import Base
from app.quality_models import TechnologyDetectionRun
from app.technology_detection import detect_technologies, persist_technology_report


class TechnologyMatrixTests(TestCase):
    def test_language_and_package_manager_matrix(self):
        matrix = (
            ("requirements.txt", "fastapi==0.115\npsycopg==3.2\n", "Python", "pip"),
            ("package.json", '{"dependencies":{"express":"5","react":"19"}}', "JavaScript/TypeScript", "npm"),
            ("pom.xml", "<project><dependencies/></project>", "Java", "Maven"),
            ("sample.csproj", "<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>", ".NET", None),
            ("composer.json", '{"require":{"laravel/framework":"11"}}', "PHP", "Composer"),
            ("Gemfile", "gem 'rails', '8.0'\n", "Ruby", "Bundler"),
            ("go.mod", "module example.com/api\ngo 1.24\n", "Go", "Go Modules"),
            ("Cargo.toml", '[package]\nname="api"\nrust-version="1.85"\n', "Rust", "Cargo"),
        )
        for filename, content, language, manager in matrix:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                Path(directory, filename).write_text(content, encoding="utf-8")
                report = detect_technologies(Path(directory))
                self.assertEqual(report.primary_language, language)
                if manager:
                    self.assertIn(manager, {item.name for item in report.by_category("package_manager")})

    def test_framework_database_auth_frontend_runtime_and_container_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(
                """{
                  "engines": {"node": ">=22"},
                  "dependencies": {
                    "express": "5.1.0",
                    "pg": "8.0.0",
                    "jsonwebtoken": "9.0.0",
                    "react": "19.0.0",
                    "graphql": "16.0.0"
                  }
                }""",
                encoding="utf-8",
            )
            (root / "Dockerfile").write_text("FROM node:22-alpine\n", encoding="utf-8")
            (root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
            report = detect_technologies(root)

        expected = {
            "framework": "Express",
            "database": "PostgreSQL",
            "authentication": "JWT",
            "frontend": "React",
            "api_type": "GraphQL",
            "runtime": "Node.js",
            "containerization": "Docker",
        }
        for category, name in expected.items():
            with self.subTest(category=category):
                fact = next(item for item in report.by_category(category) if item.name == name)
                self.assertGreaterEqual(fact.confidence, 80)
                self.assertTrue(fact.evidence)

    def test_existing_source_adapter_enriches_framework_without_execution(self):
        root = Path("tests/fixtures/fastapi_app")
        report = detect_technologies(root)
        self.assertEqual(report.primary_language, "Python")
        self.assertIn("FastAPI", {item.name for item in report.by_category("framework")})
        self.assertIn(
            "bearer-token",
            {item.name for item in report.by_category("authentication")},
        )

    def test_excluded_virtual_environment_does_not_influence_detection(self):
        report = detect_technologies(Path("tests/fixtures/excluded_python"))
        self.assertEqual(report.primary_language, "Unknown")


class TechnologyPersistenceTests(TestCase):
    def test_report_is_persisted_with_owner_source_and_version(self):
        engine = create_engine("sqlite://")
        Base.metadata.create_all(engine)
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "go.mod").write_text("module example.test/api\ngo 1.24\n")
            report = detect_technologies(Path(directory))
        with Session(engine) as db:
            public_id = persist_technology_report(
                db,
                project_id=21,
                owner_user_id=11,
                source_sha256="a" * 64,
                report=report,
            )
            duplicate_id = persist_technology_report(
                db,
                project_id=21,
                owner_user_id=11,
                source_sha256="a" * 64,
                report=report,
            )
            self.assertEqual(duplicate_id, public_id)
        with Session(engine) as db:
            row = db.scalars(select(TechnologyDetectionRun)).one()
            self.assertEqual(row.public_id, public_id)
            self.assertEqual(row.owner_user_id, 11)
            self.assertEqual(row.primary_language, "Go")
            self.assertEqual(row.report_json["detector_version"], "1")
