"""Deterministic, framework-neutral technology detection over untrusted source."""

from __future__ import annotations

import json
import os
import re
import tomllib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy.orm import Session
from sqlalchemy import select

from app.quality_models import TechnologyDetectionRun
from app.smart_data.adapters import default_registry
from app.smart_data.adapters.document_scan import SKIP_DIRECTORIES
from app.smart_data.contracts import ProjectRef

DETECTOR_VERSION = "1"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_FILES = 10_000


@dataclass(frozen=True, slots=True)
class TechnologyEvidence:
    file: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"file": self.file, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class TechnologyFact:
    category: str
    name: str
    confidence: int
    version: str = ""
    evidence: tuple[TechnologyEvidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "name": self.name,
            "version": self.version,
            "confidence": self.confidence,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class TechnologyReport:
    primary_language: str
    facts: tuple[TechnologyFact, ...]
    detector_version: str = DETECTOR_VERSION

    def by_category(self, category: str) -> tuple[TechnologyFact, ...]:
        return tuple(item for item in self.facts if item.category == category)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector_version": self.detector_version,
            "primary_language": self.primary_language,
            "facts": [item.to_dict() for item in self.facts],
        }


MANIFEST_LANGUAGES = {
    "requirements.txt": ("Python", "pip"),
    "pyproject.toml": ("Python", "pip"),
    "package.json": ("JavaScript/TypeScript", "npm"),
    "pom.xml": ("Java", "Maven"),
    "build.gradle": ("Java", "Gradle"),
    "build.gradle.kts": ("Java/Kotlin", "Gradle"),
    "composer.json": ("PHP", "Composer"),
    "gemfile": ("Ruby", "Bundler"),
    "go.mod": ("Go", "Go Modules"),
    "cargo.toml": ("Rust", "Cargo"),
}

SUFFIX_LANGUAGES = {
    ".py": "Python",
    ".js": "JavaScript/TypeScript",
    ".jsx": "JavaScript/TypeScript",
    ".ts": "JavaScript/TypeScript",
    ".tsx": "JavaScript/TypeScript",
    ".java": "Java",
    ".kt": "Java/Kotlin",
    ".cs": ".NET",
    ".php": "PHP",
    ".rb": "Ruby",
    ".go": "Go",
    ".rs": "Rust",
}

DEPENDENCY_HINTS = {
    "database": {
        "postgresql": "PostgreSQL",
        "psycopg": "PostgreSQL",
        "pg": "PostgreSQL",
        "mysql": "MySQL",
        "pymysql": "MySQL",
        "mongodb": "MongoDB",
        "mongoose": "MongoDB",
        "redis": "Redis",
        "sqlalchemy": "SQLAlchemy",
        "prisma": "Prisma",
        "entityframework": "Entity Framework",
    },
    "authentication": {
        "passport": "Passport",
        "jsonwebtoken": "JWT",
        "pyjwt": "JWT",
        "oauth": "OAuth",
        "spring-security": "Spring Security",
        "sanctum": "Laravel Sanctum",
        "devise": "Devise",
        "identity": "ASP.NET Identity",
    },
    "api_type": {
        "graphql": "GraphQL",
        "apollo-server": "GraphQL",
        "strawberry": "GraphQL",
        "grpc": "gRPC",
    },
    "frontend": {
        "react": "React",
        "next": "Next.js",
        "@angular/core": "Angular",
        "vue": "Vue",
        "svelte": "Svelte",
    },
}

FRAMEWORK_DEPENDENCIES = {
    "fastapi": "FastAPI",
    "flask": "Flask",
    "django": "Django",
    "express": "Express",
    "@nestjs/core": "NestJS",
    "next": "Next.js",
    "spring-boot": "Spring Boot",
    "microsoft.aspnetcore": "ASP.NET Core",
    "laravel/framework": "Laravel",
    "symfony/framework-bundle": "Symfony",
    "rails": "Rails",
}

FRAMEWORK_CANONICAL = {
    "fastapi": "FastAPI",
    "flask": "Flask",
    "django": "Django",
    "express": "Express",
    "nestjs": "NestJS",
    "spring": "Spring Boot",
    "laravel": "Laravel",
    "aspnet": "ASP.NET Core",
    "openapi": "OpenAPI",
    "postman": "Postman",
}


def _iter_files(root: Path) -> Iterable[Path]:
    seen = 0
    for directory, names, files in os.walk(root, followlinks=False):
        names[:] = [
            name
            for name in names
            if name.lower() not in SKIP_DIRECTORIES
            and not (Path(directory) / name).is_symlink()
        ]
        for name in sorted(files):
            path = Path(directory) / name
            if path.is_symlink():
                continue
            seen += 1
            if seen > MAX_FILES:
                return
            yield path


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _read_manifest(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _dependency_versions(path: Path, content: str) -> dict[str, str]:
    lowered_name = path.name.lower()
    dependencies: dict[str, str] = {}
    if lowered_name in {"package.json", "composer.json"}:
        try:
            payload = json.loads(content)
        except (TypeError, ValueError):
            return dependencies
        for section in ("dependencies", "devDependencies", "require", "require-dev"):
            values = payload.get(section, {})
            if isinstance(values, dict):
                dependencies.update(
                    {str(key).lower(): str(value) for key, value in values.items()}
                )
        return dependencies
    if lowered_name == "pyproject.toml" or lowered_name == "cargo.toml":
        try:
            payload = tomllib.loads(content)
        except (TypeError, tomllib.TOMLDecodeError):
            return dependencies
        if lowered_name == "cargo.toml":
            values = payload.get("dependencies", {})
            for key, value in values.items():
                version = value.get("version", "") if isinstance(value, dict) else value
                dependencies[str(key).lower()] = str(version)
        else:
            values = payload.get("project", {}).get("dependencies", [])
            for value in values if isinstance(values, list) else []:
                match = re.match(r"([A-Za-z0-9_.-]+)\s*([<>=!~].*)?$", str(value))
                if match:
                    dependencies[match.group(1).lower()] = match.group(2) or ""
        return dependencies
    if lowered_name == "requirements.txt":
        for line in content.splitlines():
            match = re.match(r"\s*([A-Za-z0-9_.-]+)\s*([<>=!~].*)?$", line)
            if match:
                dependencies[match.group(1).lower()] = match.group(2) or ""
        return dependencies
    if lowered_name in {"pom.xml", "build.gradle", "build.gradle.kts"} or path.suffix.lower() == ".csproj":
        for name, version in re.findall(
            r"(?:artifactId>|Include=[\"'])([A-Za-z0-9_.@/-]+)(?:</artifactId>|[\"'])[^\n<]{0,100}(?:<version>|Version=[\"'])?([^\"'<\s)]*)",
            content,
            flags=re.IGNORECASE,
        ):
            dependencies[name.lower()] = version
        return dependencies
    if lowered_name == "gemfile":
        for name, version in re.findall(
            r"gem\s+[\"']([^\"']+)[\"'](?:\s*,\s*[\"']([^\"']+)[\"'])?",
            content,
        ):
            dependencies[name.lower()] = version
    return dependencies


def _clean_version(value: str) -> str:
    return str(value or "").strip().lstrip("=~^<> ")[:100]


def _add(
    facts: list[TechnologyFact],
    category: str,
    name: str,
    confidence: int,
    file: str,
    reason: str,
    version: str = "",
) -> None:
    facts.append(
        TechnologyFact(
            category,
            name,
            max(0, min(100, confidence)),
            _clean_version(version),
            (TechnologyEvidence(file, reason),),
        )
    )


def _runtime_facts(
    facts: list[TechnologyFact], path: Path, relative: str, content: str
) -> None:
    name = path.name.lower()
    if name == "go.mod":
        match = re.search(r"^go\s+([0-9.]+)", content, re.MULTILINE)
        if match:
            _add(facts, "runtime", "Go", 95, relative, "go directive", match.group(1))
    elif name == "package.json":
        try:
            node = json.loads(content).get("engines", {}).get("node", "")
        except (TypeError, ValueError, AttributeError):
            node = ""
        if node:
            _add(facts, "runtime", "Node.js", 95, relative, "package engines.node", node)
    elif name == "pyproject.toml":
        try:
            python = tomllib.loads(content).get("project", {}).get("requires-python", "")
        except (TypeError, tomllib.TOMLDecodeError, AttributeError):
            python = ""
        if python:
            _add(facts, "runtime", "Python", 95, relative, "requires-python", python)
    elif path.suffix.lower() == ".csproj":
        match = re.search(r"<TargetFramework>([^<]+)</TargetFramework>", content)
        if match:
            _add(facts, "runtime", ".NET", 95, relative, "TargetFramework", match.group(1))
    elif name == "cargo.toml":
        try:
            rust = tomllib.loads(content).get("package", {}).get("rust-version", "")
        except (TypeError, tomllib.TOMLDecodeError, AttributeError):
            rust = ""
        if rust:
            _add(facts, "runtime", "Rust", 95, relative, "rust-version", rust)


def _deduplicate(facts: Iterable[TechnologyFact]) -> tuple[TechnologyFact, ...]:
    merged: dict[tuple[str, str], TechnologyFact] = {}
    for fact in facts:
        key = (fact.category.lower(), fact.name.lower())
        previous = merged.get(key)
        if previous is None:
            merged[key] = fact
            continue
        evidence = tuple(
            dict.fromkeys((*previous.evidence, *fact.evidence))
        )[:10]
        merged[key] = TechnologyFact(
            previous.category,
            previous.name,
            max(previous.confidence, fact.confidence),
            previous.version or fact.version,
            evidence,
        )
    return tuple(
        sorted(merged.values(), key=lambda item: (item.category, item.name.lower()))
    )


def detect_technologies(source_root: Path) -> TechnologyReport:
    root = source_root.resolve()
    if not root.is_dir():
        raise ValueError("Technology detection requires an existing source directory.")

    facts: list[TechnologyFact] = []
    for path in _iter_files(root):
        relative = _relative(path, root)
        lowered_name = path.name.lower()
        suffix = path.suffix.lower()
        language = SUFFIX_LANGUAGES.get(suffix)
        if language:
            _add(facts, "language", language, 55, relative, f"{suffix} source file")
        if suffix == ".csproj":
            _add(facts, "language", ".NET", 98, relative, ".csproj manifest")
            _add(facts, "package_manager", "NuGet", 98, relative, ".csproj manifest")

        manifest = MANIFEST_LANGUAGES.get(lowered_name)
        if manifest:
            _add(facts, "language", manifest[0], 98, relative, f"{path.name} manifest")
            _add(facts, "package_manager", manifest[1], 98, relative, f"{path.name} manifest")
        if lowered_name == "dockerfile" or lowered_name.startswith("dockerfile."):
            _add(facts, "containerization", "Docker", 98, relative, "Dockerfile")
        if lowered_name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
            _add(facts, "containerization", "Docker Compose", 98, relative, "Compose manifest")

        if not manifest and suffix != ".csproj":
            continue
        content = _read_manifest(path)
        if not content:
            continue
        _runtime_facts(facts, path, relative, content)
        dependencies = _dependency_versions(path, content)
        for dependency, version in dependencies.items():
            for needle, framework in FRAMEWORK_DEPENDENCIES.items():
                if needle in dependency:
                    _add(facts, "framework", framework, 92, relative, f"dependency {dependency}", version)
            for category, hints in DEPENDENCY_HINTS.items():
                for needle, detected_name in hints.items():
                    if needle in dependency:
                        _add(facts, category, detected_name, 86, relative, f"dependency {dependency}", version)

    project = ProjectRef(root)
    for adapter in default_registry().all():
        try:
            result = adapter.detect(project)
        except (OSError, ValueError, TypeError):
            continue
        if not result.detected:
            continue
        evidence = result.evidence[0] if result.evidence else None
        evidence_parts = {
            part.lower()
            for part in Path(evidence.source_file).parts
        } if evidence and evidence.source_file else set()
        if evidence_parts.intersection({"tests", "test", "fixtures"}):
            # Test applications are supporting evidence, not the host project's
            # production framework. A matching manifest dependency still wins.
            continue
        _add(
            facts,
            "framework",
            FRAMEWORK_CANONICAL.get(result.framework.lower(), result.framework),
            result.confidence_score,
            evidence.source_file if evidence else "",
            evidence.evidence_type if evidence else "adapter detection",
            result.version,
        )
        try:
            auth_flows = adapter.extract_auth_flows(project)
        except (OSError, ValueError, TypeError):
            auth_flows = []
        for flow in auth_flows:
            if not flow.required:
                continue
            auth_evidence = flow.evidence[0] if flow.evidence else None
            for mode in flow.modes:
                if mode.value in {"unknown", "public", "optional-authentication"}:
                    continue
                _add(
                    facts,
                    "authentication",
                    mode.value,
                    flow.confidence_score,
                    auth_evidence.source_file if auth_evidence else "",
                    auth_evidence.evidence_type if auth_evidence else "adapter auth detection",
                )

    framework_names = {item.name for item in facts if item.category == "framework"}
    if framework_names.intersection(
        {"FastAPI", "Flask", "Django", "Express", "NestJS", "Spring", "Spring Boot", "Laravel", "ASP.NET Core"}
    ):
        _add(facts, "api_type", "REST", 75, "", "web framework detected")

    normalized = _deduplicate(facts)
    languages = [item for item in normalized if item.category == "language"]
    primary = (
        sorted(languages, key=lambda item: (-item.confidence, item.name.lower()))[0].name
        if languages
        else "Unknown"
    )
    return TechnologyReport(primary, normalized)


def persist_technology_report(
    db: Session,
    *,
    project_id: int,
    owner_user_id: int,
    source_sha256: str,
    report: TechnologyReport,
    commit: bool = True,
) -> str:
    existing = db.scalars(
        select(TechnologyDetectionRun).where(
            TechnologyDetectionRun.project_id == project_id,
            TechnologyDetectionRun.owner_user_id == owner_user_id,
            TechnologyDetectionRun.source_sha256 == source_sha256,
            TechnologyDetectionRun.detector_version == report.detector_version,
        )
    ).first()
    if existing is not None:
        return existing.public_id
    public_id = str(uuid.uuid4())
    db.add(
        TechnologyDetectionRun(
            public_id=public_id,
            project_id=project_id,
            owner_user_id=owner_user_id,
            source_sha256=source_sha256,
            detector_version=report.detector_version,
            primary_language=report.primary_language,
            report_json=report.to_dict(),
            created_at=datetime.now(timezone.utc),
        )
    )
    if commit:
        db.commit()
    else:
        db.flush()
    return public_id
