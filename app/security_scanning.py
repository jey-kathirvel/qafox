"""Hardened scanner execution and normalized security finding contracts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from sqlalchemy.orm import Session

from app.quality_models import SecurityFindingRecord, SecurityScanRun

MAX_RESULT_BYTES = 50 * 1024 * 1024
MAX_FINDINGS = 25_000
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


class ScannerUnavailable(RuntimeError):
    pass


class ScanExecutionError(RuntimeError):
    pass


def normalize_severity(value: str, *, semgrep: bool = False) -> str:
    severity = str(value or "INFO").upper()
    if semgrep:
        return {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(
            severity, "INFO"
        )
    return severity if severity in SEVERITIES else "INFO"


def _strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set)):
        return tuple(str(item) for item in value if item)
    return ()


def safe_source_file(value: str) -> str:
    raw = str(value or "").replace("\\", "/")
    absolute = raw.startswith("/") or bool(re.match(r"^[A-Za-z]:/", raw))
    normalized = raw.lstrip("/")
    parts = [part for part in PurePosixPath(normalized).parts if part not in {"", "."}]
    if any(part == ".." for part in parts):
        return ""
    lower_parts = [part.lower() for part in parts]
    if "source" in lower_parts:
        parts = parts[len(parts) - 1 - lower_parts[::-1].index("source") + 1 :]
    elif absolute and parts:
        parts = parts[-1:]
    return "/".join(parts)[-2000:]


def redact_text(value: str, *, secret_finding: bool = False) -> str:
    if secret_finding:
        return "********"
    text = str(value or "")[:4000]
    text = re.sub(
        r"(?i)(authorization|api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+",
        r"\1=********",
        text,
    )
    text = re.sub(r"\b[A-Za-z0-9_+/=-]{40,}\b", "********", text)
    return text


@dataclass(frozen=True, slots=True)
class NormalizedSecurityFinding:
    scanner: str
    rule_id: str
    title: str
    description: str
    severity: str
    category: str
    component: str
    source_file: str = ""
    source_line: int | None = None
    evidence: str = ""
    recommendation: str = ""
    confidence: float = 0.0
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        stable = "\x1f".join(
            (
                self.scanner.lower(),
                self.rule_id.lower(),
                self.component.lower(),
                self.source_file.lower(),
                str(self.source_line or 0),
            )
        )
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ScannerOutput:
    scanner: str
    tool_version: str
    findings: tuple[NormalizedSecurityFinding, ...]


class SecurityScanner(ABC):
    name: str
    executable: str
    accepted_exit_codes: frozenset[int] = frozenset({0})

    @abstractmethod
    def command(self, binary: str, source: Path, output: Path) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def parse(self, payload: Any) -> tuple[NormalizedSecurityFinding, ...]:
        raise NotImplementedError

    def execute(self, source: Path, workspace: Path, timeout_seconds: int = 900) -> ScannerOutput:
        source = source.resolve()
        workspace = workspace.resolve()
        if not source.is_dir() or source == workspace or workspace in source.parents:
            raise ScanExecutionError("Scanner source/workspace boundaries are invalid.")
        binary = shutil.which(self.executable)
        if not binary:
            raise ScannerUnavailable(f"{self.executable} is not installed on this worker.")
        workspace.mkdir(parents=True, exist_ok=True)
        output = workspace / f"{self.name}-results.json"
        environment = {
            key: os.environ[key]
            for key in ("PATH", "SYSTEMROOT", "WINDIR")
            if key in os.environ
        }
        environment.update({"HOME": str(workspace), "USERPROFILE": str(workspace), "NO_COLOR": "1"})
        version = _tool_version(binary, environment, workspace)
        try:
            result = subprocess.run(
                self.command(binary, source, output),
                cwd=workspace,
                env=environment,
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ScanExecutionError(f"{self.name} execution failed.") from exc
        if result.returncode not in self.accepted_exit_codes:
            raise ScanExecutionError(f"{self.name} returned an execution error.")
        if not output.is_file() or output.stat().st_size > MAX_RESULT_BYTES:
            raise ScanExecutionError(f"{self.name} did not produce a bounded JSON result.")
        try:
            payload = json.loads(output.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ScanExecutionError(f"{self.name} produced invalid JSON.") from exc
        return ScannerOutput(self.name, version, self.parse(payload)[:MAX_FINDINGS])


def _tool_version(binary: str, environment: dict[str, str], cwd: Path) -> str:
    try:
        result = subprocess.run(
            [binary, "--version"], cwd=cwd, env=environment, shell=False,
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15,
            check=False,
        )
        return (result.stdout or result.stderr).strip().splitlines()[0][:100] or "unknown"
    except (OSError, subprocess.SubprocessError, IndexError):
        return "unknown"


class SemgrepScanner(SecurityScanner):
    name = "semgrep"
    executable = "semgrep"
    accepted_exit_codes = frozenset({0, 1})

    def command(self, binary: str, source: Path, output: Path) -> list[str]:
        config = os.getenv("QAFOX_SEMGREP_CONFIG", "p/default")
        return [
            binary, "scan", "--json", "--output", str(output), "--config", config,
            "--metrics", "off", "--disable-version-check", "--no-git-ignore",
            "--exclude", ".git", "--exclude", ".venv", "--exclude", "node_modules",
            str(source),
        ]

    def parse(self, payload: Any) -> tuple[NormalizedSecurityFinding, ...]:
        findings = []
        for item in (payload.get("results", []) if isinstance(payload, dict) else []):
            extra = item.get("extra") or {}
            metadata = extra.get("metadata") or {}
            path = safe_source_file(item.get("path", ""))
            line = int((item.get("start") or {}).get("line") or 0) or None
            rule_id = str(item.get("check_id") or "semgrep-unknown")[:500]
            message = redact_text(str(extra.get("message") or rule_id))
            confidence_value = str(metadata.get("confidence") or "MEDIUM").upper()
            confidence = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.4}.get(confidence_value, 0.6)
            findings.append(
                NormalizedSecurityFinding(
                    "semgrep", rule_id, message[:500], message[:4000],
                    normalize_severity(extra.get("severity", "INFO"), semgrep=True),
                    str(metadata.get("category") or "SAST")[:200], path or rule_id,
                    path, line, redact_text(str(extra.get("lines") or "")),
                    redact_text(str(extra.get("fix") or metadata.get("fix") or "Review and remediate the flagged code path.")),
                    confidence, _strings(metadata.get("cwe")), _strings(metadata.get("owasp")),
                    {"references": list(_strings(metadata.get("references")))[:20]},
                )
            )
        return tuple(findings)


class TrivyScanner(SecurityScanner):
    name = "trivy"
    executable = "trivy"

    def command(self, binary: str, source: Path, output: Path) -> list[str]:
        return [
            binary, "fs", "--format", "json", "--output", str(output),
            "--scanners", "vuln,misconfig", "--skip-dirs", ".git",
            "--skip-dirs", ".venv", "--skip-dirs", "node_modules", str(source),
        ]

    def parse(self, payload: Any) -> tuple[NormalizedSecurityFinding, ...]:
        findings = []
        results = payload.get("Results", []) if isinstance(payload, dict) else []
        for result in results:
            target = safe_source_file(result.get("Target", ""))
            for item in result.get("Vulnerabilities") or []:
                vulnerability = str(item.get("VulnerabilityID") or "trivy-vulnerability")
                package = str(item.get("PkgName") or "unknown")
                installed = str(item.get("InstalledVersion") or "")
                fixed = str(item.get("FixedVersion") or "")
                title = str(item.get("Title") or vulnerability)
                findings.append(
                    NormalizedSecurityFinding(
                        "trivy", vulnerability, title[:500],
                        str(item.get("Description") or title)[:4000],
                        normalize_severity(item.get("Severity", "UNKNOWN")),
                        "Dependency Vulnerability", package, target, None, "",
                        (f"Upgrade {package} to {fixed}." if fixed else f"Review and replace or mitigate {package}."),
                        0.95, (), (),
                        {
                            "package": package, "installed_version": installed,
                            "fixed_version": fixed, "cvss": item.get("CVSS") or {},
                            "references": list(item.get("References") or [])[:20],
                            "primary_url": str(item.get("PrimaryURL") or "")[:2000],
                        },
                    )
                )
            for item in result.get("Misconfigurations") or []:
                rule_id = str(item.get("ID") or item.get("AVDID") or "trivy-misconfiguration")
                cause = item.get("CauseMetadata") or {}
                line = int(cause.get("StartLine") or 0) or None
                title = str(item.get("Title") or rule_id)
                findings.append(
                    NormalizedSecurityFinding(
                        "trivy", rule_id, title[:500],
                        str(item.get("Description") or item.get("Message") or title)[:4000],
                        normalize_severity(item.get("Severity", "UNKNOWN")),
                        "Configuration", target or rule_id, target, line,
                        redact_text(str(item.get("Message") or "")),
                        str(item.get("Resolution") or "Apply the scanner remediation guidance.")[:4000],
                        0.9, (), _strings(item.get("PrimaryURL")),
                        {"references": list(item.get("References") or [])[:20]},
                    )
                )
        return tuple(findings)


class GitleaksScanner(SecurityScanner):
    name = "gitleaks"
    executable = "gitleaks"

    def command(self, binary: str, source: Path, output: Path) -> list[str]:
        return [
            binary, "detect", "--source", str(source), "--no-git", "--redact",
            "--report-format", "json", "--report-path", str(output), "--exit-code", "0",
            "--no-banner",
        ]

    def parse(self, payload: Any) -> tuple[NormalizedSecurityFinding, ...]:
        findings = []
        for item in payload if isinstance(payload, list) else []:
            rule_id = str(item.get("RuleID") or "gitleaks-secret")
            path = safe_source_file(item.get("File", ""))
            line = int(item.get("StartLine") or 0) or None
            description = str(item.get("Description") or "Potential secret detected")
            findings.append(
                NormalizedSecurityFinding(
                    "gitleaks", rule_id, description[:500], description[:4000], "HIGH",
                    "Secret Exposure", path or rule_id, path, line, "********",
                    "Revoke and rotate the credential, remove it from source and history, and use an encrypted secret store.",
                    0.9, (), (),
                    {
                        "redacted": True,
                        "tags": list(item.get("Tags") or [])[:20],
                        "entropy": float(item.get("Entropy") or 0.0),
                    },
                )
            )
        return tuple(findings)


SCANNERS: dict[str, SecurityScanner] = {
    "semgrep": SemgrepScanner(),
    "trivy": TrivyScanner(),
    "gitleaks": GitleaksScanner(),
}


def scanner_availability() -> dict[str, bool]:
    return {name: bool(shutil.which(scanner.executable)) for name, scanner in SCANNERS.items()}


def run_security_scanner(
    db: Session,
    *,
    scanner: SecurityScanner,
    source: Path,
    workspace: Path,
    project_id: int,
    owner_user_id: int,
    test_run_id: int | None = None,
    timeout_seconds: int = 900,
) -> SecurityScanRun:
    run = SecurityScanRun(
        public_id=str(uuid.uuid4()),
        test_run_id=test_run_id,
        project_id=project_id,
        owner_user_id=owner_user_id,
        scanner=scanner.name,
        status="RUNNING",
        tool_version="unknown",
    )
    db.add(run)
    db.commit()
    try:
        output = scanner.execute(source, workspace, timeout_seconds)
        run.tool_version = output.tool_version
        for finding in output.findings:
            db.add(
                SecurityFindingRecord(
                    public_id=str(uuid.uuid4()),
                    scan_run_id=run.id,
                    test_run_id=test_run_id,
                    project_id=project_id,
                    owner_user_id=owner_user_id,
                    fingerprint=finding.fingerprint,
                    scanner=finding.scanner,
                    rule_id=finding.rule_id,
                    title=finding.title,
                    description=finding.description,
                    severity=finding.severity,
                    category=finding.category,
                    component=finding.component,
                    source_file=finding.source_file or None,
                    source_line=finding.source_line,
                    evidence=finding.evidence,
                    recommendation=finding.recommendation,
                    confidence=finding.confidence,
                    cwe_json=list(finding.cwe),
                    owasp_json=list(finding.owasp),
                    details_json=finding.details,
                )
            )
        run.status = "COMPLETED"
    except ScannerUnavailable as exc:
        run.status = "UNAVAILABLE"
        run.error_message = str(exc)[:1000]
    except ScanExecutionError as exc:
        run.status = "FAILED"
        run.error_message = str(exc)[:1000]
    run.completed_at = datetime.now(timezone.utc)
    db.commit()
    return run
