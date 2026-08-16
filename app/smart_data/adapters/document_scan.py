"""Bounded, non-executing document discovery for definition adapters."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.smart_data.contracts import ProjectRef


SKIP_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "site-packages",
        "node_modules",
        "dist",
        "build",
        "target",
        "vendor",
        "coverage",
        "__pycache__",
        ".cache",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".npm",
        ".pnpm-store",
        ".yarn",
    }
)
SENSITIVE_NAMES = frozenset(
    {
        ".env",
        ".env.local",
        ".env.production",
        "id_rsa",
        "id_ed25519",
        "credentials",
        "credentials.json",
        "secrets.json",
    }
)
DOCUMENT_SUFFIXES = frozenset({".json", ".yaml", ".yml"})
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_DOCUMENTS = 1_000


@dataclass(frozen=True, slots=True)
class ParsedDocument:
    relative_path: str
    value: dict[str, Any]


def iter_documents(project: ProjectRef) -> Iterator[ParsedDocument]:
    root = project.root.resolve(strict=False)
    if not root.is_dir():
        return

    inspected = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if inspected >= MAX_DOCUMENTS:
            break
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part in SKIP_DIRECTORIES for part in relative.parts[:-1]):
            continue
        if path.name.lower() in SENSITIVE_NAMES:
            continue
        if path.suffix.lower() not in DOCUMENT_SUFFIXES or not path.is_file():
            continue
        try:
            if path.is_symlink() or path.stat().st_size > MAX_DOCUMENT_BYTES:
                continue
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        inspected += 1
        try:
            value = json.loads(raw) if path.suffix.lower() == ".json" else yaml.safe_load(raw)
        except (ValueError, yaml.YAMLError):
            continue
        if isinstance(value, dict):
            yield ParsedDocument(relative.as_posix(), value)
