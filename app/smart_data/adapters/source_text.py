"""Bounded, non-executing text file walking for source adapters."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from app.smart_data.adapters.document_scan import SKIP_DIRECTORIES, SENSITIVE_NAMES
from app.smart_data.contracts import ProjectRef

MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_FILES = 8_000


@dataclass(frozen=True, slots=True)
class SourceText:
    relative_path: str
    text: str


def join_path(*parts: str) -> str:
    value = "/" + "/".join(
        part.strip("/") for part in parts if part and str(part).strip("/") and part != "/"
    )
    return value or "/"


def iter_source_text(project: ProjectRef, suffixes: frozenset[str]) -> Iterator[SourceText]:
    root = project.root.resolve(strict=False)
    if not root.is_dir():
        return
    count = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if count >= MAX_SOURCE_FILES:
            break
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part in SKIP_DIRECTORIES for part in relative.parts[:-1]):
            continue
        if path.name.lower() in SENSITIVE_NAMES or not path.is_file():
            continue
        if path.suffix.lower() not in suffixes:
            continue
        try:
            if path.is_symlink() or path.stat().st_size > MAX_SOURCE_BYTES:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        count += 1
        yield SourceText(relative.as_posix(), text)
