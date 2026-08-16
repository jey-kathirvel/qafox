"""Safe Python source discovery and AST helpers.

Uploaded modules are read as text and parsed with :mod:`ast`; they are never
imported, compiled, evaluated, or executed.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from app.smart_data.adapters.document_scan import SKIP_DIRECTORIES, SENSITIVE_NAMES
from app.smart_data.contracts import ProjectRef


MAX_PYTHON_BYTES = 2 * 1024 * 1024
MAX_PYTHON_FILES = 10_000


@dataclass(frozen=True, slots=True)
class ParsedPython:
    relative_path: str
    module: str
    tree: ast.Module
    text: str


def module_name(relative_path: str) -> str:
    path = Path(relative_path)
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def iter_python(project: ProjectRef) -> Iterator[ParsedPython]:
    root = project.root.resolve(strict=False)
    if not root.is_dir():
        return
    count = 0
    for path in sorted(root.rglob("*.py"), key=lambda item: item.as_posix()):
        if count >= MAX_PYTHON_FILES:
            break
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part in SKIP_DIRECTORIES for part in relative.parts[:-1]):
            continue
        if path.name.lower() in SENSITIVE_NAMES:
            continue
        try:
            if path.is_symlink() or path.stat().st_size > MAX_PYTHON_BYTES:
                continue
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=relative.as_posix(), type_comments=True)
        except (OSError, UnicodeDecodeError, SyntaxError, ValueError):
            continue
        count += 1
        yield ParsedPython(relative.as_posix(), module_name(relative.as_posix()), tree, text)


def dotted_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return dotted_name(node.func)
    return ""


def static_value(node: ast.AST | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None


def keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def call_string(call: ast.Call, position: int = 0, keyword_name: str = "") -> str:
    node = keyword(call, keyword_name) if keyword_name else None
    if node is None and len(call.args) > position:
        node = call.args[position]
    value = static_value(node)
    return str(value) if isinstance(value, str) else ""


def annotation_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Subscript):
        base = dotted_name(node.value)
        inner = annotation_name(node.slice)
        return f"{base}[{inner}]"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return f"{annotation_name(node.left)} | {annotation_name(node.right)}"
    return dotted_name(node)


def source_excerpt(parsed: ParsedPython, node: ast.AST, limit: int = 300) -> str:
    segment = ast.get_source_segment(parsed.text, node) or ""
    return segment[:limit]
