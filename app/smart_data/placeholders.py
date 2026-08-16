"""Canonical smart-data placeholder construction and validation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterator, Mapping


class PlaceholderKind(str, Enum):
    REQUIRED = "REQUIRED"
    SECRET_REF = "SECRET_REF"
    DYNAMIC = "DYNAMIC"
    SYNTHETIC = "SYNTHETIC"


_PLACEHOLDER_RE = re.compile(
    r"\{\{(?P<kind>REQUIRED|SECRET_REF|DYNAMIC|SYNTHETIC):"
    r"(?P<reference>[a-zA-Z0-9][a-zA-Z0-9_.:/-]*)\}\}"
)
_ANY_PLACEHOLDER_RE = re.compile(r"\{\{[^{}]+\}\}")


@dataclass(frozen=True, slots=True)
class Placeholder:
    kind: PlaceholderKind
    reference: str
    raw: str

    @property
    def blocks_approval(self) -> bool:
        return self.kind in {
            PlaceholderKind.REQUIRED,
            PlaceholderKind.SECRET_REF,
            PlaceholderKind.DYNAMIC,
        }


def build_placeholder(kind: PlaceholderKind, reference: str) -> str:
    candidate = f"{{{{{kind.value}:{reference.strip()}}}}}"
    if _PLACEHOLDER_RE.fullmatch(candidate) is None:
        raise ValueError("Invalid smart-data placeholder reference")
    return candidate


def parse_placeholder(value: str) -> Placeholder | None:
    match = _PLACEHOLDER_RE.fullmatch(value.strip())
    if match is None:
        return None
    return Placeholder(
        kind=PlaceholderKind(match.group("kind")),
        reference=match.group("reference"),
        raw=match.group(0),
    )


def iter_placeholders(value: Any) -> Iterator[Placeholder]:
    if isinstance(value, str):
        for match in _PLACEHOLDER_RE.finditer(value):
            yield Placeholder(
                kind=PlaceholderKind(match.group("kind")),
                reference=match.group("reference"),
                raw=match.group(0),
            )
        return
    if isinstance(value, Mapping):
        for item in value.values():
            yield from iter_placeholders(item)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield from iter_placeholders(item)


def invalid_placeholders(value: Any) -> tuple[str, ...]:
    invalid: list[str] = []

    def visit(item: Any) -> None:
        if isinstance(item, str):
            valid_spans = {
                match.span() for match in _PLACEHOLDER_RE.finditer(item)
            }
            invalid.extend(
                match.group(0)
                for match in _ANY_PLACEHOLDER_RE.finditer(item)
                if match.span() not in valid_spans
            )
        elif isinstance(item, Mapping):
            for child in item.values():
                visit(child)
        elif isinstance(item, (list, tuple, set)):
            for child in item:
                visit(child)

    visit(value)
    return tuple(invalid)


def unresolved_mandatory(value: Any) -> tuple[Placeholder, ...]:
    return tuple(
        placeholder
        for placeholder in iter_placeholders(value)
        if placeholder.blocks_approval
    )


def approval_blockers(value: Any) -> tuple[str, ...]:
    """Return canonical, legacy, or malformed mandatory markers.

    INVALID_* markers intentionally belong to generated negative cases and
    are resolved by the runner, so they are not approval blockers.
    """
    blockers = [item.raw for item in unresolved_mandatory(value)]
    legacy = re.compile(r"\{\{(?:REQUIRED|SECRET|DYNAMIC)_[A-Z0-9_]+\}\}")

    def visit(item: Any) -> None:
        if isinstance(item, str):
            blockers.extend(match.group(0) for match in legacy.finditer(item))
            for marker in invalid_placeholders(item):
                if not marker.startswith("{{INVALID_"):
                    blockers.append(marker)
        elif isinstance(item, Mapping):
            for child in item.values():
                visit(child)
        elif isinstance(item, (list, tuple, set)):
            for child in item:
                visit(child)

    visit(value)
    return tuple(dict.fromkeys(blockers))


def _json_value(raw: Any, fallback: Any) -> Any:
    if isinstance(raw, (dict, list)) or raw is None:
        return raw if raw is not None else fallback
    if not isinstance(raw, str) or not raw.strip():
        return fallback
    try:
        return json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return fallback


def request_payload(case: Mapping[str, Any] | None) -> dict[str, Any]:
    case = case or {}
    body_raw = case.get("request_body")
    if isinstance(body_raw, str) and body_raw.strip():
        body = _json_value(body_raw, body_raw)
    else:
        body = body_raw
    return {
        "path": case.get("endpoint_path") or "",
        "headers": _json_value(case.get("request_headers"), {}),
        "query": _json_value(case.get("request_query"), {}),
        "body": body,
    }


def apply_placeholder_safety(
    case: dict[str, Any],
    *,
    safe_methods: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"}),
) -> dict[str, Any]:
    """Read-only cases with mandatory placeholders cannot auto-join a plan."""
    if approval_blockers(request_payload(case)):
        case["safe_to_execute"] = False
        case["requires_approval"] = True
    elif str(case.get("http_method", "")).upper() in safe_methods:
        case["safe_to_execute"] = True
        case["requires_approval"] = False
    return case
