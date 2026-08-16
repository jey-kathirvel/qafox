"""Bounded runtime orchestration for approved dependent API workflows.

PATCH-QAFOX-004B1A-8. This module does not execute HTTP. Callers must keep
one-run plan consumption, TLS/SSRF controls, secret masking, and owner
isolation in the hardened runner.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from app.smart_data.compatibility import canonical_path, normalize_path
from app.smart_data.placeholders import (
    PlaceholderKind,
    approval_blockers,
    build_placeholder,
    iter_placeholders,
    parse_placeholder,
    request_payload,
)


ORCHESTRATION_VERSION = "qafox-orchestration-v1"
MAX_JSON_DEPTH = 8
MAX_EXTRACT_LENGTH = 128
MAX_PATH_SEGMENTS = 8
_JSON_SEGMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_JSON_PATH = re.compile(
    r"^\$\.([A-Za-z_][A-Za-z0-9_]*)(?:\.([A-Za-z_][A-Za-z0-9_]*)){0,7}$"
)
_HEADER_EXTRACT = re.compile(r"^header:([A-Za-z0-9_-]+)$", re.IGNORECASE)
_UUID_LIKE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SAFE_SCALAR = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
CREATE_METHODS = frozenset({"POST", "PUT"})
CONSUMER_METHODS = frozenset({"GET", "PUT", "PATCH", "DELETE", "HEAD"})


@dataclass(frozen=True, slots=True)
class OrchestrationBinding:
    variable: str
    producer_case_public_id: str
    consumer_case_public_id: str
    extraction: str
    placeholder: str
    producer_path: str
    producer_method: str

    def to_json(self) -> dict[str, str]:
        return {
            "variable": self.variable,
            "producer_case_public_id": self.producer_case_public_id,
            "consumer_case_public_id": self.consumer_case_public_id,
            "extraction": self.extraction,
            "placeholder": self.placeholder,
            "producer_path": self.producer_path,
            "producer_method": self.producer_method,
        }


@dataclass(frozen=True, slots=True)
class CleanupSpec:
    producer_case_public_id: str
    variable: str
    method: str
    path_template: str
    requires_approval: bool = True
    same_run_only: bool = True

    def to_json(self) -> dict[str, Any]:
        return {
            "producer_case_public_id": self.producer_case_public_id,
            "variable": self.variable,
            "method": self.method,
            "path_template": self.path_template,
            "requires_approval": self.requires_approval,
            "same_run_only": self.same_run_only,
        }


@dataclass(slots=True)
class OrchestrationPlan:
    bindings: tuple[OrchestrationBinding, ...] = ()
    cleanup: tuple[CleanupSpec, ...] = ()
    cleanup_approved: bool = False
    execution_order: tuple[str, ...] = ()
    version: str = ORCHESTRATION_VERSION

    def to_json(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "cleanup_approved": self.cleanup_approved,
            "execution_order": list(self.execution_order),
            "bindings": [item.to_json() for item in self.bindings],
            "cleanup": [item.to_json() for item in self.cleanup],
        }

    def bindings_for_producer(self, case_public_id: str) -> tuple[OrchestrationBinding, ...]:
        return tuple(
            item
            for item in self.bindings
            if item.producer_case_public_id == case_public_id
        )

    def producers_for_consumer(self, case_public_id: str) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                item.producer_case_public_id
                for item in self.bindings
                if item.consumer_case_public_id == case_public_id
            )
        )


@dataclass(slots=True)
class RuntimeStore:
    values: dict[str, str] = field(default_factory=dict)
    created: dict[str, str] = field(default_factory=dict)
    failed_producers: set[str] = field(default_factory=set)
    captured_secrets: list[str] = field(default_factory=list)

    def remember(self, variable: str, value: str, *, created: bool) -> None:
        self.values[variable] = value
        if created:
            self.created[variable] = value
        if _looks_sensitive(variable):
            self.captured_secrets.append(value)


def _looks_sensitive(name: str) -> bool:
    lowered = name.lower()
    return any(
        token in lowered
        for token in ("secret", "token", "password", "credential", "authorization")
    )


def singularize(token: str) -> str:
    value = str(token or "").strip().lower().replace("-", "_")
    if value.endswith("ies") and len(value) > 3:
        return value[:-3] + "y"
    if value.endswith("sses"):
        return value
    if value.endswith("s") and not value.endswith("ss") and len(value) > 1:
        return value[:-1]
    return value


def collection_key(path: str) -> str:
    segments = [
        segment
        for segment in canonical_path(path).split("/")
        if segment and not segment.startswith("{")
    ]
    if not segments:
        return ""
    return singularize(segments[-1])


def field_resource(reference: str) -> str:
    text = str(reference or "").strip().lower().replace("-", "_")
    parts = [part for part in text.split(".") if part]
    if not parts:
        return ""
    last = parts[-1]
    skip = {"resource", "request", "output", "body"}
    if last in {"id", "uuid", "pk"}:
        for token in reversed(parts[:-1]):
            if token not in skip:
                return singularize(token)
        return ""
    if last.endswith("_id"):
        return singularize(last[:-3])
    if last not in skip:
        return singularize(last)
    return ""


def variable_name(method: str, path: str, field: str = "id") -> str:
    key = collection_key(path) or "resource"
    return f"{key}.{method.lower()}.output.{field}"


def default_extraction() -> str:
    return "$.id"


def is_create_like(method: str, path: str) -> bool:
    method = str(method or "").upper()
    if method not in CREATE_METHODS:
        return False
    segments = [segment for segment in canonical_path(path).split("/") if segment]
    if not segments:
        return False
    return "{" not in segments[-1] and "{{" not in segments[-1]


def extract_json_path(payload: Any, extraction: str) -> str | None:
    match = _JSON_PATH.fullmatch(str(extraction or "").strip())
    if match is None:
        return None
    current = payload
    if isinstance(current, str):
        try:
            current = json.loads(current)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
    segments = str(extraction).strip()[2:].split(".")
    if len(segments) > MAX_PATH_SEGMENTS:
        return None
    depth = 0
    for segment in segments:
        depth += 1
        if depth > MAX_JSON_DEPTH or not _JSON_SEGMENT.fullmatch(segment):
            return None
        if not isinstance(current, Mapping) or segment not in current:
            return None
        current = current[segment]
    return _scalar_token(current)


def extract_header_value(headers: Mapping[str, Any], extraction: str) -> str | None:
    match = _HEADER_EXTRACT.fullmatch(str(extraction or "").strip())
    if match is None:
        return None
    wanted = match.group(1).lower()
    for name, value in headers.items():
        if str(name).lower() == wanted:
            text = str(value or "").strip()
            if not text:
                return None
            parsed = urlsplit(text)
            if parsed.scheme and parsed.path:
                leaf = [part for part in parsed.path.split("/") if part]
                return _scalar_token(leaf[-1] if leaf else None)
            return _scalar_token(text)
    return None


def extract_runtime_value(
    *,
    body: Any,
    headers: Mapping[str, Any] | None = None,
    extraction: str,
) -> str | None:
    extraction = str(extraction or "").strip()
    if extraction.startswith("header:"):
        return extract_header_value(headers or {}, extraction)
    value = extract_json_path(body, extraction)
    if value is not None:
        return value
    if extraction == "$.id":
        for fallback in ("$.data.id", "$.uuid"):
            value = extract_json_path(body, fallback)
            if value is not None:
                return value
        header_value = extract_header_value(headers or {}, "header:Location")
        if header_value is not None:
            return header_value
    return None


def _scalar_token(value: Any) -> str | None:
    if value is None or isinstance(value, (dict, list, bool)):
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        if value < 0 or value > 10**18:
            return None
        return str(value)
    if isinstance(value, float):
        return None
    text = str(value).strip()
    if not text or len(text) > MAX_EXTRACT_LENGTH:
        return None
    if text.count(".") == 2 and len(text) > 40:
        return None
    if _UUID_LIKE.fullmatch(text) or _SAFE_SCALAR.fullmatch(text):
        return text
    return None


def substitute_placeholders(value: Any, resolved: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        updated = value
        for placeholder in iter_placeholders(value):
            if placeholder.kind is PlaceholderKind.DYNAMIC:
                replacement = resolved.get(placeholder.reference)
                if replacement is None:
                    continue
                updated = updated.replace(placeholder.raw, replacement)
        return updated
    if isinstance(value, Mapping):
        return {key: substitute_placeholders(item, resolved) for key, item in value.items()}
    if isinstance(value, list):
        return [substitute_placeholders(item, resolved) for item in value]
    return value


def remaining_dynamic(value: Any) -> tuple[str, ...]:
    return tuple(
        item.raw
        for item in iter_placeholders(value)
        if item.kind is PlaceholderKind.DYNAMIC
    )


def rewrite_bound_placeholders(
    payload: Any,
    bindings: Iterable[OrchestrationBinding],
    case_public_id: str,
) -> Any:
    mapping = {
        item.placeholder: item.placeholder
        for item in bindings
        if item.consumer_case_public_id == case_public_id
    }
    # Replace matching REQUIRED markers with the bound DYNAMIC placeholder.
    required_to_dynamic = {}
    for item in bindings:
        if item.consumer_case_public_id != case_public_id:
            continue
        resource = collection_key(item.producer_path) or field_resource(item.variable.split(".")[0])
        for placeholder in iter_placeholders(payload):
            if placeholder.kind is not PlaceholderKind.REQUIRED:
                continue
            consumer_resource = field_resource(placeholder.reference)
            if consumer_resource == resource:
                required_to_dynamic[placeholder.raw] = item.placeholder

    def visit(node: Any) -> Any:
        if isinstance(node, str):
            updated = node
            for raw, replacement in required_to_dynamic.items():
                updated = updated.replace(raw, replacement)
            return updated
        if isinstance(node, Mapping):
            return {key: visit(item) for key, item in node.items()}
        if isinstance(node, list):
            return [visit(item) for item in node]
        return node

    rewritten = visit(payload)
    return rewritten if mapping or required_to_dynamic else payload


def _case_public_id(case: Mapping[str, Any]) -> str:
    return str(case.get("public_id") or case.get("test_case_public_id") or "")


def _case_method(case: Mapping[str, Any]) -> str:
    return str(case.get("http_method") or "").upper()


def _case_path(case: Mapping[str, Any]) -> str:
    return str(case.get("endpoint_path") or "")


def infer_bindings(cases: Iterable[Mapping[str, Any]]) -> tuple[OrchestrationBinding, ...]:
    executable = [dict(item) for item in cases]
    producers = [
        case
        for case in executable
        if is_create_like(_case_method(case), _case_path(case))
    ]
    bindings: list[OrchestrationBinding] = []
    seen: set[tuple[str, str, str]] = set()

    for case in executable:
        payload = request_payload(case)
        references = [
            placeholder
            for placeholder in iter_placeholders(payload)
            if placeholder.kind in {PlaceholderKind.REQUIRED, PlaceholderKind.DYNAMIC}
        ]
        for placeholder in references:
            resource = (
                placeholder.reference.split(".")[0]
                if placeholder.kind is PlaceholderKind.DYNAMIC
                else field_resource(placeholder.reference)
            )
            resource = singularize(resource)
            producer = next(
                (
                    candidate
                    for candidate in producers
                    if _case_public_id(candidate) != _case_public_id(case)
                    and (
                        not resource
                        or collection_key(_case_path(candidate)) == resource
                    )
                ),
                None,
            )
            if producer is None:
                continue
            variable = (
                placeholder.reference
                if placeholder.kind is PlaceholderKind.DYNAMIC
                else variable_name(_case_method(producer), _case_path(producer))
            )
            dynamic = build_placeholder(PlaceholderKind.DYNAMIC, variable)
            key = (_case_public_id(producer), _case_public_id(case), variable)
            if key in seen:
                continue
            seen.add(key)
            bindings.append(
                OrchestrationBinding(
                    variable=variable,
                    producer_case_public_id=_case_public_id(producer),
                    consumer_case_public_id=_case_public_id(case),
                    extraction=default_extraction(),
                    placeholder=dynamic,
                    producer_path=normalize_path(_case_path(producer)),
                    producer_method=_case_method(producer),
                )
            )
    return tuple(bindings)


def cleanup_for_bindings(
    bindings: Iterable[OrchestrationBinding],
) -> tuple[CleanupSpec, ...]:
    specs: list[CleanupSpec] = []
    seen: set[str] = set()
    for item in bindings:
        if item.producer_case_public_id in seen:
            continue
        if item.producer_method not in CREATE_METHODS:
            continue
        seen.add(item.producer_case_public_id)
        base = normalize_path(item.producer_path)
        specs.append(
            CleanupSpec(
                producer_case_public_id=item.producer_case_public_id,
                variable=item.variable,
                method="DELETE",
                path_template=f"{base}/{item.placeholder}",
            )
        )
    return tuple(specs)


def execution_order(
    case_ids: Iterable[str],
    bindings: Iterable[OrchestrationBinding],
) -> tuple[str, ...]:
    remaining = list(dict.fromkeys(str(item) for item in case_ids if item))
    dependents = {item.consumer_case_public_id for item in bindings}
    producers = [item for item in remaining if item not in dependents]
    consumers = [item for item in remaining if item in dependents]
    return tuple(producers + consumers)


def build_orchestration(
    cases: Iterable[Mapping[str, Any]],
    *,
    cleanup_approved: bool = False,
) -> OrchestrationPlan:
    material = [dict(item) for item in cases]
    bindings = infer_bindings(material)
    order = execution_order((_case_public_id(item) for item in material), bindings)
    cleanup = cleanup_for_bindings(bindings) if cleanup_approved else ()
    return OrchestrationPlan(
        bindings=bindings,
        cleanup=cleanup,
        cleanup_approved=cleanup_approved,
        execution_order=order,
    )


def apply_orchestration_to_snapshot(
    snapshot: Mapping[str, Any],
    plan: OrchestrationPlan,
    case_public_id: str,
) -> dict[str, Any]:
    copied = dict(snapshot)
    payload = {
        "path": copied.get("endpoint_path", ""),
        "headers": copied.get("request_headers") or {},
        "query": copied.get("request_query") or {},
        "body": copied.get("request_body"),
    }
    rewritten = rewrite_bound_placeholders(payload, plan.bindings, case_public_id)
    copied["endpoint_path"] = rewritten["path"]
    copied["request_headers"] = rewritten["headers"]
    copied["request_query"] = rewritten["query"]
    copied["request_body"] = rewritten["body"]
    return copied


def bound_dynamic_placeholders(plan: OrchestrationPlan, case_public_id: str) -> set[str]:
    return {
        item.placeholder
        for item in plan.bindings
        if item.consumer_case_public_id == case_public_id
    }


def plan_blockers(
    payload: Any,
    plan: OrchestrationPlan,
    case_public_id: str,
) -> tuple[str, ...]:
    allowed = bound_dynamic_placeholders(plan, case_public_id)
    blockers = []
    for marker in approval_blockers(payload):
        parsed = parse_placeholder(marker)
        if parsed is not None and parsed.kind is PlaceholderKind.DYNAMIC and marker in allowed:
            continue
        blockers.append(marker)
    return tuple(blockers)


def orchestration_from_json(payload: Any) -> OrchestrationPlan:
    if not isinstance(payload, Mapping):
        return OrchestrationPlan()
    bindings = tuple(
        OrchestrationBinding(
            str(item.get("variable", "")),
            str(item.get("producer_case_public_id", "")),
            str(item.get("consumer_case_public_id", "")),
            str(item.get("extraction", default_extraction())),
            str(item.get("placeholder", "")),
            str(item.get("producer_path", "")),
            str(item.get("producer_method", "")),
        )
        for item in payload.get("bindings") or ()
        if isinstance(item, Mapping)
    )
    cleanup = tuple(
        CleanupSpec(
            str(item.get("producer_case_public_id", "")),
            str(item.get("variable", "")),
            str(item.get("method", "DELETE")),
            str(item.get("path_template", "")),
            bool(item.get("requires_approval", True)),
            bool(item.get("same_run_only", True)),
        )
        for item in payload.get("cleanup") or ()
        if isinstance(item, Mapping)
    )
    order = tuple(str(item) for item in payload.get("execution_order") or ())
    return OrchestrationPlan(
        bindings=bindings,
        cleanup=cleanup,
        cleanup_approved=bool(payload.get("cleanup_approved")),
        execution_order=order,
        version=str(payload.get("version") or ORCHESTRATION_VERSION),
    )
