"""Compare legacy scanner output with adapter contracts without deleting either.

Live discovery still runs `discover_source`. This module converts adapter
routes into the existing inventory shape and selects adapter rows only when
the comparison key matches or the adapter found a route the scanner missed.
Legacy-only routes (Express, Django, and similar) are preserved.
"""

from __future__ import annotations

import json
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

from app.smart_data.adapters.defaults import default_registry
from app.smart_data.contracts import (
    AuthenticationMode,
    DetectionResult,
    ProjectRef,
    RouteContract,
    TestDataSource,
)
from app.smart_data.generator import generate_field
from app.smart_data.serialization import evidence_to_json, field_to_json


_PARAM_BRACES = re.compile(r"\{([A-Za-z_][\w]*)[^}]*\}")
_PARAM_ANGLE = re.compile(r"<[^:>]*:([^>]+)>")
_PARAM_COLON = re.compile(r":([A-Za-z_][\w]*)")


def normalize_path(value: str) -> str:
    value = (value or "").strip().replace("\\", "/")
    value = re.sub(r"/+", "/", value)
    if not value:
        return "/"
    if not value.startswith("/"):
        value = "/" + value
    if len(value) > 1 and value.endswith("/"):
        value = value[:-1]
    return value


def canonical_path(value: str) -> str:
    path = normalize_path(value)
    path = _PARAM_BRACES.sub(r"{\1}", path)
    path = _PARAM_ANGLE.sub(r"{\1}", path)
    path = _PARAM_COLON.sub(r"{\1}", path)
    return path


def comparison_key(method: str, path: str) -> tuple[str, str]:
    return method.upper().strip(), canonical_path(path)


def confidence_label(score: int) -> str:
    if score >= 90:
        return "high"
    if score >= 65:
        return "medium"
    return "low"


def _auth_label(route: RouteContract) -> str:
    if not route.authentication:
        return "Unknown"
    labels: list[str] = []
    required = False
    for flow in route.authentication:
        required = required or flow.required
        for mode in flow.modes:
            if mode is AuthenticationMode.PUBLIC:
                labels.append("Public")
            elif mode is AuthenticationMode.OPTIONAL:
                labels.append("Optional")
            elif mode is AuthenticationMode.UNKNOWN:
                labels.append("Unknown")
            else:
                labels.append(mode.value.replace("-", " ").title())
    unique = list(dict.fromkeys(labels))
    if unique == ["Public"] or (not required and unique == ["Optional"]):
        return "Public"
    if unique == ["Unknown"]:
        return "Unknown"
    return ", ".join(item for item in unique if item not in {"Public", "Unknown"}) or "Protected"


def _primary_evidence(route: RouteContract) -> tuple[str, int | None]:
    if route.evidence:
        first = route.evidence[0]
        return first.source_file, first.source_line
    for schema in route.request_schemas:
        if schema.evidence:
            return schema.evidence[0].source_file, schema.evidence[0].source_line
    return "", None


def _field_payload(field) -> dict[str, Any]:
    generated = generate_field(field)
    payload = field_to_json(field)
    payload["generated_value"] = generated.value
    payload["generation_strategy"] = generated.strategy
    payload["generation_reason"] = generated.reason
    payload["generation_status"] = generated.status
    payload["confidence_score"] = max(int(payload.get("confidence_score") or 0), generated.confidence_score)
    payload["editable"] = generated.editable
    payload["type"] = payload.get("data_type") or "unknown"
    return payload


def inventory_item_from_route(route: RouteContract) -> dict[str, Any]:
    source_file, source_line = _primary_evidence(route)
    request_schema = route.request_schemas[0] if route.request_schemas else None
    fields = []
    content_type = ""
    if request_schema is not None:
        content_type = request_schema.content_type
        fields = [_field_payload(item) for item in request_schema.fields]
    score = int(route.confidence_score or 0)
    if score < 70:
        score = 88 if route.framework else 70
    warnings = list(route.warnings)
    return {
        "public_id": str(uuid.uuid4()),
        "http_method": route.method.upper().strip(),
        "endpoint_path": normalize_path(route.path),
        "original_endpoint_path": normalize_path(route.path),
        "framework": route.framework,
        "source_file": source_file,
        "source_line": source_line,
        "operation_id": route.operation_id,
        "summary": route.summary,
        "authentication": _auth_label(route),
        "request_schema": json.dumps(
            {
                "adapter": route.framework,
                "operation_id": route.operation_id,
                "schemas": [schema.name for schema in route.request_schemas],
            },
            ensure_ascii=False,
        ),
        "response_codes": ", ".join(route.response_schemas.keys()),
        "confidence": confidence_label(score),
        "confidence_score": score,
        "is_duplicate": False,
        "warnings": warnings,
        "route_prefix": "",
        "input_evidence": json.dumps(
            {
                "source": "adapter",
                "adapter": route.framework,
                "authentication": [
                    {
                        "name": flow.name,
                        "modes": [mode.value for mode in flow.modes],
                        "required": flow.required,
                    }
                    for flow in route.authentication
                ],
                "prerequisites": [
                    {
                        "resource": item.resource,
                        "field": item.field,
                        "required": item.required,
                        "placeholder": item.placeholder,
                        "reason": item.reason,
                    }
                    for item in route.prerequisites
                ],
                "setup_actions": [
                    {
                        "name": item.name,
                        "kind": item.kind.value,
                        "route_reference": item.route_reference,
                        "requires_approval": item.requires_approval,
                        "same_run_only": item.same_run_only,
                    }
                    for item in route.setup_actions
                ],
                "cleanup_actions": [
                    {
                        "name": item.name,
                        "kind": item.kind.value,
                        "route_reference": item.route_reference,
                        "requires_approval": item.requires_approval,
                        "same_run_only": item.same_run_only,
                    }
                    for item in route.cleanup_actions
                ],
                "evidence": evidence_to_json(route.evidence),
            },
            ensure_ascii=False,
        ),
        "smart_data_schema": json.dumps(
            {
                "content_type": content_type,
                "fields": fields,
                "responses": {
                    str(status): {
                        "name": schema.name,
                        "content_type": schema.content_type,
                        "fields": [
                            {
                                "name": item.name,
                                "data_type": item.data_type,
                                "required": item.required,
                                "semantic_type": item.semantic_type.value,
                            }
                            for item in schema.fields
                        ],
                    }
                    for status, schema in (route.response_schemas or {}).items()
                },
                "source": "adapter",
                "adapter": route.framework,
            },
            ensure_ascii=False,
        ),
        "discovery_source": "adapter",
    }


@dataclass(frozen=True, slots=True)
class ComparisonReport:
    agreed: int = 0
    adapter_selected: int = 0
    adapter_only: int = 0
    legacy_only: int = 0
    detections: tuple[DetectionResult, ...] = ()

    def summary(self) -> str:
        return (
            f"adapter compare agreed={self.agreed} "
            f"adapter-selected={self.adapter_selected} "
            f"adapter-only={self.adapter_only} "
            f"legacy-only={self.legacy_only}"
        )


@dataclass(slots=True)
class AdapterCollection:
    routes: list[RouteContract] = field(default_factory=list)
    fixtures: list[TestDataSource] = field(default_factory=list)
    detections: list[DetectionResult] = field(default_factory=list)


def collect_adapter_contracts(project: ProjectRef) -> AdapterCollection:
    registry = default_registry()
    collected = AdapterCollection()
    seen: dict[tuple[str, str], RouteContract] = {}
    for adapter in registry.all():
        detection = adapter.detect(project)
        collected.detections.append(detection)
        if not detection.detected:
            continue
        collected.fixtures.extend(adapter.extract_fixtures(project))
        for route in adapter.discover_routes(project):
            key = comparison_key(route.method, route.path)
            current = seen.get(key)
            if current is None or _route_richness(route) > _route_richness(current):
                seen[key] = route
    collected.routes = list(seen.values())
    return collected


def _route_richness(route: RouteContract) -> tuple[int, int, int]:
    fields = sum(len(schema.fields) for schema in route.request_schemas)
    return fields, int(route.confidence_score or 0), len(route.evidence)


def annotate_duplicates(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    endpoints = list(items)
    counts = Counter((item["http_method"], item["endpoint_path"]) for item in endpoints)
    for item in endpoints:
        key = (item["http_method"], item["endpoint_path"])
        if counts[key] > 1:
            item["is_duplicate"] = True
            warning = "Duplicate method and endpoint path"
            if warning not in item["warnings"]:
                item["warnings"].append(warning)
    return endpoints


def merge_legacy_and_adapter(
    legacy_items: Iterable[dict[str, Any]],
    adapter_items: Iterable[dict[str, Any]],
    detections: Iterable[DetectionResult] = (),
) -> tuple[list[dict[str, Any]], ComparisonReport]:
    legacy_map: dict[tuple[str, str], dict[str, Any]] = {}
    for item in legacy_items:
        key = comparison_key(item["http_method"], item["endpoint_path"])
        copied = dict(item)
        copied["warnings"] = list(item.get("warnings") or [])
        copied.setdefault("discovery_source", "legacy")
        legacy_map[key] = copied

    adapter_map: dict[tuple[str, str], dict[str, Any]] = {}
    for item in adapter_items:
        key = comparison_key(item["http_method"], item["endpoint_path"])
        copied = dict(item)
        copied["warnings"] = list(item.get("warnings") or [])
        adapter_map[key] = copied

    selected: list[dict[str, Any]] = []
    agreed = adapter_selected = adapter_only = legacy_only = 0
    for key in sorted(set(legacy_map) | set(adapter_map)):
        adapter_item = adapter_map.get(key)
        legacy_item = legacy_map.get(key)
        if adapter_item is not None and legacy_item is not None:
            agreed += 1
            adapter_selected += 1
            adapter_item["warnings"].append(
                "Adapter output selected after comparing with the legacy scanner."
            )
            selected.append(adapter_item)
        elif adapter_item is not None:
            adapter_only += 1
            adapter_item["warnings"].append(
                "Route discovered by a framework adapter and not by the legacy scanner."
            )
            selected.append(adapter_item)
        else:
            legacy_only += 1
            selected.append(legacy_item)

    report = ComparisonReport(
        agreed=agreed,
        adapter_selected=adapter_selected,
        adapter_only=adapter_only,
        legacy_only=legacy_only,
        detections=tuple(detections),
    )
    return annotate_duplicates(selected), report
