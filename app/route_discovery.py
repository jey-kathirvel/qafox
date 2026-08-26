"""Canonical route discovery boundary shared by UI, persistence, and scanners."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Iterable

from app.smart_data.compatibility import (
    AdapterCollection,
    ComparisonReport,
    canonical_path,
    collect_adapter_contracts,
    comparison_key,
    inventory_item_from_route,
    merge_legacy_and_adapter,
)
from app.smart_data.contracts import (
    AuthFlowContract,
    AuthenticationMode,
    DetectionResult,
    ProjectRef,
    RouteContract,
    SourceEvidence,
    TestDataSource,
)

ALLOWED_METHODS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
)


@dataclass(frozen=True, slots=True)
class RouteDiscoveryReport:
    routes: tuple[RouteContract, ...]
    inventory: tuple[dict[str, Any], ...]
    detections: tuple[DetectionResult, ...]
    fixtures: tuple[TestDataSource, ...]
    comparison: ComparisonReport

    @property
    def adapter_names(self) -> tuple[str, ...]:
        return tuple(
            item.framework for item in self.detections if item.detected
        )


def normalize_route(route: RouteContract) -> RouteContract | None:
    method = str(route.method or "").strip().upper()
    raw_path = str(route.path or "").strip()
    if "://" in raw_path:
        return None
    path = canonical_path(raw_path)
    if method not in ALLOWED_METHODS or not path.startswith("/"):
        return None
    if "\x00" in path or len(path) > 2000 or "://" in path:
        return None
    return replace(
        route,
        method=method,
        path=path,
        framework=str(route.framework or "Generic")[:100],
        operation_id=str(route.operation_id or "")[:300],
        summary=str(route.summary or "")[:1000],
        confidence_score=max(0, min(100, int(route.confidence_score or 0))),
    )


def route_from_inventory(item: dict[str, Any]) -> RouteContract | None:
    method = str(item.get("http_method") or "").upper()
    path = str(item.get("endpoint_path") or "")
    authentication = str(item.get("authentication") or "Unknown").lower()
    mode = AuthenticationMode.PUBLIC if authentication == "public" else AuthenticationMode.UNKNOWN
    required = authentication not in {"", "unknown", "public", "optional"}
    source_file = str(item.get("source_file") or "")
    source_line = item.get("source_line")
    route = RouteContract(
        method,
        path,
        str(item.get("framework") or "Generic"),
        str(item.get("operation_id") or ""),
        str(item.get("summary") or ""),
        authentication=(
            AuthFlowContract(
                "legacy-inventory-auth",
                (mode,),
                required,
                confidence_score=40,
            ),
        ),
        confidence_score=int(item.get("confidence_score") or 40),
        evidence=(
            SourceEvidence(
                source_file,
                source_line=int(source_line) if source_line is not None else None,
                evidence_type="legacy-static-route",
                confidence_score=int(item.get("confidence_score") or 40),
            ),
        ) if source_file else (),
        warnings=tuple(item.get("warnings") or ()),
    )
    return normalize_route(route)


def discover_normalized_routes(
    project: ProjectRef,
    legacy_items: Iterable[dict[str, Any]] = (),
) -> RouteDiscoveryReport:
    collection: AdapterCollection = collect_adapter_contracts(project)
    adapter_routes = tuple(
        route
        for route in (normalize_route(item) for item in collection.routes)
        if route is not None
    )
    adapter_inventory = [inventory_item_from_route(item) for item in adapter_routes]
    selected_inventory, comparison = merge_legacy_and_adapter(
        legacy_items,
        adapter_inventory,
        collection.detections,
    )

    adapter_by_key = {
        comparison_key(route.method, route.path): route for route in adapter_routes
    }
    selected_routes: dict[tuple[str, str], RouteContract] = {}
    for item in selected_inventory:
        key = comparison_key(item["http_method"], item["endpoint_path"])
        route = adapter_by_key.get(key) or route_from_inventory(item)
        if route is not None:
            selected_routes[key] = route

    selected_by_key = {
        comparison_key(item["http_method"], item["endpoint_path"]): item
        for item in selected_inventory
    }
    inventory = tuple(
        {
            **selected_by_key[key],
            "http_method": key[0],
            "endpoint_path": key[1],
        }
        for key in sorted(selected_routes)
    )
    return RouteDiscoveryReport(
        routes=tuple(selected_routes[key] for key in sorted(selected_routes)),
        inventory=inventory,
        detections=tuple(collection.detections),
        fixtures=tuple(collection.fixtures),
        comparison=comparison,
    )
