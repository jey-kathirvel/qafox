"""Postman Collection adapter with secret-safe variable extraction."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator, Mapping
from typing import Any
from urllib.parse import urlsplit

from app.smart_data.adapters.base import FrameworkAdapter
from app.smart_data.adapters.document_scan import ParsedDocument, iter_documents
from app.smart_data.contracts import (
    AuthenticationMode,
    AuthFlowContract,
    ConstraintContract,
    DetectionResult,
    FieldContract,
    ProjectRef,
    RouteContract,
    SchemaContract,
    SemanticType,
    SourceEvidence,
    TestDataSource,
)
from app.smart_data.placeholders import PlaceholderKind, build_placeholder


SECRET_SIGNAL = re.compile(r"(?:password|passwd|secret|token|api[_-]?key|authorization|credential)", re.IGNORECASE)


def _is_collection(document: Mapping[str, Any]) -> bool:
    info = document.get("info")
    schema = str(info.get("schema", "")) if isinstance(info, dict) else ""
    return isinstance(document.get("item"), list) and ("schema.getpostman.com" in schema or "_postman_id" in (info or {}))


def _evidence(path: str, kind: str = "postman-collection") -> tuple[SourceEvidence, ...]:
    return (SourceEvidence(path, evidence_type=kind, confidence_score=97),)


def _walk(items: list[Any], parent: str = "") -> Iterator[tuple[str, Mapping[str, Any]]]:
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        label = " / ".join(part for part in (parent, name) if part)
        if isinstance(item.get("item"), list):
            yield from _walk(item["item"], label)
        elif isinstance(item.get("request"), dict):
            yield label, item["request"]


def _path(url: Any) -> str:
    if isinstance(url, dict):
        parts = url.get("path")
        if isinstance(parts, list):
            return "/" + "/".join(str(part) for part in parts)
        raw = str(url.get("raw", ""))
    else:
        raw = str(url or "")
    if not raw:
        return "/"
    if "://" in raw:
        return urlsplit(raw).path or "/"
    without_query = raw.split("?", 1)[0]
    match = re.search(r"/(?:[^/].*)?$", without_query)
    return match.group(0) if match else "/"


def _semantic(name: str, value: Any = None) -> SemanticType:
    lowered = name.lower()
    if SECRET_SIGNAL.search(lowered):
        return SemanticType.SECRET
    if "email" in lowered:
        return SemanticType.EMAIL
    if lowered.endswith("_id") or lowered.endswith("id"):
        return SemanticType.FOREIGN_KEY
    if isinstance(value, bool):
        return SemanticType.BOOLEAN
    if isinstance(value, int):
        return SemanticType.INTEGER
    if isinstance(value, float):
        return SemanticType.DECIMAL
    if isinstance(value, list):
        return SemanticType.ARRAY
    if isinstance(value, dict):
        return SemanticType.OBJECT
    return SemanticType.UNKNOWN


def _fields(value: Any, source: str) -> tuple[FieldContract, ...]:
    if not isinstance(value, dict):
        return ()
    fields: list[FieldContract] = []
    for name, item in value.items():
        semantic = _semantic(str(name), item)
        children = _fields(item, source)
        fields.append(
            FieldContract(
                name=str(name),
                semantic_type=semantic,
                data_type=type(item).__name__,
                required=False,
                secret=semantic is SemanticType.SECRET,
                generated_value=(
                    build_placeholder(PlaceholderKind.SECRET_REF, f"configuration.{name}")
                    if semantic is SemanticType.SECRET
                    else None
                ),
                confidence_score=70,
                source_file=source,
                children=children,
                evidence=_evidence(source, "postman-example"),
            )
        )
    return tuple(fields)


def _auth(request: Mapping[str, Any], inherited: Any, source: str) -> AuthFlowContract:
    auth = request.get("auth", inherited)
    if auth is None:
        return AuthFlowContract("postman-auth", (AuthenticationMode.PUBLIC,), False, confidence_score=65, evidence=_evidence(source, "postman-auth"))
    if not isinstance(auth, dict):
        return AuthFlowContract("postman-auth", (AuthenticationMode.UNKNOWN,), False, confidence_score=50, evidence=_evidence(source, "postman-auth"))
    auth_type = str(auth.get("type", "")).lower()
    mode = {
        "noauth": AuthenticationMode.PUBLIC,
        "bearer": AuthenticationMode.BEARER,
        "apikey": AuthenticationMode.API_KEY,
        "basic": AuthenticationMode.BASIC,
        "oauth2": AuthenticationMode.OAUTH2,
        "digest": AuthenticationMode.MULTI_STEP,
    }.get(auth_type, AuthenticationMode.UNKNOWN)
    return AuthFlowContract("postman-auth", (mode,), mode is not AuthenticationMode.PUBLIC, f"configuration.auth.{auth_type}" if mode is not AuthenticationMode.PUBLIC else "", confidence_score=95, evidence=_evidence(source, "postman-auth"))


class PostmanAdapter(FrameworkAdapter):
    name = "postman"

    def _documents(self, project: ProjectRef) -> Iterable[ParsedDocument]:
        return (item for item in iter_documents(project) if _is_collection(item.value))

    def detect(self, project: ProjectRef) -> DetectionResult:
        first = next(iter(self._documents(project)), None)
        if first is None:
            return DetectionResult(self.name, False, 0)
        schema = str(first.value.get("info", {}).get("schema", ""))
        version = schema.rsplit("/", 2)[-2] if "/" in schema else ""
        return DetectionResult(self.name, True, 98, version, _evidence(first.relative_path))

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        routes: list[RouteContract] = []
        for parsed in self._documents(project):
            inherited_auth = parsed.value.get("auth")
            for label, request in _walk(parsed.value.get("item", [])):
                schemas: list[SchemaContract] = []
                body = request.get("body")
                if isinstance(body, dict):
                    mode = str(body.get("mode", ""))
                    content_type = {
                        "raw": "application/json",
                        "urlencoded": "application/x-www-form-urlencoded",
                        "formdata": "multipart/form-data",
                    }.get(mode, "")
                    value: Any = {}
                    if mode == "raw":
                        try:
                            value = json.loads(str(body.get("raw", "")))
                        except ValueError:
                            value = {}
                    elif isinstance(body.get(mode), list):
                        value = {str(entry.get("key", "field")): None for entry in body[mode] if isinstance(entry, dict) and not entry.get("disabled")}
                    if isinstance(value, dict) and value:
                        schemas.append(SchemaContract("request-body", "object", _fields(value, parsed.relative_path), content_type, confidence_score=75, evidence=_evidence(parsed.relative_path, "postman-body")))
                routes.append(
                    RouteContract(
                        method=str(request.get("method", "GET")).upper(),
                        path=_path(request.get("url")),
                        framework="Postman",
                        summary=label,
                        request_schemas=tuple(schemas),
                        authentication=(_auth(request, inherited_auth, parsed.relative_path),),
                        confidence_score=97,
                        evidence=_evidence(parsed.relative_path),
                    )
                )
        return routes

    def extract_schemas(self, project: ProjectRef) -> list[SchemaContract]:
        return [schema for route in self.discover_routes(project) for schema in route.request_schemas]

    def extract_constraints(self, project: ProjectRef) -> list[ConstraintContract]:
        return []

    def extract_auth_flows(self, project: ProjectRef) -> list[AuthFlowContract]:
        return [flow for route in self.discover_routes(project) for flow in route.authentication]

    def extract_fixtures(self, project: ProjectRef) -> list[TestDataSource]:
        fixtures: list[TestDataSource] = []
        for parsed in self._documents(project):
            values: dict[str, Any] = {}
            contains_secrets = False
            for variable in parsed.value.get("variable", []):
                if not isinstance(variable, dict):
                    continue
                key = str(variable.get("key", "")).strip()
                if not key:
                    continue
                secret = bool(SECRET_SIGNAL.search(key)) or str(variable.get("type", "")).lower() == "secret"
                contains_secrets = contains_secrets or secret
                values[key] = build_placeholder(PlaceholderKind.SECRET_REF, f"configuration.{key}") if secret else variable.get("value")
            if values:
                fixtures.append(TestDataSource(str(parsed.value.get("info", {}).get("name", parsed.relative_path)), "postman-variables", values, contains_secrets, 85, _evidence(parsed.relative_path, "postman-variables")))
        return fixtures
