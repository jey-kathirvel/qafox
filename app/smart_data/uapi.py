"""QAFox Universal API Contract V2.

Framework-neutral representation consumed by discovery, smart data, workflow
generation, assertions, execution, and reporting. Adapters keep emitting
legacy RouteContract values; this module is the normalization boundary.

Version: qafox.uapi.contract/v2
Only REST operations are produced by current adapters.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

from app.smart_data.contracts import (
    AuthenticationMode,
    AuthFlowContract,
    DetectionResult,
    FieldContract,
    PrerequisiteContract,
    ProjectRef,
    RouteContract,
    RuntimeVariableContract,
    SchemaContract,
    SourceEvidence,
    TestDataSource,
)
from app.smart_data.serialization import (
    UnsafeSecretError,
    evidence_from_json,
    evidence_to_json,
    field_from_json,
    field_to_json,
    schema_from_json,
    schema_to_json,
)

UAPI_CONTRACT_VERSION = "qafox.uapi.contract/v2"
Evidence = SourceEvidence

_PATH_PARAM_RE = re.compile(
    r"\{([A-Za-z_][\w]*)[^}]*\}|<[^:>]*:([^>]+)>|:([A-Za-z_][\w]*)"
)
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
_DESTRUCTIVE_METHODS = frozenset({"DELETE"})
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_FRAMEWORK_ADAPTER_NAMES = {
    "openapi": "openapi",
    "postman": "postman",
    "fastapi": "fastapi",
    "flask": "flask",
    "express.js": "express",
    "express": "express",
    "nestjs": "nestjs",
    "django": "django",
    "spring": "spring",
    "laravel": "laravel",
    "asp.net": "aspnet",
    "aspnet": "aspnet",
}
_SOURCE_TYPES = {
    "openapi": "definition",
    "postman": "collection",
}


class ProtocolKind(str, Enum):
    REST = "REST"
    GRAPHQL = "GRAPHQL"
    GRPC = "GRPC"
    SOAP = "SOAP"
    WEBSOCKET = "WEBSOCKET"
    ASYNCAPI = "ASYNCAPI"
    UNKNOWN = "UNKNOWN"


class ParameterLocation(str, Enum):
    PATH = "PATH"
    QUERY = "QUERY"
    HEADER = "HEADER"
    COOKIE = "COOKIE"
    BODY = "BODY"
    FORM = "FORM"
    MULTIPART = "MULTIPART"
    GRAPHQL_VARIABLE = "GRAPHQL_VARIABLE"
    GRPC_METADATA = "GRPC_METADATA"
    SOAP_HEADER = "SOAP_HEADER"
    MESSAGE = "MESSAGE"
    UNKNOWN = "UNKNOWN"


class AdapterCapability(str, Enum):
    ROUTES = "ROUTES"
    REQUEST_SCHEMA = "REQUEST_SCHEMA"
    RESPONSE_SCHEMA = "RESPONSE_SCHEMA"
    VALIDATION = "VALIDATION"
    AUTHENTICATION = "AUTHENTICATION"
    DEPENDENCIES = "DEPENDENCIES"
    FIXTURES = "FIXTURES"
    PREFIX_COMPOSITION = "PREFIX_COMPOSITION"
    MODEL_RELATIONSHIPS = "MODEL_RELATIONSHIPS"
    SECURITY_HINTS = "SECURITY_HINTS"


def _enum_parse(enum_cls: type[Enum], value: Any, default: Enum) -> Enum:
    if isinstance(value, enum_cls):
        return value
    raw = str(value or "").strip()
    if not raw:
        return default
    try:
        return enum_cls(raw)
    except ValueError:
        try:
            return enum_cls[raw.upper().replace("-", "_").replace(" ", "_")]
        except KeyError:
            return default


def _enum_value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def classify_http_safety(method: str) -> tuple[bool, bool, bool]:
    token = str(method or "").upper().strip()
    safe_read_only = token in _SAFE_METHODS
    destructive = token in _DESTRUCTIVE_METHODS
    state_changing = token in _STATE_CHANGING_METHODS or (bool(token) and not safe_read_only)
    return safe_read_only, state_changing, destructive


def adapter_name_for_framework(framework: str) -> str:
    return _FRAMEWORK_ADAPTER_NAMES.get(str(framework or "").strip().lower(), str(framework or "").strip().lower())


def source_type_for_adapter(adapter_name: str) -> str:
    return _SOURCE_TYPES.get(adapter_name, "source")


def path_parameter_names(path: str) -> tuple[str, ...]:
    names: list[str] = []
    seen: set[str] = set()
    for brace, angle, colon in _PATH_PARAM_RE.findall(path or ""):
        name = brace or angle or colon
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return tuple(names)


def _source_location(evidence: tuple[SourceEvidence, ...], explicit: str = "") -> str:
    if explicit:
        return explicit
    if not evidence:
        return ""
    first = evidence[0]
    if first.source_line is not None:
        return f"{first.source_file}:{first.source_line}"
    return first.source_file


@dataclass(frozen=True, slots=True)
class AuthenticationContract:
    name: str
    modes: tuple[AuthenticationMode, ...] = ()
    required: bool = False
    configuration_reference: str = ""
    steps: tuple[str, ...] = ()
    confidence: int = 0
    evidence: tuple[SourceEvidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "modes": [_enum_value(mode) for mode in self.modes],
            "required": self.required,
            "configuration_reference": self.configuration_reference,
            "steps": list(self.steps),
            "confidence": self.confidence,
            "evidence": evidence_to_json(self.evidence),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any] | None) -> AuthenticationContract:
        item = payload or {}
        return cls(
            name=str(item.get("name", "")),
            modes=tuple(
                _enum_parse(AuthenticationMode, mode, AuthenticationMode.UNKNOWN)
                for mode in item.get("modes") or ()
            ),
            required=bool(item.get("required")),
            configuration_reference=str(item.get("configuration_reference", "")),
            steps=tuple(str(step) for step in item.get("steps") or ()),
            confidence=int(item.get("confidence") or item.get("confidence_score") or 0),
            evidence=evidence_from_json(item.get("evidence")),
        )

    @classmethod
    def from_auth_flow(cls, flow: AuthFlowContract) -> AuthenticationContract:
        return cls(
            name=flow.name,
            modes=flow.modes,
            required=flow.required,
            configuration_reference=flow.configuration_reference,
            steps=flow.steps,
            confidence=flow.confidence_score,
            evidence=flow.evidence,
        )


@dataclass(frozen=True, slots=True)
class SecurityRequirement:
    name: str
    scopes: tuple[str, ...] = ()
    required: bool = True
    scheme: str = ""
    confidence: int = 0
    evidence: tuple[SourceEvidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "scopes": list(self.scopes),
            "required": self.required,
            "scheme": self.scheme,
            "confidence": self.confidence,
            "evidence": evidence_to_json(self.evidence),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any] | None) -> SecurityRequirement:
        item = payload or {}
        return cls(
            name=str(item.get("name", "")),
            scopes=tuple(str(scope) for scope in item.get("scopes") or ()),
            required=bool(item.get("required", True)),
            scheme=str(item.get("scheme", "")),
            confidence=int(item.get("confidence") or 0),
            evidence=evidence_from_json(item.get("evidence")),
        )


@dataclass(frozen=True, slots=True)
class DependencyContract:
    resource: str
    field: str
    relationship: str = "requires"
    confidence: int = 0
    evidence: tuple[SourceEvidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "field": self.field,
            "relationship": self.relationship,
            "confidence": self.confidence,
            "evidence": evidence_to_json(self.evidence),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any] | None) -> DependencyContract:
        item = payload or {}
        return cls(
            resource=str(item.get("resource", "")),
            field=str(item.get("field", "")),
            relationship=str(item.get("relationship", "requires")),
            confidence=int(item.get("confidence") or item.get("confidence_score") or 0),
            evidence=evidence_from_json(item.get("evidence")),
        )


@dataclass(frozen=True, slots=True)
class RuntimeBindingContract:
    name: str
    source_step: str
    extraction: str
    target_type: str = "string"
    secret: bool = False
    confidence: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source_step": self.source_step,
            "extraction": self.extraction,
            "target_type": self.target_type,
            "secret": self.secret,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any] | None) -> RuntimeBindingContract:
        item = payload or {}
        secret = bool(item.get("secret"))
        name = str(item.get("name", ""))
        extraction = str(item.get("extraction", ""))
        if secret and extraction and "{{SECRET_REF:" not in extraction:
            raise UnsafeSecretError("Secret runtime bindings must not expose plaintext values")
        return cls(
            name=name,
            source_step=str(item.get("source_step", "")),
            extraction=extraction,
            target_type=str(item.get("target_type", "string")),
            secret=secret,
            confidence=int(item.get("confidence") or item.get("confidence_score") or 0),
        )


@dataclass(frozen=True, slots=True)
class AssertionContract:
    assertion_id: str
    kind: str
    expected: Any = None
    path: str = ""
    description: str = ""
    confidence: int = 0
    evidence: tuple[SourceEvidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "assertion_id": self.assertion_id,
            "kind": self.kind,
            "expected": self.expected,
            "path": self.path,
            "description": self.description,
            "confidence": self.confidence,
            "evidence": evidence_to_json(self.evidence),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any] | None) -> AssertionContract:
        item = payload or {}
        return cls(
            assertion_id=str(item.get("assertion_id") or item.get("id") or ""),
            kind=str(item.get("kind", "")),
            expected=item.get("expected"),
            path=str(item.get("path", "")),
            description=str(item.get("description", "")),
            confidence=int(item.get("confidence") or 0),
            evidence=evidence_from_json(item.get("evidence")),
        )


@dataclass(frozen=True, slots=True)
class ParameterContract:
    name: str
    location: ParameterLocation = ParameterLocation.UNKNOWN
    field: FieldContract | None = None
    required: bool = False
    description: str = ""
    confidence: int = 0
    evidence: tuple[SourceEvidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "location": _enum_value(self.location),
            "field": None if self.field is None else field_to_json(self.field),
            "required": self.required,
            "description": self.description,
            "confidence": self.confidence,
            "evidence": evidence_to_json(self.evidence),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any] | None) -> ParameterContract:
        item = payload or {}
        field_payload = item.get("field")
        return cls(
            name=str(item.get("name", "")),
            location=_enum_parse(ParameterLocation, item.get("location"), ParameterLocation.UNKNOWN),
            field=None if not isinstance(field_payload, Mapping) else field_from_json(field_payload),
            required=bool(item.get("required")),
            description=str(item.get("description", "")),
            confidence=int(item.get("confidence") or 0),
            evidence=evidence_from_json(item.get("evidence")),
        )


@dataclass(frozen=True, slots=True)
class RequestContract:
    content_type: str = ""
    required: bool = False
    fields: tuple[FieldContract, ...] = ()
    parameters: tuple[ParameterContract, ...] = ()
    schema_name: str = ""
    confidence: int = 0
    evidence: tuple[SourceEvidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "content_type": self.content_type,
            "required": self.required,
            "fields": [field_to_json(item) for item in self.fields],
            "parameters": [item.to_dict() for item in self.parameters],
            "schema_name": self.schema_name,
            "confidence": self.confidence,
            "evidence": evidence_to_json(self.evidence),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any] | None) -> RequestContract | None:
        if not payload:
            return None
        return cls(
            content_type=str(payload.get("content_type", "")),
            required=bool(payload.get("required")),
            fields=tuple(field_from_json(item) for item in payload.get("fields") or ()),
            parameters=tuple(
                ParameterContract.from_dict(item) for item in payload.get("parameters") or ()
            ),
            schema_name=str(payload.get("schema_name", "")),
            confidence=int(payload.get("confidence") or 0),
            evidence=evidence_from_json(payload.get("evidence")),
        )


@dataclass(frozen=True, slots=True)
class ResponseContract:
    status: str
    content_type: str = ""
    fields: tuple[FieldContract, ...] = ()
    schema_name: str = ""
    description: str = ""
    confidence: int = 0
    evidence: tuple[SourceEvidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "content_type": self.content_type,
            "fields": [field_to_json(item) for item in self.fields],
            "schema_name": self.schema_name,
            "description": self.description,
            "confidence": self.confidence,
            "evidence": evidence_to_json(self.evidence),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any] | None) -> ResponseContract:
        item = payload or {}
        return cls(
            status=str(item.get("status", "")),
            content_type=str(item.get("content_type", "")),
            fields=tuple(field_from_json(field) for field in item.get("fields") or ()),
            schema_name=str(item.get("schema_name", "")),
            description=str(item.get("description", "")),
            confidence=int(item.get("confidence") or 0),
            evidence=evidence_from_json(item.get("evidence")),
        )


@dataclass(frozen=True, slots=True)
class OperationContract:
    operation_id: str
    protocol: ProtocolKind = ProtocolKind.REST
    method: str = ""
    path: str = ""
    summary: str = ""
    description: str = ""
    tags: tuple[str, ...] = ()
    parameters: tuple[ParameterContract, ...] = ()
    request: RequestContract | None = None
    responses: tuple[ResponseContract, ...] = ()
    authentication: tuple[AuthenticationContract, ...] = ()
    security_requirements: tuple[SecurityRequirement, ...] = ()
    dependencies: tuple[DependencyContract, ...] = ()
    runtime_bindings: tuple[RuntimeBindingContract, ...] = ()
    assertions: tuple[AssertionContract, ...] = ()
    safe_read_only: bool = False
    state_changing: bool = False
    destructive: bool = False
    confidence: int = 0
    evidence: tuple[SourceEvidence, ...] = ()
    source_location: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "protocol": _enum_value(self.protocol),
            "method": self.method,
            "path": self.path,
            "summary": self.summary,
            "description": self.description,
            "tags": list(self.tags),
            "parameters": [item.to_dict() for item in self.parameters],
            "request": None if self.request is None else self.request.to_dict(),
            "responses": [item.to_dict() for item in self.responses],
            "authentication": [item.to_dict() for item in self.authentication],
            "security_requirements": [item.to_dict() for item in self.security_requirements],
            "dependencies": [item.to_dict() for item in self.dependencies],
            "runtime_bindings": [item.to_dict() for item in self.runtime_bindings],
            "assertions": [item.to_dict() for item in self.assertions],
            "safe_read_only": self.safe_read_only,
            "state_changing": self.state_changing,
            "destructive": self.destructive,
            "confidence": self.confidence,
            "evidence": evidence_to_json(self.evidence),
            "source_location": self.source_location,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any] | None) -> OperationContract:
        item = payload or {}
        protocol = _enum_parse(ProtocolKind, item.get("protocol"), ProtocolKind.UNKNOWN)
        method = str(item.get("method", "")).upper()
        safe_read_only, state_changing, destructive = classify_http_safety(method)
        return cls(
            operation_id=str(item.get("operation_id", "")),
            protocol=protocol,
            method=method,
            path=str(item.get("path", "")),
            summary=str(item.get("summary", "")),
            description=str(item.get("description", "")),
            tags=tuple(str(tag) for tag in item.get("tags") or ()),
            parameters=tuple(
                ParameterContract.from_dict(param) for param in item.get("parameters") or ()
            ),
            request=RequestContract.from_dict(item.get("request")),
            responses=tuple(
                ResponseContract.from_dict(response) for response in item.get("responses") or ()
            ),
            authentication=tuple(
                AuthenticationContract.from_dict(auth) for auth in item.get("authentication") or ()
            ),
            security_requirements=tuple(
                SecurityRequirement.from_dict(req)
                for req in item.get("security_requirements") or ()
            ),
            dependencies=tuple(
                DependencyContract.from_dict(dep) for dep in item.get("dependencies") or ()
            ),
            runtime_bindings=tuple(
                RuntimeBindingContract.from_dict(bind)
                for bind in item.get("runtime_bindings") or ()
            ),
            assertions=tuple(
                AssertionContract.from_dict(assertion)
                for assertion in item.get("assertions") or ()
            ),
            safe_read_only=bool(item.get("safe_read_only", safe_read_only)),
            state_changing=bool(item.get("state_changing", state_changing)),
            destructive=bool(item.get("destructive", destructive)),
            confidence=int(item.get("confidence") or item.get("confidence_score") or 0),
            evidence=evidence_from_json(item.get("evidence")),
            source_location=str(item.get("source_location", "")),
        )


@dataclass(frozen=True, slots=True)
class ApiContract:
    contract_version: str = UAPI_CONTRACT_VERSION
    source_type: str = "unknown"
    source_framework: str = ""
    source_protocol: ProtocolKind = ProtocolKind.REST
    title: str = ""
    description: str = ""
    base_paths: tuple[str, ...] = ()
    operations: tuple[OperationContract, ...] = ()
    authentication: tuple[AuthenticationContract, ...] = ()
    schemas: tuple[SchemaContract, ...] = ()
    evidence: tuple[SourceEvidence, ...] = ()
    confidence: int = 0
    adapter_name: str = ""
    adapter_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "contract_version": self.contract_version,
            "source_type": self.source_type,
            "source_framework": self.source_framework,
            "source_protocol": _enum_value(self.source_protocol),
            "title": self.title,
            "description": self.description,
            "base_paths": list(self.base_paths),
            "operations": [item.to_dict() for item in self.operations],
            "authentication": [item.to_dict() for item in self.authentication],
            "schemas": [schema_to_json(item) for item in self.schemas],
            "evidence": evidence_to_json(self.evidence),
            "confidence": self.confidence,
            "adapter_name": self.adapter_name,
            "adapter_version": self.adapter_version,
        }
        return json.loads(json.dumps(payload, ensure_ascii=False, default=str))

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any] | None) -> ApiContract:
        item = payload or {}
        version = str(item.get("contract_version") or "")
        if version and version != UAPI_CONTRACT_VERSION:
            raise ValueError(f"Unsupported universal API contract version: {version}")
        return cls(
            contract_version=UAPI_CONTRACT_VERSION,
            source_type=str(item.get("source_type", "unknown")),
            source_framework=str(item.get("source_framework", "")),
            source_protocol=_enum_parse(
                ProtocolKind, item.get("source_protocol"), ProtocolKind.UNKNOWN
            ),
            title=str(item.get("title", "")),
            description=str(item.get("description", "")),
            base_paths=tuple(str(path) for path in item.get("base_paths") or ()),
            operations=tuple(
                OperationContract.from_dict(operation)
                for operation in item.get("operations") or ()
            ),
            authentication=tuple(
                AuthenticationContract.from_dict(auth) for auth in item.get("authentication") or ()
            ),
            schemas=tuple(schema_from_json(schema) for schema in item.get("schemas") or ()),
            evidence=evidence_from_json(item.get("evidence")),
            confidence=int(item.get("confidence") or 0),
            adapter_name=str(item.get("adapter_name", "")),
            adapter_version=str(item.get("adapter_version", "")),
        )


def _parameter_location_for_schema(schema: SchemaContract, field_name: str, path: str) -> ParameterLocation:
    name = schema.name.lower()
    content = (schema.content_type or "").lower()
    if "multipart" in content:
        return ParameterLocation.MULTIPART
    if name in {"form-data", "form"} or "x-www-form-urlencoded" in content:
        return ParameterLocation.FORM
    if name in {"request-body", "body"} or "json" in content or "xml" in content:
        return ParameterLocation.BODY
    if field_name in path_parameter_names(path):
        return ParameterLocation.PATH
    if name == "parameters":
        return ParameterLocation.PATH if field_name in path_parameter_names(path) else ParameterLocation.QUERY
    return ParameterLocation.UNKNOWN


def _dependencies_from_fields(
    fields: Iterable[FieldContract],
    extra: Iterable[PrerequisiteContract] = (),
) -> tuple[DependencyContract, ...]:
    found: list[DependencyContract] = []
    seen: set[tuple[str, str, str]] = set()

    def visit(field: FieldContract) -> None:
        if field.dependency is not None:
            key = (
                field.dependency.resource,
                field.dependency.field,
                field.dependency.relationship,
            )
            if key not in seen:
                seen.add(key)
                found.append(
                    DependencyContract(
                        field.dependency.resource,
                        field.dependency.field,
                        field.dependency.relationship,
                        field.dependency.confidence_score,
                        field.evidence,
                    )
                )
        for child in field.children:
            visit(child)
        if field.items is not None:
            visit(field.items)
        for item in (*field.one_of, *field.any_of, *field.all_of):
            visit(item)

    for item in fields:
        visit(item)
    for prerequisite in extra:
        key = (prerequisite.resource, prerequisite.field, "requires")
        if key not in seen:
            seen.add(key)
            found.append(
                DependencyContract(
                    prerequisite.resource,
                    prerequisite.field,
                    "requires",
                    prerequisite.confidence_score,
                    prerequisite.evidence,
                )
            )
    return tuple(found)


def _security_from_auth(flows: Sequence[AuthenticationContract]) -> tuple[SecurityRequirement, ...]:
    requirements: list[SecurityRequirement] = []
    for flow in flows:
        if not flow.required:
            continue
        scheme = flow.modes[0].value if flow.modes else ""
        if scheme in {"public", "unknown", "optional-authentication"}:
            continue
        requirements.append(
            SecurityRequirement(
                name=flow.name,
                required=True,
                scheme=scheme,
                confidence=flow.confidence,
                evidence=flow.evidence,
            )
        )
    return tuple(requirements)


def operation_from_route(route: RouteContract) -> OperationContract:
    method = str(route.method or "").upper()
    protocol = ProtocolKind.REST if method else ProtocolKind.UNKNOWN
    safe_read_only, state_changing, destructive = classify_http_safety(method)
    parameters: list[ParameterContract] = []
    body_fields: list[FieldContract] = []
    request_schema: SchemaContract | None = None
    seen_params: set[tuple[str, str]] = set()

    for schema in route.request_schemas:
        is_parameter_bag = schema.name.lower() == "parameters"
        if not is_parameter_bag:
            if request_schema is None:
                request_schema = schema
            body_fields.extend(schema.fields)
        for field in schema.fields:
            location = _parameter_location_for_schema(schema, field.name, route.path)
            if not is_parameter_bag:
                continue
            key = (field.name, location.value)
            if key in seen_params:
                continue
            seen_params.add(key)
            parameters.append(
                ParameterContract(
                    name=field.name,
                    location=location,
                    field=field,
                    required=field.required,
                    confidence=field.confidence_score or route.confidence_score,
                    evidence=field.evidence or schema.evidence,
                )
            )

    for name in path_parameter_names(route.path):
        key = (name, ParameterLocation.PATH.value)
        if key in seen_params:
            continue
        seen_params.add(key)
        parameters.append(
            ParameterContract(
                name=name,
                location=ParameterLocation.PATH,
                required=True,
                confidence=route.confidence_score,
                evidence=route.evidence,
            )
        )

    request = None
    if request_schema is not None or body_fields:
        schema = request_schema
        request = RequestContract(
            content_type=schema.content_type if schema else "",
            required=bool(schema.required) if schema else False,
            fields=tuple(body_fields),
            parameters=tuple(
                item for item in parameters if item.location in {ParameterLocation.FORM, ParameterLocation.MULTIPART}
            ),
            schema_name=schema.name if schema else "",
            confidence=(schema.confidence_score if schema else route.confidence_score),
            evidence=(schema.evidence if schema else route.evidence),
        )

    responses = tuple(
        ResponseContract(
            status=str(status),
            content_type=schema.content_type,
            fields=schema.fields,
            schema_name=schema.name,
            confidence=schema.confidence_score,
            evidence=schema.evidence,
        )
        for status, schema in dict(route.response_schemas).items()
    )
    authentication = tuple(AuthenticationContract.from_auth_flow(flow) for flow in route.authentication)
    runtime_bindings = tuple(
        RuntimeBindingContract(
            name=item.name,
            source_step=item.source_step,
            extraction=item.extraction,
            target_type=item.target_type,
            secret=item.secret,
            confidence=item.confidence_score,
        )
        for item in route.runtime_variables
    )
    fields_for_deps = [
        *(request.fields if request else ()),
        *(param.field for param in parameters if param.field is not None),
        *(field for response in responses for field in response.fields),
    ]
    operation_id = route.operation_id or f"{method} {route.path}".strip()
    return OperationContract(
        operation_id=operation_id,
        protocol=protocol,
        method=method,
        path=route.path,
        summary=route.summary,
        description=route.summary,
        parameters=tuple(parameters),
        request=request,
        responses=responses,
        authentication=authentication,
        security_requirements=_security_from_auth(authentication),
        dependencies=_dependencies_from_fields(fields_for_deps, route.prerequisites),
        runtime_bindings=runtime_bindings,
        assertions=(),
        safe_read_only=safe_read_only,
        state_changing=state_changing,
        destructive=destructive,
        confidence=route.confidence_score,
        evidence=route.evidence,
        source_location=_source_location(route.evidence),
    )


def route_from_operation(operation: OperationContract, framework: str = "") -> RouteContract:
    """Compatibility mapping back to the legacy route contract."""
    request_schemas: list[SchemaContract] = []
    if operation.parameters:
        path_or_query = tuple(
            (item.field or FieldContract(item.name, required=item.required, path=item.name))
            for item in operation.parameters
            if item.location in {ParameterLocation.PATH, ParameterLocation.QUERY, ParameterLocation.HEADER, ParameterLocation.COOKIE, ParameterLocation.UNKNOWN}
        )
        if path_or_query:
            request_schemas.append(SchemaContract("parameters", "object", path_or_query))
    if operation.request is not None:
        request_schemas.append(
            SchemaContract(
                operation.request.schema_name or "request-body",
                "object",
                operation.request.fields,
                operation.request.content_type,
                operation.request.required,
                operation.request.confidence,
                operation.request.evidence,
            )
        )
    responses = {
        item.status: SchemaContract(
            item.schema_name or f"response-{item.status}",
            "object",
            item.fields,
            item.content_type,
            False,
            item.confidence,
            item.evidence,
        )
        for item in operation.responses
    }
    return RouteContract(
        method=operation.method,
        path=operation.path,
        framework=framework or operation.operation_id,
        operation_id=operation.operation_id,
        summary=operation.summary,
        request_schemas=tuple(request_schemas),
        response_schemas=responses,
        authentication=tuple(
            AuthFlowContract(
                item.name,
                item.modes,
                item.required,
                item.configuration_reference,
                item.steps,
                item.confidence,
                item.evidence,
            )
            for item in operation.authentication
        ),
        prerequisites=tuple(
            PrerequisiteContract(item.resource, item.field, True, "", "", item.confidence, item.evidence)
            for item in operation.dependencies
        ),
        runtime_variables=tuple(
            RuntimeVariableContract(
                item.name,
                item.source_step,
                item.extraction,
                item.target_type,
                item.secret,
                item.confidence,
            )
            for item in operation.runtime_bindings
        ),
        confidence_score=operation.confidence,
        evidence=operation.evidence,
    )


class UniversalContractNormalizer:
    """Adapter discovery evidence → ApiContract."""

    def normalize_route(self, route: RouteContract) -> OperationContract:
        return operation_from_route(route)

    def normalize_routes(
        self,
        routes: Sequence[RouteContract],
        *,
        adapter_name: str,
        adapter_version: str = "",
        source_framework: str = "",
        title: str = "",
        description: str = "",
        schemas: Sequence[SchemaContract] = (),
        evidence: Sequence[SourceEvidence] = (),
        fixtures: Sequence[TestDataSource] = (),
    ) -> ApiContract:
        del fixtures  # fixtures remain adapter evidence; they are not API operations
        operations = tuple(operation_from_route(route) for route in routes)
        adapter = adapter_name_for_framework(adapter_name)
        framework = source_framework or adapter
        auth: list[AuthenticationContract] = []
        seen_auth: set[tuple[str, tuple[str, ...], bool]] = set()
        for operation in operations:
            for flow in operation.authentication:
                key = (flow.name, tuple(mode.value for mode in flow.modes), flow.required)
                if key not in seen_auth:
                    seen_auth.add(key)
                    auth.append(flow)
        confidence = max((item.confidence for item in operations), default=0)
        base_paths = tuple(
            sorted(
                {
                    "/" + part
                    for operation in operations
                    for part in [operation.path.strip("/").split("/")[0]]
                    if part and not part.startswith("{") and ":" not in part and "<" not in part
                }
            )
        )
        return ApiContract(
            contract_version=UAPI_CONTRACT_VERSION,
            source_type=source_type_for_adapter(adapter),
            source_framework=framework,
            source_protocol=ProtocolKind.REST,
            title=title or framework,
            description=description,
            base_paths=base_paths,
            operations=operations,
            authentication=tuple(auth),
            schemas=tuple(schemas),
            evidence=tuple(evidence),
            confidence=confidence,
            adapter_name=adapter,
            adapter_version=adapter_version,
        )

    def normalize_adapter(self, adapter: Any, project: ProjectRef) -> ApiContract:
        detection: DetectionResult = adapter.detect(project)
        routes: list[RouteContract] = []
        schemas: list[SchemaContract] = []
        fixtures: list[TestDataSource] = []
        if detection.detected:
            routes = list(adapter.discover_routes(project))
            schemas = list(adapter.extract_schemas(project))
            fixtures = list(adapter.extract_fixtures(project))
        evidence = detection.evidence
        if not evidence:
            evidence = tuple(item for route in routes for item in route.evidence[:1])
        return self.normalize_routes(
            routes,
            adapter_name=getattr(adapter, "name", ""),
            adapter_version=str(getattr(adapter, "adapter_version", "") or detection.version),
            source_framework=detection.framework or getattr(adapter, "name", ""),
            title=detection.framework or getattr(adapter, "name", ""),
            schemas=schemas,
            evidence=evidence,
            fixtures=fixtures,
        )


def canonical_operation_shape(operation: OperationContract) -> dict[str, Any]:
    from app.smart_data.compatibility import canonical_path

    return {
        "protocol": _enum_value(operation.protocol),
        "method": operation.method.upper(),
        "path": canonical_path(operation.path),
        "parameter_locations": sorted(
            {(item.name, item.location.value) for item in operation.parameters}
        ),
        "has_request_fields": bool(operation.request and operation.request.fields),
        "safe_read_only": operation.safe_read_only,
        "state_changing": operation.state_changing,
        "destructive": operation.destructive,
    }
