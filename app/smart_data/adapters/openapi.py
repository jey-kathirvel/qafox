"""OpenAPI/Swagger adapter using parsed documents only."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from app.smart_data.adapters.base import FrameworkAdapter
from app.smart_data.adapters.document_scan import ParsedDocument, iter_documents
from app.smart_data.contracts import (
    AuthenticationMode,
    AuthFlowContract,
    ConstraintContract,
    DetectionResult,
    DependencyRelationship,
    FieldContract,
    ProjectRef,
    RouteContract,
    SchemaContract,
    SemanticType,
    SourceEvidence,
    TestDataSource,
)


HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "trace"})
CONSTRAINT_KEYS = (
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "multipleOf",
    "pattern",
    "format",
    "enum",
)


def _evidence(path: str, kind: str = "definition") -> tuple[SourceEvidence, ...]:
    return (SourceEvidence(path, evidence_type=kind, confidence_score=99),)


def _is_openapi(document: Mapping[str, Any]) -> bool:
    return bool(("openapi" in document or "swagger" in document) and isinstance(document.get("paths"), dict))


def _resolve(document: Mapping[str, Any], value: Any, seen: frozenset[str] = frozenset()) -> Any:
    if not isinstance(value, dict) or "$ref" not in value:
        return value
    reference = value.get("$ref")
    if not isinstance(reference, str) or not reference.startswith("#/") or reference in seen:
        return value
    current: Any = document
    try:
        for token in reference[2:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            current = current[token]
    except (KeyError, TypeError):
        return value
    return _resolve(document, current, seen | {reference})


def _semantic(name: str, schema: Mapping[str, Any]) -> SemanticType:
    schema_type = str(schema.get("type", "")).lower()
    schema_format = str(schema.get("format", "")).lower()
    lowered = name.lower()
    if schema_format == "email":
        return SemanticType.EMAIL
    if schema_format == "uuid":
        return SemanticType.UUID
    if schema_format in {"date", "date-time"}:
        return SemanticType.DATE if schema_format == "date" else SemanticType.DATETIME
    if schema_format in {"uri", "url"}:
        return SemanticType.URL
    if schema_format in {"password", "byte", "binary"}:
        return SemanticType.SECRET if schema_format == "password" else SemanticType.FILE
    if schema.get("enum"):
        return SemanticType.ENUM
    if lowered.endswith("_id") or (lowered.endswith("id") and lowered != "id"):
        return SemanticType.FOREIGN_KEY
    if lowered == "id":
        return SemanticType.IDENTIFIER
    if schema_type == "boolean":
        return SemanticType.BOOLEAN
    if schema_type == "integer":
        return SemanticType.INTEGER
    if schema_type == "number":
        return SemanticType.DECIMAL
    if schema_type == "array":
        return SemanticType.ARRAY
    if schema_type == "object" or schema.get("properties"):
        return SemanticType.OBJECT
    return SemanticType.UNKNOWN


def _field(
    document: Mapping[str, Any],
    name: str,
    schema: Any,
    required: bool,
    source: str,
    depth: int = 0,
) -> FieldContract:
    schema = _resolve(document, schema)
    if not isinstance(schema, dict) or depth > 20:
        schema = {}
    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    required_names = set(schema.get("required", [])) if isinstance(schema.get("required"), list) else set()
    children = tuple(
        _field(document, str(child_name), child_schema, child_name in required_names, source, depth + 1)
        for child_name, child_schema in properties.items()
    )
    items = schema.get("items")
    if items and not children:
        children = (_field(document, "item", items, True, source, depth + 1),)
    semantic = _semantic(name, schema)
    dependency = None
    if semantic is SemanticType.FOREIGN_KEY:
        dependency = DependencyRelationship(name.removesuffix("_id"), "id", confidence_score=70)
    constraints = tuple(
        ConstraintContract(key, schema[key], confidence_score=99, evidence=_evidence(source, "schema-constraint"))
        for key in CONSTRAINT_KEYS
        if key in schema
    )
    return FieldContract(
        name=name,
        semantic_type=semantic,
        data_type=str(schema.get("type", "object" if properties else "unknown")),
        required=required,
        default_value=schema.get("default"),
        minimum=schema.get("minimum"),
        maximum=schema.get("maximum"),
        min_length=schema.get("minLength"),
        max_length=schema.get("maxLength"),
        pattern=str(schema.get("pattern", "")),
        format=str(schema.get("format", "")),
        enum_values=tuple(schema.get("enum", ())) if isinstance(schema.get("enum"), list) else (),
        nullable=bool(schema.get("nullable", False)) or "null" in schema.get("type", []) if isinstance(schema.get("type"), list) else bool(schema.get("nullable", False)),
        secret=semantic in {SemanticType.SECRET, SemanticType.CREDENTIAL, SemanticType.TOKEN},
        dependency=dependency,
        confidence_score=99,
        source_file=source,
        constraints=constraints,
        children=children,
        evidence=_evidence(source, "schema-field"),
    )


def _schema_contract(document: Mapping[str, Any], name: str, schema: Any, source: str, content_type: str = "", required: bool = False) -> SchemaContract:
    schema = _resolve(document, schema)
    if not isinstance(schema, dict):
        schema = {}
    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    required_names = set(schema.get("required", [])) if isinstance(schema.get("required"), list) else set()
    fields = tuple(_field(document, str(key), value, key in required_names, source) for key, value in properties.items())
    if not fields and schema:
        fields = (_field(document, name or "value", schema, required, source),)
    return SchemaContract(
        name=name,
        schema_type=str(schema.get("type", "object" if properties else "unknown")),
        fields=fields,
        content_type=content_type,
        required=required,
        confidence_score=99,
        evidence=_evidence(source, "schema"),
    )


def _security_modes(document: Mapping[str, Any], security: Any) -> tuple[AuthenticationMode, ...]:
    schemes = document.get("components", {}).get("securitySchemes", {}) if isinstance(document.get("components"), dict) else {}
    if not schemes and isinstance(document.get("securityDefinitions"), dict):
        schemes = document["securityDefinitions"]
    modes: list[AuthenticationMode] = []
    for requirement in security if isinstance(security, list) else []:
        for name in requirement if isinstance(requirement, dict) else {}:
            definition = _resolve(document, schemes.get(name, {})) if isinstance(schemes, dict) else {}
            kind = str(definition.get("type", "")).lower() if isinstance(definition, dict) else ""
            scheme = str(definition.get("scheme", "")).lower() if isinstance(definition, dict) else ""
            mode = {
                "apikey": AuthenticationMode.API_KEY,
                "oauth2": AuthenticationMode.OAUTH2,
                "openidconnect": AuthenticationMode.OAUTH2,
            }.get(kind)
            if kind == "http":
                mode = AuthenticationMode.BEARER if scheme == "bearer" else AuthenticationMode.BASIC if scheme == "basic" else AuthenticationMode.UNKNOWN
            modes.append(mode or AuthenticationMode.UNKNOWN)
    return tuple(dict.fromkeys(modes))


class OpenAPIAdapter(FrameworkAdapter):
    name = "openapi"

    def _documents(self, project: ProjectRef) -> Iterable[ParsedDocument]:
        return (item for item in iter_documents(project) if _is_openapi(item.value))

    def detect(self, project: ProjectRef) -> DetectionResult:
        first = next(iter(self._documents(project)), None)
        if first is None:
            return DetectionResult(self.name, False, 0)
        version = str(first.value.get("openapi") or first.value.get("swagger") or "")
        return DetectionResult(self.name, True, 100, version, _evidence(first.relative_path))

    def discover_routes(self, project: ProjectRef) -> list[RouteContract]:
        routes: list[RouteContract] = []
        for parsed in self._documents(project):
            document = parsed.value
            for path, path_item_raw in document.get("paths", {}).items():
                path_item = _resolve(document, path_item_raw)
                if not isinstance(path_item, dict):
                    continue
                common_parameters = path_item.get("parameters", [])
                for method, operation_raw in path_item.items():
                    if method.lower() not in HTTP_METHODS:
                        continue
                    operation = _resolve(document, operation_raw)
                    if not isinstance(operation, dict):
                        operation = {}
                    request_schemas: list[SchemaContract] = []
                    parameters = [*common_parameters, *operation.get("parameters", [])] if isinstance(operation.get("parameters", []), list) else list(common_parameters)
                    parameter_fields: list[FieldContract] = []
                    form_fields: list[FieldContract] = []
                    for parameter_raw in parameters:
                        parameter = _resolve(document, parameter_raw)
                        if not isinstance(parameter, dict):
                            continue
                        location = str(parameter.get("in", ""))
                        if location == "body":
                            request_schemas.append(_schema_contract(document, str(parameter.get("name", "request-body")), parameter.get("schema", {}), parsed.relative_path, "application/json", bool(parameter.get("required"))))
                            continue
                        parameter_schema = parameter.get("schema") if isinstance(parameter.get("schema"), dict) else {key: parameter[key] for key in ("type", "format", "enum", "minimum", "maximum", "minLength", "maxLength", "pattern", "items") if key in parameter}
                        field = _field(document, str(parameter.get("name", "parameter")), parameter_schema, bool(parameter.get("required")), parsed.relative_path)
                        if location == "formData":
                            form_fields.append(field)
                        else:
                            parameter_fields.append(field)
                    if parameter_fields:
                        request_schemas.append(SchemaContract("parameters", "object", tuple(parameter_fields), confidence_score=99, evidence=_evidence(parsed.relative_path)))
                    if form_fields:
                        consumes = operation.get("consumes", document.get("consumes", ["application/x-www-form-urlencoded"]))
                        content_type = str(consumes[0]) if isinstance(consumes, list) and consumes else "application/x-www-form-urlencoded"
                        request_schemas.append(SchemaContract("form-data", "object", tuple(form_fields), content_type, confidence_score=98, evidence=_evidence(parsed.relative_path)))
                    request_body = _resolve(document, operation.get("requestBody", {}))
                    if isinstance(request_body, dict):
                        content = request_body.get("content", {})
                        for content_type, media in content.items() if isinstance(content, dict) else ():
                            if isinstance(media, dict):
                                request_schemas.append(_schema_contract(document, "request-body", media.get("schema", {}), parsed.relative_path, str(content_type), bool(request_body.get("required"))))
                    response_schemas: dict[str, SchemaContract] = {}
                    for status, response_raw in operation.get("responses", {}).items() if isinstance(operation.get("responses"), dict) else ():
                        response = _resolve(document, response_raw)
                        content = response.get("content", {}) if isinstance(response, dict) else {}
                        for content_type, media in content.items() if isinstance(content, dict) else ():
                            if isinstance(media, dict):
                                response_schemas[str(status)] = _schema_contract(document, f"response-{status}", media.get("schema", {}), parsed.relative_path, str(content_type))
                                break
                        if isinstance(response, dict) and "schema" in response and str(status) not in response_schemas:
                            produces = operation.get("produces", document.get("produces", ["application/json"]))
                            content_type = str(produces[0]) if isinstance(produces, list) and produces else "application/json"
                            response_schemas[str(status)] = _schema_contract(document, f"response-{status}", response.get("schema", {}), parsed.relative_path, content_type)
                    security = operation.get("security", document.get("security"))
                    if security == []:
                        modes, required = (AuthenticationMode.PUBLIC,), False
                    else:
                        modes, required = _security_modes(document, security), bool(security)
                    authentication = (AuthFlowContract("openapi-security", modes or (AuthenticationMode.PUBLIC,), required, confidence_score=99, evidence=_evidence(parsed.relative_path, "security")),)
                    routes.append(RouteContract(str(method).upper(), str(path), "OpenAPI", str(operation.get("operationId", "")), str(operation.get("summary") or operation.get("description") or "")[:500], tuple(request_schemas), response_schemas, authentication, confidence_score=99, evidence=_evidence(parsed.relative_path)))
        return routes

    def extract_schemas(self, project: ProjectRef) -> list[SchemaContract]:
        schemas: list[SchemaContract] = []
        for parsed in self._documents(project):
            components = parsed.value.get("components", {})
            definitions = components.get("schemas", {}) if isinstance(components, dict) else parsed.value.get("definitions", {})
            for name, schema in definitions.items() if isinstance(definitions, dict) else ():
                schemas.append(_schema_contract(parsed.value, str(name), schema, parsed.relative_path))
        return schemas

    def extract_constraints(self, project: ProjectRef) -> list[ConstraintContract]:
        return [constraint for schema in self.extract_schemas(project) for field in schema.fields for constraint in field.constraints]

    def extract_auth_flows(self, project: ProjectRef) -> list[AuthFlowContract]:
        return [flow for route in self.discover_routes(project) for flow in route.authentication]

    def extract_fixtures(self, project: ProjectRef) -> list[TestDataSource]:
        return []
