"""Versioned JSON encoding for smart-data contracts.

Serialized payloads never include filesystem roots or uploaded source.
Secret fields must already be vault references before encoding.
"""

from __future__ import annotations

from typing import Any, Mapping

from app.smart_data.contracts import (
    ActionKind,
    AuthenticationMode,
    AuthFlowContract,
    ConstraintContract,
    DependencyRelationship,
    FieldContract,
    PrerequisiteContract,
    RouteContract,
    RuntimeVariableContract,
    SchemaContract,
    SemanticType,
    SourceEvidence,
    TestDataSource,
    WorkflowActionContract,
)
from app.smart_data.dependency_graph import (
    DependencyEdge,
    DependencyNode,
    DynamicBinding,
    NodeKind,
    TestDependencyGraph,
)
from app.smart_data.migrate import SCHEMA_VERSION
from app.smart_data.placeholders import PlaceholderKind, parse_placeholder


class UnsafeSecretError(ValueError):
    """Raised when a secret would be persisted as a raw value."""


def require_secret_reference(value: Any, *, allow_empty: bool = True) -> Any:
    if value is None or value == "":
        if allow_empty:
            return value
        raise UnsafeSecretError("Secret values must be vault references")
    if isinstance(value, str):
        parsed = parse_placeholder(value)
        if parsed is not None and parsed.kind is PlaceholderKind.SECRET_REF:
            return value
    raise UnsafeSecretError("Secret values must be stored as vault references")


_SENSITIVE_KEY_TOKENS = (
    "secret",
    "token",
    "password",
    "credential",
    "api_key",
    "authorization",
)


def sanitize_secret_mapping(values: Mapping[str, Any], contains_secrets: bool) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in values.items():
        sensitive = contains_secrets and any(
            token in str(key).lower() for token in _SENSITIVE_KEY_TOKENS
        )
        payload[str(key)] = require_secret_reference(value) if sensitive else value
    return payload


def evidence_to_json(evidence: tuple[SourceEvidence, ...]) -> list[dict[str, Any]]:
    return [
        {
            "source_file": item.source_file,
            "source_line": item.source_line,
            "source_column": item.source_column,
            "evidence_type": item.evidence_type,
            "excerpt": item.excerpt,
            "confidence_score": item.confidence_score,
        }
        for item in evidence
    ]


def evidence_from_json(payload: Any) -> tuple[SourceEvidence, ...]:
    if not payload:
        return ()
    return tuple(
        SourceEvidence(
            source_file=str(item.get("source_file", "")),
            source_line=item.get("source_line"),
            source_column=item.get("source_column"),
            evidence_type=str(item.get("evidence_type", "source")),
            excerpt=str(item.get("excerpt", "")),
            confidence_score=int(item.get("confidence_score") or 0),
        )
        for item in payload
    )


def _enum_value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def _field_examples(field: FieldContract) -> list[Any]:
    if field.secret or field.sensitive:
        return []
    return list(field.example_values)


def field_to_json(field: FieldContract) -> dict[str, Any]:
    generated = field.generated_value
    default = field.default_value
    if field.secret:
        generated = require_secret_reference(generated)
        default = None
    elif field.sensitive:
        default = None
    return {
        "name": field.name,
        "path": field.path or field.name,
        "semantic_type": _enum_value(field.semantic_type),
        "data_type": field.data_type,
        "required": field.required,
        "default_value": default,
        "minimum": field.minimum,
        "maximum": field.maximum,
        "min_length": field.min_length,
        "max_length": field.max_length,
        "pattern": field.pattern,
        "format": field.format,
        "enum_values": list(field.enum_values),
        "nullable": field.nullable,
        "secret": field.secret,
        "sensitive": field.sensitive or field.secret,
        "read_only": field.read_only,
        "write_only": field.write_only,
        "example_values": _field_examples(field),
        "exclusive_minimum": field.exclusive_minimum,
        "exclusive_maximum": field.exclusive_maximum,
        "multiple_of": field.multiple_of,
        "min_items": field.min_items,
        "max_items": field.max_items,
        "unique_items": field.unique_items,
        "dependency": None
        if field.dependency is None
        else {
            "resource": field.dependency.resource,
            "field": field.dependency.field,
            "relationship": field.dependency.relationship,
            "confidence_score": field.dependency.confidence_score,
        },
        "generation_strategy": field.generation_strategy,
        "generated_value": generated,
        "confidence_score": field.confidence_score,
        "source_file": field.source_file,
        "source_line": field.source_line,
        "source_location": field.source_location
        or (
            f"{field.source_file}:{field.source_line}"
            if field.source_file and field.source_line is not None
            else field.source_file
        ),
        "editable": field.editable,
        "constraints": [
            {
                "name": item.name,
                "value": item.value,
                "message": item.message,
                "confidence_score": item.confidence_score,
                "evidence": evidence_to_json(item.evidence),
            }
            for item in field.constraints
        ],
        "children": [field_to_json(child) for child in field.children],
        "items": None if field.items is None else field_to_json(field.items),
        "one_of": [field_to_json(item) for item in field.one_of],
        "any_of": [field_to_json(item) for item in field.any_of],
        "all_of": [field_to_json(item) for item in field.all_of],
        "evidence": evidence_to_json(field.evidence),
    }


def field_from_json(payload: Mapping[str, Any]) -> FieldContract:
    dependency_payload = payload.get("dependency")
    dependency = None
    if isinstance(dependency_payload, Mapping):
        dependency = DependencyRelationship(
            resource=str(dependency_payload.get("resource", "")),
            field=str(dependency_payload.get("field", "")),
            relationship=str(dependency_payload.get("relationship", "requires")),
            confidence_score=int(dependency_payload.get("confidence_score") or 0),
        )
    secret = bool(payload.get("secret"))
    sensitive = bool(payload.get("sensitive")) or secret
    generated = payload.get("generated_value")
    default = payload.get("default_value")
    if secret:
        generated = require_secret_reference(generated)
        default = None
    elif sensitive:
        default = None
    items_payload = payload.get("items")
    return FieldContract(
        name=str(payload.get("name", "")),
        semantic_type=SemanticType(str(payload.get("semantic_type", "unknown"))),
        data_type=str(payload.get("data_type", "unknown")),
        required=bool(payload.get("required")),
        default_value=default,
        minimum=payload.get("minimum"),
        maximum=payload.get("maximum"),
        min_length=payload.get("min_length"),
        max_length=payload.get("max_length"),
        pattern=str(payload.get("pattern", "")),
        format=str(payload.get("format", "")),
        enum_values=tuple(payload.get("enum_values") or ()),
        nullable=bool(payload.get("nullable")),
        secret=secret,
        dependency=dependency,
        generation_strategy=str(payload.get("generation_strategy", "")),
        generated_value=generated,
        confidence_score=int(payload.get("confidence_score") or 0),
        source_file=str(payload.get("source_file", "")),
        source_line=payload.get("source_line"),
        editable=bool(payload.get("editable", True)),
        constraints=tuple(
            ConstraintContract(
                name=str(item.get("name", "")),
                value=item.get("value"),
                message=str(item.get("message", "")),
                confidence_score=int(item.get("confidence_score") or 0),
                evidence=evidence_from_json(item.get("evidence")),
            )
            for item in payload.get("constraints") or ()
        ),
        children=tuple(field_from_json(child) for child in payload.get("children") or ()),
        evidence=evidence_from_json(payload.get("evidence")),
        path=str(payload.get("path") or payload.get("name") or ""),
        read_only=bool(payload.get("read_only")),
        write_only=bool(payload.get("write_only")),
        sensitive=sensitive,
        example_values=() if secret or sensitive else tuple(payload.get("example_values") or ()),
        exclusive_minimum=payload.get("exclusive_minimum"),
        exclusive_maximum=payload.get("exclusive_maximum"),
        multiple_of=payload.get("multiple_of"),
        min_items=payload.get("min_items"),
        max_items=payload.get("max_items"),
        unique_items=bool(payload.get("unique_items")),
        items=None if not isinstance(items_payload, Mapping) else field_from_json(items_payload),
        one_of=tuple(field_from_json(item) for item in payload.get("one_of") or ()),
        any_of=tuple(field_from_json(item) for item in payload.get("any_of") or ()),
        all_of=tuple(field_from_json(item) for item in payload.get("all_of") or ()),
        source_location=str(payload.get("source_location", "")),
    )


def schema_to_json(schema: SchemaContract) -> dict[str, Any]:
    return {
        "name": schema.name,
        "schema_type": schema.schema_type,
        "fields": [field_to_json(field) for field in schema.fields],
        "content_type": schema.content_type,
        "required": schema.required,
        "confidence_score": schema.confidence_score,
        "evidence": evidence_to_json(schema.evidence),
    }


def schema_from_json(payload: Mapping[str, Any]) -> SchemaContract:
    return SchemaContract(
        name=str(payload.get("name", "")),
        schema_type=str(payload.get("schema_type", "")),
        fields=tuple(field_from_json(item) for item in payload.get("fields") or ()),
        content_type=str(payload.get("content_type", "")),
        required=bool(payload.get("required")),
        confidence_score=int(payload.get("confidence_score") or 0),
        evidence=evidence_from_json(payload.get("evidence")),
    )


def runtime_to_json(variable: RuntimeVariableContract) -> dict[str, Any]:
    return {
        "name": variable.name,
        "source_step": variable.source_step,
        "extraction": variable.extraction,
        "target_type": variable.target_type,
        "secret": variable.secret,
        "confidence_score": variable.confidence_score,
    }


def runtime_from_json(payload: Mapping[str, Any]) -> RuntimeVariableContract:
    return RuntimeVariableContract(
        name=str(payload.get("name", "")),
        source_step=str(payload.get("source_step", "")),
        extraction=str(payload.get("extraction", "")),
        target_type=str(payload.get("target_type", "string")),
        secret=bool(payload.get("secret")),
        confidence_score=int(payload.get("confidence_score") or 0),
    )


def route_to_json(route: RouteContract) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "method": route.method,
        "path": route.path,
        "framework": route.framework,
        "operation_id": route.operation_id,
        "summary": route.summary,
        "request_schemas": [schema_to_json(item) for item in route.request_schemas],
        "response_schemas": {
            status: schema_to_json(schema)
            for status, schema in dict(route.response_schemas).items()
        },
        "authentication": [
            {
                "name": item.name,
                "modes": [_enum_value(mode) for mode in item.modes],
                "required": item.required,
                "configuration_reference": item.configuration_reference,
                "steps": list(item.steps),
                "confidence_score": item.confidence_score,
                "evidence": evidence_to_json(item.evidence),
            }
            for item in route.authentication
        ],
        "prerequisites": [
            {
                "resource": item.resource,
                "field": item.field,
                "required": item.required,
                "placeholder": item.placeholder,
                "reason": item.reason,
                "confidence_score": item.confidence_score,
                "evidence": evidence_to_json(item.evidence),
            }
            for item in route.prerequisites
        ],
        "runtime_variables": [runtime_to_json(item) for item in route.runtime_variables],
        "setup_actions": [_action_to_json(item) for item in route.setup_actions],
        "cleanup_actions": [_action_to_json(item) for item in route.cleanup_actions],
        "confidence_score": route.confidence_score,
        "evidence": evidence_to_json(route.evidence),
        "warnings": list(route.warnings),
    }


def _action_to_json(action: WorkflowActionContract) -> dict[str, Any]:
    return {
        "name": action.name,
        "kind": _enum_value(action.kind),
        "route_reference": action.route_reference,
        "produces": [runtime_to_json(item) for item in action.produces],
        "requires_approval": action.requires_approval,
        "same_run_only": action.same_run_only,
        "confidence_score": action.confidence_score,
        "evidence": evidence_to_json(action.evidence),
    }


def _action_from_json(payload: Mapping[str, Any]) -> WorkflowActionContract:
    return WorkflowActionContract(
        name=str(payload.get("name", "")),
        kind=ActionKind(str(payload.get("kind", "setup"))),
        route_reference=str(payload.get("route_reference", "")),
        produces=tuple(runtime_from_json(item) for item in payload.get("produces") or ()),
        requires_approval=bool(payload.get("requires_approval")),
        same_run_only=bool(payload.get("same_run_only", True)),
        confidence_score=int(payload.get("confidence_score") or 0),
        evidence=evidence_from_json(payload.get("evidence")),
    )


def route_from_json(payload: Mapping[str, Any]) -> RouteContract:
    version = int(payload.get("schema_version") or SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise ValueError(f"Unsupported smart-data schema version: {version}")
    responses = payload.get("response_schemas") or {}
    return RouteContract(
        method=str(payload.get("method", "")),
        path=str(payload.get("path", "")),
        framework=str(payload.get("framework", "")),
        operation_id=str(payload.get("operation_id", "")),
        summary=str(payload.get("summary", "")),
        request_schemas=tuple(
            schema_from_json(item) for item in payload.get("request_schemas") or ()
        ),
        response_schemas={
            str(status): schema_from_json(schema)
            for status, schema in dict(responses).items()
        },
        authentication=tuple(
            AuthFlowContract(
                name=str(item.get("name", "")),
                modes=tuple(
                    AuthenticationMode(str(mode)) for mode in item.get("modes") or ()
                ),
                required=bool(item.get("required")),
                configuration_reference=str(item.get("configuration_reference", "")),
                steps=tuple(item.get("steps") or ()),
                confidence_score=int(item.get("confidence_score") or 0),
                evidence=evidence_from_json(item.get("evidence")),
            )
            for item in payload.get("authentication") or ()
        ),
        prerequisites=tuple(
            PrerequisiteContract(
                resource=str(item.get("resource", "")),
                field=str(item.get("field", "")),
                required=bool(item.get("required", True)),
                placeholder=str(item.get("placeholder", "")),
                reason=str(item.get("reason", "")),
                confidence_score=int(item.get("confidence_score") or 0),
                evidence=evidence_from_json(item.get("evidence")),
            )
            for item in payload.get("prerequisites") or ()
        ),
        runtime_variables=tuple(
            runtime_from_json(item) for item in payload.get("runtime_variables") or ()
        ),
        setup_actions=tuple(
            _action_from_json(item) for item in payload.get("setup_actions") or ()
        ),
        cleanup_actions=tuple(
            _action_from_json(item) for item in payload.get("cleanup_actions") or ()
        ),
        confidence_score=int(payload.get("confidence_score") or 0),
        evidence=evidence_from_json(payload.get("evidence")),
        warnings=tuple(payload.get("warnings") or ()),
    )


def fixture_to_json(fixture: TestDataSource) -> dict[str, Any]:
    values = sanitize_secret_mapping(fixture.values, fixture.contains_secrets)
    return {
        "name": fixture.name,
        "source_type": fixture.source_type,
        "values": values,
        "contains_secrets": fixture.contains_secrets,
        "confidence_score": fixture.confidence_score,
        "evidence": evidence_to_json(fixture.evidence),
    }


def fixture_from_json(payload: Mapping[str, Any]) -> TestDataSource:
    contains_secrets = bool(payload.get("contains_secrets"))
    values = sanitize_secret_mapping(payload.get("values") or {}, contains_secrets)
    return TestDataSource(
        name=str(payload.get("name", "")),
        source_type=str(payload.get("source_type", "")),
        values=values,
        contains_secrets=contains_secrets,
        confidence_score=int(payload.get("confidence_score") or 0),
        evidence=evidence_from_json(payload.get("evidence")),
    )


def graph_to_json(graph: TestDependencyGraph) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "nodes": [
            {
                "node_id": node.node_id,
                "kind": node.kind.value,
                "label": node.label,
                "route_reference": node.route_reference,
                "required": node.required,
                "requires_approval": node.requires_approval,
                "same_run_only": node.same_run_only,
                "created_by_node_id": node.created_by_node_id,
            }
            for node in graph.nodes.values()
        ],
        "edges": [
            {
                "source": edge.source,
                "target": edge.target,
                "relationship": edge.relationship,
            }
            for edge in graph.edges
        ],
        "bindings": [
            {
                "variable": runtime_to_json(binding.variable),
                "producer_node_id": binding.producer_node_id,
                "consumer_node_id": binding.consumer_node_id,
                "placeholder": binding.placeholder,
            }
            for binding in graph.bindings
        ],
    }


def graph_from_json(payload: Mapping[str, Any]) -> TestDependencyGraph:
    version = int(payload.get("schema_version") or SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise ValueError(f"Unsupported smart-data schema version: {version}")
    graph = TestDependencyGraph()
    for item in payload.get("nodes") or ():
        graph.add_node(
            DependencyNode(
                node_id=str(item.get("node_id", "")),
                kind=NodeKind(str(item.get("kind", "request"))),
                label=str(item.get("label", "")),
                route_reference=str(item.get("route_reference", "")),
                required=bool(item.get("required", True)),
                requires_approval=bool(item.get("requires_approval")),
                same_run_only=bool(item.get("same_run_only")),
                created_by_node_id=str(item.get("created_by_node_id", "")),
            )
        )
    for item in payload.get("edges") or ():
        graph.add_edge(
            DependencyEdge(
                source=str(item.get("source", "")),
                target=str(item.get("target", "")),
                relationship=str(item.get("relationship", "")),
            )
        )
    for item in payload.get("bindings") or ():
        graph.add_binding(
            DynamicBinding(
                variable=runtime_from_json(item.get("variable") or {}),
                producer_node_id=str(item.get("producer_node_id", "")),
                consumer_node_id=str(item.get("consumer_node_id", "")),
                placeholder=str(item.get("placeholder", "")),
            )
        )
    return graph
