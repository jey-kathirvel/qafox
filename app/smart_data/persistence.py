"""Owner-scoped persistence for normalized smart-data contracts.

This module does not change live API discovery. Callers in later patches
must still compare adapter output with the legacy inventory before switching.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.smart_data.contracts import (
    FieldContract,
    RouteContract,
    SchemaContract,
    TestDataSource,
)
from app.smart_data.dependency_graph import (
    DependencyGraphBuilder,
    TestDependencyGraph,
)
from app.smart_data.migrate import SCHEMA_VERSION
from app.smart_data.serialization import (
    fixture_from_json,
    fixture_to_json,
    graph_from_json,
    require_secret_reference,
    route_from_json,
    route_to_json,
)

CHILD_TABLES = (
    "smart_data_graph_bindings",
    "smart_data_graph_edges",
    "smart_data_graph_nodes",
    "smart_data_constraints",
    "smart_data_fields",
    "smart_data_auth_flows",
    "smart_data_prerequisites",
    "smart_data_runtime_variables",
    "smart_data_actions",
    "smart_data_fixtures",
    "smart_data_routes",
)


class PersistenceIsolationError(LookupError):
    """Raised when a snapshot exists but is not visible to the caller."""


@dataclass(frozen=True, slots=True)
class PersistedSnapshot:
    id: int
    public_id: str
    owner_user_id: int
    project_id: int
    discovery_run_id: int
    schema_version: int
    adapter_names: tuple[str, ...]
    routes: tuple[RouteContract, ...]
    graphs: Mapping[str, TestDependencyGraph]
    fixtures: tuple[TestDataSource, ...]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _loads(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    return json.loads(value)


def _new_id() -> str:
    return str(uuid.uuid4())


def _route_key(route: RouteContract) -> str:
    return f"{route.method.upper()} {route.path}"


def _as_bool(value: Any) -> bool:
    return bool(value) and value != 0


def persist_contracts(
    session: Session,
    *,
    owner_user_id: int,
    project_id: int,
    discovery_run_id: int,
    routes: Iterable[RouteContract],
    fixtures: Iterable[TestDataSource] = (),
    graphs: Mapping[str, TestDependencyGraph] | None = None,
    adapter_names: Iterable[str] = (),
    created_at: datetime | None = None,
) -> PersistedSnapshot:
    if owner_user_id < 1 or project_id < 1 or discovery_run_id < 1:
        raise ValueError("Persistence requires owner, project, and discovery-run identity")

    route_list = tuple(routes)
    fixture_list = tuple(fixtures)
    adapter_list = tuple(str(name).strip() for name in adapter_names if str(name).strip())
    timestamp = created_at or utc_now()
    builder = DependencyGraphBuilder()
    graph_map: dict[str, TestDependencyGraph] = {}
    for route in route_list:
        key = _route_key(route)
        graph_map[key] = graphs[key] if graphs and key in graphs else builder.build_route(route)

    existing = session.execute(
        text(
            """
            SELECT id, public_id, owner_user_id, project_id
            FROM smart_data_snapshots
            WHERE discovery_run_id = :discovery_run_id
            LIMIT 1
            """
        ),
        {"discovery_run_id": discovery_run_id},
    ).mappings().first()

    if existing and (
        int(existing["owner_user_id"]) != owner_user_id
        or int(existing["project_id"]) != project_id
    ):
        raise PersistenceIsolationError("Discovery run snapshot belongs to another owner")

    if existing:
        snapshot_id = int(existing["id"])
        public_id = str(existing["public_id"])
        session.execute(
            text(
                """
                UPDATE smart_data_snapshots
                SET schema_version = :schema_version,
                    adapter_names_json = :adapter_names_json,
                    status = 'persisted'
                WHERE id = :id
                  AND owner_user_id = :owner_user_id
                  AND project_id = :project_id
                  AND discovery_run_id = :discovery_run_id
                """
            ),
            {
                "schema_version": SCHEMA_VERSION,
                "adapter_names_json": _json(adapter_list),
                "id": snapshot_id,
                "owner_user_id": owner_user_id,
                "project_id": project_id,
                "discovery_run_id": discovery_run_id,
            },
        )
        _delete_children(session, snapshot_id, owner_user_id, project_id)
    else:
        public_id = _new_id()
        inserted = session.execute(
            text(
                """
                INSERT INTO smart_data_snapshots (
                    public_id,
                    owner_user_id,
                    project_id,
                    discovery_run_id,
                    schema_version,
                    adapter_names_json,
                    status,
                    created_at
                )
                VALUES (
                    :public_id,
                    :owner_user_id,
                    :project_id,
                    :discovery_run_id,
                    :schema_version,
                    :adapter_names_json,
                    'persisted',
                    :created_at
                )
                RETURNING id
                """
            ),
            {
                "public_id": public_id,
                "owner_user_id": owner_user_id,
                "project_id": project_id,
                "discovery_run_id": discovery_run_id,
                "schema_version": SCHEMA_VERSION,
                "adapter_names_json": _json(adapter_list),
                "created_at": timestamp.isoformat(),
            },
        )
        snapshot_id = int(inserted.scalar_one())

    scope = {
        "snapshot_id": snapshot_id,
        "owner_user_id": owner_user_id,
        "project_id": project_id,
        "discovery_run_id": discovery_run_id,
        "schema_version": SCHEMA_VERSION,
        "created_at": timestamp.isoformat(),
    }

    for route in route_list:
        _insert_route(session, scope, route, graph_map[_route_key(route)])

    for fixture in fixture_list:
        _insert_fixture(session, scope, fixture)

    session.flush()
    loaded = load_snapshot(
        session,
        owner_user_id=owner_user_id,
        project_id=project_id,
        public_id=public_id,
        discovery_run_id=discovery_run_id,
    )
    if loaded is None:
        raise PersistenceIsolationError("Persisted snapshot is not visible to the owner")
    return loaded


def _delete_children(
    session: Session,
    snapshot_id: int,
    owner_user_id: int,
    project_id: int,
) -> None:
    params = {
        "snapshot_id": snapshot_id,
        "owner_user_id": owner_user_id,
        "project_id": project_id,
    }
    for table in CHILD_TABLES:
        session.execute(
            text(
                f"""
                DELETE FROM {table}
                WHERE snapshot_id = :snapshot_id
                  AND owner_user_id = :owner_user_id
                  AND project_id = :project_id
                """
            ),
            params,
        )


def _insert_route(
    session: Session,
    scope: dict[str, Any],
    route: RouteContract,
    graph: TestDependencyGraph,
) -> None:
    route_id = int(
        session.execute(
            text(
                """
                INSERT INTO smart_data_routes (
                    public_id,
                    snapshot_id,
                    owner_user_id,
                    project_id,
                    discovery_run_id,
                    schema_version,
                    http_method,
                    endpoint_path,
                    framework,
                    operation_id,
                    summary,
                    confidence_score,
                    warnings_json,
                    evidence_json,
                    contract_json,
                    created_at
                )
                VALUES (
                    :public_id,
                    :snapshot_id,
                    :owner_user_id,
                    :project_id,
                    :discovery_run_id,
                    :schema_version,
                    :http_method,
                    :endpoint_path,
                    :framework,
                    :operation_id,
                    :summary,
                    :confidence_score,
                    :warnings_json,
                    :evidence_json,
                    :contract_json,
                    :created_at
                )
                RETURNING id
                """
            ),
            {
                **scope,
                "public_id": _new_id(),
                "http_method": route.method.upper(),
                "endpoint_path": route.path,
                "framework": route.framework,
                "operation_id": route.operation_id,
                "summary": route.summary,
                "confidence_score": route.confidence_score,
                "warnings_json": _json(list(route.warnings)),
                "evidence_json": _json(route_to_json(route)["evidence"]),
                "contract_json": _json(route_to_json(route)),
            },
        ).scalar_one()
    )

    for schema in route.request_schemas:
        _insert_schema_fields(session, scope, route_id, schema, "request", "")
    for status, schema in dict(route.response_schemas).items():
        _insert_schema_fields(session, scope, route_id, schema, "response", str(status))

    for auth in route.authentication:
        session.execute(
            text(
                """
                INSERT INTO smart_data_auth_flows (
                    public_id, snapshot_id, route_id, owner_user_id, project_id,
                    discovery_run_id, schema_version, name, modes_json, required,
                    configuration_reference, steps_json, confidence_score, created_at
                )
                VALUES (
                    :public_id, :snapshot_id, :route_id, :owner_user_id, :project_id,
                    :discovery_run_id, :schema_version, :name, :modes_json, :required,
                    :configuration_reference, :steps_json, :confidence_score, :created_at
                )
                """
            ),
            {
                **scope,
                "public_id": _new_id(),
                "route_id": route_id,
                "name": auth.name,
                "modes_json": _json([mode.value for mode in auth.modes]),
                "required": auth.required,
                "configuration_reference": auth.configuration_reference,
                "steps_json": _json(list(auth.steps)),
                "confidence_score": auth.confidence_score,
            },
        )

    for prerequisite in route.prerequisites:
        session.execute(
            text(
                """
                INSERT INTO smart_data_prerequisites (
                    public_id, snapshot_id, route_id, owner_user_id, project_id,
                    discovery_run_id, schema_version, resource, field, required,
                    placeholder, reason, confidence_score, created_at
                )
                VALUES (
                    :public_id, :snapshot_id, :route_id, :owner_user_id, :project_id,
                    :discovery_run_id, :schema_version, :resource, :field, :required,
                    :placeholder, :reason, :confidence_score, :created_at
                )
                """
            ),
            {
                **scope,
                "public_id": _new_id(),
                "route_id": route_id,
                "resource": prerequisite.resource,
                "field": prerequisite.field,
                "required": prerequisite.required,
                "placeholder": prerequisite.placeholder,
                "reason": prerequisite.reason,
                "confidence_score": prerequisite.confidence_score,
            },
        )

    for variable in route.runtime_variables:
        session.execute(
            text(
                """
                INSERT INTO smart_data_runtime_variables (
                    public_id, snapshot_id, route_id, owner_user_id, project_id,
                    discovery_run_id, schema_version, name, source_step, extraction,
                    target_type, secret, confidence_score, created_at
                )
                VALUES (
                    :public_id, :snapshot_id, :route_id, :owner_user_id, :project_id,
                    :discovery_run_id, :schema_version, :name, :source_step, :extraction,
                    :target_type, :secret, :confidence_score, :created_at
                )
                """
            ),
            {
                **scope,
                "public_id": _new_id(),
                "route_id": route_id,
                "name": variable.name,
                "source_step": variable.source_step,
                "extraction": variable.extraction,
                "target_type": variable.target_type,
                "secret": variable.secret,
                "confidence_score": variable.confidence_score,
            },
        )

    for action in (*route.setup_actions, *route.cleanup_actions):
        session.execute(
            text(
                """
                INSERT INTO smart_data_actions (
                    public_id, snapshot_id, route_id, owner_user_id, project_id,
                    discovery_run_id, schema_version, name, kind, route_reference,
                    produces_json, requires_approval, same_run_only, confidence_score,
                    created_at
                )
                VALUES (
                    :public_id, :snapshot_id, :route_id, :owner_user_id, :project_id,
                    :discovery_run_id, :schema_version, :name, :kind, :route_reference,
                    :produces_json, :requires_approval, :same_run_only, :confidence_score,
                    :created_at
                )
                """
            ),
            {
                **scope,
                "public_id": _new_id(),
                "route_id": route_id,
                "name": action.name,
                "kind": action.kind.value,
                "route_reference": action.route_reference,
                "produces_json": _json(
                    [
                        {
                            "name": item.name,
                            "source_step": item.source_step,
                            "extraction": item.extraction,
                            "target_type": item.target_type,
                            "secret": item.secret,
                            "confidence_score": item.confidence_score,
                        }
                        for item in action.produces
                    ]
                ),
                "requires_approval": action.requires_approval,
                "same_run_only": action.same_run_only,
                "confidence_score": action.confidence_score,
            },
        )

    node_prefix = f"{route.method.lower()}:{route.path}:"
    for node in graph.nodes.values():
        session.execute(
            text(
                """
                INSERT INTO smart_data_graph_nodes (
                    public_id, snapshot_id, route_id, owner_user_id, project_id,
                    discovery_run_id, schema_version, node_id, kind, label,
                    route_reference, required, requires_approval, same_run_only,
                    created_by_node_id, created_at
                )
                VALUES (
                    :public_id, :snapshot_id, :route_id, :owner_user_id, :project_id,
                    :discovery_run_id, :schema_version, :node_id, :kind, :label,
                    :route_reference, :required, :requires_approval, :same_run_only,
                    :created_by_node_id, :created_at
                )
                """
            ),
            {
                **scope,
                "public_id": _new_id(),
                "route_id": route_id,
                "node_id": node_prefix + node.node_id,
                "kind": node.kind.value,
                "label": node.label,
                "route_reference": node.route_reference,
                "required": node.required,
                "requires_approval": node.requires_approval,
                "same_run_only": node.same_run_only,
                "created_by_node_id": (
                    node_prefix + node.created_by_node_id
                    if node.created_by_node_id
                    else ""
                ),
            },
        )

    for edge in graph.edges:
        session.execute(
            text(
                """
                INSERT INTO smart_data_graph_edges (
                    public_id, snapshot_id, owner_user_id, project_id, discovery_run_id,
                    schema_version, source_node_id, target_node_id, relationship, created_at
                )
                VALUES (
                    :public_id, :snapshot_id, :owner_user_id, :project_id, :discovery_run_id,
                    :schema_version, :source_node_id, :target_node_id, :relationship, :created_at
                )
                """
            ),
            {
                **scope,
                "public_id": _new_id(),
                "source_node_id": node_prefix + edge.source,
                "target_node_id": node_prefix + edge.target,
                "relationship": edge.relationship,
            },
        )

    for binding in graph.bindings:
        session.execute(
            text(
                """
                INSERT INTO smart_data_graph_bindings (
                    public_id, snapshot_id, owner_user_id, project_id, discovery_run_id,
                    schema_version, variable_name, source_step, extraction, target_type,
                    secret, producer_node_id, consumer_node_id, placeholder, created_at
                )
                VALUES (
                    :public_id, :snapshot_id, :owner_user_id, :project_id, :discovery_run_id,
                    :schema_version, :variable_name, :source_step, :extraction, :target_type,
                    :secret, :producer_node_id, :consumer_node_id, :placeholder, :created_at
                )
                """
            ),
            {
                **scope,
                "public_id": _new_id(),
                "variable_name": binding.variable.name,
                "source_step": binding.variable.source_step,
                "extraction": binding.variable.extraction,
                "target_type": binding.variable.target_type,
                "secret": binding.variable.secret,
                "producer_node_id": node_prefix + binding.producer_node_id,
                "consumer_node_id": node_prefix + binding.consumer_node_id,
                "placeholder": binding.placeholder,
            },
        )


def _insert_schema_fields(
    session: Session,
    scope: dict[str, Any],
    route_id: int,
    schema: SchemaContract,
    schema_role: str,
    response_status: str,
) -> None:
    def walk(field: FieldContract, path: str) -> None:
        field_path = f"{path}.{field.name}" if path else field.name
        generated = field.generated_value
        if field.secret:
            generated = require_secret_reference(generated)
        field_id = int(
            session.execute(
                text(
                    """
                    INSERT INTO smart_data_fields (
                        public_id, snapshot_id, route_id, owner_user_id, project_id,
                        discovery_run_id, schema_version, schema_name, schema_role,
                        response_status, field_path, name, semantic_type, data_type,
                        required, nullable, secret, editable, minimum, maximum,
                        min_length, max_length, pattern, format, enum_values_json,
                        generation_strategy, generated_value_json, dependency_json,
                        confidence_score, source_file, source_line, created_at
                    )
                    VALUES (
                        :public_id, :snapshot_id, :route_id, :owner_user_id, :project_id,
                        :discovery_run_id, :schema_version, :schema_name, :schema_role,
                        :response_status, :field_path, :name, :semantic_type, :data_type,
                        :required, :nullable, :secret, :editable, :minimum, :maximum,
                        :min_length, :max_length, :pattern, :format, :enum_values_json,
                        :generation_strategy, :generated_value_json, :dependency_json,
                        :confidence_score, :source_file, :source_line, :created_at
                    )
                    RETURNING id
                    """
                ),
                {
                    **scope,
                    "public_id": _new_id(),
                    "route_id": route_id,
                    "schema_name": schema.name,
                    "schema_role": schema_role,
                    "response_status": response_status,
                    "field_path": field_path,
                    "name": field.name,
                    "semantic_type": field.semantic_type.value,
                    "data_type": field.data_type,
                    "required": field.required,
                    "nullable": field.nullable,
                    "secret": field.secret,
                    "editable": field.editable,
                    "minimum": field.minimum,
                    "maximum": field.maximum,
                    "min_length": field.min_length,
                    "max_length": field.max_length,
                    "pattern": field.pattern,
                    "format": field.format,
                    "enum_values_json": _json(list(field.enum_values)),
                    "generation_strategy": field.generation_strategy,
                    "generated_value_json": None if generated is None else _json(generated),
                    "dependency_json": None
                    if field.dependency is None
                    else _json(
                        {
                            "resource": field.dependency.resource,
                            "field": field.dependency.field,
                            "relationship": field.dependency.relationship,
                            "confidence_score": field.dependency.confidence_score,
                        }
                    ),
                    "confidence_score": field.confidence_score,
                    "source_file": field.source_file,
                    "source_line": field.source_line,
                },
            ).scalar_one()
        )
        for constraint in field.constraints:
            session.execute(
                text(
                    """
                    INSERT INTO smart_data_constraints (
                        public_id, snapshot_id, field_id, owner_user_id, project_id,
                        discovery_run_id, schema_version, name, value_json, message,
                        confidence_score, created_at
                    )
                    VALUES (
                        :public_id, :snapshot_id, :field_id, :owner_user_id, :project_id,
                        :discovery_run_id, :schema_version, :name, :value_json, :message,
                        :confidence_score, :created_at
                    )
                    """
                ),
                {
                    **scope,
                    "public_id": _new_id(),
                    "field_id": field_id,
                    "name": constraint.name,
                    "value_json": None if constraint.value is None else _json(constraint.value),
                    "message": constraint.message,
                    "confidence_score": constraint.confidence_score,
                },
            )
        for child in field.children:
            walk(child, field_path)

    for field in schema.fields:
        walk(field, "")


def _insert_fixture(
    session: Session,
    scope: dict[str, Any],
    fixture: TestDataSource,
) -> None:
    payload = fixture_to_json(fixture)
    session.execute(
        text(
            """
            INSERT INTO smart_data_fixtures (
                public_id, snapshot_id, owner_user_id, project_id, discovery_run_id,
                schema_version, name, source_type, values_json, contains_secrets,
                confidence_score, evidence_json, created_at
            )
            VALUES (
                :public_id, :snapshot_id, :owner_user_id, :project_id, :discovery_run_id,
                :schema_version, :name, :source_type, :values_json, :contains_secrets,
                :confidence_score, :evidence_json, :created_at
            )
            """
        ),
        {
            **scope,
            "public_id": _new_id(),
            "name": payload["name"],
            "source_type": payload["source_type"],
            "values_json": _json(payload["values"]),
            "contains_secrets": payload["contains_secrets"],
            "confidence_score": payload["confidence_score"],
            "evidence_json": _json(payload["evidence"]),
        },
    )


def load_snapshot(
    session: Session,
    *,
    owner_user_id: int,
    project_id: int,
    public_id: str | None = None,
    discovery_run_id: int | None = None,
) -> PersistedSnapshot | None:
    if not public_id and discovery_run_id is None:
        raise ValueError("A snapshot public ID or discovery run is required")
    # Bind only the identifiers that are present. PostgreSQL/psycopg cannot
    # infer a type for `NULL IS NOT NULL` placeholders, which aborted live
    # discovery after adapter persistence.
    identity_sql = []
    params: dict[str, Any] = {
        "owner_user_id": owner_user_id,
        "project_id": project_id,
    }
    if public_id:
        identity_sql.append("public_id = :public_id")
        params["public_id"] = public_id
    if discovery_run_id is not None:
        identity_sql.append("discovery_run_id = :discovery_run_id")
        params["discovery_run_id"] = int(discovery_run_id)
    row = session.execute(
        text(
            f"""
            SELECT *
            FROM smart_data_snapshots
            WHERE owner_user_id = :owner_user_id
              AND project_id = :project_id
              AND ({' OR '.join(identity_sql)})
            LIMIT 1
            """
        ),
        params,
    ).mappings().first()
    if row is None:
        return None

    snapshot_id = int(row["id"])
    route_rows = session.execute(
        text(
            """
            SELECT contract_json, http_method, endpoint_path
            FROM smart_data_routes
            WHERE snapshot_id = :snapshot_id
              AND owner_user_id = :owner_user_id
              AND project_id = :project_id
            ORDER BY id
            """
        ),
        {
            "snapshot_id": snapshot_id,
            "owner_user_id": owner_user_id,
            "project_id": project_id,
        },
    ).mappings()
    routes = tuple(route_from_json(_loads(item["contract_json"], {})) for item in route_rows)

    graphs: dict[str, TestDependencyGraph] = {}
    node_rows = list(
        session.execute(
            text(
                """
                SELECT node_id, kind, label, route_reference, required, requires_approval,
                       same_run_only, created_by_node_id, route_id
                FROM smart_data_graph_nodes
                WHERE snapshot_id = :snapshot_id
                  AND owner_user_id = :owner_user_id
                  AND project_id = :project_id
                ORDER BY id
                """
            ),
            {
                "snapshot_id": snapshot_id,
                "owner_user_id": owner_user_id,
                "project_id": project_id,
            },
        ).mappings()
    )
    edge_rows = list(
        session.execute(
            text(
                """
                SELECT source_node_id, target_node_id, relationship
                FROM smart_data_graph_edges
                WHERE snapshot_id = :snapshot_id
                  AND owner_user_id = :owner_user_id
                  AND project_id = :project_id
                ORDER BY id
                """
            ),
            {
                "snapshot_id": snapshot_id,
                "owner_user_id": owner_user_id,
                "project_id": project_id,
            },
        ).mappings()
    )
    binding_rows = list(
        session.execute(
            text(
                """
                SELECT variable_name, source_step, extraction, target_type, secret,
                       producer_node_id, consumer_node_id, placeholder
                FROM smart_data_graph_bindings
                WHERE snapshot_id = :snapshot_id
                  AND owner_user_id = :owner_user_id
                  AND project_id = :project_id
                ORDER BY id
                """
            ),
            {
                "snapshot_id": snapshot_id,
                "owner_user_id": owner_user_id,
                "project_id": project_id,
            },
        ).mappings()
    )
    graphs["snapshot"] = graph_from_json(
        {
            "schema_version": SCHEMA_VERSION,
            "nodes": [
                {
                    "node_id": item["node_id"],
                    "kind": item["kind"],
                    "label": item["label"],
                    "route_reference": item["route_reference"],
                    "required": _as_bool(item["required"]),
                    "requires_approval": _as_bool(item["requires_approval"]),
                    "same_run_only": _as_bool(item["same_run_only"]),
                    "created_by_node_id": item["created_by_node_id"],
                }
                for item in node_rows
            ],
            "edges": [
                {
                    "source": item["source_node_id"],
                    "target": item["target_node_id"],
                    "relationship": item["relationship"],
                }
                for item in edge_rows
            ],
            "bindings": [
                {
                    "variable": {
                        "name": item["variable_name"],
                        "source_step": item["source_step"],
                        "extraction": item["extraction"],
                        "target_type": item["target_type"],
                        "secret": _as_bool(item["secret"]),
                    },
                    "producer_node_id": item["producer_node_id"],
                    "consumer_node_id": item["consumer_node_id"],
                    "placeholder": item["placeholder"],
                }
                for item in binding_rows
            ],
        }
    )
    for route in routes:
        graphs[_route_key(route)] = builder_graph_for_route(route)

    fixture_rows = session.execute(
        text(
            """
            SELECT name, source_type, values_json, contains_secrets, confidence_score,
                   evidence_json
            FROM smart_data_fixtures
            WHERE snapshot_id = :snapshot_id
              AND owner_user_id = :owner_user_id
              AND project_id = :project_id
            ORDER BY id
            """
        ),
        {
            "snapshot_id": snapshot_id,
            "owner_user_id": owner_user_id,
            "project_id": project_id,
        },
    ).mappings()
    fixtures = tuple(
        fixture_from_json(
            {
                "name": item["name"],
                "source_type": item["source_type"],
                "values": _loads(item["values_json"], {}),
                "contains_secrets": _as_bool(item["contains_secrets"]),
                "confidence_score": item["confidence_score"],
                "evidence": _loads(item["evidence_json"], []),
            }
        )
        for item in fixture_rows
    )

    return PersistedSnapshot(
        id=snapshot_id,
        public_id=str(row["public_id"]),
        owner_user_id=int(row["owner_user_id"]),
        project_id=int(row["project_id"]),
        discovery_run_id=int(row["discovery_run_id"]),
        schema_version=int(row["schema_version"]),
        adapter_names=tuple(_loads(row["adapter_names_json"], [])),
        routes=routes,
        graphs=graphs,
        fixtures=fixtures,
    )


def builder_graph_for_route(route: RouteContract) -> TestDependencyGraph:
    return DependencyGraphBuilder().build_route(route)


def list_snapshots(
    session: Session,
    *,
    owner_user_id: int,
    project_id: int,
) -> tuple[dict[str, Any], ...]:
    rows = session.execute(
        text(
            """
            SELECT public_id, discovery_run_id, schema_version, adapter_names_json,
                   status, created_at
            FROM smart_data_snapshots
            WHERE owner_user_id = :owner_user_id
              AND project_id = :project_id
            ORDER BY created_at DESC, id DESC
            """
        ),
        {"owner_user_id": owner_user_id, "project_id": project_id},
    ).mappings()
    return tuple(dict(row) for row in rows)


def count_table(
    session: Session,
    table: str,
    *,
    owner_user_id: int | None = None,
) -> int:
    if table not in {*CHILD_TABLES, "smart_data_snapshots"} and not table.startswith("api_"):
        raise ValueError("Refusing to count an unknown table")
    if owner_user_id is None:
        return int(session.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one())
    return int(
        session.execute(
            text(
                f"""
                SELECT COUNT(*)
                FROM {table}
                WHERE owner_user_id = :owner_user_id
                """
            ),
            {"owner_user_id": owner_user_id},
        ).scalar_one()
    )
