"""Idempotent smart-data schema patch 004B1A-6."""

from __future__ import annotations

from pathlib import Path
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

SCHEMA_VERSION = 1
PATCH_ID = "004B1A-6"

MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations" / PATCH_ID

SMART_DATA_TABLES = (
    "smart_data_snapshots",
    "smart_data_routes",
    "smart_data_fields",
    "smart_data_constraints",
    "smart_data_auth_flows",
    "smart_data_prerequisites",
    "smart_data_runtime_variables",
    "smart_data_actions",
    "smart_data_fixtures",
    "smart_data_graph_nodes",
    "smart_data_graph_edges",
    "smart_data_graph_bindings",
)

HISTORICAL_API_TABLES = (
    "api_discovery_runs",
    "api_inventory",
    "api_test_configurations",
    "api_test_cases",
    "api_execution_plans",
    "api_execution_plan_cases",
    "api_test_runs",
    "api_test_results",
    "projects",
    "project_audit_events",
)

_SQLITE_FORWARD = (
    """
    CREATE TABLE IF NOT EXISTS smart_data_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_id TEXT NOT NULL UNIQUE,
        owner_user_id INTEGER NOT NULL,
        project_id INTEGER NOT NULL,
        discovery_run_id INTEGER NOT NULL,
        schema_version INTEGER NOT NULL,
        adapter_names_json TEXT NOT NULL DEFAULT '[]',
        status TEXT NOT NULL DEFAULT 'persisted',
        created_at TEXT NOT NULL,
        UNIQUE (owner_user_id, project_id, discovery_run_id),
        UNIQUE (discovery_run_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS smart_data_snapshots_owner_project_idx
        ON smart_data_snapshots (owner_user_id, project_id, created_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS smart_data_routes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_id TEXT NOT NULL UNIQUE,
        snapshot_id INTEGER NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
        owner_user_id INTEGER NOT NULL,
        project_id INTEGER NOT NULL,
        discovery_run_id INTEGER NOT NULL,
        schema_version INTEGER NOT NULL,
        http_method TEXT NOT NULL,
        endpoint_path TEXT NOT NULL,
        framework TEXT NOT NULL,
        operation_id TEXT NOT NULL DEFAULT '',
        summary TEXT NOT NULL DEFAULT '',
        confidence_score INTEGER NOT NULL DEFAULT 0,
        warnings_json TEXT NOT NULL DEFAULT '[]',
        evidence_json TEXT NOT NULL DEFAULT '[]',
        contract_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE (owner_user_id, snapshot_id, http_method, endpoint_path, framework)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS smart_data_routes_owner_project_idx
        ON smart_data_routes (owner_user_id, project_id, discovery_run_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS smart_data_routes_owner_snapshot_idx
        ON smart_data_routes (owner_user_id, snapshot_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS smart_data_fields (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_id TEXT NOT NULL UNIQUE,
        snapshot_id INTEGER NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
        route_id INTEGER NOT NULL REFERENCES smart_data_routes (id) ON DELETE CASCADE,
        owner_user_id INTEGER NOT NULL,
        project_id INTEGER NOT NULL,
        discovery_run_id INTEGER NOT NULL,
        schema_version INTEGER NOT NULL,
        schema_name TEXT NOT NULL DEFAULT '',
        schema_role TEXT NOT NULL,
        response_status TEXT NOT NULL DEFAULT '',
        field_path TEXT NOT NULL,
        name TEXT NOT NULL,
        semantic_type TEXT NOT NULL,
        data_type TEXT NOT NULL DEFAULT 'unknown',
        required INTEGER NOT NULL DEFAULT 0,
        nullable INTEGER NOT NULL DEFAULT 0,
        secret INTEGER NOT NULL DEFAULT 0,
        editable INTEGER NOT NULL DEFAULT 1,
        minimum REAL,
        maximum REAL,
        min_length INTEGER,
        max_length INTEGER,
        pattern TEXT NOT NULL DEFAULT '',
        format TEXT NOT NULL DEFAULT '',
        enum_values_json TEXT NOT NULL DEFAULT '[]',
        generation_strategy TEXT NOT NULL DEFAULT '',
        generated_value_json TEXT,
        dependency_json TEXT,
        confidence_score INTEGER NOT NULL DEFAULT 0,
        source_file TEXT NOT NULL DEFAULT '',
        source_line INTEGER,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS smart_data_fields_owner_snapshot_idx
        ON smart_data_fields (owner_user_id, snapshot_id, route_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS smart_data_constraints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_id TEXT NOT NULL UNIQUE,
        snapshot_id INTEGER NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
        field_id INTEGER NOT NULL REFERENCES smart_data_fields (id) ON DELETE CASCADE,
        owner_user_id INTEGER NOT NULL,
        project_id INTEGER NOT NULL,
        discovery_run_id INTEGER NOT NULL,
        schema_version INTEGER NOT NULL,
        name TEXT NOT NULL,
        value_json TEXT,
        message TEXT NOT NULL DEFAULT '',
        confidence_score INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS smart_data_constraints_owner_field_idx
        ON smart_data_constraints (owner_user_id, field_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS smart_data_auth_flows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_id TEXT NOT NULL UNIQUE,
        snapshot_id INTEGER NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
        route_id INTEGER NOT NULL REFERENCES smart_data_routes (id) ON DELETE CASCADE,
        owner_user_id INTEGER NOT NULL,
        project_id INTEGER NOT NULL,
        discovery_run_id INTEGER NOT NULL,
        schema_version INTEGER NOT NULL,
        name TEXT NOT NULL,
        modes_json TEXT NOT NULL DEFAULT '[]',
        required INTEGER NOT NULL DEFAULT 0,
        configuration_reference TEXT NOT NULL DEFAULT '',
        steps_json TEXT NOT NULL DEFAULT '[]',
        confidence_score INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS smart_data_auth_flows_owner_route_idx
        ON smart_data_auth_flows (owner_user_id, route_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS smart_data_prerequisites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_id TEXT NOT NULL UNIQUE,
        snapshot_id INTEGER NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
        route_id INTEGER NOT NULL REFERENCES smart_data_routes (id) ON DELETE CASCADE,
        owner_user_id INTEGER NOT NULL,
        project_id INTEGER NOT NULL,
        discovery_run_id INTEGER NOT NULL,
        schema_version INTEGER NOT NULL,
        resource TEXT NOT NULL,
        field TEXT NOT NULL DEFAULT '',
        required INTEGER NOT NULL DEFAULT 1,
        placeholder TEXT NOT NULL DEFAULT '',
        reason TEXT NOT NULL DEFAULT '',
        confidence_score INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS smart_data_prerequisites_owner_route_idx
        ON smart_data_prerequisites (owner_user_id, route_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS smart_data_runtime_variables (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_id TEXT NOT NULL UNIQUE,
        snapshot_id INTEGER NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
        route_id INTEGER NOT NULL REFERENCES smart_data_routes (id) ON DELETE CASCADE,
        owner_user_id INTEGER NOT NULL,
        project_id INTEGER NOT NULL,
        discovery_run_id INTEGER NOT NULL,
        schema_version INTEGER NOT NULL,
        name TEXT NOT NULL,
        source_step TEXT NOT NULL,
        extraction TEXT NOT NULL,
        target_type TEXT NOT NULL DEFAULT 'string',
        secret INTEGER NOT NULL DEFAULT 0,
        confidence_score INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS smart_data_runtime_variables_owner_route_idx
        ON smart_data_runtime_variables (owner_user_id, route_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS smart_data_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_id TEXT NOT NULL UNIQUE,
        snapshot_id INTEGER NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
        route_id INTEGER NOT NULL REFERENCES smart_data_routes (id) ON DELETE CASCADE,
        owner_user_id INTEGER NOT NULL,
        project_id INTEGER NOT NULL,
        discovery_run_id INTEGER NOT NULL,
        schema_version INTEGER NOT NULL,
        name TEXT NOT NULL,
        kind TEXT NOT NULL,
        route_reference TEXT NOT NULL,
        produces_json TEXT NOT NULL DEFAULT '[]',
        requires_approval INTEGER NOT NULL DEFAULT 0,
        same_run_only INTEGER NOT NULL DEFAULT 1,
        confidence_score INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS smart_data_actions_owner_route_idx
        ON smart_data_actions (owner_user_id, route_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS smart_data_fixtures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_id TEXT NOT NULL UNIQUE,
        snapshot_id INTEGER NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
        owner_user_id INTEGER NOT NULL,
        project_id INTEGER NOT NULL,
        discovery_run_id INTEGER NOT NULL,
        schema_version INTEGER NOT NULL,
        name TEXT NOT NULL,
        source_type TEXT NOT NULL,
        values_json TEXT NOT NULL DEFAULT '{}',
        contains_secrets INTEGER NOT NULL DEFAULT 0,
        confidence_score INTEGER NOT NULL DEFAULT 0,
        evidence_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS smart_data_fixtures_owner_snapshot_idx
        ON smart_data_fixtures (owner_user_id, snapshot_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS smart_data_graph_nodes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_id TEXT NOT NULL UNIQUE,
        snapshot_id INTEGER NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
        route_id INTEGER REFERENCES smart_data_routes (id) ON DELETE CASCADE,
        owner_user_id INTEGER NOT NULL,
        project_id INTEGER NOT NULL,
        discovery_run_id INTEGER NOT NULL,
        schema_version INTEGER NOT NULL,
        node_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        label TEXT NOT NULL,
        route_reference TEXT NOT NULL DEFAULT '',
        required INTEGER NOT NULL DEFAULT 1,
        requires_approval INTEGER NOT NULL DEFAULT 0,
        same_run_only INTEGER NOT NULL DEFAULT 0,
        created_by_node_id TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        UNIQUE (owner_user_id, snapshot_id, node_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS smart_data_graph_nodes_owner_snapshot_idx
        ON smart_data_graph_nodes (owner_user_id, snapshot_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS smart_data_graph_edges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_id TEXT NOT NULL UNIQUE,
        snapshot_id INTEGER NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
        owner_user_id INTEGER NOT NULL,
        project_id INTEGER NOT NULL,
        discovery_run_id INTEGER NOT NULL,
        schema_version INTEGER NOT NULL,
        source_node_id TEXT NOT NULL,
        target_node_id TEXT NOT NULL,
        relationship TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE (owner_user_id, snapshot_id, source_node_id, target_node_id, relationship)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS smart_data_graph_edges_owner_snapshot_idx
        ON smart_data_graph_edges (owner_user_id, snapshot_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS smart_data_graph_bindings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_id TEXT NOT NULL UNIQUE,
        snapshot_id INTEGER NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
        owner_user_id INTEGER NOT NULL,
        project_id INTEGER NOT NULL,
        discovery_run_id INTEGER NOT NULL,
        schema_version INTEGER NOT NULL,
        variable_name TEXT NOT NULL,
        source_step TEXT NOT NULL,
        extraction TEXT NOT NULL,
        target_type TEXT NOT NULL DEFAULT 'string',
        secret INTEGER NOT NULL DEFAULT 0,
        producer_node_id TEXT NOT NULL,
        consumer_node_id TEXT NOT NULL,
        placeholder TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE (owner_user_id, snapshot_id, variable_name, producer_node_id, consumer_node_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS smart_data_graph_bindings_owner_snapshot_idx
        ON smart_data_graph_bindings (owner_user_id, snapshot_id)
    """,
)


def existing_tables(engine: Engine) -> set[str]:
    return set(inspect(engine).get_table_names())


def historical_api_table_counts(engine: Engine) -> dict[str, int]:
    present = existing_tables(engine)
    counts: dict[str, int] = {}
    with engine.connect() as connection:
        for name in HISTORICAL_API_TABLES:
            if name not in present:
                continue
            counts[name] = int(
                connection.execute(text(f'SELECT COUNT(*) FROM "{name}"')).scalar_one()
            )
    return counts


def smart_data_table_names_present(engine: Engine) -> tuple[str, ...]:
    present = existing_tables(engine)
    return tuple(name for name in SMART_DATA_TABLES if name in present)


def apply_forward(engine: Engine) -> None:
    dialect = engine.dialect.name
    if dialect == "postgresql":
        sql = (MIGRATIONS_DIR / "forward.sql").read_text(encoding="utf-8")
        with engine.begin() as connection:
            connection.exec_driver_sql(sql)
        return
    if dialect == "sqlite":
        with engine.begin() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys = ON")
            for statement in _SQLITE_FORWARD:
                connection.exec_driver_sql(statement)
        return
    raise ValueError(f"Unsupported dialect for {PATCH_ID}: {dialect}")


def apply_rollback(engine: Engine) -> None:
    sql = (MIGRATIONS_DIR / "rollback.sql").read_text(encoding="utf-8")
    statements = [
        line.strip()
        for line in sql.splitlines()
        if line.strip() and not line.strip().startswith("--")
    ]
    with engine.begin() as connection:
        if engine.dialect.name == "sqlite":
            connection.exec_driver_sql("PRAGMA foreign_keys = ON")
        for statement in statements:
            if engine.dialect.name == "sqlite":
                statement = statement.replace(" CASCADE", "").rstrip(";")
            connection.exec_driver_sql(statement)


def rollback_targets() -> tuple[str, ...]:
    sql = (MIGRATIONS_DIR / "rollback.sql").read_text(encoding="utf-8")
    names = []
    for line in sql.splitlines():
        stripped = line.strip().upper()
        if stripped.startswith("DROP TABLE IF EXISTS SMART_DATA_"):
            raw = line.strip().split()[4]
            names.append(raw.lower())
    return tuple(names)
