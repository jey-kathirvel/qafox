-- PATCH-QAFOX-004B1A-6
-- Additive, idempotent persistence for normalized smart-data contracts.
-- Does not alter api_inventory, api_test_cases, execution plans, runs, or results.

CREATE TABLE IF NOT EXISTS smart_data_snapshots (
    id BIGSERIAL PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    owner_user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    discovery_run_id BIGINT NOT NULL,
    schema_version INTEGER NOT NULL,
    adapter_names_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'persisted',
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT smart_data_snapshots_owner_run_unique
        UNIQUE (owner_user_id, project_id, discovery_run_id),
    CONSTRAINT smart_data_snapshots_run_unique
        UNIQUE (discovery_run_id)
);

CREATE INDEX IF NOT EXISTS smart_data_snapshots_owner_project_idx
    ON smart_data_snapshots (owner_user_id, project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS smart_data_routes (
    id BIGSERIAL PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    snapshot_id BIGINT NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
    owner_user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    discovery_run_id BIGINT NOT NULL,
    schema_version INTEGER NOT NULL,
    http_method TEXT NOT NULL,
    endpoint_path TEXT NOT NULL,
    framework TEXT NOT NULL,
    operation_id TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    confidence_score INTEGER NOT NULL DEFAULT 0,
    warnings_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    contract_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT smart_data_routes_owner_snapshot_route_unique
        UNIQUE (owner_user_id, snapshot_id, http_method, endpoint_path, framework)
);

CREATE INDEX IF NOT EXISTS smart_data_routes_owner_project_idx
    ON smart_data_routes (owner_user_id, project_id, discovery_run_id);

CREATE INDEX IF NOT EXISTS smart_data_routes_owner_snapshot_idx
    ON smart_data_routes (owner_user_id, snapshot_id);

CREATE TABLE IF NOT EXISTS smart_data_fields (
    id BIGSERIAL PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    snapshot_id BIGINT NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
    route_id BIGINT NOT NULL REFERENCES smart_data_routes (id) ON DELETE CASCADE,
    owner_user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    discovery_run_id BIGINT NOT NULL,
    schema_version INTEGER NOT NULL,
    schema_name TEXT NOT NULL DEFAULT '',
    schema_role TEXT NOT NULL,
    response_status TEXT NOT NULL DEFAULT '',
    field_path TEXT NOT NULL,
    name TEXT NOT NULL,
    semantic_type TEXT NOT NULL,
    data_type TEXT NOT NULL DEFAULT 'unknown',
    required BOOLEAN NOT NULL DEFAULT FALSE,
    nullable BOOLEAN NOT NULL DEFAULT FALSE,
    secret BOOLEAN NOT NULL DEFAULT FALSE,
    editable BOOLEAN NOT NULL DEFAULT TRUE,
    minimum DOUBLE PRECISION,
    maximum DOUBLE PRECISION,
    min_length INTEGER,
    max_length INTEGER,
    pattern TEXT NOT NULL DEFAULT '',
    format TEXT NOT NULL DEFAULT '',
    enum_values_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    generation_strategy TEXT NOT NULL DEFAULT '',
    generated_value_json JSONB,
    dependency_json JSONB,
    confidence_score INTEGER NOT NULL DEFAULT 0,
    source_file TEXT NOT NULL DEFAULT '',
    source_line INTEGER,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS smart_data_fields_owner_snapshot_idx
    ON smart_data_fields (owner_user_id, snapshot_id, route_id);

CREATE TABLE IF NOT EXISTS smart_data_constraints (
    id BIGSERIAL PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    snapshot_id BIGINT NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
    field_id BIGINT NOT NULL REFERENCES smart_data_fields (id) ON DELETE CASCADE,
    owner_user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    discovery_run_id BIGINT NOT NULL,
    schema_version INTEGER NOT NULL,
    name TEXT NOT NULL,
    value_json JSONB,
    message TEXT NOT NULL DEFAULT '',
    confidence_score INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS smart_data_constraints_owner_field_idx
    ON smart_data_constraints (owner_user_id, field_id);

CREATE TABLE IF NOT EXISTS smart_data_auth_flows (
    id BIGSERIAL PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    snapshot_id BIGINT NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
    route_id BIGINT NOT NULL REFERENCES smart_data_routes (id) ON DELETE CASCADE,
    owner_user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    discovery_run_id BIGINT NOT NULL,
    schema_version INTEGER NOT NULL,
    name TEXT NOT NULL,
    modes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    required BOOLEAN NOT NULL DEFAULT FALSE,
    configuration_reference TEXT NOT NULL DEFAULT '',
    steps_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence_score INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS smart_data_auth_flows_owner_route_idx
    ON smart_data_auth_flows (owner_user_id, route_id);

CREATE TABLE IF NOT EXISTS smart_data_prerequisites (
    id BIGSERIAL PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    snapshot_id BIGINT NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
    route_id BIGINT NOT NULL REFERENCES smart_data_routes (id) ON DELETE CASCADE,
    owner_user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    discovery_run_id BIGINT NOT NULL,
    schema_version INTEGER NOT NULL,
    resource TEXT NOT NULL,
    field TEXT NOT NULL DEFAULT '',
    required BOOLEAN NOT NULL DEFAULT TRUE,
    placeholder TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    confidence_score INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS smart_data_prerequisites_owner_route_idx
    ON smart_data_prerequisites (owner_user_id, route_id);

CREATE TABLE IF NOT EXISTS smart_data_runtime_variables (
    id BIGSERIAL PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    snapshot_id BIGINT NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
    route_id BIGINT NOT NULL REFERENCES smart_data_routes (id) ON DELETE CASCADE,
    owner_user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    discovery_run_id BIGINT NOT NULL,
    schema_version INTEGER NOT NULL,
    name TEXT NOT NULL,
    source_step TEXT NOT NULL,
    extraction TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT 'string',
    secret BOOLEAN NOT NULL DEFAULT FALSE,
    confidence_score INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS smart_data_runtime_variables_owner_route_idx
    ON smart_data_runtime_variables (owner_user_id, route_id);

CREATE TABLE IF NOT EXISTS smart_data_actions (
    id BIGSERIAL PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    snapshot_id BIGINT NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
    route_id BIGINT NOT NULL REFERENCES smart_data_routes (id) ON DELETE CASCADE,
    owner_user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    discovery_run_id BIGINT NOT NULL,
    schema_version INTEGER NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    route_reference TEXT NOT NULL,
    produces_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    requires_approval BOOLEAN NOT NULL DEFAULT FALSE,
    same_run_only BOOLEAN NOT NULL DEFAULT TRUE,
    confidence_score INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS smart_data_actions_owner_route_idx
    ON smart_data_actions (owner_user_id, route_id);

CREATE TABLE IF NOT EXISTS smart_data_fixtures (
    id BIGSERIAL PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    snapshot_id BIGINT NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
    owner_user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    discovery_run_id BIGINT NOT NULL,
    schema_version INTEGER NOT NULL,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    values_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    contains_secrets BOOLEAN NOT NULL DEFAULT FALSE,
    confidence_score INTEGER NOT NULL DEFAULT 0,
    evidence_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS smart_data_fixtures_owner_snapshot_idx
    ON smart_data_fixtures (owner_user_id, snapshot_id);

CREATE TABLE IF NOT EXISTS smart_data_graph_nodes (
    id BIGSERIAL PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    snapshot_id BIGINT NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
    route_id BIGINT REFERENCES smart_data_routes (id) ON DELETE CASCADE,
    owner_user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    discovery_run_id BIGINT NOT NULL,
    schema_version INTEGER NOT NULL,
    node_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    label TEXT NOT NULL,
    route_reference TEXT NOT NULL DEFAULT '',
    required BOOLEAN NOT NULL DEFAULT TRUE,
    requires_approval BOOLEAN NOT NULL DEFAULT FALSE,
    same_run_only BOOLEAN NOT NULL DEFAULT FALSE,
    created_by_node_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT smart_data_graph_nodes_owner_node_unique
        UNIQUE (owner_user_id, snapshot_id, node_id)
);

CREATE INDEX IF NOT EXISTS smart_data_graph_nodes_owner_snapshot_idx
    ON smart_data_graph_nodes (owner_user_id, snapshot_id);

CREATE TABLE IF NOT EXISTS smart_data_graph_edges (
    id BIGSERIAL PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    snapshot_id BIGINT NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
    owner_user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    discovery_run_id BIGINT NOT NULL,
    schema_version INTEGER NOT NULL,
    source_node_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    relationship TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT smart_data_graph_edges_owner_edge_unique
        UNIQUE (owner_user_id, snapshot_id, source_node_id, target_node_id, relationship)
);

CREATE INDEX IF NOT EXISTS smart_data_graph_edges_owner_snapshot_idx
    ON smart_data_graph_edges (owner_user_id, snapshot_id);

CREATE TABLE IF NOT EXISTS smart_data_graph_bindings (
    id BIGSERIAL PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    snapshot_id BIGINT NOT NULL REFERENCES smart_data_snapshots (id) ON DELETE CASCADE,
    owner_user_id BIGINT NOT NULL,
    project_id BIGINT NOT NULL,
    discovery_run_id BIGINT NOT NULL,
    schema_version INTEGER NOT NULL,
    variable_name TEXT NOT NULL,
    source_step TEXT NOT NULL,
    extraction TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT 'string',
    secret BOOLEAN NOT NULL DEFAULT FALSE,
    producer_node_id TEXT NOT NULL,
    consumer_node_id TEXT NOT NULL,
    placeholder TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT smart_data_graph_bindings_owner_binding_unique
        UNIQUE (owner_user_id, snapshot_id, variable_name, producer_node_id, consumer_node_id)
);

CREATE INDEX IF NOT EXISTS smart_data_graph_bindings_owner_snapshot_idx
    ON smart_data_graph_bindings (owner_user_id, snapshot_id);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = 'api_discovery_runs'
    ) AND NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'smart_data_snapshots_discovery_run_fk'
    ) THEN
        ALTER TABLE smart_data_snapshots
            ADD CONSTRAINT smart_data_snapshots_discovery_run_fk
            FOREIGN KEY (discovery_run_id)
            REFERENCES api_discovery_runs (id);
    END IF;
END
$$;
