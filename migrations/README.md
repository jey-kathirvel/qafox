# QAFox schema patches

Alembic now manages the universal quality-run and worker-job foundation. Existing
numbered SQL patches remain the historical migration path for legacy tables.

Apply current Alembic migrations with a least-privileged PostgreSQL role:

```bash
alembic upgrade head
```

The Alembic revisions are additive. They create `quality_test_runs`,
`worker_jobs`, normalized `project_sources` metadata, and versioned
`technology_detection_runs`, `security_scan_runs`, normalized
`security_findings`, inspectable k6 artifacts, cancellation state, and exact
overall/per-endpoint performance metrics without rewriting existing projects, discovery, API
execution, or smart-data tables. Existing
numbered SQL patches should still be applied as documented below when
provisioning the corresponding legacy feature.

## PATCH-QAFOX-004B1A-6

Additive owner-isolated persistence for normalized smart-data contracts and dependency graphs. It does not rewrite discovery, cases, plans, runs, or results.

### Before migration

```bash
# Schema-only backup (no table data from customer projects is required for rollback of this patch)
pg_dump --schema-only --no-owner --no-privileges \
  --table=smart_data_snapshots \
  --table=smart_data_routes \
  --table=smart_data_fields \
  --table=smart_data_constraints \
  --table=smart_data_auth_flows \
  --table=smart_data_prerequisites \
  --table=smart_data_runtime_variables \
  --table=smart_data_actions \
  --table=smart_data_fixtures \
  --table=smart_data_graph_nodes \
  --table=smart_data_graph_edges \
  --table=smart_data_graph_bindings \
  "$DATABASE_URL" > /tmp/qafox-004b1a6-schema-before.sql 2>/dev/null || true

pg_dump --schema-only --no-owner --no-privileges "$DATABASE_URL" \
  > "/tmp/qafox-schema-$(date -u +%Y%m%d-%H%M%S).sql"
```

Record historical counts (Python, skips tables that do not exist):

```bash
PYTHONPATH=. python -c \
  'from sqlalchemy import create_engine; from app.smart_data.migrate import historical_api_table_counts; import os, json; e=create_engine(os.environ["DATABASE_URL"]); print(json.dumps(historical_api_table_counts(e), indent=2))'
```

### Forward

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/004B1A-6/forward.sql
```

The forward script is idempotent (`IF NOT EXISTS` / conditional foreign key).

### Rollback

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/004B1A-6/rollback.sql
```

Rollback drops only `smart_data_*` tables. Re-check historical counts; they must match the pre-migration recording.

This patch does not consume execution plans or backfill inventory.

## PATCH-QAFOX-004B1A-8

Runtime orchestration is stored inside the immutable execution-plan JSON (`orchestration`). It does not rewrite historical plans, runs, or results. No additional tables are required. Existing v1 plans continue to execute as independent requests.

## PATCH-QAFOX-004B1A-9

Contract, schema, security, and performance assertions are stored inside immutable case snapshots. No additional tables are required. Historical plans without an `assertions` list receive default status, security, and duration checks at runtime.
