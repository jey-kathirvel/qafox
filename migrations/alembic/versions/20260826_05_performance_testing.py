"""Add k6 artifacts, cancellation, and normalized performance metrics."""

from alembic import op
import sqlalchemy as sa

revision = "20260826_05"
down_revision = "20260826_04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("quality_test_runs", sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table(
        "performance_test_artifacts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("public_id", sa.String(36), nullable=False, unique=True),
        sa.Column("test_run_id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=False),
        sa.Column("target_url", sa.String(2000), nullable=False),
        sa.Column("authorization_confirmed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authorization_confirmed_by", sa.Integer(), nullable=False),
        sa.Column("generator_version", sa.String(30), nullable=False),
        sa.Column("script_sha256", sa.String(64), nullable=False),
        sa.Column("script_text", sa.Text(), nullable=False),
        sa.Column("configuration_json", sa.JSON(), nullable=False),
        sa.Column("metric_map_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("test_run_id", name="performance_artifacts_test_run_key"),
    )
    op.create_index("performance_artifacts_owner_project_idx", "performance_test_artifacts", ["owner_user_id", "project_id", "created_at"])
    op.create_table(
        "performance_test_results",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("public_id", sa.String(36), nullable=False, unique=True),
        sa.Column("test_run_id", sa.Integer(), nullable=False),
        sa.Column("artifact_id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("tool_version", sa.String(100), nullable=False),
        sa.Column("requests", sa.Integer(), nullable=False),
        sa.Column("errors", sa.Integer(), nullable=False),
        sa.Column("error_rate", sa.Float(), nullable=False),
        sa.Column("requests_per_second", sa.Float(), nullable=False),
        sa.Column("duration_avg_ms", sa.Float(), nullable=False),
        sa.Column("duration_min_ms", sa.Float(), nullable=False),
        sa.Column("duration_max_ms", sa.Float(), nullable=False),
        sa.Column("duration_p50_ms", sa.Float(), nullable=False),
        sa.Column("duration_p90_ms", sa.Float(), nullable=False),
        sa.Column("duration_p95_ms", sa.Float(), nullable=False),
        sa.Column("duration_p99_ms", sa.Float(), nullable=False),
        sa.Column("data_received_bytes", sa.Integer(), nullable=False),
        sa.Column("data_sent_bytes", sa.Integer(), nullable=False),
        sa.Column("vus_max", sa.Integer(), nullable=False),
        sa.Column("raw_summary_json", sa.JSON(), nullable=False),
        sa.Column("error_message", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("test_run_id", name="performance_results_test_run_key"),
    )
    op.create_index("performance_results_owner_project_idx", "performance_test_results", ["owner_user_id", "project_id", "created_at"])
    op.create_table(
        "performance_endpoint_metrics",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("result_id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=False),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("path", sa.String(2000), nullable=False),
        sa.Column("requests", sa.Integer(), nullable=False),
        sa.Column("errors", sa.Integer(), nullable=False),
        sa.Column("error_rate", sa.Float(), nullable=False),
        sa.Column("duration_avg_ms", sa.Float(), nullable=False),
        sa.Column("duration_min_ms", sa.Float(), nullable=False),
        sa.Column("duration_max_ms", sa.Float(), nullable=False),
        sa.Column("duration_p50_ms", sa.Float(), nullable=False),
        sa.Column("duration_p90_ms", sa.Float(), nullable=False),
        sa.Column("duration_p95_ms", sa.Float(), nullable=False),
        sa.Column("duration_p99_ms", sa.Float(), nullable=False),
        sa.UniqueConstraint("result_id", "method", "path", name="performance_endpoint_result_route_key"),
    )
    op.create_index("performance_endpoint_owner_project_idx", "performance_endpoint_metrics", ["owner_user_id", "project_id"])


def downgrade() -> None:
    op.drop_index("performance_endpoint_owner_project_idx", table_name="performance_endpoint_metrics")
    op.drop_table("performance_endpoint_metrics")
    op.drop_index("performance_results_owner_project_idx", table_name="performance_test_results")
    op.drop_table("performance_test_results")
    op.drop_index("performance_artifacts_owner_project_idx", table_name="performance_test_artifacts")
    op.drop_table("performance_test_artifacts")
    op.drop_column("quality_test_runs", "cancel_requested")
