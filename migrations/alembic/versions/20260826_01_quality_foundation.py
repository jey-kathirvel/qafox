"""Add universal quality test runs and durable worker jobs."""

from alembic import op
import sqlalchemy as sa

revision = "20260826_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "quality_test_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("public_id", sa.String(36), nullable=False, unique=True),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=False),
        sa.Column("profile", sa.String(30), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("progress", sa.Float(), nullable=False, server_default="0"),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "quality_test_runs_project_created_idx",
        "quality_test_runs",
        ["owner_user_id", "project_id", "created_at"],
    )
    op.create_table(
        "worker_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("public_id", sa.String(36), nullable=False, unique=True),
        sa.Column("test_run_id", sa.Integer(), nullable=False),
        sa.Column("job_type", sa.String(80), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("worker_id", sa.String(150)),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("error_message", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("test_run_id", name="worker_jobs_test_run_key"),
    )
    op.create_index("worker_jobs_claim_idx", "worker_jobs", ["status", "created_at"])


def downgrade() -> None:
    op.drop_index("worker_jobs_claim_idx", table_name="worker_jobs")
    op.drop_table("worker_jobs")
    op.drop_index("quality_test_runs_project_created_idx", table_name="quality_test_runs")
    op.drop_table("quality_test_runs")
