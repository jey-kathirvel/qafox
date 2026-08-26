"""Add versioned technology detection persistence."""

from alembic import op
import sqlalchemy as sa

revision = "20260826_03"
down_revision = "20260826_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "technology_detection_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("public_id", sa.String(36), nullable=False, unique=True),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=False),
        sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column("detector_version", sa.String(30), nullable=False),
        sa.Column("primary_language", sa.String(100), nullable=False),
        sa.Column("report_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "project_id", "source_sha256", "detector_version",
            name="technology_detection_source_key",
        ),
    )
    op.create_index(
        "technology_detection_owner_project_idx",
        "technology_detection_runs",
        ["owner_user_id", "project_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "technology_detection_owner_project_idx",
        table_name="technology_detection_runs",
    )
    op.drop_table("technology_detection_runs")
