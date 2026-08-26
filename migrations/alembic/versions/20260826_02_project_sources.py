"""Add normalized project source and authorization metadata."""

from alembic import op
import sqlalchemy as sa

revision = "20260826_02"
down_revision = "20260826_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "project_sources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=False),
        sa.Column("source_type", sa.String(20), nullable=False),
        sa.Column("repository_url", sa.String(1000)),
        sa.Column("default_branch", sa.String(200)),
        sa.Column("commit_sha", sa.String(64)),
        sa.Column("authorization_confirmed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authorization_confirmed_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("project_id", name="project_sources_project_key"),
    )
    op.create_index(
        "project_sources_owner_idx", "project_sources", ["owner_user_id", "created_at"]
    )


def downgrade() -> None:
    op.drop_index("project_sources_owner_idx", table_name="project_sources")
    op.drop_table("project_sources")
