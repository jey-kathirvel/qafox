"""Add normalized security scan runs and findings."""

from alembic import op
import sqlalchemy as sa

revision = "20260826_04"
down_revision = "20260826_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_scan_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("public_id", sa.String(36), nullable=False, unique=True),
        sa.Column("test_run_id", sa.Integer()),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=False),
        sa.Column("scanner", sa.String(40), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("tool_version", sa.String(100), nullable=False),
        sa.Column("error_message", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index("security_scan_runs_owner_project_idx", "security_scan_runs", ["owner_user_id", "project_id", "created_at"])
    op.create_table(
        "security_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("public_id", sa.String(36), nullable=False, unique=True),
        sa.Column("scan_run_id", sa.Integer(), nullable=False),
        sa.Column("test_run_id", sa.Integer()),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("scanner", sa.String(40), nullable=False),
        sa.Column("rule_id", sa.String(500), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("category", sa.String(200), nullable=False),
        sa.Column("component", sa.String(1000), nullable=False),
        sa.Column("source_file", sa.String(2000)),
        sa.Column("source_line", sa.Integer()),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("cwe_json", sa.JSON(), nullable=False),
        sa.Column("owasp_json", sa.JSON(), nullable=False),
        sa.Column("details_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("scan_run_id", "fingerprint", name="security_findings_scan_fingerprint_key"),
    )
    op.create_index("security_findings_owner_project_idx", "security_findings", ["owner_user_id", "project_id", "severity"])


def downgrade() -> None:
    op.drop_index("security_findings_owner_project_idx", table_name="security_findings")
    op.drop_table("security_findings")
    op.drop_index("security_scan_runs_owner_project_idx", table_name="security_scan_runs")
    op.drop_table("security_scan_runs")
