"""GRA-006 external graph migration and integrity repair evidence.

Revision ID: 0025_gra006_graph_integrity
Revises: 0024_gra005_contradictions
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0025_gra006_graph_integrity"
down_revision = "0024_gra005_contradictions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Install append-only migration snapshots, findings, and repair authority."""
    op.create_table(
        "graph_migration_snapshots",
        sa.Column("operation_id", sa.Text(), nullable=False),
        sa.Column("snapshot_version", sa.Integer(), nullable=False),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "principal_id",
            sa.Text(),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("migration_id", sa.Text(), nullable=False),
        sa.Column("migration_checksum", sa.LargeBinary(32), nullable=False),
        sa.Column("source_watermark", sa.Integer(), nullable=False),
        sa.Column("batch_size", sa.Integer(), nullable=False),
        sa.Column("cursor", sa.Integer(), nullable=False),
        sa.Column("scanned_count", sa.Integer(), nullable=False),
        sa.Column("changed_count", sa.Integer(), nullable=False),
        sa.Column("quarantined_count", sa.Integer(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("started_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("snapshot_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("operation_id", "snapshot_version"),
        sa.UniqueConstraint(
            "operation_id", "snapshot_digest", name="uq_graph_migration_snapshot_digest"
        ),
        sa.CheckConstraint(
            "snapshot_version>=0 AND source_watermark>=0 AND batch_size BETWEEN 1 AND 4096",
            name="ck_graph_migration_bounds",
        ),
        sa.CheckConstraint(
            "cursor>=0 AND cursor<=source_watermark", name="ck_graph_migration_cursor"
        ),
        sa.CheckConstraint(
            "scanned_count>=0 AND changed_count>=0 AND quarantined_count>=0 "
            "AND changed_count+quarantined_count<=scanned_count",
            name="ck_graph_migration_counts",
        ),
        sa.CheckConstraint(
            "state IN ('running','paused','validating','completed','failed')",
            name="ck_graph_migration_state",
        ),
        sa.CheckConstraint(
            "length(scope_fingerprint)=32 AND length(migration_checksum)=32 "
            "AND length(snapshot_digest)=32",
            name="ck_graph_migration_digests",
        ),
    )
    op.create_index(
        "ix_graph_migration_latest",
        "graph_migration_snapshots",
        ["brain_id", "operation_id", "snapshot_version"],
    )
    op.create_table(
        "graph_integrity_findings",
        sa.Column("finding_id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "project_id",
            sa.Text(),
            sa.ForeignKey("projects.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "principal_id",
            sa.Text(),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("projection_kind", sa.Text(), nullable=False),
        sa.Column("projection_id", sa.Text(), nullable=False),
        sa.Column("canonical_id", sa.Text(), nullable=True),
        sa.Column("observed_generation_id", sa.LargeBinary(32), nullable=False),
        sa.Column("expected_generation_id", sa.LargeBinary(32), nullable=False),
        sa.Column("projection_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("checked_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "projection_id",
            "kind",
            "expected_generation_id",
            "checked_at",
            name="uq_graph_integrity_observation",
        ),
        sa.CheckConstraint(
            "kind IN ('unsupported_assertion','orphan_vector','orphan_edge',"
            "'invalid_temporal_range','scope_mismatch','stale_generation')",
            name="ck_graph_integrity_kind",
        ),
        sa.CheckConstraint(
            "projection_kind IN ('assertion','edge','vector')",
            name="ck_graph_integrity_projection_kind",
        ),
        sa.CheckConstraint(
            "length(finding_id)=64 AND length(scope_fingerprint)=32 "
            "AND length(observed_generation_id)=32 "
            "AND length(expected_generation_id)=32 AND length(projection_digest)=32",
            name="ck_graph_integrity_finding_digests",
        ),
    )
    op.create_index(
        "ix_graph_integrity_scope",
        "graph_integrity_findings",
        ["brain_id", "project_id", "repository_id", "checked_at"],
    )
    op.create_table(
        "graph_integrity_repairs",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column(
            "finding_id",
            sa.Text(),
            sa.ForeignKey("graph_integrity_findings.finding_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "principal_id",
            sa.Text(),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("approval_id", sa.Text(), nullable=True),
        sa.Column("repaired_at", sa.BigInteger(), nullable=False),
        sa.Column("repair_digest", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "action IN ('shadow_write','quarantine','destructive_rebuild')",
            name="ck_graph_repair_action",
        ),
        sa.CheckConstraint(
            "(action='destructive_rebuild' AND approval_id IS NOT NULL) "
            "OR (action!='destructive_rebuild' AND approval_id IS NULL)",
            name="ck_graph_repair_approval",
        ),
        sa.CheckConstraint(
            "length(scope_fingerprint)=32 AND length(repair_digest)=32",
            name="ck_graph_repair_digests",
        ),
    )
    for table in (
        "graph_migration_snapshots",
        "graph_integrity_findings",
        "graph_integrity_repairs",
    ):
        op.execute(
            f"CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} BEGIN "
            f"SELECT RAISE(ABORT, '{table} is immutable'); END"
        )
        op.execute(
            f"CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN "
            f"SELECT RAISE(ABORT, '{table} is immutable'); END"
        )


def downgrade() -> None:
    """Refuse evidence loss after any migration, finding, or repair was recorded."""
    connection = op.get_bind()
    checks = (
        "SELECT EXISTS(SELECT 1 FROM graph_migration_snapshots)",
        "SELECT EXISTS(SELECT 1 FROM graph_integrity_findings)",
        "SELECT EXISTS(SELECT 1 FROM graph_integrity_repairs)",
    )
    for statement in checks:
        if connection.execute(sa.text(statement)).scalar_one():
            message = "GRA-006 graph integrity history prevents destructive downgrade"
            raise RuntimeError(message)
    for table in (
        "graph_integrity_repairs",
        "graph_integrity_findings",
        "graph_migration_snapshots",
    ):
        op.drop_table(table)
