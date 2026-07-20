"""MEM-003 lossless memory merge lineage and idempotent operation receipts."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0017_mem003_memory_deduplication"
down_revision = "0016_mem002_memory_provenance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Permit historical merged snapshots and add append-only merge authority."""
    with op.batch_alter_table("memories", recreate="always") as batch:
        batch.drop_constraint("ck_memory_mem001_status", type_="check")
        batch.drop_constraint("ck_memory_mem001_versions", type_="check")
        batch.create_check_constraint(
            "ck_memory_status",
            "status IN ('active','merged') AND (status<>'merged' OR recorded_to IS NOT NULL)",
        )
        batch.create_check_constraint(
            "ck_memory_versions",
            "current_revision=1 AND aggregate_version>=1",
        )

    op.create_table(
        "memory_deduplication_operations",
        sa.Column("idempotency_key", sa.LargeBinary(32), primary_key=True),
        sa.Column("operation_id", sa.Text(), nullable=False, unique=True),
        sa.Column(
            "requested_memory_id",
            sa.Text(),
            sa.ForeignKey("memories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "survivor_memory_id",
            sa.Text(),
            sa.ForeignKey("memories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "actor_id",
            sa.Text(),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "grant_id",
            sa.Text(),
            sa.ForeignKey("scope_grants.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("correlation_id", sa.Text(), nullable=False),
        sa.Column("causation_id", sa.Text(), nullable=False),
        sa.Column("mode", sa.Text(), nullable=True),
        sa.Column("policy_version", sa.Text(), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("result_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("requested_at", sa.BigInteger(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "mode IS NULL OR mode IN ('exact','semantic')", name="ck_memory_deduplication_mode"
        ),
        sa.CheckConstraint(
            "json_valid(result_json) AND length(result_sha256)=32",
            name="ck_memory_deduplication_result",
        ),
        sa.CheckConstraint("requested_at<=completed_at", name="ck_memory_deduplication_time"),
    )
    op.create_index(
        "ix_memory_deduplication_target",
        "memory_deduplication_operations",
        ["brain_id", "requested_memory_id", "completed_at"],
    )

    op.create_table(
        "memory_redirects",
        sa.Column(
            "source_memory_id",
            sa.Text(),
            sa.ForeignKey("memories.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "survivor_memory_id",
            sa.Text(),
            sa.ForeignKey("memories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "operation_id",
            sa.Text(),
            sa.ForeignKey("memory_deduplication_operations.operation_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("mode", sa.Text(), nullable=False),
        sa.Column("policy_version", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "source_memory_id<>survivor_memory_id", name="ck_memory_redirect_distinct"
        ),
        sa.CheckConstraint("mode IN ('exact','semantic')", name="ck_memory_redirect_mode"),
    )
    op.create_index(
        "ix_memory_redirect_survivor",
        "memory_redirects",
        ["survivor_memory_id", "source_memory_id"],
    )

    op.create_table(
        "memory_merge_evidence",
        sa.Column(
            "survivor_memory_id",
            sa.Text(),
            sa.ForeignKey("memories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "source_memory_id",
            sa.Text(),
            sa.ForeignKey("memories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("canonical_event_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column(
            "operation_id",
            sa.Text(),
            sa.ForeignKey("memory_deduplication_operations.operation_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("survivor_memory_id", "source_memory_id", "event_id"),
        sa.CheckConstraint(
            "survivor_memory_id<>source_memory_id", name="ck_memory_merge_evidence_distinct"
        ),
        sa.CheckConstraint(
            "length(canonical_event_sha256)=32", name="ck_memory_merge_evidence_digest"
        ),
    )
    op.create_index(
        "ix_memory_merge_evidence_event",
        "memory_merge_evidence",
        ["event_id", "survivor_memory_id"],
    )


def downgrade() -> None:
    """Refuse downgrade while any MEM-003 authority or merged state exists."""
    connection = op.get_bind()
    evidence = connection.execute(
        sa.text(
            "SELECT (SELECT COUNT(*) FROM memory_deduplication_operations) + "
            "(SELECT COUNT(*) FROM memory_redirects) + "
            "(SELECT COUNT(*) FROM memory_merge_evidence) + "
            "(SELECT COUNT(*) FROM memories WHERE status='merged' OR aggregate_version<>1)"
        )
    ).scalar_one()
    if evidence:
        message = "MEM-003 downgrade refused while merge evidence exists"
        raise RuntimeError(message)
    op.drop_index("ix_memory_merge_evidence_event", table_name="memory_merge_evidence")
    op.drop_table("memory_merge_evidence")
    op.drop_index("ix_memory_redirect_survivor", table_name="memory_redirects")
    op.drop_table("memory_redirects")
    op.drop_index("ix_memory_deduplication_target", table_name="memory_deduplication_operations")
    op.drop_table("memory_deduplication_operations")
    with op.batch_alter_table("memories", recreate="always") as batch:
        batch.drop_constraint("ck_memory_versions", type_="check")
        batch.drop_constraint("ck_memory_status", type_="check")
        batch.create_check_constraint(
            "ck_memory_mem001_versions", "current_revision=1 AND aggregate_version=1"
        )
        batch.create_check_constraint("ck_memory_mem001_status", "status='active'")
