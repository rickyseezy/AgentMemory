"""MEM-004 explicit correction assertions, precedence lineage, and receipts.

Revision ID: 0018_mem004_memory_correction
Revises: 0017_mem003_memory_deduplication
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0018_mem004_memory_correction"
down_revision = "0017_mem003_memory_deduplication"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add correction lifecycle states and immutable explicit-user assertions."""
    with op.batch_alter_table("memories", recreate="always") as batch:
        batch.drop_constraint("ck_memory_status", type_="check")
        batch.create_check_constraint(
            "ck_memory_status",
            "status IN ('active','merged','disputed','superseded') AND "
            "(status<>'merged' OR recorded_to IS NOT NULL)",
        )

    op.create_table(
        "memory_correction_operations",
        sa.Column("idempotency_key", sa.LargeBinary(32), primary_key=True),
        sa.Column("operation_id", sa.Text(), nullable=False, unique=True),
        sa.Column("request_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("requested_assertion_id", sa.Text(), nullable=False),
        sa.Column(
            "root_memory_id",
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
        sa.Column("policy_version", sa.Text(), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("result_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("requested_at", sa.BigInteger(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(request_sha256)=32 AND length(result_sha256)=32 AND json_valid(result_json)",
            name="ck_memory_correction_operation_integrity",
        ),
        sa.CheckConstraint(
            "requested_at<=completed_at", name="ck_memory_correction_operation_time"
        ),
    )
    op.create_index(
        "ix_memory_correction_operation_target",
        "memory_correction_operations",
        ["brain_id", "requested_assertion_id", "completed_at"],
    )

    op.create_table(
        "memory_corrections",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "root_memory_id",
            sa.Text(),
            sa.ForeignKey("memories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("source_assertion_id", sa.Text(), nullable=False),
        sa.Column(
            "parent_correction_id",
            sa.Text(),
            sa.ForeignKey("memory_corrections.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "operation_id",
            sa.Text(),
            sa.ForeignKey("memory_correction_operations.operation_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("memory_class", sa.Text(), nullable=False),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("project_id", sa.Text(), nullable=False),
        sa.Column("repository_id", sa.Text(), nullable=False),
        sa.Column("checkout_id", sa.Text(), nullable=True),
        sa.Column("scope_json", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("statement_json", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("relation", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
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
        sa.Column("valid_from", sa.BigInteger(), nullable=False),
        sa.Column("valid_to", sa.BigInteger(), nullable=True),
        sa.Column("recorded_from", sa.BigInteger(), nullable=False),
        sa.Column("recorded_to", sa.BigInteger(), nullable=True),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("retention_policy_id", sa.Text(), nullable=False),
        sa.Column("policy_version", sa.Text(), nullable=False),
        sa.Column("aggregate_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "id<>root_memory_id AND id<>source_assertion_id",
            name="ck_memory_correction_distinct",
        ),
        sa.CheckConstraint(
            "(parent_correction_id IS NULL AND source_assertion_id=root_memory_id) OR "
            "parent_correction_id=source_assertion_id",
            name="ck_memory_correction_parent",
        ),
        sa.CheckConstraint(
            "memory_class IN ('decision','constraint','procedure','preference','lesson',"
            "'episode','unresolved_work')",
            name="ck_memory_correction_class",
        ),
        sa.CheckConstraint(
            "status IN ('active','disputed','superseded')",
            name="ck_memory_correction_status",
        ),
        sa.CheckConstraint(
            "relation IN ('supersedes','contradicts')",
            name="ck_memory_correction_relation",
        ),
        sa.CheckConstraint(
            "json_valid(scope_json) AND json_valid(statement_json) AND length(content_hash)=32",
            name="ck_memory_correction_content",
        ),
        sa.CheckConstraint(
            "classification IN ('public','internal','confidential','restricted','local_only')",
            name="ck_memory_correction_classification",
        ),
        sa.CheckConstraint(
            "valid_to IS NULL OR valid_from<valid_to",
            name="ck_memory_correction_valid_time",
        ),
        sa.CheckConstraint(
            "recorded_to IS NULL OR recorded_from<recorded_to",
            name="ck_memory_correction_recorded_time",
        ),
        sa.CheckConstraint("aggregate_version>=1", name="ck_memory_correction_version"),
    )
    op.create_index(
        "ix_memory_correction_history",
        "memory_corrections",
        ["root_memory_id", "recorded_from", "id"],
    )
    op.create_index(
        "ix_memory_correction_precedence",
        "memory_corrections",
        ["brain_id", "project_id", "repository_id", "checkout_id", "status"],
    )

    op.create_table(
        "memory_correction_evidence",
        sa.Column(
            "correction_id",
            sa.Text(),
            sa.ForeignKey("memory_corrections.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("canonical_event_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("correction_id", "event_id"),
        sa.CheckConstraint(
            "length(canonical_event_sha256)=32",
            name="ck_memory_correction_evidence_digest",
        ),
    )
    op.create_index(
        "ix_memory_correction_evidence_event",
        "memory_correction_evidence",
        ["event_id", "correction_id"],
    )

    op.execute(
        "CREATE TRIGGER memory_correction_immutable_fields "
        "BEFORE UPDATE OF root_memory_id,source_assertion_id,parent_correction_id,operation_id,"
        "memory_class,brain_id,project_id,repository_id,checkout_id,scope_json,statement_json,"
        "content_hash,relation,reason,actor_id,grant_id,valid_from,valid_to,recorded_from,classification,"
        "retention_policy_id,policy_version,created_at ON memory_corrections BEGIN "
        "SELECT RAISE(ABORT, 'memory correction assertion is immutable'); END"
    )
    op.execute(
        "CREATE TRIGGER memory_correction_evidence_immutable "
        "BEFORE UPDATE ON memory_correction_evidence BEGIN "
        "SELECT RAISE(ABORT, 'memory correction evidence is immutable'); END"
    )
    op.execute(
        "CREATE TRIGGER memory_correction_operation_immutable "
        "BEFORE UPDATE ON memory_correction_operations BEGIN "
        "SELECT RAISE(ABORT, 'memory correction receipt is immutable'); END"
    )


def downgrade() -> None:
    """Refuse downgrade while any correction receipt, assertion, evidence, or state exists."""
    connection = op.get_bind()
    evidence = connection.execute(
        sa.text(
            "SELECT (SELECT COUNT(*) FROM memory_correction_operations) + "
            "(SELECT COUNT(*) FROM memory_corrections) + "
            "(SELECT COUNT(*) FROM memory_correction_evidence) + "
            "(SELECT COUNT(*) FROM memories WHERE status IN ('disputed','superseded'))"
        )
    ).scalar_one()
    if evidence:
        message = "MEM-004 downgrade refused while correction evidence exists"
        raise RuntimeError(message)

    op.execute("DROP TRIGGER memory_correction_operation_immutable")
    op.execute("DROP TRIGGER memory_correction_evidence_immutable")
    op.execute("DROP TRIGGER memory_correction_immutable_fields")
    op.drop_index("ix_memory_correction_evidence_event", table_name="memory_correction_evidence")
    op.drop_table("memory_correction_evidence")
    op.drop_index("ix_memory_correction_precedence", table_name="memory_corrections")
    op.drop_index("ix_memory_correction_history", table_name="memory_corrections")
    op.drop_table("memory_corrections")
    op.drop_index(
        "ix_memory_correction_operation_target", table_name="memory_correction_operations"
    )
    op.drop_table("memory_correction_operations")
    with op.batch_alter_table("memories", recreate="always") as batch:
        batch.drop_constraint("ck_memory_status", type_="check")
        batch.create_check_constraint(
            "ck_memory_status",
            "status IN ('active','merged') AND (status<>'merged' OR recorded_to IS NOT NULL)",
        )
