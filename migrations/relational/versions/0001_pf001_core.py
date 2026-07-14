"""PF-001 canonical Core bootstrap and readiness state.

Revision ID: 0001_pf001_core
Revises: None
"""

import sqlalchemy as sa
from alembic import op

revision = "0001_pf001_core"
down_revision = None
branch_labels = None
depends_on = None


def _timestamps():
    return (
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
    )


def upgrade() -> None:
    op.create_table(
        "installation_state",
        sa.Column("singleton_key", sa.Text(), primary_key=True),
        sa.Column("installation_id", sa.Text(), nullable=False, unique=True),
        sa.Column("owner_principal_id", sa.Text(), nullable=False),
        sa.Column("active_release_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("active_data_generation", sa.Text(), nullable=False),
        sa.Column("security_epoch", sa.Text(), nullable=False, server_default="1"),
        *_timestamps(),
        sa.CheckConstraint("singleton_key = 'local'", name="ck_installation_singleton"),
        sa.CheckConstraint(
            "length(active_release_digest) = 32", name="ck_installation_release_digest"
        ),
    )
    op.create_table(
        "brains",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("normalized_name", sa.Text(), nullable=False, unique=True),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("trust_class", sa.Text(), nullable=False, server_default="personal"),
        sa.Column("status", sa.Text(), nullable=False, server_default="active"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        *_timestamps(),
        sa.CheckConstraint("status IN ('active', 'deletion_pending')", name="ck_brains_status"),
    )
    op.create_table(
        "principals",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("local_subject_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="active"),
        *_timestamps(),
        sa.UniqueConstraint("local_subject_digest", "type", name="uq_principal_subject_type"),
        sa.CheckConstraint("length(local_subject_digest) = 32", name="ck_principal_subject_digest"),
        sa.CheckConstraint("type IN ('owner')", name="ck_principal_type"),
        sa.CheckConstraint("status IN ('active', 'revoked')", name="ck_principal_status"),
    )
    op.create_table(
        "scope_grants",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "principal_id",
            sa.Text(),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("valid_from", sa.BigInteger(), nullable=False),
        sa.Column("valid_to", sa.BigInteger(), nullable=True),
        *_timestamps(),
        sa.UniqueConstraint("principal_id", "brain_id", "role", name="uq_scope_grant"),
        sa.CheckConstraint("role IN ('owner')", name="ck_scope_grant_role"),
    )
    op.create_table(
        "audit_events",
        sa.Column("sequence", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("brain_id", sa.Text(), nullable=True),
        sa.Column("actor_id", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target_ref", sa.Text(), nullable=False),
        sa.Column("idempotency_key", sa.Text(), nullable=False, unique=True),
        sa.Column("before_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("after_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("previous_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("event_hash", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("length(event_hash) = 32", name="ck_audit_event_hash"),
        sa.CheckConstraint("length(previous_hash) = 32", name="ck_audit_previous_hash"),
    )
    op.create_table(
        "readiness_receipts",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column("release_id", sa.Text(), nullable=False),
        sa.Column("generation_id", sa.Text(), nullable=False),
        sa.Column("receipt_digest", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("record_json", sa.Text(), nullable=False),
        sa.Column("evaluated_at", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("length(receipt_digest) = 32", name="ck_readiness_receipt_digest"),
    )
    op.create_table(
        "active_release_stages",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column("pointer_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("readiness_receipt_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("stage_digest", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("pointer_record_json", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("committed_at", sa.BigInteger(), nullable=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("length(pointer_digest) = 32", name="ck_stage_pointer_digest"),
        sa.CheckConstraint(
            "length(readiness_receipt_digest) = 32", name="ck_stage_readiness_digest"
        ),
        sa.CheckConstraint("length(stage_digest) = 32", name="ck_stage_digest"),
        sa.CheckConstraint("state IN ('staged', 'committed')", name="ck_stage_state"),
        sa.CheckConstraint(
            "(state = 'staged' AND committed_at IS NULL) OR "
            "(state = 'committed' AND committed_at IS NOT NULL)",
            name="ck_stage_commit_time",
        ),
    )
    op.create_table(
        "active_release_pointers",
        sa.Column("singleton_key", sa.Text(), primary_key=True),
        sa.Column("installation_id", sa.Text(), nullable=False, unique=True),
        sa.Column("pointer_digest", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("pointer_record_json", sa.Text(), nullable=False),
        sa.Column("release_sequence", sa.Text(), nullable=False),
        sa.Column("resource_inventory_version", sa.Text(), nullable=False),
        sa.Column("security_epoch", sa.Text(), nullable=False),
        sa.Column("activated_at", sa.BigInteger(), nullable=False),
        *_timestamps(),
        sa.CheckConstraint("singleton_key = 'local'", name="ck_active_pointer_singleton"),
        sa.CheckConstraint("length(pointer_digest) = 32", name="ck_active_pointer_digest"),
    )
    op.create_table(
        "agent_events",
        sa.Column("event_id", sa.Text(), primary_key=True),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("payload_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("ingested_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("classification IN ('internal')", name="ck_smoke_event_classification"),
    )
    op.create_table(
        "outbox_messages",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "source_event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("topic", sa.Text(), nullable=False),
        sa.Column("message_key", sa.Text(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("source_event_id", "topic", name="uq_outbox_source_topic"),
        sa.CheckConstraint("status IN ('ready', 'completed')", name="ck_outbox_status"),
    )
    op.create_table(
        "smoke_memories",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("generation_id", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("deleted", sa.Boolean(), nullable=False, server_default=sa.false()),
        *_timestamps(),
        sa.CheckConstraint("length(content_hash) = 32", name="ck_smoke_content_hash"),
    )
    op.create_table(
        "deletion_tombstones",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("effective_at", sa.BigInteger(), nullable=False),
        sa.Column("purge_state", sa.Text(), nullable=False),
        sa.Column("restore_guard_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("brain_id", "target_type", "target_id_hash", name="uq_deletion_target"),
        sa.CheckConstraint(
            "purge_state IN ('tombstoned', 'completed')", name="ck_deletion_purge_state"
        ),
    )
    op.create_table(
        "jobs",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("idempotency_key", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("lease_owner", sa.Text(), nullable=True),
        sa.Column("lease_until", sa.BigInteger(), nullable=True),
        sa.Column("next_attempt_at", sa.BigInteger(), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint("kind", "idempotency_key", name="uq_jobs_idempotency"),
        sa.CheckConstraint(
            "state IN ('queued', 'leased', 'retry_scheduled', 'succeeded')", name="ck_jobs_state"
        ),
    )
    op.create_index("ix_jobs_lease_recovery", "jobs", ["state", "lease_until"])


def downgrade() -> None:
    op.drop_index("ix_jobs_lease_recovery", table_name="jobs")
    for table in (
        "jobs",
        "deletion_tombstones",
        "smoke_memories",
        "outbox_messages",
        "agent_events",
        "active_release_pointers",
        "active_release_stages",
        "readiness_receipts",
        "audit_events",
        "scope_grants",
        "principals",
        "brains",
        "installation_state",
    ):
        op.drop_table(table)
