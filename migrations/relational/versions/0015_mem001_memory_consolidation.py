"""MEM-001 indexed task evidence and evidence-backed memory consolidation.

Revision ID: 0015_mem001_memory_consolidation
Revises: 0014_ing006_schema_evolution
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0015_mem001_memory_consolidation"
down_revision = "0014_ing006_schema_evolution"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # One terminal AgentEvent may be consolidated again under a new immutable
    # extractor fingerprint. The complete consolidation key therefore participates
    # in outbox uniqueness while exact retries remain one effective message.
    with op.batch_alter_table("outbox_messages", recreate="always") as batch:
        batch.drop_constraint("uq_outbox_source_topic", type_="unique")
        batch.create_unique_constraint(
            "uq_outbox_source_topic_key",
            ["source_event_id", "topic", "message_key"],
        )

    op.create_table(
        "event_task_lineage",
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "principal_id",
            sa.Text(),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
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
            "checkout_id",
            sa.Text(),
            sa.ForeignKey("checkouts.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("session_id", sa.Text(), nullable=False),
        sa.Column("task_id", sa.Text(), nullable=False),
        sa.Column("correlation_id", sa.Text(), nullable=False),
        sa.Column("causation_id", sa.Text(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("retention_policy_id", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("canonical_event_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "classification IN ('public','internal','confidential','restricted','local_only')",
            name="ck_event_task_lineage_classification",
        ),
        sa.CheckConstraint(
            "length(canonical_event_sha256)=32",
            name="ck_event_task_lineage_digest",
        ),
        sa.CheckConstraint(
            "length(session_id)=36 AND length(task_id)=36 "
            "AND length(correlation_id)=36 AND length(causation_id)=36",
            name="ck_event_task_lineage_ids",
        ),
    )
    op.create_index(
        "ix_event_task_lineage_snapshot",
        "event_task_lineage",
        [
            "brain_id",
            "project_id",
            "repository_id",
            "checkout_id",
            "task_id",
            "occurred_at",
            "event_id",
        ],
    )
    op.create_index(
        "ix_event_task_lineage_terminal",
        "event_task_lineage",
        ["task_id", "event_type", "occurred_at", "event_id"],
    )
    op.create_index(
        "ix_event_schema_sources_ingested_order",
        "event_schema_sources",
        ["created_at", "event_id"],
    )

    op.create_table(
        "memory_task_lineage_backfills",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("cursor_created_at", sa.BigInteger(), nullable=True),
        sa.Column("cursor_event_id", sa.Text(), nullable=True),
        sa.Column("source_watermark_created_at", sa.BigInteger(), nullable=True),
        sa.Column("source_watermark_event_id", sa.Text(), nullable=True),
        sa.Column("scanned", sa.Integer(), nullable=False),
        sa.Column("indexed", sa.Integer(), nullable=False),
        sa.Column("ignored", sa.Integer(), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("last_error_code", sa.Text(), nullable=True),
        sa.Column("started_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "state IN ('pending','running','interrupted','completed')",
            name="ck_memory_lineage_backfill_state",
        ),
        sa.CheckConstraint(
            "scanned>=0 AND indexed>=0 AND ignored>=0 AND total>=0 "
            "AND scanned=indexed+ignored AND scanned<=total",
            name="ck_memory_lineage_backfill_counts",
        ),
        sa.CheckConstraint(
            "(cursor_created_at IS NULL)=(cursor_event_id IS NULL) "
            "AND (source_watermark_created_at IS NULL)=(source_watermark_event_id IS NULL)",
            name="ck_memory_lineage_backfill_cursors",
        ),
        sa.CheckConstraint(
            "state<>'completed' OR (scanned=total AND completed_at IS NOT NULL)",
            name="ck_memory_lineage_backfill_completion",
        ),
        sa.CheckConstraint(
            "last_error_code IS NULL OR last_error_code IN "
            "('dependency_unavailable','integrity_violation','interrupted')",
            name="ck_memory_lineage_backfill_error",
        ),
    )

    op.create_table(
        "memory_consolidations",
        sa.Column("idempotency_key", sa.LargeBinary(32), primary_key=True),
        sa.Column("operation_id", sa.Text(), nullable=False, unique=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
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
        sa.Column("task_id", sa.Text(), nullable=False),
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
            "checkout_id",
            sa.Text(),
            sa.ForeignKey("checkouts.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "source_terminal_event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("evidence_watermark_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("extractor_input_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("extractor_id", sa.Text(), nullable=False),
        sa.Column("extractor_version", sa.Text(), nullable=False),
        sa.Column("model_id", sa.Text(), nullable=False),
        sa.Column("model_revision", sa.Text(), nullable=False),
        sa.Column("output_schema", sa.Text(), nullable=False),
        sa.Column("extractor_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("promotion_policy_version", sa.Text(), nullable=False),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("retention_policy_id", sa.Text(), nullable=False),
        sa.Column("promoted", sa.Integer(), nullable=False),
        sa.Column("rejected", sa.Integer(), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("result_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("requested_at", sa.BigInteger(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "brain_id",
            "task_id",
            "evidence_watermark_sha256",
            "extractor_fingerprint",
            name="uq_memory_consolidation_identity",
        ),
        sa.CheckConstraint(
            "length(idempotency_key)=32 AND length(evidence_watermark_sha256)=32 "
            "AND length(extractor_input_sha256)=32 AND length(extractor_fingerprint)=32 "
            "AND length(result_sha256)=32",
            name="ck_memory_consolidation_digests",
        ),
        sa.CheckConstraint(
            "promoted BETWEEN 0 AND 32 AND rejected BETWEEN 0 AND 32 AND promoted+rejected<=32",
            name="ck_memory_consolidation_counts",
        ),
        sa.CheckConstraint("json_valid(result_json)", name="ck_memory_consolidation_result"),
        sa.CheckConstraint(
            "classification IN ('public','internal','confidential','restricted','local_only')",
            name="ck_memory_consolidation_classification",
        ),
        sa.CheckConstraint(
            "length(correlation_id)=36 AND length(causation_id)=36 AND requested_at<=completed_at",
            name="ck_memory_consolidation_command",
        ),
    )

    op.create_table(
        "memories",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("memory_class", sa.Text(), nullable=False),
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
            "checkout_id",
            sa.Text(),
            sa.ForeignKey("checkouts.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("scope_json", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("current_revision", sa.Integer(), nullable=False),
        sa.Column("valid_from", sa.BigInteger(), nullable=False),
        sa.Column("valid_to", sa.BigInteger(), nullable=True),
        sa.Column("recorded_from", sa.BigInteger(), nullable=False),
        sa.Column("recorded_to", sa.BigInteger(), nullable=True),
        sa.Column("confidence_json", sa.Text(), nullable=False),
        sa.Column("retention_policy_id", sa.Text(), nullable=False),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("aggregate_version", sa.Integer(), nullable=False),
        sa.Column("source_task_id", sa.Text(), nullable=False),
        sa.Column("extractor_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("content_hash", sa.LargeBinary(32), nullable=False),
        sa.Column(
            "consolidation_key",
            sa.LargeBinary(32),
            sa.ForeignKey("memory_consolidations.idempotency_key", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "memory_class IN ('decision','constraint','procedure','preference','lesson',"
            "'episode','unresolved_work')",
            name="ck_memory_class",
        ),
        sa.CheckConstraint("status='active'", name="ck_memory_mem001_status"),
        sa.CheckConstraint(
            "current_revision=1 AND aggregate_version=1",
            name="ck_memory_mem001_versions",
        ),
        sa.CheckConstraint(
            "valid_to IS NULL OR valid_to>valid_from",
            name="ck_memory_valid_time",
        ),
        sa.CheckConstraint(
            "recorded_to IS NULL OR recorded_to>recorded_from",
            name="ck_memory_recorded_time",
        ),
        sa.CheckConstraint(
            "json_valid(scope_json) AND json_valid(confidence_json)",
            name="ck_memory_json",
        ),
        sa.CheckConstraint(
            "length(extractor_fingerprint)=32 AND length(content_hash)=32 "
            "AND length(consolidation_key)=32",
            name="ck_memory_digests",
        ),
        sa.CheckConstraint(
            "classification IN ('public','internal','confidential','restricted','local_only')",
            name="ck_memory_classification",
        ),
    )
    op.create_index(
        "ix_memories_scope_status",
        "memories",
        ["brain_id", "project_id", "repository_id", "status", "memory_class"],
    )
    op.create_index("ix_memories_task", "memories", ["brain_id", "source_task_id"])

    op.create_table(
        "memory_revisions",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "memory_id",
            sa.Text(),
            sa.ForeignKey("memories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("content_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("content_ref", sa.Text(), nullable=False),
        sa.Column("content_json", sa.Text(), nullable=False),
        sa.Column("provenance_json", sa.Text(), nullable=False),
        sa.Column(
            "created_by_event",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("memory_id", "revision", name="uq_memory_revision"),
        sa.UniqueConstraint("memory_id", "content_hash", name="uq_memory_content"),
        sa.CheckConstraint("revision=1", name="ck_memory_revision_mem001"),
        sa.CheckConstraint("length(content_hash)=32", name="ck_memory_revision_digest"),
        sa.CheckConstraint(
            "json_valid(content_json) AND json_valid(provenance_json)",
            name="ck_memory_revision_json",
        ),
    )

    op.create_table(
        "memory_evidence",
        sa.Column(
            "memory_id",
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
        sa.Column("relation", sa.Text(), nullable=False),
        sa.Column("canonical_event_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("added_by_event", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("memory_id", "event_id", "relation"),
        sa.CheckConstraint("relation='supports'", name="ck_memory_evidence_relation"),
        sa.CheckConstraint(
            "length(canonical_event_sha256)=32",
            name="ck_memory_evidence_digest",
        ),
    )
    op.create_index("ix_memory_evidence_event", "memory_evidence", ["event_id", "memory_id"])

    op.create_table(
        "memory_candidate_rejections",
        sa.Column(
            "consolidation_key",
            sa.LargeBinary(32),
            sa.ForeignKey("memory_consolidations.idempotency_key", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("candidate_key_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("memory_class", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("reason_code", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("consolidation_key", "candidate_key_sha256"),
        sa.CheckConstraint(
            "length(candidate_key_sha256)=32 AND length(content_hash)=32",
            name="ck_memory_rejection_digest",
        ),
        sa.CheckConstraint(
            "reason_code IN ('scope_mismatch','unsupported_evidence',"
            "'insufficient_evidence','below_class_threshold',"
            "'missing_explicit_preference_evidence','missing_outcome_evidence',"
            "'completed_task_cannot_be_unresolved')",
            name="ck_memory_rejection_reason",
        ),
    )

    op.create_table(
        "memory_consolidation_work",
        sa.Column("idempotency_key", sa.LargeBinary(32), primary_key=True),
        sa.Column("operation_id", sa.Text(), nullable=False, unique=True),
        sa.Column(
            "terminal_event_id",
            sa.Text(),
            sa.ForeignKey("event_task_lineage.event_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("extractor_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("evidence_watermark_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("observed_lineage_created_at", sa.BigInteger(), nullable=False),
        sa.Column("observed_lineage_event_id", sa.Text(), nullable=False),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
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
            "checkout_id",
            sa.Text(),
            sa.ForeignKey("checkouts.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("task_id", sa.Text(), nullable=False),
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
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.BigInteger(), nullable=False),
        sa.Column("lease_owner", sa.Text(), nullable=True),
        sa.Column("lease_until", sa.BigInteger(), nullable=True),
        sa.Column("last_error_code", sa.Text(), nullable=True),
        sa.Column("result_sha256", sa.LargeBinary(32), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "terminal_event_id",
            "extractor_fingerprint",
            "evidence_watermark_sha256",
            name="uq_memory_work_identity",
        ),
        sa.CheckConstraint(
            "length(idempotency_key)=32 AND length(extractor_fingerprint)=32 "
            "AND length(evidence_watermark_sha256)=32 "
            "AND (result_sha256 IS NULL OR length(result_sha256)=32)",
            name="ck_memory_work_digests",
        ),
        sa.CheckConstraint(
            "state IN ('queued','leased','retry_scheduled','succeeded','dead_lettered')",
            name="ck_memory_work_state",
        ),
        sa.CheckConstraint(
            "last_error_code IS NULL OR last_error_code IN "
            "('invalid_input','authorization_denied','integrity_violation',"
            "'dependency_unavailable','internal_error')",
            name="ck_memory_work_error",
        ),
        sa.CheckConstraint("attempts>=0 AND attempts<=9", name="ck_memory_work_attempts"),
        sa.CheckConstraint(
            "(state='leased')=(lease_owner IS NOT NULL AND lease_until IS NOT NULL)",
            name="ck_memory_work_lease",
        ),
        sa.CheckConstraint(
            "(state='succeeded')=(result_sha256 IS NOT NULL AND completed_at IS NOT NULL)",
            name="ck_memory_work_result",
        ),
        sa.CheckConstraint(
            "(state IN ('succeeded','dead_lettered'))=(completed_at IS NOT NULL)",
            name="ck_memory_work_completion",
        ),
    )
    op.create_index(
        "ix_memory_work_due",
        "memory_consolidation_work",
        ["state", "next_attempt_at", "created_at", "operation_id"],
    )


def downgrade() -> None:
    connection = op.get_bind()
    evidence = connection.execute(
        sa.text(
            "SELECT (SELECT COUNT(*) FROM event_task_lineage) + "
            "(SELECT COUNT(*) FROM memory_consolidations) + "
            "(SELECT COUNT(*) FROM memories) + "
            "(SELECT COUNT(*) FROM memory_revisions) + "
            "(SELECT COUNT(*) FROM memory_evidence) + "
            "(SELECT COUNT(*) FROM memory_candidate_rejections) + "
            "(SELECT COUNT(*) FROM memory_consolidation_work) + "
            "(SELECT COUNT(*) FROM memory_task_lineage_backfills)"
        )
    ).scalar_one()
    if evidence:
        msg = "MEM-001 downgrade refused while task lineage or memory evidence exists"
        raise RuntimeError(msg)
    op.drop_index("ix_memory_work_due", table_name="memory_consolidation_work")
    op.drop_table("memory_consolidation_work")
    op.drop_table("memory_candidate_rejections")
    op.drop_index("ix_memory_evidence_event", table_name="memory_evidence")
    op.drop_table("memory_evidence")
    op.drop_table("memory_revisions")
    op.drop_index("ix_memories_task", table_name="memories")
    op.drop_index("ix_memories_scope_status", table_name="memories")
    op.drop_table("memories")
    op.drop_table("memory_consolidations")
    op.drop_table("memory_task_lineage_backfills")
    op.drop_index(
        "ix_event_schema_sources_ingested_order",
        table_name="event_schema_sources",
    )
    op.drop_index("ix_event_task_lineage_terminal", table_name="event_task_lineage")
    op.drop_index("ix_event_task_lineage_snapshot", table_name="event_task_lineage")
    op.drop_table("event_task_lineage")
    with op.batch_alter_table("outbox_messages", recreate="always") as batch:
        batch.drop_constraint("uq_outbox_source_topic_key", type_="unique")
        batch.create_unique_constraint(
            "uq_outbox_source_topic",
            ["source_event_id", "topic"],
        )
