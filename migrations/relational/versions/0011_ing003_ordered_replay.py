"""ING-003 causal watermarks, gap evidence, and deterministic shadow replay.

Revision ID: 0011_ing003_ordered_replay
Revises: 0010_ing002_idempotent_delivery
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0011_ing003_ordered_replay"
down_revision = "0010_ing002_idempotent_delivery"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("outbox_messages") as batch:
        batch.drop_constraint("ck_outbox_status", type_="check")
        batch.create_check_constraint(
            "ck_outbox_status",
            "status IN ('ready','leased','completed','repair_required','replay_required')",
        )
    with op.batch_alter_table("inbox_receipts") as batch:
        batch.drop_constraint("ck_inbox_state_shape", type_="check")
        batch.drop_constraint("ck_inbox_state", type_="check")
        batch.create_check_constraint(
            "ck_inbox_state",
            "state IN ('processing','completed','repair_required','replay_required')",
        )
        batch.create_check_constraint(
            "ck_inbox_state_shape",
            "(state='processing' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL "
            "AND result_sha256 IS NULL AND processed_at IS NULL) OR "
            "(state='completed' AND lease_owner IS NULL AND lease_until IS NULL "
            "AND result_sha256 IS NOT NULL AND processed_at IS NOT NULL) OR "
            "(state IN ('repair_required','replay_required') AND lease_owner IS NULL "
            "AND lease_until IS NULL AND result_sha256 IS NULL AND processed_at IS NOT NULL)",
        )

    op.create_table(
        "ordered_replay_runs",
        sa.Column("operation_id", sa.Text(), primary_key=True),
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
        sa.Column("projection_name", sa.Text(), nullable=False),
        sa.Column("projection_generation", sa.Text(), nullable=False),
        sa.Column("code_fingerprint", sa.Text(), nullable=False),
        sa.Column("request_sha256", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("from_ingested_at", sa.BigInteger(), nullable=True),
        sa.Column("to_ingested_at", sa.BigInteger(), nullable=True),
        sa.Column(
            "from_event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "to_event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("source_watermark_ingested_at", sa.BigInteger(), nullable=False),
        sa.Column("source_watermark_event_id", sa.Text(), nullable=False),
        sa.Column("cursor_ingested_at", sa.BigInteger(), nullable=True),
        sa.Column("cursor_event_id", sa.Text(), nullable=True),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("source_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("processed_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("shadow_digest", sa.LargeBinary(32), nullable=True),
        sa.Column("live_digest", sa.LargeBinary(32), nullable=True),
        sa.Column("failure_code", sa.Text(), nullable=True),
        sa.Column("lease_owner", sa.Text(), nullable=True),
        sa.Column("lease_until", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "brain_id",
            "projection_name",
            "projection_generation",
            name="uq_ordered_replay_generation",
        ),
        sa.CheckConstraint(
            "length(code_fingerprint) IN (40,64)", name="ck_ordered_replay_code_fingerprint"
        ),
        sa.CheckConstraint("length(request_sha256)=32", name="ck_ordered_replay_request_digest"),
        sa.CheckConstraint(
            "shadow_digest IS NULL OR length(shadow_digest)=32",
            name="ck_ordered_replay_shadow_digest",
        ),
        sa.CheckConstraint(
            "live_digest IS NULL OR length(live_digest)=32",
            name="ck_ordered_replay_live_digest",
        ),
        sa.CheckConstraint(
            "state IN ('queued','building','validating','ready','partial','superseded')",
            name="ck_ordered_replay_state",
        ),
        sa.CheckConstraint(
            "source_count >= 0 AND processed_count >= 0 AND processed_count <= source_count",
            name="ck_ordered_replay_counts",
        ),
        sa.CheckConstraint(
            "(lease_owner IS NULL AND lease_until IS NULL) OR "
            "(lease_owner IS NOT NULL AND lease_until IS NOT NULL)",
            name="ck_ordered_replay_lease_shape",
        ),
        sa.CheckConstraint(
            "from_ingested_at IS NULL OR to_ingested_at IS NULL OR "
            "from_ingested_at <= to_ingested_at",
            name="ck_ordered_replay_time_range",
        ),
    )
    op.create_index(
        "ix_ordered_replay_dispatch",
        "ordered_replay_runs",
        ["state", "lease_until", "created_at", "operation_id"],
    )

    op.create_table(
        "ordered_replay_sources",
        sa.Column(
            "operation_id",
            sa.Text(),
            sa.ForeignKey("ordered_replay_runs.operation_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("source_ordinal", sa.BigInteger(), nullable=False),
        sa.Column("source_ingested_at", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "operation_id", "source_ordinal", name="uq_ordered_replay_source_ordinal"
        ),
        sa.CheckConstraint("source_ordinal >= 1", name="ck_ordered_replay_source_ordinal"),
        sa.CheckConstraint("source_ingested_at >= 0", name="ck_ordered_replay_source_time"),
    )

    op.create_table(
        "recorded_reduction_inputs",
        sa.Column("projection_name", sa.Text(), primary_key=True),
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "operation_id",
            sa.Text(),
            sa.ForeignKey("provider_operation_results.operation_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column("model_revision", sa.Text(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("result_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("result_ref", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "projection_name", "operation_id", name="uq_recorded_reduction_operation"
        ),
        sa.CheckConstraint(
            "length(model_revision) IN (40,64)", name="ck_recorded_reduction_model_revision"
        ),
        sa.CheckConstraint("length(result_sha256)=32", name="ck_recorded_reduction_result_digest"),
        sa.CheckConstraint(
            "result_ref LIKE 'cas://sha256/%'", name="ck_recorded_reduction_result_ref"
        ),
    )

    op.create_table(
        "projection_order_watermarks",
        sa.Column("projection_name", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("ordering_key", sa.Text(), primary_key=True),
        sa.Column("applied_sequence", sa.BigInteger(), nullable=False),
        sa.Column("state_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column(
            "last_event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("lease_owner", sa.Text(), nullable=True),
        sa.Column(
            "lease_event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("lease_sequence", sa.BigInteger(), nullable=True),
        sa.Column("lease_until", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("applied_sequence >= 0", name="ck_order_watermark_sequence"),
        sa.CheckConstraint("length(state_sha256)=32", name="ck_order_watermark_state_digest"),
        sa.CheckConstraint(
            "(applied_sequence=0 AND last_event_id IS NULL) OR "
            "(applied_sequence>0 AND last_event_id IS NOT NULL)",
            name="ck_order_watermark_last_event",
        ),
        sa.CheckConstraint(
            "(lease_owner IS NULL AND lease_event_id IS NULL AND lease_sequence IS NULL "
            "AND lease_until IS NULL) OR "
            "(lease_owner IS NOT NULL AND lease_event_id IS NOT NULL "
            "AND lease_sequence IS NOT NULL AND lease_until IS NOT NULL "
            "AND lease_sequence > applied_sequence)",
            name="ck_order_watermark_lease_shape",
        ),
    )
    op.create_index(
        "ix_order_watermark_expired_lease",
        "projection_order_watermarks",
        ["lease_until", "projection_name", "brain_id", "ordering_key"],
    )

    op.create_table(
        "projection_order_gaps",
        sa.Column("projection_name", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("ordering_key", sa.Text(), primary_key=True),
        sa.Column(
            "blocking_event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("from_sequence", sa.BigInteger(), nullable=False),
        sa.Column("to_sequence", sa.BigInteger(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("first_detected_at", sa.BigInteger(), nullable=False),
        sa.Column("timeout_at", sa.BigInteger(), nullable=False),
        sa.Column("declared_at", sa.BigInteger(), nullable=True),
        sa.Column(
            "late_event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("late_arrived_at", sa.BigInteger(), nullable=True),
        sa.Column("resolved_at", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("projection_name", "late_event_id", name="uq_order_gap_late_event"),
        sa.CheckConstraint(
            "from_sequence >= 1 AND to_sequence >= from_sequence", name="ck_order_gap_range"
        ),
        sa.CheckConstraint(
            "state IN ('waiting','declared','late_arrived','resolved')", name="ck_order_gap_state"
        ),
        sa.CheckConstraint("timeout_at >= first_detected_at", name="ck_order_gap_timeout"),
        sa.CheckConstraint(
            "(state='waiting' AND declared_at IS NULL AND late_event_id IS NULL "
            "AND late_arrived_at IS NULL AND resolved_at IS NULL) OR "
            "(state='declared' AND declared_at IS NOT NULL AND late_event_id IS NULL "
            "AND late_arrived_at IS NULL AND resolved_at IS NULL) OR "
            "(state='late_arrived' AND declared_at IS NOT NULL AND late_event_id IS NOT NULL "
            "AND late_arrived_at IS NOT NULL AND resolved_at IS NULL) OR "
            "(state='resolved' AND declared_at IS NOT NULL AND resolved_at IS NOT NULL)",
            name="ck_order_gap_state_shape",
        ),
    )
    op.create_index(
        "ix_order_gap_due",
        "projection_order_gaps",
        ["state", "timeout_at", "projection_name", "brain_id", "ordering_key"],
    )

    op.create_table(
        "ordered_projection_history",
        sa.Column("projection_name", sa.Text(), primary_key=True),
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("ordering_key", sa.Text(), nullable=False),
        sa.Column("event_sequence", sa.BigInteger(), nullable=True),
        sa.Column("event_schema_version", sa.Integer(), nullable=False),
        sa.Column("canonical_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("projection_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("prior_state_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("state_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("code_fingerprint", sa.Text(), nullable=False),
        sa.Column(
            "recorded_operation_id",
            sa.Text(),
            sa.ForeignKey("provider_operation_results.operation_id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("applied_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "projection_name",
            "brain_id",
            "ordering_key",
            "event_sequence",
            name="uq_ordered_history_sequence",
        ),
        sa.CheckConstraint(
            "event_sequence IS NULL OR event_sequence >= 1", name="ck_ordered_history_sequence"
        ),
        sa.CheckConstraint(
            "length(canonical_sha256)=32 AND length(projection_sha256)=32 "
            "AND length(prior_state_sha256)=32 AND length(state_sha256)=32",
            name="ck_ordered_history_digests",
        ),
        sa.CheckConstraint(
            "length(code_fingerprint) IN (40,64)", name="ck_ordered_history_code_fingerprint"
        ),
    )

    op.create_table(
        "ordered_replay_required_events",
        sa.Column("projection_name", sa.Text(), primary_key=True),
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "outbox_message_id",
            sa.Text(),
            sa.ForeignKey("outbox_messages.id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("ordering_key", sa.Text(), nullable=False),
        sa.Column("event_sequence", sa.BigInteger(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column(
            "replay_operation_id",
            sa.Text(),
            sa.ForeignKey("ordered_replay_runs.operation_id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("detected_at", sa.BigInteger(), nullable=False),
        sa.Column("resolved_at", sa.BigInteger(), nullable=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("event_sequence >= 1", name="ck_replay_required_sequence"),
        sa.CheckConstraint("state IN ('pending','resolved')", name="ck_replay_required_state"),
        sa.CheckConstraint(
            "(state='pending' AND replay_operation_id IS NULL AND resolved_at IS NULL) OR "
            "(state='resolved' AND replay_operation_id IS NOT NULL AND resolved_at IS NOT NULL)",
            name="ck_replay_required_state_shape",
        ),
    )

    op.create_table(
        "ordered_replay_shadow_history",
        sa.Column(
            "operation_id",
            sa.Text(),
            sa.ForeignKey("ordered_replay_runs.operation_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("ordering_key", sa.Text(), nullable=False),
        sa.Column("event_sequence", sa.BigInteger(), nullable=True),
        sa.Column("event_schema_version", sa.Integer(), nullable=False),
        sa.Column("canonical_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("projection_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("prior_state_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("state_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column(
            "recorded_operation_id",
            sa.Text(),
            sa.ForeignKey("provider_operation_results.operation_id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("source_ingested_at", sa.BigInteger(), nullable=False),
        sa.Column("source_ordinal", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("operation_id", "source_ordinal", name="uq_replay_shadow_ordinal"),
        sa.CheckConstraint(
            "event_sequence IS NULL OR event_sequence >= 1", name="ck_replay_shadow_sequence"
        ),
        sa.CheckConstraint(
            "length(canonical_sha256)=32 AND length(projection_sha256)=32 "
            "AND length(prior_state_sha256)=32 AND length(state_sha256)=32",
            name="ck_replay_shadow_digests",
        ),
        sa.CheckConstraint("source_ordinal >= 1", name="ck_replay_shadow_ordinal"),
    )
    op.create_table(
        "ordered_replay_shadow_states",
        sa.Column(
            "operation_id",
            sa.Text(),
            sa.ForeignKey("ordered_replay_runs.operation_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("ordering_key", sa.Text(), primary_key=True),
        sa.Column("applied_sequence", sa.BigInteger(), nullable=False),
        sa.Column("state_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("applied_sequence >= 0", name="ck_replay_shadow_state_sequence"),
        sa.CheckConstraint("length(state_sha256)=32", name="ck_replay_shadow_state_digest"),
    )


def downgrade() -> None:
    connection = op.get_bind()
    evidence = connection.execute(
        sa.text(
            "SELECT "
            "(SELECT COUNT(*) FROM ordered_replay_shadow_states) + "
            "(SELECT COUNT(*) FROM ordered_replay_shadow_history) + "
            "(SELECT COUNT(*) FROM ordered_replay_required_events) + "
            "(SELECT COUNT(*) FROM ordered_projection_history) + "
            "(SELECT COUNT(*) FROM projection_order_gaps) + "
            "(SELECT COUNT(*) FROM projection_order_watermarks) + "
            "(SELECT COUNT(*) FROM recorded_reduction_inputs) + "
            "(SELECT COUNT(*) FROM ordered_replay_sources) + "
            "(SELECT COUNT(*) FROM ordered_replay_runs)"
        )
    ).scalar_one()
    if evidence:
        msg = "ING-003 downgrade refused while ordering or replay evidence exists"
        raise RuntimeError(msg)
    op.drop_table("ordered_replay_shadow_states")
    op.drop_table("ordered_replay_shadow_history")
    op.drop_table("ordered_replay_required_events")
    op.drop_table("ordered_projection_history")
    op.drop_index("ix_order_gap_due", table_name="projection_order_gaps")
    op.drop_table("projection_order_gaps")
    op.drop_index("ix_order_watermark_expired_lease", table_name="projection_order_watermarks")
    op.drop_table("projection_order_watermarks")
    op.drop_table("recorded_reduction_inputs")
    op.drop_table("ordered_replay_sources")
    op.drop_index("ix_ordered_replay_dispatch", table_name="ordered_replay_runs")
    op.drop_table("ordered_replay_runs")
    with op.batch_alter_table("inbox_receipts") as batch:
        batch.drop_constraint("ck_inbox_state_shape", type_="check")
        batch.drop_constraint("ck_inbox_state", type_="check")
        batch.create_check_constraint(
            "ck_inbox_state",
            "state IN ('processing','completed','repair_required')",
        )
        batch.create_check_constraint(
            "ck_inbox_state_shape",
            "(state='processing' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL "
            "AND result_sha256 IS NULL AND processed_at IS NULL) OR "
            "(state='completed' AND lease_owner IS NULL AND lease_until IS NULL "
            "AND result_sha256 IS NOT NULL AND processed_at IS NOT NULL) OR "
            "(state='repair_required' AND lease_owner IS NULL AND lease_until IS NULL "
            "AND result_sha256 IS NULL AND processed_at IS NOT NULL)",
        )
    with op.batch_alter_table("outbox_messages") as batch:
        batch.drop_constraint("ck_outbox_status", type_="check")
        batch.create_check_constraint(
            "ck_outbox_status",
            "status IN ('ready','leased','completed','repair_required')",
        )
