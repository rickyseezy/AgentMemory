"""PRO-006 durable provider queues, rate state, batches, and child results.

Revision ID: 0039_pro006_provider_scheduling
Revises: 0038_pro005_provider_routing
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0039_pro006_provider_scheduling"
down_revision = "0038_pro005_provider_routing"
branch_labels = None
depends_on = None

_CLASSIFICATIONS = "'public','internal','confidential','restricted','local_only'"
_PURPOSES = (
    "'retrieval_query','retrieval_document','code_query','code_document',"
    "'semantic_similarity','classification','clustering'"
)
_WORKLOADS = "'interactive','capture','backfill','evaluation','maintenance'"
_DEADLINES = "'interactive','online','background'"
_WORK_STATES = "'queued','leased','retry_scheduled','completed','cancelled','failed'"
_BATCH_STATES = "'leased','completed','released','failed'"
_RESULT_STATES = "'succeeded','retryable_failure','permanent_failure','cancelled'"


def upgrade() -> None:
    """Install durable fair scheduling and append-only dispatch evidence."""
    op.create_table(
        "provider_scheduling_operations",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("request_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("operation_kind", sa.Text(), nullable=False),
        sa.Column("item_id", sa.Text(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(request_digest)=32 AND operation_kind IN ('enqueue','cancel') "
            "AND completed_at>=0 AND schema_version=1",
            name="ck_provider_scheduling_operation_integrity",
        ),
        sa.UniqueConstraint(
            "operation_kind",
            "item_id",
            name="uq_provider_scheduling_operation_item",
        ),
    )
    op.create_table(
        "provider_work_items",
        sa.Column("item_id", sa.Text(), primary_key=True),
        sa.Column(
            "operation_id",
            sa.Text(),
            sa.ForeignKey(
                "provider_scheduling_operations.operation_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("grant_version", sa.BigInteger(), nullable=False),
        sa.Column("authorization_policy_version", sa.Integer(), nullable=False),
        sa.Column("security_epoch", sa.Integer(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column(
            "project_id",
            sa.Text(),
            sa.ForeignKey("projects.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "profile_id",
            sa.Text(),
            sa.ForeignKey("provider_profiles.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column(
            "space_id",
            sa.Text(),
            sa.ForeignKey("embedding_spaces.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("space_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("retention_policy_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("preprocessing_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("deadline_class", sa.Text(), nullable=False),
        sa.Column("workload", sa.Text(), nullable=False),
        sa.Column("batch_key_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("ordinal", sa.BigInteger(), nullable=False),
        sa.Column("payload_ref", sa.Text(), nullable=False),
        sa.Column("content_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("token_count", sa.BigInteger(), nullable=False),
        sa.Column("byte_count", sa.BigInteger(), nullable=False),
        sa.Column("estimated_cost_micros", sa.BigInteger(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.BigInteger(), nullable=False),
        sa.Column("lease_owner", sa.Text(), nullable=True),
        sa.Column("lease_until", sa.BigInteger(), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_error_code", sa.Text(), nullable=True),
        sa.Column("enqueued_at", sa.BigInteger(), nullable=False),
        sa.Column("deadline_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["profile_id", "profile_version"],
            ["provider_profile_revisions.profile_id", "provider_profile_revisions.version"],
            name="fk_provider_work_profile_revision",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.CheckConstraint(
            "grant_version>=1 AND authorization_policy_version>=1 AND security_epoch>=1 "
            "AND length(scope_fingerprint)=32 AND profile_version>=1 "
            "AND length(space_fingerprint)=32 "
            f"AND classification IN ({_CLASSIFICATIONS}) "
            f"AND purpose IN ({_PURPOSES}) "
            "AND length(retention_policy_digest)=32 AND length(preprocessing_digest)=32 "
            f"AND deadline_class IN ({_DEADLINES}) AND workload IN ({_WORKLOADS}) "
            "AND ((deadline_class='interactive' AND workload='interactive') "
            "OR (deadline_class<>'interactive' AND workload<>'interactive')) "
            "AND length(batch_key_digest)=32 AND ordinal>=0 "
            "AND (payload_ref LIKE 'cas://%' OR payload_ref LIKE 'artifact://%' "
            "OR payload_ref LIKE 'local-object://%') "
            "AND length(content_digest)=32 AND token_count>=1 AND byte_count>=1 "
            "AND estimated_cost_micros>=0 "
            f"AND state IN ({_WORK_STATES}) AND attempts>=0 "
            "AND next_attempt_at>=enqueued_at AND deadline_at>enqueued_at "
            "AND updated_at>=enqueued_at "
            "AND ((state='leased' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL) "
            "OR (state<>'leased' AND lease_owner IS NULL AND lease_until IS NULL)) "
            "AND ((state IN ('completed','cancelled','failed') AND completed_at IS NOT NULL) "
            "OR (state NOT IN ('completed','cancelled','failed') AND completed_at IS NULL)) "
            "AND schema_version=1",
            name="ck_provider_work_integrity",
        ),
    )
    op.create_index(
        "uq_provider_work_operation",
        "provider_work_items",
        ["operation_id"],
        unique=True,
    )
    op.create_index(
        "ix_provider_work_dispatch",
        "provider_work_items",
        ["state", "next_attempt_at", "deadline_at", "profile_id", "workload"],
    )
    op.create_index(
        "ix_provider_work_partition",
        "provider_work_items",
        ["profile_id", "workload", "batch_key_digest", "ordinal", "enqueued_at", "item_id"],
    )
    op.create_table(
        "provider_scheduler_state",
        sa.Column("profile_id", sa.Text(), primary_key=True),
        sa.Column("dispatch_cursor", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "dispatch_cursor>=0 AND updated_at>=0 AND schema_version=1",
            name="ck_provider_scheduler_state_integrity",
        ),
    )
    op.create_table(
        "provider_rate_states",
        sa.Column("profile_id", sa.Text(), primary_key=True),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("request_balance_micros", sa.BigInteger(), nullable=False),
        sa.Column("token_balance_micros", sa.BigInteger(), nullable=False),
        sa.Column("last_refill_at", sa.BigInteger(), nullable=False),
        sa.Column("blocked_until", sa.BigInteger(), nullable=True),
        sa.Column("in_flight", sa.Integer(), nullable=False),
        sa.Column("period_start", sa.BigInteger(), nullable=False),
        sa.Column("cost_spent_micros", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["profile_id", "profile_version"],
            ["provider_profile_revisions.profile_id", "provider_profile_revisions.version"],
            name="fk_provider_rate_profile_revision",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.CheckConstraint(
            "profile_version>=1 AND request_balance_micros>=0 "
            "AND token_balance_micros>=0 AND last_refill_at>=0 "
            "AND (blocked_until IS NULL OR blocked_until>=0) AND in_flight>=0 "
            "AND period_start>=0 AND cost_spent_micros>=0 AND version>=1 "
            "AND schema_version=1",
            name="ck_provider_rate_state_integrity",
        ),
    )
    op.create_table(
        "provider_batches",
        sa.Column("batch_operation_id", sa.Text(), primary_key=True),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("batch_key_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("workload", sa.Text(), nullable=False),
        sa.Column("owner", sa.Text(), nullable=False),
        sa.Column("lease_until", sa.BigInteger(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("item_count", sa.Integer(), nullable=False),
        sa.Column("token_count", sa.BigInteger(), nullable=False),
        sa.Column("byte_count", sa.BigInteger(), nullable=False),
        sa.Column("estimated_cost_micros", sa.BigInteger(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("reason_code", sa.Text(), nullable=True),
        sa.Column("provider_retry_at", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "profile_version>=1 AND length(batch_key_digest)=32 "
            f"AND workload IN ({_WORKLOADS}) AND attempt>=1 AND item_count>=1 "
            "AND token_count>=1 AND byte_count>=1 AND estimated_cost_micros>=0 "
            f"AND state IN ({_BATCH_STATES}) "
            "AND ((state='leased' AND completed_at IS NULL) "
            "OR (state<>'leased' AND completed_at IS NOT NULL)) "
            "AND schema_version=1",
            name="ck_provider_batch_integrity",
        ),
    )
    op.create_index(
        "ix_provider_batch_profile",
        "provider_batches",
        ["profile_id", "created_at", "batch_operation_id"],
    )
    op.create_table(
        "provider_batch_items",
        sa.Column(
            "batch_operation_id",
            sa.Text(),
            sa.ForeignKey("provider_batches.batch_operation_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "item_id",
            sa.Text(),
            sa.ForeignKey("provider_work_items.item_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("batch_ordinal", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "batch_operation_id",
            "batch_ordinal",
            name="uq_provider_batch_item_ordinal",
        ),
        sa.CheckConstraint(
            "batch_ordinal>=0 AND schema_version=1",
            name="ck_provider_batch_item_integrity",
        ),
    )
    op.create_table(
        "provider_item_results",
        sa.Column(
            "batch_operation_id",
            sa.Text(),
            sa.ForeignKey("provider_batches.batch_operation_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "item_id",
            sa.Text(),
            sa.ForeignKey("provider_work_items.item_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("result_digest", sa.LargeBinary(32), nullable=True),
        sa.Column("result_ref", sa.Text(), nullable=True),
        sa.Column("error_code", sa.Text(), nullable=True),
        sa.Column("retry_at", sa.BigInteger(), nullable=True),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            f"attempt>=1 AND status IN ({_RESULT_STATES}) "
            "AND ((status='succeeded' AND length(result_digest)=32 "
            "AND result_ref IS NOT NULL AND error_code IS NULL AND retry_at IS NULL) "
            "OR (status<>'succeeded' AND result_digest IS NULL AND result_ref IS NULL "
            "AND error_code IS NOT NULL)) AND completed_at>=0 AND schema_version=1",
            name="ck_provider_item_result_integrity",
        ),
    )
    _immutable("provider_scheduling_operations")
    _immutable("provider_batch_items")
    _immutable("provider_item_results")
    op.execute(
        "CREATE TRIGGER trg_provider_work_identity_closed_update "
        "BEFORE UPDATE ON provider_work_items "
        "WHEN OLD.item_id<>NEW.item_id OR OLD.operation_id<>NEW.operation_id "
        "OR OLD.brain_id<>NEW.brain_id OR OLD.principal_id<>NEW.principal_id "
        "OR OLD.grant_version<>NEW.grant_version "
        "OR OLD.authorization_policy_version<>NEW.authorization_policy_version "
        "OR OLD.security_epoch<>NEW.security_epoch "
        "OR OLD.scope_fingerprint<>NEW.scope_fingerprint "
        "OR OLD.project_id IS NOT NEW.project_id OR OLD.repository_id IS NOT NEW.repository_id "
        "OR OLD.profile_id<>NEW.profile_id OR OLD.profile_version<>NEW.profile_version "
        "OR OLD.space_id<>NEW.space_id OR OLD.space_fingerprint<>NEW.space_fingerprint "
        "OR OLD.classification<>NEW.classification OR OLD.purpose<>NEW.purpose "
        "OR OLD.retention_policy_digest<>NEW.retention_policy_digest "
        "OR OLD.preprocessing_digest<>NEW.preprocessing_digest "
        "OR OLD.deadline_class<>NEW.deadline_class OR OLD.workload<>NEW.workload "
        "OR OLD.batch_key_digest<>NEW.batch_key_digest OR OLD.ordinal<>NEW.ordinal "
        "OR OLD.payload_ref<>NEW.payload_ref OR OLD.content_digest<>NEW.content_digest "
        "OR OLD.token_count<>NEW.token_count OR OLD.byte_count<>NEW.byte_count "
        "OR OLD.estimated_cost_micros<>NEW.estimated_cost_micros "
        "OR OLD.enqueued_at<>NEW.enqueued_at OR OLD.deadline_at<>NEW.deadline_at "
        "OR OLD.schema_version<>NEW.schema_version "
        "BEGIN SELECT RAISE(ABORT, 'provider work identity is immutable'); END"
    )
    op.execute(
        "CREATE TRIGGER trg_provider_work_immutable_delete "
        "BEFORE DELETE ON provider_work_items "
        "BEGIN SELECT RAISE(ABORT, 'provider work history is immutable'); END"
    )
    op.execute(
        "CREATE TRIGGER trg_provider_batches_immutable_delete "
        "BEFORE DELETE ON provider_batches "
        "BEGIN SELECT RAISE(ABORT, 'provider batch history is immutable'); END"
    )
    op.execute(
        "CREATE TRIGGER trg_provider_batches_closed_update "
        "BEFORE UPDATE ON provider_batches "
        "WHEN OLD.state<>'leased' OR NEW.state NOT IN ('completed','released','failed') "
        "OR OLD.batch_operation_id<>NEW.batch_operation_id "
        "OR OLD.brain_id<>NEW.brain_id OR OLD.profile_id<>NEW.profile_id "
        "OR OLD.profile_version<>NEW.profile_version "
        "OR OLD.batch_key_digest<>NEW.batch_key_digest OR OLD.workload<>NEW.workload "
        "OR OLD.owner<>NEW.owner OR OLD.lease_until<>NEW.lease_until "
        "OR OLD.attempt<>NEW.attempt OR OLD.item_count<>NEW.item_count "
        "OR OLD.token_count<>NEW.token_count OR OLD.byte_count<>NEW.byte_count "
        "OR OLD.estimated_cost_micros<>NEW.estimated_cost_micros "
        "OR OLD.created_at<>NEW.created_at OR OLD.schema_version<>NEW.schema_version "
        "OR NEW.completed_at IS NULL "
        "BEGIN SELECT RAISE(ABORT, 'provider batch history is immutable'); END"
    )


def _immutable(table: str) -> None:
    for operation in ("UPDATE", "DELETE"):
        op.execute(
            f"CREATE TRIGGER trg_{table}_immutable_{operation.lower()} "
            f"BEFORE {operation} ON {table} "
            "BEGIN SELECT RAISE(ABORT, 'provider scheduling history is immutable'); END"
        )


def downgrade() -> None:
    """Refuse to destroy any queue, scheduler, rate, batch, or result history."""
    connection = op.get_bind()
    tables = (
        "provider_work_items",
        "provider_scheduling_operations",
        "provider_scheduler_state",
        "provider_rate_states",
        "provider_batches",
        "provider_batch_items",
        "provider_item_results",
    )
    count = sum(
        int(
            connection.execute(
                sa.text(f"SELECT COUNT(*) FROM {table}")  # noqa: S608 -- Closed table tuple.
            ).scalar_one()
        )
        for table in tables
    )
    if count:
        message = "PRO-006 downgrade refused while provider scheduling history exists"
        raise RuntimeError(message)
    op.execute("DROP TRIGGER IF EXISTS trg_provider_batches_closed_update")
    op.execute("DROP TRIGGER IF EXISTS trg_provider_batches_immutable_delete")
    op.execute("DROP TRIGGER IF EXISTS trg_provider_work_immutable_delete")
    op.execute("DROP TRIGGER IF EXISTS trg_provider_work_identity_closed_update")
    for table in (
        "provider_item_results",
        "provider_batch_items",
        "provider_scheduling_operations",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable_delete")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable_update")
    op.drop_table("provider_item_results")
    op.drop_table("provider_batch_items")
    op.drop_index("ix_provider_batch_profile", table_name="provider_batches")
    op.drop_table("provider_batches")
    op.drop_table("provider_rate_states")
    op.drop_table("provider_scheduler_state")
    op.drop_index("ix_provider_work_partition", table_name="provider_work_items")
    op.drop_index("ix_provider_work_dispatch", table_name="provider_work_items")
    op.drop_index("uq_provider_work_operation", table_name="provider_work_items")
    op.drop_table("provider_work_items")
    op.drop_table("provider_scheduling_operations")
