"""ING-002 inbox, command, provider, job, and projection idempotency evidence.

Revision ID: 0010_ing002_idempotent_delivery
Revises: 0009_ing001_durable_processing
"""

from __future__ import annotations

import hashlib

import sqlalchemy as sa
from alembic import op

revision = "0010_ing002_idempotent_delivery"
down_revision = "0009_ing001_durable_processing"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "idempotency_conflicts",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("namespace", sa.Text(), nullable=False),
        sa.Column("identity_key", sa.Text(), nullable=False),
        sa.Column("expected_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("actual_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column(
            "source_message_id",
            sa.Text(),
            sa.ForeignKey("outbox_messages.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("detected_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "namespace",
            "identity_key",
            "actual_sha256",
            name="uq_idempotency_conflict_evidence",
        ),
        sa.CheckConstraint("length(expected_sha256) = 32", name="ck_conflict_expected_digest"),
        sa.CheckConstraint("length(actual_sha256) = 32", name="ck_conflict_actual_digest"),
    )
    op.create_index(
        "ix_idempotency_conflicts_brain_time",
        "idempotency_conflicts",
        ["brain_id", "detected_at", "id"],
    )

    op.create_table(
        "command_receipts",
        sa.Column("command_name", sa.Text(), primary_key=True),
        sa.Column("idempotency_key", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("request_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("result_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("length(request_sha256) = 32", name="ck_command_request_digest"),
        sa.CheckConstraint("length(result_sha256) = 32", name="ck_command_result_digest"),
    )

    op.create_table(
        "inbox_receipts",
        sa.Column("consumer", sa.Text(), primary_key=True),
        sa.Column(
            "message_id",
            sa.Text(),
            sa.ForeignKey("outbox_messages.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("idempotency_key", sa.Text(), nullable=False),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("request_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("result_sha256", sa.LargeBinary(32), nullable=True),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("lease_owner", sa.Text(), nullable=True),
        sa.Column("lease_until", sa.BigInteger(), nullable=True),
        sa.Column("processed_at", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("consumer", "idempotency_key", name="uq_inbox_consumer_key"),
        sa.CheckConstraint("length(request_sha256) = 32", name="ck_inbox_request_digest"),
        sa.CheckConstraint(
            "result_sha256 IS NULL OR length(result_sha256) = 32",
            name="ck_inbox_result_digest",
        ),
        sa.CheckConstraint(
            "state IN ('processing','completed','repair_required')",
            name="ck_inbox_state",
        ),
        sa.CheckConstraint("attempts >= 1", name="ck_inbox_attempts"),
        sa.CheckConstraint(
            "(state='processing' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL "
            "AND result_sha256 IS NULL AND processed_at IS NULL) OR "
            "(state='completed' AND lease_owner IS NULL AND lease_until IS NULL "
            "AND result_sha256 IS NOT NULL AND processed_at IS NOT NULL) OR "
            "(state='repair_required' AND lease_owner IS NULL AND lease_until IS NULL "
            "AND result_sha256 IS NULL AND processed_at IS NOT NULL)",
            name="ck_inbox_state_shape",
        ),
    )
    op.create_index(
        "ix_inbox_expired_lease",
        "inbox_receipts",
        ["state", "lease_until", "consumer", "message_id"],
    )

    op.create_table(
        "provider_operation_results",
        sa.Column("profile_id", sa.Text(), primary_key=True),
        sa.Column("idempotency_key", sa.Text(), primary_key=True),
        sa.Column("operation_id", sa.Text(), nullable=False, unique=True),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("cache_key_sha256", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("request_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("lease_owner", sa.Text(), nullable=True),
        sa.Column("lease_until", sa.BigInteger(), nullable=True),
        sa.Column("retry_at", sa.BigInteger(), nullable=False),
        sa.Column("result_sha256", sa.LargeBinary(32), nullable=True),
        sa.Column("result_ref", sa.Text(), nullable=True),
        sa.Column("usage_units", sa.BigInteger(), nullable=True),
        sa.Column("last_error_code", sa.Text(), nullable=True),
        sa.Column("completed_at", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("length(cache_key_sha256) = 32", name="ck_provider_cache_digest"),
        sa.CheckConstraint("length(request_sha256) = 32", name="ck_provider_request_digest"),
        sa.CheckConstraint(
            "result_sha256 IS NULL OR length(result_sha256) = 32",
            name="ck_provider_result_digest",
        ),
        sa.CheckConstraint("state IN ('processing','completed')", name="ck_provider_state"),
        sa.CheckConstraint("attempts >= 1", name="ck_provider_attempts"),
        sa.CheckConstraint(
            "(state='processing' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL "
            "AND result_sha256 IS NULL AND result_ref IS NULL AND usage_units IS NULL "
            "AND completed_at IS NULL) OR "
            "(state='completed' AND lease_owner IS NULL AND lease_until IS NULL "
            "AND result_sha256 IS NOT NULL AND result_ref IS NOT NULL "
            "AND usage_units IS NOT NULL AND completed_at IS NOT NULL)",
            name="ck_provider_state_shape",
        ),
    )
    op.create_index(
        "ix_provider_operation_dispatch",
        "provider_operation_results",
        ["state", "retry_at", "lease_until", "profile_id", "idempotency_key"],
    )

    op.create_table(
        "projection_idempotency_receipts",
        sa.Column("projection_name", sa.Text(), primary_key=True),
        sa.Column("idempotency_key", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "source_message_id",
            sa.Text(),
            sa.ForeignKey("outbox_messages.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("projection_generation", sa.Text(), nullable=False),
        sa.Column("request_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("result_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "projection_name",
            "source_message_id",
            "projection_generation",
            name="uq_projection_source_generation",
        ),
        sa.CheckConstraint("length(request_sha256) = 32", name="ck_projection_request_digest"),
        sa.CheckConstraint("length(result_sha256) = 32", name="ck_projection_result_digest"),
    )

    with op.batch_alter_table("jobs") as batch:
        batch.add_column(sa.Column("input_ref", sa.Text(), nullable=True))
        batch.add_column(sa.Column("request_sha256", sa.LargeBinary(32), nullable=True))
        batch.add_column(sa.Column("result_sha256", sa.LargeBinary(32), nullable=True))
        batch.add_column(sa.Column("completed_at", sa.BigInteger(), nullable=True))
    connection = op.get_bind()
    rows = connection.execute(
        sa.text("SELECT id,kind,idempotency_key,state,updated_at FROM jobs")
    ).all()
    for job_id, kind, idempotency_key, state, updated_at in rows:
        request_digest = hashlib.sha256(f"{kind}\x00{idempotency_key}".encode()).digest()
        result_digest = None
        completed_at = None
        if state == "succeeded":
            # Pre-ING-002 jobs retained success but no output digest. Bind an explicit opaque
            # legacy-success receipt to the immutable job identity; do not imply a provider result.
            result_digest = hashlib.sha256(
                f"legacy-succeeded\x00{kind}\x00{idempotency_key}".encode()
            ).digest()
            completed_at = updated_at
        connection.execute(
            sa.text(
                "UPDATE jobs SET request_sha256=:request,result_sha256=:result,"
                "completed_at=:completed WHERE id=:id"
            ),
            {
                "completed": completed_at,
                "id": job_id,
                "request": request_digest,
                "result": result_digest,
            },
        )
    with op.batch_alter_table("jobs") as batch:
        batch.alter_column("request_sha256", existing_type=sa.LargeBinary(32), nullable=False)
        batch.create_check_constraint("ck_jobs_request_digest", "length(request_sha256) = 32")
        batch.create_check_constraint(
            "ck_jobs_result_digest",
            "result_sha256 IS NULL OR length(result_sha256) = 32",
        )
        batch.create_check_constraint(
            "ck_jobs_completion_shape",
            "(state='succeeded' AND result_sha256 IS NOT NULL AND completed_at IS NOT NULL) OR "
            "(state<>'succeeded' AND result_sha256 IS NULL AND completed_at IS NULL)",
        )


def downgrade() -> None:
    connection = op.get_bind()
    state_count = connection.execute(
        sa.text(
            "SELECT "
            "(SELECT COUNT(*) FROM inbox_receipts) + "
            "(SELECT COUNT(*) FROM command_receipts) + "
            "(SELECT COUNT(*) FROM provider_operation_results) + "
            "(SELECT COUNT(*) FROM projection_idempotency_receipts) + "
            "(SELECT COUNT(*) FROM idempotency_conflicts)"
        )
    ).scalar_one()
    if state_count:
        msg = "ING-002 downgrade refused while idempotency evidence exists"
        raise RuntimeError(msg)
    with op.batch_alter_table("jobs") as batch:
        batch.drop_constraint("ck_jobs_completion_shape", type_="check")
        batch.drop_constraint("ck_jobs_result_digest", type_="check")
        batch.drop_constraint("ck_jobs_request_digest", type_="check")
        for column in ("completed_at", "result_sha256", "request_sha256", "input_ref"):
            batch.drop_column(column)
    op.drop_table("projection_idempotency_receipts")
    op.drop_index("ix_provider_operation_dispatch", table_name="provider_operation_results")
    op.drop_table("provider_operation_results")
    op.drop_index("ix_inbox_expired_lease", table_name="inbox_receipts")
    op.drop_table("inbox_receipts")
    op.drop_table("command_receipts")
    op.drop_index("ix_idempotency_conflicts_brain_time", table_name="idempotency_conflicts")
    op.drop_table("idempotency_conflicts")
