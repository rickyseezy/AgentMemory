"""ING-001 durable event dispatch, artifact references, and repair state.

Revision ID: 0009_ing001_durable_processing
Revises: 0008_adp003_adapter_capabilities
"""

from __future__ import annotations

import hashlib

import sqlalchemy as sa
from alembic import op

revision = "0009_ing001_durable_processing"
down_revision = "0008_adp003_adapter_capabilities"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "artifacts",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("media_type", sa.Text(), nullable=False),
        sa.Column("byte_length", sa.BigInteger(), nullable=False),
        sa.Column("encryption_key_ref", sa.Text(), nullable=False),
        sa.Column("blob_uri", sa.Text(), nullable=False),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("brain_id", "sha256", name="uq_artifact_brain_digest"),
        sa.CheckConstraint("length(sha256) = 32", name="ck_artifact_digest"),
        sa.CheckConstraint("byte_length >= 1", name="ck_artifact_byte_length"),
        sa.CheckConstraint("blob_uri LIKE 'cas://sha256/%'", name="ck_artifact_blob_uri"),
        sa.CheckConstraint(
            "classification IN ('public','internal','confidential','restricted','local_only')",
            name="ck_artifact_classification",
        ),
    )
    op.execute(
        "ALTER TABLE agent_events ADD COLUMN payload_ref TEXT NULL "
        "REFERENCES artifacts(id) ON DELETE RESTRICT"
    )

    with op.batch_alter_table("outbox_messages") as batch:
        batch.drop_constraint("ck_outbox_status", type_="check")
        batch.add_column(sa.Column("priority", sa.Integer(), nullable=False, server_default="100"))
        batch.add_column(
            sa.Column("not_before", sa.BigInteger(), nullable=False, server_default="0")
        )
        batch.add_column(sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("lease_owner", sa.Text(), nullable=True))
        batch.add_column(sa.Column("lease_until", sa.BigInteger(), nullable=True))
        batch.add_column(sa.Column("completed_at", sa.BigInteger(), nullable=True))
        batch.add_column(sa.Column("payload_sha256", sa.LargeBinary(32), nullable=True))
        batch.add_column(sa.Column("last_error_code", sa.Text(), nullable=True))
        batch.create_check_constraint(
            "ck_outbox_status",
            "status IN ('ready','leased','completed','repair_required')",
        )
        batch.create_check_constraint("ck_outbox_priority", "priority BETWEEN 0 AND 1000")
        batch.create_check_constraint("ck_outbox_attempts", "attempts >= 0")
        batch.create_check_constraint(
            "ck_outbox_lease_shape",
            "(status = 'leased' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL) OR "
            "(status <> 'leased' AND lease_owner IS NULL AND lease_until IS NULL)",
        )
        batch.create_check_constraint(
            "ck_outbox_completed_shape",
            "(status = 'completed' AND completed_at IS NOT NULL) OR "
            "(status <> 'completed' AND completed_at IS NULL)",
        )

    connection = op.get_bind()
    rows = connection.execute(sa.text("SELECT id,payload,created_at FROM outbox_messages")).all()
    for message_id, payload, created_at in rows:
        encoded = str(payload).encode("utf-8")
        connection.execute(
            sa.text(
                "UPDATE outbox_messages SET payload_sha256=:digest, not_before=:not_before "
                "WHERE id=:id"
            ),
            {
                "digest": hashlib.sha256(encoded).digest(),
                "id": message_id,
                "not_before": created_at,
            },
        )
    with op.batch_alter_table("outbox_messages") as batch:
        batch.alter_column("payload_sha256", existing_type=sa.LargeBinary(32), nullable=False)
        batch.create_check_constraint(
            "ck_outbox_payload_digest",
            "length(payload_sha256) = 32",
        )
    op.create_index(
        "ix_outbox_dispatch",
        "outbox_messages",
        ["status", "priority", "not_before", "id"],
    )
    op.create_index(
        "ix_outbox_expired_lease",
        "outbox_messages",
        ["status", "lease_until"],
    )

    op.create_table(
        "event_projection_receipts",
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "outbox_message_id",
            sa.Text(),
            sa.ForeignKey("outbox_messages.id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("canonical_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("projection_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("length(canonical_sha256) = 32", name="ck_projection_canonical_digest"),
        sa.CheckConstraint("length(projection_sha256) = 32", name="ck_projection_digest"),
        sa.CheckConstraint("status = 'completed'", name="ck_projection_terminal_status"),
    )
    op.create_table(
        "ingestion_repair_alerts",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "source_event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "outbox_message_id",
            sa.Text(),
            sa.ForeignKey("outbox_messages.id", ondelete="RESTRICT"),
            nullable=True,
            unique=True,
        ),
        sa.Column("component", sa.Text(), nullable=False),
        sa.Column("error_code", sa.Text(), nullable=False),
        sa.Column("safe_details", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("first_detected_at", sa.BigInteger(), nullable=False),
        sa.Column("last_detected_at", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("component = 'canonical_ingestion'", name="ck_repair_component"),
        sa.CheckConstraint("state IN ('open','acknowledged','resolved')", name="ck_repair_state"),
    )


def downgrade() -> None:
    connection = op.get_bind()
    irreversible = connection.execute(
        sa.text(
            "SELECT "
            "(SELECT COUNT(*) FROM event_projection_receipts) + "
            "(SELECT COUNT(*) FROM ingestion_repair_alerts) + "
            "(SELECT COUNT(*) FROM artifacts) + "
            "(SELECT COUNT(*) FROM outbox_messages WHERE status NOT IN ('ready','completed'))"
        )
    ).scalar_one()
    if irreversible:
        msg = "ING-001 downgrade refused while durable processing state exists"
        raise RuntimeError(msg)
    op.drop_table("ingestion_repair_alerts")
    op.drop_table("event_projection_receipts")
    op.drop_index("ix_outbox_expired_lease", table_name="outbox_messages")
    op.drop_index("ix_outbox_dispatch", table_name="outbox_messages")
    with op.batch_alter_table("outbox_messages") as batch:
        batch.drop_constraint("ck_outbox_payload_digest", type_="check")
        batch.drop_constraint("ck_outbox_completed_shape", type_="check")
        batch.drop_constraint("ck_outbox_lease_shape", type_="check")
        batch.drop_constraint("ck_outbox_attempts", type_="check")
        batch.drop_constraint("ck_outbox_priority", type_="check")
        batch.drop_constraint("ck_outbox_status", type_="check")
        for column in (
            "last_error_code",
            "payload_sha256",
            "completed_at",
            "lease_until",
            "lease_owner",
            "attempts",
            "not_before",
            "priority",
        ):
            batch.drop_column(column)
        batch.create_check_constraint("ck_outbox_status", "status IN ('ready','completed')")
    op.execute("ALTER TABLE agent_events DROP COLUMN payload_ref")
    op.drop_table("artifacts")
