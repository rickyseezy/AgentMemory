"""ING-006 immutable event schema lineage and resumable derived views.

Revision ID: 0014_ing006_schema_evolution
Revises: 0013_ing005_capture_privacy
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014_ing006_schema_evolution"
down_revision = "0013_ing005_capture_privacy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "event_schema_sources",
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("schema_family", sa.Text(), nullable=False),
        sa.Column("schema_major", sa.Integer(), nullable=False),
        sa.Column("event_schema_version", sa.Integer(), nullable=False),
        sa.Column("original_canonical_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(schema_family) BETWEEN 1 AND 128 AND schema_family NOT GLOB '*[^a-z0-9._-]*'",
            name="ck_event_schema_source_family",
        ),
        sa.CheckConstraint("schema_major >= 1", name="ck_event_schema_source_major"),
        sa.CheckConstraint("event_schema_version >= 1", name="ck_event_schema_source_version"),
        sa.CheckConstraint(
            "length(original_canonical_sha256)=32",
            name="ck_event_schema_source_digest",
        ),
    )
    op.create_index(
        "ix_event_schema_sources_order",
        "event_schema_sources",
        ["event_id"],
    )
    op.execute(
        "INSERT INTO event_schema_sources "
        "(event_id,schema_family,schema_major,event_schema_version,"
        "original_canonical_sha256,created_at,schema_version) "
        "SELECT e.event_id,'agent_event',1,e.schema_version,x.canonical_sha256,e.ingested_at,1 "
        "FROM agent_events e JOIN agent_event_envelopes x ON x.event_id=e.event_id"
    )

    op.create_table(
        "event_schema_migrations",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column("schema_family", sa.Text(), nullable=False),
        sa.Column("target_major", sa.Integer(), nullable=False),
        sa.Column("target_version", sa.Integer(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("cursor_event_id", sa.Text(), nullable=True),
        sa.Column("source_watermark_event_id", sa.Text(), nullable=True),
        sa.Column("scanned", sa.Integer(), nullable=False),
        sa.Column("upcasted", sa.Integer(), nullable=False),
        sa.Column("current_count", sa.Integer(), nullable=False),
        sa.Column("quarantined", sa.Integer(), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "state IN ('pending','running','interrupted','completed')",
            name="ck_event_schema_migration_state",
        ),
        sa.CheckConstraint(
            "target_major >= 1 AND target_version >= 1",
            name="ck_event_schema_migration_target",
        ),
        sa.CheckConstraint(
            "scanned >= 0 AND upcasted >= 0 AND current_count >= 0 "
            "AND quarantined >= 0 AND total >= 0 "
            "AND scanned=upcasted+current_count+quarantined AND scanned<=total",
            name="ck_event_schema_migration_counts",
        ),
        sa.CheckConstraint(
            "state<>'completed' OR scanned=total",
            name="ck_event_schema_migration_completion",
        ),
    )

    op.create_table(
        "event_schema_views",
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("event_schema_sources.event_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "operation_id",
            sa.Text(),
            sa.ForeignKey("event_schema_migrations.operation_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("target_major", sa.Integer(), nullable=False),
        sa.Column("target_version", sa.Integer(), nullable=False),
        sa.Column("original_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("derived_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("trace_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("trace_json", sa.Text(), nullable=False),
        sa.Column("envelope_version", sa.Integer(), nullable=False),
        sa.Column("algorithm", sa.Text(), nullable=False),
        sa.Column("brain_key_id", sa.Text(), nullable=False),
        sa.Column("data_key_id", sa.Text(), nullable=False),
        sa.Column("payload_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("wrapped_data_key_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("wrapped_data_key", sa.LargeBinary(), nullable=False),
        sa.Column("aad_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "target_major >= 1 AND target_version >= 1",
            name="ck_event_schema_view_target",
        ),
        sa.CheckConstraint(
            "length(original_sha256)=32 AND length(derived_sha256)=32 "
            "AND length(trace_sha256)=32 AND length(aad_sha256)=32",
            name="ck_event_schema_view_digests",
        ),
        sa.CheckConstraint("json_valid(trace_json)", name="ck_event_schema_view_trace"),
        sa.CheckConstraint(
            "envelope_version=1 AND algorithm='AES-256-GCM' "
            "AND length(payload_nonce)=12 AND length(wrapped_data_key_nonce)=12 "
            "AND length(ciphertext)>=16 AND length(wrapped_data_key)>=48",
            name="ck_event_schema_view_envelope",
        ),
    )
    op.create_index(
        "ix_event_schema_views_operation",
        "event_schema_views",
        ["operation_id", "event_id"],
    )

    op.create_table(
        "event_schema_quarantine",
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("event_schema_sources.event_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "operation_id",
            sa.Text(),
            sa.ForeignKey("event_schema_migrations.operation_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("source_major", sa.Integer(), nullable=False),
        sa.Column("source_version", sa.Integer(), nullable=False),
        sa.Column("target_major", sa.Integer(), nullable=False),
        sa.Column("target_version", sa.Integer(), nullable=False),
        sa.Column("original_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("reason_code", sa.Text(), nullable=False),
        sa.Column("quarantined_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "reason_code IN ('unsupported_major','future_version','missing_upcaster',"
            "'invalid_transform','extension_loss')",
            name="ck_event_schema_quarantine_reason",
        ),
        sa.CheckConstraint(
            "source_major >= 1 AND source_version >= 1 "
            "AND target_major >= 1 AND target_version >= 1",
            name="ck_event_schema_quarantine_versions",
        ),
        sa.CheckConstraint("length(original_sha256)=32", name="ck_event_schema_quarantine_digest"),
    )
    op.create_index(
        "ix_event_schema_quarantine_operation",
        "event_schema_quarantine",
        ["operation_id", "event_id"],
    )


def downgrade() -> None:
    connection = op.get_bind()
    evidence = connection.execute(
        sa.text(
            "SELECT (SELECT COUNT(*) FROM event_schema_sources) + "
            "(SELECT COUNT(*) FROM event_schema_migrations) + "
            "(SELECT COUNT(*) FROM event_schema_views) + "
            "(SELECT COUNT(*) FROM event_schema_quarantine)"
        )
    ).scalar_one()
    if evidence:
        msg = "ING-006 downgrade refused while schema lineage or derived evidence exists"
        raise RuntimeError(msg)
    op.drop_index(
        "ix_event_schema_quarantine_operation",
        table_name="event_schema_quarantine",
    )
    op.drop_table("event_schema_quarantine")
    op.drop_index("ix_event_schema_views_operation", table_name="event_schema_views")
    op.drop_table("event_schema_views")
    op.drop_table("event_schema_migrations")
    op.drop_index("ix_event_schema_sources_order", table_name="event_schema_sources")
    op.drop_table("event_schema_sources")
