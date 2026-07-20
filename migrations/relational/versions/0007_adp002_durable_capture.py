"""ADP-002 encrypted canonical event capture and Brain key wrappers.

Revision ID: 0007_adp002_durable_capture
Revises: 0006_id004_retrieval_scope
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_adp002_durable_capture"
down_revision = "0006_id004_retrieval_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("agent_events") as batch:
        batch.drop_constraint("ck_smoke_event_classification", type_="check")
        batch.create_check_constraint(
            "ck_agent_event_classification",
            "classification IN ('public','internal','confidential','restricted','local_only')",
        )
        batch.create_foreign_key(
            "fk_agent_event_brain",
            "brains",
            ["brain_id"],
            ["id"],
            ondelete="RESTRICT",
        )

    op.create_table(
        "brain_encryption_keys",
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("key_id", sa.Text(), nullable=False, unique=True),
        sa.Column("envelope_version", sa.Integer(), nullable=False),
        sa.Column("algorithm", sa.Text(), nullable=False),
        sa.Column("wrapping_key_id", sa.Text(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("aad_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("envelope_version = 1", name="ck_brain_key_envelope_version"),
        sa.CheckConstraint("algorithm = 'AES-256-GCM'", name="ck_brain_key_algorithm"),
        sa.CheckConstraint("length(nonce) = 12", name="ck_brain_key_nonce"),
        sa.CheckConstraint("length(ciphertext) = 48", name="ck_brain_key_ciphertext"),
        sa.CheckConstraint("length(aad_sha256) = 32", name="ck_brain_key_aad"),
    )
    op.create_table(
        "agent_adapter_manifests",
        sa.Column("adapter_id", sa.Text(), nullable=False),
        sa.Column("adapter_version", sa.Text(), nullable=False),
        sa.Column("adapter_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("manifest_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("descriptor_json", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("adapter_id", "adapter_version", "adapter_digest"),
        sa.CheckConstraint("length(adapter_digest) = 32", name="ck_adapter_digest"),
        sa.CheckConstraint("length(manifest_sha256) = 32", name="ck_adapter_manifest_digest"),
        sa.CheckConstraint("json_valid(descriptor_json)", name="ck_adapter_descriptor_json"),
        sa.CheckConstraint("status IN ('active','revoked')", name="ck_adapter_manifest_status"),
    )
    op.create_table(
        "agent_event_envelopes",
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("project_id", sa.Text(), nullable=False),
        sa.Column("repository_id", sa.Text(), nullable=False),
        sa.Column("checkout_id", sa.Text(), nullable=True),
        sa.Column("ordering_key", sa.Text(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=True),
        sa.Column("correlation_id", sa.Text(), nullable=False),
        sa.Column("causation_id", sa.Text(), nullable=True),
        sa.Column("retention_policy_id", sa.Text(), nullable=False),
        sa.Column("canonical_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("envelope_version", sa.Integer(), nullable=False),
        sa.Column("algorithm", sa.Text(), nullable=False),
        sa.Column("brain_key_id", sa.Text(), nullable=False),
        sa.Column("data_key_id", sa.Text(), nullable=False, unique=True),
        sa.Column("payload_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("wrapped_data_key_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("wrapped_data_key", sa.LargeBinary(), nullable=False),
        sa.Column("aad_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("clock_skew_microseconds", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("ordering_key", "sequence", name="uq_agent_event_order_sequence"),
        sa.CheckConstraint("envelope_version = 1", name="ck_agent_envelope_version"),
        sa.CheckConstraint("algorithm = 'AES-256-GCM'", name="ck_agent_envelope_algorithm"),
        sa.CheckConstraint("length(canonical_sha256) = 32", name="ck_agent_canonical_digest"),
        sa.CheckConstraint("length(payload_nonce) = 12", name="ck_agent_payload_nonce"),
        sa.CheckConstraint(
            "length(wrapped_data_key_nonce) = 12", name="ck_agent_wrapped_key_nonce"
        ),
        sa.CheckConstraint("length(wrapped_data_key) = 48", name="ck_agent_wrapped_key"),
        sa.CheckConstraint("length(aad_sha256) = 32", name="ck_agent_envelope_aad"),
        sa.CheckConstraint("sequence IS NULL OR sequence >= 1", name="ck_agent_sequence"),
    )
    op.create_index(
        "ix_agent_event_scope_time",
        "agent_event_envelopes",
        ["project_id", "repository_id", "created_at"],
    )
    op.create_index(
        "ix_agent_event_order",
        "agent_event_envelopes",
        ["ordering_key", "sequence", "created_at"],
    )


def downgrade() -> None:
    connection = op.get_bind()
    captured = connection.execute(
        sa.text("SELECT COUNT(*) FROM agent_event_envelopes")
    ).scalar_one()
    if captured:
        msg = "ADP-002 downgrade refused while canonical encrypted events exist"
        raise RuntimeError(msg)
    op.drop_index("ix_agent_event_order", table_name="agent_event_envelopes")
    op.drop_index("ix_agent_event_scope_time", table_name="agent_event_envelopes")
    op.drop_table("agent_event_envelopes")
    op.drop_table("agent_adapter_manifests")
    op.drop_table("brain_encryption_keys")
    with op.batch_alter_table("agent_events") as batch:
        batch.drop_constraint("fk_agent_event_brain", type_="foreignkey")
        batch.drop_constraint("ck_agent_event_classification", type_="check")
        batch.create_check_constraint(
            "ck_smoke_event_classification",
            "classification IN ('internal')",
        )
