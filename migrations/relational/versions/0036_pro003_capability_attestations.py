"""PRO-003 immutable live provider capability attestations.

Revision ID: 0036_pro003_capability_attestations
Revises: 0035_pf005_mcp_sessions
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0036_pro003_capability_attestations"
down_revision = "0035_pf005_mcp_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Bind every new activation to runtime-validated immutable coordinates."""
    op.create_table(
        "provider_capability_attestations",
        sa.Column(
            "attestation_id",
            sa.Text(),
            sa.ForeignKey("provider_probe_evidence.evidence_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "profile_id",
            sa.Text(),
            sa.ForeignKey("provider_profiles.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("adapter_digest", sa.Text(), nullable=False),
        sa.Column("endpoint_fingerprint", sa.Text(), nullable=False),
        sa.Column("configuration_digest", sa.Text(), nullable=False),
        sa.Column("suite_digest", sa.Text(), nullable=False),
        sa.Column("canary_digest", sa.Text(), nullable=False),
        sa.Column("validation_digest", sa.Text(), nullable=False),
        sa.Column("validated_batches", sa.Integer(), nullable=False),
        sa.Column("recorded_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(attestation_id)=64 AND attestation_id NOT GLOB '*[^0-9a-f]*' "
            "AND length(adapter_digest)=64 AND adapter_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(endpoint_fingerprint)=64 "
            "AND endpoint_fingerprint NOT GLOB '*[^0-9a-f]*' "
            "AND length(configuration_digest)=64 "
            "AND configuration_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(suite_digest)=64 AND suite_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(canary_digest)=64 AND canary_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(validation_digest)=64 "
            "AND validation_digest NOT GLOB '*[^0-9a-f]*' "
            "AND validated_batches BETWEEN 1 AND 7",
            name="ck_provider_capability_attestation_integrity",
        ),
    )
    op.create_index(
        "ix_provider_capability_binding",
        "provider_capability_attestations",
        ["profile_id", "configuration_digest", "adapter_digest", "endpoint_fingerprint"],
    )
    for operation in ("UPDATE", "DELETE"):
        op.execute(
            f"CREATE TRIGGER trg_provider_capability_attestations_immutable_{operation.lower()} "
            f"BEFORE {operation} ON provider_capability_attestations "
            "BEGIN SELECT RAISE(ABORT, 'immutable provider capability attestation'); END"
        )


def downgrade() -> None:
    """Refuse to discard runtime evidence after any PRO-003 probe succeeded."""
    connection = op.get_bind()
    count = connection.execute(
        sa.text("SELECT COUNT(*) FROM provider_capability_attestations")
    ).scalar_one()
    if count:
        message = "PRO-003 downgrade refused while capability attestations exist"
        raise RuntimeError(message)
    op.execute("DROP TRIGGER IF EXISTS trg_provider_capability_attestations_immutable_delete")
    op.execute("DROP TRIGGER IF EXISTS trg_provider_capability_attestations_immutable_update")
    op.drop_index(
        "ix_provider_capability_binding",
        table_name="provider_capability_attestations",
    )
    op.drop_table("provider_capability_attestations")
