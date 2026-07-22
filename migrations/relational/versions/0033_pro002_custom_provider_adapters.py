"""PRO-002 custom provider adapter registry and immutable install evidence.

Revision ID: 0033_pro002_custom_adapters
Revises: 0032_pro001_provider_profiles
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0033_pro002_custom_adapters"
down_revision = "0032_pro001_provider_profiles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the canonical adapter registry and append-only activation journal."""
    op.create_table(
        "provider_adapters",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("protocol_version", sa.Integer(), nullable=False),
        sa.Column("package_digest", sa.Text(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("manifest_digest", sa.Text(), nullable=False),
        sa.Column("plan_digest", sa.Text(), nullable=False),
        sa.Column("attestation_digest", sa.Text(), nullable=False),
        sa.Column("transport", sa.Text(), nullable=False),
        sa.Column("capabilities", sa.LargeBinary(), nullable=False),
        sa.Column("evidence_json", sa.LargeBinary(), nullable=False),
        sa.Column("runtime_id", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("installed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "package_digest", "manifest_digest", name="uq_provider_adapter_package"
        ),
        sa.CheckConstraint(
            "protocol_version=1 AND status IN ('active','disabled','quarantined') "
            "AND transport IN ('framed_stdio','authenticated_http') "
            "AND length(package_digest)=64 AND package_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(signature)=64 AND signature NOT GLOB '*[^0-9a-f]*' "
            "AND length(manifest_digest)=64 AND manifest_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(attestation_digest)=64 AND attestation_digest NOT GLOB '*[^0-9a-f]*' "
            "AND json_valid(capabilities) AND json_type(capabilities)='array' "
            "AND json_array_length(capabilities)>0 "
            "AND json_valid(evidence_json) AND json_type(evidence_json)='object'",
            name="ck_provider_adapter_integrity",
        ),
    )
    op.create_index("ix_provider_adapter_status", "provider_adapters", ["status", "id"])
    op.create_table(
        "provider_adapter_installations",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column(
            "adapter_id",
            sa.Text(),
            sa.ForeignKey("provider_adapters.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("request_digest", sa.Text(), nullable=False),
        sa.Column("manifest_digest", sa.Text(), nullable=False),
        sa.Column("plan_digest", sa.Text(), nullable=False),
        sa.Column("attestation_digest", sa.Text(), nullable=False),
        sa.Column("runtime_id", sa.Text(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(request_digest)=64 AND request_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(manifest_digest)=64 AND manifest_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(attestation_digest)=64 AND attestation_digest NOT GLOB '*[^0-9a-f]*'",
            name="ck_provider_adapter_install_integrity",
        ),
    )
    for operation in ("UPDATE", "DELETE"):
        op.execute(
            f"CREATE TRIGGER trg_provider_adapter_installations_immutable_{operation.lower()} "
            f"BEFORE {operation} ON provider_adapter_installations "
            "BEGIN SELECT RAISE(ABORT, 'immutable provider adapter evidence'); END"
        )


def downgrade() -> None:
    """Refuse downgrade after an adapter has been installed."""
    connection = op.get_bind()
    count = connection.execute(sa.text("SELECT COUNT(*) FROM provider_adapters")).scalar_one()
    if count:
        message = "PRO-002 downgrade refused while provider adapters exist"
        raise RuntimeError(message)
    op.execute("DROP TRIGGER IF EXISTS trg_provider_adapter_installations_immutable_delete")
    op.execute("DROP TRIGGER IF EXISTS trg_provider_adapter_installations_immutable_update")
    op.drop_table("provider_adapter_installations")
    op.drop_index("ix_provider_adapter_status", table_name="provider_adapters")
    op.drop_table("provider_adapters")
