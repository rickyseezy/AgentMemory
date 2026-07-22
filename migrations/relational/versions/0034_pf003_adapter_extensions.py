"""PF-003 governed external adapter registrations and operation receipts.

Revision ID: 0034_pf003_adapter_extensions
Revises: 0033_pro002_custom_adapters
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0034_pf003_adapter_extensions"
down_revision = "0033_pro002_custom_adapters"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create immutable scope-bound registration and idempotency evidence."""
    op.create_table(
        "adapter_extension_registrations",
        sa.Column("registration_id", sa.Text(), primary_key=True),
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
        sa.Column("adapter_id", sa.Text(), nullable=False),
        sa.Column("adapter_version", sa.Text(), nullable=False),
        sa.Column("adapter_kind", sa.Text(), nullable=False),
        sa.Column("package_digest", sa.Text(), nullable=False),
        sa.Column("manifest_digest", sa.Text(), nullable=False),
        sa.Column("evidence_digest", sa.Text(), nullable=False),
        sa.Column("registration_digest", sa.Text(), nullable=False, unique=True),
        sa.Column("manifest_json", sa.LargeBinary(), nullable=False),
        sa.Column("evidence_json", sa.LargeBinary(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("registered_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "brain_id",
            "adapter_id",
            "adapter_version",
            name="uq_adapter_extension_version",
        ),
        sa.CheckConstraint(
            "adapter_kind IN ('agent','provider') AND state='active' "
            "AND length(package_digest)=64 AND package_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(manifest_digest)=64 AND manifest_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(evidence_digest)=64 AND evidence_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(registration_digest)=64 "
            "AND registration_digest NOT GLOB '*[^0-9a-f]*' "
            "AND json_valid(manifest_json) AND json_type(manifest_json)='object' "
            "AND json_valid(evidence_json) AND json_type(evidence_json)='object'",
            name="ck_adapter_extension_registration_integrity",
        ),
    )
    op.create_index(
        "ix_adapter_extension_scope",
        "adapter_extension_registrations",
        ["brain_id", "adapter_kind", "state", "adapter_id"],
    )
    op.create_table(
        "adapter_extension_operations",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column("request_digest", sa.Text(), nullable=False),
        sa.Column(
            "registration_id",
            sa.Text(),
            sa.ForeignKey(
                "adapter_extension_registrations.registration_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(request_digest)=64 AND request_digest NOT GLOB '*[^0-9a-f]*'",
            name="ck_adapter_extension_operation_integrity",
        ),
    )
    for table in ("adapter_extension_registrations", "adapter_extension_operations"):
        _immutable(table)


def _immutable(table: str) -> None:
    op.execute(
        f"CREATE TRIGGER trg_{table}_immutable_update BEFORE UPDATE ON {table} "
        "BEGIN SELECT RAISE(ABORT, 'immutable adapter extension evidence'); END"
    )
    op.execute(
        f"CREATE TRIGGER trg_{table}_immutable_delete BEFORE DELETE ON {table} "
        "BEGIN SELECT RAISE(ABORT, 'immutable adapter extension evidence'); END"
    )


def downgrade() -> None:
    """Refuse destructive downgrade after any governed registration exists."""
    connection = op.get_bind()
    count = connection.execute(
        sa.text("SELECT COUNT(*) FROM adapter_extension_registrations")
    ).scalar_one()
    if count:
        message = "PF-003 downgrade refused while adapter registrations exist"
        raise RuntimeError(message)
    for table in ("adapter_extension_operations", "adapter_extension_registrations"):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable_delete")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable_update")
    op.drop_table("adapter_extension_operations")
    op.drop_index("ix_adapter_extension_scope", table_name="adapter_extension_registrations")
    op.drop_table("adapter_extension_registrations")
