"""PRO-001 provider profiles, immutable revisions, probes, and operations.

Revision ID: 0032_pro001_provider_profiles
Revises: 0031_idx006_content_policy
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0032_pro001_provider_profiles"
down_revision = "0031_idx006_content_policy"
branch_labels = None
depends_on = None

_OPERATIONS = "'embedding','reranking'"
_STATUS = "'draft','active'"
_KINDS = "'create','probe'"


def upgrade() -> None:
    """Install canonical provider configuration with append-only evidence history."""
    op.create_table(
        "provider_profiles",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("adapter_id", sa.Text(), nullable=False),
        sa.Column("operation", sa.Text(), nullable=False),
        sa.Column("model_id", sa.Text(), nullable=False),
        sa.Column("configuration_digest", sa.Text(), nullable=False),
        sa.Column("manifest_digest", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("active_probe_id", sa.Text(), nullable=True),
        sa.Column("document_json", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("brain_id", "configuration_digest", name="uq_provider_profile_config"),
        sa.CheckConstraint(
            f"operation IN ({_OPERATIONS}) AND status IN ({_STATUS}) AND version>=1 "
            "AND length(configuration_digest)=64 AND configuration_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(manifest_digest)=64 AND manifest_digest NOT GLOB '*[^0-9a-f]*' "
            "AND ((status='draft' AND active_probe_id IS NULL) OR "
            "(status='active' AND active_probe_id IS NOT NULL)) "
            "AND json_valid(document_json) AND json_type(document_json)='object'",
            name="ck_provider_profile_integrity",
        ),
    )
    op.create_index(
        "ix_provider_profile_scope",
        "provider_profiles",
        ["brain_id", "status", "operation", "adapter_id"],
    )
    op.create_table(
        "provider_profile_revisions",
        sa.Column(
            "profile_id",
            sa.Text(),
            sa.ForeignKey("provider_profiles.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("snapshot_digest", sa.Text(), nullable=False),
        sa.Column("document_json", sa.LargeBinary(), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("recorded_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("profile_id", "version"),
        sa.UniqueConstraint("snapshot_digest", name="uq_provider_profile_snapshot"),
        sa.CheckConstraint(
            f"version>=1 AND status IN ({_STATUS}) AND length(snapshot_digest)=64 "
            "AND snapshot_digest NOT GLOB '*[^0-9a-f]*' AND length(scope_fingerprint)=32 "
            "AND json_valid(document_json) AND json_type(document_json)='object'",
            name="ck_provider_profile_revision_integrity",
        ),
    )
    op.create_table(
        "provider_probe_evidence",
        sa.Column("evidence_id", sa.Text(), primary_key=True),
        sa.Column(
            "profile_id",
            sa.Text(),
            sa.ForeignKey("provider_profiles.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("manifest_digest", sa.Text(), nullable=False),
        sa.Column("adapter_id", sa.Text(), nullable=False),
        sa.Column("operation", sa.Text(), nullable=False),
        sa.Column("model_id", sa.Text(), nullable=False),
        sa.Column("model_revision", sa.Text(), nullable=False),
        sa.Column("revision_fingerprint", sa.Text(), nullable=False),
        sa.Column("dimension", sa.Integer(), nullable=True),
        sa.Column("dtype", sa.Text(), nullable=True),
        sa.Column("purposes_json", sa.LargeBinary(), nullable=False),
        sa.Column("evidence_json", sa.LargeBinary(), nullable=False),
        sa.Column("probed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["profile_id", "profile_version"],
            ["provider_profile_revisions.profile_id", "provider_profile_revisions.version"],
            name="fk_provider_probe_revision",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.UniqueConstraint("profile_id", "profile_version", name="uq_provider_probe_version"),
        sa.CheckConstraint(
            f"length(evidence_id)=64 AND evidence_id NOT GLOB '*[^0-9a-f]*' "
            f"AND length(manifest_digest)=64 AND manifest_digest NOT GLOB '*[^0-9a-f]*' "
            f"AND operation IN ({_OPERATIONS}) AND length(revision_fingerprint)=64 "
            "AND revision_fingerprint NOT GLOB '*[^0-9a-f]*' "
            "AND ((operation='embedding' AND dimension BETWEEN 1 AND 65536 AND dtype='float32') "
            "OR (operation='reranking' AND dimension IS NULL AND dtype IS NULL)) "
            "AND json_valid(purposes_json) AND json_type(purposes_json)='array' "
            "AND json_valid(evidence_json) AND json_type(evidence_json)='object'",
            name="ck_provider_probe_integrity",
        ),
    )
    with op.batch_alter_table("provider_profiles") as batch:
        batch.create_foreign_key(
            "fk_provider_profile_active_probe",
            "provider_probe_evidence",
            ["active_probe_id"],
            ["evidence_id"],
            ondelete="RESTRICT",
            use_alter=True,
        )
    op.create_table(
        "provider_profile_operations",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column("operation_kind", sa.Text(), nullable=False),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "profile_id",
            sa.Text(),
            sa.ForeignKey("provider_profiles.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("request_digest", sa.Text(), nullable=False),
        sa.Column("result_snapshot_digest", sa.Text(), nullable=False),
        sa.Column("result_version", sa.Integer(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            f"operation_kind IN ({_KINDS}) AND length(request_digest)=64 "
            "AND request_digest NOT GLOB '*[^0-9a-f]*' AND length(result_snapshot_digest)=64 "
            "AND result_snapshot_digest NOT GLOB '*[^0-9a-f]*' AND result_version>=1",
            name="ck_provider_profile_operation_integrity",
        ),
    )
    for table in (
        "provider_profile_revisions",
        "provider_probe_evidence",
        "provider_profile_operations",
    ):
        _immutable(table)


def _immutable(table: str) -> None:
    op.execute(
        f"CREATE TRIGGER trg_{table}_immutable_update BEFORE UPDATE ON {table} "
        "BEGIN SELECT RAISE(ABORT, 'immutable provider evidence'); END"
    )
    op.execute(
        f"CREATE TRIGGER trg_{table}_immutable_delete BEFORE DELETE ON {table} "
        "BEGIN SELECT RAISE(ABORT, 'immutable provider evidence'); END"
    )


def downgrade() -> None:
    """Refuse destructive downgrade after canonical provider history exists."""
    connection = op.get_bind()
    count = connection.execute(sa.text("SELECT COUNT(*) FROM provider_profiles")).scalar_one()
    if count:
        msg = "PRO-001 downgrade refused while provider profiles exist"
        raise RuntimeError(msg)
    for table in (
        "provider_profile_operations",
        "provider_probe_evidence",
        "provider_profile_revisions",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable_delete")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable_update")
    op.drop_table("provider_profile_operations")
    with op.batch_alter_table("provider_profiles") as batch:
        batch.drop_constraint("fk_provider_profile_active_probe", type_="foreignkey")
    op.drop_table("provider_probe_evidence")
    op.drop_table("provider_profile_revisions")
    op.drop_index("ix_provider_profile_scope", table_name="provider_profiles")
    op.drop_table("provider_profiles")
