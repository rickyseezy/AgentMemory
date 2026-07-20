"""PF-002 canonical replay ledger and isolated projection generations.

Revision ID: 0002_pf002_projection_rebuild
Revises: 0001_pf001_core
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_pf002_projection_rebuild"
down_revision = "0001_pf001_core"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "domain_events",
        sa.Column("sequence", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.Text(), nullable=False, unique=True),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("projection_type", sa.Text(), nullable=False),
        sa.Column("stable_id", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("payload_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("source_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("missing_dependency", sa.Text(), nullable=True),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("recorded_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "brain_id",
            "projection_type",
            "stable_id",
            "sequence",
            name="uq_domain_projection_source",
        ),
        sa.CheckConstraint(
            "projection_type IN ('graph','memory','search','code','vector')",
            name="ck_domain_event_projection_type",
        ),
        sa.CheckConstraint("length(target_id_hash) = 32", name="ck_domain_event_target_hash"),
        sa.CheckConstraint("length(payload_hash) = 32", name="ck_domain_event_payload_hash"),
        sa.CheckConstraint("length(source_digest) = 32", name="ck_domain_event_source_digest"),
        sa.CheckConstraint("json_valid(payload_json)", name="ck_domain_event_payload_json"),
    )
    op.create_index(
        "ix_domain_events_replay",
        "domain_events",
        ["brain_id", "projection_type", "sequence"],
    )
    op.create_table(
        "projection_rebuilds",
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
        sa.Column("projection_type", sa.Text(), nullable=False),
        sa.Column("source_watermark", sa.Integer(), nullable=False),
        sa.Column("cursor", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rebuild_key", sa.LargeBinary(32), nullable=False),
        sa.Column("generation_id", sa.LargeBinary(32), nullable=False),
        sa.Column("manifest_json", sa.Text(), nullable=False),
        sa.Column("manifest_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("active_generation_at_start", sa.LargeBinary(32), nullable=True),
        sa.Column("record_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("skipped_tombstones", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("generation_digest", sa.LargeBinary(32), nullable=True),
        sa.Column("partial_reason", sa.Text(), nullable=True),
        sa.Column("lease_until", sa.BigInteger(), nullable=True),
        sa.Column("retry_at", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "rebuild_key", "manifest_digest", name="uq_projection_rebuild_identity"
        ),
        sa.UniqueConstraint("generation_id", name="uq_projection_rebuild_generation"),
        sa.CheckConstraint("source_watermark >= 0", name="ck_rebuild_watermark"),
        sa.CheckConstraint("cursor >= 0 AND cursor <= source_watermark", name="ck_rebuild_cursor"),
        sa.CheckConstraint(
            "state IN ('queued','building','partial','validating','ready','active',"
            "'failed','superseded')",
            name="ck_rebuild_state",
        ),
        sa.CheckConstraint("length(rebuild_key) = 32", name="ck_rebuild_key"),
        sa.CheckConstraint("length(generation_id) = 32", name="ck_rebuild_generation"),
        sa.CheckConstraint("length(manifest_digest) = 32", name="ck_rebuild_manifest_digest"),
        sa.CheckConstraint("json_valid(manifest_json)", name="ck_rebuild_manifest_json"),
        sa.CheckConstraint(
            "(state = 'building' AND lease_until IS NOT NULL) OR "
            "(state <> 'building' AND lease_until IS NULL)",
            name="ck_rebuild_lease",
        ),
    )
    op.create_index("ix_projection_rebuild_queue", "projection_rebuilds", ["state", "updated_at"])
    op.create_table(
        "index_generations",
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("projection_type", sa.Text(), nullable=False),
        sa.Column("generation_id", sa.LargeBinary(32), nullable=False),
        sa.Column("manifest_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("activated_at", sa.BigInteger(), nullable=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("brain_id", "projection_type", "generation_id"),
        sa.CheckConstraint(
            "state IN ('shadow','active','superseded')", name="ck_index_generation_state"
        ),
        sa.CheckConstraint("length(generation_id) = 32", name="ck_index_generation_id"),
        sa.CheckConstraint("length(manifest_digest) = 32", name="ck_index_manifest_digest"),
    )
    op.create_table(
        "active_projection_generations",
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("projection_type", sa.Text(), nullable=False),
        sa.Column("generation_id", sa.LargeBinary(32), nullable=False),
        sa.Column("activated_at", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("brain_id", "projection_type"),
        sa.CheckConstraint("length(generation_id) = 32", name="ck_active_generation_id"),
    )
    op.create_table(
        "projection_records",
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("projection_type", sa.Text(), nullable=False),
        sa.Column("generation_id", sa.LargeBinary(32), nullable=False),
        sa.Column("stable_id", sa.Text(), nullable=False),
        sa.Column("source_event_id", sa.Text(), nullable=False),
        sa.Column("source_sequence", sa.Integer(), nullable=False),
        sa.Column("source_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("content_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("manifest_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("brain_id", "projection_type", "generation_id", "stable_id"),
        sa.CheckConstraint("json_valid(payload_json)", name="ck_projection_record_json"),
        sa.CheckConstraint("length(generation_id) = 32", name="ck_projection_record_generation"),
        sa.CheckConstraint("length(source_digest) = 32", name="ck_projection_record_source_digest"),
        sa.CheckConstraint(
            "length(content_digest) = 32", name="ck_projection_record_content_digest"
        ),
        sa.CheckConstraint("length(target_id_hash) = 32", name="ck_projection_record_target_hash"),
        sa.CheckConstraint("length(manifest_digest) = 32", name="ck_projection_record_manifest"),
    )
    op.create_index(
        "ix_projection_records_lineage",
        "projection_records",
        ["source_event_id", "source_sequence"],
    )


def downgrade() -> None:
    op.drop_index("ix_projection_records_lineage", table_name="projection_records")
    op.drop_table("projection_records")
    op.drop_table("active_projection_generations")
    op.drop_table("index_generations")
    op.drop_index("ix_projection_rebuild_queue", table_name="projection_rebuilds")
    op.drop_table("projection_rebuilds")
    op.drop_index("ix_domain_events_replay", table_name="domain_events")
    op.drop_table("domain_events")
