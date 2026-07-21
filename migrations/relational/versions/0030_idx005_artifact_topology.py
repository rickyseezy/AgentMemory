"""IDX-005 dependency, messaging, and infrastructure topology.

Revision ID: 0030_idx005_artifact_topology
Revises: 0029_idx004_api_topology
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op

if TYPE_CHECKING:
    from sqlalchemy.schema import SchemaItem

revision = "0030_idx005_artifact_topology"
down_revision = "0029_idx004_api_topology"
branch_labels = None
depends_on = None

_CLASSIFICATIONS = "'public','internal','confidential','restricted','local_only'"
_PLUGIN_KINDS = (
    "'dependency_manifest','dependency_lock','container','kubernetes','terraform','ci',"
    "'environment','messaging_schema'"
)
_ENTITY_KINDS = (
    "'package','container_image','workload','infrastructure_resource','pipeline',"
    "'environment_reference','message_channel','event_schema','service'"
)
_RELATIONS = "'depends_on','deployed_as','produces','consumes'"
_SENSITIVITIES = "'public_configuration','sensitive_configuration','secret_reference'"
_UNKNOWN_REASONS = "'unsupported_construct','unresolved_template','unresolved_overlay'"


def upgrade() -> None:
    """Install append-only topology observations and graph projection receipts."""
    _create_batches()
    _create_observations()
    _create_projection_receipts()
    for table in _TABLES:
        _immutable(table)


def _create_batches() -> None:
    op.create_table(
        "artifact_topology_batches",
        sa.Column("batch_id", sa.Text(), primary_key=True),
        sa.Column("operation_id", sa.Text(), nullable=False, unique=True),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "project_id",
            sa.Text(),
            sa.ForeignKey("projects.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "source_file_id",
            sa.Text(),
            sa.ForeignKey("source_files.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "source_revision_context_id",
            sa.Text(),
            sa.ForeignKey("source_revision_contexts.context_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("commit_sha", sa.Text(), nullable=False),
        sa.Column("plugin_kind", sa.Text(), nullable=False),
        sa.Column("plugin_version", sa.Text(), nullable=False),
        sa.Column("batch_digest", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("supersedes_batch_id", sa.Text(), nullable=True),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("registered_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["supersedes_batch_id"],
            ["artifact_topology_batches.batch_id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(batch_id)=64 AND length(batch_digest)=32 AND length(scope_fingerprint)=32",
            name="ck_artifact_topology_batch_digests",
        ),
        sa.CheckConstraint(
            f"plugin_kind IN ({_PLUGIN_KINDS})", name="ck_artifact_topology_batch_plugin"
        ),
        sa.CheckConstraint(
            "length(commit_sha) IN (40,64) AND commit_sha NOT GLOB '*[^0-9a-f]*'",
            name="ck_artifact_topology_batch_commit",
        ),
    )
    op.create_index(
        "ix_artifact_topology_latest_source",
        "artifact_topology_batches",
        ["brain_id", "repository_id", "source_file_id", "registered_at", "batch_id"],
    )


def _evidence_columns() -> tuple[SchemaItem, ...]:
    return (
        sa.Column(
            "evidence_id",
            sa.Text(),
            sa.ForeignKey("assertion_evidence_sources.evidence_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("source_semantic_id", sa.Text(), nullable=False),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("observed_at", sa.BigInteger(), nullable=False),
    )


def _create_observations() -> None:
    op.create_table(
        "artifact_topology_candidates",
        sa.Column("candidate_id", sa.Text(), primary_key=True),
        sa.Column(
            "batch_id",
            sa.Text(),
            sa.ForeignKey("artifact_topology_batches.batch_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        *_evidence_columns(),
        sa.Column("entity_id", sa.Text(), nullable=False),
        sa.Column("entity_kind", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("version", sa.Text(), nullable=True),
        sa.Column("environment_reference", sa.Text(), nullable=True),
        sa.Column("sensitivity", sa.Text(), nullable=True),
        sa.Column("qualifiers_json", sa.LargeBinary(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            f"length(candidate_id)=64 AND entity_kind IN ({_ENTITY_KINDS}) "
            f"AND classification IN ({_CLASSIFICATIONS}) "
            "AND length(relative_path) BETWEEN 1 AND 4096",
            name="ck_artifact_topology_candidate_identity",
        ),
        sa.CheckConstraint(
            "(environment_reference IS NULL AND sensitivity IS NULL) OR "
            f"(environment_reference IS NOT NULL AND sensitivity IN ({_SENSITIVITIES}))",
            name="ck_artifact_topology_candidate_sensitivity",
        ),
        sa.CheckConstraint(
            "json_valid(qualifiers_json) AND json_type(qualifiers_json)='array'",
            name="ck_artifact_topology_candidate_qualifiers",
        ),
    )
    op.create_index(
        "ix_artifact_topology_candidate_entity",
        "artifact_topology_candidates",
        ["entity_kind", "entity_id", "candidate_id"],
    )
    op.create_table(
        "artifact_topology_relations",
        sa.Column("relation_id", sa.Text(), primary_key=True),
        sa.Column(
            "batch_id",
            sa.Text(),
            sa.ForeignKey("artifact_topology_batches.batch_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        *_evidence_columns(),
        sa.Column("subject_entity_id", sa.Text(), nullable=False),
        sa.Column("relation_kind", sa.Text(), nullable=False),
        sa.Column("object_entity_id", sa.Text(), nullable=False),
        sa.Column("environment_reference", sa.Text(), nullable=True),
        sa.Column("valid_from", sa.BigInteger(), nullable=False),
        sa.Column("valid_to", sa.BigInteger(), nullable=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            f"length(relation_id)=64 AND relation_kind IN ({_RELATIONS}) "
            f"AND classification IN ({_CLASSIFICATIONS}) AND subject_entity_id<>object_entity_id",
            name="ck_artifact_topology_relation_identity",
        ),
        sa.CheckConstraint(
            "valid_to IS NULL OR valid_to>valid_from",
            name="ck_artifact_topology_relation_interval",
        ),
    )
    op.create_index(
        "ix_artifact_topology_relation_temporal",
        "artifact_topology_relations",
        ["relation_kind", "subject_entity_id", "object_entity_id", "valid_from", "valid_to"],
    )
    op.create_table(
        "artifact_topology_unknown_evidence",
        sa.Column("unknown_id", sa.Text(), primary_key=True),
        sa.Column(
            "batch_id",
            sa.Text(),
            sa.ForeignKey("artifact_topology_batches.batch_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        *_evidence_columns(),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("fragment_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("start_line", sa.Integer(), nullable=False),
        sa.Column("end_line", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            f"length(unknown_id)=64 AND reason IN ({_UNKNOWN_REASONS}) "
            "AND length(fragment_digest)=32 AND start_line BETWEEN 1 AND 10000000 "
            "AND end_line BETWEEN start_line AND 10000000",
            name="ck_artifact_topology_unknown_identity",
        ),
    )


def _create_projection_receipts() -> None:
    op.create_table(
        "artifact_topology_projection_receipts",
        sa.Column(
            "relation_id",
            sa.Text(),
            sa.ForeignKey("artifact_topology_relations.relation_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "assertion_id",
            sa.Text(),
            sa.ForeignKey("assertion_candidates.assertion_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("operation_id", sa.Text(), nullable=False),
        sa.Column("projected_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
    )


_TABLES = (
    "artifact_topology_batches",
    "artifact_topology_candidates",
    "artifact_topology_relations",
    "artifact_topology_unknown_evidence",
    "artifact_topology_projection_receipts",
)


def _immutable(table: str) -> None:
    op.execute(
        f"CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} BEGIN "
        f"SELECT RAISE(ABORT, '{table} is immutable'); END"
    )
    op.execute(
        f"CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN "
        f"SELECT RAISE(ABORT, '{table} is immutable'); END"
    )


def downgrade() -> None:
    """Refuse to erase any retained topology observation or projection receipt."""
    connection = op.get_bind()
    if any(
        connection.execute(  # nosec B608 -- Closed migration-owned table tuple.
            sa.text(f"SELECT EXISTS(SELECT 1 FROM {table})")  # noqa: S608
        ).scalar_one()
        for table in _TABLES
    ):
        message = "IDX-005 artifact topology history prevents destructive downgrade"
        raise RuntimeError(message)
    op.drop_index(
        "ix_artifact_topology_relation_temporal", table_name="artifact_topology_relations"
    )
    op.drop_index(
        "ix_artifact_topology_candidate_entity", table_name="artifact_topology_candidates"
    )
    op.drop_index("ix_artifact_topology_latest_source", table_name="artifact_topology_batches")
    for table in reversed(_TABLES):
        op.drop_table(table)
