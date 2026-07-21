"""IDX-002 durable incremental plans, bindings, lineage, and projection outbox.

Revision ID: 0027_idx002_incremental_index
Revises: 0026_idx001_code_entities
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0027_idx002_incremental_index"
down_revision = "0026_idx001_code_entities"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Install append-only incremental run, lineage, binding, and outbox evidence."""
    _create_runs()
    _create_plans_and_snapshots()
    _create_bindings_and_lineage()
    _create_projection_outbox()
    for table in (
        "incremental_index_runs",
        "incremental_index_plan_operations",
        "incremental_index_run_snapshots",
        "incremental_index_cancellations",
        "snapshot_file_bindings",
        "source_file_lineage",
        "index_semantic_dependencies",
        "index_projection_events",
        "index_projection_delivery_snapshots",
        "code_semantic_vector_projections",
        "code_semantic_vector_invalidations",
        "index_topology_fact_invalidations",
    ):
        _immutable(table)


def _create_runs() -> None:
    op.create_table(
        "incremental_index_runs",
        sa.Column("run_id", sa.Text(), primary_key=True),
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
            "principal_id",
            sa.Text(),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column(
            "base_snapshot_id",
            sa.Text(),
            sa.ForeignKey("source_snapshots.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "target_snapshot_id",
            sa.Text(),
            sa.ForeignKey("source_snapshots.id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("target_commit_id", sa.Text(), nullable=True),
        sa.Column("working_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("implementation_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("plan_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("total_operations", sa.Integer(), nullable=False),
        sa.Column("changed_operations", sa.Integer(), nullable=False),
        sa.Column("detected_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(run_id)=64 AND length(scope_fingerprint)=32 "
            "AND length(working_digest)=32 AND length(implementation_fingerprint)=32 "
            "AND length(plan_digest)=32",
            name="ck_incremental_index_run_digests",
        ),
        sa.CheckConstraint(
            "total_operations>=0 AND changed_operations>=0 "
            "AND changed_operations<=total_operations",
            name="ck_incremental_index_run_counts",
        ),
        sa.CheckConstraint(
            "role IN ('owner','admin','editor','reader','auditor','adapter','worker')",
            name="ck_incremental_index_run_role",
        ),
    )
    op.create_index(
        "ix_incremental_index_run_scope",
        "incremental_index_runs",
        ["brain_id", "project_id", "repository_id", "detected_at"],
    )


def _create_plans_and_snapshots() -> None:
    op.create_table(
        "incremental_index_plan_operations",
        sa.Column(
            "run_id",
            sa.Text(),
            sa.ForeignKey("incremental_index_runs.run_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("operation_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.Column("previous_path", sa.Text(), nullable=True),
        sa.Column("content_digest", sa.LargeBinary(32), nullable=True),
        sa.Column("cache_key", sa.LargeBinary(32), nullable=True),
        sa.Column("previous_source_file_id", sa.Text(), nullable=True),
        sa.Column("previous_file_revision_id", sa.Text(), nullable=True),
        sa.Column("previous_semantic_ids_json", sa.LargeBinary(), nullable=False),
        sa.Column("generated", sa.Boolean(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("run_id", "ordinal"),
        sa.CheckConstraint("ordinal>=0", name="ck_incremental_plan_ordinal"),
        sa.CheckConstraint(
            "kind IN ('add','modify','rename','delete','reuse')",
            name="ck_incremental_plan_kind",
        ),
        sa.CheckConstraint(
            "reason IN ('new_content','content_changed','fingerprint_changed','path_changed',"
            "'copied_content','content_deleted','generated_excluded','cache_hit')",
            name="ck_incremental_plan_reason",
        ),
        sa.CheckConstraint(
            "length(operation_digest)=32 AND length(relative_path) BETWEEN 1 AND 4096",
            name="ck_incremental_plan_identity",
        ),
    )
    op.create_table(
        "incremental_index_run_snapshots",
        sa.Column(
            "run_id",
            sa.Text(),
            sa.ForeignKey("incremental_index_runs.run_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("snapshot_version", sa.Integer(), nullable=False),
        sa.Column("cursor", sa.Integer(), nullable=False),
        sa.Column("indexed_count", sa.Integer(), nullable=False),
        sa.Column("reused_count", sa.Integer(), nullable=False),
        sa.Column("deleted_count", sa.Integer(), nullable=False),
        sa.Column("failed_count", sa.Integer(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("started_at", sa.BigInteger(), nullable=True),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=True),
        sa.Column("failure_code", sa.Text(), nullable=True),
        sa.Column("snapshot_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("run_id", "snapshot_version"),
        sa.UniqueConstraint("run_id", "snapshot_digest", name="uq_index_run_snapshot_digest"),
        sa.CheckConstraint(
            "snapshot_version>=0 AND cursor>=0 AND indexed_count>=0 AND reused_count>=0 "
            "AND deleted_count>=0 AND failed_count>=0",
            name="ck_index_run_snapshot_counts",
        ),
        sa.CheckConstraint(
            "state IN ('queued','running','cancelling','cancelled','completed','failed')",
            name="ck_index_run_snapshot_state",
        ),
        sa.CheckConstraint("length(snapshot_digest)=32", name="ck_index_run_snapshot_digest"),
    )
    op.create_index(
        "ix_incremental_index_run_latest",
        "incremental_index_run_snapshots",
        ["run_id", "snapshot_version"],
    )
    op.create_table(
        "incremental_index_cancellations",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column(
            "run_id",
            sa.Text(),
            sa.ForeignKey("incremental_index_runs.run_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("requested_at", sa.BigInteger(), nullable=False),
        sa.Column("request_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(scope_fingerprint)=32 AND length(request_digest)=32",
            name="ck_incremental_index_cancel_digests",
        ),
    )


def _create_bindings_and_lineage() -> None:
    op.create_table(
        "snapshot_file_bindings",
        sa.Column(
            "snapshot_id",
            sa.Text(),
            sa.ForeignKey("source_snapshots.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.Column(
            "source_file_id",
            sa.Text(),
            sa.ForeignKey("source_files.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "file_revision_id",
            sa.Text(),
            sa.ForeignKey("file_revisions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("cache_key", sa.LargeBinary(32), nullable=False),
        sa.Column("semantic_ids_json", sa.LargeBinary(), nullable=False),
        sa.Column("binding_kind", sa.Text(), nullable=False),
        sa.Column("operation_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("snapshot_id", "relative_path"),
        sa.CheckConstraint(
            "binding_kind IN ('add','modify','rename','reuse')",
            name="ck_snapshot_file_binding_kind",
        ),
        sa.CheckConstraint(
            "length(cache_key)=32 AND length(operation_digest)=32 "
            "AND length(relative_path) BETWEEN 1 AND 4096",
            name="ck_snapshot_file_binding_identity",
        ),
    )
    op.create_index(
        "ix_snapshot_file_binding_revision",
        "snapshot_file_bindings",
        ["file_revision_id", "snapshot_id"],
    )
    op.create_table(
        "source_file_lineage",
        sa.Column("lineage_id", sa.Text(), primary_key=True),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "snapshot_id",
            sa.Text(),
            sa.ForeignKey("source_snapshots.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "from_source_file_id",
            sa.Text(),
            sa.ForeignKey("source_files.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "to_source_file_id",
            sa.Text(),
            sa.ForeignKey("source_files.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("operation_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "snapshot_id",
            "from_source_file_id",
            "to_source_file_id",
            "kind",
            name="uq_source_file_lineage_edge",
        ),
        sa.CheckConstraint("kind IN ('rename','copy')", name="ck_source_file_lineage_kind"),
        sa.CheckConstraint(
            "length(lineage_id)=64 AND length(operation_digest)=32",
            name="ck_source_file_lineage_identity",
        ),
    )


def _create_projection_outbox() -> None:
    op.create_table(
        "index_semantic_dependencies",
        sa.Column("dependency_id", sa.Text(), primary_key=True),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("source_semantic_id", sa.Text(), nullable=False),
        sa.Column("dependent_fact_id", sa.Text(), nullable=True),
        sa.Column("assertion_evidence_id", sa.Text(), nullable=True),
        sa.Column("registered_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "dependent_fact_id IS NOT NULL OR assertion_evidence_id IS NOT NULL",
            name="ck_index_semantic_dependency_target",
        ),
        sa.CheckConstraint("length(dependency_id)=64", name="ck_index_dependency_id"),
    )
    op.create_index(
        "ix_index_semantic_dependency_source",
        "index_semantic_dependencies",
        ["source_semantic_id", "repository_id"],
    )
    op.create_table(
        "index_projection_events",
        sa.Column("event_id", sa.Text(), primary_key=True),
        sa.Column(
            "run_id",
            sa.Text(),
            sa.ForeignKey("incremental_index_runs.run_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("operation_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("snapshot_id", sa.Text(), nullable=False),
        sa.Column("previous_file_revision_ids_json", sa.LargeBinary(), nullable=False),
        sa.Column("current_file_revision_ids_json", sa.LargeBinary(), nullable=False),
        sa.Column("affected_semantic_ids_json", sa.LargeBinary(), nullable=False),
        sa.Column("dependent_fact_ids_json", sa.LargeBinary(), nullable=False),
        sa.Column("assertion_evidence_ids_json", sa.LargeBinary(), nullable=False),
        sa.Column("reembed_semantic_ids_json", sa.LargeBinary(), nullable=False),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("event_digest", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(event_id)=64 AND length(operation_digest)=32 AND length(event_digest)=32",
            name="ck_index_projection_event_digests",
        ),
    )
    op.create_index(
        "ix_index_projection_event_pending",
        "index_projection_events",
        ["occurred_at", "event_id"],
    )
    op.create_table(
        "index_projection_delivery_snapshots",
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("index_projection_events.event_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("snapshot_version", sa.Integer(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("leased_until", sa.BigInteger(), nullable=True),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("delivery_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("event_id", "snapshot_version"),
        sa.CheckConstraint("state IN ('leased','completed')", name="ck_index_delivery_state"),
        sa.CheckConstraint("attempt>=1", name="ck_index_delivery_attempt"),
        sa.CheckConstraint("length(delivery_digest)=32", name="ck_index_delivery_digest"),
    )
    op.create_table(
        "code_semantic_vector_projections",
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("index_projection_events.event_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "semantic_id",
            sa.Text(),
            sa.ForeignKey("symbol_revisions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "snapshot_id",
            sa.Text(),
            sa.ForeignKey("source_snapshots.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("model_id", sa.Text(), nullable=False),
        sa.Column("model_revision", sa.Text(), nullable=False),
        sa.Column("dimension", sa.Integer(), nullable=False),
        sa.Column("vector_json", sa.LargeBinary(), nullable=False),
        sa.Column("content_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("projected_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("event_id", "semantic_id"),
        sa.CheckConstraint(
            "dimension>0 AND length(content_digest)=32 AND json_valid(vector_json) "
            "AND json_type(vector_json)='array'",
            name="ck_code_semantic_vector_shape",
        ),
    )
    op.create_index(
        "ix_code_semantic_vector_current",
        "code_semantic_vector_projections",
        ["semantic_id", "model_id", "model_revision", "projected_at"],
    )
    op.create_table(
        "code_semantic_vector_invalidations",
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("index_projection_events.event_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("semantic_id", sa.Text(), nullable=False),
        sa.Column("invalidated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("event_id", "semantic_id"),
    )
    op.create_index(
        "ix_code_semantic_vector_invalidation",
        "code_semantic_vector_invalidations",
        ["semantic_id", "invalidated_at"],
    )
    op.create_table(
        "index_topology_fact_invalidations",
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("index_projection_events.event_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("fact_id", sa.Text(), nullable=False),
        sa.Column("invalidated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("event_id", "fact_id"),
    )
    op.create_index(
        "ix_index_topology_fact_invalidation",
        "index_topology_fact_invalidations",
        ["fact_id", "invalidated_at"],
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
    """Refuse destructive rollback after any IDX-002 history exists."""
    connection = op.get_bind()
    tables = (
        "incremental_index_runs",
        "source_file_lineage",
        "index_semantic_dependencies",
        "index_projection_events",
    )
    if any(
        connection.execute(  # nosec B608 -- Names come from the closed tuple above.
            sa.text(f"SELECT EXISTS(SELECT 1 FROM {table})")  # noqa: S608
        ).scalar_one()
        for table in tables
    ):
        message = "IDX-002 incremental indexing history prevents destructive downgrade"
        raise RuntimeError(message)
    for table in (
        "index_topology_fact_invalidations",
        "code_semantic_vector_invalidations",
        "code_semantic_vector_projections",
        "index_projection_delivery_snapshots",
        "index_projection_events",
        "index_semantic_dependencies",
        "source_file_lineage",
        "snapshot_file_bindings",
        "incremental_index_cancellations",
        "incremental_index_run_snapshots",
        "incremental_index_plan_operations",
        "incremental_index_runs",
    ):
        op.drop_table(table)
