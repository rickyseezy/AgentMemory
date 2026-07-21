"""IDX-003 commit-scoped source history and reverse evidence lineage.

Revision ID: 0028_idx003_revision_history
Revises: 0027_idx002_incremental_index
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0028_idx003_revision_history"
down_revision = "0027_idx002_incremental_index"
branch_labels = None
depends_on = None

_COMMIT_CHECK = "length({column}) IN (40,64) AND {column} NOT GLOB '*[^0-9a-f]*'"


def upgrade() -> None:
    """Install immutable revision contexts, graph answers, lineage, and extraction jobs."""
    _create_run_contexts()
    _create_graph_answers()
    _create_revision_contexts()
    _create_lineage_and_validity()
    _create_jobs_and_receipts()
    for table in (
        "incremental_index_run_revision_contexts",
        "commit_graph_query_answers",
        "source_revision_contexts",
        "source_revision_context_invalidations",
        "source_revision_evidence_lineage",
        "source_revision_lineage_registrations",
        "source_revision_reextraction_jobs",
        "source_revision_claim_snapshots",
        "source_revision_processing_receipts",
    ):
        _immutable(table)


def _create_run_contexts() -> None:
    op.create_table(
        "incremental_index_run_revision_contexts",
        sa.Column(
            "run_id",
            sa.Text(),
            sa.ForeignKey("incremental_index_runs.run_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("revision_context", sa.Text(), nullable=False),
        sa.Column("recorded_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "revision_context IN ('committed','worktree')",
            name="ck_incremental_run_revision_context",
        ),
    )


def _create_graph_answers() -> None:
    op.create_table(
        "commit_graph_query_answers",
        sa.Column("answer_id", sa.Text(), primary_key=True),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("query_kind", sa.Text(), nullable=False),
        sa.Column("left_commit_sha", sa.Text(), nullable=False),
        sa.Column("right_commit_sha", sa.Text(), nullable=False),
        sa.Column("graph_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("is_ancestor", sa.Boolean(), nullable=True),
        sa.Column("merge_base_shas_json", sa.LargeBinary(), nullable=False),
        sa.Column("recorded_at", sa.BigInteger(), nullable=False),
        sa.Column("answered_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(answer_id)=64 AND length(graph_digest)=32",
            name="ck_commit_graph_answer_digests",
        ),
        sa.CheckConstraint(
            _COMMIT_CHECK.format(column="left_commit_sha")
            + " AND "
            + _COMMIT_CHECK.format(column="right_commit_sha"),
            name="ck_commit_graph_answer_commits",
        ),
        sa.CheckConstraint(
            "query_kind IN ('ancestry','merge_base') AND "
            "json_valid(merge_base_shas_json) AND json_type(merge_base_shas_json)='array'",
            name="ck_commit_graph_answer_shape",
        ),
        sa.CheckConstraint(
            "(query_kind='ancestry' AND is_ancestor IS NOT NULL "
            "AND json_array_length(merge_base_shas_json)=0) OR "
            "(query_kind='merge_base' AND is_ancestor IS NULL "
            "AND json_array_length(merge_base_shas_json)>=1)",
            name="ck_commit_graph_answer_result",
        ),
        sa.UniqueConstraint(
            "brain_id",
            "repository_id",
            "query_kind",
            "left_commit_sha",
            "right_commit_sha",
            "graph_digest",
            name="uq_commit_graph_answer_query",
        ),
    )
    op.create_index(
        "ix_commit_graph_answer_lookup",
        "commit_graph_query_answers",
        [
            "brain_id",
            "repository_id",
            "graph_digest",
            "query_kind",
            "left_commit_sha",
            "right_commit_sha",
        ],
    )


def _create_revision_contexts() -> None:
    op.create_table(
        "source_revision_contexts",
        sa.Column("context_id", sa.Text(), primary_key=True),
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("index_projection_events.event_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "run_id",
            sa.Text(),
            sa.ForeignKey("incremental_index_runs.run_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("brain_id", sa.Text(), nullable=False),
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
        sa.Column("previous_source_file_id", sa.Text(), nullable=True),
        sa.Column(
            "snapshot_id",
            sa.Text(),
            sa.ForeignKey("source_snapshots.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("previous_snapshot_id", sa.Text(), nullable=True),
        sa.Column(
            "file_revision_id",
            sa.Text(),
            sa.ForeignKey("file_revisions.id", ondelete="RESTRICT"),
            nullable=True,
            unique=True,
        ),
        sa.Column("previous_file_revision_id", sa.Text(), nullable=True),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.Column("previous_path", sa.Text(), nullable=True),
        sa.Column("commit_sha", sa.Text(), nullable=False),
        sa.Column("base_commit_sha", sa.Text(), nullable=True),
        sa.Column("content_digest", sa.LargeBinary(32), nullable=True),
        sa.Column("previous_content_digest", sa.LargeBinary(32), nullable=True),
        sa.Column("change_kind", sa.Text(), nullable=False),
        sa.Column("transition_digest", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("reintroduced_from_context_id", sa.Text(), nullable=True),
        sa.Column("observed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["reintroduced_from_context_id"],
            ["source_revision_contexts.context_id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(context_id)=64 AND length(transition_digest)=32 "
            "AND length(relative_path) BETWEEN 1 AND 4096",
            name="ck_source_revision_context_identity",
        ),
        sa.CheckConstraint(
            _COMMIT_CHECK.format(column="commit_sha")
            + " AND (base_commit_sha IS NULL OR "
            + _COMMIT_CHECK.format(column="base_commit_sha")
            + ")",
            name="ck_source_revision_context_commits",
        ),
        sa.CheckConstraint(
            "change_kind IN ('add','modify','rename','delete','reintroduce')",
            name="ck_source_revision_context_kind",
        ),
        sa.CheckConstraint(
            "(change_kind='delete' AND file_revision_id IS NULL AND content_digest IS NULL) OR "
            "(change_kind<>'delete' AND file_revision_id IS NOT NULL "
            "AND length(content_digest)=32)",
            name="ck_source_revision_context_current",
        ),
    )
    op.create_index(
        "ix_source_revision_history",
        "source_revision_contexts",
        ["brain_id", "repository_id", "source_file_id", "observed_at", "context_id"],
    )
    op.create_index(
        "ix_source_revision_path",
        "source_revision_contexts",
        ["brain_id", "repository_id", "relative_path", "observed_at"],
    )


def _create_lineage_and_validity() -> None:
    op.create_table(
        "source_revision_context_invalidations",
        sa.Column(
            "context_id",
            sa.Text(),
            sa.ForeignKey("source_revision_contexts.context_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("invalidating_commit_sha", sa.Text(), nullable=False),
        sa.Column(
            "invalidating_event_id",
            sa.Text(),
            sa.ForeignKey("index_projection_events.event_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("invalidated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("context_id", "invalidating_commit_sha"),
        sa.CheckConstraint(
            _COMMIT_CHECK.format(column="invalidating_commit_sha"),
            name="ck_source_revision_invalidation_commit",
        ),
    )
    op.create_table(
        "source_revision_evidence_lineage",
        sa.Column(
            "context_id",
            sa.Text(),
            sa.ForeignKey("source_revision_contexts.context_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "evidence_id",
            sa.Text(),
            sa.ForeignKey("assertion_evidence_sources.evidence_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "assertion_id",
            sa.Text(),
            sa.ForeignKey("assertion_candidates.assertion_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("registered_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("context_id", "evidence_id", "assertion_id"),
    )
    op.create_index(
        "ix_source_revision_lineage_reverse",
        "source_revision_evidence_lineage",
        ["evidence_id", "assertion_id", "context_id"],
    )
    op.create_table(
        "source_revision_lineage_registrations",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column("context_id", sa.Text(), nullable=False),
        sa.Column("evidence_id", sa.Text(), nullable=False),
        sa.Column("assertion_id", sa.Text(), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("registration_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("registered_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["context_id", "evidence_id", "assertion_id"],
            [
                "source_revision_evidence_lineage.context_id",
                "source_revision_evidence_lineage.evidence_id",
                "source_revision_evidence_lineage.assertion_id",
            ],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(scope_fingerprint)=32 AND length(registration_digest)=32",
            name="ck_source_revision_registration_digests",
        ),
    )


def _create_jobs_and_receipts() -> None:
    op.create_table(
        "source_revision_reextraction_jobs",
        sa.Column("job_id", sa.Text(), primary_key=True),
        sa.Column(
            "context_id",
            sa.Text(),
            sa.ForeignKey("source_revision_contexts.context_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("queued_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("length(job_id)=64", name="ck_source_revision_job_id"),
        sa.CheckConstraint("action IN ('extract','retract')", name="ck_source_revision_job_action"),
        sa.CheckConstraint("state='queued'", name="ck_source_revision_job_state"),
    )
    op.create_table(
        "source_revision_claim_snapshots",
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("index_projection_events.event_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("claim_version", sa.Integer(), nullable=False),
        sa.Column("leased_until", sa.BigInteger(), nullable=False),
        sa.Column("claimed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("event_id", "claim_version"),
        sa.CheckConstraint("claim_version>=0", name="ck_source_revision_claim_version"),
        sa.CheckConstraint("leased_until>claimed_at", name="ck_source_revision_claim_lease"),
    )
    op.create_table(
        "source_revision_processing_receipts",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("index_projection_events.event_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "context_id",
            sa.Text(),
            sa.ForeignKey("source_revision_contexts.context_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("transition_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("graph_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("graph_answer_ids_json", sa.LargeBinary(), nullable=False),
        sa.Column(
            "job_id",
            sa.Text(),
            sa.ForeignKey("source_revision_reextraction_jobs.job_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("closed_evidence_count", sa.Integer(), nullable=False),
        sa.Column("affected_assertion_count", sa.Integer(), nullable=False),
        sa.Column("processed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(transition_digest)=32 AND length(graph_digest)=32 "
            "AND json_valid(graph_answer_ids_json) "
            "AND json_type(graph_answer_ids_json)='array'",
            name="ck_source_revision_receipt_digests",
        ),
        sa.CheckConstraint(
            "closed_evidence_count>=0 AND affected_assertion_count>=0",
            name="ck_source_revision_receipt_counts",
        ),
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
    """Refuse to erase processed revision history, lineage, or graph decisions."""
    connection = op.get_bind()
    guarded = (
        "incremental_index_run_revision_contexts",
        "source_revision_contexts",
        "source_revision_context_invalidations",
        "source_revision_evidence_lineage",
        "source_revision_processing_receipts",
        "source_revision_lineage_registrations",
        "source_revision_reextraction_jobs",
        "source_revision_claim_snapshots",
        "commit_graph_query_answers",
    )
    if any(
        connection.execute(  # nosec B608 -- Table names come from the closed tuple.
            sa.text(f"SELECT EXISTS(SELECT 1 FROM {table})")  # noqa: S608
        ).scalar_one()
        for table in guarded
    ):
        message = "IDX-003 revision history prevents destructive downgrade"
        raise RuntimeError(message)
    for table in (
        "source_revision_processing_receipts",
        "source_revision_reextraction_jobs",
        "source_revision_claim_snapshots",
        "source_revision_lineage_registrations",
        "source_revision_evidence_lineage",
        "source_revision_context_invalidations",
        "source_revision_contexts",
        "commit_graph_query_answers",
        "incremental_index_run_revision_contexts",
    ):
        op.drop_table(table)
