"""GRA-004 bitemporal assertion and immutable VCS revision evidence.

Revision ID: 0023_gra004_temporal_revision_truth
Revises: 0022_gra003_materialized_assertion_edges
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0023_gra004_temporal_revision_truth"
down_revision = "0022_gra003_materialized_assertion_edges"
branch_labels = None
depends_on = None

_COMMIT_CHECK = "length({column}) IN (40,64) AND {column} NOT GLOB '*[^0-9a-f]*'"


def upgrade() -> None:
    """Install immutable commit DAG, ref history, evidence anchors, and impacts."""
    op.create_table(
        "vcs_revision_batches",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "principal_id",
            sa.Text(),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("batch_digest", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("source_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("node_count", sa.Integer(), nullable=False),
        sa.Column("ref_count", sa.Integer(), nullable=False),
        sa.Column("impact_count", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(scope_fingerprint)=32 AND length(batch_digest)=32 AND length(source_digest)=32",
            name="ck_vcs_revision_batch_digests",
        ),
        sa.CheckConstraint(
            "node_count BETWEEN 0 AND 20000 AND ref_count BETWEEN 0 AND 1000 "
            "AND impact_count BETWEEN 0 AND 20000 "
            "AND node_count+ref_count+impact_count>0",
            name="ck_vcs_revision_batch_counts",
        ),
    )
    op.create_index(
        "ix_vcs_revision_batch_watermark",
        "vcs_revision_batches",
        ["brain_id", "repository_id", "observed_at", "operation_id"],
    )
    op.create_table(
        "vcs_commits",
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("repository_id", sa.Text(), nullable=False),
        sa.Column("commit_sha", sa.Text(), nullable=False),
        sa.Column(
            "first_batch_id",
            sa.Text(),
            sa.ForeignKey("vcs_revision_batches.operation_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("first_observed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("repository_id", "commit_sha"),
        sa.ForeignKeyConstraint(["repository_id"], ["repositories.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(_COMMIT_CHECK.format(column="commit_sha"), name="ck_vcs_commit_sha"),
    )
    op.create_index(
        "ix_vcs_commit_brain",
        "vcs_commits",
        ["brain_id", "repository_id", "first_observed_at", "commit_sha"],
    )
    op.create_table(
        "vcs_commit_parents",
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("repository_id", sa.Text(), nullable=False),
        sa.Column("child_sha", sa.Text(), nullable=False),
        sa.Column("parent_sha", sa.Text(), nullable=False),
        sa.Column(
            "batch_id",
            sa.Text(),
            sa.ForeignKey("vcs_revision_batches.operation_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("observed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("repository_id", "child_sha", "parent_sha"),
        sa.ForeignKeyConstraint(
            ["repository_id", "child_sha"],
            ["vcs_commits.repository_id", "vcs_commits.commit_sha"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["repository_id", "parent_sha"],
            ["vcs_commits.repository_id", "vcs_commits.commit_sha"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("child_sha<>parent_sha", name="ck_vcs_parent_distinct"),
        sa.CheckConstraint(
            _COMMIT_CHECK.format(column="child_sha")
            + " AND "
            + _COMMIT_CHECK.format(column="parent_sha"),
            name="ck_vcs_parent_shas",
        ),
    )
    op.create_index(
        "ix_vcs_parent_reverse",
        "vcs_commit_parents",
        ["repository_id", "parent_sha", "child_sha", "observed_at"],
    )
    op.create_table(
        "vcs_ref_observations",
        sa.Column("observation_id", sa.Text(), primary_key=True),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("repository_id", sa.Text(), nullable=False),
        sa.Column("branch_name", sa.Text(), nullable=False),
        sa.Column("commit_sha", sa.Text(), nullable=False),
        sa.Column(
            "batch_id",
            sa.Text(),
            sa.ForeignKey("vcs_revision_batches.operation_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("observed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("repository_id", "branch_name", "observed_at", name="uq_vcs_ref_time"),
        sa.ForeignKeyConstraint(
            ["repository_id", "commit_sha"],
            ["vcs_commits.repository_id", "vcs_commits.commit_sha"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(observation_id)=64 AND observation_id NOT GLOB '*[^0-9a-f]*'",
            name="ck_vcs_ref_observation_id",
        ),
        sa.CheckConstraint(
            "length(branch_name) BETWEEN 1 AND 1024 AND instr(branch_name,char(0))=0 "
            "AND instr(branch_name,char(10))=0 AND instr(branch_name,char(13))=0",
            name="ck_vcs_ref_branch",
        ),
        sa.CheckConstraint(_COMMIT_CHECK.format(column="commit_sha"), name="ck_vcs_ref_commit"),
    )
    op.create_index(
        "ix_vcs_ref_resolve",
        "vcs_ref_observations",
        ["brain_id", "repository_id", "branch_name", "observed_at", "observation_id"],
    )
    op.create_table(
        "assertion_evidence_revision_anchors",
        sa.Column(
            "evidence_id",
            sa.Text(),
            sa.ForeignKey("assertion_evidence_sources.evidence_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("repository_id", sa.Text(), nullable=False),
        sa.Column(
            "checkout_id",
            sa.Text(),
            sa.ForeignKey("checkouts.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("commit_sha", sa.Text(), nullable=False),
        sa.Column("branch_at_capture", sa.Text(), nullable=True),
        sa.Column("revision_observed_at", sa.BigInteger(), nullable=False),
        sa.Column("anchored_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(["repository_id"], ["repositories.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            _COMMIT_CHECK.format(column="commit_sha"), name="ck_assertion_evidence_commit"
        ),
        sa.CheckConstraint(
            "branch_at_capture IS NULL OR (length(branch_at_capture) BETWEEN 1 AND 1024 "
            "AND instr(branch_at_capture,char(0))=0 AND instr(branch_at_capture,char(10))=0 "
            "AND instr(branch_at_capture,char(13))=0)",
            name="ck_assertion_evidence_branch",
        ),
    )
    op.create_index(
        "ix_assertion_evidence_revision",
        "assertion_evidence_revision_anchors",
        ["brain_id", "repository_id", "commit_sha", "evidence_id"],
    )
    op.execute(
        "INSERT INTO assertion_evidence_revision_anchors "
        "(evidence_id,brain_id,repository_id,checkout_id,commit_sha,branch_at_capture,"
        "revision_observed_at,anchored_at,schema_version) "
        "SELECT s.evidence_id,s.brain_id,s.repository_id,s.checkout_id,o.head_commit,o.branch,"
        "o.observed_at,s.registered_at,1 FROM assertion_evidence_sources AS s "
        "JOIN checkout_observations AS o ON o.brain_id=s.brain_id "
        "AND o.repository_id=s.repository_id AND o.checkout_id=s.checkout_id "
        "AND o.observed_at<=s.occurred_at AND o.head_commit IS NOT NULL "
        "WHERE s.kind<>'user_statement' AND s.checkout_id IS NOT NULL AND NOT EXISTS ("
        "SELECT 1 FROM checkout_observations AS newer WHERE newer.brain_id=o.brain_id "
        "AND newer.repository_id=o.repository_id AND newer.checkout_id=o.checkout_id "
        "AND newer.observed_at<=s.occurred_at AND newer.head_commit IS NOT NULL AND ("
        "newer.observed_at>o.observed_at OR (newer.observed_at=o.observed_at "
        "AND newer.aggregate_version>o.aggregate_version)))"
    )
    op.create_table(
        "vcs_evidence_impacts",
        sa.Column("impact_id", sa.Text(), primary_key=True),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("repository_id", sa.Text(), nullable=False),
        sa.Column(
            "evidence_id",
            sa.Text(),
            sa.ForeignKey("assertion_evidence_sources.evidence_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("invalidating_commit_sha", sa.Text(), nullable=False),
        sa.Column(
            "batch_id",
            sa.Text(),
            sa.ForeignKey("vcs_revision_batches.operation_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("changed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "evidence_id", "invalidating_commit_sha", name="uq_vcs_evidence_impact"
        ),
        sa.ForeignKeyConstraint(
            ["repository_id", "invalidating_commit_sha"],
            ["vcs_commits.repository_id", "vcs_commits.commit_sha"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(impact_id)=64 AND impact_id NOT GLOB '*[^0-9a-f]*'",
            name="ck_vcs_impact_id",
        ),
        sa.CheckConstraint(
            _COMMIT_CHECK.format(column="invalidating_commit_sha"),
            name="ck_vcs_impact_commit",
        ),
    )
    op.create_index(
        "ix_vcs_evidence_impact_query",
        "vcs_evidence_impacts",
        ["brain_id", "repository_id", "evidence_id", "changed_at"],
    )

    for table in (
        "vcs_revision_batches",
        "vcs_commits",
        "vcs_commit_parents",
        "vcs_ref_observations",
        "assertion_evidence_revision_anchors",
        "vcs_evidence_impacts",
    ):
        op.execute(
            f"CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} BEGIN "
            f"SELECT RAISE(ABORT, '{table} is immutable'); END"
        )
        op.execute(
            f"CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN "
            f"SELECT RAISE(ABORT, '{table} is immutable'); END"
        )


def downgrade() -> None:
    """Refuse rollback once any temporal or VCS authority evidence exists."""
    connection = op.get_bind()
    tables = (
        "vcs_revision_batches",
        "vcs_commits",
        "vcs_commit_parents",
        "vcs_ref_observations",
        "assertion_evidence_revision_anchors",
        "vcs_evidence_impacts",
    )
    for table in tables:
        if connection.execute(sa.text(f"SELECT COUNT(*) FROM {table}")).scalar_one():  # noqa: S608
            msg = "GRA-004 downgrade refused while temporal revision evidence exists"
            raise RuntimeError(msg)
    for table in reversed(tables):
        op.execute(f"DROP TRIGGER {table}_no_delete")
        op.execute(f"DROP TRIGGER {table}_no_update")
    op.drop_index("ix_vcs_evidence_impact_query", table_name="vcs_evidence_impacts")
    op.drop_table("vcs_evidence_impacts")
    op.drop_index(
        "ix_assertion_evidence_revision", table_name="assertion_evidence_revision_anchors"
    )
    op.drop_table("assertion_evidence_revision_anchors")
    op.drop_index("ix_vcs_ref_resolve", table_name="vcs_ref_observations")
    op.drop_table("vcs_ref_observations")
    op.drop_index("ix_vcs_parent_reverse", table_name="vcs_commit_parents")
    op.drop_table("vcs_commit_parents")
    op.drop_index("ix_vcs_commit_brain", table_name="vcs_commits")
    op.drop_table("vcs_commits")
    op.drop_index("ix_vcs_revision_batch_watermark", table_name="vcs_revision_batches")
    op.drop_table("vcs_revision_batches")
