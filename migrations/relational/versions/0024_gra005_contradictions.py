"""GRA-005 explicit contradiction and resolution history.

Revision ID: 0024_gra005_contradictions
Revises: 0023_gra004_temporal_revision_truth
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0024_gra005_contradictions"
down_revision = "0023_gra004_temporal_revision_truth"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Install first-class assertion polarity and append-only dispute history."""
    op.add_column(
        "assertion_candidates",
        sa.Column("polarity", sa.Text(), nullable=False, server_default="positive"),
    )
    op.execute(
        "CREATE TRIGGER assertion_candidate_polarity_guard BEFORE INSERT ON assertion_candidates "
        "WHEN NEW.polarity NOT IN ('positive','negative') BEGIN "
        "SELECT RAISE(ABORT, 'assertion polarity is invalid'); END"
    )
    op.create_table(
        "graph_contradiction_operations",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
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
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("request_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("result_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("result_count", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "action IN ('detect','resolve')", name="ck_graph_contradiction_operation_action"
        ),
        sa.CheckConstraint(
            "length(scope_fingerprint)=32 AND length(request_digest)=32 "
            "AND length(result_digest)=32",
            name="ck_graph_contradiction_operation_digests",
        ),
        sa.CheckConstraint("result_count>=0", name="ck_graph_contradiction_operation_count"),
    )
    op.create_table(
        "graph_contradictions",
        sa.Column("contradiction_id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "detection_operation_id",
            sa.Text(),
            sa.ForeignKey("graph_contradiction_operations.operation_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "left_assertion_id",
            sa.Text(),
            sa.ForeignKey("assertion_candidates.assertion_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "right_assertion_id",
            sa.Text(),
            sa.ForeignKey("assertion_candidates.assertion_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("predicate", sa.Text(), nullable=False),
        sa.Column("dimension", sa.Text(), nullable=False),
        sa.Column("valid_from", sa.BigInteger(), nullable=False),
        sa.Column("valid_to", sa.BigInteger(), nullable=True),
        sa.Column("evidence_ids_json", sa.Text(), nullable=False),
        sa.Column("detected_at", sa.BigInteger(), nullable=False),
        sa.Column("detection_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("policy_version", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "brain_id",
            "repository_id",
            "left_assertion_id",
            "right_assertion_id",
            "dimension",
            "valid_from",
            "valid_to",
            "detection_digest",
            name="uq_graph_contradiction_fact",
        ),
        sa.CheckConstraint("length(contradiction_id)=64", name="ck_graph_contradiction_id"),
        sa.CheckConstraint(
            "left_assertion_id<right_assertion_id", name="ck_graph_contradiction_pair"
        ),
        sa.CheckConstraint(
            "dimension IN ('polarity','exclusive_object')",
            name="ck_graph_contradiction_dimension",
        ),
        sa.CheckConstraint(
            "valid_to IS NULL OR valid_to>valid_from", name="ck_graph_contradiction_time"
        ),
        sa.CheckConstraint(
            "json_valid(evidence_ids_json) AND json_type(evidence_ids_json)='array'",
            name="ck_graph_contradiction_evidence_json",
        ),
        sa.CheckConstraint("length(detection_digest)=32", name="ck_graph_contradiction_digest"),
        sa.CheckConstraint(
            "policy_version='graph-contradiction.v1'", name="ck_graph_contradiction_policy"
        ),
    )
    op.create_index(
        "ix_graph_contradiction_assertions",
        "graph_contradictions",
        ["brain_id", "repository_id", "left_assertion_id", "right_assertion_id"],
    )
    op.create_table(
        "graph_contradiction_evidence",
        sa.Column(
            "contradiction_id",
            sa.Text(),
            sa.ForeignKey("graph_contradictions.contradiction_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "evidence_id",
            sa.Text(),
            sa.ForeignKey("assertion_evidence_sources.evidence_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("contradiction_id", "evidence_id"),
    )
    op.create_table(
        "graph_contradiction_resolutions",
        sa.Column(
            "contradiction_id",
            sa.Text(),
            sa.ForeignKey("graph_contradictions.contradiction_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "operation_id",
            sa.Text(),
            sa.ForeignKey("graph_contradiction_operations.operation_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
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
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("reason_code", sa.Text(), nullable=False),
        sa.Column("evidence_ids_json", sa.Text(), nullable=False),
        sa.Column("resolved_at", sa.BigInteger(), nullable=False),
        sa.Column("resolution_digest", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("policy_version", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "outcome IN ('left_assertion','right_assertion','both_valid','neither_valid')",
            name="ck_graph_contradiction_resolution_outcome",
        ),
        sa.CheckConstraint(
            "json_valid(evidence_ids_json) AND json_type(evidence_ids_json)='array'",
            name="ck_graph_contradiction_resolution_evidence",
        ),
        sa.CheckConstraint(
            "length(resolution_digest)=32", name="ck_graph_contradiction_resolution_digest"
        ),
        sa.CheckConstraint(
            "policy_version='graph-contradiction.v1'",
            name="ck_graph_contradiction_resolution_policy",
        ),
    )
    for table in (
        "graph_contradiction_operations",
        "graph_contradictions",
        "graph_contradiction_evidence",
        "graph_contradiction_resolutions",
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
    """Refuse rollback after any contradiction operation has been recorded."""
    connection = op.get_bind()
    if connection.execute(
        sa.text("SELECT COUNT(*) FROM graph_contradiction_operations")
    ).scalar_one():
        msg = "GRA-005 downgrade refused while contradiction history exists"
        raise RuntimeError(msg)
    for table in reversed(
        (
            "graph_contradiction_operations",
            "graph_contradictions",
            "graph_contradiction_evidence",
            "graph_contradiction_resolutions",
        )
    ):
        op.execute(f"DROP TRIGGER {table}_no_delete")
        op.execute(f"DROP TRIGGER {table}_no_update")
    op.drop_table("graph_contradiction_resolutions")
    op.drop_table("graph_contradiction_evidence")
    op.drop_index("ix_graph_contradiction_assertions", table_name="graph_contradictions")
    op.drop_table("graph_contradictions")
    op.drop_table("graph_contradiction_operations")
    op.execute("DROP TRIGGER assertion_candidate_polarity_guard")
    op.drop_column("assertion_candidates", "polarity")
