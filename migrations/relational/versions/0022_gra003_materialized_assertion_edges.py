"""GRA-003 durable assertion-edge projection and integrity evidence.

Revision ID: 0022_gra003_materialized_assertion_edges
Revises: 0021_gra002_evidence_assertions
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0022_gra003_materialized_assertion_edges"
down_revision = "0021_gra002_evidence_assertions"
branch_labels = None
depends_on = None

_CLASSIFICATIONS = "'public','internal','confidential','restricted','local_only'"


def upgrade() -> None:
    """Install durable projection work plus append-only completion and repair evidence."""
    op.create_table(
        "assertion_edge_projection_jobs",
        sa.Column(
            "source_event_id",
            sa.Text(),
            sa.ForeignKey("domain_events.event_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "assertion_id",
            sa.Text(),
            sa.ForeignKey("assertion_candidates.assertion_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "principal_id",
            sa.Text(),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
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
            "checkout_id",
            sa.Text(),
            sa.ForeignKey("checkouts.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("aggregate_version", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("event_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("state", sa.Text(), nullable=False, server_default="ready"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("not_before", sa.BigInteger(), nullable=False),
        sa.Column("lease_owner", sa.Text(), nullable=True),
        sa.Column("lease_until", sa.BigInteger(), nullable=True),
        sa.Column("last_error_code", sa.Text(), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            f"classification IN ({_CLASSIFICATIONS})",
            name="ck_assertion_edge_job_classification",
        ),
        sa.CheckConstraint(
            "aggregate_version IN (1,2) AND "
            "((aggregate_version=1 AND event_type='AssertionActivated') OR "
            "(aggregate_version=2 AND event_type='AssertionDisputed'))",
            name="ck_assertion_edge_job_event",
        ),
        sa.CheckConstraint(
            "state IN ('ready','leased','completed','quarantined')",
            name="ck_assertion_edge_job_state",
        ),
        sa.CheckConstraint("attempts BETWEEN 0 AND 1000", name="ck_assertion_edge_job_attempts"),
        sa.CheckConstraint(
            "length(scope_fingerprint)=32 AND length(event_digest)=32",
            name="ck_assertion_edge_job_digests",
        ),
        sa.CheckConstraint(
            "(state='leased' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL "
            "AND completed_at IS NULL) OR "
            "(state IN ('ready','quarantined') AND lease_owner IS NULL "
            "AND lease_until IS NULL AND completed_at IS NULL) OR "
            "(state='completed' AND lease_owner IS NULL AND lease_until IS NULL "
            "AND completed_at IS NOT NULL)",
            name="ck_assertion_edge_job_lease",
        ),
    )
    op.create_index(
        "ix_assertion_edge_job_queue",
        "assertion_edge_projection_jobs",
        ["state", "not_before", "created_at", "source_event_id"],
    )
    op.create_index(
        "ix_assertion_edge_job_scope",
        "assertion_edge_projection_jobs",
        ["brain_id", "project_id", "repository_id", "assertion_id", "aggregate_version"],
    )
    op.execute(
        "CREATE TRIGGER assertion_edge_projection_jobs_binding_immutable "
        "BEFORE UPDATE ON assertion_edge_projection_jobs WHEN "
        "OLD.source_event_id<>NEW.source_event_id OR OLD.assertion_id<>NEW.assertion_id OR "
        "OLD.brain_id<>NEW.brain_id OR OLD.principal_id<>NEW.principal_id OR "
        "OLD.scope_fingerprint<>NEW.scope_fingerprint OR OLD.project_id<>NEW.project_id OR "
        "OLD.repository_id<>NEW.repository_id OR "
        "NOT (OLD.checkout_id IS NEW.checkout_id) OR "
        "OLD.classification<>NEW.classification OR "
        "OLD.aggregate_version<>NEW.aggregate_version OR OLD.event_type<>NEW.event_type OR "
        "OLD.event_digest<>NEW.event_digest OR OLD.created_at<>NEW.created_at OR "
        "OLD.schema_version<>NEW.schema_version BEGIN "
        "SELECT RAISE(ABORT, 'assertion edge projection job binding is immutable'); END"
    )
    op.create_table(
        "assertion_edge_projection_receipts",
        sa.Column(
            "source_event_id",
            sa.Text(),
            sa.ForeignKey("assertion_edge_projection_jobs.source_event_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("assertion_id", sa.Text(), nullable=False),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("generation_id", sa.LargeBinary(32), nullable=False),
        sa.Column("projection_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("projection_status", sa.Text(), nullable=False),
        sa.Column("aggregate_version", sa.Integer(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(generation_id)=32 AND length(projection_digest)=32",
            name="ck_assertion_edge_receipt_digests",
        ),
        sa.CheckConstraint(
            "(aggregate_version=1 AND projection_status='active') OR "
            "(aggregate_version=2 AND projection_status='retired')",
            name="ck_assertion_edge_receipt_status",
        ),
    )
    op.create_index(
        "ix_assertion_edge_receipt_scope",
        "assertion_edge_projection_receipts",
        ["brain_id", "generation_id", "assertion_id", "aggregate_version"],
    )
    op.create_table(
        "assertion_edge_integrity_findings",
        sa.Column("finding_id", sa.Text(), primary_key=True),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("generation_id", sa.LargeBinary(32), nullable=False),
        sa.Column("assertion_id", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("expected_digest", sa.LargeBinary(32), nullable=True),
        sa.Column("actual_digest", sa.LargeBinary(32), nullable=True),
        sa.Column("detected_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "kind IN ('orphan','missing','mismatch')", name="ck_assertion_edge_finding_kind"
        ),
        sa.CheckConstraint(
            "length(scope_fingerprint)=32 AND length(generation_id)=32 AND "
            "(expected_digest IS NULL OR length(expected_digest)=32) AND "
            "(actual_digest IS NULL OR length(actual_digest)=32)",
            name="ck_assertion_edge_finding_digests",
        ),
    )
    op.create_index(
        "ix_assertion_edge_finding_scope",
        "assertion_edge_integrity_findings",
        ["brain_id", "generation_id", "detected_at", "finding_id"],
    )
    op.create_table(
        "assertion_edge_integrity_repairs",
        sa.Column(
            "finding_id",
            sa.Text(),
            sa.ForeignKey("assertion_edge_integrity_findings.finding_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("repaired_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("length(scope_fingerprint)=32", name="ck_assertion_edge_repair_scope"),
    )
    for table in (
        "assertion_edge_projection_receipts",
        "assertion_edge_integrity_findings",
        "assertion_edge_integrity_repairs",
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
    """Refuse rollback after durable projection or integrity evidence exists."""
    connection = op.get_bind()
    for table in (
        "assertion_edge_projection_jobs",
        "assertion_edge_projection_receipts",
        "assertion_edge_integrity_findings",
        "assertion_edge_integrity_repairs",
    ):
        if connection.execute(sa.text(f"SELECT COUNT(*) FROM {table}")).scalar_one():  # noqa: S608
            msg = "GRA-003 downgrade refused while assertion-edge evidence exists"
            raise RuntimeError(msg)
    for table in (
        "assertion_edge_integrity_repairs",
        "assertion_edge_integrity_findings",
        "assertion_edge_projection_receipts",
    ):
        op.execute(f"DROP TRIGGER {table}_no_delete")
        op.execute(f"DROP TRIGGER {table}_no_update")
    op.execute("DROP TRIGGER assertion_edge_projection_jobs_binding_immutable")
    op.drop_table("assertion_edge_integrity_repairs")
    op.drop_index("ix_assertion_edge_finding_scope", table_name="assertion_edge_integrity_findings")
    op.drop_table("assertion_edge_integrity_findings")
    op.drop_index(
        "ix_assertion_edge_receipt_scope", table_name="assertion_edge_projection_receipts"
    )
    op.drop_table("assertion_edge_projection_receipts")
    op.drop_index("ix_assertion_edge_job_scope", table_name="assertion_edge_projection_jobs")
    op.drop_index("ix_assertion_edge_job_queue", table_name="assertion_edge_projection_jobs")
    op.drop_table("assertion_edge_projection_jobs")
