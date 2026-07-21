"""GRA-002 immutable evidence handles and assertion lifecycle.

Revision ID: 0021_gra002_evidence_assertions
Revises: 0020_mem006_session_briefing
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0021_gra002_evidence_assertions"
down_revision = "0020_mem006_session_briefing"
branch_labels = None
depends_on = None

_CLASSIFICATIONS = "'public','internal','confidential','restricted','local_only'"
_PREDICATES = "'calls','imports','consumes','implements','depends_on','produces','deployed_as'"


def upgrade() -> None:
    """Install append-only evidence, proposal, assertion, and operation ledgers."""
    op.create_table(
        "assertion_evidence_sources",
        sa.Column("evidence_id", sa.Text(), primary_key=True),
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
            "checkout_id",
            sa.Text(),
            sa.ForeignKey("checkouts.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("agent_events.event_id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "artifact_id",
            sa.Text(),
            sa.ForeignKey("artifacts.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("span_start", sa.BigInteger(), nullable=True),
        sa.Column("span_end", sa.BigInteger(), nullable=True),
        sa.Column("source_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("registered_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            f"classification IN ({_CLASSIFICATIONS})", name="ck_assertion_evidence_classification"
        ),
        sa.CheckConstraint(
            "kind IN ('event','artifact','source_span','user_statement')",
            name="ck_assertion_evidence_kind",
        ),
        sa.CheckConstraint("length(source_digest)=32", name="ck_assertion_evidence_digest"),
        sa.CheckConstraint(
            "(kind IN ('event','user_statement') AND event_id IS NOT NULL "
            "AND artifact_id IS NULL AND span_start IS NULL AND span_end IS NULL) OR "
            "(kind='artifact' AND event_id IS NOT NULL AND artifact_id IS NOT NULL "
            "AND span_start IS NULL AND span_end IS NULL) OR "
            "(kind='source_span' AND event_id IS NOT NULL AND artifact_id IS NOT NULL "
            "AND span_start>=0 AND span_end>span_start)",
            name="ck_assertion_evidence_source_shape",
        ),
    )
    op.create_index(
        "ix_assertion_evidence_scope",
        "assertion_evidence_sources",
        ["brain_id", "project_id", "repository_id", "checkout_id", "classification"],
    )
    op.create_table(
        "assertion_evidence_revocations",
        sa.Column(
            "evidence_id",
            sa.Text(),
            sa.ForeignKey("assertion_evidence_sources.evidence_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("operation_id", sa.Text(), nullable=False, unique=True),
        sa.Column(
            "principal_id",
            sa.Text(),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("request_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("revoked_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "reason IN ('deleted','access_revoked','source_invalidated','user_retracted')",
            name="ck_assertion_evidence_revocation_reason",
        ),
        sa.CheckConstraint(
            "length(scope_fingerprint)=32 AND length(request_digest)=32",
            name="ck_assertion_evidence_revocation_digests",
        ),
    )
    op.create_table(
        "assertion_operations",
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
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("assertion_id", sa.Text(), nullable=False),
        sa.Column("request_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("event_id", sa.Text(), nullable=True, unique=True),
        sa.Column("result_status", sa.Text(), nullable=False),
        sa.Column("aggregate_version", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(scope_fingerprint)=32 AND length(request_digest)=32",
            name="ck_assertion_operation_digests",
        ),
        sa.CheckConstraint(
            "action IN ('propose','activate','dispute')", name="ck_assertion_operation_action"
        ),
        sa.CheckConstraint(
            "result_status IN ('candidate','active','disputed')",
            name="ck_assertion_operation_status",
        ),
        sa.CheckConstraint(
            "aggregate_version BETWEEN 0 AND 2", name="ck_assertion_operation_version"
        ),
    )
    op.create_table(
        "assertion_candidates",
        sa.Column("assertion_id", sa.Text(), primary_key=True),
        sa.Column(
            "proposal_operation_id",
            sa.Text(),
            sa.ForeignKey("assertion_operations.operation_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
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
            "checkout_id",
            sa.Text(),
            sa.ForeignKey("checkouts.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("subject_id", sa.Text(), nullable=False),
        sa.Column("predicate", sa.Text(), nullable=False),
        sa.Column("object_id", sa.Text(), nullable=False),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("valid_from", sa.BigInteger(), nullable=False),
        sa.Column("valid_to", sa.BigInteger(), nullable=True),
        sa.Column("proposed_at", sa.BigInteger(), nullable=False),
        sa.Column("confidence_evidence_support", sa.Integer(), nullable=False),
        sa.Column("confidence_source_reliability", sa.Integer(), nullable=False),
        sa.Column("confidence_extraction_quality", sa.Integer(), nullable=False),
        sa.Column("extractor_id", sa.Text(), nullable=False),
        sa.Column("extractor_version", sa.Text(), nullable=False),
        sa.Column("model_id", sa.Text(), nullable=False),
        sa.Column("model_revision", sa.Text(), nullable=False),
        sa.Column("evidence_ids_json", sa.Text(), nullable=False),
        sa.Column("content_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("revision_id", sa.LargeBinary(32), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            f"predicate IN ({_PREDICATES})", name="ck_assertion_candidate_predicate"
        ),
        sa.CheckConstraint(
            f"classification IN ({_CLASSIFICATIONS})", name="ck_assertion_candidate_classification"
        ),
        sa.CheckConstraint("subject_id<>object_id", name="ck_assertion_candidate_endpoints"),
        sa.CheckConstraint(
            "valid_to IS NULL OR valid_to>valid_from", name="ck_assertion_candidate_valid_time"
        ),
        sa.CheckConstraint(
            "confidence_evidence_support BETWEEN 0 AND 10000 AND "
            "confidence_source_reliability BETWEEN 0 AND 10000 AND "
            "confidence_extraction_quality BETWEEN 0 AND 10000",
            name="ck_assertion_candidate_confidence",
        ),
        sa.CheckConstraint(
            "json_valid(evidence_ids_json) AND json_type(evidence_ids_json)='array'",
            name="ck_assertion_candidate_evidence_json",
        ),
        sa.CheckConstraint(
            "length(content_fingerprint)=32 AND length(revision_id)=32",
            name="ck_assertion_candidate_digests",
        ),
        sa.CheckConstraint("status='candidate'", name="ck_assertion_candidate_status"),
    )
    op.create_index(
        "ix_assertion_candidate_scope",
        "assertion_candidates",
        ["brain_id", "project_id", "repository_id", "checkout_id", "status"],
    )
    op.create_table(
        "assertion_lifecycle",
        sa.Column(
            "assertion_id",
            sa.Text(),
            sa.ForeignKey("assertion_candidates.assertion_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("aggregate_version", sa.Integer(), nullable=False),
        sa.Column(
            "operation_id",
            sa.Text(),
            sa.ForeignKey("assertion_operations.operation_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("domain_events.event_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("recorded_from", sa.BigInteger(), nullable=False),
        sa.Column("recorded_to", sa.BigInteger(), nullable=True),
        sa.Column("event_digest", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("assertion_id", "aggregate_version"),
        sa.CheckConstraint(
            "(aggregate_version=1 AND status='active' AND recorded_to IS NULL) OR "
            "(aggregate_version=2 AND status='disputed' AND recorded_to>recorded_from)",
            name="ck_assertion_lifecycle_transition",
        ),
        sa.CheckConstraint("length(event_digest)=32", name="ck_assertion_lifecycle_digest"),
    )
    op.create_index(
        "ix_assertion_lifecycle_current",
        "assertion_lifecycle",
        ["assertion_id", "aggregate_version", "status"],
    )
    op.create_table(
        "assertion_evidence_snapshots",
        sa.Column("assertion_id", sa.Text(), nullable=False),
        sa.Column(
            "evidence_id",
            sa.Text(),
            sa.ForeignKey("assertion_evidence_sources.evidence_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("source_id", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("project_id", sa.Text(), nullable=False),
        sa.Column("repository_id", sa.Text(), nullable=False),
        sa.Column("checkout_id", sa.Text(), nullable=True),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("source_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["assertion_id", "aggregate_version"],
            ["assertion_lifecycle.assertion_id", "assertion_lifecycle.aggregate_version"],
            ondelete="RESTRICT",
        ),
        sa.Column("aggregate_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("assertion_id", "evidence_id"),
        sa.CheckConstraint("aggregate_version=1", name="ck_assertion_evidence_snapshot_version"),
        sa.CheckConstraint(
            "kind IN ('event','artifact','source_span','user_statement')",
            name="ck_assertion_evidence_snapshot_kind",
        ),
        sa.CheckConstraint(
            f"classification IN ({_CLASSIFICATIONS})",
            name="ck_assertion_evidence_snapshot_classification",
        ),
        sa.CheckConstraint(
            "length(source_digest)=32", name="ck_assertion_evidence_snapshot_digest"
        ),
    )

    for table in (
        "assertion_evidence_sources",
        "assertion_evidence_revocations",
        "assertion_operations",
        "assertion_candidates",
        "assertion_lifecycle",
        "assertion_evidence_snapshots",
    ):
        op.execute(
            f"CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} BEGIN "
            f"SELECT RAISE(ABORT, '{table} is immutable'); END"
        )
        op.execute(
            f"CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN "
            f"SELECT RAISE(ABORT, '{table} is immutable'); END"
        )
    op.execute(
        "CREATE TRIGGER assertion_domain_events_no_update BEFORE UPDATE ON domain_events "
        "WHEN OLD.aggregate_type='assertion' BEGIN "
        "SELECT RAISE(ABORT, 'assertion domain events are immutable'); END"
    )
    op.execute(
        "CREATE TRIGGER assertion_domain_events_no_delete BEFORE DELETE ON domain_events "
        "WHEN OLD.aggregate_type='assertion' BEGIN "
        "SELECT RAISE(ABORT, 'assertion domain events are immutable'); END"
    )


def downgrade() -> None:
    """Refuse rollback once any GRA-002 evidence or assertion record exists."""
    connection = op.get_bind()
    count = connection.execute(
        sa.text(
            "SELECT (SELECT COUNT(*) FROM assertion_evidence_sources) + "
            "(SELECT COUNT(*) FROM assertion_operations) + "
            "(SELECT COUNT(*) FROM assertion_evidence_revocations)"
        )
    ).scalar_one()
    if count:
        msg = "GRA-002 downgrade refused while assertion evidence exists"
        raise RuntimeError(msg)
    op.execute("DROP TRIGGER assertion_domain_events_no_delete")
    op.execute("DROP TRIGGER assertion_domain_events_no_update")
    for table in reversed(
        (
            "assertion_evidence_sources",
            "assertion_evidence_revocations",
            "assertion_operations",
            "assertion_candidates",
            "assertion_lifecycle",
            "assertion_evidence_snapshots",
        )
    ):
        op.execute(f"DROP TRIGGER {table}_no_delete")
        op.execute(f"DROP TRIGGER {table}_no_update")
    op.drop_table("assertion_evidence_snapshots")
    op.drop_index("ix_assertion_lifecycle_current", table_name="assertion_lifecycle")
    op.drop_table("assertion_lifecycle")
    op.drop_index("ix_assertion_candidate_scope", table_name="assertion_candidates")
    op.drop_table("assertion_candidates")
    op.drop_table("assertion_operations")
    op.drop_table("assertion_evidence_revocations")
    op.drop_index("ix_assertion_evidence_scope", table_name="assertion_evidence_sources")
    op.drop_table("assertion_evidence_sources")
