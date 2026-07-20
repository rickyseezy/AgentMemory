"""ING-005 immutable capture policies and content-free privacy decisions.

Revision ID: 0013_ing005_capture_privacy
Revises: 0012_ing004_backpressure_dlq
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0013_ing005_capture_privacy"
down_revision = "0012_ing004_backpressure_dlq"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "capture_policy_versions",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("scope_key", sa.Text(), nullable=False),
        sa.Column("policy_id", sa.Text(), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("policy_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("document_json", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "brain_id",
            "scope_key",
            "policy_version",
            name="uq_capture_policy_scope_version",
        ),
        sa.UniqueConstraint(
            "brain_id",
            "scope_key",
            "policy_sha256",
            name="uq_capture_policy_scope_digest",
        ),
        sa.CheckConstraint(
            "(repository_id IS NULL AND scope_key='@brain') OR "
            "(repository_id IS NOT NULL AND scope_key=repository_id)",
            name="ck_capture_policy_scope",
        ),
        sa.CheckConstraint("policy_version >= 1", name="ck_capture_policy_version"),
        sa.CheckConstraint("length(policy_sha256)=32", name="ck_capture_policy_digest"),
        sa.CheckConstraint("json_valid(document_json)", name="ck_capture_policy_json"),
        sa.CheckConstraint("status IN ('active','superseded')", name="ck_capture_policy_status"),
    )
    op.create_index(
        "uq_capture_policy_active_scope",
        "capture_policy_versions",
        ["brain_id", "scope_key"],
        unique=True,
        sqlite_where=sa.text("status='active'"),
    )

    op.create_table(
        "privacy_decisions",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("subject_kind", sa.Text(), nullable=False),
        sa.Column("subject_id", sa.Text(), nullable=False),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "actor_id",
            sa.Text(),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("policy_id", sa.Text(), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("policy_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("input_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("output_sha256", sa.LargeBinary(32), nullable=True),
        sa.Column("disposition", sa.Text(), nullable=False),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("egress_decision", sa.Text(), nullable=False),
        sa.Column("reason_code", sa.Text(), nullable=False),
        sa.Column("finding_counts_json", sa.Text(), nullable=False),
        sa.Column("redaction_count", sa.Integer(), nullable=False),
        sa.Column("stage_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("stage_evidence_json", sa.Text(), nullable=False),
        sa.Column("decided_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("subject_kind", "subject_id", name="uq_privacy_decision_subject"),
        sa.CheckConstraint(
            "subject_kind IN ('agent_event','provider_operation')",
            name="ck_privacy_decision_subject_kind",
        ),
        sa.CheckConstraint("policy_version >= 1", name="ck_privacy_decision_version"),
        sa.CheckConstraint("length(policy_sha256)=32", name="ck_privacy_decision_policy_digest"),
        sa.CheckConstraint("length(input_sha256)=32", name="ck_privacy_decision_input_digest"),
        sa.CheckConstraint(
            "output_sha256 IS NULL OR length(output_sha256)=32",
            name="ck_privacy_decision_output_digest",
        ),
        sa.CheckConstraint(
            "(disposition='excluded' AND output_sha256 IS NULL) OR "
            "(disposition IN ('sanitized','local_only') AND output_sha256 IS NOT NULL)",
            name="ck_privacy_decision_disposition",
        ),
        sa.CheckConstraint(
            "classification IN ('public','internal','confidential','restricted','local_only')",
            name="ck_privacy_decision_classification",
        ),
        sa.CheckConstraint(
            "egress_decision IN ('allow','deny')", name="ck_privacy_decision_egress"
        ),
        sa.CheckConstraint(
            "length(reason_code) BETWEEN 1 AND 128 AND reason_code NOT GLOB '*[^a-z0-9._-]*'",
            name="ck_privacy_decision_reason",
        ),
        sa.CheckConstraint(
            "json_valid(finding_counts_json)", name="ck_privacy_decision_finding_counts"
        ),
        sa.CheckConstraint("redaction_count >= 0", name="ck_privacy_decision_redactions"),
        sa.CheckConstraint("length(stage_sha256)=32", name="ck_privacy_decision_stage_digest"),
        sa.CheckConstraint(
            "json_valid(stage_evidence_json)", name="ck_privacy_decision_stage_json"
        ),
    )
    op.create_index(
        "ix_privacy_decisions_brain_time",
        "privacy_decisions",
        ["brain_id", "decided_at", "id"],
    )


def downgrade() -> None:
    connection = op.get_bind()
    evidence = connection.execute(
        sa.text(
            "SELECT (SELECT COUNT(*) FROM privacy_decisions) + "
            "(SELECT COUNT(*) FROM capture_policy_versions)"
        )
    ).scalar_one()
    if evidence:
        msg = "ING-005 downgrade refused while policy or privacy evidence exists"
        raise RuntimeError(msg)
    op.drop_index("ix_privacy_decisions_brain_time", table_name="privacy_decisions")
    op.drop_table("privacy_decisions")
    op.drop_index("uq_capture_policy_active_scope", table_name="capture_policy_versions")
    op.drop_table("capture_policy_versions")
