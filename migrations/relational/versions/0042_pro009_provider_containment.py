"""PRO-009 provider-egress policy, permits, and runtime evidence.

Revision ID: 0042_pro009_provider_containment
Revises: 0041_pro008_embedding_migrations
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0042_pro009_provider_containment"
down_revision = "0041_pro008_embedding_migrations"
branch_labels = None
depends_on = None

_CLASSIFICATIONS = "'public','internal','confidential','restricted','local_only'"


def upgrade() -> None:
    """Install immutable egress policies, short-lived permits, and safe runtime facts."""
    op.create_table(
        "provider_egress_policies",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("security_epoch", sa.BigInteger(), nullable=False),
        sa.Column("classification_ceiling", sa.Text(), nullable=False),
        sa.Column("policy_digest", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("document_json", sa.LargeBinary(), nullable=False),
        sa.Column("attestation_id", sa.Text(), nullable=False),
        sa.Column("attestation_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("valid_from", sa.BigInteger(), nullable=False),
        sa.Column("valid_until", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("brain_id", "version", name="uq_provider_egress_policy_version"),
        sa.CheckConstraint(
            f"version>=1 AND security_epoch>=1 "
            f"AND classification_ceiling IN ({_CLASSIFICATIONS}) "
            "AND length(policy_digest)=32 AND length(document_json)>1 "
            "AND length(attestation_digest)=32 "
            "AND valid_from>=0 AND valid_until>valid_from "
            "AND created_at>=0 AND schema_version=1",
            name="ck_provider_egress_policy_integrity",
        ),
    )
    op.create_table(
        "active_provider_egress_policies",
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "policy_id",
            sa.Text(),
            sa.ForeignKey("provider_egress_policies.id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("policy_version", sa.BigInteger(), nullable=False),
        sa.Column("pointer_version", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "policy_version>=1 AND pointer_version>=1 AND updated_at>=0 AND schema_version=1",
            name="ck_active_provider_egress_policy_integrity",
        ),
    )
    op.create_table(
        "provider_egress_operations",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "policy_id",
            sa.Text(),
            sa.ForeignKey("provider_egress_policies.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("request_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(request_digest)=32 AND length(scope_fingerprint)=32 "
            "AND completed_at>=0 AND schema_version=1",
            name="ck_provider_egress_operation_integrity",
        ),
    )
    op.create_table(
        "provider_egress_permits",
        sa.Column("permit_digest", sa.LargeBinary(32), primary_key=True),
        sa.Column("operation_id", sa.Text(), nullable=False),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "policy_id",
            sa.Text(),
            sa.ForeignKey("provider_egress_policies.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("policy_version", sa.BigInteger(), nullable=False),
        sa.Column("security_epoch", sa.BigInteger(), nullable=False),
        sa.Column("request_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("destination_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("document_json", sa.LargeBinary(), nullable=False),
        sa.Column("issued_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "operation_id",
            "request_digest",
            "issued_at",
            name="uq_provider_egress_permit_attempt",
        ),
        sa.CheckConstraint(
            "length(permit_digest)=32 AND policy_version>=1 AND security_epoch>=1 "
            "AND length(request_digest)=32 AND length(destination_fingerprint)=32 "
            "AND length(document_json)>1 AND issued_at>=0 AND expires_at>issued_at "
            "AND schema_version=1",
            name="ck_provider_egress_permit_integrity",
        ),
    )
    op.create_index(
        "ix_provider_egress_permit_expiry",
        "provider_egress_permits",
        ["expires_at", "brain_id"],
    )
    op.create_table(
        "provider_runtime_facts",
        sa.Column("fact_digest", sa.LargeBinary(32), primary_key=True),
        sa.Column("operation_id", sa.Text(), nullable=False),
        sa.Column("adapter_image_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("outcome_code", sa.Text(), nullable=False),
        sa.Column("runtime_milliseconds", sa.BigInteger(), nullable=False),
        sa.Column("cleanup_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(fact_digest)=32 AND length(adapter_image_digest)=32 "
            "AND length(outcome_code) BETWEEN 1 AND 64 "
            "AND runtime_milliseconds BETWEEN 0 AND 300000 "
            "AND length(cleanup_digest)=32 AND occurred_at>=0 AND schema_version=1",
            name="ck_provider_runtime_fact_integrity",
        ),
    )
    op.create_table(
        "provider_egress_decisions",
        sa.Column("fact_digest", sa.LargeBinary(32), primary_key=True),
        sa.Column("permit_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("operation_id", sa.Text(), nullable=False),
        sa.Column("destination_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("outcome_code", sa.Text(), nullable=False),
        sa.Column("request_bytes", sa.BigInteger(), nullable=False),
        sa.Column("response_bytes", sa.BigInteger(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(fact_digest)=32 AND length(permit_digest)=32 "
            "AND length(destination_fingerprint)=32 "
            "AND length(outcome_code) BETWEEN 1 AND 64 "
            "AND request_bytes BETWEEN 0 AND 8388608 "
            "AND response_bytes BETWEEN 0 AND 8388608 "
            "AND (status_code IS NULL OR status_code BETWEEN 100 AND 599) "
            "AND occurred_at>=0 AND schema_version=1",
            name="ck_provider_egress_decision_integrity",
        ),
    )
    for table in (
        "provider_egress_policies",
        "provider_egress_operations",
        "provider_egress_permits",
        "provider_runtime_facts",
        "provider_egress_decisions",
    ):
        _immutable(table)
    op.execute(
        "CREATE TRIGGER trg_active_provider_egress_policies_closed_update "
        "BEFORE UPDATE ON active_provider_egress_policies "
        "WHEN OLD.brain_id<>NEW.brain_id OR OLD.schema_version<>NEW.schema_version "
        "OR NEW.pointer_version<>OLD.pointer_version+1 "
        "OR NEW.policy_version<=OLD.policy_version OR NEW.updated_at<OLD.updated_at "
        "BEGIN SELECT RAISE(ABORT, 'immutable provider egress pointer'); END"
    )
    op.execute(
        "CREATE TRIGGER trg_active_provider_egress_policies_immutable_delete "
        "BEFORE DELETE ON active_provider_egress_policies "
        "BEGIN SELECT RAISE(ABORT, 'immutable provider egress pointer'); END"
    )


def _immutable(table: str) -> None:
    for operation in ("UPDATE", "DELETE"):
        op.execute(
            f"CREATE TRIGGER trg_{table}_immutable_{operation.lower()} "
            f"BEFORE {operation} ON {table} "
            "BEGIN SELECT RAISE(ABORT, 'immutable provider containment evidence'); END"
        )


def downgrade() -> None:
    """Refuse to destroy any provider-containment authority or evidence."""
    connection = op.get_bind()
    count = connection.execute(
        sa.text(
            "SELECT "
            "(SELECT COUNT(*) FROM provider_egress_policies)+"
            "(SELECT COUNT(*) FROM provider_egress_permits)+"
            "(SELECT COUNT(*) FROM provider_runtime_facts)+"
            "(SELECT COUNT(*) FROM provider_egress_decisions)"
        )
    ).scalar_one()
    if count:
        message = "PRO-009 downgrade refused while provider containment authority exists"
        raise RuntimeError(message)
    for table in (
        "provider_egress_policies",
        "provider_egress_operations",
        "provider_egress_permits",
        "provider_runtime_facts",
        "provider_egress_decisions",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable_update")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable_delete")
    op.execute("DROP TRIGGER IF EXISTS trg_active_provider_egress_policies_closed_update")
    op.execute("DROP TRIGGER IF EXISTS trg_active_provider_egress_policies_immutable_delete")
    op.drop_table("provider_egress_decisions")
    op.drop_table("provider_runtime_facts")
    op.drop_index("ix_provider_egress_permit_expiry", table_name="provider_egress_permits")
    op.drop_table("provider_egress_permits")
    op.drop_table("provider_egress_operations")
    op.drop_table("active_provider_egress_policies")
    op.drop_table("provider_egress_policies")
