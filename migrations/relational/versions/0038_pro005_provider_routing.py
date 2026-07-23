"""PRO-005 immutable provider routing policies, restrictions, and decisions.

Revision ID: 0038_pro005_provider_routing
Revises: 0037_pro004_embedding_spaces
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0038_pro005_provider_routing"
down_revision = "0037_pro004_embedding_spaces"
branch_labels = None
depends_on = None

_OPERATIONS = "'embedding','reranking'"
_KINDS = "'policy','restriction'"


def upgrade() -> None:
    """Install append-only routing authority and content-free decision evidence."""
    op.create_table(
        "provider_routing_policies",
        sa.Column("policy_id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("policy_digest", sa.Text(), nullable=False),
        sa.Column("guard_json", sa.LargeBinary(), nullable=False),
        sa.Column("document_json", sa.LargeBinary(), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("grant_version", sa.BigInteger(), nullable=False),
        sa.Column("authorization_policy_version", sa.Integer(), nullable=False),
        sa.Column("security_epoch", sa.Integer(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("brain_id", "version", name="uq_provider_routing_policy_version"),
        sa.UniqueConstraint("brain_id", "policy_digest", name="uq_provider_routing_policy_digest"),
        sa.CheckConstraint(
            "version>=1 AND length(policy_digest)=64 "
            "AND policy_digest NOT GLOB '*[^0-9a-f]*' "
            "AND json_valid(guard_json) AND json_type(guard_json)='object' "
            "AND json_valid(document_json) AND json_type(document_json)='object' "
            "AND grant_version>=1 AND authorization_policy_version>=1 "
            "AND security_epoch>=1 AND length(scope_fingerprint)=32 "
            "AND schema_version=1",
            name="ck_provider_routing_policy_integrity",
        ),
    )
    op.create_index(
        "ix_provider_routing_policy_current",
        "provider_routing_policies",
        ["brain_id", "version"],
    )
    op.create_table(
        "provider_route_rules",
        sa.Column("rule_id", sa.Text(), primary_key=True),
        sa.Column(
            "policy_id",
            sa.Text(),
            sa.ForeignKey("provider_routing_policies.policy_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "profile_id",
            sa.Text(),
            sa.ForeignKey("provider_profiles.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("profile_snapshot_digest", sa.Text(), nullable=False),
        sa.Column("operation", sa.Text(), nullable=False),
        sa.Column("selector_json", sa.LargeBinary(), nullable=False),
        sa.Column("project_specificity", sa.Integer(), nullable=False),
        sa.Column("dimension_specificity", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["profile_id", "profile_version"],
            ["provider_profile_revisions.profile_id", "provider_profile_revisions.version"],
            name="fk_provider_route_profile_revision",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.CheckConstraint(
            "profile_version>=1 AND length(profile_snapshot_digest)=64 "
            "AND profile_snapshot_digest NOT GLOB '*[^0-9a-f]*' "
            f"AND operation IN ({_OPERATIONS}) "
            "AND json_valid(selector_json) AND json_type(selector_json)='object' "
            "AND project_specificity IN (0,1) "
            "AND dimension_specificity BETWEEN 0 AND 5 "
            "AND length(reason) BETWEEN 1 AND 64 AND schema_version=1",
            name="ck_provider_route_rule_integrity",
        ),
    )
    op.create_index(
        "ix_provider_route_rule_policy",
        "provider_route_rules",
        ["policy_id", "enabled", "project_specificity", "dimension_specificity"],
    )
    op.create_table(
        "provider_repository_route_restrictions",
        sa.Column("restriction_id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("restriction_digest", sa.Text(), nullable=False),
        sa.Column("document_json", sa.LargeBinary(), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("grant_version", sa.BigInteger(), nullable=False),
        sa.Column("authorization_policy_version", sa.Integer(), nullable=False),
        sa.Column("security_epoch", sa.Integer(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "brain_id",
            "repository_id",
            "version",
            name="uq_provider_repository_route_restriction_version",
        ),
        sa.CheckConstraint(
            "version>=1 AND length(restriction_digest)=64 "
            "AND restriction_digest NOT GLOB '*[^0-9a-f]*' "
            "AND json_valid(document_json) AND json_type(document_json)='object' "
            "AND grant_version>=1 AND authorization_policy_version>=1 "
            "AND security_epoch>=1 AND length(scope_fingerprint)=32 "
            "AND schema_version=1",
            name="ck_provider_repository_route_restriction_integrity",
        ),
    )
    op.create_index(
        "ix_provider_repository_route_restriction_current",
        "provider_repository_route_restrictions",
        ["brain_id", "repository_id", "version"],
    )
    op.create_table(
        "provider_routing_operations",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column("operation_kind", sa.Text(), nullable=False),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("request_digest", sa.Text(), nullable=False),
        sa.Column("result_id", sa.Text(), nullable=False),
        sa.Column("result_version", sa.Integer(), nullable=False),
        sa.Column("result_digest", sa.Text(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            f"operation_kind IN ({_KINDS}) AND length(request_digest)=64 "
            "AND request_digest NOT GLOB '*[^0-9a-f]*' AND result_version>=1 "
            "AND length(result_digest)=64 AND result_digest NOT GLOB '*[^0-9a-f]*' "
            "AND schema_version=1",
            name="ck_provider_routing_operation_integrity",
        ),
    )
    op.create_table(
        "provider_route_decisions",
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
            sa.ForeignKey("provider_routing_policies.policy_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "rule_id",
            sa.Text(),
            sa.ForeignKey("provider_route_rules.rule_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "profile_id",
            sa.Text(),
            sa.ForeignKey("provider_profiles.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("cache_key_digest", sa.Text(), nullable=False),
        sa.Column("request_digest", sa.Text(), nullable=False),
        sa.Column("decision_json", sa.LargeBinary(), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("grant_version", sa.BigInteger(), nullable=False),
        sa.Column("authorization_policy_version", sa.Integer(), nullable=False),
        sa.Column("security_epoch", sa.Integer(), nullable=False),
        sa.Column("decided_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["profile_id", "profile_version"],
            ["provider_profile_revisions.profile_id", "provider_profile_revisions.version"],
            name="fk_provider_route_decision_profile_revision",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.CheckConstraint(
            "profile_version>=1 AND length(cache_key_digest)=64 "
            "AND cache_key_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(request_digest)=64 AND request_digest NOT GLOB '*[^0-9a-f]*' "
            "AND json_valid(decision_json) AND json_type(decision_json)='object' "
            "AND grant_version>=1 AND authorization_policy_version>=1 "
            "AND security_epoch>=1 AND schema_version=1",
            name="ck_provider_route_decision_integrity",
        ),
    )
    op.create_index(
        "ix_provider_route_decision_policy",
        "provider_route_decisions",
        ["brain_id", "policy_id", "decided_at"],
    )
    for table in (
        "provider_routing_policies",
        "provider_route_rules",
        "provider_repository_route_restrictions",
        "provider_routing_operations",
        "provider_route_decisions",
    ):
        _immutable(table)


def _immutable(table: str) -> None:
    for operation in ("UPDATE", "DELETE"):
        op.execute(
            f"CREATE TRIGGER trg_{table}_immutable_{operation.lower()} "
            f"BEFORE {operation} ON {table} "
            "BEGIN SELECT RAISE(ABORT, 'immutable provider routing history'); END"
        )


def downgrade() -> None:
    """Refuse to destroy any published routing authority or evidence."""
    connection = op.get_bind()
    count = connection.execute(
        sa.text(
            "SELECT (SELECT COUNT(*) FROM provider_routing_policies) "
            "+(SELECT COUNT(*) FROM provider_repository_route_restrictions) "
            "+(SELECT COUNT(*) FROM provider_route_decisions)"
        )
    ).scalar_one()
    if count:
        message = "PRO-005 downgrade refused while provider routing history exists"
        raise RuntimeError(message)
    for table in (
        "provider_route_decisions",
        "provider_routing_operations",
        "provider_repository_route_restrictions",
        "provider_route_rules",
        "provider_routing_policies",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable_delete")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable_update")
    op.drop_index(
        "ix_provider_route_decision_policy",
        table_name="provider_route_decisions",
    )
    op.drop_table("provider_route_decisions")
    op.drop_table("provider_routing_operations")
    op.drop_index(
        "ix_provider_repository_route_restriction_current",
        table_name="provider_repository_route_restrictions",
    )
    op.drop_table("provider_repository_route_restrictions")
    op.drop_index("ix_provider_route_rule_policy", table_name="provider_route_rules")
    op.drop_table("provider_route_rules")
    op.drop_index(
        "ix_provider_routing_policy_current",
        table_name="provider_routing_policies",
    )
    op.drop_table("provider_routing_policies")
