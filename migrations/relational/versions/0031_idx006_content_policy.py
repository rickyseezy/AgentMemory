"""IDX-006 content policy revisions, decisions, and derivative reconciliation.

Revision ID: 0031_idx006_content_policy
Revises: 0030_idx005_artifact_topology
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0031_idx006_content_policy"
down_revision = "0030_idx005_artifact_topology"
branch_labels = None
depends_on = None

_LAYERS = "'brain','agentmemoryignore','private_block','gitignore','default'"
_DISPOSITIONS = "'include','exclude'"
_PHASES = "'path','content'"
_ACTIONS = "'delete','reindex'"


def upgrade() -> None:
    """Install append-only policy authority, evidence, and bounded work."""
    _create_policy_versions()
    _create_sources_and_decisions()
    _create_changes_and_work()
    _create_projection_receipts()
    for table in _TABLES:
        _immutable(table)


def _create_policy_versions() -> None:
    op.create_table(
        "index_content_policy_versions",
        sa.Column("policy_digest", sa.Text(), primary_key=True),
        sa.Column("operation_id", sa.Text(), nullable=False, unique=True),
        sa.Column("policy_id", sa.Text(), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("document_json", sa.LargeBinary(), nullable=False),
        sa.Column("activated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "brain_id", "repository_id", "policy_version", name="uq_index_content_policy_version"
        ),
        sa.CheckConstraint(
            "length(policy_digest)=64 AND policy_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(scope_fingerprint)=32 AND json_valid(document_json) "
            "AND json_type(document_json)='object'",
            name="ck_index_content_policy_identity",
        ),
    )
    op.create_index(
        "ix_index_content_policy_active",
        "index_content_policy_versions",
        ["brain_id", "repository_id", "policy_version", "activated_at"],
    )


def _create_sources_and_decisions() -> None:
    op.create_table(
        "index_policy_rule_sources",
        sa.Column("source_id", sa.Text(), primary_key=True),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("layer", sa.Text(), nullable=False),
        sa.Column("source_version", sa.Integer(), nullable=False),
        sa.Column("source_hash", sa.Text(), nullable=False),
        sa.Column("rules_json", sa.LargeBinary(), nullable=False),
        sa.Column("observed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "repository_id", "layer", "source_version", name="uq_index_policy_source_version"
        ),
        sa.UniqueConstraint(
            "repository_id", "layer", "source_hash", name="uq_index_policy_source_hash"
        ),
        sa.CheckConstraint(
            f"length(source_id)=64 AND layer IN ({_LAYERS}) AND source_version>=1 "
            "AND length(source_hash)=64 AND source_hash NOT GLOB '*[^0-9a-f]*' "
            "AND json_valid(rules_json) AND json_type(rules_json)='array'",
            name="ck_index_policy_source_identity",
        ),
    )
    op.create_table(
        "index_policy_decisions",
        sa.Column("decision_id", sa.Text(), primary_key=True),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.Column("phase", sa.Text(), nullable=False),
        sa.Column("disposition", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("layer", sa.Text(), nullable=False),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("source_hash", sa.Text(), nullable=False),
        sa.Column("policy_digest", sa.Text(), nullable=False),
        sa.Column("byte_length", sa.BigInteger(), nullable=False),
        sa.Column("content_hash", sa.Text(), nullable=True),
        sa.Column("is_binary", sa.Boolean(), nullable=False),
        sa.Column("is_encrypted", sa.Boolean(), nullable=False),
        sa.Column("is_private", sa.Boolean(), nullable=False),
        sa.Column("is_symlink", sa.Boolean(), nullable=False),
        sa.Column("decided_at", sa.BigInteger(), nullable=False),
        sa.Column("decision_json", sa.LargeBinary(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            f"length(decision_id)=64 AND phase IN ({_PHASES}) "
            f"AND disposition IN ({_DISPOSITIONS}) AND layer IN ({_LAYERS}) "
            "AND length(relative_path) BETWEEN 1 AND 4096 AND rule_version>=1 "
            "AND length(source_hash)=64 AND length(policy_digest)=64 AND byte_length>=0 "
            "AND (content_hash IS NULL OR length(content_hash)=64) "
            "AND json_valid(decision_json) AND json_type(decision_json)='object'",
            name="ck_index_policy_decision_identity",
        ),
    )
    op.create_index(
        "ix_index_policy_decision_path",
        "index_policy_decisions",
        ["repository_id", "relative_path", "decided_at", "decision_id"],
    )


def _create_changes_and_work() -> None:
    op.create_table(
        "index_policy_changes",
        sa.Column("change_id", sa.Text(), primary_key=True),
        sa.Column("operation_id", sa.Text(), nullable=False, unique=True),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("previous_policy_digest", sa.Text(), nullable=True),
        sa.Column(
            "current_policy_digest",
            sa.Text(),
            sa.ForeignKey("index_content_policy_versions.policy_digest", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("delete_count", sa.Integer(), nullable=False),
        sa.Column("reindex_count", sa.Integer(), nullable=False),
        sa.Column("activated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(change_id)=64 AND (previous_policy_digest IS NULL OR "
            "length(previous_policy_digest)=64) AND length(current_policy_digest)=64 "
            "AND delete_count>=0 AND reindex_count>=0",
            name="ck_index_policy_change_identity",
        ),
    )
    op.create_table(
        "index_policy_reconciliation_items",
        sa.Column("item_id", sa.Text(), primary_key=True),
        sa.Column(
            "change_id",
            sa.Text(),
            sa.ForeignKey("index_policy_changes.change_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("policy_digest", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("change_id", "ordinal", name="uq_index_policy_work_ordinal"),
        sa.UniqueConstraint("change_id", "relative_path", "action", name="uq_index_policy_work"),
        sa.CheckConstraint(
            f"length(item_id)=64 AND ordinal>=0 AND action IN ({_ACTIONS}) "
            "AND length(relative_path) BETWEEN 1 AND 4096 AND length(policy_digest)=64",
            name="ck_index_policy_work_identity",
        ),
    )
    op.create_table(
        "index_policy_reconciliation_snapshots",
        sa.Column(
            "item_id",
            sa.Text(),
            sa.ForeignKey("index_policy_reconciliation_items.item_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("snapshot_version", sa.Integer(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("leased_until", sa.BigInteger(), nullable=True),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("snapshot_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("item_id", "snapshot_version"),
        sa.CheckConstraint(
            "snapshot_version>=0 AND state IN ('queued','claimed','completed') AND attempt>=0 "
            "AND length(snapshot_digest)=32 AND ((state='claimed' AND leased_until IS NOT NULL) "
            "OR (state<>'claimed' AND leased_until IS NULL))",
            name="ck_index_policy_work_snapshot",
        ),
    )


def _create_projection_receipts() -> None:
    op.create_table(
        "index_policy_derivative_invalidations",
        sa.Column(
            "item_id",
            sa.Text(),
            sa.ForeignKey("index_policy_reconciliation_items.item_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("repository_id", sa.Text(), nullable=False),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.Column("semantic_ids_json", sa.LargeBinary(), nullable=False),
        sa.Column("dependent_fact_ids_json", sa.LargeBinary(), nullable=False),
        sa.Column("assertion_evidence_ids_json", sa.LargeBinary(), nullable=False),
        sa.Column("invalidated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "json_valid(semantic_ids_json) AND json_type(semantic_ids_json)='array' "
            "AND json_valid(dependent_fact_ids_json) "
            "AND json_type(dependent_fact_ids_json)='array' "
            "AND json_valid(assertion_evidence_ids_json) "
            "AND json_type(assertion_evidence_ids_json)='array'",
            name="ck_index_policy_invalidation_evidence",
        ),
    )
    op.create_table(
        "index_policy_reindex_requests",
        sa.Column(
            "item_id",
            sa.Text(),
            sa.ForeignKey("index_policy_reconciliation_items.item_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("repository_id", sa.Text(), nullable=False),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.Column("policy_digest", sa.Text(), nullable=False),
        sa.Column("requested_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
    )


_TABLES = (
    "index_content_policy_versions",
    "index_policy_rule_sources",
    "index_policy_decisions",
    "index_policy_changes",
    "index_policy_reconciliation_items",
    "index_policy_reconciliation_snapshots",
    "index_policy_derivative_invalidations",
    "index_policy_reindex_requests",
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
    """Refuse to erase policy authority or derivative lifecycle evidence."""
    connection = op.get_bind()
    for table in _TABLES:
        statement = sa.select(sa.exists(sa.select(1).select_from(sa.table(table))))
        if connection.execute(statement).scalar_one():
            message = "IDX-006 content-policy history prevents destructive downgrade"
            raise RuntimeError(message)
    for table in reversed(_TABLES):
        op.drop_table(table)
