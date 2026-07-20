"""ID-003 governed repository topology links and correction history.

Revision ID: 0005_id003_repository_topology
Revises: 0004_id002_checkout_observation
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_id003_repository_topology"
down_revision = "0004_id002_checkout_observation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repository_topology_links",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("subject_type", sa.Text(), nullable=False),
        sa.Column("subject_id", sa.Text(), nullable=False),
        sa.Column("relation_type", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("component_root_fingerprint", sa.LargeBinary(32), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("valid_from", sa.BigInteger(), nullable=False),
        sa.Column("valid_to", sa.BigInteger(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "subject_type IN ('project','repository') AND target_type IN ('project','repository')",
            name="ck_topology_link_endpoint_types",
        ),
        sa.CheckConstraint(
            "relation_type IN ('contains_repository','submodule_of','fork_of',"
            "'project_uses_repository')",
            name="ck_topology_link_relation",
        ),
        sa.CheckConstraint(
            "((relation_type = 'project_uses_repository' AND subject_type = 'project' "
            "AND target_type = 'repository') OR "
            "(relation_type != 'project_uses_repository' AND subject_type = 'repository' "
            "AND target_type = 'repository' AND subject_id != target_id))",
            name="ck_topology_link_shape",
        ),
        sa.CheckConstraint(
            "(relation_type = 'project_uses_repository') OR component_root_fingerprint IS NULL",
            name="ck_topology_link_component_scope",
        ),
        sa.CheckConstraint(
            "component_root_fingerprint IS NULL OR length(component_root_fingerprint) = 32",
            name="ck_topology_link_component_fingerprint",
        ),
        sa.CheckConstraint("status IN ('active','revoked')", name="ck_topology_link_status"),
        sa.CheckConstraint("version >= 1", name="ck_topology_link_version"),
        sa.CheckConstraint(
            "valid_to IS NULL OR valid_to > valid_from",
            name="ck_topology_link_validity",
        ),
    )
    op.create_index(
        "uq_topology_link_active_endpoints",
        "repository_topology_links",
        ["brain_id", "subject_type", "subject_id", "target_type", "target_id"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
    )
    op.create_index(
        "ix_topology_link_subject",
        "repository_topology_links",
        ["brain_id", "subject_type", "subject_id", "status"],
    )
    op.create_index(
        "ix_topology_link_target",
        "repository_topology_links",
        ["brain_id", "target_type", "target_id", "status"],
    )
    op.create_table(
        "repository_topology_link_history",
        sa.Column(
            "link_id",
            sa.Text(),
            sa.ForeignKey("repository_topology_links.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("operation_id", sa.Text(), nullable=False),
        sa.Column("request_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("event_id", sa.Text(), nullable=False, unique=True),
        sa.Column("subject_type", sa.Text(), nullable=False),
        sa.Column("subject_id", sa.Text(), nullable=False),
        sa.Column("relation_type", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("component_root_fingerprint", sa.LargeBinary(32), nullable=True),
        sa.Column("evidence_json", sa.Text(), nullable=False),
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
        sa.Column("confirmation_source", sa.Text(), nullable=False),
        sa.Column("correction_reason", sa.Text(), nullable=True),
        sa.Column("effective_at", sa.BigInteger(), nullable=False),
        sa.Column("recorded_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("link_id", "version"),
        sa.UniqueConstraint("brain_id", "operation_id", name="uq_topology_operation"),
        sa.CheckConstraint("version >= 1", name="ck_topology_history_version"),
        sa.CheckConstraint("length(request_digest) = 32", name="ck_topology_request_digest"),
        sa.CheckConstraint(
            "json_valid(evidence_json) AND json_type(evidence_json) = 'array' "
            "AND json_array_length(evidence_json) BETWEEN 1 AND 32",
            name="ck_topology_evidence_json",
        ),
        sa.CheckConstraint(
            "subject_type IN ('project','repository') AND target_type = 'repository'",
            name="ck_topology_history_endpoint_types",
        ),
        sa.CheckConstraint(
            "relation_type IN ('contains_repository','submodule_of','fork_of',"
            "'project_uses_repository')",
            name="ck_topology_history_relation",
        ),
        sa.CheckConstraint(
            "((relation_type = 'project_uses_repository' AND subject_type = 'project') OR "
            "(relation_type != 'project_uses_repository' AND subject_type = 'repository' "
            "AND subject_id != target_id))",
            name="ck_topology_history_shape",
        ),
        sa.CheckConstraint(
            "(relation_type = 'project_uses_repository') OR component_root_fingerprint IS NULL",
            name="ck_topology_history_component_scope",
        ),
        sa.CheckConstraint(
            "length(operation_id) BETWEEN 1 AND 128 AND effective_at >= 1",
            name="ck_topology_history_operation",
        ),
        sa.CheckConstraint(
            "confirmation_source IN ('deterministic_vcs','deterministic_manifest','user')",
            name="ck_topology_confirmation_source",
        ),
        sa.CheckConstraint(
            "component_root_fingerprint IS NULL OR length(component_root_fingerprint) = 32",
            name="ck_topology_history_component_fingerprint",
        ),
    )
    op.create_index(
        "ix_topology_history_operation",
        "repository_topology_link_history",
        ["brain_id", "operation_id"],
    )
    op.execute(
        "CREATE TRIGGER repository_topology_history_no_update "
        "BEFORE UPDATE ON repository_topology_link_history BEGIN "
        "SELECT RAISE(ABORT, 'repository topology history is append-only'); END"
    )
    op.execute(
        "CREATE TRIGGER repository_topology_history_no_delete "
        "BEFORE DELETE ON repository_topology_link_history BEGIN "
        "SELECT RAISE(ABORT, 'repository topology history is append-only'); END"
    )


def downgrade() -> None:
    connection = op.get_bind()
    link_count = connection.execute(
        sa.text("SELECT COUNT(*) FROM repository_topology_links")
    ).scalar_one()
    if link_count:
        msg = "ID-003 downgrade refused while canonical repository links exist"
        raise RuntimeError(msg)
    op.execute("DROP TRIGGER repository_topology_history_no_delete")
    op.execute("DROP TRIGGER repository_topology_history_no_update")
    op.drop_index(
        "ix_topology_history_operation",
        table_name="repository_topology_link_history",
    )
    op.drop_table("repository_topology_link_history")
    op.drop_index("ix_topology_link_target", table_name="repository_topology_links")
    op.drop_index("ix_topology_link_subject", table_name="repository_topology_links")
    op.drop_index("uq_topology_link_active_endpoints", table_name="repository_topology_links")
    op.drop_table("repository_topology_links")
