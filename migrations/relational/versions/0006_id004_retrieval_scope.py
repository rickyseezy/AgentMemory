"""ID-004 scoped roles and revocation-sensitive grant versions.

Revision ID: 0006_id004_retrieval_scope
Revises: 0005_id003_repository_topology
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_id004_retrieval_scope"
down_revision = "0005_id003_repository_topology"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("scope_grants") as batch:
        batch.drop_constraint("uq_scope_grant", type_="unique")
        batch.drop_constraint("ck_scope_grant_role", type_="check")
        batch.add_column(sa.Column("project_id", sa.Text(), nullable=True))
        batch.add_column(sa.Column("repository_id", sa.Text(), nullable=True))
        batch.add_column(sa.Column("version", sa.Integer(), nullable=False, server_default="1"))
        batch.create_foreign_key(
            "fk_scope_grant_project",
            "projects",
            ["project_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_foreign_key(
            "fk_scope_grant_repository",
            "repositories",
            ["repository_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_unique_constraint(
            "uq_scope_grant",
            ["principal_id", "brain_id", "role", "project_id", "repository_id"],
        )
        batch.create_check_constraint(
            "ck_scope_grant_role",
            "role IN ('owner','admin','editor','reader','auditor','adapter','worker')",
        )
        batch.create_check_constraint(
            "ck_scope_grant_narrowing",
            "repository_id IS NULL OR project_id IS NOT NULL",
        )
        batch.create_check_constraint("ck_scope_grant_version", "version >= 1")
        batch.create_check_constraint(
            "ck_scope_grant_validity", "valid_to IS NULL OR valid_to > valid_from"
        )
    op.create_index(
        "ix_scope_grant_authorization",
        "scope_grants",
        ["brain_id", "principal_id", "valid_from", "valid_to"],
    )
    op.create_index(
        "ix_scope_grant_project",
        "scope_grants",
        ["brain_id", "project_id", "repository_id"],
    )


def downgrade() -> None:
    connection = op.get_bind()
    grant_references = connection.execute(
        sa.text(
            "SELECT (SELECT COUNT(*) FROM projection_rebuilds) + "
            "(SELECT COUNT(*) FROM repository_topology_link_history)"
        )
    ).scalar_one()
    if grant_references:
        msg = "ID-004 downgrade refused while canonical grant references exist"
        raise RuntimeError(msg)
    incompatible = connection.execute(
        sa.text(
            "SELECT COUNT(*) FROM scope_grants WHERE role != 'owner' "
            "OR project_id IS NOT NULL OR repository_id IS NOT NULL"
        )
    ).scalar_one()
    if incompatible:
        msg = "ID-004 downgrade refused while scoped or non-owner grants exist"
        raise RuntimeError(msg)
    op.drop_index("ix_scope_grant_project", table_name="scope_grants")
    op.drop_index("ix_scope_grant_authorization", table_name="scope_grants")
    with op.batch_alter_table("scope_grants") as batch:
        batch.drop_constraint("ck_scope_grant_validity", type_="check")
        batch.drop_constraint("ck_scope_grant_version", type_="check")
        batch.drop_constraint("ck_scope_grant_narrowing", type_="check")
        batch.drop_constraint("ck_scope_grant_role", type_="check")
        batch.drop_constraint("uq_scope_grant", type_="unique")
        batch.drop_constraint("fk_scope_grant_repository", type_="foreignkey")
        batch.drop_constraint("fk_scope_grant_project", type_="foreignkey")
        batch.drop_column("version")
        batch.drop_column("repository_id")
        batch.drop_column("project_id")
        batch.create_unique_constraint("uq_scope_grant", ["principal_id", "brain_id", "role"])
        batch.create_check_constraint("ck_scope_grant_role", "role IN ('owner')")
