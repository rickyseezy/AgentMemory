"""ID-001 stable Project, Repository, Checkout, and keyed alias state.

Revision ID: 0003_id001_workspace_identity
Revises: 0002_pf002_projection_rebuild
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_id001_workspace_identity"
down_revision = "0002_pf002_projection_rebuild"
branch_labels = None
depends_on = None


def _timestamps():
    return (
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
    )


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("device_fingerprint", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("status", sa.Text(), nullable=False),
        *_timestamps(),
        sa.CheckConstraint("length(device_fingerprint) = 32", name="ck_device_fingerprint"),
        sa.CheckConstraint(
            "status IN ('verified','unverified_changed')",
            name="ck_device_status",
        ),
    )
    op.create_table(
        "projects",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("manifest_key", sa.LargeBinary(32), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint("brain_id", "manifest_key", name="uq_project_manifest_key"),
        sa.CheckConstraint("length(manifest_key) = 32", name="ck_project_manifest_key"),
        sa.CheckConstraint("status IN ('active','archived')", name="ck_project_status"),
    )
    op.create_table(
        "repositories",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("vcs_type", sa.Text(), nullable=False),
        sa.Column("root_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("primary_remote_fingerprint", sa.LargeBinary(32), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint(
            "brain_id",
            "root_fingerprint",
            "primary_remote_fingerprint",
            name="uq_repository_canonical_evidence",
        ),
        sa.CheckConstraint("vcs_type IN ('git','none')", name="ck_repository_vcs_type"),
        sa.CheckConstraint("length(root_fingerprint) = 32", name="ck_repository_root"),
        sa.CheckConstraint(
            "primary_remote_fingerprint IS NULL OR length(primary_remote_fingerprint) = 32",
            name="ck_repository_remote",
        ),
        sa.CheckConstraint("status IN ('active','archived')", name="ck_repository_status"),
    )
    op.create_table(
        "repository_fingerprints",
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("algorithm", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("evidence_json", sa.Text(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("brain_id", "algorithm", "fingerprint"),
        sa.CheckConstraint("length(fingerprint) = 32", name="ck_repository_fingerprint"),
        sa.CheckConstraint("json_valid(evidence_json)", name="ck_repository_evidence_json"),
    )
    op.create_index(
        "ix_repository_fingerprint_lookup",
        "repository_fingerprints",
        ["brain_id", "fingerprint", "active"],
    )
    op.create_table(
        "project_repositories",
        sa.Column(
            "project_id",
            sa.Text(),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("relation_type", sa.Text(), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("project_id", "repository_id"),
        sa.CheckConstraint(
            "relation_type IN ('primary','component','dependency')",
            name="ck_project_repository_relation",
        ),
    )
    op.create_table(
        "checkouts",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "device_id",
            sa.Text(),
            sa.ForeignKey("devices.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("canonical_path_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("checkout_fingerprint", sa.LargeBinary(32), nullable=True),
        sa.Column("worktree_id", sa.LargeBinary(32), nullable=True),
        sa.Column("branch", sa.Text(), nullable=True),
        sa.Column("head_commit", sa.Text(), nullable=True),
        sa.Column("last_seen_at", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint(
            "brain_id", "device_id", "canonical_path_hash", name="uq_checkout_path"
        ),
        sa.CheckConstraint("length(canonical_path_hash) = 32", name="ck_checkout_path_hash"),
        sa.CheckConstraint(
            "checkout_fingerprint IS NULL OR length(checkout_fingerprint) = 32",
            name="ck_checkout_fingerprint",
        ),
        sa.CheckConstraint(
            "worktree_id IS NULL OR length(worktree_id) = 32",
            name="ck_checkout_worktree",
        ),
        sa.CheckConstraint("status IN ('active','missing','archived')", name="ck_checkout_status"),
    )
    op.create_index(
        "ix_checkout_fingerprint_lookup",
        "checkouts",
        ["brain_id", "checkout_fingerprint"],
    )
    op.create_table(
        "checkout_aliases",
        sa.Column(
            "checkout_id",
            sa.Text(),
            sa.ForeignKey("checkouts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("path_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("continuity_fingerprint", sa.LargeBinary(32), nullable=True),
        sa.Column("approved", sa.Boolean(), nullable=False),
        sa.Column("first_seen_at", sa.BigInteger(), nullable=False),
        sa.Column("last_seen_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("checkout_id", "path_fingerprint"),
        sa.CheckConstraint("length(path_fingerprint) = 32", name="ck_checkout_alias_path"),
        sa.CheckConstraint(
            "continuity_fingerprint IS NULL OR length(continuity_fingerprint) = 32",
            name="ck_checkout_alias_continuity",
        ),
    )
    op.create_index(
        "ix_checkout_alias_lookup",
        "checkout_aliases",
        ["brain_id", "path_fingerprint", "approved"],
    )


def downgrade() -> None:
    op.drop_index("ix_checkout_alias_lookup", table_name="checkout_aliases")
    op.drop_table("checkout_aliases")
    op.drop_index("ix_checkout_fingerprint_lookup", table_name="checkouts")
    op.drop_table("checkouts")
    op.drop_table("project_repositories")
    op.drop_index("ix_repository_fingerprint_lookup", table_name="repository_fingerprints")
    op.drop_table("repository_fingerprints")
    op.drop_table("repositories")
    op.drop_table("projects")
    op.drop_table("devices")
