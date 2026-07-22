"""PF-005 append-only MCP session credentials and lifecycle snapshots.

Revision ID: 0035_pf005_mcp_sessions
Revises: 0034_pf003_adapter_extensions
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0035_pf005_mcp_sessions"
down_revision = "0034_pf003_adapter_extensions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Install immutable hash-only credential authority and lifecycle snapshots."""
    op.create_table(
        "mcp_session_credentials",
        sa.Column("session_id", sa.Text(), primary_key=True),
        sa.Column("installation_id", sa.Text(), nullable=False),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("actor_id", sa.Text(), nullable=False),
        sa.Column("grant_id", sa.Text(), nullable=False),
        sa.Column("agent_id", sa.Text(), nullable=False),
        sa.Column("workspace_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("device_identity", sa.Text(), nullable=False),
        sa.Column("git_repository_id", sa.Text(), nullable=True),
        sa.Column("git_worktree_id", sa.Text(), nullable=True),
        sa.Column("git_coverage", sa.Text(), nullable=False),
        sa.Column("project_id", sa.Text(), nullable=True),
        sa.Column("repository_id", sa.Text(), nullable=True),
        sa.Column("checkout_id", sa.Text(), nullable=True),
        sa.Column("security_epoch", sa.Text(), nullable=False),
        sa.Column("credential_digest", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("issued_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("registration_digest", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["installation_id"], ["installation_state.installation_id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["brain_id"], ["brains.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["actor_id"], ["principals.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["grant_id"], ["scope_grants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["repository_id"], ["repositories.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["checkout_id"], ["checkouts.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "length(workspace_fingerprint)=32 AND length(credential_digest)=32 "
            "AND length(registration_digest)=32",
            name="ck_mcp_session_credential_digests",
        ),
        sa.CheckConstraint(
            "issued_at>=0 AND expires_at>issued_at AND expires_at-issued_at<=43200000000",
            name="ck_mcp_session_credential_lifetime",
        ),
        sa.CheckConstraint(
            "length(device_identity) BETWEEN 1 AND 512 AND "
            "git_coverage IN ('none','partial','complete') AND "
            "((git_coverage='none' AND git_repository_id IS NULL AND git_worktree_id IS NULL) "
            "OR (git_coverage IN ('partial','complete') AND git_repository_id IS NOT NULL "
            "AND git_worktree_id IS NOT NULL AND length(git_repository_id) BETWEEN 1 AND 512 "
            "AND length(git_worktree_id) BETWEEN 1 AND 512))",
            name="ck_mcp_session_workspace_identity",
        ),
        sa.CheckConstraint(
            "(project_id IS NULL)=(repository_id IS NULL) AND "
            "(checkout_id IS NULL OR repository_id IS NOT NULL)",
            name="ck_mcp_session_canonical_scope",
        ),
    )
    op.create_table(
        "mcp_session_snapshots",
        sa.Column("session_id", sa.Text(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("lease_expires_at", sa.BigInteger(), nullable=True),
        sa.Column("revoked_at", sa.BigInteger(), nullable=True),
        sa.Column("finished_at", sa.BigInteger(), nullable=True),
        sa.Column("record_json", sa.Text(), nullable=False),
        sa.Column("previous_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("record_digest", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["session_id"], ["mcp_session_credentials.session_id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("session_id", "revision"),
        sa.CheckConstraint("revision>=0", name="ck_mcp_session_snapshot_revision"),
        sa.CheckConstraint(
            "state IN ('registered','active','completed','interrupted')",
            name="ck_mcp_session_snapshot_state",
        ),
        sa.CheckConstraint(
            "event_type IN ('registered','began','heartbeat','revoked','completed',"
            "'interrupted','expired')",
            name="ck_mcp_session_snapshot_event",
        ),
        sa.CheckConstraint(
            "length(previous_digest)=32 AND length(record_digest)=32",
            name="ck_mcp_session_snapshot_digests",
        ),
    )
    op.create_index(
        "ix_mcp_session_expiry",
        "mcp_session_snapshots",
        ["state", "lease_expires_at", "session_id", "revision"],
    )
    op.create_table(
        "mcp_workspace_checkpoint_batches",
        sa.Column("batch_digest", sa.LargeBinary(32), primary_key=True),
        sa.Column("batch_sequence", sa.Integer(), nullable=False, unique=True),
        sa.Column("session_id", sa.Text(), nullable=False),
        sa.Column("workspace_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("partial", sa.Integer(), nullable=False),
        sa.Column("change_count", sa.Integer(), nullable=False),
        sa.Column("algorithm", sa.Text(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(12), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("aad_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("canonical_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["session_id"], ["mcp_session_credentials.session_id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint("partial IN (0,1)", name="ck_mcp_workspace_checkpoint_partial"),
        sa.CheckConstraint("batch_sequence>=1", name="ck_mcp_workspace_checkpoint_sequence"),
        sa.CheckConstraint(
            "change_count>=0 AND change_count<=10000",
            name="ck_mcp_workspace_checkpoint_change_count",
        ),
        sa.CheckConstraint(
            "algorithm='AES-256-GCM' AND length(nonce)=12 AND length(ciphertext)>=16",
            name="ck_mcp_workspace_checkpoint_envelope",
        ),
        sa.CheckConstraint(
            "length(batch_digest)=32 AND length(workspace_fingerprint)=32 "
            "AND length(aad_sha256)=32 AND length(canonical_sha256)=32",
            name="ck_mcp_workspace_checkpoint_digests",
        ),
        sa.CheckConstraint("state='pending'", name="ck_mcp_workspace_checkpoint_state"),
    )
    op.create_index(
        "ix_mcp_workspace_checkpoint_pending",
        "mcp_workspace_checkpoint_batches",
        ["state", "batch_sequence"],
    )
    op.create_table(
        "mcp_workspace_checkpoint_receipts",
        sa.Column("batch_digest", sa.LargeBinary(32), primary_key=True),
        sa.Column("result_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["batch_digest"],
            ["mcp_workspace_checkpoint_batches.batch_digest"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(batch_digest)=32 AND length(result_sha256)=32",
            name="ck_mcp_workspace_checkpoint_receipt_digests",
        ),
        sa.CheckConstraint(
            "event_count>=0 AND event_count<=10000 AND completed_at>=0",
            name="ck_mcp_workspace_checkpoint_receipt_result",
        ),
    )
    op.create_table(
        "mcp_workspace_checkpoint_changes",
        sa.Column("batch_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("change_id", sa.Text(), nullable=False, unique=True),
        sa.Column("event_id", sa.Text(), nullable=False, unique=True),
        sa.Column("session_id", sa.Text(), nullable=False),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("project_id", sa.Text(), nullable=False),
        sa.Column("repository_id", sa.Text(), nullable=False),
        sa.Column("checkout_id", sa.Text(), nullable=True),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.Column("relative_path_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("source_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("preparation_sha256", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("disposition", sa.Text(), nullable=False),
        sa.Column("deleted", sa.Integer(), nullable=False),
        sa.Column("partial", sa.Integer(), nullable=False),
        sa.Column("classification", sa.Text(), nullable=True),
        sa.Column("policy_result_json", sa.Text(), nullable=True),
        sa.Column("encryption_key_ref", sa.Text(), nullable=True),
        sa.Column("algorithm", sa.Text(), nullable=True),
        sa.Column("nonce", sa.LargeBinary(12), nullable=True),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("aad_sha256", sa.LargeBinary(32), nullable=True),
        sa.Column("sanitized_sha256", sa.LargeBinary(32), nullable=True),
        sa.Column("sanitized_size", sa.BigInteger(), nullable=True),
        sa.Column("rejection_code", sa.Text(), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["batch_digest"],
            ["mcp_workspace_checkpoint_batches.batch_digest"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["session_id"], ["mcp_session_credentials.session_id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["brain_id"], ["brains.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["repository_id"], ["repositories.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["checkout_id"], ["checkouts.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("batch_digest", "ordinal"),
        sa.CheckConstraint("ordinal>=0 AND ordinal<10000", name="ck_mcp_change_ordinal"),
        sa.CheckConstraint(
            "length(relative_path) BETWEEN 1 AND 4096 AND "
            "length(relative_path_sha256)=32 AND length(source_sha256)=32 AND "
            "length(preparation_sha256)=32",
            name="ck_mcp_change_identity",
        ),
        sa.CheckConstraint(
            "disposition IN ('event','excluded','rejected') AND deleted IN (0,1) "
            "AND partial IN (0,1)",
            name="ck_mcp_change_state",
        ),
        sa.CheckConstraint(
            "(disposition='event' AND classification IS NOT NULL AND "
            "policy_result_json IS NOT NULL AND encryption_key_ref IS NOT NULL AND "
            "algorithm='AES-256-GCM' AND length(nonce)=12 AND length(ciphertext)>=16 AND "
            "length(aad_sha256)=32 AND length(sanitized_sha256)=32 AND sanitized_size>=1 "
            "AND rejection_code IS NULL) OR "
            "(disposition='excluded' AND classification='local_only' AND "
            "policy_result_json IS NOT NULL AND encryption_key_ref IS NULL AND "
            "algorithm IS NULL AND nonce IS NULL AND ciphertext IS NULL AND "
            "aad_sha256 IS NULL AND sanitized_sha256 IS NULL AND sanitized_size IS NULL "
            "AND rejection_code IS NULL) OR "
            "(disposition='rejected' AND classification IS NULL AND "
            "policy_result_json IS NULL AND encryption_key_ref IS NULL AND "
            "algorithm IS NULL AND nonce IS NULL AND ciphertext IS NULL AND "
            "aad_sha256 IS NULL AND sanitized_sha256 IS NULL AND sanitized_size IS NULL "
            "AND rejection_code IS NOT NULL)",
            name="ck_mcp_change_payload_shape",
        ),
    )
    op.create_index(
        "ix_mcp_workspace_change_scope",
        "mcp_workspace_checkpoint_changes",
        ["brain_id", "project_id", "repository_id", "created_at", "change_id"],
    )
    for table in (
        "mcp_session_credentials",
        "mcp_session_snapshots",
        "mcp_workspace_checkpoint_batches",
        "mcp_workspace_checkpoint_changes",
        "mcp_workspace_checkpoint_receipts",
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
    """Refuse to erase session security evidence after first use."""
    connection = op.get_bind()
    credentials_exist = connection.execute(
        sa.text("SELECT EXISTS(SELECT 1 FROM mcp_session_credentials)")
    ).scalar_one()
    snapshots_exist = connection.execute(
        sa.text("SELECT EXISTS(SELECT 1 FROM mcp_session_snapshots)")
    ).scalar_one()
    checkpoints_exist = connection.execute(
        sa.text("SELECT EXISTS(SELECT 1 FROM mcp_workspace_checkpoint_batches)")
    ).scalar_one()
    receipts_exist = connection.execute(
        sa.text("SELECT EXISTS(SELECT 1 FROM mcp_workspace_checkpoint_receipts)")
    ).scalar_one()
    changes_exist = connection.execute(
        sa.text("SELECT EXISTS(SELECT 1 FROM mcp_workspace_checkpoint_changes)")
    ).scalar_one()
    if credentials_exist or snapshots_exist or checkpoints_exist or receipts_exist or changes_exist:
        message = "PF-005 MCP session history prevents destructive downgrade"
        raise RuntimeError(message)
    op.drop_index("ix_mcp_session_expiry", table_name="mcp_session_snapshots")
    op.drop_index(
        "ix_mcp_workspace_checkpoint_pending",
        table_name="mcp_workspace_checkpoint_batches",
    )
    op.drop_table("mcp_workspace_checkpoint_receipts")
    op.drop_index(
        "ix_mcp_workspace_change_scope",
        table_name="mcp_workspace_checkpoint_changes",
    )
    op.drop_table("mcp_workspace_checkpoint_changes")
    op.drop_table("mcp_workspace_checkpoint_batches")
    op.drop_table("mcp_session_snapshots")
    op.drop_table("mcp_session_credentials")
