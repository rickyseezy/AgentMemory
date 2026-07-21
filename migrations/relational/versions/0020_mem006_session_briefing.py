"""MEM-006 content-free session briefing receipts and ContextInjected events.

Revision ID: 0020_mem006_session_briefing
Revises: 0019_mem005_memory_lifecycle
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020_mem006_session_briefing"
down_revision = "0019_mem005_memory_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Install immutable request, selection, budget, and event evidence."""
    op.create_table(
        "session_briefing_receipts",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column(
            "event_id",
            sa.Text(),
            sa.ForeignKey("domain_events.event_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "principal_id",
            sa.Text(),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("request_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("selected_json", sa.Text(), nullable=False),
        sa.Column("event_sha256", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("budget_json", sa.Text(), nullable=False),
        sa.Column("used_tokens", sa.Integer(), nullable=False),
        sa.Column("used_items", sa.Integer(), nullable=False),
        sa.Column("used_bytes", sa.Integer(), nullable=False),
        sa.Column("truncated", sa.Boolean(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("policy_version", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(scope_fingerprint)=32 AND length(request_sha256)=32 "
            "AND length(event_sha256)=32",
            name="ck_session_briefing_digests",
        ),
        sa.CheckConstraint(
            "json_valid(selected_json) AND json_type(selected_json)='array' "
            "AND json_valid(budget_json) AND json_type(budget_json)='object'",
            name="ck_session_briefing_json",
        ),
        sa.CheckConstraint(
            "used_tokens>=0 AND used_items>=0 AND used_bytes>=0",
            name="ck_session_briefing_usage",
        ),
        sa.CheckConstraint(
            "status IN ('ready','no_answer')",
            name="ck_session_briefing_status",
        ),
        sa.CheckConstraint(
            "policy_version='session-briefing.v1'",
            name="ck_session_briefing_policy",
        ),
    )
    op.create_index(
        "ix_session_briefing_scope_time",
        "session_briefing_receipts",
        ["brain_id", "principal_id", "occurred_at", "operation_id"],
    )
    op.execute(
        "CREATE TRIGGER session_briefing_receipts_no_update "
        "BEFORE UPDATE ON session_briefing_receipts BEGIN "
        "SELECT RAISE(ABORT, 'session briefing receipts are immutable'); END"
    )
    op.execute(
        "CREATE TRIGGER session_briefing_receipts_no_delete "
        "BEFORE DELETE ON session_briefing_receipts BEGIN "
        "SELECT RAISE(ABORT, 'session briefing receipts are immutable'); END"
    )
    op.execute(
        "CREATE TRIGGER domain_events_no_update "
        "BEFORE UPDATE ON domain_events WHEN OLD.event_type='ContextInjected' BEGIN "
        "SELECT RAISE(ABORT, 'ContextInjected events are immutable'); END"
    )
    op.execute(
        "CREATE TRIGGER domain_events_no_delete "
        "BEFORE DELETE ON domain_events WHEN OLD.event_type='ContextInjected' BEGIN "
        "SELECT RAISE(ABORT, 'ContextInjected events are immutable'); END"
    )


def downgrade() -> None:
    """Refuse rollback after any MEM-006 event exists."""
    connection = op.get_bind()
    count = connection.execute(
        sa.text("SELECT COUNT(*) FROM session_briefing_receipts")
    ).scalar_one()
    if count:
        msg = "MEM-006 downgrade refused while session briefing evidence exists"
        raise RuntimeError(msg)
    op.execute("DROP TRIGGER domain_events_no_delete")
    op.execute("DROP TRIGGER domain_events_no_update")
    op.execute("DROP TRIGGER session_briefing_receipts_no_delete")
    op.execute("DROP TRIGGER session_briefing_receipts_no_update")
    op.drop_index("ix_session_briefing_scope_time", table_name="session_briefing_receipts")
    op.drop_table("session_briefing_receipts")
