"""ING-004 priority scheduling, capacity alerts, and immutable dead letters.

Revision ID: 0012_ing004_backpressure_dlq
Revises: 0011_ing003_ordered_replay
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0012_ing004_backpressure_dlq"
down_revision = "0011_ing003_ordered_replay"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("jobs") as batch:
        batch.drop_constraint("ck_jobs_completion_shape", type_="check")
        batch.drop_constraint("ck_jobs_state", type_="check")
        batch.add_column(
            sa.Column("priority_class", sa.Text(), nullable=False, server_default="standard")
        )
        batch.add_column(sa.Column("last_error_code", sa.Text(), nullable=True))
        batch.add_column(sa.Column("parent_job_id", sa.Text(), nullable=True))
        batch.create_foreign_key(
            "fk_jobs_parent_job", "jobs", ["parent_job_id"], ["id"], ondelete="RESTRICT"
        )
    op.execute("UPDATE jobs SET last_error_code='internal_error' WHERE state='retry_scheduled'")
    with op.batch_alter_table("jobs") as batch:
        batch.create_check_constraint(
            "ck_jobs_state",
            "state IN ('queued','leased','retry_scheduled','succeeded','dead_lettered')",
        )
        batch.create_check_constraint(
            "ck_jobs_priority",
            "priority_class IN ('interactive','capture','standard','background')",
        )
        batch.create_check_constraint(
            "ck_jobs_lease_shape",
            "(state='leased' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL) OR "
            "(state<>'leased' AND lease_owner IS NULL AND lease_until IS NULL)",
        )
        batch.create_check_constraint(
            "ck_jobs_completion_shape",
            "(state='succeeded' AND result_sha256 IS NOT NULL AND completed_at IS NOT NULL) OR "
            "(state<>'succeeded' AND result_sha256 IS NULL AND completed_at IS NULL)",
        )
        batch.create_check_constraint(
            "ck_jobs_failure_shape",
            "(state IN ('retry_scheduled','dead_lettered') AND last_error_code IS NOT NULL) OR "
            "(state NOT IN ('retry_scheduled','dead_lettered') AND last_error_code IS NULL)",
        )
        batch.create_check_constraint(
            "ck_jobs_error_code",
            "last_error_code IS NULL OR last_error_code IN "
            "('invalid_input','authorization_denied','integrity_violation','poison_job',"
            "'rate_limited','capacity_exhausted','dependency_unavailable',"
            "'transient_storage','internal_error')",
        )
        batch.create_check_constraint("ck_jobs_attempts", "attempts >= 0")
        batch.create_check_constraint("ck_jobs_next_attempt", "next_attempt_at >= 0")
        batch.create_check_constraint(
            "ck_jobs_parent", "parent_job_id IS NULL OR parent_job_id <> id"
        )
    op.create_index(
        "ix_jobs_priority_dispatch",
        "jobs",
        ["priority_class", "state", "next_attempt_at", "created_at", "id"],
    )
    op.create_index("ix_jobs_parent", "jobs", ["parent_job_id"])

    op.create_table(
        "job_authorizations",
        sa.Column(
            "job_id", sa.Text(), sa.ForeignKey("jobs.id", ondelete="RESTRICT"), primary_key=True
        ),
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
        sa.Column("input_ref", sa.Text(), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "input_ref IS NULL OR input_ref GLOB 'artifact://*' OR "
            "input_ref GLOB 'cas://*' OR input_ref GLOB 'local-object://*'",
            name="ck_job_authorization_input_ref",
        ),
    )

    op.create_table(
        "dead_letters",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "original_job_id",
            sa.Text(),
            sa.ForeignKey("jobs.id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("priority_class", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("request_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("error_code", sa.Text(), nullable=False),
        sa.Column("diagnostic_code", sa.Text(), nullable=False),
        sa.Column("failed_at", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "priority_class IN ('interactive','capture','standard','background')",
            name="ck_dead_letter_priority",
        ),
        sa.CheckConstraint("length(request_sha256)=32", name="ck_dead_letter_request_digest"),
        sa.CheckConstraint("attempts >= 1", name="ck_dead_letter_attempts"),
        sa.CheckConstraint(
            "error_code IN ('invalid_input','authorization_denied','integrity_violation',"
            "'poison_job','rate_limited','capacity_exhausted','dependency_unavailable',"
            "'transient_storage','internal_error')",
            name="ck_dead_letter_error_code",
        ),
        sa.CheckConstraint(
            "length(diagnostic_code) BETWEEN 1 AND 64 AND diagnostic_code NOT GLOB '*[^a-z0-9_]*'",
            name="ck_dead_letter_diagnostic",
        ),
    )
    op.create_index(
        "ix_dead_letters_brain_created", "dead_letters", ["brain_id", "created_at", "id"]
    )

    op.create_table(
        "dead_letter_replays",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column(
            "dead_letter_id",
            sa.Text(),
            sa.ForeignKey("dead_letters.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "new_job_id",
            sa.Text(),
            sa.ForeignKey("jobs.id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
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
        sa.Column("request_sha256", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("length(request_sha256)=32", name="ck_dead_letter_replay_digest"),
    )

    op.create_table(
        "scheduler_state",
        sa.Column("singleton_id", sa.Integer(), primary_key=True),
        sa.Column("dispatch_cursor", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("singleton_id=1", name="ck_scheduler_state_singleton"),
        sa.CheckConstraint("dispatch_cursor >= 0", name="ck_scheduler_dispatch_cursor"),
    )
    op.execute(
        "INSERT INTO scheduler_state (singleton_id,dispatch_cursor,updated_at,schema_version) "
        "VALUES (1,0,0,1)"
    )

    op.create_table(
        "scheduler_alerts",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("metric", sa.Text(), nullable=False),
        sa.Column("threshold_percent", sa.Integer(), nullable=False),
        sa.Column("observed_value", sa.BigInteger(), nullable=False),
        sa.Column("observed_limit", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("metric", "threshold_percent", name="uq_scheduler_alert_threshold"),
        sa.CheckConstraint(
            "metric IN ('queue_pending','disk_free','dead_letter_count')",
            name="ck_scheduler_alert_metric",
        ),
        sa.CheckConstraint(
            "threshold_percent BETWEEN 1 AND 100", name="ck_scheduler_alert_threshold"
        ),
        sa.CheckConstraint(
            "observed_value >= 0 AND observed_limit >= 0", name="ck_scheduler_alert_values"
        ),
    )


def downgrade() -> None:
    connection = op.get_bind()
    evidence = connection.execute(
        sa.text(
            "SELECT (SELECT COUNT(*) FROM job_authorizations) + "
            "(SELECT COUNT(*) FROM dead_letters) + "
            "(SELECT COUNT(*) FROM dead_letter_replays) + "
            "(SELECT COUNT(*) FROM scheduler_alerts) + "
            "(SELECT COUNT(*) FROM jobs WHERE priority_class<>'standard' "
            "OR parent_job_id IS NOT NULL OR state='dead_lettered')"
        )
    ).scalar_one()
    if evidence:
        msg = "ING-004 downgrade refused while scheduler or dead-letter evidence exists"
        raise RuntimeError(msg)
    op.drop_table("scheduler_alerts")
    op.drop_table("scheduler_state")
    op.drop_table("dead_letter_replays")
    op.drop_index("ix_dead_letters_brain_created", table_name="dead_letters")
    op.drop_table("dead_letters")
    op.drop_table("job_authorizations")
    op.drop_index("ix_jobs_parent", table_name="jobs")
    op.drop_index("ix_jobs_priority_dispatch", table_name="jobs")
    with op.batch_alter_table("jobs") as batch:
        batch.drop_constraint("ck_jobs_parent", type_="check")
        batch.drop_constraint("ck_jobs_next_attempt", type_="check")
        batch.drop_constraint("ck_jobs_attempts", type_="check")
        batch.drop_constraint("ck_jobs_error_code", type_="check")
        batch.drop_constraint("ck_jobs_failure_shape", type_="check")
        batch.drop_constraint("ck_jobs_completion_shape", type_="check")
        batch.drop_constraint("ck_jobs_lease_shape", type_="check")
        batch.drop_constraint("ck_jobs_priority", type_="check")
        batch.drop_constraint("ck_jobs_state", type_="check")
        batch.drop_constraint("fk_jobs_parent_job", type_="foreignkey")
        batch.drop_column("parent_job_id")
        batch.drop_column("last_error_code")
        batch.drop_column("priority_class")
        batch.create_check_constraint(
            "ck_jobs_state", "state IN ('queued','leased','retry_scheduled','succeeded')"
        )
        batch.create_check_constraint(
            "ck_jobs_completion_shape",
            "(state='succeeded' AND result_sha256 IS NOT NULL AND completed_at IS NOT NULL) OR "
            "(state<>'succeeded' AND result_sha256 IS NULL AND completed_at IS NULL)",
        )
