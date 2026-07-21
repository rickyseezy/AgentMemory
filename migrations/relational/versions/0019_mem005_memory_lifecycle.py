"""MEM-005 root-memory lifecycle, expiry schedule, and deletion-saga handoff.

Revision ID: 0019_mem005_memory_lifecycle
Revises: 0018_mem004_memory_correction
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019_mem005_memory_lifecycle"
down_revision = "0018_mem004_memory_correction"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add a guarded lifecycle overlay without rewriting semantic memory history."""
    op.create_table(
        "memory_lifecycle",
        sa.Column(
            "memory_id",
            sa.Text(),
            sa.ForeignKey("memories.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("project_id", sa.Text(), nullable=False),
        sa.Column("repository_id", sa.Text(), nullable=False),
        sa.Column("checkout_id", sa.Text(), nullable=True),
        sa.Column("recall_state", sa.Text(), nullable=False),
        sa.Column("pinned", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expires_at", sa.BigInteger(), nullable=True),
        sa.Column("aggregate_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "recall_state IN ('active','archived','expired','forgotten')",
            name="ck_memory_lifecycle_state",
        ),
        sa.CheckConstraint("pinned IN (0,1)", name="ck_memory_lifecycle_pinned"),
        sa.CheckConstraint(
            "(recall_state='active' OR pinned=0) AND "
            "(recall_state<>'expired' OR expires_at IS NOT NULL) AND "
            "(recall_state<>'forgotten' OR expires_at IS NULL)",
            name="ck_memory_lifecycle_state_fields",
        ),
        sa.CheckConstraint("aggregate_version>=1", name="ck_memory_lifecycle_version"),
    )
    op.create_index(
        "ix_memory_lifecycle_recall",
        "memory_lifecycle",
        ["brain_id", "project_id", "repository_id", "checkout_id", "recall_state", "pinned"],
    )
    op.create_index(
        "ix_memory_lifecycle_expiry",
        "memory_lifecycle",
        ["recall_state", "expires_at", "memory_id"],
    )

    op.create_table(
        "memory_lifecycle_operations",
        sa.Column("idempotency_key", sa.LargeBinary(32), primary_key=True),
        sa.Column("operation_id", sa.Text(), nullable=False, unique=True),
        sa.Column("request_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("memory_id", sa.Text(), nullable=False),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("actor_id", sa.Text(), nullable=False),
        sa.Column("grant_id", sa.Text(), nullable=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("correlation_id", sa.Text(), nullable=False),
        sa.Column("causation_id", sa.Text(), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("result_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("requested_at", sa.BigInteger(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(["memory_id"], ["memories.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "action IN ('pin','archive','set_expiry','expire','forget')",
            name="ck_memory_lifecycle_operation_action",
        ),
        sa.CheckConstraint(
            "length(idempotency_key)=32 AND length(request_sha256)=32 "
            "AND length(result_sha256)=32 AND json_valid(result_json)",
            name="ck_memory_lifecycle_operation_integrity",
        ),
        sa.CheckConstraint(
            "requested_at<=completed_at AND (action='expire' OR grant_id IS NOT NULL)",
            name="ck_memory_lifecycle_operation_authority",
        ),
    )
    op.create_index(
        "ix_memory_lifecycle_operation_target",
        "memory_lifecycle_operations",
        ["brain_id", "memory_id", "completed_at"],
    )

    op.create_table(
        "memory_lifecycle_events",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column("memory_id", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("before_state", sa.Text(), nullable=False),
        sa.Column("after_state", sa.Text(), nullable=False),
        sa.Column("before_pinned", sa.Integer(), nullable=False),
        sa.Column("after_pinned", sa.Integer(), nullable=False),
        sa.Column("before_expires_at", sa.BigInteger(), nullable=True),
        sa.Column("after_expires_at", sa.BigInteger(), nullable=True),
        sa.Column("before_version", sa.Integer(), nullable=False),
        sa.Column("after_version", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("policy_version", sa.Text(), nullable=False),
        sa.Column("result_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["operation_id"],
            ["memory_lifecycle_operations.operation_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["memory_id"], ["memories.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "action IN ('pin','archive','set_expiry','expire','forget') "
            "AND before_state IN ('active','archived','expired') "
            "AND after_state IN ('active','archived','expired','forgotten')",
            name="ck_memory_lifecycle_event_states",
        ),
        sa.CheckConstraint(
            "before_pinned IN (0,1) AND after_pinned IN (0,1) "
            "AND after_version=before_version+1 AND length(result_sha256)=32",
            name="ck_memory_lifecycle_event_integrity",
        ),
    )
    op.create_index(
        "ix_memory_lifecycle_history",
        "memory_lifecycle_events",
        ["memory_id", "occurred_at", "operation_id"],
    )

    op.create_table(
        "memory_deletion_manifests",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column("memory_id", sa.Text(), nullable=False),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("tombstone_id", sa.Text(), nullable=False, unique=True),
        sa.Column("job_id", sa.Text(), nullable=False, unique=True),
        sa.Column("dependency_types_json", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["operation_id"],
            ["memory_lifecycle_operations.operation_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["memory_id"], ["memories.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tombstone_id"], ["deletion_tombstones.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"]),
        sa.CheckConstraint(
            "state IN ('tombstoned','purging','verification','completed','blocked') "
            "AND json_valid(dependency_types_json)",
            name="ck_memory_deletion_manifest",
        ),
    )
    op.create_table(
        "memory_deletion_targets",
        sa.Column("operation_id", sa.Text(), nullable=False),
        sa.Column("tombstone_id", sa.Text(), nullable=False, unique=True),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["operation_id"],
            ["memory_deletion_manifests.operation_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["tombstone_id"], ["deletion_tombstones.id"]),
        sa.PrimaryKeyConstraint(
            "operation_id",
            "target_type",
            "target_id_hash",
            name="pk_memory_deletion_targets",
        ),
        sa.CheckConstraint(
            "target_type IN ('memory','memory_assertion') AND length(target_id_hash)=32",
            name="ck_memory_deletion_target",
        ),
    )

    op.execute(
        "INSERT INTO memory_lifecycle "
        "(memory_id,brain_id,project_id,repository_id,checkout_id,recall_state,pinned,"
        "expires_at,aggregate_version,updated_at,schema_version) "
        "SELECT id,brain_id,project_id,repository_id,checkout_id,"
        "CASE WHEN status='active' THEN 'active' ELSE 'archived' END,0,NULL,1,updated_at,1 "
        "FROM memories"
    )
    op.execute(
        "CREATE TRIGGER memory_lifecycle_after_memory_insert AFTER INSERT ON memories BEGIN "
        "INSERT INTO memory_lifecycle "
        "(memory_id,brain_id,project_id,repository_id,checkout_id,recall_state,pinned,expires_at,"
        "aggregate_version,updated_at,schema_version) VALUES "
        "(NEW.id,NEW.brain_id,NEW.project_id,NEW.repository_id,NEW.checkout_id,'active',0,NULL,1,"
        "NEW.updated_at,1); END"
    )
    op.execute(
        "CREATE TRIGGER memory_lifecycle_identity_immutable "
        "BEFORE UPDATE OF memory_id,brain_id,project_id,repository_id,checkout_id,schema_version "
        "ON memory_lifecycle BEGIN "
        "SELECT RAISE(ABORT, 'memory lifecycle identity is immutable'); END"
    )
    op.execute(
        "CREATE TRIGGER memory_lifecycle_transition_guard BEFORE UPDATE ON memory_lifecycle BEGIN "
        "SELECT CASE WHEN NEW.aggregate_version<>OLD.aggregate_version+1 "
        "OR NEW.updated_at<OLD.updated_at "
        "OR NOT ((OLD.recall_state='active' AND NEW.recall_state IN "
        "('active','archived','expired','forgotten')) OR "
        "(OLD.recall_state='archived' AND NEW.recall_state IN "
        "('archived','expired','forgotten')) OR "
        "(OLD.recall_state='expired' AND NEW.recall_state='forgotten')) "
        "THEN RAISE(ABORT, 'invalid memory lifecycle transition') END; END"
    )
    op.execute(
        "CREATE TRIGGER memory_lifecycle_delete_forbidden BEFORE DELETE ON memory_lifecycle BEGIN "
        "SELECT RAISE(ABORT, 'memory lifecycle cannot be deleted'); END"
    )
    op.execute(
        "CREATE TRIGGER memory_lifecycle_operations_immutable BEFORE UPDATE "
        "ON memory_lifecycle_operations BEGIN "
        "SELECT RAISE(ABORT, 'memory lifecycle receipt is immutable'); END"
    )
    op.execute(
        "CREATE TRIGGER memory_lifecycle_events_immutable BEFORE UPDATE "
        "ON memory_lifecycle_events BEGIN "
        "SELECT RAISE(ABORT, 'memory lifecycle event is immutable'); END"
    )
    op.execute(
        "CREATE TRIGGER memory_deletion_manifest_guard BEFORE UPDATE "
        "ON memory_deletion_manifests BEGIN SELECT CASE WHEN "
        "NEW.operation_id<>OLD.operation_id OR NEW.memory_id<>OLD.memory_id "
        "OR NEW.brain_id<>OLD.brain_id OR NEW.tombstone_id<>OLD.tombstone_id "
        "OR NEW.job_id<>OLD.job_id OR NEW.dependency_types_json<>OLD.dependency_types_json "
        "OR NEW.created_at<>OLD.created_at OR NEW.schema_version<>OLD.schema_version "
        "OR NEW.updated_at<OLD.updated_at OR NOT ("
        "(OLD.state='tombstoned' AND NEW.state IN ('purging','blocked')) OR "
        "(OLD.state='purging' AND NEW.state IN ('verification','blocked')) OR "
        "(OLD.state='verification' AND NEW.state IN ('completed','blocked')) OR "
        "(OLD.state='blocked' AND NEW.state='purging')) "
        "THEN RAISE(ABORT, 'invalid memory deletion transition') END; END"
    )
    op.execute(
        "CREATE TRIGGER memory_deletion_targets_immutable BEFORE UPDATE "
        "ON memory_deletion_targets BEGIN "
        "SELECT RAISE(ABORT, 'memory deletion target is immutable'); END"
    )
    for table in (
        "memory_lifecycle_operations",
        "memory_lifecycle_events",
        "memory_deletion_manifests",
        "memory_deletion_targets",
    ):
        op.execute(
            f"CREATE TRIGGER {table}_delete_forbidden BEFORE DELETE ON {table} BEGIN "
            "SELECT RAISE(ABORT, 'memory lifecycle evidence cannot be deleted'); END"
        )


def downgrade() -> None:
    """Refuse downgrade after any lifecycle mutation or memory deletion handoff."""
    connection = op.get_bind()
    evidence = connection.execute(
        sa.text(
            "SELECT (SELECT COUNT(*) FROM memory_lifecycle_operations) + "
            "(SELECT COUNT(*) FROM memory_lifecycle_events) + "
            "(SELECT COUNT(*) FROM memory_deletion_manifests) + "
            "(SELECT COUNT(*) FROM memory_deletion_targets) + "
            "(SELECT COUNT(*) FROM memory_lifecycle WHERE aggregate_version>1 OR pinned<>0 "
            "OR expires_at IS NOT NULL OR recall_state IN ('expired','forgotten')) + "
            "(SELECT COUNT(*) FROM deletion_tombstones "
            "WHERE target_type IN ('memory','memory_assertion'))"
        )
    ).scalar_one()
    if evidence:
        message = "MEM-005 downgrade refused while lifecycle or deletion evidence exists"
        raise RuntimeError(message)

    op.execute("DROP TRIGGER memory_deletion_targets_delete_forbidden")
    op.execute("DROP TRIGGER memory_deletion_manifests_delete_forbidden")
    op.execute("DROP TRIGGER memory_lifecycle_events_delete_forbidden")
    op.execute("DROP TRIGGER memory_lifecycle_operations_delete_forbidden")
    op.execute("DROP TRIGGER memory_deletion_manifest_guard")
    op.execute("DROP TRIGGER memory_deletion_targets_immutable")
    op.execute("DROP TRIGGER memory_lifecycle_events_immutable")
    op.execute("DROP TRIGGER memory_lifecycle_operations_immutable")
    op.execute("DROP TRIGGER memory_lifecycle_delete_forbidden")
    op.execute("DROP TRIGGER memory_lifecycle_transition_guard")
    op.execute("DROP TRIGGER memory_lifecycle_identity_immutable")
    op.execute("DROP TRIGGER memory_lifecycle_after_memory_insert")
    op.drop_table("memory_deletion_targets")
    op.drop_table("memory_deletion_manifests")
    op.drop_index("ix_memory_lifecycle_history", table_name="memory_lifecycle_events")
    op.drop_table("memory_lifecycle_events")
    op.drop_index("ix_memory_lifecycle_operation_target", table_name="memory_lifecycle_operations")
    op.drop_table("memory_lifecycle_operations")
    op.drop_index("ix_memory_lifecycle_expiry", table_name="memory_lifecycle")
    op.drop_index("ix_memory_lifecycle_recall", table_name="memory_lifecycle")
    op.drop_table("memory_lifecycle")
