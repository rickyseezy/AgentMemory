"""PRO-008 resumable live embedding-generation migration authority.

Revision ID: 0041_pro008_embedding_migrations
Revises: 0040_pro007_provider_resilience
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0041_pro008_embedding_migrations"
down_revision = "0040_pro007_provider_resilience"
branch_labels = None
depends_on = None

_STATES = (
    "'planned','building','backfilling','dual_write','catching_up','validating',"
    "'shadowing','ready','paused','active','rolled_back','failed'"
)
_PURPOSES = (
    "'retrieval_query','retrieval_document','code_query','code_document',"
    "'semantic_similarity','classification','clustering'"
)


def upgrade() -> None:
    """Install migration snapshots, active pointers, dual-write routes, and evidence."""
    op.create_table(
        "embedding_generation_migrations",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "source_space_id",
            sa.Text(),
            sa.ForeignKey("embedding_spaces.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "source_generation_id",
            sa.Text(),
            sa.ForeignKey("embedding_index_generations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("source_space_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column(
            "target_space_id",
            sa.Text(),
            sa.ForeignKey("embedding_spaces.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "target_generation_id",
            sa.Text(),
            sa.ForeignKey("embedding_index_generations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("target_space_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("source_watermark", sa.BigInteger(), nullable=False),
        sa.Column("backfill_cursor", sa.BigInteger(), nullable=False),
        sa.Column("catchup_watermark", sa.BigInteger(), nullable=False),
        sa.Column("catchup_cursor", sa.BigInteger(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("resume_state", sa.Text(), nullable=True),
        sa.Column("validation_digest", sa.LargeBinary(32), nullable=True),
        sa.Column("rollback_until", sa.BigInteger(), nullable=True),
        sa.Column("source_retired_at", sa.BigInteger(), nullable=True),
        sa.Column("source_deleted_at", sa.BigInteger(), nullable=True),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "target_generation_id",
            name="uq_embedding_migration_target_generation",
        ),
        sa.CheckConstraint(
            "source_space_id<>target_space_id "
            "AND source_generation_id<>target_generation_id "
            "AND length(source_space_fingerprint)=32 "
            "AND length(target_space_fingerprint)=32 "
            "AND source_watermark>=0 "
            "AND backfill_cursor BETWEEN 0 AND source_watermark "
            "AND catchup_watermark>=source_watermark "
            "AND catchup_cursor BETWEEN backfill_cursor AND catchup_watermark "
            f"AND state IN ({_STATES}) "
            f"AND (resume_state IS NULL OR resume_state IN ({_STATES})) "
            "AND ((state='paused' AND resume_state IS NOT NULL "
            "AND resume_state NOT IN ('paused','active','rolled_back','failed')) "
            "OR (state<>'paused' AND resume_state IS NULL)) "
            "AND (validation_digest IS NULL OR length(validation_digest)=32) "
            "AND ((state IN ('ready','active','rolled_back') "
            "OR (state='paused' AND resume_state='ready')) "
            "= (validation_digest IS NOT NULL)) "
            "AND (rollback_until IS NULL OR rollback_until>=0) "
            "AND ((state IN ('active','rolled_back')) "
            "= (rollback_until IS NOT NULL)) "
            "AND (source_retired_at IS NULL OR "
            "(state='active' AND rollback_until IS NOT NULL "
            "AND source_retired_at>=rollback_until)) "
            "AND (source_deleted_at IS NULL OR "
            "(source_retired_at IS NOT NULL AND source_deleted_at>=source_retired_at)) "
            "AND version>=1 AND created_at>=0 AND updated_at>=created_at "
            "AND schema_version=1",
            name="ck_embedding_migration_integrity",
        ),
    )
    op.create_index(
        "ix_embedding_migration_brain_state",
        "embedding_generation_migrations",
        ["brain_id", "state", "updated_at"],
    )
    op.create_table(
        "embedding_migration_operations",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "migration_id",
            sa.Text(),
            sa.ForeignKey("embedding_generation_migrations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("request_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(request_digest)=32 AND length(scope_fingerprint)=32 "
            "AND created_at>=0 AND schema_version=1",
            name="ck_embedding_migration_operation_integrity",
        ),
    )
    op.create_table(
        "active_embedding_generations",
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column(
            "space_id",
            sa.Text(),
            sa.ForeignKey("embedding_spaces.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "generation_id",
            sa.Text(),
            sa.ForeignKey("embedding_index_generations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("brain_id", "purpose"),
        sa.UniqueConstraint(
            "generation_id",
            name="uq_active_embedding_generation",
        ),
        sa.CheckConstraint(
            f"purpose IN ({_PURPOSES}) AND version>=1 AND updated_at>=0 AND schema_version=1",
            name="ck_active_embedding_generation_integrity",
        ),
    )
    op.create_table(
        "embedding_generation_write_routes",
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "source_space_id",
            sa.Text(),
            sa.ForeignKey("embedding_spaces.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("primary_space_id", sa.Text(), nullable=False),
        sa.Column("primary_space_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("primary_generation_id", sa.Text(), nullable=False),
        sa.Column("secondary_space_id", sa.Text(), nullable=True),
        sa.Column("secondary_space_fingerprint", sa.LargeBinary(32), nullable=True),
        sa.Column("secondary_generation_id", sa.Text(), nullable=True),
        sa.Column(
            "migration_id",
            sa.Text(),
            sa.ForeignKey("embedding_generation_migrations.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("brain_id", "source_space_id"),
        sa.ForeignKeyConstraint(
            ["primary_space_id"],
            ["embedding_spaces.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["primary_generation_id"],
            ["embedding_index_generations.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["secondary_space_id"],
            ["embedding_spaces.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["secondary_generation_id"],
            ["embedding_index_generations.id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(primary_space_fingerprint)=32 "
            "AND ((secondary_space_id IS NULL "
            "AND secondary_space_fingerprint IS NULL "
            "AND secondary_generation_id IS NULL AND migration_id IS NULL) "
            "OR (secondary_space_id IS NOT NULL "
            "AND length(secondary_space_fingerprint)=32 "
            "AND secondary_generation_id IS NOT NULL AND migration_id IS NOT NULL)) "
            "AND version>=1 AND updated_at>=0 AND schema_version=1",
            name="ck_embedding_write_route_integrity",
        ),
    )
    op.create_table(
        "embedding_migration_evidence",
        sa.Column("sequence", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "migration_id",
            sa.Text(),
            sa.ForeignKey("embedding_generation_migrations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("from_state", sa.Text(), nullable=True),
        sa.Column("to_state", sa.Text(), nullable=False),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("snapshot_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "migration_id",
            "version",
            name="uq_embedding_migration_evidence_version",
        ),
        sa.CheckConstraint(
            f"(from_state IS NULL OR from_state IN ({_STATES})) "
            f"AND to_state IN ({_STATES}) "
            "AND version>=1 AND length(snapshot_digest)=32 "
            "AND occurred_at>=0 AND schema_version=1",
            name="ck_embedding_migration_evidence_integrity",
        ),
    )
    op.create_table(
        "embedding_migration_activations",
        sa.Column(
            "migration_id",
            sa.Text(),
            sa.ForeignKey("embedding_generation_migrations.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("operation_id", sa.Text(), nullable=False, unique=True),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column(
            "approval_id",
            sa.Text(),
            sa.ForeignKey("scope_grants.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("expected_version", sa.BigInteger(), nullable=False),
        sa.Column("rollback_until", sa.BigInteger(), nullable=False),
        sa.Column("activated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(scope_fingerprint)=32 AND expected_version>=1 "
            "AND rollback_until>activated_at AND activated_at>=0 AND schema_version=1",
            name="ck_embedding_migration_activation_integrity",
        ),
    )
    _immutable("embedding_migration_operations")
    _immutable("embedding_migration_evidence")
    _immutable("embedding_migration_activations")
    _no_delete("embedding_generation_migrations")
    _closed_migration_update()
    _closed_pointer_update()
    _closed_route_update()


def _closed_migration_update() -> None:
    op.execute(
        "CREATE TRIGGER trg_embedding_generation_migrations_closed_update "
        "BEFORE UPDATE ON embedding_generation_migrations "
        "WHEN OLD.id<>NEW.id OR OLD.brain_id<>NEW.brain_id "
        "OR OLD.source_space_id<>NEW.source_space_id "
        "OR OLD.source_generation_id<>NEW.source_generation_id "
        "OR OLD.source_space_fingerprint<>NEW.source_space_fingerprint "
        "OR OLD.target_space_id<>NEW.target_space_id "
        "OR OLD.target_generation_id<>NEW.target_generation_id "
        "OR OLD.target_space_fingerprint<>NEW.target_space_fingerprint "
        "OR OLD.source_watermark<>NEW.source_watermark "
        "OR OLD.created_at<>NEW.created_at OR OLD.schema_version<>NEW.schema_version "
        "OR NEW.version<>OLD.version+1 OR NEW.updated_at<OLD.updated_at "
        "OR NEW.backfill_cursor<OLD.backfill_cursor "
        "OR NEW.catchup_watermark<OLD.catchup_watermark "
        "OR NEW.catchup_cursor<OLD.catchup_cursor "
        "OR NOT ((NEW.state=OLD.state AND NEW.resume_state IS OLD.resume_state) OR "
        "(OLD.state='planned' AND NEW.state IN ('building','failed') "
        "AND NEW.resume_state IS NULL) OR "
        "(OLD.state='building' AND NEW.state IN ('backfilling','failed') "
        "AND NEW.resume_state IS NULL) OR "
        "(OLD.state='backfilling' AND NEW.state IN ('dual_write','failed') "
        "AND NEW.resume_state IS NULL) OR "
        "(OLD.state='dual_write' AND NEW.state IN ('catching_up','failed') "
        "AND NEW.resume_state IS NULL) OR "
        "(OLD.state='catching_up' AND NEW.state IN ('validating','failed') "
        "AND NEW.resume_state IS NULL) OR "
        "(OLD.state='validating' AND NEW.state IN ('shadowing','failed') "
        "AND NEW.resume_state IS NULL) OR "
        "(OLD.state='shadowing' AND NEW.state IN ('ready','failed') "
        "AND NEW.resume_state IS NULL) OR "
        "(OLD.state='ready' AND NEW.state IN ('active','failed') "
        "AND NEW.resume_state IS NULL) OR "
        "(OLD.state NOT IN ('active','rolled_back','failed','paused') "
        "AND NEW.state='paused' AND NEW.resume_state=OLD.state) OR "
        "(OLD.state='paused' AND NEW.state=OLD.resume_state "
        "AND NEW.resume_state IS NULL) OR "
        "(OLD.state='active' AND NEW.state='rolled_back')) "
        "BEGIN SELECT RAISE(ABORT, 'immutable embedding migration'); END"
    )


def _closed_pointer_update() -> None:
    _no_delete("active_embedding_generations")
    op.execute(
        "CREATE TRIGGER trg_active_embedding_generations_closed_update "
        "BEFORE UPDATE ON active_embedding_generations "
        "WHEN OLD.brain_id<>NEW.brain_id OR OLD.purpose<>NEW.purpose "
        "OR OLD.schema_version<>NEW.schema_version OR NEW.version<>OLD.version+1 "
        "OR NEW.updated_at<OLD.updated_at "
        "BEGIN SELECT RAISE(ABORT, 'immutable active embedding pointer'); END"
    )


def _closed_route_update() -> None:
    _no_delete("embedding_generation_write_routes")
    op.execute(
        "CREATE TRIGGER trg_embedding_generation_write_routes_closed_update "
        "BEFORE UPDATE ON embedding_generation_write_routes "
        "WHEN OLD.brain_id<>NEW.brain_id OR OLD.source_space_id<>NEW.source_space_id "
        "OR OLD.schema_version<>NEW.schema_version OR NEW.version<>OLD.version+1 "
        "OR NEW.updated_at<OLD.updated_at "
        "BEGIN SELECT RAISE(ABORT, 'immutable embedding write route'); END"
    )


def _immutable(table: str) -> None:
    for operation in ("UPDATE", "DELETE"):
        op.execute(
            f"CREATE TRIGGER trg_{table}_immutable_{operation.lower()} "
            f"BEFORE {operation} ON {table} "
            "BEGIN SELECT RAISE(ABORT, 'immutable embedding migration evidence'); END"
        )


def _no_delete(table: str) -> None:
    op.execute(
        f"CREATE TRIGGER trg_{table}_immutable_delete BEFORE DELETE ON {table} "
        "BEGIN SELECT RAISE(ABORT, 'immutable embedding migration authority'); END"
    )


def downgrade() -> None:
    """Refuse to destroy migration, activation, routing, or deletion evidence."""
    connection = op.get_bind()
    count = connection.execute(
        sa.text(
            "SELECT "
            "(SELECT COUNT(*) FROM embedding_generation_migrations)+"
            "(SELECT COUNT(*) FROM active_embedding_generations)+"
            "(SELECT COUNT(*) FROM embedding_generation_write_routes)+"
            "(SELECT COUNT(*) FROM embedding_migration_activations)"
        )
    ).scalar_one()
    if count:
        message = "PRO-008 downgrade refused while embedding migration authority exists"
        raise RuntimeError(message)
    for table in (
        "embedding_generation_write_routes",
        "active_embedding_generations",
        "embedding_generation_migrations",
        "embedding_migration_activations",
        "embedding_migration_evidence",
        "embedding_migration_operations",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable_delete")
    op.execute("DROP TRIGGER IF EXISTS trg_embedding_generation_write_routes_closed_update")
    op.execute("DROP TRIGGER IF EXISTS trg_active_embedding_generations_closed_update")
    op.execute("DROP TRIGGER IF EXISTS trg_embedding_generation_migrations_closed_update")
    op.execute("DROP TRIGGER IF EXISTS trg_embedding_migration_evidence_immutable_update")
    op.execute("DROP TRIGGER IF EXISTS trg_embedding_migration_activations_immutable_update")
    op.execute("DROP TRIGGER IF EXISTS trg_embedding_migration_operations_immutable_update")
    op.drop_table("embedding_migration_activations")
    op.drop_table("embedding_migration_evidence")
    op.drop_table("embedding_generation_write_routes")
    op.drop_table("active_embedding_generations")
    op.drop_table("embedding_migration_operations")
    op.drop_index(
        "ix_embedding_migration_brain_state",
        table_name="embedding_generation_migrations",
    )
    op.drop_table("embedding_generation_migrations")
