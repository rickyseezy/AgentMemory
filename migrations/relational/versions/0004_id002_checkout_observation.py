"""ID-002 versioned Checkout observations and general domain events.

Revision ID: 0004_id002_checkout_observation
Revises: 0003_id001_workspace_identity
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_id002_checkout_observation"
down_revision = "0003_id001_workspace_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("domain_events") as batch:
        batch.add_column(sa.Column("aggregate_type", sa.Text(), nullable=True))
        batch.add_column(sa.Column("aggregate_id", sa.Text(), nullable=True))
        batch.add_column(sa.Column("aggregate_version", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("event_type", sa.Text(), nullable=True))
        batch.add_column(sa.Column("event_json", sa.Text(), nullable=True))
        batch.add_column(sa.Column("correlation_id", sa.Text(), nullable=True))
        batch.add_column(sa.Column("causation_id", sa.Text(), nullable=True))
        for column in (
            "projection_type",
            "stable_id",
            "target_type",
            "target_id_hash",
            "payload_json",
            "payload_hash",
            "source_digest",
            "missing_dependency",
        ):
            batch.alter_column(column, existing_type=_domain_event_type(column), nullable=True)
        batch.drop_constraint("ck_domain_event_payload_json", type_="check")
        batch.create_check_constraint(
            "ck_domain_event_payload_json",
            "payload_json IS NULL OR json_valid(payload_json)",
        )
        batch.create_check_constraint(
            "ck_domain_event_general_shape",
            "(aggregate_type IS NULL AND aggregate_id IS NULL AND aggregate_version IS NULL "
            "AND event_type IS NULL AND event_json IS NULL AND correlation_id IS NULL) OR "
            "(aggregate_type IS NOT NULL AND aggregate_id IS NOT NULL "
            "AND aggregate_version >= 1 AND event_type IS NOT NULL "
            "AND json_valid(event_json) AND correlation_id IS NOT NULL)",
        )
    op.create_index(
        "uq_domain_event_aggregate_version",
        "domain_events",
        ["brain_id", "aggregate_type", "aggregate_id", "aggregate_version"],
        unique=True,
    )
    op.create_index(
        "uq_domain_event_correlation",
        "domain_events",
        ["brain_id", "aggregate_type", "correlation_id"],
        unique=True,
    )

    with op.batch_alter_table("checkouts") as batch:
        batch.add_column(sa.Column("version", sa.Integer(), nullable=False, server_default="1"))
        batch.add_column(sa.Column("logical_path_hash", sa.LargeBinary(32), nullable=True))
        batch.add_column(sa.Column("volume_fingerprint", sa.LargeBinary(32), nullable=True))
        batch.add_column(sa.Column("file_fingerprint", sa.LargeBinary(32), nullable=True))
        batch.add_column(
            sa.Column("common_directory_fingerprint", sa.LargeBinary(32), nullable=True)
        )
        batch.add_column(sa.Column("dirty_digest", sa.LargeBinary(32), nullable=True))
        batch.add_column(sa.Column("remote_fingerprints_json", sa.Text(), nullable=True))
        batch.create_check_constraint("ck_checkout_version", "version >= 1")
        batch.create_check_constraint(
            "ck_checkout_logical_path",
            "logical_path_hash IS NULL OR length(logical_path_hash) = 32",
        )
        batch.create_check_constraint(
            "ck_checkout_volume",
            "volume_fingerprint IS NULL OR length(volume_fingerprint) = 32",
        )
        batch.create_check_constraint(
            "ck_checkout_file",
            "file_fingerprint IS NULL OR length(file_fingerprint) = 32",
        )
        batch.create_check_constraint(
            "ck_checkout_common_directory",
            "common_directory_fingerprint IS NULL OR length(common_directory_fingerprint) = 32",
        )
        batch.create_check_constraint(
            "ck_checkout_dirty",
            "dirty_digest IS NULL OR length(dirty_digest) = 32",
        )
        batch.create_check_constraint(
            "ck_checkout_remotes_json",
            "remote_fingerprints_json IS NULL OR json_valid(remote_fingerprints_json)",
        )
    op.create_index(
        "ix_checkout_file_continuity",
        "checkouts",
        ["brain_id", "repository_id", "device_id", "volume_fingerprint", "file_fingerprint"],
    )
    op.create_index(
        "ix_checkout_worktree_continuity",
        "checkouts",
        [
            "brain_id",
            "repository_id",
            "device_id",
            "common_directory_fingerprint",
            "worktree_id",
        ],
    )
    op.create_table(
        "checkout_observations",
        sa.Column("operation_id", sa.Text(), nullable=False),
        sa.Column("event_id", sa.Text(), nullable=False, unique=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "checkout_id",
            sa.Text(),
            sa.ForeignKey("checkouts.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("aggregate_version", sa.Integer(), nullable=False),
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
        sa.Column("volume_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("path_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("logical_path_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("file_fingerprint", sa.LargeBinary(32), nullable=True),
        sa.Column("checkout_fingerprint", sa.LargeBinary(32), nullable=True),
        sa.Column("worktree_fingerprint", sa.LargeBinary(32), nullable=True),
        sa.Column("common_directory_fingerprint", sa.LargeBinary(32), nullable=True),
        sa.Column("branch", sa.Text(), nullable=True),
        sa.Column("head_commit", sa.Text(), nullable=True),
        sa.Column("dirty_digest", sa.LargeBinary(32), nullable=True),
        sa.Column("remote_fingerprints_json", sa.Text(), nullable=False),
        sa.Column("observed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("brain_id", "operation_id"),
        sa.UniqueConstraint(
            "checkout_id", "aggregate_version", name="uq_checkout_observation_version"
        ),
        sa.CheckConstraint("aggregate_version >= 1", name="ck_checkout_observation_version"),
        sa.CheckConstraint(
            "length(volume_fingerprint) = 32 AND length(path_fingerprint) = 32 "
            "AND length(logical_path_fingerprint) = 32",
            name="ck_checkout_observation_required_fingerprints",
        ),
        sa.CheckConstraint(
            "file_fingerprint IS NULL OR length(file_fingerprint) = 32",
            name="ck_checkout_observation_file",
        ),
        sa.CheckConstraint(
            "checkout_fingerprint IS NULL OR length(checkout_fingerprint) = 32",
            name="ck_checkout_observation_checkout",
        ),
        sa.CheckConstraint(
            "worktree_fingerprint IS NULL OR length(worktree_fingerprint) = 32",
            name="ck_checkout_observation_worktree",
        ),
        sa.CheckConstraint(
            "common_directory_fingerprint IS NULL OR length(common_directory_fingerprint) = 32",
            name="ck_checkout_observation_common_directory",
        ),
        sa.CheckConstraint(
            "dirty_digest IS NULL OR length(dirty_digest) = 32",
            name="ck_checkout_observation_dirty",
        ),
        sa.CheckConstraint(
            "json_valid(remote_fingerprints_json)",
            name="ck_checkout_observation_remotes_json",
        ),
    )
    op.create_index(
        "ix_checkout_observation_history",
        "checkout_observations",
        ["brain_id", "checkout_id", "aggregate_version"],
    )
    op.execute(
        "CREATE TRIGGER checkout_observations_no_update "
        "BEFORE UPDATE ON checkout_observations BEGIN "
        "SELECT RAISE(ABORT, 'checkout observations are append-only'); END"
    )
    op.execute(
        "CREATE TRIGGER checkout_observations_no_delete "
        "BEFORE DELETE ON checkout_observations BEGIN "
        "SELECT RAISE(ABORT, 'checkout observations are append-only'); END"
    )


def downgrade() -> None:
    connection = op.get_bind()
    identity_events = connection.execute(
        sa.text("SELECT COUNT(*) FROM domain_events WHERE aggregate_type IS NOT NULL")
    ).scalar_one()
    if identity_events:
        msg = "ID-002 downgrade refused while canonical Checkout events exist"
        raise RuntimeError(msg)
    op.execute("DROP TRIGGER checkout_observations_no_delete")
    op.execute("DROP TRIGGER checkout_observations_no_update")
    op.drop_index("ix_checkout_observation_history", table_name="checkout_observations")
    op.drop_table("checkout_observations")
    op.drop_index("ix_checkout_worktree_continuity", table_name="checkouts")
    op.drop_index("ix_checkout_file_continuity", table_name="checkouts")
    with op.batch_alter_table("checkouts") as batch:
        batch.drop_constraint("ck_checkout_remotes_json", type_="check")
        batch.drop_constraint("ck_checkout_dirty", type_="check")
        batch.drop_constraint("ck_checkout_common_directory", type_="check")
        batch.drop_constraint("ck_checkout_file", type_="check")
        batch.drop_constraint("ck_checkout_volume", type_="check")
        batch.drop_constraint("ck_checkout_logical_path", type_="check")
        batch.drop_constraint("ck_checkout_version", type_="check")
        for column in (
            "remote_fingerprints_json",
            "dirty_digest",
            "common_directory_fingerprint",
            "file_fingerprint",
            "volume_fingerprint",
            "logical_path_hash",
            "version",
        ):
            batch.drop_column(column)
    op.drop_index("uq_domain_event_correlation", table_name="domain_events")
    op.drop_index("uq_domain_event_aggregate_version", table_name="domain_events")
    with op.batch_alter_table("domain_events") as batch:
        batch.drop_constraint("ck_domain_event_general_shape", type_="check")
        batch.drop_constraint("ck_domain_event_payload_json", type_="check")
        batch.create_check_constraint("ck_domain_event_payload_json", "json_valid(payload_json)")
        for column in (
            "projection_type",
            "stable_id",
            "target_type",
            "target_id_hash",
            "payload_json",
            "payload_hash",
            "source_digest",
        ):
            batch.alter_column(column, existing_type=_domain_event_type(column), nullable=False)
        for column in (
            "causation_id",
            "correlation_id",
            "event_json",
            "event_type",
            "aggregate_version",
            "aggregate_id",
            "aggregate_type",
        ):
            batch.drop_column(column)


def _domain_event_type(column: str) -> sa.types.TypeEngine:
    if column in {"target_id_hash", "payload_hash", "source_digest"}:
        return sa.LargeBinary(32)
    return sa.Text()
