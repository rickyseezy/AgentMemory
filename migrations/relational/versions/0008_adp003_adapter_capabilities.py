"""ADP-003 immutable adapter manifests and effective capability observations.

Revision ID: 0008_adp003_adapter_capabilities
Revises: 0007_adp002_durable_capture
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_adp003_adapter_capabilities"
down_revision = "0007_adp002_durable_capture"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    duplicate_versions = connection.execute(
        sa.text(
            "SELECT COUNT(*) FROM ("
            "SELECT adapter_id, adapter_version FROM agent_adapter_manifests "
            "GROUP BY adapter_id, adapter_version HAVING COUNT(*) > 1)"
        )
    ).scalar_one()
    if duplicate_versions:
        msg = "ADP-003 migration refused conflicting immutable adapter versions"
        raise RuntimeError(msg)
    with op.batch_alter_table("agent_adapter_manifests") as batch:
        batch.add_column(
            sa.Column(
                "manifest_format",
                sa.Text(),
                nullable=False,
                server_default="legacy-descriptor-v1",
            )
        )
        batch.create_check_constraint(
            "ck_adapter_manifest_format",
            "manifest_format IN ('legacy-descriptor-v1','capability-matrix-v1')",
        )
    op.create_index(
        "uq_agent_adapter_version",
        "agent_adapter_manifests",
        ["adapter_id", "adapter_version"],
        unique=True,
    )
    op.create_index(
        "ix_agent_adapter_status",
        "agent_adapter_manifests",
        ["status", "created_at"],
    )

    op.create_table(
        "agent_adapter_capability_observations",
        sa.Column("observation_id", sa.Text(), primary_key=True),
        sa.Column("operation_id", sa.Text(), nullable=False),
        sa.Column("adapter_id", sa.Text(), nullable=False),
        sa.Column("adapter_version", sa.Text(), nullable=False),
        sa.Column("adapter_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("manifest_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("availability_json", sa.Text(), nullable=False),
        sa.Column("observed_at", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["adapter_id", "adapter_version", "adapter_digest"],
            [
                "agent_adapter_manifests.adapter_id",
                "agent_adapter_manifests.adapter_version",
                "agent_adapter_manifests.adapter_digest",
            ],
            name="fk_capability_observation_manifest",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "adapter_id",
            "adapter_version",
            "revision",
            name="uq_adapter_capability_revision",
        ),
        sa.CheckConstraint("length(adapter_digest) = 32", name="ck_observation_adapter_digest"),
        sa.CheckConstraint("length(manifest_sha256) = 32", name="ck_observation_manifest_digest"),
        sa.CheckConstraint("revision >= 1", name="ck_capability_observation_revision"),
        sa.CheckConstraint("json_valid(availability_json)", name="ck_observation_availability"),
    )
    op.create_index(
        "ix_adapter_capability_latest",
        "agent_adapter_capability_observations",
        ["adapter_id", "adapter_version", "revision"],
    )

    op.create_table(
        "agent_adapter_compatibility_warnings",
        sa.Column("warning_id", sa.Text(), primary_key=True),
        sa.Column(
            "observation_id",
            sa.Text(),
            sa.ForeignKey(
                "agent_adapter_capability_observations.observation_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("adapter_id", sa.Text(), nullable=False),
        sa.Column("adapter_version", sa.Text(), nullable=False),
        sa.Column("capability", sa.Text(), nullable=False),
        sa.Column("previous_status", sa.Text(), nullable=False),
        sa.Column("current_status", sa.Text(), nullable=False),
        sa.Column("impact", sa.Text(), nullable=False),
        sa.Column("warning_code", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "observation_id",
            "capability",
            name="uq_capability_warning_observation",
        ),
        sa.CheckConstraint(
            "previous_status IN "
            "('native','inferred','explicit_tool_only','unsupported','permission_denied')",
            name="ck_warning_previous_status",
        ),
        sa.CheckConstraint(
            "current_status IN "
            "('native','inferred','explicit_tool_only','unsupported','permission_denied')",
            name="ck_warning_current_status",
        ),
        sa.CheckConstraint(
            "impact IN ('informational','degraded','breaking')",
            name="ck_capability_warning_impact",
        ),
    )
    op.create_index(
        "ix_adapter_capability_warning",
        "agent_adapter_compatibility_warnings",
        ["adapter_id", "created_at", "impact"],
    )

    op.create_table(
        "agent_adapter_capability_commands",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column("request_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column(
            "observation_id",
            sa.Text(),
            sa.ForeignKey(
                "agent_adapter_capability_observations.observation_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("disposition", sa.Text(), nullable=False),
        sa.Column("warnings_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("length(request_sha256) = 32", name="ck_capability_command_digest"),
        sa.CheckConstraint(
            "disposition IN ('registered','observed','unchanged')",
            name="ck_capability_command_disposition",
        ),
        sa.CheckConstraint("json_valid(warnings_json)", name="ck_capability_command_warnings"),
    )

    with op.batch_alter_table("agent_event_envelopes") as batch:
        batch.add_column(sa.Column("adapter_id", sa.Text(), nullable=True))
        batch.add_column(sa.Column("adapter_version", sa.Text(), nullable=True))
        batch.add_column(sa.Column("adapter_digest", sa.LargeBinary(32), nullable=True))
        batch.add_column(sa.Column("capability_manifest_sha256", sa.LargeBinary(32), nullable=True))
        batch.add_column(sa.Column("capture_method", sa.Text(), nullable=True))
        batch.create_check_constraint(
            "ck_agent_event_capability_binding",
            "(adapter_id IS NULL AND adapter_version IS NULL AND adapter_digest IS NULL "
            "AND capability_manifest_sha256 IS NULL AND capture_method IS NULL) OR "
            "(adapter_id IS NOT NULL AND adapter_version IS NOT NULL "
            "AND length(adapter_digest) = 32 AND length(capability_manifest_sha256) = 32 "
            "AND capture_method IN ('native','inferred','explicit_tool_only'))",
        )
    op.create_index(
        "ix_agent_event_capability_manifest",
        "agent_event_envelopes",
        ["adapter_id", "adapter_version", "capability_manifest_sha256", "created_at"],
    )


def downgrade() -> None:
    connection = op.get_bind()
    references = connection.execute(
        sa.text(
            "SELECT (SELECT COUNT(*) FROM agent_adapter_capability_commands) + "
            "(SELECT COUNT(*) FROM agent_adapter_capability_observations) + "
            "(SELECT COUNT(*) FROM agent_adapter_compatibility_warnings) + "
            "(SELECT COUNT(*) FROM agent_event_envelopes "
            " WHERE capability_manifest_sha256 IS NOT NULL)"
        )
    ).scalar_one()
    if references:
        msg = "ADP-003 downgrade refused while capability evidence exists"
        raise RuntimeError(msg)
    op.drop_index("ix_agent_event_capability_manifest", table_name="agent_event_envelopes")
    with op.batch_alter_table("agent_event_envelopes") as batch:
        batch.drop_constraint("ck_agent_event_capability_binding", type_="check")
        batch.drop_column("capture_method")
        batch.drop_column("capability_manifest_sha256")
        batch.drop_column("adapter_digest")
        batch.drop_column("adapter_version")
        batch.drop_column("adapter_id")
    op.drop_table("agent_adapter_capability_commands")
    op.drop_index(
        "ix_adapter_capability_warning",
        table_name="agent_adapter_compatibility_warnings",
    )
    op.drop_table("agent_adapter_compatibility_warnings")
    op.drop_index(
        "ix_adapter_capability_latest",
        table_name="agent_adapter_capability_observations",
    )
    op.drop_table("agent_adapter_capability_observations")
    op.drop_index("ix_agent_adapter_status", table_name="agent_adapter_manifests")
    op.drop_index("uq_agent_adapter_version", table_name="agent_adapter_manifests")
    with op.batch_alter_table("agent_adapter_manifests") as batch:
        batch.drop_constraint("ck_adapter_manifest_format", type_="check")
        batch.drop_column("manifest_format")
