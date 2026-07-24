"""PRO-007 endpoint equivalence, circuits, dispatch evidence, and terminal failures.

Revision ID: 0040_pro007_provider_resilience
Revises: 0039_pro006_provider_scheduling
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0040_pro007_provider_resilience"
down_revision = "0039_pro006_provider_scheduling"
branch_labels = None
depends_on = None

_CIRCUIT_STATES = "'closed','open','half_open'"
_ERROR_CODES = (
    "'authentication','permission','invalid_configuration','unsupported_capability',"
    "'missing_model','oversized_input','rate_limit','quota','timeout','cancellation',"
    "'transient_upstream','malformed_response','dimension_mismatch','model_drift',"
    "'privacy_denial','adapter_crash'"
)
_ATTEMPT_CODES = _ERROR_CODES + ",'started','succeeded','circuit_open'"


def upgrade() -> None:
    """Install immutable equivalence/failure evidence and durable endpoint circuits."""
    op.create_table(
        "provider_equivalent_endpoint_sets",
        sa.Column("set_id", sa.LargeBinary(32), primary_key=True),
        sa.Column("primary_profile_id", sa.Text(), nullable=False),
        sa.Column("primary_profile_version", sa.Integer(), nullable=False),
        sa.Column(
            "space_id",
            sa.Text(),
            sa.ForeignKey("embedding_spaces.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("space_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("output_contract_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("output_contract_json", sa.LargeBinary(), nullable=False),
        sa.Column("endpoint_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["primary_profile_id", "primary_profile_version"],
            ["provider_profile_revisions.profile_id", "provider_profile_revisions.version"],
            name="fk_equivalent_set_primary_revision",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.UniqueConstraint(
            "primary_profile_id",
            "primary_profile_version",
            "space_id",
            name="uq_equivalent_set_primary_space_revision",
        ),
        sa.CheckConstraint(
            "length(set_id)=32 AND primary_profile_version>=1 "
            "AND length(space_fingerprint)=32 AND length(output_contract_digest)=32 "
            "AND json_valid(output_contract_json) "
            "AND json_type(output_contract_json)='object' "
            "AND endpoint_count BETWEEN 1 AND 100 AND created_at>=0 "
            "AND schema_version=1",
            name="ck_provider_equivalent_set_integrity",
        ),
    )
    op.create_table(
        "provider_equivalent_endpoints",
        sa.Column(
            "set_id",
            sa.LargeBinary(32),
            sa.ForeignKey("provider_equivalent_endpoint_sets.set_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column(
            "capability_attestation_id",
            sa.Text(),
            sa.ForeignKey(
                "provider_capability_attestations.attestation_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("endpoint_fingerprint", sa.Text(), nullable=False),
        sa.Column("configuration_digest", sa.Text(), nullable=False),
        sa.Column("adapter_digest", sa.Text(), nullable=False),
        sa.Column("endpoint_attestation_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("output_contract_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("set_id", "ordinal"),
        sa.ForeignKeyConstraint(
            ["profile_id", "profile_version"],
            ["provider_profile_revisions.profile_id", "provider_profile_revisions.version"],
            name="fk_equivalent_endpoint_revision",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.UniqueConstraint(
            "set_id",
            "profile_id",
            name="uq_equivalent_endpoint_profile",
        ),
        sa.UniqueConstraint(
            "set_id",
            "endpoint_fingerprint",
            name="uq_equivalent_endpoint_fingerprint",
        ),
        sa.CheckConstraint(
            "ordinal BETWEEN 0 AND 99 AND profile_version>=1 "
            "AND length(capability_attestation_id)=64 "
            "AND capability_attestation_id NOT GLOB '*[^0-9a-f]*' "
            "AND length(endpoint_fingerprint)=64 "
            "AND endpoint_fingerprint NOT GLOB '*[^0-9a-f]*' "
            "AND length(configuration_digest)=64 "
            "AND configuration_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(adapter_digest)=64 AND adapter_digest NOT GLOB '*[^0-9a-f]*' "
            "AND length(endpoint_attestation_digest)=32 "
            "AND length(output_contract_digest)=32 AND schema_version=1",
            name="ck_provider_equivalent_endpoint_integrity",
        ),
    )
    op.create_index(
        "ix_provider_equivalent_endpoint_lookup",
        "provider_equivalent_endpoints",
        ["profile_id", "profile_version", "endpoint_fingerprint"],
    )
    op.create_table(
        "provider_equivalence_operations",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "set_id",
            sa.LargeBinary(32),
            sa.ForeignKey("provider_equivalent_endpoint_sets.set_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("request_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(set_id)=32 AND length(request_digest)=32 "
            "AND length(scope_fingerprint)=32 AND completed_at>=0 "
            "AND schema_version=1",
            name="ck_provider_equivalence_operation_integrity",
        ),
    )
    op.create_table(
        "provider_endpoint_circuits",
        sa.Column("endpoint_fingerprint", sa.Text(), primary_key=True),
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("endpoint_attestation_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("window_started_at", sa.BigInteger(), nullable=True),
        sa.Column("open_until", sa.BigInteger(), nullable=True),
        sa.Column("probe_in_flight", sa.Boolean(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["profile_id", "profile_version"],
            ["provider_profile_revisions.profile_id", "provider_profile_revisions.version"],
            name="fk_provider_circuit_profile_revision",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.CheckConstraint(
            "length(endpoint_fingerprint)=64 "
            "AND endpoint_fingerprint NOT GLOB '*[^0-9a-f]*' "
            "AND profile_version>=1 AND length(endpoint_attestation_digest)=32 "
            f"AND state IN ({_CIRCUIT_STATES}) AND consecutive_failures>=0 "
            "AND (window_started_at IS NULL OR window_started_at>=0) "
            "AND (open_until IS NULL OR open_until>=0) AND version>=0 AND updated_at>=0 "
            "AND ((state='closed' AND open_until IS NULL AND probe_in_flight=0) "
            "OR (state='open' AND open_until IS NOT NULL AND probe_in_flight=0) "
            "OR (state='half_open' AND open_until IS NOT NULL AND probe_in_flight=1)) "
            "AND schema_version=1",
            name="ck_provider_endpoint_circuit_integrity",
        ),
    )
    op.create_index(
        "ix_provider_endpoint_circuit_state",
        "provider_endpoint_circuits",
        ["state", "open_until", "profile_id"],
    )
    op.create_table(
        "provider_dispatch_attempts",
        sa.Column("fact_id", sa.LargeBinary(32), primary_key=True),
        sa.Column("operation_key_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("endpoint_fingerprint", sa.Text(), nullable=False),
        sa.Column("endpoint_attestation_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("fallback_ordinal", sa.Integer(), nullable=False),
        sa.Column("outcome_code", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(fact_id)=32 AND length(operation_key_sha256)=32 "
            "AND length(endpoint_fingerprint)=64 "
            "AND endpoint_fingerprint NOT GLOB '*[^0-9a-f]*' "
            "AND length(endpoint_attestation_digest)=32 "
            f"AND attempt BETWEEN 1 AND 100 AND fallback_ordinal BETWEEN 0 AND 100 "
            f"AND outcome_code IN ({_ATTEMPT_CODES}) "
            "AND occurred_at>=0 AND schema_version=1",
            name="ck_provider_dispatch_attempt_integrity",
        ),
    )
    op.create_index(
        "ix_provider_dispatch_operation",
        "provider_dispatch_attempts",
        ["operation_key_sha256", "attempt", "fallback_ordinal", "occurred_at"],
    )
    op.create_table(
        "provider_operation_failures",
        sa.Column("profile_id", sa.Text(), primary_key=True),
        sa.Column("idempotency_key", sa.Text(), primary_key=True),
        sa.Column("operation_id", sa.Text(), nullable=False, unique=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("cache_key_sha256", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("request_sha256", sa.LargeBinary(32), nullable=False),
        sa.Column("error_code", sa.Text(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("failed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(cache_key_sha256)=32 AND length(request_sha256)=32 "
            f"AND error_code IN ({_ERROR_CODES}) AND attempts>=1 "
            "AND failed_at>=0 AND schema_version=1",
            name="ck_provider_operation_failure_integrity",
        ),
    )
    op.create_index(
        "ix_provider_operation_failure_brain",
        "provider_operation_failures",
        ["brain_id", "failed_at", "error_code"],
    )
    for table in (
        "provider_equivalent_endpoint_sets",
        "provider_equivalent_endpoints",
        "provider_equivalence_operations",
        "provider_dispatch_attempts",
        "provider_operation_failures",
    ):
        _immutable(table)


def _immutable(table: str) -> None:
    op.execute(
        f"CREATE TRIGGER trg_{table}_immutable_update BEFORE UPDATE ON {table} "
        "BEGIN SELECT RAISE(ABORT, 'immutable PRO-007 evidence'); END"
    )
    op.execute(
        f"CREATE TRIGGER trg_{table}_immutable_delete BEFORE DELETE ON {table} "
        "BEGIN SELECT RAISE(ABORT, 'immutable PRO-007 evidence'); END"
    )


def downgrade() -> None:
    """Refuse to discard any PRO-007 authority or execution evidence."""
    connection = op.get_bind()
    count = connection.execute(
        sa.text(
            "SELECT "
            "(SELECT COUNT(*) FROM provider_equivalent_endpoint_sets) + "
            "(SELECT COUNT(*) FROM provider_equivalence_operations) + "
            "(SELECT COUNT(*) FROM provider_endpoint_circuits) + "
            "(SELECT COUNT(*) FROM provider_dispatch_attempts) + "
            "(SELECT COUNT(*) FROM provider_operation_failures)"
        )
    ).scalar_one()
    if count:
        message = "PRO-007 downgrade refused while provider resilience evidence exists"
        raise RuntimeError(message)
    for table in (
        "provider_operation_failures",
        "provider_dispatch_attempts",
        "provider_equivalence_operations",
        "provider_equivalent_endpoints",
        "provider_equivalent_endpoint_sets",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable_delete")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable_update")
    op.drop_index(
        "ix_provider_operation_failure_brain",
        table_name="provider_operation_failures",
    )
    op.drop_table("provider_operation_failures")
    op.drop_index(
        "ix_provider_dispatch_operation",
        table_name="provider_dispatch_attempts",
    )
    op.drop_table("provider_dispatch_attempts")
    op.drop_table("provider_equivalence_operations")
    op.drop_index(
        "ix_provider_endpoint_circuit_state",
        table_name="provider_endpoint_circuits",
    )
    op.drop_table("provider_endpoint_circuits")
    op.drop_index(
        "ix_provider_equivalent_endpoint_lookup",
        table_name="provider_equivalent_endpoints",
    )
    op.drop_table("provider_equivalent_endpoints")
    op.drop_table("provider_equivalent_endpoint_sets")
