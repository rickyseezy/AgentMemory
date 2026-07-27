"""PRO-010 provider health, cost, budget, and drift authority.

Revision ID: 0043_pro010_provider_observability
Revises: 0042_pro009_provider_containment
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0043_pro010_provider_observability"
down_revision = "0042_pro009_provider_containment"
branch_labels = None
depends_on = None

_OPERATIONS = "'embedding','reranking'"
_BUDGET_BEHAVIORS = "'queue','degrade'"
_BUDGET_DECISIONS = "'reserved','queued','degraded'"
_RESERVATION_STATES = "'reserved','queued','degraded','reconciled'"
_OUTCOMES = (
    "'succeeded','retry_scheduled','permanent_failure','cancelled',"
    "'privacy_denied','budget_queued','budget_degraded'"
)
_ERROR_CODES = (
    "'authentication','permission','invalid_configuration','unsupported_capability',"
    "'missing_model','oversized_input','rate_limit','quota','timeout','cancellation',"
    "'transient_upstream','malformed_response','dimension_mismatch','model_drift',"
    "'privacy_denial','adapter_crash'"
)
_VERDICTS = "'stable','drifted'"


def upgrade() -> None:
    """Install immutable catalogs/evidence and serialized budget/drift state."""
    _create_operations()
    _create_pricing()
    _create_budgets()
    _create_telemetry()
    _create_drift()
    _create_alerts()
    _create_guards()


def _create_operations() -> None:
    op.create_table(
        "provider_observability_operations",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("operation_kind", sa.Text(), nullable=False),
        sa.Column("target_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("request_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "operation_kind IN ('pricing','budget','canary') "
            "AND length(target_digest)=32 AND length(request_digest)=32 "
            "AND length(scope_fingerprint)=32 AND completed_at>=0 AND schema_version=1",
            name="ck_provider_observability_operation_integrity",
        ),
    )
    _immutable("provider_observability_operations")


def _create_pricing() -> None:
    op.create_table(
        "provider_pricing_snapshots",
        sa.Column("snapshot_id", sa.LargeBinary(32), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("catalog_version", sa.Integer(), nullable=False),
        sa.Column("currency", sa.Text(), nullable=False),
        sa.Column("operation", sa.Text(), nullable=False),
        sa.Column("request_micros", sa.BigInteger(), nullable=False),
        sa.Column("input_micros_per_million", sa.BigInteger(), nullable=False),
        sa.Column("output_micros_per_million", sa.BigInteger(), nullable=False),
        sa.Column("effective_from", sa.BigInteger(), nullable=False),
        sa.Column("effective_until", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["profile_id", "profile_version"],
            ["provider_profile_revisions.profile_id", "provider_profile_revisions.version"],
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.UniqueConstraint(
            "profile_id",
            "profile_version",
            "catalog_version",
            name="uq_provider_pricing_version",
        ),
        sa.CheckConstraint(
            "length(snapshot_id)=32 AND profile_version>=1 AND catalog_version>=1 "
            "AND length(currency)=3 AND currency NOT GLOB '*[^A-Z]*' "
            f"AND operation IN ({_OPERATIONS}) "
            "AND request_micros BETWEEN 0 AND 1000000000000000 "
            "AND input_micros_per_million BETWEEN 0 AND 1000000000000000 "
            "AND output_micros_per_million BETWEEN 0 AND 1000000000000000 "
            "AND effective_from>=0 AND effective_until>effective_from "
            "AND created_at BETWEEN 0 AND effective_from AND schema_version=1",
            name="ck_provider_pricing_integrity",
        ),
    )
    op.create_table(
        "active_provider_pricing",
        sa.Column("profile_id", sa.Text(), primary_key=True),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column(
            "snapshot_id",
            sa.LargeBinary(32),
            sa.ForeignKey("provider_pricing_snapshots.snapshot_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("catalog_version", sa.Integer(), nullable=False),
        sa.Column("pointer_version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "profile_version>=1 AND catalog_version>=1 AND pointer_version>=1 "
            "AND updated_at>=0 AND schema_version=1",
            name="ck_active_provider_pricing_integrity",
        ),
    )
    _immutable("provider_pricing_snapshots")
    _closed_pointer("active_provider_pricing", "catalog_version")


def _create_budgets() -> None:
    op.create_table(
        "provider_budget_policies",
        sa.Column("policy_id", sa.LargeBinary(32), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("currency", sa.Text(), nullable=False),
        sa.Column("limit_micros", sa.BigInteger(), nullable=False),
        sa.Column("behavior", sa.Text(), nullable=False),
        sa.Column("degraded_channels_json", sa.LargeBinary(), nullable=False),
        sa.Column("period_start", sa.BigInteger(), nullable=False),
        sa.Column("period_end", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["profile_id", "profile_version"],
            ["provider_profile_revisions.profile_id", "provider_profile_revisions.version"],
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.UniqueConstraint(
            "profile_id",
            "profile_version",
            "policy_version",
            name="uq_provider_budget_policy_version",
        ),
        sa.CheckConstraint(
            "length(policy_id)=32 AND profile_version>=1 AND policy_version>=1 "
            "AND length(currency)=3 AND currency NOT GLOB '*[^A-Z]*' "
            "AND limit_micros BETWEEN 0 AND 1000000000000000 "
            f"AND behavior IN ({_BUDGET_BEHAVIORS}) "
            "AND json_valid(degraded_channels_json) "
            "AND json_type(degraded_channels_json)='array' "
            "AND period_start>=0 AND period_end>period_start "
            "AND created_at BETWEEN 0 AND period_start AND schema_version=1",
            name="ck_provider_budget_policy_integrity",
        ),
    )
    op.create_table(
        "active_provider_budget_policies",
        sa.Column("profile_id", sa.Text(), primary_key=True),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column(
            "policy_id",
            sa.LargeBinary(32),
            sa.ForeignKey("provider_budget_policies.policy_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("pointer_version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "profile_version>=1 AND policy_version>=1 AND pointer_version>=1 "
            "AND updated_at>=0 AND schema_version=1",
            name="ck_active_provider_budget_integrity",
        ),
    )
    op.create_table(
        "provider_budget_accounts",
        sa.Column(
            "policy_id",
            sa.LargeBinary(32),
            sa.ForeignKey("provider_budget_policies.policy_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("spent_micros", sa.BigInteger(), nullable=False),
        sa.Column("reserved_micros", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "spent_micros BETWEEN 0 AND 1000000000000000 "
            "AND reserved_micros BETWEEN 0 AND 1000000000000000 "
            "AND version>=1 AND updated_at>=0 AND schema_version=1",
            name="ck_provider_budget_account_integrity",
        ),
    )
    op.create_table(
        "provider_budget_reservations",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column(
            "policy_id",
            sa.LargeBinary(32),
            sa.ForeignKey("provider_budget_policies.policy_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "pricing_snapshot_id",
            sa.LargeBinary(32),
            sa.ForeignKey("provider_pricing_snapshots.snapshot_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("request_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("decision", sa.Text(), nullable=False),
        sa.Column("degraded_channels_json", sa.LargeBinary(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("estimated_micros", sa.BigInteger(), nullable=False),
        sa.Column("reserved_micros", sa.BigInteger(), nullable=False),
        sa.Column("actual_micros", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("reconciled_at", sa.BigInteger(), nullable=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "profile_version>=1 AND length(policy_id)=32 "
            "AND length(pricing_snapshot_id)=32 AND length(request_digest)=32 "
            f"AND decision IN ({_BUDGET_DECISIONS}) "
            "AND json_valid(degraded_channels_json) "
            "AND json_type(degraded_channels_json)='array' "
            f"AND state IN ({_RESERVATION_STATES}) "
            "AND estimated_micros BETWEEN 0 AND 1000000000000000 "
            "AND reserved_micros BETWEEN 0 AND estimated_micros "
            "AND ((decision='reserved' AND state IN ('reserved','reconciled') "
            "AND reserved_micros=estimated_micros) "
            "OR (decision<>'reserved' AND state=decision AND reserved_micros=0)) "
            "AND ((state='reconciled' AND actual_micros IS NOT NULL "
            "AND actual_micros BETWEEN 0 AND 1000000000000000 "
            "AND reconciled_at>=created_at) "
            "OR (state<>'reconciled' AND actual_micros IS NULL "
            "AND reconciled_at IS NULL)) AND created_at>=0 AND schema_version=1",
            name="ck_provider_budget_reservation_integrity",
        ),
    )
    _immutable("provider_budget_policies")
    _closed_pointer("active_provider_budget_policies", "policy_version")
    op.execute(
        "CREATE TRIGGER trg_provider_budget_accounts_closed_update "
        "BEFORE UPDATE ON provider_budget_accounts "
        "WHEN OLD.policy_id<>NEW.policy_id OR OLD.schema_version<>NEW.schema_version "
        "OR NEW.version<>OLD.version+1 OR NEW.updated_at<OLD.updated_at "
        "OR NEW.spent_micros<OLD.spent_micros "
        "BEGIN SELECT RAISE(ABORT, 'invalid provider budget account'); END"
    )
    op.execute(
        "CREATE TRIGGER trg_provider_budget_accounts_immutable_delete "
        "BEFORE DELETE ON provider_budget_accounts "
        "BEGIN SELECT RAISE(ABORT, 'immutable provider budget account'); END"
    )
    op.execute(
        "CREATE TRIGGER trg_provider_budget_reservations_closed_update "
        "BEFORE UPDATE ON provider_budget_reservations "
        "WHEN OLD.state<>'reserved' OR NEW.state<>'reconciled' "
        "OR OLD.operation_id<>NEW.operation_id OR OLD.brain_id<>NEW.brain_id "
        "OR OLD.profile_id<>NEW.profile_id "
        "OR OLD.profile_version<>NEW.profile_version "
        "OR OLD.policy_id<>NEW.policy_id "
        "OR OLD.pricing_snapshot_id<>NEW.pricing_snapshot_id "
        "OR OLD.request_digest<>NEW.request_digest OR OLD.decision<>NEW.decision "
        "OR OLD.estimated_micros<>NEW.estimated_micros "
        "OR OLD.reserved_micros<>NEW.reserved_micros "
        "OR OLD.created_at<>NEW.created_at OR OLD.schema_version<>NEW.schema_version "
        "BEGIN SELECT RAISE(ABORT, 'immutable provider budget reservation'); END"
    )
    op.execute(
        "CREATE TRIGGER trg_provider_budget_reservations_immutable_delete "
        "BEFORE DELETE ON provider_budget_reservations "
        "BEGIN SELECT RAISE(ABORT, 'immutable provider budget reservation'); END"
    )


def _create_telemetry() -> None:
    op.create_table(
        "provider_operation_facts",
        sa.Column("fact_digest", sa.LargeBinary(32), primary_key=True),
        sa.Column(
            "operation_id",
            sa.Text(),
            sa.ForeignKey("provider_budget_reservations.operation_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("space_id", sa.Text(), nullable=True),
        sa.Column("generation_id", sa.Text(), nullable=True),
        sa.Column("pricing_snapshot_id", sa.LargeBinary(32), nullable=False),
        sa.Column("operation", sa.Text(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("error_code", sa.Text(), nullable=True),
        sa.Column("request_count", sa.BigInteger(), nullable=False),
        sa.Column("item_count", sa.BigInteger(), nullable=False),
        sa.Column("input_units", sa.BigInteger(), nullable=False),
        sa.Column("output_units", sa.BigInteger(), nullable=False),
        sa.Column("request_bytes", sa.BigInteger(), nullable=False),
        sa.Column("response_bytes", sa.BigInteger(), nullable=False),
        sa.Column("attempt_count", sa.BigInteger(), nullable=False),
        sa.Column("latency_microseconds", sa.BigInteger(), nullable=False),
        sa.Column("estimated_cost_micros", sa.BigInteger(), nullable=False),
        sa.Column("actual_cost_micros", sa.BigInteger(), nullable=False),
        sa.Column("cache_hit", sa.Boolean(), nullable=False),
        sa.Column("deduplicated", sa.Boolean(), nullable=False),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(fact_digest)=32 AND profile_version>=1 "
            "AND ((space_id IS NULL AND generation_id IS NULL) "
            "OR (space_id IS NOT NULL AND generation_id IS NOT NULL)) "
            "AND length(pricing_snapshot_id)=32 "
            f"AND operation IN ({_OPERATIONS}) AND outcome IN ({_OUTCOMES}) "
            f"AND (error_code IS NULL OR error_code IN ({_ERROR_CODES})) "
            "AND ((outcome IN ('retry_scheduled','permanent_failure','cancelled',"
            "'privacy_denied') AND error_code IS NOT NULL) "
            "OR (outcome NOT IN ('retry_scheduled','permanent_failure','cancelled',"
            "'privacy_denied') AND error_code IS NULL)) "
            "AND request_count>=0 AND item_count>=0 AND input_units>=0 "
            "AND output_units>=0 AND request_bytes>=0 AND response_bytes>=0 "
            "AND attempt_count>=0 AND latency_microseconds BETWEEN 0 AND 3600000000 "
            "AND estimated_cost_micros BETWEEN 0 AND 1000000000000000 "
            "AND actual_cost_micros BETWEEN 0 AND 1000000000000000 "
            "AND occurred_at>=0 AND schema_version=1",
            name="ck_provider_operation_fact_integrity",
        ),
    )
    op.create_index(
        "ix_provider_operation_fact_status",
        "provider_operation_facts",
        ["brain_id", "profile_id", "occurred_at"],
    )
    _immutable("provider_operation_facts")


def _create_drift() -> None:
    op.create_table(
        "provider_drift_canaries",
        sa.Column("canary_id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
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
            unique=True,
        ),
        sa.Column("capability_attestation_id", sa.Text(), nullable=False),
        sa.Column("revision_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("canary_set_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("vector_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("canary_item_ids_json", sa.LargeBinary(), nullable=False),
        sa.Column("norms_json", sa.LargeBinary(), nullable=False),
        sa.Column("distance_order_json", sa.LargeBinary(), nullable=False),
        sa.Column("norm_tolerance_ppm", sa.Integer(), nullable=False),
        sa.Column("maximum_order_inversions", sa.Integer(), nullable=False),
        sa.Column("interval_microseconds", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["profile_id", "profile_version"],
            ["provider_profile_revisions.profile_id", "provider_profile_revisions.version"],
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.CheckConstraint(
            "profile_version>=1 AND length(revision_fingerprint)=32 "
            "AND length(canary_set_digest)=32 AND length(vector_fingerprint)=32 "
            "AND json_valid(canary_item_ids_json) "
            "AND json_type(canary_item_ids_json)='array' "
            "AND json_valid(norms_json) AND json_type(norms_json)='array' "
            "AND json_array_length(norms_json) BETWEEN 2 AND 100 "
            "AND json_array_length(canary_item_ids_json)=json_array_length(norms_json) "
            "AND json_valid(distance_order_json) "
            "AND json_type(distance_order_json)='array' "
            "AND json_array_length(distance_order_json)=json_array_length(norms_json) "
            "AND norm_tolerance_ppm BETWEEN 0 AND 1000000 "
            "AND maximum_order_inversions>=0 AND interval_microseconds>=1 "
            "AND created_at>=0 AND schema_version=1",
            name="ck_provider_drift_canary_integrity",
        ),
    )
    op.create_table(
        "provider_drift_probe_state",
        sa.Column(
            "canary_id",
            sa.Text(),
            sa.ForeignKey("provider_drift_canaries.canary_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("next_probe_at", sa.BigInteger(), nullable=False),
        sa.Column("lease_owner", sa.Text(), nullable=True),
        sa.Column("lease_until", sa.BigInteger(), nullable=True),
        sa.Column("last_observation_digest", sa.LargeBinary(32), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "state IN ('active','suspended') AND next_probe_at>=0 AND version>=1 "
            "AND ((lease_owner IS NULL AND lease_until IS NULL) "
            "OR (state='active' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL)) "
            "AND (last_observation_digest IS NULL OR length(last_observation_digest)=32) "
            "AND updated_at>=0 AND schema_version=1",
            name="ck_provider_drift_probe_state_integrity",
        ),
    )
    op.create_index(
        "ix_provider_drift_probe_due",
        "provider_drift_probe_state",
        ["state", "next_probe_at", "lease_until"],
    )
    op.create_table(
        "provider_drift_observations",
        sa.Column("observation_digest", sa.LargeBinary(32), primary_key=True),
        sa.Column(
            "canary_id",
            sa.Text(),
            sa.ForeignKey("provider_drift_canaries.canary_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("revision_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("vector_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("canary_item_ids_json", sa.LargeBinary(), nullable=False),
        sa.Column("norms_json", sa.LargeBinary(), nullable=False),
        sa.Column("distance_order_json", sa.LargeBinary(), nullable=False),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("reason_code", sa.Text(), nullable=True),
        sa.Column("observed_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(observation_digest)=32 AND length(revision_fingerprint)=32 "
            "AND length(vector_fingerprint)=32 AND json_valid(canary_item_ids_json) "
            "AND json_valid(norms_json) "
            "AND json_valid(distance_order_json) "
            f"AND verdict IN ({_VERDICTS}) "
            "AND ((verdict='stable' AND reason_code IS NULL) "
            "OR (verdict='drifted' AND length(reason_code) BETWEEN 1 AND 64)) "
            "AND observed_at>=0 AND schema_version=1",
            name="ck_provider_drift_observation_integrity",
        ),
    )
    op.create_table(
        "provider_generation_write_suspensions",
        sa.Column(
            "generation_id",
            sa.Text(),
            sa.ForeignKey("embedding_index_generations.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "space_id",
            sa.Text(),
            sa.ForeignKey("embedding_spaces.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "observation_digest",
            sa.LargeBinary(32),
            sa.ForeignKey(
                "provider_drift_observations.observation_digest",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("reason_code", sa.Text(), nullable=False),
        sa.Column("suspended_at", sa.BigInteger(), nullable=False),
        sa.Column("requires_new_space", sa.Boolean(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(observation_digest)=32 AND length(reason_code) BETWEEN 1 AND 64 "
            "AND requires_new_space=1 AND suspended_at>=0 AND schema_version=1",
            name="ck_provider_generation_suspension_integrity",
        ),
    )
    _immutable("provider_drift_canaries")
    _immutable("provider_drift_observations")
    _immutable("provider_generation_write_suspensions")
    op.execute(
        "CREATE TRIGGER trg_provider_drift_probe_state_closed_update "
        "BEFORE UPDATE ON provider_drift_probe_state "
        "WHEN OLD.canary_id<>NEW.canary_id OR OLD.schema_version<>NEW.schema_version "
        "OR NEW.version<>OLD.version+1 OR NEW.updated_at<OLD.updated_at "
        "OR (OLD.state='suspended' AND NEW.state<>'suspended') "
        "BEGIN SELECT RAISE(ABORT, 'invalid provider drift probe state'); END"
    )
    op.execute(
        "CREATE TRIGGER trg_provider_drift_probe_state_immutable_delete "
        "BEFORE DELETE ON provider_drift_probe_state "
        "BEGIN SELECT RAISE(ABORT, 'immutable provider drift probe state'); END"
    )


def _create_alerts() -> None:
    op.create_table(
        "provider_observability_alerts",
        sa.Column("alert_digest", sa.LargeBinary(32), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column("generation_id", sa.Text(), nullable=True),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("code", sa.Text(), nullable=False),
        sa.Column("evidence_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "severity IN ('warning','critical') AND length(code) BETWEEN 1 AND 64 "
            "AND length(evidence_digest)=32 AND created_at>=0 "
            "AND state='active' AND schema_version=1",
            name="ck_provider_observability_alert_integrity",
        ),
    )
    _immutable("provider_observability_alerts")


def _create_guards() -> None:
    op.execute(
        "CREATE TRIGGER trg_provider_work_items_drift_write_guard "
        "BEFORE INSERT ON provider_work_items "
        "WHEN NEW.purpose IN ('retrieval_document','code_document') "
        "AND EXISTS ("
        "SELECT 1 FROM active_embedding_generations a "
        "JOIN provider_generation_write_suspensions s "
        "ON s.generation_id=a.generation_id "
        "WHERE a.brain_id=NEW.brain_id AND a.space_id=NEW.space_id "
        "AND a.purpose=NEW.purpose"
        ") BEGIN SELECT RAISE(ABORT, 'provider generation write suspended'); END"
    )


def _immutable(table: str) -> None:
    for operation in ("UPDATE", "DELETE"):
        op.execute(
            f"CREATE TRIGGER trg_{table}_immutable_{operation.lower()} "
            f"BEFORE {operation} ON {table} "
            "BEGIN SELECT RAISE(ABORT, 'immutable provider observability evidence'); END"
        )


def _closed_pointer(table: str, authority_version: str) -> None:
    op.execute(
        f"CREATE TRIGGER trg_{table}_closed_update BEFORE UPDATE ON {table} "
        "WHEN OLD.profile_id<>NEW.profile_id OR OLD.schema_version<>NEW.schema_version "
        "OR NEW.pointer_version<>OLD.pointer_version+1 "
        f"OR NEW.{authority_version}<>OLD.{authority_version}+1 "
        "OR NEW.updated_at<OLD.updated_at "
        "BEGIN SELECT RAISE(ABORT, 'invalid provider observability pointer'); END"
    )
    op.execute(
        f"CREATE TRIGGER trg_{table}_immutable_delete BEFORE DELETE ON {table} "
        "BEGIN SELECT RAISE(ABORT, 'immutable provider observability pointer'); END"
    )


def downgrade() -> None:
    """Refuse to destroy any provider observability authority or evidence."""
    connection = op.get_bind()
    count_statements = (
        "SELECT COUNT(*) FROM provider_pricing_snapshots",
        "SELECT COUNT(*) FROM provider_budget_policies",
        "SELECT COUNT(*) FROM provider_budget_reservations",
        "SELECT COUNT(*) FROM provider_operation_facts",
        "SELECT COUNT(*) FROM provider_drift_canaries",
        "SELECT COUNT(*) FROM provider_drift_observations",
        "SELECT COUNT(*) FROM provider_generation_write_suspensions",
        "SELECT COUNT(*) FROM provider_observability_alerts",
        "SELECT COUNT(*) FROM provider_observability_operations",
    )
    count = sum(
        int(connection.execute(sa.text(statement)).scalar_one()) for statement in count_statements
    )
    if count:
        message = "PRO-010 downgrade refused while provider observability history exists"
        raise RuntimeError(message)

    op.execute("DROP TRIGGER IF EXISTS trg_provider_work_items_drift_write_guard")
    op.drop_table("provider_observability_alerts")
    op.drop_table("provider_generation_write_suspensions")
    op.drop_table("provider_drift_observations")
    op.drop_index("ix_provider_drift_probe_due", table_name="provider_drift_probe_state")
    op.drop_table("provider_drift_probe_state")
    op.drop_table("provider_drift_canaries")
    op.drop_index("ix_provider_operation_fact_status", table_name="provider_operation_facts")
    op.drop_table("provider_operation_facts")
    op.drop_table("provider_budget_reservations")
    op.drop_table("provider_budget_accounts")
    op.drop_table("active_provider_budget_policies")
    op.drop_table("provider_budget_policies")
    op.drop_table("active_provider_pricing")
    op.drop_table("provider_pricing_snapshots")
    op.drop_table("provider_observability_operations")
