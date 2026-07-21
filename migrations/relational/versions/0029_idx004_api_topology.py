"""IDX-004 deterministic API topology candidates, matching, and assertion receipts.

Revision ID: 0029_idx004_api_topology
Revises: 0028_idx003_revision_history
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op

if TYPE_CHECKING:
    from sqlalchemy.schema import SchemaItem

revision = "0029_idx004_api_topology"
down_revision = "0028_idx003_revision_history"
branch_labels = None
depends_on = None

_CLASSIFICATIONS = "'public','internal','confidential','restricted','local_only'"
_PROTOCOLS = "'rest','graphql','grpc'"


def upgrade() -> None:
    """Install append-only candidate batches, decisions, matches, and assertion receipts."""
    _create_batches()
    _create_candidates()
    _create_decisions()
    for table in _TABLES:
        _immutable(table)


def _create_batches() -> None:
    op.create_table(
        "api_topology_candidate_batches",
        sa.Column("batch_id", sa.Text(), primary_key=True),
        sa.Column("operation_id", sa.Text(), nullable=False, unique=True),
        sa.Column(
            "brain_id", sa.Text(), sa.ForeignKey("brains.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "project_id",
            sa.Text(),
            sa.ForeignKey("projects.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "source_file_id",
            sa.Text(),
            sa.ForeignKey("source_files.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "source_revision_context_id",
            sa.Text(),
            sa.ForeignKey("source_revision_contexts.context_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("commit_sha", sa.Text(), nullable=False),
        sa.Column("plugin_kind", sa.Text(), nullable=False),
        sa.Column("plugin_version", sa.Text(), nullable=False),
        sa.Column("batch_digest", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("supersedes_batch_id", sa.Text(), nullable=True),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("registered_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["supersedes_batch_id"],
            ["api_topology_candidate_batches.batch_id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(batch_id)=64 AND length(batch_digest)=32 AND length(scope_fingerprint)=32",
            name="ck_api_topology_batch_digests",
        ),
        sa.CheckConstraint(
            "plugin_kind IN ('openapi','graphql','protobuf','source_calls')",
            name="ck_api_topology_batch_plugin",
        ),
        sa.CheckConstraint(
            "length(commit_sha) IN (40,64) AND commit_sha NOT GLOB '*[^0-9a-f]*'",
            name="ck_api_topology_batch_commit",
        ),
    )
    op.create_index(
        "ix_api_topology_latest_source",
        "api_topology_candidate_batches",
        ["brain_id", "repository_id", "source_file_id", "registered_at", "batch_id"],
    )


def _evidence_columns() -> tuple[SchemaItem, ...]:
    return (
        sa.Column(
            "evidence_id",
            sa.Text(),
            sa.ForeignKey("assertion_evidence_sources.evidence_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "source_semantic_id",
            sa.Text(),
            nullable=False,
        ),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("observed_at", sa.BigInteger(), nullable=False),
    )


def _candidate_root(table: str) -> tuple[SchemaItem, ...]:
    return (
        sa.Column("candidate_id", sa.Text(), primary_key=True),
        sa.Column(
            "batch_id",
            sa.Text(),
            sa.ForeignKey("api_topology_candidate_batches.batch_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        *_evidence_columns(),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            f"length(candidate_id)=64 AND classification IN ({_CLASSIFICATIONS}) "
            "AND length(relative_path) BETWEEN 1 AND 4096",
            name=f"ck_{table}_identity",
        ),
    )


def _create_candidates() -> None:
    op.create_table(
        "api_topology_endpoint_candidates",
        *_candidate_root("api_topology_endpoint"),
        sa.Column("endpoint_entity_id", sa.Text(), nullable=False),
        sa.Column("protocol", sa.Text(), nullable=False),
        sa.Column("service_name", sa.Text(), nullable=False),
        sa.Column("transport_operation", sa.Text(), nullable=False),
        sa.Column("route_template", sa.Text(), nullable=False),
        sa.Column("contract_operation_id", sa.Text(), nullable=True),
        sa.Column("dynamic", sa.Boolean(), nullable=False),
        sa.CheckConstraint(f"protocol IN ({_PROTOCOLS})", name="ck_api_endpoint_protocol"),
    )
    op.create_index(
        "ix_api_endpoint_match",
        "api_topology_endpoint_candidates",
        ["protocol", "contract_operation_id", "service_name", "transport_operation"],
    )
    op.create_table(
        "api_topology_client_call_candidates",
        *_candidate_root("api_topology_client_call"),
        sa.Column("consumer_entity_id", sa.Text(), nullable=False),
        sa.Column("protocol", sa.Text(), nullable=False),
        sa.Column("transport_operation", sa.Text(), nullable=False),
        sa.Column("route_template", sa.Text(), nullable=False),
        sa.Column("contract_operation_id", sa.Text(), nullable=True),
        sa.Column("generated_client_symbol", sa.Text(), nullable=True),
        sa.Column("service_reference", sa.Text(), nullable=True),
        sa.Column("base_url_reference", sa.Text(), nullable=True),
        sa.Column("dynamic", sa.Boolean(), nullable=False),
        sa.CheckConstraint(f"protocol IN ({_PROTOCOLS})", name="ck_api_client_protocol"),
    )
    op.create_table(
        "api_topology_contract_binding_candidates",
        *_candidate_root("api_topology_contract_binding"),
        sa.Column("protocol", sa.Text(), nullable=False),
        sa.Column("contract_operation_id", sa.Text(), nullable=False),
        sa.Column("service_name", sa.Text(), nullable=False),
        sa.Column("transport_operation", sa.Text(), nullable=False),
        sa.Column("route_template", sa.Text(), nullable=False),
        sa.Column("generated_client_symbols_json", sa.LargeBinary(), nullable=False),
        sa.CheckConstraint(f"protocol IN ({_PROTOCOLS})", name="ck_api_contract_protocol"),
        sa.CheckConstraint(
            "json_valid(generated_client_symbols_json) AND "
            "json_type(generated_client_symbols_json)='array'",
            name="ck_api_contract_symbols",
        ),
    )
    op.create_index(
        "ix_api_contract_match",
        "api_topology_contract_binding_candidates",
        ["protocol", "contract_operation_id", "service_name"],
    )
    op.create_table(
        "api_topology_service_ownership_candidates",
        *_candidate_root("api_topology_service_ownership"),
        sa.Column("service_name", sa.Text(), nullable=False),
        sa.Column("aliases_json", sa.LargeBinary(), nullable=False),
        sa.Column("base_url_references_json", sa.LargeBinary(), nullable=False),
        sa.Column("gateway_prefixes_json", sa.LargeBinary(), nullable=False),
        sa.CheckConstraint(
            "json_valid(aliases_json) AND json_type(aliases_json)='array' AND "
            "json_valid(base_url_references_json) AND "
            "json_type(base_url_references_json)='array' AND "
            "json_valid(gateway_prefixes_json) AND json_type(gateway_prefixes_json)='array'",
            name="ck_api_ownership_arrays",
        ),
    )
    op.create_index(
        "ix_api_ownership_match",
        "api_topology_service_ownership_candidates",
        ["service_name", "candidate_id"],
    )


def _create_decisions() -> None:
    op.create_table(
        "api_topology_link_operations",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column("brain_id", sa.Text(), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column(
            "client_call_id",
            sa.Text(),
            sa.ForeignKey("api_topology_client_call_candidates.candidate_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("candidate_universe_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("decision_digest", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column("match_count", sa.Integer(), nullable=False),
        sa.Column("linked_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(scope_fingerprint)=32 AND length(candidate_universe_digest)=32 "
            "AND length(decision_digest)=32 AND match_count BETWEEN 0 AND 100000",
            name="ck_api_link_operation",
        ),
    )
    op.create_table(
        "api_topology_match_decisions",
        sa.Column("match_id", sa.Text(), primary_key=True),
        sa.Column(
            "operation_id",
            sa.Text(),
            sa.ForeignKey("api_topology_link_operations.operation_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "client_call_id",
            sa.Text(),
            sa.ForeignKey("api_topology_client_call_candidates.candidate_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.Column("endpoint_id", sa.Text(), nullable=False),
        sa.Column("client_entity_id", sa.Text(), nullable=False),
        sa.Column("endpoint_entity_id", sa.Text(), nullable=False),
        sa.Column("rule", sa.Text(), nullable=False),
        sa.Column("rule_version", sa.Text(), nullable=False),
        sa.Column("disposition", sa.Text(), nullable=False),
        sa.Column("confidence_basis_points", sa.Integer(), nullable=False),
        sa.Column("client_evidence_id", sa.Text(), nullable=False),
        sa.Column("server_evidence_id", sa.Text(), nullable=False),
        sa.Column("supporting_candidate_ids_json", sa.LargeBinary(), nullable=False),
        sa.Column("supporting_evidence_ids_json", sa.LargeBinary(), nullable=False),
        sa.Column("qualification_codes_json", sa.LargeBinary(), nullable=False),
        sa.Column("assertion_id", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["endpoint_id"],
            ["api_topology_endpoint_candidates.candidate_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["assertion_id"], ["assertion_candidates.assertion_id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint("operation_id", "rank", name="uq_api_topology_match_rank"),
        sa.CheckConstraint(
            "length(match_id)=64 AND rank BETWEEN 1 AND 100000 "
            "AND confidence_basis_points BETWEEN 0 AND 10000",
            name="ck_api_match_identity",
        ),
        sa.CheckConstraint(
            "rule IN ('contract_operation','generated_client_symbol','service_base_url',"
            "'heuristic_path') AND disposition IN ('confirmed','qualified')",
            name="ck_api_match_rule",
        ),
        sa.CheckConstraint(
            "json_valid(supporting_candidate_ids_json) AND "
            "json_type(supporting_candidate_ids_json)='array' AND "
            "json_valid(supporting_evidence_ids_json) AND "
            "json_type(supporting_evidence_ids_json)='array' AND "
            "json_valid(qualification_codes_json) AND "
            "json_type(qualification_codes_json)='array'",
            name="ck_api_match_arrays",
        ),
    )


_TABLES = (
    "api_topology_candidate_batches",
    "api_topology_endpoint_candidates",
    "api_topology_client_call_candidates",
    "api_topology_contract_binding_candidates",
    "api_topology_service_ownership_candidates",
    "api_topology_link_operations",
    "api_topology_match_decisions",
)


def _immutable(table: str) -> None:
    op.execute(
        f"CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} BEGIN "
        f"SELECT RAISE(ABORT, '{table} is immutable'); END"
    )
    op.execute(
        f"CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN "
        f"SELECT RAISE(ABORT, '{table} is immutable'); END"
    )


def downgrade() -> None:
    """Refuse to erase any API topology source or decision evidence."""
    connection = op.get_bind()
    if any(
        connection.execute(  # nosec B608 -- Closed migration-owned table tuple.
            sa.text(f"SELECT EXISTS(SELECT 1 FROM {table})")  # noqa: S608
        ).scalar_one()
        for table in _TABLES
    ):
        message = "IDX-004 API topology history prevents destructive downgrade"
        raise RuntimeError(message)
    op.drop_index("ix_api_ownership_match", table_name="api_topology_service_ownership_candidates")
    op.drop_index("ix_api_contract_match", table_name="api_topology_contract_binding_candidates")
    op.drop_index("ix_api_endpoint_match", table_name="api_topology_endpoint_candidates")
    op.drop_index("ix_api_topology_latest_source", table_name="api_topology_candidate_batches")
    for table in reversed(_TABLES):
        op.drop_table(table)
