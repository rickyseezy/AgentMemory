"""IDX-001 immutable source snapshots and semantic code evidence.

Revision ID: 0026_idx001_code_entities
Revises: 0025_gra006_graph_integrity
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op

if TYPE_CHECKING:
    from sqlalchemy.sql.schema import SchemaItem

revision = "0026_idx001_code_entities"
down_revision = "0025_gra006_graph_integrity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Install append-only source, symbol, occurrence, and parser evidence tables."""
    op.create_table(
        "source_snapshots",
        sa.Column("id", sa.Text(), primary_key=True),
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
            "principal_id",
            sa.Text(),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("scope_fingerprint", sa.LargeBinary(32), nullable=False),
        sa.Column("commit_id", sa.Text(), nullable=True),
        sa.Column("working_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(id)=64 AND length(working_digest)=32 AND length(scope_fingerprint)=32",
            name="ck_source_snapshot_digests",
        ),
        sa.CheckConstraint(
            "length(operation_id) BETWEEN 1 AND 128",
            name="ck_source_snapshot_operation",
        ),
    )
    op.create_index(
        "ix_source_snapshots_scope",
        "source_snapshots",
        ["brain_id", "project_id", "repository_id", "created_at"],
    )
    op.create_table(
        "source_files",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.UniqueConstraint("repository_id", "relative_path", name="uq_source_file_path"),
        sa.CheckConstraint(
            "length(id)=64 AND length(relative_path) BETWEEN 1 AND 4096",
            name="ck_source_file_identity",
        ),
    )
    op.create_table(
        "file_revisions",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "file_id",
            sa.Text(),
            sa.ForeignKey("source_files.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "snapshot_id",
            sa.Text(),
            sa.ForeignKey("source_snapshots.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("content_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("byte_length", sa.BigInteger(), nullable=False),
        sa.Column("language", sa.Text(), nullable=False),
        sa.Column("language_tier", sa.Text(), nullable=False),
        sa.Column("parser_version", sa.Text(), nullable=False),
        sa.Column("grammar_revision", sa.Text(), nullable=False),
        sa.Column("query_pack_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("error_count", sa.Integer(), nullable=False),
        sa.UniqueConstraint("file_id", "snapshot_id", name="uq_file_revision_snapshot"),
        sa.CheckConstraint(
            "length(id)=64 AND length(content_digest)=32 AND length(query_pack_digest)=32",
            name="ck_file_revision_digests",
        ),
        sa.CheckConstraint("byte_length>=0 AND error_count>=0", name="ck_file_revision_counts"),
        sa.CheckConstraint(
            "language_tier IN ('precise','structural','lexical')", name="ck_file_revision_tier"
        ),
        sa.CheckConstraint(
            "status IN ('succeeded','recovered','failed','lexical_only')",
            name="ck_file_revision_status",
        ),
        sa.CheckConstraint(
            "(status='succeeded' AND error_count=0) OR "
            "(status IN ('recovered','failed') AND error_count>=1) OR "
            "status='lexical_only'",
            name="ck_file_revision_parse_state",
        ),
    )
    op.create_index(
        "ix_file_revisions_snapshot", "file_revisions", ["snapshot_id", "language", "status"]
    )
    op.create_table(
        "code_symbols",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "repository_id",
            sa.Text(),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("stable_key", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.UniqueConstraint("repository_id", "stable_key", name="uq_code_symbol_stable_key"),
        sa.CheckConstraint(
            "length(id)=64 AND length(stable_key) BETWEEN 1 AND 2048 "
            "AND length(display_name) BETWEEN 1 AND 512",
            name="ck_code_symbol_identity",
        ),
    )
    op.create_index(
        "ix_code_symbols_name", "code_symbols", ["repository_id", "display_name", "kind"]
    )
    _create_semantic_table("symbol_revisions", include_role=False)
    _create_semantic_table("symbol_occurrences", include_role=True)
    op.create_table(
        "parse_failures",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "file_revision_id",
            sa.Text(),
            sa.ForeignKey("file_revisions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("language", sa.Text(), nullable=False),
        sa.Column("parser_version", sa.Text(), nullable=False),
        sa.Column("error_code", sa.Text(), nullable=False),
        sa.Column("recoverable", sa.Boolean(), nullable=False),
        sa.UniqueConstraint("file_revision_id", "error_code", name="uq_parse_failure_code"),
        sa.CheckConstraint("length(id)=64", name="ck_parse_failure_id"),
    )
    for table in (
        "source_snapshots",
        "source_files",
        "file_revisions",
        "code_symbols",
        "symbol_revisions",
        "symbol_occurrences",
        "parse_failures",
    ):
        op.execute(
            f"CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} BEGIN "
            f"SELECT RAISE(ABORT, '{table} is immutable'); END"
        )
        op.execute(
            f"CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN "
            f"SELECT RAISE(ABORT, '{table} is immutable'); END"
        )


def _create_semantic_table(name: str, *, include_role: bool) -> None:
    columns: list[SchemaItem] = [
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "file_revision_id",
            sa.Text(),
            sa.ForeignKey("file_revisions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "symbol_id",
            sa.Text(),
            sa.ForeignKey("code_symbols.id", ondelete="RESTRICT"),
            nullable=False,
        ),
    ]
    if include_role:
        columns.append(sa.Column("role", sa.Text(), nullable=False))
    columns.extend(
        [
            sa.Column("start_byte", sa.BigInteger(), nullable=False),
            sa.Column("end_byte", sa.BigInteger(), nullable=False),
            sa.Column("start_line", sa.Integer(), nullable=False),
            sa.Column("start_column", sa.Integer(), nullable=False),
            sa.Column("end_line", sa.Integer(), nullable=False),
            sa.Column("end_column", sa.Integer(), nullable=False),
            sa.Column("source", sa.Text(), nullable=False),
            sa.Column("priority", sa.Integer(), nullable=False),
            sa.Column("source_identity", sa.Text(), nullable=False),
            sa.CheckConstraint(
                "start_byte>=0 AND end_byte>=start_byte AND start_line>=0 "
                "AND start_column>=0 AND end_line>=start_line AND end_column>=0",
                name=f"ck_{name}_span",
            ),
            sa.CheckConstraint(
                "source IN ('lexical','tree_sitter','scip','compiler') "
                "AND priority IN (10,100,300,400)",
                name=f"ck_{name}_source",
            ),
        ]
    )
    if include_role:
        columns.append(
            sa.CheckConstraint(
                "role IN ('definition','reference','call','inheritance','implementation','import')",
                name="ck_symbol_occurrence_role",
            )
        )
    op.create_table(name, *columns)
    op.create_index(f"ix_{name}_file_span", name, ["file_revision_id", "start_byte", "priority"])


def downgrade() -> None:
    """Refuse to erase any source or semantic history."""
    connection = op.get_bind()
    if connection.execute(sa.text("SELECT EXISTS(SELECT 1 FROM source_snapshots)")).scalar_one():
        message = "IDX-001 source history prevents destructive downgrade"
        raise RuntimeError(message)
    for table in (
        "parse_failures",
        "symbol_occurrences",
        "symbol_revisions",
        "code_symbols",
        "file_revisions",
        "source_files",
        "source_snapshots",
    ):
        op.drop_table(table)
