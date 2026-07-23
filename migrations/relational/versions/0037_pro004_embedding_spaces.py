"""PRO-004 immutable embedding spaces and dedicated index generations.

Revision ID: 0037_pro004_embedding_spaces
Revises: 0036_pro003_capability_attestations
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0037_pro004_embedding_spaces"
down_revision = "0036_pro003_capability_attestations"
branch_labels = None
depends_on = None

_DTYPES = "'float16','float32','float64'"
_NORMALIZATIONS = "'none','l2','provider_defined'"
_SIMILARITIES = "'cosine','euclidean'"
_PURPOSES = (
    "'retrieval_query','retrieval_document','code_query','code_document',"
    "'semantic_similarity','classification','clustering'"
)
_STATES = (
    "'creating','populating','validating','shadow_ready','active',"
    "'rollback_ready','retired','failed'"
)


def upgrade() -> None:
    """Install the immutable semantic authority and recoverable generation journal."""
    op.create_table(
        "embedding_spaces",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("immutable_fingerprint", sa.Text(), nullable=False),
        sa.Column(
            "profile_id",
            sa.Text(),
            sa.ForeignKey("provider_profiles.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "capability_attestation_id",
            sa.Text(),
            sa.ForeignKey(
                "provider_capability_attestations.attestation_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("descriptor_json", sa.LargeBinary(), nullable=False),
        sa.Column("adapter_digest", sa.Text(), nullable=False),
        sa.Column("model_revision", sa.Text(), nullable=True),
        sa.Column("dimension", sa.Integer(), nullable=False),
        sa.Column("dtype", sa.Text(), nullable=False),
        sa.Column("normalization", sa.Text(), nullable=False),
        sa.Column("similarity", sa.Text(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(immutable_fingerprint)=64 "
            "AND immutable_fingerprint NOT GLOB '*[^0-9a-f]*' "
            "AND length(adapter_digest)=64 AND adapter_digest NOT GLOB '*[^0-9a-f]*' "
            "AND dimension BETWEEN 1 AND 4096 "
            f"AND dtype IN ({_DTYPES}) "
            f"AND normalization IN ({_NORMALIZATIONS}) "
            f"AND similarity IN ({_SIMILARITIES}) "
            f"AND purpose IN ({_PURPOSES}) "
            "AND json_valid(descriptor_json) AND json_type(descriptor_json)='object' "
            "AND schema_version=1",
            name="ck_embedding_space_integrity",
        ),
    )
    op.create_index(
        "uq_embedding_space_brain_fingerprint",
        "embedding_spaces",
        ["brain_id", "immutable_fingerprint"],
        unique=True,
    )
    op.create_table(
        "embedding_index_generations",
        sa.Column("id", sa.Text(), primary_key=True),
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
        sa.Column("space_fingerprint", sa.Text(), nullable=False),
        sa.Column("generated_label", sa.Text(), nullable=False),
        sa.Column("vector_index_name", sa.Text(), nullable=False),
        sa.Column(
            "vector_property",
            sa.Text(),
            nullable=False,
            server_default="embedding",
        ),
        sa.Column("dimension", sa.Integer(), nullable=False),
        sa.Column("similarity", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(space_fingerprint)=64 "
            "AND space_fingerprint NOT GLOB '*[^0-9a-f]*' "
            "AND length(generated_label)=41 AND substr(generated_label,1,9)='AMVector_' "
            "AND substr(generated_label,10) NOT GLOB '*[^0-9a-f]*' "
            "AND length(vector_index_name)=39 "
            "AND substr(vector_index_name,1,7)='am_vec_' "
            "AND substr(vector_index_name,8) NOT GLOB '*[^0-9a-f]*' "
            "AND vector_property='embedding' "
            "AND dimension BETWEEN 1 AND 4096 "
            f"AND similarity IN ({_SIMILARITIES}) "
            f"AND state IN ({_STATES}) "
            "AND updated_at>=created_at AND version>=1 AND schema_version=1",
            name="ck_embedding_generation_integrity",
        ),
    )
    op.create_index(
        "uq_embedding_generation_brain_space",
        "embedding_index_generations",
        ["brain_id", "space_id"],
        unique=True,
    )
    op.create_index(
        "uq_embedding_generation_label",
        "embedding_index_generations",
        ["generated_label"],
        unique=True,
    )
    op.create_index(
        "uq_embedding_generation_vector_index",
        "embedding_index_generations",
        ["vector_index_name"],
        unique=True,
    )
    op.create_table(
        "embedding_generation_operations",
        sa.Column("operation_id", sa.Text(), primary_key=True),
        sa.Column(
            "brain_id",
            sa.Text(),
            sa.ForeignKey("brains.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("request_digest", sa.Text(), nullable=False),
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
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("completed_at", sa.BigInteger(), nullable=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "length(request_digest)=64 AND request_digest NOT GLOB '*[^0-9a-f]*' "
            "AND status IN ('reserved','complete') "
            "AND ((status='reserved' AND completed_at IS NULL) "
            "OR (status='complete' AND completed_at>=created_at)) "
            "AND schema_version=1",
            name="ck_embedding_generation_operation_integrity",
        ),
    )
    op.create_index(
        "ix_embedding_generation_operation_result",
        "embedding_generation_operations",
        ["brain_id", "space_id", "generation_id"],
    )
    _immutable("embedding_spaces")
    op.execute(
        "CREATE TRIGGER trg_embedding_index_generations_immutable_delete "
        "BEFORE DELETE ON embedding_index_generations "
        "BEGIN SELECT RAISE(ABORT, 'immutable embedding generation'); END"
    )
    op.execute(
        "CREATE TRIGGER trg_embedding_index_generations_closed_update "
        "BEFORE UPDATE ON embedding_index_generations "
        "WHEN OLD.id<>NEW.id OR OLD.brain_id<>NEW.brain_id OR OLD.space_id<>NEW.space_id "
        "OR OLD.space_fingerprint<>NEW.space_fingerprint "
        "OR OLD.generated_label<>NEW.generated_label "
        "OR OLD.vector_index_name<>NEW.vector_index_name "
        "OR OLD.vector_property<>NEW.vector_property OR OLD.dimension<>NEW.dimension "
        "OR OLD.similarity<>NEW.similarity OR OLD.created_at<>NEW.created_at "
        "OR OLD.schema_version<>NEW.schema_version OR NEW.version<>OLD.version+1 "
        "OR NEW.updated_at<OLD.updated_at "
        "OR NOT ((OLD.state='creating' AND NEW.state IN ('populating','failed')) "
        "OR (OLD.state='populating' AND NEW.state IN ('validating','failed')) "
        "OR (OLD.state='validating' AND NEW.state IN ('shadow_ready','failed')) "
        "OR (OLD.state='shadow_ready' AND NEW.state IN ('active','failed')) "
        "OR (OLD.state='active' AND NEW.state='rollback_ready') "
        "OR (OLD.state='rollback_ready' AND NEW.state IN ('active','retired'))) "
        "BEGIN SELECT RAISE(ABORT, 'immutable embedding generation'); END"
    )
    op.execute(
        "CREATE TRIGGER trg_embedding_generation_operations_immutable_delete "
        "BEFORE DELETE ON embedding_generation_operations "
        "BEGIN SELECT RAISE(ABORT, 'immutable embedding generation operation'); END"
    )
    op.execute(
        "CREATE TRIGGER trg_embedding_generation_operations_closed_update "
        "BEFORE UPDATE ON embedding_generation_operations "
        "WHEN OLD.status<>'reserved' OR NEW.status<>'complete' "
        "OR OLD.operation_id<>NEW.operation_id OR OLD.brain_id<>NEW.brain_id "
        "OR OLD.request_digest<>NEW.request_digest OR OLD.space_id<>NEW.space_id "
        "OR OLD.generation_id<>NEW.generation_id OR OLD.created_at<>NEW.created_at "
        "OR OLD.schema_version<>NEW.schema_version OR NEW.completed_at IS NULL "
        "BEGIN SELECT RAISE(ABORT, 'immutable embedding generation operation'); END"
    )


def _immutable(table: str) -> None:
    for operation in ("UPDATE", "DELETE"):
        op.execute(
            f"CREATE TRIGGER trg_{table}_immutable_{operation.lower()} "
            f"BEFORE {operation} ON {table} "
            "BEGIN SELECT RAISE(ABORT, 'immutable embedding space'); END"
        )


def downgrade() -> None:
    """Refuse to destroy semantic identity or physical generation history."""
    connection = op.get_bind()
    count = connection.execute(sa.text("SELECT COUNT(*) FROM embedding_spaces")).scalar_one()
    if count:
        message = "PRO-004 downgrade refused while embedding-space history exists"
        raise RuntimeError(message)
    op.execute("DROP TRIGGER IF EXISTS trg_embedding_generation_operations_closed_update")
    op.execute("DROP TRIGGER IF EXISTS trg_embedding_generation_operations_immutable_delete")
    op.execute("DROP TRIGGER IF EXISTS trg_embedding_index_generations_closed_update")
    op.execute("DROP TRIGGER IF EXISTS trg_embedding_index_generations_immutable_delete")
    op.execute("DROP TRIGGER IF EXISTS trg_embedding_spaces_immutable_delete")
    op.execute("DROP TRIGGER IF EXISTS trg_embedding_spaces_immutable_update")
    op.drop_index(
        "ix_embedding_generation_operation_result",
        table_name="embedding_generation_operations",
    )
    op.drop_table("embedding_generation_operations")
    op.drop_index(
        "uq_embedding_generation_vector_index",
        table_name="embedding_index_generations",
    )
    op.drop_index(
        "uq_embedding_generation_label",
        table_name="embedding_index_generations",
    )
    op.drop_index(
        "uq_embedding_generation_brain_space",
        table_name="embedding_index_generations",
    )
    op.drop_table("embedding_index_generations")
    op.drop_index("uq_embedding_space_brain_fingerprint", table_name="embedding_spaces")
    op.drop_table("embedding_spaces")
