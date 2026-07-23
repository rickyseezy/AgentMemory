"""PRO-004 Neo4j generation provisioning and atomic vector-write tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Self, cast

import pytest
from neo4j import Query
from neo4j.exceptions import ServiceUnavailable

from agentmemory.providers.adapters.neo4j_embedding_spaces import (
    Neo4jIndexGenerationProvisioner,
    Neo4jVectorWriteRepository,
)
from agentmemory.providers.domain.embedding_spaces import (
    IndexGenerationState,
    VectorWriteBatch,
)
from agentmemory.providers.domain.errors import (
    EmbeddingSpaceConflictError,
    EmbeddingSpaceDependencyError,
    EmbeddingSpaceValidationError,
)
from tests.core.support import FixedClock
from tests.providers.test_pro004_embedding_spaces_domain import (
    generation,
    record,
    space,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from neo4j import AsyncDriver


@dataclass(slots=True)
class _Result:
    row: dict[str, object] | None

    async def single(self, *, strict: bool = False) -> dict[str, object] | None:
        del strict
        return self.row


@dataclass(slots=True)
class _Transaction:
    driver: _Driver

    async def run(self, query: str | Query, **parameters: object) -> _Result:
        query_text = query.text if isinstance(query, Query) else query
        self.driver.transaction_calls.append((query_text, parameters))
        if "AS binding_count" in query_text:
            return _Result({"binding_count": self.driver.binding_count})
        if "AS source_count" in query_text:
            return _Result({"source_count": self.driver.source_count})
        if "AS compatible_count" in query_text:
            return _Result({"compatible_count": self.driver.compatible_count})
        if "AS written_count" in query_text:
            self.driver.write_calls += 1
            return _Result({"written_count": self.driver.written_count})
        return _Result(None)


@dataclass(slots=True)
class _Session:
    driver: _Driver

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        del args

    async def execute_write(self, callback: object, *args: object) -> object:
        if self.driver.fail:
            message = "unavailable"
            raise ServiceUnavailable(message)
        typed_callback = cast("Callable[..., Awaitable[object]]", callback)
        return await typed_callback(_Transaction(self.driver), *args)


def _calls() -> list[tuple[str, dict[str, object]]]:
    return []


@dataclass(slots=True)
class _Driver:
    exact_index: bool = True
    index_quantization: str = "NONE"
    binding_count: int = 1
    source_count: int = 1
    compatible_count: int = 1
    written_count: int = 1
    fail: bool = False
    write_calls: int = 0
    calls: list[tuple[str, dict[str, object]]] = field(default_factory=_calls)
    transaction_calls: list[tuple[str, dict[str, object]]] = field(default_factory=_calls)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def session(self, **config: object) -> _Session:
        assert config["database"] == "agentmemory"
        return _Session(self)

    async def execute_query(
        self,
        query: str | Query,
        **parameters: object,
    ) -> tuple[list[dict[str, object]], None, None]:
        query_text = query.text if isinstance(query, Query) else query
        self.calls.append((query_text, parameters))
        if self.fail:
            message = "unavailable"
            raise ServiceUnavailable(message)
        if "RETURN space.immutable_fingerprint" in query_text:
            return (
                [
                    {
                        "immutable_fingerprint": parameters["fingerprint"],
                        "space_id": parameters["space_id"],
                        "generation_id": parameters["generation_id"],
                        "generated_label": parameters["generated_label"],
                        "vector_index_name": parameters["vector_index_name"],
                        "dimension": parameters["dimension"],
                        "similarity": parameters["similarity"],
                    }
                ],
                None,
                None,
            )
        if "SHOW VECTOR INDEXES" in query_text:
            dimension = parameters["dimension"] if self.exact_index else 1536
            return (
                [
                    {
                        "name": parameters["index_name"],
                        "state": "ONLINE",
                        "labelsOrTypes": [parameters["generated_label"]],
                        "properties": ["embedding"],
                        "options": {
                            "indexConfig": {
                                "vector.dimensions": dimension,
                                "vector.similarity_function": parameters["similarity"],
                                "vector.quantization.type": self.index_quantization,
                            }
                        },
                    }
                ],
                None,
                None,
            )
        if "SET generation.state='populating'" in query_text:
            return ([{"state": "populating"}], None, None)
        return ([], None, None)


def _driver(value: _Driver) -> AsyncDriver:
    return cast("AsyncDriver", value)


def test_neo4j_adapters_reject_invalid_database_identity() -> None:
    with pytest.raises(ValueError, match="database identity"):
        Neo4jIndexGenerationProvisioner(_driver(_Driver()), "neo4j; DROP DATABASE")


@pytest.mark.asyncio
async def test_generation_provisioner_creates_only_uuid_named_exact_index() -> None:
    driver = _Driver()
    embedding_space = space()
    index_generation = generation(embedding_space, state=IndexGenerationState.CREATING)
    provisioner = Neo4jIndexGenerationProvisioner(_driver(driver), "agentmemory")
    await provisioner.ensure(embedding_space, index_generation)
    create_query = next(query for query, _ in driver.calls if "CREATE VECTOR INDEX" in query)
    assert index_generation.names.vector_index in create_query
    assert index_generation.names.label in create_query
    assert embedding_space.descriptor.model_id not in create_query
    assert f"`vector.dimensions`: {embedding_space.descriptor.dimension}" in create_query
    assert "`vector.similarity_function`: 'cosine'" in create_query
    assert "`vector.quantization.type`: 'none'" in create_query
    metadata_query = next(
        query for query, _ in driver.calls if "RETURN space.immutable_fingerprint" in query
    )
    assert "EmbeddingSpace {brain_id: $brain_id" in metadata_query
    show_parameters = next(
        parameters for query, parameters in driver.calls if "SHOW VECTOR INDEXES" in query
    )
    assert show_parameters["generated_label"] == index_generation.names.label


@pytest.mark.asyncio
async def test_generation_provisioner_rejects_existing_index_contract_drift() -> None:
    embedding_space = space()
    index_generation = generation(embedding_space, state=IndexGenerationState.CREATING)
    with pytest.raises(EmbeddingSpaceConflictError, match="physical index"):
        await Neo4jIndexGenerationProvisioner(
            _driver(_Driver(exact_index=False)),
            "agentmemory",
        ).ensure(embedding_space, index_generation)


@pytest.mark.asyncio
async def test_generation_provisioner_rejects_silent_default_scalar_quantization() -> None:
    embedding_space = space()
    index_generation = generation(embedding_space, state=IndexGenerationState.CREATING)
    with pytest.raises(EmbeddingSpaceConflictError, match="physical index"):
        await Neo4jIndexGenerationProvisioner(
            _driver(_Driver(index_quantization="SCALAR")),
            "agentmemory",
        ).ensure(embedding_space, index_generation)


@pytest.mark.asyncio
async def test_vector_repository_commits_one_preflighted_managed_transaction() -> None:
    driver = _Driver()
    embedding_space = space()
    index_generation = generation(embedding_space)
    batch = VectorWriteBatch.create(
        embedding_space,
        index_generation,
        (record(embedding_space, index_generation),),
    )
    receipt = await Neo4jVectorWriteRepository(
        _driver(driver),
        "agentmemory",
        FixedClock(),
    ).write(batch)
    assert receipt.batch_digest == batch.batch_digest
    assert receipt.record_count == 1
    assert driver.write_calls == 1
    assert len(driver.transaction_calls) == 4
    write_query = driver.transaction_calls[-1][0]
    assert index_generation.names.label in write_query
    assert embedding_space.descriptor.model_id not in write_query
    assert "WITH record, vector" in write_query
    assert "vector.embedding=record.vector" in write_query
    assert "vector.checkout_id IS NULL AND record.checkout_id IS NULL" in write_query
    binding_query = driver.transaction_calls[0][0]
    assert "EmbeddingSpace {brain_id: $brain_id" in binding_query


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"binding_count": 0}, "generation binding"),
        ({"source_count": 0}, "source content"),
        ({"compatible_count": 0}, "existing vector"),
        ({"written_count": 0}, "write cardinality"),
    ],
)
async def test_vector_repository_rolls_back_on_every_preflight_or_cardinality_mismatch(
    change: dict[str, int],
    message: str,
) -> None:
    driver = _Driver(
        binding_count=change.get("binding_count", 1),
        source_count=change.get("source_count", 1),
        compatible_count=change.get("compatible_count", 1),
        written_count=change.get("written_count", 1),
    )
    embedding_space = space()
    index_generation = generation(embedding_space)
    batch = VectorWriteBatch.create(
        embedding_space,
        index_generation,
        (record(embedding_space, index_generation),),
    )
    with pytest.raises(EmbeddingSpaceConflictError, match=message):
        await Neo4jVectorWriteRepository(
            _driver(driver),
            "agentmemory",
            FixedClock(),
        ).write(batch)
    if "written_count" not in change:
        assert driver.write_calls == 0


@pytest.mark.asyncio
async def test_vector_repository_revalidates_batch_before_opening_session() -> None:
    driver = _Driver()
    embedding_space = space()
    index_generation = generation(embedding_space)
    valid = record(embedding_space, index_generation)
    invalid_batch = VectorWriteBatch(
        embedding_space,
        index_generation,
        (replace(valid, vector=(1.0,)),),
    )
    with pytest.raises(EmbeddingSpaceValidationError):
        await Neo4jVectorWriteRepository(
            _driver(driver),
            "agentmemory",
            FixedClock(),
        ).write(invalid_batch)
    assert driver.transaction_calls == []


@pytest.mark.asyncio
async def test_neo4j_dependency_failures_are_typed_and_content_free() -> None:
    embedding_space = space()
    index_generation = generation(embedding_space)
    batch = VectorWriteBatch.create(
        embedding_space,
        index_generation,
        (record(embedding_space, index_generation),),
    )
    with pytest.raises(EmbeddingSpaceDependencyError, match="graph storage"):
        await Neo4jVectorWriteRepository(
            _driver(_Driver(fail=True)),
            "agentmemory",
            FixedClock(),
        ).write(batch)
