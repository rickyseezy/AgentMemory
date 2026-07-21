"""IDX-004 application authorization, plugin selection, and replay tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta, tzinfo
from typing import TYPE_CHECKING, override

import pytest

from agentmemory.indexing.application.api_topology import (
    ExtractAndRegisterApiTopologyCommand,
    ExtractAndRegisterApiTopologyHandler,
    LinkApiTopologyCommand,
    LinkApiTopologyHandler,
    RegisterApiTopologyBatchCommand,
    RegisterApiTopologyBatchHandler,
)
from agentmemory.indexing.domain.api_topology import (
    ApiTopologyCandidateBatch,
    ApiTopologyEvidence,
    ApiTopologyLinkDecision,
    ApiTopologyPluginKind,
    ApiTopologySourceArtifact,
    EndpointCandidate,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingValidationError,
)
from tests.indexing.test_idx001_sqlite_code_index import (
    _scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.indexing.test_idx004_api_topology_domain import (
    ENDPOINT_A,
    _endpoint,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.api_topology import (
        ApiTopologyMatch,
        ClientCallCandidate,
        ContractBindingCandidate,
        ServiceOwnershipCandidate,
    )

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)


@dataclass(slots=True)
class _Repository:
    batch: ApiTopologyCandidateBatch
    existing_batch: ApiTopologyCandidateBatch | None = None
    replay: ApiTopologyLinkDecision | None = None

    async def find_batch_by_operation(
        self, scope: AuthorizedScope, operation_id: str
    ) -> ApiTopologyCandidateBatch | None:
        del scope, operation_id
        return self.existing_batch

    async def register_batch(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        batch: ApiTopologyCandidateBatch,
        registered_at: datetime,
    ) -> ApiTopologyCandidateBatch:
        del scope, operation_id, registered_at
        return batch

    async def load_link_universe(
        self, scope: AuthorizedScope, client_call_id: str, linked_at: datetime
    ) -> tuple[
        ClientCallCandidate,
        tuple[EndpointCandidate, ...],
        tuple[ContractBindingCandidate, ...],
        tuple[ServiceOwnershipCandidate, ...],
    ]:
        del scope, client_call_id, linked_at
        raise AssertionError

    async def find_link_decision(
        self, scope: AuthorizedScope, operation_id: str
    ) -> ApiTopologyLinkDecision | None:
        del scope, operation_id
        return self.replay

    async def record_link_decision(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        decision: ApiTopologyLinkDecision,
        assertion_ids: tuple[str, ...],
        linked_at: datetime,
    ) -> ApiTopologyLinkDecision:
        del scope, operation_id, assertion_ids, linked_at
        return decision


@dataclass(frozen=True, slots=True)
class _Plugin:
    supported: bool
    batch: ApiTopologyCandidateBatch

    def supports(self, relative_path: str) -> bool:
        del relative_path
        return self.supported

    def extract(self, artifact: object) -> ApiTopologyCandidateBatch:
        del artifact
        return self.batch


@dataclass(frozen=True, slots=True)
class _UnusedAssertions:
    async def record(
        self, scope: AuthorizedScope, match: ApiTopologyMatch, occurred_at: datetime
    ) -> str:
        del scope, match, occurred_at
        raise AssertionError


@dataclass(frozen=True, slots=True)
class _UnusedLineage:
    async def register(  # noqa: PLR0913
        self,
        scope: AuthorizedScope,
        operation_id: str,
        source_revision_context_id: str,
        source_semantic_id: str,
        evidence_id: str,
        assertion_id: str,
        registered_at: datetime,
    ) -> str:
        del (
            scope,
            operation_id,
            source_revision_context_id,
            source_semantic_id,
            evidence_id,
            assertion_id,
            registered_at,
        )
        raise AssertionError


def test_commands_reject_wrong_action_scope_identity_and_time() -> None:
    batch = _batch()
    with pytest.raises(IndexingValidationError, match="API topology command conflicts"):
        RegisterApiTopologyBatchCommand("invalid operation!", _register_scope(), batch, NOW)
    with pytest.raises(IndexingValidationError, match="API topology command conflicts"):
        RegisterApiTopologyBatchCommand(
            "idx004-naive", _register_scope(), batch, NOW.replace(tzinfo=None)
        )
    with pytest.raises(IndexingAuthorizationError):
        RegisterApiTopologyBatchCommand(
            "idx004-cross-brain",
            _register_scope(),
            _batch(replace(_endpoint(ENDPOINT_A, contract=None), evidence=_foreign_evidence())),
            NOW,
        )
    with pytest.raises(IndexingValidationError):
        LinkApiTopologyCommand("idx004-bad-client", _link_scope(), "bad", NOW)
    with pytest.raises(IndexingAuthorizationError):
        LinkApiTopologyCommand(
            "idx004-empty-scope",
            replace(_link_scope(), members=()),
            hashlib.sha256(b"client").hexdigest(),
            NOW,
        )


class _IndeterminateTimezone(tzinfo):
    @override
    def utcoffset(self, value: datetime | None) -> None:
        del value

    @override
    def dst(self, value: datetime | None) -> timedelta | None:
        del value
        return None

    @override
    def tzname(self, value: datetime | None) -> str | None:
        del value
        return None


def test_commands_reject_indeterminate_timezone_with_governed_error() -> None:
    with pytest.raises(IndexingValidationError, match="API topology command conflicts"):
        RegisterApiTopologyBatchCommand(
            "idx004-indeterminate-time",
            _register_scope(),
            _batch(),
            NOW.replace(tzinfo=_IndeterminateTimezone()),
        )


def test_registration_requires_exact_brain_project_and_repository() -> None:
    scope = _register_scope()
    evidence_variants = (
        replace(
            _endpoint(ENDPOINT_A, contract=None).evidence,
            brain_id="018f0000-0000-7000-8000-000000000099",
            project_id=scope.members[0].project_id.value,
            repository_id=scope.members[0].repository_ids[0].value,
        ),
        replace(
            _endpoint(ENDPOINT_A, contract=None).evidence,
            brain_id=scope.brain_id.value,
            project_id="018f0000-0000-7000-8000-000000000098",
            repository_id=scope.members[0].repository_ids[0].value,
        ),
        replace(
            _endpoint(ENDPOINT_A, contract=None).evidence,
            brain_id=scope.brain_id.value,
            project_id=scope.members[0].project_id.value,
            repository_id="018f0000-0000-7000-8000-000000000097",
        ),
    )
    for evidence in evidence_variants:
        with pytest.raises(IndexingAuthorizationError, match="outside authorized scope"):
            RegisterApiTopologyBatchCommand(
                "idx004-exact-scope",
                scope,
                _batch(replace(_endpoint(ENDPOINT_A, contract=None), evidence=evidence)),
                NOW,
            )


@pytest.mark.asyncio
async def test_registration_replay_conflict_and_plugin_cardinality_fail_closed() -> None:
    batch = _batch()
    with pytest.raises(IndexingAuthorizationError, match="API topology action is not authorized"):
        await RegisterApiTopologyBatchHandler(_Repository(batch)).execute(
            RegisterApiTopologyBatchCommand(
                "idx004-wrong-action", _scope("indexing.search"), batch, NOW
            )
        )
    repository = _Repository(batch, existing_batch=replace(batch, plugin_version="v2.0.0"))
    command = RegisterApiTopologyBatchCommand(
        "idx004-register-conflict", _register_scope(), batch, NOW
    )
    with pytest.raises(IndexingConflictError):
        await RegisterApiTopologyBatchHandler(repository).execute(command)

    artifact = ApiTopologySourceArtifact(batch.endpoints[0].evidence, "1" * 40, b"source")
    extraction = ExtractAndRegisterApiTopologyCommand(
        "idx004-extract", _register_scope(), artifact, NOW
    )
    handler = ExtractAndRegisterApiTopologyHandler(
        (), RegisterApiTopologyBatchHandler(_Repository(batch))
    )
    with pytest.raises(IndexingValidationError):
        await handler.execute(extraction)
    handler = ExtractAndRegisterApiTopologyHandler(
        (_Plugin(supported=True, batch=batch), _Plugin(supported=True, batch=batch)),
        RegisterApiTopologyBatchHandler(_Repository(batch)),
    )
    with pytest.raises(IndexingValidationError):
        await handler.execute(extraction)

    with pytest.raises(IndexingAuthorizationError):
        ExtractAndRegisterApiTopologyCommand(
            "idx004-foreign-artifact",
            _register_scope(),
            replace(artifact, evidence=_foreign_evidence()),
            NOW,
        )


@pytest.mark.asyncio
async def test_link_replay_with_different_client_is_a_conflict() -> None:
    requested_client = hashlib.sha256(b"requested").hexdigest()
    replay = ApiTopologyLinkDecision(
        hashlib.sha256(b"other").hexdigest(), hashlib.sha256(b"universe").hexdigest(), ()
    )
    repository = _Repository(_batch(), replay=replay)
    handler = LinkApiTopologyHandler(repository, _UnusedAssertions(), _UnusedLineage())
    with pytest.raises(IndexingConflictError):
        await handler.execute(
            LinkApiTopologyCommand("idx004-replay-conflict", _link_scope(), requested_client, NOW)
        )


def _batch(endpoint: EndpointCandidate | None = None) -> ApiTopologyCandidateBatch:
    if endpoint is None:
        scope = _register_scope()
        base = _endpoint(ENDPOINT_A, contract=None)
        evidence = replace(
            base.evidence,
            brain_id=scope.brain_id.value,
            project_id=scope.members[0].project_id.value,
            repository_id=scope.members[0].repository_ids[0].value,
        )
        value = replace(base, evidence=evidence)
    else:
        value = endpoint
    return ApiTopologyCandidateBatch(
        ApiTopologyPluginKind.SOURCE_CALLS,
        "v1.0.0",
        value.evidence.source_revision_context_id,
        value.evidence.source_file_id,
        "1" * 40,
        (value,),
    )


def _foreign_evidence() -> ApiTopologyEvidence:
    original = _endpoint(ENDPOINT_A, contract=None).evidence
    return replace(
        original,
        brain_id="018f0000-0000-7000-8000-000000000099",
        project_id="018f0000-0000-7000-8000-000000000098",
        repository_id="018f0000-0000-7000-8000-000000000097",
    )


def _register_scope() -> AuthorizedScope:
    return _scope("indexing.api_topology.register")


def _link_scope() -> AuthorizedScope:
    return _scope("indexing.api_topology.link")
