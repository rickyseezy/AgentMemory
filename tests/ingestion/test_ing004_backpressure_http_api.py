"""ING-004 authenticated content-free scheduler HTTP contract tests."""

from __future__ import annotations

from dataclasses import dataclass

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.ingestion.adapters.inbound.backpressure_http_api import (
    create_backpressure_router,
    create_contract_backpressure_router,
)
from agentmemory.ingestion.domain.backpressure import (
    DeadLetter,
    JobErrorCode,
    JobPriority,
    JobRequest,
    JobState,
    ReplayDeadLetterRequest,
    ScheduledJob,
)
from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionCapacityError,
    IngestionConflictError,
    IngestionDependencyError,
    IngestionIntegrityError,
)
from tests.core.support import BRAIN_ID, GRANT_ID, digest
from tests.ingestion.adp002_support import PRINCIPAL_ID

JOB_ID = "018f0000-0000-7000-8000-000000000301"
DLQ_ID = "018f0000-0000-7000-8000-000000000302"
OPERATION_ID = "018f0000-0000-7000-8000-000000000303"
REPLAY_JOB_ID = "018f0000-0000-7000-8000-000000000304"


def job() -> ScheduledJob:
    return ScheduledJob(
        JobRequest(
            JOB_ID,
            BRAIN_ID,
            PRINCIPAL_ID,
            GRANT_ID,
            "memory-index",
            "memory-index:event-301",
            digest("request").value,
            JobPriority.STANDARD,
            "cas://sha256/" + digest("secret-input-reference").value,
        ),
        JobState.DEAD_LETTERED,
        3,
        10,
        None,
        None,
        JobErrorCode.POISON_JOB,
        None,
        None,
        None,
        None,
        1,
        20,
    )


def dead_letter() -> DeadLetter:
    return DeadLetter(
        DLQ_ID,
        JOB_ID,
        BRAIN_ID,
        JobPriority.STANDARD,
        "memory-index",
        digest("request").value,
        3,
        JobErrorCode.POISON_JOB,
        "malformed_projection_input",
        20,
        20,
    )


@dataclass
class Authenticator:
    allowed: bool = True

    async def authenticate(self, authorization: str | None) -> None:
        if not self.allowed or authorization != "Bearer local-secret":
            message = "denied"
            raise IngestionAuthorizationError(message)


class GetJob:
    async def execute(self, job_id: str) -> ScheduledJob:
        assert job_id == JOB_ID
        return job()


class ListDeadLetters:
    async def execute(
        self,
        actor_id: str,
        grant_id: str,
        brain_id: str,
        *,
        maximum: int = 100,
    ) -> tuple[DeadLetter, ...]:
        assert (actor_id, grant_id, brain_id, maximum) == (
            PRINCIPAL_ID,
            GRANT_ID,
            BRAIN_ID,
            10,
        )
        return (dead_letter(),)


class Replay:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.requests: list[ReplayDeadLetterRequest] = []

    async def execute(self, request: ReplayDeadLetterRequest) -> ScheduledJob:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return job()


def client(
    authenticator: Authenticator | None = None,
    replay: Replay | None = None,
) -> tuple[httpx.AsyncClient, Replay]:
    app = FastAPI()
    resolved_replay = replay or Replay()
    app.include_router(
        create_backpressure_router(
            authenticator or Authenticator(),
            GetJob(),
            ListDeadLetters(),
            resolved_replay,
        )
    )
    return (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ),
        resolved_replay,
    )


@pytest.mark.asyncio
@pytest.mark.contract
async def test_job_and_dead_letter_queries_return_only_content_free_authorized_evidence() -> None:
    http, _ = client()
    headers = {"Authorization": "Bearer local-secret"}
    try:
        job_response = await http.get(f"/v1/scheduler/jobs/{JOB_ID}", headers=headers)
        dead_response = await http.get(
            "/v1/dead-letters",
            headers=headers,
            params={
                "actor_id": PRINCIPAL_ID,
                "grant_id": GRANT_ID,
                "brain_id": BRAIN_ID,
                "maximum": 10,
            },
        )
    finally:
        await http.aclose()
    assert job_response.status_code == 200
    assert dead_response.status_code == 200
    serialized = job_response.text + dead_response.text
    assert "secret-input-reference" not in serialized
    assert "actor_id" not in job_response.json()
    assert "grant_id" not in job_response.json()
    assert dead_response.json()["items"][0]["diagnostic_code"] == ("malformed_projection_input")


@pytest.mark.asyncio
@pytest.mark.contract
async def test_replay_binds_idempotency_and_translates_capacity_without_leaking_reason() -> None:
    replay = Replay(IngestionCapacityError("disk_hard_limit", retryable=True))
    http, _ = client(replay=replay)
    body = {
        "operation_id": OPERATION_ID,
        "new_job_id": REPLAY_JOB_ID,
        "actor_id": PRINCIPAL_ID,
        "grant_id": GRANT_ID,
        "corrected_request_sha256": digest("corrected").value,
        "corrected_input_ref": "cas://sha256/" + digest("corrected-input").value,
    }
    try:
        mismatch = await http.post(
            f"/v1/dead-letters/{DLQ_ID}:replay",
            headers={"Authorization": "Bearer local-secret", "Idempotency-Key": REPLAY_JOB_ID},
            json=body,
        )
        capacity = await http.post(
            f"/v1/dead-letters/{DLQ_ID}:replay",
            headers={"Authorization": "Bearer local-secret", "Idempotency-Key": OPERATION_ID},
            json=body,
        )
    finally:
        await http.aclose()
    assert mismatch.status_code == 422
    assert capacity.status_code == 507
    assert capacity.json() == {
        "code": "AM_CAPACITY_EXHAUSTED",
        "retryable": True,
        "detail": "Scheduler request was rejected",
    }
    assert "disk_hard_limit" not in capacity.text


@pytest.mark.asyncio
@pytest.mark.contract
@pytest.mark.parametrize(
    ("error", "expected_status", "expected_code"),
    [
        (IngestionConflictError("conflict"), 409, "AM_CONFLICT"),
        (IngestionDependencyError("dependency"), 503, "AM_DEPENDENCY_UNAVAILABLE"),
        (IngestionIntegrityError("integrity"), 500, "AM_INTEGRITY"),
    ],
)
async def test_replay_translates_typed_failures_without_arbitrary_details(
    error: Exception,
    expected_status: int,
    expected_code: str,
) -> None:
    http, _ = client(replay=Replay(error))
    body = {
        "operation_id": OPERATION_ID,
        "new_job_id": REPLAY_JOB_ID,
        "actor_id": PRINCIPAL_ID,
        "grant_id": GRANT_ID,
        "corrected_request_sha256": digest("corrected").value,
        "corrected_input_ref": None,
    }
    try:
        response = await http.post(
            f"/v1/dead-letters/{DLQ_ID}:replay",
            headers={"Authorization": "Bearer local-secret", "Idempotency-Key": OPERATION_ID},
            json=body,
        )
    finally:
        await http.aclose()
    assert response.status_code == expected_status
    assert response.json()["code"] == expected_code
    assert str(error) not in response.text


@pytest.mark.asyncio
@pytest.mark.contract
async def test_replay_rejects_empty_and_malformed_strict_bodies() -> None:
    http, _ = client()
    headers = {"Authorization": "Bearer local-secret", "Idempotency-Key": OPERATION_ID}
    try:
        empty = await http.post(
            f"/v1/dead-letters/{DLQ_ID}:replay",
            headers=headers,
            content=b"",
        )
        malformed = await http.post(
            f"/v1/dead-letters/{DLQ_ID}:replay",
            headers=headers,
            content=b'{"unknown":true}',
        )
    finally:
        await http.aclose()
    assert empty.status_code == 422
    assert malformed.status_code == 422
    assert malformed.json()["fields"]


@pytest.mark.asyncio
@pytest.mark.security
async def test_installation_authentication_precedes_scheduler_handlers() -> None:
    http, replay = client(Authenticator(allowed=False))
    try:
        response = await http.get(f"/v1/scheduler/jobs/{JOB_ID}")
    finally:
        await http.aclose()
    assert response.status_code == 403
    assert replay.requests == []


def test_contract_router_exports_all_scheduler_paths_without_runtime_dependencies() -> None:
    app = FastAPI()
    app.include_router(create_contract_backpressure_router())
    paths = app.openapi()["paths"]
    assert {
        "/v1/scheduler/jobs/{job_id}",
        "/v1/dead-letters",
        "/v1/dead-letters/{dead_letter_id}:replay",
    }.issubset(paths)
