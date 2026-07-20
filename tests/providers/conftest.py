from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from agentmemory.providers.domain.models import EMBEDDING_DIMENSION


@dataclass
class RecordingBackend:
    healthy: bool = True
    cancellation_error: Exception | None = None
    vectors: tuple[tuple[float, ...], ...] = ()
    scores: tuple[float, ...] = ()
    subject: str = "persistent memory"
    memory_candidates: bytes = (
        b'{"candidates":[],"input_sha256":"'
        + (b"a" * 64)
        + b'","schema":"agentmemory.memory-candidates.v1"}'
    )
    calls: list[tuple[str, object]] = field(default_factory=list[tuple[str, object]])

    async def health(self) -> None:
        self.calls.append(("health", None))
        if not self.healthy:
            message = "unhealthy"
            raise RuntimeError(message)

    async def verify_cancellation(self) -> None:
        self.calls.append(("cancel", None))
        if self.cancellation_error is not None:
            raise self.cancellation_error

    async def embed(self, contents: tuple[str, ...]) -> tuple[tuple[float, ...], ...]:
        self.calls.append(("embed", contents))
        if self.vectors:
            return self.vectors
        return tuple((1.0,) * EMBEDDING_DIMENSION for _ in contents)

    async def rerank(self, query: str, documents: tuple[str, ...]) -> tuple[float, ...]:
        self.calls.append(("rerank", (query, documents)))
        return self.scores or tuple(float(index) for index in range(len(documents)))

    async def extract_subject(self, content: str) -> str:
        self.calls.append(("extract", content))
        return self.subject

    async def extract_memory_candidates(self, content: str, input_sha256: str) -> bytes:
        self.calls.append(("extract_memory", (content, input_sha256)))
        return self.memory_candidates.replace(b"a" * 64, input_sha256.encode())


@pytest.fixture
def backend() -> RecordingBackend:
    return RecordingBackend()
