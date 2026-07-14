"""Narrow model-runtime port owned by the provider domain."""

from __future__ import annotations

from typing import Protocol


class InferenceBackend(Protocol):
    """Capabilities required from the pinned local inference runtime."""

    async def health(self) -> None:
        """Require the exact model process to be loaded and responsive."""
        ...

    async def verify_cancellation(self) -> None:
        """Prove an in-flight backend request can be cancelled."""
        ...

    async def embed(self, contents: tuple[str, ...]) -> tuple[tuple[float, ...], ...]:
        """Generate one vector for every input in original order."""
        ...

    async def rerank(self, query: str, documents: tuple[str, ...]) -> tuple[float, ...]:
        """Return one score per document in original order."""
        ...

    async def extract_subject(self, content: str) -> str:
        """Produce one schema-constrained subject."""
        ...
