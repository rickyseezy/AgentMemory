"""Safe placeholder for CAS-backed payload references until CAS is composed."""

from __future__ import annotations

from agentmemory.ingestion.domain.errors import IngestionDependencyError


class InlineOnlyPayloadReader:
    """Fail closed when an event references CAS that is not yet available."""

    async def read(self, reference: object) -> bytes:
        """Never fabricate referenced content or perform outbound I/O."""
        del reference
        message = "Referenced AgentEvent payload is unavailable"
        raise IngestionDependencyError(message)
