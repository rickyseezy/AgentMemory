"""Closed environment contract for one local-provider container."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Literal, Self, cast

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from agentmemory.providers.adapters.model_artifact import ModelArtifactBinding
from agentmemory.providers.domain.models import (
    EMBEDDING_DIMENSION,
    ProviderIdentity,
    ProviderRole,
)

if TYPE_CHECKING:
    from collections.abc import Callable


class ProviderSettings(BaseSettings):
    """Only release-bound values accepted by the provider runtime."""

    model_config = SettingsConfigDict(
        env_prefix="AM_PROVIDER_",
        # Environment variables are projected by Compose using conventional
        # upper-case names (for example ``AM_PROVIDER_ROLE``). Pydantic maps
        # those names to the lower-case field names only in case-insensitive
        # mode; values and accepted fields remain closed by the model itself.
        case_sensitive=False,
        extra="forbid",
        frozen=True,
    )

    role: ProviderRole
    model_revision: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    model_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_size: int = Field(gt=0, le=16 * 1024 * 1024 * 1024)
    listen_host: Literal["0.0.0.0"] = "0.0.0.0"  # noqa: S104  # nosec B104
    port: Literal[8080] = 8080
    llama_binary: Literal["/app/llama-server"] = "/app/llama-server"

    @classmethod
    def from_environment(cls) -> Self:
        """Load a complete release-projected role binding."""
        factory = cast("Callable[[], Self]", cls)
        return factory()

    @property
    def identity(self) -> ProviderIdentity:
        """Derive the exact public identity; callers cannot substitute a model name."""
        model_id = {
            ProviderRole.EMBEDDING: "Qwen/Qwen3-Embedding-0.6B",
            ProviderRole.RERANKING: "Qwen/Qwen3-Reranker-0.6B",
            ProviderRole.EXTRACTION: "Qwen/Qwen3-4B-GGUF-Q4_K_M",
        }[self.role]
        return ProviderIdentity(
            role=self.role,
            model_id=model_id,
            model_revision=self.model_revision,
            dimension=EMBEDDING_DIMENSION if self.role is ProviderRole.EMBEDDING else None,
        )

    @property
    def artifact_binding(self) -> ModelArtifactBinding:
        """Build the descriptor-bound model verification input."""
        return ModelArtifactBinding(
            role=self.role,
            sha256=self.model_sha256,
            size=self.model_size,
        )

    @property
    def capability_file(self) -> Path:
        """Return the fixed Docker secret path for this role."""
        name = {
            ProviderRole.EMBEDDING: "agentmemory_embedding_capability",
            ProviderRole.RERANKING: "agentmemory_reranking_capability",
            ProviderRole.EXTRACTION: "agentmemory_extraction_capability",
        }[self.role]
        return Path("/run/secrets") / name

    @property
    def internal_host(self) -> str:
        """Return the only Compose DNS identity permitted in Host headers."""
        return {
            ProviderRole.EMBEDDING: "local-embedding",
            ProviderRole.RERANKING: "local-reranker",
            ProviderRole.EXTRACTION: "local-extractor",
        }[self.role]
