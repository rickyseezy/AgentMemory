"""Immutable strict local-Core runtime configuration."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Literal, Self, cast

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

if TYPE_CHECKING:
    from collections.abc import Callable


class CoreSettings(BaseSettings):
    """Validated non-secret references and internal service identities."""

    model_config = SettingsConfigDict(
        env_prefix="AM_",
        case_sensitive=False,
        extra="forbid",
        frozen=True,
    )

    state_directory: Path = Path("/var/lib/agentmemory/state")
    artifact_directory: Path = Path("/var/lib/agentmemory/artifacts")
    api_credential_file: Path = Path("/run/secrets/agentmemory_api_credential")
    installation_root_key_file: Path = Path("/run/secrets/agentmemory_installation_root_key")
    attestation_hmac_key_file: Path = Path("/run/secrets/agentmemory_attestation_hmac_key")
    neo4j_password_file: Path = Path("/run/secrets/agentmemory_neo4j_password")
    embedding_capability_file: Path = Path("/run/secrets/agentmemory_embedding_capability")
    reranking_capability_file: Path = Path("/run/secrets/agentmemory_reranking_capability")
    extraction_capability_file: Path = Path("/run/secrets/agentmemory_extraction_capability")
    egress_attestation_file: Path = Path("/run/secrets/agentmemory_egress_attestation")
    relational_migrations_directory: Path = Path("/opt/agentmemory/migrations/relational")
    neo4j_migrations_directory: Path = Path("/opt/agentmemory/migrations/neo4j")
    # Container-only bind; Compose must publish exclusively on host loopback.
    listen_host: Literal["0.0.0.0"] = "0.0.0.0"  # noqa: S104  # nosec B104
    port: int = Field(default=9411, ge=1024, le=65_535)
    neo4j_uri: Literal["neo4j://neo4j:7687"] = "neo4j://neo4j:7687"
    # The signed default image is Neo4j Community, whose single writable user
    # database is `neo4j`. Accepting an ambient database name would make the
    # pristine migration target nonexistent or redirect graph state.
    neo4j_database: Literal["neo4j"] = "neo4j"
    neo4j_username: str = Field(default="agentmemory", pattern=r"^[A-Za-z0-9_]{1,63}$")
    embedding_url: Literal["http://local-embedding:8080"] = "http://local-embedding:8080"
    reranking_url: Literal["http://local-reranker:8080"] = "http://local-reranker:8080"
    extraction_url: Literal["http://local-extractor:8080"] = "http://local-extractor:8080"
    embedding_model_id: Literal["Qwen/Qwen3-Embedding-0.6B"] = "Qwen/Qwen3-Embedding-0.6B"
    reranking_model_id: Literal["Qwen/Qwen3-Reranker-0.6B"] = "Qwen/Qwen3-Reranker-0.6B"
    extraction_model_id: Literal["Qwen/Qwen3-4B-GGUF-Q4_K_M"] = "Qwen/Qwen3-4B-GGUF-Q4_K_M"
    embedding_model_revision: str = Field(min_length=7, max_length=128)
    reranking_model_revision: str = Field(min_length=7, max_length=128)
    extraction_model_revision: str = Field(min_length=7, max_length=128)
    egress_enabled: Literal[False] = False

    @classmethod
    def from_environment(cls) -> Self:
        """Load required release bindings from the process environment."""
        factory = cast("Callable[[], Self]", cls)
        return factory()

    @property
    def database_path(self) -> Path:
        """Return the only active canonical SQLite file."""
        return self.state_directory / "agentmemory.sqlite3"

    @property
    def allowed_hosts(self) -> tuple[str, str, str]:
        """Derive the closed Host allowlist from the validated selected port."""
        return (
            f"127.0.0.1:{self.port}",
            f"[::1]:{self.port}",
            f"localhost:{self.port}",
        )
