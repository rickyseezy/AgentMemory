"""Typed builders and infrastructure helpers for Core tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from alembic import command
from alembic.config import Config

from agentmemory.operations.adapters.outbound.sqlite_store import (
    SqliteCoreStore,
    SqliteRuntimePolicy,
)
from agentmemory.operations.domain.active_release import (
    ActiveReleasePointer,
    ActiveReleasePointerInput,
)
from agentmemory.operations.domain.bootstrap import BootstrapRequest
from agentmemory.operations.domain.readiness import (
    ProbeEvidence,
    ProbeStatus,
    ReadinessBinding,
    ReadinessProbe,
    ReadinessReceipt,
)
from agentmemory.operations.domain.value_objects import (
    OperationId,
    ReleaseId,
    Sha256Digest,
    Uuid7Id,
)

NOW = datetime(2026, 7, 14, 8, 9, 10, 123456, tzinfo=UTC)
INSTALLATION_ID = "018f0000-0000-7000-8000-000000000001"
OWNER_ID = "018f0000-0000-7000-8000-000000000002"
GRANT_ID = "018f0000-0000-7000-8000-000000000003"
BRAIN_ID = "018f0000-0000-7000-8000-000000000004"
GENERATION_ID = "018f0000-0000-7000-8000-000000000005"


@dataclass(frozen=True, slots=True)
class FixedClock:
    """Deterministic policy clock."""

    value: datetime = NOW

    def now(self) -> datetime:
        """Return the injected timestamp."""
        return self.value


def digest(seed: str) -> Sha256Digest:
    """Build a valid deterministic non-zero digest."""
    return Sha256Digest(hashlib.sha256(seed.encode()).hexdigest())


def binding(operation_id: str = "install-0001") -> ReadinessBinding:
    """Build one exact signed-operation readiness binding."""
    return ReadinessBinding(
        operation_id=OperationId(operation_id),
        plan_digest=digest("plan"),
        release_id=ReleaseId("v1.0.0"),
        generation_id=Uuid7Id(GENERATION_ID),
        manifest_digest=digest("manifest"),
        compose_digest=digest("compose"),
    )


def bootstrap_request(command_id: str = "bootstrap-0001") -> BootstrapRequest:
    """Build the first local installation aggregate command."""
    return BootstrapRequest(
        command_id=OperationId(command_id),
        installation_id=Uuid7Id(INSTALLATION_ID),
        owner_principal_id=Uuid7Id(OWNER_ID),
        owner_grant_id=Uuid7Id(GRANT_ID),
        owner_subject_digest=digest("owner-subject"),
        brain_id=Uuid7Id(BRAIN_ID),
        brain_name="personal",
        release_digest=digest("release"),
        generation_id=Uuid7Id(GENERATION_ID),
    )


def receipt(
    readiness_binding: ReadinessBinding | None = None,
    evaluated_at: datetime = NOW,
) -> ReadinessReceipt:
    """Build a complete passing receipt in closed probe order."""
    resolved = readiness_binding or binding()
    results = tuple(
        ProbeEvidence(
            probe=probe,
            status=ProbeStatus.PASSED,
            binding=resolved,
            evidence_digest=digest(f"evidence-{probe.evidence_key}"),
            observed_at=evaluated_at,
        )
        for probe in ReadinessProbe
    )
    return ReadinessReceipt.create(resolved, evaluated_at, results)


def active_pointer(  # noqa: PLR0913 -- Test builder mirrors the complete pointer authority.
    readiness_receipt: ReadinessReceipt | None = None,
    *,
    installation_id: str = INSTALLATION_ID,
    release_id: str | None = None,
    release_sequence: int = 7,
    resource_inventory_version: int = 9,
    security_epoch: int = 3,
) -> ActiveReleasePointer:
    """Build the exact active pointer authorized by one complete test receipt."""
    resolved = readiness_receipt or receipt()
    readiness_binding = resolved.binding
    return ActiveReleasePointer.create(
        ActiveReleasePointerInput(
            installation_id=Uuid7Id(installation_id),
            release_id=(
                readiness_binding.release_id if release_id is None else ReleaseId(release_id)
            ),
            generation_id=readiness_binding.generation_id,
            manifest_digest=readiness_binding.manifest_digest,
            compose_digest=readiness_binding.compose_digest,
            readiness_receipt_digest=resolved.digest,
            runtime_endpoint="unix:///var/run/docker.sock",
            release_sequence=release_sequence,
            resource_inventory_version=resource_inventory_version,
            resource_inventory_digest=digest("inventory"),
            security_epoch=security_epoch,
            activated_at=NOW,
        )
    )


def migrated_store(tmp_path: Path) -> SqliteCoreStore:
    """Apply the real Alembic bundle and open a permissive test-policy store."""
    database_path = tmp_path / "agentmemory.sqlite3"
    migrations = Path(__file__).parents[2] / "migrations" / "relational"
    configuration = Config(str(migrations / "alembic.ini"))
    configuration.set_main_option("script_location", str(migrations))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")
    command.upgrade(configuration, "head")
    return SqliteCoreStore.create(
        database_path,
        SqliteRuntimePolicy(minimum_version=(3, 0, 0), required_compile_options=frozenset()),
    )


def write_secret(path: Path, value: bytes) -> None:
    """Create an owner-only protected test secret."""
    path.write_bytes(value)
    path.chmod(0o600)
