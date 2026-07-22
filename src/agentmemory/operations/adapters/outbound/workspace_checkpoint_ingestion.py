"""PF-005 bridge from encrypted checkpoints to canonical events and artifacts."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Final, cast

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.ingestion.adapters.native_event_translator import (
    CanonicalNativeEventTranslator,
    NativeEventObservation,
)
from agentmemory.ingestion.adapters.outbound.payload_reader import InlineOnlyPayloadReader
from agentmemory.ingestion.application.admit_agent_event import AgentEventAdmissionHandler
from agentmemory.ingestion.application.append_agent_event import AppendAgentEventCommand
from agentmemory.ingestion.application.privacy import CapturePolicyCommand
from agentmemory.ingestion.domain.adapter_capability import (
    AdapterCapabilityManifest,
    AdapterCapabilityObservation,
    EvidenceAvailability,
    RegisteredAdapterCapabilities,
)
from agentmemory.ingestion.domain.agent_event import (
    AgentEventData,
    AgentEventIdentity,
    CaptureCapability,
    CaptureMethod,
    Classification,
    EventFamily,
)
from agentmemory.ingestion.domain.capture import AdmittedAgentEvent, AppendDisposition
from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionCapacityError,
    IngestionConflictError,
    IngestionDependencyError,
    IngestionValidationError,
)
from agentmemory.ingestion.domain.generic_adapter import stable_evidence_uuid7
from agentmemory.ingestion.domain.privacy import (
    CaptureDisposition,
    CapturePolicyResult,
    EgressDisposition,
    PolicyStage,
    SensitiveFinding,
    SensitiveKind,
    StageEvidence,
)
from agentmemory.operations.adapters.outbound.protected_file import zero_secret
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.value_objects import Sha256Digest
from agentmemory.operations.domain.workspace_checkpoint import (
    WorkspaceCheckpointBatch,
    WorkspaceCheckpointChange,
    WorkspaceCheckpointIngestionResult,
)

if TYPE_CHECKING:
    from sqlalchemy.engine import RowMapping

    from agentmemory.ingestion.adapters.outbound.envelope_crypto import BrainKeyProvider
    from agentmemory.ingestion.application.append_agent_event import AppendAgentEventHandler
    from agentmemory.ingestion.application.privacy import CapturePolicyPipeline
    from agentmemory.ingestion.domain.agent_event import AgentEvent
    from agentmemory.ingestion.domain.ports import (
        AgentEventScopeResolver,
        CapturePolicyDecisionRepository,
    )
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.operations.domain.mcp_session import McpSessionRegistration
    from agentmemory.shared.clock import Clock

_ALGORITHM: Final = "AES-256-GCM"
_NONCE_BYTES: Final = 12
_ADAPTER_ID: Final = "agentmemory.mcp-session"
_ADAPTER_VERSION: Final = "1.0.0"
_ADAPTER_DIGEST: Final = hashlib.sha256(
    b"agentmemory:mcp-session:pf005:adapter-protocol-v1"
).hexdigest()
_OBSERVATION_ID: Final = "018f0000-0000-7000-8000-000000000505"
_OBSERVED_AT: Final = datetime(2024, 5, 1, tzinfo=UTC)


class WorkspaceChangeDisposition(StrEnum):
    """Closed durable outcome decided before canonical event append."""

    EVENT = "event"
    EXCLUDED = "excluded"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class PreparedWorkspaceChange:
    """Replay-stable, privacy-evaluated checkpoint change."""

    batch_digest: str
    ordinal: int
    change_id: str
    event_id: str
    session_id: str
    brain_id: str
    project_id: str
    repository_id: str
    checkout_id: str | None
    relative_path: str
    relative_path_sha256: str
    source_sha256: str
    disposition: WorkspaceChangeDisposition
    deleted: bool
    partial: bool
    policy: CapturePolicyResult | None
    rejection_code: str | None
    preparation_sha256: str

    @property
    def emits_event(self) -> bool:
        """Return whether this preparation owns one canonical event identity."""
        return self.disposition is WorkspaceChangeDisposition.EVENT

    @property
    def artifact_content(self) -> bytes | None:
        """Return sanitized source bytes only for an included non-deletion."""
        if not self.emits_event or self.deleted or self.policy is None:
            return None
        return self.policy.payload


@dataclass(slots=True)
class SqlitePreparedWorkspaceChangeRepository:
    """Persist and authenticate privacy results before event append can race workers."""

    store: SqliteCoreStore
    keys: BrainKeyProvider
    clock: Clock

    async def load(
        self,
        batch: WorkspaceCheckpointBatch,
        registration: McpSessionRegistration,
        ordinal: int,
        change: WorkspaceCheckpointChange,
    ) -> PreparedWorkspaceChange | None:
        """Restore one exact preparation or reject mismatched durable identity."""
        try:
            async with self.store.engine.connect() as connection:
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT * FROM mcp_workspace_checkpoint_changes "
                                "WHERE batch_digest=:batch AND ordinal=:ordinal"
                            ),
                            {
                                "batch": bytes.fromhex(batch.batch_digest.value),
                                "ordinal": ordinal,
                            },
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
            if row is None:
                return None
            prepared = await self._restore(row)
            if _base_document(batch, registration, ordinal, change) != _base_from(prepared):
                _conflict()
        except OperationError:
            raise
        except IngestionDependencyError as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "workspace artifact key is unavailable",
                retryable=True,
            ) from error
        except (SQLAlchemyError, TypeError, ValueError) as error:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "workspace artifact preparation is invalid",
            ) from error
        return prepared

    async def save(self, prepared: PreparedWorkspaceChange) -> PreparedWorkspaceChange:
        """Append one encrypted preparation, accepting only an exact concurrent replay."""
        policy_document = _policy_document(prepared.policy)
        policy_json = None if policy_document is None else _canonical_json(policy_document).decode()
        payload = None if prepared.policy is None else prepared.policy.payload
        key_ref: str | None = None
        nonce: bytes | None = None
        ciphertext: bytes | None = None
        aad_digest: bytes | None = None
        if payload is not None:
            brain_key = await self.keys.current(prepared.brain_id)
            mutable = bytearray(payload)
            try:
                nonce = os.urandom(_NONCE_BYTES)
                aad = _artifact_aad(prepared, brain_key.key_id)
                ciphertext = AESGCM(brain_key.material).encrypt(nonce, bytes(mutable), aad)
                aad_digest = hashlib.sha256(aad).digest()
                key_ref = brain_key.key_id
            finally:
                zero_secret(mutable)
        parameters: dict[str, object] = {
            "batch": bytes.fromhex(prepared.batch_digest),
            "ordinal": prepared.ordinal,
            "change_id": prepared.change_id,
            "event_id": prepared.event_id,
            "session": prepared.session_id,
            "brain": prepared.brain_id,
            "project": prepared.project_id,
            "repository": prepared.repository_id,
            "checkout": prepared.checkout_id,
            "path": prepared.relative_path,
            "path_digest": bytes.fromhex(prepared.relative_path_sha256),
            "source": bytes.fromhex(prepared.source_sha256),
            "preparation": bytes.fromhex(prepared.preparation_sha256),
            "disposition": prepared.disposition.value,
            "deleted": int(prepared.deleted),
            "partial": int(prepared.partial),
            "classification": (
                None if prepared.policy is None else prepared.policy.classification.value
            ),
            "policy": policy_json,
            "key_ref": key_ref,
            "algorithm": None if payload is None else _ALGORITHM,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "aad": aad_digest,
            "sanitized": (
                None
                if prepared.policy is None or prepared.policy.output_sha256 is None
                else bytes.fromhex(prepared.policy.output_sha256)
            ),
            "size": None if payload is None else len(payload),
            "rejection": prepared.rejection_code,
            "created": _microseconds(self.clock.now()),
        }
        try:
            async with self.store.write_lock, self.store.engine.begin() as connection:
                existing = (
                    (
                        await connection.execute(
                            text(
                                "SELECT preparation_sha256 FROM "
                                "mcp_workspace_checkpoint_changes WHERE "
                                "batch_digest=:batch AND ordinal=:ordinal"
                            ),
                            parameters,
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if existing is not None:
                    if _blob(existing, "preparation_sha256", 32).hex() != (
                        prepared.preparation_sha256
                    ):
                        _conflict()
                else:
                    await connection.execute(
                        text(
                            "INSERT INTO mcp_workspace_checkpoint_changes "
                            "(batch_digest,ordinal,change_id,event_id,session_id,brain_id,"
                            "project_id,repository_id,checkout_id,relative_path,"
                            "relative_path_sha256,source_sha256,preparation_sha256,disposition,"
                            "deleted,partial,classification,policy_result_json,encryption_key_ref,"
                            "algorithm,nonce,ciphertext,aad_sha256,sanitized_sha256,sanitized_size,"
                            "rejection_code,created_at,schema_version) VALUES "
                            "(:batch,:ordinal,:change_id,:event_id,:session,:brain,:project,"
                            ":repository,:checkout,:path,:path_digest,:source,:preparation,"
                            ":disposition,:deleted,:partial,:classification,:policy,:key_ref,"
                            ":algorithm,:nonce,:ciphertext,:aad,:sanitized,:size,:rejection,"
                            ":created,1)"
                        ),
                        parameters,
                    )
        except OperationError:
            raise
        except IntegrityError as error:
            raise OperationError(ErrorCode.CONFLICT, "workspace change conflicted") from error
        except SQLAlchemyError as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "workspace artifact storage is unavailable",
                retryable=True,
            ) from error
        restored = await self.load_by_identity(prepared.batch_digest, prepared.ordinal)
        if restored.preparation_sha256 != prepared.preparation_sha256:
            _conflict()
        return restored

    async def load_by_identity(self, batch_digest: str, ordinal: int) -> PreparedWorkspaceChange:
        """Load a just-stored change through the same authenticated read boundary."""
        try:
            async with self.store.engine.connect() as connection:
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT * FROM mcp_workspace_checkpoint_changes "
                                "WHERE batch_digest=:batch AND ordinal=:ordinal"
                            ),
                            {"batch": bytes.fromhex(batch_digest), "ordinal": ordinal},
                        )
                    )
                    .mappings()
                    .one()
                )
            return await self._restore(row)
        except OperationError:
            raise
        except IngestionDependencyError as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "workspace artifact key is unavailable",
                retryable=True,
            ) from error
        except (SQLAlchemyError, TypeError, ValueError) as error:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "workspace artifact preparation is invalid",
            ) from error

    async def _restore(self, row: RowMapping) -> PreparedWorkspaceChange:
        disposition = WorkspaceChangeDisposition(str(row["disposition"]))
        policy_document = (
            None if row["policy_result_json"] is None else str(row["policy_result_json"])
        )
        payload: bytes | None = None
        if disposition is WorkspaceChangeDisposition.EVENT:
            key_ref = _required_text(row["encryption_key_ref"])
            brain_id = _required_text(row["brain_id"])
            brain_key = await self.keys.current(brain_id)
            if brain_key.key_id != key_ref or _required_text(row["algorithm"]) != _ALGORITHM:
                raise ValueError
            prepared_without_policy = _row_identity(row, disposition, None)
            aad = _artifact_aad(prepared_without_policy, key_ref)
            if hashlib.sha256(aad).digest() != _blob(row, "aad_sha256", 32):
                raise ValueError
            payload = AESGCM(brain_key.material).decrypt(
                _blob(row, "nonce", _NONCE_BYTES),
                _blob(row, "ciphertext"),
                aad,
            )
            if hashlib.sha256(payload).digest() != _blob(row, "sanitized_sha256", 32):
                raise ValueError
            if len(payload) != _integer(row["sanitized_size"]):
                raise ValueError
        policy = (
            None if policy_document is None else _decode_policy_result(policy_document, payload)
        )
        prepared = _row_identity(row, disposition, policy)
        if _preparation_digest(prepared) != prepared.preparation_sha256:
            raise ValueError
        return prepared


@dataclass(frozen=True, slots=True)
class CanonicalWorkspaceCheckpointIngestor:
    """Apply Core privacy policy and append replay-stable canonical file events."""

    preparations: SqlitePreparedWorkspaceChangeRepository
    policy_pipeline: CapturePolicyPipeline
    policy_decisions: CapturePolicyDecisionRepository
    scope_resolver: AgentEventScopeResolver
    appender: AppendAgentEventHandler
    clock: Clock

    async def ingest(  # noqa: C901 -- Maps every cross-context failure to a closed Core error.
        self,
        batch: WorkspaceCheckpointBatch,
        registration: McpSessionRegistration,
    ) -> WorkspaceCheckpointIngestionResult:
        """Durably settle every change or leave the entire batch retryable."""
        if registration.project_id is None or registration.repository_id is None:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "workspace identity is not resolved",
                retryable=True,
            )
        outcomes: list[dict[str, object]] = []
        event_count = 0
        try:
            for ordinal, change in enumerate(batch.changes):
                prepared = await self.preparations.load(
                    batch,
                    registration,
                    ordinal,
                    change,
                )
                if prepared is None:
                    prepared = await self._prepare(batch, registration, ordinal, change)
                    prepared = await self.preparations.save(prepared)
                if prepared.disposition is WorkspaceChangeDisposition.EXCLUDED:
                    if prepared.policy is None:  # pragma: no cover - restored invariant.
                        raise AssertionError
                    await self.policy_decisions.record(
                        prepared.event_id,
                        prepared.brain_id,
                        registration.actor_id.value,
                        prepared.policy,
                        _microseconds(self.clock.now()),
                    )
                elif prepared.emits_event:
                    await self._append(prepared, registration, ordinal)
                    event_count += 1
                outcomes.append(
                    {
                        "disposition": prepared.disposition.value,
                        "event_id": prepared.event_id if prepared.emits_event else None,
                        "ordinal": ordinal,
                        "preparation_sha256": prepared.preparation_sha256,
                    }
                )
        except OperationError:
            raise
        except IngestionAuthorizationError as error:
            raise OperationError(
                ErrorCode.FORBIDDEN,
                "workspace event is not authorized",
            ) from error
        except IngestionConflictError as error:
            raise OperationError(ErrorCode.CONFLICT, "workspace event conflicted") from error
        except IngestionCapacityError as error:
            raise OperationError(
                ErrorCode.CAPACITY_EXHAUSTED,
                "workspace event capacity is unavailable",
                retryable=error.retryable,
            ) from error
        except IngestionDependencyError as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "workspace event ingestion is unavailable",
                retryable=True,
            ) from error
        result = _canonical_json(
            {
                "batch_digest": batch.batch_digest.value,
                "outcomes": outcomes,
                "schema_version": 1,
            }
        )
        return WorkspaceCheckpointIngestionResult(
            Sha256Digest.from_bytes(result),
            event_count,
        )

    async def _prepare(
        self,
        batch: WorkspaceCheckpointBatch,
        registration: McpSessionRegistration,
        ordinal: int,
        change: WorkspaceCheckpointChange,
    ) -> PreparedWorkspaceChange:
        base = _base_document(batch, registration, ordinal, change)
        base_digest = hashlib.sha256(_canonical_json(base)).hexdigest()
        event_id = stable_evidence_uuid7(_framed_digest("pf005-event-v1", base_digest))
        change_id = stable_evidence_uuid7(_framed_digest("pf005-change-v1", base_digest))
        repository_id = registration.repository_id
        if repository_id is None:  # pragma: no cover - ingest precondition.
            raise AssertionError
        try:
            policy = await self.policy_pipeline.execute(
                CapturePolicyCommand(
                    brain_id=registration.brain_id.value,
                    repository_id=repository_id.value,
                    content=bytearray(
                        _deleted_policy_payload(change) if change.deleted else change.content
                    ),
                    media_type="application/json" if change.deleted else "text/plain",
                    source_path=change.relative_path,
                    declared_classification=Classification.INTERNAL,
                )
            )
        except IngestionValidationError:
            prepared = _prepared_from_base(
                base,
                event_id,
                change_id,
                disposition=WorkspaceChangeDisposition.REJECTED,
                policy=None,
                rejection_code="policy_validation",
            )
            return _with_preparation_digest(prepared)
        disposition = (
            WorkspaceChangeDisposition.EXCLUDED
            if policy.disposition is CaptureDisposition.EXCLUDED
            else WorkspaceChangeDisposition.EVENT
        )
        prepared = _prepared_from_base(
            base,
            event_id,
            change_id,
            disposition=disposition,
            policy=policy,
            rejection_code=None,
        )
        return _with_preparation_digest(prepared)

    async def _append(
        self,
        prepared: PreparedWorkspaceChange,
        registration: McpSessionRegistration,
        ordinal: int,
    ) -> None:
        if prepared.policy is None or prepared.policy.payload is None:
            raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "workspace policy is invalid")
        event = _event(prepared, registration, ordinal)
        admitted = await AgentEventAdmissionHandler(
            _BUILTIN_CAPABILITIES,
            self.scope_resolver,
            InlineOnlyPayloadReader(),
            self.clock,
        ).execute(event)
        result = await self.appender.execute(
            AppendAgentEventCommand(
                AdmittedAgentEvent(
                    event,
                    admitted.identity,
                    admitted.ingested_at,
                    admitted.clock_skew_microseconds,
                    prepared.policy,
                )
            )
        )
        if result.event_id != prepared.event_id or result.disposition not in {
            AppendDisposition.ACCEPTED,
            AppendDisposition.DUPLICATE,
        }:
            raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "workspace event ACK is invalid")


def _event(
    prepared: PreparedWorkspaceChange,
    registration: McpSessionRegistration,
    ordinal: int,
) -> AgentEvent:
    if registration.project_id is None or registration.repository_id is None:
        raise AssertionError
    policy = prepared.policy
    if policy is None or policy.payload is None:
        raise AssertionError
    family = EventFamily.FILE_DELETED if prepared.deleted else EventFamily.FILE_CHANGED
    artifact_content = prepared.artifact_content
    payload = _canonical_json(
        {
            "artifact": (
                None
                if artifact_content is None
                else {
                    "change_id": prepared.change_id,
                    "content_sha256": hashlib.sha256(artifact_content).hexdigest(),
                    "size_bytes": len(artifact_content),
                }
            ),
            "batch_sha256": prepared.batch_digest,
            "change_kind": "deleted" if prepared.deleted else "changed",
            "partial_checkpoint": prepared.partial,
            "path": prepared.relative_path,
            "source_content_sha256": prepared.source_sha256,
        }
    )
    data = AgentEventData(payload, hashlib.sha256(payload).hexdigest())
    observation = NativeEventObservation(
        event_id=prepared.event_id,
        event_type=family,
        subject=(
            f"repository/{registration.repository_id.value}/file/{prepared.relative_path_sha256}"
        ),
        occurred_at=registration.issued_at + timedelta(microseconds=ordinal),
        claimed_identity=AgentEventIdentity(
            registration.brain_id.value,
            registration.actor_id.value,
            registration.project_id.value,
            registration.repository_id.value,
            None if registration.checkout_id is None else registration.checkout_id.value,
            None,
            None,
        ),
        agent_host=registration.agent_id,
        model_id="unknown",
        session_id=registration.session_id.value,
        task_id=None,
        turn_id=None,
        subagent_id=None,
        correlation_id=registration.session_id.value,
        causation_id=None,
        ordering_key=stable_evidence_uuid7(_framed_digest("pf005-order-v1", prepared.batch_digest)),
        sequence=ordinal + 1,
        classification=policy.classification,
        retention_policy_id="default",
        capture_method=CaptureMethod.NATIVE,
        source_sha256=prepared.preparation_sha256,
        payload=data,
        payload_reference=None,
        capture_capabilities=(CaptureCapability.FILE_OBSERVATION,),
    )
    return CanonicalNativeEventTranslator(_BUILTIN_MANIFEST).translate(observation)


def _base_document(
    batch: WorkspaceCheckpointBatch,
    registration: McpSessionRegistration,
    ordinal: int,
    change: WorkspaceCheckpointChange,
) -> dict[str, object]:
    if registration.project_id is None or registration.repository_id is None:
        raise OperationError(
            ErrorCode.DEPENDENCY_UNAVAILABLE,
            "workspace identity is not resolved",
            retryable=True,
        )
    return {
        "batch_digest": batch.batch_digest.value,
        "brain_id": registration.brain_id.value,
        "checkout_id": None if registration.checkout_id is None else registration.checkout_id.value,
        "deleted": change.deleted,
        "ordinal": ordinal,
        "partial": batch.partial,
        "project_id": registration.project_id.value,
        "relative_path": change.relative_path,
        "relative_path_sha256": hashlib.sha256(change.relative_path.encode()).hexdigest(),
        "repository_id": registration.repository_id.value,
        "session_id": registration.session_id.value,
        "source_sha256": change.sha256.value,
    }


def _base_from(prepared: PreparedWorkspaceChange) -> dict[str, object]:
    return {
        "batch_digest": prepared.batch_digest,
        "brain_id": prepared.brain_id,
        "checkout_id": prepared.checkout_id,
        "deleted": prepared.deleted,
        "ordinal": prepared.ordinal,
        "partial": prepared.partial,
        "project_id": prepared.project_id,
        "relative_path": prepared.relative_path,
        "relative_path_sha256": prepared.relative_path_sha256,
        "repository_id": prepared.repository_id,
        "session_id": prepared.session_id,
        "source_sha256": prepared.source_sha256,
    }


def _prepared_from_base(  # noqa: PLR0913 -- Canonical preparation is intentionally explicit.
    base: dict[str, object],
    event_id: str,
    change_id: str,
    *,
    disposition: WorkspaceChangeDisposition,
    policy: CapturePolicyResult | None,
    rejection_code: str | None,
) -> PreparedWorkspaceChange:
    return PreparedWorkspaceChange(
        batch_digest=str(base["batch_digest"]),
        ordinal=int(cast("int", base["ordinal"])),
        change_id=change_id,
        event_id=event_id,
        session_id=str(base["session_id"]),
        brain_id=str(base["brain_id"]),
        project_id=str(base["project_id"]),
        repository_id=str(base["repository_id"]),
        checkout_id=None if base["checkout_id"] is None else str(base["checkout_id"]),
        relative_path=str(base["relative_path"]),
        relative_path_sha256=str(base["relative_path_sha256"]),
        source_sha256=str(base["source_sha256"]),
        disposition=disposition,
        deleted=bool(base["deleted"]),
        partial=bool(base["partial"]),
        policy=policy,
        rejection_code=rejection_code,
        preparation_sha256="",
    )


def _row_identity(
    row: RowMapping,
    disposition: WorkspaceChangeDisposition,
    policy: CapturePolicyResult | None,
) -> PreparedWorkspaceChange:
    return PreparedWorkspaceChange(
        batch_digest=_blob(row, "batch_digest", 32).hex(),
        ordinal=_integer(row["ordinal"]),
        change_id=_required_text(row["change_id"]),
        event_id=_required_text(row["event_id"]),
        session_id=_required_text(row["session_id"]),
        brain_id=_required_text(row["brain_id"]),
        project_id=_required_text(row["project_id"]),
        repository_id=_required_text(row["repository_id"]),
        checkout_id=None if row["checkout_id"] is None else _required_text(row["checkout_id"]),
        relative_path=_required_text(row["relative_path"]),
        relative_path_sha256=_blob(row, "relative_path_sha256", 32).hex(),
        source_sha256=_blob(row, "source_sha256", 32).hex(),
        disposition=disposition,
        deleted=bool(_integer(row["deleted"])),
        partial=bool(_integer(row["partial"])),
        policy=policy,
        rejection_code=(
            None if row["rejection_code"] is None else _required_text(row["rejection_code"])
        ),
        preparation_sha256=_blob(row, "preparation_sha256", 32).hex(),
    )


def _with_preparation_digest(prepared: PreparedWorkspaceChange) -> PreparedWorkspaceChange:
    return replace(prepared, preparation_sha256=_preparation_digest(prepared))


def _preparation_digest(prepared: PreparedWorkspaceChange) -> str:
    document = {
        **_base_from(prepared),
        "change_id": prepared.change_id,
        "disposition": prepared.disposition.value,
        "event_id": prepared.event_id,
        "policy": _policy_document(prepared.policy),
        "rejection_code": prepared.rejection_code,
        "schema_version": 1,
    }
    return hashlib.sha256(_canonical_json(document)).hexdigest()


def _policy_document(result: CapturePolicyResult | None) -> dict[str, object] | None:
    if result is None:
        return None
    return {
        "classification": result.classification.value,
        "disposition": result.disposition.value,
        "egress": result.egress.value,
        "finding_counts": [
            {
                "detector_id": finding.detector_id,
                "end": finding.end,
                "field_path": finding.field_path,
                "kind": finding.kind.value,
                "start": finding.start,
            }
            for finding in result.findings
        ],
        "input_sha256": result.input_sha256,
        "output_sha256": result.output_sha256,
        "policy_id": result.policy_id,
        "policy_sha256": result.policy_sha256,
        "policy_version": result.policy_version,
        "reason_code": result.reason_code,
        "redaction_count": result.redaction_count,
        "stages": [
            {
                "outcome_code": stage.outcome_code,
                "rule_ids": list(stage.rule_ids),
                "stage": stage.stage.value,
            }
            for stage in result.stages
        ],
    }


def _decode_policy_result(document_json: str, payload: bytes | None) -> CapturePolicyResult:
    raw = cast("dict[str, object]", json.loads(document_json))
    findings = cast("list[dict[str, object]]", raw["finding_counts"])
    stages = cast("list[dict[str, object]]", raw["stages"])
    result = CapturePolicyResult(
        disposition=CaptureDisposition(str(raw["disposition"])),
        payload=payload,
        classification=Classification(str(raw["classification"])),
        egress=EgressDisposition(str(raw["egress"])),
        reason_code=str(raw["reason_code"]),
        policy_id=str(raw["policy_id"]),
        policy_version=int(cast("int", raw["policy_version"])),
        policy_sha256=str(raw["policy_sha256"]),
        input_sha256=str(raw["input_sha256"]),
        output_sha256=None if raw["output_sha256"] is None else str(raw["output_sha256"]),
        findings=tuple(
            SensitiveFinding(
                SensitiveKind(str(item["kind"])),
                str(item["field_path"]),
                int(cast("int", item["start"])),
                int(cast("int", item["end"])),
                str(item["detector_id"]),
            )
            for item in findings
        ),
        redaction_count=int(cast("int", raw["redaction_count"])),
        stages=tuple(
            StageEvidence(
                PolicyStage(str(item["stage"])),
                tuple(str(value) for value in cast("list[object]", item["rule_ids"])),
                str(item["outcome_code"]),
            )
            for item in stages
        ),
    )
    if _canonical_json(_policy_document(result)).decode() != document_json:
        raise ValueError
    return result


def _artifact_aad(prepared: PreparedWorkspaceChange, key_ref: str) -> bytes:
    return _canonical_json(
        {
            "batch_digest": prepared.batch_digest,
            "brain_id": prepared.brain_id,
            "change_id": prepared.change_id,
            "encryption_key_ref": key_ref,
            "event_id": prepared.event_id,
            "preparation_sha256": prepared.preparation_sha256,
            "purpose": "mcp-workspace-artifact-v1",
        }
    )


def _deleted_policy_payload(change: WorkspaceCheckpointChange) -> bytes:
    return _canonical_json(
        {
            "change_kind": "deleted",
            "path": change.relative_path,
            "source_content_sha256": change.sha256.value,
        }
    )


def _framed_digest(namespace: str, *parts: str) -> str:
    encoded = bytearray()
    for part in (namespace, *parts):
        value = part.encode()
        encoded.extend(len(value).to_bytes(8, "big"))
        encoded.extend(value)
    return hashlib.sha256(encoded).hexdigest()


def _canonical_json(document: object) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _microseconds(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        raise ValueError
    return int(value.timestamp()) * 1_000_000 + value.microsecond


def _required_text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError
    return value


def _blob(row: RowMapping, key: str, length: int | None = None) -> bytes:
    value = row[key]
    if not isinstance(value, bytes) or (length is not None and len(value) != length):
        raise ValueError
    return value


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError
    return value


def _conflict() -> None:
    raise OperationError(ErrorCode.CONFLICT, "workspace change conflicted")


def _built_in_capabilities() -> tuple[AdapterCapabilityManifest, RegisteredAdapterCapabilities]:
    availability = tuple(
        EvidenceAvailability(
            capability,
            CaptureMethod.NATIVE
            if capability is CaptureCapability.FILE_OBSERVATION
            else CaptureMethod.UNSUPPORTED,
        )
        for capability in CaptureCapability
    )
    manifest = AdapterCapabilityManifest.create(
        adapter_id=_ADAPTER_ID,
        adapter_version=_ADAPTER_VERSION,
        adapter_digest=_ADAPTER_DIGEST,
        schema_major=1,
        supported_families=(EventFamily.FILE_CHANGED, EventFamily.FILE_DELETED),
        evidence_availability=availability,
    )
    observation = AdapterCapabilityObservation.create(
        observation_id=_OBSERVATION_ID,
        operation_id="pf005-built-in",
        adapter_id=manifest.adapter_id,
        adapter_version=manifest.adapter_version,
        adapter_digest=manifest.adapter_digest,
        capability_manifest_digest=manifest.manifest_sha256,
        revision=1,
        evidence_availability=availability,
        observed_at=_OBSERVED_AT,
    )
    return manifest, RegisteredAdapterCapabilities(manifest, observation)


_BUILTIN_MANIFEST, _BUILTIN_CAPABILITIES = _built_in_capabilities()
