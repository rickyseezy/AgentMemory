"""PRO-001 SQLite provider profile, revision, probe, and operation repository."""

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.providers.adapters.strict_json import (
    StrictJsonError,
    canonical_bytes,
    loads,
    require_object,
)
from agentmemory.providers.domain.errors import (
    ProviderModelDriftError,
    ProviderProfileAuthorizationError,
    ProviderProfileConflictError,
    ProviderProfileDependencyError,
)
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderBudget,
    ProviderDataPolicy,
    ProviderExecutionClass,
    ProviderLimits,
    ProviderOperation,
    ProviderProbeBinding,
    ProviderProbeEvidence,
    ProviderProbeResult,
    ProviderProfile,
    ProviderProfileConfiguration,
    ProviderProfileStatus,
    ProviderQuota,
    SimilarityMetric,
    VectorDtype,
    VectorNormalization,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_ERR_AUTHORIZATION = "provider profile storage action is not authorized"
_ERR_CONFLICT = "provider profile conflicts with immutable history"
_ERR_INTEGRITY = "provider profile storage failed integrity verification"
_ERR_STORAGE = "provider profile storage is unavailable"
_ACTIONS = {
    "create": "provider.profile.create",
    "probe": "provider.profile.probe",
    "read": "provider.profile.read",
}
_ROLES = frozenset({"owner", "admin"})


class SqliteProviderProfileRepository:
    """Persist profile snapshots while retaining immutable revisions and probe evidence."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the sole canonical SQLite writer."""
        self._store = store

    async def create(  # noqa: PLR0913 -- Binds authority, identity, manifest, and time.
        self,
        scope: AuthorizedScope,
        operation_id: str,
        profile_id: str,
        configuration: ProviderProfileConfiguration,
        manifest_digest: str,
        created_at: datetime,
    ) -> ProviderProfile:
        """Create or exactly replay one draft in a serialized transaction."""
        try:
            async with _write_transaction(self._store) as connection:
                await _authorize(connection, scope, "create", created_at)
                replay = await _operation_row(connection, operation_id)
                if replay is not None:
                    return await _replay(
                        connection,
                        replay,
                        scope,
                        "create",
                        None,
                        configuration.digest,
                    )
                profile = ProviderProfile(
                    profile_id=profile_id,
                    configuration=configuration,
                    manifest_digest=manifest_digest,
                    status=ProviderProfileStatus.DRAFT,
                    version=1,
                    created_at=created_at,
                    updated_at=created_at,
                )
                await _insert_profile(connection, profile)
                await _insert_revision(connection, scope, profile)
                await _insert_operation(
                    connection,
                    operation_id,
                    "create",
                    profile,
                    configuration.digest,
                    created_at,
                )
                await _append_command_evidence(
                    connection,
                    scope,
                    operation_id,
                    "create",
                    None,
                    profile,
                    created_at,
                )
                return profile
        except ProviderProfileAuthorizationError, ProviderProfileConflictError:
            raise
        except IntegrityError as error:
            raise ProviderProfileConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderProfileDependencyError(_ERR_STORAGE) from error

    async def get(
        self,
        scope: AuthorizedScope,
        profile_id: str,
        requested_at: datetime,
    ) -> ProviderProfile | None:
        """Read a current snapshot only after fresh Brain-wide authorization."""
        try:
            async with self._store.engine.connect() as connection:
                await _authorize(connection, scope, "read", requested_at)
                row = await _profile_row(connection, profile_id, scope.brain_id.value)
                return None if row is None else await _decode_row(connection, row)
        except ProviderProfileAuthorizationError:
            raise
        except SQLAlchemyError as error:
            raise ProviderProfileDependencyError(_ERR_STORAGE) from error
        except (StrictJsonError, KeyError, TypeError, ValueError) as error:
            raise ProviderProfileConflictError(_ERR_INTEGRITY) from error

    async def find_operation(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        operation_kind: str,
        profile_id: str | None,
        requested_at: datetime,
    ) -> ProviderProfile | None:
        """Replay the exact historical response before another provider call."""
        try:
            async with self._store.engine.connect() as connection:
                await _authorize(connection, scope, operation_kind, requested_at)
                row = await _operation_row(connection, operation_id)
                if row is None:
                    return None
                return await _replay(
                    connection,
                    row,
                    scope,
                    operation_kind,
                    profile_id,
                    None,
                )
        except ProviderProfileAuthorizationError, ProviderProfileConflictError:
            raise
        except SQLAlchemyError as error:
            raise ProviderProfileDependencyError(_ERR_STORAGE) from error
        except (StrictJsonError, KeyError, TypeError, ValueError) as error:
            raise ProviderProfileConflictError(_ERR_INTEGRITY) from error

    async def activate(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        expected_version: int,
        evidence: ProviderProbeEvidence,
    ) -> ProviderProfile:
        """Bind a live result only to the exact profile version probed by the caller."""
        try:
            async with _write_transaction(self._store) as connection:
                await _authorize(connection, scope, "probe", evidence.probed_at)
                request_digest = _probe_request_digest(evidence.profile_id, expected_version)
                replay = await _operation_row(connection, operation_id)
                if replay is not None:
                    return await _replay(
                        connection,
                        replay,
                        scope,
                        "probe",
                        evidence.profile_id,
                        request_digest,
                    )
                row = await _profile_row(connection, evidence.profile_id, scope.brain_id.value)
                if row is None:
                    raise ProviderProfileAuthorizationError(_ERR_AUTHORIZATION)  # noqa: TRY301
                profile = await _decode_row(connection, row)
                if profile.version != expected_version:
                    raise ProviderProfileConflictError(_ERR_CONFLICT)  # noqa: TRY301
                activated = profile.activate(evidence)
                await _insert_probe(connection, activated, evidence)
                result = await connection.execute(
                    text(
                        "UPDATE provider_profiles SET status=:status,version=:version,"
                        "active_probe_id=:probe,document_json=:document,updated_at=:updated "
                        "WHERE id=:profile AND brain_id=:brain AND version=:expected"
                    ),
                    {
                        "brain": scope.brain_id.value,
                        "document": activated.canonical_bytes,
                        "expected": expected_version,
                        "probe": evidence.evidence_id,
                        "profile": activated.profile_id,
                        "status": activated.status.value,
                        "updated": _micros(activated.updated_at),
                        "version": activated.version,
                    },
                )
                if result.rowcount != 1:
                    raise ProviderProfileConflictError(_ERR_CONFLICT)  # noqa: TRY301
                await _insert_revision(connection, scope, activated)
                await _insert_operation(
                    connection,
                    operation_id,
                    "probe",
                    activated,
                    request_digest,
                    evidence.probed_at,
                )
                await _append_command_evidence(
                    connection,
                    scope,
                    operation_id,
                    "probe",
                    profile,
                    activated,
                    evidence.probed_at,
                )
                return activated
        except (
            ProviderModelDriftError,
            ProviderProfileAuthorizationError,
            ProviderProfileConflictError,
        ):
            raise
        except IntegrityError as error:
            raise ProviderProfileConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderProfileDependencyError(_ERR_STORAGE) from error
        except (StrictJsonError, KeyError, TypeError, ValueError) as error:
            raise ProviderProfileConflictError(_ERR_INTEGRITY) from error


async def _authorize(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    operation_kind: str,
    at: datetime,
) -> None:
    expected = _ACTIONS.get(operation_kind)
    if (
        expected is None
        or scope.action != expected
        or scope.role.value not in _ROLES
        or scope.principal_id.value == ""
    ):
        raise ProviderProfileAuthorizationError(_ERR_AUTHORIZATION)
    authorized = (
        await connection.execute(
            text(
                "SELECT 1 FROM brains AS brain JOIN principals AS principal "
                "ON principal.id=:principal JOIN scope_grants AS grant "
                "ON grant.principal_id=principal.id AND grant.brain_id=brain.id "
                "WHERE brain.id=:brain AND brain.status='active' AND principal.status='active' "
                "AND grant.role IN ('owner','admin') AND grant.project_id IS NULL "
                "AND grant.repository_id IS NULL AND grant.valid_from<=:at "
                "AND (grant.valid_to IS NULL OR grant.valid_to>:at) LIMIT 1"
            ),
            {
                "at": _micros(at),
                "brain": scope.brain_id.value,
                "principal": scope.principal_id.value,
            },
        )
    ).scalar_one_or_none()
    if authorized is None:
        raise ProviderProfileAuthorizationError(_ERR_AUTHORIZATION)


async def _operation_row(connection: AsyncConnection, operation_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM provider_profile_operations WHERE operation_id=:operation"),
                {"operation": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _profile_row(
    connection: AsyncConnection,
    profile_id: str,
    brain_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM provider_profiles WHERE id=:profile AND brain_id=:brain"),
                {"brain": brain_id, "profile": profile_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _replay(  # noqa: PLR0913 -- Exact replay checks every immutable coordinate.
    connection: AsyncConnection,
    operation: RowMapping,
    scope: AuthorizedScope,
    expected_kind: str,
    expected_profile_id: str | None,
    expected_request_digest: str | None,
) -> ProviderProfile:
    if (
        str(operation["brain_id"]) != scope.brain_id.value
        or str(operation["operation_kind"]) != expected_kind
        or (expected_profile_id is not None and str(operation["profile_id"]) != expected_profile_id)
        or (
            expected_request_digest is not None
            and str(operation["request_digest"]) != expected_request_digest
        )
    ):
        raise ProviderProfileConflictError(_ERR_CONFLICT)
    row = (
        (
            await connection.execute(
                text(
                    "SELECT revision.document_json FROM provider_profile_revisions AS revision "
                    "WHERE revision.profile_id=:profile AND revision.version=:version"
                ),
                {
                    "profile": str(operation["profile_id"]),
                    "version": int(operation["result_version"]),
                },
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ProviderProfileConflictError(_ERR_INTEGRITY)
    profile = await _decode_document(connection, _blob(row["document_json"]))
    if profile.snapshot_digest != str(operation["result_snapshot_digest"]):
        raise ProviderProfileConflictError(_ERR_INTEGRITY)
    return profile


async def _decode_row(connection: AsyncConnection, row: RowMapping) -> ProviderProfile:
    profile = await _decode_document(connection, _blob(row["document_json"]))
    stored_status = str(row["status"])
    reprobe_overlay = (
        profile.status is ProviderProfileStatus.REPROBE_REQUIRED
        and stored_status == ProviderProfileStatus.ACTIVE.value
    )
    stored_probe_id = None if row["active_probe_id"] is None else str(row["active_probe_id"])
    document = require_object(loads(_blob(row["document_json"])))
    if (
        profile.profile_id != str(row["id"])
        or profile.configuration.brain_id != str(row["brain_id"])
        or profile.configuration.digest != str(row["configuration_digest"])
        or profile.manifest_digest != str(row["manifest_digest"])
        or (profile.status.value != stored_status and not reprobe_overlay)
        or profile.version != int(row["version"])
        or _optional_string(document.get("active_probe_id")) != stored_probe_id
    ):
        raise ProviderProfileConflictError(_ERR_INTEGRITY)
    return profile


async def _decode_document(connection: AsyncConnection, raw: bytes) -> ProviderProfile:
    document = require_object(loads(raw))
    active_probe_id = _optional_string(document.get("active_probe_id"))
    evidence = (
        None if active_probe_id is None else await _load_evidence(connection, active_probe_id)
    )
    configuration = _decode_configuration(require_object(document["configuration"]))
    status = ProviderProfileStatus(_string(document["status"]))
    if status is ProviderProfileStatus.ACTIVE and active_probe_id is not None and evidence is None:
        status = ProviderProfileStatus.REPROBE_REQUIRED
    return ProviderProfile(
        profile_id=_string(document["profile_id"]),
        configuration=configuration,
        manifest_digest=_string(document["manifest_digest"]),
        status=status,
        version=_integer(document["version"]),
        created_at=_instant(document["created_at"]),
        updated_at=_instant(document["updated_at"]),
        active_probe=evidence,
    )


async def _load_evidence(
    connection: AsyncConnection,
    evidence_id: str,
) -> ProviderProbeEvidence | None:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT evidence.evidence_json,attestation.adapter_digest,"
                    "attestation.endpoint_fingerprint,attestation.configuration_digest,"
                    "attestation.suite_digest,attestation.canary_digest,"
                    "attestation.validation_digest,attestation.validated_batches,"
                    "evidence.schema_version AS evidence_schema_version "
                    "FROM provider_probe_evidence AS evidence "
                    "LEFT JOIN provider_capability_attestations AS attestation "
                    "ON attestation.attestation_id=evidence.evidence_id "
                    "WHERE evidence.evidence_id=:evidence"
                ),
                {"evidence": evidence_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ProviderProfileConflictError(_ERR_INTEGRITY)
    if row["adapter_digest"] is None:
        if int(row["evidence_schema_version"]) == 1:
            return None
        raise ProviderProfileConflictError(_ERR_INTEGRITY)
    document = require_object(loads(_blob(row["evidence_json"])))
    result = ProviderProbeResult(
        adapter_id=_string(document["adapter_id"]),
        model_id=_string(document["model_id"]),
        model_revision=_string(document["model_revision"]),
        revision_fingerprint=_string(document["revision_fingerprint"]),
        endpoint_fingerprint=_string(document["endpoint_fingerprint"]),
        operation=ProviderOperation(_string(document["operation"])),
        purposes=_purposes(document["purposes"]),
        dimension=_optional_integer(document.get("dimension")),
        dtype=(None if document.get("dtype") is None else VectorDtype(_string(document["dtype"]))),
        normalization=(
            None
            if document.get("normalization") is None
            else VectorNormalization(_string(document["normalization"]))
        ),
        similarity=(
            None
            if document.get("similarity") is None
            else SimilarityMetric(_string(document["similarity"]))
        ),
        max_items=_integer(document["max_items"]),
        cancellation_verified=_boolean(document["cancellation_verified"]),
        suite_digest=_string(document["suite_digest"]),
        canary_digest=_string(document["canary_digest"]),
        validation_digest=_string(document["validation_digest"]),
        validated_batches=_integer(document["validated_batches"]),
    )
    evidence = ProviderProbeEvidence.create(
        ProviderProbeBinding(
            profile_id=_string(document["profile_id"]),
            manifest_digest=_string(document["manifest_digest"]),
            adapter_digest=_string(document["adapter_digest"]),
            configuration_digest=_string(document["configuration_digest"]),
        ),
        result,
        _instant(document["probed_at"]),
    )
    if evidence.evidence_id != evidence_id:
        raise ProviderProfileConflictError(_ERR_INTEGRITY)
    if (
        evidence.adapter_digest != str(row["adapter_digest"])
        or evidence.endpoint_fingerprint != str(row["endpoint_fingerprint"])
        or evidence.configuration_digest != str(row["configuration_digest"])
        or evidence.suite_digest != str(row["suite_digest"])
        or evidence.result.canary_digest != str(row["canary_digest"])
        or evidence.result.validation_digest != str(row["validation_digest"])
        or evidence.result.validated_batches != int(row["validated_batches"])
    ):
        raise ProviderProfileConflictError(_ERR_INTEGRITY)
    return evidence


def _decode_configuration(document: dict[str, object]) -> ProviderProfileConfiguration:
    data_raw = document.get("data_policy")
    quota_raw = document.get("quota")
    budget_raw = document.get("budget")
    data = None if data_raw is None else require_object(data_raw)
    quota = None if quota_raw is None else require_object(quota_raw)
    budget = None if budget_raw is None else require_object(budget_raw)
    limits = require_object(document["limits"])
    return ProviderProfileConfiguration(
        brain_id=_string(document["brain_id"]),
        adapter_id=_string(document["adapter_id"]),
        operation=ProviderOperation(_string(document["operation"])),
        model_id=_string(document["model_id"]),
        purposes=_purposes(document["purposes"]),
        limits=ProviderLimits(
            _integer(limits["max_items"]),
            _integer(limits["max_input_bytes"]),
            _integer(limits["max_item_tokens"]),
            _integer(limits["max_request_tokens"]),
            _integer(limits["timeout_milliseconds"]),
        ),
        execution_class=ProviderExecutionClass(_string(document["execution_class"])),
        endpoint_policy_ref=_optional_string(document.get("endpoint_policy_ref")),
        secret_ref=_optional_string(document.get("secret_ref")),
        egress_approval_ref=_optional_string(document.get("egress_approval_ref")),
        data_policy=(
            None
            if data is None
            else ProviderDataPolicy(
                _string(data["declaration_version"]),
                _integer(data["retention_days"]),
                _boolean(data["training_allowed"]),
                _string(data["residency"]),
            )
        ),
        quota=(
            None
            if quota is None
            else ProviderQuota(
                _integer(quota["requests_per_minute"]),
                _integer(quota["tokens_per_minute"]),
                _integer(quota["monthly_tokens"]),
            )
        ),
        budget=(
            None
            if budget is None
            else ProviderBudget(
                _string(budget["currency"]),
                _integer(budget["monthly_micros"]),
            )
        ),
    )


async def _insert_profile(connection: AsyncConnection, profile: ProviderProfile) -> None:
    configuration = profile.configuration
    await connection.execute(
        text(
            "INSERT INTO provider_profiles "
            "(id,brain_id,adapter_id,operation,model_id,configuration_digest,manifest_digest,"
            "status,version,active_probe_id,document_json,created_at,updated_at,schema_version) "
            "VALUES (:id,:brain,:adapter,:operation,:model,:configuration,:manifest,:status,"
            ":version,NULL,:document,:created,:updated,1)"
        ),
        {
            "adapter": configuration.adapter_id,
            "brain": configuration.brain_id,
            "configuration": configuration.digest,
            "created": _micros(profile.created_at),
            "document": profile.canonical_bytes,
            "id": profile.profile_id,
            "manifest": profile.manifest_digest,
            "model": configuration.model_id,
            "operation": configuration.operation.value,
            "status": profile.status.value,
            "updated": _micros(profile.updated_at),
            "version": profile.version,
        },
    )


async def _insert_revision(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    profile: ProviderProfile,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO provider_profile_revisions "
            "(profile_id,version,brain_id,status,snapshot_digest,document_json,principal_id,"
            "scope_fingerprint,recorded_at,schema_version) VALUES "
            "(:profile,:version,:brain,:status,:digest,:document,:principal,:scope,:at,1)"
        ),
        {
            "at": _micros(profile.updated_at),
            "brain": profile.configuration.brain_id,
            "digest": profile.snapshot_digest,
            "document": profile.canonical_bytes,
            "principal": scope.principal_id.value,
            "profile": profile.profile_id,
            "scope": bytes.fromhex(scope.scope_fingerprint),
            "status": profile.status.value,
            "version": profile.version,
        },
    )


async def _insert_probe(
    connection: AsyncConnection,
    profile: ProviderProfile,
    evidence: ProviderProbeEvidence,
) -> None:
    result = evidence.result
    await connection.execute(
        text(
            "INSERT INTO provider_probe_evidence "
            "(evidence_id,profile_id,profile_version,manifest_digest,adapter_id,operation,model_id,"
            "model_revision,revision_fingerprint,dimension,dtype,purposes_json,evidence_json,"
            "probed_at,schema_version) VALUES (:evidence,:profile,:version,:manifest,:adapter,"
            ":operation,:model,:revision,:fingerprint,:dimension,:dtype,:purposes,:document,:at,2)"
        ),
        {
            "adapter": result.adapter_id,
            "at": _micros(evidence.probed_at),
            "dimension": result.dimension,
            "document": evidence.canonical_bytes,
            "dtype": None if result.dtype is None else result.dtype.value,
            "evidence": evidence.evidence_id,
            "fingerprint": result.revision_fingerprint,
            "manifest": evidence.manifest_digest,
            "model": result.model_id,
            "operation": result.operation.value,
            "profile": evidence.profile_id,
            "purposes": canonical_bytes([item.value for item in result.purposes]),
            "revision": result.model_revision,
            "version": profile.version,
        },
    )
    await connection.execute(
        text(
            "INSERT INTO provider_capability_attestations "
            "(attestation_id,profile_id,adapter_digest,endpoint_fingerprint,"
            "configuration_digest,suite_digest,canary_digest,validation_digest,"
            "validated_batches,recorded_at,schema_version) VALUES "
            "(:attestation,:profile,:adapter,:endpoint,:configuration,:suite,:canary,"
            ":validation,:batches,:at,1)"
        ),
        {
            "adapter": evidence.adapter_digest,
            "at": _micros(evidence.probed_at),
            "attestation": evidence.evidence_id,
            "batches": result.validated_batches,
            "canary": result.canary_digest,
            "configuration": evidence.configuration_digest,
            "endpoint": evidence.endpoint_fingerprint,
            "profile": evidence.profile_id,
            "suite": evidence.suite_digest,
            "validation": result.validation_digest,
        },
    )


async def _insert_operation(  # noqa: PLR0913 -- Ledger binds complete result coordinates.
    connection: AsyncConnection,
    operation_id: str,
    kind: str,
    profile: ProviderProfile,
    request_digest: str,
    completed_at: datetime,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO provider_profile_operations "
            "(operation_id,operation_kind,brain_id,profile_id,request_digest,"
            "result_snapshot_digest,result_version,completed_at,schema_version) VALUES "
            "(:operation,:kind,:brain,:profile,:request,:result,:version,:at,1)"
        ),
        {
            "at": _micros(completed_at),
            "brain": profile.configuration.brain_id,
            "kind": kind,
            "operation": operation_id,
            "profile": profile.profile_id,
            "request": request_digest,
            "result": profile.snapshot_digest,
            "version": profile.version,
        },
    )


async def _append_command_evidence(  # noqa: PLR0913 -- One atomic command fact.
    connection: AsyncConnection,
    scope: AuthorizedScope,
    operation_id: str,
    kind: str,
    before: ProviderProfile | None,
    after: ProviderProfile,
    completed_at: datetime,
) -> None:
    """Append one content-free integration event and audit fact atomically."""
    event_name = "ProviderProfileCreated" if kind == "create" else "ProviderProfileActivated"
    action_name = "created" if kind == "create" else "activated"
    event_name_slug = "profile-created" if kind == "create" else "profile-activated"
    data: dict[str, object] = {
        "adapter_id": after.configuration.adapter_id,
        "brain_id": after.configuration.brain_id,
        "configuration_digest": after.configuration.digest,
        "manifest_digest": after.manifest_digest,
        "model_id": after.configuration.model_id,
        "operation": after.configuration.operation.value,
        "profile_id": after.profile_id,
        "schema_version": 1,
        "status": after.status.value,
        "version": after.version,
    }
    if after.active_probe is not None:
        data.update(
            {
                "evidence_id": after.active_probe.evidence_id,
                "model_revision": after.active_probe.result.model_revision,
                "revision_fingerprint": after.active_probe.result.revision_fingerprint,
            }
        )
    operation_digest = hashlib.sha256(
        f"provider-profile-command.v1\0{kind}\0{operation_id}".encode()
    ).hexdigest()
    source_event_id = f"provider-profile-event-{operation_digest}"
    integration_event_id = f"provider-profile-outbox-{operation_digest}"
    topic = f"am.local.{after.configuration.brain_id}.provider.{event_name_slug}.v1"
    payload = canonical_bytes(
        {
            "brain_id": after.configuration.brain_id,
            "correlation_id": operation_id,
            "data": data,
            "datacontenttype": "application/json",
            "dataschema": f"urn:agentmemory:schema:provider:{event_name_slug}:v1",
            "id": integration_event_id,
            "source": f"urn:agentmemory:brain:{after.configuration.brain_id}:providers",
            "specversion": "1.0",
            "subject": f"provider-profile/{after.profile_id}",
            "time": completed_at.isoformat(),
            "type": topic,
        }
    )
    now = _micros(completed_at)
    await connection.execute(
        text(
            "INSERT INTO agent_events "
            "(event_id,brain_id,type,payload_hash,classification,occurred_at,ingested_at,"
            "payload_ref,schema_version) VALUES "
            "(:event,:brain,:type,:payload_hash,'internal',:now,:now,NULL,1)"
        ),
        {
            "brain": after.configuration.brain_id,
            "event": source_event_id,
            "now": now,
            "payload_hash": hashlib.sha256(payload).digest(),
            "type": event_name,
        },
    )
    await connection.execute(
        text(
            "INSERT INTO outbox_messages "
            "(id,source_event_id,topic,message_key,payload,status,priority,not_before,attempts,"
            "lease_owner,lease_until,completed_at,payload_sha256,last_error_code,created_at,"
            "schema_version) VALUES (:id,:source,:topic,:key,:payload,'ready',100,:now,0,NULL,"
            "NULL,NULL,:digest,NULL,:now,1)"
        ),
        {
            "digest": hashlib.sha256(payload).digest(),
            "id": integration_event_id,
            "key": after.profile_id,
            "now": now,
            "payload": payload.decode(),
            "source": source_event_id,
            "topic": topic,
        },
    )
    previous = (
        await connection.execute(
            text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
        )
    ).scalar_one_or_none()
    previous_hash = bytes(32) if previous is None else _blob(previous)
    before_hash = bytes(32) if before is None else bytes.fromhex(before.snapshot_digest)
    after_hash = bytes.fromhex(after.snapshot_digest)
    audit_fact = canonical_bytes(
        {
            "action": f"provider.profile.{action_name}",
            "actor_id": scope.principal_id.value,
            "after_hash": after.snapshot_digest,
            "before_hash": None if before is None else before.snapshot_digest,
            "brain_id": after.configuration.brain_id,
            "operation_id": operation_id,
            "profile_id": after.profile_id,
        }
    )
    await connection.execute(
        text(
            "INSERT INTO audit_events "
            "(brain_id,actor_id,action,target_ref,idempotency_key,before_hash,after_hash,"
            "previous_hash,event_hash,occurred_at,schema_version) VALUES "
            "(:brain,:actor,:action,:target,:key,:before,:after,:previous,:event,:now,1)"
        ),
        {
            "action": f"provider.profile.{action_name}",
            "actor": scope.principal_id.value,
            "after": after_hash,
            "before": before_hash,
            "brain": after.configuration.brain_id,
            "event": hashlib.sha256(previous_hash + audit_fact).digest(),
            "key": f"provider.profile.{kind}:{operation_id}",
            "now": now,
            "previous": previous_hash,
            "target": f"provider-profile:{after.profile_id}",
        },
    )


def _probe_request_digest(profile_id: str, version: int) -> str:
    return hashlib.sha256(f"provider-probe.v1\0{profile_id}\0{version}".encode()).hexdigest()


def _purposes(value: object) -> tuple[CanonicalPurpose, ...]:
    if not isinstance(value, list):
        raise TypeError
    items = cast("list[object]", value)
    return tuple(CanonicalPurpose(_string(item)) for item in items)


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError
    return value


def _optional_string(value: object) -> str | None:
    return None if value is None else _string(value)


def _integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError
    return value


def _optional_integer(value: object) -> int | None:
    return None if value is None else _integer(value)


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError
    return value


def _instant(value: object) -> datetime:
    return datetime.fromtimestamp(_integer(value) / 1_000_000, tz=UTC)


def _blob(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode()
    raise TypeError


def _micros(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)


@asynccontextmanager
async def _write_transaction(store: SqliteCoreStore) -> AsyncIterator[AsyncConnection]:
    async with store.write_lock, store.engine.connect() as connection:
        await connection.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            yield connection
        except BaseException:
            await connection.rollback()
            raise
        else:
            await connection.commit()
