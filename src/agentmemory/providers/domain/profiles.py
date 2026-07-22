"""PRO-001 immutable provider-profile, manifest, and probe contracts."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Never
from uuid import UUID

from agentmemory.providers.domain.errors import (
    ProviderModelDriftError,
    ProviderProfileValidationError,
)

_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SECRET_REF = re.compile(r"^secret://[a-z0-9][a-z0-9/_-]{0,254}$")
_POLICY_REF = re.compile(r"^policy://[a-z0-9][a-z0-9/_-]{0,254}$")
_APPROVAL_REF = re.compile(r"^approval://[a-z0-9][a-z0-9/_-]{0,254}$")
_REGION = re.compile(r"^[A-Z]{2}(?:-[A-Z0-9]{1,8})*$|^global$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_UUID_VERSION = 7
_MAX_PURPOSES = 7
_MAX_ITEMS = 1000
_MAX_TOKENS = 1_000_000
_MAX_REQUESTS_PER_MINUTE = 1_000_000
_MAX_TOKENS_PER_MINUTE = 1_000_000_000
_MIN_TIMEOUT_MILLISECONDS = 100
_MAX_TIMEOUT_MILLISECONDS = 300_000
_MAX_RETENTION_DAYS = 3650
_MAX_VECTOR_DIMENSION = 65_536
_ERR_INPUT = "provider profile input is invalid"
_ERR_DRIFT = "provider model revision drifted"


class ProviderOperation(StrEnum):
    """Closed inference operations configurable by a profile."""

    EMBEDDING = "embedding"
    RERANKING = "reranking"


class ProviderExecutionClass(StrEnum):
    """Whether inference remains local or requires governed egress."""

    LOCAL = "local"
    REMOTE = "remote"


class ProviderProfileStatus(StrEnum):
    """Activation lifecycle exposed by PRO-001."""

    DRAFT = "draft"
    ACTIVE = "active"


class CanonicalPurpose(StrEnum):
    """Vendor-neutral semantic purposes from the provider protocol."""

    RETRIEVAL_QUERY = "retrieval_query"
    RETRIEVAL_DOCUMENT = "retrieval_document"
    CODE_QUERY = "code_query"
    CODE_DOCUMENT = "code_document"
    SEMANTIC_SIMILARITY = "semantic_similarity"
    CLASSIFICATION = "classification"
    CLUSTERING = "clustering"


class VectorDtype(StrEnum):
    """Numeric representations accepted by the first-party conformance suite."""

    FLOAT32 = "float32"


class VectorNormalization(StrEnum):
    """Declared vector normalization behavior."""

    NONE = "none"
    L2 = "l2"
    PROVIDER_DEFINED = "provider_defined"


class SimilarityMetric(StrEnum):
    """Declared comparison semantics for an embedding model."""

    COSINE = "cosine"
    DOT_PRODUCT = "dot_product"


@dataclass(frozen=True, slots=True)
class ProviderLimits:
    """Profile limits that can only narrow an adapter manifest."""

    max_items: int
    max_input_bytes: int
    max_item_tokens: int
    max_request_tokens: int
    timeout_milliseconds: int

    def __post_init__(self) -> None:
        """Require positive, production-bounded values."""
        if (
            not 1 <= self.max_items <= _MAX_ITEMS
            or not 1 <= self.max_input_bytes <= 8 * 1024 * 1024
            or not 1 <= self.max_item_tokens <= _MAX_TOKENS
            or not self.max_item_tokens <= self.max_request_tokens <= _MAX_TOKENS
            or not _MIN_TIMEOUT_MILLISECONDS
            <= self.timeout_milliseconds
            <= _MAX_TIMEOUT_MILLISECONDS
        ):
            _invalid()

    def narrows(self, maximum: ProviderLimits) -> bool:
        """Return whether every limit is no broader than the manifest."""
        return (
            self.max_items <= maximum.max_items
            and self.max_input_bytes <= maximum.max_input_bytes
            and self.max_item_tokens <= maximum.max_item_tokens
            and self.max_request_tokens <= maximum.max_request_tokens
            and self.timeout_milliseconds <= maximum.timeout_milliseconds
        )

    @property
    def document(self) -> dict[str, int]:
        """Return deterministic persistence fields."""
        return {
            "max_input_bytes": self.max_input_bytes,
            "max_item_tokens": self.max_item_tokens,
            "max_items": self.max_items,
            "max_request_tokens": self.max_request_tokens,
            "timeout_milliseconds": self.timeout_milliseconds,
        }


@dataclass(frozen=True, slots=True)
class ProviderQuota:
    """Explicit remote consumption ceiling."""

    requests_per_minute: int
    tokens_per_minute: int
    monthly_tokens: int

    def __post_init__(self) -> None:
        """Require explicit positive rate and monthly token ceilings."""
        if (
            not 1 <= self.requests_per_minute <= _MAX_REQUESTS_PER_MINUTE
            or not 1 <= self.tokens_per_minute <= _MAX_TOKENS_PER_MINUTE
            or not self.tokens_per_minute <= self.monthly_tokens <= 10**15
        ):
            _invalid()

    @property
    def document(self) -> dict[str, int]:
        """Return deterministic persistence fields."""
        return {
            "monthly_tokens": self.monthly_tokens,
            "requests_per_minute": self.requests_per_minute,
            "tokens_per_minute": self.tokens_per_minute,
        }


@dataclass(frozen=True, slots=True)
class ProviderBudget:
    """Owner-approved monthly monetary ceiling in integer micros."""

    currency: str
    monthly_micros: int

    def __post_init__(self) -> None:
        """Require an ISO-style currency and a positive integer-micro ceiling."""
        if _CURRENCY.fullmatch(self.currency) is None or not 1 <= self.monthly_micros <= 10**15:
            _invalid()

    @property
    def document(self) -> dict[str, object]:
        """Return deterministic persistence fields."""
        return {"currency": self.currency, "monthly_micros": self.monthly_micros}


@dataclass(frozen=True, slots=True)
class ProviderDataPolicy:
    """Administrator-recorded provider retention, training, and residency declaration."""

    declaration_version: str
    retention_days: int
    training_allowed: bool
    residency: str

    def __post_init__(self) -> None:
        """Require a versioned, bounded, explicit declaration."""
        if (
            _VERSION.fullmatch(self.declaration_version) is None
            or not 0 <= self.retention_days <= _MAX_RETENTION_DAYS
            or _REGION.fullmatch(self.residency) is None
        ):
            _invalid()

    @property
    def document(self) -> dict[str, object]:
        """Return deterministic persistence fields."""
        return {
            "declaration_version": self.declaration_version,
            "residency": self.residency,
            "retention_days": self.retention_days,
            "training_allowed": self.training_allowed,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderManifest:
    """Certified, content-free adapter capability manifest."""

    adapter_id: str
    implementation_version: str
    implementation_digest: str
    protocol_version: str
    execution_class: ProviderExecutionClass
    operations: tuple[ProviderOperation, ...]
    purposes: tuple[CanonicalPurpose, ...]
    limits: ProviderLimits
    revision_evidence: bool
    cancellation: bool
    vendor: str

    def __post_init__(self) -> None:
        """Require one canonical, revision-capable certified manifest."""
        if (
            _TOKEN.fullmatch(self.adapter_id) is None
            or _VERSION.fullmatch(self.implementation_version) is None
            or _DIGEST.fullmatch(self.implementation_digest) is None
            or self.protocol_version != "1.0"
            or not self.operations
            or tuple(sorted(set(self.operations), key=str)) != self.operations
            or not self.purposes
            or len(self.purposes) > _MAX_PURPOSES
            or tuple(sorted(set(self.purposes), key=str)) != self.purposes
            or not self.revision_evidence
            or _TOKEN.fullmatch(self.vendor) is None
        ):
            _invalid()

    @property
    def canonical_bytes(self) -> bytes:
        """Serialize the complete manifest authority canonically."""
        return _canonical_json(
            {
                "adapter_id": self.adapter_id,
                "cancellation": self.cancellation,
                "execution_class": self.execution_class.value,
                "implementation_digest": self.implementation_digest,
                "implementation_version": self.implementation_version,
                "limits": self.limits.document,
                "operations": [item.value for item in self.operations],
                "protocol_version": self.protocol_version,
                "purposes": [item.value for item in self.purposes],
                "revision_evidence": self.revision_evidence,
                "vendor": self.vendor,
            }
        )

    @property
    def digest(self) -> str:
        """Return the immutable manifest identity."""
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    def validate_configuration(self, configuration: ProviderProfileConfiguration) -> None:
        """Apply the same capability checks to every built-in adapter."""
        if (
            configuration.adapter_id != self.adapter_id
            or configuration.operation not in self.operations
            or not set(configuration.purposes).issubset(self.purposes)
            or not configuration.limits.narrows(self.limits)
            or configuration.execution_class is not self.execution_class
        ):
            _invalid()


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderProfileConfiguration:
    """Credential-reference-only configuration used to create a profile."""

    brain_id: str
    adapter_id: str
    operation: ProviderOperation
    model_id: str
    purposes: tuple[CanonicalPurpose, ...]
    limits: ProviderLimits
    execution_class: ProviderExecutionClass
    endpoint_policy_ref: str | None = None
    secret_ref: str | None = None
    egress_approval_ref: str | None = None
    data_policy: ProviderDataPolicy | None = None
    quota: ProviderQuota | None = None
    budget: ProviderBudget | None = None

    def __post_init__(self) -> None:
        """Require explicit local fields or the complete remote governance set."""
        try:
            brain = UUID(self.brain_id)
        except (TypeError, ValueError) as error:
            raise ProviderProfileValidationError(_ERR_INPUT) from error
        if (
            brain.version != _UUID_VERSION
            or _TOKEN.fullmatch(self.adapter_id) is None
            or _MODEL.fullmatch(self.model_id) is None
            or not self.purposes
            or len(self.purposes) > _MAX_PURPOSES
            or tuple(sorted(set(self.purposes), key=str)) != self.purposes
        ):
            _invalid()
        remote_values = (
            self.endpoint_policy_ref,
            self.secret_ref,
            self.egress_approval_ref,
            self.data_policy,
            self.quota,
            self.budget,
        )
        if self.execution_class is ProviderExecutionClass.REMOTE:
            if (
                any(value is None for value in remote_values)
                or _POLICY_REF.fullmatch(self.endpoint_policy_ref or "") is None
                or _SECRET_REF.fullmatch(self.secret_ref or "") is None
                or _APPROVAL_REF.fullmatch(self.egress_approval_ref or "") is None
            ):
                _invalid()
        elif any(value is not None for value in remote_values):
            _invalid()

    @property
    def canonical_bytes(self) -> bytes:
        """Serialize configuration including references but no credential values."""
        return _canonical_json(self.document)

    @property
    def digest(self) -> str:
        """Return the immutable configuration identity."""
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    @property
    def document(self) -> dict[str, object]:
        """Return the complete canonical persistence document."""
        return {
            "adapter_id": self.adapter_id,
            "brain_id": self.brain_id,
            "budget": None if self.budget is None else self.budget.document,
            "data_policy": None if self.data_policy is None else self.data_policy.document,
            "egress_approval_ref": self.egress_approval_ref,
            "endpoint_policy_ref": self.endpoint_policy_ref,
            "execution_class": self.execution_class.value,
            "limits": self.limits.document,
            "model_id": self.model_id,
            "operation": self.operation.value,
            "purposes": [item.value for item in self.purposes],
            "quota": None if self.quota is None else self.quota.document,
            "secret_ref": self.secret_ref,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderProbeResult:
    """Strict adapter output before it becomes durable activation evidence."""

    adapter_id: str
    model_id: str
    model_revision: str
    revision_fingerprint: str
    operation: ProviderOperation
    purposes: tuple[CanonicalPurpose, ...]
    dimension: int | None
    dtype: VectorDtype | None
    normalization: VectorNormalization | None
    similarity: SimilarityMetric | None
    max_items: int
    cancellation_verified: bool

    def __post_init__(self) -> None:
        """Reject incomplete, non-finite, or operation-incompatible probe facts."""
        embedding = self.operation is ProviderOperation.EMBEDDING
        if (
            _TOKEN.fullmatch(self.adapter_id) is None
            or _MODEL.fullmatch(self.model_id) is None
            or _VERSION.fullmatch(self.model_revision) is None
            or _DIGEST.fullmatch(self.revision_fingerprint) is None
            or not self.purposes
            or tuple(sorted(set(self.purposes), key=str)) != self.purposes
            or not 1 <= self.max_items <= _MAX_ITEMS
            or not self.cancellation_verified
            or (
                embedding
                and (
                    self.dimension is None
                    or not 1 <= self.dimension <= _MAX_VECTOR_DIMENSION
                    or self.dtype is None
                    or self.normalization is None
                    or self.similarity is None
                )
            )
            or (
                not embedding
                and any(
                    value is not None
                    for value in (self.dimension, self.dtype, self.normalization, self.similarity)
                )
            )
        ):
            _invalid()


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderProbeEvidence:
    """Content-free, immutable live capability attestation."""

    evidence_id: str
    profile_id: str
    manifest_digest: str
    result: ProviderProbeResult
    probed_at: datetime

    def __post_init__(self) -> None:
        """Authenticate this evidence against its canonical content identity."""
        if (
            _DIGEST.fullmatch(self.evidence_id) is None
            or _DIGEST.fullmatch(self.manifest_digest) is None
            or self.probed_at.tzinfo is None
            or self.probed_at.utcoffset() != UTC.utcoffset(self.probed_at)
        ):
            _invalid()
        try:
            profile = UUID(self.profile_id)
        except (TypeError, ValueError) as error:
            raise ProviderProfileValidationError(_ERR_INPUT) from error
        if profile.version != _UUID_VERSION or self.evidence_id != self.expected_id:
            _invalid()

    @classmethod
    def create(
        cls,
        profile_id: str,
        manifest_digest: str,
        result: ProviderProbeResult,
        probed_at: datetime,
    ) -> ProviderProbeEvidence:
        """Construct a content-addressed live probe attestation."""
        payload = _canonical_json(
            {
                "adapter_id": result.adapter_id,
                "cancellation_verified": result.cancellation_verified,
                "dimension": result.dimension,
                "dtype": None if result.dtype is None else result.dtype.value,
                "manifest_digest": manifest_digest,
                "max_items": result.max_items,
                "model_id": result.model_id,
                "model_revision": result.model_revision,
                "normalization": (
                    None if result.normalization is None else result.normalization.value
                ),
                "operation": result.operation.value,
                "probed_at": _micros(probed_at),
                "profile_id": profile_id,
                "purposes": [item.value for item in result.purposes],
                "revision_fingerprint": result.revision_fingerprint,
                "similarity": None if result.similarity is None else result.similarity.value,
            }
        )
        return cls(
            evidence_id=hashlib.sha256(payload).hexdigest(),
            profile_id=profile_id,
            manifest_digest=manifest_digest,
            result=result,
            probed_at=probed_at,
        )

    @property
    def expected_id(self) -> str:
        """Recompute the expected content-addressed evidence identity."""
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    @property
    def canonical_bytes(self) -> bytes:
        """Serialize only content-free probe capability evidence."""
        result = self.result
        return _canonical_json(
            {
                "adapter_id": result.adapter_id,
                "cancellation_verified": result.cancellation_verified,
                "dimension": result.dimension,
                "dtype": None if result.dtype is None else result.dtype.value,
                "manifest_digest": self.manifest_digest,
                "max_items": result.max_items,
                "model_id": result.model_id,
                "model_revision": result.model_revision,
                "normalization": (
                    None if result.normalization is None else result.normalization.value
                ),
                "operation": result.operation.value,
                "probed_at": _micros(self.probed_at),
                "profile_id": self.profile_id,
                "purposes": [item.value for item in result.purposes],
                "revision_fingerprint": result.revision_fingerprint,
                "similarity": None if result.similarity is None else result.similarity.value,
            }
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderProfile:
    """Current profile snapshot backed by immutable revisions and probe evidence."""

    profile_id: str
    configuration: ProviderProfileConfiguration
    manifest_digest: str
    status: ProviderProfileStatus
    version: int
    created_at: datetime
    updated_at: datetime
    active_probe: ProviderProbeEvidence | None = None

    def __post_init__(self) -> None:
        """Require a valid revision/status/evidence snapshot shape."""
        try:
            profile = UUID(self.profile_id)
        except (TypeError, ValueError) as error:
            raise ProviderProfileValidationError(_ERR_INPUT) from error
        if (
            profile.version != _UUID_VERSION
            or _DIGEST.fullmatch(self.manifest_digest) is None
            or not 1 <= self.version <= 2**31 - 1
            or self.created_at.tzinfo is None
            or self.updated_at.tzinfo is None
            or self.created_at.utcoffset() != UTC.utcoffset(self.created_at)
            or self.updated_at.utcoffset() != UTC.utcoffset(self.updated_at)
            or self.updated_at < self.created_at
            or (self.status is ProviderProfileStatus.DRAFT) != (self.active_probe is None)
            or (
                self.active_probe is not None
                and (
                    self.active_probe.profile_id != self.profile_id
                    or self.active_probe.manifest_digest != self.manifest_digest
                )
            )
        ):
            _invalid()

    @property
    def canonical_bytes(self) -> bytes:
        """Serialize the snapshot canonically."""
        return _canonical_json(self.document)

    @property
    def snapshot_digest(self) -> str:
        """Return the content identity of this exact snapshot revision."""
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    @property
    def document(self) -> dict[str, object]:
        """Return persistence fields without embedding secret values or probe payloads."""
        return {
            "active_probe_id": None if self.active_probe is None else self.active_probe.evidence_id,
            "configuration": self.configuration.document,
            "created_at": _micros(self.created_at),
            "manifest_digest": self.manifest_digest,
            "profile_id": self.profile_id,
            "status": self.status.value,
            "updated_at": _micros(self.updated_at),
            "version": self.version,
        }

    def activate(self, evidence: ProviderProbeEvidence) -> ProviderProfile:
        """Bind one live result while refusing mutable-alias or manifest drift."""
        result = evidence.result
        configuration = self.configuration
        if (
            evidence.profile_id != self.profile_id
            or evidence.manifest_digest != self.manifest_digest
            or evidence.probed_at < self.updated_at
            or result.adapter_id != configuration.adapter_id
            or result.model_id != configuration.model_id
            or result.operation is not configuration.operation
            or not set(configuration.purposes).issubset(result.purposes)
            or result.max_items < configuration.limits.max_items
        ):
            _invalid()
        if (
            self.active_probe is not None
            and self.active_probe.result.revision_fingerprint != result.revision_fingerprint
        ):
            raise ProviderModelDriftError(_ERR_DRIFT)
        return replace(
            self,
            status=ProviderProfileStatus.ACTIVE,
            version=self.version + 1,
            updated_at=evidence.probed_at,
            active_probe=evidence,
        )


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError) as error:
        raise ProviderProfileValidationError(_ERR_INPUT) from error


def _micros(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)


def finite_vector(values: tuple[float, ...]) -> bool:
    """Shared conformance predicate for adapter probe vectors."""
    return bool(values) and all(math.isfinite(value) for value in values)


def _invalid() -> Never:
    raise ProviderProfileValidationError(_ERR_INPUT)
