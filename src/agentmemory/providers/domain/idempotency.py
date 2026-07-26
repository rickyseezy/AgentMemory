"""Provider-operation identities and persistent semantic-cache evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from agentmemory.providers.domain.errors import ProviderErrorCode

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MODEL_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$")
_SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_SAFE_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UUID7 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_MAX_CONTENT_ITEMS = 1024
_MAX_TOKEN_COUNT = 1_000_000
_MAX_ESTIMATED_COST_MICROS = 10**15


class ProviderPurpose(StrEnum):
    """Closed provider purposes that require independently keyed result spaces."""

    EMBED_DOCUMENT = "embed_document"
    EMBED_QUERY = "embed_query"
    RERANK = "rerank"
    EXTRACT = "extract"


class ProviderPrivacyClass(StrEnum):
    """Privacy dimension included in every provider cache identity."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    LOCAL_ONLY = "local_only"


class ProviderClaimDisposition(StrEnum):
    """Closed result of atomically consulting the provider operation cache."""

    CLAIMED = "claimed"
    CACHED = "cached"
    FAILED = "failed"
    WAIT = "wait"


@dataclass(frozen=True, slots=True)
class ProviderOperationRequest:
    """Complete immutable identity of one potentially billable provider operation."""

    operation_id: str
    idempotency_key: str
    brain_id: str
    profile_id: str
    model_revision: str
    purpose: ProviderPurpose
    content_sha256: tuple[str, ...]
    preprocessing_revision: str
    privacy_class: ProviderPrivacyClass
    project_id: str | None
    private_block: bool
    secret_bearing: bool
    token_count: int
    estimated_cost_micros: int

    def __post_init__(self) -> None:
        """Reject missing cache dimensions and ambiguous mutable identifiers."""
        for value, name in (
            (self.operation_id, "operation_id"),
            (self.brain_id, "brain_id"),
            (self.profile_id, "profile_id"),
        ):
            if _UUID7.fullmatch(value) is None:
                msg = f"provider {name} is invalid"
                raise ValueError(msg)
        if self.project_id is not None and _UUID7.fullmatch(self.project_id) is None:
            msg = "provider project_id is invalid"
            raise ValueError(msg)
        if _SAFE_KEY.fullmatch(self.idempotency_key) is None:
            msg = "provider idempotency key is invalid"
            raise ValueError(msg)
        if _MODEL_REVISION.fullmatch(self.model_revision) is None:
            msg = "provider model revision is invalid"
            raise ValueError(msg)
        if not 1 <= len(self.content_sha256) <= _MAX_CONTENT_ITEMS or any(
            _DIGEST.fullmatch(value) is None for value in self.content_sha256
        ):
            msg = "provider content digest set is invalid"
            raise ValueError(msg)
        if _SAFE_REVISION.fullmatch(self.preprocessing_revision) is None:
            msg = "provider preprocessing revision is invalid"
            raise ValueError(msg)
        if (
            not 1 <= self.token_count <= _MAX_TOKEN_COUNT
            or not 0 <= self.estimated_cost_micros <= _MAX_ESTIMATED_COST_MICROS
        ):
            msg = "provider operation accounting is invalid"
            raise ValueError(msg)

    @property
    def cache_key_sha256(self) -> str:
        """Hash every semantic dimension that may alter provider output or authorization."""
        return _canonical_digest(
            {
                "brain_id": self.brain_id,
                "content_sha256": list(self.content_sha256),
                "model_revision": self.model_revision,
                "preprocessing_revision": self.preprocessing_revision,
                "private_block": self.private_block,
                "privacy_class": self.privacy_class.value,
                "profile_id": self.profile_id,
                "project_id": self.project_id,
                "purpose": self.purpose.value,
                "secret_bearing": self.secret_bearing,
            }
        )

    @property
    def request_sha256(self) -> str:
        """Bind the caller operation identity to the complete semantic request."""
        return _canonical_digest(
            {
                "brain_id": self.brain_id,
                "cache_key_sha256": self.cache_key_sha256,
                "estimated_cost_micros": self.estimated_cost_micros,
                "operation_id": self.operation_id,
                "token_count": self.token_count,
            }
        )

    @property
    def preprocessing_digest(self) -> str:
        """Bind the named preprocessing contract to one canonical digest."""
        return hashlib.sha256(self.preprocessing_revision.encode()).hexdigest()

    @property
    def downstream_idempotency_key(self) -> str:
        """Return the stable key that every billable adapter must forward unchanged."""
        return f"am-provider-v1:{self.cache_key_sha256}"


@dataclass(frozen=True, slots=True)
class ProviderOperationOutcome:
    """Content-addressed provider result safe to replay without another invocation."""

    result_sha256: str
    result_ref: str
    usage_units: int

    def __post_init__(self) -> None:
        """Require an exact CAS result and nonnegative recorded usage."""
        if (
            _DIGEST.fullmatch(self.result_sha256) is None
            or self.result_ref != f"cas://sha256/{self.result_sha256}"
            or self.usage_units < 0
        ):
            msg = "provider operation outcome is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class ProviderOperationClaim:
    """Claim, wait, or replay evidence returned by persistent cache arbitration."""

    operation: ProviderOperationRequest
    disposition: ProviderClaimDisposition
    owner: str | None
    lease_until_microseconds: int | None
    attempt: int
    cached_outcome: ProviderOperationOutcome | None
    failure_code: str | None = None

    def __post_init__(self) -> None:
        """Enforce the exact evidence shape for each claim disposition."""
        claimed = self.disposition is ProviderClaimDisposition.CLAIMED
        cached = self.disposition is ProviderClaimDisposition.CACHED
        failed = self.disposition is ProviderClaimDisposition.FAILED
        if self.attempt < 1:
            msg = "provider operation claim attempt is invalid"
            raise ValueError(msg)
        if claimed != (self.owner is not None and self.lease_until_microseconds is not None):
            msg = "provider operation lease evidence is invalid"
            raise ValueError(msg)
        if cached != (self.cached_outcome is not None):
            msg = "provider operation cache evidence is invalid"
            raise ValueError(msg)
        if failed != (self.failure_code is not None) or (
            self.failure_code is not None
            and self.failure_code not in {item.value for item in ProviderErrorCode}
        ):
            msg = "provider operation failure evidence is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class ProviderExecutionResult:
    """Application result distinguishing a charged execution from a cache replay."""

    outcome: ProviderOperationOutcome
    cached: bool


def _canonical_digest(document: dict[str, object]) -> str:
    encoded = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()
