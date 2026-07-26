"""PRO-009 pure provider-egress and operation-sandbox contracts."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Never
from uuid import UUID

from agentmemory.identity.domain.retrieval_scope import Classification
from agentmemory.providers.domain.errors import (
    ProviderContainmentDeniedError,
    ProviderContainmentValidationError,
)

_UUID_VERSION = 7
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$")
_HOSTNAME = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_REGION = re.compile(r"^[A-Z]{2}(?:-[A-Z0-9]{1,8})*$|^global$")
_PURPOSES = frozenset(
    {
        "retrieval_query",
        "retrieval_document",
        "code_query",
        "code_document",
        "semantic_similarity",
        "classification",
        "clustering",
    }
)
_OPERATION_TYPES = frozenset({"embedding", "reranking"})
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/:.-]{1,500}@sha256:[0-9a-f]{64}$")
_NETWORK = re.compile(r"^agentmemory_[0-9a-f]{32}_internal$")
_OPERATION_PATH = re.compile(
    r"^/run/agentmemory/operations/[A-Za-z0-9._:-]{1,128}/(?:input|output)$"
)
_MAX_BYTES = 8 * 1024 * 1024
_MAX_PORT = 65_535
_MAX_PATH = 512
_MAX_RETENTION_DAYS = 3650
_MIN_TIMEOUT_MILLISECONDS = 100
_MAX_TIMEOUT_MILLISECONDS = 300_000
_MAX_ITEMS = 1000
_MAX_TOKENS = 1_000_000
_MAX_RATE = 1_000_000_000
_MAX_COST = 10**15
_MAX_SANDBOX_SECONDS = 300
_CLASSIFICATION_RANK = {
    Classification.PUBLIC: 0,
    Classification.INTERNAL: 1,
    Classification.CONFIDENTIAL: 2,
    Classification.RESTRICTED: 3,
    Classification.LOCAL_ONLY: 4,
}
_ERR_INPUT = "provider containment input is invalid"
_ERR_DENIED = "provider egress is denied"
_ERR_HOMOGENEOUS = "provider egress batch must be homogeneous"
_ERR_SANDBOX = "provider adapter sandbox is invalid"
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_RESULT_REF = re.compile(r"^cas://sha256/[0-9a-f]{64}$")
_CREDENTIAL_HEADERS = frozenset({"Authorization", "X-Goog-Api-Key", "X-Api-Key"})
_MAX_CREDENTIAL_BYTES = 4096
_MIN_HTTP_STATUS = 100
_MAX_HTTP_STATUS = 599
_ASCII_SPACE = 0x20
_ASCII_TILDE = 0x7E
_MAX_PERMIT_TOKEN_BYTES = 16_384


@dataclass(frozen=True, slots=True, kw_only=True)
class ContentTaint:
    """Closed content classification and irreversible sensitive-source taints."""

    classification: Classification
    private_block: bool
    secret_bearing: bool

    @property
    def intrinsically_denied(self) -> bool:
        """Return whether remote egress is forbidden regardless of policy."""
        return (
            self.classification in {Classification.RESTRICTED, Classification.LOCAL_ONLY}
            or self.private_block
            or self.secret_bearing
        )

    @property
    def document(self) -> dict[str, object]:
        """Return content-free taint coordinates."""
        return {
            "classification": self.classification.value,
            "private_block": self.private_block,
            "secret_bearing": self.secret_bearing,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class EgressDestination:
    """One exact HTTPS authority, residency, and allowed path prefix."""

    scheme: str
    hostname: str
    port: int
    region: str
    path_prefix: str

    def __post_init__(self) -> None:
        """Reject aliases, literals, wildcards, traversal, and non-HTTPS routes."""
        try:
            ipaddress.ip_address(self.hostname)
        except ValueError:
            is_address = False
        else:
            is_address = True
        if (
            self.scheme != "https"
            or self.hostname != self.hostname.lower()
            or is_address
            or _HOSTNAME.fullmatch(self.hostname) is None
            or not 1 <= self.port <= _MAX_PORT
            or _REGION.fullmatch(self.region) is None
            or not self.path_prefix.startswith("/")
            or self.path_prefix == "/"
            or any(value in self.path_prefix for value in ("..", "\\", "\x00", "?", "#", "//"))
            or len(self.path_prefix) > _MAX_PATH
        ):
            _invalid()

    @property
    def document(self) -> dict[str, object]:
        """Return exact destination authority without a credential or payload."""
        return {
            "hostname": self.hostname,
            "path_prefix": self.path_prefix,
            "port": self.port,
            "region": self.region,
            "scheme": self.scheme,
        }

    @property
    def fingerprint(self) -> str:
        """Return the immutable destination identity."""
        return _digest(self.document)


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderEgressRoute:
    """One exact profile revision, model, operation, purpose, and destination."""

    profile_id: str
    profile_version: int
    profile_attestation_id: str
    model_revision: str
    operation_type: str
    purpose: str
    destination: EgressDestination

    def __post_init__(self) -> None:
        """Reject a route containing any mutable or open-ended coordinate."""
        _uuid7(self.profile_id)
        if (
            not 1 <= self.profile_version <= 2**31 - 1
            or _DIGEST.fullmatch(self.profile_attestation_id) is None
            or _MODEL.fullmatch(self.model_revision) is None
            or self.operation_type not in _OPERATION_TYPES
            or self.purpose not in _PURPOSES
        ):
            _invalid()

    @property
    def document(self) -> dict[str, object]:
        """Return the canonical exact route."""
        return {
            "destination": self.destination.document,
            "model_revision": self.model_revision,
            "operation_type": self.operation_type,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "profile_attestation_id": self.profile_attestation_id,
            "purpose": self.purpose,
        }

    @property
    def digest(self) -> str:
        """Return the immutable route identity."""
        return _digest(self.document)

    def matches(self, request: ProviderEgressRequest) -> bool:
        """Require equality across every dispatch coordinate."""
        return (
            self.profile_id == request.profile_id
            and self.profile_version == request.profile_version
            and self.profile_attestation_id == request.profile_attestation_id
            and self.model_revision == request.model_revision
            and self.operation_type == request.operation_type
            and self.purpose == request.purpose
            and self.destination == request.destination
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderEgressRequest:
    """Every coordinate required immediately before a provider socket."""

    operation_id: str
    brain_id: str
    project_id: str | None
    profile_id: str
    profile_version: int
    profile_attestation_id: str
    model_revision: str
    purpose: str
    operation_type: str
    destination: EgressDestination
    taint: ContentTaint
    retention_days: int
    training_allowed: bool
    policy_version: int
    security_epoch: int
    quota_requests_per_minute: int
    quota_tokens_per_minute: int
    budget_monthly_micros: int
    request_bytes: int
    maximum_response_bytes: int
    timeout_milliseconds: int
    content_digests: tuple[str, ...]
    wire_request_digest: str
    token_count: int
    estimated_cost_micros: int

    def __post_init__(self) -> None:
        """Require complete, bounded, canonical, content-free coordinates."""
        _uuid7(self.brain_id)
        _uuid7(self.profile_id)
        if self.project_id is not None:
            _uuid7(self.project_id)
        if (
            _OPERATION.fullmatch(self.operation_id) is None
            or not 1 <= self.profile_version <= 2**31 - 1
            or _DIGEST.fullmatch(self.profile_attestation_id) is None
            or _MODEL.fullmatch(self.model_revision) is None
            or self.purpose not in _PURPOSES
            or self.operation_type not in _OPERATION_TYPES
            or not 0 <= self.retention_days <= _MAX_RETENTION_DAYS
            or not 1 <= self.policy_version <= 2**31 - 1
            or not 1 <= self.security_epoch <= 2**63 - 1
            or not 1 <= self.quota_requests_per_minute <= _MAX_RATE
            or not 1 <= self.quota_tokens_per_minute <= _MAX_RATE
            or not 0 <= self.budget_monthly_micros <= _MAX_COST
            or not 1 <= self.request_bytes <= _MAX_BYTES
            or not 1 <= self.maximum_response_bytes <= _MAX_BYTES
            or not _MIN_TIMEOUT_MILLISECONDS
            <= self.timeout_milliseconds
            <= _MAX_TIMEOUT_MILLISECONDS
            or not self.content_digests
            or len(self.content_digests) > _MAX_ITEMS
            or tuple(dict.fromkeys(self.content_digests)) != self.content_digests
            or any(_DIGEST.fullmatch(value) is None for value in self.content_digests)
            or _DIGEST.fullmatch(self.wire_request_digest) is None
            or not 1 <= self.token_count <= _MAX_TOKENS
            or not 0 <= self.estimated_cost_micros <= _MAX_COST
        ):
            _invalid()

    @property
    def document(self) -> dict[str, object]:
        """Return authorization coordinates without content or credentials."""
        return {
            "brain_id": self.brain_id,
            "budget_monthly_micros": self.budget_monthly_micros,
            "content_digests": list(self.content_digests),
            "destination": self.destination.document,
            "estimated_cost_micros": self.estimated_cost_micros,
            "maximum_response_bytes": self.maximum_response_bytes,
            "model_revision": self.model_revision,
            "operation_id": self.operation_id,
            "operation_type": self.operation_type,
            "policy_version": self.policy_version,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "profile_attestation_id": self.profile_attestation_id,
            "project_id": self.project_id,
            "purpose": self.purpose,
            "quota_requests_per_minute": self.quota_requests_per_minute,
            "quota_tokens_per_minute": self.quota_tokens_per_minute,
            "request_bytes": self.request_bytes,
            "retention_days": self.retention_days,
            "security_epoch": self.security_epoch,
            "taint": self.taint.document,
            "timeout_milliseconds": self.timeout_milliseconds,
            "token_count": self.token_count,
            "training_allowed": self.training_allowed,
            "wire_request_digest": self.wire_request_digest,
        }


def provider_egress_request_digest(request: ProviderEgressRequest) -> str:
    """Bind every authorization coordinate in canonical JSON."""
    return _digest(request.document)


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderEgressPermit:
    """Short-lived content-free proof for one exact provider operation."""

    operation_id: str
    brain_id: str
    profile_id: str
    profile_version: int
    profile_attestation_id: str
    model_revision: str
    purpose: str
    operation_type: str
    destination: EgressDestination
    content_digests: tuple[str, ...]
    wire_request_digest: str
    policy_id: str
    policy_version: int
    security_epoch: int
    maximum_request_bytes: int
    maximum_response_bytes: int
    timeout_milliseconds: int
    quota_requests_per_minute: int
    quota_tokens_per_minute: int
    budget_monthly_micros: int
    token_count: int
    estimated_cost_micros: int
    attestation_id: str
    attestation_digest: str
    request_digest: str
    issued_at_microseconds: int
    expires_at_microseconds: int

    def __post_init__(self) -> None:
        """Require a finite exact proof with canonical content identities."""
        for value in (self.brain_id, self.profile_id, self.policy_id, self.attestation_id):
            _uuid7(value)
        if (
            _OPERATION.fullmatch(self.operation_id) is None
            or not 1 <= self.profile_version <= 2**31 - 1
            or _MODEL.fullmatch(self.model_revision) is None
            or self.purpose not in _PURPOSES
            or self.operation_type not in _OPERATION_TYPES
            or any(
                _DIGEST.fullmatch(value) is None
                for value in (
                    self.profile_attestation_id,
                    self.attestation_digest,
                    self.request_digest,
                    self.wire_request_digest,
                    *self.content_digests,
                )
            )
            or not 1 <= self.policy_version <= 2**31 - 1
            or not 1 <= self.security_epoch <= 2**63 - 1
            or not 1 <= self.maximum_request_bytes <= _MAX_BYTES
            or not 1 <= self.maximum_response_bytes <= _MAX_BYTES
            or not _MIN_TIMEOUT_MILLISECONDS
            <= self.timeout_milliseconds
            <= _MAX_TIMEOUT_MILLISECONDS
            or not 1 <= self.quota_requests_per_minute <= _MAX_RATE
            or not 1 <= self.quota_tokens_per_minute <= _MAX_RATE
            or not 0 <= self.budget_monthly_micros <= _MAX_COST
            or not 1 <= self.token_count <= _MAX_TOKENS
            or not 0 <= self.estimated_cost_micros <= self.budget_monthly_micros
            or self.issued_at_microseconds < 0
            or self.expires_at_microseconds <= self.issued_at_microseconds
        ):
            _invalid()

    @property
    def document(self) -> dict[str, object]:
        """Return the complete permit payload for persistence/signing."""
        return {
            "attestation_digest": self.attestation_digest,
            "attestation_id": self.attestation_id,
            "brain_id": self.brain_id,
            "budget_monthly_micros": self.budget_monthly_micros,
            "content_digests": list(self.content_digests),
            "destination": self.destination.document,
            "estimated_cost_micros": self.estimated_cost_micros,
            "expires_at_microseconds": self.expires_at_microseconds,
            "issued_at_microseconds": self.issued_at_microseconds,
            "maximum_request_bytes": self.maximum_request_bytes,
            "maximum_response_bytes": self.maximum_response_bytes,
            "model_revision": self.model_revision,
            "operation_id": self.operation_id,
            "operation_type": self.operation_type,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "profile_attestation_id": self.profile_attestation_id,
            "purpose": self.purpose,
            "quota_requests_per_minute": self.quota_requests_per_minute,
            "quota_tokens_per_minute": self.quota_tokens_per_minute,
            "request_digest": self.request_digest,
            "security_epoch": self.security_epoch,
            "timeout_milliseconds": self.timeout_milliseconds,
            "token_count": self.token_count,
            "wire_request_digest": self.wire_request_digest,
        }

    @property
    def digest(self) -> str:
        """Return the immutable permit identity."""
        return _digest(self.document)


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderEgressPolicy:
    """Brain-owned immutable remote-provider policy and attestation."""

    policy_id: str
    brain_id: str
    version: int
    security_epoch: int
    classification_ceiling: Classification
    allowed_destinations: tuple[EgressDestination, ...]
    allowed_profile_ids: tuple[str, ...]
    allowed_purposes: tuple[str, ...]
    allowed_operation_types: tuple[str, ...]
    allowed_routes: tuple[ProviderEgressRoute, ...]
    maximum_retention_days: int
    training_allowed: bool
    maximum_request_bytes: int
    maximum_response_bytes: int
    maximum_timeout_milliseconds: int
    maximum_requests_per_minute: int
    maximum_tokens_per_minute: int
    maximum_monthly_cost_micros: int
    attestation_id: str
    attestation_digest: str
    valid_from_microseconds: int
    valid_until_microseconds: int

    def __post_init__(self) -> None:
        """Require one canonical, finite, independently attested policy."""
        for value in (self.policy_id, self.brain_id, self.attestation_id):
            _uuid7(value)
        for value in self.allowed_profile_ids:
            _uuid7(value)
        if (
            not 1 <= self.version <= 2**31 - 1
            or not 1 <= self.security_epoch <= 2**63 - 1
            or not self.allowed_destinations
            or tuple(sorted(set(self.allowed_destinations), key=lambda item: item.fingerprint))
            != self.allowed_destinations
            or not self.allowed_profile_ids
            or tuple(sorted(set(self.allowed_profile_ids))) != self.allowed_profile_ids
            or not self.allowed_purposes
            or tuple(sorted(set(self.allowed_purposes))) != self.allowed_purposes
            or any(value not in _PURPOSES for value in self.allowed_purposes)
            or not self.allowed_operation_types
            or tuple(sorted(set(self.allowed_operation_types))) != self.allowed_operation_types
            or any(value not in _OPERATION_TYPES for value in self.allowed_operation_types)
            or not self.allowed_routes
            or tuple(sorted(set(self.allowed_routes), key=lambda value: value.digest))
            != self.allowed_routes
            or any(
                route.profile_id not in self.allowed_profile_ids
                or route.purpose not in self.allowed_purposes
                or route.operation_type not in self.allowed_operation_types
                or route.destination not in self.allowed_destinations
                for route in self.allowed_routes
            )
            or not 0 <= self.maximum_retention_days <= _MAX_RETENTION_DAYS
            or not 1 <= self.maximum_request_bytes <= _MAX_BYTES
            or not 1 <= self.maximum_response_bytes <= _MAX_BYTES
            or not _MIN_TIMEOUT_MILLISECONDS
            <= self.maximum_timeout_milliseconds
            <= _MAX_TIMEOUT_MILLISECONDS
            or not 1 <= self.maximum_requests_per_minute <= _MAX_RATE
            or not 1 <= self.maximum_tokens_per_minute <= _MAX_RATE
            or not 0 <= self.maximum_monthly_cost_micros <= _MAX_COST
            or _DIGEST.fullmatch(self.attestation_digest) is None
            or self.valid_from_microseconds < 0
            or self.valid_until_microseconds <= self.valid_from_microseconds
        ):
            _invalid()

    def authorize(
        self,
        request: ProviderEgressRequest,
        *,
        now_microseconds: int,
    ) -> ProviderEgressPermit:
        """Issue one short-lived exact permit or unconditionally deny."""
        denied = (
            request.taint.intrinsically_denied
            or request.brain_id != self.brain_id
            or request.profile_id not in self.allowed_profile_ids
            or request.purpose not in self.allowed_purposes
            or request.operation_type not in self.allowed_operation_types
            or not any(route.matches(request) for route in self.allowed_routes)
            or request.destination not in self.allowed_destinations
            or request.policy_version != self.version
            or request.security_epoch != self.security_epoch
            or not self.valid_from_microseconds <= now_microseconds < self.valid_until_microseconds
            or _CLASSIFICATION_RANK[request.taint.classification]
            > _CLASSIFICATION_RANK[self.classification_ceiling]
            or request.retention_days > self.maximum_retention_days
            or (request.training_allowed and not self.training_allowed)
            or request.request_bytes > self.maximum_request_bytes
            or request.maximum_response_bytes > self.maximum_response_bytes
            or request.timeout_milliseconds > self.maximum_timeout_milliseconds
            or request.quota_requests_per_minute > self.maximum_requests_per_minute
            or request.quota_tokens_per_minute > self.maximum_tokens_per_minute
            or request.budget_monthly_micros > self.maximum_monthly_cost_micros
            or request.estimated_cost_micros > request.budget_monthly_micros
        )
        if denied:
            raise ProviderContainmentDeniedError(_ERR_DENIED)
        expires_at = min(
            self.valid_until_microseconds,
            now_microseconds + request.timeout_milliseconds * 1000,
        )
        return ProviderEgressPermit(
            operation_id=request.operation_id,
            brain_id=request.brain_id,
            profile_id=request.profile_id,
            profile_version=request.profile_version,
            profile_attestation_id=request.profile_attestation_id,
            model_revision=request.model_revision,
            purpose=request.purpose,
            operation_type=request.operation_type,
            destination=request.destination,
            content_digests=request.content_digests,
            wire_request_digest=request.wire_request_digest,
            policy_id=self.policy_id,
            policy_version=self.version,
            security_epoch=self.security_epoch,
            maximum_request_bytes=self.maximum_request_bytes,
            maximum_response_bytes=request.maximum_response_bytes,
            timeout_milliseconds=request.timeout_milliseconds,
            quota_requests_per_minute=request.quota_requests_per_minute,
            quota_tokens_per_minute=request.quota_tokens_per_minute,
            budget_monthly_micros=request.budget_monthly_micros,
            token_count=request.token_count,
            estimated_cost_micros=request.estimated_cost_micros,
            attestation_id=self.attestation_id,
            attestation_digest=self.attestation_digest,
            request_digest=provider_egress_request_digest(request),
            issued_at_microseconds=now_microseconds,
            expires_at_microseconds=expires_at,
        )

    @property
    def document(self) -> dict[str, object]:
        """Return the complete canonical policy snapshot."""
        return {
            "allowed_destinations": [value.document for value in self.allowed_destinations],
            "allowed_profile_ids": list(self.allowed_profile_ids),
            "allowed_purposes": list(self.allowed_purposes),
            "allowed_operation_types": list(self.allowed_operation_types),
            "allowed_routes": [value.document for value in self.allowed_routes],
            "attestation_digest": self.attestation_digest,
            "attestation_id": self.attestation_id,
            "brain_id": self.brain_id,
            "classification_ceiling": self.classification_ceiling.value,
            "maximum_monthly_cost_micros": self.maximum_monthly_cost_micros,
            "maximum_request_bytes": self.maximum_request_bytes,
            "maximum_requests_per_minute": self.maximum_requests_per_minute,
            "maximum_response_bytes": self.maximum_response_bytes,
            "maximum_retention_days": self.maximum_retention_days,
            "maximum_timeout_milliseconds": self.maximum_timeout_milliseconds,
            "maximum_tokens_per_minute": self.maximum_tokens_per_minute,
            "policy_id": self.policy_id,
            "security_epoch": self.security_epoch,
            "training_allowed": self.training_allowed,
            "valid_from_microseconds": self.valid_from_microseconds,
            "valid_until_microseconds": self.valid_until_microseconds,
            "version": self.version,
        }

    @property
    def digest(self) -> str:
        """Return the immutable policy identity."""
        return _digest(self.document)


@dataclass(frozen=True, slots=True)
class ProviderEgressBatch:
    """One provider batch homogeneous across every security coordinate."""

    requests: tuple[ProviderEgressRequest, ...]

    def __post_init__(self) -> None:
        """Reject mixed Brain, profile, purpose, destination, or taint."""
        if not self.requests:
            _invalid()
        first = self.requests[0]
        identity = (
            first.brain_id,
            first.project_id,
            first.profile_id,
            first.profile_version,
            first.profile_attestation_id,
            first.model_revision,
            first.purpose,
            first.operation_type,
            first.destination,
            first.taint,
            first.retention_days,
            first.training_allowed,
            first.policy_version,
            first.security_epoch,
        )
        if any(
            (
                value.brain_id,
                value.project_id,
                value.profile_id,
                value.profile_version,
                value.profile_attestation_id,
                value.model_revision,
                value.purpose,
                value.operation_type,
                value.destination,
                value.taint,
                value.retention_days,
                value.training_allowed,
                value.policy_version,
                value.security_epoch,
            )
            != identity
            for value in self.requests[1:]
        ):
            raise ProviderContainmentValidationError(_ERR_HOMOGENEOUS)


@dataclass(frozen=True, slots=True, kw_only=True)
class AdapterOperationSandbox:
    """Closed per-operation container authority for an untrusted adapter."""

    operation_id: str
    image: str
    user: str
    read_only_rootfs: bool
    cap_drop: tuple[str, ...]
    security_options: tuple[str, ...]
    networks: tuple[str, ...]
    input_source: str
    output_source: str
    tmpfs: tuple[tuple[str, int, int], ...]
    environment: tuple[tuple[str, str], ...]
    secret_mounts: tuple[str, ...]
    publish_ports: tuple[int, ...]
    docker_socket: bool
    privileged: bool
    auto_remove: bool
    pids_limit: int
    memory_bytes: int
    nano_cpus: int
    timeout_seconds: int

    @classmethod
    def production(  # noqa: PLR0913 -- Closed sandbox needs every authority explicitly.
        cls,
        *,
        operation_id: str,
        image: str,
        internal_network: str,
        input_source: str,
        output_source: str,
        timeout_seconds: int,
    ) -> AdapterOperationSandbox:
        """Build the only supported production operation sandbox."""
        if (
            _OPERATION.fullmatch(operation_id) is None
            or _IMAGE.fullmatch(image) is None
            or _NETWORK.fullmatch(internal_network) is None
            or _OPERATION_PATH.fullmatch(input_source) is None
            or _OPERATION_PATH.fullmatch(output_source) is None
            or not input_source.endswith("/input")
            or not output_source.endswith("/output")
            or input_source.rsplit("/", 1)[0] != output_source.rsplit("/", 1)[0]
            or not 1 <= timeout_seconds <= _MAX_SANDBOX_SECONDS
        ):
            raise ProviderContainmentValidationError(_ERR_SANDBOX)
        return cls(
            operation_id=operation_id,
            image=image,
            user="10001:10001",
            read_only_rootfs=True,
            cap_drop=("ALL",),
            security_options=("no-new-privileges:true",),
            networks=(internal_network,),
            input_source=input_source,
            output_source=output_source,
            # Operation-private container tmpfs, never a host temporary directory.
            tmpfs=(("/tmp", 64 * 1024 * 1024, 0o1777),),  # noqa: S108  # nosec B108
            environment=(),
            secret_mounts=(),
            publish_ports=(),
            docker_socket=False,
            privileged=False,
            auto_remove=True,
            pids_limit=128,
            memory_bytes=1024 * 1024 * 1024,
            nano_cpus=1_000_000_000,
            timeout_seconds=timeout_seconds,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class AdapterOperationResult:
    """Content-addressed custom-adapter output and mandatory cleanup evidence."""

    operation_id: str
    result_digest: str
    result_ref: str
    usage_units: int
    exit_code: int
    runtime_milliseconds: int
    cleanup_digest: str

    def __post_init__(self) -> None:
        """Reject missing output, nonzero success, or absent cleanup evidence."""
        if (
            _OPERATION.fullmatch(self.operation_id) is None
            or _DIGEST.fullmatch(self.result_digest) is None
            or _RESULT_REF.fullmatch(self.result_ref) is None
            or self.result_ref != f"cas://sha256/{self.result_digest}"
            or not 0 <= self.usage_units <= 2**63 - 1
            or self.exit_code != 0
            or not 0 <= self.runtime_milliseconds <= _MAX_SANDBOX_SECONDS * 1000
            or _DIGEST.fullmatch(self.cleanup_digest) is None
        ):
            _invalid()


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderRuntimeFact:
    """Closed, content-free provider runtime telemetry."""

    operation_id: str
    adapter_image_digest: str
    outcome_code: str
    runtime_milliseconds: int
    cleanup_digest: str
    occurred_at_microseconds: int

    def __post_init__(self) -> None:
        """Require only bounded pseudonymous runtime evidence."""
        if (
            _OPERATION.fullmatch(self.operation_id) is None
            or _DIGEST.fullmatch(self.adapter_image_digest) is None
            or _SAFE_CODE.fullmatch(self.outcome_code) is None
            or not 0 <= self.runtime_milliseconds <= _MAX_SANDBOX_SECONDS * 1000
            or _DIGEST.fullmatch(self.cleanup_digest) is None
            or self.occurred_at_microseconds < 0
        ):
            _invalid()

    @property
    def document(self) -> dict[str, object]:
        """Return the exact safe telemetry fields."""
        return {
            "adapter_image_digest": self.adapter_image_digest,
            "cleanup_digest": self.cleanup_digest,
            "occurred_at_microseconds": self.occurred_at_microseconds,
            "operation_id": self.operation_id,
            "outcome_code": self.outcome_code,
            "runtime_milliseconds": self.runtime_milliseconds,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderEgressDecisionFact:
    """Content-free gateway decision and bounded transport evidence."""

    permit_digest: str
    operation_id: str
    destination_fingerprint: str
    outcome_code: str
    request_bytes: int
    response_bytes: int
    status_code: int | None
    occurred_at_microseconds: int

    def __post_init__(self) -> None:
        """Reject any field outside the low-cardinality decision vocabulary."""
        if (
            _DIGEST.fullmatch(self.permit_digest) is None
            or _OPERATION.fullmatch(self.operation_id) is None
            or _DIGEST.fullmatch(self.destination_fingerprint) is None
            or _SAFE_CODE.fullmatch(self.outcome_code) is None
            or not 0 <= self.request_bytes <= _MAX_BYTES
            or not 0 <= self.response_bytes <= _MAX_BYTES
            or (
                self.status_code is not None
                and not _MIN_HTTP_STATUS <= self.status_code <= _MAX_HTTP_STATUS
            )
            or self.occurred_at_microseconds < 0
        ):
            _invalid()

    @property
    def document(self) -> dict[str, object]:
        """Return the only fields allowed into gateway decision telemetry."""
        return {
            "destination_fingerprint": self.destination_fingerprint,
            "occurred_at_microseconds": self.occurred_at_microseconds,
            "operation_id": self.operation_id,
            "outcome_code": self.outcome_code,
            "permit_digest": self.permit_digest,
            "request_bytes": self.request_bytes,
            "response_bytes": self.response_bytes,
            "status_code": self.status_code,
        }


@dataclass(slots=True, kw_only=True)
class ProviderGatewayCredential:
    """One brokered provider header held in a caller-owned mutable buffer."""

    header_name: str
    value: bytearray = field(repr=False)

    def __post_init__(self) -> None:
        """Reject arbitrary headers, control bytes, or unbounded credential data."""
        if (
            self.header_name not in _CREDENTIAL_HEADERS
            or not 1 <= len(self.value) <= _MAX_CREDENTIAL_BYTES
            or self.value[0] == _ASCII_SPACE
            or self.value[-1] == _ASCII_SPACE
            or any(value < _ASCII_SPACE or value > _ASCII_TILDE for value in self.value)
        ):
            _invalid()

    def text(self) -> str:
        """Materialize the bounded ASCII header only at the socket boundary."""
        return self.value.decode("ascii")

    def destroy(self) -> None:
        """Best-effort overwrite the mutable credential buffer."""
        self.value[:] = b"\x00" * len(self.value)


@dataclass(frozen=True, slots=True)
class ProviderEgressHttpResponse:
    """Bounded raw provider response returned by the pinned transport."""

    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes = field(repr=False)
    retry_after_microseconds: int | None = None

    def __post_init__(self) -> None:
        """Require a normalized absolute retry time when the gateway supplies one."""
        if self.retry_after_microseconds is not None and self.retry_after_microseconds < 0:
            _invalid()


@dataclass(frozen=True, slots=True)
class ExecuteProviderEgress:
    """One internal authenticated gateway command with an opaque signed permit."""

    permit_token: bytes = field(repr=False)
    path: str
    body: bytearray = field(repr=False)

    def __post_init__(self) -> None:
        """Bound the opaque token and wire payload before application work."""
        if (
            not 1 <= len(self.permit_token) <= _MAX_PERMIT_TOKEN_BYTES
            or not self.path
            or not 1 <= len(self.body) <= _MAX_BYTES
        ):
            _invalid()


@dataclass(frozen=True, slots=True)
class PreparedProviderWireRequest:
    """Deterministic vendor wire request built from authorized operation input."""

    path: str
    body: bytearray = field(repr=False)

    def __post_init__(self) -> None:
        """Require one bounded nonempty path and mutable body."""
        if (
            not self.path.startswith("/")
            or any(value in self.path for value in ("..", "\\", "\x00", "?", "#", "//"))
            or not 1 <= len(self.body) <= _MAX_BYTES
        ):
            _invalid()

    @property
    def digest(self) -> str:
        """Return the wire-body identity authorized by the permit."""
        return hashlib.sha256(bytes(self.body)).hexdigest()

    def destroy(self) -> None:
        """Best-effort overwrite the prepared provider request."""
        self.body[:] = b"\x00" * len(self.body)


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderEgressOperationContext:
    """Resolved policy/profile/content coordinates needed to request egress."""

    project_id: str | None
    destination: EgressDestination
    private_block: bool
    secret_bearing: bool
    retention_days: int
    training_allowed: bool
    policy_version: int
    security_epoch: int
    quota_requests_per_minute: int
    quota_tokens_per_minute: int
    budget_monthly_micros: int
    maximum_response_bytes: int
    timeout_milliseconds: int
    token_count: int
    estimated_cost_micros: int


def _digest(value: object) -> str:
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError) as error:
        raise ProviderContainmentValidationError(_ERR_INPUT) from error
    return hashlib.sha256(payload).hexdigest()


def _uuid7(value: str) -> None:
    try:
        parsed = UUID(value)
    except (TypeError, ValueError) as error:
        raise ProviderContainmentValidationError(_ERR_INPUT) from error
    if parsed.version != _UUID_VERSION or str(parsed) != value:
        _invalid()


def _invalid() -> Never:
    raise ProviderContainmentValidationError(_ERR_INPUT)
