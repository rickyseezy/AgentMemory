"""Shared fail-closed conformance machinery for certified remote adapters."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast

from agentmemory.providers.adapters.strict_json import StrictJsonError, canonical_bytes, loads
from agentmemory.providers.domain.errors import ProviderAdapterError, ProviderErrorCode
from agentmemory.providers.domain.profile_ports import ProviderGatewayRequest
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderExecutionClass,
    ProviderLimits,
    ProviderManifest,
    ProviderOperation,
    ProviderProbeResult,
    SimilarityMetric,
    VectorDtype,
    VectorNormalization,
)

if TYPE_CHECKING:
    from agentmemory.providers.domain.profile_ports import (
        ProviderGatewayResponse,
        ProviderGatewayTransport,
    )
    from agentmemory.providers.domain.profiles import ProviderProfile

_PROBE_INPUTS = ("AgentMemory provider probe alpha", "AgentMemory provider probe beta")
_PROBE_QUERY = "AgentMemory provider probe"
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_SUCCESS_STATUS = 200
_ERR_REMOTE_MANIFEST = "remote adapter requires a remote manifest"
_STATUS_CODES = {
    401: ProviderErrorCode.AUTHENTICATION,
    403: ProviderErrorCode.PERMISSION,
    404: ProviderErrorCode.MISSING_MODEL,
    408: ProviderErrorCode.TIMEOUT,
    413: ProviderErrorCode.OVERSIZED_INPUT,
    429: ProviderErrorCode.RATE_LIMIT,
    498: ProviderErrorCode.AUTHENTICATION,
    499: ProviderErrorCode.CANCELLATION,
    500: ProviderErrorCode.TRANSIENT_UPSTREAM,
    502: ProviderErrorCode.TRANSIENT_UPSTREAM,
    503: ProviderErrorCode.TRANSIENT_UPSTREAM,
    504: ProviderErrorCode.TIMEOUT,
}


@dataclass(frozen=True, slots=True)
class ParsedProbe:
    """Validated provider-specific response facts."""

    dimension: int | None
    dtype: VectorDtype | None
    normalization: VectorNormalization | None
    similarity: SimilarityMetric | None


class RemoteProtocol(Protocol):
    """Vendor-specific request and response mapping."""

    def request(
        self,
        operation: ProviderOperation,
        purpose: CanonicalPurpose,
        model_id: str,
    ) -> tuple[str, dict[str, object]]:
        """Return a fixed relative path and strict JSON request."""
        ...

    def parse(
        self,
        operation: ProviderOperation,
        model_id: str,
        response: object,
    ) -> ParsedProbe:
        """Validate count, IDs/order, numeric shape, and model echo."""
        ...


class CertifiedRemoteAdapter:
    """Run every built-in remote adapter through one conformance lifecycle."""

    def __init__(
        self,
        manifest: ProviderManifest,
        transport: ProviderGatewayTransport,
        protocol: RemoteProtocol,
    ) -> None:
        """Bind a certified remote manifest to one gateway and wire protocol."""
        if manifest.execution_class is not ProviderExecutionClass.REMOTE:
            raise ValueError(_ERR_REMOTE_MANIFEST)
        self._manifest = manifest
        self._transport = transport
        self._protocol = protocol

    @property
    def manifest(self) -> ProviderManifest:
        """Return the immutable certified manifest."""
        return self._manifest

    async def probe(self, profile: ProviderProfile) -> ProviderProbeResult:
        """Probe every configured purpose and require one stable model revision."""
        configuration = profile.configuration
        self._manifest.validate_configuration(configuration)
        if configuration.endpoint_policy_ref is None or configuration.secret_ref is None:
            raise ProviderAdapterError(ProviderErrorCode.INVALID_CONFIGURATION)
        parsed_results: list[ParsedProbe] = []
        revisions: set[tuple[str, str]] = set()
        cancellation = True
        for purpose in configuration.purposes:
            path, body = self._protocol.request(
                configuration.operation,
                purpose,
                configuration.model_id,
            )
            response = await self._transport.execute(
                ProviderGatewayRequest(
                    adapter_id=self._manifest.adapter_id,
                    endpoint_policy_ref=configuration.endpoint_policy_ref,
                    secret_ref=configuration.secret_ref,
                    method="POST",
                    path=path,
                    body=canonical_bytes(body),
                    timeout_milliseconds=configuration.limits.timeout_milliseconds,
                    max_response_bytes=_MAX_RESPONSE_BYTES,
                )
            )
            _require_success(response)
            try:
                parsed = self._protocol.parse(
                    configuration.operation,
                    configuration.model_id,
                    loads(response.body),
                )
            except (StrictJsonError, TypeError, ValueError, KeyError, IndexError) as error:
                raise ProviderAdapterError(ProviderErrorCode.MALFORMED_RESPONSE) from error
            parsed_results.append(parsed)
            revisions.add((response.model_revision, response.revision_fingerprint))
            cancellation = cancellation and response.cancellation_verified
        if len(revisions) != 1 or not cancellation:
            code = (
                ProviderErrorCode.MODEL_DRIFT
                if len(revisions) != 1
                else ProviderErrorCode.CANCELLATION
            )
            raise ProviderAdapterError(code)
        if len(set(parsed_results)) != 1:
            raise ProviderAdapterError(ProviderErrorCode.DIMENSION_MISMATCH)
        model_revision, revision_fingerprint = revisions.pop()
        parsed = parsed_results[0]
        return ProviderProbeResult(
            adapter_id=self._manifest.adapter_id,
            model_id=configuration.model_id,
            model_revision=model_revision,
            revision_fingerprint=revision_fingerprint,
            operation=configuration.operation,
            purposes=configuration.purposes,
            dimension=parsed.dimension,
            dtype=parsed.dtype,
            normalization=parsed.normalization,
            similarity=parsed.similarity,
            max_items=self._manifest.limits.max_items,
            cancellation_verified=True,
        )


def certified_manifest(
    *,
    adapter_id: str,
    vendor: str,
    operations: tuple[ProviderOperation, ...],
    purposes: tuple[CanonicalPurpose, ...],
    limits: ProviderLimits,
) -> ProviderManifest:
    """Build a release-stable built-in manifest identity."""
    version = "1.0.0"
    digest = hashlib.sha256(
        f"agentmemory:{adapter_id}:{version}:provider-protocol-1.0".encode()
    ).hexdigest()
    return ProviderManifest(
        adapter_id=adapter_id,
        implementation_version=version,
        implementation_digest=digest,
        protocol_version="1.0",
        execution_class=ProviderExecutionClass.REMOTE,
        operations=operations,
        purposes=purposes,
        limits=limits,
        revision_evidence=True,
        cancellation=True,
        vendor=vendor,
    )


def probe_inputs() -> tuple[str, str]:
    """Return the fixed non-sensitive conformance inputs."""
    return _PROBE_INPUTS


def probe_query() -> str:
    """Return the fixed non-sensitive reranking query."""
    return _PROBE_QUERY


def require_object(value: object) -> dict[str, object]:
    """Narrow one strict JSON value to a string-keyed object."""
    if not isinstance(value, dict):
        raise TypeError
    mapping = cast("dict[object, object]", value)
    if not all(isinstance(key, str) for key in mapping):
        raise TypeError
    return cast("dict[str, object]", mapping)


def require_list(value: object, expected: int) -> list[object]:
    """Require a JSON list with an exact item count."""
    if not isinstance(value, list):
        raise TypeError
    items = cast("list[object]", value)
    if len(items) != expected:
        raise TypeError
    return items


def require_float(value: object) -> float:
    """Require one finite JSON floating-point value."""
    if not isinstance(value, float) or not math.isfinite(value):
        raise TypeError
    return value


def require_vector(value: object) -> tuple[float, ...]:
    """Require one non-empty finite float vector."""
    if not isinstance(value, list):
        raise TypeError
    values = cast("list[object]", value)
    values = require_list(values, len(values))
    result = tuple(require_float(item) for item in values)
    if not result:
        raise ValueError
    return result


def require_model(value: object, expected: str) -> None:
    """Require the provider to echo the exact configured model ID."""
    if value != expected:
        raise ValueError


def _require_success(response: ProviderGatewayResponse) -> None:
    if len(response.body) > _MAX_RESPONSE_BYTES:
        raise ProviderAdapterError(ProviderErrorCode.MALFORMED_RESPONSE)
    code = _status_code(response.status_code)
    if code is not None:
        raise ProviderAdapterError(code)


def _status_code(status: int) -> ProviderErrorCode | None:
    return (
        None
        if status == _SUCCESS_STATUS
        else _STATUS_CODES.get(status, ProviderErrorCode.INVALID_CONFIGURATION)
    )
