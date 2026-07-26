"""Shared fail-closed conformance machinery for certified remote adapters."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast

from agentmemory.providers.adapters.strict_json import StrictJsonError, canonical_bytes, loads
from agentmemory.providers.domain.capability_probe import (
    EmbeddingProbeBatch,
    ProviderProbeSuite,
    RerankingProbeBatch,
    ValidatedProbeBatch,
    VectorValidator,
    probe_canaries,
)
from agentmemory.providers.domain.errors import (
    ProviderAdapterError,
    ProviderErrorCode,
    ProviderProfileValidationError,
)
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
    batch: EmbeddingProbeBatch | RerankingProbeBatch


@dataclass(frozen=True, slots=True)
class _PurposeProbe:
    parsed: ParsedProbe
    validated: ValidatedProbeBatch
    revision: tuple[str, str, str]
    cancellation_verified: bool


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
        purpose_results: list[_PurposeProbe] = []
        revisions: set[tuple[str, str, str]] = set()
        cancellation = True
        suite = ProviderProbeSuite()
        expected_dimension: int | None = None
        for purpose in configuration.purposes:
            result = await self._probe_purpose(profile, purpose, expected_dimension)
            purpose_results.append(result)
            expected_dimension = result.validated.dimension
            revisions.add(result.revision)
            cancellation = cancellation and result.cancellation_verified
        if len(revisions) != 1 or not cancellation:
            code = (
                ProviderErrorCode.MODEL_DRIFT
                if len(revisions) != 1
                else ProviderErrorCode.CANCELLATION
            )
            raise ProviderAdapterError(code)
        contracts = {
            (item.dimension, item.dtype, item.normalization, item.similarity)
            for item in (result.parsed for result in purpose_results)
        }
        if len(contracts) != 1:
            raise ProviderAdapterError(ProviderErrorCode.DIMENSION_MISMATCH)
        model_revision, revision_fingerprint, endpoint_fingerprint = revisions.pop()
        parsed = purpose_results[0].parsed
        try:
            suite_result = suite.finalize(
                configuration.operation,
                configuration.purposes,
                tuple(result.validated for result in purpose_results),
                cancellation_verified=cancellation,
            )
        except ProviderProfileValidationError as error:
            raise ProviderAdapterError(ProviderErrorCode.MALFORMED_RESPONSE) from error
        return ProviderProbeResult(
            adapter_id=self._manifest.adapter_id,
            model_id=configuration.model_id,
            model_revision=model_revision,
            revision_fingerprint=revision_fingerprint,
            endpoint_fingerprint=endpoint_fingerprint,
            operation=configuration.operation,
            purposes=configuration.purposes,
            dimension=parsed.dimension,
            dtype=parsed.dtype,
            normalization=parsed.normalization,
            similarity=parsed.similarity,
            max_items=self._manifest.limits.max_items,
            cancellation_verified=True,
            suite_digest=suite_result.suite_digest,
            canary_digest=suite_result.canary_digest,
            validation_digest=suite_result.validation_digest,
            validated_batches=suite_result.validated_batches,
        )

    async def _probe_purpose(
        self,
        profile: ProviderProfile,
        purpose: CanonicalPurpose,
        expected_dimension: int | None,
    ) -> _PurposeProbe:
        configuration = profile.configuration
        path, body = self._protocol.request(
            configuration.operation,
            purpose,
            configuration.model_id,
        )
        response = await self._transport.execute(
            ProviderGatewayRequest(
                operation_id=(
                    f"profile-probe:{profile.profile_id}:{profile.version}:{purpose.value}"
                ),
                brain_id=configuration.brain_id,
                profile_id=profile.profile_id,
                profile_version=profile.version,
                configuration_digest=configuration.digest,
                adapter_id=self._manifest.adapter_id,
                model_id=configuration.model_id,
                operation_type=configuration.operation.value,
                purpose=purpose.value,
                endpoint_policy_ref=configuration.endpoint_policy_ref or "",
                secret_ref=configuration.secret_ref or "",
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
        validated = _validate_parsed_batch(
            configuration.operation,
            purpose,
            parsed,
            expected_dimension,
        )
        return _PurposeProbe(
            parsed=parsed,
            validated=validated,
            revision=(
                response.model_revision,
                response.revision_fingerprint,
                response.endpoint_fingerprint,
            ),
            cancellation_verified=response.cancellation_verified,
        )


def _validate_parsed_batch(
    operation: ProviderOperation,
    purpose: CanonicalPurpose,
    parsed: ParsedProbe,
    expected_dimension: int | None,
) -> ValidatedProbeBatch:
    validator = VectorValidator()
    if operation is ProviderOperation.EMBEDDING and not isinstance(
        parsed.batch, EmbeddingProbeBatch
    ):
        raise ProviderAdapterError(ProviderErrorCode.MALFORMED_RESPONSE)
    if operation is ProviderOperation.RERANKING and not isinstance(
        parsed.batch, RerankingProbeBatch
    ):
        raise ProviderAdapterError(ProviderErrorCode.MALFORMED_RESPONSE)
    if (
        operation is ProviderOperation.EMBEDDING
        and expected_dimension is not None
        and parsed.dimension != expected_dimension
    ):
        raise ProviderAdapterError(ProviderErrorCode.DIMENSION_MISMATCH)
    try:
        if operation is ProviderOperation.EMBEDDING:
            embedding_batch = cast("EmbeddingProbeBatch", parsed.batch)
            validated = validator.validate_embedding(
                operation,
                purpose,
                probe_canaries(),
                embedding_batch,
                expected_dimension=expected_dimension,
            )
        else:
            reranking_batch = cast("RerankingProbeBatch", parsed.batch)
            validated = validator.validate_reranking(
                purpose,
                probe_canaries(),
                reranking_batch,
            )
    except ProviderProfileValidationError as error:
        raise ProviderAdapterError(ProviderErrorCode.MALFORMED_RESPONSE) from error
    if parsed.dimension != validated.dimension:
        raise ProviderAdapterError(ProviderErrorCode.DIMENSION_MISMATCH)
    return validated


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
    first, second = probe_canaries()
    return first.content, second.content


def probe_content_ids() -> tuple[str, str]:
    """Return the exact ordered content identities for the fixed canaries."""
    first, second = probe_canaries()
    return first.content_id, second.content_id


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
        raise ProviderAdapterError(
            code,
            retry_after_microseconds=response.retry_after_microseconds,
        )


def _status_code(status: int) -> ProviderErrorCode | None:
    return (
        None
        if status == _SUCCESS_STATUS
        else _STATUS_CODES.get(status, ProviderErrorCode.INVALID_CONFIGURATION)
    )
