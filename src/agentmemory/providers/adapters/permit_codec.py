"""Authenticated, strict, content-free PRO-009 provider permit codec."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from typing import TYPE_CHECKING, cast

from agentmemory.providers.adapters.protected_file import read_capability, zero
from agentmemory.providers.adapters.strict_json import (
    StrictJsonError,
    canonical_bytes,
    loads,
    require_object,
)
from agentmemory.providers.domain.containment import (
    EgressDestination,
    ProviderEgressPermit,
)
from agentmemory.providers.domain.errors import (
    ProviderContainmentDeniedError,
    ProviderContainmentValidationError,
)

if TYPE_CHECKING:
    from pathlib import Path

_KEY_BYTES = 32
_SIGNATURE_BYTES = 32
_MAX_TOKEN_BYTES = 16_384
_ERR_PERMIT = "provider egress permit is invalid"
_ERR_DENIED = "provider egress permit is denied"
_FIELDS = frozenset(
    {
        "attestation_digest",
        "attestation_id",
        "brain_id",
        "budget_monthly_micros",
        "content_digests",
        "destination",
        "estimated_cost_micros",
        "expires_at_microseconds",
        "issued_at_microseconds",
        "maximum_request_bytes",
        "maximum_response_bytes",
        "model_revision",
        "operation_id",
        "operation_type",
        "policy_id",
        "policy_version",
        "profile_id",
        "profile_version",
        "profile_attestation_id",
        "purpose",
        "quota_requests_per_minute",
        "quota_tokens_per_minute",
        "request_digest",
        "security_epoch",
        "timeout_milliseconds",
        "token_count",
        "wire_request_digest",
    }
)
_DESTINATION_FIELDS = frozenset({"scheme", "hostname", "port", "region", "path_prefix"})


class HmacProviderPermitCodec:
    """Issue and verify canonical permits using one gateway capability key."""

    def __init__(self, key: bytes) -> None:
        """Copy one exact high-entropy capability into this process boundary."""
        if len(key) != _KEY_BYTES:
            raise ProviderContainmentValidationError(_ERR_PERMIT)
        self._key = bytes(key)

    def encode(self, permit: ProviderEgressPermit) -> bytes:
        """Return a compact authenticated token with no content or credential."""
        payload = _encode(canonical_bytes(permit.document))
        signature = _encode(hmac.digest(self._key, payload, hashlib.sha256))
        token = payload + b"." + signature
        if len(token) > _MAX_TOKEN_BYTES:
            raise ProviderContainmentValidationError(_ERR_PERMIT)
        return token

    def decode(self, token: bytes) -> ProviderEgressPermit:
        """Authenticate before parsing and reconstruct every closed permit field."""
        if not token or len(token) > _MAX_TOKEN_BYTES or token.count(b".") != 1:
            raise ProviderContainmentValidationError(_ERR_PERMIT)
        payload, supplied_signature = token.split(b".")
        try:
            signature = _decode(supplied_signature)
        except (ValueError, binascii.Error) as error:
            raise ProviderContainmentValidationError(_ERR_PERMIT) from error
        expected = hmac.digest(self._key, payload, hashlib.sha256)
        if len(signature) != _SIGNATURE_BYTES or not hmac.compare_digest(signature, expected):
            raise ProviderContainmentDeniedError(_ERR_DENIED)
        try:
            raw = _decode(payload)
            _require_canonical_encoding(raw, payload)
            document = require_object(loads(raw))
            permit = _permit(document)
        except (
            KeyError,
            TypeError,
            ValueError,
            binascii.Error,
            StrictJsonError,
            ProviderContainmentValidationError,
        ) as error:
            raise ProviderContainmentValidationError(_ERR_PERMIT) from error
        if canonical_bytes(permit.document) != raw:
            raise ProviderContainmentValidationError(_ERR_PERMIT)
        return permit


class ProtectedFileProviderPermitCodec:
    """Load the shared permit key from a protected file for each operation."""

    def __init__(self, key_file: Path) -> None:
        """Store only a protected-file reference, never key bytes."""
        self._key_file = key_file

    def encode(self, permit: ProviderEgressPermit) -> bytes:
        """Sign with a short-lived mutable key buffer."""
        key = read_capability(self._key_file)
        try:
            return HmacProviderPermitCodec(bytes(key)).encode(permit)
        finally:
            zero(key)

    def decode(self, token: bytes) -> ProviderEgressPermit:
        """Verify with a short-lived mutable key buffer."""
        key = read_capability(self._key_file)
        try:
            return HmacProviderPermitCodec(bytes(key)).decode(token)
        finally:
            zero(key)


def _permit(document: dict[str, object]) -> ProviderEgressPermit:
    if frozenset(document) != _FIELDS:
        raise ValueError
    destination_document = require_object(document["destination"])
    if frozenset(destination_document) != _DESTINATION_FIELDS:
        raise ValueError
    destination = EgressDestination(
        scheme=_string(destination_document, "scheme"),
        hostname=_string(destination_document, "hostname"),
        port=_integer(destination_document, "port"),
        region=_string(destination_document, "region"),
        path_prefix=_string(destination_document, "path_prefix"),
    )
    return ProviderEgressPermit(
        operation_id=_string(document, "operation_id"),
        brain_id=_string(document, "brain_id"),
        profile_id=_string(document, "profile_id"),
        profile_version=_integer(document, "profile_version"),
        profile_attestation_id=_string(document, "profile_attestation_id"),
        model_revision=_string(document, "model_revision"),
        purpose=_string(document, "purpose"),
        operation_type=_string(document, "operation_type"),
        destination=destination,
        content_digests=_strings(document, "content_digests"),
        wire_request_digest=_string(document, "wire_request_digest"),
        policy_id=_string(document, "policy_id"),
        policy_version=_integer(document, "policy_version"),
        security_epoch=_integer(document, "security_epoch"),
        maximum_request_bytes=_integer(document, "maximum_request_bytes"),
        maximum_response_bytes=_integer(document, "maximum_response_bytes"),
        timeout_milliseconds=_integer(document, "timeout_milliseconds"),
        quota_requests_per_minute=_integer(document, "quota_requests_per_minute"),
        quota_tokens_per_minute=_integer(document, "quota_tokens_per_minute"),
        budget_monthly_micros=_integer(document, "budget_monthly_micros"),
        token_count=_integer(document, "token_count"),
        estimated_cost_micros=_integer(document, "estimated_cost_micros"),
        attestation_id=_string(document, "attestation_id"),
        attestation_digest=_string(document, "attestation_digest"),
        request_digest=_string(document, "request_digest"),
        issued_at_microseconds=_integer(document, "issued_at_microseconds"),
        expires_at_microseconds=_integer(document, "expires_at_microseconds"),
    )


def _encode(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def _decode(value: bytes) -> bytes:
    if not value or b"=" in value:
        raise ValueError
    padding = b"=" * (-len(value) % 4)
    return base64.b64decode(value + padding, altchars=b"-_", validate=True)


def _require_canonical_encoding(raw: bytes, encoded: bytes) -> None:
    if _encode(raw) != encoded:
        raise ValueError


def _string(document: dict[str, object], key: str) -> str:
    value = document[key]
    if not isinstance(value, str):
        raise TypeError
    return value


def _integer(document: dict[str, object], key: str) -> int:
    value = document[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError
    return value


def _strings(document: dict[str, object], key: str) -> tuple[str, ...]:
    value = document[key]
    if not isinstance(value, list):
        raise TypeError
    values = cast("list[object]", value)
    if any(not isinstance(item, str) for item in values):
        raise TypeError
    return tuple(cast("list[str]", values))
