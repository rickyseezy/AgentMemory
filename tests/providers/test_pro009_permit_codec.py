"""PRO-009 signed permit boundary tests."""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import TYPE_CHECKING

import pytest

from agentmemory.providers.adapters import permit_codec
from agentmemory.providers.adapters.permit_codec import (
    HmacProviderPermitCodec,
    ProtectedFileProviderPermitCodec,
)
from agentmemory.providers.adapters.strict_json import canonical_bytes
from agentmemory.providers.domain.errors import (
    ProviderContainmentDeniedError,
    ProviderContainmentValidationError,
)
from tests.providers.test_pro009_containment_application import permit

if TYPE_CHECKING:
    from pathlib import Path


def codec(value: int = 7) -> HmacProviderPermitCodec:
    return HmacProviderPermitCodec(bytes([value]) * 32)


def test_signed_permit_round_trip_preserves_every_authority_coordinate() -> None:
    token = codec().encode(permit())

    assert codec().decode(token) == permit()
    assert b"payload" not in token
    assert b"Bearer" not in token
    assert len(token) < 16_384


def test_wrong_key_signature_payload_or_noncanonical_token_is_denied() -> None:
    token = codec().encode(permit())
    payload, signature = token.split(b".")
    changed_payload = bytearray(payload)
    changed_payload[-1] = ord("A") if changed_payload[-1] != ord("A") else ord("B")

    for changed, candidate in (
        (codec(8), token),
        (codec(), bytes(changed_payload) + b"." + signature),
    ):
        with pytest.raises(ProviderContainmentDeniedError, match="permit"):
            changed.decode(candidate)

    with pytest.raises(ProviderContainmentValidationError, match="permit"):
        codec().decode(token + b"=")


def test_unknown_missing_or_wrong_typed_permit_fields_fail_closed() -> None:
    value = permit().document
    cases = (
        {**value, "unexpected": True},
        {key: item for key, item in value.items() if key != "brain_id"},
        {**value, "policy_version": True},
    )
    for document in cases:
        payload = base64.urlsafe_b64encode(canonical_bytes(document)).rstrip(b"=")
        signature = base64.urlsafe_b64encode(
            hmac.digest(bytes([7]) * 32, payload, hashlib.sha256)
        ).rstrip(b"=")
        token = payload + b"." + signature
        with pytest.raises(ProviderContainmentValidationError, match="permit"):
            codec().decode(token)


def test_codec_rejects_invalid_key_and_oversized_or_ambiguous_tokens() -> None:
    for key in (b"", b"x" * 31, b"x" * 33):
        with pytest.raises(ProviderContainmentValidationError, match="permit"):
            HmacProviderPermitCodec(key)

    for token in (b"", b"x" * 16_385, b"a.b.c", b"\xff.b"):
        with pytest.raises(ProviderContainmentValidationError, match="permit"):
            codec().decode(token)


def test_protected_file_codec_rejects_unsafe_key_and_round_trips(tmp_path: Path) -> None:
    key_file = tmp_path / "permit-key"
    key_file.write_bytes(b"k" * 32)
    key_file.chmod(0o600)
    protected = ProtectedFileProviderPermitCodec(key_file)

    assert protected.decode(protected.encode(permit())) == permit()

    key_file.chmod(0o640)
    with pytest.raises(PermissionError):
        protected.encode(permit())


def test_codec_rejects_tokens_over_the_configured_encoding_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(permit_codec, "_MAX_TOKEN_BYTES", 1)

    with pytest.raises(ProviderContainmentValidationError, match="permit"):
        codec().encode(permit())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("operation_id", 7),
        ("content_digests", "not-a-list"),
        ("content_digests", ["valid", 7]),
    ],
)
def test_signed_permit_rejects_wrong_typed_authority_fields(
    field: str,
    value: object,
) -> None:
    document = {**permit().document, field: value}
    payload = base64.urlsafe_b64encode(canonical_bytes(document)).rstrip(b"=")
    signature = base64.urlsafe_b64encode(
        hmac.digest(bytes([7]) * 32, payload, hashlib.sha256)
    ).rstrip(b"=")

    with pytest.raises(ProviderContainmentValidationError, match="permit"):
        codec().decode(payload + b"." + signature)


def test_signed_permit_rejects_open_destination_shape() -> None:
    document = permit().document
    document["destination"] = {
        **document["destination"],  # type: ignore[dict-item]
        "ambient": "authority",
    }
    payload = base64.urlsafe_b64encode(canonical_bytes(document)).rstrip(b"=")
    signature = base64.urlsafe_b64encode(
        hmac.digest(bytes([7]) * 32, payload, hashlib.sha256)
    ).rstrip(b"=")

    with pytest.raises(ProviderContainmentValidationError, match="permit"):
        codec().decode(payload + b"." + signature)
