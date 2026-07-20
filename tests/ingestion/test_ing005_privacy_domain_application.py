"""ING-005 versioned privacy-policy and ordered pipeline acceptance tests."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from typing import Any, cast

import pytest

from agentmemory.ingestion.application import privacy as privacy_module
from agentmemory.ingestion.application.privacy import (
    CapturePolicyCommand,
    CapturePolicyPipeline,
    SanitizedProviderEgressHandler,
)
from agentmemory.ingestion.domain.agent_event import Classification
from agentmemory.ingestion.domain.errors import IngestionEgressDeniedError, IngestionValidationError
from agentmemory.ingestion.domain.privacy import (
    AllowedEgressRoute,
    CaptureDisposition,
    CapturePolicy,
    EgressDestination,
    EgressDisposition,
    PolicyStage,
    SensitiveAction,
    SensitiveFinding,
    SensitiveKind,
    SourceClass,
    StageEvidence,
    maximum_classification,
)
from tests.core.support import BRAIN_ID
from tests.ingestion.adp002_support import REPOSITORY_ID, privacy_result


class Policies:
    """Exact in-memory revision repository used by application tests."""

    def __init__(self, *policies: CapturePolicy) -> None:
        self.policies = policies or (CapturePolicy.secure_default(BRAIN_ID, REPOSITORY_ID),)
        self.calls: list[tuple[str, str | None, int | None]] = []

    async def resolve(
        self,
        brain_id: str,
        repository_id: str | None,
        version: int | None,
    ) -> CapturePolicy:
        self.calls.append((brain_id, repository_id, version))
        candidates = [
            item
            for item in self.policies
            if item.brain_id == brain_id
            and item.repository_id == repository_id
            and (version is None or item.version == version)
        ]
        if not candidates:
            field = "policy_version"
            raise IngestionValidationError.single(field, "not_found")
        return max(candidates, key=lambda item: item.version)


class EgressSpy:
    """Socket-owner spy proving denial happens before provider invocation."""

    def __init__(self) -> None:
        self.calls: list[tuple[EgressDestination, bytes, str]] = []

    async def invoke(
        self,
        destination: EgressDestination,
        sanitized_payload: bytes,
        downstream_idempotency_key: str,
    ) -> bytes:
        self.calls.append((destination, sanitized_payload, downstream_idempotency_key))
        return b"provider-result"


def destination() -> EgressDestination:
    return EgressDestination(
        provider_id="cohere",
        endpoint="https://api.cohere.example",
        region="eu",
        model_id="embed-v4",
        purpose="embedding",
    )


def policy(**changes: object) -> CapturePolicy:
    value = CapturePolicy.secure_default(BRAIN_ID, REPOSITORY_ID)
    return replace(value, **cast("Any", changes))


def command(
    payload: bytes,
    **changes: object,
) -> CapturePolicyCommand:
    value = CapturePolicyCommand(
        brain_id=BRAIN_ID,
        repository_id=REPOSITORY_ID,
        content=bytearray(payload),
        media_type="application/json",
        source_path="src/service.py",
        declared_classification=Classification.INTERNAL,
    )
    return replace(value, **cast("Any", changes))


def canonical(document: object) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def assert_violation(error: IngestionValidationError, field: str, code: str) -> None:
    """Assert the complete stable public validation contract."""
    assert [(item.field, item.code) for item in error.violations] == [(field, code)]


def test_policy_revision_is_canonical_complete_and_content_addressed() -> None:
    first = policy()
    second = policy()
    assert first.canonical_bytes == second.canonical_bytes
    assert first.sha256 == hashlib.sha256(first.canonical_bytes).hexdigest()
    assert json.loads(first.canonical_bytes)["limits"] == {
        "max_decoded_characters": 1_048_576,
        "max_findings": 1024,
        "max_input_bytes": 1_048_576,
        "max_json_depth": 64,
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"version": 0},
        {"ignore_patterns": ("z", "a")},
        {"private_block_pairs": (("same", "same"),)},
        {"allowed_media_types": ("JSON",)},
        {"max_input_bytes": 0},
        {"max_json_depth": 0},
    ],
)
def test_policy_rejects_ambiguous_or_unbounded_rules(changes: dict[str, object]) -> None:
    with pytest.raises(IngestionValidationError):
        policy(**changes)


def test_route_rejects_credentials_non_https_paths_and_unsafe_classes() -> None:
    for endpoint in (
        "http://api.example.test",
        "https://user:secret@api.example.test",
        "https://api.example.test/v1",
        "https://127.0.0.1",
    ):
        with pytest.raises(IngestionValidationError):
            replace(destination(), endpoint=endpoint)
    with pytest.raises(IngestionValidationError):
        AllowedEgressRoute(destination(), (Classification.RESTRICTED,))


def test_policy_result_rejects_excluded_or_tainted_egress_shape() -> None:
    base = privacy_result()
    with pytest.raises(IngestionValidationError):
        replace(
            base,
            disposition=CaptureDisposition.EXCLUDED,
            payload=None,
            output_sha256=None,
            classification=Classification.INTERNAL,
        )
    finding = SensitiveFinding(
        SensitiveKind.SECRET,
        "$/value",
        0,
        1,
        "secret.test",
    )
    with pytest.raises(IngestionValidationError):
        replace(base, egress=EgressDisposition.ALLOW, findings=(finding,))


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ((Classification.PUBLIC,), Classification.PUBLIC),
        (
            (Classification.INTERNAL, Classification.PUBLIC, Classification.CONFIDENTIAL),
            Classification.CONFIDENTIAL,
        ),
        (
            (Classification.RESTRICTED, Classification.LOCAL_ONLY),
            Classification.LOCAL_ONLY,
        ),
    ],
)
def test_maximum_classification_uses_the_explicit_security_order(
    values: tuple[Classification, ...],
    expected: Classification,
) -> None:
    assert maximum_classification(*values) is expected
    with pytest.raises(IngestionValidationError) as captured:
        maximum_classification()
    assert_violation(captured.value, "classification", "required")


@pytest.mark.parametrize(
    ("changes", "field", "code"),
    [
        ({"version": 0}, "policy_version", "out_of_range"),
        ({"ignore_patterns": ()}, "ignore_patterns", "not_canonical"),
        ({"ignore_patterns": ("a", "a")}, "ignore_patterns", "not_canonical"),
        ({"ignore_patterns": ("b", "a")}, "ignore_patterns", "not_canonical"),
        ({"ignore_patterns": ("a\x00",)}, "ignore_patterns", "not_canonical"),
        ({"private_block_pairs": ()}, "private_block_pairs", "invalid"),
        ({"private_block_pairs": (("a", "a"),)}, "private_block_pairs", "invalid"),
        ({"allowed_media_types": ("APPLICATION/JSON",)}, "allowed_media_types", "invalid"),
        ({"allowed_media_types": ("json",)}, "allowed_media_types", "invalid"),
        ({"max_input_bytes": 0}, "max_input_bytes", "out_of_range"),
        ({"max_decoded_characters": 0}, "max_decoded_characters", "out_of_range"),
        ({"max_json_depth": 0}, "max_json_depth", "out_of_range"),
        ({"max_findings": 0}, "max_findings", "out_of_range"),
    ],
)
def test_policy_invariants_return_exact_content_free_evidence(
    changes: dict[str, object],
    field: str,
    code: str,
) -> None:
    with pytest.raises(IngestionValidationError) as captured:
        policy(**changes)
    assert_violation(captured.value, field, code)


@pytest.mark.parametrize(
    ("factory", "field", "code"),
    [
        (
            lambda: SensitiveFinding(SensitiveKind.SECRET, "$", -1, 1, "secret.test"),
            "finding_range",
            "invalid",
        ),
        (
            lambda: SensitiveFinding(SensitiveKind.SECRET, "$", 1, 1, "secret.test"),
            "finding_range",
            "invalid",
        ),
        (
            lambda: SensitiveFinding(SensitiveKind.SECRET, "", 0, 1, "secret.test"),
            "field_path",
            "invalid",
        ),
        (
            lambda: SensitiveFinding(SensitiveKind.SECRET, "$\x00", 0, 1, "secret.test"),
            "field_path",
            "invalid",
        ),
        (
            lambda: SensitiveFinding(SensitiveKind.SECRET, "$", 0, 1, "INVALID"),
            "detector_id",
            "invalid",
        ),
        (
            lambda: StageEvidence(PolicyStage.DECODE, (), "decoded"),
            "rule_ids",
            "not_canonical",
        ),
        (
            lambda: StageEvidence(PolicyStage.DECODE, ("b", "a"), "decoded"),
            "rule_ids",
            "not_canonical",
        ),
        (
            lambda: StageEvidence(PolicyStage.DECODE, ("ing005.decode.v1",), "BAD"),
            "outcome_code",
            "invalid",
        ),
    ],
)
def test_content_free_evidence_types_enforce_exact_invariants(
    factory: Any,
    field: str,
    code: str,
) -> None:
    with pytest.raises(IngestionValidationError) as captured:
        factory()
    assert_violation(captured.value, field, code)


@pytest.mark.asyncio
async def test_ignore_precedence_excludes_before_malformed_archive_decode_and_zeroes_raw() -> None:
    raw = bytearray(b"PK\x03\x04secret archive bytes")
    result = await CapturePolicyPipeline(Policies()).execute(
        CapturePolicyCommand(
            BRAIN_ID,
            REPOSITORY_ID,
            raw,
            "application/zip",
            ".env",
            Classification.INTERNAL,
        )
    )
    assert result.disposition is CaptureDisposition.EXCLUDED
    assert result.reason_code == "ignored_path"
    assert result.payload is None
    assert raw == bytearray(len(raw))
    assert tuple(item.stage for item in result.stages) == tuple(PolicyStage)
    assert result.stages[1].outcome_code == "not_run"


@pytest.mark.asyncio
async def test_nested_environment_file_is_ignored_before_decode() -> None:
    result = await CapturePolicyPipeline(Policies()).execute(
        command(b"malformed-private-input", source_path="services/api/.env.production")
    )
    assert result.disposition is CaptureDisposition.EXCLUDED
    assert result.reason_code == "ignored_path"


@pytest.mark.asyncio
@pytest.mark.parametrize("source_path", ["../secret", "a/../../secret", "/etc/passwd", "a\\b"])
async def test_path_traversal_and_nonportable_paths_fail_closed_and_release_raw(
    source_path: str,
) -> None:
    raw = bytearray(canonical({"status": "safe"}))
    with pytest.raises(IngestionValidationError) as captured:
        await CapturePolicyPipeline(Policies()).execute(
            command(bytes(raw), content=raw, source_path=source_path)
        )
    assert captured.value.has_field("source_path")
    assert raw == bytearray(len(raw))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "media_type", "code"),
    [
        (b"PK\x03\x04" + b"x" * 100, "application/json", "archive_prohibited"),
        (b"\x1f\x8b" + b"x" * 100, "application/json", "archive_prohibited"),
        (b"\xff\xfe\x00\x00x", "application/json", "unsupported"),
        (b'{"x":\xff}', "application/json", "malformed"),
        (b'{"x":1,"x":2}', "application/json", "duplicate_key"),
        (b'{"x":"a\x00b"}', "application/json", "binary_prohibited"),
    ],
)
async def test_binary_encoding_and_archive_inputs_cannot_bypass_inspection(
    payload: bytes,
    media_type: str,
    code: str,
) -> None:
    with pytest.raises(IngestionValidationError) as captured:
        await CapturePolicyPipeline(Policies()).execute(
            command(payload, media_type=media_type, source_path="src/input.dat")
        )
    expected_field = "encoding" if code in {"unsupported", "malformed"} else "content"
    assert_violation(captured.value, expected_field, code)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "signature",
    [
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"PK\x07\x08",
        b"\x1f\x8b",
        b"BZh",
        b"\xfd7zXZ\x00",
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!\x1a\x07",
    ],
)
async def test_every_archive_signature_is_rejected_with_exact_evidence(signature: bytes) -> None:
    with pytest.raises(IngestionValidationError) as captured:
        await CapturePolicyPipeline(Policies()).execute(
            command(signature + b"bounded payload", media_type="text/plain")
        )
    assert_violation(captured.value, "content", "archive_prohibited")


@pytest.mark.asyncio
async def test_tar_signature_is_rejected_at_the_exact_header_offset() -> None:
    payload = b"x" * 257 + b"ustar" + b"x"
    with pytest.raises(IngestionValidationError) as captured:
        await CapturePolicyPipeline(Policies()).execute(command(payload, media_type="text/plain"))
    assert_violation(captured.value, "content", "archive_prohibited")


@pytest.mark.asyncio
@pytest.mark.parametrize("bom", [b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"])
async def test_every_utf32_bom_is_rejected_with_exact_evidence(bom: bytes) -> None:
    with pytest.raises(IngestionValidationError) as captured:
        await CapturePolicyPipeline(Policies()).execute(command(bom + b"{}"))
    assert_violation(captured.value, "encoding", "unsupported")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b'\xef\xbb\xbf{"z":1,"a":2}', b'{"a":2,"z":1}'),
        (b"\xff\xfe" + '{"z":1,"a":2}'.encode("utf-16-le"), b'{"a":2,"z":1}'),
        (b"\xfe\xff" + '{"z":1,"a":2}'.encode("utf-16-be"), b'{"a":2,"z":1}'),
    ],
)
async def test_supported_boms_have_exact_canonical_utf8_output(
    payload: bytes,
    expected: bytes,
) -> None:
    result = await CapturePolicyPipeline(Policies()).execute(command(payload))
    assert result.payload == expected
    assert result.output_sha256 == hashlib.sha256(expected).hexdigest()


@pytest.mark.asyncio
@pytest.mark.parametrize("character", ["\x00", "\x01", "\x08", "\x0e", "\x1f"])
async def test_prohibited_controls_fail_with_exact_binary_evidence(character: str) -> None:
    with pytest.raises(IngestionValidationError) as captured:
        await CapturePolicyPipeline(Policies()).execute(
            command(f"safe{character}text".encode(), media_type="text/plain")
        )
    assert_violation(captured.value, "content", "binary_prohibited")


@pytest.mark.asyncio
@pytest.mark.parametrize("character", ["\t", "\n", "\r"])
async def test_permitted_text_controls_remain_byte_exact(character: str) -> None:
    payload = f"safe{character}text".encode()
    result = await CapturePolicyPipeline(Policies()).execute(
        command(payload, media_type="text/plain")
    )
    assert result.payload == payload


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "media_type", "field", "code"),
    [
        (b"{}", "image/png", "media_type", "prohibited"),
        (b"", "application/json", "content", "empty"),
        (b"{", "application/json", "content", "invalid_json"),
        (b'{"x":NaN}', "application/json", "content", "non_finite_number"),
        (b'{"x":Infinity}', "application/json", "content", "non_finite_number"),
        (b'{"x":1,"x":2}', "application/json", "content", "duplicate_key"),
    ],
)
async def test_decoder_failures_expose_only_the_exact_stable_contract(
    payload: bytes,
    media_type: str,
    field: str,
    code: str,
) -> None:
    with pytest.raises(IngestionValidationError) as captured:
        await CapturePolicyPipeline(Policies()).execute(command(payload, media_type=media_type))
    assert_violation(captured.value, field, code)


@pytest.mark.asyncio
async def test_media_type_normalization_accepts_parameters_case_and_whitespace() -> None:
    result = await CapturePolicyPipeline(Policies()).execute(
        command(b'{"z":1,"a":2}', media_type=" Application/JSON ; charset=utf-8")
    )
    assert result.payload == b'{"a":2,"z":1}'


@pytest.mark.asyncio
async def test_raw_and_decoded_size_limits_are_independently_enforced() -> None:
    raw_policy = policy(max_input_bytes=2)
    with pytest.raises(IngestionValidationError) as raw_error:
        await CapturePolicyPipeline(Policies(raw_policy)).execute(
            command(b"abc", media_type="text/plain")
        )
    assert_violation(raw_error.value, "content", "too_large")

    decoded_policy = policy(max_decoded_characters=2)
    with pytest.raises(IngestionValidationError) as decoded_error:
        await CapturePolicyPipeline(Policies(decoded_policy)).execute(
            command(b"abc", media_type="text/plain")
        )
    assert_violation(decoded_error.value, "content", "decoded_too_large")


@pytest.mark.asyncio
async def test_json_nesting_limit_counts_containers_and_scalars_exactly() -> None:
    bounded = policy(max_json_depth=2)
    accepted = await CapturePolicyPipeline(Policies(bounded)).execute(command(b'{"x":1}'))
    assert accepted.payload == b'{"x":1}'
    with pytest.raises(IngestionValidationError) as captured:
        await CapturePolicyPipeline(Policies(bounded)).execute(command(b'{"x":{"y":1}}'))
    assert_violation(captured.value, "content", "nesting_too_deep")


@pytest.mark.asyncio
async def test_utf16_is_explicitly_decoded_scanned_and_reencoded_as_canonical_utf8() -> None:
    secret = "sk-abcdefghijklmnopqrstuvwxyz123456"  # noqa: S105 -- Detection fixture.
    payload = b"\xff\xfe" + json.dumps({"token": secret}).encode("utf-16-le")
    result = await CapturePolicyPipeline(Policies()).execute(command(payload))
    assert result.payload == b'{"token":"[REDACTED:SECRET]"}'
    assert secret.encode() not in result.payload
    assert result.egress is EgressDisposition.DENY


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("AKIAIOSFODNN7EXAMPLE", SensitiveKind.SECRET),
        ("ghp_abcdefghijklmnopqrstuvwxyz123456", SensitiveKind.SECRET),
        ("sk-abcdefghijklmnopqrstuvwxyz123456", SensitiveKind.SECRET),
        ("Bearer abcdefghijklmnopqrstuvwxyz", SensitiveKind.SECRET),
        ("password=hunter22", SensitiveKind.SECRET),
        ("user@example.com", SensitiveKind.EMAIL),
        ("202-555-0198", SensitiveKind.PHONE),
        ("123-45-6789", SensitiveKind.GOVERNMENT_ID),
        ("4111 1111 1111 1111", SensitiveKind.PAYMENT_CARD),
    ],
)
async def test_secret_and_pii_corpus_is_redacted_and_remains_nonegress_tainted(
    value: str,
    kind: SensitiveKind,
) -> None:
    result = await CapturePolicyPipeline(Policies()).execute(command(canonical({"value": value})))
    assert result.payload is not None
    assert value.encode() not in result.payload
    assert kind in {finding.kind for finding in result.findings}
    assert result.redaction_count >= 1
    assert result.egress is EgressDisposition.DENY
    assert result.reason_code == "sensitive_taint"


@pytest.mark.asyncio
@pytest.mark.parametrize("encoding", ["base64", "percent", "html"])
async def test_nested_encoded_secrets_are_detected_without_persisting_encoded_canary(
    encoding: str,
) -> None:
    secret = "sk-abcdefghijklmnopqrstuvwxyz123456"  # noqa: S105 -- Detection fixture.
    encoded = {
        "base64": base64.b64encode(secret.encode()).decode(),
        "percent": secret.replace("-", "%2D"),
        "html": secret.replace("-", "&#45;"),
    }[encoding]
    result = await CapturePolicyPipeline(Policies()).execute(command(canonical({"value": encoded})))
    assert result.payload == b'{"value":"[REDACTED:SECRET]"}'
    assert encoded.encode() not in result.payload


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "document",
    [
        {"password": "otherwise-undetectable"},
        {"apiKey": "otherwise-undetectable"},
        {"client_secret": {"opaque": 123456}},
        {"refresh-token": 123456},
    ],
)
async def test_sensitive_json_field_names_redact_the_complete_value(document: object) -> None:
    result = await CapturePolicyPipeline(Policies()).execute(command(canonical(document)))
    assert result.payload is not None
    assert b"otherwise-undetectable" not in result.payload
    assert b"123456" not in result.payload
    assert b"[REDACTED:SECRET]" in result.payload
    assert SensitiveKind.SECRET in {finding.kind for finding in result.findings}


@pytest.mark.asyncio
@pytest.mark.parametrize("encoding", ["standard", "urlsafe"])
async def test_nested_base64_and_base64url_secret_cannot_bypass_scanning(
    encoding: str,
) -> None:
    secret = b"sk-abcdefghijklmnopqrstuvwxyz123456"
    encode = base64.urlsafe_b64encode if encoding == "urlsafe" else base64.b64encode
    encoded = encode(encode(secret)).decode()
    result = await CapturePolicyPipeline(Policies()).execute(command(canonical({"value": encoded})))
    assert result.payload == b'{"value":"[REDACTED:SECRET]"}'
    assert encoded.encode() not in result.payload


@pytest.mark.asyncio
async def test_private_blocks_are_removed_before_persistence_and_keep_nonegress_taint() -> None:
    value = "visible <agentmemory-private>never-persist-this</agentmemory-private> tail"
    result = await CapturePolicyPipeline(Policies()).execute(command(canonical({"value": value})))
    assert result.payload == b'{"value":"visible [REDACTED:PRIVATE] tail"}'
    assert b"never-persist-this" not in result.payload
    assert result.egress is EgressDisposition.DENY
    assert result.findings[0].kind is SensitiveKind.PRIVATE_BLOCK


@pytest.mark.asyncio
async def test_private_blocks_cover_both_rules_nested_paths_and_multiple_occurrences() -> None:
    document = {
        "a/b~c": [
            "x <agentmemory-private>one</agentmemory-private> y "
            "<agentmemory-private>two</agentmemory-private>",
            "agentmemory:private:startthreeagentmemory:private:end",
            7,
        ]
    }
    result = await CapturePolicyPipeline(Policies()).execute(command(canonical(document)))
    assert result.payload == canonical(
        {
            "a/b~c": [
                "x [REDACTED:PRIVATE] y [REDACTED:PRIVATE]",
                "[REDACTED:PRIVATE]",
                7,
            ]
        }
    )
    assert [finding.field_path for finding in result.findings] == [
        "$/a~1b~0c/0",
        "$/a~1b~0c/0",
        "$/a~1b~0c/1",
    ]
    assert [finding.detector_id for finding in result.findings] == [
        "private.block.1",
        "private.block.1",
        "private.block.2",
    ]
    assert result.redaction_count == 3


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [
        "<agentmemory-private>missing end",
        "missing start</agentmemory-private>",
        "</agentmemory-private><agentmemory-private>x</agentmemory-private>",
    ],
)
async def test_unbalanced_private_markers_fail_with_exact_evidence(value: str) -> None:
    with pytest.raises(IngestionValidationError) as captured:
        await CapturePolicyPipeline(Policies()).execute(command(canonical({"value": value})))
    assert_violation(captured.value, "private_block", "unbalanced")


def test_json_depth_and_pointer_helpers_are_exact_for_every_container_shape() -> None:
    json_depth = privacy_module._json_depth  # pyright: ignore[reportPrivateUsage]
    pointer_token = privacy_module._json_pointer_token  # pyright: ignore[reportPrivateUsage]
    assert json_depth(1) == 1
    assert json_depth({}) == 1
    assert json_depth([]) == 1
    assert json_depth({"a": [1, {"b": 2}]}) == 4
    assert pointer_token("a~/b") == "a~0~1b"


@pytest.mark.parametrize(
    ("digits", "expected"),
    [
        ("4111111111111111", True),
        ("5555555555554444", True),
        ("4111111111111112", False),
        ("1234567890123", False),
    ],
)
def test_luhn_validation_is_exact_for_odd_and_even_lengths(digits: str, expected: object) -> None:
    luhn_valid = privacy_module._luhn_valid  # pyright: ignore[reportPrivateUsage]
    assert luhn_valid(digits) is expected


@pytest.mark.asyncio
async def test_clean_content_uses_exact_route_but_never_allows_a_second_destination() -> None:
    route = AllowedEgressRoute(
        destination(),
        (Classification.CONFIDENTIAL, Classification.INTERNAL, Classification.PUBLIC),
    )
    configured = policy(egress_routes=(route,))
    pipeline = CapturePolicyPipeline(Policies(configured))
    allowed = await pipeline.execute(
        command(canonical({"status": "safe"}), destination=destination())
    )
    assert allowed.egress is EgressDisposition.ALLOW
    assert allowed.reason_code == "route_allowed"

    denied = await pipeline.execute(
        command(
            canonical({"status": "safe"}),
            destination=replace(destination(), endpoint="https://other.example.test"),
        )
    )
    assert denied.egress is EgressDisposition.DENY
    assert denied.reason_code == "route_denied"


@pytest.mark.asyncio
async def test_local_only_and_exclusion_actions_apply_before_durability() -> None:
    secret = canonical({"value": "password=hunter22"})
    local = await CapturePolicyPipeline(
        Policies(policy(secret_action=SensitiveAction.LOCAL_ONLY))
    ).execute(command(secret))
    assert local.disposition is CaptureDisposition.LOCAL_ONLY
    assert local.classification is Classification.LOCAL_ONLY
    assert local.egress is EgressDisposition.DENY

    excluded = await CapturePolicyPipeline(
        Policies(policy(secret_action=SensitiveAction.EXCLUDE))
    ).execute(command(secret))
    assert excluded.disposition is CaptureDisposition.EXCLUDED
    assert excluded.payload is None


@pytest.mark.asyncio
async def test_hidden_reasoning_is_excluded_without_decode_or_content_evidence() -> None:
    result = await CapturePolicyPipeline(Policies()).execute(
        command(b"not even json", source_class=SourceClass.HIDDEN_REASONING)
    )
    assert result.disposition is CaptureDisposition.EXCLUDED
    assert result.reason_code == "hidden_reasoning"
    assert result.findings == ()


@pytest.mark.asyncio
async def test_exact_rule_version_replay_is_deterministic_after_active_policy_changes() -> None:
    revision_one = policy()
    revision_two = replace(
        revision_one,
        policy_id="018f0000-0000-7000-8000-000000000402",
        version=2,
        secret_action=SensitiveAction.LOCAL_ONLY,
    )
    policies = Policies(revision_one, revision_two)
    payload = canonical({"value": "password=hunter22"})
    replay_a = await CapturePolicyPipeline(policies).execute(command(payload, policy_version=1))
    active = await CapturePolicyPipeline(policies).execute(command(payload))
    replay_b = await CapturePolicyPipeline(policies).execute(command(payload, policy_version=1))
    assert replay_a == replay_b
    assert replay_a.policy_sha256 == revision_one.sha256
    assert active.policy_sha256 == revision_two.sha256
    assert active.disposition is CaptureDisposition.LOCAL_ONLY


@pytest.mark.asyncio
async def test_provider_egress_spy_is_never_called_for_secret_or_unapproved_route() -> None:
    route = AllowedEgressRoute(
        destination(),
        (Classification.CONFIDENTIAL, Classification.INTERNAL, Classification.PUBLIC),
    )
    spy = EgressSpy()
    handler = SanitizedProviderEgressHandler(
        CapturePolicyPipeline(Policies(policy(egress_routes=(route,)))),
        spy,
    )
    raw = bytearray(canonical({"value": "password=hunter22"}))
    with pytest.raises(IngestionEgressDeniedError) as captured:
        await handler.execute(
            command(bytes(raw), content=raw, destination=destination()),
            "operation-1",
        )
    assert captured.value.reason_code == "sensitive_taint"
    assert spy.calls == []
    assert raw == bytearray(len(raw))

    with pytest.raises(IngestionEgressDeniedError):
        await handler.execute(
            command(
                canonical({"value": "safe"}),
                destination=replace(destination(), endpoint="https://other.example.test"),
            ),
            "operation-2",
        )
    assert spy.calls == []


@pytest.mark.asyncio
async def test_provider_egress_receives_only_the_deterministic_sanitized_payload() -> None:
    route = AllowedEgressRoute(
        destination(),
        (Classification.CONFIDENTIAL, Classification.INTERNAL, Classification.PUBLIC),
    )
    spy = EgressSpy()
    handler = SanitizedProviderEgressHandler(
        CapturePolicyPipeline(Policies(policy(egress_routes=(route,)))),
        spy,
    )
    response, result = await handler.execute(
        command(canonical({"z": 1, "a": "safe"}), destination=destination()),
        "operation-3",
    )
    assert response == b"provider-result"
    assert result.egress is EgressDisposition.ALLOW
    assert spy.calls == [(destination(), b'{"a":"safe","z":1}', "operation-3")]
