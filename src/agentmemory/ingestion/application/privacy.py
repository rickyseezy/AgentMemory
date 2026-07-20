"""Ordered pre-persistence and pre-egress capture privacy pipeline."""

from __future__ import annotations

import base64
import binascii
import fnmatch
import hashlib
import html
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Never, cast
from urllib.parse import unquote

from agentmemory.ingestion.domain.agent_event import Classification, JsonValue
from agentmemory.ingestion.domain.errors import IngestionEgressDeniedError, IngestionValidationError
from agentmemory.ingestion.domain.privacy import (
    CaptureDisposition,
    CapturePolicy,
    CapturePolicyResult,
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

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.ports import CapturePolicyRepository, ProviderEgressInvoker

_ARCHIVE_SIGNATURES = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07",
)
_UTF8_BOM = b"\xef\xbb\xbf"
_UTF16_LE_BOM = b"\xff\xfe"
_UTF16_BE_BOM = b"\xfe\xff"
_UTF32_BOMS = (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")
_BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])")
_SECRET_FIELD_NAMES = frozenset(
    {
        "accesskey",
        "accesstoken",
        "apikey",
        "authtoken",
        "authorization",
        "clientsecret",
        "password",
        "passwd",
        "privatekey",
        "pwd",
        "refreshtoken",
        "secret",
        "token",
    }
)
_SECRET_PATTERNS = (
    ("secret.aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("secret.github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b")),
    ("secret.openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,255}\b")),
    (
        "secret.bearer",
        re.compile(r"(?i)\bbearer[ \t]+[A-Za-z0-9._~+/-]{12,}={0,2}"),
    ),
    (
        "secret.assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|secret)"
            r"[ \t]*[:=][ \t]*[^\s,;\"']{6,}"
        ),
    ),
    (
        "secret.private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
)
_EMAIL = re.compile(r"(?i)(?<![A-Z0-9._%+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![A-Z0-9.-])")
_PHONE = re.compile(
    r"(?<!\d)(?:\+?[1-9]\d{0,2}[ .-]?)?(?:\(?\d{2,4}\)?[ .-]?)\d{3}[ .-]?\d{4}(?!\d)"
)
_GOVERNMENT_ID = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_PRIVATE_TOKEN = "[REDACTED:PRIVATE]"  # noqa: S105  # nosec B105 -- Replacement marker.
_REDACTION_TOKENS = {
    SensitiveKind.SECRET: "[REDACTED:SECRET]",
    SensitiveKind.EMAIL: "[REDACTED:EMAIL]",
    SensitiveKind.PHONE: "[REDACTED:PHONE]",
    SensitiveKind.GOVERNMENT_ID: "[REDACTED:GOVERNMENT_ID]",
    SensitiveKind.PAYMENT_CARD: "[REDACTED:PAYMENT_CARD]",
}
_MAX_TRANSFORM_PASSES = 2
_MAX_SOURCE_PATH = 4096
_TAR_MAGIC_END = 262
_TAR_MAGIC_START = 257
_MIN_PERMITTED_CONTROL = 9
_CARRIAGE_RETURN = 13
_C0_CONTROL_LIMIT = 32
_MAX_DECODED_TOKEN_BYTES = 4096
_MIN_PAYMENT_CARD_DIGITS = 13
_MAX_PAYMENT_CARD_DIGITS = 19
_LUHN_DECIMAL_MAX = 9
_MAX_IDEMPOTENCY_KEY = 256


@dataclass(frozen=True, slots=True)
class CapturePolicyCommand:
    """Bounded mutable input and immutable scope/destination policy facts."""

    brain_id: str
    repository_id: str | None
    content: bytearray
    media_type: str
    source_path: str | None
    declared_classification: Classification
    source_class: SourceClass = SourceClass.OBSERVABLE
    destination: EgressDestination | None = None
    policy_version: int | None = None

    def __post_init__(self) -> None:
        """Reject immutable/unbounded raw buffers and ambiguous policy versions."""
        if not isinstance(cast("object", self.content), bytearray):
            _invalid("content", "mutable_buffer_required")
        if self.policy_version is not None and self.policy_version < 1:
            _invalid("policy_version", "out_of_range")


@dataclass(frozen=True, slots=True)
class _DecodedContent:
    media_type: str
    value: JsonValue | str


@dataclass(frozen=True, slots=True)
class _Inspection:
    value: JsonValue | str
    findings: tuple[SensitiveFinding, ...]
    private_count: int


class CapturePolicyPipeline:
    """Execute closed privacy stages and always release the raw mutable buffer."""

    def __init__(self, policies: CapturePolicyRepository) -> None:
        """Depend only on the versioned policy repository port."""
        self._policies = policies

    async def execute(self, command: CapturePolicyCommand) -> CapturePolicyResult:
        """Return sanitized/rejected content without retaining pre-redaction bytes."""
        policy = await self._policies.resolve(
            command.brain_id,
            command.repository_id,
            command.policy_version,
        )
        raw = command.content
        input_sha256 = hashlib.sha256(raw).hexdigest()
        try:
            path_reason = _path_exclusion(command.source_path, policy)
            source_reason = (
                "hidden_reasoning" if command.source_class is SourceClass.HIDDEN_REASONING else None
            )
            excluded_reason = source_reason or path_reason
            if excluded_reason is not None:
                return _excluded_result(policy, input_sha256, excluded_reason)
            decoded = _decode(bytes(raw), command.media_type, policy)
            private_value, private_findings = _remove_private_blocks(decoded.value, policy)
            scanned = _scan(private_value, private_findings, policy)
            classification = _classify(command.declared_classification, scanned.findings, policy)
            disposition = _disposition(scanned.findings, policy)
            if disposition is CaptureDisposition.EXCLUDED:
                return _excluded_result(
                    policy,
                    input_sha256,
                    "sensitive_content_excluded",
                    findings=scanned.findings,
                    decode_outcome="decoded",
                )
            redacted, redaction_count = _redact(scanned.value, scanned.findings, policy)
            payload = _encode(redacted, decoded.media_type, policy)
            egress, egress_reason = _decide_egress(
                command.destination,
                classification,
                scanned.findings,
                disposition,
                policy,
            )
            if disposition is CaptureDisposition.LOCAL_ONLY:
                classification = Classification.LOCAL_ONLY
                egress = EgressDisposition.DENY
                egress_reason = "local_only"
            stages = _stages(
                exclusion="included",
                decode="decoded",
                classification=f"classified_{classification.value}",
                scan="findings" if scanned.findings else "clear",
                redaction="redacted" if redaction_count else "unchanged",
                egress=f"egress_{egress.value}",
            )
            return CapturePolicyResult(
                disposition=disposition,
                payload=payload,
                classification=classification,
                egress=egress,
                reason_code=egress_reason,
                policy_id=policy.policy_id,
                policy_version=policy.version,
                policy_sha256=policy.sha256,
                input_sha256=input_sha256,
                output_sha256=hashlib.sha256(payload).hexdigest(),
                findings=scanned.findings,
                redaction_count=redaction_count,
                stages=stages,
            )
        finally:
            raw[:] = b"\x00" * len(raw)


@dataclass(frozen=True, slots=True)
class SanitizedProviderEgressHandler:
    """Permit socket-owning provider code only after the shared privacy pipeline."""

    pipeline: CapturePolicyPipeline
    invoker: ProviderEgressInvoker

    async def execute(
        self,
        command: CapturePolicyCommand,
        downstream_idempotency_key: str,
    ) -> tuple[bytes, CapturePolicyResult]:
        """Invoke with sanitized bytes or fail before the provider port is called."""
        if (
            not downstream_idempotency_key
            or len(downstream_idempotency_key) > _MAX_IDEMPOTENCY_KEY
            or any(ord(character) < _C0_CONTROL_LIMIT for character in downstream_idempotency_key)
        ):
            _invalid("downstream_idempotency_key", "invalid")
        result = await self.pipeline.execute(command)
        if (
            result.egress is not EgressDisposition.ALLOW
            or result.payload is None
            or command.destination is None
        ):
            raise IngestionEgressDeniedError(result.reason_code)
        response = await self.invoker.invoke(
            command.destination,
            result.payload,
            downstream_idempotency_key,
        )
        return response, result


def _path_exclusion(source_path: str | None, policy: CapturePolicy) -> str | None:
    if source_path is None:
        return None
    if (
        not source_path
        or "\\" in source_path
        or "\x00" in source_path
        or source_path.startswith("/")
        or len(source_path) > _MAX_SOURCE_PATH
    ):
        _invalid("source_path", "unsafe")
    path = PurePosixPath(source_path)
    if any(part in {"", ".", ".."} for part in path.parts):
        _invalid("source_path", "unsafe")
    normalized = path.as_posix()
    for pattern in policy.ignore_patterns:
        root_pattern = pattern.removeprefix("**/")
        if fnmatch.fnmatchcase(normalized, pattern) or fnmatch.fnmatchcase(
            normalized, root_pattern
        ):
            return "ignored_path"
    return None


def _decode(  # noqa: C901, PLR0912 -- Decode rejects every ambiguous binary/text shape.
    content: bytes,
    media_type: str,
    policy: CapturePolicy,
) -> _DecodedContent:
    normalized_media_type = media_type.partition(";")[0].strip().lower()
    if normalized_media_type not in policy.allowed_media_types:
        _invalid("media_type", "prohibited")
    if not content:
        _invalid("content", "empty")
    if len(content) > policy.max_input_bytes:
        _invalid("content", "too_large")
    if any(content.startswith(signature) for signature in _ARCHIVE_SIGNATURES) or (
        len(content) > _TAR_MAGIC_END and content[_TAR_MAGIC_START:_TAR_MAGIC_END] == b"ustar"
    ):
        _invalid("content", "archive_prohibited")
    if any(content.startswith(signature) for signature in _UTF32_BOMS):
        _invalid("encoding", "unsupported")
    try:
        if content.startswith(_UTF8_BOM):
            text = content.decode("utf-8-sig", errors="strict")
        elif content.startswith(_UTF16_LE_BOM):
            text = content[len(_UTF16_LE_BOM) :].decode("utf-16-le", errors="strict")
        elif content.startswith(_UTF16_BE_BOM):
            text = content[len(_UTF16_BE_BOM) :].decode("utf-16-be", errors="strict")
        else:
            text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _invalid("encoding", "malformed")
    if len(text) > policy.max_decoded_characters:
        _invalid("content", "decoded_too_large")
    if "\x00" in text or any(
        ord(character) < _MIN_PERMITTED_CONTROL
        or _CARRIAGE_RETURN < ord(character) < _C0_CONTROL_LIMIT
        for character in text
    ):
        _invalid("content", "binary_prohibited")
    if normalized_media_type == "application/json":
        value = _strict_json(text)
        if _json_depth(value) > policy.max_json_depth:
            _invalid("content", "nesting_too_deep")
        return _DecodedContent(normalized_media_type, value)
    return _DecodedContent(normalized_media_type, text)


def _strict_json(text: str) -> JsonValue:
    def reject_constant(_: str) -> None:
        _invalid("content", "non_finite_number")

    def unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {}
        for key, value in pairs:
            if key in result:
                _invalid("content", "duplicate_key")
            result[key] = value
        return result

    try:
        return cast(
            "JsonValue",
            json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_constant),
        )
    except json.JSONDecodeError:
        _invalid("content", "invalid_json")


def _json_depth(value: JsonValue, current: int = 1) -> int:
    if isinstance(value, dict):
        return max((_json_depth(item, current + 1) for item in value.values()), default=current)
    if isinstance(value, list):
        return max((_json_depth(item, current + 1) for item in value), default=current)
    return current


def _remove_private_blocks(
    value: JsonValue | str,
    policy: CapturePolicy,
) -> tuple[JsonValue | str, tuple[SensitiveFinding, ...]]:
    findings: list[SensitiveFinding] = []

    def visit(item: JsonValue | str, path: str) -> JsonValue | str:
        if isinstance(item, dict):
            return {
                key: visit(child, f"{path}/{_json_pointer_token(key)}")
                for key, child in item.items()
            }
        if isinstance(item, list):
            return [visit(child, f"{path}/{index}") for index, child in enumerate(item)]
        if not isinstance(item, str):
            return item
        result = item
        for pair_index, (start_marker, end_marker) in enumerate(policy.private_block_pairs):
            while start_marker in result or end_marker in result:
                start = result.find(start_marker)
                end_without_start = result.find(end_marker)
                if start < 0 or (0 <= end_without_start < start):
                    _invalid("private_block", "unbalanced")
                end = result.find(end_marker, start + len(start_marker))
                if end < 0:
                    _invalid("private_block", "unbalanced")
                finish = end + len(end_marker)
                findings.append(
                    SensitiveFinding(
                        SensitiveKind.PRIVATE_BLOCK,
                        path,
                        start,
                        finish,
                        f"private.block.{pair_index + 1}",
                    )
                )
                result = result[:start] + _PRIVATE_TOKEN + result[finish:]
        return result

    transformed = visit(value, "$")
    return transformed, tuple(sorted(findings))


def _scan(
    value: JsonValue | str,
    private_findings: tuple[SensitiveFinding, ...],
    policy: CapturePolicy,
) -> _Inspection:
    findings = list(private_findings)

    def visit(item: JsonValue | str, path: str) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                child_path = f"{path}/{_json_pointer_token(key)}"
                normalized_key = "".join(
                    character for character in key.lower() if character.isalnum()
                )
                if normalized_key in _SECRET_FIELD_NAMES:
                    serialized = json.dumps(
                        child,
                        allow_nan=False,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    findings.append(
                        SensitiveFinding(
                            SensitiveKind.SECRET,
                            child_path,
                            0,
                            max(1, len(serialized)),
                            "secret.field_name",
                        )
                    )
                else:
                    visit(child, child_path)
            return
        if isinstance(item, list):
            for index, child in enumerate(item):
                visit(child, f"{path}/{index}")
            return
        if isinstance(item, str):
            findings.extend(_scan_text(item, path))

    visit(value, "$")
    canonical = tuple(sorted(set(findings)))
    if len(canonical) > policy.max_findings:
        _invalid("findings", "too_many")
    return _Inspection(value, canonical, len(private_findings))


def _scan_text(value: str, path: str) -> list[SensitiveFinding]:
    findings = _direct_findings(value, path)
    transformed = value
    for _ in range(_MAX_TRANSFORM_PASSES):
        decoded = html.unescape(unquote(transformed))
        if decoded == transformed:
            break
        if _direct_findings(decoded, path):
            findings.append(
                SensitiveFinding(
                    SensitiveKind.SECRET,
                    path,
                    0,
                    max(1, len(value)),
                    "secret.encoded_text",
                )
            )
            break
        transformed = decoded
    for match in _BASE64_TOKEN.finditer(value):
        token = match.group(0)
        if _encoded_token_contains_finding(token, path):
            findings.append(
                SensitiveFinding(
                    SensitiveKind.SECRET,
                    path,
                    match.start(),
                    match.end(),
                    "secret.base64",
                )
            )
    return findings


def _encoded_token_contains_finding(token: str, path: str) -> bool:
    transformed = token
    for _ in range(_MAX_TRANSFORM_PASSES):
        try:
            decoded_bytes = base64.b64decode(
                transformed,
                altchars=b"-_",
                validate=True,
            )
            if len(decoded_bytes) > _MAX_DECODED_TOKEN_BYTES:
                return False
            decoded_text = decoded_bytes.decode("utf-8", errors="strict")
        except binascii.Error, UnicodeDecodeError:
            return False
        if _direct_findings(decoded_text, path):
            return True
        transformed = decoded_text
    return False


def _direct_findings(value: str, path: str) -> list[SensitiveFinding]:
    findings: list[SensitiveFinding] = []
    for detector_id, pattern in _SECRET_PATTERNS:
        findings.extend(
            SensitiveFinding(SensitiveKind.SECRET, path, match.start(), match.end(), detector_id)
            for match in pattern.finditer(value)
        )
    for kind, detector_id, pattern in (
        (SensitiveKind.EMAIL, "pii.email", _EMAIL),
        (SensitiveKind.PHONE, "pii.phone", _PHONE),
        (SensitiveKind.GOVERNMENT_ID, "pii.government_id", _GOVERNMENT_ID),
    ):
        findings.extend(
            SensitiveFinding(kind, path, match.start(), match.end(), detector_id)
            for match in pattern.finditer(value)
        )
    for match in _CARD_CANDIDATE.finditer(value):
        digits = "".join(character for character in match.group(0) if character.isdigit())
        if _MIN_PAYMENT_CARD_DIGITS <= len(digits) <= _MAX_PAYMENT_CARD_DIGITS and _luhn_valid(
            digits
        ):
            findings.append(
                SensitiveFinding(
                    SensitiveKind.PAYMENT_CARD,
                    path,
                    match.start(),
                    match.end(),
                    "pii.payment_card",
                )
            )
    return findings


def _classify(
    declared: Classification,
    findings: tuple[SensitiveFinding, ...],
    policy: CapturePolicy,
) -> Classification:
    result = maximum_classification(declared, policy.base_classification)
    kinds = {finding.kind for finding in findings}
    if kinds & {SensitiveKind.EMAIL, SensitiveKind.PHONE}:
        result = maximum_classification(result, Classification.CONFIDENTIAL)
    if kinds & {SensitiveKind.GOVERNMENT_ID, SensitiveKind.PAYMENT_CARD}:
        result = maximum_classification(result, Classification.RESTRICTED)
    if SensitiveKind.SECRET in kinds or SensitiveKind.PRIVATE_BLOCK in kinds:
        result = maximum_classification(result, Classification.RESTRICTED)
    if (SensitiveKind.SECRET in kinds and policy.secret_action is SensitiveAction.LOCAL_ONLY) or (
        kinds
        & {
            SensitiveKind.EMAIL,
            SensitiveKind.PHONE,
            SensitiveKind.GOVERNMENT_ID,
            SensitiveKind.PAYMENT_CARD,
        }
        and policy.pii_action is SensitiveAction.LOCAL_ONLY
    ):
        return Classification.LOCAL_ONLY
    return result


def _disposition(
    findings: tuple[SensitiveFinding, ...],
    policy: CapturePolicy,
) -> CaptureDisposition:
    kinds = {finding.kind for finding in findings}
    has_secret = SensitiveKind.SECRET in kinds
    has_pii = bool(
        kinds
        & {
            SensitiveKind.EMAIL,
            SensitiveKind.PHONE,
            SensitiveKind.GOVERNMENT_ID,
            SensitiveKind.PAYMENT_CARD,
        }
    )
    actions = {
        policy.secret_action if has_secret else SensitiveAction.REDACT,
        policy.pii_action if has_pii else SensitiveAction.REDACT,
    }
    if SensitiveAction.EXCLUDE in actions:
        return CaptureDisposition.EXCLUDED
    if SensitiveAction.LOCAL_ONLY in actions:
        return CaptureDisposition.LOCAL_ONLY
    return CaptureDisposition.SANITIZED


def _redact(
    value: JsonValue | str,
    findings: tuple[SensitiveFinding, ...],
    policy: CapturePolicy,
) -> tuple[JsonValue | str, int]:
    applicable = [
        finding
        for finding in findings
        if finding.kind is not SensitiveKind.PRIVATE_BLOCK
        and (
            (
                finding.kind is SensitiveKind.SECRET
                and policy.secret_action is SensitiveAction.REDACT
            )
            or (
                finding.kind is not SensitiveKind.SECRET
                and policy.pii_action is SensitiveAction.REDACT
            )
        )
    ]
    by_path: dict[str, list[SensitiveFinding]] = {}
    for finding in applicable:
        by_path.setdefault(finding.field_path, []).append(finding)

    def visit(item: JsonValue | str, path: str) -> JsonValue | str:
        selected = by_path.get(path, [])
        if selected and not isinstance(item, str):
            return _REDACTION_TOKENS[selected[0].kind]
        if isinstance(item, dict):
            return {
                key: visit(child, f"{path}/{_json_pointer_token(key)}")
                for key, child in item.items()
            }
        if isinstance(item, list):
            return [visit(child, f"{path}/{index}") for index, child in enumerate(item)]
        if not isinstance(item, str):
            return item
        result = item
        for finding in sorted(selected, key=lambda found: (found.start, found.end), reverse=True):
            start = min(finding.start, len(result))
            end = min(finding.end, len(result))
            if end <= start:
                start, end = 0, len(result)
            result = result[:start] + _REDACTION_TOKENS[finding.kind] + result[end:]
        return result

    return visit(value, "$"), len(applicable) + sum(
        finding.kind is SensitiveKind.PRIVATE_BLOCK for finding in findings
    )


def _encode(value: JsonValue | str, media_type: str, policy: CapturePolicy) -> bytes:
    if media_type == "application/json":
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    elif isinstance(value, str):
        encoded = value.encode("utf-8")
    else:  # pragma: no cover - decoder binds value shape to media type.
        raise AssertionError
    if not encoded or len(encoded) > policy.max_input_bytes:
        _invalid("content", "sanitized_size_invalid")
    return encoded


def _decide_egress(
    destination: EgressDestination | None,
    classification: Classification,
    findings: tuple[SensitiveFinding, ...],
    disposition: CaptureDisposition,
    policy: CapturePolicy,
) -> tuple[EgressDisposition, str]:
    if disposition is CaptureDisposition.LOCAL_ONLY:
        return EgressDisposition.DENY, "local_only"
    if findings:
        return EgressDisposition.DENY, "sensitive_taint"
    if destination is None:
        return EgressDisposition.DENY, "no_destination"
    if classification in {Classification.RESTRICTED, Classification.LOCAL_ONLY}:
        return EgressDisposition.DENY, "classification_denied"
    for route in policy.egress_routes:
        if route.destination == destination and classification in route.allowed_classifications:
            return EgressDisposition.ALLOW, "route_allowed"
    return EgressDisposition.DENY, "route_denied"


def _excluded_result(
    policy: CapturePolicy,
    input_sha256: str,
    reason: str,
    *,
    findings: tuple[SensitiveFinding, ...] = (),
    decode_outcome: str = "not_run",
) -> CapturePolicyResult:
    return CapturePolicyResult(
        disposition=CaptureDisposition.EXCLUDED,
        payload=None,
        classification=Classification.LOCAL_ONLY,
        egress=EgressDisposition.DENY,
        reason_code=reason,
        policy_id=policy.policy_id,
        policy_version=policy.version,
        policy_sha256=policy.sha256,
        input_sha256=input_sha256,
        output_sha256=None,
        findings=findings,
        redaction_count=0,
        stages=_stages(
            exclusion="excluded",
            decode=decode_outcome,
            classification="not_run",
            scan="not_run",
            redaction="not_run",
            egress="egress_deny",
        ),
    )


def _stages(  # noqa: PLR0913 -- Exact closed stage outcomes are intentionally explicit.
    *,
    exclusion: str,
    decode: str,
    classification: str,
    scan: str,
    redaction: str,
    egress: str,
) -> tuple[StageEvidence, ...]:
    outcomes = (exclusion, decode, classification, scan, redaction, egress)
    return tuple(
        StageEvidence(stage, (f"ing005.{stage.value}.v1",), outcome)
        for stage, outcome in zip(PolicyStage, outcomes, strict=True)
    )


def _json_pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _luhn_valid(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        value = int(character)
        if index % 2 == parity:
            value *= 2
            if value > _LUHN_DECIMAL_MAX:
                value -= _LUHN_DECIMAL_MAX
        total += value
    return total % 10 == 0


def _invalid(field: str, code: str) -> Never:
    raise IngestionValidationError.single(field, code)
