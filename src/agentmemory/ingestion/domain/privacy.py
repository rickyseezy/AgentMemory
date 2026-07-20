"""Versioned pre-persistence privacy policy and audit-safe outcomes."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Never, cast
from urllib.parse import urlsplit
from uuid import UUID

from agentmemory.ingestion.domain.agent_event import Classification
from agentmemory.ingestion.domain.errors import IngestionValidationError

if TYPE_CHECKING:
    from collections.abc import Mapping

_UUID_VERSION = 7
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RULE_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_DESTINATION_HOST = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_MAX_RULES = 256
_MAX_RULE_LENGTH = 512
_MAX_POLICY_BYTES = 256 * 1024
_MAX_INPUT_BYTES = 1024 * 1024
_MAX_DECODED_CHARACTERS = 1024 * 1024
_MAX_JSON_DEPTH = 64
_MAX_FINDINGS = 1024
_MAX_MODEL_ID = 256
_MAX_FIELD_PATH = 512
_C0_CONTROL_LIMIT = 32
_DELETE_CONTROL = 127


class SensitiveKind(StrEnum):
    """Closed taints that deterministic inspection may discover."""

    PRIVATE_BLOCK = "private_block"
    SECRET = "secret"  # noqa: S105  # nosec B105 -- Classification token.
    EMAIL = "email"
    PHONE = "phone"
    GOVERNMENT_ID = "government_id"
    PAYMENT_CARD = "payment_card"


class SensitiveAction(StrEnum):
    """Closed handling action for discovered content."""

    REDACT = "redact"
    LOCAL_ONLY = "local_only"
    EXCLUDE = "exclude"


class CaptureDisposition(StrEnum):
    """Durability result selected before any canonical payload write."""

    EXCLUDED = "excluded"
    SANITIZED = "sanitized"
    LOCAL_ONLY = "local_only"


class EgressDisposition(StrEnum):
    """Closed decision made before a provider adapter may be invoked."""

    ALLOW = "allow"
    DENY = "deny"


class PolicyStage(StrEnum):
    """Ordered capture stages retained as content-free evidence."""

    EXCLUSION = "exclusion"
    DECODE = "decode"
    CLASSIFICATION = "classification"
    SECRET_SCAN = "secret_scan"  # noqa: S105  # nosec B105 -- Stage token.
    REDACTION = "redaction"
    EGRESS_DECISION = "egress_decision"


class SourceClass(StrEnum):
    """Adapter-declared source classes; hidden reasoning is never admissible."""

    OBSERVABLE = "observable"
    EXPLICIT_USER_CONTENT = "explicit_user_content"
    HIDDEN_REASONING = "hidden_reasoning"


_CLASSIFICATION_ORDER: Mapping[Classification, int] = MappingProxyType(
    {
        Classification.PUBLIC: 0,
        Classification.INTERNAL: 1,
        Classification.CONFIDENTIAL: 2,
        Classification.RESTRICTED: 3,
        Classification.LOCAL_ONLY: 4,
    }
)


def maximum_classification(*values: Classification) -> Classification:
    """Return the most restrictive class without relying on enum declaration order."""
    if not values:
        _invalid("classification", "required")
    return max(values, key=_CLASSIFICATION_ORDER.__getitem__)


@dataclass(frozen=True, slots=True, order=True)
class EgressDestination:
    """Exact provider destination facts, excluding credentials and content."""

    provider_id: str
    endpoint: str
    region: str
    model_id: str
    purpose: str

    def __post_init__(self) -> None:
        """Require an exact public HTTPS origin and canonical policy tokens."""
        for value, field in (
            (self.provider_id, "provider_id"),
            (self.region, "region"),
            (self.purpose, "purpose"),
        ):
            _require_token(value, field)
        if not self.model_id or len(self.model_id) > _MAX_MODEL_ID or _has_control(self.model_id):
            _invalid("model_id", "invalid")
        parsed = urlsplit(self.endpoint)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or _DESTINATION_HOST.fullmatch(parsed.hostname) is None
            or not _is_public_dns_name(parsed.hostname)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or parsed.port not in {None, 443}
        ):
            _invalid("endpoint", "unsafe")

    @property
    def canonical_origin(self) -> str:
        """Return the normalized exact HTTPS origin used by policy matching."""
        parsed = urlsplit(self.endpoint)
        return f"https://{cast('str', parsed.hostname).lower()}:443"


@dataclass(frozen=True, slots=True, order=True)
class AllowedEgressRoute:
    """One policy-authorized provider route with closed allowed classifications."""

    destination: EgressDestination
    allowed_classifications: tuple[Classification, ...]

    def __post_init__(self) -> None:
        """Reject empty, duplicate, or intrinsically unsafe egress classes."""
        canonical = tuple(sorted(set(self.allowed_classifications), key=str))
        forbidden = {Classification.RESTRICTED, Classification.LOCAL_ONLY}
        if not canonical or canonical != self.allowed_classifications or forbidden & set(canonical):
            _invalid("allowed_classifications", "unsafe")


@dataclass(frozen=True, slots=True)
class CapturePolicy:
    """Immutable complete policy revision resolved for one Brain/repository scope."""

    policy_id: str
    version: int
    brain_id: str
    repository_id: str | None
    ignore_patterns: tuple[str, ...]
    private_block_pairs: tuple[tuple[str, str], ...]
    allowed_media_types: tuple[str, ...]
    secret_action: SensitiveAction
    pii_action: SensitiveAction
    base_classification: Classification
    egress_routes: tuple[AllowedEgressRoute, ...]
    max_input_bytes: int = _MAX_INPUT_BYTES
    max_decoded_characters: int = _MAX_DECODED_CHARACTERS
    max_json_depth: int = _MAX_JSON_DEPTH
    max_findings: int = _MAX_FINDINGS

    def __post_init__(self) -> None:  # noqa: C901, PLR0912 -- Complete policy is fail-closed.
        """Require canonical, bounded rules that can be replayed without ambiguity."""
        _require_uuid7(self.policy_id, "policy_id")
        _require_uuid7(self.brain_id, "brain_id")
        if self.repository_id is not None:
            _require_uuid7(self.repository_id, "repository_id")
        if self.version < 1:
            _invalid("policy_version", "out_of_range")
        _require_canonical_rules(self.ignore_patterns, "ignore_patterns")
        if not self.private_block_pairs or len(self.private_block_pairs) > _MAX_RULES:
            _invalid("private_block_pairs", "invalid")
        if tuple(sorted(set(self.private_block_pairs))) != self.private_block_pairs:
            _invalid("private_block_pairs", "not_canonical")
        flattened: list[str] = []
        for start, end in self.private_block_pairs:
            if not start or not end or start == end:
                _invalid("private_block_pairs", "invalid")
            flattened.extend((start, end))
        _require_bounded_rules(tuple(flattened), "private_block_pairs")
        _require_canonical_rules(self.allowed_media_types, "allowed_media_types")
        if not all("/" in item and item == item.lower() for item in self.allowed_media_types):
            _invalid("allowed_media_types", "invalid")
        if not 1 <= self.max_input_bytes <= _MAX_INPUT_BYTES:
            _invalid("max_input_bytes", "out_of_range")
        if not 1 <= self.max_decoded_characters <= _MAX_DECODED_CHARACTERS:
            _invalid("max_decoded_characters", "out_of_range")
        if not 1 <= self.max_json_depth <= _MAX_JSON_DEPTH:
            _invalid("max_json_depth", "out_of_range")
        if not 1 <= self.max_findings <= _MAX_FINDINGS:
            _invalid("max_findings", "out_of_range")
        canonical_routes = tuple(sorted(set(self.egress_routes), key=_route_sort_key))
        if canonical_routes != self.egress_routes:
            _invalid("egress_routes", "not_canonical")
        if len({route.destination for route in self.egress_routes}) != len(self.egress_routes):
            _invalid("egress_routes", "duplicate")
        if len(self.canonical_bytes) > _MAX_POLICY_BYTES:
            _invalid("policy", "too_large")

    @classmethod
    def secure_default(cls, brain_id: str, repository_id: str | None) -> CapturePolicy:
        """Return the versioned offline-first policy used until an owner narrows it."""
        return cls(
            policy_id="018f0000-0000-7000-8000-000000000401",
            version=1,
            brain_id=brain_id,
            repository_id=repository_id,
            ignore_patterns=(
                "**/*.key",
                "**/*.pem",
                "**/*secret*",
                "**/.env",
                "**/.env.*",
                ".agentmemory-private/**",
                ".env",
                ".env.*",
            ),
            private_block_pairs=(
                ("<agentmemory-private>", "</agentmemory-private>"),
                ("agentmemory:private:start", "agentmemory:private:end"),
            ),
            allowed_media_types=("application/json", "text/plain"),
            secret_action=SensitiveAction.REDACT,
            pii_action=SensitiveAction.REDACT,
            base_classification=Classification.INTERNAL,
            egress_routes=(),
        )

    @property
    def canonical_bytes(self) -> bytes:
        """Serialize the complete revision without ambient defaults."""
        document = {
            "allowed_media_types": list(self.allowed_media_types),
            "base_classification": self.base_classification.value,
            "brain_id": self.brain_id,
            "egress_routes": [
                {
                    "allowed_classifications": [
                        item.value for item in route.allowed_classifications
                    ],
                    "destination": {
                        "endpoint": route.destination.canonical_origin,
                        "model_id": route.destination.model_id,
                        "provider_id": route.destination.provider_id,
                        "purpose": route.destination.purpose,
                        "region": route.destination.region,
                    },
                }
                for route in self.egress_routes
            ],
            "ignore_patterns": list(self.ignore_patterns),
            "limits": {
                "max_decoded_characters": self.max_decoded_characters,
                "max_findings": self.max_findings,
                "max_input_bytes": self.max_input_bytes,
                "max_json_depth": self.max_json_depth,
            },
            "pii_action": self.pii_action.value,
            "policy_id": self.policy_id,
            "private_block_pairs": [list(pair) for pair in self.private_block_pairs],
            "repository_id": self.repository_id,
            "secret_action": self.secret_action.value,
            "version": self.version,
        }
        return json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @property
    def sha256(self) -> str:
        """Return the deterministic complete rule fingerprint."""
        return hashlib.sha256(self.canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True, order=True)
class SensitiveFinding:
    """Content-free scanner evidence used for classification and redaction."""

    kind: SensitiveKind
    field_path: str
    start: int
    end: int
    detector_id: str

    def __post_init__(self) -> None:
        """Reject unbounded locations or arbitrary detector descriptions."""
        if self.start < 0 or self.end <= self.start:
            _invalid("finding_range", "invalid")
        if (
            not self.field_path
            or len(self.field_path) > _MAX_FIELD_PATH
            or _has_control(self.field_path)
        ):
            _invalid("field_path", "invalid")
        _require_token(self.detector_id, "detector_id")


@dataclass(frozen=True, slots=True, order=True)
class StageEvidence:
    """One deterministic content-free stage result."""

    stage: PolicyStage
    rule_ids: tuple[str, ...]
    outcome_code: str

    def __post_init__(self) -> None:
        """Require sorted closed identifiers suitable for audit and replay."""
        _require_canonical_rules(self.rule_ids, "rule_ids")
        _require_token(self.outcome_code, "outcome_code")


@dataclass(frozen=True, slots=True)
class CapturePolicyResult:
    """Sanitized bytes or an exclusion plus exact replay/audit evidence."""

    disposition: CaptureDisposition
    payload: bytes | None
    classification: Classification
    egress: EgressDisposition
    reason_code: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    input_sha256: str
    output_sha256: str | None
    findings: tuple[SensitiveFinding, ...]
    redaction_count: int
    stages: tuple[StageEvidence, ...]

    def __post_init__(self) -> None:
        """Reject any result whose content and audit evidence disagree."""
        _require_uuid7(self.policy_id, "policy_id")
        if self.policy_version < 1:
            _invalid("policy_version", "out_of_range")
        for value, field in (
            (self.policy_sha256, "policy_sha256"),
            (self.input_sha256, "input_sha256"),
        ):
            _require_digest(value, field)
        _require_token(self.reason_code, "reason_code")
        expected_stages = tuple(PolicyStage)
        if self.disposition is CaptureDisposition.EXCLUDED:
            if (
                self.payload is not None
                or self.output_sha256 is not None
                or self.classification is not Classification.LOCAL_ONLY
                or self.egress is not EgressDisposition.DENY
                or self.redaction_count != 0
            ):
                _invalid("payload", "excluded_shape")
        elif (
            self.payload is None
            or self.output_sha256 is None
            or hashlib.sha256(self.payload).hexdigest() != self.output_sha256
        ):
            _invalid("payload", "digest_mismatch")
        if self.disposition is CaptureDisposition.LOCAL_ONLY and (
            self.classification is not Classification.LOCAL_ONLY
            or self.egress is not EgressDisposition.DENY
        ):
            _invalid("local_only", "unsafe_shape")
        _require_result_egress_safety(self)
        if self.redaction_count < 0 or self.redaction_count > len(self.findings):
            _invalid("redaction_count", "invalid")
        if tuple(item.stage for item in self.stages) != expected_stages:
            _invalid("stages", "invalid_order")
        canonical_findings = tuple(sorted(set(self.findings)))
        if canonical_findings != self.findings:
            _invalid("findings", "not_canonical")

    @property
    def stage_sha256(self) -> str:
        """Fingerprint ordered decisions without serializing sensitive content."""
        payload = json.dumps(
            [
                {
                    "outcome_code": item.outcome_code,
                    "rule_ids": list(item.rule_ids),
                    "stage": item.stage.value,
                }
                for item in self.stages
            ],
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return hashlib.sha256(payload).hexdigest()

    @property
    def finding_counts(self) -> Mapping[SensitiveKind, int]:
        """Return immutable content-free counts by closed finding type."""
        counts = dict.fromkeys(SensitiveKind, 0)
        for finding in self.findings:
            counts[finding.kind] += 1
        return MappingProxyType(counts)


def _route_sort_key(route: AllowedEgressRoute) -> tuple[str, str, str, str, str]:
    destination = route.destination
    return (
        destination.provider_id,
        destination.canonical_origin,
        destination.region,
        destination.model_id,
        destination.purpose,
    )


def _require_result_egress_safety(result: CapturePolicyResult) -> None:
    if result.egress is EgressDisposition.ALLOW and (
        result.findings
        or result.classification in {Classification.RESTRICTED, Classification.LOCAL_ONLY}
    ):
        _invalid("egress", "unsafe_shape")


def _require_canonical_rules(values: tuple[str, ...], field: str) -> None:
    if not values or len(values) > _MAX_RULES or tuple(sorted(set(values))) != values:
        raise IngestionValidationError.single(field, "not_canonical")
    _require_bounded_rules(values, field)


def _require_bounded_rules(values: tuple[str, ...], field: str) -> None:
    if any(not value or len(value) > _MAX_RULE_LENGTH or _has_control(value) for value in values):
        raise IngestionValidationError.single(field, "not_canonical")


def _require_token(value: str, field: str) -> None:
    if _RULE_TOKEN.fullmatch(value) is None:
        raise IngestionValidationError.single(field, "invalid")


def _require_digest(value: str, field: str) -> None:
    if _DIGEST.fullmatch(value) is None:
        raise IngestionValidationError.single(field, "invalid_digest")


def _require_uuid7(value: str, field: str) -> None:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise IngestionValidationError.single(field, "invalid_uuid7") from error
    if str(parsed) != value or parsed.version != _UUID_VERSION:
        raise IngestionValidationError.single(field, "invalid_uuid7")


def _has_control(value: str) -> bool:
    return any(
        ord(character) < _C0_CONTROL_LIMIT or ord(character) == _DELETE_CONTROL
        for character in value
    )


def _is_public_dns_name(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        lowered = hostname.casefold().rstrip(".")
        return not lowered.endswith((".local", ".localhost", ".internal"))
    return False


def _invalid(field: str, code: str) -> Never:
    raise IngestionValidationError.single(field, code)
