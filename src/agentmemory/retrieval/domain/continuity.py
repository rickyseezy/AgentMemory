"""ADP-006 host-neutral continuity values and procedure applicability."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC
from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID

from agentmemory.retrieval.domain.errors import RetrievalValidationError

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_VERSION = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_MAX_CONTENT = 8_192
_MAX_MODEL = 256
_MAX_BRANCH = 1_024
_MAX_TOKENS = 8_192
_MIN_TOKENS = 64
_MAX_ITEMS = 100
_MAX_BYTES = 1_048_576
_MIN_BYTES = 512
_UUID_VERSION = 7
_C0_LIMIT = 32
_CLASSIFICATION_ORDER = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
    "local_only": 4,
}
_ERR_PROVENANCE_FIELD = "continuity provenance token is invalid"
_ERR_ADAPTER_VERSION = "continuity adapter version is invalid"
_ERR_MODEL = "continuity model ID is invalid"
_ERR_ITEM_ID = "continuity item identity is invalid"
_ERR_CONTENT = "continuity item content is invalid"
_ERR_BRANCH = "continuity branch is invalid"
_ERR_COMMIT = "continuity commit is invalid"
_ERR_CLASSIFICATION = "continuity classification is invalid"
_ERR_CONTEXT_BUDGET = "briefing token budget is invalid"
_ERR_ITEM_BUDGET = "briefing item budget is invalid"
_ERR_BYTE_BUDGET = "briefing byte budget is invalid"
_ERR_PLATFORM = "procedure platform is invalid"
_ERR_CAPABILITIES = "procedure capabilities are invalid"
_ERR_PLATFORMS = "procedure platforms are invalid"
_ERR_REQUIRED_CAPABILITIES = "procedure required capabilities are invalid"
_ERR_PROCEDURE_ID = "procedure identity is invalid"
_ERR_PROCEDURE_CONTENT = "procedure content is invalid"
_ERR_SCOPE_ACTION = "briefing scope action is invalid"
_ERR_UUID = "continuity identity is not UUIDv7"
_ERR_TIME = "continuity time is not UTC"


class AgentHost(StrEnum):
    """Certified consumer host profiles in the ADP-006 conformance matrix."""

    CLAUDE_CODE = "claude_code"
    CODEX = "codex"
    GEMINI_CLI = "gemini_cli"
    CURSOR_COMPATIBLE = "cursor_compatible"
    GENERIC = "generic"


class ContinuityKind(StrEnum):
    """Canonical semantic units required for cross-agent continuity."""

    FACT = "fact"
    DECISION = "decision"
    CHANGE = "change"
    FAILURE = "failure"
    NEXT_STEP = "next_step"


@dataclass(frozen=True, slots=True)
class ItemProvenance:
    """Original producer identity shown independently of the consumer host."""

    producer_host: str
    model_id: str
    adapter_id: str
    adapter_version: str
    capture_method: str

    def __post_init__(self) -> None:
        """Require bounded explicit provenance rather than consumer inference."""
        for value in (self.producer_host, self.adapter_id, self.capture_method):
            if _TOKEN.fullmatch(value) is None:
                raise RetrievalValidationError(_ERR_PROVENANCE_FIELD)
        if _VERSION.fullmatch(self.adapter_version) is None:
            raise RetrievalValidationError(_ERR_ADAPTER_VERSION)
        _require_text(self.model_id, _MAX_MODEL, _ERR_MODEL)


@dataclass(frozen=True, slots=True)
class ContinuityItem:
    """One atomic authorized semantic item backed by a canonical event."""

    item_id: str
    semantic_id: str
    kind: ContinuityKind
    content: str
    brain_id: str
    project_id: str
    repository_id: str
    checkout_id: str | None
    branch_name: str | None
    commit_sha: str | None
    occurred_at: datetime
    ingested_at: datetime
    classification: str
    evidence_event_id: str
    provenance: ItemProvenance

    def __post_init__(self) -> None:
        """Bound content, evidence, identity, time, and classification."""
        if (
            _IDENTIFIER.fullmatch(self.item_id) is None
            or _IDENTIFIER.fullmatch(self.semantic_id) is None
        ):
            raise RetrievalValidationError(_ERR_ITEM_ID)
        _require_text(self.content, _MAX_CONTENT, _ERR_CONTENT)
        for value in (
            self.brain_id,
            self.project_id,
            self.repository_id,
            self.evidence_event_id,
        ):
            _require_uuid7(value)
        if self.checkout_id is not None:
            _require_uuid7(self.checkout_id)
        if self.branch_name is not None:
            _require_text(self.branch_name, _MAX_BRANCH, _ERR_BRANCH)
        if self.commit_sha is not None and _COMMIT.fullmatch(self.commit_sha) is None:
            raise RetrievalValidationError(_ERR_COMMIT)
        _require_utc(self.occurred_at)
        _require_utc(self.ingested_at)
        if self.classification not in _CLASSIFICATION_ORDER:
            raise RetrievalValidationError(_ERR_CLASSIFICATION)

    def context_document(self) -> dict[str, object]:
        """Return the exact typed untrusted-data representation used for budgeting."""
        return {
            "classification": self.classification,
            "content": self.content,
            "evidence_event_id": self.evidence_event_id,
            "item_id": self.item_id,
            "kind": self.kind.value,
            "provenance": {
                "adapter_id": self.provenance.adapter_id,
                "adapter_version": self.provenance.adapter_version,
                "capture_method": self.provenance.capture_method,
                "model_id": self.provenance.model_id,
                "producer_host": self.provenance.producer_host,
            },
            "semantic_id": self.semantic_id,
        }

    def context_bytes(self) -> bytes:
        """Encode one indivisible unit for conservative context accounting."""
        return _canonical_json(self.context_document())


@dataclass(frozen=True, slots=True)
class BriefingBudget:
    """Caller bound clamped by a host adapter before host-neutral selection."""

    max_tokens: int = 1_200
    max_items: int = 12
    max_bytes: int = 20_480

    def __post_init__(self) -> None:
        """Apply the accepted server bounds from ADR-012."""
        if not _MIN_TOKENS <= self.max_tokens <= _MAX_TOKENS:
            raise RetrievalValidationError(_ERR_CONTEXT_BUDGET)
        if not 1 <= self.max_items <= _MAX_ITEMS:
            raise RetrievalValidationError(_ERR_ITEM_BUDGET)
        if not _MIN_BYTES <= self.max_bytes <= _MAX_BYTES:
            raise RetrievalValidationError(_ERR_BYTE_BUDGET)

    def clamp(self, ceiling: BriefingBudget) -> BriefingBudget:
        """Return the component-wise safe intersection with a host profile."""
        return BriefingBudget(
            min(self.max_tokens, ceiling.max_tokens),
            min(self.max_items, ceiling.max_items),
            min(self.max_bytes, ceiling.max_bytes),
        )


@dataclass(frozen=True, slots=True)
class ProcedureEnvironment:
    """Structured consumer semantics used only for procedure applicability."""

    platform: str
    capabilities: tuple[str, ...]

    def __post_init__(self) -> None:
        """Require a canonical capability set without trusting host names."""
        if _TOKEN.fullmatch(self.platform) is None:
            raise RetrievalValidationError(_ERR_PLATFORM)
        _require_canonical_tokens(self.capabilities, _ERR_CAPABILITIES)


@dataclass(frozen=True, slots=True)
class ProcedureApplicability:
    """Explicit environment predicates evaluated after memory authorization."""

    platforms: tuple[str, ...]
    required_capabilities: tuple[str, ...]

    def __post_init__(self) -> None:
        """Require nonempty, sorted, unique structured predicates."""
        _require_canonical_tokens(self.platforms, _ERR_PLATFORMS)
        _require_canonical_tokens(self.required_capabilities, _ERR_REQUIRED_CAPABILITIES)

    def exclusion_reason(self, environment: ProcedureEnvironment) -> str | None:
        """Return one stable incompatibility reason or None when applicable."""
        if environment.platform not in self.platforms:
            return f"platform_mismatch:{environment.platform}"
        missing = sorted(set(self.required_capabilities).difference(environment.capabilities))
        if missing:
            return f"missing_capability:{missing[0]}"
        return None


@dataclass(frozen=True, slots=True)
class ProcedureCandidate:
    """Authorized active procedure awaiting independent applicability filtering."""

    procedure_id: str
    content: str
    applicability: ProcedureApplicability

    def __post_init__(self) -> None:
        """Require an atomic bounded procedure representation."""
        if _IDENTIFIER.fullmatch(self.procedure_id) is None:
            raise RetrievalValidationError(_ERR_PROCEDURE_ID)
        _require_text(self.content, _MAX_CONTENT, _ERR_PROCEDURE_CONTENT)

    def context_bytes(self) -> bytes:
        """Encode the selected procedure atom for the common budget."""
        return _canonical_json(
            {
                "content": self.content,
                "procedure_id": self.procedure_id,
                "type": "procedure",
            }
        )


@dataclass(frozen=True, slots=True)
class ExcludedProcedure:
    """Content-free explanation of a procedure compatibility rejection."""

    procedure_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class StartSessionBriefingQuery:
    """Host-independent query; delivery adapters supply budget/environment values."""

    scope: AuthorizedScope
    budget: BriefingBudget
    procedure_environment: ProcedureEnvironment

    def __post_init__(self) -> None:
        """Require a recall-authorized immutable scope."""
        if self.scope.action != "memory.recall":
            raise RetrievalValidationError(_ERR_SCOPE_ACTION)


@dataclass(frozen=True, slots=True)
class SessionBriefing:
    """Deterministic host-neutral selection plus independent procedures."""

    items: tuple[ContinuityItem, ...]
    procedures: tuple[ProcedureCandidate, ...]
    excluded_procedures: tuple[ExcludedProcedure, ...]
    used_tokens: int
    used_items: int
    used_bytes: int
    truncated: bool
    scope_fingerprint: str
    policy_version: str = "continuity-v1"


def classification_permitted(item: ContinuityItem, ceiling: str) -> bool:
    """Compare classifications using the closed product ordering."""
    return _CLASSIFICATION_ORDER[item.classification] <= _CLASSIFICATION_ORDER[ceiling]


def conservative_tokens(value: bytes) -> int:
    """Count one token per three UTF-8 bytes when no host tokenizer is trusted."""
    return max(1, (len(value) + 2) // 3)


def _canonical_json(document: dict[str, object]) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _require_uuid7(value: str) -> None:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise RetrievalValidationError(_ERR_UUID) from error
    if str(parsed) != value or parsed.version != _UUID_VERSION:
        raise RetrievalValidationError(_ERR_UUID)


def _require_utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        raise RetrievalValidationError(_ERR_TIME)


def _require_text(value: str, maximum: int, message: str) -> None:
    if (
        not value
        or len(value) > maximum
        or any(ord(character) < _C0_LIMIT and character not in "\t\n" for character in value)
        or "\x7f" in value
    ):
        raise RetrievalValidationError(message)


def _require_canonical_tokens(values: tuple[str, ...], message: str) -> None:
    if (
        not values
        or values != tuple(sorted(set(values)))
        or any(_TOKEN.fullmatch(value) is None for value in values)
    ):
        raise RetrievalValidationError(message)
