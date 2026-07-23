"""PRO-005 deterministic, immutable provider routing policy."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Never
from uuid import UUID

from agentmemory.identity.domain.retrieval_scope import Classification
from agentmemory.providers.domain.errors import (
    ProviderRoutingCapabilityError,
    ProviderRoutingDeniedError,
    ProviderRoutingValidationError,
)
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderExecutionClass,
    ProviderOperation,
    ProviderProfileStatus,
)

if TYPE_CHECKING:
    from agentmemory.providers.domain.profiles import ProviderProfile

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_LANGUAGE = re.compile(r"^[a-z][a-z0-9+#.-]{0,31}$")
_REGION = re.compile(r"^[A-Z]{2}(?:-[A-Z0-9]{1,8})*$|^global$|^local$")
_REASON = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_UUID_VERSION = 7
_MAX_RULES = 10_000
_CLASSIFICATION_RANK = {
    Classification.PUBLIC: 0,
    Classification.INTERNAL: 1,
    Classification.CONFIDENTIAL: 2,
    Classification.RESTRICTED: 3,
    Classification.LOCAL_ONLY: 4,
}
_ERR_INPUT = "provider routing input is invalid"
_ERR_AMBIGUOUS = "provider routing policy contains an ambiguous overlap"
_ERR_NOT_FOUND = "no provider route matches the request"
_ERR_POLICY = "provider route is denied by privacy policy"
_ERR_CAPABILITY = "provider route profile capability is incompatible"


class ProviderCorpus(StrEnum):
    """Closed content families used by routing selectors."""

    CODE = "code"
    MEMORY = "memory"
    DOCUMENT = "document"


class ProviderWorkload(StrEnum):
    """Closed scheduling classes independently routable by administrators."""

    INTERACTIVE = "interactive"
    CAPTURE = "capture"
    BACKFILL = "backfill"
    EVALUATION = "evaluation"
    MAINTENANCE = "maintenance"


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderRoutingGuard:
    """Brain-owned egress, residency, and classification ceiling."""

    allow_remote: bool
    allowed_remote_residencies: tuple[str, ...]
    remote_classification_ceiling: Classification

    def __post_init__(self) -> None:
        """Canonicalize by rejection and forbid nonsensical remote grants."""
        if (
            tuple(sorted(set(self.allowed_remote_residencies))) != self.allowed_remote_residencies
            or any(
                region == "local" or _REGION.fullmatch(region) is None
                for region in self.allowed_remote_residencies
            )
            or (not self.allow_remote and self.allowed_remote_residencies)
            or self.remote_classification_ceiling is Classification.LOCAL_ONLY
        ):
            _invalid()

    @property
    def document(self) -> dict[str, object]:
        """Return canonical policy-lattice fields."""
        return {
            "allow_remote": self.allow_remote,
            "allowed_remote_residencies": list(self.allowed_remote_residencies),
            "remote_classification_ceiling": self.remote_classification_ceiling.value,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class RepositoryRoutingRestriction:
    """Repository-owned filters that may only narrow the Brain policy."""

    restriction_id: str
    brain_id: str
    repository_id: str
    version: int
    allow_remote: bool
    allowed_remote_residencies: tuple[str, ...]
    remote_classification_ceiling: Classification
    allowed_profile_ids: tuple[str, ...] = ()
    allowed_purposes: tuple[CanonicalPurpose, ...] = ()
    allowed_workloads: tuple[ProviderWorkload, ...] = ()

    def __post_init__(self) -> None:
        """Require canonical immutable restriction coordinates."""
        _uuid7(self.restriction_id)
        _uuid7(self.brain_id)
        _uuid7(self.repository_id)
        if (
            not 1 <= self.version <= 2**31 - 1
            or tuple(sorted(set(self.allowed_remote_residencies)))
            != self.allowed_remote_residencies
            or any(
                region == "local" or _REGION.fullmatch(region) is None
                for region in self.allowed_remote_residencies
            )
            or tuple(sorted(set(self.allowed_profile_ids))) != self.allowed_profile_ids
            or tuple(sorted(set(self.allowed_purposes), key=str)) != self.allowed_purposes
            or tuple(sorted(set(self.allowed_workloads), key=str)) != self.allowed_workloads
            or (not self.allow_remote and self.allowed_remote_residencies)
        ):
            _invalid()
        for profile_id in self.allowed_profile_ids:
            _uuid7(profile_id)

    def validate_narrows(self, guard: ProviderRoutingGuard) -> None:
        """Reject every attempted egress, region, or classification broadening."""
        if (
            (self.allow_remote and not guard.allow_remote)
            or not set(self.allowed_remote_residencies).issubset(guard.allowed_remote_residencies)
            or _classification_rank(self.remote_classification_ceiling)
            > _classification_rank(guard.remote_classification_ceiling)
        ):
            _invalid()

    @property
    def document(self) -> dict[str, object]:
        """Return canonical immutable restriction content."""
        return {
            "allow_remote": self.allow_remote,
            "allowed_profile_ids": list(self.allowed_profile_ids),
            "allowed_purposes": [item.value for item in self.allowed_purposes],
            "allowed_remote_residencies": list(self.allowed_remote_residencies),
            "allowed_workloads": [item.value for item in self.allowed_workloads],
            "brain_id": self.brain_id,
            "remote_classification_ceiling": self.remote_classification_ceiling.value,
            "repository_id": self.repository_id,
            "restriction_id": self.restriction_id,
            "version": self.version,
        }

    @property
    def digest(self) -> str:
        """Return the restriction cache and persistence identity."""
        return _digest(self.document)


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderRouteSelector:
    """Optional match dimensions; ``None`` means an explicit wildcard."""

    project_id: str | None = None
    corpus: ProviderCorpus | None = None
    language: str | None = None
    classification: Classification | None = None
    purpose: CanonicalPurpose | None = None
    workload: ProviderWorkload | None = None

    def __post_init__(self) -> None:
        """Require canonical values wherever the selector is constrained."""
        if self.project_id is not None:
            _uuid7(self.project_id)
        if self.language is not None and _LANGUAGE.fullmatch(self.language) is None:
            _invalid()

    @property
    def precedence(self) -> tuple[int, int]:
        """Rank project scope first, then all remaining dimensions equally."""
        constrained = sum(
            value is not None
            for value in (
                self.corpus,
                self.language,
                self.classification,
                self.purpose,
                self.workload,
            )
        )
        return (int(self.project_id is not None), constrained)

    def matches(self, request: ProviderRouteRequest) -> bool:
        """Return exact match across every constrained dimension."""
        return all(
            expected is None or expected == actual
            for expected, actual in (
                (self.project_id, request.project_id),
                (self.corpus, request.corpus),
                (self.language, request.language),
                (self.classification, request.classification),
                (self.purpose, request.purpose),
                (self.workload, request.workload),
            )
        )

    def overlaps(self, other: ProviderRouteSelector) -> bool:
        """Return whether some valid request can match both selectors."""
        return all(
            left is None or right is None or left == right
            for left, right in (
                (self.project_id, other.project_id),
                (self.corpus, other.corpus),
                (self.language, other.language),
                (self.classification, other.classification),
                (self.purpose, other.purpose),
                (self.workload, other.workload),
            )
        )

    @property
    def document(self) -> dict[str, str | None]:
        """Return the selector in fixed canonical field order."""
        return {
            "classification": (None if self.classification is None else self.classification.value),
            "corpus": None if self.corpus is None else self.corpus.value,
            "language": self.language,
            "project_id": self.project_id,
            "purpose": None if self.purpose is None else self.purpose.value,
            "workload": None if self.workload is None else self.workload.value,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderRouteRule:
    """One immutable route bound to an exact active profile snapshot."""

    rule_id: str
    profile_id: str
    profile_version: int
    profile_snapshot_digest: str
    operation: ProviderOperation
    selector: ProviderRouteSelector
    enabled: bool
    reason: str

    def __post_init__(self) -> None:
        """Require exact profile identity and a stable explanation code."""
        _uuid7(self.rule_id)
        _uuid7(self.profile_id)
        if (
            not 1 <= self.profile_version <= 2**31 - 1
            or _DIGEST.fullmatch(self.profile_snapshot_digest) is None
            or _REASON.fullmatch(self.reason) is None
        ):
            _invalid()

    @property
    def document(self) -> dict[str, object]:
        """Return canonical immutable rule content."""
        return {
            "enabled": self.enabled,
            "operation": self.operation.value,
            "profile_id": self.profile_id,
            "profile_snapshot_digest": self.profile_snapshot_digest,
            "profile_version": self.profile_version,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "selector": self.selector.document,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderRouteDraft:
    """Administrator input before exact profile and rule identities are bound."""

    draft_key: str
    profile_id: str
    operation: ProviderOperation
    selector: ProviderRouteSelector
    enabled: bool
    reason: str

    def __post_init__(self) -> None:
        """Require a stable command-local identity and profile reference."""
        _uuid7(self.profile_id)
        if _REASON.fullmatch(self.draft_key) is None or _REASON.fullmatch(self.reason) is None:
            _invalid()

    @property
    def document(self) -> dict[str, object]:
        """Return the request digest fields before publication."""
        return {
            "draft_key": self.draft_key,
            "enabled": self.enabled,
            "operation": self.operation.value,
            "profile_id": self.profile_id,
            "reason": self.reason,
            "selector": self.selector.document,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderRouteRequest:
    """Complete content-free coordinates used to select one provider."""

    brain_id: str
    project_id: str | None
    repository_id: str | None
    operation: ProviderOperation
    corpus: ProviderCorpus
    language: str | None
    classification: Classification
    purpose: CanonicalPurpose
    workload: ProviderWorkload

    def __post_init__(self) -> None:
        """Reject non-canonical scope and language coordinates."""
        _uuid7(self.brain_id)
        if self.project_id is not None:
            _uuid7(self.project_id)
        if self.repository_id is not None:
            _uuid7(self.repository_id)
        if self.language is not None and _LANGUAGE.fullmatch(self.language) is None:
            _invalid()

    @property
    def document(self) -> dict[str, str | None]:
        """Return a payload-free request description."""
        return {
            "brain_id": self.brain_id,
            "classification": self.classification.value,
            "corpus": self.corpus.value,
            "language": self.language,
            "operation": self.operation.value,
            "project_id": self.project_id,
            "purpose": self.purpose.value,
            "repository_id": self.repository_id,
            "workload": self.workload.value,
        }

    @property
    def digest(self) -> str:
        """Return the request identity without content or credentials."""
        return _digest(self.document)


@dataclass(frozen=True, slots=True, kw_only=True)
class RoutableProviderProfile:
    """Minimal current profile projection needed for a fail-closed decision."""

    profile_id: str
    version: int
    snapshot_digest: str
    status: ProviderProfileStatus
    operation: ProviderOperation
    purposes: tuple[CanonicalPurpose, ...]
    execution_class: ProviderExecutionClass
    residency: str

    def __post_init__(self) -> None:
        """Require a canonical capability snapshot."""
        _uuid7(self.profile_id)
        if (
            not 1 <= self.version <= 2**31 - 1
            or _DIGEST.fullmatch(self.snapshot_digest) is None
            or tuple(sorted(set(self.purposes), key=str)) != self.purposes
            or _REGION.fullmatch(self.residency) is None
            or (self.execution_class is ProviderExecutionClass.LOCAL and self.residency != "local")
            or (self.execution_class is ProviderExecutionClass.REMOTE and self.residency == "local")
        ):
            _invalid()

    @classmethod
    def from_profile(cls, profile: ProviderProfile) -> RoutableProviderProfile:
        """Project one persisted provider snapshot without credentials."""
        configuration = profile.configuration
        residency = (
            "local"
            if configuration.execution_class is ProviderExecutionClass.LOCAL
            else configuration.data_policy.residency
            if configuration.data_policy is not None
            else ""
        )
        return cls(
            profile_id=profile.profile_id,
            version=profile.version,
            snapshot_digest=profile.snapshot_digest,
            status=profile.status,
            operation=configuration.operation,
            purposes=configuration.purposes,
            execution_class=configuration.execution_class,
            residency=residency,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class RouteDecision:
    """Reviewable routing result bound to all policy and profile versions."""

    policy_id: str
    policy_version: int
    rule_id: str
    profile_id: str
    profile_version: int
    profile_snapshot_digest: str
    precedence: tuple[int, int]
    reason: str
    request_digest: str

    def __post_init__(self) -> None:
        """Require stable, content-free decision evidence."""
        _uuid7(self.policy_id)
        _uuid7(self.rule_id)
        _uuid7(self.profile_id)
        if (
            not 1 <= self.policy_version <= 2**31 - 1
            or not 1 <= self.profile_version <= 2**31 - 1
            or _DIGEST.fullmatch(self.profile_snapshot_digest) is None
            or _DIGEST.fullmatch(self.request_digest) is None
            or _REASON.fullmatch(self.reason) is None
        ):
            _invalid()

    @property
    def document(self) -> dict[str, object]:
        """Return content-free persistence and audit fields."""
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "precedence": list(self.precedence),
            "profile_id": self.profile_id,
            "profile_snapshot_digest": self.profile_snapshot_digest,
            "profile_version": self.profile_version,
            "reason": self.reason,
            "request_digest": self.request_digest,
            "rule_id": self.rule_id,
        }

    @property
    def digest(self) -> str:
        """Return the immutable decision identity."""
        return _digest(self.document)


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderRoutingPolicy:
    """Immutable ordered route set governed by one Brain policy lattice."""

    policy_id: str
    brain_id: str
    version: int
    guard: ProviderRoutingGuard
    rules: tuple[ProviderRouteRule, ...]
    created_at: datetime

    def __post_init__(self) -> None:
        """Reject unordered, duplicate, empty, or ambiguous enabled policies."""
        _uuid7(self.policy_id)
        _uuid7(self.brain_id)
        if (
            not 1 <= self.version <= 2**31 - 1
            or not self.rules
            or len(self.rules) > _MAX_RULES
            or self.created_at.tzinfo is None
            or self.created_at.utcoffset() != UTC.utcoffset(self.created_at)
            or tuple(sorted(self.rules, key=lambda item: item.rule_id)) != self.rules
            or len({rule.rule_id for rule in self.rules}) != len(self.rules)
        ):
            _invalid()
        self.validate_unambiguous()

    def validate_unambiguous(self) -> None:
        """Reject equal-precedence enabled rules that can match one request."""
        enabled = tuple(rule for rule in self.rules if rule.enabled)
        for index, left in enumerate(enabled):
            for right in enabled[index + 1 :]:
                if (
                    left.operation is right.operation
                    and left.selector.precedence == right.selector.precedence
                    and left.selector.overlaps(right.selector)
                ):
                    raise ProviderRoutingValidationError(_ERR_AMBIGUOUS)

    def decide(
        self,
        request: ProviderRouteRequest,
        profiles: tuple[RoutableProviderProfile, ...],
        restriction: RepositoryRoutingRestriction | None = None,
    ) -> RouteDecision:
        """Select once, then fail closed instead of falling through on denial."""
        if request.brain_id != self.brain_id:
            _invalid()
        if restriction is not None:
            if (
                request.repository_id is None
                or restriction.brain_id != self.brain_id
                or restriction.repository_id != request.repository_id
            ):
                _invalid()
            restriction.validate_narrows(self.guard)
        matches = [
            rule
            for rule in self.rules
            if rule.enabled
            and rule.operation is request.operation
            and rule.selector.matches(request)
        ]
        if not matches:
            raise ProviderRoutingCapabilityError(_ERR_NOT_FOUND)
        rule = max(matches, key=lambda item: item.selector.precedence)
        profile = next(
            (item for item in profiles if item.profile_id == rule.profile_id),
            None,
        )
        if (
            profile is None
            or profile.status is not ProviderProfileStatus.ACTIVE
            or profile.version != rule.profile_version
            or profile.snapshot_digest != rule.profile_snapshot_digest
            or profile.operation is not request.operation
            or request.purpose not in profile.purposes
        ):
            raise ProviderRoutingCapabilityError(_ERR_CAPABILITY)
        self._enforce_policy(request, profile, restriction)
        return RouteDecision(
            policy_id=self.policy_id,
            policy_version=self.version,
            rule_id=rule.rule_id,
            profile_id=profile.profile_id,
            profile_version=profile.version,
            profile_snapshot_digest=profile.snapshot_digest,
            precedence=rule.selector.precedence,
            reason=rule.reason,
            request_digest=request.digest,
        )

    def _enforce_policy(
        self,
        request: ProviderRouteRequest,
        profile: RoutableProviderProfile,
        restriction: RepositoryRoutingRestriction | None,
    ) -> None:
        if restriction is not None and (
            (
                restriction.allowed_profile_ids
                and profile.profile_id not in restriction.allowed_profile_ids
            )
            or (
                restriction.allowed_purposes and request.purpose not in restriction.allowed_purposes
            )
            or (
                restriction.allowed_workloads
                and request.workload not in restriction.allowed_workloads
            )
        ):
            raise ProviderRoutingDeniedError(_ERR_POLICY)
        if profile.execution_class is ProviderExecutionClass.LOCAL:
            return
        guard = self.guard
        if (
            request.classification is Classification.LOCAL_ONLY
            or not guard.allow_remote
            or profile.residency not in guard.allowed_remote_residencies
            or _classification_rank(request.classification)
            > _classification_rank(guard.remote_classification_ceiling)
        ):
            raise ProviderRoutingDeniedError(_ERR_POLICY)
        if restriction is not None and (
            not restriction.allow_remote
            or profile.residency not in restriction.allowed_remote_residencies
            or _classification_rank(request.classification)
            > _classification_rank(restriction.remote_classification_ceiling)
        ):
            raise ProviderRoutingDeniedError(_ERR_POLICY)

    @property
    def document(self) -> dict[str, object]:
        """Return the complete immutable policy document."""
        return {
            "brain_id": self.brain_id,
            "created_at": round(self.created_at.timestamp() * 1_000_000),
            "guard": self.guard.document,
            "policy_id": self.policy_id,
            "rules": [rule.document for rule in self.rules],
            "version": self.version,
        }

    @property
    def digest(self) -> str:
        """Return the policy persistence and cache identity."""
        return _digest(self.document)


def routing_cache_key(  # noqa: PLR0913 -- Cache identity includes every security epoch.
    *,
    request: ProviderRouteRequest,
    policy: ProviderRoutingPolicy,
    grant_version: int,
    authorization_policy_version: int,
    security_epoch: int,
    profiles: tuple[RoutableProviderProfile, ...],
    restriction: RepositoryRoutingRestriction | None,
) -> str:
    """Bind cache reuse to every mutable authorization/capability coordinate."""
    if min(grant_version, authorization_policy_version, security_epoch) < 1:
        _invalid()
    profile_versions = [
        [item.profile_id, item.version, item.snapshot_digest]
        for item in sorted(profiles, key=lambda item: item.profile_id)
    ]
    content = {
        "authorization_policy_version": authorization_policy_version,
        "grant_version": grant_version,
        "policy_digest": policy.digest,
        "policy_version": policy.version,
        "profile_versions": profile_versions,
        "request_digest": request.digest,
        "restriction_digest": None if restriction is None else restriction.digest,
        "restriction_version": None if restriction is None else restriction.version,
        "security_epoch": security_epoch,
    }
    return f"provider-route:v1:{_digest(content)}"


def _classification_rank(value: Classification) -> int:
    return _CLASSIFICATION_RANK[value]


def _digest(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError) as error:
        raise ProviderRoutingValidationError(_ERR_INPUT) from error
    return hashlib.sha256(encoded).hexdigest()


def _uuid7(value: str) -> None:
    try:
        parsed = UUID(value)
    except (TypeError, ValueError) as error:
        raise ProviderRoutingValidationError(_ERR_INPUT) from error
    if parsed.version != _UUID_VERSION:
        _invalid()


def _invalid() -> Never:
    raise ProviderRoutingValidationError(_ERR_INPUT)
