"""IDX-007 revision-safe source navigation and explicit local-open use cases."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
)
from agentmemory.indexing.domain.source_navigation import (
    CheckoutCandidate,
    CheckoutResolution,
    CurrentWorktreeMapping,
    LocalSourceTarget,
    SourceLink,
    WorktreeMappingKind,
    span_for_offsets,
)

if TYPE_CHECKING:
    from agentmemory.indexing.domain.source_navigation import SourceEvidence
    from agentmemory.indexing.domain.source_navigation_ports import (
        LocalPathResolverPort,
        SourceContentPort,
        SourceEvidenceRepository,
    )

_ERR_ACTION = "source navigation action is not authorized"
_ERR_EVIDENCE = "source navigation evidence is unavailable"
_ERR_CONFLICT = "source navigation evidence failed integrity verification"
_ERR_OPEN = "local source target is invalid"
_MAX_CANDIDATES = 16


@dataclass(frozen=True, slots=True)
class ResolveSourceEvidenceQuery:
    """Resolve one persisted semantic evidence identity against local source bytes."""

    scope: AuthorizedScope
    evidence_id: str


@dataclass(frozen=True, slots=True)
class ResolveLocalSourceTargetQuery:
    """Explicitly resolve a previously returned current mapping for a host open action."""

    scope: AuthorizedScope
    evidence_id: str
    immutable_revision_uri: str
    expected_relative_path: str
    expected_content_digest: str


@dataclass(frozen=True, slots=True)
class ResolveSourceEvidenceHandler:
    """Verify immutable evidence and compute only uniquely provable checkout mappings."""

    repository: SourceEvidenceRepository
    content: SourceContentPort

    async def execute(self, query: ResolveSourceEvidenceQuery) -> SourceLink:
        """Resolve without ever retargeting a historical span to unrelated current lines."""
        _require_action(query.scope, "indexing.source.navigate")
        evidence = await self.repository.get(query.scope, query.evidence_id)
        if evidence is None:
            raise IndexingUnavailableError(_ERR_EVIDENCE)
        historical = await self.content.historical(evidence)
        historical_available = historical is not None
        if historical is not None:
            _verify_revision(evidence, historical)
        candidates = await self.content.checkout_candidates(evidence)
        if len(candidates) > _MAX_CANDIDATES:
            raise IndexingUnavailableError(_ERR_EVIDENCE)
        checkout_commit, checkout_dirty = _checkout_metadata(candidates)
        exact = tuple(item for item in candidates if item.content_digest == evidence.content_digest)
        if historical is None:
            if len(exact) != 1:
                raise IndexingUnavailableError(_ERR_EVIDENCE)
            _verify_revision(evidence, exact[0].content)
            historical_source = exact[0].content
        else:
            historical_source = historical
        mapping = _mapping(evidence, historical_source, candidates)
        commit_matches = evidence.commit_id is not None and checkout_commit == evidence.commit_id
        exact_checkout = (
            commit_matches
            and checkout_dirty is False
            and mapping is not None
            and mapping.relative_path == evidence.relative_path
            and mapping.content_digest == evidence.content_digest
            and mapping.span == evidence.span
        )
        if exact_checkout:
            resolution = CheckoutResolution.EXACT
            mismatch = False
        elif mapping is not None:
            resolution = CheckoutResolution.DIFFERENT_MAPPED
            mismatch = True
        elif candidates:
            resolution = CheckoutResolution.DIFFERENT_UNMAPPED
            mismatch = True
        else:
            resolution = CheckoutResolution.UNAVAILABLE
            mismatch = True
        return SourceLink(
            evidence,
            evidence.immutable_revision_uri,
            resolution,
            checkout_commit,
            checkout_dirty,
            mismatch,
            historical_available,
            mapping,
        )


@dataclass(frozen=True, slots=True)
class ResolveLocalSourceTargetHandler:
    """Re-resolve evidence before a host opens a verified current-worktree target."""

    navigation: ResolveSourceEvidenceHandler
    paths: LocalPathResolverPort

    async def execute(self, query: ResolveLocalSourceTargetQuery) -> LocalSourceTarget:
        """Bind the open target to the exact link and digest accepted by the user/host."""
        _require_action(query.scope, "indexing.source.open")
        navigation_scope = AuthorizedScope.create(
            brain_id=query.scope.brain_id,
            principal_id=query.scope.principal_id,
            role=query.scope.role,
            mode=query.scope.mode,
            members=query.scope.members,
            classification_ceiling=query.scope.classification_ceiling,
            temporal_scope=query.scope.temporal_scope,
            grant_version=query.scope.grant_version,
            policy_version=query.scope.policy_version,
            security_epoch=query.scope.security_epoch,
            action="indexing.source.navigate",
            purpose="source_navigation",
        )
        link = await self.navigation.execute(
            ResolveSourceEvidenceQuery(navigation_scope, query.evidence_id)
        )
        mapping = link.current_mapping
        if (
            mapping is None
            or link.immutable_revision_uri != query.immutable_revision_uri
            or mapping.relative_path != query.expected_relative_path
            or mapping.content_digest != query.expected_content_digest
        ):
            raise IndexingConflictError(_ERR_OPEN)
        absolute = await self.paths.resolve(
            link.evidence.repository_id,
            mapping.relative_path,
            mapping.content_digest,
        )
        if absolute is None:
            raise IndexingUnavailableError(_ERR_OPEN)
        return LocalSourceTarget(
            absolute,
            mapping.relative_path,
            mapping.span,
            mapping.content_digest,
        )


def _verify_revision(evidence: SourceEvidence, content: bytes) -> None:
    if (
        len(content) != evidence.byte_length
        or hashlib.sha256(content).hexdigest() != evidence.content_digest
    ):
        raise IndexingConflictError(_ERR_CONFLICT)
    evidence.span.validate_source(content)


def _checkout_metadata(
    candidates: tuple[CheckoutCandidate, ...],
) -> tuple[str | None, bool | None]:
    commits = {item.commit_id for item in candidates}
    dirty_states = {item.checkout_dirty for item in candidates}
    if len(commits) > 1 or len(dirty_states) > 1:
        raise IndexingConflictError(_ERR_CONFLICT)
    return next(iter(commits), None), next(iter(dirty_states), None)


def _mapping(
    evidence: SourceEvidence,
    historical: bytes,
    candidates: tuple[CheckoutCandidate, ...],
) -> CurrentWorktreeMapping | None:
    fragment = historical[evidence.span.start_byte : evidence.span.end_byte]
    mappings: list[CurrentWorktreeMapping] = []
    seen_paths: set[str] = set()
    for candidate in candidates:
        if candidate.relative_path in seen_paths:
            raise IndexingConflictError(_ERR_CONFLICT)
        seen_paths.add(candidate.relative_path)
        if candidate.content_digest == evidence.content_digest:
            start, end = evidence.span.start_byte, evidence.span.end_byte
        else:
            offsets = _unique_fragment(candidate.content, fragment)
            if offsets is None:
                continue
            start, end = offsets
        span = span_for_offsets(candidate.content, start, end)
        renamed = candidate.relative_path != evidence.relative_path
        shifted = span != evidence.span
        if renamed and shifted:
            kind = WorktreeMappingKind.RENAMED_AND_SHIFTED
        elif renamed:
            kind = WorktreeMappingKind.RENAMED
        elif shifted:
            kind = WorktreeMappingKind.SHIFTED
        else:
            kind = WorktreeMappingKind.EXACT
        mappings.append(
            CurrentWorktreeMapping(
                candidate.relative_path,
                span,
                candidate.content_digest,
                kind,
            )
        )
    if len(mappings) != 1:
        return None
    return mappings[0]


def _unique_fragment(content: bytes, fragment: bytes) -> tuple[int, int] | None:
    first = content.find(fragment)
    if first < 0 or content.find(fragment, first + 1) >= 0:
        return None
    return first, first + len(fragment)


def _require_action(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action:
        raise IndexingAuthorizationError(_ERR_ACTION)
