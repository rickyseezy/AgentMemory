"""Pure identity resolution policy."""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from agentmemory.identity.domain.errors import IdentityValidationError
from agentmemory.identity.domain.value_objects import (
    IdentityCandidate,
    IdentityEvidence,
    IdentitySource,
    ResolutionStatus,
    StableId,
    WorkspaceResolution,
)

_SCP_REMOTE = re.compile(r"^(?:(?P<user>[^@/:]+)@)?(?P<host>[A-Za-z0-9._-]+):(?P<path>[^/].+)$")
_SUPPORTED_REMOTE_SCHEMES = frozenset({"http", "https", "ssh", "git", "git+ssh"})


def normalize_git_remote(remote: str) -> str:
    """Canonicalize a network Git remote while stripping all credentials and URL noise."""
    candidate = remote.strip()
    scp_match = _SCP_REMOTE.fullmatch(candidate)
    if scp_match is not None:
        host = scp_match.group("host").lower()
        path = _normalize_remote_path(scp_match.group("path"))
        return f"ssh://{host}/{path}"

    parsed = urlsplit(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in _SUPPORTED_REMOTE_SCHEMES or parsed.hostname is None:
        msg = "Git remote must be an approved network identity"
        raise IdentityValidationError(msg)
    normalized_scheme = "ssh" if scheme == "git+ssh" else scheme
    port = parsed.port
    if (normalized_scheme, port) in {("https", 443), ("http", 80), ("ssh", 22)}:
        port = None
    host = parsed.hostname.lower()
    authority = host if port is None else f"{host}:{port}"
    path = _normalize_remote_path(parsed.path)
    return urlunsplit((normalized_scheme, authority, f"/{path}", "", ""))


def _normalize_remote_path(path: str) -> str:
    normalized = path.strip().strip("/").removesuffix(".git")
    if not normalized or normalized.startswith(".") or "//" in normalized or "\\" in normalized:
        msg = "Git remote path is invalid"
        raise IdentityValidationError(msg)
    return normalized


class IdentityResolutionPolicy:
    """Apply fail-separate identity precedence without storage or framework coupling."""

    def resolve(self, brain_id: StableId, evidence: IdentityEvidence) -> WorkspaceResolution:
        """Select the first non-empty evidence tier and never merge ambiguity."""
        tiers = (
            (IdentitySource.MANIFEST, evidence.manifest),
            (IdentitySource.CHECKOUT_REGISTRY, evidence.checkout),
            (IdentitySource.REPOSITORY_FINGERPRINT, evidence.repository),
            (IdentitySource.APPROVED_HEURISTIC, evidence.heuristic),
        )
        for source, candidates in tiers:
            if candidates:
                return self._from_candidates(brain_id, source, candidates)
        return WorkspaceResolution.not_found(brain_id)

    @staticmethod
    def _from_candidates(
        brain_id: StableId,
        source: IdentitySource,
        candidates: tuple[IdentityCandidate, ...],
    ) -> WorkspaceResolution:
        unique = tuple(dict.fromkeys(candidates))
        if len(unique) == 1:
            return WorkspaceResolution(
                brain_id,
                ResolutionStatus.RESOLVED,
                source,
                unique[0],
                unique,
                (f"selected:{source.value}",),
            )
        return WorkspaceResolution(
            brain_id,
            ResolutionStatus.AMBIGUOUS,
            source,
            None,
            unique,
            (f"ambiguous:{source.value}",),
        )
