"""IDX-006 deterministic, content-free repository indexing policy decisions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Never, cast
from uuid import UUID

from agentmemory.indexing.domain.errors import IndexingValidationError

if TYPE_CHECKING:
    from collections.abc import Iterable

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RULE_ID = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_MAX_PATH = 4096
_MAX_RULES = 2048
_MAX_RULE_BYTES = 1024
_MAX_SOURCE_BYTES = 256 * 1024
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_OBSERVED_BYTES = 2**63 - 1
_MAX_PRIVATE_BLOCK_PAIRS = 64
_DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
_UUID_VERSION = 7
_MIN_TEXT_CONTROL = 9
_CARRIAGE_RETURN = 13
_C0_CONTROL_LIMIT = 32
_DELETE_CONTROL = 127
_ERR_INPUT = "content policy input is invalid"
_POLICY_ID = "018f0000-0000-7000-8000-000000000601"
_POLICY_FILES = frozenset({".agentmemoryignore", ".gitignore"})
_VENDORED_PARTS = frozenset({"vendor", "node_modules", ".venv", "third_party"})
_GENERATED_PARTS = frozenset({"dist", "build", "generated", "gen", ".generated"})
_ENCRYPTED_SUFFIXES = (
    ".age",
    ".enc",
    ".gpg",
    ".jks",
    ".p12",
    ".pfx",
    ".pgp",
)
_ENCRYPTED_HEADERS = (
    b"-----BEGIN PGP MESSAGE-----",
    b"Salted__",
    b"age-encryption.org/v1",
)
_ARCHIVE_HEADERS = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"\x1f\x8b",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07",
)
_DEFAULT_PRIVATE_BLOCKS = (
    ("<agentmemory-private>", "</agentmemory-private>"),
    ("agentmemory:private:start", "agentmemory:private:end"),
)


class PolicyLayer(StrEnum):
    """Closed precedence layers from strongest to weakest."""

    BRAIN = "brain"
    AGENTMEMORY_IGNORE = "agentmemoryignore"
    PRIVATE_BLOCK = "private_block"
    GITIGNORE = "gitignore"
    DEFAULT = "default"


class PolicyAction(StrEnum):
    """Action declared by an explicit path rule."""

    INCLUDE = "include"
    EXCLUDE = "exclude"


class PolicyDisposition(StrEnum):
    """Final result exposed to every indexing consumer."""

    INCLUDE = "include"
    EXCLUDE = "exclude"


class PolicyPhase(StrEnum):
    """The phase at which a decision became final."""

    PATH = "path"
    CONTENT = "content"


class ReconciliationAction(StrEnum):
    """Bounded derivative work required after a policy change."""

    DELETE = "delete"
    REINDEX = "reindex"


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """One canonical include/exclude rule in an immutable source revision."""

    layer: PolicyLayer
    rule_id: str
    version: int
    pattern: str
    action: PolicyAction

    def __post_init__(self) -> None:
        """Reject ambiguous paths, identifiers, and policy-source versions."""
        if (
            self.layer in {PolicyLayer.PRIVATE_BLOCK, PolicyLayer.DEFAULT}
            or _RULE_ID.fullmatch(self.rule_id) is None
            or not 1 <= self.version <= 2**31 - 1
            or not _valid_pattern(self.pattern, self.layer)
        ):
            _invalid()

    @property
    def canonical_document(self) -> dict[str, object]:
        """Return the exact content-free rule representation."""
        return {
            "action": self.action.value,
            "layer": self.layer.value,
            "pattern": self.pattern,
            "rule_id": self.rule_id,
            "version": self.version,
        }

    def matches(self, relative_path: str) -> bool:
        """Match one already-normalized repository-relative path."""
        return _glob_matches(relative_path, self.pattern)


@dataclass(frozen=True, slots=True)
class PolicyRuleSource:
    """One ordered, hash-bound rule source; the last matching line wins."""

    layer: PolicyLayer
    version: int
    source_hash: str
    rules: tuple[PolicyRule, ...]

    def __post_init__(self) -> None:
        """Require one bounded canonical source with unique rule identities."""
        if (
            self.layer in {PolicyLayer.PRIVATE_BLOCK, PolicyLayer.DEFAULT}
            or not 1 <= self.version <= 2**31 - 1
            or _DIGEST.fullmatch(self.source_hash) is None
            or len(self.rules) > _MAX_RULES
            or any(
                rule.layer is not self.layer or rule.version != self.version for rule in self.rules
            )
            or len({rule.rule_id for rule in self.rules}) != len(self.rules)
        ):
            _invalid()

    @classmethod
    def empty(cls, layer: PolicyLayer, version: int = 1) -> PolicyRuleSource:
        """Build an explicit empty source revision."""
        return cls(layer, version, hashlib.sha256(b"").hexdigest(), ())

    @classmethod
    def create(
        cls,
        layer: PolicyLayer,
        version: int,
        rules: tuple[PolicyRule, ...],
    ) -> PolicyRuleSource:
        """Build a Brain source hash from its canonical rule sequence."""
        document = [rule.canonical_document for rule in rules]
        payload = _canonical_json(document)
        return cls(layer, version, hashlib.sha256(payload).hexdigest(), rules)

    @classmethod
    def from_ignore_bytes(
        cls,
        layer: PolicyLayer,
        version: int,
        source: bytes,
    ) -> PolicyRuleSource:
        """Parse one bounded Git-compatible ignore source without retaining its bytes."""
        if layer not in {PolicyLayer.AGENTMEMORY_IGNORE, PolicyLayer.GITIGNORE} or (
            not isinstance(cast("object", source), bytes) or len(source) > _MAX_SOURCE_BYTES
        ):
            _invalid()
        try:
            text = source.decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise IndexingValidationError(_ERR_INPUT) from error
        if "\x00" in text:
            _invalid()
        rules: list[PolicyRule] = []
        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            parsed = _parse_ignore_line(raw_line)
            if parsed is None:
                continue
            pattern, action = parsed
            rules.append(
                PolicyRule(
                    layer,
                    f"{layer.value}.{line_number}",
                    version,
                    pattern,
                    action,
                )
            )
        return cls(layer, version, hashlib.sha256(source).hexdigest(), tuple(rules))

    def matching_rule(self, relative_path: str) -> PolicyRule | None:
        """Return the last matching rule exactly as Git ignore files require."""
        match: PolicyRule | None = None
        for rule in self.rules:
            if rule.matches(relative_path):
                match = rule
        return match


@dataclass(frozen=True, slots=True, kw_only=True)
class IndexPolicyRevision:
    """Complete immutable Brain policy for one repository or Brain scope."""

    policy_id: str
    version: int
    brain_id: str
    repository_id: str | None
    brain_rules: PolicyRuleSource
    max_file_bytes: int
    private_block_pairs: tuple[tuple[str, str], ...]
    exclude_binary: bool
    exclude_generated: bool
    exclude_encrypted: bool
    activated_at: datetime

    def __post_init__(self) -> None:
        """Require a replayable, bounded revision and exact scope."""
        try:
            policy_id = UUID(self.policy_id)
            brain_id = UUID(self.brain_id)
            repository_id = None if self.repository_id is None else UUID(self.repository_id)
        except (TypeError, ValueError) as error:
            raise IndexingValidationError(_ERR_INPUT) from error
        if (
            policy_id.version != _UUID_VERSION
            or brain_id.version != _UUID_VERSION
            or (repository_id is not None and repository_id.version != _UUID_VERSION)
            or not 1 <= self.version <= 2**31 - 1
            or self.brain_rules.layer is not PolicyLayer.BRAIN
            or self.brain_rules.version != self.version
            or not 1 <= self.max_file_bytes <= _MAX_FILE_BYTES
            or not self.private_block_pairs
            or len(self.private_block_pairs) > _MAX_PRIVATE_BLOCK_PAIRS
            or len(set(self.private_block_pairs)) != len(self.private_block_pairs)
            or any(not start or not end or start == end for start, end in self.private_block_pairs)
            or self.activated_at.tzinfo is None
            or self.activated_at.utcoffset() != UTC.utcoffset(self.activated_at)
        ):
            _invalid()

    @property
    def canonical_bytes(self) -> bytes:
        """Serialize all policy authority without ambient defaults."""
        return _canonical_json(
            {
                "activated_at": _micros(self.activated_at),
                "brain_id": self.brain_id,
                "brain_rules": [rule.canonical_document for rule in self.brain_rules.rules],
                "brain_source_hash": self.brain_rules.source_hash,
                "exclude_binary": self.exclude_binary,
                "exclude_encrypted": self.exclude_encrypted,
                "exclude_generated": self.exclude_generated,
                "max_file_bytes": self.max_file_bytes,
                "policy_id": self.policy_id,
                "private_block_pairs": [list(pair) for pair in self.private_block_pairs],
                "repository_id": self.repository_id,
                "version": self.version,
            }
        )

    @property
    def digest(self) -> str:
        """Return the complete immutable revision identity."""
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    @classmethod
    def production_default(
        cls,
        brain_id: str,
        repository_id: str | None,
        activated_at: datetime,
    ) -> IndexPolicyRevision:
        """Return the fail-closed default used before an administrator changes policy."""
        return cls(
            policy_id=_POLICY_ID,
            version=1,
            brain_id=brain_id,
            repository_id=repository_id,
            brain_rules=PolicyRuleSource.empty(PolicyLayer.BRAIN),
            max_file_bytes=_DEFAULT_MAX_FILE_BYTES,
            private_block_pairs=_DEFAULT_PRIVATE_BLOCKS,
            exclude_binary=True,
            exclude_generated=True,
            exclude_encrypted=True,
            activated_at=activated_at,
        )


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Content-free evidence for one path or content gate evaluation."""

    repository_id: str
    relative_path: str
    phase: PolicyPhase
    disposition: PolicyDisposition
    reason: str
    layer: PolicyLayer
    rule_id: str
    rule_version: int
    source_hash: str
    policy_digest: str
    byte_length: int
    content_hash: str | None
    binary: bool
    encrypted: bool
    private: bool
    symlink: bool
    decided_at: datetime

    def __post_init__(self) -> None:
        """Reject raw, ambiguous, or unbounded decision evidence."""
        _normalize_path(self.relative_path)
        if (
            _RULE_ID.fullmatch(self.rule_id) is None
            or _RULE_ID.fullmatch(self.reason) is None
            or not 1 <= self.rule_version <= 2**31 - 1
            or _DIGEST.fullmatch(self.source_hash) is None
            or _DIGEST.fullmatch(self.policy_digest) is None
            or (self.content_hash is not None and _DIGEST.fullmatch(self.content_hash) is None)
            or not 0 <= self.byte_length <= _MAX_OBSERVED_BYTES
            or self.decided_at.tzinfo is None
            or self.decided_at.utcoffset() != UTC.utcoffset(self.decided_at)
        ):
            _invalid()

    @property
    def canonical_bytes(self) -> bytes:
        """Serialize decision evidence without source content."""
        return _canonical_json(
            {
                "binary": self.binary,
                "byte_length": self.byte_length,
                "content_hash": self.content_hash,
                "decided_at": _micros(self.decided_at),
                "disposition": self.disposition.value,
                "encrypted": self.encrypted,
                "layer": self.layer.value,
                "phase": self.phase.value,
                "policy_digest": self.policy_digest,
                "private": self.private,
                "reason": self.reason,
                "relative_path": self.relative_path,
                "repository_id": self.repository_id,
                "rule_id": self.rule_id,
                "rule_version": self.rule_version,
                "source_hash": self.source_hash,
                "symlink": self.symlink,
            }
        )

    @property
    def id(self) -> str:
        """Return a stable event identity over complete evidence."""
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    @property
    def included(self) -> bool:
        """Return whether downstream source access is authorized."""
        return self.disposition is PolicyDisposition.INCLUDE

    @property
    def excluded(self) -> bool:
        """Return whether every downstream consumer must be bypassed."""
        return not self.included


@dataclass(frozen=True, slots=True)
class IndexContentPolicy:
    """Sole decision point for pre-open paths and bounded content observations."""

    revision: IndexPolicyRevision
    agentmemoryignore: PolicyRuleSource | None
    gitignore: PolicyRuleSource | None

    def __post_init__(self) -> None:
        """Require repository sources in their exact precedence layers."""
        if (
            self.agentmemoryignore is not None
            and self.agentmemoryignore.layer is not PolicyLayer.AGENTMEMORY_IGNORE
        ) or (self.gitignore is not None and self.gitignore.layer is not PolicyLayer.GITIGNORE):
            _invalid()

    @property
    def digest(self) -> str:
        """Bind Brain authority and both repository-owned rule sources."""
        return hashlib.sha256(
            _canonical_json(
                {
                    "agentmemoryignore": (
                        None
                        if self.agentmemoryignore is None
                        else self.agentmemoryignore.source_hash
                    ),
                    "brain": self.revision.digest,
                    "gitignore": None if self.gitignore is None else self.gitignore.source_hash,
                }
            )
        ).hexdigest()

    @classmethod
    def production_default(
        cls,
        brain_id: str,
        repository_id: str,
        activated_at: datetime,
    ) -> IndexContentPolicy:
        """Build the initial complete policy with explicit empty repository sources."""
        return cls(
            IndexPolicyRevision.production_default(brain_id, repository_id, activated_at),
            PolicyRuleSource.empty(PolicyLayer.AGENTMEMORY_IGNORE),
            PolicyRuleSource.empty(PolicyLayer.GITIGNORE),
        )

    def evaluate_path(
        self,
        relative_path: str,
        *,
        symlink: bool,
        byte_length: int,
        decided_at: datetime,
    ) -> PolicyDecision:
        """Decide normalized path and metadata before a content descriptor is opened."""
        path = _normalize_path(relative_path)
        if (
            isinstance(cast("object", symlink), bool) is False
            or isinstance(cast("object", byte_length), bool)
            or not isinstance(cast("object", byte_length), int)
            or byte_length < 0
        ):
            _invalid()
        if symlink:
            return self._default_decision(
                path, PolicyPhase.PATH, "symlink", byte_length, decided_at, symlink=True
            )
        if byte_length > self.revision.max_file_bytes:
            return self._default_decision(
                path, PolicyPhase.PATH, "oversized", byte_length, decided_at
            )
        explicit = self._explicit_path_decision(path, decided_at, byte_length)
        if explicit is not None and explicit.layer in {
            PolicyLayer.BRAIN,
            PolicyLayer.AGENTMEMORY_IGNORE,
        }:
            return explicit
        if explicit is not None:
            return explicit
        default_reason = self._default_path_reason(path)
        if default_reason is not None:
            return self._default_decision(
                path, PolicyPhase.PATH, default_reason, byte_length, decided_at
            )
        return self._default_decision(
            path,
            PolicyPhase.PATH,
            "included",
            byte_length,
            decided_at,
            disposition=PolicyDisposition.INCLUDE,
        )

    def evaluate_content(
        self,
        relative_path: str,
        content: bytes,
        decided_at: datetime,
    ) -> PolicyDecision:
        """Classify one bounded read and produce no retained source bytes."""
        path = _normalize_path(relative_path)
        if not isinstance(cast("object", content), bytes):
            _invalid()
        metadata = self.evaluate_path(
            path,
            symlink=False,
            byte_length=len(content),
            decided_at=decided_at,
        )
        digest = hashlib.sha256(content).hexdigest()
        if metadata.layer in {PolicyLayer.BRAIN, PolicyLayer.AGENTMEMORY_IGNORE}:
            return _with_content(metadata, digest)
        binary = _binary(content)
        encrypted = _encrypted(path, content)
        private = _private(content, self.revision.private_block_pairs)
        if private:
            return self._decision(
                path,
                PolicyPhase.CONTENT,
                PolicyDisposition.EXCLUDE,
                "private_block",
                PolicyLayer.PRIVATE_BLOCK,
                "private.block",
                self.revision.version,
                self.revision.digest,
                len(content),
                decided_at,
                content_hash=digest,
                binary=binary,
                encrypted=encrypted,
                private=True,
            )
        if metadata.excluded:
            return _with_content(
                metadata,
                digest,
                binary=binary,
                encrypted=encrypted,
            )
        if encrypted and self.revision.exclude_encrypted:
            return self._default_decision(
                path,
                PolicyPhase.CONTENT,
                "encrypted",
                len(content),
                decided_at,
                content_hash=digest,
                binary=binary,
                encrypted=True,
            )
        if binary and self.revision.exclude_binary:
            return self._default_decision(
                path,
                PolicyPhase.CONTENT,
                "binary",
                len(content),
                decided_at,
                content_hash=digest,
                binary=True,
                encrypted=encrypted,
            )
        return self._default_decision(
            path,
            PolicyPhase.CONTENT,
            "included",
            len(content),
            decided_at,
            disposition=PolicyDisposition.INCLUDE,
            content_hash=digest,
            binary=binary,
            encrypted=encrypted,
        )

    def _explicit_path_decision(
        self, path: str, decided_at: datetime, byte_length: int
    ) -> PolicyDecision | None:
        for source in (self.revision.brain_rules, self.agentmemoryignore, self.gitignore):
            if source is None:
                continue
            rule = source.matching_rule(path)
            if rule is not None:
                # Negation cancels excludes in its own ignore source and then falls
                # through to the next safety layer. A Brain include is different:
                # it is the administrator's explicit highest-precedence override.
                if rule.action is PolicyAction.INCLUDE and rule.layer is not PolicyLayer.BRAIN:
                    continue
                return self._decision(
                    path,
                    PolicyPhase.PATH,
                    PolicyDisposition(rule.action.value),
                    "explicit_include" if rule.action is PolicyAction.INCLUDE else "ignored_path",
                    rule.layer,
                    rule.rule_id,
                    rule.version,
                    source.source_hash,
                    byte_length,
                    decided_at,
                )
        return None

    def _default_path_reason(self, path: str) -> str | None:
        parts = tuple(part.lower() for part in PurePosixPath(path).parts)
        if PurePosixPath(path).name in _POLICY_FILES:
            return "policy_metadata"
        if self.revision.exclude_generated:
            if any(part in _VENDORED_PARTS for part in parts[:-1]):
                return "vendored"
            if any(part in _GENERATED_PARTS for part in parts[:-1]) or _generated_name(parts[-1]):
                return "generated"
        return None

    def _default_decision(  # noqa: PLR0913 -- Complete decision evidence is explicit.
        self,
        path: str,
        phase: PolicyPhase,
        reason: str,
        byte_length: int,
        decided_at: datetime,
        *,
        disposition: PolicyDisposition = PolicyDisposition.EXCLUDE,
        content_hash: str | None = None,
        binary: bool = False,
        encrypted: bool = False,
        private: bool = False,
        symlink: bool = False,
    ) -> PolicyDecision:
        return self._decision(
            path,
            phase,
            disposition,
            reason,
            PolicyLayer.DEFAULT,
            f"default.{reason}",
            self.revision.version,
            self.revision.digest,
            byte_length,
            decided_at,
            content_hash=content_hash,
            binary=binary,
            encrypted=encrypted,
            private=private,
            symlink=symlink,
        )

    def _decision(  # noqa: PLR0913 -- Complete immutable decision evidence is explicit.
        self,
        path: str,
        phase: PolicyPhase,
        disposition: PolicyDisposition,
        reason: str,
        layer: PolicyLayer,
        rule_id: str,
        rule_version: int,
        source_hash: str,
        byte_length: int,
        decided_at: datetime,
        *,
        content_hash: str | None = None,
        binary: bool = False,
        encrypted: bool = False,
        private: bool = False,
        symlink: bool = False,
    ) -> PolicyDecision:
        repository_id = self.revision.repository_id
        if repository_id is None:
            _invalid()
        return PolicyDecision(
            repository_id,
            path,
            phase,
            disposition,
            reason,
            layer,
            rule_id,
            rule_version,
            source_hash,
            self.revision.digest,
            byte_length,
            content_hash,
            binary,
            encrypted,
            private,
            symlink,
            decided_at,
        )


def classify_policy_change(
    previous: PolicyDecision,
    current: PolicyDecision,
) -> ReconciliationAction | None:
    """Map one exact old/new decision pair to bounded projection work."""
    if (
        previous.repository_id != current.repository_id
        or previous.relative_path != current.relative_path
    ):
        _invalid()
    if previous.included and current.excluded:
        return ReconciliationAction.DELETE
    if previous.excluded and current.included:
        return ReconciliationAction.REINDEX
    return None


def _with_content(
    decision: PolicyDecision,
    content_hash: str,
    *,
    binary: bool = False,
    encrypted: bool = False,
) -> PolicyDecision:
    return PolicyDecision(
        decision.repository_id,
        decision.relative_path,
        PolicyPhase.CONTENT,
        decision.disposition,
        decision.reason,
        decision.layer,
        decision.rule_id,
        decision.rule_version,
        decision.source_hash,
        decision.policy_digest,
        decision.byte_length,
        content_hash,
        binary,
        encrypted,
        decision.private,
        decision.symlink,
        decision.decided_at,
    )


def _parse_ignore_line(raw_line: str) -> tuple[str, PolicyAction] | None:
    line = raw_line.rstrip("\r")
    if not line or line.startswith("#"):
        return None
    if len(line.encode()) > _MAX_RULE_BYTES:
        _invalid()
    if line.startswith("\\#"):
        line = line[1:]
    action = PolicyAction.EXCLUDE
    if line.startswith("\\!"):
        line = line[1:]
    elif line.startswith("!"):
        action = PolicyAction.INCLUDE
        line = line[1:]
    # Git preserves escaped trailing spaces and removes unescaped ones.
    while line.endswith(" ") and not line.endswith("\\ "):
        line = line[:-1]
    line = line.replace("\\ ", " ")
    if not line:
        _invalid()
    return line, action


def _valid_pattern(pattern: str, layer: PolicyLayer) -> bool:
    structurally_valid = (
        bool(pattern)
        and len(pattern.encode()) <= _MAX_RULE_BYTES
        and "\x00" not in pattern
        and "\\" not in pattern
        and (layer is not PolicyLayer.BRAIN or not pattern.startswith("!"))
        and "//" not in pattern
        and not any(part in {".", ".."} for part in pattern.lstrip("/").split("/"))
    )
    if not structurally_valid:
        return False
    try:
        re.compile(_translate_glob(pattern.rstrip("/").lstrip("/")))
    except re.error:
        return False
    return True


def _glob_matches(path: str, pattern: str) -> bool:
    directory_only = pattern.endswith("/")
    body = pattern[:-1] if directory_only else pattern
    anchored = body.startswith("/")
    body = body.lstrip("/")
    translated = _translate_glob(body)
    prefix = "^" if anchored or "/" in body else r"(?:^|.*/)"
    suffix = r"(?:/.*)?$" if directory_only or "/" not in body else "$"
    return re.fullmatch(prefix + translated + suffix, path) is not None


def _translate_glob(pattern: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                index += 1
                if index + 1 < len(pattern) and pattern[index + 1] == "/":
                    index += 1
                    result.append(r"(?:.*/)?")
                else:
                    result.append(".*")
            else:
                result.append("[^/]*")
        elif char == "?":
            result.append("[^/]")
        elif char == "[":
            end = pattern.find("]", index + 1)
            if end < 0:
                result.append(r"\[")
            else:
                content = pattern[index + 1 : end]
                negate = content.startswith("!")
                if negate:
                    content = "^" + content[1:]
                result.append("[" + content.replace("\\", r"\\") + "]")
                index = end
        else:
            result.append(re.escape(char))
        index += 1
    return "".join(result)


def _normalize_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or len(value.encode()) > _MAX_PATH
        or "\\" in value
        or "\x00" in value
        or value.startswith("/")
        or "//" in value
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        _invalid()
    return value


def _binary(content: bytes) -> bool:
    if not content:
        return False
    if any(content.startswith(header) for header in _ARCHIVE_HEADERS) or b"\x00" in content:
        return True
    try:
        text = content.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return True
    controls = sum(
        1
        for character in text
        if (
            ord(character) < _MIN_TEXT_CONTROL
            or _CARRIAGE_RETURN < ord(character) < _C0_CONTROL_LIMIT
            or ord(character) == _DELETE_CONTROL
        )
    )
    return controls * 100 > max(1, len(text))


def _encrypted(path: str, content: bytes) -> bool:
    lowered = path.lower()
    return lowered.endswith(_ENCRYPTED_SUFFIXES) or any(
        content.startswith(header) for header in _ENCRYPTED_HEADERS
    )


def _private(content: bytes, pairs: Iterable[tuple[str, str]]) -> bool:
    for start, _end in pairs:
        start_bytes = start.encode()
        start_index = content.find(start_bytes)
        if start_index >= 0:
            # An unterminated private marker is private, not malformed public content.
            return True
    return False


def _generated_name(name: str) -> bool:
    return ".generated." in name or name.endswith(
        (".min.css", ".min.js", ".designer.cs", "_pb2.py")
    )


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _micros(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)


def _invalid() -> Never:
    raise IndexingValidationError(_ERR_INPUT)
