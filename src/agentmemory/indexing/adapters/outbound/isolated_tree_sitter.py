"""Bounded subprocess isolation for native Tree-sitter parsing."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass
from multiprocessing import get_context
from typing import TYPE_CHECKING

from agentmemory.indexing.adapters.outbound.tree_sitter_plugin import (
    TreeSitterLanguagePlugin,
    configured_languages,
)
from agentmemory.indexing.domain.errors import (
    IndexingUnavailableError,
    IndexingValidationError,
)

if TYPE_CHECKING:
    from agentmemory.indexing.domain.ports import ParsedSource, ParserDescriptor

_ERR_POLICY = "parser isolation policy is invalid"
_ERR_WORKER = "isolated source parser failed"
_MAX_WORKERS = 8
_MIN_TIMEOUT_SECONDS = 0.1
_MAX_TIMEOUT_SECONDS = 300.0


@dataclass(frozen=True, slots=True)
class ParserIsolationPolicy:
    """Bound the native parser worker pool and each file's wall time."""

    max_workers: int = 2
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        """Reject unbounded concurrency and ineffective deadlines."""
        if not 1 <= self.max_workers <= _MAX_WORKERS or not (
            _MIN_TIMEOUT_SECONDS <= self.timeout_seconds <= _MAX_TIMEOUT_SECONDS
        ):
            raise IndexingValidationError(_ERR_POLICY)


class IsolatedTreeSitterLanguagePlugin:
    """Run native parsing in a replaceable spawn-based subprocess pool."""

    def __init__(
        self,
        available: frozenset[str] | None = None,
        policy: ParserIsolationPolicy | None = None,
    ) -> None:
        """Snapshot certified grammar inventory and create no worker until first parse."""
        resolved = configured_languages() if available is None else available
        self._delegate = TreeSitterLanguagePlugin(resolved)
        self._available = resolved
        self._policy = policy or ParserIsolationPolicy()
        self._executor: ProcessPoolExecutor | None = None

    def detect(self, relative_path: str, content: bytes) -> str | None:
        """Perform content-safe detection without invoking native grammar code."""
        return self._delegate.detect(relative_path, content)

    def describe(self, language: str) -> ParserDescriptor:
        """Return immutable evidence in the parent process."""
        return self._delegate.describe(language)

    def parse(self, language: str, relative_path: str, content: bytes) -> ParsedSource:
        """Parse with a deadline; replace a crashed or timed-out native pool."""
        executor = self._executor_instance()
        future = executor.submit(
            _parse_source,
            language,
            relative_path,
            content,
            self._available,
        )
        try:
            return future.result(timeout=self._policy.timeout_seconds)
        except (BrokenProcessPool, FuturesTimeoutError, OSError) as error:
            self._retire_executor()
            raise IndexingUnavailableError(_ERR_WORKER) from error
        except Exception as error:
            self._retire_executor()
            raise IndexingUnavailableError(_ERR_WORKER) from error

    def close(self) -> None:
        """Release parser workers during graceful Core shutdown."""
        if self._executor is not None:
            self._executor.shutdown(wait=True, cancel_futures=True)
            self._executor = None

    def _executor_instance(self) -> ProcessPoolExecutor:
        if self._executor is None:
            self._executor = ProcessPoolExecutor(
                max_workers=self._policy.max_workers,
                mp_context=get_context("spawn"),
            )
        return self._executor

    def _retire_executor(self) -> None:
        executor = self._executor
        self._executor = None
        if executor is None:
            return
        executor.shutdown(wait=False, cancel_futures=True)


def _parse_source(
    language: str,
    relative_path: str,
    content: bytes,
    available: frozenset[str],
) -> ParsedSource:
    return TreeSitterLanguagePlugin(available).parse(language, relative_path, content)
