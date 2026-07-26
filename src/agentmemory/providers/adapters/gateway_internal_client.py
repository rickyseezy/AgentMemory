"""Authenticated Core-side client for the isolated PRO-009 provider gateway."""

from __future__ import annotations

import asyncio
import base64
import binascii
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import httpx

from agentmemory.providers.adapters.protected_file import read_capability, zero
from agentmemory.providers.adapters.strict_json import (
    StrictJsonError,
    canonical_bytes,
    loads,
    require_object,
)
from agentmemory.providers.domain.containment import ProviderEgressHttpResponse
from agentmemory.providers.domain.errors import (
    ProviderContainmentDeniedError,
    ProviderContainmentDependencyError,
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.providers.domain.containment import ExecuteProviderEgress

_PORT = 8080
_SUCCESS = 200
_MIN_HTTP_STATUS = 100
_MAX_HTTP_STATUS = 599
_MAX_ENVELOPE_BYTES = 12 * 1024 * 1024
_MAX_BODY_BYTES = 8 * 1024 * 1024
_FIELDS = frozenset(
    {
        "schema_version",
        "status_code",
        "body_base64",
        "retry_after_microseconds",
    }
)
_ERR_URL = "provider gateway URL is invalid"
_ERR_DENIED = "provider gateway request is denied"
_ERR_UNAVAILABLE = "provider gateway is unavailable"
_ERR_RESPONSE = "provider gateway response is invalid"


class ProviderGatewayInternalHttpClient:
    """Send one signed operation envelope to the fixed internal service."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        capability_file: Path,
    ) -> None:
        """Reject external, credential-bearing, or path-bearing gateway URLs."""
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "provider-gateway"
            or parsed.port != _PORT
            or parsed.path not in {"", "/"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(_ERR_URL)
        self._client = client
        self._base_url = base_url.rstrip("/")
        self._capability_file = capability_file

    async def execute(self, command: ExecuteProviderEgress) -> ProviderEgressHttpResponse:
        """Execute with no redirect, proxy, credential reference, or unsafe error detail."""
        try:
            token = command.permit_token.decode("ascii")
            capability = await asyncio.to_thread(read_capability, self._capability_file)
        except (OSError, PermissionError, UnicodeError, ValueError) as error:
            raise ProviderContainmentDependencyError(_ERR_UNAVAILABLE) from error
        try:
            envelope = canonical_bytes(
                {
                    "body_base64": base64.b64encode(command.body).decode("ascii"),
                    "path": command.path,
                    "permit_token": token,
                    "schema_version": 1,
                }
            )
            response = await self._client.post(
                f"{self._base_url}/v1/provider-operations/execute",
                content=envelope,
                headers={
                    "Content-Type": "application/json",
                    "X-AgentMemory-Capability": capability.hex(),
                },
            )
        except (httpx.TimeoutException, httpx.NetworkError, OSError) as error:
            raise ProviderContainmentDependencyError(_ERR_UNAVAILABLE) from error
        finally:
            zero(capability)
        if response.status_code in {401, 403}:
            raise ProviderContainmentDeniedError(_ERR_DENIED)
        if response.status_code != _SUCCESS or len(response.content) > _MAX_ENVELOPE_BYTES:
            raise ProviderContainmentDependencyError(_ERR_UNAVAILABLE)
        try:
            document = require_object(loads(response.content))
            _require_schema(document)
            status_code = _integer(document, "status_code")
            body = base64.b64decode(_string(document, "body_base64"), validate=True)
            retry_after_microseconds = _optional_integer(
                document,
                "retry_after_microseconds",
            )
        except (StrictJsonError, KeyError, TypeError, ValueError, binascii.Error) as error:
            raise ProviderContainmentDependencyError(_ERR_RESPONSE) from error
        if not _MIN_HTTP_STATUS <= status_code <= _MAX_HTTP_STATUS or len(body) > _MAX_BODY_BYTES:
            raise ProviderContainmentDependencyError(_ERR_RESPONSE)
        return ProviderEgressHttpResponse(
            status_code,
            (),
            body,
            retry_after_microseconds,
        )


def _string(document: dict[str, object], key: str) -> str:
    value = document[key]
    if not isinstance(value, str):
        raise TypeError
    return value


def _integer(document: dict[str, object], key: str) -> int:
    value = document[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError
    return value


def _optional_integer(document: dict[str, object], key: str) -> int | None:
    value = document[key]
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise TypeError
    return value


def _require_schema(document: dict[str, object]) -> None:
    if frozenset(document) != _FIELDS or document.get("schema_version") != 1:
        raise ValueError
