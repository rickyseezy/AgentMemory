"""Authenticated internal HTTP client for the isolated provider egress gateway."""

from __future__ import annotations

import asyncio
import base64
import binascii
import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import httpx

from agentmemory.providers.adapters.protected_file import read_capability, zero
from agentmemory.providers.adapters.strict_json import canonical_bytes, loads, require_object
from agentmemory.providers.domain.errors import (
    ProviderAdapterError,
    ProviderErrorCode,
    ProviderProfileDependencyError,
)
from agentmemory.providers.domain.profile_ports import ProviderGatewayResponse

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.providers.domain.profile_ports import ProviderGatewayRequest

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$")
_MAX_ENVELOPE_BYTES = 12 * 1024 * 1024
_GATEWAY_PORT = 8080
_SUCCESS_STATUS = 200
_MIN_HTTP_STATUS = 100
_MAX_HTTP_STATUS = 599
_MIN_TIMEOUT_MILLISECONDS = 100
_MAX_TIMEOUT_MILLISECONDS = 300_000
_ERR_URL = "provider gateway URL is invalid"
_ERR_UNAVAILABLE = "provider gateway is unavailable"
_ERR_REJECTED = "provider gateway rejected the operation"
_ERR_RESPONSE = "provider gateway response is invalid"


class ProviderGatewayHttpTransport:
    """Send credential references to one fixed internal gateway, never to a vendor."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        capability_file: Path,
    ) -> None:
        """Bind one exact internal service identity and protected capability file."""
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "provider-gateway"
            or parsed.port != _GATEWAY_PORT
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

    async def execute(self, request: ProviderGatewayRequest) -> ProviderGatewayResponse:
        """Execute one bounded envelope with no inherited proxy or redirect behavior."""
        _validate_request(request)
        try:
            capability = await asyncio.to_thread(read_capability, self._capability_file)
        except OSError as error:
            raise ProviderProfileDependencyError(_ERR_UNAVAILABLE) from error
        try:
            payload = canonical_bytes(
                {
                    "adapter_id": request.adapter_id,
                    "body_base64": base64.b64encode(request.body).decode("ascii"),
                    "endpoint_policy_ref": request.endpoint_policy_ref,
                    "max_response_bytes": request.max_response_bytes,
                    "method": request.method,
                    "path": request.path,
                    "secret_ref": request.secret_ref,
                    "timeout_milliseconds": request.timeout_milliseconds,
                }
            )
            response = await self._client.post(
                f"{self._base_url}/v1/provider-operations/probe",
                content=payload,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "X-AgentMemory-Capability": capability.hex(),
                },
            )
        except (httpx.TimeoutException, httpx.NetworkError, OSError) as error:
            raise ProviderProfileDependencyError(_ERR_UNAVAILABLE) from error
        finally:
            zero(capability)
        if response.status_code in {401, 403}:
            raise ProviderAdapterError(ProviderErrorCode.PRIVACY_DENIAL)
        if response.status_code != _SUCCESS_STATUS or len(response.content) > _MAX_ENVELOPE_BYTES:
            raise ProviderProfileDependencyError(_ERR_REJECTED)
        try:
            document = require_object(loads(response.content))
            body_encoded = _string(document.get("body_base64"))
            body = base64.b64decode(body_encoded, validate=True)
            status = _integer(document.get("status_code"))
            revision = _string(document.get("model_revision"))
            fingerprint = _string(document.get("revision_fingerprint"))
            endpoint_fingerprint = _string(document.get("endpoint_fingerprint"))
            cancellation = _boolean(document.get("cancellation_verified"))
        except (TypeError, ValueError, binascii.Error) as error:
            raise ProviderProfileDependencyError(_ERR_RESPONSE) from error
        if (
            len(body) > request.max_response_bytes
            or not _MIN_HTTP_STATUS <= status <= _MAX_HTTP_STATUS
            or _REVISION.fullmatch(revision) is None
            or _DIGEST.fullmatch(fingerprint) is None
            or _DIGEST.fullmatch(endpoint_fingerprint) is None
        ):
            raise ProviderProfileDependencyError(_ERR_RESPONSE)
        return ProviderGatewayResponse(
            status,
            body,
            revision,
            fingerprint,
            endpoint_fingerprint,
            cancellation,
        )


def _validate_request(request: ProviderGatewayRequest) -> None:
    path = PurePosixPath(request.path)
    if (
        request.method != "POST"
        or not request.path.startswith("/")
        or "//" in request.path
        or ".." in path.parts
        or "\\" in request.path
        or "\x00" in request.path
        or len(request.body) > 8 * 1024 * 1024
        or not _MIN_TIMEOUT_MILLISECONDS
        <= request.timeout_milliseconds
        <= _MAX_TIMEOUT_MILLISECONDS
        or not 1 <= request.max_response_bytes <= 8 * 1024 * 1024
    ):
        raise ProviderAdapterError(ProviderErrorCode.INVALID_CONFIGURATION)


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError
    return value


def _integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError
    return value


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError
    return value
