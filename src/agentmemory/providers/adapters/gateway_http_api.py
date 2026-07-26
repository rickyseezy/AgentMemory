"""Authenticated strict internal HTTP API for the PRO-009 provider gateway."""

from __future__ import annotations

import base64
import binascii
import hmac
import re
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from agentmemory.providers.adapters.protected_file import read_capability, zero
from agentmemory.providers.adapters.strict_json import (
    StrictJsonError,
    canonical_bytes,
    loads,
    require_object,
)
from agentmemory.providers.domain.containment import ExecuteProviderEgress
from agentmemory.providers.domain.errors import (
    ProviderContainmentDeniedError,
    ProviderContainmentDependencyError,
    ProviderContainmentValidationError,
)

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Protocol

    from agentmemory.providers.domain.containment import ProviderEgressHttpResponse

    class ProviderGatewayHandler(Protocol):
        """Execute one authenticated internal gateway command."""

        async def execute(
            self,
            command: ExecuteProviderEgress,
        ) -> ProviderEgressHttpResponse:
            """Return one bounded provider response."""
            ...


_HOST = "provider-gateway:8080"
_CONTENT_TYPE = "application/json"
_MAX_ENVELOPE_BYTES = 12 * 1024 * 1024
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_CAPABILITY_HEX_BYTES = 64
_TOKEN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_FIELDS = frozenset({"schema_version", "permit_token", "path", "body_base64"})
_SAFE_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'",
    "X-Content-Type-Options": "nosniff",
}
_ERR_INVALID = "provider gateway request is invalid"


def create_provider_gateway_app(  # noqa: C901 -- Closed route handlers remain colocated.
    handler: ProviderGatewayHandler,
    capability_file: Path,
) -> FastAPI:
    """Compose the one non-extendable internal operation endpoint."""
    app = FastAPI(
        title="AgentMemory Provider Gateway",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.post("/v1/health", status_code=204)
    async def health(request: Request) -> Response:  # pyright: ignore[reportUnusedFunction]
        """Authenticate an internal liveness probe without provider I/O."""
        authentication = _authenticate(request, capability_file)
        if authentication is not None:
            return authentication
        if await request.body() != b"{}":
            return _error(400, "provider gateway request invalid")
        return Response(status_code=204, headers=_SAFE_HEADERS)

    @app.post("/v1/provider-operations/execute")
    async def execute(  # noqa: PLR0911  # pyright: ignore[reportUnusedFunction]
        request: Request,
    ) -> Response:
        authentication = _authenticate(request, capability_file)
        if authentication is not None:
            return authentication
        length = request.headers.get("content-length")
        if length is not None and (not length.isdecimal() or int(length) > _MAX_ENVELOPE_BYTES):
            return _error(400, "provider gateway request invalid")
        raw = await request.body()
        if len(raw) > _MAX_ENVELOPE_BYTES:
            return _error(400, "provider gateway request invalid")
        try:
            command = _command(raw)
            response = await handler.execute(command)
        except ProviderContainmentDeniedError:
            return _error(403, "provider gateway request denied")
        except ProviderContainmentValidationError:
            return _error(400, "provider gateway request invalid")
        except ProviderContainmentDependencyError:
            return _error(503, "provider gateway unavailable")
        if len(response.body) > _MAX_RESPONSE_BYTES:
            return _error(502, "provider gateway response invalid")
        return Response(
            content=canonical_bytes(
                {
                    "body_base64": base64.b64encode(response.body).decode("ascii"),
                    "retry_after_microseconds": response.retry_after_microseconds,
                    "schema_version": 1,
                    "status_code": response.status_code,
                }
            ),
            media_type=_CONTENT_TYPE,
            headers=_SAFE_HEADERS,
        )

    return app


def _authenticate(request: Request, capability_file: Path) -> Response | None:
    if request.headers.get("host") != _HOST or request.headers.get("content-type") != _CONTENT_TYPE:
        return _error(400, "provider gateway request invalid")
    supplied = request.headers.get("x-agentmemory-capability", "")
    if len(supplied) != _CAPABILITY_HEX_BYTES:
        return _error(401, "provider gateway authentication required")
    try:
        supplied_bytes = bytes.fromhex(supplied)
        expected = read_capability(capability_file)
    except OSError, PermissionError, ValueError:
        return _error(503, "provider gateway unavailable")
    try:
        if not hmac.compare_digest(supplied_bytes, expected):
            return _error(403, "provider gateway request denied")
    finally:
        zero(expected)
    return None


def _command(raw: bytes) -> ExecuteProviderEgress:
    try:
        document = require_object(loads(raw))
        _require_schema(document)
        token = _string(document, "permit_token")
        path = _string(document, "path")
        encoded_body = _string(document, "body_base64")
        _require_token(token)
        body = base64.b64decode(encoded_body, validate=True)
    except (StrictJsonError, KeyError, TypeError, ValueError, binascii.Error) as error:
        raise ProviderContainmentValidationError(_ERR_INVALID) from error
    return ExecuteProviderEgress(
        permit_token=token.encode("ascii"),
        path=path,
        body=bytearray(body),
    )


def _string(document: dict[str, object], key: str) -> str:
    value = document[key]
    if not isinstance(value, str):
        raise TypeError
    return value


def _require_schema(document: dict[str, object]) -> None:
    if frozenset(document) != _FIELDS or document.get("schema_version") != 1:
        raise ValueError


def _require_token(token: str) -> None:
    if _TOKEN.fullmatch(token) is None:
        raise ValueError


def _error(status_code: int, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail},
        headers=_SAFE_HEADERS,
    )
