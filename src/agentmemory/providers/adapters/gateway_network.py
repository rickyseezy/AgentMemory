"""PRO-009 DNS-pinned, redirect-free, bounded HTTPS provider transport."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast

from agentmemory.providers.domain.containment import ProviderEgressHttpResponse
from agentmemory.providers.domain.errors import (
    ProviderContainmentDeniedError,
    ProviderContainmentDependencyError,
    ProviderContainmentValidationError,
)

if TYPE_CHECKING:
    from asyncio import StreamReader, StreamWriter
    from collections.abc import Awaitable, Callable, Mapping, Sequence

    from agentmemory.providers.domain.containment import ProviderEgressPermit

_MAX_BODY_BYTES = 8 * 1024 * 1024
_MAX_HEADERS = 64
_MAX_HEADER_BYTES = 32 * 1024
_MAX_PATH_BYTES = 512
_MAX_STATUS_LINE_BYTES = 4 * 1024
_MIN_HTTP_STATUS = 100
_MAX_HTTP_STATUS = 599
_INFORMATIONAL_STATUS_LIMIT = 200
_NO_CONTENT_STATUS = 204
_NOT_MODIFIED_STATUS = 304
_MIN_TIMEOUT_MILLISECONDS = 100
_HTTPS_PORT = 443
_REDIRECT_STATUS_MIN = 300
_REDIRECT_STATUS_MAX = 399
_ERR_ADDRESS = "provider gateway address is denied"
_ERR_INPUT = "provider gateway request is invalid"
_ERR_RESPONSE = "provider gateway response is invalid"
_ERR_REDIRECT = "provider redirect is denied"
_ERR_UNAVAILABLE = "provider gateway is unavailable"
_DENIED_REQUEST_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


@dataclass(frozen=True, slots=True)
class NetworkAddressPolicy:
    """Closed address policy denying every non-global DNS answer."""

    require_global: bool

    @classmethod
    def public_only(cls) -> NetworkAddressPolicy:
        """Create the immutable production address policy."""
        return cls(require_global=True)

    def authorize(self, addresses: Sequence[str]) -> tuple[str, ...]:
        """Validate the complete DNS answer and return canonical sorted addresses."""
        if not addresses:
            raise ProviderContainmentValidationError(_ERR_ADDRESS)
        canonical: list[str] = []
        try:
            for value in addresses:
                address = ipaddress.ip_address(value)
                if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                    address = address.ipv4_mapped
                if self.require_global and (
                    not address.is_global
                    or address.is_multicast
                    or address.is_unspecified
                    or address.is_loopback
                    or address.is_link_local
                    or address.is_private
                    or address.is_reserved
                ):
                    raise ProviderContainmentDeniedError(_ERR_ADDRESS)
                canonical.append(address.compressed)
        except ValueError as error:
            raise ProviderContainmentValidationError(_ERR_ADDRESS) from error
        if len(set(canonical)) != len(canonical):
            raise ProviderContainmentValidationError(_ERR_ADDRESS)
        return tuple(sorted(canonical))


class HostnameResolver(Protocol):
    """Resolve one exact hostname without opening a provider socket."""

    async def resolve(self, hostname: str, port: int) -> tuple[str, ...]:
        """Return all DNS answers for policy evaluation."""
        ...


class PinnedHttpsExchange(Protocol):
    """Open one TLS socket to an already authorized numeric address."""

    async def exchange(  # noqa: PLR0913 -- Socket authority must remain explicit.
        self,
        *,
        address: str,
        hostname: str,
        port: int,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
        maximum_response_bytes: int,
        minimum_tls_version: ssl.TLSVersion,
    ) -> ProviderEgressHttpResponse:
        """Perform exactly one request without redirect or proxy support."""
        ...


class PinnedHttpsProviderTransport:
    """Validate a live permit and bind DNS, SNI, Host, TLS, path, and limits."""

    def __init__(
        self,
        resolver: HostnameResolver,
        exchange: PinnedHttpsExchange,
        address_policy: NetworkAddressPolicy,
        *,
        now_microseconds: Callable[[], int],
    ) -> None:
        """Store explicit network seams and a monotonic wall-clock boundary."""
        self._resolver = resolver
        self._exchange = exchange
        self._address_policy = address_policy
        self._now_microseconds = now_microseconds

    async def execute(  # noqa: PLR0913 -- Every network authority is explicit.
        self,
        permit_value: ProviderEgressPermit,
        *,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        maximum_response_bytes: int,
        timeout_milliseconds: int,
    ) -> ProviderEgressHttpResponse:
        """Execute one exact authorized request, denying before DNS when possible."""
        now = self._now_microseconds()
        destination = permit_value.destination
        self._validate_request(
            permit_value,
            now=now,
            method=method,
            path=path,
            headers=headers,
            body=body,
            maximum_response_bytes=maximum_response_bytes,
            timeout_milliseconds=timeout_milliseconds,
        )
        outbound_headers = dict(headers)
        outbound_headers["Host"] = (
            destination.hostname
            if destination.port == _HTTPS_PORT
            else f"{destination.hostname}:{destination.port}"
        )
        try:
            answers = await self._resolver.resolve(destination.hostname, destination.port)
            authorized_addresses = self._address_policy.authorize(answers)
            response = await self._exchange.exchange(
                address=authorized_addresses[0],
                hostname=destination.hostname,
                port=destination.port,
                method=method,
                path=path,
                headers=outbound_headers,
                body=body,
                timeout_seconds=timeout_milliseconds / 1000,
                maximum_response_bytes=maximum_response_bytes,
                minimum_tls_version=ssl.TLSVersion.TLSv1_2,
            )
        except (
            ProviderContainmentDeniedError,
            ProviderContainmentValidationError,
        ):
            raise
        except (OSError, TimeoutError, ssl.SSLError) as error:
            raise ProviderContainmentDependencyError(_ERR_UNAVAILABLE) from error
        if _REDIRECT_STATUS_MIN <= response.status_code <= _REDIRECT_STATUS_MAX:
            raise ProviderContainmentDeniedError(_ERR_REDIRECT)
        if len(response.body) > maximum_response_bytes:
            raise ProviderContainmentValidationError(_ERR_RESPONSE)
        _validate_response(response)
        return response

    @staticmethod
    def _validate_request(  # noqa: PLR0913 -- This is the independent policy boundary.
        permit_value: ProviderEgressPermit,
        *,
        now: int,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        maximum_response_bytes: int,
        timeout_milliseconds: int,
    ) -> None:
        destination = permit_value.destination
        path_bytes = path.encode("utf-8")
        header_bytes = 0
        headers_valid = len(headers) <= _MAX_HEADERS
        for name, value in headers.items():
            lowered = name.lower()
            header_bytes += len(name.encode("utf-8")) + len(value.encode("utf-8"))
            headers_valid = headers_valid and (
                bool(name)
                and name == name.strip()
                and lowered not in _DENIED_REQUEST_HEADERS
                and all(
                    character not in name and character not in value for character in ("\r", "\n")
                )
            )
        path_allowed = path == destination.path_prefix or path.startswith(
            f"{destination.path_prefix}/"
        )
        if (
            not permit_value.issued_at_microseconds <= now < permit_value.expires_at_microseconds
            or method != "POST"
            or not path_allowed
            or not path.startswith("/")
            or len(path_bytes) > _MAX_PATH_BYTES
            or any(value in path for value in ("..", "\\", "\x00", "?", "#", "//"))
            or not headers_valid
            or header_bytes > _MAX_HEADER_BYTES
            or not body
            or len(body) > _MAX_BODY_BYTES
            or len(body) > permit_value.maximum_request_bytes
            or not 1 <= maximum_response_bytes <= permit_value.maximum_response_bytes
            or not _MIN_TIMEOUT_MILLISECONDS
            <= timeout_milliseconds
            <= permit_value.timeout_milliseconds
        ):
            permit_live = (
                permit_value.issued_at_microseconds <= now < permit_value.expires_at_microseconds
            )
            if not permit_live:
                raise ProviderContainmentDeniedError(_ERR_INPUT)
            raise ProviderContainmentValidationError(_ERR_INPUT)


class SystemDnsResolver:
    """Resolve DNS with the operating system resolver outside the event loop."""

    async def resolve(self, hostname: str, port: int) -> tuple[str, ...]:
        """Return all stream-socket addresses without connecting."""
        try:
            return await asyncio.to_thread(self._resolve, hostname, port)
        except OSError as error:
            raise ProviderContainmentDependencyError(_ERR_UNAVAILABLE) from error

    @staticmethod
    def _resolve(hostname: str, port: int) -> tuple[str, ...]:
        records = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
        return tuple(cast("str", record[4][0]) for record in records)


class StdlibPinnedHttpsExchange:
    """Cancellation-safe direct TLS exchange with no proxy or redirect implementation."""

    def __init__(
        self,
        open_connection: Callable[..., Awaitable[tuple[StreamReader, StreamWriter]]] | None = None,
    ) -> None:
        """Inject only the asyncio stream connection seam used by tests."""
        self._open_connection = open_connection or asyncio.open_connection

    async def exchange(  # noqa: PLR0913 -- Implements the explicit socket protocol.
        self,
        *,
        address: str,
        hostname: str,
        port: int,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
        maximum_response_bytes: int,
        minimum_tls_version: ssl.TLSVersion,
    ) -> ProviderEgressHttpResponse:
        """Close the live socket on timeout or task cancellation."""
        writer: StreamWriter | None = None
        context = ssl.create_default_context()
        context.minimum_version = minimum_tls_version
        try:
            async with asyncio.timeout(timeout_seconds):
                reader, writer = await self._open_connection(
                    host=address,
                    port=port,
                    ssl=context,
                    server_hostname=hostname,
                    ssl_handshake_timeout=timeout_seconds,
                    limit=_MAX_HEADER_BYTES + 1,
                )
                request_headers = dict(headers)
                request_headers["Accept-Encoding"] = "identity"
                request_headers["Connection"] = "close"
                request_headers["Content-Length"] = str(len(body))
                request = [f"{method} {path} HTTP/1.1"]
                request.extend(f"{name}: {value}" for name, value in request_headers.items())
                writer.write(("\r\n".join(request) + "\r\n\r\n").encode("latin-1"))
                writer.write(body)
                await writer.drain()
                return await _read_http_response(reader, maximum_response_bytes)
        finally:
            if writer is not None:
                writer.close()
                with suppress(Exception):
                    await writer.wait_closed()


async def _read_http_response(
    reader: StreamReader,
    maximum_response_bytes: int,
) -> ProviderEgressHttpResponse:
    status_line = await _read_line(reader, _MAX_STATUS_LINE_BYTES)
    try:
        version, status_text, reason = status_line.decode("latin-1").split(" ", 2)
        status = int(status_text)
    except (UnicodeError, ValueError) as error:
        raise ProviderContainmentValidationError(_ERR_RESPONSE) from error
    if version not in {"HTTP/1.0", "HTTP/1.1"} or not reason:
        raise ProviderContainmentValidationError(_ERR_RESPONSE)
    headers = await _read_headers(reader)
    body = await _read_body(reader, headers, status, maximum_response_bytes)
    return ProviderEgressHttpResponse(status, headers, body)


async def _read_headers(reader: StreamReader) -> tuple[tuple[str, str], ...]:
    headers: list[tuple[str, str]] = []
    total = 0
    while True:
        raw = await _read_line(reader, _MAX_HEADER_BYTES)
        total += len(raw) + 2
        if total > _MAX_HEADER_BYTES:
            raise ProviderContainmentValidationError(_ERR_RESPONSE)
        if raw == b"":
            return tuple(headers)
        if raw[:1] in {b" ", b"\t"} or b":" not in raw:
            raise ProviderContainmentValidationError(_ERR_RESPONSE)
        name_bytes, value_bytes = raw.split(b":", 1)
        try:
            name = name_bytes.decode("ascii").lower()
            value = value_bytes.decode("latin-1").strip()
        except UnicodeError as error:
            raise ProviderContainmentValidationError(_ERR_RESPONSE) from error
        headers.append((name, value))
        if len(headers) > _MAX_HEADERS:
            raise ProviderContainmentValidationError(_ERR_RESPONSE)


async def _read_body(
    reader: StreamReader,
    headers: tuple[tuple[str, str], ...],
    status: int,
    maximum_response_bytes: int,
) -> bytes:
    if _MIN_HTTP_STATUS <= status < _INFORMATIONAL_STATUS_LIMIT or status in {
        _NO_CONTENT_STATUS,
        _NOT_MODIFIED_STATUS,
    }:
        return b""
    values: dict[str, list[str]] = {}
    for name, value in headers:
        values.setdefault(name, []).append(value)
    transfer = values.get("transfer-encoding", [])
    lengths = values.get("content-length", [])
    if transfer:
        if transfer != ["chunked"] or lengths:
            raise ProviderContainmentValidationError(_ERR_RESPONSE)
        return await _read_chunked_body(reader, maximum_response_bytes)
    if lengths:
        if len(lengths) != 1 or not lengths[0].isdecimal():
            raise ProviderContainmentValidationError(_ERR_RESPONSE)
        length = int(lengths[0])
        if length > maximum_response_bytes:
            raise ProviderContainmentValidationError(_ERR_RESPONSE)
        try:
            return await reader.readexactly(length)
        except asyncio.IncompleteReadError as error:
            raise ProviderContainmentValidationError(_ERR_RESPONSE) from error
    body = await reader.read(maximum_response_bytes + 1)
    if len(body) > maximum_response_bytes:
        raise ProviderContainmentValidationError(_ERR_RESPONSE)
    return body


async def _read_chunked_body(reader: StreamReader, maximum_response_bytes: int) -> bytes:
    body = bytearray()
    while True:
        size_line = await _read_line(reader, 128)
        if not size_line or b";" in size_line:
            raise ProviderContainmentValidationError(_ERR_RESPONSE)
        try:
            size = int(size_line, 16)
        except ValueError as error:
            raise ProviderContainmentValidationError(_ERR_RESPONSE) from error
        if size == 0:
            if await _read_line(reader, _MAX_HEADER_BYTES) != b"":
                raise ProviderContainmentValidationError(_ERR_RESPONSE)
            return bytes(body)
        if size > maximum_response_bytes - len(body):
            raise ProviderContainmentValidationError(_ERR_RESPONSE)
        try:
            body.extend(await reader.readexactly(size))
            ending = await reader.readexactly(2)
        except asyncio.IncompleteReadError as error:
            raise ProviderContainmentValidationError(_ERR_RESPONSE) from error
        if ending != b"\r\n":
            raise ProviderContainmentValidationError(_ERR_RESPONSE)


async def _read_line(reader: StreamReader, maximum_bytes: int) -> bytes:
    try:
        raw = await reader.readuntil(b"\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as error:
        raise ProviderContainmentValidationError(_ERR_RESPONSE) from error
    if len(raw) > maximum_bytes + 2:
        raise ProviderContainmentValidationError(_ERR_RESPONSE)
    return raw[:-2]


def _validate_response(response: ProviderEgressHttpResponse) -> None:
    header_bytes = sum(
        len(name.encode("utf-8")) + len(value.encode("utf-8")) for name, value in response.headers
    )
    if (
        not _MIN_HTTP_STATUS <= response.status_code <= _MAX_HTTP_STATUS
        or len(response.headers) > _MAX_HEADERS
        or header_bytes > _MAX_HEADER_BYTES
        or any(
            not name
            or name != name.lower()
            or any(character in name or character in value for character in ("\r", "\n"))
            for name, value in response.headers
        )
        or len(response.body) > _MAX_BODY_BYTES
    ):
        raise ProviderContainmentValidationError(_ERR_RESPONSE)
