"""PRO-009 DNS, address, redirect, TLS, and bounded HTTPS gateway tests."""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

import pytest

from agentmemory.providers.adapters.gateway_network import (
    NetworkAddressPolicy,
    PinnedHttpsProviderTransport,
    StdlibPinnedHttpsExchange,
    SystemDnsResolver,
)
from agentmemory.providers.domain.containment import ProviderEgressHttpResponse
from agentmemory.providers.domain.errors import (
    ProviderContainmentDeniedError,
    ProviderContainmentDependencyError,
    ProviderContainmentValidationError,
)
from tests.providers.test_pro009_containment_application import permit

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass
class StreamWriter:
    writes: list[bytes] = field(default_factory=list[bytes])
    closed: bool = False

    def write(self, value: bytes) -> None:
        self.writes.append(value)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


@dataclass
class Resolver:
    addresses: tuple[str, ...]
    calls: list[tuple[str, int]] = field(default_factory=list[tuple[str, int]])

    async def resolve(self, hostname: str, port: int) -> tuple[str, ...]:
        self.calls.append((hostname, port))
        return self.addresses


@dataclass
class Exchange:
    response: ProviderEgressHttpResponse = field(
        default_factory=lambda: ProviderEgressHttpResponse(
            status_code=200,
            headers=(("content-type", "application/json"),),
            body=b'{"data":[]}',
        )
    )
    error: Exception | None = None
    calls: list[dict[str, object]] = field(default_factory=list[dict[str, object]])

    async def exchange(  # noqa: PLR0913 -- Test double matches explicit socket port.
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
        self.calls.append(
            {
                "address": address,
                "body": body,
                "headers": dict(headers),
                "hostname": hostname,
                "maximum_response_bytes": maximum_response_bytes,
                "method": method,
                "minimum_tls_version": minimum_tls_version,
                "path": path,
                "port": port,
                "timeout_seconds": timeout_seconds,
            }
        )
        if self.error is not None:
            raise self.error
        return self.response


@pytest.mark.asyncio
async def test_system_dns_resolver_uses_bounded_stream_tcp_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []

    def getaddrinfo(
        hostname: str,
        port: int,
        **options: int,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        calls.append(
            (
                hostname,
                port,
                options["family"],
                options["type"],
                options["proto"],
            )
        )
        return [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("2606:4700:4700::1111", port),
            ),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("1.1.1.1", port)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)

    assert await SystemDnsResolver().resolve("api.openai.com", 443) == (
        "2606:4700:4700::1111",
        "1.1.1.1",
    )
    assert calls == [
        (
            "api.openai.com",
            443,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        )
    ]


@pytest.mark.asyncio
async def test_system_dns_resolver_closes_operating_system_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def getaddrinfo(
        hostname: str,
        port: int,
        **options: int,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        del hostname, port, options
        detail = "secret resolver detail"
        raise OSError(detail)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)

    with pytest.raises(ProviderContainmentDependencyError, match="unavailable") as caught:
        await SystemDnsResolver().resolve("api.openai.com", 443)
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",  # noqa: S104 -- Deliberate denied wildcard regression fixture.
        "127.0.0.1",
        "10.0.0.1",
        "100.64.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.168.1.1",
        "224.0.0.1",
        "240.0.0.1",
        "::",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
    ],
)
def test_default_address_policy_denies_nonpublic_and_metadata_ranges(address: str) -> None:
    with pytest.raises(ProviderContainmentDeniedError, match="address"):
        NetworkAddressPolicy.public_only().authorize((address,))


def test_address_policy_rejects_empty_malformed_duplicate_or_mixed_dns_answers() -> None:
    policy = NetworkAddressPolicy.public_only()
    for addresses in (
        (),
        ("not-an-ip",),
        ("8.8.8.8", "8.8.8.8"),
        ("8.8.8.8", "127.0.0.1"),
    ):
        with pytest.raises((ProviderContainmentDeniedError, ProviderContainmentValidationError)):
            policy.authorize(addresses)


@pytest.mark.asyncio
async def test_transport_pins_authorized_dns_address_sni_host_tls_and_limits() -> None:
    resolver = Resolver(("8.8.8.8", "1.1.1.1"))
    exchange = Exchange()
    transport = PinnedHttpsProviderTransport(
        resolver,
        exchange,
        NetworkAddressPolicy.public_only(),
        now_microseconds=lambda: 2_000,
    )

    response = await transport.execute(
        permit(),
        method="POST",
        path="/v1/embeddings",
        headers={"Authorization": "Bearer opaque-brokered-value"},
        body=b'{"input":["safe"]}',
        maximum_response_bytes=4096,
        timeout_milliseconds=5000,
    )

    assert response.status_code == 200
    assert resolver.calls == [("api.openai.com", 443)]
    assert exchange.calls == [
        {
            "address": "1.1.1.1",
            "body": b'{"input":["safe"]}',
            "headers": {
                "Authorization": "Bearer opaque-brokered-value",
                "Host": "api.openai.com",
            },
            "hostname": "api.openai.com",
            "maximum_response_bytes": 4096,
            "method": "POST",
            "minimum_tls_version": ssl.TLSVersion.TLSv1_2,
            "path": "/v1/embeddings",
            "port": 443,
            "timeout_seconds": 5.0,
        }
    ]


@pytest.mark.asyncio
async def test_denied_dns_answer_never_reaches_socket_exchange() -> None:
    resolver = Resolver(("8.8.8.8", "169.254.169.254"))
    exchange = Exchange()
    transport = PinnedHttpsProviderTransport(
        resolver,
        exchange,
        NetworkAddressPolicy.public_only(),
        now_microseconds=lambda: 2_000,
    )

    with pytest.raises(ProviderContainmentDeniedError, match="address"):
        await transport.execute(
            permit(),
            method="POST",
            path="/v1/embeddings",
            headers={},
            body=b"safe",
            maximum_response_bytes=4096,
            timeout_milliseconds=5000,
        )
    assert exchange.calls == []


@pytest.mark.asyncio
async def test_expired_permit_or_invalid_request_fails_before_dns() -> None:
    resolver = Resolver(("8.8.8.8",))
    exchange = Exchange()
    transport = PinnedHttpsProviderTransport(
        resolver,
        exchange,
        NetworkAddressPolicy.public_only(),
        now_microseconds=lambda: 10_000,
    )
    cases = (
        {"permit_value": permit()},
        {"permit_value": replace(permit(), expires_at_microseconds=10_001), "method": "GET"},
        {
            "permit_value": replace(permit(), expires_at_microseconds=10_001),
            "path": "/v1/embeddings/../models",
        },
        {
            "permit_value": replace(permit(), expires_at_microseconds=10_001),
            "body": b"x" * (8 * 1024 * 1024 + 1),
        },
    )
    for changed in cases:
        parameters: dict[str, object] = {
            "permit_value": changed.get("permit_value"),
            "method": changed.get("method", "POST"),
            "path": changed.get("path", "/v1/embeddings"),
            "headers": {},
            "body": changed.get("body", b"safe"),
            "maximum_response_bytes": 4096,
            "timeout_milliseconds": 5000,
        }
        with pytest.raises((ProviderContainmentDeniedError, ProviderContainmentValidationError)):
            await transport.execute(**parameters)  # type: ignore[arg-type]
    assert resolver.calls == []
    assert exchange.calls == []


@pytest.mark.asyncio
async def test_redirect_is_not_followed_and_response_limit_is_independent() -> None:
    resolver = Resolver(("8.8.8.8",))
    redirect = Exchange(
        ProviderEgressHttpResponse(
            status_code=302,
            headers=(("location", "https://evil.example/steal"),),
            body=b"",
        )
    )
    transport = PinnedHttpsProviderTransport(
        resolver,
        redirect,
        NetworkAddressPolicy.public_only(),
        now_microseconds=lambda: 2_000,
    )
    with pytest.raises(ProviderContainmentDeniedError, match="redirect"):
        await transport.execute(
            permit(),
            method="POST",
            path="/v1/embeddings",
            headers={},
            body=b"safe",
            maximum_response_bytes=4096,
            timeout_milliseconds=5000,
        )
    assert len(redirect.calls) == 1
    assert resolver.calls == [("api.openai.com", 443)]

    oversized = Exchange(
        ProviderEgressHttpResponse(200, (), b"x" * 5),
    )
    with pytest.raises(ProviderContainmentValidationError, match="response"):
        await PinnedHttpsProviderTransport(
            Resolver(("8.8.8.8",)),
            oversized,
            NetworkAddressPolicy.public_only(),
            now_microseconds=lambda: 2_000,
        ).execute(
            permit(),
            method="POST",
            path="/v1/embeddings",
            headers={},
            body=b"safe",
            maximum_response_bytes=4,
            timeout_milliseconds=5000,
        )


@pytest.mark.asyncio
async def test_tls_or_socket_failure_becomes_one_content_free_dependency_error() -> None:
    exchange = Exchange(error=ssl.SSLError("certificate body secret"))
    with pytest.raises(ProviderContainmentDependencyError, match="unavailable") as caught:
        await PinnedHttpsProviderTransport(
            Resolver(("8.8.8.8",)),
            exchange,
            NetworkAddressPolicy.public_only(),
            now_microseconds=lambda: 2_000,
        ).execute(
            permit(),
            method="POST",
            path="/v1/embeddings",
            headers={},
            body=b"safe",
            maximum_response_bytes=4096,
            timeout_milliseconds=5000,
        )
    assert "certificate" not in str(caught.value)


@pytest.mark.asyncio
async def test_direct_exchange_pins_numeric_address_sni_and_parses_bounded_chunking() -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"4\r\nsafe\r\n"
        b"0\r\n\r\n"
    )
    reader.feed_eof()
    writer = StreamWriter()
    calls: list[dict[str, object]] = []

    async def connect(**values: object) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        calls.append(values)
        return reader, writer  # type: ignore[return-value]

    response = await StdlibPinnedHttpsExchange(connect).exchange(
        address="1.1.1.1",
        hostname="api.openai.com",
        port=443,
        method="POST",
        path="/v1/embeddings",
        headers={"Host": "api.openai.com"},
        body=b"{}",
        timeout_seconds=1.0,
        maximum_response_bytes=4,
        minimum_tls_version=ssl.TLSVersion.TLSv1_2,
    )

    assert response == ProviderEgressHttpResponse(
        200,
        (
            ("content-type", "application/json"),
            ("transfer-encoding", "chunked"),
        ),
        b"safe",
    )
    assert calls[0]["host"] == "1.1.1.1"
    assert calls[0]["server_hostname"] == "api.openai.com"
    assert b"Accept-Encoding: identity" in b"".join(writer.writes)
    assert writer.closed


@pytest.mark.asyncio
async def test_direct_exchange_closes_socket_when_calling_task_is_cancelled() -> None:
    reader = asyncio.StreamReader()
    writer = StreamWriter()
    connected = asyncio.Event()

    async def connect(**values: object) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        del values
        connected.set()
        return reader, writer  # type: ignore[return-value]

    task = asyncio.create_task(
        StdlibPinnedHttpsExchange(connect).exchange(
            address="1.1.1.1",
            hostname="api.openai.com",
            port=443,
            method="POST",
            path="/v1/embeddings",
            headers={"Host": "api.openai.com"},
            body=b"{}",
            timeout_seconds=30.0,
            maximum_response_bytes=4096,
            minimum_tls_version=ssl.TLSVersion.TLSv1_2,
        )
    )
    await connected.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert writer.closed


@pytest.mark.asyncio
async def test_direct_exchange_rejects_oversized_or_ambiguous_response_framing() -> None:
    for response in (
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nlarge",
        (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 4\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"4\r\nsafe\r\n0\r\n\r\n"
        ),
    ):
        reader = asyncio.StreamReader()
        reader.feed_data(response)
        reader.feed_eof()
        writer = StreamWriter()

        async def connect(
            *,
            reader_value: asyncio.StreamReader = reader,
            writer_value: StreamWriter = writer,
            **values: object,
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            del values
            return reader_value, writer_value  # type: ignore[return-value]

        with pytest.raises(ProviderContainmentValidationError, match="response"):
            await StdlibPinnedHttpsExchange(connect).exchange(
                address="1.1.1.1",
                hostname="api.openai.com",
                port=443,
                method="POST",
                path="/v1/embeddings",
                headers={"Host": "api.openai.com"},
                body=b"{}",
                timeout_seconds=1.0,
                maximum_response_bytes=4,
                minimum_tls_version=ssl.TLSVersion.TLSv1_2,
            )
        assert writer.closed
