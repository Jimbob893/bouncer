"""M4 — the HTTP forward proxy.

These tests drive a real socket: a live proxy, a live upstream, and raw HTTP on
the wire. Anything less would not exercise the part that actually stands in an
agent's network path.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import AsyncIterator

import pytest

from bouncer.approvals import ApprovalQueue
from bouncer.audit import AuditLog
from bouncer.enforcement import Enforcer
from bouncer.forward_proxy import ProxyServer
from bouncer.keys import OperatorKey
from bouncer.mandate import NonceStore
from bouncer.policy import Policy
from bouncer.sources import StaticSource

from .conftest import NOW

PROXY_POLICY = """
version: 1
currency: USD
agents:
  research-bot:
    per_transaction_cap: 100.00
    merchants:
      allow: ["127.0.0.1", "localhost", "api.example.com"]
      deny: ["evil.example.com"]
"""


def build_enforcer(tmp_path: Path, key: OperatorKey, policy: str = PROXY_POLICY) -> Enforcer:
    audit = AuditLog(tmp_path / "proxy.db", key)
    return Enforcer(
        source=StaticSource(Policy.from_yaml(policy)),
        audit=audit,
        key=key,
        nonces=NonceStore(tmp_path / "proxy.db", engine=audit.engine),
        approvals=ApprovalQueue(tmp_path / "proxy.db", engine=audit.engine),
        clock=lambda: NOW,
    )


class Upstream:
    """A trivial origin server that records what reached it."""

    def __init__(self) -> None:
        self.requests: list[bytes] = []
        self.port = 0
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        async def handle(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            head = await reader.readuntil(b"\r\n\r\n")
            lookup = {}
            for line in head.decode("iso-8859-1").split("\r\n")[1:]:
                name, sep, value = line.partition(":")
                if sep:
                    lookup[name.strip().lower()] = value.strip()
            body = b""
            if "content-length" in lookup:
                body = await reader.readexactly(int(lookup["content-length"]))
            self.requests.append(head + body)

            payload = b'{"ok": true}'
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + payload
            )
            await writer.drain()
            writer.close()

        self._server = await asyncio.start_server(handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


async def run_proxy(enforcer: Enforcer, *, allow_connect: bool = False) -> tuple[asyncio.AbstractServer, int]:
    proxy = ProxyServer(enforcer, allow_connect=allow_connect)
    server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def proxy_request(
    port: int, raw: bytes, *, read_all: bool = True
) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(raw)
    await writer.drain()
    data = await reader.read(-1) if read_all else await reader.read(4096)
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionResetError, BrokenPipeError):
        pass
    return data


def http_request(url: str, body: bytes, *, agent: str = "research-bot", method: str = "POST") -> bytes:
    from urllib.parse import urlsplit

    host = urlsplit(url).netloc
    return (
        f"{method} {url} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"X-Bouncer-Agent: {agent}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode() + body


def intent_body(amount: str, merchant: str = "api.example.com") -> bytes:
    return json.dumps({"merchant": merchant, "amount": amount}).encode()


# ---------------------------------------------------------------------------


def test_allowed_request_is_forwarded_upstream(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    async def scenario() -> None:
        upstream = Upstream()
        await upstream.start()
        enforcer = build_enforcer(tmp_path, operator_key)
        server, port = await run_proxy(enforcer)

        async with server:
            url = f"http://127.0.0.1:{upstream.port}/pay"
            response = await proxy_request(
                port, http_request(url, intent_body("10.00", "127.0.0.1"))
            )

        assert b"200 OK" in response
        assert b'{"ok": true}' in response
        assert len(upstream.requests) == 1
        # The upstream is handed the mandate so it can verify the authorization.
        assert b"X-Bouncer-Mandate:" in upstream.requests[0]
        await upstream.stop()

    asyncio.run(scenario())


def test_denied_request_never_reaches_upstream(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    """The point of the whole system: the money call does not go out."""

    async def scenario() -> None:
        upstream = Upstream()
        await upstream.start()
        enforcer = build_enforcer(tmp_path, operator_key)
        server, port = await run_proxy(enforcer)

        async with server:
            url = f"http://127.0.0.1:{upstream.port}/pay"
            response = await proxy_request(
                port, http_request(url, intent_body("5000.00", "127.0.0.1"))
            )

        assert b"403 Forbidden" in response
        assert b"OVER_PER_TXN_CAP" in response
        assert upstream.requests == []
        await upstream.stop()

    asyncio.run(scenario())


def test_blocked_request_is_recorded_in_the_audit_log(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    async def scenario() -> Enforcer:
        enforcer = build_enforcer(tmp_path, operator_key)
        server, port = await run_proxy(enforcer)
        async with server:
            await proxy_request(
                port,
                http_request("http://evil.example.com/pay", intent_body("10.00", "evil.example.com")),
            )
        return enforcer

    enforcer = asyncio.run(scenario())
    entries = enforcer.audit.entries()
    assert len(entries) == 1
    assert entries[0].outcome == "DENY"
    assert entries[0].reason_code == "MERCHANT_DENIED"
    assert enforcer.audit.verify().ok


def test_unparseable_traffic_is_blocked_not_forwarded(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    async def scenario() -> tuple[bytes, Enforcer, Upstream]:
        upstream = Upstream()
        await upstream.start()
        enforcer = build_enforcer(tmp_path, operator_key)
        server, port = await run_proxy(enforcer)
        async with server:
            url = f"http://127.0.0.1:{upstream.port}/anything"
            response = await proxy_request(port, http_request(url, b"just some bytes"))
        await upstream.stop()
        return response, enforcer, upstream

    response, enforcer, upstream = asyncio.run(scenario())
    assert b"403 Forbidden" in response
    assert upstream.requests == []
    assert enforcer.audit.entries()[0].reason_code == "UNPARSEABLE_INTENT"


def test_connect_is_denied_by_default(tmp_path: Path, operator_key: OperatorKey) -> None:
    """bouncer will not open a channel whose contents it cannot police."""

    async def scenario() -> bytes:
        enforcer = build_enforcer(tmp_path, operator_key)
        server, port = await run_proxy(enforcer, allow_connect=False)
        async with server:
            return await proxy_request(
                port,
                b"CONNECT api.example.com:443 HTTP/1.1\r\n"
                b"Host: api.example.com:443\r\n"
                b"X-Bouncer-Agent: research-bot\r\n\r\n",
            )

    response = asyncio.run(scenario())
    assert b"403 Forbidden" in response
    assert b"CONNECT tunnels are disabled" in response


def test_connect_to_unallowlisted_host_is_denied_even_when_enabled(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    async def scenario() -> bytes:
        enforcer = build_enforcer(tmp_path, operator_key)
        server, port = await run_proxy(enforcer, allow_connect=True)
        async with server:
            return await proxy_request(
                port,
                b"CONNECT unknown.example.com:443 HTTP/1.1\r\n"
                b"X-Bouncer-Agent: research-bot\r\n\r\n",
            )

    response = asyncio.run(scenario())
    assert b"403 Forbidden" in response
    assert b"TUNNEL_NOT_PERMITTED" in response


def test_relative_uri_is_rejected(tmp_path: Path, operator_key: OperatorKey) -> None:
    """A non-proxy-form request means the client is not actually proxying."""

    async def scenario() -> bytes:
        enforcer = build_enforcer(tmp_path, operator_key)
        server, port = await run_proxy(enforcer)
        async with server:
            return await proxy_request(
                port, b"POST /pay HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
            )

    response = asyncio.run(scenario())
    assert b"400 Bad Request" in response
    assert b"absolute URI" in response


def test_chunked_bodies_are_refused(tmp_path: Path, operator_key: OperatorKey) -> None:
    """bouncer must read the whole intent before judging it."""

    async def scenario() -> bytes:
        enforcer = build_enforcer(tmp_path, operator_key)
        server, port = await run_proxy(enforcer)
        async with server:
            return await proxy_request(
                port,
                b"POST http://api.example.com/pay HTTP/1.1\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n",
            )

    response = asyncio.run(scenario())
    assert b"400 Bad Request" in response
    assert b"chunked" in response


def test_hop_by_hop_headers_are_not_forwarded(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    async def scenario() -> Upstream:
        upstream = Upstream()
        await upstream.start()
        enforcer = build_enforcer(tmp_path, operator_key)
        server, port = await run_proxy(enforcer)
        async with server:
            body = intent_body("10.00", "127.0.0.1")
            raw = (
                f"POST http://127.0.0.1:{upstream.port}/pay HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{upstream.port}\r\n"
                "X-Bouncer-Agent: research-bot\r\n"
                "Proxy-Authorization: Basic c2VjcmV0\r\n"
                "Proxy-Connection: keep-alive\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            ).encode() + body
            await proxy_request(port, raw)
        await upstream.stop()
        return upstream

    upstream = asyncio.run(scenario())
    forwarded = upstream.requests[0].lower()
    assert b"proxy-authorization" not in forwarded
    assert b"proxy-connection" not in forwarded


def test_unknown_agent_is_blocked_at_the_proxy(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    async def scenario() -> bytes:
        enforcer = build_enforcer(tmp_path, operator_key)
        server, port = await run_proxy(enforcer)
        async with server:
            return await proxy_request(
                port,
                http_request(
                    "http://api.example.com/pay", intent_body("1.00"), agent="rogue-bot"
                ),
            )

    response = asyncio.run(scenario())
    assert b"403 Forbidden" in response
    assert b"AGENT_NOT_IN_POLICY" in response
