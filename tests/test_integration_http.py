"""End-to-end over real transports: a stdio subprocess upstream, an HTTP subprocess upstream,
and the gateway on a real 127.0.0.1 socket with JWT-protected Streamable HTTP."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import anyio
import httpx2
import pytest
from mcp.shared.exceptions import MCPError

from mcpgate.client import connect_gateway
from mcpgate.devissuer import DevIssuer, generate_keys
from mcpgate.gateway import Gateway
from tests.helpers import POLICY
from mcpgate.config import parse_config

pytestmark = [pytest.mark.anyio, pytest.mark.integration]

ISSUER = "https://issuer.test"
UPSTREAM_SECRET = "upstream-secret-for-tests"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_port(port: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise TimeoutError(f"port {port} never opened")


class InventoryProcess:
    def __init__(self, port: int, variant_file: Path) -> None:
        self.port = port
        self.variant_file = variant_file
        self.proc: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        env = {**os.environ, "INVENTORY_TOKEN": UPSTREAM_SECRET}
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "mcpgate.samples.inventory_server", "--port", str(self.port),
             "--variant-file", str(self.variant_file), "--require-token-env", "INVENTORY_TOKEN"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        wait_port(self.port)

    def stop(self) -> None:
        if self.proc is not None:
            self.proc.terminate()
            self.proc.wait(timeout=10)
            self.proc = None


@pytest.fixture
def inventory(tmp_path: Path) -> Iterator[InventoryProcess]:
    variant = tmp_path / "inventory.variant"
    variant.write_text("clean")
    proc = InventoryProcess(free_port(), variant)
    proc.start()
    yield proc
    proc.stop()


class Env:
    def __init__(self, gw: Gateway, url: str, signer: DevIssuer) -> None:
        self.gw = gw
        self.url = url
        self.signer = signer

    def token(self, client_id: str, scopes: tuple[str, ...] = ("mcp:tools",), **kw: Any) -> str:
        args: dict[str, Any] = {"issuer": ISSUER, "audience": self.url, "client_id": client_id, "scopes": scopes}
        args.update(kw)
        return self.signer.mint(**args)

    def audit(self) -> list[dict[str, Any]]:
        return [json.loads(x) for x in self.gw.audit.path.read_text().splitlines()]


@pytest.fixture
async def env(tmp_path: Path, inventory: InventoryProcess) -> AsyncIterator[Env]:
    signer = generate_keys(tmp_path / "keys", kid="it-1")
    port = free_port()
    cfg = parse_config(
        {
            "refresh_interval_s": 0,
            "listen": {"host": "127.0.0.1", "port": port},
            "auth": {"issuer": ISSUER, "jwks_file": "keys/jwks.json"},
            "upstreams": [
                {"name": "notes", "transport": "stdio", "command": "${PYTHON}",
                 "args": ["-m", "mcpgate.samples.notes_server"]},
                {"name": "inventory", "transport": "http", "url": f"http://127.0.0.1:{inventory.port}/mcp",
                 "headers": {"Authorization": "Bearer ${INVENTORY_TOKEN}"}, "timeout_s": 10},
            ],
            "policy": POLICY,
            "rate_limits": {"per_client": {"rate": 100, "burst": 100}},
        },
        tmp_path,
        env={"INVENTORY_TOKEN": UPSTREAM_SECRET},
    )
    gw = Gateway(cfg)
    stop = anyio.Event()
    ready = anyio.Event()
    async with gw.running(), anyio.create_task_group() as tg:
        tg.start_soon(lambda: gw.serve_http(ready=ready, stop=stop))
        await ready.wait()
        yield Env(gw, cfg.listen.resource_url, signer)
        stop.set()


async def test_requests_without_valid_tokens_are_refused(env: Env) -> None:
    async with httpx2.AsyncClient() as http:
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        headers = {"accept": "application/json, text/event-stream"}
        missing = await http.post(env.url, json=body, headers=headers)
        assert missing.status_code == 401
        assert "resource_metadata=" in missing.headers["www-authenticate"]
        wrong_aud = env.token("agent-analyst", audience="http://some-other-mcp-server/mcp")
        rejected = await http.post(env.url, json=body, headers={**headers, "authorization": f"Bearer {wrong_aud}"})
        assert rejected.status_code == 401
        no_scope = env.token("agent-analyst", scopes=("profile",))
        forbidden = await http.post(env.url, json=body, headers={**headers, "authorization": f"Bearer {no_scope}"})
        assert forbidden.status_code == 403
        assert "insufficient_scope" in forbidden.headers["www-authenticate"]
        meta = await http.get(env.url.replace("/mcp", "/.well-known/oauth-protected-resource/mcp"))
        assert meta.json()["resource"] == env.url
        assert meta.json()["authorization_servers"] == [ISSUER]
        health = await http.get(env.url.replace("/mcp", "/healthz"))
        assert health.json()["status"] == "ok"
    records = env.audit()
    assert [r["status"] for r in records if r["event"] == "http_denied"] == [401, 401, 403]
    assert [r["reason"] for r in records if r["event"] == "auth_rejected"] == ["wrong_audience"]


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_rbac_over_both_transports_and_protocol_eras(env: Env, mode: str) -> None:
    async with connect_gateway(env.url, env.token("agent-analyst"), mode=mode) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert "inventory__get_stock" in names and "notes__add_note" in names
        assert "inventory__adjust_stock" not in names and "notes__delete_note" not in names
        stock = await client.call_tool("inventory__get_stock", {"sku": "SKU-002"})  # HTTP upstream
        assert stock.structured_content == {"sku": "SKU-002", "name": "Gear", "on_hand": 7}
        note = await client.call_tool("notes__add_note", {"title": "t", "body": "b"})  # stdio upstream
        assert note.structured_content is not None and note.structured_content["id"] == 3
        with pytest.raises(MCPError, match="not found or not permitted"):
            await client.call_tool("inventory__adjust_stock", {"sku": "SKU-002", "delta": 5, "reason": "restock"})
    # a role granted through a token scope
    async with connect_gateway(env.url, env.token("someone", scopes=("mcp:tools", "mcpgate:operator")),
                               mode=mode) as client:
        adjusted = await client.call_tool("inventory__adjust_stock", {"sku": "SKU-002", "delta": 5,
                                                                      "reason": "restock"})
        assert adjusted.structured_content == {"sku": "SKU-002", "on_hand": 12, "reason": "restock"}
    calls = [r for r in env.audit() if r["event"] == "tool_call"]
    assert [(c["client_id"], c["decision"]) for c in calls] == [
        ("agent-analyst", "allowed"), ("agent-analyst", "allowed"), ("agent-analyst", "denied_policy"),
        ("someone", "allowed"),
    ]
    assert calls[0]["sub"] == "user:agent-analyst"


async def test_http_upstream_rug_pull_is_quarantined(env: Env, inventory: InventoryProcess) -> None:
    ops = env.token("agent-ops")
    async with connect_gateway(env.url, ops) as client:
        ok = await client.call_tool("inventory__adjust_stock", {"sku": "SKU-001", "delta": 1, "reason": "count"})
        assert not ok.is_error
        # restart the upstream with a silently loosened schema on the same port
        inventory.stop()
        inventory.variant_file.write_text("drifted")
        inventory.start()
        # Re-list. On the stateless 2026-07-28 wire the existing client simply reaches the new
        # process; on the session-based wire the dead session triggers a reconnect first.
        with anyio.fail_after(20):
            while env.gw.health()["quarantined"] == 0:
                await env.gw.refresh()
                await anyio.sleep(0.1)
        blocked = await client.call_tool("inventory__adjust_stock", {"sku": "SKU-001", "delta": 5000})
        assert blocked.is_error
        assert "quarantined" in blocked.content[0].text  # type: ignore[union-attr]
        assert "inventory__adjust_stock" not in {t.name for t in (await client.list_tools()).tools}
    alert = next(r for r in env.audit() if r["event"] == "pin_alert")
    assert alert["tool"] == "adjust_stock"
    assert "- /properties/delta/maximum" in alert["detail"]["inputSchema_diff"]
