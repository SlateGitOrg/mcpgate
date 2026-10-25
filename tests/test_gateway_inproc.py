"""Gateway pipeline tests with in-process upstreams and an in-process downstream client."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import mcp_types as types
import pytest
from mcp import Client
from mcp.server import MCPServer
from mcp.shared.exceptions import MCPError

from mcpgate.audit import verify_chain
from mcpgate.gateway import Gateway
from mcpgate.samples import inventory_server, notes_server
from tests.helpers import gateway_config, inproc

pytestmark = pytest.mark.anyio


class Variants:
    """Lets a test swap what the next upstream (re)connection serves."""

    def __init__(self) -> None:
        self.notes = "clean"
        self.inventory = "clean"
        self.inventory_server: MCPServer | None = None

    def notes_factory(self) -> MCPServer:
        return notes_server.build_server(self.notes)

    def inventory_factory(self) -> MCPServer:
        self.inventory_server = inventory_server.build_server(self.inventory)
        return self.inventory_server


def make_gateway(tmp_path: Path, variants: Variants, **overrides: Any) -> Gateway:
    return Gateway(
        gateway_config(tmp_path, **overrides),
        connectors={"notes": inproc(variants.notes_factory), "inventory": inproc(variants.inventory_factory)},
    )


def audit_records(gw: Gateway) -> list[dict[str, Any]]:
    return [json.loads(line) for line in gw.audit.path.read_text().splitlines()]


def calls(gw: Gateway) -> list[dict[str, Any]]:
    return [r for r in audit_records(gw) if r["event"] == "tool_call"]


async def test_catalog_is_namespaced_and_filtered(tmp_path: Path) -> None:
    gw = make_gateway(tmp_path, Variants())
    async with gw.running(), Client(gw.server, cache=None) as client:
        names = [t.name for t in (await client.list_tools()).tools]
        assert names == [
            "inventory__get_stock", "inventory__list_skus",
            "notes__add_note", "notes__list_notes", "notes__search_notes",
        ]
        tool = next(t for t in (await client.list_tools()).tools if t.name == "notes__search_notes")
        assert tool.meta is not None
        assert tool.meta["io.github.mcpgate/upstream"] == "notes"
    health = gw.health()
    assert health["tools"] == 7


async def test_allowed_call_is_forwarded_and_audited(tmp_path: Path) -> None:
    gw = make_gateway(tmp_path, Variants())
    async with gw.running(), Client(gw.server, cache=None) as client:
        result = await client.call_tool("inventory__get_stock", {"sku": "SKU-001"})
        assert result.structured_content == {"sku": "SKU-001", "name": "Widget", "on_hand": 42}
        upstream_error = await client.call_tool("inventory__get_stock", {"sku": "SKU-999"})
        assert upstream_error.is_error
    (ok, err) = calls(gw)
    assert ok["decision"] == "allowed"
    assert ok["upstream"] == "inventory"
    assert ok["args"] == {"sku": "SKU-001"}
    assert ok["pin"].startswith("sha256:")
    assert ok["latency_ms"] >= 0
    assert err["decision"] == "allowed"
    assert err["is_error"] is True
    assert verify_chain(gw.audit.path).ok


async def test_policy_denial_looks_like_unknown_tool(tmp_path: Path) -> None:
    gw = make_gateway(tmp_path, Variants())
    async with gw.running(), Client(gw.server, cache=None) as client:
        with pytest.raises(MCPError) as denied:
            await client.call_tool("inventory__adjust_stock", {"sku": "SKU-001", "delta": 1, "reason": "x"})
        with pytest.raises(MCPError) as unknown:
            await client.call_tool("inventory__does_not_exist", {})
        assert denied.value.message == unknown.value.message == "tool not found or not permitted"
    decisions = [(c["decision"], c.get("rule")) for c in calls(gw)]
    assert decisions == [("denied_policy", None), ("unknown_tool", None)]


async def test_invalid_arguments_are_rejected_before_upstream(tmp_path: Path) -> None:
    gw = make_gateway(tmp_path, Variants())
    async with gw.running(), Client(gw.server, cache=None) as client:
        result = await client.call_tool("inventory__get_stock", {"sku": "../../etc/passwd"})
        assert result.is_error
        text = result.content[0].text  # type: ignore[union-attr]
        assert "invalid arguments" in text
        assert "../../etc/passwd" not in text
    (record,) = calls(gw)
    assert record["decision"] == "invalid_arguments"
    assert record["issues"][0]["path"] == "$.sku"


async def test_rate_limit(tmp_path: Path) -> None:
    gw = make_gateway(
        tmp_path, Variants(),
        rate_limits={"per_client": {"rate": 100, "burst": 100},
                     "per_tool": {"inventory__get_*": {"rate": 0.01, "burst": 2}}},
    )
    async with gw.running(), Client(gw.server, cache=None) as client:
        results = [await client.call_tool("inventory__get_stock", {"sku": "SKU-002"}) for _ in range(3)]
        assert [r.is_error for r in results] == [False, False, True]
        assert results[2].meta is not None
        assert results[2].meta["io.github.mcpgate/decision"]["decision"] == "rate_limited"
        # other tools are unaffected by the per-tool budget
        assert not (await client.call_tool("inventory__list_skus", {})).is_error
    assert [c["decision"] for c in calls(gw)] == ["allowed", "allowed", "rate_limited", "allowed"]


async def test_rug_pull_is_detected_and_quarantined(tmp_path: Path) -> None:
    variants = Variants()
    gw = make_gateway(tmp_path, variants)
    async with gw.running(), Client(gw.server, cache=None) as client:
        assert not (await client.call_tool("notes__search_notes", {"query": "restock"})).is_error
        # the upstream changes its tool definition behind the gateway's back
        variants.notes = "poisoned"
        gw.upstreams["notes"].request_reconnect()
        await wait_for(lambda: gw.upstreams["notes"].connects == 2 and gw.upstreams["notes"].state == "ready")
        names = [t.name for t in (await client.list_tools()).tools]
        assert "notes__search_notes" not in names  # hidden while quarantined
        blocked = await client.call_tool("notes__search_notes", {"query": "restock", "context": "x"})
        assert blocked.is_error
        assert "quarantined" in blocked.content[0].text  # type: ignore[union-attr]
        # an operator approves the change -> the tool is served again, no restart needed
        gw.pins.approve("notes", "search_notes")
        assert not (await client.call_tool("notes__search_notes", {"query": "restock"})).is_error
    alerts = [r for r in audit_records(gw) if r["event"] == "pin_alert"]
    assert [(a["kind"], a["tool"]) for a in alerts] == [("changed", "search_notes")]
    detail = alerts[0]["detail"]
    assert detail["changed_fields"] == ["description", "inputSchema"]
    assert detail["inputSchema_diff"] == ["+ /properties/context"]
    lint = [r for r in audit_records(gw) if r["event"] == "tool_lint"]
    assert lint
    assert lint[-1]["severity"] == "high"
    assert {f["rule"] for f in lint[-1]["findings"]} >= {"sensitive_path", "concealment"}
    assert gw.alerts


async def test_schema_drift_via_refresh(tmp_path: Path) -> None:
    variants = Variants()
    gw = make_gateway(tmp_path, variants, stdio_identity={"client_id": "agent-ops"})
    async with gw.running(), Client(gw.server, cache=None) as client:
        variants.inventory = "drifted"
        gw.upstreams["inventory"].request_reconnect()
        await wait_for(lambda: gw.upstreams["inventory"].connects == 2 and gw.upstreams["inventory"].state == "ready")
        await gw.refresh()
        result = await client.call_tool("inventory__adjust_stock", {"sku": "SKU-001", "delta": 5000})
        assert result.is_error
        assert gw.health()["quarantined"] == 1
    alert = next(r for r in audit_records(gw) if r["event"] == "pin_alert")
    assert "- /properties/delta/maximum" in alert["detail"]["inputSchema_diff"]


async def test_warn_mode_serves_changed_tools(tmp_path: Path) -> None:
    variants = Variants()
    gw = make_gateway(tmp_path, variants, pinning={"store": "var/pins.json", "mode": "warn"})
    async with gw.running(), Client(gw.server, cache=None) as client:
        variants.notes = "poisoned"
        gw.upstreams["notes"].request_reconnect()
        await wait_for(lambda: gw.upstreams["notes"].connects == 2 and gw.upstreams["notes"].state == "ready")
        assert not (await client.call_tool("notes__search_notes", {"query": "gear"})).is_error
    assert any(r["event"] == "pin_alert" for r in audit_records(gw))


async def test_upstream_down_hides_tools_and_fails_calls(tmp_path: Path) -> None:
    variants = Variants()

    def broken() -> MCPServer:
        raise OSError("connection refused")

    gw = Gateway(
        gateway_config(tmp_path),
        connectors={"notes": inproc(variants.notes_factory), "inventory": inproc(broken)},
    )
    async with gw.running(startup_timeout_s=1), Client(gw.server, cache=None) as client:
        names = [t.name for t in (await client.list_tools()).tools]
        assert all(n.startswith("notes__") for n in names)
        assert gw.health()["status"] == "degraded"
        assert gw.upstreams["inventory"].state == "down"
        assert "connection refused" in (gw.upstreams["inventory"].last_error or "")
    states = [r for r in audit_records(gw) if r["event"] == "upstream_state"]
    assert any(s["state"] == "down" for s in states)


async def test_pagination(tmp_path: Path) -> None:
    gw = make_gateway(tmp_path, Variants(), page_size=2)
    async with gw.running(), Client(gw.server, cache=None) as client:
        seen: list[str] = []
        cursor: str | None = None
        for _ in range(5):
            page = await client.list_tools(cursor=cursor)
            seen += [t.name for t in page.tools]
            cursor = page.next_cursor
            if cursor is None:
                break
        assert len(seen) == 5
        with pytest.raises(MCPError, match="invalid cursor"):
            await client.session.list_tools(params=types.PaginatedRequestParams(cursor="garbage!"))


async def wait_for(predicate: Any, timeout: float = 10.0) -> None:
    import anyio

    with anyio.fail_after(timeout):
        while not predicate():
            await anyio.sleep(0.02)
