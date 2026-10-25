"""A stdio upstream that crashes mid-session is restarted by its supervisor."""

from __future__ import annotations

from pathlib import Path

import anyio
import pytest
from mcp import Client

from mcpgate.config import parse_config
from mcpgate.gateway import Gateway

pytestmark = [pytest.mark.anyio, pytest.mark.integration]

FIXTURE = Path(__file__).parent / "fixtures" / "crashy_server.py"


async def test_crashed_stdio_upstream_is_restarted(tmp_path: Path) -> None:
    cfg = parse_config(
        {
            "refresh_interval_s": 0,
            "upstreams": [
                {
                    "name": "crashy",
                    "transport": "stdio",
                    "command": "${PYTHON}",
                    "args": [str(FIXTURE)],
                    "timeout_s": 5,
                }
            ],
            "policy": {"roles": {"all": {"allow": ["*"]}}, "clients": {"local": {"roles": ["all"]}}},
        },
        tmp_path,
        env={},
    )
    gw = Gateway(cfg)
    async with gw.running(), Client(gw.server, cache=None) as client:
        first = await client.call_tool("crashy__ping", {})
        died = await client.call_tool("crashy__die", {})
        assert died.is_error
        upstream = gw.upstreams["crashy"]
        with anyio.fail_after(20):
            while not (upstream.connects >= 2 and upstream.state == "ready"):
                await anyio.sleep(0.05)
        second = await client.call_tool("crashy__ping", {})
        assert not second.is_error
        assert first.content[0].text != second.content[0].text  # type: ignore[union-attr]  # new pid
    decisions = [line for line in gw.audit.path.read_text().splitlines() if '"tool_call"' in line]
    assert '"decision":"upstream_error"' in decisions[1] or '"is_error":true' in decisions[1]
