"""Shared builders for gateway tests."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from typing import Any

from mcp import Client
from mcp.server import MCPServer

from mcpgate.config import GatewayConfig, parse_config

POLICY: dict[str, Any] = {
    "roles": {
        "analyst": {"allow": ["inventory__get_*", "inventory__list_*", "notes__*"], "deny": ["notes__delete_*"]},
        "operator": {"allow": ["*"]},
    },
    "clients": {"agent-analyst": {"roles": ["analyst"]}, "agent-ops": {"roles": ["operator"]}},
    "scope_roles": {"mcpgate:operator": "operator"},
}


def gateway_config(tmp_path: Path, **overrides: Any) -> GatewayConfig:
    data: dict[str, Any] = {
        "refresh_interval_s": 0,
        "upstreams": [
            {"name": "notes", "transport": "stdio", "command": "${PYTHON}",
             "args": ["-m", "mcpgate.samples.notes_server"]},
            {"name": "inventory", "transport": "http", "url": "http://127.0.0.1:1/mcp"},
        ],
        "policy": POLICY,
        "stdio_identity": {"client_id": "agent-analyst"},
        "rate_limits": {"per_client": {"rate": 50, "burst": 50}},
        "pinning": {"store": "var/pins.json"},
        "audit": {"path": "var/audit.jsonl", "arguments": "redacted"},
    }
    data.update(overrides)
    return parse_config(data, tmp_path, env={})


def inproc(server_factory: Callable[[], MCPServer]) -> Callable[[], AbstractAsyncContextManager[Client]]:
    """Connector that talks to a fresh in-process server instance (same process, no framing)."""
    return lambda: Client(server_factory(), cache=None)
