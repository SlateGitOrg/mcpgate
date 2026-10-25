"""Client-side helpers for talking to a gateway (used by the demo agent, the CLI and tests)."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from typing import Any

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

__all__ = ["connect_gateway"]


@contextlib.asynccontextmanager
async def connect_gateway(
    url: str, token: str | None, *, mode: str = "auto", timeout_s: float = 60.0, **client_kwargs: Any
) -> AsyncIterator[Client]:
    """Open an MCP session to ``url`` presenting ``token`` as an OAuth bearer token."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    timeout = httpx2.Timeout(timeout_s, read=max(timeout_s, 60.0))
    async with httpx2.AsyncClient(headers=headers, timeout=timeout) as http_client:
        transport = streamable_http_client(url, http_client=http_client)
        async with Client(transport, cache=None, mode=mode, **client_kwargs) as client:
            yield client
