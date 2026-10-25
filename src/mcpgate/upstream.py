"""Connections to upstream MCP servers (stdio subprocesses and Streamable HTTP endpoints).

Each upstream is owned by a *supervisor* task that keeps one ``mcp.Client`` session open,
re-lists the upstream's tools whenever the session is (re)established, and reconnects with
capped exponential backoff when the session dies. Request handlers never open connections
themselves: they borrow the live client, bounded by a per-upstream concurrency limiter, so a
slow upstream cannot exhaust the gateway.

The SDK client's response cache is disabled (``cache=None``): the gateway must see every
re-listing verbatim, otherwise a cached ``tools/list`` could hide a changed definition from
the pinning check.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from typing import Any, Literal

import anyio
import httpx2
import mcp_types as types
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError

from mcpgate import __version__
from mcpgate.config import HttpUpstream, StdioUpstream
from mcpgate.errors import UpstreamError

__all__ = ["Connector", "ToolsListener", "Upstream", "connector_for"]

logger = logging.getLogger(__name__)

Connector = Callable[[], AbstractAsyncContextManager[Client]]
"""Factory for a fresh, not-yet-entered client session context."""

ToolsListener = Callable[[str, list[types.Tool]], Awaitable[None]]
"""Called with ``(upstream_name, tools)`` after every successful (re)listing."""

UpstreamState = Literal["connecting", "ready", "down", "stopped"]

_CLIENT_INFO = types.Implementation(name="mcpgate", version=__version__)
_MAX_PAGES = 100
_CONNECTION_ERRORS: tuple[type[BaseException], ...] = (
    anyio.ClosedResourceError,
    anyio.BrokenResourceError,
    anyio.EndOfStream,
    OSError,
    httpx2.HTTPError,
)


def connector_for(config: StdioUpstream | HttpUpstream, message_handler: Any = None) -> Connector:
    """Build the connector for a configured upstream."""
    if isinstance(config, StdioUpstream):
        params = StdioServerParameters(
            command=config.command, args=list(config.args), env=dict(config.env) or None, cwd=config.cwd
        )

        def stdio() -> AbstractAsyncContextManager[Client]:
            return Client(
                params,
                cache=None,
                client_info=_CLIENT_INFO,
                read_timeout_seconds=config.timeout_s,
                message_handler=message_handler,
            )

        return stdio

    @contextlib.asynccontextmanager
    async def http() -> AsyncIterator[Client]:
        timeout = httpx2.Timeout(config.timeout_s, read=max(config.timeout_s, 60.0))
        async with httpx2.AsyncClient(headers=dict(config.headers), timeout=timeout) as http_client:
            transport = streamable_http_client(config.url, http_client=http_client)
            async with Client(
                transport,
                cache=None,
                client_info=_CLIENT_INFO,
                read_timeout_seconds=config.timeout_s,
                message_handler=message_handler,
            ) as client:
                yield client

    return http


class Upstream:
    """Supervises one upstream session and forwards tool calls to it."""

    def __init__(
        self,
        name: str,
        connector: Connector | None,
        *,
        on_tools: ToolsListener,
        on_state: Callable[[str, UpstreamState, str | None], None] | None = None,
        timeout_s: float = 30.0,
        max_concurrency: int = 8,
        backoff_initial_s: float = 0.5,
        backoff_max_s: float = 30.0,
        config: StdioUpstream | HttpUpstream | None = None,
    ) -> None:
        self.name = name
        self._connector = connector or connector_for(self._require(config), self._on_message)
        self._on_tools = on_tools
        self._on_state = on_state
        self._timeout = timeout_s
        self._limiter = anyio.CapacityLimiter(max_concurrency)
        self._backoff_initial = backoff_initial_s
        self._backoff_max = backoff_max_s
        self._client: Client | None = None
        self._ready = anyio.Event()
        self._reconnect = anyio.Event()
        self._stop = anyio.Event()
        self._refresh_lock = anyio.Lock()
        self.state: UpstreamState = "connecting"
        self.last_error: str | None = None
        self.connects = 0
        self._task_group: anyio.abc.TaskGroup | None = None

    @staticmethod
    def _require(config: StdioUpstream | HttpUpstream | None) -> StdioUpstream | HttpUpstream:
        if config is None:
            raise ValueError("either a connector or a config is required")
        return config

    @classmethod
    def from_config(
        cls,
        config: StdioUpstream | HttpUpstream,
        *,
        on_tools: ToolsListener,
        on_state: Callable[[str, UpstreamState, str | None], None] | None = None,
    ) -> Upstream:
        return cls(
            config.name,
            None,
            config=config,
            on_tools=on_tools,
            on_state=on_state,
            timeout_s=config.timeout_s,
            max_concurrency=config.max_concurrency,
        )

    # -- lifecycle ---------------------------------------------------------------------------

    def _set_state(self, state: UpstreamState, error: str | None = None) -> None:
        if state != self.state or error != self.last_error:
            self.state = state
            self.last_error = error
            if self._on_state is not None:
                self._on_state(self.name, state, error)

    async def run(self) -> None:
        """Supervisor loop; returns after :meth:`stop`."""
        delay = self._backoff_initial
        async with anyio.create_task_group() as tg:
            self._task_group = tg
            while not self._stop.is_set():
                self._reconnect = anyio.Event()
                try:
                    async with self._connector() as client:
                        self._client = client
                        self.connects += 1
                        await self._list_and_publish(client)
                        self._set_state("ready")
                        self._ready.set()
                        delay = self._backoff_initial
                        await self._wait_reconnect_or_stop()
                except Exception as exc:  # any transport/session failure -> backoff and retry
                    detail = _describe_exception(exc)
                    logger.warning("upstream %s failed: %s", self.name, detail)
                    self._set_state("down", detail)
                finally:
                    self._client = None
                    self._ready = anyio.Event() if self._ready.is_set() else self._ready
                if self._stop.is_set():
                    break
                if self.state == "ready":
                    self._set_state("connecting")
                    continue  # explicit reconnect: no backoff
                with anyio.move_on_after(delay):
                    await self._stop.wait()
                delay = min(self._backoff_max, delay * 2)
            tg.cancel_scope.cancel()
        self._set_state("stopped")

    async def _wait_reconnect_or_stop(self) -> None:
        async with anyio.create_task_group() as tg:

            async def wait(event: anyio.Event) -> None:
                await event.wait()
                tg.cancel_scope.cancel()

            tg.start_soon(wait, self._reconnect)
            tg.start_soon(wait, self._stop)

    def stop(self) -> None:
        self._stop.set()

    def request_reconnect(self) -> None:
        self._reconnect.set()

    async def wait_ready(self, timeout: float) -> bool:
        with anyio.move_on_after(timeout):
            await self._ready.wait()
            return True
        return False

    # -- tools ------------------------------------------------------------------------------

    async def _list_and_publish(self, client: Client) -> None:
        async with self._refresh_lock:
            tools: list[types.Tool] = []
            cursor: str | None = None
            for _ in range(_MAX_PAGES):
                with anyio.fail_after(self._timeout):
                    page = await client.list_tools(cursor=cursor, cache_mode="refresh")
                tools.extend(page.tools)
                cursor = page.next_cursor
                if cursor is None:
                    break
            else:
                raise UpstreamError(self.name, f"tools/list did not finish within {_MAX_PAGES} pages")
            await self._on_tools(self.name, tools)

    async def refresh(self) -> bool:
        """Re-list tools now. Returns ``False`` (and schedules a reconnect) on failure."""
        client = self._client
        if client is None:
            return False
        try:
            await self._list_and_publish(client)
        except Exception as exc:
            logger.warning("refresh of upstream %s failed: %s", self.name, _describe_exception(exc))
            self.request_reconnect()
            return False
        return True

    async def _on_message(self, message: Any) -> None:
        if isinstance(message, types.ToolListChangedNotification) and self._task_group is not None:
            logger.info("upstream %s announced tools/list_changed", self.name)
            self._task_group.start_soon(self.refresh)

    async def call_tool(self, tool: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        """Forward one call. Upstream JSON-RPC errors become ``isError`` results."""
        client = self._client
        if client is None or self.state != "ready":
            raise UpstreamError(self.name, f"unavailable ({self.state})")
        async with self._limiter:
            try:
                with anyio.fail_after(self._timeout):
                    return await client.call_tool(tool, arguments, read_timeout_seconds=self._timeout)
            except MCPError as exc:
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text=f"upstream error {exc.code}: {exc.message}")],
                    is_error=True,
                )
            except TimeoutError:
                raise UpstreamError(self.name, f"timed out after {self._timeout:g}s") from None
            except _CONNECTION_ERRORS as exc:
                self.request_reconnect()
                raise UpstreamError(self.name, f"connection failed: {_describe_exception(exc)}") from None


def _describe_exception(exc: BaseException) -> str:
    """Flatten exception groups into one readable line."""
    if isinstance(exc, BaseExceptionGroup):
        return "; ".join(_describe_exception(e) for e in exc.exceptions)
    text = str(exc) or type(exc).__name__
    return f"{type(exc).__name__}: {text}" if not text.startswith(type(exc).__name__) else text

