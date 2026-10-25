"""The gateway: one MCP server in front of many upstream MCP servers.

Request pipeline for ``tools/call`` (every exit is audited with a ``decision`` field)::

    identify caller ──► resolve namespaced tool ──► RBAC ──► pin check ──► upstream ready?
        ──► rate limit ──► argument schema validation ──► forward ──► audit result

* Unknown tools and tools the caller may not use produce the *same* JSON-RPC error, so the
  gateway is not an oracle for which tools exist; the audit log records the real reason.
* Quarantined tools, rate limiting, invalid arguments and upstream outages produce
  ``isError`` tool results, so an LLM agent sees a readable reason and can recover.
* ``tools/list`` returns only tools the caller is allowed to call, that are not quarantined,
  and whose upstream is currently connected.

The gateway is built on the official SDK's low-level :class:`mcp.server.lowlevel.Server`, so
it speaks both the 2025-11-25 handshake protocol and the 2026-07-28 stateless protocol, over
Streamable HTTP (OAuth-protected) or stdio (trusted local identity).
"""

from __future__ import annotations

import contextlib
import logging
import time
from collections import Counter, deque
from collections.abc import AsyncIterator, Mapping
from typing import Any

import anyio
import mcp_types as types
import uvicorn
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.settings import AuthSettings
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mcpgate import __version__
from mcpgate.audit import AuditLog, summarize_arguments
from mcpgate.auth import JWTVerifier, Principal
from mcpgate.catalog import Catalog, CatalogEntry, decode_cursor, encode_cursor
from mcpgate.config import GatewayConfig
from mcpgate.errors import AuthError, UpstreamError
from mcpgate.lint import lint_definition
from mcpgate.pinning import PinEvent, PinManager
from mcpgate.policy import PolicyEngine
from mcpgate.ratelimit import RateLimiter
from mcpgate.upstream import Connector, Upstream, UpstreamState
from mcpgate.validation import ArgumentValidator

__all__ = ["Gateway"]

logger = logging.getLogger(__name__)

NOT_FOUND_MESSAGE = "tool not found or not permitted"


def _error_result(text: str, **meta: Any) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=f"mcpgate: {text}")],
        is_error=True,
        _meta={"io.github.mcpgate/decision": meta} if meta else None,
    )


def _result_size(result: types.CallToolResult) -> int:
    return len(result.model_dump_json(by_alias=True, exclude_none=True))


class Gateway:
    """Composes catalog, auth, policy, limits, pinning and audit around SDK servers/clients."""

    def __init__(
        self,
        config: GatewayConfig,
        *,
        connectors: Mapping[str, Connector] | None = None,
        verifier: JWTVerifier | None = None,
        monotonic: Any = time.monotonic,
    ) -> None:
        self.config = config
        self._monotonic = monotonic
        self.audit = AuditLog(config.audit)
        self.catalog = Catalog(config.namespace_separator)
        self.policy = PolicyEngine(config.policy)
        self.rate_limiter = RateLimiter(config.rate_limits, clock=monotonic)
        self.validator = ArgumentValidator(config.limits)
        self.pins = PinManager(config.pinning)
        self.alerts: deque[dict[str, Any]] = deque(maxlen=200)
        self.stats: Counter[str] = Counter()
        self.verifier = verifier
        if self.verifier is None and config.auth is not None and config.auth.enabled:
            self.verifier = JWTVerifier(config.auth, config.audience, on_reject=self._audit_token_rejection)
        connectors = connectors or {}
        self.upstreams: dict[str, Upstream] = {}
        for up in config.upstreams:
            connector = connectors.get(up.name)
            if connector is not None:
                self.upstreams[up.name] = Upstream(
                    up.name,
                    connector,
                    on_tools=self._on_tools,
                    on_state=self._on_upstream_state,
                    timeout_s=up.timeout_s,
                    max_concurrency=up.max_concurrency,
                    heartbeat_s=up.heartbeat_s,
                )
            else:
                self.upstreams[up.name] = Upstream.from_config(
                    up, on_tools=self._on_tools, on_state=self._on_upstream_state
                )
        self.server: Server[Any] = Server(
            config.name,
            version=__version__,
            instructions=(
                "Tools are namespaced as <upstream>" + config.namespace_separator + "<tool>. "
                "Calls are authorized, rate limited, validated and audited by mcpgate."
            ),
            on_list_tools=self.handle_list_tools,
            on_call_tool=self.handle_call_tool,
            get_tool_input_schema=self._input_schema_for,
        )

    # -- upstream events ---------------------------------------------------------------------

    def _on_upstream_state(self, name: str, state: UpstreamState, error: str | None) -> None:
        self.audit.write("upstream_state", upstream=name, state=state, error=error)

    async def _on_tools(self, upstream: str, tools: list[types.Tool]) -> None:
        for warning in self.catalog.update(upstream, tools):
            self.audit.write("tool_refused", upstream=upstream, reason=warning)
        events = self.pins.reconcile(upstream, self.catalog.fingerprints(upstream))
        for event in events:
            self._record_pin_event(event)
        self._lint_upstream(upstream, events)
        self.audit.write("catalog_refreshed", upstream=upstream, tools=len(self.catalog.entries(upstream)))

    def _record_pin_event(self, event: PinEvent) -> None:
        record = self.audit.write(
            "pin_alert" if event.kind in {"changed", "new_tool", "removed"} else "pin_event",
            kind=event.kind,
            upstream=event.upstream,
            tool=event.tool,
            severity=event.severity,
            detail=dict(event.detail) or None,
        )
        if record["event"] == "pin_alert":
            self.alerts.append(record)

    def _lint_upstream(self, upstream: str, events: list[PinEvent]) -> None:
        if not self.config.pinning.lint:
            return
        if any(e.kind == "tofu" for e in events):
            targets = {e.original for e in self.catalog.entries(upstream)}
        else:
            targets = {
                e.tool for e in events if e.tool and e.kind in {"changed", "new_tool", "new_tool_pinned"}
            }
        others = self.catalog.names_outside(upstream)
        for entry in self.catalog.entries(upstream):
            if entry.original not in targets:
                continue
            findings = lint_definition(entry.fingerprint.definition, others)
            if findings:
                record = self.audit.write(
                    "tool_lint",
                    upstream=upstream,
                    tool=entry.original,
                    severity=max((f.severity for f in findings), key=["low", "medium", "high"].index),
                    findings=[{"rule": f.rule, "severity": f.severity, "at": f.location} for f in findings],
                )
                self.alerts.append(record)

    def _audit_token_rejection(self, error: AuthError, facts: dict[str, Any]) -> None:
        self.stats["auth_rejected"] += 1
        self.audit.write("auth_rejected", reason=error.reason, alg=facts.get("alg"), kid=facts.get("kid"))

    # -- identity ----------------------------------------------------------------------------

    def _identify(self, ctx: ServerRequestContext[Any]) -> Principal:
        request = ctx.request
        if isinstance(request, Request):
            user = request.scope.get("user")
            if isinstance(user, AuthenticatedUser):
                return Principal.from_access_token(user.access_token)
            if self.verifier is not None:
                # Unreachable through the HTTP app (the bearer middleware answers 401 first);
                # kept as a fail-closed guard for embedders who mount the server differently.
                raise MCPError(types.INVALID_REQUEST, "unauthenticated request")
        ident = self.config.stdio_identity
        return Principal(client_id=ident.client_id, subject=None, issuer=None, scopes=frozenset(ident.scopes))

    def _visible_entry(self, entry: CatalogEntry, principal: Principal) -> bool:
        upstream = self.upstreams.get(entry.upstream)
        if upstream is None or upstream.state != "ready":
            return False
        if self.pins.blocks(self.pins.status(entry.upstream, entry.original, entry.fingerprint)):
            return False
        return self.policy.check(principal.client_id, principal.scopes, entry.name).allowed

    def _input_schema_for(self, name: str) -> Mapping[str, Any] | None:
        entry = self.catalog.get(name)
        return entry.input_schema if entry is not None else None

    # -- handlers ----------------------------------------------------------------------------

    async def handle_list_tools(
        self, ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        principal = self._identify(ctx)
        visible = [e for e in self.catalog.entries() if self._visible_entry(e, principal)]
        offset = decode_cursor(params.cursor if params is not None else None)
        if offset is None:
            raise MCPError(types.INVALID_PARAMS, "invalid cursor")
        page = visible[offset : offset + self.config.page_size]
        next_offset = offset + len(page)
        self.audit.write(
            "tools_list",
            client_id=principal.client_id,
            sub=principal.subject,
            returned=len(page),
            hidden=len(self.catalog) - len(visible),
        )
        return types.ListToolsResult(
            tools=[e.exposed() for e in page],
            next_cursor=encode_cursor(next_offset) if next_offset < len(visible) else None,
        )

    async def handle_call_tool(
        self, ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        started = self._monotonic()
        principal = self._identify(ctx)
        arguments = dict(params.arguments or {})
        base: dict[str, Any] = {
            "client_id": principal.client_id,
            "sub": principal.subject,
            "jti": principal.token_id,
            "tool": params.name,
            **summarize_arguments(arguments, self.config.audit.arguments, self.config.audit.redact_keys),
        }

        def audit(decision: str, **extra: Any) -> None:
            self.stats[decision] += 1
            latency = round((self._monotonic() - started) * 1000, 3)
            self.audit.write("tool_call", decision=decision, latency_ms=latency, **base, **extra)

        entry = self.catalog.get(params.name)
        if entry is None:
            audit("unknown_tool")
            raise MCPError(types.INVALID_PARAMS, NOT_FOUND_MESSAGE)
        base["upstream"] = entry.upstream
        base["pin"] = entry.fingerprint.digest

        verdict = self.policy.check(principal.client_id, principal.scopes, entry.name)
        if not verdict.allowed:
            audit("denied_policy", reason=verdict.reason, roles=list(verdict.roles), rule=verdict.rule)
            raise MCPError(types.INVALID_PARAMS, NOT_FOUND_MESSAGE)

        status = self.pins.status(entry.upstream, entry.original, entry.fingerprint)
        if self.pins.blocks(status):
            audit("quarantined", pin_status=status.value)
            return _error_result(
                f"tool {entry.name} is quarantined: its definition ({status.value}) differs from the "
                "approved pin. An operator must review it (mcpgate pins diff/approve).",
                decision="quarantined",
            )

        upstream = self.upstreams[entry.upstream]
        if upstream.state != "ready":
            audit("upstream_unavailable", upstream_state=upstream.state)
            return _error_result(f"upstream {entry.upstream} is unavailable", decision="upstream_unavailable")

        rate = self.rate_limiter.check(principal.client_id, entry.name)
        if not rate.allowed:
            audit("rate_limited", scope=rate.scope, retry_after_s=round(rate.retry_after_s, 3))
            return _error_result(
                f"rate limit exceeded ({rate.scope} budget); retry after {rate.retry_after_s:.2f}s",
                decision="rate_limited",
                retry_after_s=round(rate.retry_after_s, 3),
            )

        outcome = self.validator.validate(entry.fingerprint.digest, entry.input_schema, arguments)
        if not outcome.ok:
            issues = [{"path": i.path, "keyword": i.keyword, "message": i.message} for i in outcome.issues]
            audit("invalid_arguments", issues=issues)
            return _error_result(
                f"invalid arguments for {entry.name}: {outcome.summary()}", decision="invalid"
            )

        try:
            result = await upstream.call_tool(entry.original, arguments)
        except UpstreamError as exc:
            audit("upstream_error", error=exc.detail)
            return _error_result(f"upstream {entry.upstream} failed: {exc.detail}", decision="upstream_error")
        audit("allowed", is_error=bool(result.is_error), result_bytes=_result_size(result))
        return result

    # -- lifecycle ---------------------------------------------------------------------------

    @contextlib.asynccontextmanager
    async def running(self, *, startup_timeout_s: float = 20.0) -> AsyncIterator[Gateway]:
        """Start upstream supervisors and the refresh loop; stop them on exit."""
        self.audit.write("gateway_start", version=__version__, upstreams=sorted(self.upstreams))
        try:
            async with anyio.create_task_group() as tg:
                for upstream in self.upstreams.values():
                    tg.start_soon(upstream.run)
                with anyio.move_on_after(startup_timeout_s):
                    for upstream in self.upstreams.values():
                        await upstream.wait_ready(startup_timeout_s)
                not_ready = sorted(n for n, u in self.upstreams.items() if u.state != "ready")
                if not_ready:
                    logger.warning("starting degraded; upstreams not ready: %s", ", ".join(not_ready))
                if self.config.refresh_interval_s > 0:
                    tg.start_soon(self._refresh_loop)
                try:
                    yield self
                finally:
                    for upstream in self.upstreams.values():
                        upstream.stop()
                    tg.cancel_scope.cancel()
        finally:
            self.audit.write("gateway_stop")

    async def _refresh_loop(self) -> None:
        while True:
            await anyio.sleep(self.config.refresh_interval_s)
            await self.refresh()

    async def refresh(self) -> None:
        """Re-list every connected upstream now (pinning runs on the fresh listings)."""
        for upstream in self.upstreams.values():
            if upstream.state == "ready":
                await upstream.refresh()

    def health(self) -> dict[str, Any]:
        states = Counter(u.state for u in self.upstreams.values())
        quarantined = sum(
            1
            for e in self.catalog.entries()
            if self.pins.blocks(self.pins.status(e.upstream, e.original, e.fingerprint))
        )
        return {
            "status": "ok" if states.get("ready", 0) == len(self.upstreams) else "degraded",
            "upstreams": dict(states),
            "tools": len(self.catalog),
            "quarantined": quarantined,
        }

    # -- transports --------------------------------------------------------------------------

    def http_app(self) -> ASGIApp:
        """The Streamable HTTP ASGI app, OAuth-protected when ``auth`` is configured."""
        listen = self.config.listen

        async def healthz(_: Request) -> JSONResponse:
            return JSONResponse(self.health())

        routes = [Route("/healthz", healthz)]
        if self.verifier is not None and self.config.auth is not None:
            settings = AuthSettings(
                issuer_url=self.config.auth.issuer,  # type: ignore[arg-type]
                resource_server_url=listen.resource_url,  # type: ignore[arg-type]
                required_scopes=self.config.auth.required_scopes,
                validate_token_resource=False,  # the JWT verifier enforces `aud` itself
            )
            app: Starlette = self.server.streamable_http_app(
                streamable_http_path=listen.path,
                host=listen.host,
                auth=settings,
                token_verifier=self.verifier,
                custom_starlette_routes=routes,
            )
        else:
            logger.warning("HTTP listener has NO authentication configured")
            app = self.server.streamable_http_app(
                streamable_http_path=listen.path, host=listen.host, custom_starlette_routes=routes
            )
        return _DenialAuditor(app, self, listen.path)

    async def serve_http(self, *, ready: anyio.Event | None = None, stop: anyio.Event | None = None) -> None:
        """Serve Streamable HTTP until ``stop`` is set (or uvicorn exits on a signal)."""
        listen = self.config.listen
        config = uvicorn.Config(
            self.http_app(), host=listen.host, port=listen.port, log_level="warning", lifespan="on"
        )
        server = uvicorn.Server(config)
        async with anyio.create_task_group() as tg:

            async def run() -> None:
                await server.serve()
                tg.cancel_scope.cancel()

            tg.start_soon(run)
            while not server.started:  # noqa: ASYNC110 -- uvicorn exposes a flag, not an event
                await anyio.sleep(0.02)
            logger.info("mcpgate listening on http://%s:%s%s", listen.host, listen.port, listen.path)
            if ready is not None:
                ready.set()
            if stop is not None:
                await stop.wait()
                server.should_exit = True

    async def serve_stdio(self) -> None:
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(read_stream, write_stream, self.server.create_initialization_options())


class _DenialAuditor:
    """ASGI wrapper that audits 401/403 answers on the MCP endpoint (incl. missing tokens)."""

    def __init__(self, app: ASGIApp, gateway: Gateway, path: str) -> None:
        self.app = app
        self.gateway = gateway
        self.path = path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") != self.path:
            await self.app(scope, receive, send)
            return

        async def watch(message: Message) -> None:
            if message["type"] == "http.response.start" and message["status"] in (401, 403):
                headers = dict(message.get("headers", []))
                challenge = headers.get(b"www-authenticate", b"").decode("latin-1")
                client = scope.get("client")
                self.gateway.stats[f"http_{message['status']}"] += 1
                self.gateway.audit.write(
                    "http_denied",
                    status=message["status"],
                    method=scope.get("method"),
                    remote=f"{client[0]}" if client else None,
                    challenge=challenge[:300] or None,
                )
            await send(message)

        await self.app(scope, receive, watch)
