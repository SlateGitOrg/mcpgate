"""Sample upstream #2: an inventory server (Streamable HTTP transport).

Run: ``python -m mcpgate.samples.inventory_server --port 9101 [--variant clean|drifted]
[--require-token-env NAME]``. With ``--require-token-env`` every request must carry
``Authorization: Bearer $NAME``, which demonstrates the gateway holding upstream credentials
that clients never see.
"""

from __future__ import annotations

import argparse
import hmac
import os
from collections.abc import Callable
from typing import Annotated, Any

import mcp_types as types
import uvicorn
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field
from starlette.types import ASGIApp, Receive, Scope, Send

from mcpgate.samples import read_variant

__all__ = ["StaticBearer", "build_server"]

SKU = Annotated[str, Field(pattern=r"^SKU-[0-9]{3}$", description="Stock keeping unit, e.g. SKU-001")]


def build_server(variant: str = "clean") -> MCPServer:
    """Create the inventory server. ``variant='drifted'`` silently loosens ``adjust_stock``."""
    server = MCPServer("sample-inventory", version="1.0.0")
    stock: dict[str, dict[str, Any]] = {
        "SKU-001": {"name": "Widget", "on_hand": 42},
        "SKU-002": {"name": "Gear", "on_hand": 7},
        "SKU-003": {"name": "Sprocket", "on_hand": 0},
    }

    @server.tool(annotations=types.ToolAnnotations(read_only_hint=True))
    def list_skus() -> list[dict[str, Any]]:
        """List every SKU with its name."""
        return [{"sku": s, "name": v["name"]} for s, v in sorted(stock.items())]

    @server.tool(annotations=types.ToolAnnotations(read_only_hint=True))
    def get_stock(sku: SKU) -> dict[str, Any]:
        """Return the on-hand quantity for one SKU."""
        if sku not in stock:
            raise ToolError(f"unknown SKU {sku}")
        return {"sku": sku, **stock[sku]}

    def _adjust(sku: str, delta: int, reason: str) -> dict[str, Any]:
        if sku not in stock:
            raise ToolError(f"unknown SKU {sku}")
        stock[sku]["on_hand"] = max(0, stock[sku]["on_hand"] + delta)
        return {"sku": sku, "on_hand": stock[sku]["on_hand"], "reason": reason}

    (_register_drifted_adjust if variant == "drifted" else _register_clean_adjust)(server, _adjust)
    return server


Adjust = Callable[[str, int, str], dict[str, Any]]
_DESTRUCTIVE = types.ToolAnnotations(destructive_hint=True)


def _register_clean_adjust(server: MCPServer, adjust: Adjust) -> None:
    @server.tool(annotations=_DESTRUCTIVE)
    def adjust_stock(
        sku: SKU,
        delta: Annotated[int, Field(ge=-100, le=100)],
        reason: Annotated[str, Field(min_length=3, max_length=200)],
    ) -> dict[str, Any]:
        """Add or remove units for a SKU (at most 100 per call); a reason is required."""
        return adjust(sku, delta, reason)


def _register_drifted_adjust(server: MCPServer, adjust: Adjust) -> None:
    @server.tool(annotations=_DESTRUCTIVE)
    def adjust_stock(sku: SKU, delta: int, reason: str = "") -> dict[str, Any]:
        """Add or remove units for a SKU."""
        return adjust(sku, delta, reason)


class StaticBearer:
    """Minimal ASGI guard: require one static bearer token (constant-time comparison)."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        self.app = app
        self.expected = f"Bearer {token}".encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            supplied = dict(scope["headers"]).get(b"authorization", b"")
            if not hmac.compare_digest(supplied, self.expected):
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [(b"content-type", b"text/plain")],
                    }
                )
                await send({"type": "http.response.body", "body": b"upstream credential required"})
                return
        await self.app(scope, receive, send)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--variant", choices=["clean", "drifted"])
    parser.add_argument("--variant-file")
    parser.add_argument("--require-token-env", help="env var holding the bearer token this server requires")
    args = parser.parse_args(argv)
    app: ASGIApp = build_server(read_variant(args.variant, args.variant_file)).streamable_http_app(
        host=args.host
    )
    if args.require_token_env:
        app = StaticBearer(app, os.environ[args.require_token_env])
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
