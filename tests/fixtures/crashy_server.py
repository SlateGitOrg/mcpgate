"""Test-only stdio MCP server whose `die` tool kills the process (to exercise reconnects)."""

from __future__ import annotations

import os

from mcp.server import MCPServer

server = MCPServer("crashy")


@server.tool()
def ping() -> str:
    """Answer pong with this process id."""
    return f"pong from {os.getpid()}"


@server.tool()
def die() -> str:
    """Terminate the server process abruptly."""
    os._exit(3)


if __name__ == "__main__":
    server.run("stdio")
