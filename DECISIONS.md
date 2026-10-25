# Decisions

Rulings made while building mcpgate, in the format
`- Ruling: <what> — <why> — <cost if wrong>`.

- Ruling: target the official `mcp` Python SDK 2.3.x (v2 API: `mcp.Client`, low-level `Server(on_list_tools=..., on_call_tool=...)`, `TokenVerifier`) and pin `<2.4` — the brief demands the official SDK and v2 is current; v2 serves both the 2025-11-25 handshake era and the 2026-07-28 stateless era from one server object — an SDK minor bump may move provisional APIs (the SDK marks middleware/context as provisional), so the pin must be raised deliberately.
