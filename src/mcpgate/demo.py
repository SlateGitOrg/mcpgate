"""End-to-end demo: ``make demo`` (offline; everything runs on 127.0.0.1).

It starts the two bundled sample MCP servers (inventory over Streamable HTTP, notes over
stdio), puts mcpgate in front of them on a real socket with JWT auth, and then walks through:
authentication failures, per-client catalogs, an LLM agent working through the gateway,
argument validation and rate limits, a tool-definition "rug pull" being caught, and audit-log
verification. The agent uses the local Ollama model when it is reachable (``--provider auto``)
and otherwise a deterministic scripted agent; the output says which one ran.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import anyio
import httpx2
from mcp.shared.exceptions import MCPError

from mcpgate.agent import (
    AgentStep,
    AssistantTurn,
    ChatProvider,
    OllamaProvider,
    ScriptedProvider,
    ToolCall,
    ollama_available,
    result_text,
    run_agent,
)
from mcpgate.audit import verify_chain
from mcpgate.client import connect_gateway
from mcpgate.config import GatewayConfig, parse_config
from mcpgate.devissuer import DevIssuer, generate_keys
from mcpgate.gateway import Gateway

ISSUER = "https://issuer.demo.test"
UPSTREAM_SECRET = "demo-upstream-credential"
TASK = (
    "Check how many units of SKU-002 are on hand. If it is fewer than 20, save a note titled "
    "'Reorder SKU-002' that states the current level, then increase the stock of SKU-002 by 50 "
    "units with reason 'reorder'. Report what you did."
)


def say(text: str = "") -> None:
    print(text, flush=True)


def section(title: str) -> None:
    say()
    say(f"== {title} " + "=" * max(0, 72 - len(title)))


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_port(port: int, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise TimeoutError(f"port {port} did not open")


@contextmanager
def inventory_upstream(port: int) -> Iterator[subprocess.Popen[bytes]]:
    env = {**os.environ, "INVENTORY_TOKEN": UPSTREAM_SECRET}
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "mcpgate.samples.inventory_server",
            "--port",
            str(port),
            "--require-token-env",
            "INVENTORY_TOKEN",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_port(port)
        yield proc
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def build_config(work: Path, gateway_port: int, inventory_port: int) -> GatewayConfig:
    return parse_config(
        {
            "refresh_interval_s": 0,
            "listen": {"host": "127.0.0.1", "port": gateway_port},
            "auth": {"issuer": ISSUER, "jwks_file": "keys/jwks.json"},
            "upstreams": [
                {
                    "name": "notes",
                    "transport": "stdio",
                    "command": "${PYTHON}",
                    "args": ["-m", "mcpgate.samples.notes_server", "--variant-file", "notes.variant"],
                },
                {
                    "name": "inventory",
                    "transport": "http",
                    "url": f"http://127.0.0.1:{inventory_port}/mcp",
                    "headers": {"Authorization": "Bearer ${INVENTORY_TOKEN}"},
                },
            ],
            "policy": {
                "roles": {
                    "analyst": {
                        "allow": ["inventory__get_*", "inventory__list_*", "notes__*"],
                        "deny": ["notes__delete_*"],
                    },
                    "operator": {"allow": ["*"]},
                },
                "clients": {"agent-analyst": {"roles": ["analyst"]}, "agent-ops": {"roles": ["operator"]}},
            },
            "rate_limits": {
                "per_client": {"rate": 20, "burst": 40},
                "per_tool": {"inventory__list_*": {"rate": 0.5, "burst": 3}},
            },
            "pinning": {"store": "var/pins.json"},
            "audit": {"path": "var/audit.jsonl", "arguments": "redacted"},
        },
        work,
        env={"INVENTORY_TOKEN": UPSTREAM_SECRET},
    )


def short(text: str, limit: int = 110) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


async def demo_auth(gw: Gateway, url: str, signer: DevIssuer) -> None:
    section("1. OAuth 2.1 bearer validation (local JWKS)")
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    accept = {"accept": "application/json, text/event-stream"}
    cases = [
        ("no token", None),
        (
            "token minted for a different MCP server",
            signer.mint(issuer=ISSUER, audience="http://other-server.test/mcp", client_id="agent-analyst"),
        ),
        ("expired token", signer.mint(issuer=ISSUER, audience=url, client_id="agent-analyst", ttl_s=-600)),
        (
            "token without the mcp:tools scope",
            signer.mint(issuer=ISSUER, audience=url, client_id="agent-analyst", scopes=["profile"]),
        ),
    ]
    async with httpx2.AsyncClient() as http:
        for label, token in cases:
            headers = dict(accept)
            if token:
                headers["authorization"] = f"Bearer {token}"
            response = await http.post(url, json=body, headers=headers)
            challenge = response.headers.get("www-authenticate", "")
            error = challenge.split('error="')[1].split('"')[0] if 'error="' in challenge else "-"
            say(f"  {label:<42} -> HTTP {response.status_code} ({error})")
        meta = (await http.get(url.replace("/mcp", "/.well-known/oauth-protected-resource/mcp"))).json()
        servers = meta["authorization_servers"]
        say(f"  RFC 9728 metadata: resource={meta['resource']} authorization_servers={servers}")
    records = [json.loads(line) for line in gw.audit.path.read_text().splitlines()]
    reasons = [r["reason"] for r in records if r["event"] == "auth_rejected"]
    say(f"  audited verifier reasons: {', '.join(reasons)}")


async def demo_catalogs(url: str, tokens: dict[str, str]) -> None:
    section("2. One gateway, per-client catalogs (RBAC)")
    for client_id, token in tokens.items():
        async with connect_gateway(url, token) as client:
            names = [t.name for t in (await client.list_tools()).tools]
        say(f"  {client_id:<14} sees {len(names)} tools: {', '.join(names)}")


def scripted_agent() -> ScriptedProvider:
    return ScriptedProvider(
        [
            AssistantTurn(tool_calls=(ToolCall("inventory__get_stock", {"sku": "SKU-002"}),)),
            AssistantTurn(
                tool_calls=(
                    ToolCall(
                        "notes__add_note",
                        {"title": "Reorder SKU-002", "body": "SKU-002 (Gear) has 7 units on hand."},
                    ),
                    ToolCall("inventory__adjust_stock", {"sku": "SKU-002", "delta": 50, "reason": "reorder"}),
                )
            ),
        ],
        final="SKU-002 has 7 units on hand, so I saved the note 'Reorder SKU-002'. "
        "Adjusting the stock was refused: that tool is not available to me.",
    )


async def demo_agent(gw: Gateway, url: str, token: str, provider: ChatProvider) -> None:
    section(f"3. LLM agent through the gateway (provider: {provider.name}, client: agent-analyst)")
    say(f"  task: {short(TASK, 200)}")

    def show(step: AgentStep) -> None:
        verdict = "refused" if step.is_error else "ok"
        say(f"  -> {step.call.name} {json.dumps(step.call.arguments, sort_keys=True)}")
        say(f"     {verdict}: {short(step.output.removeprefix('error: '))}")

    started = time.monotonic()
    async with connect_gateway(url, token) as client:
        transcript = await run_agent(client, provider, TASK, max_steps=6, on_step=show)
    answer = short(transcript.answer or transcript.stopped_reason, 300)
    say(f"  answer ({time.monotonic() - started:.1f}s): {answer}")
    # The agent's narrative is not evidence; the gateway's audit log is.
    records = [json.loads(line) for line in gw.audit.path.read_text().splitlines()]
    calls = [r for r in records if r["event"] == "tool_call" and r["client_id"] == "agent-analyst"]
    summary = ", ".join(f"{r['tool']}={r['decision']}" for r in calls)
    say(f"  audit ground truth for agent-analyst: {summary}")
    say(
        f"  stock-changing calls that reached the inventory server: "
        f"{sum(r['tool'] == 'inventory__adjust_stock' and r['decision'] == 'allowed' for r in calls)}"
    )


async def demo_guardrails(url: str, tokens: dict[str, str], inventory_port: int) -> None:
    section("4. Guardrails: RBAC, schema validation, rate limits, credential isolation")
    async with connect_gateway(url, tokens["agent-analyst"]) as client:
        try:
            await client.call_tool(
                "inventory__adjust_stock", {"sku": "SKU-002", "delta": 50, "reason": "reorder"}
            )
            outcome = "allowed (unexpected)"
        except MCPError as exc:
            outcome = f"JSON-RPC error {exc.code}: {exc.message}"
        say(f"  agent-analyst calls hidden inventory__adjust_stock -> {outcome}")
    async with connect_gateway(url, tokens["agent-ops"]) as client:
        bad = await client.call_tool(
            "inventory__adjust_stock", {"sku": "SKU-001; DROP TABLE stock", "delta": 100000, "reason": "x"}
        )
        say(f"  malformed arguments  -> {short(result_text(bad), 160)}")
        outcomes = []
        for _ in range(5):
            result = await client.call_tool("inventory__list_skus", {})
            meta = (result.meta or {}).get("io.github.mcpgate/decision", {})
            outcomes.append(meta.get("decision", "allowed"))
        say(f"  5 rapid list_skus    -> {', '.join(outcomes)}  (rule inventory__list_*: burst 3, 0.5/s)")
    async with httpx2.AsyncClient() as http:
        direct = await http.post(
            f"http://127.0.0.1:{inventory_port}/mcp",
            json={},
            headers={"authorization": f"Bearer {tokens['agent-ops']}"},
        )
    say(
        f"  client token sent straight to the upstream -> HTTP {direct.status_code} "
        "(only the gateway holds the upstream credential; no token passthrough)"
    )


async def demo_rug_pull(gw: Gateway, url: str, token: str, variant_file: Path) -> None:
    section("5. Tool-definition pinning: an upstream 'rug pull'")
    upstream = gw.upstreams["notes"]
    before = upstream.connects
    variant_file.write_text("poisoned\n")
    upstream.request_reconnect()  # e.g. the notes server was upgraded and restarted
    with anyio.fail_after(30):
        while not (upstream.connects > before and upstream.state == "ready"):
            await anyio.sleep(0.05)
    say("  notes server restarted with a modified search_notes definition")
    for alert in list(gw.alerts):
        if alert["event"] == "pin_alert":
            detail = alert.get("detail", {})
            say(
                f"  ALERT {alert['kind']} {alert['upstream']}/{alert['tool']} "
                f"fields={detail.get('changed_fields')}"
            )
            for line in detail.get("description_diff", [])[3:]:
                say(f"      {short(line, 104)}")
            for line in detail.get("inputSchema_diff", []):
                say(f"      inputSchema {line}")
        elif alert["event"] == "tool_lint" and alert["tool"] == "search_notes":
            rules = sorted({f["rule"] for f in alert["findings"]})
            say(f"  LINT  {alert['severity']}: {', '.join(rules)}")
    async with connect_gateway(url, token) as client:
        names = [t.name for t in (await client.list_tools()).tools]
        say(f"  agent-analyst catalog now: {', '.join(names)}")
        blocked = await client.call_tool("notes__search_notes", {"query": "restock"})
        say(f"  call notes__search_notes -> {short(result_text(blocked), 150)}")
        variant_file.write_text("clean\n")
        before = upstream.connects
        upstream.request_reconnect()
        with anyio.fail_after(30):
            while not (upstream.connects > before and upstream.state == "ready"):
                await anyio.sleep(0.05)
        again = await client.call_tool("notes__search_notes", {"query": "restock"})
        say(f"  upstream reverted to the pinned definition -> served again: {short(result_text(again), 90)}")


def demo_audit(gw: Gateway, work: Path) -> None:
    section("6. Tamper-evident audit log")
    report = verify_chain(gw.audit.path)
    say(
        f"  {report.records} records, chain {'intact' if report.ok else 'BROKEN'}, head {report.head[:16]}..."
    )
    records = [json.loads(line) for line in gw.audit.path.read_text().splitlines()]
    events = Counter(r["event"] for r in records)
    decisions = Counter(r["decision"] for r in records if r["event"] == "tool_call")
    say(f"  events:    {dict(sorted(events.items()))}")
    say(f"  decisions: {dict(sorted(decisions.items()))}")
    sample = next(r for r in records if r["event"] == "tool_call" and r["decision"] == "denied_policy")
    shown = {k: sample.get(k) for k in ("seq", "client_id", "tool", "decision", "reason")}
    say("  e.g. " + short(json.dumps(shown), 160))
    tampered = work / "tampered.jsonl"
    lines = gw.audit.path.read_text().splitlines()
    index = next(i for i, r in enumerate(records) if r.get("decision") == "denied_policy")
    lines[index] = lines[index].replace('"denied_policy"', '"allowed"')
    tampered.write_text("\n".join(lines) + "\n")
    broken = verify_chain(tampered)
    say(f"  copy with one decision rewritten to 'allowed' -> FAILED at line {broken.line}: {broken.error}")


async def pick_provider(choice: str) -> ChatProvider:
    if choice == "scripted":
        return scripted_agent()
    if await ollama_available():
        return OllamaProvider()
    if choice == "ollama":
        raise SystemExit("Ollama with llama3.1:8b is not reachable on 127.0.0.1:11434")
    say("  (Ollama not reachable: using the deterministic scripted agent)")
    return scripted_agent()


async def run_sections(
    gw: Gateway, signer: DevIssuer, provider_choice: str, inventory_port: int, work: Path
) -> None:
    url = gw.config.listen.resource_url
    tokens = {
        cid: signer.mint(issuer=ISSUER, audience=url, client_id=cid) for cid in ("agent-analyst", "agent-ops")
    }
    say(f"  gateway      {url}  (JWT ES256, kid demo-1, issuer {ISSUER})")
    say(f"  upstream     inventory  streamable-http  127.0.0.1:{inventory_port} (needs a credential)")
    say("  upstream     notes      stdio            python -m mcpgate.samples.notes_server")
    say(f"  catalog      {len(gw.catalog)} tools pinned on first use -> {gw.config.pinning.store.name}")
    provider = await pick_provider(provider_choice)
    await demo_auth(gw, url, signer)
    await demo_catalogs(url, tokens)
    await demo_agent(gw, url, tokens["agent-analyst"], provider)
    await demo_guardrails(url, tokens, inventory_port)
    await demo_rug_pull(gw, url, tokens["agent-analyst"], work / "notes.variant")


async def main_async(provider_choice: str) -> None:
    work = Path(tempfile.mkdtemp(prefix="mcpgate-demo-"))
    try:
        signer = generate_keys(work / "keys", kid="demo-1")
        (work / "notes.variant").write_text("clean\n")
        gateway_port, inventory_port = free_port(), free_port()
        cfg = build_config(work, gateway_port, inventory_port)
        section("setup")
        with inventory_upstream(inventory_port):
            gw = Gateway(cfg)
            async with gw.running():
                stop, ready = anyio.Event(), anyio.Event()
                async with anyio.create_task_group() as tg:
                    tg.start_soon(lambda: gw.serve_http(ready=ready, stop=stop))
                    await ready.wait()
                    try:
                        await run_sections(gw, signer, provider_choice, inventory_port, work)
                    finally:
                        stop.set()
            demo_audit(gw, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    say()
    say("demo finished; all state lived in a temporary directory that has been removed")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=["auto", "ollama", "scripted"], default="auto")
    parser.add_argument("--require-ollama", action="store_true", help="same as --provider ollama")
    args = parser.parse_args(argv)
    choice = "ollama" if args.require_ollama else args.provider
    logging.basicConfig(level=logging.ERROR, format="%(levelname)s %(name)s: %(message)s")
    anyio.run(main_async, choice)


if __name__ == "__main__":
    main()
