from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx2
import mcp_types as types
import pytest
from mcp import Client

from mcpgate.agent import (
    AssistantTurn,
    OllamaProvider,
    ScriptedProvider,
    ToolCall,
    ollama_available,
    result_text,
    run_agent,
    tools_as_functions,
)
from mcpgate.gateway import Gateway
from mcpgate.samples import inventory_server, notes_server
from tests.helpers import gateway_config, inproc

pytestmark = pytest.mark.anyio


async def test_scripted_agent_through_gateway(tmp_path: Path) -> None:
    gw = Gateway(
        gateway_config(tmp_path),
        connectors={"notes": inproc(notes_server.build_server), "inventory": inproc(inventory_server.build_server)},
    )
    provider = ScriptedProvider([
        AssistantTurn(tool_calls=(ToolCall("inventory__get_stock", {"sku": "SKU-002"}),)),
        AssistantTurn(tool_calls=(
            ToolCall("notes__add_note", {"title": "Reorder SKU-002", "body": "7 on hand"}),
            ToolCall("inventory__adjust_stock", {"sku": "SKU-002", "delta": 50, "reason": "reorder"}),
        )),
    ], final="Stock is low; I saved a note. I may not adjust stock.")
    seen: list[str] = []
    async with gw.running(), Client(gw.server, cache=None) as client:
        transcript = await run_agent(client, provider, "check SKU-002", on_step=lambda s: seen.append(s.call.name))
    assert transcript.provider == "scripted"
    assert [s.is_error for s in transcript.steps] == [False, False, True]
    assert "not found or not permitted" in transcript.steps[2].output
    assert json.loads(transcript.steps[0].output)["on_hand"] == 7
    assert transcript.answer.startswith("Stock is low")
    assert seen == ["inventory__get_stock", "notes__add_note", "inventory__adjust_stock"]


async def test_step_budget_and_default_final(tmp_path: Path) -> None:
    gw = Gateway(
        gateway_config(tmp_path),
        connectors={"notes": inproc(notes_server.build_server), "inventory": inproc(inventory_server.build_server)},
    )
    loop = [AssistantTurn(tool_calls=(ToolCall("notes__list_notes", {}),)) for _ in range(5)]
    async with gw.running(), Client(gw.server, cache=None) as client:
        capped = await run_agent(client, ScriptedProvider(loop), "loop", max_steps=2)
        assert capped.stopped_reason.startswith("step budget")
        assert len(capped.steps) == 2
        summary = await run_agent(client, ScriptedProvider([AssistantTurn(tool_calls=(
            ToolCall("notes__list_notes", {}),))]), "once")
        assert summary.answer.startswith("Done. Tool outputs:")


def test_result_text_and_function_specs() -> None:
    text = types.CallToolResult(content=[types.TextContent(type="text", text="a" * 3000)])
    assert result_text(text).endswith("...[truncated]")
    structured = types.CallToolResult(content=[], structured_content={"b": 1, "a": 2})
    assert result_text(structured) == '{"a": 2, "b": 1}'
    spec = tools_as_functions([types.Tool(name="x", input_schema={"type": "object"})])
    assert spec == [{"type": "function", "function": {"name": "x", "description": "",
                                                      "parameters": {"type": "object"}}}]


def ollama_transport(reply: dict[str, Any], captured: list[dict[str, Any]]) -> httpx2.MockTransport:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/api/tags":
            return httpx2.Response(200, json={"models": [{"name": "llama3.1:8b"}]})
        captured.append(json.loads(request.content))
        return httpx2.Response(200, json={"message": reply})

    return httpx2.MockTransport(handler)


async def test_ollama_provider_parses_tool_calls() -> None:
    captured: list[dict[str, Any]] = []
    reply = {"role": "assistant", "content": "", "tool_calls": [
        {"function": {"name": "inventory__get_stock", "arguments": {"sku": "SKU-001"}}},
        {"function": {"name": "notes__add_note", "arguments": '{"title": "t", "body": "b"}'}},
        {"function": {"name": "x", "arguments": "{bad json"}},
        {"function": {"arguments": {}}},
    ]}
    provider = OllamaProvider(transport=ollama_transport(reply, captured))
    turn = await provider.chat([{"role": "user", "content": "hi"}], [{"type": "function"}])
    assert [c.name for c in turn.tool_calls] == ["inventory__get_stock", "notes__add_note", "x"]
    assert turn.tool_calls[1].arguments == {"title": "t", "body": "b"}
    assert turn.tool_calls[2].arguments == {"_unparseable": "{bad json"}
    assert captured[0]["options"] == {"temperature": 0, "seed": 7}
    assert captured[0]["stream"] is False
    assert provider.name == "ollama:llama3.1:8b"


async def test_ollama_availability_probe() -> None:
    assert await ollama_available(transport=ollama_transport({}, []))
    assert not await ollama_available("other:1b", transport=ollama_transport({}, []))

    def down(_: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("refused")

    assert not await ollama_available(transport=httpx2.MockTransport(down))
