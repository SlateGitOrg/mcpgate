"""A minimal tool-using LLM agent that reaches its tools *through* the gateway.

The agent is deliberately small: it lists the tools the gateway lets it see, offers them to a
chat model as functions, executes the model's tool calls via MCP, and feeds the results back
until the model answers in plain text or the step budget runs out. Everything security-related
happens in the gateway, which is the point of the demo: the agent cannot call a tool it was not
granted, cannot see quarantined tools, and every attempt is audited.

Two providers implement :class:`ChatProvider`:

* :class:`OllamaProvider` -- a local model via Ollama's ``/api/chat`` (tool calling);
* :class:`ScriptedProvider` -- a deterministic, model-free stand-in for tests and for running
  the demo on machines without Ollama.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx2
import mcp_types as types
from mcp import Client
from mcp.shared.exceptions import MCPError

__all__ = [
    "AgentStep",
    "AgentTranscript",
    "AssistantTurn",
    "ChatProvider",
    "OllamaProvider",
    "ScriptedProvider",
    "ToolCall",
    "ollama_available",
    "result_text",
    "run_agent",
    "tools_as_functions",
]

logger = logging.getLogger(__name__)

Message = dict[str, Any]


@dataclass(frozen=True, slots=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True, slots=True)
class AssistantTurn:
    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()


class ChatProvider(Protocol):
    name: str

    async def chat(self, messages: Sequence[Message], tools: Sequence[dict[str, Any]]) -> AssistantTurn: ...


@dataclass(slots=True)
class AgentStep:
    call: ToolCall
    output: str
    is_error: bool


@dataclass(slots=True)
class AgentTranscript:
    provider: str
    steps: list[AgentStep] = field(default_factory=list)
    answer: str = ""
    stopped_reason: str = "answered"


def tools_as_functions(tools: Sequence[types.Tool]) -> list[dict[str, Any]]:
    """MCP tool definitions -> OpenAI/Ollama-style function specs."""
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.input_schema,
            },
        }
        for t in tools
    ]


def result_text(result: types.CallToolResult, limit: int = 2000) -> str:
    """Flatten a tool result for the model: structured content wins, else joined text blocks."""
    if result.structured_content is not None:
        text = json.dumps(result.structured_content, ensure_ascii=False, sort_keys=True)
    else:
        text = "\n".join(c.text for c in result.content if isinstance(c, types.TextContent))
    return text if len(text) <= limit else text[:limit] + " ...[truncated]"


async def run_agent(
    client: Client,
    provider: ChatProvider,
    task: str,
    *,
    system: str = "You are an operations assistant. Use the provided tools; never invent tool results.",
    max_steps: int = 8,
    on_step: Callable[[AgentStep], None] | None = None,
) -> AgentTranscript:
    """Run one task to completion (or until ``max_steps`` tool calls were made)."""
    listing = await client.list_tools()
    functions = tools_as_functions(listing.tools)
    messages: list[Message] = [{"role": "system", "content": system}, {"role": "user", "content": task}]
    transcript = AgentTranscript(provider=provider.name)
    while True:
        turn = await provider.chat(messages, functions)
        if not turn.tool_calls:
            transcript.answer = turn.content.strip()
            return transcript
        messages.append(
            {
                "role": "assistant",
                "content": turn.content,
                "tool_calls": [{"function": {"name": c.name, "arguments": c.arguments}} for c in turn.tool_calls],
            }
        )
        for call in turn.tool_calls:
            if len(transcript.steps) >= max_steps:
                transcript.stopped_reason = f"step budget of {max_steps} tool calls exhausted"
                transcript.answer = turn.content.strip()
                return transcript
            logger.debug("agent calls %s", call.name)
            try:
                result = await client.call_tool(call.name, call.arguments)
                step = AgentStep(call, result_text(result), bool(result.is_error))
            except MCPError as exc:
                step = AgentStep(call, f"error: {exc.message}", True)
            transcript.steps.append(step)
            if on_step is not None:
                on_step(step)
            messages.append({"role": "tool", "content": step.output, "tool_name": call.name})


class ScriptedProvider:
    """Replays a fixed list of turns; once exhausted, answers with a summary of tool outputs."""

    name = "scripted"

    def __init__(self, turns: Sequence[AssistantTurn], final: str | None = None) -> None:
        self._turns = list(turns)
        self._final = final

    async def chat(self, messages: Sequence[Message], tools: Sequence[dict[str, Any]]) -> AssistantTurn:
        # A script may name tools it was never shown; the gateway, not the agent, must refuse them.
        if self._turns:
            return self._turns.pop(0)
        if self._final is not None:
            return AssistantTurn(content=self._final)
        outputs = [m["content"] for m in messages if m.get("role") == "tool"]
        return AssistantTurn(content="Done. Tool outputs: " + " | ".join(outputs))


class OllamaProvider:
    """Chat via a local Ollama server's ``/api/chat`` endpoint with tool calling."""

    def __init__(
        self,
        model: str = "llama3.1:8b",
        base_url: str = "http://127.0.0.1:11434",
        *,
        timeout_s: float = 180.0,
        seed: int = 7,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self.model = model
        self.name = f"ollama:{model}"
        self._base = base_url.rstrip("/")
        self._timeout = timeout_s
        self._seed = seed
        self._transport = transport

    async def chat(self, messages: Sequence[Message], tools: Sequence[dict[str, Any]]) -> AssistantTurn:
        payload = {
            "model": self.model,
            "messages": list(messages),
            "tools": list(tools),
            "stream": False,
            "options": {"temperature": 0, "seed": self._seed},
        }
        async with httpx2.AsyncClient(timeout=self._timeout, transport=self._transport) as http:
            response = await http.post(f"{self._base}/api/chat", json=payload)
            response.raise_for_status()
            message = response.json().get("message", {})
        calls: list[ToolCall] = []
        for raw in message.get("tool_calls") or []:
            fn = raw.get("function", {})
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except ValueError:
                    args = {"_unparseable": args}
            if isinstance(fn.get("name"), str):
                calls.append(ToolCall(fn["name"], args if isinstance(args, dict) else {}))
        return AssistantTurn(content=str(message.get("content") or ""), tool_calls=tuple(calls))


async def ollama_available(
    model: str = "llama3.1:8b",
    base_url: str = "http://127.0.0.1:11434",
    *,
    transport: httpx2.AsyncBaseTransport | None = None,
) -> bool:
    """True if Ollama answers and has ``model`` pulled (never pulls anything)."""
    try:
        async with httpx2.AsyncClient(timeout=3.0, transport=transport) as http:
            response = await http.get(f"{base_url.rstrip('/')}/api/tags")
            response.raise_for_status()
            names = {m.get("name") for m in response.json().get("models", [])}
    except (httpx2.HTTPError, ValueError):
        return False
    return model in names
