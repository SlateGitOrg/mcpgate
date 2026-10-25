"""The aggregated, namespaced tool catalog.

Each upstream's tools are exposed as ``<upstream><sep><tool>`` (default separator ``__``,
because many model APIs reject ``.`` and ``/`` in function names). Upstream names are
restricted to ``[a-z][a-z0-9-]*`` and may not contain the separator, so splitting a namespaced
name at the *first* separator is unambiguous even when the upstream's own tool name contains
the separator. Two upstreams therefore can never shadow each other's tools -- the classic
"tool name collision" attack on multi-server MCP clients is structurally impossible here.

Names that would exceed the SEP-986 limits (128 chars of ``[A-Za-z0-9._-]``) are refused
rather than truncated, and duplicate names inside one upstream listing keep only the first.
"""

from __future__ import annotations

import base64
import binascii
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import mcp_types as types
from mcp.shared.tool_name_validation import TOOL_NAME_REGEX

from mcpgate.fingerprint import Fingerprint, fingerprint

__all__ = ["Catalog", "CatalogEntry", "decode_cursor", "encode_cursor"]

logger = logging.getLogger(__name__)

META_UPSTREAM = "io.github.mcpgate/upstream"
META_PIN = "io.github.mcpgate/pin"


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    name: str
    """Namespaced name exposed to clients."""
    upstream: str
    original: str
    tool: types.Tool
    """The definition exactly as the upstream advertised it."""
    fingerprint: Fingerprint

    def exposed(self) -> types.Tool:
        """The definition as clients see it: renamed, annotated with provenance in ``_meta``."""
        meta = dict(self.tool.meta or {})
        meta[META_UPSTREAM] = self.upstream
        meta[META_PIN] = self.fingerprint.digest
        return self.tool.model_copy(update={"name": self.name, "meta": meta})

    @property
    def input_schema(self) -> Mapping[str, Any]:
        return self.tool.input_schema


class Catalog:
    """Holds the latest tool listing of every upstream, keyed by namespaced name."""

    def __init__(self, separator: str = "__") -> None:
        self.separator = separator
        self._by_upstream: dict[str, dict[str, CatalogEntry]] = {}
        self._index: dict[str, CatalogEntry] = {}

    def namespaced(self, upstream: str, tool: str) -> str:
        return f"{upstream}{self.separator}{tool}"

    def split(self, name: str) -> tuple[str, str] | None:
        upstream, sep, tool = name.partition(self.separator)
        return (upstream, tool) if sep and upstream and tool else None

    def update(self, upstream: str, tools: Iterable[types.Tool]) -> list[str]:
        """Replace ``upstream``'s listing. Returns warnings for tools that were refused."""
        warnings: list[str] = []
        entries: dict[str, CatalogEntry] = {}
        for tool in tools:
            name = self.namespaced(upstream, tool.name)
            if not TOOL_NAME_REGEX.fullmatch(name):
                warnings.append(f"refused tool {tool.name!r}: namespaced name {name!r} violates SEP-986")
                continue
            if tool.name in entries:
                warnings.append(f"refused duplicate tool {tool.name!r} from upstream {upstream!r}")
                continue
            entries[tool.name] = CatalogEntry(name, upstream, tool.name, tool, fingerprint(tool))
        for old in self._by_upstream.get(upstream, {}).values():
            self._index.pop(old.name, None)
        self._by_upstream[upstream] = entries
        for entry in entries.values():
            self._index[entry.name] = entry
        for message in warnings:
            logger.warning(message)
        return warnings

    def drop(self, upstream: str) -> None:
        for old in self._by_upstream.pop(upstream, {}).values():
            self._index.pop(old.name, None)

    def get(self, name: str) -> CatalogEntry | None:
        return self._index.get(name)

    def entries(self, upstream: str | None = None) -> list[CatalogEntry]:
        if upstream is not None:
            return sorted(self._by_upstream.get(upstream, {}).values(), key=lambda e: e.name)
        return sorted(self._index.values(), key=lambda e: e.name)

    def fingerprints(self, upstream: str) -> dict[str, Fingerprint]:
        return {e.original: e.fingerprint for e in self._by_upstream.get(upstream, {}).values()}

    def names_outside(self, upstream: str) -> list[str]:
        """Original tool names of every *other* upstream (for cross-tool reference linting)."""
        return [
            e.original for up, tools in self._by_upstream.items() if up != upstream for e in tools.values()
        ]

    def __len__(self) -> int:
        return len(self._index)


def encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(f"o:{offset}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> int | None:
    """Offset encoded in an opaque cursor; ``None`` if the cursor is malformed."""
    if cursor is None:
        return 0
    try:
        text = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if not text.startswith("o:") or not text[2:].isdigit():
        return None
    return int(text[2:])
