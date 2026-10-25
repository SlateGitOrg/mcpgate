from __future__ import annotations

import mcp_types as types

from mcpgate.catalog import META_PIN, META_UPSTREAM, Catalog, decode_cursor, encode_cursor


def tool(name: str) -> types.Tool:
    return types.Tool(name=name, input_schema={"type": "object"}, _meta={"upstream-own": 1})


def test_namespacing_and_split() -> None:
    cat = Catalog()
    assert cat.update("notes", [tool("add_note"), tool("weird__name")]) == []
    entry = cat.get("notes__weird__name")
    assert entry is not None
    assert (entry.upstream, entry.original) == ("notes", "weird__name")
    assert cat.split("notes__weird__name") == ("notes", "weird__name")
    assert cat.split("nosep") is None
    assert cat.split("__x") is None
    exposed = entry.exposed()
    assert exposed.name == "notes__weird__name"
    assert exposed.meta is not None
    assert exposed.meta[META_UPSTREAM] == "notes"
    assert exposed.meta[META_PIN] == entry.fingerprint.digest
    assert exposed.meta["upstream-own"] == 1
    assert entry.input_schema == {"type": "object"}


def test_invalid_and_duplicate_names_are_refused() -> None:
    cat = Catalog()
    warnings = cat.update("notes", [tool("ok"), tool("ok"), tool("has space"), tool("x" * 130)])
    assert len(warnings) == 3
    assert [e.name for e in cat.entries()] == ["notes__ok"]


def test_update_replaces_and_drop_removes() -> None:
    cat = Catalog(separator=".")
    cat.update("a", [tool("one"), tool("two")])
    cat.update("b", [tool("three")])
    cat.update("a", [tool("two")])
    assert [e.name for e in cat.entries()] == ["a.two", "b.three"]
    assert [e.name for e in cat.entries("a")] == ["a.two"]
    assert cat.names_outside("a") == ["three"]
    assert set(cat.fingerprints("a")) == {"two"}
    cat.drop("a")
    assert len(cat) == 1
    assert cat.get("a.two") is None


def test_cursor_roundtrip_and_garbage() -> None:
    assert decode_cursor(encode_cursor(42)) == 42
    assert decode_cursor(None) == 0
    assert decode_cursor("!!!") is None
    assert decode_cursor("eDox") is None  # "x:1"
    assert decode_cursor("_w") is None  # invalid utf-8
