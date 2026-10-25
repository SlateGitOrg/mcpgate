from __future__ import annotations

import urllib.request
from typing import Any

import pytest

from mcpgate.config import LimitsConfig
from mcpgate.validation import ArgumentValidator

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "sku": {"type": "string", "pattern": "^SKU-[0-9]{3}$"},
        "delta": {"type": "integer", "minimum": -100, "maximum": 100},
        "when": {"type": "string", "format": "date"},
        "tags": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["sku", "delta"],
    "additionalProperties": False,
}


def v(**limits: Any) -> ArgumentValidator:
    return ArgumentValidator(LimitsConfig(**limits))


def test_valid_arguments_pass() -> None:
    out = v().validate("k", SCHEMA, {"sku": "SKU-001", "delta": 5, "tags": ["a"]})
    assert out.ok
    assert out.size_bytes > 0


def test_errors_do_not_echo_values() -> None:
    secret = "hunter2-very-secret"
    out = v().validate("k", SCHEMA, {"sku": secret, "delta": 500, "extra": secret})
    assert not out.ok
    text = out.summary()
    assert secret not in text
    paths = {i.path for i in out.issues}
    assert {"$", "$.sku", "$.delta"} <= paths
    assert "unexpected properties ['extra']" in text


def test_required_and_format() -> None:
    out = v().validate("k", SCHEMA, {"delta": 1})
    assert out.issues[0].message == "missing required properties ['sku']"
    out = v().validate("k", SCHEMA, {"sku": "SKU-001", "delta": 1, "when": "not-a-date"})
    assert [i.keyword for i in out.issues] == ["format"]
    assert v(assert_formats=False).validate("k2", SCHEMA, {"sku": "SKU-001", "delta": 1, "when": "x"}).ok


def test_size_and_depth_limits() -> None:
    big = {"sku": "SKU-001", "delta": 1, "tags": ["x" * 200]}
    assert v(max_argument_bytes=100).validate("k", SCHEMA, big).issues[0].keyword == "size"
    nested: Any = "leaf"
    for _ in range(40):
        nested = [nested]
    out = v(max_argument_depth=32).validate("k", {"type": "object"}, {"deep": nested})
    assert out.issues[0].keyword == "depth"


def test_invalid_schema_and_non_json() -> None:
    validator = v()
    bad = {"type": "object", "properties": {"x": {"type": "nonsense"}}}
    assert validator.schema_error("bad", bad) is not None
    assert validator.validate("bad", bad, {}).issues[0].keyword == "schema"
    assert validator.schema_error("k", SCHEMA) is None
    assert validator.validate("k", SCHEMA, {"sku": float("nan")}).issues[0].keyword == "json"


def test_remote_refs_are_never_fetched(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: object, **__: object) -> None:
        raise AssertionError("validator attempted a network fetch")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    schema = {"type": "object", "properties": {"x": {"$ref": "http://127.0.0.1:9/evil.json"}}}
    out = v().validate("r", schema, {"x": 1})
    assert not out.ok
    assert out.issues[0].keyword == "$ref"


def test_local_refs_and_draft_selection() -> None:
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "definitions": {"n": {"type": "integer"}},
        "properties": {"x": {"$ref": "#/definitions/n"}},
    }
    assert v().validate("d7", schema, {"x": 1}).ok
    assert not v().validate("d7b", schema, {"x": "1"}).ok


def test_issue_cap_and_generic_keywords() -> None:
    schema = {"type": "object", "properties": {f"p{i}": {"type": "integer"} for i in range(10)}}
    out = v().validate("cap", schema, {f"p{i}": "x" for i in range(10)})
    assert len(out.issues) == 5
    one_of = {"type": "object", "properties": {"x": {"oneOf": [{"type": "integer"}, {"type": "boolean"}]}}}
    assert v().validate("o", one_of, {"x": "s"}).issues[0].message == "violates 'oneOf'"
    long_enum = {"type": "object", "properties": {"x": {"enum": [f"value-{i}" for i in range(50)]}}}
    assert v().validate("e", long_enum, {"x": "s"}).issues[0].message.endswith("...)")


def test_cache_is_bounded() -> None:
    validator = v()
    for i in range(4100):
        validator.compile(f"k{i}", {"type": "object"})
    assert len(validator._cache) <= 4097
