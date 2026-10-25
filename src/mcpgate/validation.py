"""Argument validation against each tool's (pinned) input schema.

The gateway validates ``tools/call`` arguments *before* they reach an upstream, so a malformed
or oversized payload produced by a confused or manipulated model is stopped at the edge.

* Size and nesting depth are capped first, in one linear pass, so an adversarial payload
  cannot make schema validation itself expensive.
* Schemas are compiled once per pin digest and cached; the validator class follows the
  schema's ``$schema`` (Draft 2020-12 when absent, as MCP specifies).
* Remote ``$ref`` resolution is impossible. jsonschema's *default* registry still fetches
  unknown ``$ref`` URLs with ``urlopen`` (deprecated, but live in 4.26); we pass a registry
  holding only the bundled meta-schemas and no retriever, so a hostile upstream schema cannot
  make the gateway issue HTTP requests (no SSRF via ``$ref``).
* Error messages name the failing location and keyword but never echo the offending value,
  so rejected secrets do not leak into logs or back to the model.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import jsonschema
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError
from jsonschema.protocols import Validator
from referencing.exceptions import Unresolvable
from referencing import Registry

from mcpgate.canonical import canonical_bytes
from mcpgate.config import LimitsConfig

__all__ = ["ArgumentValidator", "ValidationIssue", "ValidationOutcome"]

_MAX_ISSUES = 5
_NO_RETRIEVAL: Registry[Any] = Registry()  # meta-schemas are merged in by jsonschema; nothing is fetched


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    path: str
    keyword: str
    message: str


@dataclass(frozen=True, slots=True)
class ValidationOutcome:
    ok: bool
    issues: tuple[ValidationIssue, ...] = ()
    size_bytes: int = 0

    def summary(self) -> str:
        return "; ".join(f"{i.path}: {i.message}" for i in self.issues)


def _depth(value: Any, limit: int) -> int:
    """Max nesting depth, stopping early once ``limit`` is exceeded (iterative, no recursion)."""
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > deepest:
            deepest = depth
            if deepest > limit:
                return deepest
        if isinstance(item, Mapping):
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)
    return deepest


def _path(error: jsonschema.ValidationError) -> str:
    parts = ["$"]
    for part in error.absolute_path:
        parts.append(f"[{part}]" if isinstance(part, int) else f".{part}")
    return "".join(parts)


def _describe(error: jsonschema.ValidationError) -> str:
    """A value-free description of a validation failure."""
    keyword = str(error.validator)
    expected = error.validator_value
    if keyword == "required":
        missing = [p for p in expected if isinstance(error.instance, Mapping) and p not in error.instance]
        return f"missing required properties {missing}"
    if keyword == "additionalProperties" and isinstance(error.instance, Mapping):
        props = error.schema.get("properties", {}) if isinstance(error.schema, Mapping) else {}
        extra = sorted(k for k in error.instance if k not in props)
        return f"unexpected properties {extra}"
    if keyword in {"type", "enum", "const", "format", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
                   "minLength", "maxLength", "minItems", "maxItems", "multipleOf", "pattern", "uniqueItems"}:
        shown = repr(expected)
        if len(shown) > 80:
            shown = shown[:77] + "..."
        return f"violates '{keyword}' (schema expects {shown})"
    return f"violates '{keyword}'"


class ArgumentValidator:
    """Validates tool arguments; compiled validators are cached by pin digest."""

    def __init__(self, limits: LimitsConfig) -> None:
        self._limits = limits
        self._cache: dict[str, Validator | SchemaError] = {}

    def compile(self, key: str, schema: Mapping[str, Any]) -> Validator | SchemaError:
        """Compile (and cache) the validator for ``schema``; a broken schema is cached as its error."""
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        result: Validator | SchemaError
        try:
            cls = jsonschema.validators.validator_for(schema, default=Draft202012Validator)
            cls.check_schema(schema)
            format_checker = FormatChecker() if self._limits.assert_formats else None
            result = cls(schema, format_checker=format_checker, registry=_NO_RETRIEVAL)
        except SchemaError as exc:
            result = exc
        if len(self._cache) > 4096:
            self._cache.clear()
        self._cache[key] = result
        return result

    def schema_error(self, key: str, schema: Mapping[str, Any]) -> str | None:
        """Return a description if ``schema`` is not a valid JSON Schema, else ``None``."""
        compiled = self.compile(key, schema)
        return f"invalid input schema: {compiled.message}" if isinstance(compiled, SchemaError) else None

    def validate(self, key: str, schema: Mapping[str, Any], arguments: Mapping[str, Any]) -> ValidationOutcome:
        try:
            size = len(canonical_bytes(arguments))
        except (TypeError, ValueError) as exc:
            return ValidationOutcome(False, (ValidationIssue("$", "json", f"arguments are not valid JSON: {exc}"),))
        if size > self._limits.max_argument_bytes:
            issue = ValidationIssue("$", "size", f"arguments are {size} bytes; limit {self._limits.max_argument_bytes}")
            return ValidationOutcome(False, (issue,), size)
        depth = _depth(arguments, self._limits.max_argument_depth)
        if depth > self._limits.max_argument_depth:
            issue = ValidationIssue("$", "depth", f"arguments nest deeper than {self._limits.max_argument_depth}")
            return ValidationOutcome(False, (issue,), size)
        compiled = self.compile(key, schema)
        if isinstance(compiled, SchemaError):
            issue = ValidationIssue("$", "schema", "the tool's input schema is invalid; call refused")
            return ValidationOutcome(False, (issue,), size)
        try:
            found = list(compiled.iter_errors(arguments))
        except Unresolvable as exc:
            issue = ValidationIssue("$", "$ref", f"schema reference cannot be resolved locally: {exc.ref!r}")
            return ValidationOutcome(False, (issue,), size)
        errors = sorted(found, key=lambda e: (list(map(str, e.absolute_path)), str(e.validator)))
        if not errors:
            return ValidationOutcome(True, (), size)
        issues = tuple(ValidationIssue(_path(e), str(e.validator), _describe(e)) for e in errors[:_MAX_ISSUES])
        return ValidationOutcome(False, issues, size)
