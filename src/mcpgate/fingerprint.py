"""Tool-definition fingerprints and structural diffs.

A fingerprint is the SHA-256 of the canonical JSON of the security-relevant part of a tool
definition: ``name``, ``title``, ``description``, ``inputSchema``, ``outputSchema`` and
``annotations``. Those are exactly the fields a model reads to decide *whether* and *how* to
call a tool, so they are the fields a "rug pull" (an upstream silently changing a tool after it
was approved) has to touch. ``_meta``, ``icons`` and the era-specific ``execution`` block are
excluded: they do not steer the model and differ legitimately between protocol versions.

Per-field digests are stored alongside the overall digest so an alert can say *which* part
changed, and :func:`json_diff` produces a JSON-pointer level diff for the alert body.
"""

from __future__ import annotations

import difflib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import mcp_types as types

from mcpgate.canonical import digest

__all__ = ["PIN_FIELDS", "Fingerprint", "describe_change", "fingerprint", "json_diff", "pinned_view"]

PIN_FIELDS: tuple[str, ...] = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


def pinned_view(tool: types.Tool | Mapping[str, Any]) -> dict[str, Any]:
    """The subset of a tool definition covered by the pin, in wire (camelCase) form."""
    wire = (
        tool.model_dump(by_alias=True, mode="json", exclude_none=True)
        if isinstance(tool, types.Tool)
        else tool
    )
    return {k: wire[k] for k in PIN_FIELDS if k in wire and wire[k] is not None}


@dataclass(frozen=True, slots=True)
class Fingerprint:
    digest: str
    fields: Mapping[str, str]
    definition: Mapping[str, Any]

    def changed_fields(self, other: Fingerprint) -> list[str]:
        names = set(self.fields) | set(other.fields)
        return sorted(n for n in names if self.fields.get(n) != other.fields.get(n))

    def to_json(self) -> dict[str, Any]:
        return {"digest": self.digest, "fields": dict(self.fields), "definition": dict(self.definition)}

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Fingerprint:
        return cls(
            digest=str(data["digest"]), fields=dict(data["fields"]), definition=dict(data["definition"])
        )


def fingerprint(tool: types.Tool | Mapping[str, Any]) -> Fingerprint:
    view = pinned_view(tool)
    return Fingerprint(
        digest=digest(view),
        fields={k: digest(v) for k, v in view.items()},
        definition=view,
    )


def json_diff(old: Any, new: Any, pointer: str = "", limit: int = 50) -> list[str]:
    """Structural diff as ``+ /path``, ``- /path`` and ``~ /path`` lines (RFC 6901 pointers)."""
    out: list[str] = []

    def walk(a: Any, b: Any, ptr: str) -> None:
        if len(out) >= limit:
            return
        if isinstance(a, Mapping) and isinstance(b, Mapping):
            for key in sorted(set(a) | set(b)):
                child = f"{ptr}/{str(key).replace('~', '~0').replace('/', '~1')}"
                if key not in a:
                    out.append(f"+ {child}")
                elif key not in b:
                    out.append(f"- {child}")
                else:
                    walk(a[key], b[key], child)
        elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
            for index, (x, y) in enumerate(zip(a, b, strict=True)):
                walk(x, y, f"{ptr}/{index}")
        elif a != b or type(a) is not type(b):
            out.append(f"~ {ptr or '/'}")

    walk(old, new, pointer)
    return out[:limit]


def describe_change(old: Fingerprint, new: Fingerprint, *, max_lines: int = 40) -> dict[str, Any]:
    """A human/machine readable explanation of what changed between two fingerprints."""
    fields = old.changed_fields(new)
    detail: dict[str, Any] = {"changed_fields": fields}
    if "description" in fields:
        before = str(old.definition.get("description", "")).splitlines()
        after = str(new.definition.get("description", "")).splitlines()
        diff = list(difflib.unified_diff(before, after, "pinned", "observed", lineterm="", n=1))
        detail["description_diff"] = diff[:max_lines]
    for schema_field in ("inputSchema", "outputSchema", "annotations"):
        if schema_field in fields:
            detail[f"{schema_field}_diff"] = json_diff(
                old.definition.get(schema_field, {}), new.definition.get(schema_field, {})
            )
    return detail
