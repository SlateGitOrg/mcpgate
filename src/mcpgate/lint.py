"""Heuristic lint for tool definitions ("tool poisoning" indicators).

Tool descriptions are read by the model as instructions, which makes them an injection
channel: a malicious or compromised upstream can hide directives in a description or a
parameter description. Hash pinning catches *changes*; this lint flags suspicious content in
any definition, including the very first one seen (which TOFU pinning would otherwise accept
silently).

The checks are deliberately simple and explainable -- regexes and Unicode categories, no
model -- and they report, they do not block. False positives and negatives are expected;
see ``docs/THREAT_MODEL.md``.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Literal

__all__ = ["LintFinding", "lint_definition"]

Severity = Literal["high", "medium", "low"]

_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")

_PATTERNS: tuple[tuple[str, Severity, re.Pattern[str]], ...] = (
    ("instruction_override", "high",
     re.compile(r"ignore (all |any )?(previous|prior|above|earlier) (instructions|rules|messages)", re.I)),
    ("concealment", "high",
     re.compile(r"(do not|don't|never) (tell|mention|inform|reveal|show)[^.]{0,40}\b(user|human)", re.I)),
    ("hidden_directive_tag", "medium",
     re.compile(r"<\s*/?\s*(important|system|instructions?|secret|hidden)\s*>", re.I)),
    ("sensitive_path", "high",
     re.compile(r"(~/\.ssh|id_rsa|id_ed25519|/etc/passwd|/etc/shadow|\.aws/credentials|\.env\b|"
                r"mcp\.json|\.netrc|private[ _-]?key)", re.I)),
    ("exfiltration_hint", "medium",
     re.compile(r"(send|post|upload|forward|include)[^.]{0,60}\b(contents?|secrets?|credentials?|tokens?|"
                r"conversation|chat history)\b", re.I)),
    ("model_directed_imperative", "low",
     re.compile(r"\b(before|after) (using|calling) (this|any other) tool\b", re.I)),
)

_MAX_DESCRIPTION_CHARS = 2000


@dataclass(frozen=True, slots=True)
class LintFinding:
    rule: str
    severity: Severity
    location: str
    excerpt: str


def _strings(value: Any, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield from _strings(item, f"{path}/{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _strings(item, f"{path}/{index}")


def _excerpt(text: str, start: int, end: int) -> str:
    lo, hi = max(0, start - 20), min(len(text), end + 20)
    snippet = text[lo:hi].replace("\n", " ")
    return ("..." if lo else "") + snippet + ("..." if hi < len(text) else "")


def lint_definition(definition: Mapping[str, Any], other_tools: Iterable[str] = ()) -> list[LintFinding]:
    """Return findings for one tool definition (wire form, as produced by ``pinned_view``).

    ``other_tools`` are the names of tools from *other* upstreams; a description that names
    one of them is flagged as possible cross-server shadowing.
    """
    findings: list[LintFinding] = []
    others = [t for t in other_tools if len(t) >= 4]
    for location, text in _strings(definition, ""):
        loc = location or "/"
        hidden = _INVISIBLE.search(text)
        if hidden:
            name = unicodedata.name(hidden.group(), f"U+{ord(hidden.group()):04X}")
            findings.append(LintFinding("invisible_unicode", "high", loc, f"contains {name}"))
        for rule, severity, pattern in _PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(LintFinding(rule, severity, loc, _excerpt(text, match.start(), match.end())))
        for other in others:
            if other in text:
                findings.append(LintFinding("cross_tool_reference", "medium", loc, f"mentions tool {other!r}"))
                break
    description = definition.get("description")
    if isinstance(description, str) and len(description) > _MAX_DESCRIPTION_CHARS:
        findings.append(
            LintFinding("oversized_description", "low", "/description", f"{len(description)} characters")
        )
    return findings
