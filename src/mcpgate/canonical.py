"""Canonical JSON serialisation and hashing.

Tool-definition pins and audit-log hash chains both need a byte-exact, order-independent
encoding of JSON values. This module implements the RFC 8785 (JSON Canonicalization Scheme)
rules that matter for MCP payloads:

* object members sorted by the UTF-16 code units of their keys (JCS section 3.2.3);
* no insignificant whitespace;
* strings emitted as UTF-8 with only the mandatory escapes;
* integers printed exactly, floats in the shortest round-trip form with integral values
  collapsed to integers (``1.0`` -> ``1``), and NaN/Infinity rejected.

The float rendering follows ECMAScript ``Number.prototype.toString`` for the common range;
exotic exponents fall back to Python's shortest ``repr``. That is a documented deviation
from strict JCS (see ``docs/ARCHITECTURE.md``) that cannot affect equality checks performed
by this program, because both sides of every comparison are produced here.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from typing import Any

__all__ = ["canonical_bytes", "canonical_json", "digest", "sha256_hex"]

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _encode_string(value: str) -> str:
    out = ['"']
    for ch in value:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _encode_float(value: float) -> str:
    if math.isnan(value) or math.isinf(value):
        raise ValueError("NaN and Infinity are not valid JSON numbers")
    if value == 0:
        return "0"  # covers -0.0 as JCS requires
    if value.is_integer() and abs(value) < 1e21:
        return str(int(value))
    text = repr(value)
    if "e" in text:
        mantissa, exponent = text.split("e")
        exp = int(exponent)
        text = f"{mantissa}e{'+' if exp > 0 else '-'}{abs(exp)}"
    return text


def _utf16_key(key: str) -> bytes:
    return key.encode("utf-16-be")


def _encode(value: Any, out: list[str], depth: int) -> None:
    if depth > 256:
        raise ValueError("JSON value nested deeper than 256 levels")
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        out.append(str(value))
    elif isinstance(value, float):
        out.append(_encode_float(value))
    elif isinstance(value, str):
        out.append(_encode_string(value))
    elif isinstance(value, Mapping):
        out.append("{")
        keys = list(value.keys())
        for key in keys:
            if not isinstance(key, str):
                raise TypeError(f"object keys must be strings, got {type(key).__name__}")
        for index, key in enumerate(sorted(keys, key=_utf16_key)):
            if index:
                out.append(",")
            out.append(_encode_string(key))
            out.append(":")
            _encode(value[key], out, depth + 1)
        out.append("}")
    elif isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _encode(item, out, depth + 1)
        out.append("]")
    else:
        raise TypeError(f"value of type {type(value).__name__} is not JSON-serialisable")


def canonical_json(value: Any) -> str:
    """Return the canonical JSON text of ``value``."""
    out: list[str] = []
    _encode(value, out, 0)
    return "".join(out)


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical JSON encoding of ``value`` as UTF-8 bytes."""
    return canonical_json(value).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Hex SHA-256 of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def digest(value: Any) -> str:
    """``sha256:<hex>`` digest of the canonical encoding of ``value``."""
    return "sha256:" + sha256_hex(canonical_bytes(value))


def loads(text: str | bytes) -> Any:
    """Parse JSON while rejecting the non-standard NaN/Infinity literals."""

    def _reject(token: str) -> Any:
        raise ValueError(f"invalid JSON number literal {token!r}")

    return json.loads(text, parse_constant=_reject)
