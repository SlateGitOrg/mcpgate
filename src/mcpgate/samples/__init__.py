"""Two small, self-contained MCP servers used by the integration tests and the demo.

* :mod:`~mcpgate.samples.notes_server` -- a note-taking server spoken to over **stdio**;
* :mod:`~mcpgate.samples.inventory_server` -- a stock-keeping server on **Streamable HTTP**.

Each has a ``clean`` variant and a deliberately altered one (``poisoned`` / ``drifted``) that
changes tool definitions the way a rug-pull would, so pinning can be exercised end to end.
The altered variants only *describe* malicious intent in text; they never read files or
send data anywhere.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["read_variant"]


def read_variant(variant: str | None, variant_file: str | None, default: str = "clean") -> str:
    """Resolve the variant from ``--variant`` or the first line of ``--variant-file``."""
    if variant:
        return variant
    if variant_file:
        path = Path(variant_file)
        if path.exists():
            text = path.read_text(encoding="utf-8").strip()
            if text:
                return text.splitlines()[0].strip()
    return default
