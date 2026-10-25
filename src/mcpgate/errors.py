"""Exception hierarchy for mcpgate.

Every error the gateway raises on purpose derives from :class:`GatewayError`, so callers can
catch the whole family in one place while still distinguishing configuration problems (fail
fast at startup) from per-request denials (reported to the caller and the audit log).
"""

from __future__ import annotations


class GatewayError(Exception):
    """Base class for all mcpgate errors."""


class ConfigError(GatewayError):
    """The configuration file is missing, malformed or internally inconsistent."""


class AuthError(GatewayError):
    """A bearer token was rejected. ``reason`` is a short machine-readable code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class CatalogError(GatewayError):
    """The aggregated tool catalog cannot be built (e.g. a namespaced name is invalid)."""


class PinStoreError(GatewayError):
    """The pin store file is unreadable or corrupt, or a pin operation names nothing pending."""


class PinApprovalMismatch(PinStoreError):
    """An approval named a digest that is not what is pending now.

    The upstream changed its definition (or the pending set) after the operator reviewed it, so
    approving would pin something nobody has seen. ``expected`` is the digest the operator
    reviewed, ``observed`` what is pending at approval time (``None`` if nothing is).
    """

    def __init__(self, upstream: str, tool: str | None, expected: str, observed: str | None) -> None:
        target = f"{upstream}/{tool}" if tool is not None else f"the pending set of {upstream}"
        if observed is None:
            detail = f"nothing is pending for {target} (reviewed {expected})"
        else:
            detail = (
                f"{target} changed after review: pending is {observed}, reviewed was {expected}; "
                "run `mcpgate pins diff` again and approve what it shows"
            )
        super().__init__(f"approval refused: {detail}")
        self.upstream = upstream
        self.tool = tool
        self.expected = expected
        self.observed = observed


class AuditError(GatewayError):
    """The audit log cannot be written, or its hash chain failed verification."""


class UpstreamError(GatewayError):
    """An upstream MCP server is unreachable or failed while serving a request."""

    def __init__(self, upstream: str, detail: str) -> None:
        super().__init__(f"upstream {upstream!r}: {detail}")
        self.upstream = upstream
        self.detail = detail
