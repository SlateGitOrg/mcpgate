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
    """The pin store file is unreadable or corrupt."""


class AuditError(GatewayError):
    """The audit log cannot be written, or its hash chain failed verification."""


class UpstreamError(GatewayError):
    """An upstream MCP server is unreachable or failed while serving a request."""

    def __init__(self, upstream: str, detail: str) -> None:
        super().__init__(f"upstream {upstream!r}: {detail}")
        self.upstream = upstream
        self.detail = detail
