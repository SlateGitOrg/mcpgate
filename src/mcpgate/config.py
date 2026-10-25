"""Typed gateway configuration, loaded from YAML.

The configuration is validated in full at startup so that a typo becomes a clear
:class:`~mcpgate.errors.ConfigError` instead of a permissive runtime default. Relative paths
are resolved against the directory of the configuration file, and ``${VAR}`` references in
string values are expanded from the environment (an unset variable is an error, never an
empty string). The literal ``${PYTHON}`` expands to the running interpreter so that sample
stdio upstreams can be launched portably.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from mcpgate.errors import ConfigError

__all__ = [
    "AuditConfig",
    "AuthConfig",
    "GatewayConfig",
    "HttpUpstream",
    "LimitsConfig",
    "ListenConfig",
    "PinningConfig",
    "PolicyConfig",
    "RateLimitConfig",
    "RateRule",
    "RoleConfig",
    "StdioUpstream",
    "UpstreamConfig",
    "load_config",
    "parse_config",
]

NAMESPACE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class StdioUpstream(_Model):
    """An upstream MCP server launched as a subprocess speaking stdio."""

    name: str
    transport: Literal["stdio"]
    command: str
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: Path | None = None
    timeout_s: float = Field(default=30.0, gt=0)
    max_concurrency: int = Field(default=8, ge=1)
    heartbeat_s: float = Field(default=15.0, ge=0)


class HttpUpstream(_Model):
    """An upstream MCP server reached over Streamable HTTP."""

    name: str
    transport: Literal["http"]
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    timeout_s: float = Field(default=30.0, gt=0)
    max_concurrency: int = Field(default=8, ge=1)
    heartbeat_s: float = Field(default=15.0, ge=0)

    @field_validator("url")
    @classmethod
    def _http_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("upstream url must start with http:// or https://")
        return value


UpstreamConfig = Annotated[StdioUpstream | HttpUpstream, Field(discriminator="transport")]


class ListenConfig(_Model):
    """Where the gateway itself listens (Streamable HTTP)."""

    host: str = "127.0.0.1"
    port: int = Field(default=8740, ge=0, le=65535)
    path: str = "/mcp"
    public_url: str | None = None
    """Externally visible URL of the MCP endpoint; doubles as the OAuth resource identifier
    (RFC 8707 / RFC 9728). Defaults to ``http://{host}:{port}{path}``."""

    @property
    def resource_url(self) -> str:
        return self.public_url or f"http://{self.host}:{self.port}{self.path}"


class AuthConfig(_Model):
    """OAuth 2.1 resource-server settings: JWT access tokens checked against a local JWKS."""

    enabled: bool = True
    issuer: str
    jwks_file: Path
    audience: str | None = None
    """Expected ``aud``; defaults to the gateway's resource URL."""
    algorithms: list[str] = Field(default_factory=lambda: ["RS256", "ES256", "EdDSA"])
    required_scopes: list[str] = Field(default_factory=lambda: ["mcp:tools"])
    leeway_s: int = Field(default=30, ge=0, le=300)
    max_token_bytes: int = Field(default=8192, ge=256)
    accepted_typ: list[str] = Field(default_factory=lambda: ["at+jwt", "JWT"])
    require_jti: bool = False
    jwks_reload_min_interval_s: float = Field(default=5.0, ge=0)

    @field_validator("algorithms")
    @classmethod
    def _asymmetric_only(cls, value: list[str]) -> list[str]:
        allowed = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
        bad = sorted(set(value) - allowed)
        if bad:
            raise ValueError(f"unsupported or symmetric JWT algorithms: {bad} (allowed: {sorted(allowed)})")
        if not value:
            raise ValueError("at least one algorithm is required")
        return value


class RoleConfig(_Model):
    """A named set of tool permissions. Patterns are shell-style globs on namespaced names."""

    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)


class ClientBinding(_Model):
    roles: list[str] = Field(default_factory=list)


class PolicyConfig(_Model):
    """Per-client tool RBAC. Anything not explicitly allowed is denied."""

    roles: dict[str, RoleConfig] = Field(default_factory=dict)
    clients: dict[str, ClientBinding] = Field(default_factory=dict)
    scope_roles: dict[str, str] = Field(default_factory=dict)
    """Token scope -> role, so an authorization server can grant roles without a config edit."""

    @model_validator(mode="after")
    def _roles_exist(self) -> PolicyConfig:
        known = set(self.roles)
        for client, binding in self.clients.items():
            missing = sorted(set(binding.roles) - known)
            if missing:
                raise ValueError(f"client {client!r} references unknown roles {missing}")
        for scope, role in self.scope_roles.items():
            if role not in known:
                raise ValueError(f"scope {scope!r} maps to unknown role {role!r}")
        return self


class RateRule(_Model):
    """Token bucket: ``rate`` tokens per second, holding at most ``burst``."""

    rate: float = Field(gt=0)
    burst: int = Field(ge=1)


class RateLimitConfig(_Model):
    enabled: bool = True
    per_client: RateRule = RateRule(rate=10.0, burst=20)
    """Budget shared by every tool a client calls."""
    per_tool: dict[str, RateRule] = Field(default_factory=dict)
    """Glob on namespaced tool name -> stricter per-(client, tool) budget. First match wins."""
    client_overrides: dict[str, RateRule] = Field(default_factory=dict)
    max_tracked_buckets: int = Field(default=10_000, ge=16)


class LimitsConfig(_Model):
    max_argument_bytes: int = Field(default=65_536, ge=64)
    max_argument_depth: int = Field(default=32, ge=1, le=256)
    assert_formats: bool = True


class PinningConfig(_Model):
    enabled: bool = True
    store: Path = Path("var/pins.json")
    mode: Literal["enforce", "warn"] = "enforce"
    """``enforce`` quarantines changed tools until approved; ``warn`` only alerts."""
    on_new_tool: Literal["quarantine", "pin"] = "quarantine"
    """What to do with a tool that appears on an already-pinned upstream."""
    lint: bool = True


class AuditConfig(_Model):
    path: Path = Path("var/audit.jsonl")
    arguments: Literal["digest", "redacted", "full"] = "digest"
    fsync: bool = False
    redact_keys: list[str] = Field(
        default_factory=lambda: ["password", "secret", "token", "api_key", "apikey", "authorization", "cookie"]
    )


class StdioIdentity(_Model):
    """Identity assumed for callers on the gateway's stdio transport (no OAuth on stdio)."""

    client_id: str = "local"
    scopes: list[str] = Field(default_factory=lambda: ["mcp:tools"])


class GatewayConfig(_Model):
    name: str = "mcpgate"
    namespace_separator: str = "__"
    refresh_interval_s: float = Field(default=60.0, ge=0)
    page_size: int = Field(default=100, ge=1, le=1000)
    listen: ListenConfig = ListenConfig()
    auth: AuthConfig | None = None
    stdio_identity: StdioIdentity = StdioIdentity()
    upstreams: list[UpstreamConfig]
    policy: PolicyConfig = PolicyConfig()
    rate_limits: RateLimitConfig = RateLimitConfig()
    limits: LimitsConfig = LimitsConfig()
    pinning: PinningConfig = PinningConfig()
    audit: AuditConfig = AuditConfig()

    @field_validator("namespace_separator")
    @classmethod
    def _separator(cls, value: str) -> str:
        if not value or not re.fullmatch(r"[A-Za-z0-9._-]{1,4}", value):
            raise ValueError("namespace_separator must be 1-4 characters from [A-Za-z0-9._-]")
        return value

    @model_validator(mode="after")
    def _unique_namespaces(self) -> GatewayConfig:
        seen: set[str] = set()
        for upstream in self.upstreams:
            if not NAMESPACE_RE.fullmatch(upstream.name):
                raise ValueError(f"upstream name {upstream.name!r} must match {NAMESPACE_RE.pattern}")
            if self.namespace_separator in upstream.name:
                raise ValueError(f"upstream name {upstream.name!r} contains the namespace separator")
            if upstream.name in seen:
                raise ValueError(f"duplicate upstream name {upstream.name!r}")
            seen.add(upstream.name)
        if not self.upstreams:
            raise ValueError("at least one upstream is required")
        return self

    @property
    def audience(self) -> str:
        if self.auth is not None and self.auth.audience:
            return self.auth.audience
        return self.listen.resource_url


def _expand(value: Any, env: Mapping[str, str]) -> Any:
    if isinstance(value, str):

        def repl(match: re.Match[str]) -> str:
            var = match.group(1)
            if var == "PYTHON":
                return sys.executable
            if var not in env:
                raise ConfigError(f"environment variable ${{{var}}} referenced by the config is not set")
            return env[var]

        return _ENV_RE.sub(repl, value)
    if isinstance(value, list):
        return [_expand(v, env) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v, env) for k, v in value.items()}
    return value


def _resolve_paths(cfg: GatewayConfig, base: Path) -> GatewayConfig:
    def fix(path: Path) -> Path:
        return path if path.is_absolute() else (base / path).resolve()

    updates: dict[str, Any] = {
        "pinning": cfg.pinning.model_copy(update={"store": fix(cfg.pinning.store)}),
        "audit": cfg.audit.model_copy(update={"path": fix(cfg.audit.path)}),
    }
    if cfg.auth is not None:
        updates["auth"] = cfg.auth.model_copy(update={"jwks_file": fix(cfg.auth.jwks_file)})
    upstreams: list[StdioUpstream | HttpUpstream] = []
    for up in cfg.upstreams:
        if isinstance(up, StdioUpstream):
            upstreams.append(up.model_copy(update={"cwd": fix(up.cwd) if up.cwd else base}))
        else:
            upstreams.append(up)
    updates["upstreams"] = upstreams
    return cfg.model_copy(update=updates)


def parse_config(data: Mapping[str, Any], base_dir: Path, env: Mapping[str, str] | None = None) -> GatewayConfig:
    """Validate an already-parsed mapping. Relative paths resolve against ``base_dir``."""
    expanded = _expand(dict(data), os.environ if env is None else env)
    try:
        cfg = GatewayConfig.model_validate(expanded)
    except ValidationError as exc:
        lines = []
        for err in exc.errors():
            loc = ".".join(str(p) for p in err["loc"]) or "<root>"
            lines.append(f"  {loc}: {err['msg']}")
        raise ConfigError("invalid gateway configuration:\n" + "\n".join(lines)) from None
    return _resolve_paths(cfg, base_dir)


def load_config(path: Path, env: Mapping[str, str] | None = None) -> GatewayConfig:
    """Load and validate a YAML configuration file."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"config {path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"config {path} must be a YAML mapping at the top level")
    return parse_config(raw, path.parent.resolve(), env)
