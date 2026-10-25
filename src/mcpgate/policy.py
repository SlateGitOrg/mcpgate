"""Per-client tool RBAC.

A caller's effective roles are the union of the roles bound to its ``client_id`` in the
config and the roles granted by any of its token scopes (``scope_roles``). A tool is allowed
iff at least one role's ``allow`` glob matches the namespaced tool name **and** no role's
``deny`` glob matches it. Deny always wins, and an unknown client gets no roles: the default
is deny.

Globs use :func:`fnmatch.fnmatchcase` (case-sensitive, ``*``/``?``/``[...]``), matched
against the full namespaced name such as ``inventory__adjust_stock``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from functools import lru_cache

from mcpgate.config import PolicyConfig

__all__ = ["Decision", "PolicyEngine"]


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str
    roles: tuple[str, ...]
    rule: str | None = None


class PolicyEngine:
    """Evaluates RBAC decisions. Decisions are cached per (roles, tool) pair."""

    def __init__(self, config: PolicyConfig) -> None:
        self._cfg = config
        self._decide = lru_cache(maxsize=4096)(self._decide_uncached)

    def roles_for(self, client_id: str, scopes: Iterable[str]) -> tuple[str, ...]:
        roles: set[str] = set()
        binding = self._cfg.clients.get(client_id)
        if binding is not None:
            roles.update(binding.roles)
        for scope in scopes:
            role = self._cfg.scope_roles.get(scope)
            if role is not None:
                roles.add(role)
        return tuple(sorted(roles))

    def check(self, client_id: str, scopes: Iterable[str], tool: str) -> Decision:
        return self._decide(self.roles_for(client_id, scopes), tool)

    def _decide_uncached(self, roles: tuple[str, ...], tool: str) -> Decision:
        if not roles:
            return Decision(False, "no roles bound to this client", roles)
        allow_rule: str | None = None
        for role_name in roles:
            role = self._cfg.roles[role_name]
            for pattern in role.deny:
                if fnmatchcase(tool, pattern):
                    return Decision(False, f"denied by role {role_name!r}", roles, f"{role_name}:deny:{pattern}")
            if allow_rule is None:
                for pattern in role.allow:
                    if fnmatchcase(tool, pattern):
                        allow_rule = f"{role_name}:allow:{pattern}"
                        break
        if allow_rule is None:
            return Decision(False, "no role allows this tool", roles)
        return Decision(True, "allowed", roles, allow_rule)

    def visible(self, client_id: str, scopes: Iterable[str], tools: Iterable[str]) -> list[str]:
        """Filter ``tools`` down to the ones the caller may invoke (used for ``tools/list``)."""
        roles = self.roles_for(client_id, scopes)
        return [t for t in tools if self._decide(roles, t).allowed]
