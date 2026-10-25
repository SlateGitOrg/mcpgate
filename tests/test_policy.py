from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from mcpgate.config import ClientBinding, PolicyConfig, RoleConfig
from mcpgate.policy import PolicyEngine

CFG = PolicyConfig(
    roles={
        "analyst": RoleConfig(allow=["inventory__get_*", "inventory__list_*", "notes__*"], deny=["notes__delete_*"]),
        "operator": RoleConfig(allow=["*"]),
        "no-writes": RoleConfig(deny=["*__adjust_*", "*__delete_*"]),
    },
    clients={"agent-analyst": ClientBinding(roles=["analyst"]), "agent-ops": ClientBinding(roles=["operator"])},
    scope_roles={"mcpgate:operator": "operator", "mcpgate:readonly": "no-writes"},
)


def test_allow_and_deny_globs() -> None:
    engine = PolicyEngine(CFG)
    assert engine.check("agent-analyst", [], "inventory__get_stock").allowed
    assert engine.check("agent-analyst", [], "notes__add_note").rule == "analyst:allow:notes__*"
    denied = engine.check("agent-analyst", [], "notes__delete_note")
    assert not denied.allowed
    assert denied.rule == "analyst:deny:notes__delete_*"
    assert not engine.check("agent-analyst", [], "inventory__adjust_stock").allowed
    assert engine.check("agent-ops", [], "inventory__adjust_stock").allowed


def test_unknown_client_is_denied_by_default() -> None:
    decision = PolicyEngine(CFG).check("stranger", ["mcp:tools"], "inventory__get_stock")
    assert not decision.allowed
    assert decision.reason == "no roles bound to this client"


def test_scope_granted_roles_and_deny_precedence() -> None:
    engine = PolicyEngine(CFG)
    assert engine.check("stranger", ["mcpgate:operator"], "inventory__adjust_stock").allowed
    # an operator token that also carries the read-only scope loses write tools: deny wins
    capped = engine.check("agent-ops", ["mcpgate:readonly"], "inventory__adjust_stock")
    assert not capped.allowed
    assert capped.roles == ("no-writes", "operator")


def test_visible_filters_catalog() -> None:
    tools = ["inventory__get_stock", "inventory__adjust_stock", "notes__add_note", "notes__delete_note"]
    assert PolicyEngine(CFG).visible("agent-analyst", [], tools) == ["inventory__get_stock", "notes__add_note"]


def test_matching_is_case_sensitive() -> None:
    assert not PolicyEngine(CFG).check("agent-analyst", [], "Notes__add_note").allowed


tool_names = st.from_regex(r"[a-z]{1,6}__[a-z_]{1,10}", fullmatch=True)


@given(tool_names, st.lists(st.sampled_from(["mcpgate:operator", "mcpgate:readonly", "x"]), max_size=3))
def test_deny_always_wins(tool: str, scopes: list[str]) -> None:
    engine = PolicyEngine(CFG)
    decision = engine.check("agent-ops", scopes, tool)
    if "mcpgate:readonly" in scopes and ("__adjust_" in tool or "__delete_" in tool):
        assert not decision.allowed
    else:
        assert decision.allowed  # operator allows "*"
