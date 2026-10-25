from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcpgate.config import HttpUpstream, StdioUpstream, load_config, parse_config
from mcpgate.errors import ConfigError

BASE = {
    "upstreams": [
        {"name": "notes", "transport": "stdio", "command": "${PYTHON}", "args": ["-m", "x"]},
        {"name": "inventory", "transport": "http", "url": "http://127.0.0.1:9/mcp",
         "headers": {"Authorization": "Bearer ${UP_TOKEN}"}},
    ],
    "auth": {"issuer": "https://issuer.test", "jwks_file": "keys/jwks.json"},
    "policy": {"roles": {"r": {"allow": ["*"]}}, "clients": {"c": {"roles": ["r"]}}, "scope_roles": {"s": "r"}},
}


def test_parse_resolves_paths_and_env(tmp_path: Path) -> None:
    cfg = parse_config(BASE, tmp_path, env={"UP_TOKEN": "abc"})
    notes, inventory = cfg.upstreams
    assert isinstance(notes, StdioUpstream)
    assert notes.command == sys.executable
    assert notes.cwd == tmp_path
    assert isinstance(inventory, HttpUpstream)
    assert inventory.headers["Authorization"] == "Bearer abc"
    assert cfg.auth is not None
    assert cfg.auth.jwks_file == (tmp_path / "keys/jwks.json").resolve()
    assert cfg.pinning.store == (tmp_path / "var/pins.json").resolve()
    assert cfg.audience == "http://127.0.0.1:8740/mcp"


def test_unset_env_var_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="UP_TOKEN"):
        parse_config(BASE, tmp_path, env={})


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        ({"upstreams": []}, "at least one upstream"),
        ({"upstreams": [{"name": "Bad Name", "transport": "stdio", "command": "x"}]}, "must match"),
        ({"upstreams": [{"name": "a__b", "transport": "stdio", "command": "x"}]}, "must match"),
        ({"upstreams": [{"name": "a", "transport": "stdio", "command": "x"}] * 2}, "duplicate upstream"),
        ({"upstreams": [{"name": "a", "transport": "http", "url": "ftp://x"}]}, "http://"),
        ({"namespace_separator": "/"}, "namespace_separator"),
        ({"auth": {"issuer": "i", "jwks_file": "j", "algorithms": ["HS256"]}}, "symmetric"),
        ({"auth": {"issuer": "i", "jwks_file": "j", "algorithms": []}}, "at least one"),
        ({"policy": {"clients": {"c": {"roles": ["ghost"]}}}}, "unknown roles"),
        ({"policy": {"scope_roles": {"s": "ghost"}}}, "unknown role"),
        ({"bogus": 1}, "Extra inputs"),
    ],
)
def test_invalid_configs(tmp_path: Path, patch: dict[str, object], message: str) -> None:
    data = {**BASE, **patch}
    with pytest.raises(ConfigError, match=message):
        parse_config(data, tmp_path, env={"UP_TOKEN": "x"})


def test_load_config_file_errors(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("a: [unclosed")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(bad)
    bad.write_text("- just a list")
    with pytest.raises(ConfigError, match="mapping"):
        load_config(bad)
    good = tmp_path / "good.yaml"
    good.write_text(
        "listen: {public_url: 'https://gw.example/mcp'}\n"
        "auth: {issuer: i, jwks_file: j, audience: 'urn:aud'}\n"
        "upstreams: [{name: a, transport: stdio, command: x, cwd: sub}]\n"
    )
    cfg = load_config(good, env={})
    assert cfg.listen.resource_url == "https://gw.example/mcp"
    assert cfg.audience == "urn:aud"
    assert cfg.upstreams[0].cwd == (tmp_path / "sub").resolve()  # type: ignore[union-attr]
