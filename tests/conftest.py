from __future__ import annotations

from pathlib import Path

import pytest

from mcpgate.config import AuthConfig
from mcpgate.devissuer import DevIssuer, generate_keys

ISSUER = "https://issuer.test"
AUDIENCE = "http://127.0.0.1:8740/mcp"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def keydir(tmp_path: Path) -> Path:
    return tmp_path / "keys"


@pytest.fixture
def issuer(keydir: Path) -> DevIssuer:
    return generate_keys(keydir, kid="k1")


@pytest.fixture
def auth_config(issuer: DevIssuer, keydir: Path) -> AuthConfig:
    return AuthConfig(issuer=ISSUER, jwks_file=keydir / "jwks.json", jwks_reload_min_interval_s=0)
