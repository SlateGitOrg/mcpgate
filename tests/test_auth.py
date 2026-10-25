from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import jwt
import pytest

from mcpgate.auth import JWKSStore, JWTVerifier, Principal
from mcpgate.config import AuthConfig
from mcpgate.devissuer import DevIssuer, generate_keys
from mcpgate.errors import AuthError
from tests.conftest import AUDIENCE, ISSUER


def _mint(signer: DevIssuer, /, **kw: object) -> str:
    args: dict[str, object] = {"issuer": ISSUER, "audience": AUDIENCE, "client_id": "agent-a"}
    args.update(kw)
    return signer.mint(**args)  # type: ignore[arg-type]


def _reason(verifier: JWTVerifier, token: str) -> str:
    with pytest.raises(AuthError) as info:
        verifier.verify(token)
    return info.value.reason


def test_valid_token_yields_access_token(issuer: DevIssuer, auth_config: AuthConfig) -> None:
    verifier = JWTVerifier(auth_config, AUDIENCE)
    token = _mint(issuer, scopes=["mcp:tools", "inventory:read"], subject="alice")
    access = verifier.verify(token)
    assert access.client_id == "agent-a"
    assert access.subject == "alice"
    assert access.scopes == ["inventory:read", "mcp:tools"]
    assert access.resource == AUDIENCE
    principal = Principal.from_access_token(access)
    assert principal.issuer == ISSUER
    assert principal.token_id is not None
    assert "inventory:read" in principal.scopes


@pytest.mark.anyio
async def test_sdk_hook_returns_none_on_failure(issuer: DevIssuer, auth_config: AuthConfig) -> None:
    rejected: list[tuple[str, dict[str, object]]] = []
    verifier = JWTVerifier(auth_config, AUDIENCE, on_reject=lambda e, f: rejected.append((e.reason, f)))
    assert await verifier.verify_token(_mint(issuer)) is not None
    assert await verifier.verify_token("not-a-jwt") is None
    assert rejected == [("malformed_token", {})]


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"issuer": "https://evil.test"}, "wrong_issuer"),
        ({"audience": "http://other-service/mcp"}, "wrong_audience"),
        ({"audience": ["http://a", "http://b"]}, "wrong_audience"),
        ({"ttl_s": -3600}, "token_expired"),
        ({"now": time.time() + 3600}, "token_not_yet_valid"),
        ({"extra_claims": {"nbf": int(time.time()) + 3600}}, "token_not_yet_valid"),
        ({"extra_claims": {"client_id": ""}}, "missing_claim"),
        ({"extra_claims": {"sub": 7}}, "missing_claim"),
        ({"extra_claims": {"exp": "tomorrow"}}, "malformed_token"),
        ({"extra_claims": {"scope": ["a"]}}, "malformed_token"),
        ({"headers": {"typ": "id+jwt"}}, "wrong_token_type"),
        ({"headers": {"crit": ["exp"]}}, "unsupported_critical_header"),
        ({"headers": {"kid": "nope"}}, "unknown_key"),
    ],
)
def test_rejections(
    issuer: DevIssuer, auth_config: AuthConfig, kwargs: dict[str, object], reason: str
) -> None:
    assert _reason(JWTVerifier(auth_config, AUDIENCE), _mint(issuer, **kwargs)) == reason


def test_audience_list_containing_gateway_is_accepted(issuer: DevIssuer, auth_config: AuthConfig) -> None:
    access = JWTVerifier(auth_config, AUDIENCE).verify(_mint(issuer, audience=["http://x", AUDIENCE]))
    assert access.resource == AUDIENCE


def test_leeway_tolerates_small_skew(issuer: DevIssuer, auth_config: AuthConfig) -> None:
    now = time.time()
    token = _mint(issuer, now=now - 905)  # expired 5 s ago with a 900 s ttl
    assert JWTVerifier(auth_config, AUDIENCE, clock=lambda: now).verify(token)
    assert _reason(JWTVerifier(auth_config, AUDIENCE, clock=lambda: now + 60), token) == "token_expired"


def test_missing_required_claims(issuer: DevIssuer, auth_config: AuthConfig) -> None:
    token = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "s", "client_id": "c", "iat": int(time.time())},
        issuer.key,
        algorithm="ES256",
        headers={"kid": "k1"},
    )
    assert _reason(JWTVerifier(auth_config, AUDIENCE), token) == "missing_claim"
    cfg = auth_config.model_copy(update={"require_jti": True})
    token2 = _mint(issuer, extra_claims={"jti": None})
    assert _reason(JWTVerifier(cfg, AUDIENCE), token2) == "missing_claim"


def test_azp_and_scp_fallbacks(issuer: DevIssuer, auth_config: AuthConfig) -> None:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "s",
        "azp": "web",
        "scp": ["x", "y"],
        "iat": now,
        "exp": now + 60,
    }
    token = jwt.encode(claims, issuer.key, algorithm="ES256", headers={"kid": "k1"})
    access = JWTVerifier(auth_config, AUDIENCE).verify(token)
    assert access.client_id == "web"
    assert access.scopes == ["x", "y"]
    del claims["scp"]
    token = jwt.encode(claims, issuer.key, algorithm="ES256", headers={"kid": "k1"})
    assert JWTVerifier(auth_config, AUDIENCE).verify(token).scopes == []


def _b64(data: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def test_alg_none_is_refused(issuer: DevIssuer, auth_config: AuthConfig) -> None:
    now = int(time.time())
    body = {"iss": ISSUER, "aud": AUDIENCE, "sub": "s", "client_id": "c", "iat": now, "exp": now + 60}
    token = f"{_b64({'alg': 'none', 'kid': 'k1'})}.{_b64(body)}."
    assert _reason(JWTVerifier(auth_config, AUDIENCE), token) == "algorithm_not_allowed"


def test_hmac_key_confusion_is_refused(issuer: DevIssuer, auth_config: AuthConfig, keydir: Path) -> None:
    # Classic attack: sign HS256 with the *public* key bytes as the shared secret.
    public = json.loads((keydir / "jwks.json").read_text())["keys"][0]
    now = int(time.time())
    body = {"iss": ISSUER, "aud": AUDIENCE, "sub": "s", "client_id": "c", "iat": now, "exp": now + 60}
    token = jwt.encode(body, json.dumps(public).encode() * 2, algorithm="HS256", headers={"kid": "k1"})
    assert _reason(JWTVerifier(auth_config, AUDIENCE), token) == "algorithm_not_allowed"


def test_tampered_payload_fails_signature(issuer: DevIssuer, auth_config: AuthConfig) -> None:
    head, _, sig = _mint(issuer).split(".")
    now = int(time.time())
    forged = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "root",
        "client_id": "admin",
        "iat": now,
        "exp": now + 60,
    }
    token = f"{head}.{_b64(forged)}.{sig}"
    assert _reason(JWTVerifier(auth_config, AUDIENCE), token) == "bad_signature"


def test_algorithm_mismatch_between_header_and_key(issuer: DevIssuer, auth_config: AuthConfig) -> None:
    token = _mint(issuer)
    _, body, sig = token.split(".")
    token = f"{_b64({'alg': 'EdDSA', 'kid': 'k1', 'typ': 'at+jwt'})}.{body}.{sig}"
    assert _reason(JWTVerifier(auth_config, AUDIENCE), token) == "algorithm_mismatch"


def test_oversized_and_garbage_tokens(auth_config: AuthConfig) -> None:
    verifier = JWTVerifier(auth_config, AUDIENCE)
    assert _reason(verifier, "a" * 10_000) == "token_too_large"
    assert _reason(verifier, "abc.def") == "malformed_token"
    assert _reason(verifier, "!!!.e30.sig") == "malformed_token"
    assert _reason(verifier, f"{_b64([1])}.e30.sig") == "malformed_token"  # type: ignore[arg-type]
    bad_kid = f"{_b64({'alg': 'ES256', 'kid': 5})}.{_b64({})}.sig"
    assert _reason(verifier, bad_kid) == "malformed_token"


def test_key_rotation_picked_up_from_disk(issuer: DevIssuer, auth_config: AuthConfig, keydir: Path) -> None:
    verifier = JWTVerifier(auth_config, AUDIENCE)
    assert verifier.verify(_mint(issuer))
    rotated = generate_keys(keydir, alg="EdDSA", kid="k2")  # appended to the JWKS
    access = verifier.verify(rotated.mint(issuer=ISSUER, audience=AUDIENCE, client_id="agent-b"))
    assert access.client_id == "agent-b"
    assert verifier.verify(_mint(issuer))  # old key still trusted until removed


def test_jwks_store_validation(tmp_path: Path, issuer: DevIssuer, keydir: Path) -> None:
    path = tmp_path / "jwks.json"
    path.write_text("{}")
    with pytest.raises(AuthError, match="no 'keys'"):
        JWKSStore(path)
    path.write_text(json.dumps({"keys": [{"kty": "oct", "k": "c2VjcmV0"}]}))
    with pytest.raises(AuthError, match="no usable"):
        JWKSStore(path)
    with pytest.raises(AuthError, match="cannot load"):
        JWKSStore(tmp_path / "missing.json")
    good = json.loads((keydir / "jwks.json").read_text())["keys"][0]
    private_leak = dict(good, kid="leak", d="AAAA")
    enc = dict(good, kid="enc", use="enc")
    broken = {"kty": "EC", "kid": "broken", "crv": "P-256", "x": "AA", "y": "AA"}
    path.write_text(json.dumps({"keys": [good, private_leak, enc, broken, "junk"]}))
    store = JWKSStore(path)
    assert store.key_ids == ["k1"]
    assert store.get(None) is not None  # single key: kid may be omitted


def test_jwks_reload_failure_keeps_last_good_keys(tmp_path: Path, issuer: DevIssuer, keydir: Path) -> None:
    path = tmp_path / "jwks.json"
    path.write_text((keydir / "jwks.json").read_text())
    clock = [0.0]
    store = JWKSStore(path, min_reload_interval_s=10, monotonic=lambda: clock[0])
    path.write_text("{ half written")
    clock[0] = 20
    assert store.get("k1") is not None
    assert store.get("unknown") is None  # reload is rate-limited after the failure
