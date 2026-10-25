"""A development-only token issuer: key generation and access-token minting.

Real deployments point ``auth.jwks_file`` at the public keys of their authorization server
(Keycloak, Auth0, Entra ID, ...). For tests, the demo and local experiments this module plays
that role: it creates an ES256 or EdDSA signing key, writes the private key (mode 0600) and the
matching public JWKS, and mints RFC 9068-shaped access tokens. It never runs inside the gateway
request path.
"""

from __future__ import annotations

import json
import os
import secrets
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from jwt.algorithms import ECAlgorithm, OKPAlgorithm

__all__ = ["DevIssuer", "KeyAlgorithm", "generate_keys"]

KeyAlgorithm = Literal["ES256", "EdDSA"]
PrivateKey = ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey


def _public_jwk(key: PrivateKey, kid: str, alg: KeyAlgorithm) -> dict[str, Any]:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        jwk: dict[str, Any] = json.loads(ECAlgorithm.to_jwk(key.public_key()))
    else:
        jwk = json.loads(OKPAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid=kid, alg=alg, use="sig")
    return jwk


def _new_key(alg: KeyAlgorithm) -> PrivateKey:
    if alg == "ES256":
        return ec.generate_private_key(ec.SECP256R1())
    return ed25519.Ed25519PrivateKey.generate()


def generate_keys(directory: Path, *, alg: KeyAlgorithm = "ES256", kid: str | None = None) -> DevIssuer:
    """Create ``signing-key.pem`` (0600) and ``jwks.json`` in ``directory``.

    If a JWKS already exists the new public key is *appended*, which models key rotation:
    tokens signed by the old key keep validating until its entry is removed.
    """
    directory.mkdir(parents=True, exist_ok=True)
    kid = kid or f"dev-{secrets.token_hex(4)}"
    key = _new_key(alg)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = directory / "signing-key.pem"
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    meta_path = directory / "signing-key.json"
    meta_path.write_text(json.dumps({"kid": kid, "alg": alg}, indent=2) + "\n", encoding="utf-8")

    jwks_path = directory / "jwks.json"
    existing: list[dict[str, Any]] = []
    if jwks_path.exists():
        existing = [k for k in json.loads(jwks_path.read_text(encoding="utf-8")).get("keys", []) if k.get("kid") != kid]
    jwks = {"keys": [*existing, _public_jwk(key, kid, alg)]}
    tmp = jwks_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(jwks, indent=2) + "\n", encoding="utf-8")
    tmp.replace(jwks_path)
    return DevIssuer(key=key, kid=kid, alg=alg)


@dataclass(frozen=True)
class DevIssuer:
    """Signs access tokens with one private key."""

    key: PrivateKey
    kid: str
    alg: KeyAlgorithm

    @classmethod
    def load(cls, directory: Path) -> DevIssuer:
        meta = json.loads((directory / "signing-key.json").read_text(encoding="utf-8"))
        key = serialization.load_pem_private_key((directory / "signing-key.pem").read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey):
            raise ValueError("signing-key.pem must hold an EC P-256 or Ed25519 private key")
        return cls(key=key, kid=str(meta["kid"]), alg=meta["alg"])

    def mint(
        self,
        *,
        issuer: str,
        audience: str | list[str],
        client_id: str,
        subject: str | None = None,
        scopes: Iterable[str] = ("mcp:tools",),
        ttl_s: int = 900,
        now: float | None = None,
        extra_claims: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
    ) -> str:
        """Return a signed RFC 9068 access token."""
        issued = int(time.time() if now is None else now)
        claims: dict[str, Any] = {
            "iss": issuer,
            "aud": audience,
            "sub": subject or f"user:{client_id}",
            "client_id": client_id,
            "scope": " ".join(scopes),
            "iat": issued,
            "exp": issued + ttl_s,
            "jti": str(uuid.uuid4()),
        }
        claims.update(extra_claims or {})
        hdrs = {"kid": self.kid, "typ": "at+jwt"}
        hdrs.update(headers or {})
        return jwt.encode(claims, self.key, algorithm=self.alg, headers=hdrs)
