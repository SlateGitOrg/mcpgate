"""OAuth 2.1 bearer-token validation against a local JWKS.

mcpgate acts as an OAuth 2.1 *resource server* (MCP authorization spec, RFC 9728). Access
tokens are JWTs (RFC 9068 profile) signed by an authorization server whose public keys are
provided as a JWKS file on local disk -- no network fetch happens on the request path, which
removes a whole class of SSRF / JWKS-poisoning problems and keeps validation deterministic.

Validation order (each step has a distinct, audited rejection reason):

1. size cap and structural parse of the JOSE header;
2. ``alg`` must be in the configured asymmetric allowlist (``none`` and every HMAC algorithm
   are impossible to configure, closing algorithm-confusion attacks);
3. ``crit`` headers are refused (we understand no extensions) and ``typ`` is checked;
4. key selection by ``kid`` -- an unknown ``kid`` triggers one rate-limited JWKS reload, which
   is how key rotation is picked up -- and the key's own ``alg``/``use`` must agree;
5. signature verification;
6. registered claims: ``iss`` exact match, ``aud`` must contain the gateway's resource URL
   (RFC 8707 audience binding, which stops token passthrough from other services),
   ``exp``/``nbf``/``iat`` against an injectable clock with bounded leeway;
7. identity claims: ``sub`` and ``client_id`` (or ``azp``) must be non-empty strings.

The verifier implements the SDK's :class:`mcp.server.auth.provider.TokenVerifier` protocol so
the SDK's bearer middleware produces the HTTP 401/403 responses and ``WWW-Authenticate``
headers required by the MCP spec.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jwt
from jwt import PyJWK
from mcp.server.auth.provider import AccessToken

from mcpgate.config import AuthConfig
from mcpgate.errors import AuthError

__all__ = ["JWKSStore", "JWTVerifier", "Principal", "RejectHook"]

logger = logging.getLogger(__name__)

_ASYMMETRIC_KTY = {"RSA", "EC", "OKP"}

RejectHook = Callable[[AuthError, dict[str, Any]], None]
"""Called with the rejection and non-secret header facts (``alg``, ``kid``) on every failure."""


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller as the rest of the gateway sees it."""

    client_id: str
    subject: str | None
    issuer: str | None
    scopes: frozenset[str] = field(default_factory=frozenset)
    token_id: str | None = None
    expires_at: int | None = None

    @classmethod
    def from_access_token(cls, token: AccessToken) -> Principal:
        claims = token.claims or {}
        iss = claims.get("iss")
        jti = claims.get("jti")
        return cls(
            client_id=token.client_id,
            subject=token.subject,
            issuer=str(iss) if iss is not None else None,
            scopes=frozenset(token.scopes),
            token_id=str(jti) if jti is not None else None,
            expires_at=token.expires_at,
        )


class JWKSStore:
    """A JWKS loaded from a local file, reloaded when the file changes or a kid is unknown."""

    def __init__(
        self,
        path: Path,
        *,
        min_reload_interval_s: float = 5.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._path = path
        self._min_interval = min_reload_interval_s
        self._monotonic = monotonic
        self._keys: dict[str | None, PyJWK] = {}
        self._mtime_ns: int | None = None
        self._last_load: float | None = None
        self.load()

    @property
    def key_ids(self) -> list[str | None]:
        return list(self._keys)

    def load(self) -> None:
        """(Re)read the JWKS file. Raises :class:`AuthError` if it is unusable."""
        try:
            stat = os.stat(self._path)
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise AuthError("jwks_unavailable", f"cannot load JWKS {self._path.name}: {exc}") from exc
        keys_raw = raw.get("keys") if isinstance(raw, dict) else None
        if not isinstance(keys_raw, list):
            raise AuthError("jwks_unavailable", "JWKS document has no 'keys' array")
        keys: dict[str | None, PyJWK] = {}
        for entry in keys_raw:
            if not isinstance(entry, dict) or entry.get("kty") not in _ASYMMETRIC_KTY:
                continue  # symmetric or malformed keys are never usable for verification here
            if "d" in entry:
                logger.warning("JWKS entry %r contains private key material; ignoring it", entry.get("kid"))
                continue
            try:
                jwk = PyJWK.from_dict(entry)
            except jwt.PyJWTError as exc:
                logger.warning("skipping unusable JWKS entry %r: %s", entry.get("kid"), exc)
                continue
            if entry.get("use") not in (None, "sig"):
                continue  # encryption keys must never verify signatures
            keys[entry.get("kid")] = jwk
        if not keys:
            raise AuthError("jwks_unavailable", "JWKS contains no usable public signing keys")
        self._keys = keys
        self._mtime_ns = stat.st_mtime_ns
        self._last_load = self._monotonic()
        logger.info("loaded %d signing key(s) from %s", len(keys), self._path.name)

    def _changed_on_disk(self) -> bool:
        try:
            return os.stat(self._path).st_mtime_ns != self._mtime_ns
        except OSError:
            return False

    def _may_reload(self) -> bool:
        return self._last_load is None or self._monotonic() - self._last_load >= self._min_interval

    def get(self, kid: str | None) -> PyJWK | None:
        """Look up a key; reload once (rate-limited) if the file changed or the kid is unknown."""
        if self._changed_on_disk() and self._may_reload():
            self._safe_reload()
        if kid is None:
            return next(iter(self._keys.values())) if len(self._keys) == 1 else None
        key = self._keys.get(kid)
        if key is None and self._may_reload():
            self._safe_reload()
            key = self._keys.get(kid)
        return key

    def _safe_reload(self) -> None:
        try:
            self.load()
        except AuthError as exc:
            # Keep serving with the last good key set rather than failing open or closed on a
            # half-written file; the next request retries after the interval.
            logger.error("JWKS reload failed, keeping previous keys: %s", exc)
            self._last_load = self._monotonic()


class JWTVerifier:
    """Validates RFC 9068 JWT access tokens; usable as the SDK's ``TokenVerifier``."""

    def __init__(
        self,
        config: AuthConfig,
        audience: str,
        *,
        clock: Callable[[], float] = time.time,
        jwks: JWKSStore | None = None,
        on_reject: RejectHook | None = None,
    ) -> None:
        self._cfg = config
        self._audience = audience
        self._clock = clock
        self._jwks = jwks or JWKSStore(config.jwks_file, min_reload_interval_s=config.jwks_reload_min_interval_s)
        self._on_reject = on_reject
        self._accepted_typ = {t.lower().removeprefix("application/") for t in config.accepted_typ}

    @property
    def audience(self) -> str:
        return self._audience

    async def verify_token(self, token: str) -> AccessToken | None:
        """SDK hook: return an :class:`AccessToken` or ``None`` (-> HTTP 401)."""
        try:
            return self.verify(token)
        except AuthError:
            return None

    def verify(self, token: str) -> AccessToken:
        """Validate ``token`` and return its access info, or raise :class:`AuthError`."""
        facts: dict[str, Any] = {}
        try:
            return self._verify(token, facts)
        except AuthError as exc:
            logger.info("bearer token rejected: %s", exc.reason)
            if self._on_reject is not None:
                self._on_reject(exc, facts)
            raise

    def _verify(self, token: str, facts: dict[str, Any]) -> AccessToken:
        if len(token.encode("utf-8", "replace")) > self._cfg.max_token_bytes:
            raise AuthError("token_too_large", f"token exceeds {self._cfg.max_token_bytes} bytes")
        header = _parse_header(token)
        alg = header.get("alg")
        kid = header.get("kid")
        facts.update(alg=alg, kid=kid)
        if not isinstance(alg, str) or alg not in self._cfg.algorithms:
            raise AuthError("algorithm_not_allowed", f"alg {alg!r} is not in the allowlist")
        if "crit" in header:
            raise AuthError("unsupported_critical_header", "tokens with 'crit' headers are refused")
        typ = header.get("typ")
        typ_norm = str(typ).lower().removeprefix("application/") if typ is not None else "jwt"
        if typ_norm not in self._accepted_typ:
            raise AuthError("wrong_token_type", f"typ {typ!r} is not accepted")
        if kid is not None and not isinstance(kid, str):
            raise AuthError("malformed_token", "kid must be a string")

        jwk = self._jwks.get(kid)
        if jwk is None:
            raise AuthError("unknown_key", f"no signing key for kid {kid!r}")
        if jwk.algorithm_name != alg:
            raise AuthError("algorithm_mismatch", f"key {kid!r} is for {jwk.algorithm_name}, token uses {alg}")
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=jwk.key,
                algorithms=[alg],
                options={
                    "verify_signature": True,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_sub": False,
                    "verify_jti": False,
                },
            )
        except jwt.InvalidSignatureError:
            raise AuthError("bad_signature", "signature verification failed") from None
        except jwt.PyJWTError as exc:
            raise AuthError("malformed_token", str(exc)) from None

        self._check_registered_claims(claims)
        return self._to_access_token(token, claims)

    def _check_registered_claims(self, claims: dict[str, Any]) -> None:
        now = self._clock()
        leeway = self._cfg.leeway_s
        if claims.get("iss") != self._cfg.issuer:
            raise AuthError("wrong_issuer", f"iss {claims.get('iss')!r} is not the trusted issuer")
        aud = claims.get("aud")
        audiences = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
        if self._audience not in audiences:
            raise AuthError("wrong_audience", "token was not issued for this gateway (aud mismatch)")
        exp = _numeric(claims, "exp", required=True)
        if exp is not None and now > exp + leeway:
            raise AuthError("token_expired", "exp is in the past")
        nbf = _numeric(claims, "nbf", required=False)
        if nbf is not None and now + leeway < nbf:
            raise AuthError("token_not_yet_valid", "nbf is in the future")
        iat = _numeric(claims, "iat", required=True)
        if iat is not None and now + leeway < iat:
            raise AuthError("token_not_yet_valid", "iat is in the future")
        if self._cfg.require_jti and not isinstance(claims.get("jti"), str):
            raise AuthError("missing_claim", "jti is required")

    def _to_access_token(self, token: str, claims: dict[str, Any]) -> AccessToken:
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise AuthError("missing_claim", "sub must be a non-empty string")
        client_id = claims.get("client_id", claims.get("azp"))
        if not isinstance(client_id, str) or not client_id:
            raise AuthError("missing_claim", "client_id (or azp) must be a non-empty string")
        scopes = _scopes(claims)
        kept = {k: claims[k] for k in ("iss", "jti", "iat") if k in claims}
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=sorted(scopes),
            expires_at=int(claims["exp"]),
            resource=self._audience,
            subject=subject,
            claims=kept,
        )


def _parse_header(token: str) -> dict[str, Any]:
    """Decode the JOSE header ourselves so every header-level failure gets a precise reason."""
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError("malformed_token", "a JWS compact token has exactly three segments")
    segment = parts[0]
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        header = json.loads(raw)
    except (ValueError, binascii.Error):
        raise AuthError("malformed_token", "header is not base64url-encoded JSON") from None
    if not isinstance(header, dict):
        raise AuthError("malformed_token", "header must be a JSON object")
    return header


def _numeric(claims: dict[str, Any], name: str, *, required: bool) -> float | None:
    value = claims.get(name)
    if value is None:
        if required:
            raise AuthError("missing_claim", f"{name} is required")
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise AuthError("malformed_token", f"{name} must be a NumericDate")
    return float(value)


def _scopes(claims: dict[str, Any]) -> set[str]:
    scope = claims.get("scope")
    if isinstance(scope, str):
        return {s for s in scope.split(" ") if s}
    scp = claims.get("scp")
    if isinstance(scp, list) and all(isinstance(s, str) for s in scp):
        return set(scp)
    if scope is None and scp is None:
        return set()
    raise AuthError("malformed_token", "scope must be a space-delimited string (or scp a string list)")
