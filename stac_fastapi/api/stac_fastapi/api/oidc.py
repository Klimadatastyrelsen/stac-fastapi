"""Optional OIDC authentication for any STAC API backend.

One credential reaches the API as an `Authorization: Bearer` header, a `token` header
or a `token` query parameter. A JWT is verified in-process against cached JWKS,
anything else is an opaque API key introspected over RFC 7662 behind a decision cache.
"""

import base64
import hashlib
import json
import logging
import time
import urllib.parse
import urllib.request
from threading import Lock
from typing import Dict, NamedTuple, Optional, Sequence, Set

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.routing import APIRoute
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from stac_fastapi.api.routes import add_route_dependencies

logger = logging.getLogger(__name__)
bearer = HTTPBearer(auto_error=False)
PUBLIC_USER_PRODUCTS = {"skraafoto_fri", "skraafoto_pix"}
DEFENCE_USER_PRODUCTS = {"skraafoto_fri", "skraafoto_forsvar"}
DEFENCE_PRODUCT = "skraafoto_forsvar"
API_KEY_SCOPE = "api:access"
UNAUTHORIZED = {"WWW-Authenticate": "Bearer"}
TIMEOUT = 3  # secs, outbound deadline for both jwks and introspection
DECISION_TTL = 30.0  # secs, the issuer's cache ceiling, so revocation lags by this
MAX_DECISIONS = 10_000


class _Decision(NamedTuple):
    expires_at: float
    claims: Optional[dict]  # None is a cached denial


def _deny() -> HTTPException:
    return HTTPException(status_code=401, detail="invalid token", headers=UNAUTHORIZED)


def _unavailable() -> HTTPException:
    return HTTPException(status_code=503, detail="authentication unavailable")


class OIDCTokenAuth:
    """Validate tokens using a cached JWKS client in FastAPI's worker pool."""

    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_url: str,
        algorithms: Sequence[str] = ("EdDSA",),
        introspection_url: str = "",
        introspection_client_id: str = "",
        introspection_client_secret: str = "",
    ):
        if not issuer or not audience or not jwks_url:
            raise ValueError("OIDC issuer, audience and JWKS URL are required")
        if not algorithms or any(
            not isinstance(value, str) or not value.strip() for value in algorithms
        ):
            raise ValueError("At least one non-empty JWT algorithm is required")
        if introspection_url and not (
            introspection_client_id and introspection_client_secret
        ):
            raise ValueError("Introspection requires a client id and secret")
        self.issuer = issuer
        self.audience = audience
        self.algorithms = tuple(value.strip() for value in algorithms)
        self.jwks = jwt.PyJWKClient(jwks_url, timeout=TIMEOUT)
        self.introspection_url = introspection_url
        self.introspection_client_id = introspection_client_id
        self.introspection_client_secret = introspection_client_secret
        self._decisions: Dict[str, _Decision] = {}
        self._lock = Lock()

    def __call__(
        self,
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    ) -> dict:
        token = (
            credentials.credentials
            if credentials
            else request.headers.get("token") or request.query_params.get("token")
        )
        if not token:
            raise HTTPException(
                status_code=401, detail="missing token", headers=UNAUTHORIZED
            )
        # three dot-separated segments is a jws, anything else can only be an opaque key
        claims = self._jwt(token) if token.count(".") == 2 else self._key(token)
        request.state.auth = claims
        request.scope["allowed_products"] = self._products(claims)
        return claims

    def _jwt(self, token: str) -> dict:
        try:
            key = self.jwks.get_signing_key_from_jwt(token).key
            return jwt.decode(
                token,
                key,
                algorithms=self.algorithms,
                issuer=self.issuer,
                audience=self.audience,
                leeway=60,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWKClientConnectionError as exc:
            logger.warning("OIDC signing keys unavailable: %s", exc)
            raise _unavailable() from exc
        except (jwt.InvalidTokenError, jwt.PyJWKClientError) as exc:
            logger.warning("OIDC token validation failed: %s", exc)
            raise _deny() from exc

    def _key(self, token: str) -> dict:
        if not self.introspection_url:
            raise _deny()
        digest = hashlib.blake2b(token.encode(), digest_size=16).hexdigest()
        cached = self._decisions.get(digest)
        decision = (
            cached
            if cached and cached.expires_at > time.monotonic()
            else self._resolve(digest, token)
        )
        if decision.claims is None:
            raise _deny()
        return decision.claims

    def _resolve(self, digest: str, token: str) -> _Decision:
        try:
            body = self._introspect(token)
        except Exception as exc:
            # a refusal here rejects this API's own credentials, never the caller's key
            logger.warning("Token introspection failed: %s", exc)
            raise _unavailable() from None
        claims = self._active(body)
        ttl = DECISION_TTL
        if claims is not None and claims.get("exp") is not None:
            ttl = min(ttl, max(0.0, claims["exp"] - time.time()))  # never outlive the key
        decision = _Decision(time.monotonic() + ttl, claims)
        with self._lock:
            if len(self._decisions) >= MAX_DECISIONS:
                # drop the oldest insert, dicts are ordered; an lru would buy nothing here
                del self._decisions[next(iter(self._decisions))]
            self._decisions[digest] = decision
        return decision

    def _introspect(self, token: str) -> dict:
        pair = f"{self.introspection_client_id}:{self.introspection_client_secret}"
        request = urllib.request.Request(
            self.introspection_url,
            data=urllib.parse.urlencode(
                {"token": token, "token_type_hint": "access_token"}
            ).encode(),
            headers={
                "authorization": "Basic " + base64.b64encode(pair.encode()).decode(),
                "content-type": "application/x-www-form-urlencoded",
                "accept": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return json.loads(response.read())

    def _active(self, body: dict) -> Optional[dict]:
        if body.get("active") is not True or body.get("iss") != self.issuer:
            return None
        audience = body.get("aud")
        audiences = {audience} if isinstance(audience, str) else set(audience or ())
        # a key names the applications it may be spent on, this API has to be one of them
        if self.introspection_client_id not in audiences:
            return None
        if API_KEY_SCOPE not in str(body.get("scope", "")).split():
            return None
        exp = body.get("exp")
        if exp is not None and (not isinstance(exp, (int, float)) or exp <= time.time()):
            return None
        subject = body.get("sub")
        if not isinstance(subject, str) or not subject:
            return None
        return body

    def _products(self, claims: dict) -> Set[str]:
        products = claims.get("hiddenProductSlugs", [])
        if not isinstance(products, list) or any(
            not isinstance(value, str) for value in products
        ):
            logger.warning("Invalid OIDC product entitlement claims")
            raise HTTPException(status_code=403, detail="invalid product entitlements")
        return (
            DEFENCE_USER_PRODUCTS
            if DEFENCE_PRODUCT in products
            else PUBLIC_USER_PRODUCTS
        )

    def install(self, app: FastAPI) -> None:
        """Protect registered API routes after all extensions have registered."""
        prefix = getattr(app.state, "router_prefix", "")
        for route in app.routes:
            if not isinstance(route, APIRoute) or route.path == f"{prefix}/_mgmt/ping":
                continue
            if any(dependency.dependency is self for dependency in route.dependencies):
                continue
            # One matching method attaches the dependency to the whole route.
            add_route_dependencies(
                [route],
                [{"path": route.path, "method": next(iter(route.methods))}],
                [Depends(self)],
            )
        app.openapi_schema = None
