import base64
import contextlib
import io
import json
import time
import urllib.error
from datetime import datetime
from types import SimpleNamespace
from unittest import mock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import stac_fastapi.api.oidc as oidc
from stac_fastapi.api.oidc import OIDCTokenAuth
from test_api import TestRouteDependencies as RouteDependencies


@pytest.fixture
def authenticated_app(monkeypatch):
    monkeypatch.setattr(oidc, "PUBLIC_USER_PRODUCTS", {"demo-product"})
    monkeypatch.setattr(
        oidc, "DEFENCE_USER_PRODUCTS", {"demo-product", "defence-product"}
    )
    monkeypatch.setattr(oidc, "DEFENCE_PRODUCT", "defence-product")
    private_key = Ed25519PrivateKey.generate()
    auth = OIDCTokenAuth("https://issuer.example", "stac", "https://issuer.example/jwks")
    monkeypatch.setattr(
        auth.jwks,
        "get_signing_key_from_jwt",
        lambda token: SimpleNamespace(key=private_key.public_key()),
    )
    app = FastAPI()

    @app.api_route("/data", methods=["GET", "POST", "PUT", "DELETE"])
    def data(request: Request):
        return {
            "sub": request.state.auth["sub"],
            "products": sorted(request.scope["allowed_products"]),
        }

    @app.get("/_mgmt/ping")
    def ping():
        return {"message": "PONG"}

    auth.install(app)
    auth.install(app)
    return app, auth, private_key


def token(private_key, **overrides):
    now = int(time.time())
    claims = {
        "iss": "https://issuer.example",
        "aud": "stac",
        "sub": "demo-user",
        "iat": now,
        "exp": now + 300,
        "hiddenProductSlugs": ["defence-product"],
        **overrides,
    }
    return jwt.encode(claims, private_key, algorithm="EdDSA")


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE"])
def test_missing_token_and_valid_token(authenticated_app, method):
    app, _, key = authenticated_app
    with TestClient(app) as client:
        response = client.request(method, "/data")
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
        response = client.request(
            method, "/data", headers={"Authorization": f"Bearer {token(key)}"}
        )
        assert response.status_code == 200
        assert response.json() == {
            "sub": "demo-user",
            "products": ["defence-product", "demo-product"],
        }
    data_route = next(route for route in app.routes if route.path == "/data")
    assert len(data_route.dependencies) == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://wrong.example"},
        {"aud": "wrong"},
        {"exp": 1},
        {"iat": int(time.time()) + 3600},
    ],
)
def test_invalid_claims(authenticated_app, overrides):
    app, _, key = authenticated_app
    with TestClient(app) as client:
        response = client.get(
            "/data", headers={"Authorization": f"Bearer {token(key, **overrides)}"}
        )
        assert response.status_code == 401


@pytest.mark.parametrize(
    "claim,offset,status",
    [("exp", -59, 200), ("exp", -60, 401), ("iat", 60, 200), ("iat", 61, 401)],
)
def test_fixed_leeway(authenticated_app, monkeypatch, claim, offset, status):
    app, _, key = authenticated_app
    now = int(time.time())

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromtimestamp(now, tz)

    monkeypatch.setattr(jwt.api_jwt, "datetime", FrozenDatetime)
    encoded = token(key, **{"iat": now, "exp": now + 300, claim: now + offset})
    with TestClient(app) as client:
        response = client.get("/data", headers={"Authorization": f"Bearer {encoded}"})
        assert response.status_code == status


@pytest.mark.parametrize("claim", ["iss", "aud", "sub", "iat", "exp"])
def test_required_claims(authenticated_app, claim):
    app, _, key = authenticated_app
    claims = jwt.decode(token(key), options={"verify_signature": False})
    del claims[claim]
    encoded = jwt.encode(claims, key, algorithm="EdDSA")
    with TestClient(app) as client:
        assert client.get(
            "/data", headers={"Authorization": f"Bearer {encoded}"}
        ).status_code == 401


@pytest.mark.parametrize("authorization", ["Basic abc", "Bearer", "Bearer malformed"])
def test_malformed_credentials(authenticated_app, authorization):
    app, _, _ = authenticated_app
    with TestClient(app) as client:
        assert client.get(
            "/data", headers={"Authorization": authorization}
        ).status_code == 401


def test_invalid_signature(authenticated_app):
    app, _, _ = authenticated_app
    other_key = Ed25519PrivateKey.generate()
    with TestClient(app) as client:
        assert client.get(
            "/data", headers={"Authorization": f"Bearer {token(other_key)}"}
        ).status_code == 401


def test_disallowed_algorithm(authenticated_app):
    app, _, _ = authenticated_app
    encoded = jwt.encode({"sub": "demo-user"}, "not-an-allowed-key", algorithm="HS256")
    with TestClient(app) as client:
        assert client.get(
            "/data", headers={"Authorization": f"Bearer {encoded}"}
        ).status_code == 401


@pytest.mark.parametrize("algorithm", ["HS256", "EdDSA"])
def test_configured_algorithm(monkeypatch, algorithm):
    monkeypatch.setattr(oidc, "PUBLIC_USER_PRODUCTS", {"demo-product"})
    app = FastAPI()
    if algorithm == "EdDSA":
        signing_key = Ed25519PrivateKey.generate()
        verification_key = signing_key.public_key()
    else:
        signing_key = verification_key = "configured-test-secret"
    auth = OIDCTokenAuth(
        "https://issuer.example",
        "stac",
        "https://issuer.example/jwks",
        algorithms=[algorithm],
    )
    monkeypatch.setattr(
        auth.jwks,
        "get_signing_key_from_jwt",
        lambda token: SimpleNamespace(key=verification_key),
    )

    @app.get("/data")
    def data(request: Request):
        return {"products": sorted(request.scope["allowed_products"])}

    auth.install(app)
    now = int(time.time())
    encoded = jwt.encode(
        {
            "iss": "https://issuer.example",
            "aud": "stac",
            "sub": "demo-user",
            "iat": now,
            "exp": now + 300,
            "hiddenProductSlugs": [],
        },
        signing_key,
        algorithm=algorithm,
    )
    with TestClient(app) as client:
        response = client.get("/data", headers={"Authorization": f"Bearer {encoded}"})
    assert response.status_code == 200
    assert response.json() == {
        "products": ["demo-product"],
    }
    assert auth.algorithms == (algorithm,)


@pytest.mark.parametrize("algorithms", [(), ("",), ("  ",)])
def test_empty_configured_algorithms_are_rejected(algorithms):
    with pytest.raises(ValueError, match="JWT algorithm"):
        OIDCTokenAuth(
            "https://issuer.example",
            "stac",
            "https://issuer.example/jwks",
            algorithms=algorithms,
        )


@pytest.mark.parametrize(
    "error,status",
    [
        (jwt.PyJWKClientConnectionError("unavailable"), 503),
        (jwt.PyJWKClientError("unknown kid"), 401),
    ],
)
def test_jwks_failures(authenticated_app, monkeypatch, error, status):
    app, auth, key = authenticated_app

    def fail(token):
        raise error

    monkeypatch.setattr(auth.jwks, "get_signing_key_from_jwt", fail)
    with TestClient(app) as client:
        assert client.get(
            "/data", headers={"Authorization": f"Bearer {token(key)}"}
        ).status_code == status


def test_public_routes_and_openapi(authenticated_app):
    app, _, _ = authenticated_app
    with TestClient(app) as client:
        for path in ["/_mgmt/ping", "/docs", "/openapi.json"]:
            assert client.get(path).status_code == 200
        schema = client.get("/openapi.json").json()
        assert schema["components"]["securitySchemes"]["HTTPBearer"]["scheme"] == "bearer"
        for method in ["get", "post", "put", "delete"]:
            assert schema["paths"]["/data"][method]["security"] == [{"HTTPBearer": []}]


def test_stac_extension_routes_are_protected():
    api = RouteDependencies._build_api()
    auth = OIDCTokenAuth("https://issuer.example", "stac", "https://issuer.example/jwks")
    auth.install(api.app)
    with TestClient(api.app) as client:
        for method, path in [
            ("GET", "/"),
            ("GET", "/collections"),
            ("POST", "/search"),
            ("POST", "/collections"),
            ("DELETE", "/collections/demo"),
            ("POST", "/collections/demo/items"),
        ]:
            assert client.request(method, path).status_code == 401
        assert client.get("/_mgmt/ping").status_code == 200


def test_late_routes_are_protected_on_reinstallation(authenticated_app):
    app, auth, key = authenticated_app

    @app.get("/late")
    def late():
        return {}

    auth.install(app)
    with TestClient(app) as client:
        assert client.get("/late").status_code == 401
        assert client.get(
            "/late", headers={"Authorization": f"Bearer {token(key)}"}
        ).status_code == 200


@pytest.mark.parametrize(
    "overrides,status,products",
    [
        ({}, 200, ["demo-product"]),
        ({"hiddenProductSlugs": []}, 200, ["demo-product"]),
        (
            {"hiddenProductSlugs": ["defence-product", "defence-product"]},
            200,
            ["defence-product", "demo-product"],
        ),
        ({"hiddenProductSlugs": ["unknown"]}, 200, ["demo-product"]),
        (
            {"hiddenProductSlugs": ["defence-product", "unknown"]},
            200,
            ["defence-product", "demo-product"],
        ),
        ({"hiddenProductSlugs": None}, 403, None),
        ({"hiddenProductSlugs": "defence-product"}, 403, None),
        ({"hiddenProductSlugs": [123]}, 403, None),
    ],
)
def test_product_claim_validation(authenticated_app, overrides, status, products):
    app, _, key = authenticated_app
    claims = jwt.decode(token(key), options={"verify_signature": False})
    del claims["hiddenProductSlugs"]
    claims.update(overrides)
    encoded = jwt.encode(claims, key, algorithm="EdDSA")
    with TestClient(app) as client:
        response = client.get("/data", headers={"Authorization": f"Bearer {encoded}"})
        assert response.status_code == status
        if status == 200:
            assert response.json()["products"] == products


def test_prefixed_health_route_is_public():
    app = FastAPI()
    app.state.router_prefix = "/stac"

    @app.get("/stac/_mgmt/ping")
    def ping():
        return {}

    @app.get("/stac/collections")
    def collections():
        return {}

    OIDCTokenAuth("https://issuer.example", "stac", "https://issuer.example/jwks").install(app)
    with TestClient(app) as client:
        assert client.get("/stac/_mgmt/ping").status_code == 200
        assert client.get("/stac/collections").status_code == 401


@pytest.fixture
def introspecting_app(monkeypatch):
    monkeypatch.setattr(oidc, "PUBLIC_USER_PRODUCTS", {"demo-product"})
    monkeypatch.setattr(oidc, "DEFENCE_PRODUCT", "defence-product")
    auth = OIDCTokenAuth(
        "https://issuer.example",
        "stac",
        "https://issuer.example/jwks",
        introspection_url="https://issuer.example/api/keys/introspect",
        introspection_client_id="stac-api",
        introspection_client_secret="s3cret",
    )
    calls = []

    def introspect(token):
        calls.append(token)
        return reply()

    monkeypatch.setattr(auth, "_introspect", introspect)
    app = FastAPI()

    @app.get("/data")
    def data(request: Request):
        return {
            "sub": request.state.auth["sub"],
            "products": sorted(request.scope["allowed_products"]),
        }

    auth.install(app)
    return app, auth, calls


def reply(**overrides):
    now = int(time.time())
    return {
        "active": True,
        "iss": "https://issuer.example",
        "sub": "org:demo-org",
        "aud": ["stac-api"],
        "scope": "api:access",
        "jti": "key-1",
        "iat": now,
        "exp": now + 3600,
        **overrides,
    }


@pytest.mark.parametrize(
    "call",
    [
        lambda client: client.get(
            "/data", headers={"Authorization": "Bearer opaque-key"}
        ),
        lambda client: client.get("/data", headers={"token": "opaque-key"}),
        lambda client: client.get("/data", params={"token": "opaque-key"}),
    ],
    ids=["authorization", "header", "query"],
)
def test_opaque_key_from_every_source(introspecting_app, call):
    app, _, calls = introspecting_app
    with TestClient(app) as client:
        response = call(client)
    assert response.status_code == 200
    assert response.json() == {"sub": "org:demo-org", "products": ["demo-product"]}
    assert calls == ["opaque-key"]


def test_jwt_still_verifies_locally_when_introspection_is_configured(
    introspecting_app, monkeypatch
):
    app, auth, calls = introspecting_app
    private_key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(
        auth.jwks,
        "get_signing_key_from_jwt",
        lambda token: SimpleNamespace(key=private_key.public_key()),
    )
    with TestClient(app) as client:
        response = client.get("/data", params={"token": token(private_key)})
    assert response.status_code == 200
    assert response.json()["sub"] == "demo-user"
    assert calls == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"active": False},
        {"iss": "https://wrong.example"},
        {"aud": ["other-api"]},
        {"aud": None},
        {"scope": "openid profile"},
        {"exp": int(time.time()) - 1},
        {"sub": ""},
    ],
)
def test_unusable_key_is_denied(introspecting_app, monkeypatch, overrides):
    app, auth, _ = introspecting_app
    monkeypatch.setattr(auth, "_introspect", lambda token: reply(**overrides))
    with TestClient(app) as client:
        response = client.get("/data", params={"token": "opaque-key"})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_a_single_audience_string_is_accepted(introspecting_app, monkeypatch):
    app, auth, _ = introspecting_app
    monkeypatch.setattr(auth, "_introspect", lambda token: reply(aud="stac-api"))
    with TestClient(app) as client:
        assert client.get("/data", params={"token": "opaque-key"}).status_code == 200


def test_opaque_keys_need_a_configured_introspection_endpoint(monkeypatch):
    monkeypatch.setattr(oidc, "PUBLIC_USER_PRODUCTS", {"demo-product"})
    auth = OIDCTokenAuth("https://issuer.example", "stac", "https://issuer.example/jwks")
    app = FastAPI()

    @app.get("/data")
    def data(request: Request):
        return {"sub": request.state.auth["sub"]}

    auth.install(app)
    with TestClient(app) as client:
        assert client.get("/data", params={"token": "opaque-key"}).status_code == 401


def test_introspection_needs_client_credentials():
    with pytest.raises(ValueError):
        OIDCTokenAuth(
            "https://issuer.example",
            "stac",
            "https://issuer.example/jwks",
            introspection_url="https://issuer.example/api/keys/introspect",
        )


def test_decisions_are_cached_and_capped(introspecting_app):
    app, auth, calls = introspecting_app
    with TestClient(app) as client:
        for _ in range(3):
            assert client.get("/data", params={"token": "opaque-key"}).status_code == 200
    assert len(calls) == 1
    assert len(auth._decisions) == 1
    expires_at, _ = next(iter(auth._decisions.values()))
    assert expires_at <= time.monotonic() + oidc.DECISION_TTL


def test_a_denial_is_cached_too(introspecting_app, monkeypatch):
    app, auth, calls = introspecting_app

    def introspect(token):
        calls.append(token)
        return {"active": False}

    monkeypatch.setattr(auth, "_introspect", introspect)
    with TestClient(app) as client:
        for _ in range(3):
            assert client.get("/data", params={"token": "opaque-key"}).status_code == 401
    assert len(calls) == 1


def test_a_decision_is_never_cached_past_the_keys_expiry(introspecting_app, monkeypatch):
    app, auth, _ = introspecting_app
    monkeypatch.setattr(
        auth, "_introspect", lambda token: reply(exp=int(time.time()) + 5)
    )
    with TestClient(app) as client:
        assert client.get("/data", params={"token": "opaque-key"}).status_code == 200
    expires_at, _ = next(iter(auth._decisions.values()))
    assert expires_at <= time.monotonic() + 5


def test_the_oldest_decision_is_evicted(introspecting_app, monkeypatch):
    app, auth, _ = introspecting_app
    monkeypatch.setattr(oidc, "MAX_DECISIONS", 2)
    with TestClient(app) as client:
        for key in ["a", "b", "c"]:
            assert client.get("/data", params={"token": key}).status_code == 200
    assert len(auth._decisions) == 2


@pytest.mark.parametrize(
    "boom",
    [
        # built on demand: an HTTPError holds a file object, which pytest cannot name
        lambda: urllib.error.HTTPError("url", 401, "invalid_client", {}, None),
        lambda: urllib.error.URLError("connection refused"),
        lambda: ValueError("not json"),
    ],
    ids=["refused", "unreachable", "unparseable"],
)
def test_introspection_failure_is_unavailable_and_uncached(
    introspecting_app, monkeypatch, boom
):
    app, auth, calls = introspecting_app

    def introspect(token):
        calls.append(token)
        raise boom()

    monkeypatch.setattr(auth, "_introspect", introspect)
    with TestClient(app, raise_server_exceptions=False) as client:
        for _ in range(2):
            assert client.get("/data", params={"token": "opaque-key"}).status_code == 503
    assert len(calls) == 2
    assert auth._decisions == {}


def test_the_introspection_request_is_a_basic_authenticated_form(introspecting_app):
    _, auth, _ = introspecting_app
    sent = {}
    introspect = OIDCTokenAuth._introspect  # the fixture stubbed the bound one away

    def urlopen(request, timeout=None):
        sent["url"] = request.full_url
        sent["headers"] = {k.lower(): v for k, v in request.headers.items()}
        sent["body"] = request.data.decode()
        return contextlib.closing(io.BytesIO(json.dumps(reply()).encode()))

    with mock.patch.object(oidc.urllib.request, "urlopen", urlopen):
        assert introspect(auth, "opaque-key")["active"] is True
    assert sent["url"] == "https://issuer.example/api/keys/introspect"
    assert sent["body"] == "token=opaque-key&token_type_hint=access_token"
    assert sent["headers"]["authorization"] == "Basic " + base64.b64encode(
        b"stac-api:s3cret"
    ).decode()
    assert sent["headers"]["content-type"] == "application/x-www-form-urlencoded"
