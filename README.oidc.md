# OIDC authentication

Install the optional dependency:

```bash
pip install "stac-fastapi.api[oidc]"
```

Enable authentication after registering the API routes:

```python
from stac_fastapi.api.oidc import OIDCTokenAuth

OIDCTokenAuth(
    issuer="https://issuer.example",
    audience="stac",
    jwks_url="https://issuer.example/jwks",
    algorithms=("EdDSA",),
    introspection_url="https://issuer.example/api/keys/introspect",
    introspection_client_id="stac-api",
    introspection_client_secret="...",
).install(api.app)
```

One credential reaches the API as an `Authorization: Bearer` header, a `token`
header or a `token` query parameter, in that order of preference. The query
parameter carries the API keys that desktop clients use, which cannot run an
OAuth flow.

A token with three dot-separated segments is treated as a JWT and verified in
process against the cached JWKS. Validation defaults to EdDSA, with 60 seconds
of clock leeway and a 3-second JWKS timeout. Pass accepted JWT algorithms
through `algorithms`. Tokens must contain `exp`, `iat`, `iss`, `aud` and `sub`.

Anything else is an opaque API key, which carries nothing to verify, so it is
resolved at the issuer over RFC 7662. The call is a form POST authenticated as
this API's own OAuth client with HTTP Basic. A key is accepted when the reply
is `active`, names this issuer in `iss`, names the introspection client id in
`aud`, holds `api:access` in `scope`, has not expired and carries a subject.
Decisions, allow and deny alike, are cached for 30 seconds and never past the
key's `exp`, so a revoked key keeps working for up to 30 seconds. Transport
failures are not cached and answer 503. Without `introspection_url` the opaque
path is closed and only JWTs are accepted.

The dependency makes the claims, or the introspection reply, available through
`request.state.auth`. Product access is derived from the `hiddenProductSlugs`
claim: an absent or empty claim selects the standard profile, while the defence
marker selects the defence profile. The claim lists every hidden product the
holder reaches, so other slugs are ignored; a claim that is not a list of
strings is rejected. `request.scope["allowed_products"]` contains the resulting
product allowlist. An API key carries the claim only from kds-auth 3.8.0, and
only an organisation key can hold a hidden product.
