# aauth

Python primitives for [AAuth Protocol draft -11](https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol-11), built on HTTP Message Signatures (RFC 9421), Signature-Key discovery, and JWT proof of possession.

| Package | Install | Responsibility |
|---|---|---|
| `aauth` | `pip install aauth` | Agent/resource APIs, person/auth/resource tokens, discovery, deferred requests, missions, and revocation helpers |
| `aauth-signing` | `pip install aauth-signing` | Standalone HTTP signatures and Signature-Key (`hwk`, `jwks_uri`, `jwt`, `jkt-jwt`) |

`aauth` re-exports the signing package. AAuth agents use `jwt`; servers signing in their own right use `jwks_uri`. Other schemes remain available through the standalone signing API.

## Draft -11 flow

1. The agent presents its agent token to its Person Server (PS).
2. The PS issues a person token for a specific resource.
3. The agent presents the person token to the resource.
4. The resource verifies it and issues a resource token naming its `jti`.
5. The agent sends both `resource_token` and `presented_token` to its PS's `auth_token_endpoint`.
6. The agent presents the resulting auth token to the resource. In four-party access, the PS obtains the auth token from the Access Server (AS); the agent still calls its own PS.

Agent identity and resource-managed access use an agent token directly. A resource-managed session additionally uses `Authorization: AAuth <session-token>`.

## Local token and verification example

This example uses generated keys and an in-memory JWKS lookup. Production applications provide issuer discovery, caching, egress policy, and a trusted issuer configuration.

```python
import time
import aauth

AP = "https://agent.example"
PS = "https://ps.example"
RESOURCE = "https://resource.example"

agent_private, agent_public = aauth.generate_ed25519_keypair()
provider_private, provider_public = aauth.generate_ed25519_keypair()
ps_private, ps_public = aauth.generate_ed25519_keypair()
resource_private, resource_public = aauth.generate_ed25519_keypair()
agent_jwk = aauth.public_key_to_jwk(agent_public)

issuer_keys = {
    AP: {"keys": [aauth.public_key_to_jwk(provider_public, kid="provider-1")]},
    PS: {"keys": [aauth.public_key_to_jwk(ps_public, kid="ps-1")]},
    RESOURCE: {"keys": [aauth.public_key_to_jwk(resource_public, kid="resource-1")]},
}

def jwks_fetcher(issuer, dwk, kid):
    return issuer_keys[issuer]

agent_exp = int(time.time()) + 1800
agent_token = aauth.create_agent_token(
    AP, "aauth:Agent@agent.example", agent_jwk,
    provider_private, "provider-1", exp=agent_exp, ps=PS,
)

# At the PS, after authenticating the agent and obtaining consent:
person_token = aauth.create_person_token(
    PS, RESOURCE, "directed-person-id", agent_jwk, ps_private, "ps-1",
    agent_exp=agent_exp,
)
person_claims = aauth.verify_person_token(
    person_token, jwks_fetcher, expected_aud=RESOURCE,
    request_signing_jwk=agent_jwk,
)

# At the resource, after verifying the signed request:
resource_token = aauth.create_resource_token(
    RESOURCE, PS, aauth.calculate_jwk_thumbprint(agent_jwk),
    resource_private, "resource-1", presented_token=person_token,
    jwks_fetcher=jwks_fetcher, scope="data.read",
)

# At the PS, after verifying the resource-token/presented-token pair:
resource_claims = aauth.verify_resource_token(
    resource_token, jwks_fetcher, presented_token=person_token,
    expected_aud=PS, expected_ps=PS,
    expected_agent_jkt=aauth.calculate_jwk_thumbprint(agent_jwk),
)
auth_token = aauth.create_auth_token(
    PS, RESOURCE, agent_jwk, ps_private, "ps-1",
    ps=PS, sub=resource_claims["sub"], scope="data.read",
    agent_exp=agent_exp, presented_exp=person_claims["exp"],
    dwk="aauth-person.json",
)

signer = aauth.AgentRequestSigner(agent_private, agent_token=agent_token)
headers = signer.sign_request("GET", RESOURCE + "/data", {}, token=auth_token)
verifier = aauth.RequestVerifier(
    canonical_authorities=["resource.example"], resource_id=RESOURCE,
    jwks_fetcher=jwks_fetcher, trusted_auth_servers=[PS],
)
result = verifier.verify_request(
    "GET", RESOURCE + "/data", headers,
    require_auth_token=True, required_scopes=["data.read"],
)
assert result["valid"]
assert result["user_sub"] == "directed-person-id"
```

`RequestVerifier` checks JWT type, issuer trust, audience, required claims, key algorithms, expiration, request-signature freshness and coverage, and any covered body digest. `require_identity=True` specifically requires an agent token. An auth token identifies a person and authorization; it does not carry an agent identifier. An empty trusted-issuer list authorizes no person/auth issuers.

## Async acquisition and exchange

```python
person_token = await aauth.request_person_token(
    PS, RESOURCE, agent_private, agent_token,
    jwks_fetcher=jwks_fetcher, capabilities=["interaction"],
)

# resource_token comes from the resource's AAuth-Requirement response.
auth_token = await aauth.exchange_resource_token(
    resource_token, agent_private, agent_token,
    presented_token=person_token, resource_id=RESOURCE, person_server=PS,
    jwks_fetcher=jwks_fetcher,
)
```

The exchange verifies the resource challenge before discovery, reads `auth_token_endpoint`, signs the JSON body, handles immediate/deferred issuance, and validates the returned token. Discovery failures are surfaced; there is no guessed `/token` fallback. Pending URLs must remain on the responding server's origin.

For `202` auth challenges that hold a resource invocation, use `complete_deferred_resource_request(response, request_uri, ...)` with the same exchange context. It acquires the auth token and polls using that token, without repeating the original invocation. `PollingResult.response` preserves the terminal HTTP response, including non-JSON application results.

The sync and async pollers handle interaction requirements from headers, late interaction prompts, clarification actions, problem details, and backoff. Applications supply interaction/clarification callbacks. Servers supply durable pending records and ownership checks.

## Signing bodies and sessions

For a request with a body to a PS, AS, or revocation endpoint, use `AgentRequestSigner.sign_request(..., recipient_role="ps")` (or `"as"` / `"revocation"`). It covers `content-digest` and `content-type`. The standalone `sign_request` requires those components explicitly through `additional_signature_components`.

Resource body coverage is declared with `additional_signature_components` on both the signer and `RequestVerifier`. A covered digest is checked against the actual received bytes. `Authorization` is automatically covered when present.

Session credentials must be a single token68 value. Configure `session_token_verifier(token, signing_key_thumbprint)` to verify the resource's stored session binding; use `require_session_token=True` to require it. Applications must store each new `AAuth-Access` value for subsequent requests.

## Metadata and keys

`generate_ps_metadata` requires `auth_token_endpoint` and `person_token_endpoint`. Metadata uses `name`, `description`, `documentation_uri`, and optional `accept_signature_algs`. Discovery verifies the returned `issuer` against the requested server identifier.

JWKs include a fully specified `alg`: `Ed25519`, `ES256`, or `ES384`. JWTs use the same identifiers. The signing package uses its own PyJWT registry to support `Ed25519` without modifying the application's global registry. `EdDSA`, symmetric algorithms, missing algorithms, and key/algorithm mismatches are rejected.

The synchronous verification APIs take a synchronous JWKS callback accepting `(issuer, dwk, kid)`; one-argument callbacks are also supported. `JWKSFetcher.fetch` is async and can populate an application-owned cache; it is not directly usable as that synchronous callback. The built-in network clients perform public-address admission. Applications supplying custom clients or JWKS callbacks own their egress policy. Enforce network egress separately in production to address DNS changes between admission and connection.

## Missions, refresh, and revocation

Use `mission_s256` on person-token requests and tokens. `AAuth-Mission` and the old `{approver, s256}` token claim are removed. `build_mission_approval` returns base64url mission bytes and their hash; `parse_mission_approval` verifies those exact bytes. `mission_request` constructs update/completion requests to the mission's URL.

Issuers supply verified dependency expiration timestamps to token constructors. Person/auth lifetimes are capped at one hour and at their agent, presented, upstream, and mission bounds. Mission-aware issuance requires a mission expiration bound. PS verification of mission-bearing resource tokens requires `mission_checker(hash)` to check current mission state. `token_needs_refresh` reports the five-minute refresh margin; applications refresh agent, person, and auth credentials in that order.

`RevocationStore` tracks `(iss, jti)` entries, accepted agent identities, and issued-token dependencies. `RevocationManager` records revocation before sending and waits for terminal cascade outcomes; repeated requests retry failed deliveries. Register every accepted agent token and issued-token dependency so cascades can reach them. Configure `revocation_checker=store.is_revoked` on token/request verification. `sign_revocation_request` and `send_revocation` use signed `{jti, exp}` bodies and same-origin server polling.

The included store is in memory. Multi-worker deployments must provide shared durable state. Applications host HTTP routes, apply revocation quotas, persist pending sessions, and authenticate users; these helpers do not implement a complete PS/AS service.

## Migrating from 0.3.x

This is a breaking protocol update. Token constructors require person/dependency context. Resource/auth tokens no longer emit `agent`, `act`, or `mission`; legacy JWTs using `EdDSA` are rejected. The exchange requires `presented_token`, `resource_id`, `person_server`, and a JWKS fetcher. PS/AS metadata uses `auth_token_endpoint`. Removed login metadata is not emitted. See the [upstream migration guides](https://github.com/dickhardt/AAuth/tree/main/upgrade-10-to-11).

Target: published draft -11. Open -12 proposals, including changing person identity to `(ps, sub)` and adding signature nonces, are not adopted here. Consumers should retain issuer and PS context with `sub`; do not key records on `sub` alone.

## Development

```bash
uv sync --extra dev
uv run pytest tests/ -q
```

Both the protocol regressions and HTTP transport tests run without external services.

MIT license.
