"""Draft -11 interoperability and adversarial validation regressions."""

import asyncio
import base64
import json
import time
from unittest.mock import AsyncMock

import httpx
import jwt
import pytest

import aauth
from aauth_signing.signature_base import build_signature_base
from aauth_signing.signature_key import build_signature_key_header
from aauth_signing.signature import build_signature_header
from aauth.errors import TokenError, SignatureError

RESOURCE = "https://resource.example"
PS = "https://ps.example"
AP = "https://agent.example"


@pytest.fixture
def ctx():
    agent, pub = aauth.generate_ed25519_keypair()
    issuer, ipub = aauth.generate_ed25519_keypair()
    jwk = aauth.public_key_to_jwk(pub)
    ijwk = aauth.public_key_to_jwk(ipub, kid="issuer-1")
    now = int(time.time())
    return dict(
        agent=agent,
        issuer=issuer,
        jwk=jwk,
        ijwk=ijwk,
        now=now,
        fetch=lambda *args: {"keys": [ijwk]},
    )


def claims(c, typ="aa-auth+jwt", **changes):
    p = dict(
        iss=PS,
        aud=RESOURCE,
        sub="person-1",
        ps=PS,
        dwk="aauth-person.json",
        jti="token-1",
        iat=c["now"],
        exp=c["now"] + 600,
        cnf={"jwk": c["jwk"]},
        scope="read",
    )
    if typ == "aa-agent+jwt":
        p.update(iss=AP, sub="aauth:Agent@agent.example", dwk="aauth-agent.json")
        p.pop("ps")
    if typ == "aa-person+jwt":
        p.pop("ps")
        p.pop("scope")
    p.update(changes)
    return p


def mint(c, payload, typ="aa-auth+jwt", alg="Ed25519"):
    # Independent encoding: test the wire format, not the library's encoder.
    h = {"alg": alg, "kid": "issuer-1", "typ": typ}
    enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
    data = enc(json.dumps(h).encode()) + b"." + enc(json.dumps(payload).encode())
    return (data + b"." + enc(c["issuer"].sign(data))).decode()


def signed(c, token, components=None, params=None, body=None, headers=None):
    headers = dict(headers or {})
    if components is None:
        headers.update(
            aauth.sign_request(
                "GET",
                RESOURCE + "/data",
                headers,
                body,
                c["agent"],
                sig_scheme="jwt",
                jwt=token,
            )
        )
        return headers
    sk = build_signature_key_header("jwt", jwt=token)
    params = (
        params
        or "(" + " ".join('"' + v + '"' for v in components) + f');created={c["now"]}'
    )
    base = build_signature_base(
        "GET", "resource.example", "/data", None, headers, body, sk, components, params
    )
    return {
        **headers,
        "Signature-Key": sk,
        "Signature-Input": "sig=" + params,
        "Signature": build_signature_header(c["agent"].sign(base.encode())),
    }


def verify(c, headers, body=None, **kw):
    v = aauth.RequestVerifier(
        ["resource.example"],
        c["fetch"],
        trusted_auth_servers=[PS],
        resource_id=RESOURCE,
    )
    return v.verify_request("GET", RESOURCE + "/data", headers, body, **kw)


@pytest.mark.parametrize(
    "change",
    [
        dict(aud="https://other.example"),
        dict(iss="https://untrusted.example"),
        dict(exp=None),
        dict(iat=None),
        dict(jti=None),
        dict(dwk="aauth-agent.json"),
        dict(sub=None),
        dict(ps=None),
        dict(exp=True),
    ],
)
def test_resource_rejects_invalid_auth_context(ctx, change):
    p = claims(ctx, **change)
    p = {k: v for k, v in p.items() if v is not None}
    assert not verify(ctx, signed(ctx, mint(ctx, p)), require_auth_token=True)["valid"]


def test_current_auth_token_accepted_without_agent_or_act(ctx):
    p = claims(ctx)
    result = verify(ctx, signed(ctx, mint(ctx, p)), require_auth_token=True)
    assert result["valid"] and result["user_sub"] == "person-1"
    assert result["agent_id"] is None


@pytest.mark.parametrize("typ", ["aa-person+jwt", "aa-agent+jwt", "unrelated+jwt"])
def test_other_token_types_cannot_authorize(ctx, typ):
    assert not verify(
        ctx, signed(ctx, mint(ctx, claims(ctx, typ), typ)), require_auth_token=True
    )["valid"]


@pytest.mark.parametrize(
    "components,params",
    [
        (["@method"], None),
        (
            ["@method", "@authority", "@path", "signature-key"],
            '("@method" "@authority" "@path" "signature-key")',
        ),
        (
            ["@method", "@authority", "@path", "signature-key"],
            '("@method" "@authority" "@path" "signature-key");created=1',
        ),
        (["@method", "@authority", "@path", "signature-key"], None),
    ],
)
def test_signature_rejects_missing_coverage_freshness_and_expiry(
    ctx, components, params
):
    if params is None and len(components) > 1:
        params = (
            '("@method" "@authority" "@path" "signature-key");created='
            + str(ctx["now"])
            + ";expires=1"
        )
    assert not verify(
        ctx,
        signed(ctx, mint(ctx, claims(ctx)), components, params),
        require_auth_token=True,
    )["valid"]


def test_digest_checked_against_actual_body(ctx):
    headers = {"Content-Type": "application/json"}
    body = b'{"scope":"read"}'
    headers.update(
        aauth.sign_request(
            "GET",
            RESOURCE + "/data",
            headers,
            body,
            ctx["agent"],
            sig_scheme="jwt",
            jwt=mint(ctx, claims(ctx)),
            additional_signature_components=["content-digest", "content-type"],
        )
    )
    assert verify(ctx, headers, body, require_auth_token=True)["valid"]
    assert not verify(ctx, headers, b'{"scope":"admin"}', require_auth_token=True)[
        "valid"
    ]


@pytest.mark.parametrize("alg", ["EdDSA", "HS256", "none"])
def test_polymorphic_and_symmetric_algorithms_rejected(ctx, alg):
    assert not verify(
        ctx, signed(ctx, mint(ctx, claims(ctx), alg=alg)), require_auth_token=True
    )["valid"]


@pytest.mark.parametrize("jwk_change", [{"alg": None}, {"alg": "ES256"}])
def test_confirmation_algorithm_required_and_bound(ctx, jwk_change):
    p = claims(ctx)
    p["cnf"] = {"jwk": {**ctx["jwk"], **jwk_change}}
    assert not verify(ctx, signed(ctx, mint(ctx, p)), require_auth_token=True)["valid"]


def test_auth_token_without_scope_is_still_an_auth_token(ctx):
    p = claims(ctx)
    p.pop("scope")
    assert verify(ctx, signed(ctx, mint(ctx, p)), require_auth_token=True)["valid"]


def test_person_token_issuance_and_lifetime_caps(ctx):
    token = aauth.create_person_token(
        PS,
        RESOURCE,
        "person-1",
        ctx["jwk"],
        ctx["issuer"],
        "issuer-1",
        agent_exp=ctx["now"] + 500,
        upstream_exp=ctx["now"] + 300,
        mission_s256="m" * 43,
        mission_exp=ctx["now"] + 200,
    )
    p = aauth.verify_person_token(
        token, ctx["fetch"], expected_aud=RESOURCE, request_signing_jwk=ctx["jwk"]
    )
    assert p["exp"] == ctx["now"] + 200 and p["mission_s256"] == "m" * 43
    assert jwt.get_unverified_header(token)["alg"] == "Ed25519"
    assert "agent" not in p and "act" not in p


def test_resource_token_binds_verified_presented_token(ctx):
    presented = mint(
        ctx,
        claims(ctx, "aa-person+jwt", mission_s256="m" * 43, tenant="tenant-1"),
        "aa-person+jwt",
    )
    rt = aauth.create_resource_token(
        RESOURCE,
        PS,
        aauth.calculate_jwk_thumbprint(ctx["jwk"]),
        ctx["issuer"],
        "issuer-1",
        presented_token=presented,
        jwks_fetcher=ctx["fetch"],
        scope="read",
    )
    p = aauth.verify_resource_token(
        rt,
        ctx["fetch"],
        expected_aud=PS,
        expected_ps=PS,
        expected_agent_jkt=aauth.calculate_jwk_thumbprint(ctx["jwk"]),
        presented_token=presented,
        mission_checker=lambda s: True,
    )
    assert p["presented_jti"] == "token-1" and p["ps"] == PS and p["sub"] == "person-1"
    assert p["mission_s256"] == "m" * 43 and p["tenant"] == "tenant-1"
    assert p["exp"] - p["iat"] <= 300 and "agent" not in p
    other = mint(ctx, claims(ctx, "aa-person+jwt", jti="other"), "aa-person+jwt")
    with pytest.raises(TokenError):
        aauth.verify_resource_token(
            rt, ctx["fetch"], expected_aud=PS, presented_token=other
        )


def test_auth_creation_caps_dependencies_and_emits_new_claims(ctx):
    t = aauth.create_auth_token(
        PS,
        RESOURCE,
        ctx["jwk"],
        ctx["issuer"],
        "issuer-1",
        ps=PS,
        sub="person-1",
        agent_exp=ctx["now"] + 500,
        presented_exp=ctx["now"] + 400,
        upstream_exp=ctx["now"] + 300,
    )
    p = aauth.verify_token(
        t, ctx["fetch"], expected_typ="aa-auth+jwt", expected_aud=RESOURCE
    )
    assert p["exp"] == ctx["now"] + 300 and "agent" not in p and "act" not in p


@pytest.mark.parametrize("requirement", ["agent-token", "person-token", "unknown"])
def test_challenges_never_fall_back_to_hwk(requirement):
    h = aauth.ChallengeHandler()
    if requirement == "unknown":
        with pytest.raises(aauth.ChallengeError):
            h.determine_response_scheme({"require": requirement})
    else:
        assert (
            h.determine_response_scheme(
                {"require": requirement}, has_agent_token=True, has_person_token=True
            )
            == "jwt"
        )


def test_new_metadata_fields():
    m = aauth.generate_ps_metadata(
        PS, PS + "/token", PS + "/jwks", person_token_endpoint=PS + "/person"
    )
    assert (
        m["auth_token_endpoint"] == PS + "/token"
        and m["person_token_endpoint"] == PS + "/person"
    )
    assert "token_endpoint" not in m


def test_agent_identifiers_accept_uppercase():
    from aauth.identifiers import validate_agent_identifier

    assert (
        validate_agent_identifier("aauth:Agent@agent.example")
        == "aauth:Agent@agent.example"
    )


def test_problem_details():
    assert aauth.build_error_response("denied", "User rejected") == {
        "error": "denied",
        "detail": "User rejected",
    }


def test_session_credential_signed_and_bound(ctx):
    headers = {"Authorization": "AAuth session-value"}
    token = mint(ctx, claims(ctx, "aa-agent+jwt"), "aa-agent+jwt")
    headers = signed(ctx, token, headers=headers)
    assert '"authorization"' in headers["Signature-Input"]
    v = aauth.RequestVerifier(
        ["resource.example"],
        ctx["fetch"],
        resource_id=RESOURCE,
        session_token_verifier=lambda token, jkt: token == "session-value"
        and jkt == aauth.calculate_jwk_thumbprint(ctx["jwk"]),
    )
    assert v.verify_request(
        "GET", RESOURCE + "/data", headers, None, require_session_token=True
    )["valid"]
    headers["Authorization"] = "AAuth different"
    assert not v.verify_request(
        "GET", RESOURCE + "/data", headers, None, require_session_token=True
    )["valid"]


@pytest.mark.parametrize("kind", ["sync", "async"])
def test_header_only_late_interaction_and_clarification(kind, ctx):
    from aauth.agent.poller import poll_pending_url, async_poll_pending_url

    responses = [
        httpx.Response(202, headers={"Retry-After": "0"}, json={"status": "pending"}),
        httpx.Response(
            202,
            headers={
                "Retry-After": "0",
                "AAuth-Requirement": 'requirement=interaction; url="https://ps.example/interaction"; code="ABCD1234"',
            },
            json={"status": "pending"},
        ),
        httpx.Response(
            202,
            headers={
                "Retry-After": "0",
                "AAuth-Requirement": "requirement=clarification",
            },
            json={"status": "pending", "clarification": "Why?"},
        ),
        httpx.Response(200, json={"auth_token": "tok"}),
    ]
    calls = []
    posts = []
    queue = iter(responses)
    if kind == "sync":
        r = poll_pending_url(
            PS + "/pending/1",
            lambda url: next(queue),
            on_interaction=lambda *args: calls.append(args),
            on_clarification=lambda *args: "Because",
            sign_and_send_post=lambda url, b: posts.append(b),
        )
    else:

        async def get(url):
            return next(queue)

        async def interaction(*args):
            calls.append(args)

        async def clarify(*args):
            return "Because"

        async def post(url, b):
            posts.append(b)

        r = asyncio.run(
            async_poll_pending_url(
                PS + "/pending/1",
                get,
                on_interaction=interaction,
                on_clarification=clarify,
                sign_and_send_post=post,
            )
        )
    assert r.success and len(calls) == 1
    assert posts == [
        {"action": "clarification_response", "clarification_response": "Because"}
    ]


@pytest.mark.parametrize("curve", ["ed25519", "P-256", "P-384"])
def test_key_algorithms_interoperate_in_both_jwt_and_http_signatures(curve):
    if curve == "ed25519":
        private, public = aauth.generate_ed25519_keypair()
    else:
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1

        private, public = aauth.generate_ec_keypair(
            SECP256R1() if curve == "P-256" else SECP384R1()
        )
    jwk = aauth.public_key_to_jwk(public, kid="key")
    now = int(time.time())
    t = aauth.create_auth_token(
        PS,
        RESOURCE,
        jwk,
        private,
        "key",
        ps=PS,
        sub="person-1",
        agent_exp=now + 600,
        presented_exp=now + 600,
        dwk="aauth-person.json",
    )
    h = {}
    h.update(
        aauth.sign_request(
            "GET", RESOURCE + "/data", h, None, private, sig_scheme="jwt", jwt=t
        )
    )
    v = aauth.RequestVerifier(
        ["resource.example"], lambda *args: {"keys": [jwk]}, trusted_auth_servers=[PS]
    )
    assert v.verify_request("GET", RESOURCE + "/data", h, require_auth_token=True)[
        "valid"
    ]


def test_empty_body_and_extra_component_coverage(ctx):
    h = {"X-Request-Id": "request-1", "Content-Type": "application/json"}
    h.update(
        aauth.sign_request(
            "GET",
            RESOURCE + "/data",
            h,
            b"",
            ctx["agent"],
            sig_scheme="jwt",
            jwt=mint(ctx, claims(ctx)),
            additional_signature_components=[
                "content-digest",
                "content-type",
                "x-request-id",
            ],
        )
    )
    v = aauth.RequestVerifier(
        ["resource.example"],
        ctx["fetch"],
        trusted_auth_servers=[PS],
        additional_signature_components=["x-request-id"],
    )
    assert v.verify_request("GET", RESOURCE + "/data", h, b"", require_auth_token=True)[
        "valid"
    ]
    h["X-Request-Id"] = "changed"
    assert not v.verify_request(
        "GET", RESOURCE + "/data", h, b"", require_auth_token=True
    )["valid"]


def test_keyid_conflict_rejected(ctx):
    params = (
        '("@method" "@authority" "@path" "signature-key");created='
        + str(ctx["now"])
        + ';keyid="other-key"'
    )
    h = signed(
        ctx,
        mint(ctx, claims(ctx)),
        ["@method", "@authority", "@path", "signature-key"],
        params,
    )
    assert not verify(ctx, h, require_auth_token=True)["valid"]


def test_selected_jwks_key_does_not_require_unrelated_algorithms(ctx):
    tok = mint(ctx, claims(ctx))
    v = aauth.RequestVerifier(
        ["resource.example"],
        lambda *args: {
            "keys": [
                {"kid": "future", "kty": "ML-DSA", "alg": "ML-DSA-65"},
                ctx["ijwk"],
            ]
        },
        trusted_auth_servers=[PS],
    )
    assert v.verify_request(
        "GET", RESOURCE + "/data", signed(ctx, tok), require_auth_token=True
    )["valid"]


def test_standalone_signature_jwt_is_not_aauth_authorization(ctx):
    p = claims(ctx)
    p.pop("exp")
    h = signed(ctx, mint(ctx, p))
    with pytest.raises(SignatureError):
        aauth.verify_signature(
            "GET",
            RESOURCE + "/data",
            h,
            None,
            h["Signature-Input"],
            h["Signature"],
            h["Signature-Key"],
            jwks_fetcher=ctx["fetch"],
        )


@pytest.mark.parametrize(
    "change",
    [
        {"mission_s256": None},
        {"tenant": None},
        {"sub": "other"},
        {"presented_jti": "other"},
    ],
)
def test_resource_token_context_cannot_be_stripped_or_substituted(ctx, change):
    presented = mint(
        ctx,
        claims(ctx, "aa-person+jwt", mission_s256="m" * 43, tenant="tenant-1"),
        "aa-person+jwt",
    )
    rt = aauth.create_resource_token(
        RESOURCE,
        PS,
        aauth.calculate_jwk_thumbprint(ctx["jwk"]),
        ctx["issuer"],
        "issuer-1",
        presented_token=presented,
        jwks_fetcher=ctx["fetch"],
    )
    payload = aauth.parse_token_claims(rt)["payload"]
    payload.update(change)
    payload = {k: v for k, v in payload.items() if v is not None}
    bad = mint(ctx, payload, "aa-resource+jwt")
    with pytest.raises(TokenError):
        aauth.verify_resource_token(
            bad,
            ctx["fetch"],
            presented_token=presented,
            expected_aud=PS,
            expected_ps=PS,
            mission_checker=lambda s: True,
        )


def test_person_token_is_not_authorization_even_with_scope(ctx):
    tok = mint(ctx, claims(ctx, "aa-person+jwt", scope="admin"), "aa-person+jwt")
    assert not verify(ctx, signed(ctx, tok), require_auth_token=True)["valid"]


def test_unbound_session_fails_closed(ctx):
    tok = mint(ctx, claims(ctx, "aa-agent+jwt"), "aa-agent+jwt")
    h = signed(ctx, tok, headers={"Authorization": "AAuth session"})
    assert not verify(ctx, h, require_session_token=True)["valid"]


def test_readme_local_flow_executes():
    from pathlib import Path

    text = (Path(__file__).parents[1] / "README.md").read_text()
    example = text.split("```python\n")[1].split("```")[0]
    exec(compile(example, "README.md", "exec"), {})


def test_jkt_jwt_delegation_supports_fully_specified_ed25519(ctx):
    durable = ctx["ijwk"]
    payload = {
        "iss": "urn:jkt:sha-256:" + aauth.calculate_jwk_thumbprint(durable),
        "iat": ctx["now"],
        "exp": ctx["now"] + 600,
        "cnf": {"jwk": ctx["jwk"]},
    }
    header = {"typ": "jkt-s256+jwt", "alg": "Ed25519", "jwk": durable}
    enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
    data = enc(json.dumps(header).encode()) + b"." + enc(json.dumps(payload).encode())
    token = (data + b"." + enc(ctx["issuer"].sign(data))).decode()
    h = {}
    h.update(
        aauth.sign_request(
            "GET",
            RESOURCE + "/data",
            h,
            None,
            ctx["agent"],
            sig_scheme="jkt-jwt",
            jwt=token,
        )
    )
    assert aauth.verify_signature(
        "GET",
        RESOURCE + "/data",
        h,
        None,
        h["Signature-Input"],
        h["Signature"],
        h["Signature-Key"],
    )


def test_jwks_discovery_rejects_issuer_mismatch(ctx):
    class Client:
        async def fetch_json(self, url):
            return {"issuer": "https://wrong.example", "jwks_uri": PS + "/jwks"}

    fetcher = aauth.JWKSFetcher(http_client=Client())
    with pytest.raises(aauth.JWKSError):
        asyncio.run(fetcher.fetch(PS, metadata_path="aauth-person.json"))


def test_failed_jwks_fetch_counts_toward_rate_limit():
    calls = []

    class Client:
        async def fetch_json(self, url):
            calls.append(url)
            if "/.well-known/" in url:
                return {"issuer": PS, "jwks_uri": PS + "/jwks"}
            raise ConnectionError("Unavailable")

    fetcher = aauth.JWKSFetcher(http_client=Client())

    async def run():
        for _ in range(2):
            with pytest.raises(aauth.JWKSError):
                await fetcher.fetch(PS)

    asyncio.run(run())
    assert calls.count(PS + "/jwks") == 1


@pytest.mark.parametrize(
    "url", ["http://public.example", "https://127.0.0.1", "https://user@public.example"]
)
def test_default_egress_admission_rejects_non_public_targets(url):
    from aauth.keys.jwks import admit_public_url

    with pytest.raises(aauth.JWKSError):
        admit_public_url(url)
