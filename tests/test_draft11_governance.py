"""Revocation, dependency cascades, and mission bytes."""

import asyncio
import json
import pytest
import aauth
from tests.test_draft11 import ctx, claims, mint, PS, AP, RESOURCE, signed, verify


def test_revoked_jwt_rejected_after_signature_verification(ctx):
    store = aauth.RevocationStore()
    token = mint(ctx, claims(ctx))
    store.record(PS, "token-1", ctx["now"] + 600)
    v = aauth.RequestVerifier(
        ["resource.example"],
        ctx["fetch"],
        trusted_auth_servers=[PS],
        resource_id=RESOURCE,
        revocation_checker=store.is_revoked,
    )
    r = v.verify_request(
        "GET", RESOURCE + "/data", signed(ctx, token), None, require_auth_token=True
    )
    assert not r["valid"] and r["error_code"] == "revoked_jwt"


def test_stateless_revocation_and_issuer_namespace(ctx):
    store = aauth.RevocationStore()
    store.record(PS, "unknown", ctx["now"] + 600)
    assert store.is_revoked(PS, "unknown") and not store.is_revoked(AP, "unknown")
    store.record(PS, "expired", ctx["now"] - 1)
    assert not store.is_revoked(PS, "expired")


def test_agent_revocation_cascades_by_identity_and_retries_failures(ctx):
    store = aauth.RevocationStore()
    store.record_agent(
        {
            "iss": AP,
            "jti": "agent-old",
            "sub": "aauth:Agent@agent.example",
            "exp": ctx["now"] + 600,
        }
    )
    for jti in ("grant-old", "grant-new"):
        store.record_issued(
            {"iss": PS, "jti": jti, "exp": ctx["now"] + 600},
            [RESOURCE],
            agent_identity=(AP, "aauth:Agent@agent.example"),
        )
    sent = []

    async def send(recipient, jti, exp):
        assert store.is_revoked(AP, "agent-old") and store.is_revoked(PS, jti)
        sent.append(jti)
        return (
            {"error": "revocation_unavailable"}
            if jti == "grant-new" and sent.count(jti) == 1
            else {}
        )

    m = aauth.RevocationManager(PS, "ps", store, send, [AP])

    async def run():
        assert await m.revoke(AP, "agent-old", ctx["now"] + 600) == {}
        assert await m.revoke(AP, "agent-old", ctx["now"] + 600) == {}

    asyncio.run(run())
    assert sent.count("grant-old") == 1 and sent.count("grant-new") == 2


def test_person_revocation_cascades_auth_tokens_and_reports_outcomes(ctx):
    store = aauth.RevocationStore()
    store.record_issued(
        {"iss": "https://as.example", "jti": "auth", "exp": ctx["now"] + 600},
        [RESOURCE],
        dependencies=[(PS, "person")],
    )

    async def send(*args):
        return {"error": "revocation_unsupported"}

    m = aauth.RevocationManager("https://as.example", "as", store, send, [PS])
    result = asyncio.run(m.revoke(PS, "person", ctx["now"] + 600))
    assert result == {
        "downstream": [{"recipient": RESOURCE, "error": "revocation_unsupported"}]
    }


@pytest.mark.parametrize("tamper", [False, True])
def test_revocation_endpoint_checks_body_and_verified_issuer(ctx, tamper):
    store = aauth.RevocationStore()

    async def send(*args):
        pytest.fail("Nothing downstream")

    m = aauth.RevocationManager(RESOURCE, "resource", store, send, [PS])
    headers, body = aauth.sign_revocation_request(
        RESOURCE + "/revoke",
        "unknown",
        ctx["now"] + 600,
        ctx["issuer"],
        PS,
        "issuer-1",
        "aauth-person.json",
    )
    if tamper:
        body = body.replace(b"unknown", b"another")
    r = asyncio.run(
        m.handle_request("POST", RESOURCE + "/revoke", headers, body, ctx["fetch"])
    )
    assert r.status_code == (401 if tamper else 200)
    assert store.is_revoked(PS, "unknown") == (not tamper)
    if not tamper:
        assert r.body is None and not r.headers


@pytest.mark.parametrize("bad", ["", "a b", "a,b", "a\nb", "a\tb"])
def test_session_token68_rejects_invalid_values(bad):
    with pytest.raises(aauth.ChallengeError):
        aauth.build_aauth_access_header(bad)


def test_mission_approval_validates_original_bytes_and_hash():
    r = aauth.build_mission_approval(
        {"description": "Trip", "approved_at": 123}, capabilities=["interaction"]
    )
    p = aauth.parse_mission_approval(r)
    url, body = aauth.mission_request(
        PS + "/mission", p["mission_s256"], "completion", summary="Done"
    )
    assert url.endswith(p["mission_s256"]) and body == {
        "action": "completion",
        "summary": "Done",
    }
    r["mission"] = r["mission"][:-1] + ("A" if r["mission"][-1] != "A" else "B")
    with pytest.raises(aauth.TokenError):
        aauth.parse_mission_approval(r)


def test_refresh_margin():
    assert aauth.token_needs_refresh({"exp": 1000}, now=701)
    assert not aauth.token_needs_refresh({"exp": 1000}, now=700)


def test_deferred_revocation_uses_same_server_identity_and_empty_200(ctx):
    import httpx

    calls = []

    def handler(req):
        calls.append(req)
        key = aauth.parse_signature_key(req.headers["signature-key"])
        assert key["scheme"] == "jwks_uri" and key["params"]["id"] == PS
        if req.method == "POST":
            return httpx.Response(
                202,
                headers={"Location": "/pending/revoke", "Retry-After": "0"},
                json={"status": "pending"},
            )
        assert req.method == "GET" and not req.content
        return httpx.Response(200)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            assert (
                await aauth.send_revocation(
                    RESOURCE + "/revoke",
                    "jti",
                    ctx["now"] + 600,
                    ctx["issuer"],
                    PS,
                    "issuer-1",
                    "aauth-person.json",
                    http_client=client,
                )
                == {}
            )

    asyncio.run(run())
    assert len(calls) == 2


def test_unaccepted_revocation_issuer_is_forbidden(ctx):
    async def send(*args):
        pytest.fail("Unauthorized cascade")

    m = aauth.RevocationManager(RESOURCE, "resource", aauth.RevocationStore(), send, [])
    h, b = aauth.sign_revocation_request(
        RESOURCE + "/revoke",
        "jti",
        ctx["now"] + 600,
        ctx["issuer"],
        PS,
        "issuer-1",
        "aauth-person.json",
    )
    r = asyncio.run(m.handle_request("POST", RESOURCE + "/revoke", h, b, ctx["fetch"]))
    assert r.status_code == 403 and json.loads(r.body)["error"] == "unsupported_iss"
    assert "Signature-Error" not in r.headers


def test_subagent_cannot_spawn_another_subagent(ctx):
    parent = mint(ctx, claims(ctx, "aa-agent+jwt"), "aa-agent+jwt")
    private, public = aauth.generate_ed25519_keypair()
    child = aauth.create_agent_token(
        AP,
        "aauth:Agent+child@agent.example",
        aauth.public_key_to_jwk(public),
        ctx["issuer"],
        "issuer-1",
        parent_token=parent,
        jwks_fetcher=ctx["fetch"],
    )
    with pytest.raises(aauth.TokenError):
        aauth.create_agent_token(
            AP,
            "aauth:Agent+child+grandchild@agent.example",
            ctx["jwk"],
            ctx["issuer"],
            "issuer-1",
            parent_token=child,
            jwks_fetcher=ctx["fetch"],
        )


@pytest.mark.parametrize("typ", ["aa-person+jwt", "aa-auth+jwt"])
def test_upstream_binding_uses_intermediary_provider_not_own_ps(ctx, typ):
    intermediary = mint(
        ctx, claims(ctx, "aa-agent+jwt", ps="https://other-ps.example"), "aa-agent+jwt"
    )
    upstream = mint(ctx, claims(ctx, typ, aud=AP), typ)
    assert (
        aauth.verify_upstream_token(
            upstream,
            ctx["fetch"],
            intermediary_agent_token=intermediary,
            person_server=PS,
        )["aud"]
        == AP
    )
    wrong = mint(ctx, claims(ctx, typ, aud=RESOURCE), typ)
    with pytest.raises(aauth.TokenError):
        aauth.verify_upstream_token(
            wrong, ctx["fetch"], intermediary_agent_token=intermediary, person_server=PS
        )
