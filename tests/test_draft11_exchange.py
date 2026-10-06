"""HTTP transport integration tests with real JWTs and request signatures."""

import asyncio
import time
import pytest
import httpx
import aauth
from tests.test_draft11 import ctx, claims, mint, PS, AP, RESOURCE


def setup_flow(c, audience=PS):
    agent = mint(c, claims(c, "aa-agent+jwt", exp=c["now"] + 600), "aa-agent+jwt")
    person = mint(c, claims(c, "aa-person+jwt"), "aa-person+jwt")
    resource = aauth.create_resource_token(
        RESOURCE,
        audience,
        aauth.calculate_jwk_thumbprint(c["jwk"]),
        c["issuer"],
        "issuer-1",
        presented_token=person,
        jwks_fetcher=c["fetch"],
        scope="read",
        login_hint="user@example.com",
    )
    auth = aauth.create_auth_token(
        audience,
        RESOURCE,
        c["jwk"],
        c["issuer"],
        "issuer-1",
        ps=PS,
        sub="person-1",
        agent_exp=c["now"] + 600,
        presented_exp=c["now"] + 600,
        dwk="aauth-person.json" if audience == PS else "aauth-access.json",
    )
    return agent, person, resource, auth


def metadata():
    return aauth.generate_ps_metadata(
        PS, PS + "/authorize", PS + "/jwks", person_token_endpoint=PS + "/identity"
    )


def validate_post(c, request):
    assert request.method == "POST"
    h = dict(request.headers)
    assert aauth.verify_signature(
        "POST",
        str(request.url),
        h,
        request.content,
        h["signature-input"],
        h["signature"],
        h["signature-key"],
        jwks_fetcher=c["fetch"],
        required_components=[
            "@method",
            "@authority",
            "@path",
            "signature-key",
            "content-digest",
            "content-type",
        ],
    )


@pytest.mark.parametrize("audience", [PS, "https://as.example"])
@pytest.mark.parametrize("deferred", [False, True])
def test_verified_exchange_uses_own_ps_and_new_endpoint(ctx, audience, deferred):
    agent, person, resource, auth = setup_flow(ctx, audience)
    calls = []
    interaction = []

    def handler(request):
        calls.append((request.method, str(request.url)))
        if request.url.path == "/.well-known/aauth-person.json":
            return httpx.Response(200, json=metadata())
        if request.url.path == "/authorize":
            validate_post(ctx, request)
            import json

            data = json.loads(request.content)
            assert (
                data["resource_token"] == resource and data["presented_token"] == person
            )
            assert data["login_hint"] == "user@example.com"
            if deferred:
                return httpx.Response(
                    202,
                    headers={
                        "Location": "/pending/1",
                        "Retry-After": "0",
                        "AAuth-Requirement": 'requirement=interaction; url="https://ps.example/interaction"; code="ABCD1234"',
                    },
                    json={"status": "pending"},
                )
            return httpx.Response(200, json={"auth_token": auth})
        assert request.url.path == "/pending/1" and request.method == "GET"
        return httpx.Response(200, json={"auth_token": auth})

    async def run():
        async def prompt(*args):
            interaction.append(args)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await aauth.exchange_resource_token(
                resource,
                ctx["agent"],
                agent,
                presented_token=person,
                resource_id=RESOURCE,
                person_server=PS,
                jwks_fetcher=ctx["fetch"],
                http_client=client,
                on_interaction=prompt,
            )
            assert result == auth

    asyncio.run(run())
    assert all(url.startswith(PS + "/") for method, url in calls)
    assert len(interaction) == int(deferred)


@pytest.mark.parametrize(
    "change",
    [
        {"aud": "https://other.example"},
        {"iss": "https://wrong.example"},
        {"sub": "other-person"},
        {"ps": "https://wrong.example"},
        {"exp": int(time.time()) + 3599},
    ],
)
def test_exchange_rejects_wrong_returned_context(ctx, change):
    agent, person, resource, _ = setup_flow(ctx)
    bad = mint(ctx, claims(ctx, **change))

    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json=metadata())
        return httpx.Response(200, json={"auth_token": bad})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(aauth.TokenError):
                await aauth.exchange_resource_token(
                    resource,
                    ctx["agent"],
                    agent,
                    presented_token=person,
                    resource_id=RESOURCE,
                    person_server=PS,
                    jwks_fetcher=ctx["fetch"],
                    http_client=client,
                )

    asyncio.run(run())


@pytest.mark.parametrize(
    "location",
    [None, "https://evil.example/pending", "https://ps.example:8443/pending"],
)
def test_exchange_rejects_missing_or_foreign_location(ctx, location):
    agent, person, resource, _ = setup_flow(ctx)
    calls = []

    def handler(request):
        calls.append(str(request.url))
        if request.method == "GET":
            return httpx.Response(200, json=metadata())
        return httpx.Response(
            202,
            headers={"Location": location} if location else {},
            json={"status": "pending"},
        )

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(aauth.TokenError):
                await aauth.exchange_resource_token(
                    resource,
                    ctx["agent"],
                    agent,
                    presented_token=person,
                    resource_id=RESOURCE,
                    person_server=PS,
                    jwks_fetcher=ctx["fetch"],
                    http_client=client,
                )

    asyncio.run(run())
    assert len(calls) == 2


def test_person_token_acquisition(ctx):
    agent, person, _, _ = setup_flow(ctx)

    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json=metadata())
        validate_post(ctx, request)
        assert request.url.path == "/identity"
        import json

        assert json.loads(request.content)["resource"] == RESOURCE
        return httpx.Response(200, json={"person_token": person, "expires_in": 600})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            assert (
                await aauth.request_person_token(
                    PS,
                    RESOURCE,
                    ctx["agent"],
                    agent,
                    jwks_fetcher=ctx["fetch"],
                    http_client=client,
                    capabilities=["interaction"],
                )
                == person
            )

    asyncio.run(run())


@pytest.mark.parametrize("metadata_value", [{}, {"issuer": "https://wrong.example"}])
def test_discovery_identity_failure_never_falls_back(ctx, metadata_value):
    agent, person, resource, _ = setup_flow(ctx)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            200, json={**metadata(), **metadata_value} if metadata_value else {}
        )

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(aauth.MetadataError):
                await aauth.exchange_resource_token(
                    resource,
                    ctx["agent"],
                    agent,
                    presented_token=person,
                    resource_id=RESOURCE,
                    person_server=PS,
                    jwks_fetcher=ctx["fetch"],
                    http_client=client,
                )

    asyncio.run(run())
    assert len(calls) == 1


def test_invalid_resource_challenge_rejected_before_network(ctx):
    agent, person, resource, _ = setup_flow(ctx)
    # Modify the payload without recomputing its JWT signature.
    import base64, json

    parts = resource.split(".")
    p = aauth.parse_token_claims(resource)["payload"]
    p["aud"] = "https://evil.example"
    parts[1] = base64.urlsafe_b64encode(json.dumps(p).encode()).rstrip(b"=").decode()

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: pytest.fail("Unexpected network"))
        ) as client:
            with pytest.raises(aauth.TokenError):
                await aauth.exchange_resource_token(
                    ".".join(parts),
                    ctx["agent"],
                    agent,
                    presented_token=person,
                    resource_id=RESOURCE,
                    person_server=PS,
                    jwks_fetcher=ctx["fetch"],
                    http_client=client,
                )

    asyncio.run(run())


def test_deferred_resource_invocation_is_not_repeated(ctx):
    agent, person, resource, auth = setup_flow(ctx)
    initial = httpx.Response(
        202,
        headers={
            "Location": "/pending/result",
            "Retry-After": "0",
            "AAuth-Requirement": f'requirement=auth-token; resource-token="{resource}"',
        },
        json={"status": "pending"},
    )
    calls = []

    def handler(request):
        calls.append((request.method, str(request.url)))
        if str(request.url) == PS + "/.well-known/aauth-person.json":
            return httpx.Response(200, json=metadata())
        if str(request.url) == PS + "/authorize":
            return httpx.Response(200, json={"auth_token": auth})
        assert (
            request.method == "GET" and str(request.url) == RESOURCE + "/pending/result"
        )
        parsed = aauth.parse_signature_key(request.headers["signature-key"])
        assert parsed["params"]["jwt"] == auth and not request.content
        return httpx.Response(201, content=b"invocation result")

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await aauth.complete_deferred_resource_request(
                initial,
                RESOURCE + "/submit",
                ctx["agent"],
                agent,
                presented_token=person,
                resource_id=RESOURCE,
                person_server=PS,
                jwks_fetcher=ctx["fetch"],
                http_client=client,
            )
            assert (
                result.success
                and result.status_code == 201
                and result.response.content == b"invocation result"
            )

    asyncio.run(run())
    assert calls == [
        ("GET", PS + "/.well-known/aauth-person.json"),
        ("POST", PS + "/authorize"),
        ("GET", RESOURCE + "/pending/result"),
    ]


def test_parent_mediated_exchange_binds_child_key(ctx):
    child_private, child_public = aauth.generate_ed25519_keypair()
    child_jwk = aauth.public_key_to_jwk(child_public)
    parent, _, _, _ = setup_flow(ctx)
    child = aauth.create_agent_token(
        AP,
        "aauth:Agent+child@agent.example",
        child_jwk,
        ctx["issuer"],
        "issuer-1",
        exp=ctx["now"] + 600,
        parent_token=parent,
        jwks_fetcher=ctx["fetch"],
    )
    person = aauth.create_person_token(
        PS,
        RESOURCE,
        "person-1",
        child_jwk,
        ctx["issuer"],
        "issuer-1",
        agent_exp=ctx["now"] + 600,
    )
    rt = aauth.create_resource_token(
        RESOURCE,
        PS,
        aauth.calculate_jwk_thumbprint(child_jwk),
        ctx["issuer"],
        "issuer-1",
        presented_token=person,
        jwks_fetcher=ctx["fetch"],
    )
    auth = aauth.create_auth_token(
        PS,
        RESOURCE,
        child_jwk,
        ctx["issuer"],
        "issuer-1",
        ps=PS,
        sub="person-1",
        agent_exp=ctx["now"] + 600,
        presented_exp=ctx["now"] + 600,
        dwk="aauth-person.json",
    )

    def handler(req):
        if req.method == "GET":
            return httpx.Response(200, json=metadata())
        validate_post(ctx, req)
        import json

        assert json.loads(req.content)["subagent_token"] == child
        return httpx.Response(200, json={"auth_token": auth})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            assert (
                await aauth.exchange_resource_token(
                    rt,
                    ctx["agent"],
                    parent,
                    presented_token=person,
                    resource_id=RESOURCE,
                    person_server=PS,
                    jwks_fetcher=ctx["fetch"],
                    subagent_token=child,
                    http_client=client,
                )
                == auth
            )

    asyncio.run(run())
    h = {}
    h.update(
        aauth.sign_request(
            "GET",
            RESOURCE + "/data",
            h,
            None,
            child_private,
            sig_scheme="jwt",
            jwt=auth,
        )
    )
    verifier = aauth.RequestVerifier(
        ["resource.example"], ctx["fetch"], trusted_auth_servers=[PS]
    )
    assert verifier.verify_request(
        "GET", RESOURCE + "/data", h, require_auth_token=True
    )["valid"]


def test_ps_non_object_error_body_is_reported_as_token_error(ctx):
    from aauth.agent.token_exchange import _post_ps

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(400, json=[]))
        ) as client:
            with pytest.raises(aauth.TokenError, match="PS request failed"):
                await _post_ps(
                    PS + "/auth", {}, ctx["agent"], setup_flow(ctx)[0], client
                )

    asyncio.run(run())
