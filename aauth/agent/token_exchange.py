"""Person-token acquisition, verified resource challenges, and PS token exchange."""

import json
import httpx
from ..tokens.common import verify_token
from ..tokens.delegation import verify_subagent_token, verify_upstream_token
from ..tokens.resource_token import verify_resource_token
from ..keys.jwk import public_key_to_jwk, calculate_jwk_thumbprint
from ..metadata.mission_manager import fetch_ps_metadata_async
from ..identifiers import validate_server_identifier
from ..errors import TokenError
from ..signing.signer import sign_request
from .poller import async_poll_pending_url, pending_location


def extract_resource_token(headers):
    from ..headers.aauth_header import get_challenge_header_value, parse_aauth_header

    raw = get_challenge_header_value(headers)
    try:
        return parse_aauth_header(raw).get("resource_token") if raw else None
    except Exception:
        return None


async def _post_ps(
    endpoint,
    params,
    private_key,
    agent_jwt,
    client,
    *,
    on_interaction=None,
    on_clarification=None,
    max_polls=60,
):
    async def post(url, params):
        body = json.dumps(params, separators=(",", ":")).encode()
        h = {"Content-Type": "application/json"}
        h.update(
            sign_request(
                "POST",
                url,
                h,
                body,
                private_key,
                sig_scheme="jwt",
                jwt=agent_jwt,
                additional_signature_components=["content-digest", "content-type"],
            )
        )
        return await client.post(url, headers=h, content=body)

    async def get(url):
        h = sign_request(
            "GET", url, {}, None, private_key, sig_scheme="jwt", jwt=agent_jwt
        )
        return await client.get(url, headers=h)

    response = await post(endpoint, params)
    if response.status_code == 202:
        location = pending_location(response.headers.get("location"), endpoint)
        result = await async_poll_pending_url(
            location,
            get,
            max_polls=max_polls,
            on_interaction=on_interaction,
            on_clarification=on_clarification,
            sign_and_send_post=post,
            initial_response=response,
        )
        if not result.success:
            raise TokenError(
                f"PS deferred exchange failed: {result.error}: {result.error_description}"
            )
        response = result.response
    if response.status_code != 200:
        try:
            data = response.json()
            if not isinstance(data, dict):
                data = {}
        except Exception:
            data = {}
        raise TokenError(
            data.get("detail", "PS request failed"),
            error_code=data.get("error", "server_error"),
        )
    try:
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError()
        return data
    except Exception as exc:
        raise TokenError("PS response is not a JSON object") from exc


async def exchange_resource_token(
    resource_token,
    private_key,
    agent_jwt,
    *,
    presented_token,
    resource_id,
    person_server,
    jwks_fetcher,
    ps_discovery_timeout=10.0,
    exchange_timeout=30.0,
    on_interaction=None,
    on_clarification=None,
    max_polls=60,
    http_client=None,
    subagent_token=None,
    upstream_token=None,
    **options,
):
    validate_server_identifier(person_server)
    signing_jwk = public_key_to_jwk(private_key.public_key())
    signing = verify_token(
        agent_jwt,
        jwks_fetcher,
        expected_typ="aa-agent+jwt",
        request_signing_jwk=signing_jwk,
    )
    if signing.get("parent_agent"):
        raise TokenError("Sub-agents cannot request authorization directly")
    key = signing_jwk
    child = (
        verify_subagent_token(agent_jwt, subagent_token, jwks_fetcher)
        if subagent_token
        else None
    )
    if child:
        key = child["cnf"]["jwk"]
    upstream = None
    if upstream_token:
        upstream = verify_upstream_token(
            upstream_token,
            jwks_fetcher,
            intermediary_agent_token=agent_jwt,
            person_server=person_server,
            recipient_role="as",
        )
    rt = verify_resource_token(
        resource_token,
        jwks_fetcher,
        presented_token=presented_token,
        expected_iss=resource_id,
        expected_ps=person_server,
        expected_agent_jkt=calculate_jwk_thumbprint(key),
    )
    params = dict(
        options, resource_token=resource_token, presented_token=presented_token
    )
    if "login_hint" in rt:
        params["login_hint"] = rt["login_hint"]
    if subagent_token:
        params["subagent_token"] = subagent_token
    if upstream_token:
        params["upstream_token"] = upstream_token
    if http_client is None:
        from ..keys.jwks import admit_public_url, AdmittedHTTPClient

        admit_public_url(person_server)
        async with httpx.AsyncClient(timeout=exchange_timeout) as client:
            return await exchange_resource_token(
                resource_token,
                private_key,
                agent_jwt,
                presented_token=presented_token,
                resource_id=resource_id,
                person_server=person_server,
                jwks_fetcher=jwks_fetcher,
                http_client=AdmittedHTTPClient(client),
                subagent_token=subagent_token,
                upstream_token=upstream_token,
                ps_discovery_timeout=ps_discovery_timeout,
                exchange_timeout=exchange_timeout,
                on_interaction=on_interaction,
                on_clarification=on_clarification,
                max_polls=max_polls,
                **options,
            )
    meta = await fetch_ps_metadata_async(
        person_server, ps_discovery_timeout, http_client
    )
    data = await _post_ps(
        meta["auth_token_endpoint"],
        params,
        private_key,
        agent_jwt,
        http_client,
        on_interaction=on_interaction,
        on_clarification=on_clarification,
        max_polls=max_polls,
    )
    token = data.get("auth_token")
    if not token:
        raise TokenError("PS response missing auth_token")
    p = verify_token(
        token,
        jwks_fetcher,
        expected_typ="aa-auth+jwt",
        expected_iss=rt["aud"],
        expected_aud=resource_id,
        request_signing_jwk=key,
    )
    if p["sub"] != rt["sub"] or p["ps"] != person_server:
        raise TokenError("Returned auth token person binding mismatch")
    if p.get("mission_s256") != rt.get("mission_s256") or p.get("tenant") != rt.get(
        "tenant"
    ):
        raise TokenError("Returned auth token context mismatch")
    presented = verify_token(presented_token, jwks_fetcher)
    limits = [signing["exp"], presented["exp"]]
    if child:
        limits.append(child["exp"])
    if upstream:
        limits.append(upstream["exp"])
        if p.get("mission_s256") != upstream.get("mission_s256"):
            raise TokenError("Downstream mission does not match upstream context")
    if p["exp"] > min(limits):
        raise TokenError("Auth token outlives dependency")
    return token


async def request_person_token(
    person_server,
    resource_id,
    private_key,
    agent_jwt,
    *,
    jwks_fetcher,
    http_client=None,
    on_interaction=None,
    on_clarification=None,
    max_polls=60,
    subagent_token=None,
    **options,
):
    validate_server_identifier(person_server)
    validate_server_identifier(resource_id)
    key = public_key_to_jwk(private_key.public_key())
    agent = verify_token(
        agent_jwt, jwks_fetcher, expected_typ="aa-agent+jwt", request_signing_jwk=key
    )
    if agent.get("parent_agent"):
        raise TokenError("Sub-agent must use parent-mediated authorization")
    child = (
        verify_subagent_token(agent_jwt, subagent_token, jwks_fetcher)
        if subagent_token
        else None
    )
    if child:
        key = child["cnf"]["jwk"]
        options["subagent_token"] = subagent_token
    upstream = None
    if options.get("upstream_token"):
        upstream = verify_upstream_token(
            options["upstream_token"],
            jwks_fetcher,
            intermediary_agent_token=agent_jwt,
            person_server=person_server,
            recipient_role="as",
        )
        if upstream.get("mission_s256"):
            options["mission_s256"] = upstream["mission_s256"]
    if http_client is None:
        from ..keys.jwks import admit_public_url, AdmittedHTTPClient

        admit_public_url(person_server)
        async with httpx.AsyncClient(timeout=30) as client:
            return await request_person_token(
                person_server,
                resource_id,
                private_key,
                agent_jwt,
                jwks_fetcher=jwks_fetcher,
                http_client=AdmittedHTTPClient(client),
                on_interaction=on_interaction,
                on_clarification=on_clarification,
                max_polls=max_polls,
                subagent_token=subagent_token,
                **{k: v for k, v in options.items() if k != "subagent_token"},
            )
    meta = await fetch_ps_metadata_async(person_server, http_client=http_client)
    data = await _post_ps(
        meta["person_token_endpoint"],
        dict(options, resource=resource_id),
        private_key,
        agent_jwt,
        http_client,
        on_interaction=on_interaction,
        on_clarification=on_clarification,
        max_polls=max_polls,
    )
    token = data.get("person_token")
    if not token:
        raise TokenError("PS response missing person_token")
    p = verify_token(
        token,
        jwks_fetcher,
        expected_typ="aa-person+jwt",
        expected_iss=person_server,
        expected_aud=resource_id,
        request_signing_jwk=key,
    )
    if p["exp"] > min(agent["exp"], child["exp"] if child else agent["exp"]) or p.get(
        "mission_s256"
    ) != options.get("mission_s256"):
        raise TokenError("Person token context or lifetime mismatch")
    if (
        options.get("upstream_token")
        and p["exp"] > verify_token(options["upstream_token"], jwks_fetcher)["exp"]
    ):
        raise TokenError("Person token outlives upstream token")
    return token


async def complete_deferred_resource_request(
    response,
    request_uri,
    private_key,
    agent_jwt,
    *,
    presented_token,
    resource_id,
    person_server,
    jwks_fetcher,
    http_client=None,
    on_interaction=None,
    on_clarification=None,
    max_polls=60,
):
    """Resolve a resource's 202 auth challenge without repeating its invocation.

    The resource holds the original request. Obtain authorization through the
    PS, then GET the same-origin pending URL using the auth token.
    """
    if response.status_code != 202:
        raise TokenError("Expected a deferred resource response")
    location = pending_location(response.headers.get("location"), request_uri)
    rt = extract_resource_token(response.headers)
    if not rt:
        raise TokenError("Deferred auth challenge missing resource token")
    if http_client is None:
        from ..keys.jwks import AdmittedHTTPClient

        async with httpx.AsyncClient(timeout=30) as client:
            return await complete_deferred_resource_request(
                response,
                request_uri,
                private_key,
                agent_jwt,
                presented_token=presented_token,
                resource_id=resource_id,
                person_server=person_server,
                jwks_fetcher=jwks_fetcher,
                http_client=AdmittedHTTPClient(client),
                on_interaction=on_interaction,
                on_clarification=on_clarification,
                max_polls=max_polls,
            )
    token = await exchange_resource_token(
        rt,
        private_key,
        agent_jwt,
        presented_token=presented_token,
        resource_id=resource_id,
        person_server=person_server,
        jwks_fetcher=jwks_fetcher,
        http_client=http_client,
        on_interaction=on_interaction,
        on_clarification=on_clarification,
        max_polls=max_polls,
    )

    async def get(url):
        headers = sign_request(
            "GET", url, {}, None, private_key, sig_scheme="jwt", jwt=token
        )
        return await http_client.get(url, headers=headers)

    return await async_poll_pending_url(
        location,
        get,
        initial_response=response,
        max_polls=max_polls,
        on_interaction=on_interaction,
    )
