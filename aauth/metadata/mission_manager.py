"""Person Server metadata and identity-checked discovery."""

import httpx
from .common import common_fields, validate_metadata


def generate_ps_metadata(
    person_server,
    auth_token_endpoint,
    jwks_uri,
    *,
    person_token_endpoint,
    mission_endpoint=None,
    permission_endpoint=None,
    audit_endpoint=None,
    interaction_endpoint=None,
    mission_control_endpoint=None,
    revocation_endpoint=None,
    scopes_supported=None,
    claims_supported=None,
    **common,
):
    m = common_fields(person_server, jwks_uri, **common)
    m.update(
        auth_token_endpoint=auth_token_endpoint,
        person_token_endpoint=person_token_endpoint,
    )
    for k, v in [
        ("mission_endpoint", mission_endpoint),
        ("permission_endpoint", permission_endpoint),
        ("audit_endpoint", audit_endpoint),
        ("interaction_endpoint", interaction_endpoint),
        ("mission_control_endpoint", mission_control_endpoint),
        ("revocation_endpoint", revocation_endpoint),
        ("scopes_supported", scopes_supported),
        ("claims_supported", claims_supported),
    ]:
        if v is not None:
            m[k] = v
    return validate_metadata(
        m, person_server, ("jwks_uri", "auth_token_endpoint", "person_token_endpoint")
    )


def fetch_ps_metadata(ps_url, timeout=10.0):
    from ..keys.jwks import admit_public_url

    admit_public_url(ps_url)
    r = httpx.get(ps_url + "/.well-known/aauth-person.json", timeout=timeout)
    r.raise_for_status()
    return validate_metadata(
        r.json(), ps_url, ("jwks_uri", "auth_token_endpoint", "person_token_endpoint")
    )


async def fetch_ps_metadata_async(ps_url, timeout=10.0, http_client=None):
    if http_client is None:
        from ..keys.jwks import admit_public_url

        admit_public_url(ps_url)
        async with httpx.AsyncClient(timeout=timeout) as client:
            return await fetch_ps_metadata_async(ps_url, timeout, client)
    r = await http_client.get(
        ps_url + "/.well-known/aauth-person.json", timeout=timeout
    )
    r.raise_for_status()
    return validate_metadata(
        r.json(), ps_url, ("jwks_uri", "auth_token_endpoint", "person_token_endpoint")
    )


generate_mm_metadata = generate_ps_metadata
fetch_mm_metadata = fetch_ps_metadata
fetch_mm_metadata_async = fetch_ps_metadata_async
