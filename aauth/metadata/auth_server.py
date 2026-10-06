"""Access server metadata and checked metadata fetching."""

from .common import common_fields, validate_metadata, issuer_from_metadata_url


def generate_auth_metadata(
    auth_id, jwks_uri, auth_token_endpoint, revocation_endpoint=None, **common
):
    m = common_fields(auth_id, jwks_uri, **common)
    m["auth_token_endpoint"] = auth_token_endpoint
    if revocation_endpoint:
        m["revocation_endpoint"] = revocation_endpoint
    return validate_metadata(m, auth_id, ("auth_token_endpoint", "jwks_uri"))


def fetch_metadata(url):
    import httpx
    from ..keys.jwks import admit_public_url

    admit_public_url(url)
    r = httpx.get(url, timeout=10)
    r.raise_for_status()
    return validate_metadata(r.json(), issuer_from_metadata_url(url), ("jwks_uri",))


async def fetch_auth_metadata(url, http_client=None):
    from ..keys.jwks import DefaultHTTPClient

    client = http_client or DefaultHTTPClient()
    m = await client.fetch_json(url)
    return validate_metadata(
        m, issuer_from_metadata_url(url), ("jwks_uri", "auth_token_endpoint")
    )
