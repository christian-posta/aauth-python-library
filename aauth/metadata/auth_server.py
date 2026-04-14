"""Access server metadata handling for AAuth.

Published at /.well-known/aauth-access.json
"""

from typing import Dict, Any, Optional


def generate_auth_metadata(
    auth_id: str,
    jwks_uri: str,
    token_endpoint: str,
    interaction_endpoint: str,
    login_endpoint: Optional[str] = None,
    revocation_endpoint: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate access server metadata JSON per AAuth spec.

    Args:
        auth_id: Access server identifier (HTTPS URL) - REQUIRED
        jwks_uri: URL to access server's JSON Web Key Set - REQUIRED
        token_endpoint: Single endpoint for all agent-to-AS communication - REQUIRED
        interaction_endpoint: URL where users are sent for authentication and consent - REQUIRED
        login_endpoint: URL for third-party login initiation (OPTIONAL)
        revocation_endpoint: URL for token revocation (OPTIONAL)

    Returns:
        Access server metadata dictionary
    """
    meta = {
        "issuer": auth_id,
        "token_endpoint": token_endpoint,
        "interaction_endpoint": interaction_endpoint,
        "jwks_uri": jwks_uri,
    }
    if login_endpoint:
        meta["login_endpoint"] = login_endpoint
    if revocation_endpoint:
        meta["revocation_endpoint"] = revocation_endpoint
    return meta


def fetch_metadata(url: str) -> Dict[str, Any]:
    """Fetch metadata document from URL via HTTPS (sync version).

    Args:
        url: HTTPS URL to metadata document (HTTP allowed for localhost development)

    Returns:
        Parsed metadata dictionary

    Raises:
        ValueError: If URL is not HTTPS (except localhost for development)
        MetadataError: If HTTP request fails
    """
    import httpx
    from ..errors import MetadataError

    if not url.startswith("https://"):
        parsed = httpx.URL(url)
        if parsed.host not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError(f"Metadata URL must use HTTPS (except localhost): {url}")

    try:
        response = httpx.get(url, timeout=10.0)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise MetadataError(
            f"Failed to fetch metadata from {url}: {e}",
            metadata_url=url
        ) from e


async def fetch_auth_metadata(url: str, http_client=None) -> Dict[str, Any]:
    """Fetch auth server metadata from URL (async version).

    Args:
        url: URL to auth server metadata document
        http_client: Optional HTTP client

    Returns:
        Parsed auth server metadata dictionary

    Raises:
        MetadataError: If fetch fails
    """
    from ..keys.jwks import DefaultHTTPClient
    from ..errors import MetadataError

    client = http_client or DefaultHTTPClient()

    try:
        return await client.fetch_json(url)
    except Exception as e:
        raise MetadataError(
            f"Failed to fetch auth server metadata from {url}: {e}",
            metadata_url=url
        )
