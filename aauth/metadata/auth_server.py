"""Auth server metadata handling for AAuth."""

from typing import Dict, Any, Optional


def generate_auth_metadata(
    auth_id: str,
    jwks_uri: str,
    token_endpoint: str,
    auth_endpoint: str,
    signing_algs_supported: Optional[list[str]] = None,
    request_types_supported: Optional[list[str]] = None,
    scopes_supported: Optional[list[str]] = None
) -> Dict[str, Any]:
    """Generate auth server metadata JSON per AAuth spec Section 8.2.
    
    Args:
        auth_id: Auth server identifier (HTTPS URL)
        jwks_uri: URL to auth server's JSON Web Key Set
        token_endpoint: Endpoint for auth requests, code exchange, token exchange, and refresh
        auth_endpoint: Endpoint for user authentication and consent flow
        signing_algs_supported: Optional list of supported HTTPSig algorithms
        request_types_supported: Optional list of supported request_type values
        scopes_supported: Optional list of supported scopes
        
    Returns:
        Auth server metadata dictionary with required fields
    """
    metadata = {
        "issuer": auth_id,
        "jwks_uri": jwks_uri,
        "agent_token_endpoint": token_endpoint,
        "agent_auth_endpoint": auth_endpoint
    }
    
    if signing_algs_supported:
        metadata["agent_signing_algs_supported"] = signing_algs_supported
    else:
        # Default to Ed25519
        metadata["agent_signing_algs_supported"] = ["ed25519"]
    
    if request_types_supported:
        metadata["request_types_supported"] = request_types_supported
    else:
        # Default to auth, code, exchange, refresh
        metadata["request_types_supported"] = ["auth", "code", "exchange", "refresh"]
    
    if scopes_supported:
        metadata["scopes_supported"] = scopes_supported
    
    return metadata


def fetch_metadata(url: str) -> Dict[str, Any]:
    """Fetch metadata document from URL via HTTPS (sync version for backward compatibility).
    
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
    
    # Verify HTTPS (allow HTTP for localhost development)
    if not url.startswith("https://"):
        # Allow HTTP for localhost/127.0.0.1 for development
        parsed = httpx.URL(url)
        if parsed.host not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError(f"Metadata URL must use HTTPS (except localhost): {url}")
    
    # Fetch metadata
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
        url: URL to auth server metadata document (e.g., https://auth.example/.well-known/aauth-issuer)
        http_client: Optional HTTP client (default: uses DefaultHTTPClient from keys.jwks)
        
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

