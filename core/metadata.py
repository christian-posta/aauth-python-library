"""Metadata document handling for AAuth."""

from typing import Dict, Any, Optional
import httpx
import json


def generate_agent_metadata(agent_id: str, jwks_uri: str) -> Dict[str, Any]:
    """Generate agent metadata JSON per AAuth spec Section 8.1.
    
    Args:
        agent_id: Agent identifier (HTTPS URL)
        jwks_uri: URL to agent's JSON Web Key Set
        
    Returns:
        Agent metadata dictionary with required fields
    """
    return {
        "agent": agent_id,
        "jwks_uri": jwks_uri
    }


def generate_resource_metadata(
    resource_id: str,
    jwks_uri: str,
    resource_token_endpoint: str,
    supported_scopes: Optional[list[str]] = None,
    scope_descriptions: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Generate resource metadata JSON per AAuth spec Section 8.3.
    
    Args:
        resource_id: Resource identifier (HTTPS URL)
        jwks_uri: URL to resource's JSON Web Key Set (REQUIRED)
        resource_token_endpoint: Endpoint where agents request resource tokens (REQUIRED per spec)
        supported_scopes: Optional list of supported scope values
        scope_descriptions: Optional dictionary mapping scope names to descriptions
        
    Returns:
        Resource metadata dictionary with required fields
        
    Note:
        Per SPEC.md Section 8.3, resource_token_endpoint is REQUIRED.
        auth_server is NOT in resource metadata - it's only provided in Agent-Auth challenge headers.
    """
    metadata = {
        "resource": resource_id,
        "jwks_uri": jwks_uri,
        "resource_token_endpoint": resource_token_endpoint
    }
    
    if supported_scopes:
        metadata["supported_scopes"] = supported_scopes
    
    if scope_descriptions:
        metadata["scope_descriptions"] = scope_descriptions
    
    return metadata


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
    """Fetch metadata document from URL via HTTPS.
    
    Args:
        url: HTTPS URL to metadata document (HTTP allowed for localhost development)
        
    Returns:
        Parsed metadata dictionary
        
    Raises:
        ValueError: If URL is not HTTPS (except localhost for development)
        httpx.HTTPError: If HTTP request fails
        json.JSONDecodeError: If response is not valid JSON
    """
    # Verify HTTPS (allow HTTP for localhost development)
    if not url.startswith("https://"):
        # Allow HTTP for localhost/127.0.0.1 for development
        parsed = httpx.URL(url)
        if parsed.host not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError(f"Metadata URL must use HTTPS (except localhost): {url}")
    
    # Fetch metadata
    response = httpx.get(url, timeout=10.0)
    response.raise_for_status()
    
    # Parse JSON
    return response.json()


def fetch_resource_metadata(url: str) -> Dict[str, Any]:
    """Fetch resource metadata from URL.
    
    Args:
        url: URL to resource metadata document (e.g., https://resource.example/.well-known/aauth-resource)
        
    Returns:
        Parsed resource metadata dictionary
    """
    return fetch_metadata(url)


def fetch_auth_metadata(url: str) -> Dict[str, Any]:
    """Fetch auth server metadata from URL.
    
    Args:
        url: URL to auth server metadata document (e.g., https://auth.example/.well-known/aauth-issuer)
        
    Returns:
        Parsed auth server metadata dictionary
    """
    return fetch_metadata(url)

