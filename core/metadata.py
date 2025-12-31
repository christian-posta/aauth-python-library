"""Metadata document handling for AAuth."""

from typing import Dict, Any
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

