"""Person Server metadata (/.well-known/aauth-person.json)."""

from typing import Dict, Any, Optional
import httpx


def generate_ps_metadata(
    person_server: str,
    token_endpoint: str,
    mission_endpoint: str,
    jwks_uri: str,
    mission_control_endpoint: Optional[str] = None,
    interaction_endpoint: Optional[str] = None,
    login_endpoint: Optional[str] = None,
    revocation_endpoint: Optional[str] = None,
    scopes_supported: Optional[list] = None,
    claims_supported: Optional[list] = None,
) -> Dict[str, Any]:
    """Build PS metadata per AAuth spec Section 16.2."""
    meta: Dict[str, Any] = {
        "issuer": person_server,
        "token_endpoint": token_endpoint,
        "mission_endpoint": mission_endpoint,
        "jwks_uri": jwks_uri,
    }
    if mission_control_endpoint:
        meta["mission_control_endpoint"] = mission_control_endpoint
    if interaction_endpoint:
        meta["interaction_endpoint"] = interaction_endpoint
    if login_endpoint:
        meta["login_endpoint"] = login_endpoint
    if revocation_endpoint:
        meta["revocation_endpoint"] = revocation_endpoint
    if scopes_supported is not None:
        meta["scopes_supported"] = scopes_supported
    if claims_supported is not None:
        meta["claims_supported"] = claims_supported
    return meta


def fetch_ps_metadata(ps_url: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Synchronous fetch of ``/.well-known/aauth-person.json``."""
    base = ps_url.rstrip("/")
    for path in ("/.well-known/aauth-person.json", "/.well-known/aauth-person"):
        url = f"{base}{path}"
        r = httpx.get(url, timeout=timeout)
        if r.status_code == 200:
            return r.json()
    raise ValueError(f"Could not fetch PS metadata from {ps_url}")


async def fetch_ps_metadata_async(ps_url: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Async fetch of PS metadata."""
    base = ps_url.rstrip("/")
    async with httpx.AsyncClient() as client:
        for path in ("/.well-known/aauth-person.json", "/.well-known/aauth-person"):
            url = f"{base}{path}"
            r = await client.get(url, timeout=timeout)
            if r.status_code == 200:
                return r.json()
    raise ValueError(f"Could not fetch PS metadata from {ps_url}")


# Backward-compatibility aliases (deprecated — use generate_ps_metadata etc.)
generate_mm_metadata = generate_ps_metadata
fetch_mm_metadata = fetch_ps_metadata
fetch_mm_metadata_async = fetch_ps_metadata_async
