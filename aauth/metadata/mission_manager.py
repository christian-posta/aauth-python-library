"""Person Server metadata (/.well-known/aauth-person.json)."""

from typing import Dict, Any, Optional
import httpx


def generate_ps_metadata(
    person_server: str,
    token_endpoint: str,
    jwks_uri: str,
    mission_endpoint: Optional[str] = None,
    permission_endpoint: Optional[str] = None,
    audit_endpoint: Optional[str] = None,
    interaction_endpoint: Optional[str] = None,
    mission_control_endpoint: Optional[str] = None,
    login_endpoint: Optional[str] = None,
    revocation_endpoint: Optional[str] = None,
    scopes_supported: Optional[list] = None,
    claims_supported: Optional[list] = None,
) -> Dict[str, Any]:
    """Build PS metadata per SPEC §PS Metadata.

    Published at ``/.well-known/aauth-person.json``.

    Args:
        person_server: PS's HTTPS URL (issuer) — REQUIRED
        token_endpoint: URL where agents send token requests — REQUIRED
        jwks_uri: URL to the PS's JSON Web Key Set — REQUIRED
        mission_endpoint: URL for mission lifecycle operations (OPTIONAL)
        permission_endpoint: URL where agents request permission for local actions (OPTIONAL)
        audit_endpoint: URL where agents log actions performed (OPTIONAL)
        interaction_endpoint: URL where agents relay interactions to the user (OPTIONAL)
        mission_control_endpoint: URL for mission administrative interface (OPTIONAL)
        login_endpoint: URL for third-party login initiation (OPTIONAL)
        revocation_endpoint: URL where authorized parties can revoke tokens (OPTIONAL)
        scopes_supported: Array of scope values the PS supports (RECOMMENDED)
        claims_supported: Array of identity claim names the PS can provide (RECOMMENDED)
    """
    meta: Dict[str, Any] = {
        "issuer": person_server,
        "token_endpoint": token_endpoint,
        "jwks_uri": jwks_uri,
    }
    if mission_endpoint:
        meta["mission_endpoint"] = mission_endpoint
    if permission_endpoint:
        meta["permission_endpoint"] = permission_endpoint
    if audit_endpoint:
        meta["audit_endpoint"] = audit_endpoint
    if interaction_endpoint:
        meta["interaction_endpoint"] = interaction_endpoint
    if mission_control_endpoint:
        meta["mission_control_endpoint"] = mission_control_endpoint
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
