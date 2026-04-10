"""Mission Manager metadata (/.well-known/aauth-mission.json)."""

from typing import Dict, Any, Optional
import httpx


def generate_mm_metadata(
    manager: str,
    token_endpoint: str,
    mission_endpoint: str,
    jwks_uri: str,
    mission_control_endpoint: Optional[str] = None,
) -> Dict[str, Any]:
    """Build MM metadata per SPEC_UPDATED Section 16.2."""
    meta: Dict[str, Any] = {
        "manager": manager,
        "token_endpoint": token_endpoint,
        "mission_endpoint": mission_endpoint,
        "jwks_uri": jwks_uri,
    }
    if mission_control_endpoint:
        meta["mission_control_endpoint"] = mission_control_endpoint
    return meta


def fetch_mm_metadata(manager_url: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Synchronous fetch of ``/.well-known/aauth-mission.json``."""
    base = manager_url.rstrip("/")
    for path in ("/.well-known/aauth-mission.json", "/.well-known/aauth-mission"):
        url = f"{base}{path}"
        r = httpx.get(url, timeout=timeout)
        if r.status_code == 200:
            return r.json()
    raise ValueError(f"Could not fetch MM metadata from {manager_url}")


async def fetch_mm_metadata_async(manager_url: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Async fetch of MM metadata."""
    base = manager_url.rstrip("/")
    async with httpx.AsyncClient() as client:
        for path in ("/.well-known/aauth-mission.json", "/.well-known/aauth-mission"):
            url = f"{base}{path}"
            r = await client.get(url, timeout=timeout)
            if r.status_code == 200:
                return r.json()
    raise ValueError(f"Could not fetch MM metadata from {manager_url}")
