"""Agent metadata handling for AAuth.

Published at /.well-known/aauth-agent.json
"""

from typing import Dict, Any, Optional


def generate_agent_metadata(
    agent_id: str,
    jwks_uri: str,
    client_name: Optional[str] = None,
    logo_uri: Optional[str] = None,
    logo_dark_uri: Optional[str] = None,
    callback_endpoint: Optional[str] = None,
    login_endpoint: Optional[str] = None,
    localhost_callback_allowed: Optional[bool] = None,
    clarification_supported: Optional[bool] = None,
    tos_uri: Optional[str] = None,
    policy_uri: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate agent metadata JSON per SPEC §Agent Server Metadata.

    Published at ``/.well-known/aauth-agent.json``.

    Args:
        agent_id: Agent identifier (HTTPS URL) — REQUIRED
        jwks_uri: URL to agent's JSON Web Key Set — REQUIRED
        client_name: Human-readable agent name (OPTIONAL)
        logo_uri: URL to agent logo (OPTIONAL)
        logo_dark_uri: URL to agent logo for dark backgrounds (OPTIONAL)
        callback_endpoint: Agent's HTTPS callback endpoint URL (OPTIONAL)
        login_endpoint: URL for third-party login initiation (OPTIONAL)
        localhost_callback_allowed: Whether agent supports localhost callbacks (OPTIONAL)
        clarification_supported: Whether agent supports clarification chat (OPTIONAL)
        tos_uri: URL to terms of service (OPTIONAL)
        policy_uri: URL to privacy policy (OPTIONAL)

    Returns:
        Agent metadata dictionary
    """
    metadata = {
        "issuer": agent_id,
        "jwks_uri": jwks_uri,
    }

    if client_name is not None:
        metadata["client_name"] = client_name
    if logo_uri is not None:
        metadata["logo_uri"] = logo_uri
    if logo_dark_uri is not None:
        metadata["logo_dark_uri"] = logo_dark_uri
    if callback_endpoint is not None:
        metadata["callback_endpoint"] = callback_endpoint
    if login_endpoint is not None:
        metadata["login_endpoint"] = login_endpoint
    if localhost_callback_allowed is not None:
        metadata["localhost_callback_allowed"] = localhost_callback_allowed
    if clarification_supported is not None:
        metadata["clarification_supported"] = clarification_supported
    if tos_uri is not None:
        metadata["tos_uri"] = tos_uri
    if policy_uri is not None:
        metadata["policy_uri"] = policy_uri

    return metadata
