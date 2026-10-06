"""Resource metadata handling for AAuth.

Published at /.well-known/aauth-resource.json
"""

from typing import Dict, Any, Optional, List


def generate_resource_metadata(
    resource_id: str,
    jwks_uri: Optional[str] = None,
    client_name: Optional[str] = None,
    logo_uri: Optional[str] = None,
    logo_dark_uri: Optional[str] = None,
    authorization_endpoint: Optional[str] = None,
    resource_token_endpoint: Optional[str] = None,
    interaction_endpoint: Optional[str] = None,
    scope_descriptions: Optional[Dict[str, str]] = None,
    additional_signature_components: Optional[List[str]] = None,
    signature_window: Optional[int] = None,
    revocation_endpoint: Optional[str] = None,
    access_mode: Optional[str] = None,
    description: Optional[str] = None,
    documentation_uri: Optional[str] = None,
    accept_signature_algs: Optional[list] = None,
) -> Dict[str, Any]:
    """Generate resource metadata JSON per AAuth spec Section 13.3.

    Args:
        resource_id: Resource identifier (HTTPS URL) - REQUIRED
        jwks_uri: URL to resource's JSON Web Key Set - REQUIRED
        client_name: Human-readable resource name (optional)
        logo_uri: URL to resource logo (optional)
        logo_dark_uri: URL to resource logo for dark backgrounds (optional)
        authorization_endpoint: URL where agents request access (optional; REQUIRED in full spec)
        resource_token_endpoint: Legacy URL for proactive resource token requests (optional)
        interaction_endpoint: URL for resource-level user interaction (optional)
        scope_descriptions: Object mapping scope names to descriptions (optional)
        additional_signature_components: Additional HTTP components for signatures (optional)
        signature_window: Signature validity window in seconds for ``created`` (optional)
        login_endpoint: URL for third-party login initiation (OPTIONAL)
        revocation_endpoint: URL where authorized parties can revoke auth tokens (OPTIONAL)

    Returns:
        Resource metadata dictionary
    """
    metadata = {"issuer": resource_id}
    if jwks_uri is not None:
        metadata["jwks_uri"] = jwks_uri

    if client_name is not None:
        metadata["name"] = client_name
    if logo_uri is not None:
        metadata["logo_uri"] = logo_uri
    if logo_dark_uri is not None:
        metadata["logo_dark_uri"] = logo_dark_uri
    if authorization_endpoint is not None:
        metadata["authorization_endpoint"] = authorization_endpoint
    if resource_token_endpoint is not None:
        metadata["resource_token_endpoint"] = resource_token_endpoint
    if interaction_endpoint is not None:
        metadata["interaction_endpoint"] = interaction_endpoint
    if scope_descriptions is not None:
        metadata["scope_descriptions"] = scope_descriptions
    if additional_signature_components is not None:
        metadata["additional_signature_components"] = additional_signature_components
    if signature_window is not None:
        metadata["signature_window"] = signature_window
    if revocation_endpoint is not None:
        metadata["revocation_endpoint"] = revocation_endpoint

    for k, v in [
        ("access_mode", access_mode),
        ("description", description),
        ("documentation_uri", documentation_uri),
        ("accept_signature_algs", accept_signature_algs),
    ]:
        if v is not None:
            metadata[k] = v
    from .common import validate_metadata

    return validate_metadata(
        metadata, resource_id, ("jwks_uri",) if jwks_uri is not None else ()
    )
