"""Resource metadata handling for AAuth.

Published at /.well-known/aauth-resource.json
"""

from typing import Dict, Any, Optional, List


def generate_resource_metadata(
    resource_id: str,
    jwks_uri: str,
    client_name: Optional[str] = None,
    logo_uri: Optional[str] = None,
    logo_dark_uri: Optional[str] = None,
    resource_token_endpoint: Optional[str] = None,
    interaction_endpoint: Optional[str] = None,
    scope_descriptions: Optional[Dict[str, str]] = None,
    additional_signature_components: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Generate resource metadata JSON per AAuth spec Section 13.3.

    Args:
        resource_id: Resource identifier (HTTPS URL) - REQUIRED
        jwks_uri: URL to resource's JSON Web Key Set - REQUIRED
        client_name: Human-readable resource name (optional)
        logo_uri: URL to resource logo (optional)
        logo_dark_uri: URL to resource logo for dark backgrounds (optional)
        resource_token_endpoint: URL for proactive resource token requests (optional)
        interaction_endpoint: URL for resource-level user interaction (optional)
        scope_descriptions: Object mapping scope names to descriptions (optional)
        additional_signature_components: Additional HTTP components for signatures (optional)

    Returns:
        Resource metadata dictionary
    """
    metadata = {
        "resource": resource_id,
        "jwks_uri": jwks_uri,
    }

    if client_name is not None:
        metadata["client_name"] = client_name
    if logo_uri is not None:
        metadata["logo_uri"] = logo_uri
    if logo_dark_uri is not None:
        metadata["logo_dark_uri"] = logo_dark_uri
    if resource_token_endpoint is not None:
        metadata["resource_token_endpoint"] = resource_token_endpoint
    if interaction_endpoint is not None:
        metadata["interaction_endpoint"] = interaction_endpoint
    if scope_descriptions is not None:
        metadata["scope_descriptions"] = scope_descriptions
    if additional_signature_components is not None:
        metadata["additional_signature_components"] = additional_signature_components

    return metadata
