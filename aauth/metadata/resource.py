"""Resource metadata handling for AAuth."""

from typing import Dict, Any, Optional


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

