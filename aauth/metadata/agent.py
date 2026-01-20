"""Agent metadata handling for AAuth."""

from typing import Dict, Any


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

