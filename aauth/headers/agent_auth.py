"""Agent-Auth header parsing and building for AAuth."""

import re
from typing import Dict, Any, Optional, List
from ..errors import ChallengeError


def parse_agent_auth_header(header_value: str) -> Dict[str, Any]:
    """Parse Agent-Auth header per AAuth spec Section 4.
    
    Agent-Auth header uses RFC 8941 structured fields format:
    - httpsig (required)
    - identity=?1 (optional boolean)
    - auth-token (optional bare token)
    - resource_token="..." (optional string)
    - auth_server="..." (optional string)
    - user_interaction="..." (optional string)
    - algs=("ed25519" "rsa-pss-sha512") (optional inner list)
    
    Args:
        header_value: Agent-Auth header value
        
    Returns:
        Dictionary with parsed parameters:
        - httpsig: bool (always True)
        - identity: Optional[bool]
        - auth_token: Optional[bool]
        - resource_token: Optional[str]
        - auth_server: Optional[str]
        - user_interaction: Optional[str]
        - algs: Optional[List[str]]
        
    Raises:
        ChallengeError: If header format is invalid
    """
    try:
        result = {
            "httpsig": True,
            "identity": None,
            "auth_token": False,
            "resource_token": None,
            "auth_server": None,
            "user_interaction": None,
            "algs": None
        }
        
        # Parse structured fields format
        # Basic format: httpsig; identity=?1; auth-token; resource_token="..."; auth_server="..."
        
        # Check for httpsig (required)
        if "httpsig" not in header_value:
            raise ChallengeError("Agent-Auth header must include 'httpsig'")
        
        # Parse identity parameter (?1 = true)
        if "identity=?1" in header_value or "identity=?1;" in header_value:
            result["identity"] = True
        elif "identity=" in header_value:
            # Could be ?0 or other value
            match = re.search(r'identity=(\?[01])', header_value)
            if match:
                result["identity"] = match.group(1) == "?1"
        
        # Parse auth-token (bare token, no value)
        if re.search(r'\bauth-token\b', header_value):
            result["auth_token"] = True
        
        # Parse resource_token="..."
        resource_token_match = re.search(r'resource_token="([^"]+)"', header_value)
        if resource_token_match:
            result["resource_token"] = resource_token_match.group(1)
        
        # Parse auth_server="..."
        auth_server_match = re.search(r'auth_server="([^"]+)"', header_value)
        if auth_server_match:
            result["auth_server"] = auth_server_match.group(1)
        
        # Parse user_interaction="..."
        user_interaction_match = re.search(r'user_interaction="([^"]+)"', header_value)
        if user_interaction_match:
            result["user_interaction"] = user_interaction_match.group(1)
        
        # Parse algs=("ed25519" "rsa-pss-sha512") (inner list)
        algs_match = re.search(r'algs=\("([^"]+)"(?:\s+"([^"]+)")*\)', header_value)
        if algs_match:
            # Extract all quoted strings
            algs = re.findall(r'"([^"]+)"', algs_match.group(0))
            result["algs"] = algs
        
        return result
    
    except ChallengeError:
        raise
    except Exception as e:
        raise ChallengeError(f"Failed to parse Agent-Auth header: {e}") from e


def build_agent_auth_challenge(
    require_signature: bool = True,
    require_identity: bool = False,
    require_auth_token: bool = False,
    resource_token: Optional[str] = None,
    auth_server: Optional[str] = None,
    user_interaction: Optional[str] = None,
    algs: Optional[List[str]] = None
) -> str:
    """Build Agent-Auth challenge header per AAuth spec Section 4.
    
    Args:
        require_signature: Require HTTP signature (default: True)
        require_identity: Require agent identity verification
        require_auth_token: Require authorization token
        resource_token: Resource token (required if require_auth_token=True)
        auth_server: Auth server URL (required if require_auth_token=True)
        user_interaction: User interaction URL
        algs: List of supported algorithms
        
    Returns:
        Agent-Auth header value
        
    Raises:
        ChallengeError: If parameters are invalid
    """
    if not require_signature:
        raise ChallengeError("Agent-Auth header must require httpsig")
    
    parts = ["httpsig"]
    
    if require_identity:
        parts.append("identity=?1")
    
    if require_auth_token:
        parts.append("auth-token")
        if resource_token:
            parts.append(f'resource_token="{resource_token}"')
        if auth_server:
            parts.append(f'auth_server="{auth_server}"')
    
    if user_interaction:
        parts.append(f'user_interaction="{user_interaction}"')
    
    if algs:
        algs_str = ' '.join([f'"{alg}"' for alg in algs])
        parts.append(f'algs=({algs_str})')
    
    return "; ".join(parts)

