"""Resource token creation and validation for AAuth."""

import json
import time
from typing import Dict, Any, Optional
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ..keys.jwk import calculate_jwk_thumbprint
from ..errors import TokenError


def create_resource_token(
    iss: str,
    aud: str,
    agent: str,
    agent_jkt: str,
    scope: str,
    private_key: Ed25519PrivateKey,
    kid: str,
    exp: Optional[int] = None
) -> str:
    """Create a resource token (resource+jwt) per AAuth spec Section 6.
    
    Args:
        iss: Resource identifier (HTTPS URL)
        aud: Auth server identifier (HTTPS URL)
        agent: Agent identifier (HTTPS URL)
        agent_jkt: JWK Thumbprint of agent's signing key
        scope: Space-separated scope values
        private_key: Resource's Ed25519 private key for signing
        kid: Key ID for signing key
        exp: Expiration timestamp (Unix time). If None, defaults to 10 minutes from now.
        
    Returns:
        Signed JWT string (resource+jwt)
    """
    # Set expiration (default 10 minutes)
    if exp is None:
        exp = int(time.time()) + 600  # 10 minutes
    
    # Build header
    header = {
        "typ": "resource+jwt",
        "alg": "EdDSA",
        "kid": kid
    }
    
    # Build payload
    payload = {
        "iss": iss,
        "aud": aud,
        "agent": agent,
        "agent_jkt": agent_jkt,
        "scope": scope,
        "exp": exp
    }
    
    # Sign token
    # PyJWT supports EdDSA with cryptography Ed25519PrivateKey objects directly
    token = jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
        headers=header
    )
    
    return token

