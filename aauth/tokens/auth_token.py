"""Auth token creation and validation for AAuth."""

import json
import time
from typing import Dict, Any, Optional, Callable
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ..keys.jwk import jwk_to_public_key
from ..errors import TokenError


def create_auth_token(
    iss: str,
    aud: str,
    agent: str,
    cnf_jwk: Dict[str, Any],
    scope: str,
    private_key: Ed25519PrivateKey,
    kid: str,
    exp: Optional[int] = None,
    sub: Optional[str] = None,
    agent_delegate: Optional[str] = None,
    agent_is_resource: bool = False,
    act: Optional[Dict[str, Any]] = None
) -> str:
    """Create an auth token (auth+jwt) per AAuth spec Section 7.
    
    Args:
        iss: Auth server identifier (HTTPS URL)
        aud: Resource identifier (HTTPS URL). When agent_is_resource=True, this should be the agent identifier.
        agent: Agent identifier (HTTPS URL). Omitted from payload when agent_is_resource=True.
        cnf_jwk: Agent's public signing key (JWK format)
        scope: Space-separated scope values
        private_key: Auth server's Ed25519 private key for signing
        kid: Key ID for signing key
        exp: Expiration timestamp (Unix time). If None, defaults to 1 hour from now.
        sub: Optional user identifier
        agent_delegate: Optional agent delegate identifier
        agent_is_resource: If True, omit 'agent' claim and set aud to agent identifier (Phase 5: agent is resource)
        act: Optional actor claim for token exchange delegation chain (Phase 7).
             Contains: agent (REQUIRED), agent_delegate (OPTIONAL), sub (OPTIONAL), act (OPTIONAL for nested chains)
        
    Returns:
        Signed JWT string (auth+jwt)
    """
    # Set expiration (default 1 hour)
    if exp is None:
        exp = int(time.time()) + 3600  # 1 hour
    
    # Build header
    header = {
        "typ": "auth+jwt",
        "alg": "EdDSA",
        "kid": kid
    }
    
    # Build payload
    payload = {
        "iss": iss,
        "aud": aud,
        "cnf": {
            "jwk": cnf_jwk
        },
        "scope": scope,
        "exp": exp
    }
    
    # Phase 5: When agent is resource, omit 'agent' claim per SPEC.md Section 7.3
    if not agent_is_resource:
        payload["agent"] = agent
    
    if sub:
        payload["sub"] = sub
    
    if agent_delegate:
        payload["agent_delegate"] = agent_delegate
    
    # Phase 7: Token exchange - add actor claim for delegation chain
    if act:
        payload["act"] = act
    
    # Sign token
    # PyJWT supports EdDSA with cryptography Ed25519PrivateKey objects directly
    token = jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
        headers=header
    )
    
    return token


def parse_token_claims(token: str) -> Dict[str, Any]:
    """Parse token claims without verification (for inspection).
    
    Args:
        token: JWT token string
        
    Returns:
        Dictionary with header and payload claims
    """
    # Decode without verification
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})
    
    return {
        "header": header,
        "payload": payload
    }


def verify_token(
    token: str,
    jwks_fetcher: Callable[[str], Optional[Dict[str, Any]]],
    expected_typ: Optional[str] = None,
    expected_iss: Optional[str] = None,
    expected_aud: Optional[str] = None
) -> Dict[str, Any]:
    """Verify a JWT token signature and claims.
    
    Args:
        token: JWT token string
        jwks_fetcher: Function that takes issuer URL and returns JWKS dict
        expected_typ: Expected typ claim (e.g., "resource+jwt", "auth+jwt")
        expected_iss: Expected issuer (optional)
        expected_aud: Expected audience (optional)
        
    Returns:
        Dictionary with verified claims
        
    Raises:
        TokenError: If token is invalid
        jwt.InvalidTokenError: If token is invalid
        ValueError: If claims don't match expectations
    """
    # Parse header and payload (unverified first)
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        raise TokenError(f"Failed to parse token: {e}", token_type=expected_typ or "jwt")
    
    # Check typ claim
    if expected_typ:
        typ = header.get("typ")
        if typ != expected_typ:
            raise TokenError(
                f"Invalid token type: expected {expected_typ}, got {typ}",
                token_type=expected_typ
            )
    
    # Check exp claim
    exp = payload.get("exp")
    if exp:
        now = int(time.time())
        if now >= exp:
            raise jwt.ExpiredSignatureError("Token has expired")
    
    # Check iss claim
    iss = payload.get("iss")
    if expected_iss and iss != expected_iss:
        raise TokenError(
            f"Invalid issuer: expected {expected_iss}, got {iss}",
            token_type=expected_typ or "jwt"
        )
    
    # Check aud claim
    aud = payload.get("aud")
    if expected_aud:
        # Handle both string and array audience (per JWT spec)
        if isinstance(aud, list):
            aud_matches = expected_aud in aud
        else:
            aud_matches = aud == expected_aud
        
        if not aud_matches:
            raise TokenError(
                f"Invalid audience: expected {expected_aud}, got {aud}",
                token_type=expected_typ or "jwt"
            )
    
    # Get signing key from JWKS
    kid = header.get("kid")
    if not kid:
        raise TokenError("Token header missing 'kid'", token_type=expected_typ or "jwt")
    
    jwks = jwks_fetcher(iss)
    if not jwks:
        raise TokenError(
            f"Failed to fetch JWKS from {iss}",
            token_type=expected_typ or "jwt"
        )
    
    # Find key by kid
    keys = jwks.get("keys", [])
    signing_key = None
    for key in keys:
        if key.get("kid") == kid:
            signing_key = key
            break
    
    if not signing_key:
        raise TokenError(
            f"Signing key with kid={kid} not found in JWKS",
            token_type=expected_typ or "jwt"
        )
    
    # Convert JWK to public key
    public_key = jwk_to_public_key(signing_key)
    
    # Verify signature
    try:
        jwt.decode(
            token,
            public_key,
            algorithms=["EdDSA"],
            options={"verify_signature": True, "verify_exp": False, "verify_aud": False}
        )
    except jwt.InvalidSignatureError as e:
        raise TokenError(
            f"JWT signature verification failed: {e}",
            token_type=expected_typ or "jwt"
        )
    
    return payload

