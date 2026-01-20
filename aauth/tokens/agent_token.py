"""Agent token creation and validation for AAuth."""

import json
import time
from typing import Dict, Any, Optional, Callable
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ..keys.jwk import jwk_to_public_key
from ..errors import TokenError


def create_agent_token(
    iss: str,
    sub: str,
    cnf_jwk: Dict[str, Any],
    private_key: Ed25519PrivateKey,
    kid: str,
    exp: Optional[int] = None,
    aud: Optional[str] = None
) -> str:
    """Create an agent token (agent+jwt) per AAuth spec Section 5.
    
    Args:
        iss: Agent server identifier (HTTPS URL) - also the agent identifier
        sub: Agent delegate identifier (persists across key rotations)
        cnf_jwk: Agent delegate's public signing key (JWK format)
        private_key: Agent server's Ed25519 private key for signing
        kid: Key ID for agent server's signing key
        exp: Expiration timestamp (Unix time). If None, defaults to 1 hour from now.
        aud: Optional audience restriction (string or array of strings)
        
    Returns:
        Signed JWT string (agent+jwt)
    """
    # Set expiration (default 1 hour)
    if exp is None:
        exp = int(time.time()) + 3600  # 1 hour
    
    # Build header
    header = {
        "typ": "agent+jwt",
        "alg": "EdDSA",
        "kid": kid
    }
    
    # Build payload
    payload = {
        "iss": iss,
        "sub": sub,
        "exp": exp,
        "cnf": {
            "jwk": cnf_jwk
        }
    }
    
    if aud:
        payload["aud"] = aud
    
    # Sign token
    # PyJWT supports EdDSA with cryptography Ed25519PrivateKey objects directly
    token = jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
        headers=header
    )
    
    return token


def verify_agent_token(
    token: str,
    jwks_fetcher: Callable[[str], Optional[Dict[str, Any]]],
    expected_aud: Optional[str] = None
) -> Dict[str, Any]:
    """Verify an agent token per AAuth spec Section 5.7.
    
    Args:
        token: Agent token JWT string
        jwks_fetcher: Function that takes agent server URL (iss) and returns JWKS dict
        expected_aud: Optional expected audience (for recipient validation)
        
    Returns:
        Dictionary with verified claims including 'cnf' with 'jwk'
        
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
        raise TokenError(f"Failed to parse agent token: {e}", token_type="agent+jwt")
    
    # Step 1-2: Check typ claim
    typ = header.get("typ")
    if typ != "agent+jwt":
        raise TokenError(
            f"Invalid token type: expected agent+jwt, got {typ}",
            token_type="agent+jwt"
        )
    
    # Step 3-4: Extract kid and iss
    kid = header.get("kid")
    if not kid:
        raise TokenError("Token header missing 'kid'", token_type="agent+jwt")
    
    iss = payload.get("iss")
    if not iss:
        raise TokenError("Token payload missing 'iss'", token_type="agent+jwt")
    
    # Step 5-6: Fetch agent server's JWKS and match key
    jwks = jwks_fetcher(iss)
    if not jwks:
        raise TokenError(
            f"Failed to fetch JWKS from {iss}",
            token_type="agent+jwt",
            details={"iss": iss}
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
            token_type="agent+jwt",
            details={"kid": kid, "iss": iss}
        )
    
    # Step 7: Verify JWT signature
    try:
        public_key = jwk_to_public_key(signing_key)
        jwt.decode(
            token,
            public_key,
            algorithms=["EdDSA"],
            options={"verify_signature": True, "verify_exp": False, "verify_aud": False}
        )
    except jwt.InvalidSignatureError as e:
        raise TokenError(
            f"JWT signature verification failed: {e}",
            token_type="agent+jwt"
        )
    except Exception as e:
        raise TokenError(
            f"Failed to verify JWT signature: {e}",
            token_type="agent+jwt"
        )
    
    # Step 8: Verify exp claim
    exp = payload.get("exp")
    if exp:
        now = int(time.time())
        if now >= exp:
            raise jwt.ExpiredSignatureError("Token has expired")
    else:
        raise TokenError("Token missing 'exp' claim", token_type="agent+jwt")
    
    # Step 9: Verify sub claim is present
    sub = payload.get("sub")
    if not sub:
        raise TokenError(
            "Token missing 'sub' claim (agent delegate identifier)",
            token_type="agent+jwt"
        )
    
    # Step 10: Verify aud claim if present
    aud = payload.get("aud")
    if aud and expected_aud:
        # Handle both string and array audience (per JWT spec)
        if isinstance(aud, list):
            aud_matches = expected_aud in aud
        else:
            aud_matches = aud == expected_aud
        
        if not aud_matches:
            raise TokenError(
                f"Invalid audience: expected {expected_aud}, got {aud}",
                token_type="agent+jwt"
            )
    
    # Step 11: Extract cnf.jwk (already in payload)
    cnf = payload.get("cnf")
    if not cnf:
        raise TokenError("Token missing 'cnf' claim", token_type="agent+jwt")
    
    cnf_jwk = cnf.get("jwk")
    if not cnf_jwk:
        raise TokenError("Token missing 'cnf.jwk' claim", token_type="agent+jwt")
    
    # Return verified claims (including cnf.jwk for HTTPSig verification)
    return payload

