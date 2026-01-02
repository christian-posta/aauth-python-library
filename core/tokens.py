"""Token generation and validation for AAuth (resource tokens and auth tokens)."""

import json
import base64
import hashlib
import time
from typing import Dict, Any, Optional, Callable
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .crypto_utils import public_key_to_jwk, jwk_to_public_key
from . import _is_debug_enabled


def calculate_jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    """Calculate JWK Thumbprint per RFC 7638.
    
    Args:
        jwk: JWK dictionary (must be canonical - only include required fields)
        
    Returns:
        Base64url-encoded SHA-256 hash of canonical JWK JSON
    """
    debug = _is_debug_enabled()
    
    # Create canonical JWK (only include required fields, sorted)
    # For Ed25519: kty, crv, x (and kid if present, but exclude from thumbprint)
    canonical_jwk = {}
    
    # Required fields in order
    if "kty" in jwk:
        canonical_jwk["kty"] = jwk["kty"]
    if "crv" in jwk:
        canonical_jwk["crv"] = jwk["crv"]
    if "x" in jwk:
        canonical_jwk["x"] = jwk["x"]
    
    # Convert to canonical JSON (no spaces, sorted keys)
    canonical_json = json.dumps(canonical_jwk, separators=(',', ':'), sort_keys=True)
    
    if debug:
        import sys
        print(f"DEBUG TOKEN: JWK Thumbprint calculation:", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Input JWK: {json.dumps(jwk, indent=2)}", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Canonical JWK: {canonical_json}", file=sys.stderr, flush=True)
    
    # SHA-256 hash
    hash_bytes = hashlib.sha256(canonical_json.encode('utf-8')).digest()
    
    if debug:
        import sys
        print(f"DEBUG TOKEN:   SHA-256 hash (hex): {hash_bytes.hex()}", file=sys.stderr, flush=True)
    
    # Base64url encode (no padding)
    thumbprint = base64.urlsafe_b64encode(hash_bytes).decode('utf-8').rstrip('=')
    
    if debug:
        import sys
        print(f"DEBUG TOKEN:   Base64url thumbprint: {thumbprint}", file=sys.stderr, flush=True)
    
    return thumbprint


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
    debug = _is_debug_enabled()
    
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
    
    if debug:
        import sys
        print(f"DEBUG TOKEN: Creating resource token:", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Header: {json.dumps(header, indent=2)}", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Payload: {json.dumps(payload, indent=2)}", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Expiration: {exp} ({time.ctime(exp)})", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Current time: {int(time.time())} ({time.ctime()})", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Time until expiration: {exp - int(time.time())} seconds", file=sys.stderr, flush=True)
    
    # Sign token
    # PyJWT supports EdDSA with cryptography Ed25519PrivateKey objects directly
    token = jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
        headers=header
    )
    
    if debug:
        import sys
        # Decode to show signature (last part)
        parts = token.split('.')
        if len(parts) == 3:
            signature_b64 = parts[2]
            print(f"DEBUG TOKEN:   Signature (base64url): {signature_b64[:50]}...", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Full token: {token[:100]}...", file=sys.stderr, flush=True)
    
    return token


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
    agent_delegate: Optional[str] = None
) -> str:
    """Create an auth token (auth+jwt) per AAuth spec Section 7.
    
    Args:
        iss: Auth server identifier (HTTPS URL)
        aud: Resource identifier (HTTPS URL)
        agent: Agent identifier (HTTPS URL)
        cnf_jwk: Agent's public signing key (JWK format)
        scope: Space-separated scope values
        private_key: Auth server's Ed25519 private key for signing
        kid: Key ID for signing key
        exp: Expiration timestamp (Unix time). If None, defaults to 1 hour from now.
        sub: Optional user identifier
        agent_delegate: Optional agent delegate identifier
        
    Returns:
        Signed JWT string (auth+jwt)
    """
    debug = _is_debug_enabled()
    
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
        "agent": agent,
        "cnf": {
            "jwk": cnf_jwk
        },
        "scope": scope,
        "exp": exp
    }
    
    if sub:
        payload["sub"] = sub
    
    if agent_delegate:
        payload["agent_delegate"] = agent_delegate
    
    if debug:
        import sys
        print(f"DEBUG TOKEN: Creating auth token:", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Header: {json.dumps(header, indent=2)}", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Payload: {json.dumps(payload, indent=2)}", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   cnf.jwk: {json.dumps(cnf_jwk, indent=2)}", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Expiration: {exp} ({time.ctime(exp)})", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Current time: {int(time.time())} ({time.ctime()})", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Time until expiration: {exp - int(time.time())} seconds", file=sys.stderr, flush=True)
        if sub:
            print(f"DEBUG TOKEN:   User (sub): {sub}", file=sys.stderr, flush=True)
        if agent_delegate:
            print(f"DEBUG TOKEN:   Agent delegate: {agent_delegate}", file=sys.stderr, flush=True)
    
    # Sign token
    # PyJWT supports EdDSA with cryptography Ed25519PrivateKey objects directly
    token = jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
        headers=header
    )
    
    if debug:
        import sys
        # Decode to show signature (last part)
        parts = token.split('.')
        if len(parts) == 3:
            signature_b64 = parts[2]
            print(f"DEBUG TOKEN:   Signature (base64url): {signature_b64[:50]}...", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Full token: {token[:100]}...", file=sys.stderr, flush=True)
    
    return token


def parse_token_claims(token: str) -> Dict[str, Any]:
    """Parse token claims without verification (for inspection).
    
    Args:
        token: JWT token string
        
    Returns:
        Dictionary with header and payload claims
    """
    debug = _is_debug_enabled()
    
    # Decode without verification
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})
    
    if debug:
        import sys
        print(f"DEBUG TOKEN: Parsing token claims (unverified):", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Header: {json.dumps(header, indent=2)}", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Payload: {json.dumps(payload, indent=2)}", file=sys.stderr, flush=True)
    
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
        jwt.InvalidTokenError: If token is invalid
        ValueError: If claims don't match expectations
    """
    debug = _is_debug_enabled()
    
    if debug:
        import sys
        print(f"DEBUG TOKEN: Verifying token:", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Token (first 100 chars): {token[:100]}...", file=sys.stderr, flush=True)
    
    # Parse header and payload (unverified first)
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})
    
    if debug:
        import sys
        print(f"DEBUG TOKEN:   Parsed header: {json.dumps(header, indent=2)}", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Parsed payload: {json.dumps(payload, indent=2)}", file=sys.stderr, flush=True)
    
    # Check typ claim
    if expected_typ:
        typ = header.get("typ")
        if typ != expected_typ:
            if debug:
                import sys
                print(f"DEBUG TOKEN:   Typ check FAILED: expected={expected_typ}, got={typ}", file=sys.stderr, flush=True)
            raise ValueError(f"Invalid token type: expected {expected_typ}, got {typ}")
        if debug:
            import sys
            print(f"DEBUG TOKEN:   Typ check PASSED: {typ}", file=sys.stderr, flush=True)
    
    # Check exp claim
    exp = payload.get("exp")
    if exp:
        now = int(time.time())
        if now >= exp:
            if debug:
                import sys
                print(f"DEBUG TOKEN:   Exp check FAILED: exp={exp} ({time.ctime(exp)}), now={now} ({time.ctime()})", file=sys.stderr, flush=True)
            raise jwt.ExpiredSignatureError("Token has expired")
        if debug:
            import sys
            print(f"DEBUG TOKEN:   Exp check PASSED: exp={exp} ({time.ctime(exp)}), now={now} ({time.ctime()})", file=sys.stderr, flush=True)
            print(f"DEBUG TOKEN:   Time until expiration: {exp - now} seconds", file=sys.stderr, flush=True)
    
    # Check iss claim
    iss = payload.get("iss")
    if expected_iss and iss != expected_iss:
        if debug:
            import sys
            print(f"DEBUG TOKEN:   Iss check FAILED: expected={expected_iss}, got={iss}", file=sys.stderr, flush=True)
        raise ValueError(f"Invalid issuer: expected {expected_iss}, got {iss}")
    if debug and iss:
        import sys
        print(f"DEBUG TOKEN:   Issuer: {iss}", file=sys.stderr, flush=True)
    
    # Check aud claim
    aud = payload.get("aud")
    if debug:
        import sys
        print(f"DEBUG TOKEN:   Checking audience claim:", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:     aud from token: {aud!r} (type: {type(aud).__name__})", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:     expected_aud: {expected_aud!r} (type: {type(expected_aud).__name__ if expected_aud else 'None'})", file=sys.stderr, flush=True)
    
    if expected_aud:
        # Handle both string and array audience (per JWT spec)
        if isinstance(aud, list):
            aud_matches = expected_aud in aud
        else:
            aud_matches = aud == expected_aud
        
        if not aud_matches:
            if debug:
                import sys
                print(f"DEBUG TOKEN:   Aud check FAILED: expected={expected_aud!r}, got={aud!r}", file=sys.stderr, flush=True)
            raise ValueError(f"Invalid audience: expected {expected_aud}, got {aud}")
        elif debug:
            import sys
            print(f"DEBUG TOKEN:   Aud check PASSED: {aud}", file=sys.stderr, flush=True)
    elif debug and aud:
        import sys
        print(f"DEBUG TOKEN:   Audience: {aud} (no expected_aud specified)", file=sys.stderr, flush=True)
    
    # Get signing key from JWKS
    kid = header.get("kid")
    if not kid:
        raise ValueError("Token header missing 'kid'")
    
    if debug:
        import sys
        print(f"DEBUG TOKEN:   Key ID (kid): {kid}", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Fetching JWKS from issuer: {iss}", file=sys.stderr, flush=True)
    
    jwks = jwks_fetcher(iss)
    if not jwks:
        raise ValueError(f"Failed to fetch JWKS from {iss}")
    
    if debug:
        import sys
        print(f"DEBUG TOKEN:   JWKS received: {json.dumps(jwks, indent=2)}", file=sys.stderr, flush=True)
    
    # Find key by kid
    keys = jwks.get("keys", [])
    signing_key = None
    for key in keys:
        if key.get("kid") == kid:
            signing_key = key
            break
    
    if not signing_key:
        if debug:
            import sys
            print(f"DEBUG TOKEN:   Key lookup FAILED: kid={kid} not found in JWKS", file=sys.stderr, flush=True)
        raise ValueError(f"Signing key with kid={kid} not found in JWKS")
    
    if debug:
        import sys
        print(f"DEBUG TOKEN:   Key found: {json.dumps(signing_key, indent=2)}", file=sys.stderr, flush=True)
    
    # Convert JWK to public key
    public_key = jwk_to_public_key(signing_key)
    
    if debug:
        import sys
        print(f"DEBUG TOKEN:   Converting JWK to public key for signature verification", file=sys.stderr, flush=True)
    
    # Verify signature
    # PyJWT supports EdDSA with cryptography Ed25519PublicKey objects directly
    try:
        # Verify signature
        # Note: We don't pass audience to jwt.decode() because we check it manually above
        # PyJWT's audience validation requires the audience parameter, but we want to check it ourselves
        jwt.decode(
            token,
            public_key,
            algorithms=["EdDSA"],
            options={"verify_signature": True, "verify_exp": False, "verify_aud": False}  # We check aud manually above
        )
        if debug:
            import sys
            print(f"DEBUG TOKEN:   Signature verification PASSED", file=sys.stderr, flush=True)
    except jwt.InvalidSignatureError as e:
        if debug:
            import sys
            print(f"DEBUG TOKEN:   Signature verification FAILED: {e}", file=sys.stderr, flush=True)
        raise
    
    if debug:
        import sys
        print(f"DEBUG TOKEN:   Token verification SUCCESS", file=sys.stderr, flush=True)
        print(f"DEBUG TOKEN:   Extracted claims:", file=sys.stderr, flush=True)
        for key, value in payload.items():
            print(f"DEBUG TOKEN:     {key}: {value}", file=sys.stderr, flush=True)
    
    return payload

