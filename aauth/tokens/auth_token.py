"""Auth token creation and validation for AAuth."""

import time
import uuid
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
    private_key: Ed25519PrivateKey,
    kid: str,
    scope: Optional[str] = None,
    sub: Optional[str] = None,
    exp: Optional[int] = None,
    mission: Optional[Dict[str, Any]] = None,
) -> str:
    """Create an auth token (aa-auth+jwt) per AAuth spec Section 9.1.

    Args:
        iss: Auth server identifier (HTTPS URL)
        aud: Resource identifier, or agent identifier for self-access
        agent: Agent identifier (local@domain) - omitted from token when agent == aud (self-access)
        cnf_jwk: Agent's public signing key (JWK format)
        private_key: Auth server's Ed25519 private key for signing
        kid: Key ID for signing key
        scope: Authorized scopes (at least one of scope or sub MUST be present)
        sub: User identifier (at least one of scope or sub MUST be present)
        exp: Expiration timestamp. Defaults to 1 hour from now.
        mission: Optional mission object when issued in mission context.

    Returns:
        Signed JWT string (aa-auth+jwt)

    Raises:
        TokenError: If neither sub nor scope is provided
    """
    if not sub and not scope:
        raise TokenError(
            "At least one of 'sub' or 'scope' must be present in auth token",
            token_type="aa-auth+jwt"
        )

    now = int(time.time())
    if exp is None:
        exp = now + 3600  # 1 hour

    header = {
        "typ": "aa-auth+jwt",
        "alg": "EdDSA",
        "kid": kid
    }

    payload = {
        "iss": iss,
        "aud": aud,
        "dwk": "aauth-issuer.json",
        "jti": str(uuid.uuid4()),
        "cnf": {"jwk": cnf_jwk},
        "iat": now,
        "exp": exp,
    }

    # agent is REQUIRED per spec Section 9.1
    if agent:
        payload["agent"] = agent

    if sub:
        payload["sub"] = sub
    if scope:
        payload["scope"] = scope
    if mission is not None:
        payload["mission"] = mission
    return jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
        headers=header
    )


def parse_token_claims(token: str) -> Dict[str, Any]:
    """Parse token claims without verification (for inspection).

    Args:
        token: JWT token string

    Returns:
        Dictionary with header and payload claims
    """
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
        expected_typ: Expected typ claim
        expected_iss: Expected issuer
        expected_aud: Expected audience

    Returns:
        Dictionary with verified claims

    Raises:
        TokenError: If token is invalid
    """
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        raise TokenError(f"Failed to parse token: {e}", token_type=expected_typ or "jwt")

    if expected_typ:
        typ = header.get("typ")
        if typ != expected_typ:
            raise TokenError(
                f"Invalid token type: expected {expected_typ}, got {typ}",
                token_type=expected_typ
            )

    # Check exp
    exp = payload.get("exp")
    if exp:
        now = int(time.time())
        if now >= exp:
            raise jwt.ExpiredSignatureError("Token has expired")

    # Check iat (must not be in the future)
    iat = payload.get("iat")
    if iat:
        now = int(time.time())
        if iat > now + 60:  # Allow 60 second clock skew
            raise TokenError("Token iat is in the future", token_type=expected_typ or "jwt")

    # Check iss
    iss = payload.get("iss")
    if expected_iss and iss != expected_iss:
        raise TokenError(
            f"Invalid issuer: expected {expected_iss}, got {iss}",
            token_type=expected_typ or "jwt"
        )

    # Check aud
    aud = payload.get("aud")
    if expected_aud:
        if isinstance(aud, list):
            aud_matches = expected_aud in aud
        else:
            aud_matches = aud == expected_aud
        if not aud_matches:
            raise TokenError(
                f"Invalid audience: expected {expected_aud}, got {aud}",
                token_type=expected_typ or "jwt"
            )

    # Verify jti is present (required for all token types)
    if "jti" not in payload:
        raise TokenError("Token missing required 'jti' claim", token_type=expected_typ or "jwt")

    # Get signing key from JWKS
    kid_header = header.get("kid")
    if not kid_header:
        raise TokenError("Token header missing 'kid'", token_type=expected_typ or "jwt")

    jwks = jwks_fetcher(iss)
    if not jwks:
        raise TokenError(
            f"Failed to fetch JWKS from {iss}",
            token_type=expected_typ or "jwt"
        )

    keys = jwks.get("keys", [])
    signing_key = None
    for key in keys:
        if key.get("kid") == kid_header:
            signing_key = key
            break

    if not signing_key:
        raise TokenError(
            f"Signing key with kid={kid_header} not found in JWKS",
            token_type=expected_typ or "jwt"
        )

    public_key = jwk_to_public_key(signing_key)

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
