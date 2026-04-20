"""Agent token creation and validation for AAuth."""

import time
import uuid
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
    aud: Optional[str] = None,
    aud_sub: Optional[str] = None,
    ps: Optional[str] = None,
) -> str:
    """Create an agent token (aa-agent+jwt) per AAuth spec Section 7.1.

    Args:
        iss: Agent server identifier (HTTPS URL) - also the agent identifier
        sub: Agent delegate identifier (persists across key rotations)
        cnf_jwk: Agent delegate's public signing key (JWK format)
        private_key: Agent server's Ed25519 private key for signing
        kid: Key ID for agent server's signing key
        exp: Expiration timestamp. Defaults to 1 hour from now.
        aud: Optional audience restriction (single URL or array)
        aud_sub: Optional user identifier hint for the auth server in aud
        ps: Optional HTTPS URL of the agent's person server

    Returns:
        Signed JWT string (aa-agent+jwt)
    """
    now = int(time.time())
    if exp is None:
        exp = now + 3600  # 1 hour

    header = {
        "typ": "aa-agent+jwt",
        "alg": "EdDSA",
        "kid": kid
    }

    payload = {
        "iss": iss,
        "sub": sub,
        "dwk": "aauth-agent.json",
        "jti": str(uuid.uuid4()),
        "cnf": {"jwk": cnf_jwk},
        "iat": now,
        "exp": exp,
    }

    if aud is not None:
        payload["aud"] = aud
    if aud_sub is not None:
        payload["aud_sub"] = aud_sub
    if ps is not None:
        payload["ps"] = ps

    return jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
        headers=header
    )


def verify_agent_token(
    token: str,
    jwks_fetcher: Callable[[str], Optional[Dict[str, Any]]],
    expected_aud: Optional[str] = None
) -> Dict[str, Any]:
    """Verify an agent token per AAuth spec Section 16.2.1.

    Args:
        token: Agent token JWT string
        jwks_fetcher: Function that takes agent server URL (iss) and returns JWKS dict
        expected_aud: Optional expected audience (for recipient validation)

    Returns:
        Dictionary with verified claims including 'cnf' with 'jwk'

    Raises:
        TokenError: If token is invalid
    """
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        raise TokenError(f"Failed to parse agent token: {e}", token_type="aa-agent+jwt")

    # Check typ
    typ = header.get("typ")
    if typ != "aa-agent+jwt":
        raise TokenError(
            f"Invalid token type: expected aa-agent+jwt, got {typ}",
            token_type="aa-agent+jwt"
        )

    # Check required claims
    kid_header = header.get("kid")
    if not kid_header:
        raise TokenError("Token header missing 'kid'", token_type="aa-agent+jwt")

    iss = payload.get("iss")
    if not iss:
        raise TokenError("Token payload missing 'iss'", token_type="aa-agent+jwt")

    if "jti" not in payload:
        raise TokenError("Token missing required 'jti' claim", token_type="aa-agent+jwt")

    sub = payload.get("sub")
    if not sub:
        raise TokenError("Token missing 'sub' claim (agent delegate identifier)", token_type="aa-agent+jwt")

    # Fetch agent server's JWKS and verify signature
    jwks = jwks_fetcher(iss)
    if not jwks:
        raise TokenError(
            f"Failed to fetch JWKS from {iss}",
            token_type="aa-agent+jwt",
            details={"iss": iss}
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
            token_type="aa-agent+jwt",
            details={"kid": kid_header, "iss": iss}
        )

    try:
        public_key = jwk_to_public_key(signing_key)
        jwt.decode(
            token,
            public_key,
            algorithms=["EdDSA"],
            options={"verify_signature": True, "verify_exp": False, "verify_aud": False}
        )
    except jwt.InvalidSignatureError as e:
        raise TokenError(f"JWT signature verification failed: {e}", token_type="aa-agent+jwt")
    except Exception as e:
        raise TokenError(f"Failed to verify JWT signature: {e}", token_type="aa-agent+jwt")

    # Verify exp
    exp = payload.get("exp")
    if exp:
        if int(time.time()) >= exp:
            raise jwt.ExpiredSignatureError("Token has expired")
    else:
        raise TokenError("Token missing 'exp' claim", token_type="aa-agent+jwt")

    # Verify aud if present
    aud = payload.get("aud")
    if aud and expected_aud:
        if isinstance(aud, list):
            aud_matches = expected_aud in aud
        else:
            aud_matches = aud == expected_aud
        if not aud_matches:
            raise TokenError(
                f"Invalid audience: expected {expected_aud}, got {aud}",
                token_type="aa-agent+jwt"
            )

    # Verify cnf.jwk
    cnf = payload.get("cnf")
    if not cnf:
        raise TokenError("Token missing 'cnf' claim", token_type="aa-agent+jwt")
    if not cnf.get("jwk"):
        raise TokenError("Token missing 'cnf.jwk' claim", token_type="aa-agent+jwt")

    return payload
