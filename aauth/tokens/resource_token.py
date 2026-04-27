"""Resource token creation and validation for AAuth."""

import time
import uuid
from typing import Dict, Any, Optional, Callable
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
    exp: Optional[int] = None,
    mission: Optional[Dict[str, Any]] = None,
) -> str:
    """Create a resource token (aa-resource+jwt) per AAuth spec Section 8.1.

    Args:
        iss: Resource identifier (HTTPS URL)
        aud: Auth server identifier (HTTPS URL)
        agent: Agent identifier (HTTPS URL)
        agent_jkt: JWK Thumbprint of agent's signing key
        scope: Space-separated scope values
        private_key: Resource's Ed25519 private key for signing
        kid: Key ID for signing key
        exp: Expiration timestamp (Unix time). Defaults to 10 minutes from now.
        mission: Optional ``{"approver": url, "s256": hash}`` when mission-aware.

    Returns:
        Signed JWT string (aa-resource+jwt)
    """
    now = int(time.time())
    if exp is None:
        exp = now + 600  # 10 minutes

    header = {
        "typ": "aa-resource+jwt",
        "alg": "EdDSA",
        "kid": kid
    }

    payload = {
        "iss": iss,
        "aud": aud,
        "dwk": "aauth-resource.json",
        "jti": str(uuid.uuid4()),
        "agent": agent,
        "agent_jkt": agent_jkt,
        "scope": scope,
        "iat": now,
        "exp": exp,
    }
    if mission is not None:
        payload["mission"] = mission

    return jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
        headers=header
    )


def verify_resource_token(
    token: str,
    jwks_fetcher: Callable[[str], Optional[Dict[str, Any]]],
    expected_aud: Optional[str] = None,
    expected_agent: Optional[str] = None,
    expected_agent_jkt: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify a resource token per SPEC §Resource Token Verification.

    Steps:
    1. Decode JWT header. Verify typ is aa-resource+jwt.
    2. Verify dwk is aauth-resource.json. Discover JWKS and verify JWT signature.
    3. Verify exp is in the future and iat is not in the future.
    4. Verify aud matches the recipient's own identifier.
    5. Verify agent matches the requesting agent's identifier.
    6. Verify agent_jkt matches the JWK Thumbprint of the signing key.
    7. If mission is present, verify mission.approver matches the PS.

    Args:
        token: Resource token JWT string
        jwks_fetcher: Function that takes issuer URL and returns JWKS dict
        expected_aud: Expected audience (PS or AS identifier)
        expected_agent: Expected agent identifier
        expected_agent_jkt: Expected JWK Thumbprint of agent's signing key

    Returns:
        Dictionary with verified claims

    Raises:
        TokenError: If token is invalid
    """
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        raise TokenError(f"Failed to parse resource token: {e}", token_type="aa-resource+jwt")

    # Step 1: Verify typ
    typ = header.get("typ")
    if typ != "aa-resource+jwt":
        raise TokenError(
            f"Invalid token type: expected aa-resource+jwt, got {typ}",
            token_type="aa-resource+jwt"
        )

    # Step 2: Verify dwk
    dwk = payload.get("dwk")
    if dwk != "aauth-resource.json":
        raise TokenError(
            f"Invalid dwk: expected aauth-resource.json, got {dwk}",
            token_type="aa-resource+jwt"
        )

    # Step 3: Check exp and iat
    exp_val = payload.get("exp")
    if exp_val:
        now = int(time.time())
        if now >= exp_val:
            raise TokenError("Resource token has expired", token_type="aa-resource+jwt")
    else:
        raise TokenError("Resource token missing 'exp' claim", token_type="aa-resource+jwt")

    iat = payload.get("iat")
    if iat:
        now = int(time.time())
        if iat > now + 60:
            raise TokenError("Resource token iat is in the future", token_type="aa-resource+jwt")

    # Step 4: Verify aud
    if expected_aud:
        aud = payload.get("aud")
        if aud != expected_aud:
            raise TokenError(
                f"Invalid audience: expected {expected_aud}, got {aud}",
                token_type="aa-resource+jwt"
            )

    # Step 5: Verify agent
    if expected_agent:
        agent = payload.get("agent")
        if agent != expected_agent:
            raise TokenError(
                f"Invalid agent: expected {expected_agent}, got {agent}",
                token_type="aa-resource+jwt"
            )

    # Step 6: Verify agent_jkt
    if expected_agent_jkt:
        agent_jkt = payload.get("agent_jkt")
        if agent_jkt != expected_agent_jkt:
            raise TokenError(
                f"agent_jkt mismatch: expected {expected_agent_jkt}, got {agent_jkt}",
                token_type="aa-resource+jwt"
            )

    # Verify required claims
    for claim in ("jti", "iss", "aud", "agent", "agent_jkt", "scope"):
        if claim not in payload:
            raise TokenError(
                f"Resource token missing required '{claim}' claim",
                token_type="aa-resource+jwt"
            )

    # Verify JWT signature via JWKS
    kid_header = header.get("kid")
    if not kid_header:
        raise TokenError("Token header missing 'kid'", token_type="aa-resource+jwt")

    iss = payload.get("iss")
    jwks = jwks_fetcher(iss)
    if not jwks:
        raise TokenError(
            f"Failed to fetch JWKS from {iss}",
            token_type="aa-resource+jwt"
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
            token_type="aa-resource+jwt"
        )

    from ..keys.jwk import jwk_to_public_key
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
            f"Resource token signature verification failed: {e}",
            token_type="aa-resource+jwt"
        )

    return payload
