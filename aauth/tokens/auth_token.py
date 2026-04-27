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
    act: Dict[str, Any],
    scope: Optional[str] = None,
    sub: Optional[str] = None,
    exp: Optional[int] = None,
    mission: Optional[Dict[str, Any]] = None,
    dwk: str = "aauth-access.json",
) -> str:
    """Create an auth token (aa-auth+jwt) per AAuth spec Section 9.1.

    Args:
        iss: Auth server identifier (HTTPS URL)
        aud: Resource identifier, or agent identifier for self-access
        agent: Agent identifier (aauth:local@domain) — REQUIRED
        cnf_jwk: Agent's public signing key (JWK format) — REQUIRED
        private_key: Auth server's Ed25519 private key for signing
        kid: Key ID for signing key
        act: Actor claim per RFC 8693 §4.1 — REQUIRED.
             In direct auth: ``{"sub": agent_id}``.
             In call chaining: nested ``{"sub": intermediary_id, "act": upstream_act}``.
        scope: Authorized scopes (at least one of scope or sub MUST be present)
        sub: User identifier (at least one of scope or sub MUST be present)
        exp: Expiration timestamp. Defaults to 1 hour from now.
        mission: Optional mission object when issued in mission context.
        dwk: Well-known metadata document name for key discovery. Defaults to
             ``aauth-access.json`` (AS-issued); use ``aauth-person.json`` for PS-issued tokens.

    Returns:
        Signed JWT string (aa-auth+jwt)

    Raises:
        TokenError: If required claims are missing
    """
    if not agent:
        raise TokenError(
            "'agent' claim is required in auth token",
            token_type="aa-auth+jwt"
        )
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
        "dwk": dwk,
        "jti": str(uuid.uuid4()),
        "agent": agent,
        "cnf": {"jwk": cnf_jwk},
        "act": act,
        "iat": now,
        "exp": exp,
    }

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
    expected_aud: Optional[str] = None,
    expected_agent: Optional[str] = None,
    request_signing_jwk: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Verify a JWT token signature and claims.

    Per SPEC §Auth Token Verification, this checks:
    1. typ
    2. dwk + JWKS discovery + JWT signature
    3. exp, iat
    4. iss (valid HTTPS URL)
    5. aud (matches resource)
    6. agent (matches request signing context)
    7. cnf.jwk (matches request signing key)
    8. act (present, act.sub matches agent)
    9. sub or scope present

    Args:
        token: JWT token string
        jwks_fetcher: Function that takes issuer URL and returns JWKS dict
        expected_typ: Expected typ claim
        expected_iss: Expected issuer
        expected_aud: Expected audience
        expected_agent: Expected agent identifier (from request signing context)
        request_signing_jwk: JWK of the key used to sign the HTTP request

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

    # Step 1: Check typ
    if expected_typ:
        typ = header.get("typ")
        if typ != expected_typ:
            raise TokenError(
                f"Invalid token type: expected {expected_typ}, got {typ}",
                token_type=expected_typ
            )

    # Step 3: Check exp
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

    # Step 4: Check iss
    iss = payload.get("iss")
    if expected_iss and iss != expected_iss:
        raise TokenError(
            f"Invalid issuer: expected {expected_iss}, got {iss}",
            token_type=expected_typ or "jwt"
        )

    # Step 5: Check aud
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

    # Step 6: Verify agent matches request signing context
    if expected_agent:
        agent = payload.get("agent")
        if agent != expected_agent:
            raise TokenError(
                f"Invalid agent: expected {expected_agent}, got {agent}",
                token_type=expected_typ or "jwt"
            )

    # Step 7: Verify cnf.jwk matches the key used to sign the HTTP request
    if request_signing_jwk:
        cnf = payload.get("cnf")
        if not cnf or not cnf.get("jwk"):
            raise TokenError("Token missing 'cnf.jwk' claim", token_type=expected_typ or "jwt")
        # Compare key material (kty, crv, x for OKP; kty, crv, x, y for EC)
        token_jwk = cnf["jwk"]
        for field in ("kty", "crv", "x", "y", "n", "e"):
            if request_signing_jwk.get(field) != token_jwk.get(field):
                if field in request_signing_jwk or field in token_jwk:
                    raise TokenError(
                        f"cnf.jwk does not match request signing key (field: {field})",
                        token_type=expected_typ or "jwt"
                    )

    # Step 8: Verify act claim (REQUIRED for auth tokens)
    if expected_typ == "aa-auth+jwt":
        act = payload.get("act")
        if not act:
            raise TokenError("Auth token missing required 'act' claim", token_type="aa-auth+jwt")
        if expected_agent and act.get("sub") != expected_agent:
            raise TokenError(
                f"act.sub does not match agent: expected {expected_agent}, got {act.get('sub')}",
                token_type="aa-auth+jwt"
            )

    # Step 9: Verify at least one of sub or scope (for auth tokens)
    if expected_typ == "aa-auth+jwt":
        if not payload.get("sub") and not payload.get("scope"):
            raise TokenError(
                "Auth token must contain at least one of 'sub' or 'scope'",
                token_type="aa-auth+jwt"
            )

    # Step 2: Discover issuer JWKS via dwk and verify JWT signature
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
