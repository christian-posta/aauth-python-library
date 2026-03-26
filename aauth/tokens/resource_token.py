"""Resource token creation and validation for AAuth."""

import time
import uuid
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
    exp: Optional[int] = None,
    txn: Optional[str] = None,
) -> str:
    """Create a resource token (resource+jwt) per AAuth spec Section 8.1.

    Args:
        iss: Resource identifier (HTTPS URL)
        aud: Auth server identifier (HTTPS URL)
        agent: Agent identifier (HTTPS URL)
        agent_jkt: JWK Thumbprint of agent's signing key
        scope: Space-separated scope values
        private_key: Resource's Ed25519 private key for signing
        kid: Key ID for signing key
        exp: Expiration timestamp (Unix time). Defaults to 10 minutes from now.
        txn: Optional transaction identifier for correlation

    Returns:
        Signed JWT string (resource+jwt)
    """
    now = int(time.time())
    if exp is None:
        exp = now + 600  # 10 minutes

    header = {
        "typ": "resource+jwt",
        "alg": "EdDSA",
        "kid": kid
    }

    payload = {
        "iss": iss,
        "aud": aud,
        "jti": str(uuid.uuid4()),
        "agent": agent,
        "agent_jkt": agent_jkt,
        "scope": scope,
        "iat": now,
        "exp": exp,
    }

    if txn is not None:
        payload["txn"] = txn

    return jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
        headers=header
    )
