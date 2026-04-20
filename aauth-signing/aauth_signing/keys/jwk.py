"""JWK (JSON Web Key) operations for aauth-signing."""

import base64
import hashlib
import json
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


def private_key_to_jwk(private_key: Ed25519PrivateKey, kid: Optional[str] = None) -> Dict[str, Any]:
    """Convert Ed25519 private key to JWK format.

    Args:
        private_key: Ed25519 private key
        kid: Optional key ID

    Returns:
        JWK dictionary
    """
    public_key = private_key.public_key()
    return public_key_to_jwk(public_key, kid)


def public_key_to_jwk(public_key: Ed25519PublicKey, kid: Optional[str] = None) -> Dict[str, Any]:
    """Convert Ed25519 public key to JWK format.

    Args:
        public_key: Ed25519 public key
        kid: Optional key ID

    Returns:
        JWK dictionary
    """
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Ed25519 public key is 32 bytes, encode as base64url
    x = base64.urlsafe_b64encode(public_bytes).decode('utf-8').rstrip('=')

    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x
    }

    if kid:
        jwk["kid"] = kid

    return jwk


def jwk_to_public_key(jwk: Dict[str, Any]) -> Ed25519PublicKey:
    """Convert JWK to Ed25519PublicKey object.

    Args:
        jwk: JWK dictionary with kty="OKP", crv="Ed25519"

    Returns:
        Ed25519PublicKey object

    Raises:
        ValueError: If JWK is not Ed25519 format
    """
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("JWK must be Ed25519 (OKP, Ed25519)")

    x = jwk["x"]
    # Add padding if needed
    x += '=' * (4 - len(x) % 4)
    public_bytes = base64.urlsafe_b64decode(x)

    return Ed25519PublicKey.from_public_bytes(public_bytes)


def calculate_jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    """Calculate JWK Thumbprint per RFC 7638.

    Args:
        jwk: JWK dictionary (must be canonical - only include required fields)

    Returns:
        Base64url-encoded SHA-256 hash of canonical JWK JSON
    """
    # Create canonical JWK (only include required fields, sorted)
    # For Ed25519: kty, crv, x (kid excluded from thumbprint)
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

    # SHA-256 hash
    hash_bytes = hashlib.sha256(canonical_json.encode('utf-8')).digest()

    # Base64url encode (no padding)
    thumbprint = base64.urlsafe_b64encode(hash_bytes).decode('utf-8').rstrip('=')

    return thumbprint


def generate_jwks(keys: list[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate a JWKS document from a list of JWKs.

    Args:
        keys: List of JWK dictionaries

    Returns:
        JWKS document dictionary
    """
    return {
        "keys": keys
    }
