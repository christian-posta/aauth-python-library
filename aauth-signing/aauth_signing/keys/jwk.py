"""JWK (JSON Web Key) operations for aauth-signing."""

import base64
import hashlib
import json
from typing import Dict, Any, Optional, Union
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey, EllipticCurvePrivateKey,
    EllipticCurvePublicNumbers, SECP256R1, SECP384R1,
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

PublicKey = Union[Ed25519PublicKey, EllipticCurvePublicKey]

# Map JWK crv names to cryptography curve objects
_CURVE_MAP = {
    "P-256": SECP256R1,
    "P-384": SECP384R1,
}

# Map curve class names to JWK crv strings
_CURVE_NAME_MAP = {
    "SECP256R1": "P-256",
    "SECP384R1": "P-384",
}


def _pad_b64(s: str) -> str:
    return s + "=" * (4 - len(s) % 4)


def private_key_to_jwk(private_key, kid: Optional[str] = None) -> Dict[str, Any]:
    """Convert a private key to JWK format (Ed25519 or EC).

    Args:
        private_key: Ed25519PrivateKey or EllipticCurvePrivateKey
        kid: Optional key ID

    Returns:
        JWK dictionary
    """
    return public_key_to_jwk(private_key.public_key(), kid)


def public_key_to_jwk(public_key: PublicKey, kid: Optional[str] = None) -> Dict[str, Any]:
    """Convert a public key to JWK format (Ed25519 or EC P-256/P-384).

    Args:
        public_key: Ed25519PublicKey or EllipticCurvePublicKey
        kid: Optional key ID

    Returns:
        JWK dictionary
    """
    if isinstance(public_key, Ed25519PublicKey):
        raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        x = base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
        jwk: Dict[str, Any] = {"kty": "OKP", "crv": "Ed25519", "x": x}
    elif isinstance(public_key, EllipticCurvePublicKey):
        nums = public_key.public_numbers()
        curve_name = type(public_key.curve).__name__
        crv = _CURVE_NAME_MAP.get(curve_name)
        if crv is None:
            raise ValueError(f"Unsupported EC curve: {curve_name}")
        key_size = (public_key.key_size + 7) // 8
        x = base64.urlsafe_b64encode(nums.x.to_bytes(key_size, "big")).decode("utf-8").rstrip("=")
        y = base64.urlsafe_b64encode(nums.y.to_bytes(key_size, "big")).decode("utf-8").rstrip("=")
        jwk = {"kty": "EC", "crv": crv, "x": x, "y": y}
    else:
        raise ValueError(f"Unsupported key type: {type(public_key)}")

    if kid:
        jwk["kid"] = kid
    return jwk


def jwk_to_public_key(jwk: Dict[str, Any]) -> PublicKey:
    """Convert a JWK to a public key object (Ed25519 or EC P-256/P-384).

    Args:
        jwk: JWK dictionary

    Returns:
        Ed25519PublicKey or EllipticCurvePublicKey

    Raises:
        ValueError: If the JWK uses an unsupported key type or curve
    """
    kty = jwk.get("kty")

    if kty == "OKP":
        if jwk.get("crv") != "Ed25519":
            raise ValueError(f"Unsupported OKP curve: {jwk.get('crv')}")
        x_bytes = base64.urlsafe_b64decode(_pad_b64(jwk["x"]))
        return Ed25519PublicKey.from_public_bytes(x_bytes)

    if kty == "EC":
        crv = jwk.get("crv")
        curve_cls = _CURVE_MAP.get(crv)
        if curve_cls is None:
            raise ValueError(f"Unsupported EC curve: {crv}")
        x = int.from_bytes(base64.urlsafe_b64decode(_pad_b64(jwk["x"])), "big")
        y = int.from_bytes(base64.urlsafe_b64decode(_pad_b64(jwk["y"])), "big")
        nums = EllipticCurvePublicNumbers(x=x, y=y, curve=curve_cls())
        return nums.public_key(default_backend())

    raise ValueError(f"Unsupported JWK kty: {kty!r}")


def calculate_jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    """Calculate JWK Thumbprint per RFC 7638.

    Args:
        jwk: JWK dictionary

    Returns:
        Base64url-encoded SHA-256 hash of canonical JWK JSON (no padding)
    """
    kty = jwk.get("kty", "")

    # RFC 7638 §3.2: only the required members, lexicographically sorted
    if kty == "OKP":
        canonical_jwk = {"crv": jwk["crv"], "kty": kty, "x": jwk["x"]}
    elif kty == "EC":
        canonical_jwk = {"crv": jwk["crv"], "kty": kty, "x": jwk["x"], "y": jwk["y"]}
    elif kty == "RSA":
        canonical_jwk = {"e": jwk["e"], "kty": kty, "n": jwk["n"]}
    else:
        raise ValueError(f"Unsupported kty for thumbprint: {kty!r}")

    canonical_json = json.dumps(canonical_jwk, separators=(",", ":"), sort_keys=True)
    hash_bytes = hashlib.sha256(canonical_json.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(hash_bytes).decode("utf-8").rstrip("=")


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
