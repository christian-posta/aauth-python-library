"""Cryptographic utilities for AAuth implementation."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
import secrets
from typing import Dict, Any, Tuple


def generate_ed25519_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a new Ed25519 key pair.
    
    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def private_key_to_jwk(private_key: Ed25519PrivateKey, kid: str = None) -> Dict[str, Any]:
    """Convert Ed25519 private key to JWK format.
    
    Args:
        private_key: Ed25519 private key
        kid: Optional key ID
        
    Returns:
        JWK dictionary
    """
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    # Ed25519 public key is 32 bytes, encode as base64url
    import base64
    x = base64.urlsafe_b64encode(public_bytes).decode('utf-8').rstrip('=')
    
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x
    }
    
    if kid:
        jwk["kid"] = kid
    
    return jwk


def public_key_to_jwk(public_key: Ed25519PublicKey, kid: str = None) -> Dict[str, Any]:
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
    import base64
    x = base64.urlsafe_b64encode(public_bytes).decode('utf-8').rstrip('=')
    
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x
    }
    
    if kid:
        jwk["kid"] = kid
    
    return jwk


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


def jwk_to_public_key(jwk: Dict[str, Any]) -> Ed25519PublicKey:
    """Convert JWK to Ed25519PublicKey object.
    
    Args:
        jwk: JWK dictionary with kty="OKP", crv="Ed25519"
        
    Returns:
        Ed25519PublicKey object
    """
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("JWK must be Ed25519 (OKP, Ed25519)")
    
    import base64
    x = jwk["x"]
    # Add padding if needed
    x += '=' * (4 - len(x) % 4)
    public_bytes = base64.urlsafe_b64decode(x)
    
    return Ed25519PublicKey.from_public_bytes(public_bytes)

