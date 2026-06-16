"""Key pair generation for aauth-signing."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ec import (
    generate_private_key, SECP256R1, EllipticCurvePrivateKey, EllipticCurvePublicKey
)
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Union


def generate_ed25519_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a new Ed25519 key pair.

    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def generate_ec_keypair(curve=None) -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate a new EC P-256 key pair.

    Args:
        curve: Elliptic curve instance (default: SECP256R1 / P-256)

    Returns:
        Tuple of (private_key, public_key)
    """
    if curve is None:
        curve = SECP256R1()
    private_key = generate_private_key(curve, default_backend())
    return private_key, private_key.public_key()
