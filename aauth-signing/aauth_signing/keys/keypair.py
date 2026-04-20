"""Key pair generation for aauth-signing."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from typing import Tuple


def generate_ed25519_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a new Ed25519 key pair.

    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key
