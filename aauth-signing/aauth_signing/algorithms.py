"""Signature algorithm support for AAuth."""

# Supported algorithms per AAuth spec Section 10.2
# MUST support ed25519, MAY support others

ED25519 = "ed25519"
RSA_PSS_SHA512 = "rsa-pss-sha512"
RSA_PSS_SHA256 = "rsa-pss-sha256"
ECDSA_P256_SHA256 = "ecdsa-p256-sha256"
ECDSA_P384_SHA384 = "ecdsa-p384-sha384"

# Required algorithm
REQUIRED_ALGORITHM = ED25519

# All supported algorithms
SUPPORTED_ALGORITHMS = [
    ED25519,
    RSA_PSS_SHA512,
    RSA_PSS_SHA256,
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
]


def is_supported(algorithm: str) -> bool:
    """Check if algorithm is supported.

    Args:
        algorithm: Algorithm name

    Returns:
        True if supported, False otherwise
    """
    return algorithm.lower() in [alg.lower() for alg in SUPPORTED_ALGORITHMS]
