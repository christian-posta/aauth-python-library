"""HTTP Message Signing layer (RFC 9421 + draft-hardt-httpbis-signature-key).

This package provides AAuth-oriented HTTP message signing:

  - HTTP Message Signatures per RFC 9421
  - Signature-Key header per draft-hardt-httpbis-signature-key
    (schemes: hwk, jwks_uri, jwt, jkt-jwt)

Typical usage::

    from aauth_signing import sign_request, verify_signature
    from aauth_signing import build_signature_key_header, parse_signature_key
"""

from .signer import sign_request
from .verifier import verify_signature
from .algorithms import (
    ED25519,
    RSA_PSS_SHA512,
    RSA_PSS_SHA256,
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    SUPPORTED_ALGORITHMS,
    is_supported,
)
from .signature_base import (
    build_signature_base,
    build_signature_params,
    calculate_content_digest,
)
from .signature_key import build_signature_key_header, parse_signature_key
from .signature_input import build_signature_input_header, parse_signature_input
from .signature import build_signature_header, parse_signature

__all__ = [
    # Core sign/verify
    "sign_request",
    "verify_signature",
    # Algorithms
    "ED25519",
    "RSA_PSS_SHA512",
    "RSA_PSS_SHA256",
    "ECDSA_P256_SHA256",
    "ECDSA_P384_SHA384",
    "SUPPORTED_ALGORITHMS",
    "is_supported",
    # Signature base (RFC 9421)
    "build_signature_base",
    "build_signature_params",
    "calculate_content_digest",
    # Signature-Key header (draft-hardt-httpbis-signature-key)
    "build_signature_key_header",
    "parse_signature_key",
    # Signature-Input header (RFC 9421)
    "build_signature_input_header",
    "parse_signature_input",
    # Signature header (RFC 9421)
    "build_signature_header",
    "parse_signature",
]
