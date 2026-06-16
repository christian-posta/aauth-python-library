"""HTTP request signing for AAuth."""

from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
import time
import logging
from .signature_key import build_signature_key_header
from .signature import build_signature_header
from .signature_base import build_signature_base, calculate_content_digest, build_signature_params
from .errors import SignatureError


def sign_request(
    method: str,
    target_uri: str,
    headers: Dict[str, str],
    body: Optional[bytes],
    private_key,
    sig_scheme: str = "hwk",
    additional_signature_components: Optional[List[str]] = None,
    **kwargs
) -> Dict[str, str]:
    """Sign an HTTP request using HTTP Message Signatures (RFC 9421).

    Args:
        method: HTTP method (GET, POST, etc.)
        target_uri: Target URI
        headers: Request headers dictionary (will be modified)
        body: Request body bytes (None if no body)
        private_key: Ed25519 private key
        sig_scheme: Signature scheme - "hwk", "jwks_uri", or "jwt"
        additional_signature_components: Additional components to cover (from resource metadata)
        **kwargs: Additional parameters for signature schemes:
            - For "jwks_uri": id (required), kid (required)
            - For "jwt": jwt (required)

    Returns:
        Dictionary with Signature-Input, Signature, and Signature-Key headers

    Raises:
        SignatureError: If signing fails
    """
    try:
        parsed_uri = urlparse(target_uri)
        authority = parsed_uri.netloc
        path = parsed_uri.path or "/"
        query_string = parsed_uri.query if parsed_uri.query else None

        label = "sig"

        # Build Signature-Key header first (needed for signature-key component)
        signature_key_header = build_signature_key_header(
            sig_scheme=sig_scheme,
            private_key=private_key,
            label=label,
            **kwargs
        )

        headers["Signature-Key"] = signature_key_header

        # Determine body components to include (opt-in only)
        body_components = []
        if body and additional_signature_components:
            for comp in additional_signature_components:
                if comp in ("content-type", "content-digest"):
                    body_components.append(comp)

            if "content-digest" in body_components and "Content-Digest" not in headers:
                content_digest = calculate_content_digest(body)
                headers["Content-Digest"] = content_digest

            if "content-type" in body_components and "Content-Type" not in headers:
                headers["Content-Type"] = "application/octet-stream"

        # Include aauth-mission when the request carries AAuth-Mission (spec §Authorization Endpoint Request).
        include_aauth_mission = any(k.lower() == "aauth-mission" for k in headers)

        # Determine covered components
        from .signature_base import _determine_covered_components
        covered_components = _determine_covered_components(
            query_string,
            body,
            additional_components=body_components,
            include_aauth_mission=include_aauth_mission,
        )

        # Build signature params (only created is required per spec Section 15.4)
        created = int(time.time())
        signature_params = build_signature_params(
            covered_components=covered_components,
            created=created
        )

        signature_input_header = f"{label}={signature_params}"

        # Build signature base
        signature_base = build_signature_base(
            method=method,
            authority=authority,
            path=path,
            query=query_string,
            headers=headers,
            body=body,
            signature_key_header=signature_key_header,
            covered_components=covered_components,
            signature_params=signature_params
        )

        logger = logging.getLogger("aauth_signing")
        logger.debug(f"Signature base length: {len(signature_base)} bytes")
        for i, line in enumerate(signature_base.split('\n')):
            logger.debug(f"  Line {i}: {repr(line)}")

        # Sign the signature base
        signature_bytes = _sign_with_key(private_key, signature_base.encode("utf-8"))

        # Build Signature header
        signature_header = build_signature_header(signature_bytes, label=label)

        return {
            "Signature-Input": signature_input_header,
            "Signature": signature_header,
            "Signature-Key": signature_key_header
        }
    except Exception as e:
        raise SignatureError(f"Failed to sign request: {e}", details={"scheme": sig_scheme}) from e


def _sign_with_key(private_key, message: bytes) -> bytes:
    """Sign *message* with *private_key*, dispatching on key type."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, ECDSA, SECP384R1
    from cryptography.hazmat.primitives import hashes

    if isinstance(private_key, Ed25519PrivateKey):
        return private_key.sign(message)

    if isinstance(private_key, EllipticCurvePrivateKey):
        curve = private_key.curve
        hash_alg = hashes.SHA384() if isinstance(curve, SECP384R1) else hashes.SHA256()
        return private_key.sign(message, ECDSA(hash_alg))

    raise ValueError(f"Unsupported private key type: {type(private_key)}")
