"""HTTP request signing for AAuth."""

from typing import Dict, Any, Optional
from urllib.parse import urlparse
from ..headers.signature_key import build_signature_key_header
from ..headers.signature_input import build_signature_input_header
from ..headers.signature import build_signature_header
from ..signing.signature_base import build_signature_base, calculate_content_digest
from ..errors import SignatureError


def sign_request(
    method: str,
    target_uri: str,
    headers: Dict[str, str],
    body: Optional[bytes],
    private_key,
    sig_scheme: str = "hwk",
    **kwargs
) -> Dict[str, str]:
    """Sign an HTTP request using HTTP Message Signatures (RFC 9421).
    
    Args:
        method: HTTP method (GET, POST, etc.)
        target_uri: Target URI
        headers: Request headers dictionary (will be modified)
        body: Request body bytes (None if no body)
        private_key: Ed25519 private key
        sig_scheme: Signature scheme - "hwk", "jwks", or "jwt"
        **kwargs: Additional parameters for signature schemes:
            - For "jwks": id (required), kid (required), well-known (optional)
            - For "jwt": jwt (required)
    
    Returns:
        Dictionary with Signature-Input, Signature, and Signature-Key headers
        
    Raises:
        SignatureError: If signing fails
    """
    try:
        # Parse URI for derived components
        parsed_uri = urlparse(target_uri)
        authority = parsed_uri.netloc
        path = parsed_uri.path or "/"
        query_string = parsed_uri.query if parsed_uri.query else None
        
        # Build Signature-Key header first (needed for signature-key component)
        # Use label "sig1" to match Signature-Input and Signature headers
        signature_key_header = build_signature_key_header(
            sig_scheme=sig_scheme,
            private_key=private_key,
            label="sig1",
            **kwargs
        )
        
        # Add Signature-Key to headers (needed for signature-key component)
        headers["Signature-Key"] = signature_key_header
        
        # Add Content-Digest if body exists and not already present (RFC 9530)
        if body:
            # Only calculate Content-Digest if not already provided
            if "Content-Digest" not in headers:
                content_digest = calculate_content_digest(body)
                headers["Content-Digest"] = content_digest
            
            # Add content-type if not present
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/octet-stream"
        
        # Determine covered components
        from ..signing.signature_base import _determine_covered_components
        covered_components = _determine_covered_components(query_string, body)
        
        # Build Signature-Input header FIRST (needed for @signature-params in signature base)
        signature_input_header = build_signature_input_header(
            covered_components=covered_components,
            label="sig1"
        )
        
        # Extract signature params (the part after "sig1=")
        # Signature-Input format: sig1=("@method" "@authority" ...);created=...
        signature_params = signature_input_header[5:] if signature_input_header.startswith("sig1=") else signature_input_header
        
        # Build signature base (now includes @signature-params per RFC 9421)
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
        
        # DEBUG: Print the signature base for debugging
        import logging
        logger = logging.getLogger("aauth.signing")
        logger.info(f"🔐 AAUTH LIBRARY SIGNATURE BASE:")
        logger.info(f"🔐 Signature base length: {len(signature_base)} bytes")
        logger.info(f"🔐 Signature base hex (first 200): {signature_base.encode('utf-8').hex()[:200]}...")
        for i, line in enumerate(signature_base.split('\n')):
            logger.info(f"🔐   Line {i}: {repr(line)}")
        
        # Sign the signature base
        signature_bytes = private_key.sign(signature_base.encode('utf-8'))
        
        # Build Signature header
        signature_header = build_signature_header(signature_bytes, label="sig1")
        
        return {
            "Signature-Input": signature_input_header,
            "Signature": signature_header,
            "Signature-Key": signature_key_header
        }
    except Exception as e:
        raise SignatureError(f"Failed to sign request: {e}", details={"scheme": sig_scheme}) from e

