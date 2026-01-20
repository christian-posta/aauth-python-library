"""Signature base construction for HTTP Message Signing (RFC 9421)."""

from typing import List, Tuple, Dict, Optional
from urllib.parse import urlparse
import base64
import hashlib


def build_signature_base(
    method: str,
    authority: str,
    path: str,
    query: Optional[str],
    headers: Dict[str, str],
    body: Optional[bytes],
    signature_key_header: str,
    covered_components: Optional[List[str]] = None
) -> str:
    """Build signature base string per RFC 9421 Section 2.5.
    
    Args:
        method: HTTP method
        authority: Canonical authority (host:port)
        path: Request path
        query: Query string (without leading "?")
        headers: Request headers
        body: Request body bytes (None if no body)
        signature_key_header: Signature-Key header value
        covered_components: Optional list of components to cover (auto-detected if None)
        
    Returns:
        Signature base string
    """
    # Auto-detect covered components if not provided
    if covered_components is None:
        covered_components = _determine_covered_components(query, body)
    
    # Build component list
    components: List[Tuple[str, str]] = []
    
    for component_name in covered_components:
        if component_name == "@method":
            components.append(("@method", method))
        elif component_name == "@authority":
            components.append(("@authority", authority))
        elif component_name == "@path":
            components.append(("@path", path))
        elif component_name == "@query":
            if query:
                components.append(("@query", query))
            else:
                raise ValueError("@query component specified but no query string present")
        elif component_name == "content-type":
            if body:
                content_type = _get_header(headers, "content-type")
                if content_type:
                    components.append(("content-type", content_type))
                else:
                    raise ValueError("content-type component required but header missing")
            else:
                raise ValueError("content-type component specified but no body present")
        elif component_name == "content-digest":
            if body:
                content_digest = _get_header(headers, "content-digest")
                if content_digest:
                    components.append(("content-digest", content_digest))
                else:
                    raise ValueError("content-digest component required but header missing")
            else:
                raise ValueError("content-digest component specified but no body present")
        elif component_name == "signature-key":
            components.append(("signature-key", signature_key_header))
        else:
            raise ValueError(f"Unknown component: {component_name}")
    
    # Build signature base (RFC 9421 Section 2.3)
    signature_base_parts = []
    for component_name, component_value in components:
        if component_name.startswith("@"):
            signature_base_parts.append(f'"{component_name}": {component_value}')
        else:
            header_name = component_name.lower()
            signature_base_parts.append(f'"{header_name}": {component_value}')
    
    signature_base = "\n".join(signature_base_parts) + "\n"
    
    return signature_base


def _determine_covered_components(query: Optional[str], body: Optional[bytes]) -> List[str]:
    """Determine covered components based on request structure.
    
    Per AAuth spec Section 10.3:
    - Always: @method, @authority, @path, signature-key
    - If query present: @query
    - If body present: content-type, content-digest
    
    Args:
        query: Query string (None if no query)
        body: Request body (None if no body)
        
    Returns:
        List of component names
    """
    components = ["@method", "@authority", "@path"]
    
    if query:
        components.append("@query")
    
    if body:
        components.append("content-type")
        components.append("content-digest")
    
    # signature-key MUST always be included
    components.append("signature-key")
    
    return components


def _get_header(headers: Dict[str, str], name: str) -> Optional[str]:
    """Get header value (case-insensitive).
    
    Args:
        headers: Headers dictionary
        name: Header name (case-insensitive)
        
    Returns:
        Header value or None
    """
    name_lower = name.lower()
    for key, value in headers.items():
        if key.lower() == name_lower:
            return value
    return None


def calculate_content_digest(body: bytes) -> str:
    """Calculate Content-Digest header value per RFC 9530.
    
    Args:
        body: Request body bytes
        
    Returns:
        Content-Digest header value (e.g., "sha-256=:...:")
    """
    digest = hashlib.sha256(body).digest()
    digest_b64 = base64.b64encode(digest).decode('ascii')
    return f"sha-256=:{digest_b64}:"

