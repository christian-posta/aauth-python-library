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
    covered_components: Optional[List[str]] = None,
    signature_params: Optional[str] = None
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
        signature_params: Signature-Input header value (required for @signature-params line)

    Returns:
        Signature base string
    """
    if covered_components is None:
        covered_components = _determine_covered_components(query, body, additional_components=None)

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
                components.append(("@query", f"?{query}"))
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
        elif component_name == "aauth-mission":
            mission_val = _get_header(headers, "aauth-mission")
            if not mission_val:
                raise ValueError("aauth-mission in Signature-Input but AAuth-Mission header missing")
            components.append(("aauth-mission", mission_val))
        else:
            raise ValueError(f"Unknown component: {component_name}")

    # Build signature base (RFC 9421 Section 2.5)
    signature_base_parts = []
    for component_name, component_value in components:
        if component_name.startswith("@"):
            signature_base_parts.append(f'"{component_name}": {component_value}')
        else:
            header_name = component_name.lower()
            signature_base_parts.append(f'"{header_name}": {component_value}')

    # Add @signature-params as the FINAL line (RFC 9421 Section 2.5)
    if not signature_params:
        raise ValueError("signature_params is required for valid signature base")
    signature_base_parts.append(f'"@signature-params": {signature_params}')

    return "\n".join(signature_base_parts)


def _determine_covered_components(
    query: Optional[str],
    body: Optional[bytes],
    additional_components: Optional[List[str]] = None,
    *,
    include_aauth_mission: bool = False,
) -> List[str]:
    """Determine covered components based on request structure.

    Per AAuth spec Section 15.3, MUST cover:
    - @method, @authority, @path, signature-key

    With ``AAuth-Mission`` on authorization requests, also cover ``aauth-mission`` after
    ``signature-key`` (spec §Authorization Endpoint Request).

    Resources MAY require additional components via additional_signature_components.

    Args:
        query: Query string (None if no query)
        body: Request body (None if no body)
        additional_components: Optional list of additional components to include
        include_aauth_mission: If True, append ``aauth-mission`` after ``signature-key``.

    Returns:
        List of component names
    """
    components = ["@method", "@authority", "@path"]

    if query:
        components.append("@query")

    if additional_components:
        components.extend(additional_components)

    # signature-key MUST always be included
    components.append("signature-key")

    if include_aauth_mission:
        components.append("aauth-mission")

    return components


def _get_header(headers: Dict[str, str], name: str) -> Optional[str]:
    """Get header value (case-insensitive)."""
    name_lower = name.lower()
    for key, value in headers.items():
        if key.lower() == name_lower:
            return value
    return None


def build_signature_params(
    covered_components: List[str],
    created: int
) -> str:
    """Build the Signature-Input value (the part after the label).

    Per AAuth spec Section 15.4, only `created` is REQUIRED.

    Args:
        covered_components: List of component names
        created: Creation timestamp (Unix time)

    Returns:
        Signature params string: ("@method" "@authority" ...);created=1234567890
    """
    components_str = " ".join(f'"{c}"' for c in covered_components)
    return f"({components_str});created={created}"


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
