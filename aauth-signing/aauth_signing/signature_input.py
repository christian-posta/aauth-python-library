"""Signature-Input header parsing and building (RFC 9421)."""

import re
import time
from typing import List, Dict, Any, Optional


def build_signature_input_header(
    covered_components: List[str], label: str = "sig", created: Optional[int] = None
) -> str:
    """Build Signature-Input header per RFC 9421 Section 4.1.

    Args:
        covered_components: List of component names to cover
        label: Signature label (default: "sig")
        created: Creation timestamp (Unix time). If None, uses current time.

    Returns:
        Signature-Input header value
    """
    if created is None:
        created = int(time.time())

    component_list = " ".join([f'"{comp}"' for comp in covered_components])

    return f"{label}=({component_list});created={created}"


def parse_signature_input(header_value: str) -> tuple[List[str], Dict[str, Any]]:
    """Parse Signature-Input header to extract covered components and parameters.

    Args:
        header_value: Signature-Input header value

    Returns:
        Tuple of (components list, parameters dict)

    Raises:
        ValueError: If header format is invalid
    """
    import http_sfv

    fields = http_sfv.Dictionary()
    fields.parse(header_value.encode("ascii"))
    if len(fields) != 1:
        raise ValueError("Exactly one signature label is supported")
    inner = next(iter(fields.values()))
    if not isinstance(inner, http_sfv.InnerList):
        raise ValueError("Covered components must be an inner list")
    components = [item.value for item in inner]
    if any(not isinstance(c, str) or isinstance(c, http_sfv.Token) for c in components):
        raise ValueError("Covered components must be strings")
    if len(set(components)) != len(components):
        raise ValueError("Duplicate covered components")
    return components, dict(inner.params)
