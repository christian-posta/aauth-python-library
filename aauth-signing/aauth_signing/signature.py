"""Signature header parsing and building (RFC 9421)."""

import re
import base64
from typing import Optional


def build_signature_header(signature_bytes: bytes, label: str = "sig") -> str:
    """Build Signature header per RFC 9421 Section 4.2.

    Args:
        signature_bytes: Raw signature bytes
        label: Signature label (default: "sig")

    Returns:
        Signature header value
    """
    signature_b64 = base64.urlsafe_b64encode(signature_bytes).decode('utf-8').rstrip('=')
    return f'{label}=:{signature_b64}:'


def parse_signature(header_value: str, label: Optional[str] = None) -> bytes:
    """Parse Signature header to extract signature bytes.

    Args:
        header_value: Signature header value
        label: Optional expected label (for validation)

    Returns:
        Signature bytes

    Raises:
        ValueError: If header format is invalid or label doesn't match
    """
    match = re.search(r'(\w+)=:([A-Za-z0-9_-]+):', header_value)
    if not match:
        raise ValueError(f"Invalid Signature format: {header_value}")

    found_label = match.group(1)
    signature_b64 = match.group(2)

    if label and found_label != label:
        raise ValueError(f"Label mismatch: expected {label}, got {found_label}")

    # Add padding if needed
    signature_b64 += '=' * (4 - len(signature_b64) % 4)

    try:
        signature_bytes = base64.urlsafe_b64decode(signature_b64)
        return signature_bytes
    except Exception as e:
        raise ValueError(f"Failed to decode signature: {e}")
