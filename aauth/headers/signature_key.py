"""Signature-Key header parsing and building for AAuth."""

import re
from typing import Dict, Any
from ..keys.jwk import public_key_to_jwk


def build_signature_key_header(
    sig_scheme: str,
    private_key,
    label: str = "sig",
    **kwargs
) -> str:
    """Build Signature-Key header as RFC 8941 Structured Fields Dictionary.

    Format: {label}=(scheme=hwk kty="OKP" crv="Ed25519" x="...")
    The label must match the label used in Signature-Input and Signature headers.

    Args:
        sig_scheme: Signature scheme ("hwk", "jwks_uri", "jwt")
        private_key: Private key (for hwk scheme)
        label: Signature label (default: "sig")
        **kwargs: Additional parameters:
            - For "hwk": None (key extracted from private_key)
            - For "jwks_uri": id (required), kid (required)
            - For "jwt": jwt (required)

    Returns:
        Signature-Key header value

    Raises:
        ValueError: If required parameters are missing
    """
    if sig_scheme == "hwk":
        public_key = private_key.public_key()
        jwk = public_key_to_jwk(public_key)
        return f'{label}=(scheme=hwk kty="{jwk["kty"]}" crv="{jwk["crv"]}" x="{jwk["x"]}")'
    elif sig_scheme == "jwks_uri":
        agent_id = kwargs.get("id")
        kid = kwargs.get("kid", "key-1")
        if not agent_id:
            raise ValueError("sig=jwks_uri requires 'id' parameter")
        header_parts = [f'scheme=jwks_uri', f'id="{agent_id}"', f'kid="{kid}"']
        return f'{label}=({" ".join(header_parts)})'
    elif sig_scheme == "jwt":
        jwt_token = kwargs.get("jwt")
        if not jwt_token:
            raise ValueError("sig=jwt requires 'jwt' parameter")
        return f'{label}=(scheme=jwt jwt="{jwt_token}")'
    else:
        raise ValueError(f"Unknown signature scheme: {sig_scheme}")


def parse_signature_key(header_value: str) -> Dict[str, Any]:
    """Parse Signature-Key header value (RFC 8941 Structured Fields Dictionary).

    Supports any label (sig, sig1, etc.) - the label is extracted but not validated here.

    Args:
        header_value: Signature-Key header value

    Returns:
        Dictionary with keys: scheme, params, label

    Raises:
        ValueError: If header format is invalid
    """
    # Match any label: sig=, sig1=, etc.
    match = re.match(r'([\w]+)=\((.*)\)', header_value)
    if not match:
        raise ValueError(f"Invalid Signature-Key format: {header_value}")

    label = match.group(1)
    inner_content = match.group(2)
    params = {}
    scheme = None

    # Allow hyphens and underscores in parameter names
    param_pattern = r'([\w_-]+)=(?:"([^"]*)"|([^\s)]+))'
    for m in re.finditer(param_pattern, inner_content):
        key = m.group(1)
        value = m.group(2) if m.group(2) is not None else m.group(3)
        if key == "scheme":
            scheme = value
        else:
            params[key] = value

    if not scheme:
        raise ValueError(f"Missing scheme in Signature-Key: {header_value}")

    return {
        "scheme": scheme,
        "params": params,
        "label": label
    }
