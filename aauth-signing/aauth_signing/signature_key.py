"""Signature-Key header parsing and building.

Supports schemes per draft-hardt-httpbis-signature-key:
- hwk: Hardware/inline public key (pseudonymous)
- jkt-jwt: Self-issued key delegation from hardware-backed enclave key (pseudonymous)
- jwks_uri: Reference to JWKS endpoint (identity)
- jwt: JWT containing public key in cnf claim (identity)
"""

import re
from typing import Dict, Any, List, Tuple
from .keys.jwk import public_key_to_jwk


def _escape_sf_string(value: str) -> str:
    """Escape a value for use inside an RFC 8941 quoted string."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _format_sf_item_parameters(pairs: List[Tuple[str, str]]) -> str:
    """Build semicolon-separated `key="value"` parameters (RFC 8941 Item parameters)."""
    return ";".join(f'{k}="{_escape_sf_string(v)}"' for k, v in pairs)


def build_signature_key_header(
    sig_scheme: str,
    private_key=None,
    label: str = "sig",
    **kwargs
) -> str:
    """Build Signature-Key header as RFC 8941 Structured Fields Dictionary.

    Per draft-hardt-httpbis-signature-key: each member is an Item whose bare
    item is the scheme token, with semicolon-separated parameters, e.g.::

        sig=hwk;kty="OKP";crv="Ed25519";x="..."
        sig=jwks_uri;id="https://...";kid="key-1"

    The label must match the label used in Signature-Input and Signature headers.

    Args:
        sig_scheme: Signature scheme ("hwk", "jkt-jwt", "jwks_uri", "jwt")
        private_key: Private key (for hwk scheme)
        label: Signature label (default: "sig")
        **kwargs: Additional parameters:
            - For "hwk": None (key extracted from private_key)
            - For "jkt-jwt": jwt (required) - the delegation JWT
            - For "jwks_uri": id (required), dwk (required), kid (optional, default "key-1")
            - For "jwt": jwt (required)

    Returns:
        Signature-Key header value

    Raises:
        ValueError: If required parameters are missing
    """
    if sig_scheme == "hwk":
        public_key = private_key.public_key()
        jwk = public_key_to_jwk(public_key)
        params = _format_sf_item_parameters(
            [
                ("kty", jwk["kty"]),
                ("crv", jwk["crv"]),
                ("x", jwk["x"]),
            ]
        )
        return f"{label}=hwk;{params}"
    if sig_scheme == "jkt-jwt":
        jwt_token = kwargs.get("jwt")
        if not jwt_token:
            raise ValueError("scheme=jkt-jwt requires 'jwt' parameter")
        params = _format_sf_item_parameters([("jwt", jwt_token)])
        return f"{label}=jkt-jwt;{params}"
    if sig_scheme == "jwks_uri":
        agent_id = kwargs.get("id")
        kid = kwargs.get("kid", "key-1")
        dwk = kwargs.get("dwk")
        if not agent_id:
            raise ValueError("scheme=jwks_uri requires 'id' parameter")
        if not dwk:
            raise ValueError("scheme=jwks_uri requires 'dwk' parameter")
        pairs: List[Tuple[str, str]] = [("id", agent_id)]
        pairs.append(("dwk", dwk))
        pairs.append(("kid", kid))
        params = _format_sf_item_parameters(pairs)
        return f"{label}=jwks_uri;{params}"
    if sig_scheme == "jwt":
        jwt_token = kwargs.get("jwt")
        if not jwt_token:
            raise ValueError("scheme=jwt requires 'jwt' parameter")
        params = _format_sf_item_parameters([("jwt", jwt_token)])
        return f"{label}=jwt;{params}"
    if sig_scheme == "x509":
        x5u = kwargs.get("x5u")
        x5t = kwargs.get("x5t")
        if not x5u:
            raise ValueError("scheme=x509 requires 'x5u' parameter")
        if not x5t:
            raise ValueError("scheme=x509 requires 'x5t' parameter")
        # x5t is a byte sequence in RFC 8941 format (:base64:)
        # but we accept a base64 string here and format it
        return f'{label}=x509;x5u="{_escape_sf_string(x5u)}";x5t=:{x5t}:'
    raise ValueError(f"Unknown signature scheme: {sig_scheme}")


def _parse_sf_parameters(param_str: str) -> Dict[str, str]:
    """Parse RFC 8941 Item parameters after the scheme token (leading `;` optional)."""
    params: Dict[str, str] = {}
    i = 0
    n = len(param_str)
    while i < n:
        while i < n and param_str[i] in " \t;":
            i += 1
        if i >= n:
            break
        eq = param_str.find("=", i)
        if eq == -1:
            break
        key = param_str[i:eq].strip()
        i = eq + 1
        if i >= n:
            params[key] = ""
            break
        if param_str[i] == '"':
            i += 1
            buf: List[str] = []
            while i < n:
                c = param_str[i]
                if c == "\\" and i + 1 < n:
                    buf.append(param_str[i + 1])
                    i += 2
                    continue
                if c == '"':
                    i += 1
                    break
                buf.append(c)
                i += 1
            params[key] = "".join(buf)
        else:
            start = i
            while i < n and param_str[i] != ";":
                i += 1
            params[key] = param_str[start:i].strip()
    return params


def _parse_dictionary_item_form(label: str, rest: str) -> Dict[str, Any]:
    """Parse ``label=scheme;k=v;...`` (draft-hardt-httpbis-signature-key §3)."""
    rest = rest.strip()
    if not rest:
        raise ValueError("Missing scheme in Signature-Key")
    semicolon = rest.find(";")
    if semicolon == -1:
        scheme, param_str = rest, ""
    else:
        scheme = rest[:semicolon].strip()
        param_str = rest[semicolon + 1 :]
    if not scheme:
        raise ValueError("Missing scheme in Signature-Key")
    params = _parse_sf_parameters(param_str)
    return {"scheme": scheme, "params": params, "label": label}


def _parse_inner_list_legacy(label: str, inner_content: str) -> Dict[str, Any]:
    """Parse legacy ``label=(scheme=hwk kty="..." ...)`` format for compatibility."""
    params: Dict[str, str] = {}
    scheme = None
    param_pattern = r'([\w_-]+)=(?:"([^"]*)"|([^\s)]+))'
    for m in re.finditer(param_pattern, inner_content):
        key = m.group(1)
        value = m.group(2) if m.group(2) is not None else m.group(3)
        if key == "scheme":
            scheme = value
        else:
            params[key] = value
    if not scheme:
        raise ValueError(f"Missing scheme in Signature-Key: ({inner_content})")
    return {"scheme": scheme, "params": params, "label": label}


def parse_signature_key(header_value: str) -> Dict[str, Any]:
    """Parse Signature-Key header value (RFC 8941 Structured Fields Dictionary).

    Supports any label (sig, sig1, etc.) - the label is extracted but not validated here.

    Accepts the spec form ``label=scheme;param="value";...`` and the legacy
    inner-list form ``label=(scheme=hwk ...)`` emitted by older library versions.

    Args:
        header_value: Signature-Key header value

    Returns:
        Dictionary with keys: scheme, params, label

    Raises:
        ValueError: If header format is invalid
    """
    header_value = header_value.strip()
    match = re.match(r"^([\w]+)=(.*)$", header_value, re.DOTALL)
    if not match:
        raise ValueError(f"Invalid Signature-Key format: {header_value}")

    label = match.group(1)
    rest = match.group(2).strip()

    if rest.startswith("(") and rest.endswith(")"):
        return _parse_inner_list_legacy(label, rest[1:-1])

    return _parse_dictionary_item_form(label, rest)
