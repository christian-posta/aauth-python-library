"""HTTP Message Signing implementation (RFC 9421) for AAuth."""

from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse
import base64
import hashlib
import time
import re
import jwt

# Try to import http-message-signatures library, fall back to manual implementation
try:
    from http_message_signatures import HTTPMessageSigner, HTTPMessageVerifier
    from http_message_signatures.algorithms import ED25519
    from http_message_signatures.structures import CaseInsensitiveDict
    HAS_LIBRARY = True
except ImportError:
    HAS_LIBRARY = False


def _is_debug_enabled(env_var: str = "AAUTH_DEBUG") -> bool:
    """Check if debug is enabled (defaults to True unless explicitly disabled)."""
    import os
    value = os.environ.get(env_var, "1")
    return value.lower() not in ("0", "false", "no", "off", "")


def sign_request(
    method: str,
    target_uri: str,
    headers: Dict[str, str],
    body: bytes,
    private_key,
    sig_scheme: str = "hwk",
    **kwargs
) -> Dict[str, str]:
    """Sign an HTTP request using http-message-signatures library (RFC 9421).
    
    Args:
        method: HTTP method (GET, POST, etc.)
        target_uri: Target URI
        headers: Request headers dictionary (will be modified)
        body: Request body bytes
        private_key: Ed25519 private key
        sig_scheme: Signature scheme - "hwk", "jwks", or "jwt"
        **kwargs: Additional parameters for signature schemes
    
    Returns:
        Dictionary with Signature-Input, Signature, and Signature-Key headers
    """
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
    
    # Add Content-Digest if body exists (RFC 9530)
    if body:
        digest = hashlib.sha256(body).digest()
        digest_b64 = base64.b64encode(digest).decode('ascii')
        headers["Content-Digest"] = f"sha-256=:{digest_b64}:"
        
        # Add content-type if not present
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/octet-stream"
    
    # Parse URI for derived components
    parsed_uri = urlparse(target_uri)
    
    # Build component list per AAuth spec Section 10.3
    covered_components = ["@method", "@authority", "@path"]
    
    if parsed_uri.query:
        covered_components.append("@query")
    
    if body:
        covered_components.append("content-type")
        covered_components.append("content-digest")
    
    # signature-key MUST always be included (AAuth spec Section 10)
    covered_components.append("signature-key")
    
    # For now, use manual implementation
    # TODO: Once http-message-signatures library is installed and API is verified,
    # we can use it here for more robust RFC 9421 compliance
    return _sign_request_manual(
        method, target_uri, headers, body, private_key, sig_scheme, **kwargs
    )


def _sign_request_manual(
    method: str,
    target_uri: str,
    headers: Dict[str, str],
    body: bytes,
    private_key,
    sig_scheme: str = "hwk",
    **kwargs
) -> Dict[str, str]:
    """Manual signing implementation (fallback if library API differs)."""
    # Parse URI to extract authority, path, and query
    parsed_uri = urlparse(target_uri)
    authority = parsed_uri.netloc
    path = parsed_uri.path or "/"
    query_string = parsed_uri.query
    
    # Use Signature-Key from headers (already added by sign_request)
    signature_key_header = headers.get("Signature-Key")
    if not signature_key_header:
        # Fallback: build it if not present (shouldn't happen)
        signature_key_header = build_signature_key_header(
            sig_scheme=sig_scheme,
            private_key=private_key,
            label="sig1",
            **kwargs
        )
        headers["Signature-Key"] = signature_key_header
    
    # Build covered components list
    components = []
    components.append(("@method", method))
    components.append(("@authority", authority))
    components.append(("@path", path))
    
    if query_string:
        components.append(("@query", query_string))
    
    if body:
        digest = hashlib.sha256(body).digest()
        digest_b64 = base64.b64encode(digest).decode('ascii')
        content_digest = f"sha-256=:{digest_b64}:"
        headers["Content-Digest"] = content_digest
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/octet-stream"
        components.append(("content-type", headers["Content-Type"]))
        components.append(("content-digest", content_digest))
    
    components.append(("signature-key", signature_key_header))
    
    # Build signature base (RFC 9421 Section 2.3)
    signature_base_parts = []
    for component_name, component_value in components:
        if component_name.startswith("@"):
            signature_base_parts.append(f'"{component_name}": {component_value}')
        else:
            header_name = component_name.lower()
            signature_base_parts.append(f'"{header_name}": {component_value}')
    
    signature_base = "\n".join(signature_base_parts) + "\n"
    
    # Debug output
    import os
    if _is_debug_enabled():
        print(f"DEBUG Signature base (sign): {repr(signature_base)}")
        print(f"DEBUG Components: {components}")
        print(f"DEBUG Signature-Key header: {signature_key_header[:80]}...")
    
    # Sign the signature base
    signature_bytes = private_key.sign(signature_base.encode('utf-8'))
    signature_b64 = base64.urlsafe_b64encode(signature_bytes).decode('utf-8').rstrip('=')
    
    # Build Signature-Input header
    created = int(time.time())
    component_list = ' '.join([f'"{c[0]}"' if c[0].startswith('@') else f'"{c[0].lower()}"' for c in components])
    signature_input_header = f'sig1=({component_list});created={created}'
    
    # Build Signature header
    signature_header = f'sig1=:{signature_b64}:'
    
    return {
        "Signature-Input": signature_input_header,
        "Signature": signature_header,
        "Signature-Key": signature_key_header
    }


def build_signature_key_header(
    sig_scheme: str,
    private_key,
    label: str = "sig1",
    **kwargs
) -> str:
    """Build Signature-Key header as RFC 8941 Structured Fields Dictionary.
    
    Format: {label}=(scheme=hwk kty="OKP" crv="Ed25519" x="...")
    The label must match the label used in Signature-Input and Signature headers.
    """
    from .crypto_utils import public_key_to_jwk
    
    if sig_scheme == "hwk":
        public_key = private_key.public_key()
        jwk = public_key_to_jwk(public_key)
        return f'{label}=(scheme=hwk kty="{jwk["kty"]}" crv="{jwk["crv"]}" x="{jwk["x"]}")'
    elif sig_scheme == "jwks":
        agent_id = kwargs.get("id")
        kid = kwargs.get("kid", "key-1")
        if not agent_id:
            raise ValueError("sig=jwks requires 'id' parameter")
        return f'{label}=(scheme=jwks id="{agent_id}" kid="{kid}")'
    elif sig_scheme == "jwt":
        jwt = kwargs.get("jwt")
        if not jwt:
            raise ValueError("sig=jwt requires 'jwt' parameter")
        return f'{label}=(scheme=jwt jwt="{jwt}")'
    else:
        raise ValueError(f"Unknown signature scheme: {sig_scheme}")


def parse_signature_key(header_value: str) -> Dict[str, Any]:
    """Parse Signature-Key header value (RFC 8941 Structured Fields Dictionary).
    
    Supports any label (sig, sig1, etc.) - the label is extracted but not validated here.
    """
    # Match any label: sig=, sig1=, etc.
    match = re.match(r'(\w+)=\((.*)\)', header_value)
    if not match:
        raise ValueError(f"Invalid Signature-Key format: {header_value}")
    
    label = match.group(1)
    inner_content = match.group(2)
    params = {}
    scheme = None
    
    param_pattern = r'(\w+)=(?:"([^"]*)"|([^\s)]+))'
    for match in re.finditer(param_pattern, inner_content):
        key = match.group(1)
        value = match.group(2) or match.group(3)
        if key == "scheme":
            scheme = value
        else:
            params[key] = value
    
    if not scheme:
        raise ValueError(f"Missing scheme in Signature-Key: {header_value}")
    
    return {
        "scheme": scheme,
        "params": params,
        "label": label  # Include label for consistency checking
    }


def parse_signature_input(header_value: str) -> Tuple[list, Dict[str, Any]]:
    """Parse Signature-Input header to extract covered components and parameters."""
    match = re.match(r'(\w+)=\((.*)\)(?:;(.*))?', header_value)
    if not match:
        raise ValueError(f"Invalid Signature-Input format: {header_value}")
    
    label = match.group(1)
    components_str = match.group(2)
    params_str = match.group(3) or ""
    
    components = []
    for match in re.finditer(r'"([^"]+)"', components_str):
        components.append(match.group(1))
    
    params = {}
    for match in re.finditer(r'(\w+)=([^\s;]+)', params_str):
        key = match.group(1)
        value = match.group(2).strip('"')
        params[key] = value
    
    return components, params


def verify_signature(
    method: str,
    target_uri: str,
    headers: Dict[str, str],
    body: bytes,
    signature_input_header: str,
    signature_header: str,
    signature_key_header: str,
    public_key=None,
    jwks_fetcher=None
) -> bool:
    """Verify HTTP signature using http-message-signatures library."""
    import os
    import sys
    debug = _is_debug_enabled()
    
    if debug:
        print(f"DEBUG VERIFY_TOP: Starting verify_signature", file=sys.stderr, flush=True)
        print(f"DEBUG VERIFY_TOP: Method={method}, URI={target_uri}", file=sys.stderr, flush=True)
    
    # Parse Signature-Input
    try:
        components, sig_params = parse_signature_input(signature_input_header)
        if debug:
            print(f"DEBUG VERIFY_TOP: Parsed components: {components}", file=sys.stderr, flush=True)
    except Exception as e:
        if debug:
            print(f"DEBUG VERIFY_TOP: Failed to parse Signature-Input: {e}", file=sys.stderr, flush=True)
        return False
    
    # Verify created timestamp
    if "created" in sig_params:
        created = int(sig_params["created"])
        now = int(time.time())
        if debug:
            print(f"DEBUG VERIFY_TOP: Created={created}, Now={now}, Diff={abs(now - created)}", file=sys.stderr, flush=True)
        if abs(now - created) > 60:
            if debug:
                print(f"DEBUG VERIFY_TOP: Timestamp too old/new", file=sys.stderr, flush=True)
            return False
    
    # Parse Signature-Key
    try:
        parsed_key = parse_signature_key(signature_key_header)
        if debug:
            print(f"DEBUG VERIFY_TOP: Parsed key scheme: {parsed_key['scheme']}", file=sys.stderr, flush=True)
    except Exception as e:
        if debug:
            print(f"DEBUG VERIFY_TOP: Failed to parse Signature-Key: {e}", file=sys.stderr, flush=True)
        return False
    
    scheme = parsed_key["scheme"]
    params = parsed_key["params"]
    
    # Verify label consistency
    label_match = re.match(r'(\w+)=', signature_input_header)
    sig_label_match = re.match(r'(\w+)=', signature_header)
    key_label_match = re.match(r'(\w+)=', signature_key_header)
    
    if debug:
        print(f"DEBUG VERIFY_TOP: Label matches - input: {label_match.group(1) if label_match else None}, sig: {sig_label_match.group(1) if sig_label_match else None}, key: {key_label_match.group(1) if key_label_match else None}", file=sys.stderr, flush=True)
    
    if not (label_match and sig_label_match and key_label_match):
        if debug:
            print(f"DEBUG VERIFY_TOP: Label matching failed", file=sys.stderr, flush=True)
        return False
    
    if not (label_match.group(1) == sig_label_match.group(1) == key_label_match.group(1)):
        if debug:
            print(f"DEBUG VERIFY_TOP: Label consistency check failed", file=sys.stderr, flush=True)
        return False
    
    if scheme == "hwk":
        # Extract public key from header
        if not public_key:
            from .crypto_utils import jwk_to_public_key
            jwk = {
                "kty": params.get("kty"),
                "crv": params.get("crv"),
                "x": params.get("x")
            }
            public_key = jwk_to_public_key(jwk)
        
        # Use manual verification for now
        # TODO: Once http-message-signatures library is installed and API is verified,
        # we can use it here for more robust RFC 9421 compliance
        import os
        import sys
        if _is_debug_enabled():
            print(f"DEBUG VERIFY: Calling _verify_signature_manual for scheme={scheme}", file=sys.stderr, flush=True)
        return _verify_signature_manual(
            method, target_uri, headers, body,
            signature_input_header, signature_header, signature_key_header,
            public_key, jwks_fetcher
        )
    
    elif scheme == "jwks":
        if not jwks_fetcher:
            raise ValueError("sig=jwks requires jwks_fetcher")
        agent_id = params.get("id")
        kid = params.get("kid")
        
        if debug:
            print(f"DEBUG VERIFY: sig=jwks - agent_id={agent_id}, kid={kid}", file=sys.stderr, flush=True)
        
        jwks = jwks_fetcher(agent_id, kid)
        if not jwks:
            if debug:
                print(f"DEBUG VERIFY: JWKS not found for agent_id={agent_id}, kid={kid}", file=sys.stderr, flush=True)
            return False
        
        if debug:
            print(f"DEBUG VERIFY: JWKS found, converting to public key", file=sys.stderr, flush=True)
        
        from .crypto_utils import jwk_to_public_key, public_key_to_jwk
        public_key = jwk_to_public_key(jwks)
        
        if debug:
            # Debug: Show the public key that will be used for verification
            jwk_for_debug = public_key_to_jwk(public_key)
            print(f"DEBUG VERIFY: Public key from JWKS - kty={jwk_for_debug.get('kty')}, crv={jwk_for_debug.get('crv')}, x={jwk_for_debug.get('x')[:20]}...", file=sys.stderr, flush=True)
            print(f"DEBUG VERIFY: Calling _verify_signature_manual for scheme=jwks", file=sys.stderr, flush=True)
        
        return _verify_signature_manual(
            method, target_uri, headers, body,
            signature_input_header, signature_header, signature_key_header,
            public_key, jwks_fetcher
        )
    
    elif scheme == "jwt":
        if not jwks_fetcher:
            raise ValueError("sig=jwt requires jwks_fetcher")
        jwt_token = params.get("jwt")
        if not jwt_token:
            if debug:
                print(f"DEBUG VERIFY: sig=jwt missing jwt parameter", file=sys.stderr, flush=True)
            return False
        
        if debug:
            print(f"DEBUG VERIFY: sig=jwt - extracting JWT from Signature-Key header", file=sys.stderr, flush=True)
            print(f"DEBUG VERIFY:   JWT (first 100 chars): {jwt_token[:100]}...", file=sys.stderr, flush=True)
        
        # Parse JWT to extract header and payload (unverified first)
        try:
            header = jwt.get_unverified_header(jwt_token)
            payload = jwt.decode(jwt_token, options={"verify_signature": False})
            
            if debug:
                import json
                print(f"DEBUG VERIFY:   Decoded header: {json.dumps(header, indent=2)}", file=sys.stderr, flush=True)
                print(f"DEBUG VERIFY:   Decoded payload: {json.dumps(payload, indent=2)}", file=sys.stderr, flush=True)
        except Exception as e:
            if debug:
                print(f"DEBUG VERIFY:   Failed to parse JWT: {e}", file=sys.stderr, flush=True)
            return False
        
        # Check typ claim (must be auth+jwt for resource access)
        typ = header.get("typ")
        if debug:
            print(f"DEBUG VERIFY:   Typ claim: {typ}", file=sys.stderr, flush=True)
        
        if typ != "auth+jwt":
            if debug:
                print(f"DEBUG VERIFY:   Typ check FAILED: expected=auth+jwt, got={typ}", file=sys.stderr, flush=True)
            return False
        
        if debug:
            print(f"DEBUG VERIFY:   Typ check PASSED: {typ}", file=sys.stderr, flush=True)
        
        # Extract cnf.jwk from payload
        cnf = payload.get("cnf")
        if not cnf:
            if debug:
                print(f"DEBUG VERIFY:   Missing cnf claim in JWT payload", file=sys.stderr, flush=True)
            return False
        
        cnf_jwk = cnf.get("jwk")
        if not cnf_jwk:
            if debug:
                print(f"DEBUG VERIFY:   Missing cnf.jwk claim in JWT payload", file=sys.stderr, flush=True)
            return False
        
        if debug:
            import json
            print(f"DEBUG VERIFY:   Extracted cnf.jwk: {json.dumps(cnf_jwk, indent=2)}", file=sys.stderr, flush=True)
        
        # Verify JWT signature using auth server's JWKS
        iss = payload.get("iss")
        if not iss:
            if debug:
                print(f"DEBUG VERIFY:   Missing iss claim in JWT payload", file=sys.stderr, flush=True)
            return False
        
        kid = header.get("kid")
        if not kid:
            if debug:
                print(f"DEBUG VERIFY:   Missing kid in JWT header", file=sys.stderr, flush=True)
            return False
        
        if debug:
            print(f"DEBUG VERIFY:   Verifying JWT signature using auth server JWKS", file=sys.stderr, flush=True)
            print(f"DEBUG VERIFY:     Issuer (auth server): {iss}", file=sys.stderr, flush=True)
            print(f"DEBUG VERIFY:     Key ID: {kid}", file=sys.stderr, flush=True)
        
        # Fetch auth server JWKS
        # jwks_fetcher interface: for jwt scheme, it should accept (issuer_url, None) or similar
        # We'll try calling it with issuer URL
        try:
            # Try calling with issuer URL (for auth server JWKS)
            auth_jwks = jwks_fetcher(iss, None) if callable(jwks_fetcher) else None
            if not auth_jwks:
                # Try alternative: jwks_fetcher might be a dict mapping issuer -> JWKS fetcher
                # Or it might accept just the issuer URL
                if debug:
                    print(f"DEBUG VERIFY:   Attempting to fetch auth server JWKS from {iss}", file=sys.stderr, flush=True)
                # For now, we'll need to handle this in the caller
                # But let's try a simple approach: if jwks_fetcher is callable with one arg
                try:
                    auth_jwks = jwks_fetcher(iss) if callable(jwks_fetcher) else None
                except:
                    auth_jwks = None
            
            if not auth_jwks:
                if debug:
                    print(f"DEBUG VERIFY:   Failed to fetch auth server JWKS", file=sys.stderr, flush=True)
                return False
            
            if debug:
                import json
                print(f"DEBUG VERIFY:   Auth server JWKS received: {json.dumps(auth_jwks, indent=2)}", file=sys.stderr, flush=True)
        except Exception as e:
            if debug:
                print(f"DEBUG VERIFY:   Error fetching auth server JWKS: {e}", file=sys.stderr, flush=True)
            return False
        
        # Find signing key by kid
        keys = auth_jwks.get("keys", [])
        signing_key = None
        for key in keys:
            if key.get("kid") == kid:
                signing_key = key
                break
        
        if not signing_key:
            if debug:
                print(f"DEBUG VERIFY:   Key with kid={kid} not found in auth server JWKS", file=sys.stderr, flush=True)
            return False
        
        if debug:
            import json
            print(f"DEBUG VERIFY:   Found signing key: {json.dumps(signing_key, indent=2)}", file=sys.stderr, flush=True)
        
        # Verify JWT signature
        from .crypto_utils import jwk_to_public_key
        auth_public_key = jwk_to_public_key(signing_key)
        
        if debug:
            print(f"DEBUG VERIFY:   Verifying JWT signature with auth server public key", file=sys.stderr, flush=True)
        
        try:
            jwt.decode(
                jwt_token,
                auth_public_key,
                algorithms=["EdDSA"],
                options={"verify_signature": True, "verify_exp": False, "verify_aud": False}  # We'll check exp and aud separately
            )
            if debug:
                print(f"DEBUG VERIFY:   JWT signature verification PASSED", file=sys.stderr, flush=True)
        except jwt.ExpiredSignatureError:
            if debug:
                print(f"DEBUG VERIFY:   JWT has expired", file=sys.stderr, flush=True)
            return False
        except jwt.InvalidSignatureError as e:
            if debug:
                print(f"DEBUG VERIFY:   JWT signature verification FAILED: {e}", file=sys.stderr, flush=True)
            return False
        
        # Check expiration
        exp = payload.get("exp")
        if exp:
            now = int(time.time())
            if now >= exp:
                if debug:
                    print(f"DEBUG VERIFY:   JWT expiration check FAILED: exp={exp}, now={now}", file=sys.stderr, flush=True)
                return False
            if debug:
                print(f"DEBUG VERIFY:   JWT expiration check PASSED: exp={exp}, now={now}, time until expiration: {exp - now} seconds", file=sys.stderr, flush=True)
        
        # Convert cnf.jwk to public key for HTTPSig verification
        if debug:
            print(f"DEBUG VERIFY:   Converting cnf.jwk to public key for HTTPSig verification", file=sys.stderr, flush=True)
        
        try:
            public_key = jwk_to_public_key(cnf_jwk)
            if debug:
                from .crypto_utils import public_key_to_jwk
                jwk_for_debug = public_key_to_jwk(public_key)
                print(f"DEBUG VERIFY:   Public key from cnf.jwk - kty={jwk_for_debug.get('kty')}, crv={jwk_for_debug.get('crv')}, x={jwk_for_debug.get('x')[:20]}...", file=sys.stderr, flush=True)
        except Exception as e:
            if debug:
                print(f"DEBUG VERIFY:   Failed to convert cnf.jwk to public key: {e}", file=sys.stderr, flush=True)
            return False
        
        # Use extracted key for HTTPSig verification
        if debug:
            print(f"DEBUG VERIFY:   Calling _verify_signature_manual for scheme=jwt", file=sys.stderr, flush=True)
        
        return _verify_signature_manual(
            method, target_uri, headers, body,
            signature_input_header, signature_header, signature_key_header,
            public_key, jwks_fetcher
        )
    
    else:
        raise ValueError(f"Unknown signature scheme: {scheme}")


def _verify_signature_manual(
    method: str,
    target_uri: str,
    headers: Dict[str, str],
    body: bytes,
    signature_input_header: str,
    signature_header: str,
    signature_key_header: str,
    public_key=None,
    jwks_fetcher=None
) -> bool:
    """Manual verification implementation (fallback)."""
    import os
    import sys
    debug = _is_debug_enabled()
    
    if debug:
        print(f"DEBUG VERIFY: Starting manual verification", file=sys.stderr, flush=True)
        print(f"DEBUG VERIFY: Method={method}, URI={target_uri}", file=sys.stderr, flush=True)
        print(f"DEBUG VERIFY: Signature-Input={signature_input_header}", file=sys.stderr, flush=True)
        print(f"DEBUG VERIFY: Signature-Key={signature_key_header[:80]}...", file=sys.stderr, flush=True)
    
    # Parse Signature-Input
    try:
        components, sig_params = parse_signature_input(signature_input_header)
        if debug:
            print(f"DEBUG VERIFY: Parsed components: {components}", file=sys.stderr, flush=True)
            print(f"DEBUG VERIFY: Signature params: {sig_params}", file=sys.stderr, flush=True)
    except Exception as e:
        if debug:
            print(f"DEBUG VERIFY: Failed to parse Signature-Input: {e}", file=sys.stderr, flush=True)
        return False
    
    # Verify created timestamp
    if "created" in sig_params:
        created = int(sig_params["created"])
        now = int(time.time())
        if debug:
            print(f"DEBUG VERIFY: Created={created}, Now={now}, Diff={abs(now - created)}", file=sys.stderr, flush=True)
        if abs(now - created) > 60:
            if debug:
                print(f"DEBUG VERIFY: Timestamp too old/new (tolerance: 60s)", file=sys.stderr, flush=True)
            return False
    
    # Parse Signature-Key
    try:
        parsed_key = parse_signature_key(signature_key_header)
        if debug:
            print(f"DEBUG VERIFY: Parsed key scheme: {parsed_key['scheme']}", file=sys.stderr, flush=True)
    except Exception as e:
        if debug:
            print(f"DEBUG VERIFY: Failed to parse Signature-Key: {e}", file=sys.stderr, flush=True)
        return False
    
    scheme = parsed_key["scheme"]
    params = parsed_key["params"]
    
    # Extract public key if not provided
    if not public_key:
        if scheme == "hwk":
            from .crypto_utils import jwk_to_public_key
            jwk = {
                "kty": params.get("kty"),
                "crv": params.get("crv"),
                "x": params.get("x")
            }
            public_key = jwk_to_public_key(jwk)
        elif scheme == "jwks":
            # For jwks, public_key should be provided via jwks_fetcher
            if debug:
                print(f"DEBUG VERIFY: sig=jwks requires public_key to be provided", file=sys.stderr, flush=True)
            return False
        else:
            if debug:
                print(f"DEBUG VERIFY: Unsupported scheme in manual verification: {scheme}", file=sys.stderr, flush=True)
            return False
    
    # Verify signature (works for hwk, jwks, and jwt once we have public_key)
    if scheme in ("hwk", "jwks", "jwt"):
        
        # Reconstruct signature base
        parsed_uri = urlparse(target_uri)
        authority = parsed_uri.netloc
        path = parsed_uri.path or "/"
        query_string = parsed_uri.query
        
        if debug:
            import sys
            print(f"DEBUG VERIFY: Reconstructing signature base", file=sys.stderr, flush=True)
            print(f"DEBUG VERIFY: Method={method}, Authority={authority}, Path={path}, Query={query_string}", file=sys.stderr, flush=True)
            print(f"DEBUG VERIFY: Body length={len(body) if body else 0}", file=sys.stderr, flush=True)
        
        signature_base_parts = []
        
        for component in components:
            if component == "@method":
                signature_base_parts.append(f'"@method": {method}')
            elif component == "@authority":
                signature_base_parts.append(f'"@authority": {authority}')
            elif component == "@path":
                signature_base_parts.append(f'"@path": {path}')
            elif component == "@query":
                if query_string:
                    signature_base_parts.append(f'"@query": {query_string}')
                else:
                    return False
            elif component == "content-type":
                content_type_value = None
                for header_name, header_value in headers.items():
                    if header_name.lower() == "content-type":
                        content_type_value = header_value
                        break
                if body and content_type_value:
                    signature_base_parts.append(f'"content-type": {content_type_value}')
                else:
                    if debug:
                        print(f"DEBUG VERIFY: content-type component required but missing or no body")
                    return False
            elif component == "content-digest":
                content_digest_value = None
                for header_name, header_value in headers.items():
                    if header_name.lower() == "content-digest":
                        content_digest_value = header_value
                        break
                if body and content_digest_value:
                    signature_base_parts.append(f'"content-digest": {content_digest_value}')
                else:
                    if debug:
                        print(f"DEBUG VERIFY: content-digest component required but missing or no body")
                    return False
            elif component == "signature-key":
                signature_base_parts.append(f'"signature-key": {signature_key_header}')
            else:
                if debug:
                    print(f"DEBUG VERIFY: Unknown component: {component}")
                return False
        
        signature_base = "\n".join(signature_base_parts) + "\n"
        
        # Debug output
        import os
        import sys
        if _is_debug_enabled():
            print(f"DEBUG VERIFY Signature base: {repr(signature_base)}", file=sys.stderr, flush=True)
            print(f"DEBUG VERIFY Components: {components}", file=sys.stderr, flush=True)
            print(f"DEBUG VERIFY Signature-Key header: {signature_key_header[:80]}...", file=sys.stderr, flush=True)
        
        # Parse signature
        if debug:
            print(f"DEBUG VERIFY: Parsing signature header: {signature_header[:100]}...", file=sys.stderr, flush=True)
        match = re.search(r'sig\d+=:([A-Za-z0-9_-]+):', signature_header)
        if not match:
            if _is_debug_enabled():
                print("DEBUG VERIFY: Failed to parse signature header", file=sys.stderr, flush=True)
                print(f"DEBUG VERIFY: Signature header value: {repr(signature_header)}", file=sys.stderr, flush=True)
            return False
        
        signature_b64 = match.group(1)
        if debug:
            print(f"DEBUG VERIFY: Extracted signature base64 (before padding): {signature_b64[:50]}...", file=sys.stderr, flush=True)
        signature_b64 += '=' * (4 - len(signature_b64) % 4)
        try:
            signature_bytes = base64.urlsafe_b64decode(signature_b64)
            if debug:
                print(f"DEBUG VERIFY: Parsed signature bytes length: {len(signature_bytes)}", file=sys.stderr, flush=True)
                print(f"DEBUG VERIFY: Signature bytes (hex): {signature_bytes.hex()[:64]}...", file=sys.stderr, flush=True)
        except Exception as e:
            if debug:
                print(f"DEBUG VERIFY: Failed to decode signature: {e}", file=sys.stderr, flush=True)
                print(f"DEBUG VERIFY: Exception type: {type(e).__name__}", file=sys.stderr, flush=True)
            return False
        
        # Verify signature
        try:
            if debug:
                print(f"DEBUG VERIFY: Verifying signature with public key", file=sys.stderr, flush=True)
                print(f"DEBUG VERIFY: Signature base bytes length: {len(signature_base.encode('utf-8'))}", file=sys.stderr, flush=True)
            public_key.verify(signature_bytes, signature_base.encode('utf-8'))
            if debug:
                import sys
                print(f"DEBUG VERIFY: Signature verification SUCCESS", file=sys.stderr, flush=True)
            return True
        except Exception as e:
            # Debug output
            import os
            import sys
            if _is_debug_enabled():
                print(f"DEBUG VERIFY: Signature verification FAILED: {e}", file=sys.stderr, flush=True)
                print(f"DEBUG VERIFY: Exception type: {type(e).__name__}", file=sys.stderr, flush=True)
                print(f"DEBUG VERIFY: Signature base (verify): {repr(signature_base)}", file=sys.stderr, flush=True)
                print(f"DEBUG VERIFY: Signature base bytes: {signature_base.encode('utf-8')[:100]}...", file=sys.stderr, flush=True)
                print(f"DEBUG VERIFY: Signature bytes length: {len(signature_bytes)}", file=sys.stderr, flush=True)
                print(f"DEBUG VERIFY: Components: {components}", file=sys.stderr, flush=True)
                print(f"DEBUG VERIFY: Headers received: {list(headers.keys())}", file=sys.stderr, flush=True)
                print(f"DEBUG VERIFY: Signature-Key header: {signature_key_header[:80]}...", file=sys.stderr, flush=True)
            return False
    
    return False
