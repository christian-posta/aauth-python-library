"""HTTP signature verification for AAuth."""

import re
import time
from typing import Dict, Any, Optional, Callable
from urllib.parse import urlparse
import jwt
from ..headers.signature_key import parse_signature_key
from ..headers.signature_input import parse_signature_input
from ..headers.signature import parse_signature
from ..signing.signature_base import build_signature_base
from ..keys.jwk import jwk_to_public_key
from ..tokens.agent_token import verify_agent_token
from ..errors import SignatureError


def verify_signature(
    method: str,
    target_uri: str,
    headers: Dict[str, str],
    body: Optional[bytes],
    signature_input_header: str,
    signature_header: str,
    signature_key_header: str,
    public_key=None,
    jwks_fetcher: Optional[Callable] = None
) -> bool:
    """Verify HTTP signature using HTTP Message Signatures (RFC 9421).
    
    Args:
        method: HTTP method
        target_uri: Target URI
        headers: Request headers
        body: Request body bytes (None if no body)
        signature_input_header: Signature-Input header value
        signature_header: Signature header value
        signature_key_header: Signature-Key header value
        public_key: Optional public key (for hwk scheme)
        jwks_fetcher: Optional JWKS fetcher function (for jwks/jwt schemes)
        
    Returns:
        True if signature is valid, False otherwise
        
    Raises:
        SignatureError: If verification fails due to invalid format
    """
    try:
        # Parse Signature-Input
        components, sig_params = parse_signature_input(signature_input_header)
        
        # Verify created timestamp (per spec Section 10.4)
        if "created" in sig_params:
            created = int(sig_params["created"])
            now = int(time.time())
            if abs(now - created) > 60:
                return False
        
        # Parse Signature-Key
        parsed_key = parse_signature_key(signature_key_header)
        scheme = parsed_key["scheme"]
        params = parsed_key["params"]
        label = parsed_key["label"]
        
        # Verify label consistency (per spec Section 10.1.1)
        label_match = re.match(r'(\w+)=', signature_input_header)
        sig_label_match = re.match(r'(\w+)=', signature_header)
        
        if not (label_match and sig_label_match):
            return False
        
        if not (label_match.group(1) == sig_label_match.group(1) == label):
            return False
        
        # Extract public key based on scheme
        if scheme == "hwk":
            if not public_key:
                jwk = {
                    "kty": params.get("kty"),
                    "crv": params.get("crv"),
                    "x": params.get("x")
                }
                public_key = jwk_to_public_key(jwk)
        
        elif scheme == "jwks":
            if not jwks_fetcher:
                raise SignatureError("sig=jwks requires jwks_fetcher")
            
            agent_id = params.get("id")
            kid = params.get("kid")
            well_known = params.get("well-known")
            jwks_param = params.get("jwks")
            
            # Per spec Section 10.7 Mode 2: jwks parameter MUST NOT be present
            if jwks_param:
                return False
            
            # Fetch JWKS
            if callable(jwks_fetcher):
                # Try both calling patterns
                try:
                    jwks = jwks_fetcher(agent_id, kid) if kid else jwks_fetcher(agent_id)
                except:
                    jwks = jwks_fetcher(agent_id)
            else:
                jwks = jwks_fetcher
            
            if not jwks:
                return False
            
            # Find key by kid
            keys = jwks.get("keys", [])
            signing_key = None
            for key in keys:
                if key.get("kid") == kid:
                    signing_key = key
                    break
            
            if not signing_key:
                return False
            
            public_key = jwk_to_public_key(signing_key)
        
        elif scheme == "jwt":
            if not jwks_fetcher:
                raise SignatureError("sig=jwt requires jwks_fetcher")
            
            jwt_token = params.get("jwt")
            if not jwt_token:
                return False
            
            # Parse JWT to determine type
            try:
                header = jwt.get_unverified_header(jwt_token)
                payload = jwt.decode(jwt_token, options={"verify_signature": False})
            except Exception:
                return False
            
            typ = header.get("typ")
            if typ not in ("agent+jwt", "auth+jwt"):
                return False
            
            # Validate JWT and extract cnf.jwk
            if typ == "agent+jwt":
                # Verify agent token
                try:
                    agent_claims = verify_agent_token(
                        token=jwt_token,
                        jwks_fetcher=jwks_fetcher,
                        expected_aud=None
                    )
                    cnf = agent_claims.get("cnf")
                    cnf_jwk = cnf.get("jwk") if cnf else None
                except Exception:
                    return False
            
            elif typ == "auth+jwt":
                # Extract cnf.jwk from payload
                cnf = payload.get("cnf")
                if not cnf:
                    return False
                
                cnf_jwk = cnf.get("jwk")
                if not cnf_jwk:
                    return False
                
                # Verify JWT signature using auth server's JWKS
                iss = payload.get("iss")
                kid_header = header.get("kid")
                if not iss or not kid_header:
                    return False
                
                # Fetch auth server JWKS
                try:
                    if callable(jwks_fetcher):
                        auth_jwks = jwks_fetcher(iss)
                    else:
                        auth_jwks = jwks_fetcher
                    
                    if not auth_jwks:
                        return False
                    
                    # Find signing key
                    keys = auth_jwks.get("keys", [])
                    signing_key = None
                    for key in keys:
                        if key.get("kid") == kid_header:
                            signing_key = key
                            break
                    
                    if not signing_key:
                        return False
                    
                    auth_public_key = jwk_to_public_key(signing_key)
                    
                    # Verify JWT signature
                    jwt.decode(
                        jwt_token,
                        auth_public_key,
                        algorithms=["EdDSA"],
                        options={"verify_signature": True, "verify_exp": False, "verify_aud": False}
                    )
                    
                    # Check expiration
                    exp = payload.get("exp")
                    if exp and int(time.time()) >= exp:
                        return False
                except Exception:
                    return False
            
            # Convert cnf.jwk to public key for HTTPSig verification
            public_key = jwk_to_public_key(cnf_jwk)
        
        else:
            raise SignatureError(f"Unknown signature scheme: {scheme}")
        
        # Reconstruct signature base
        parsed_uri = urlparse(target_uri)
        authority = parsed_uri.netloc
        path = parsed_uri.path or "/"
        query_string = parsed_uri.query if parsed_uri.query else None
        
        signature_base = build_signature_base(
            method=method,
            authority=authority,
            path=path,
            query=query_string,
            headers=headers,
            body=body,
            signature_key_header=signature_key_header,
            covered_components=components
        )
        
        # Parse signature
        signature_bytes = parse_signature(signature_header, label=label)
        
        # Verify signature
        try:
            public_key.verify(signature_bytes, signature_base.encode('utf-8'))
            return True
        except Exception:
            return False
    
    except SignatureError:
        raise
    except Exception as e:
        raise SignatureError(f"Signature verification failed: {e}") from e

