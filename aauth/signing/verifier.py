"""HTTP signature verification for AAuth."""

import re
import time
from typing import Dict, Any, Optional, Callable
from urllib.parse import urlparse
import jwt
from .signature_key import parse_signature_key
from .signature_input import parse_signature_input
from .signature import parse_signature
from .signature_base import build_signature_base
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
    import logging
    logger = logging.getLogger("aauth.signing")

    logger.debug(f"🔐 VERIFIER: verify_signature() called")
    logger.debug(f"🔐 VERIFIER: method={method}, target_uri={target_uri}")
    logger.debug(f"🔐 VERIFIER: signature_input_header={signature_input_header}")
    
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
        
        elif scheme in ("jwks", "jwks_uri"):
            if not jwks_fetcher:
                raise SignatureError("sig=jwks_uri requires jwks_fetcher")
            
            agent_id = params.get("id")
            kid = params.get("kid")
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
            if typ not in ("aa-agent+jwt", "aa-auth+jwt"):
                return False
            
            # Validate JWT and extract cnf.jwk
            if typ == "aa-agent+jwt":
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
            
            elif typ == "aa-auth+jwt":
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
                        logger.debug(f"🔐 VERIFIER: Signing key not found in JWKS (kid={kid_header})")
                        return False
                    
                    logger.debug(f"🔐 VERIFIER: Found signing key in JWKS: {signing_key}")
                    
                    # Get algorithm from JWT header
                    alg = header.get("alg")
                    if not alg:
                        logger.debug(f"🔐 VERIFIER: JWT header missing 'alg' field")
                        return False
                    
                    # Map algorithm to PyJWT algorithm names
                    # RS256 -> RS256, EdDSA -> EdDSA, etc.
                    algorithms = [alg]
                    
                    logger.debug(f"🔐 VERIFIER: Verifying JWT with algorithm: {alg}")
                    logger.debug(f"🔐 VERIFIER: JWT token (first 100 chars): {jwt_token[:100]}...")
                    
                    # Handle different key types
                    # For RSA keys (RS256, etc.), convert JWK to public key using PyJWT's RSA algorithm
                    # For Ed25519 keys, we need to convert using jwk_to_public_key
                    key_type = signing_key.get("kty")
                    if key_type == "RSA":
                        # Convert RSA JWK to public key object using PyJWT's RSA algorithm
                        from jwt.algorithms import RSAAlgorithm
                        auth_public_key = RSAAlgorithm.from_jwk(signing_key)
                        logger.debug(f"🔐 VERIFIER: Converted RSA JWK to public key using RSAAlgorithm.from_jwk()")
                    elif key_type == "OKP" and signing_key.get("crv") == "Ed25519":
                        # Convert Ed25519 JWK to public key
                        auth_public_key = jwk_to_public_key(signing_key)
                        logger.debug(f"🔐 VERIFIER: Converted Ed25519 JWK to public key")
                    else:
                        logger.debug(f"🔐 VERIFIER: Unsupported key type: {key_type}")
                        return False
                    
                    logger.debug(f"🔐 VERIFIER: Auth public key type: {type(auth_public_key)}")
                    
                    # Verify JWT signature
                    try:
                        jwt.decode(
                            jwt_token,
                            auth_public_key,
                            algorithms=algorithms,
                            options={"verify_signature": True, "verify_exp": False, "verify_aud": False}
                        )
                        logger.debug(f"🔐 VERIFIER: JWT signature verification PASSED")
                    except Exception as jwt_error:
                        logger.debug(f"🔐 VERIFIER: JWT decode failed: {jwt_error}")
                        import traceback
                        logger.debug(f"🔐 VERIFIER: JWT decode traceback: {traceback.format_exc()}")
                        raise
                    
                    # Check expiration
                    exp = payload.get("exp")
                    if exp and int(time.time()) >= exp:
                        logger.debug(f"🔐 VERIFIER: JWT expired (exp={exp}, now={int(time.time())})")
                        return False
                except Exception as e:
                    logger.debug(f"🔐 VERIFIER: JWT verification failed with exception: {e}")
                    import traceback
                    logger.debug(f"🔐 VERIFIER: Exception traceback: {traceback.format_exc()}")
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
        
        # Extract signature params (the part after "{label}=") for @signature-params line
        # Signature-Input format: sig=("@method" "@authority" ...);created=...
        prefix = f"{label}="
        if signature_input_header.startswith(prefix):
            signature_params = signature_input_header[len(prefix):]
        else:
            signature_params = signature_input_header
        if not signature_params:
            return False
        
        logger.debug(f"🔐 VERIFIER: Building signature base")
        logger.debug(f"🔐 VERIFIER: method={method}, authority={authority}, path={path}")
        logger.debug(f"🔐 VERIFIER: covered_components={components}")
        logger.debug(f"🔐 VERIFIER: signature_params={signature_params}")
        logger.debug(f"🔐 VERIFIER: signature_key_header={signature_key_header[:100]}...")
        logger.debug(f"🔐 VERIFIER: body is None: {body is None}")
        
        signature_base = build_signature_base(
            method=method,
            authority=authority,
            path=path,
            query=query_string,
            headers=headers,
            body=body,
            signature_key_header=signature_key_header,
            covered_components=components,
            signature_params=signature_params
        )
        
        logger.debug(f"🔐 VERIFIER SIGNATURE BASE:")
        logger.debug(f"🔐 Signature base length: {len(signature_base)} bytes")
        logger.debug(f"🔐 Signature base hex (first 200): {signature_base.encode('utf-8').hex()[:200]}...")
        for i, line in enumerate(signature_base.split('\n')):
            logger.debug(f"🔐   Line {i}: {repr(line)}")
        
        # Parse signature
        signature_bytes = parse_signature(signature_header, label=label)
        
        # Verify signature
        try:
            public_key.verify(signature_bytes, signature_base.encode('utf-8'))
            logger.debug(f"🔐 VERIFIER: ✅ Signature verification PASSED")
            return True
        except Exception as e:
            logger.debug(f"🔐 VERIFIER: ❌ Signature verification FAILED: {e}")
            import traceback
            logger.debug(f"🔐 VERIFIER: Exception traceback: {traceback.format_exc()}")
            return False
    
    except SignatureError:
        raise
    except Exception as e:
        raise SignatureError(f"Signature verification failed: {e}") from e

