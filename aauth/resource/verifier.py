"""Request verification for resource role."""

from typing import Dict, Any, Optional, List, Callable
from ..signing.verifier import verify_signature
from ..headers.signature_key import parse_signature_key
from ..headers.signature_input import parse_signature_input
from ..errors import SignatureError


class RequestVerifier:
    """Verifies incoming requests for resources."""
    
    def __init__(
        self,
        canonical_authorities: List[str],
        jwks_fetcher: Optional[Callable] = None,
        trusted_auth_servers: Optional[List[str]] = None
    ):
        """Initialize request verifier.
        
        Args:
            canonical_authorities: List of canonical authorities (host:port) per SPEC 10.3.1
            jwks_fetcher: Optional JWKS fetcher function
            trusted_auth_servers: Optional list of trusted auth server identifiers
        """
        self.canonical_authorities = canonical_authorities
        self.jwks_fetcher = jwks_fetcher
        self.trusted_auth_servers = trusted_auth_servers or []
    
    def verify_request(
        self,
        method: str,
        target_uri: str,
        headers: Dict[str, str],
        body: Optional[bytes],
        require_identity: bool = False,
        require_auth_token: bool = False
    ) -> Dict[str, Any]:
        """Verify incoming request.
        
        Args:
            method: HTTP method
            target_uri: Target URI
            headers: Request headers
            body: Request body bytes
            require_identity: Whether agent identity is required
            require_auth_token: Whether auth token is required
            
        Returns:
            Dictionary with verification result:
            - valid: bool
            - agent_id: Optional[str]
            - agent_delegate: Optional[str]
            - user_sub: Optional[str]
            - scopes: Optional[List[str]]
            - error: Optional[str]
            
        Raises:
            SignatureError: If verification fails due to invalid format
        """
        # Extract signature headers
        signature_input_header = headers.get("signature-input") or headers.get("Signature-Input")
        signature_header = headers.get("signature") or headers.get("Signature")
        signature_key_header = headers.get("signature-key") or headers.get("Signature-Key")
        
        if not (signature_input_header and signature_header and signature_key_header):
            return {
                "valid": False,
                "error": "Missing signature headers"
            }
        
        # Parse Signature-Key to determine scheme
        try:
            parsed_key = parse_signature_key(signature_key_header)
            scheme = parsed_key["scheme"]
        except Exception as e:
            return {
                "valid": False,
                "error": f"Invalid Signature-Key: {e}"
            }
        
        # Check canonical authority
        from urllib.parse import urlparse
        parsed_uri = urlparse(target_uri)
        request_authority = parsed_uri.netloc
        
        if request_authority not in self.canonical_authorities:
            return {
                "valid": False,
                "error": f"Request authority {request_authority} not in canonical authorities"
            }
        
        # Verify signature
        try:
            is_valid = verify_signature(
                method=method,
                target_uri=target_uri,
                headers=headers,
                body=body,
                signature_input_header=signature_input_header,
                signature_header=signature_header,
                signature_key_header=signature_key_header,
                jwks_fetcher=self.jwks_fetcher
            )
            
            if not is_valid:
                return {
                    "valid": False,
                    "error": "Signature verification failed"
                }
        except SignatureError as e:
            return {
                "valid": False,
                "error": str(e)
            }
        
        # Extract identity/authorization info based on scheme
        result = {
            "valid": True,
            "agent_id": None,
            "agent_delegate": None,
            "user_sub": None,
            "scopes": None
        }
        
        if scheme == "jwks":
            # Extract agent ID from Signature-Key
            params = parsed_key["params"]
            result["agent_id"] = params.get("id")
        
        elif scheme == "jwt":
            # Extract from JWT token
            jwt_token = parsed_key["params"].get("jwt")
            if jwt_token:
                try:
                    import jwt as pyjwt
                    payload = pyjwt.decode(jwt_token, options={"verify_signature": False})
                    
                    # Determine token type
                    header = pyjwt.get_unverified_header(jwt_token)
                    typ = header.get("typ")
                    
                    if typ == "agent+jwt":
                        result["agent_id"] = payload.get("iss")
                        result["agent_delegate"] = payload.get("sub")
                    elif typ == "auth+jwt":
                        result["agent_id"] = payload.get("agent")
                        result["agent_delegate"] = payload.get("agent_delegate")
                        result["user_sub"] = payload.get("sub")
                        scope_str = payload.get("scope")
                        if scope_str:
                            result["scopes"] = scope_str.split()
                except Exception:
                    pass
        
        # Check requirements
        if require_identity and not result["agent_id"]:
            return {
                "valid": False,
                "error": "Agent identity required but not present"
            }
        
        if require_auth_token and not result.get("scopes"):
            return {
                "valid": False,
                "error": "Auth token required but not present"
            }
        
        return result

