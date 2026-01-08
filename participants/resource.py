"""Resource participant - protected API that validates signatures."""

from fastapi import FastAPI, Request, Response, Header
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.httpsig import verify_signature, parse_signature_key, parse_signature_input
from core.crypto_utils import jwk_to_public_key, generate_ed25519_keypair, public_key_to_jwk, generate_jwks
from core.metadata import fetch_metadata, generate_resource_metadata
from core.tokens import create_resource_token, verify_token, calculate_jwk_thumbprint
from core import _is_debug_enabled, _is_http_debug_enabled
import httpx
from typing import Optional
import time
import json


class Resource:
    """Resource server that validates signatures."""
    
    def __init__(self, resource_id: str, port: int = 8002, auth_server: Optional[str] = None):
        """Initialize resource.
        
        Args:
            resource_id: Resource identifier (HTTPS URL)
            port: Port to run resource server on
            auth_server: Optional auth server identifier (HTTPS URL) for Phase 3
        """
        self.resource_id = resource_id
        self.port = port
        self.auth_server = auth_server
        
        # Generate key pair for resource token signing
        self.private_key, self.public_key = generate_ed25519_keypair()
        self.kid = "resource-key-1"
        
        # Create FastAPI app
        self.app = FastAPI(title="AAuth Resource")
        
        # Setup routes
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup FastAPI routes."""
        
        @self.app.get("/")
        async def root():
            return {"resource_id": self.resource_id, "status": "running"}
        
        @self.app.get("/data")
        async def get_data(request: Request):
            """Protected endpoint that requires signature (defaults to sig=hwk for backward compatibility)."""
            return await self._handle_protected_request(request, "GET", required_scheme="hwk")
        
        @self.app.post("/data")
        async def post_data(request: Request):
            """Protected endpoint that requires signature (defaults to sig=hwk for backward compatibility)."""
            return await self._handle_protected_request(request, "POST", required_scheme="hwk")
        
        @self.app.get("/data-hwk")
        async def get_data_hwk(request: Request):
            """Protected endpoint that requires sig=hwk scheme."""
            return await self._handle_protected_request(request, "GET", required_scheme="hwk")
        
        @self.app.post("/data-hwk")
        async def post_data_hwk(request: Request):
            """Protected endpoint that requires sig=hwk scheme."""
            return await self._handle_protected_request(request, "POST", required_scheme="hwk")
        
        @self.app.get("/data-jwks")
        async def get_data_jwks(request: Request):
            """Protected endpoint that requires sig=jwks scheme."""
            return await self._handle_protected_request(request, "GET", required_scheme="jwks")
        
        @self.app.post("/data-jwks")
        async def post_data_jwks(request: Request):
            """Protected endpoint that requires sig=jwks scheme."""
            return await self._handle_protected_request(request, "POST", required_scheme="jwks")
        
        @self.app.get("/data-auth")
        async def get_data_auth(request: Request):
            """Protected endpoint that requires auth token (sig=jwt)."""
            return await self._handle_protected_request(request, "GET", require_auth_token=True)
        
        @self.app.post("/data-auth")
        async def post_data_auth(request: Request):
            """Protected endpoint that requires auth token (sig=jwt)."""
            return await self._handle_protected_request(request, "POST", require_auth_token=True)
        
        @self.app.get("/.well-known/aauth-resource")
        async def resource_metadata():
            """Resource metadata endpoint per AAuth spec Section 8.3."""
            jwks_uri = f"{self.resource_id}/jwks.json"
            resource_token_endpoint = f"{self.resource_id}/resource/token"
            metadata = generate_resource_metadata(
                resource_id=self.resource_id,
                jwks_uri=jwks_uri,
                resource_token_endpoint=resource_token_endpoint,
                supported_scopes=["data.read", "data.write"]
            )
            return metadata
        
        @self.app.get("/jwks.json")
        async def jwks():
            """Resource JWKS endpoint."""
            jwk = public_key_to_jwk(self.public_key, kid=self.kid)
            return generate_jwks([jwk])
        
        @self.app.post("/resource/token")
        async def resource_token_endpoint(request: Request):
            """Resource token endpoint per AAuth spec Section 9.2.5.
            
            Allows agents to request resource tokens directly when they know the required scope upfront.
            """
            return await self._handle_resource_token_request(request)
    
    async def _handle_protected_request(self, request: Request, method: str, required_scheme: str = "hwk", require_auth_token: bool = False):
        """Handle a protected request with signature verification.
        
        Args:
            request: FastAPI request object
            method: HTTP method
            required_scheme: Required signature scheme ("hwk", "jwks", or None if checking for jwt)
            require_auth_token: If True, require auth token (sig=jwt) for access
        """
        import os
        import sys
        
        # Get request body first (can only be read once)
        body = await request.body()
        
        # Debug: Print incoming HTTP request (curl-like format)
        if _is_http_debug_enabled():
            print("\n" + "=" * 80, file=sys.stderr)
            print(f">>> RESOURCE REQUEST received", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"{method} {request.url.path} HTTP/1.1", file=sys.stderr)
            print(f"Host: {request.url.hostname}:{request.url.port}", file=sys.stderr)
            for name, value in sorted(request.headers.items()):
                # Truncate long values for readability
                display_value = value
                if len(display_value) > 100:
                    display_value = display_value[:97] + "..."
                print(f"{name}: {display_value}", file=sys.stderr)
            if body:
                print(f"\n[Body ({len(body)} bytes)]", file=sys.stderr)
                try:
                    print(body.decode('utf-8'), file=sys.stderr)
                except:
                    print(f"[Binary body: {len(body)} bytes]", file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)
        
        # Get signature headers (all three required per spec)
        signature_input_header = request.headers.get("Signature-Input")
        signature_header = request.headers.get("Signature")
        signature_key_header = request.headers.get("Signature-Key")
        
        # Helper function to build appropriate Agent-Auth challenge based on endpoint requirements
        # Per SPEC.md Section 4:
        # - httpsig = any signature scheme (pseudonymous) - Section 4.1
        # - httpsig; identity=?1 = requires identity (jwks, x509, or jwt with agent token) - Section 4.2
        # - httpsig; auth-token; resource_token="..."; auth_server="..." = requires authorization - Section 4.3
        def build_agent_auth_challenge():
            """Build Agent-Auth challenge based on endpoint requirements."""
            if require_auth_token:
                # For auth token endpoints, we need agent identity first to issue resource token
                # So challenge for identity, then we can issue resource token on retry
                return "httpsig; identity=?1"
            elif required_scheme == "jwks":
                return "httpsig; identity=?1"
            elif required_scheme == "jwt":
                # Shouldn't happen (handled by require_auth_token), but fallback
                return "httpsig; identity=?1"
            else:
                # required_scheme == "hwk" or None - any signature is fine
                return "httpsig"
        
        if not signature_input_header or not signature_header or not signature_key_header:
            agent_auth_value = build_agent_auth_challenge()
            
            response = Response(
                status_code=401,
                headers={"Agent-Auth": agent_auth_value},
                content="Missing signature headers"
            )
            if _is_http_debug_enabled():
                self._print_response_debug(response)
            return response
        
        # Parse signature key to determine scheme
        try:
            parsed_key = parse_signature_key(signature_key_header)
        except Exception as e:
            agent_auth_value = build_agent_auth_challenge()
            
            response = Response(
                status_code=401,
                headers={"Agent-Auth": agent_auth_value},
                content=f"Invalid Signature-Key header: {e}"
            )
            if _is_http_debug_enabled():
                self._print_response_debug(response)
            return response
        
        scheme = parsed_key["scheme"]
        params = parsed_key["params"]
        
        # Check if auth token is required
        if require_auth_token:
            if scheme != "jwt":
                # Issue resource token challenge
                if _is_debug_enabled():
                    print(f"DEBUG RESOURCE: Auth token required but scheme={scheme}, issuing resource token challenge", file=sys.stderr, flush=True)
                return await self._issue_resource_token_challenge(request, method, scheme, params)
        else:
            # Verify scheme matches required scheme (for backward compatibility)
            # Phase 6: When identity is required (required_scheme == "jwks"), also accept scheme=jwt with agent token
            if required_scheme and scheme != required_scheme:
                # Phase 6: Check if scheme=jwt contains an agent token (acceptable for identity requirement)
                if required_scheme == "jwks" and scheme == "jwt":
                    jwt_token = params.get("jwt")
                    if jwt_token:
                        # Parse token header to check if it's an agent token
                        try:
                            import jwt as jwt_lib
                            header = jwt_lib.get_unverified_header(jwt_token)
                            typ = header.get("typ")
                            
                            if typ == "agent+jwt":
                                # Phase 6: Agent token is acceptable for identity requirement (SPEC.md Section 4.2)
                                if _is_debug_enabled():
                                    print(f"DEBUG RESOURCE: scheme=jwt with agent token is acceptable for identity requirement", file=sys.stderr, flush=True)
                                # Continue with validation (don't reject)
                            else:
                                # Not an agent token, reject
                                if _is_debug_enabled():
                                    print(f"DEBUG RESOURCE: Scheme mismatch - required={required_scheme}, got={scheme} (not agent token)", file=sys.stderr, flush=True)
                                
                                agent_auth_value = "httpsig; identity=?1"
                                response = Response(
                                    status_code=401,
                                    headers={"Agent-Auth": agent_auth_value},
                                    content=f"Invalid signature scheme: expected {required_scheme}, got {scheme}"
                                )
                                if _is_http_debug_enabled():
                                    self._print_response_debug(response)
                                return response
                        except Exception as e:
                            # Failed to parse token, reject
                            if _is_debug_enabled():
                                print(f"DEBUG RESOURCE: Failed to parse JWT token: {e}", file=sys.stderr, flush=True)
                            
                            agent_auth_value = "httpsig; identity=?1"
                            response = Response(
                                status_code=401,
                                headers={"Agent-Auth": agent_auth_value},
                                content=f"Invalid signature scheme: expected {required_scheme}, got {scheme}"
                            )
                            if _is_http_debug_enabled():
                                self._print_response_debug(response)
                            return response
                    else:
                        # No jwt parameter, reject
                        if _is_debug_enabled():
                            print(f"DEBUG RESOURCE: Scheme mismatch - required={required_scheme}, got={scheme} (no jwt parameter)", file=sys.stderr, flush=True)
                        
                        agent_auth_value = "httpsig; identity=?1"
                        response = Response(
                            status_code=401,
                            headers={"Agent-Auth": agent_auth_value},
                            content=f"Invalid signature scheme: expected {required_scheme}, got {scheme}"
                        )
                        if _is_http_debug_enabled():
                            self._print_response_debug(response)
                        return response
                else:
                    # Not the special case, reject normally
                    if _is_debug_enabled():
                        print(f"DEBUG RESOURCE: Scheme mismatch - required={required_scheme}, got={scheme}", file=sys.stderr, flush=True)
                    
                    # Build appropriate Agent-Auth challenge based on required scheme
                    # Per SPEC.md Section 4:
                    # - httpsig = any scheme (pseudonymous)
                    # - httpsig; identity=?1 = requires identity (jwks, x509, or jwt with agent token)
                    # - httpsig; auth-token = requires authorization (jwt with auth token)
                    if required_scheme == "jwks":
                        agent_auth_value = "httpsig; identity=?1"
                    elif required_scheme == "jwt":
                        # This shouldn't happen here (handled by require_auth_token above)
                        # But if it does, we'd need resource_token and auth_server
                        agent_auth_value = "httpsig; identity=?1"  # Fallback to identity requirement
                    else:
                        # required_scheme == "hwk" or None - any signature is fine
                        agent_auth_value = "httpsig"
                    
                    response = Response(
                        status_code=401,
                        headers={"Agent-Auth": agent_auth_value},
                        content=f"Invalid signature scheme: expected {required_scheme}, got {scheme}"
                    )
                    if _is_http_debug_enabled():
                        self._print_response_debug(response)
                    return response
        
        # Build target URI
        target_uri = str(request.url)
        
        # Verify signature based on scheme
        if scheme == "hwk":
            # Extract public key from header
            jwk = {
                "kty": params.get("kty"),
                "crv": params.get("crv"),
                "x": params.get("x")
            }
            
            try:
                public_key = jwk_to_public_key(jwk)
            except Exception as e:
                return Response(
                    status_code=401,
                    content=f"Invalid public key in header: {e}"
                )
            
        # Convert headers to dict, preserving original case
        headers_dict = {}
        try:
            if hasattr(request, '_headers'):
                for name, value in request._headers:
                    headers_dict[name.decode('latin-1')] = value.decode('latin-1')
            else:
                for name, value in request.headers.items():
                    headers_dict[name] = value
        except:
            for name, value in request.headers.items():
                headers_dict[name] = value
        
        # Verify signature based on scheme
        if scheme == "hwk":
            # Extract public key from header
            jwk = {
                "kty": params.get("kty"),
                "crv": params.get("crv"),
                "x": params.get("x")
            }
            
            try:
                public_key = jwk_to_public_key(jwk)
            except Exception as e:
                response = Response(
                    status_code=401,
                    content=f"Invalid public key in header: {e}"
                )
                if _is_http_debug_enabled():
                    self._print_response_debug(response)
                return response
            
            # Verify signature
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE: Method={method}, URI={target_uri}", file=sys.stderr, flush=True)
                print(f"DEBUG RESOURCE: Signature-Input={signature_input_header}", file=sys.stderr, flush=True)
                print(f"DEBUG RESOURCE: Signature-Key={signature_key_header[:80]}...", file=sys.stderr, flush=True)
                print(f"DEBUG RESOURCE: Headers keys={list(headers_dict.keys())}", file=sys.stderr, flush=True)
            
            is_valid = verify_signature(
                method=method,
                target_uri=target_uri,
                headers=headers_dict,
                body=body,
                signature_input_header=signature_input_header,
                signature_header=signature_header,
                signature_key_header=signature_key_header,
                public_key=public_key
            )
            
            if not is_valid:
                if _is_debug_enabled():
                    print("DEBUG RESOURCE: Signature verification failed", file=sys.stderr, flush=True)
                response = Response(
                    status_code=401,
                    headers={"Agent-Auth": "httpsig"},
                    content="Invalid signature"
                )
                if _is_http_debug_enabled():
                    self._print_response_debug(response)
                return response
            
            # Signature valid - return data
            response = JSONResponse({
                "message": "Access granted",
                "data": "This is protected data",
                "scheme": "hwk",
                "method": method
            })
            if _is_http_debug_enabled():
                self._print_response_debug(response)
            return response
        
        elif scheme == "jwks":
            # Extract agent_id, kid, and optional well-known from Signature-Key
            agent_id = params.get("id")
            kid = params.get("kid")
            well_known = params.get("well-known")
            jwks_param = params.get("jwks")
            
            # Per spec Section 10.7 Mode 2: jwks parameter MUST NOT be present
            if jwks_param:
                response = Response(
                    status_code=401,
                    headers={"Agent-Auth": "httpsig; identity=?1"},
                    content="Invalid Signature-Key: jwks parameter must not be present for sig=jwks"
                )
                if _is_http_debug_enabled():
                    self._print_response_debug(response)
                return response
            
            if not agent_id or not kid:
                response = Response(
                    status_code=401,
                    headers={"Agent-Auth": "httpsig; identity=?1"},
                    content="Missing id or kid in Signature-Key for sig=jwks"
                )
                if _is_http_debug_enabled():
                    self._print_response_debug(response)
                return response
            
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE: sig=jwks - agent_id={agent_id}, kid={kid}, well-known={well_known}", file=sys.stderr, flush=True)
            
            # Create jwks_fetcher callback
            def jwks_fetcher(agent_id_param: str, kid_param: str):
                return self._fetch_jwks_for_agent(agent_id_param, kid_param, well_known)
            
            # Verify signature
            is_valid = verify_signature(
                method=method,
                target_uri=target_uri,
                headers=headers_dict,
                body=body,
                signature_input_header=signature_input_header,
                signature_header=signature_header,
                signature_key_header=signature_key_header,
                jwks_fetcher=jwks_fetcher
            )
            
            if not is_valid:
                if _is_debug_enabled():
                    print("DEBUG RESOURCE: Signature verification failed", file=sys.stderr, flush=True)
                response = Response(
                    status_code=401,
                    headers={"Agent-Auth": "httpsig"},
                    content="Invalid signature"
                )
                if _is_http_debug_enabled():
                    self._print_response_debug(response)
                return response
            
            # Signature valid - return data
            response = JSONResponse({
                "message": "Access granted",
                "data": "This is protected data",
                "scheme": "jwks",
                "method": method,
                "agent_id": agent_id
            })
            if _is_http_debug_enabled():
                self._print_response_debug(response)
            return response
        
        elif scheme == "jwt":
            # JWT token verification (Phase 6: supports both agent tokens and auth tokens)
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE: sig=jwt - validating JWT token", file=sys.stderr, flush=True)
            
            jwt_token = params.get("jwt")
            if not jwt_token:
                response = Response(
                    status_code=401,
                    headers={"Agent-Auth": "httpsig; identity=?1"},
                    content="Missing jwt parameter in Signature-Key for sig=jwt"
                )
                if _is_http_debug_enabled():
                    self._print_response_debug(response)
                return response
            
            # Parse token header to determine type
            try:
                import jwt as jwt_lib
                header = jwt_lib.get_unverified_header(jwt_token)
                typ = header.get("typ")
                
                if _is_debug_enabled():
                    print(f"DEBUG RESOURCE:   Token type: {typ}", file=sys.stderr, flush=True)
            except Exception as e:
                if _is_debug_enabled():
                    print(f"DEBUG RESOURCE:   Failed to parse token header: {e}", file=sys.stderr, flush=True)
                response = Response(
                    status_code=401,
                    headers={"Agent-Auth": "httpsig; identity=?1"},
                    content="Invalid JWT token"
                )
                if _is_http_debug_enabled():
                    self._print_response_debug(response)
                return response
            
            # Route to appropriate validator based on token type
            if typ == "agent+jwt":
                # Phase 6: Agent token (delegated identity)
                if _is_debug_enabled():
                    print(f"DEBUG RESOURCE:   Validating as agent token (agent+jwt)", file=sys.stderr, flush=True)
                
                # Verify agent token and HTTPSig signature
                agent_token_valid, agent_claims = await self._verify_agent_token(jwt_token, method, target_uri, headers_dict, body, signature_input_header, signature_header, signature_key_header)
                
                if not agent_token_valid:
                    response = Response(
                        status_code=401,
                        headers={"Agent-Auth": "httpsig; identity=?1"},
                        content="Invalid or expired agent token"
                    )
                    if _is_http_debug_enabled():
                        self._print_response_debug(response)
                    return response
                
                # Agent token valid - return data (identified request)
                response = JSONResponse({
                    "message": "Access granted",
                    "data": "This is protected data (identified via agent token)",
                    "scheme": "jwt",
                    "token_type": "agent+jwt",
                    "method": method,
                    "agent": agent_claims.get("iss"),  # Agent server identifier
                    "agent_delegate": agent_claims.get("sub")  # Delegate identifier
                })
                if _is_http_debug_enabled():
                    self._print_response_debug(response)
                return response
            
            elif typ == "auth+jwt":
                # Phase 3/4/5: Auth token (authorized request)
                if _is_debug_enabled():
                    print(f"DEBUG RESOURCE:   Validating as auth token (auth+jwt)", file=sys.stderr, flush=True)
                
                # Validate auth token
                auth_token_valid, auth_claims = await self._verify_auth_token(jwt_token, method, target_uri, headers_dict, body, signature_input_header, signature_header, signature_key_header)
                
                if not auth_token_valid:
                    response = Response(
                        status_code=401,
                        headers={"Agent-Auth": "httpsig; auth-token"},
                        content="Invalid or expired auth token"
                    )
                    if _is_http_debug_enabled():
                        self._print_response_debug(response)
                    return response
                
                # Auth token valid - return data
                response = JSONResponse({
                    "message": "Access granted",
                    "data": "This is protected data (authorized)",
                    "scheme": "jwt",
                    "token_type": "auth+jwt",
                    "method": method,
                    "agent": auth_claims.get("agent"),
                    "agent_delegate": auth_claims.get("agent_delegate"),
                    "scope": auth_claims.get("scope")
                })
                if _is_http_debug_enabled():
                    self._print_response_debug(response)
                return response
            
            else:
                # Unknown token type
                response = Response(
                    status_code=401,
                    headers={"Agent-Auth": "httpsig; identity=?1"},
                    content=f"Unsupported token type: {typ}"
                )
                if _is_http_debug_enabled():
                    self._print_response_debug(response)
                return response
        
        else:
            response = Response(
                status_code=401,
                headers={"Agent-Auth": "httpsig"},
                content=f"Unsupported signature scheme: {scheme}"
            )
            if _is_http_debug_enabled():
                self._print_response_debug(response)
            return response
    
    async def _issue_resource_token_challenge(self, request: Request, method: str, scheme: str, params: Dict[str, Any]) -> Response:
        """Issue resource token challenge when auth token is required but not present.
        
        Args:
            request: FastAPI request object
            method: HTTP method
            scheme: Current signature scheme
            params: Signature-Key parameters
            
        Returns:
            Response with Agent-Auth header containing resource_token
        """
        import sys
        
        if not self.auth_server:
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE: Cannot issue resource token challenge - no auth_server configured", file=sys.stderr, flush=True)
            return Response(
                status_code=500,
                content="Resource not configured with auth server"
            )
        
        # Extract agent identity from current signature
        agent_id = None
        agent_jkt = None
        
        if scheme == "jwks":
            agent_id = params.get("id")
            if agent_id:
                # Fetch agent's JWKS to calculate thumbprint
                kid = params.get("kid")
                well_known = params.get("well-known")
                agent_jwk = self._fetch_jwks_for_agent(agent_id, kid, well_known)
                if agent_jwk:
                    agent_jkt = calculate_jwk_thumbprint(agent_jwk)
        elif scheme == "hwk":
            # For hwk, we can extract the public key from params
            jwk = {
                "kty": params.get("kty"),
                "crv": params.get("crv"),
                "x": params.get("x")
            }
            if all(jwk.values()):
                agent_jkt = calculate_jwk_thumbprint(jwk)
                # For hwk, we don't have agent_id, so we'll use a placeholder
                # In practice, resources might require identified requests for auth token challenges
                agent_id = "unknown-agent"
        
        if not agent_id or not agent_jkt:
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE: Cannot issue resource token - missing agent identity or key", file=sys.stderr, flush=True)
            return Response(
                status_code=401,
                headers={"Agent-Auth": "httpsig; identity=?1"},
                content="Agent identity required for authorization"
            )
        
        # Issue resource token
        scope = "data.read data.write"  # Default scope for Phase 3
        resource_token = self._issue_resource_token(agent_id, agent_jkt, scope)
        
        if _is_debug_enabled():
            print(f"DEBUG RESOURCE: Issued resource token for agent_id={agent_id}, agent_jkt={agent_jkt[:20]}...", file=sys.stderr, flush=True)
        
        # Build Agent-Auth challenge header
        agent_auth_header = f'httpsig; auth-token; resource_token="{resource_token}"; auth_server="{self.auth_server}"'
        
        response = Response(
            status_code=401,
            headers={"Agent-Auth": agent_auth_header},
            content="Authorization required"
        )
        
        if _is_http_debug_enabled():
            self._print_response_debug(response)
        
        return response
    
    def _issue_resource_token(self, agent_id: str, agent_jkt: str, scope: str) -> str:
        """Issue a resource token (resource+jwt).
        
        Args:
            agent_id: Agent identifier
            agent_jkt: JWK Thumbprint of agent's signing key
            scope: Space-separated scope values
            
        Returns:
            Resource token JWT string
        """
        import sys
        
        if _is_debug_enabled():
            print(f"DEBUG RESOURCE: Issuing resource token:", file=sys.stderr, flush=True)
            print(f"DEBUG RESOURCE:   agent_id={agent_id}", file=sys.stderr, flush=True)
            print(f"DEBUG RESOURCE:   agent_jkt={agent_jkt}", file=sys.stderr, flush=True)
            print(f"DEBUG RESOURCE:   scope={scope}", file=sys.stderr, flush=True)
        
        if not self.auth_server:
            raise ValueError("Cannot issue resource token: auth_server not configured")
        
        # Create resource token (10 minute expiration)
        exp = int(time.time()) + 600
        token = create_resource_token(
            iss=self.resource_id,
            aud=self.auth_server,
            agent=agent_id,
            agent_jkt=agent_jkt,
            scope=scope,
            private_key=self.private_key,
            kid=self.kid,
            exp=exp
        )
        
        if _is_debug_enabled():
            print(f"DEBUG RESOURCE:   Resource token generated: {token[:100]}...", file=sys.stderr, flush=True)
        
        return token
    
    async def _verify_auth_token(
        self,
        jwt_token: str,
        method: str,
        target_uri: str,
        headers_dict: Dict[str, str],
        body: bytes,
        signature_input_header: str,
        signature_header: str,
        signature_key_header: str
    ) -> tuple[bool, Optional[Dict[str, Any]]]:
        """Verify auth token and HTTPSig signature.
        
        Args:
            jwt_token: Auth token JWT string
            method: HTTP method
            target_uri: Target URI
            headers_dict: Request headers
            body: Request body
            signature_input_header: Signature-Input header
            signature_header: Signature header
            signature_key_header: Signature-Key header
            
        Returns:
            Tuple of (is_valid, claims_dict)
        """
        import sys
        
        if _is_debug_enabled():
            print(f"DEBUG RESOURCE: Verifying auth token:", file=sys.stderr, flush=True)
            print(f"DEBUG RESOURCE:   Token (first 100 chars): {jwt_token[:100]}...", file=sys.stderr, flush=True)
        
        # Parse token to extract issuer (auth server)
        try:
            import jwt as jwt_lib
            payload = jwt_lib.decode(jwt_token, options={"verify_signature": False})
            iss = payload.get("iss")
            aud = payload.get("aud")
            agent = payload.get("agent")
            scope = payload.get("scope")
            cnf = payload.get("cnf", {})
            cnf_jwk = cnf.get("jwk")
            
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE:   Extracted claims:", file=sys.stderr, flush=True)
                print(f"DEBUG RESOURCE:     iss={iss}", file=sys.stderr, flush=True)
                print(f"DEBUG RESOURCE:     aud={aud}", file=sys.stderr, flush=True)
                print(f"DEBUG RESOURCE:     agent={agent}", file=sys.stderr, flush=True)
                print(f"DEBUG RESOURCE:     scope={scope}", file=sys.stderr, flush=True)
                print(f"DEBUG RESOURCE:     cnf.jwk present: {cnf_jwk is not None}", file=sys.stderr, flush=True)
        except Exception as e:
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE:   Failed to parse auth token: {e}", file=sys.stderr, flush=True)
            return False, None
        
        # Verify audience matches this resource
        if aud != self.resource_id:
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE:   Audience mismatch: expected={self.resource_id}, got={aud}", file=sys.stderr, flush=True)
            return False, None
        
        # Create JWKS fetcher for auth server
        def auth_jwks_fetcher(issuer_url: str, kid_param: Optional[str] = None):
            """Fetch auth server JWKS."""
            try:
                # Fetch auth server metadata
                metadata_url = f"{issuer_url}/.well-known/aauth-issuer"
                metadata = fetch_metadata(metadata_url)
                jwks_uri = metadata.get("jwks_uri")
                if not jwks_uri:
                    return None
                
                # Fetch JWKS
                jwks_response = httpx.get(jwks_uri, timeout=10.0)
                jwks_response.raise_for_status()
                return jwks_response.json()
            except Exception as e:
                if _is_debug_enabled():
                    print(f"DEBUG RESOURCE:   Error fetching auth server JWKS: {e}", file=sys.stderr, flush=True)
                return None
        
        # Verify token signature and claims
        try:
            from core.tokens import verify_token
            claims = verify_token(
                jwt_token,
                auth_jwks_fetcher,
                expected_typ="auth+jwt",
                expected_aud=self.resource_id
            )
            
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE:   Auth token signature verification PASSED", file=sys.stderr, flush=True)
        except Exception as e:
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE:   Auth token verification FAILED: {e}", file=sys.stderr, flush=True)
            return False, None
        
        # Verify HTTPSig signature using key from cnf.jwk
        if _is_debug_enabled():
            print(f"DEBUG RESOURCE:   Verifying HTTPSig signature using key from cnf.jwk", file=sys.stderr, flush=True)
        
        # Create jwks_fetcher for HTTPSig verification (for sig=jwt scheme)
        def jwt_jwks_fetcher(issuer_url: str, kid_param: Optional[str] = None):
            """JWKS fetcher for sig=jwt verification (returns auth server JWKS)."""
            return auth_jwks_fetcher(issuer_url, kid_param)
        
        is_valid = verify_signature(
            method=method,
            target_uri=target_uri,
            headers=headers_dict,
            body=body,
            signature_input_header=signature_input_header,
            signature_header=signature_header,
            signature_key_header=signature_key_header,
            jwks_fetcher=jwt_jwks_fetcher
        )
        
        if not is_valid:
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE:   HTTPSig signature verification FAILED", file=sys.stderr, flush=True)
            return False, None
        
        if _is_debug_enabled():
            print(f"DEBUG RESOURCE:   HTTPSig signature verification PASSED", file=sys.stderr, flush=True)
            print(f"DEBUG RESOURCE:   Auth token validation SUCCESS", file=sys.stderr, flush=True)
        
        return True, claims
    
    async def _verify_agent_token(
        self,
        jwt_token: str,
        method: str,
        target_uri: str,
        headers_dict: Dict[str, str],
        body: bytes,
        signature_input_header: str,
        signature_header: str,
        signature_key_header: str
    ) -> tuple[bool, Optional[Dict[str, Any]]]:
        """Verify agent token and HTTPSig signature (Phase 6: agent delegation).
        
        Args:
            jwt_token: Agent token JWT string
            method: HTTP method
            target_uri: Target URI
            headers_dict: Request headers
            body: Request body
            signature_input_header: Signature-Input header
            signature_header: Signature header
            signature_key_header: Signature-Key header
            
        Returns:
            Tuple of (is_valid, claims_dict)
        """
        import sys
        
        if _is_debug_enabled():
            print(f"DEBUG RESOURCE: Verifying agent token:", file=sys.stderr, flush=True)
            print(f"DEBUG RESOURCE:   Token (first 100 chars): {jwt_token[:100]}...", file=sys.stderr, flush=True)
        
        # Create JWKS fetcher for agent server
        def agent_jwks_fetcher(issuer_url: str, kid_param: Optional[str] = None):
            """Fetch agent server JWKS."""
            try:
                # Fetch agent server metadata
                metadata_url = f"{issuer_url}/.well-known/aauth-agent"
                metadata = fetch_metadata(metadata_url)
                jwks_uri = metadata.get("jwks_uri")
                if not jwks_uri:
                    return None
                
                # Fetch JWKS
                jwks_response = httpx.get(jwks_uri, timeout=10.0)
                jwks_response.raise_for_status()
                return jwks_response.json()
            except Exception as e:
                if _is_debug_enabled():
                    print(f"DEBUG RESOURCE:   Error fetching agent server JWKS: {e}", file=sys.stderr, flush=True)
                return None
        
        # Step 1: Verify agent token JWT signature
        try:
            from core.tokens import verify_agent_token
            claims = verify_agent_token(
                token=jwt_token,
                jwks_fetcher=agent_jwks_fetcher,
                expected_aud=None  # Could be enhanced to check audience
            )
            
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE:   Agent token JWT verification PASSED", file=sys.stderr, flush=True)
                print(f"DEBUG RESOURCE:   Agent server (iss): {claims.get('iss')}", file=sys.stderr, flush=True)
                print(f"DEBUG RESOURCE:   Agent delegate (sub): {claims.get('sub')}", file=sys.stderr, flush=True)
        except Exception as e:
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE:   Agent token verification FAILED: {e}", file=sys.stderr, flush=True)
                import traceback
                traceback.print_exc()
            return False, None
        
        # Step 2: Extract delegate's public key from cnf.jwk
        cnf = claims.get("cnf", {})
        cnf_jwk = cnf.get("jwk")
        if not cnf_jwk:
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE:   Missing cnf.jwk in agent token", file=sys.stderr, flush=True)
            return False, None
        
        if _is_debug_enabled():
            import json
            print(f"DEBUG RESOURCE:   Delegate's public key (cnf.jwk): {json.dumps(cnf_jwk)}", file=sys.stderr, flush=True)
        
        # Step 3: Convert JWK to public key
        try:
            from core.crypto_utils import jwk_to_public_key
            delegate_public_key = jwk_to_public_key(cnf_jwk)
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE:   Converted cnf.jwk to public key", file=sys.stderr, flush=True)
        except Exception as e:
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE:   Failed to convert cnf.jwk to public key: {e}", file=sys.stderr, flush=True)
            return False, None
        
        # Step 4: Verify HTTPSig signature using delegate's public key
        from core.httpsig import _verify_signature_manual
        
        is_valid = _verify_signature_manual(
            method=method,
            target_uri=target_uri,
            headers=headers_dict,
            body=body,
            signature_input_header=signature_input_header,
            signature_header=signature_header,
            signature_key_header=signature_key_header,
            public_key=delegate_public_key,
            jwks_fetcher=None
        )
        
        if not is_valid:
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE:   HTTPSig signature verification FAILED", file=sys.stderr, flush=True)
            return False, None
        
        if _is_debug_enabled():
            print(f"DEBUG RESOURCE:   HTTPSig signature verification PASSED", file=sys.stderr, flush=True)
        
        return True, claims
    
    def _fetch_jwks_for_agent(self, agent_id: str, kid: str, well_known: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Fetch JWKS for an agent using Mode 2 discovery (spec Section 10.7).
        
        Args:
            agent_id: Agent identifier (HTTPS URL)
            kid: Key identifier
            well_known: Optional well-known document name (e.g., "aauth-agent")
            
        Returns:
            JWK dictionary if found, None otherwise
            
        Discovery procedure per spec Section 10.7 Mode 2:
        1. If well-known is present:
           - Fetch metadata from {id}/.well-known/{well-known} via HTTPS
           - Extract jwks_uri from metadata
           - Fetch JWKS from jwks_uri
        2. If well-known is absent:
           - Fetch {id} directly as JWKS via HTTPS
        3. Match key by kid
        """
        import os
        import sys
        
        if _is_debug_enabled():
            print(f"DEBUG RESOURCE: Fetching JWKS for agent_id={agent_id}, kid={kid}, well-known={well_known}", file=sys.stderr, flush=True)
        
        try:
            jwks_uri = None
            
            if well_known:
                # Step 1: Fetch metadata from agent using well-known parameter
                metadata_url = f"{agent_id}/.well-known/{well_known}"
                if _is_debug_enabled():
                    print(f"DEBUG RESOURCE: Fetching metadata from {metadata_url}", file=sys.stderr, flush=True)
                
                metadata = fetch_metadata(metadata_url)
                
                if _is_debug_enabled():
                    print(f"DEBUG RESOURCE: Metadata received: {metadata}", file=sys.stderr, flush=True)
                
                # Step 2: Extract jwks_uri from metadata
                jwks_uri = metadata.get("jwks_uri")
                if not jwks_uri:
                    if _is_debug_enabled():
                        print(f"DEBUG RESOURCE: No jwks_uri in metadata", file=sys.stderr, flush=True)
                    return None
            else:
                # Step 1: Fetch {id} directly as JWKS (well-known absent)
                jwks_uri = agent_id
                if _is_debug_enabled():
                    print(f"DEBUG RESOURCE: well-known absent, fetching {agent_id} directly as JWKS", file=sys.stderr, flush=True)
            
            # Step 2/3: Fetch JWKS from jwks_uri
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE: Fetching JWKS from {jwks_uri}", file=sys.stderr, flush=True)
            
            jwks_response = httpx.get(jwks_uri, timeout=10.0)
            jwks_response.raise_for_status()
            jwks_doc = jwks_response.json()
            
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE: JWKS received: {jwks_doc}", file=sys.stderr, flush=True)
            
            # Step 3/4: Find key by kid
            keys = jwks_doc.get("keys", [])
            for key in keys:
                if key.get("kid") == kid:
                    if _is_debug_enabled():
                        print(f"DEBUG RESOURCE: Found key with kid={kid}", file=sys.stderr, flush=True)
                    return key
            
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE: Key with kid={kid} not found in JWKS", file=sys.stderr, flush=True)
            return None
            
        except Exception as e:
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE: Error fetching JWKS: {e}", file=sys.stderr, flush=True)
            return None
    
    async def _handle_resource_token_request(self, request: Request) -> Response:
        """Handle resource token endpoint request per SPEC.md Section 9.2.5.
        
        Args:
            request: FastAPI request object
            
        Returns:
            JSONResponse with resource_token and auth_server, or error response
        """
        import sys
        import json
        from urllib.parse import parse_qs
        
        # Get request body
        body = await request.body()
        body_text = body.decode('utf-8') if body else ""
        
        if _is_http_debug_enabled():
            print("\n" + "=" * 80, file=sys.stderr)
            print(">>> RESOURCE TOKEN ENDPOINT REQUEST", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"{request.method} {request.url.path} HTTP/1.1", file=sys.stderr)
            for name, value in sorted(request.headers.items()):
                display_value = value
                if len(display_value) > 100:
                    display_value = display_value[:97] + "..."
                print(f"{name}: {display_value}", file=sys.stderr)
            if body_text:
                print(f"\n[Body ({len(body)} bytes)]", file=sys.stderr)
                print(body_text, file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)
        
        # Parse request body (application/x-www-form-urlencoded)
        try:
            params = parse_qs(body_text, keep_blank_values=True)
            params_dict = {k: v[0] if v else "" for k, v in params.items()}
        except Exception as e:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": f"Failed to parse request body: {e}"}
            )
        
        # Extract scope or auth_request_url (exactly one required per spec)
        scope = params_dict.get("scope", "").strip()
        auth_request_url = params_dict.get("auth_request_url", "").strip()
        
        if not scope and not auth_request_url:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Either scope or auth_request_url is required"}
            )
        
        if scope and auth_request_url:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Cannot specify both scope and auth_request_url"}
            )
        
        # For Phase 3, we only support scope (auth_request_url is Phase 4+)
        if auth_request_url:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "auth_request_url not supported in Phase 3"}
            )
        
        # Verify agent's signature (must be identified - sig=jwks)
        headers_dict = dict(request.headers)
        signature_input_header = headers_dict.get("signature-input", "")
        signature_header = headers_dict.get("signature", "")
        signature_key_header = headers_dict.get("signature-key", "")
        
        if not signature_input_header or not signature_header or not signature_key_header:
            return JSONResponse(
                status_code=401,
                headers={"Agent-Auth": "httpsig; identity=?1"},
                content={"error": "invalid_request", "error_description": "Missing signature headers"}
            )
        
        # Parse signature key
        try:
            parsed_key = parse_signature_key(signature_key_header)
            scheme = parsed_key["scheme"]
            key_params = parsed_key["params"]
        except Exception as e:
            return JSONResponse(
                status_code=401,
                headers={"Agent-Auth": "httpsig; identity=?1"},
                content={"error": "invalid_request", "error_description": f"Invalid Signature-Key: {e}"}
            )
        
        # Require sig=jwks for resource token endpoint (agent identity required)
        if scheme != "jwks":
            return JSONResponse(
                status_code=401,
                headers={"Agent-Auth": "httpsig; identity=?1"},
                content={"error": "invalid_request", "error_description": "Resource token endpoint requires sig=jwks"}
            )
        
        # Extract agent identity
        agent_id = key_params.get("id")
        if not agent_id:
            return JSONResponse(
                status_code=401,
                headers={"Agent-Auth": "httpsig; identity=?1"},
                content={"error": "invalid_request", "error_description": "Could not extract agent identifier"}
            )
        
        # Verify signature
        target_uri = str(request.url)
        well_known = key_params.get("well-known")
        def jwks_fetcher(agent_id_param: str, kid_param: str = None):
            return self._fetch_jwks_for_agent(agent_id_param, kid_param, well_known)
        
        is_valid = verify_signature(
            method=request.method,
            target_uri=target_uri,
            headers=headers_dict,
            body=body,
            signature_input_header=signature_input_header,
            signature_header=signature_header,
            signature_key_header=signature_key_header,
            jwks_fetcher=jwks_fetcher
        )
        
        if not is_valid:
            return JSONResponse(
                status_code=401,
                headers={"Agent-Auth": "httpsig; identity=?1"},
                content={"error": "invalid_signature", "error_description": "Signature verification failed"}
            )
        
        # Get agent's key for agent_jkt calculation
        kid = key_params.get("kid")
        well_known = key_params.get("well-known")
        agent_jwk = self._fetch_jwks_for_agent(agent_id, kid, well_known)
        if not agent_jwk:
            return JSONResponse(
                status_code=500,
                content={"error": "server_error", "error_description": "Failed to fetch agent JWKS"}
            )
        
        agent_jkt = calculate_jwk_thumbprint(agent_jwk)
        
        # Issue resource token
        if not self.auth_server:
            return JSONResponse(
                status_code=500,
                content={"error": "server_error", "error_description": "Resource not configured with auth server"}
            )
        
        resource_token = self._issue_resource_token(agent_id, agent_jkt, scope)
        
        # Calculate expiration (10 minutes default)
        expires_in = 600
        
        # Return response per SPEC.md Section 9.2.5
        response_data = {
            "resource_token": resource_token,
            "auth_server": self.auth_server,
            "expires_in": expires_in
        }
        
        if _is_http_debug_enabled():
            print("\n" + "=" * 80, file=sys.stderr)
            print("<<< RESOURCE TOKEN ENDPOINT RESPONSE", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"HTTP/1.1 200 OK", file=sys.stderr)
            print(f"Content-Type: application/json", file=sys.stderr)
            print(f"\n[Body]", file=sys.stderr)
            print(json.dumps(response_data, indent=2), file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)
        
        return JSONResponse(content=response_data)
    
    def _print_response_debug(self, response: Response):
        """Print HTTP response in curl-like format for debugging."""
        import json
        print("\n" + "=" * 80, file=sys.stderr)
        print(f"<<< RESOURCE RESPONSE", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print(f"HTTP/1.1 {response.status_code}", file=sys.stderr)
        for name, value in sorted(response.headers.items()):
            display_value = value
            if len(display_value) > 100:
                display_value = display_value[:97] + "..."
            print(f"{name}: {display_value}", file=sys.stderr)
        if hasattr(response, 'body') and response.body:
            body_bytes = response.body if isinstance(response.body, bytes) else response.body.encode()
            print(f"\n[Body ({len(body_bytes)} bytes)]", file=sys.stderr)
            try:
                print(body_bytes.decode('utf-8'), file=sys.stderr)
            except:
                print(f"[Binary body: {len(body_bytes)} bytes]", file=sys.stderr)
        elif hasattr(response, 'content') and response.content:
            body_bytes = response.content if isinstance(response.content, bytes) else response.content.encode()
            print(f"\n[Body ({len(body_bytes)} bytes)]", file=sys.stderr)
            try:
                print(body_bytes.decode('utf-8'), file=sys.stderr)
            except:
                print(f"[Binary body: {len(body_bytes)} bytes]", file=sys.stderr)
        # For JSONResponse, get the body from the response
        elif isinstance(response, JSONResponse):
            # JSONResponse stores body in _content, but we can't easily access it here
            # The body will be serialized by FastAPI
            pass
        print("=" * 80 + "\n", file=sys.stderr)
    
    def run(self):
        """Run the resource server."""
        import uvicorn
        uvicorn.run(self.app, host="0.0.0.0", port=self.port)


if __name__ == "__main__":
    resource = Resource("https://resource.example", port=8002)
    resource.run()

