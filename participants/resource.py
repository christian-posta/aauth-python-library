"""Resource participant - protected API that validates signatures."""

from fastapi import FastAPI, Request, Response, Header
from fastapi.responses import JSONResponse, RedirectResponse
from typing import Optional, Dict, Any
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aauth.signing.verifier import verify_signature
from aauth.signing.signer import sign_request
from aauth.headers.signature_key import parse_signature_key
from aauth.headers.signature_input import parse_signature_input
from aauth.keys.jwk import jwk_to_public_key, public_key_to_jwk, generate_jwks, calculate_jwk_thumbprint
from aauth.keys.keypair import generate_ed25519_keypair
from aauth.metadata.resource import generate_resource_metadata
from aauth.metadata.auth_server import fetch_metadata
from aauth.tokens.resource_token import create_resource_token
from aauth.tokens.auth_token import parse_token_claims, verify_token
from aauth.debug import _is_debug_enabled, _is_http_debug_enabled
from aauth.http.deferred import (
    generate_pending_id,
    generate_interaction_code,
    build_pending_response_body,
    build_pending_response_headers,
)
import httpx
from typing import Optional
import time
import json
import uuid


class Resource:
    """Resource server that validates signatures."""
    
    def __init__(
        self,
        resource_id: str,
        port: int = 8002,
        auth_server: Optional[str] = None,
        downstream_resource_url: Optional[str] = None,
    ):
        """Initialize resource.

        Args:
            resource_id: Resource identifier (HTTPS URL)
            port: Port to run resource server on
            auth_server: Optional auth server identifier (HTTPS URL) for Phase 3
        """
        self.resource_id = resource_id
        self.port = port
        self.auth_server = auth_server
        self.downstream_resource_url = downstream_resource_url
        self.chained_pending_requests: Dict[str, Dict[str, Any]] = {}
        
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
            return await self._handle_protected_request(request, "GET", required_scheme="jwks_uri")
        
        @self.app.post("/data-jwks")
        async def post_data_jwks(request: Request):
            """Protected endpoint that requires sig=jwks scheme."""
            return await self._handle_protected_request(request, "POST", required_scheme="jwks_uri")
        
        @self.app.get("/data-auth")
        async def get_data_auth(request: Request):
            """Protected endpoint that requires auth token (sig=jwt)."""
            try:
                return await self._handle_protected_request(request, "GET", require_auth_token=True)
            except Exception as e:
                if _is_debug_enabled():
                    import sys
                    import traceback
                    print(f"DEBUG RESOURCE: Exception in get_data_auth: {e}", file=sys.stderr, flush=True)
                    traceback.print_exc()
                return JSONResponse(
                    status_code=500,
                    content={"error": "internal_error", "error_description": str(e)}
                )
        
        @self.app.post("/data-auth")
        async def post_data_auth(request: Request):
            """Protected endpoint that requires auth token (sig=jwt)."""
            try:
                return await self._handle_protected_request(request, "POST", require_auth_token=True)
            except Exception as e:
                if _is_debug_enabled():
                    import sys
                    import traceback
                    print(f"DEBUG RESOURCE: Exception in post_data_auth: {e}", file=sys.stderr, flush=True)
                    traceback.print_exc()
                return JSONResponse(
                    status_code=500,
                    content={"error": "internal_error", "error_description": str(e)}
                )

        @self.app.get("/data-chain-auth")
        async def get_data_chain_auth(request: Request):
            """Protected endpoint that chains downstream interaction via this resource."""
            return await self._handle_chained_request(request, "GET")
        
        @self.app.get("/.well-known/aauth-resource")
        @self.app.get("/.well-known/aauth-resource.json")
        async def resource_metadata():
            """Resource metadata endpoint per AAuth spec Section 13.3."""
            jwks_uri = f"{self.resource_id}/jwks.json"
            resource_token_endpoint = f"{self.resource_id}/resource/token"
            metadata = generate_resource_metadata(
                resource_id=self.resource_id,
                jwks_uri=jwks_uri,
                resource_token_endpoint=resource_token_endpoint,
                scope_descriptions={
                    "data.read": "Read access to your data",
                    "data.write": "Write access to your data",
                },
            )
            return metadata

        @self.app.get("/.well-known/aauth-agent")
        @self.app.get("/.well-known/aauth-agent.json")
        async def agent_metadata():
            """Agent metadata endpoint for call chaining.

            Per spec: resources acting as agents MUST publish agent metadata
            at /.well-known/aauth-agent.json so downstream resources and
            auth servers can verify identity.
            """
            from aauth.metadata.agent import generate_agent_metadata
            jwks_uri = f"{self.resource_id}/jwks.json"
            return generate_agent_metadata(self.resource_id, jwks_uri)
        
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

        @self.app.get("/pending/{pending_id}")
        async def chained_pending_get(pending_id: str):
            """Agent polls this pending URL while Resource chains downstream interaction."""
            return await self._handle_chained_pending_get(pending_id)

        @self.app.get("/interact")
        async def chained_interact(request: Request):
            """User interaction endpoint that redirects to downstream auth server interaction."""
            return await self._handle_chained_interact(request)
    
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
        
        # Helper function to build appropriate AAuth challenge based on endpoint requirements
        # Per SPEC_UPDATED.md Section 4:
        # - require=pseudonym = any signature scheme (pseudonymous) - Section 4.1
        # - require=identity = requires identity (jwks, x509, or jwt with agent token) - Section 4.2
        # - require=auth-token; resource-token="..."; auth-server="..." = requires authorization - Section 4.3
        def build_aauth_challenge():
            """Build AAuth challenge value based on endpoint requirements."""
            if require_auth_token:
                # For auth token endpoints, we need agent identity first to issue resource token
                # So challenge for identity, then we can issue resource token on retry
                return "requirement=identity"
            elif required_scheme in ("jwks", "jwks_uri"):
                return "requirement=identity"
            elif required_scheme == "jwt":
                # Shouldn't happen (handled by require_auth_token), but fallback
                return "requirement=identity"
            else:
                # required_scheme == "hwk" or None - any signature is fine
                return "requirement=pseudonym"
        
        if not signature_input_header or not signature_header or not signature_key_header:
            agent_auth_value = build_aauth_challenge()
            
            response = Response(
                status_code=401,
                headers={"Signature-Requirement": agent_auth_value},
                content="Missing signature headers"
            )
            if _is_http_debug_enabled():
                self._print_response_debug(response)
            return response
        
        # Parse signature key to determine scheme
        try:
            parsed_key = parse_signature_key(signature_key_header)
        except Exception as e:
            agent_auth_value = build_aauth_challenge()
            
            response = Response(
                status_code=401,
                headers={"Signature-Requirement": agent_auth_value},
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
            # Phase 6: When identity is required (required_scheme in ("jwks", "jwks_uri")), also accept scheme=jwt with agent token
            if required_scheme and scheme != required_scheme:
                # Phase 6: Check if scheme=jwt contains an agent token (acceptable for identity requirement)
                if required_scheme in ("jwks", "jwks_uri") and scheme == "jwt":
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
                                
                                agent_auth_value = "requirement=identity"
                                response = Response(
                                    status_code=401,
                                    headers={"Signature-Requirement": agent_auth_value},
                                    content=f"Invalid signature scheme: expected {required_scheme}, got {scheme}"
                                )
                                if _is_http_debug_enabled():
                                    self._print_response_debug(response)
                                return response
                        except Exception as e:
                            # Failed to parse token, reject
                            if _is_debug_enabled():
                                print(f"DEBUG RESOURCE: Failed to parse JWT token: {e}", file=sys.stderr, flush=True)
                            
                            agent_auth_value = "requirement=identity"
                            response = Response(
                                status_code=401,
                                headers={"Signature-Requirement": agent_auth_value},
                                content=f"Invalid signature scheme: expected {required_scheme}, got {scheme}"
                            )
                            if _is_http_debug_enabled():
                                self._print_response_debug(response)
                            return response
                    else:
                        # No jwt parameter, reject
                        if _is_debug_enabled():
                            print(f"DEBUG RESOURCE: Scheme mismatch - required={required_scheme}, got={scheme} (no jwt parameter)", file=sys.stderr, flush=True)
                        
                        agent_auth_value = "requirement=identity"
                        response = Response(
                            status_code=401,
                            headers={"Signature-Requirement": agent_auth_value},
                            content=f"Invalid signature scheme: expected {required_scheme}, got {scheme}"
                        )
                        if _is_http_debug_enabled():
                            self._print_response_debug(response)
                        return response
                else:
                    # Not the special case, reject normally
                    if _is_debug_enabled():
                        print(f"DEBUG RESOURCE: Scheme mismatch - required={required_scheme}, got={scheme}", file=sys.stderr, flush=True)
                    
                    # Build appropriate AAuth challenge based on required scheme
                    # Per SPEC_UPDATED.md Section 4:
                    # - require=pseudonym = any scheme (pseudonymous)
                    # - require=identity = requires identity (jwks, x509, or jwt with agent token)
                    # - require=auth-token = requires authorization (jwt with auth token)
                    if required_scheme in ("jwks", "jwks_uri"):
                        agent_auth_value = "requirement=identity"
                    elif required_scheme == "jwt":
                        # This shouldn't happen here (handled by require_auth_token above)
                        # But if it does, we'd need resource_token and auth_server
                        agent_auth_value = "requirement=identity"  # Fallback to identity requirement
                    else:
                        # required_scheme == "hwk" or None - any signature is fine
                        agent_auth_value = "requirement=pseudonym"
                    
                    response = Response(
                        status_code=401,
                        headers={"Signature-Requirement": agent_auth_value},
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
                    headers={"Signature-Requirement": "requirement=pseudonym"},
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
        
        elif scheme in ("jwks", "jwks_uri"):
            # Extract agent_id, kid, and optional well-known from Signature-Key
            agent_id = params.get("id")
            kid = params.get("kid")
            jwks_param = params.get("jwks")

            # Per spec: jwks parameter MUST NOT be present
            if jwks_param:
                response = Response(
                    status_code=401,
                    headers={"Signature-Requirement": "requirement=identity"},
                    content="Invalid Signature-Key: jwks parameter must not be present for sig=jwks"
                )
                if _is_http_debug_enabled():
                    self._print_response_debug(response)
                return response

            if not agent_id or not kid:
                response = Response(
                    status_code=401,
                    headers={"Signature-Requirement": "requirement=identity"},
                    content="Missing id or kid in Signature-Key for sig=jwks"
                )
                if _is_http_debug_enabled():
                    self._print_response_debug(response)
                return response

            if _is_debug_enabled():
                print(f"DEBUG RESOURCE: sig=jwks - agent_id={agent_id}, kid={kid}", file=sys.stderr, flush=True)

            # Create jwks_fetcher callback
            def jwks_fetcher(agent_id_param: str, kid_param: Optional[str] = None):
                if not kid_param:
                    kid_param = params.get("kid")  # Use kid from params if not provided
                return self._fetch_jwks_for_agent(agent_id_param, kid_param)
            
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
                    headers={"Signature-Requirement": "requirement=pseudonym"},
                    content="Invalid signature"
                )
                if _is_http_debug_enabled():
                    self._print_response_debug(response)
                return response
            
            # Signature valid - return data
            response = JSONResponse({
                "message": "Access granted",
                "data": "This is protected data",
                "scheme": "jwks_uri",
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
                    headers={"Signature-Requirement": "requirement=identity"},
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
                    headers={"Signature-Requirement": "requirement=identity"},
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
                        headers={"Signature-Requirement": "requirement=identity"},
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
                        headers={"Signature-Requirement": "requirement=auth-token"},
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
                    headers={"Signature-Requirement": "requirement=identity"},
                    content=f"Unsupported token type: {typ}"
                )
                if _is_http_debug_enabled():
                    self._print_response_debug(response)
                return response
        
        else:
            response = Response(
                status_code=401,
                headers={"Signature-Requirement": "requirement=pseudonym"},
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
            Response with AAuth header containing resource-token
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
        
        if scheme in ("jwks", "jwks_uri"):
            agent_id = params.get("id")
            if agent_id:
                # Fetch agent's JWKS to calculate thumbprint
                kid = params.get("kid")
                agent_jwks = self._fetch_jwks_for_agent(agent_id, kid)
                if agent_jwks:
                    # Extract the matching key from JWKS
                    keys = agent_jwks.get("keys", [])
                    agent_jwk = None
                    for key in keys:
                        if key.get("kid") == kid:
                            agent_jwk = key
                            break
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
                headers={"Signature-Requirement": "requirement=identity"},
                content="Agent identity required for authorization"
            )
        
        # Issue resource token
        scope = "data.read data.write"  # Default scope for Phase 3
        resource_token = self._issue_resource_token(agent_id, agent_jkt, scope)
        
        if _is_debug_enabled():
            print(f"DEBUG RESOURCE: Issued resource token for agent_id={agent_id}, agent_jkt={agent_jkt[:20]}...", file=sys.stderr, flush=True)
        
        # Build AAuth challenge header
        aauth_header = f'requirement=auth-token; resource-token="{resource_token}"'

        response = Response(
            status_code=401,
            headers={"Signature-Requirement": aauth_header},
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
            exp=exp,
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
            from aauth.tokens.auth_token import verify_token
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
                # For testing: map example.com URLs to localhost if server is running locally
                # This handles cases where token has example.com URL but server is on localhost
                metadata_url = f"{issuer_url}/.well-known/aauth-agent"
                
                # Try to fetch metadata, but if it fails and issuer_url contains example.com,
                # try mapping to localhost (common in test scenarios)
                try:
                    metadata = fetch_metadata(metadata_url)
                except Exception:
                    # If fetch fails and URL contains example.com, try localhost mapping
                    if "example.com" in issuer_url or issuer_url.startswith("https://agent"):
                        # Try common localhost ports
                        for port in [8001, 8000, 8080]:
                            try:
                                local_url = f"http://127.0.0.1:{port}"
                                local_metadata_url = f"{local_url}/.well-known/aauth-agent"
                                metadata = fetch_metadata(local_metadata_url)
                                # If successful, update jwks_uri to use local URL
                                jwks_uri = metadata.get("jwks_uri")
                                if jwks_uri and "example.com" in jwks_uri:
                                    jwks_uri = f"{local_url}/jwks.json"
                                break
                            except:
                                continue
                        else:
                            raise
                    else:
                        raise
                
                jwks_uri = metadata.get("jwks_uri")
                if not jwks_uri:
                    return None
                
                # Map jwks_uri to localhost if it contains example.com
                if "example.com" in jwks_uri:
                    # Extract port from issuer_url if possible, otherwise use 8001
                    port = 8001
                    if "127.0.0.1:" in issuer_url or "localhost:" in issuer_url:
                        try:
                            from urllib.parse import urlparse
                            parsed = urlparse(issuer_url)
                            if parsed.port:
                                port = parsed.port
                        except:
                            pass
                    jwks_uri = f"http://127.0.0.1:{port}/jwks.json"
                
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
            from aauth.tokens.agent_token import verify_agent_token
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
            from aauth.keys.jwk import jwk_to_public_key
            delegate_public_key = jwk_to_public_key(cnf_jwk)
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE:   Converted cnf.jwk to public key", file=sys.stderr, flush=True)
        except Exception as e:
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE:   Failed to convert cnf.jwk to public key: {e}", file=sys.stderr, flush=True)
            return False, None
        
        # Step 4: Verify HTTPSig signature using delegate's public key
        # For sig=jwt, verify_signature will validate the agent token JWT and extract cnf.jwk
        # We've already validated the token, but verify_signature needs the agent server's JWKS
        # to validate the JWT signature, then it will extract cnf.jwk and verify HTTPSig.
        # Use the agent_jwks_fetcher we created earlier (it returns agent server's JWKS)
        if _is_debug_enabled():
            print(f"DEBUG RESOURCE:   Calling verify_signature with jwks_fetcher={agent_jwks_fetcher}", file=sys.stderr, flush=True)
        
        is_valid = verify_signature(
            method=method,
            target_uri=target_uri,
            headers=headers_dict,
            body=body,
            signature_input_header=signature_input_header,
            signature_header=signature_header,
            signature_key_header=signature_key_header,
            jwks_fetcher=agent_jwks_fetcher
        )
        
        if not is_valid:
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE:   HTTPSig signature verification FAILED", file=sys.stderr, flush=True)
            return False, None
        
        if _is_debug_enabled():
            print(f"DEBUG RESOURCE:   HTTPSig signature verification PASSED", file=sys.stderr, flush=True)
        
        return True, claims
    
    def _fetch_jwks_for_agent(self, agent_id: str, kid: str) -> Optional[Dict[str, Any]]:
        """Fetch JWKS for an agent via metadata discovery.

        Per SPEC_UPDATED.md, agents publish metadata at the fixed path
        /.well-known/aauth-agent.json which contains jwks_uri.

        Args:
            agent_id: Agent identifier (HTTPS URL)
            kid: Key identifier

        Returns:
            JWKS document (dict with "keys" array) if found, None otherwise

        Discovery procedure:
        1. Fetch metadata from {agent_id}/.well-known/aauth-agent.json
        2. Extract jwks_uri from metadata
        3. Fetch JWKS from jwks_uri
        4. Verify key with matching kid exists
        """
        import sys

        if _is_debug_enabled():
            print(f"DEBUG RESOURCE: Fetching JWKS for agent_id={agent_id}, kid={kid}", file=sys.stderr, flush=True)

        try:
            # Step 1: Fetch agent metadata from fixed well-known path
            metadata_url = f"{agent_id}/.well-known/aauth-agent.json"
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

            # Step 3: Fetch JWKS from jwks_uri
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE: Fetching JWKS from {jwks_uri}", file=sys.stderr, flush=True)

            jwks_response = httpx.get(jwks_uri, timeout=10.0)
            jwks_response.raise_for_status()
            jwks_doc = jwks_response.json()

            if _is_debug_enabled():
                print(f"DEBUG RESOURCE: JWKS received: {jwks_doc}", file=sys.stderr, flush=True)

            # Step 4: Verify key exists if kid is provided
            if kid:
                keys = jwks_doc.get("keys", [])
                key_found = False
                for key in keys:
                    if key.get("kid") == kid:
                        key_found = True
                        if _is_debug_enabled():
                            print(f"DEBUG RESOURCE: Found key with kid={kid}", file=sys.stderr, flush=True)
                        break

                if not key_found:
                    if _is_debug_enabled():
                        print(f"DEBUG RESOURCE: Key with kid={kid} not found in JWKS", file=sys.stderr, flush=True)
                    return None

            # Return full JWKS document (verifier will extract the key it needs)
            return jwks_doc

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
                headers={"Signature-Requirement": "requirement=identity"},
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
                headers={"Signature-Requirement": "requirement=identity"},
                content={"error": "invalid_request", "error_description": f"Invalid Signature-Key: {e}"}
            )
        
        # Require sig=jwks for resource token endpoint (agent identity required)
        if scheme not in ("jwks", "jwks_uri"):
            return JSONResponse(
                status_code=401,
                headers={"Signature-Requirement": "requirement=identity"},
                content={"error": "invalid_request", "error_description": "Resource token endpoint requires sig=jwks"}
            )
        
        # Extract agent identity
        agent_id = key_params.get("id")
        if not agent_id:
            return JSONResponse(
                status_code=401,
                headers={"Signature-Requirement": "requirement=identity"},
                content={"error": "invalid_request", "error_description": "Could not extract agent identifier"}
            )
        
        # Verify signature
        target_uri = str(request.url)
        def jwks_fetcher(agent_id_param: str, kid_param: Optional[str] = None):
            if not kid_param:
                kid_param = key_params.get("kid")  # Use kid from params if not provided
            return self._fetch_jwks_for_agent(agent_id_param, kid_param)
        
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
                headers={"Signature-Requirement": "requirement=identity"},
                content={"error": "invalid_signature", "error_description": "Signature verification failed"}
            )
        
        # Get agent's key for agent_jkt calculation
        kid = key_params.get("kid")
        agent_jwks = self._fetch_jwks_for_agent(agent_id, kid)
        if not agent_jwks:
            return JSONResponse(
                status_code=500,
                content={"error": "server_error", "error_description": "Failed to fetch agent JWKS"}
            )
        
        # Extract the matching key from JWKS
        keys = agent_jwks.get("keys", [])
        agent_jwk = None
        for key in keys:
            if key.get("kid") == kid:
                agent_jwk = key
                break
        
        if not agent_jwk:
            return JSONResponse(
                status_code=500,
                content={"error": "server_error", "error_description": f"Key with kid={kid} not found in JWKS"}
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
    
    async def call_downstream_resource(
        self,
        downstream_url: str,
        method: str = "GET",
        upstream_auth_token: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None
    ) -> httpx.Response:
        """Act as agent to call a downstream resource (Phase 7: Token Exchange).
        
        When this resource needs to call a downstream resource to fulfill a request,
        it uses the upstream auth token to obtain a new token via token exchange.
        
        Args:
            downstream_url: URL of the downstream resource
            method: HTTP method
            upstream_auth_token: Auth token from the upstream request
            headers: Optional request headers
            body: Optional request body
            
        Returns:
            Response from downstream resource
        """
        debug = _is_debug_enabled()
        http_debug = _is_http_debug_enabled()
        
        if headers is None:
            headers = {}
        
        if body is None:
            body = b""
        
        if debug:
            print(f"DEBUG RESOURCE: Acting as agent to call downstream resource", file=sys.stderr, flush=True)
            print(f"DEBUG RESOURCE:   Downstream URL: {downstream_url}", file=sys.stderr, flush=True)
            print(f"DEBUG RESOURCE:   Method: {method}", file=sys.stderr, flush=True)
            if upstream_auth_token:
                print(f"DEBUG RESOURCE:   Upstream auth token: {upstream_auth_token[:100]}...", file=sys.stderr, flush=True)
        
        # Step 1: Send signed request with identity (scheme=jwks) to trigger resource_token challenge
        from aauth.signing.signer import sign_request
        
        # Sign the initial request with this resource's identity (scheme=jwks)
        # Note: "well-known" uses hyphen as the kwarg key (Python allows this with **kwargs)
        sig_headers = sign_request(
            method=method,
            target_uri=downstream_url,
            headers=dict(headers),
            body=body,
            private_key=self.private_key,
            sig_scheme="jwks_uri",
            id=self.resource_id,
            kid=self.kid,
        )
        
        initial_headers = {**headers, **sig_headers}
        
        if debug:
            print(f"DEBUG RESOURCE:   Sending initial request with scheme=jwks", file=sys.stderr, flush=True)
        
        async with httpx.AsyncClient() as client:
            initial_response = await client.request(
                method=method,
                url=downstream_url,
                headers=initial_headers,
                content=body
            )
        
        if initial_response.status_code != 401:
            # Either access granted or error (not auth challenge)
            if debug:
                print(f"DEBUG RESOURCE:   Downstream resource returned {initial_response.status_code}", file=sys.stderr, flush=True)
            return initial_response
        
        # Parse AAuth challenge from response (with Agent-Auth fallback)
        aauth_header = initial_response.headers.get("Signature-Requirement", "") or initial_response.headers.get("AAuth", "") or initial_response.headers.get("Agent-Auth", "")
        if debug:
            print(f"DEBUG RESOURCE:   Received AAuth challenge: {aauth_header}", file=sys.stderr, flush=True)

        # Extract resource-token from challenge
        # New format: requirement=auth-token; resource-token="..."
        # Old format: httpsig; auth-token; resource_token="..."; auth_server="..."
        import re
        resource_token_match = re.search(r'resource[-_]token="([^"]+)"', aauth_header)

        if not resource_token_match:
            if debug:
                print(f"DEBUG RESOURCE:   No resource_token in challenge (may be identity challenge)", file=sys.stderr, flush=True)
            return initial_response

        resource_token = resource_token_match.group(1)

        # Discover auth server from resource token aud claim, fall back to header
        auth_server_match = re.search(r'auth[-_]server="([^"]+)"', aauth_header)
        auth_server = auth_server_match.group(1) if auth_server_match else None
        if not auth_server:
            try:
                import jwt as jwt_lib
                rt_payload = jwt_lib.decode(resource_token, options={"verify_signature": False})
                auth_server = rt_payload.get("aud")
            except Exception:
                pass

        if debug:
            print(f"DEBUG RESOURCE:   Resource token: {resource_token[:100]}...", file=sys.stderr, flush=True)
            print(f"DEBUG RESOURCE:   Auth server: {auth_server}", file=sys.stderr, flush=True)

        if not auth_server:
            if debug:
                print(f"DEBUG RESOURCE:   No auth_server discoverable from challenge or resource token", file=sys.stderr, flush=True)
            return initial_response
        
        if not upstream_auth_token:
            if debug:
                print(f"DEBUG RESOURCE:   No upstream auth token available for exchange", file=sys.stderr, flush=True)
            return initial_response
        
        # Step 2: Exchange upstream token for downstream token
        exchange_token = await self._exchange_token(
            auth_server=auth_server,
            resource_token=resource_token,
            upstream_auth_token=upstream_auth_token
        )
        
        if not exchange_token:
            if debug:
                print(f"DEBUG RESOURCE:   Token exchange failed", file=sys.stderr, flush=True)
            return initial_response
        
        if debug:
            print(f"DEBUG RESOURCE:   Token exchange successful: {exchange_token[:100]}...", file=sys.stderr, flush=True)
        
        # Step 3: Access downstream resource with new token
        from aauth.signing.signer import sign_request
        
        # Sign request with scheme=jwt using the exchanged token
        sig_headers = sign_request(
            method=method,
            target_uri=downstream_url,
            headers=dict(headers),
            body=body,
            private_key=self.private_key,
            sig_scheme="jwt",
            jwt=exchange_token
        )
        
        # Add signature headers to request
        request_headers = {**headers, **sig_headers}
        
        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print(f">>> RESOURCE (as agent) REQUEST to {downstream_url}", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"{method} {downstream_url} HTTP/1.1", file=sys.stderr)
            for name, value in sorted(request_headers.items()):
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
        
        # Make final request with auth token
        async with httpx.AsyncClient() as client:
            final_response = await client.request(
                method=method,
                url=downstream_url,
                headers=request_headers,
                content=body
            )
        
        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print(f"<<< DOWNSTREAM RESPONSE from {downstream_url}", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"HTTP/1.1 {final_response.status_code} {final_response.reason_phrase}", file=sys.stderr)
            for name, value in sorted(final_response.headers.items()):
                display_value = value
                if len(display_value) > 100:
                    display_value = display_value[:97] + "..."
                print(f"{name}: {display_value}", file=sys.stderr)
            if final_response.content:
                print(f"\n[Body ({len(final_response.content)} bytes)]", file=sys.stderr)
                try:
                    print(final_response.text, file=sys.stderr)
                except:
                    print(f"[Binary body: {len(final_response.content)} bytes]", file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)
        
        return final_response
    
    async def _exchange_token(
        self,
        auth_server: str,
        resource_token: str,
        upstream_auth_token: str
    ) -> Optional[str]:
        """Exchange upstream auth token for downstream auth token (Phase 7).
        
        Args:
            auth_server: Downstream auth server URL
            resource_token: Resource token from downstream resource's challenge
            upstream_auth_token: Auth token from upstream request
            
        Returns:
            Downstream auth token, or None if exchange failed
        """
        debug = _is_debug_enabled()
        http_debug = _is_http_debug_enabled()
        
        if debug:
            print(f"DEBUG RESOURCE: Exchanging token", file=sys.stderr, flush=True)
            print(f"DEBUG RESOURCE:   Auth server: {auth_server}", file=sys.stderr, flush=True)
        
        # Build exchange request (call chaining: resource_token + upstream_token)
        token_endpoint = f"{auth_server}/token"
        request_data = {
            "resource_token": resource_token,
            "upstream_token": upstream_auth_token
        }
        request_body = json.dumps(request_data)
        request_body_bytes = request_body.encode('utf-8')

        from aauth.signing.signer import sign_request

        # Build base headers - sign_request will add Content-Digest to this dict
        base_headers = {"Content-Type": "application/json"}
        
        # Sign request with scheme=jwt using upstream auth token
        # Note: sign_request modifies base_headers to add Content-Digest
        sig_headers = sign_request(
            method="POST",
            target_uri=token_endpoint,
            headers=base_headers,
            body=request_body_bytes,
            private_key=self.private_key,
            sig_scheme="jwt",
            jwt=upstream_auth_token
        )
        
        # Combine base headers (now includes Content-Digest) with signature headers
        request_headers = {
            **base_headers,
            **sig_headers
        }
        
        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print(f">>> TOKEN EXCHANGE REQUEST to {token_endpoint}", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"POST {token_endpoint} HTTP/1.1", file=sys.stderr)
            for name, value in sorted(request_headers.items()):
                display_value = value
                if len(display_value) > 100:
                    display_value = display_value[:97] + "..."
                print(f"{name}: {display_value}", file=sys.stderr)
            print(f"\n[Body ({len(request_body_bytes)} bytes)]", file=sys.stderr)
            print(request_body, file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)
        
        # Make exchange request
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_endpoint,
                headers=request_headers,
                content=request_body_bytes
            )
        
        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print(f"<<< TOKEN EXCHANGE RESPONSE from {token_endpoint}", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"HTTP/1.1 {response.status_code} {response.reason_phrase}", file=sys.stderr)
            for name, value in sorted(response.headers.items()):
                display_value = value
                if len(display_value) > 100:
                    display_value = display_value[:97] + "..."
                print(f"{name}: {display_value}", file=sys.stderr)
            if response.content:
                print(f"\n[Body ({len(response.content)} bytes)]", file=sys.stderr)
                try:
                    print(response.text, file=sys.stderr)
                except:
                    print(f"[Binary body: {len(response.content)} bytes]", file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)
        
        if response.status_code != 200:
            if debug:
                print(f"DEBUG RESOURCE:   Token exchange failed: {response.status_code}", file=sys.stderr, flush=True)
                try:
                    error_data = response.json()
                    print(f"DEBUG RESOURCE:   Error: {json.dumps(error_data, indent=2)}", file=sys.stderr, flush=True)
                except:
                    print(f"DEBUG RESOURCE:   Error: {response.text}", file=sys.stderr, flush=True)
            return None
        
        # Parse response
        try:
            response_data = response.json()
            auth_token = response_data.get("auth_token")
            
            if debug:
                print(f"DEBUG RESOURCE:   Token exchange successful", file=sys.stderr, flush=True)
                if auth_token:
                    print(f"DEBUG RESOURCE:   Auth token: {auth_token[:100]}...", file=sys.stderr, flush=True)
            
            return auth_token
        except Exception as e:
            if debug:
                print(f"DEBUG RESOURCE:   Failed to parse response: {e}", file=sys.stderr, flush=True)
            return None

    async def _request_downstream_authorization(
        self,
        downstream_url: str,
        upstream_auth_token: str,
        method: str = "GET",
    ) -> Dict[str, Any]:
        """Request downstream authorization token or deferred interaction details."""
        # Step 1: get challenge from downstream resource
        sig_headers = sign_request(
            method=method,
            target_uri=downstream_url,
            headers={},
            body=b"",
            private_key=self.private_key,
            sig_scheme="jwks_uri",
            id=self.resource_id,
            kid=self.kid,
        )
        async with httpx.AsyncClient() as client:
            challenge_response = await client.request(method=method, url=downstream_url, headers=sig_headers)

        if challenge_response.status_code != 401:
            return {"mode": "final_response", "response": challenge_response}

        aauth_header = challenge_response.headers.get("Signature-Requirement", "") or challenge_response.headers.get("AAuth", "") or challenge_response.headers.get("Agent-Auth", "")
        import re
        resource_token_match = re.search(r'resource[-_]token="([^"]+)"', aauth_header)
        if not resource_token_match:
            return {"mode": "final_response", "response": challenge_response}

        resource_token = resource_token_match.group(1)
        # Discover auth server from resource token aud claim, fall back to header
        auth_server_match = re.search(r'auth[-_]server="([^"]+)"', aauth_header)
        auth_server = auth_server_match.group(1) if auth_server_match else None
        if not auth_server:
            try:
                import jwt as jwt_lib
                rt_payload = jwt_lib.decode(resource_token, options={"verify_signature": False})
                auth_server = rt_payload.get("aud")
            except Exception:
                pass
        if not auth_server:
            return {"mode": "final_response", "response": challenge_response}
        token_endpoint = f"{auth_server}/token"
        request_data = {"resource_token": resource_token, "upstream_token": upstream_auth_token}
        request_body = json.dumps(request_data).encode("utf-8")
        base_headers = {"Content-Type": "application/json"}
        token_sig_headers = sign_request(
            method="POST",
            target_uri=token_endpoint,
            headers=base_headers,
            body=request_body,
            private_key=self.private_key,
            sig_scheme="jwt",
            jwt=upstream_auth_token,
        )
        token_headers = {**base_headers, **token_sig_headers}

        async with httpx.AsyncClient() as client:
            token_response = await client.post(token_endpoint, headers=token_headers, content=request_body)

        if token_response.status_code == 200:
            token_data = token_response.json()
            return {"mode": "token", "auth_token": token_data.get("auth_token")}

        if token_response.status_code == 202:
            body = token_response.json()
            pending_url = body.get("location") or token_response.headers.get("location")
            code = body.get("code")
            metadata = fetch_metadata(f"{auth_server}/.well-known/aauth-issuer")
            interaction_endpoint = metadata.get("interaction_endpoint")
            return {
                "mode": "deferred",
                "downstream_pending_url": pending_url,
                "downstream_code": code,
                "downstream_interaction_endpoint": interaction_endpoint,
            }

        return {"mode": "final_response", "response": token_response}

    async def _handle_chained_request(self, request: Request, method: str) -> Response:
        """Handle Resource1->Resource2 interaction chaining and bubble 202 via Resource1."""
        # First validate upstream auth token as normal
        auth_result = await self._handle_protected_request(request, method, require_auth_token=True)
        if auth_result.status_code != 200:
            return auth_result
        if not self.downstream_resource_url:
            return JSONResponse(status_code=500, content={"error": "server_error", "error_description": "Missing downstream_resource_url"})

        signature_key_header = request.headers.get("Signature-Key", "")
        try:
            parsed_key = parse_signature_key(signature_key_header)
            upstream_auth_token = parsed_key["params"].get("jwt")
        except Exception:
            upstream_auth_token = None
        if not upstream_auth_token:
            return JSONResponse(status_code=401, content={"error": "invalid_request", "error_description": "Missing upstream auth token"})

        downstream_authz = await self._request_downstream_authorization(
            downstream_url=self.downstream_resource_url,
            upstream_auth_token=upstream_auth_token,
            method="GET",
        )

        if downstream_authz["mode"] == "token":
            auth_token = downstream_authz.get("auth_token")
            if not auth_token:
                return JSONResponse(status_code=500, content={"error": "server_error", "error_description": "Missing downstream auth token"})
            sig_headers = sign_request(
                method="GET",
                target_uri=self.downstream_resource_url,
                headers={},
                body=b"",
                private_key=self.private_key,
                sig_scheme="jwt",
                jwt=auth_token,
            )
            async with httpx.AsyncClient() as client:
                final_response = await client.get(self.downstream_resource_url, headers=sig_headers)
            return JSONResponse(status_code=final_response.status_code, content=final_response.json())

        if downstream_authz["mode"] == "deferred":
            pending_id = generate_pending_id()
            interaction_code = generate_interaction_code()
            local_pending_url = f"{self.resource_id}/pending/{pending_id}"
            self.chained_pending_requests[pending_id] = {
                "status": "pending",
                "local_interaction_code": interaction_code,
                "downstream_pending_url": downstream_authz.get("downstream_pending_url"),
                "downstream_code": downstream_authz.get("downstream_code"),
                "downstream_interaction_endpoint": downstream_authz.get("downstream_interaction_endpoint"),
                "downstream_url": self.downstream_resource_url,
                "created_at": int(time.time()),
                "expires_at": int(time.time()) + 600,
            }
            body = build_pending_response_body(
                location=local_pending_url,
                require="interaction",
                code=interaction_code,
            )
            body["interaction_endpoint"] = f"{self.resource_id}/interact"
            headers = build_pending_response_headers(
                location=local_pending_url,
                retry_after=2,
                require="interaction",
                code=interaction_code,
            )
            return Response(content=json.dumps(body), status_code=202, headers=headers, media_type="application/json")

        final_resp = downstream_authz.get("response")
        if final_resp is None:
            return JSONResponse(status_code=500, content={"error": "server_error"})
        try:
            return JSONResponse(status_code=final_resp.status_code, content=final_resp.json())
        except Exception:
            return Response(status_code=final_resp.status_code, content=final_resp.text)

    async def _handle_chained_pending_get(self, pending_id: str) -> Response:
        """Poll downstream pending URL and return terminal response to the original agent."""
        pending = self.chained_pending_requests.get(pending_id)
        if not pending:
            return JSONResponse(status_code=404, content={"error": "not_found"})
        if int(time.time()) >= pending.get("expires_at", 0):
            del self.chained_pending_requests[pending_id]
            return JSONResponse(status_code=408, content={"error": "expired", "error_description": "Request expired"})

        downstream_pending_url = pending.get("downstream_pending_url")
        if not downstream_pending_url:
            return JSONResponse(status_code=500, content={"error": "server_error", "error_description": "Missing downstream pending URL"})

        sig_headers = sign_request(
            method="GET",
            target_uri=downstream_pending_url,
            headers={},
            body=b"",
            private_key=self.private_key,
            sig_scheme="jwks_uri",
            id=self.resource_id,
            kid=self.kid,
        )
        async with httpx.AsyncClient() as client:
            downstream_poll = await client.get(downstream_pending_url, headers=sig_headers)

        if downstream_poll.status_code == 202:
            local_pending_url = f"{self.resource_id}/pending/{pending_id}"
            body = build_pending_response_body(location=local_pending_url)
            headers = build_pending_response_headers(location=local_pending_url, retry_after=2)
            return Response(content=json.dumps(body), status_code=202, headers=headers, media_type="application/json")

        if downstream_poll.status_code == 200:
            data = downstream_poll.json()
            auth_token = data.get("auth_token")
            if not auth_token:
                return JSONResponse(status_code=500, content={"error": "server_error", "error_description": "Missing downstream auth token"})
            sig_headers = sign_request(
                method="GET",
                target_uri=pending["downstream_url"],
                headers={},
                body=b"",
                private_key=self.private_key,
                sig_scheme="jwt",
                jwt=auth_token,
            )
            async with httpx.AsyncClient() as client:
                final_response = await client.get(pending["downstream_url"], headers=sig_headers)
            del self.chained_pending_requests[pending_id]
            return JSONResponse(status_code=final_response.status_code, content=final_response.json())

        if downstream_poll.status_code in (403, 408, 410):
            del self.chained_pending_requests[pending_id]
            try:
                return JSONResponse(status_code=downstream_poll.status_code, content=downstream_poll.json())
            except Exception:
                return Response(status_code=downstream_poll.status_code, content=downstream_poll.text)

        return JSONResponse(status_code=500, content={"error": "server_error", "error_description": "Unexpected downstream pending response"})

    async def _handle_chained_interact(self, request: Request) -> Response:
        """Redirect user from Resource1 interaction endpoint to downstream auth interaction endpoint."""
        code = request.query_params.get("code")
        if not code:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "Missing code"})
        selected = None
        for _, details in self.chained_pending_requests.items():
            if details.get("local_interaction_code") == code:
                selected = details
                break
        if not selected:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "Invalid code"})

        interaction_endpoint = selected.get("downstream_interaction_endpoint")
        downstream_code = selected.get("downstream_code")
        if not interaction_endpoint or not downstream_code:
            return JSONResponse(status_code=500, content={"error": "server_error", "error_description": "Downstream interaction unavailable"})
        return RedirectResponse(url=f"{interaction_endpoint}?code={downstream_code}", status_code=303)
    
    def run(self):
        """Run the resource server."""
        import uvicorn
        uvicorn.run(self.app, host="0.0.0.0", port=self.port)


if __name__ == "__main__":
    resource = Resource("https://resource.example", port=8002)
    resource.run()

