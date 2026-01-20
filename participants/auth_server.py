"""Auth server participant - issues auth tokens for autonomous authorization."""

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any, List
import sys
import os
import json
import time
from urllib.parse import urlparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aauth.signing.verifier import verify_signature
from aauth.headers.signature_key import parse_signature_key
from aauth.keys.keypair import generate_ed25519_keypair
from aauth.keys.jwk import public_key_to_jwk, generate_jwks, jwk_to_public_key, calculate_jwk_thumbprint
from aauth.metadata.auth_server import generate_auth_metadata, fetch_metadata as fetch_resource_metadata
from aauth.tokens.auth_token import verify_token, create_auth_token
from core import _is_debug_enabled, _is_http_debug_enabled


class AuthServer:
    """Auth server that issues auth tokens for autonomous authorization."""
    
    def __init__(self, auth_id: str, port: int = 8003, require_user_consent: bool = False, trusted_auth_servers: Optional[List[str]] = None):
        """Initialize auth server.
        
        Args:
            auth_id: Auth server identifier (HTTPS URL)
            port: Port to run auth server on
            trusted_auth_servers: List of trusted auth server identifiers for token exchange (Phase 7)
            require_user_consent: If True, require user consent for all requests (Phase 4 demo mode)
        """
        self.auth_id = auth_id
        self.port = port
        self.require_user_consent = require_user_consent
        
        # Generate key pair for signing auth tokens
        self.private_key, self.public_key = generate_ed25519_keypair()
        self.kid = "auth-key-1"
        
        # Phase 4: State management for user consent flows
        self.pending_requests: Dict[str, Dict[str, Any]] = {}  # request_token -> request details
        self.authorization_codes: Dict[str, Dict[str, Any]] = {}  # code -> request details
        self.users: Dict[str, Dict[str, str]] = {  # Simple in-memory user database
            "testuser": {"password": "testpass", "name": "Test User", "email": "testuser@example.com"}
        }
        
        # Phase 7: Federation trust - list of trusted auth servers for token exchange
        # In production, this would be configured via policy or discovered via metadata
        self.trusted_auth_servers: List[str] = trusted_auth_servers if trusted_auth_servers else []
        
        # Create FastAPI app
        self.app = FastAPI(title="AAuth Auth Server")
        
        # Setup routes
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup FastAPI routes."""
        
        @self.app.get("/")
        async def root():
            return {"auth_id": self.auth_id, "status": "running"}
        
        @self.app.get("/jwks.json")
        async def jwks():
            """JWKS endpoint for auth server signing keys."""
            jwk = public_key_to_jwk(self.public_key, kid=self.kid)
            return generate_jwks([jwk])
        
        @self.app.get("/.well-known/aauth-issuer")
        async def metadata():
            """Auth server metadata endpoint per AAuth spec Section 8.2."""
            jwks_uri = f"{self.auth_id}/jwks.json"
            token_endpoint = f"{self.auth_id}/agent/token"
            auth_endpoint = f"{self.auth_id}/agent/auth"
            return generate_auth_metadata(
                auth_id=self.auth_id,
                jwks_uri=jwks_uri,
                token_endpoint=token_endpoint,
                auth_endpoint=auth_endpoint,
                signing_algs_supported=["ed25519"],
                request_types_supported=["auth", "code", "exchange", "refresh"]
            )
        
        @self.app.post("/agent/token")
        async def token_endpoint(request: Request):
            """Token endpoint for autonomous authorization per AAuth spec Section 9.3.
            
            Supports:
            - request_type=auth: Autonomous authorization (Phase 3) or user consent flow (Phase 4)
            - request_type=code: Authorization code exchange (Phase 4)
            """
            return await self._handle_token_request(request)
        
        @self.app.get("/agent/auth")
        async def auth_endpoint_get(request: Request):
            """Authorization endpoint (user-facing) per AAuth spec Section 9.5.
            
            Displays login page (if not authenticated) or consent page.
            """
            return await self._handle_auth_get(request)
        
        @self.app.post("/agent/auth")
        async def auth_endpoint_post(request: Request):
            """Authorization endpoint for login and consent submission per AAuth spec Section 9.5."""
            return await self._handle_auth_post(request)
    
    async def _handle_token_request(self, request: Request) -> Response:
        """Handle token request from agent.
        
        Per AAuth spec Section 9.3, supports request_type=auth for autonomous authorization.
        """
        debug = _is_debug_enabled()
        http_debug = _is_http_debug_enabled()
        
        # Get request body
        body_bytes = await request.body()
        body_text = body_bytes.decode('utf-8') if body_bytes else ""
        
        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print(">>> AUTH SERVER REQUEST received", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"{request.method} {request.url.path} HTTP/1.1", file=sys.stderr)
            for name, value in sorted(request.headers.items()):
                display_value = value
                if len(display_value) > 100:
                    display_value = display_value[:97] + "..."
                print(f"{name}: {display_value}", file=sys.stderr)
            if body_text:
                print(f"\n[Body ({len(body_bytes)} bytes)]", file=sys.stderr)
                print(body_text, file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)
        
        if debug:
            print(f"DEBUG AUTH: Handling token request", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Method: {request.method}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Path: {request.url.path}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Body: {body_text}", file=sys.stderr, flush=True)
        
        # Parse request body (application/x-www-form-urlencoded)
        try:
            from urllib.parse import parse_qs
            params = parse_qs(body_text, keep_blank_values=True)
            # Convert to simple dict (take first value from each list)
            params_dict = {k: v[0] if v else "" for k, v in params.items()}
        except Exception as e:
            if debug:
                print(f"DEBUG AUTH:   Failed to parse request body: {e}", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": f"Failed to parse request body: {e}"}
            )
        
        if debug:
            print(f"DEBUG AUTH:   Parsed parameters: {json.dumps(params_dict, indent=2)}", file=sys.stderr, flush=True)
        
        # Check request_type
        request_type = params_dict.get("request_type")
        
        # Phase 4: Handle authorization code exchange
        if request_type == "code":
            return await self._handle_code_exchange(request, params_dict, body_bytes)
        
        # Phase 7: Handle token exchange
        if request_type == "exchange":
            return await self._handle_token_exchange(request, params_dict, body_bytes)
        
        # Phase 3/4: Handle auth request (autonomous or user consent)
        if request_type != "auth":
            if debug:
                print(f"DEBUG AUTH:   Unsupported request_type: {request_type}", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=400,
                content={"error": "unsupported_request_type", "error_description": f"Unsupported request_type: {request_type}"}
            )
        
        # Verify agent's HTTPSig signature
        headers_dict = dict(request.headers)
        method = request.method
        target_uri = str(request.url)
        
        if debug:
            print(f"DEBUG AUTH:   Verifying agent's HTTPSig signature", file=sys.stderr, flush=True)
        
        # Extract signature headers
        signature_input_header = headers_dict.get("signature-input", "")
        signature_header = headers_dict.get("signature", "")
        signature_key_header = headers_dict.get("signature-key", "")
        
        if not signature_input_header or not signature_header or not signature_key_header:
            if debug:
                print(f"DEBUG AUTH:   Missing signature headers", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": "Missing signature headers"}
            )
        
        # Parse signature key to determine scheme
        try:
            parsed_key = parse_signature_key(signature_key_header)
            scheme = parsed_key["scheme"]
            key_params = parsed_key["params"]
        except Exception as e:
            if debug:
                print(f"DEBUG AUTH:   Failed to parse Signature-Key: {e}", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": f"Invalid Signature-Key: {e}"}
            )
        
        if debug:
            print(f"DEBUG AUTH:   Signature scheme: {scheme}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Key params: {json.dumps(key_params, indent=2)}", file=sys.stderr, flush=True)
        
        # Extract agent identifier from signature
        agent_id = None
        agent_delegate_sub = None  # Phase 6: agent delegation
        agent_jwk = None  # Phase 6: delegate's key from agent token
        
        if scheme == "jwks":
            agent_id = key_params.get("id")
        elif scheme == "jwt":
            # Phase 6: Agent delegation - validate agent token
            jwt_token = key_params.get("jwt")
            if not jwt_token:
                if debug:
                    print(f"DEBUG AUTH:   sig=jwt missing jwt parameter", file=sys.stderr, flush=True)
                return JSONResponse(
                    status_code=401,
                    content={"error": "invalid_request", "error_description": "Missing jwt parameter in Signature-Key"}
                )
            
            # Parse token header to determine type
            try:
                import jwt as jwt_lib
                header = jwt_lib.get_unverified_header(jwt_token)
                typ = header.get("typ")
                
                if debug:
                    print(f"DEBUG AUTH:   JWT token type: {typ}", file=sys.stderr, flush=True)
            except Exception as e:
                if debug:
                    print(f"DEBUG AUTH:   Failed to parse JWT header: {e}", file=sys.stderr, flush=True)
                return JSONResponse(
                    status_code=401,
                    content={"error": "invalid_request", "error_description": f"Invalid JWT token: {e}"}
                )
            
            if typ == "agent+jwt":
                # Phase 6: Agent token (delegated identity)
                if debug:
                    print(f"DEBUG AUTH:   Validating agent token (agent+jwt)", file=sys.stderr, flush=True)
                
                # Create JWKS fetcher for agent server
                def agent_jwks_fetcher(issuer_url: str, kid_param: Optional[str] = None):
                    """Fetch agent server JWKS."""
                    try:
                        from aauth.metadata.auth_server import fetch_metadata
                        import httpx
                        metadata_url = f"{issuer_url}/.well-known/aauth-agent"
                        metadata = fetch_metadata(metadata_url)
                        jwks_uri = metadata.get("jwks_uri")
                        if not jwks_uri:
                            return None
                        
                        jwks_response = httpx.get(jwks_uri, timeout=10.0)
                        jwks_response.raise_for_status()
                        return jwks_response.json()
                    except Exception as e:
                        if debug:
                            print(f"DEBUG AUTH:   Error fetching agent server JWKS: {e}", file=sys.stderr, flush=True)
                        return None
                
                # Verify agent token
                try:
                    from aauth.tokens.agent_token import verify_agent_token
                    agent_claims = verify_agent_token(
                        token=jwt_token,
                        jwks_fetcher=agent_jwks_fetcher,
                        expected_aud=None
                    )
                    
                    # Extract agent identifier and delegate identifier
                    agent_id = agent_claims.get("iss")  # Agent server identifier
                    agent_delegate_sub = agent_claims.get("sub")  # Delegate identifier
                    cnf = agent_claims.get("cnf", {})
                    agent_jwk = cnf.get("jwk")  # Delegate's key for agent_jkt calculation
                    
                    if debug:
                        print(f"DEBUG AUTH:   Agent token validated successfully", file=sys.stderr, flush=True)
                        print(f"DEBUG AUTH:     Agent server (iss): {agent_id}", file=sys.stderr, flush=True)
                        print(f"DEBUG AUTH:     Agent delegate (sub): {agent_delegate_sub}", file=sys.stderr, flush=True)
                except Exception as e:
                    if debug:
                        print(f"DEBUG AUTH:   Agent token validation failed: {e}", file=sys.stderr, flush=True)
                        import traceback
                        traceback.print_exc()
                    return JSONResponse(
                        status_code=401,
                        content={"error": "invalid_token", "error_description": f"Invalid agent token: {e}"}
                    )
            
            elif typ == "auth+jwt":
                # Phase 3/4/5: Auth token (for token exchange or refresh)
                # This is handled elsewhere, but we shouldn't reach here for initial token requests
                if debug:
                    print(f"DEBUG AUTH:   sig=jwt with auth token - this should be handled by exchange/refresh endpoints", file=sys.stderr, flush=True)
                return JSONResponse(
                    status_code=401,
                    content={"error": "invalid_request", "error_description": "Auth tokens should be used with request_type=exchange or request_type=refresh"}
                )
            else:
                if debug:
                    print(f"DEBUG AUTH:   Unsupported token type: {typ}", file=sys.stderr, flush=True)
                return JSONResponse(
                    status_code=401,
                    content={"error": "invalid_request", "error_description": f"Unsupported token type: {typ}"}
                )
        
        if not agent_id:
            if debug:
                print(f"DEBUG AUTH:   Could not extract agent_id from signature", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": "Could not extract agent identifier"}
            )
        
        if debug:
            print(f"DEBUG AUTH:   Agent ID: {agent_id}", file=sys.stderr, flush=True)
            if agent_delegate_sub:
                print(f"DEBUG AUTH:   Agent delegate (sub): {agent_delegate_sub}", file=sys.stderr, flush=True)
        
        # Extract well-known parameter (optional, defaults to "aauth-agent" for AAuth agents)
        well_known = key_params.get("well-known", "aauth-agent") if scheme == "jwks" else None
        
        # Verify signature
        # For agent tokens, we've already validated the JWT, but we still need to verify HTTPSig
        # using the delegate's key from cnf.jwk
        def jwks_fetcher(agent_id_param: str, kid_param: str = None):
            """Fetch JWKS for agent and return full JWKS document.
            
            Returns full JWKS document (with "keys" array) for verify_signature.
            Uses well-known parameter from signature if present, otherwise fetches {id} directly as JWKS.
            """
            if debug:
                print(f"DEBUG AUTH:   Fetching JWKS for agent: {agent_id_param}, kid={kid_param}, well-known={well_known}", file=sys.stderr, flush=True)
            try:
                import httpx
                jwks_uri = None
                
                if well_known:
                    # Fetch metadata from {id}/.well-known/{well-known}
                    from aauth.metadata.auth_server import fetch_metadata
                    metadata_url = f"{agent_id_param}/.well-known/{well_known}"
                    if debug:
                        print(f"DEBUG AUTH:   Fetching metadata from {metadata_url}", file=sys.stderr, flush=True)
                    metadata = fetch_metadata(metadata_url)
                    jwks_uri = metadata.get("jwks_uri")
                    if debug:
                        print(f"DEBUG AUTH:   JWKS URI from metadata: {jwks_uri}", file=sys.stderr, flush=True)
                else:
                    # Fetch {id} directly as JWKS
                    jwks_uri = agent_id_param
                    if debug:
                        print(f"DEBUG AUTH:   well-known absent, fetching {agent_id_param} directly as JWKS", file=sys.stderr, flush=True)
                
                if not jwks_uri:
                    if debug:
                        print(f"DEBUG AUTH:   No jwks_uri found", file=sys.stderr, flush=True)
                    return None
                
                response = httpx.get(jwks_uri, timeout=10.0)
                response.raise_for_status()
                jwks_doc = response.json()
                if debug:
                    print(f"DEBUG AUTH:   JWKS received: {json.dumps(jwks_doc, indent=2)}", file=sys.stderr, flush=True)
                
                # Verify key exists if kid is provided (but return full JWKS document for verifier)
                if kid_param:
                    keys = jwks_doc.get("keys", [])
                    key_found = False
                    for key in keys:
                        if key.get("kid") == kid_param:
                            key_found = True
                            if debug:
                                print(f"DEBUG AUTH:   Found matching key with kid={kid_param}", file=sys.stderr, flush=True)
                            break
                    if not key_found:
                        if debug:
                            print(f"DEBUG AUTH:   Key with kid={kid_param} not found in JWKS", file=sys.stderr, flush=True)
                        return None
                
                # Return full JWKS document (verifier will extract the key it needs)
                return jwks_doc
            except Exception as e:
                if debug:
                    print(f"DEBUG AUTH:   Error fetching JWKS: {e}", file=sys.stderr, flush=True)
                return None
        
        is_valid = verify_signature(
            method=method,
            target_uri=target_uri,
            headers=headers_dict,
            body=body_bytes,
            signature_input_header=signature_input_header,
            signature_header=signature_header,
            signature_key_header=signature_key_header,
            jwks_fetcher=jwks_fetcher
        )
        
        if not is_valid:
            if debug:
                print(f"DEBUG AUTH:   Signature verification FAILED", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_signature", "error_description": "Signature verification failed"}
            )
        
        if debug:
            print(f"DEBUG AUTH:   Signature verification PASSED", file=sys.stderr, flush=True)
        
        # Get redirect_uri (REQUIRED per SPEC.md Section 9.3, even for autonomous flows)
        redirect_uri = params_dict.get("redirect_uri")
        if not redirect_uri:
            if debug:
                print(f"DEBUG AUTH:   Missing redirect_uri parameter (REQUIRED per spec)", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Missing redirect_uri parameter (required per spec)"}
            )
        
        if debug:
            print(f"DEBUG AUTH:   redirect_uri: {redirect_uri}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Note: For Phase 3 autonomous flow, redirect_uri is not used but required by spec", file=sys.stderr, flush=True)
        
        # Phase 5: Support direct authorization (agent is resource)
        # Exactly one of resource_token, scope, or auth_request_url must be provided
        resource_token = params_dict.get("resource_token")
        scope = params_dict.get("scope")
        auth_request_url = params_dict.get("auth_request_url")
        
        # Count how many are provided
        provided_count = sum([bool(resource_token), bool(scope), bool(auth_request_url)])
        
        if provided_count == 0:
            if debug:
                print(f"DEBUG AUTH:   Missing required parameter: must provide resource_token, scope, or auth_request_url", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Must provide exactly one of: resource_token, scope, or auth_request_url"}
            )
        
        if provided_count > 1:
            if debug:
                print(f"DEBUG AUTH:   Multiple parameters provided: resource_token={bool(resource_token)}, scope={bool(scope)}, auth_request_url={bool(auth_request_url)}", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Must provide exactly one of: resource_token, scope, or auth_request_url"}
            )
        
        # Determine if this is Phase 5 (agent is resource) or Phase 4 (resource token)
        agent_is_resource = bool(scope) or bool(auth_request_url)
        
        if debug:
            if agent_is_resource:
                print(f"DEBUG AUTH:   Phase 5: Agent is resource (direct authorization)", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:   Scope: {scope}", file=sys.stderr, flush=True)
                if auth_request_url:
                    print(f"DEBUG AUTH:   Auth request URL: {auth_request_url}", file=sys.stderr, flush=True)
            else:
                print(f"DEBUG AUTH:   Phase 4: Resource token provided", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:   Resource token received: {resource_token[:100]}...", file=sys.stderr, flush=True)
        
        # Extract agent's current signing key for agent_jkt verification
        # We need to get the JWK from the signature to verify agent_jkt
        agent_jwk = None
        if scheme == "jwks":
            # Fetch agent's JWKS and find the key used for signing
            kid = key_params.get("kid")
            if debug:
                print(f"DEBUG AUTH:   Extracting agent JWK for agent_jkt verification: scheme={scheme}, kid={kid}", file=sys.stderr, flush=True)
            
            if kid:
                # jwks_fetcher returns a single JWK, but we need the full JWKS document
                # So we'll fetch it directly using the same well-known logic
                try:
                    import httpx
                    jwks_uri = None
                    
                    if well_known:
                        from aauth.metadata.auth_server import fetch_metadata
                        metadata_url = f"{agent_id}/.well-known/{well_known}"
                        if debug:
                            print(f"DEBUG AUTH:   Fetching agent metadata from {metadata_url} for agent_jkt verification", file=sys.stderr, flush=True)
                        metadata = fetch_metadata(metadata_url)
                        jwks_uri = metadata.get("jwks_uri")
                    else:
                        jwks_uri = agent_id
                        if debug:
                            print(f"DEBUG AUTH:   well-known absent, fetching {agent_id} directly as JWKS for agent_jkt verification", file=sys.stderr, flush=True)
                    
                    if jwks_uri:
                        if debug:
                            print(f"DEBUG AUTH:   Fetching agent JWKS from {jwks_uri} for agent_jkt verification", file=sys.stderr, flush=True)
                        response = httpx.get(jwks_uri, timeout=10.0)
                        response.raise_for_status()
                        agent_jwks_doc = response.json()
                        if debug:
                            print(f"DEBUG AUTH:   Agent JWKS document received: {json.dumps(agent_jwks_doc, indent=2)}", file=sys.stderr, flush=True)
                        # Find the key by kid
                        for key in agent_jwks_doc.get("keys", []):
                            if key.get("kid") == kid:
                                agent_jwk = key
                                if debug:
                                    print(f"DEBUG AUTH:   ✓ Found agent JWK for agent_jkt verification: kid={kid}", file=sys.stderr, flush=True)
                                    print(f"DEBUG AUTH:   Agent JWK: {json.dumps(agent_jwk, indent=2)}", file=sys.stderr, flush=True)
                                break
                        if not agent_jwk:
                            if debug:
                                print(f"DEBUG AUTH:   ✗ Key with kid={kid} not found in agent JWKS", file=sys.stderr, flush=True)
                    else:
                        if debug:
                            print(f"DEBUG AUTH:   ✗ No jwks_uri in agent metadata", file=sys.stderr, flush=True)
                except Exception as e:
                    if debug:
                        print(f"DEBUG AUTH:   ✗ Error fetching agent JWKS for agent_jkt: {e}", file=sys.stderr, flush=True)
                        import traceback
                        traceback.print_exc()
            else:
                if debug:
                    print(f"DEBUG AUTH:   ✗ No kid in signature key params", file=sys.stderr, flush=True)
        else:
            if debug:
                print(f"DEBUG AUTH:   ✗ Cannot extract agent_jwk: scheme={scheme} (not jwks)", file=sys.stderr, flush=True)
        
        if debug:
            print(f"DEBUG AUTH:   agent_jwk extracted: {agent_jwk is not None}", file=sys.stderr, flush=True)
        
        # Phase 5: Handle agent-is-resource vs Phase 4 resource-token flow
        if agent_is_resource:
            # Phase 5: Agent is resource - use agent identifier as resource
            resource_id = agent_id  # Agent is the resource
            # Scope is provided directly in the request
            if not scope:
                scope = ""  # Empty scope if not provided
            
            if debug:
                print(f"DEBUG AUTH:   Phase 5: Using agent as resource", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:   Resource ID (agent): {resource_id}", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:   Scope: {scope}", file=sys.stderr, flush=True)
        else:
            # Phase 4: Validate resource token
            try:
                resource_claims = await self._verify_resource_token(resource_token, agent_id, agent_jwk)
            except Exception as e:
                if debug:
                    print(f"DEBUG AUTH:   Resource token validation FAILED: {e}", file=sys.stderr, flush=True)
                return JSONResponse(
                    status_code=400,
                    content={"error": "invalid_resource_token", "error_description": str(e)}
                )
            
            if debug:
                print(f"DEBUG AUTH:   Resource token validation PASSED", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:   Resource claims: {json.dumps(resource_claims, indent=2)}", file=sys.stderr, flush=True)
            
            # Extract resource and scope from resource token
            resource_id = resource_claims.get("iss")  # Resource is the issuer
            scope = resource_claims.get("scope", "")
            
            if debug:
                print(f"DEBUG AUTH:   Resource ID: {resource_id}", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:   Scope: {scope}", file=sys.stderr, flush=True)
        
        # Evaluate policy
        policy_result = self._evaluate_policy(agent_id, resource_id, scope)
        
        if debug:
            print(f"DEBUG AUTH:   Policy evaluation: {json.dumps(policy_result, indent=2)}", file=sys.stderr, flush=True)
        
        # Phase 4: Check if user consent is required
        if policy_result.get("requires_user_consent"):
            redirect_uri = params_dict.get("redirect_uri")
            if not redirect_uri:
                return JSONResponse(
                    status_code=400,
                    content={"error": "invalid_request", "error_description": "redirect_uri is required when user consent is needed"}
                )
            
            # Generate request_token
            request_token = self._generate_request_token(
                agent=agent_id,
                resource=resource_id,
                scope=scope,
                redirect_uri=redirect_uri,
                agent_jwk=agent_jwk,
                agent_is_resource=agent_is_resource
            )
            
            if debug:
                print(f"DEBUG AUTH:   User consent required, returning request_token", file=sys.stderr, flush=True)
            
            response_data = {
                "request_token": request_token,
                "expires_in": 600  # 10 minutes
            }
            
            if http_debug:
                print("\n" + "=" * 80, file=sys.stderr)
                print("<<< AUTH SERVER RESPONSE", file=sys.stderr)
                print("=" * 80, file=sys.stderr)
                print(f"HTTP/1.1 200 OK", file=sys.stderr)
                print(f"Content-Type: application/json", file=sys.stderr)
                print(f"\n[Body]", file=sys.stderr)
                print(json.dumps(response_data, indent=2), file=sys.stderr)
                print("=" * 80 + "\n", file=sys.stderr)
            
            return JSONResponse(content=response_data)
        
        # Phase 3: Direct grant (autonomous authorization)
        if not policy_result.get("allowed"):
            return JSONResponse(
                status_code=403,
                content={"error": "access_denied", "error_description": policy_result.get("reason", "Access denied")}
            )
        
        # Get agent's current signing key for cnf.jwk
        # For agent tokens (Phase 6), use delegate's key from agent token
        # For agent server (scheme=jwks), use agent server's key
        if scheme == "jwt" and agent_jwk:
            # Phase 6: Agent token - use delegate's key from agent token
            agent_key = agent_jwk  # This is the delegate's key from cnf.jwk in agent token
            if debug:
                print(f"DEBUG AUTH:   Using delegate's JWK from agent token for cnf.jwk: {json.dumps(agent_key, indent=2)}", file=sys.stderr, flush=True)
        elif scheme == "jwks":
            # Use the agent_jwk we already extracted for agent_jkt verification
            if not agent_jwk:
                return JSONResponse(
                    status_code=500,
                    content={"error": "server_error", "error_description": "Agent JWK not available for auth token issuance"}
                )
            agent_key = agent_jwk
            if debug:
                print(f"DEBUG AUTH:   Using agent JWK for cnf.jwk: {json.dumps(agent_key, indent=2)}", file=sys.stderr, flush=True)
        else:
            # For sig=hwk, we'd need to extract from signature-key header
            # For Phase 3, we expect sig=jwks
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Agent must use sig=jwks or sig=jwt with agent token"}
            )
        
        # Issue auth token
        cnf_jwk = agent_key
        auth_token = self._issue_auth_token(
            agent=agent_id,
            resource=resource_id,
            scope=scope,
            cnf_jwk=cnf_jwk,
            agent_delegate=agent_delegate_sub,  # Phase 6: Include delegate identifier
            agent_is_resource=agent_is_resource
        )
        
        if debug:
            print(f"DEBUG AUTH:   Auth token issued: {auth_token[:100]}...", file=sys.stderr, flush=True)
        
        # Build response
        response_data = {
            "auth_token": auth_token,
            "expires_in": 3600,  # 1 hour
            "token_type": "Bearer"  # For compatibility, though AAuth uses proof-of-possession
        }
        
        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print("<<< AUTH SERVER RESPONSE", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"HTTP/1.1 200 OK", file=sys.stderr)
            print(f"Content-Type: application/json", file=sys.stderr)
            print(f"\n[Body]", file=sys.stderr)
            print(json.dumps(response_data, indent=2), file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)
        
        return JSONResponse(content=response_data)
    
    async def _verify_resource_token(self, token: str, expected_agent: str, agent_jwk: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Verify resource token per AAuth spec Section 6.5.
        
        Args:
            token: Resource token JWT string
            expected_agent: Expected agent identifier
            agent_jwk: Optional agent's current signing key (JWK) for agent_jkt verification
            
        Returns:
            Dictionary with verified claims
            
        Raises:
            ValueError: If token is invalid
        """
        debug = _is_debug_enabled()
        
        if debug:
            print(f"DEBUG AUTH: Verifying resource token:", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Token (first 100 chars): {token[:100]}...", file=sys.stderr, flush=True)
        
        # JWKS fetcher for resource
        def resource_jwks_fetcher(resource_id: str):
            """Fetch JWKS for resource."""
            if debug:
                print(f"DEBUG AUTH:   Fetching resource metadata from: {resource_id}", file=sys.stderr, flush=True)
            try:
                metadata_url = f"{resource_id}/.well-known/aauth-resource"
                metadata = fetch_resource_metadata(metadata_url)
                jwks_uri = metadata.get("jwks_uri")
                if debug:
                    print(f"DEBUG AUTH:   Resource JWKS URI: {jwks_uri}", file=sys.stderr, flush=True)
                import httpx
                response = httpx.get(jwks_uri, timeout=10.0)
                response.raise_for_status()
                jwks = response.json()
                if debug:
                    print(f"DEBUG AUTH:   Resource JWKS received: {json.dumps(jwks, indent=2)}", file=sys.stderr, flush=True)
                return jwks
            except Exception as e:
                if debug:
                    print(f"DEBUG AUTH:   Error fetching resource JWKS: {e}", file=sys.stderr, flush=True)
                return None
        
        # Verify token
        try:
            claims = verify_token(
                token=token,
                jwks_fetcher=resource_jwks_fetcher,
                expected_typ="resource+jwt",
                expected_aud=self.auth_id  # Resource token audience must be this auth server
            )
        except Exception as e:
            if debug:
                print(f"DEBUG AUTH:   Token verification failed: {e}", file=sys.stderr, flush=True)
            raise ValueError(f"Invalid resource token: {e}")
        
        # Verify agent claim matches expected agent
        agent = claims.get("agent")
        if agent != expected_agent:
            if debug:
                print(f"DEBUG AUTH:   Agent claim mismatch: expected={expected_agent}, got={agent}", file=sys.stderr, flush=True)
            raise ValueError(f"Agent claim mismatch: expected {expected_agent}, got {agent}")
        
        if debug:
            print(f"DEBUG AUTH:   Agent claim verified: {agent}", file=sys.stderr, flush=True)
        
        # Verify agent_jkt matches agent's current signing key (SPEC.md Section 6.5 step 12)
        agent_jkt = claims.get("agent_jkt")
        if agent_jkt:
            if debug:
                print(f"DEBUG AUTH:   Verifying agent_jkt: {agent_jkt}", file=sys.stderr, flush=True)
            
            if not agent_jwk:
                if debug:
                    print(f"DEBUG AUTH:   Cannot verify agent_jkt - agent JWK not provided", file=sys.stderr, flush=True)
                raise ValueError("Cannot verify agent_jkt: agent signing key not available")
            
            # Calculate thumbprint of agent's current signing key
            from aauth.keys.jwk import calculate_jwk_thumbprint
            calculated_jkt = calculate_jwk_thumbprint(agent_jwk)
            
            if debug:
                print(f"DEBUG AUTH:   Calculated agent_jkt from current key: {calculated_jkt}", file=sys.stderr, flush=True)
            
            if calculated_jkt != agent_jkt:
                if debug:
                    print(f"DEBUG AUTH:   agent_jkt mismatch: expected={calculated_jkt}, got={agent_jkt}", file=sys.stderr, flush=True)
                raise ValueError(f"agent_jkt mismatch: token was issued for different key")
            
            if debug:
                print(f"DEBUG AUTH:   agent_jkt verification PASSED", file=sys.stderr, flush=True)
        
        if debug:
            print(f"DEBUG AUTH:   Resource token verification SUCCESS", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Extracted claims:", file=sys.stderr, flush=True)
            for key, value in claims.items():
                print(f"DEBUG AUTH:     {key}: {value}", file=sys.stderr, flush=True)
        
        return claims
    
    def _evaluate_policy(self, agent: str, resource: str, scope: str) -> Dict[str, Any]:
        """Evaluate authorization policy.
        
        Phase 3: Simple allow-all policy (autonomous authorization).
        Phase 4: Requires user consent when require_user_consent is True.
        
        Args:
            agent: Agent identifier
            resource: Resource identifier
            scope: Requested scope
            
        Returns:
            Dictionary with 'allowed' (bool), 'requires_user_consent' (bool), and 'reason' (str) keys
        """
        debug = _is_debug_enabled()
        
        if debug:
            print(f"DEBUG AUTH: Evaluating policy:", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Agent: {agent}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Resource: {resource}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Scope: {scope}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   require_user_consent: {self.require_user_consent}", file=sys.stderr, flush=True)
        
        # Phase 4: Require user consent if configured
        if self.require_user_consent:
            result = {
                "allowed": False,
                "requires_user_consent": True,
                "reason": "User consent required (Phase 4: user delegation flow)"
            }
        else:
            # Phase 3: Simple allow-all for autonomous authorization
            result = {
                "allowed": True,
                "requires_user_consent": False,
                "reason": "Autonomous authorization granted (Phase 3: allow-all policy)"
            }
        
        if debug:
            print(f"DEBUG AUTH:   Policy result: {json.dumps(result, indent=2)}", file=sys.stderr, flush=True)
        
        return result
    
    def _issue_auth_token(
        self,
        agent: str,
        resource: str,
        scope: str,
        cnf_jwk: Dict[str, Any],
        sub: Optional[str] = None,
        agent_delegate: Optional[str] = None,
        agent_is_resource: bool = False,
        act: Optional[Dict[str, Any]] = None
    ) -> str:
        """Issue auth token per AAuth spec Section 7.
        
        Args:
            agent: Agent identifier
            resource: Resource identifier (audience). When agent_is_resource=True, this should be the agent identifier.
            scope: Authorized scope
            cnf_jwk: Agent's public signing key (JWK format)
            sub: Optional user identifier
            agent_delegate: Optional agent delegate identifier
            agent_is_resource: If True, omit 'agent' claim and set aud to agent identifier (Phase 5)
            act: Optional actor claim for token exchange delegation chain (Phase 7)
            
        Returns:
            Signed auth token JWT string
        """
        debug = _is_debug_enabled()
        
        if debug:
            print(f"DEBUG AUTH: Issuing auth token:", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Agent: {agent}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Resource (aud): {resource}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Scope: {scope}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   cnf.jwk: {json.dumps(cnf_jwk, indent=2)}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Agent is resource: {agent_is_resource}", file=sys.stderr, flush=True)
            if sub:
                print(f"DEBUG AUTH:   User (sub): {sub}", file=sys.stderr, flush=True)
            if agent_delegate:
                print(f"DEBUG AUTH:   Agent delegate: {agent_delegate}", file=sys.stderr, flush=True)
            if act:
                print(f"DEBUG AUTH:   Actor (act): {json.dumps(act, indent=2)}", file=sys.stderr, flush=True)
        
        # Create auth token
        token = create_auth_token(
            iss=self.auth_id,
            aud=resource,
            agent=agent,
            cnf_jwk=cnf_jwk,
            scope=scope,
            private_key=self.private_key,
            kid=self.kid,
            exp=None,  # Default 1 hour
            sub=sub,
            agent_delegate=agent_delegate,
            agent_is_resource=agent_is_resource,
            act=act
        )
        
        if debug:
            print(f"DEBUG AUTH:   Auth token issued successfully", file=sys.stderr, flush=True)
        
        return token
    
    def _generate_request_token(
        self,
        agent: str,
        resource: str,
        scope: str,
        redirect_uri: str,
        agent_jwk: Optional[Dict[str, Any]] = None,
        agent_is_resource: bool = False
    ) -> str:
        """Generate request_token for user consent flow.
        
        Args:
            agent: Agent identifier
            resource: Resource identifier
            scope: Requested scope
            redirect_uri: Agent's callback URI
            agent_jwk: Agent's JWK (for future use)
            agent_is_resource: If True, agent is requesting authorization to itself (Phase 5)
            
        Returns:
            Opaque request_token string
        """
        import secrets
        import base64
        
        debug = _is_debug_enabled()
        
        # Generate random token (opaque string)
        token_bytes = secrets.token_bytes(32)
        request_token = base64.urlsafe_b64encode(token_bytes).decode('utf-8').rstrip('=')
        
        # Store request details
        expires_at = int(time.time()) + 600  # 10 minutes
        self.pending_requests[request_token] = {
            "agent": agent,
            "resource": resource,
            "scope": scope,
            "redirect_uri": redirect_uri,
            "expires_at": expires_at,
            "agent_jwk": agent_jwk,
            "agent_is_resource": agent_is_resource
        }
        
        if debug:
            print(f"DEBUG AUTH: Generated request_token:", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Token: {request_token[:20]}...", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Agent: {agent}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Resource: {resource}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Scope: {scope}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Redirect URI: {redirect_uri}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Expires at: {expires_at}", file=sys.stderr, flush=True)
        
        return request_token
    
    def _generate_authorization_code(self, request_details: Dict[str, Any]) -> str:
        """Generate authorization code for code exchange.
        
        Args:
            request_details: Request details from pending_requests
            
        Returns:
            Authorization code string
        """
        import secrets
        import base64
        
        debug = _is_debug_enabled()
        
        # Generate random code (opaque string)
        code_bytes = secrets.token_bytes(32)
        code = base64.urlsafe_b64encode(code_bytes).decode('utf-8').rstrip('=')
        
        # Store code with request details
        expires_at = int(time.time()) + 60  # 60 seconds
        self.authorization_codes[code] = {
            **request_details,
            "expires_at": expires_at
        }
        
        if debug:
            print(f"DEBUG AUTH: Generated authorization code:", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Code: {code[:20]}...", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Expires at: {expires_at}", file=sys.stderr, flush=True)
        
        return code
    
    async def _handle_code_exchange(
        self,
        request: Request,
        params_dict: Dict[str, str],
        body_bytes: bytes
    ) -> Response:
        """Handle authorization code exchange (request_type=code).
        
        Per AAuth spec Section 9.6.
        """
        from fastapi.responses import RedirectResponse
        
        debug = _is_debug_enabled()
        http_debug = _is_http_debug_enabled()
        
        if debug:
            print(f"DEBUG AUTH: Handling code exchange", file=sys.stderr, flush=True)
        
        # Extract parameters
        code = params_dict.get("code")
        redirect_uri = params_dict.get("redirect_uri")
        
        if not code:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Missing code parameter"}
            )
        
        if not redirect_uri:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Missing redirect_uri parameter"}
            )
        
        # Verify authorization code
        code_details = self.authorization_codes.get(code)
        if not code_details:
            if debug:
                print(f"DEBUG AUTH:   Invalid authorization code", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "Invalid or expired authorization code"}
            )
        
        # Check expiration
        if int(time.time()) >= code_details.get("expires_at", 0):
            if debug:
                print(f"DEBUG AUTH:   Authorization code expired", file=sys.stderr, flush=True)
            del self.authorization_codes[code]
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "Authorization code expired"}
            )
        
        # Verify redirect_uri matches
        if code_details.get("redirect_uri") != redirect_uri:
            if debug:
                print(f"DEBUG AUTH:   redirect_uri mismatch", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "redirect_uri mismatch"}
            )
        
        # Verify agent's HTTPSig signature
        headers_dict = dict(request.headers)
        signature_input_header = headers_dict.get("signature-input", "")
        signature_header = headers_dict.get("signature", "")
        signature_key_header = headers_dict.get("signature-key", "")
        
        if not signature_input_header or not signature_header or not signature_key_header:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": "Missing signature headers"}
            )
        
        # Parse signature key to get agent ID
        try:
            parsed_key = parse_signature_key(signature_key_header)
            scheme = parsed_key["scheme"]
            key_params = parsed_key["params"]
        except Exception as e:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": f"Invalid Signature-Key: {e}"}
            )
        
        agent_id = None
        agent_jwk = None
        agent_delegate_sub = None  # Phase 6: agent delegation
        
        if scheme == "jwks":
            agent_id = key_params.get("id")
            kid = key_params.get("kid")
            
            # Fetch agent JWK for cnf.jwk
            if agent_id and kid:
                try:
                    from aauth.metadata.auth_server import fetch_metadata
                    metadata_url = f"{agent_id}/.well-known/aauth-agent"
                    metadata = fetch_metadata(metadata_url)
                    jwks_uri = metadata.get("jwks_uri")
                    
                    import httpx
                    response = httpx.get(jwks_uri, timeout=10.0)
                    response.raise_for_status()
                    jwks_doc = response.json()
                    
                    # Find matching key
                    for key in jwks_doc.get("keys", []):
                        if key.get("kid") == kid:
                            agent_jwk = key
                            break
                    
                    if debug:
                        print(f"DEBUG AUTH:   Fetched agent JWK for code exchange", file=sys.stderr, flush=True)
                except Exception as e:
                    if debug:
                        print(f"DEBUG AUTH:   Error fetching agent JWK: {e}", file=sys.stderr, flush=True)
        elif scheme == "jwt":
            # Phase 6: Agent delegation - validate agent token
            jwt_token = key_params.get("jwt")
            if not jwt_token:
                return JSONResponse(
                    status_code=401,
                    content={"error": "invalid_request", "error_description": "Missing jwt parameter in Signature-Key"}
                )
            
            # Parse token header to determine type
            try:
                import jwt as jwt_lib
                header = jwt_lib.get_unverified_header(jwt_token)
                typ = header.get("typ")
            except Exception as e:
                return JSONResponse(
                    status_code=401,
                    content={"error": "invalid_request", "error_description": f"Invalid JWT token: {e}"}
                )
            
            if typ == "agent+jwt":
                # Phase 6: Agent token (delegated identity)
                if debug:
                    print(f"DEBUG AUTH:   Validating agent token for code exchange", file=sys.stderr, flush=True)
                
                # Create JWKS fetcher for agent server
                def agent_jwks_fetcher(issuer_url: str, kid_param: Optional[str] = None):
                    """Fetch agent server JWKS."""
                    try:
                        from aauth.metadata.auth_server import fetch_metadata
                        import httpx
                        metadata_url = f"{issuer_url}/.well-known/aauth-agent"
                        metadata = fetch_metadata(metadata_url)
                        jwks_uri = metadata.get("jwks_uri")
                        if not jwks_uri:
                            return None
                        
                        jwks_response = httpx.get(jwks_uri, timeout=10.0)
                        jwks_response.raise_for_status()
                        return jwks_response.json()
                    except Exception as e:
                        if debug:
                            print(f"DEBUG AUTH:   Error fetching agent server JWKS: {e}", file=sys.stderr, flush=True)
                        return None
                
                # Verify agent token
                try:
                    from aauth.tokens.agent_token import verify_agent_token
                    agent_claims = verify_agent_token(
                        token=jwt_token,
                        jwks_fetcher=agent_jwks_fetcher,
                        expected_aud=None
                    )
                    
                    # Extract agent identifier and delegate identifier
                    agent_id = agent_claims.get("iss")  # Agent server identifier
                    agent_delegate_sub = agent_claims.get("sub")  # Delegate identifier
                    cnf = agent_claims.get("cnf", {})
                    agent_jwk = cnf.get("jwk")  # Delegate's key for cnf.jwk
                    
                    if debug:
                        print(f"DEBUG AUTH:   Agent token validated for code exchange", file=sys.stderr, flush=True)
                        print(f"DEBUG AUTH:     Agent server (iss): {agent_id}", file=sys.stderr, flush=True)
                        print(f"DEBUG AUTH:     Agent delegate (sub): {agent_delegate_sub}", file=sys.stderr, flush=True)
                except Exception as e:
                    if debug:
                        print(f"DEBUG AUTH:   Agent token validation failed: {e}", file=sys.stderr, flush=True)
                    return JSONResponse(
                        status_code=401,
                        content={"error": "invalid_token", "error_description": f"Invalid agent token: {e}"}
                    )
            elif typ == "auth+jwt":
                # Auth tokens shouldn't be used for code exchange
                return JSONResponse(
                    status_code=401,
                    content={"error": "invalid_request", "error_description": "Auth tokens cannot be used for code exchange"}
                )
            else:
                return JSONResponse(
                    status_code=401,
                    content={"error": "invalid_request", "error_description": f"Unsupported token type: {typ}"}
                )
        
        if not agent_id:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": "Could not determine agent identity"}
            )
        
        # Verify agent matches code details
        if code_details.get("agent") != agent_id:
            if debug:
                print(f"DEBUG AUTH:   Agent mismatch: {agent_id} != {code_details.get('agent')}", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "Agent mismatch"}
            )
        
        # Verify signature
        method = request.method
        target_uri = str(request.url)
        
        # Extract well-known parameter from signature (if present)
        well_known = key_params.get("well-known", "aauth-agent") if scheme == "jwks" else None
        
        # Create JWKS fetcher for verify_signature
        # For agent tokens (Phase 6), this fetches agent server's JWKS (to validate agent token JWT)
        # For agent server (scheme=jwks), this fetches agent server's JWKS (to validate HTTPSig)
        def jwks_fetcher(agent_id_param: str, kid_param: str = None):
            """Fetch JWKS for agent and return full JWKS document.
            
            Uses well-known parameter from signature if present, otherwise fetches {id} directly as JWKS.
            For agent tokens, this fetches the agent server's JWKS.
            Returns full JWKS document (with "keys" array) for verify_signature.
            """
            try:
                import httpx
                jwks_uri = None
                
                if well_known:
                    from aauth.metadata.auth_server import fetch_metadata
                    metadata_url = f"{agent_id_param}/.well-known/{well_known}"
                    metadata = fetch_metadata(metadata_url)
                    jwks_uri = metadata.get("jwks_uri")
                else:
                    # For agent tokens, agent_id_param is the agent server identifier
                    # Try fetching metadata first
                    try:
                        from aauth.metadata.auth_server import fetch_metadata
                        metadata_url = f"{agent_id_param}/.well-known/aauth-agent"
                        metadata = fetch_metadata(metadata_url)
                        jwks_uri = metadata.get("jwks_uri")
                    except:
                        # Fall back to fetching {id} directly as JWKS
                        jwks_uri = agent_id_param
                
                if not jwks_uri:
                    return None
                
                response = httpx.get(jwks_uri, timeout=10.0)
                response.raise_for_status()
                jwks_doc = response.json()
                
                # Verify key exists if kid is provided (but return full JWKS document for verifier)
                if kid_param:
                    keys = jwks_doc.get("keys", [])
                    key_found = False
                    for key in keys:
                        if key.get("kid") == kid_param:
                            key_found = True
                            break
                    if not key_found:
                        if debug:
                            print(f"DEBUG AUTH:   Key with kid={kid_param} not found in JWKS", file=sys.stderr, flush=True)
                        return None
                
                # Return full JWKS document (verifier will extract the key it needs)
                return jwks_doc
            except Exception as e:
                if debug:
                    print(f"DEBUG AUTH:   Error fetching JWKS: {e}", file=sys.stderr, flush=True)
                return None
        
        is_valid = verify_signature(
            method=method,
            target_uri=target_uri,
            headers=headers_dict,
            body=body_bytes,
            signature_input_header=signature_input_header,
            signature_header=signature_header,
            signature_key_header=signature_key_header,
            jwks_fetcher=jwks_fetcher
        )
        
        if not is_valid:
            if debug:
                print(f"DEBUG AUTH:   Signature verification FAILED", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": "Invalid signature"}
            )
        
        # Extract request details
        resource_id = code_details.get("resource")
        scope = code_details.get("scope")
        user_id = code_details.get("user_id")  # Set during consent
        agent_is_resource = code_details.get("agent_is_resource", False)  # Phase 5: agent is resource
        
        # Use fetched agent_jwk, or fall back to stored one
        # For agent tokens (Phase 6), agent_jwk is the delegate's key from agent token
        # For agent server (scheme=jwks), agent_jwk is the agent server's key
        if not agent_jwk:
            agent_jwk = code_details.get("agent_jwk")
        
        if not agent_jwk:
            if debug:
                print(f"DEBUG AUTH:   Agent JWK not available", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=500,
                content={"error": "server_error", "error_description": "Agent JWK not available"}
            )
        
        # Issue auth token with user identity
        # Phase 6: Include agent_delegate if present (from agent token)
        auth_token = self._issue_auth_token(
            agent=agent_id,
            resource=resource_id,
            scope=scope,
            cnf_jwk=agent_jwk,
            sub=user_id,
            agent_delegate=agent_delegate_sub,  # Phase 6: Include delegate identifier
            agent_is_resource=agent_is_resource
        )
        
        # Remove code (single-use)
        del self.authorization_codes[code]
        
        if debug:
            print(f"DEBUG AUTH:   Code exchanged successfully, auth token issued", file=sys.stderr, flush=True)
        
        # Build response
        response_data = {
            "auth_token": auth_token,
            "expires_in": 3600,
            "token_type": "Bearer"
        }
        
        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print("<<< AUTH SERVER RESPONSE", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"HTTP/1.1 200 OK", file=sys.stderr)
            print(f"Content-Type: application/json", file=sys.stderr)
            print(f"\n[Body]", file=sys.stderr)
            print(json.dumps(response_data, indent=2), file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)
        
        return JSONResponse(content=response_data)
    
    async def _handle_token_exchange(
        self,
        request: Request,
        params_dict: Dict[str, str],
        body_bytes: bytes
    ) -> Response:
        """Handle token exchange (request_type=exchange) per AAuth spec Section 9.10.
        
        Enables multi-hop resource access. When a resource needs to call a downstream
        resource, it exchanges the upstream auth token for a new token bound to its own key.
        
        The upstream auth token MUST be presented via scheme=jwt in the Signature-Key header.
        """
        debug = _is_debug_enabled()
        http_debug = _is_http_debug_enabled()
        
        if debug:
            print(f"DEBUG AUTH: Handling token exchange (request_type=exchange)", file=sys.stderr, flush=True)
        
        # Extract request parameters
        resource_token = params_dict.get("resource_token")
        
        if not resource_token:
            if debug:
                print(f"DEBUG AUTH:   Missing resource_token parameter", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Missing resource_token parameter"}
            )
        
        if debug:
            print(f"DEBUG AUTH:   Resource token: {resource_token[:100]}...", file=sys.stderr, flush=True)
        
        # Extract and parse signature headers
        headers_dict = dict(request.headers)
        method = request.method
        target_uri = str(request.url)
        
        signature_input_header = headers_dict.get("signature-input", "")
        signature_header = headers_dict.get("signature", "")
        signature_key_header = headers_dict.get("signature-key", "")
        
        if not signature_input_header or not signature_header or not signature_key_header:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": "Missing signature headers"}
            )
        
        # Parse Signature-Key header
        try:
            parsed_key = parse_signature_key(signature_key_header)
            scheme = parsed_key["scheme"]
            key_params = parsed_key["params"]
        except Exception as e:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": f"Invalid Signature-Key: {e}"}
            )
        
        if debug:
            print(f"DEBUG AUTH:   Signature scheme: {scheme}", file=sys.stderr, flush=True)
        
        # Token exchange MUST use scheme=jwt with auth token
        if scheme != "jwt":
            if debug:
                print(f"DEBUG AUTH:   Token exchange requires scheme=jwt, got {scheme}", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": "Token exchange requires scheme=jwt with upstream auth token"}
            )
        
        # Extract upstream auth token from Signature-Key
        upstream_token = key_params.get("jwt")
        if not upstream_token:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": "Missing jwt parameter in Signature-Key"}
            )
        
        if debug:
            print(f"DEBUG AUTH:   Upstream token: {upstream_token[:100]}...", file=sys.stderr, flush=True)
        
        # Parse upstream token header to verify it's an auth token
        try:
            import jwt as jwt_lib
            upstream_header = jwt_lib.get_unverified_header(upstream_token)
            upstream_typ = upstream_header.get("typ")
            
            if debug:
                print(f"DEBUG AUTH:   Upstream token type: {upstream_typ}", file=sys.stderr, flush=True)
        except Exception as e:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_token", "error_description": f"Invalid upstream token: {e}"}
            )
        
        if upstream_typ != "auth+jwt":
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_token", "error_description": f"Token exchange requires auth+jwt, got {upstream_typ}"}
            )
        
        # Parse upstream token claims (without verification first)
        try:
            import jwt as jwt_lib
            upstream_payload = jwt_lib.decode(upstream_token, options={"verify_signature": False})
            upstream_iss = upstream_payload.get("iss")  # Upstream auth server
            upstream_aud = upstream_payload.get("aud")  # Should be the requesting resource
            upstream_agent = upstream_payload.get("agent")  # Original agent
            upstream_agent_delegate = upstream_payload.get("agent_delegate")  # Original delegate
            upstream_sub = upstream_payload.get("sub")  # User identifier
            upstream_cnf = upstream_payload.get("cnf", {})
            upstream_cnf_jwk = upstream_cnf.get("jwk")
            
            if debug:
                print(f"DEBUG AUTH:   Upstream token claims:", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:     iss (upstream auth server): {upstream_iss}", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:     aud (requesting resource): {upstream_aud}", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:     agent (original agent): {upstream_agent}", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:     sub (user): {upstream_sub}", file=sys.stderr, flush=True)
                if upstream_agent_delegate:
                    print(f"DEBUG AUTH:     agent_delegate: {upstream_agent_delegate}", file=sys.stderr, flush=True)
        except Exception as e:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_token", "error_description": f"Failed to parse upstream token: {e}"}
            )
        
        # Validate upstream auth server is trusted (federation trust)
        if upstream_iss not in self.trusted_auth_servers:
            if debug:
                print(f"DEBUG AUTH:   Upstream auth server not trusted: {upstream_iss}", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:   Trusted auth servers: {self.trusted_auth_servers}", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_token", "error_description": f"Upstream auth server not trusted: {upstream_iss}"}
            )
        
        if debug:
            print(f"DEBUG AUTH:   Upstream auth server trusted: {upstream_iss}", file=sys.stderr, flush=True)
        
        # Verify upstream token signature using upstream auth server's JWKS
        try:
            from core.metadata import fetch_metadata
            import httpx
            
            # Fetch upstream auth server metadata
            metadata_url = f"{upstream_iss}/.well-known/aauth-issuer"
            if debug:
                print(f"DEBUG AUTH:   Fetching upstream auth server metadata from {metadata_url}", file=sys.stderr, flush=True)
            
            metadata = fetch_metadata(metadata_url)
            jwks_uri = metadata.get("jwks_uri")
            
            if not jwks_uri:
                return JSONResponse(
                    status_code=401,
                    content={"error": "invalid_token", "error_description": "Upstream auth server metadata missing jwks_uri"}
                )
            
            # Fetch JWKS
            if debug:
                print(f"DEBUG AUTH:   Fetching upstream auth server JWKS from {jwks_uri}", file=sys.stderr, flush=True)
            
            jwks_response = httpx.get(jwks_uri, timeout=10.0)
            jwks_response.raise_for_status()
            upstream_jwks = jwks_response.json()
            
            # Find signing key
            upstream_kid = upstream_header.get("kid")
            signing_key = None
            for key in upstream_jwks.get("keys", []):
                if key.get("kid") == upstream_kid:
                    signing_key = key
                    break
            
            if not signing_key:
                return JSONResponse(
                    status_code=401,
                    content={"error": "invalid_token", "error_description": f"Key {upstream_kid} not found in upstream auth server JWKS"}
                )
            
            # Verify signature
            from aauth.keys.jwk import jwk_to_public_key
            upstream_public_key = jwk_to_public_key(signing_key)
            
            import jwt as jwt_lib
            jwt_lib.decode(
                upstream_token,
                upstream_public_key,
                algorithms=["EdDSA"],
                options={"verify_signature": True, "verify_exp": True, "verify_aud": False}
            )
            
            if debug:
                print(f"DEBUG AUTH:   Upstream token signature verified", file=sys.stderr, flush=True)
                
        except jwt_lib.ExpiredSignatureError:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_token", "error_description": "Upstream token has expired"}
            )
        except Exception as e:
            if debug:
                print(f"DEBUG AUTH:   Failed to verify upstream token: {e}", file=sys.stderr, flush=True)
                import traceback
                traceback.print_exc()
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_token", "error_description": f"Failed to verify upstream token: {e}"}
            )
        
        # Verify upstream token audience matches the requesting resource
        # The requesting resource is identified by the Signature-Key (its identity)
        # For now, we'll extract it from the resource token's agent claim
        
        # Parse resource token to get requesting resource identity and scope
        try:
            from aauth.tokens.auth_token import verify_token
            
            # Create JWKS fetcher for resource
            def resource_jwks_fetcher(issuer_url: str, kid_param: str = None):
                try:
                    from core.metadata import fetch_metadata
                    import httpx
                    metadata_url = f"{issuer_url}/.well-known/aauth-resource"
                    metadata = fetch_metadata(metadata_url)
                    jwks_uri = metadata.get("jwks_uri")
                    if not jwks_uri:
                        return None
                    response = httpx.get(jwks_uri, timeout=10.0)
                    response.raise_for_status()
                    jwks_doc = response.json()
                    if kid_param:
                        for key in jwks_doc.get("keys", []):
                            if key.get("kid") == kid_param:
                                return key
                        return None
                    return jwks_doc
                except Exception as e:
                    if debug:
                        print(f"DEBUG AUTH:   Error fetching resource JWKS: {e}", file=sys.stderr, flush=True)
                    return None
            
            # Verify resource token
            resource_claims = verify_token(
                resource_token,
                resource_jwks_fetcher,
                expected_typ="resource+jwt",
                expected_aud=self.auth_id
            )
            
            downstream_resource = resource_claims.get("iss")  # Downstream resource
            requesting_agent = resource_claims.get("agent")  # The resource acting as agent
            scope = resource_claims.get("scope", "")
            
            if debug:
                print(f"DEBUG AUTH:   Resource token verified:", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:     Downstream resource (iss): {downstream_resource}", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:     Requesting agent (agent): {requesting_agent}", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:     Scope: {scope}", file=sys.stderr, flush=True)
                
        except Exception as e:
            if debug:
                print(f"DEBUG AUTH:   Resource token validation failed: {e}", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_resource_token", "error_description": str(e)}
            )
        
        # Verify upstream token audience matches requesting agent
        if upstream_aud != requesting_agent:
            if debug:
                print(f"DEBUG AUTH:   Upstream token audience mismatch: {upstream_aud} != {requesting_agent}", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_token", "error_description": f"Upstream token audience mismatch: expected {requesting_agent}"}
            )
        
        if debug:
            print(f"DEBUG AUTH:   Upstream token audience verified: {upstream_aud}", file=sys.stderr, flush=True)
        
        # Verify HTTPSig signature using requesting resource's key
        # The requesting resource signs with its own key (identified by agent_jkt in resource_token)
        # We need to fetch the requesting resource's JWKS to verify the signature
        from aauth.signing.verifier import verify_signature
        
        # Extract the agent_jkt from resource token for verification
        resource_agent_jkt = resource_claims.get("agent_jkt")
        
        if debug:
            print(f"DEBUG AUTH:   Verifying HTTPSig using requesting resource's key", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:     Resource token agent_jkt: {resource_agent_jkt}", file=sys.stderr, flush=True)
        
        # Fetch the requesting resource's JWKS
        try:
            from core.metadata import fetch_metadata
            import httpx
            
            # Fetch resource metadata
            metadata_url = f"{requesting_agent}/.well-known/aauth-resource"
            if debug:
                print(f"DEBUG AUTH:   Fetching requesting resource metadata from {metadata_url}", file=sys.stderr, flush=True)
            
            metadata = fetch_metadata(metadata_url)
            jwks_uri = metadata.get("jwks_uri")
            if not jwks_uri:
                return JSONResponse(
                    status_code=401,
                    content={"error": "invalid_request", "error_description": "No jwks_uri in requesting resource metadata"}
                )
            
            # Fetch JWKS
            jwks_response = httpx.get(jwks_uri, timeout=10.0)
            jwks_response.raise_for_status()
            jwks_doc = jwks_response.json()
            
            # Find the key by agent_jkt (JWK Thumbprint)
            resource_jwk_for_cnf = None
            for key in jwks_doc.get("keys", []):
                key_jkt = calculate_jwk_thumbprint(key)
                if key_jkt == resource_agent_jkt:
                    resource_jwk_for_cnf = key
                    break
            
            if not resource_jwk_for_cnf:
                if debug:
                    print(f"DEBUG AUTH:   No key matching agent_jkt in requesting resource's JWKS", file=sys.stderr, flush=True)
                return JSONResponse(
                    status_code=401,
                    content={"error": "invalid_request", "error_description": "Signing key not found in requesting resource's JWKS"}
                )
            
            if debug:
                print(f"DEBUG AUTH:   Found requesting resource's key: kid={resource_jwk_for_cnf.get('kid')}", file=sys.stderr, flush=True)
                
        except Exception as e:
            if debug:
                print(f"DEBUG AUTH:   Error fetching requesting resource JWKS: {e}", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": f"Could not fetch requesting resource's JWKS: {e}"}
            )
        
        # For scheme=jwt in token exchange, the requesting resource signs HTTPSig with its own key,
        # not the key from cnf.jwk in the upstream token. However, verify_signature for scheme=jwt
        # will try to verify HTTPSig using cnf.jwk from the upstream token.
        # We need to verify HTTPSig separately using the resource's key.
        # Verify HTTPSig manually using the resource's public key.
        if debug:
            print(f"DEBUG AUTH:   Starting HTTPSig verification for token exchange", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:     Resource agent_jkt from token: {resource_agent_jkt}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:     Resource JWK kid: {resource_jwk_for_cnf.get('kid') if resource_jwk_for_cnf else 'N/A'}", file=sys.stderr, flush=True)
        try:
            from aauth.signing.signature_base import build_signature_base
            from aauth.headers.signature_input import parse_signature_input
            from aauth.headers.signature import parse_signature
            from urllib.parse import urlparse
            
            # Parse signature input to get covered components
            components, params = parse_signature_input(signature_input_header)
            
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
                headers=headers_dict,
                body=body_bytes,
                signature_key_header=signature_key_header,
                covered_components=components
            )
            
            # Parse signature
            signature_bytes = parse_signature(signature_header, label="sig1")
            
            # Verify HTTPSig using requesting resource's public key
            from aauth.keys.jwk import jwk_to_public_key
            requesting_resource_public_key = jwk_to_public_key(resource_jwk_for_cnf)
            
            requesting_resource_public_key.verify(signature_bytes, signature_base.encode('utf-8'))
            is_valid = True
            
        except Exception as e:
            error_msg = str(e)
            if debug:
                print(f"DEBUG AUTH:   HTTPSig signature verification error: {error_msg}", file=sys.stderr, flush=True)
                import traceback
                traceback.print_exc()
                if 'signature_base' in locals():
                    print(f"DEBUG AUTH:   Signature base (first 200 chars): {signature_base[:200]}", file=sys.stderr, flush=True)
                if 'signature_bytes' in locals():
                    print(f"DEBUG AUTH:   Signature bytes length: {len(signature_bytes)}", file=sys.stderr, flush=True)
                if resource_jwk_for_cnf:
                    print(f"DEBUG AUTH:   Resource JWK kid: {resource_jwk_for_cnf.get('kid')}", file=sys.stderr, flush=True)
            is_valid = False
            verification_error = error_msg
        else:
            verification_error = None
        
        if not is_valid:
            if debug:
                print(f"DEBUG AUTH:   HTTPSig signature verification failed", file=sys.stderr, flush=True)
            error_description = "HTTPSig signature verification failed"
            if verification_error:
                error_description += f": {verification_error}"
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_signature", "error_description": error_description}
            )
        
        if debug:
            print(f"DEBUG AUTH:   HTTPSig signature verified", file=sys.stderr, flush=True)
        
        # Evaluate policy for the exchange
        policy_result = self._evaluate_policy(requesting_agent, downstream_resource, scope)
        
        if not policy_result.get("allowed"):
            return JSONResponse(
                status_code=403,
                content={"error": "access_denied", "error_description": policy_result.get("reason", "Access denied")}
            )
        
        if debug:
            print(f"DEBUG AUTH:   Policy evaluation passed", file=sys.stderr, flush=True)
        
        # Build actor (act) claim for delegation chain
        act_claim = {
            "agent": upstream_agent  # Required: the upstream agent
        }
        if upstream_agent_delegate:
            act_claim["agent_delegate"] = upstream_agent_delegate
        if upstream_sub:
            act_claim["sub"] = upstream_sub
        
        # Check for nested act claim (multi-hop chains)
        upstream_act = upstream_payload.get("act")
        if upstream_act:
            act_claim["act"] = upstream_act
        
        if debug:
            print(f"DEBUG AUTH:   Actor claim: {json.dumps(act_claim, indent=2)}", file=sys.stderr, flush=True)
        
        # Issue auth token for downstream resource
        # Bound to requesting resource's key (from requesting resource's JWKS)
        if debug:
            print(f"DEBUG AUTH:   Issuing token with cnf.jwk from requesting resource's JWKS", file=sys.stderr, flush=True)
        
        auth_token = self._issue_auth_token(
            agent=requesting_agent,
            resource=downstream_resource,
            scope=scope,
            cnf_jwk=resource_jwk_for_cnf,
            sub=upstream_sub,  # Maintain user context through the chain
            act=act_claim
        )
        
        if debug:
            print(f"DEBUG AUTH:   Token exchange successful, auth token issued", file=sys.stderr, flush=True)
        
        # Build response
        response_data = {
            "auth_token": auth_token,
            "expires_in": 3600
        }
        
        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print("<<< AUTH SERVER RESPONSE (Token Exchange)", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"HTTP/1.1 200 OK", file=sys.stderr)
            print(f"Content-Type: application/json", file=sys.stderr)
            print(f"\n[Body]", file=sys.stderr)
            print(json.dumps(response_data, indent=2), file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)
        
        return JSONResponse(content=response_data)
    
    async def _handle_auth_get(self, request: Request) -> Response:
        """Handle GET /agent/auth - display login or consent page."""
        from fastapi.responses import HTMLResponse
        
        debug = _is_debug_enabled()
        
        # Extract query parameters
        request_token = request.query_params.get("request_token")
        redirect_uri = request.query_params.get("redirect_uri")
        
        if not request_token:
            return HTMLResponse(
                status_code=400,
                content="<html><body><h1>Error</h1><p>Missing request_token parameter</p></body></html>"
            )
        
        # Validate request_token
        request_details = self.pending_requests.get(request_token)
        if not request_details:
            return HTMLResponse(
                status_code=400,
                content="<html><body><h1>Error</h1><p>Invalid or expired request_token</p></body></html>"
            )
        
        # Check expiration
        if int(time.time()) >= request_details.get("expires_at", 0):
            del self.pending_requests[request_token]
            return HTMLResponse(
                status_code=400,
                content="<html><body><h1>Error</h1><p>Request token expired</p></body></html>"
            )
        
        # Check if user is authenticated (simplified - check session/cookie)
        # For demo, we'll check if there's a user_id in request_details
        user_id = request_details.get("user_id")
        
        if not user_id:
            # Show login page
            return self._render_login_page(request_token, redirect_uri, request_details)
        else:
            # Show consent page
            return self._render_consent_page(request_token, redirect_uri, request_details, user_id)
    
    async def _handle_auth_post(self, request: Request) -> Response:
        """Handle POST /agent/auth - process login or consent submission."""
        from fastapi.responses import RedirectResponse
        
        debug = _is_debug_enabled()
        
        # Parse form data
        form_data = await request.form()
        request_token = form_data.get("request_token")
        redirect_uri = form_data.get("redirect_uri")
        action = form_data.get("action", "")
        username = form_data.get("username", "")
        password = form_data.get("password", "")
        consent = form_data.get("consent", "")
        
        if not request_token:
            return HTMLResponse(
                status_code=400,
                content="<html><body><h1>Error</h1><p>Missing request_token</p></body></html>"
            )
        
        # Get request details
        request_details = self.pending_requests.get(request_token)
        if not request_details:
            return HTMLResponse(
                status_code=400,
                content="<html><body><h1>Error</h1><p>Invalid request_token</p></body></html>"
            )
        
        # Handle login
        if action == "login" or (username and password):
            # Validate credentials
            user = self.users.get(username)
            if not user or user.get("password") != password:
                return self._render_login_page(
                    request_token, redirect_uri, request_details,
                    error="Invalid username or password"
                )
            
            # Store user_id in request_details
            request_details["user_id"] = username
            request_details["user_name"] = user.get("name", username)
            request_details["user_email"] = user.get("email", "")
            
            if debug:
                print(f"DEBUG AUTH: User authenticated: {username}", file=sys.stderr, flush=True)
            
            # Redirect back to consent page
            auth_url = f"{self.auth_id}/agent/auth?request_token={request_token}&redirect_uri={redirect_uri}"
            return RedirectResponse(url=auth_url, status_code=303)
        
        # Handle consent
        if consent:
            user_id = request_details.get("user_id")
            if not user_id:
                # Not authenticated, redirect to login
                return self._render_login_page(
                    request_token, redirect_uri, request_details,
                    error="Please authenticate first"
                )
            
            if consent == "grant":
                # Generate authorization code
                code = self._generate_authorization_code(request_details)
                
                # Clean up request_token
                del self.pending_requests[request_token]
                
                if debug:
                    print(f"DEBUG AUTH: Consent granted, redirecting with code", file=sys.stderr, flush=True)
                
                # Redirect to agent's callback with code
                redirect_url = f"{redirect_uri}?code={code}"
                return RedirectResponse(url=redirect_url, status_code=303)
            
            elif consent == "deny":
                # Clean up request_token
                del self.pending_requests[request_token]
                
                if debug:
                    print(f"DEBUG AUTH: Consent denied, redirecting with error", file=sys.stderr, flush=True)
                
                # Redirect to agent's callback with error
                redirect_url = f"{redirect_uri}?error=access_denied&error_description=User+denied+consent"
                return RedirectResponse(url=redirect_url, status_code=303)
        
        return HTMLResponse(
            status_code=400,
            content="<html><body><h1>Error</h1><p>Invalid request</p></body></html>"
        )
    
    def _render_login_page(
        self,
        request_token: str,
        redirect_uri: str,
        request_details: Dict[str, Any],
        error: Optional[str] = None
    ) -> Response:
        """Render login page HTML."""
        from fastapi.responses import HTMLResponse
        
        agent = request_details.get("agent", "Unknown")
        resource = request_details.get("resource", "Unknown")
        
        error_html = f'<div style="color: red; margin: 10px 0;">{error}</div>' if error else ""
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>AAuth Login</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 500px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            margin-top: 0;
            color: #333;
        }}
        .info {{
            background: #f0f0f0;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
            font-size: 14px;
        }}
        .info strong {{
            display: block;
            margin-bottom: 5px;
        }}
        form {{
            margin-top: 20px;
        }}
        label {{
            display: block;
            margin: 10px 0 5px;
            font-weight: 500;
        }}
        input[type="text"],
        input[type="password"] {{
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            box-sizing: border-box;
        }}
        button {{
            width: 100%;
            padding: 12px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            margin-top: 15px;
        }}
        button:hover {{
            background: #0056b3;
        }}
        .demo-credentials {{
            background: #e7f3ff;
            padding: 10px;
            border-radius: 4px;
            margin: 15px 0;
            font-size: 12px;
            color: #0066cc;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>AAuth Login</h1>
        <div class="info">
            <strong>Agent:</strong> {agent}
            <strong>Resource:</strong> {resource}
        </div>
        {error_html}
        <form method="POST" action="/agent/auth">
            <input type="hidden" name="request_token" value="{request_token}">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}">
            <input type="hidden" name="action" value="login">
            
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
            
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
            
            <div class="demo-credentials">
                <strong>Demo Credentials:</strong><br>
                Username: testuser<br>
                Password: testpass
            </div>
            
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>"""
        
        return HTMLResponse(content=html)
    
    def _render_consent_page(
        self,
        request_token: str,
        redirect_uri: str,
        request_details: Dict[str, Any],
        user_id: str
    ) -> Response:
        """Render consent page HTML."""
        from fastapi.responses import HTMLResponse
        
        agent = request_details.get("agent", "Unknown")
        resource = request_details.get("resource", "Unknown")
        scope = request_details.get("scope", "")
        user_name = request_details.get("user_name", user_id)
        
        # Parse scopes
        scopes = scope.split() if scope else []
        scope_descriptions = {
            "data.read": "Read access to your data",
            "data.write": "Write access to your data",
            "data.delete": "Delete access to your data"
        }
        
        scope_list_html = ""
        for s in scopes:
            desc = scope_descriptions.get(s, s)
            scope_list_html += f'<li><strong>{s}</strong> - {desc}</li>'
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>AAuth Authorization</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            margin-top: 0;
            color: #333;
        }}
        .info {{
            background: #f0f0f0;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
            font-size: 14px;
        }}
        .info strong {{
            display: block;
            margin-bottom: 5px;
        }}
        .scopes {{
            background: #fff9e6;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }}
        .scopes ul {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        .scopes li {{
            margin: 5px 0;
        }}
        .buttons {{
            display: flex;
            gap: 10px;
            margin-top: 25px;
        }}
        button {{
            flex: 1;
            padding: 12px;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
        }}
        .grant {{
            background: #28a745;
            color: white;
        }}
        .grant:hover {{
            background: #218838;
        }}
        .deny {{
            background: #dc3545;
            color: white;
        }}
        .deny:hover {{
            background: #c82333;
        }}
        form {{
            margin: 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Authorize Access</h1>
        <p>Hello, <strong>{user_name}</strong>!</p>
        
        <div class="info">
            <strong>Agent:</strong> {agent}
            <strong>Resource:</strong> {resource}
        </div>
        
        <div class="scopes">
            <strong>The following permissions are requested:</strong>
            <ul>
                {scope_list_html if scope_list_html else '<li>No specific scopes requested</li>'}
            </ul>
        </div>
        
        <div class="buttons">
            <form method="POST" action="/agent/auth" style="flex: 1;">
                <input type="hidden" name="request_token" value="{request_token}">
                <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                <input type="hidden" name="consent" value="grant">
                <button type="submit" class="grant">Grant Access</button>
            </form>
            
            <form method="POST" action="/agent/auth" style="flex: 1;">
                <input type="hidden" name="request_token" value="{request_token}">
                <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                <input type="hidden" name="consent" value="deny">
                <button type="submit" class="deny">Deny</button>
            </form>
        </div>
    </div>
</body>
</html>"""
        
        return HTMLResponse(content=html)
    
    def run(self):
        """Run the auth server."""
        import uvicorn
        uvicorn.run(self.app, host="0.0.0.0", port=self.port)


if __name__ == "__main__":
    auth_server = AuthServer("https://auth.example", port=8003)
    auth_server.run()

