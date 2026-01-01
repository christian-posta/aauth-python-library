"""Auth server participant - issues auth tokens for autonomous authorization."""

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any
import sys
import os
import json
import time
from urllib.parse import urlparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.httpsig import verify_signature, parse_signature_key
from core.crypto_utils import generate_ed25519_keypair, public_key_to_jwk, generate_jwks, jwk_to_public_key
from core.metadata import generate_auth_metadata, fetch_resource_metadata
from core.tokens import verify_token, create_auth_token, calculate_jwk_thumbprint


def _is_debug_enabled(env_var: str = "AAUTH_DEBUG") -> bool:
    """Check if debug is enabled (defaults to True unless explicitly disabled)."""
    value = os.environ.get(env_var, "1")
    return value.lower() not in ("0", "false", "no", "off", "")


def _is_http_debug_enabled() -> bool:
    """Check if HTTP debug is enabled (defaults to True unless explicitly disabled)."""
    return _is_debug_enabled("AAUTH_DEBUG_HTTP")


class AuthServer:
    """Auth server that issues auth tokens for autonomous authorization."""
    
    def __init__(self, auth_id: str, port: int = 8003):
        """Initialize auth server.
        
        Args:
            auth_id: Auth server identifier (HTTPS URL)
            port: Port to run auth server on
        """
        self.auth_id = auth_id
        self.port = port
        
        # Generate key pair for signing auth tokens
        self.private_key, self.public_key = generate_ed25519_keypair()
        self.kid = "auth-key-1"
        
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
            """Token endpoint for autonomous authorization per AAuth spec Section 9.3."""
            return await self._handle_token_request(request)
    
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
        if scheme == "jwks":
            agent_id = key_params.get("id")
        elif scheme == "jwt":
            # For Phase 3, we expect sig=jwks from agent server
            # sig=jwt with agent token will be Phase 4
            if debug:
                print(f"DEBUG AUTH:   sig=jwt not supported for Phase 3 (agent server should use sig=jwks)", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": "Agent must use sig=jwks or sig=hwk"}
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
        
        # Verify signature
        def jwks_fetcher(agent_id_param: str, kid_param: str = None):
            """Fetch JWKS for agent and return the matching key.
            
            Returns a single JWK matching the kid, not the full JWKS document.
            """
            if debug:
                print(f"DEBUG AUTH:   Fetching JWKS for agent: {agent_id_param}, kid={kid_param}", file=sys.stderr, flush=True)
            try:
                from core.metadata import fetch_metadata
                metadata_url = f"{agent_id_param}/.well-known/aauth-agent"
                metadata = fetch_metadata(metadata_url)
                jwks_uri = metadata.get("jwks_uri")
                if debug:
                    print(f"DEBUG AUTH:   JWKS URI: {jwks_uri}", file=sys.stderr, flush=True)
                import httpx
                response = httpx.get(jwks_uri, timeout=10.0)
                response.raise_for_status()
                jwks_doc = response.json()
                if debug:
                    print(f"DEBUG AUTH:   JWKS received: {json.dumps(jwks_doc, indent=2)}", file=sys.stderr, flush=True)
                
                # Extract the matching key by kid
                if kid_param:
                    keys = jwks_doc.get("keys", [])
                    for key in keys:
                        if key.get("kid") == kid_param:
                            if debug:
                                print(f"DEBUG AUTH:   Found matching key with kid={kid_param}", file=sys.stderr, flush=True)
                            return key
                    if debug:
                        print(f"DEBUG AUTH:   Key with kid={kid_param} not found in JWKS", file=sys.stderr, flush=True)
                    return None
                else:
                    # If no kid specified, return first key (shouldn't happen for sig=jwks)
                    keys = jwks_doc.get("keys", [])
                    if keys:
                        return keys[0]
                    return None
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
        
        # Get resource_token from request body
        resource_token = params_dict.get("resource_token")
        if not resource_token:
            if debug:
                print(f"DEBUG AUTH:   Missing resource_token parameter", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Missing resource_token parameter"}
            )
        
        if debug:
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
                # So we'll fetch it directly
                try:
                    from core.metadata import fetch_metadata
                    metadata_url = f"{agent_id}/.well-known/aauth-agent"
                    if debug:
                        print(f"DEBUG AUTH:   Fetching agent metadata from {metadata_url} for agent_jkt verification", file=sys.stderr, flush=True)
                    metadata = fetch_metadata(metadata_url)
                    jwks_uri = metadata.get("jwks_uri")
                    if jwks_uri:
                        if debug:
                            print(f"DEBUG AUTH:   Fetching agent JWKS from {jwks_uri} for agent_jkt verification", file=sys.stderr, flush=True)
                        import httpx
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
        
        # Validate resource token
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
        
        # Evaluate policy (Phase 3: simple allow-all)
        policy_result = self._evaluate_policy(agent_id, resource_id, scope)
        
        if debug:
            print(f"DEBUG AUTH:   Policy evaluation: {json.dumps(policy_result, indent=2)}", file=sys.stderr, flush=True)
        
        if not policy_result.get("allowed"):
            return JSONResponse(
                status_code=403,
                content={"error": "access_denied", "error_description": policy_result.get("reason", "Access denied")}
            )
        
        # Get agent's current signing key for cnf.jwk
        # We already extracted agent_jwk earlier, so we can reuse it
        if scheme == "jwks":
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
                content={"error": "invalid_request", "error_description": "Agent must use sig=jwks"}
            )
        
        # Issue auth token
        cnf_jwk = agent_key
        auth_token = self._issue_auth_token(
            agent=agent_id,
            resource=resource_id,
            scope=scope,
            cnf_jwk=cnf_jwk
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
            from core.tokens import calculate_jwk_thumbprint
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
        Phase 4 will add user consent and more complex policies.
        
        Args:
            agent: Agent identifier
            resource: Resource identifier
            scope: Requested scope
            
        Returns:
            Dictionary with 'allowed' (bool) and 'reason' (str) keys
        """
        debug = _is_debug_enabled()
        
        if debug:
            print(f"DEBUG AUTH: Evaluating policy:", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Agent: {agent}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Resource: {resource}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Scope: {scope}", file=sys.stderr, flush=True)
        
        # Phase 3: Simple allow-all for autonomous authorization
        result = {
            "allowed": True,
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
        agent_delegate: Optional[str] = None
    ) -> str:
        """Issue auth token per AAuth spec Section 7.
        
        Args:
            agent: Agent identifier
            resource: Resource identifier (audience)
            scope: Authorized scope
            cnf_jwk: Agent's public signing key (JWK format)
            sub: Optional user identifier
            agent_delegate: Optional agent delegate identifier
            
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
            if sub:
                print(f"DEBUG AUTH:   User (sub): {sub}", file=sys.stderr, flush=True)
            if agent_delegate:
                print(f"DEBUG AUTH:   Agent delegate: {agent_delegate}", file=sys.stderr, flush=True)
        
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
            agent_delegate=agent_delegate
        )
        
        if debug:
            print(f"DEBUG AUTH:   Auth token issued successfully", file=sys.stderr, flush=True)
        
        return token
    
    def run(self):
        """Run the auth server."""
        import uvicorn
        uvicorn.run(self.app, host="0.0.0.0", port=self.port)


if __name__ == "__main__":
    auth_server = AuthServer("https://auth.example", port=8003)
    auth_server.run()

