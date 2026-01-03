"""Agent participant - acts as agent server using sig=jwks (no delegation)."""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx
from typing import Dict, Optional
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto_utils import generate_ed25519_keypair, public_key_to_jwk, generate_jwks
from core.httpsig import sign_request
from core.metadata import generate_agent_metadata, fetch_auth_metadata
from core import _is_debug_enabled, _is_http_debug_enabled
import json
import re
import threading


class Agent:
    """Agent that requests access to resources."""
    
    def __init__(self, agent_id: str, port: int = 8001, use_user_simulator: bool = True):
        """Initialize agent.
        
        Args:
            agent_id: Agent identifier (HTTPS URL)
            port: Port to run agent server on
            use_user_simulator: If True, use user simulator for automated consent flow.
                               If False, pause and wait for manual browser interaction.
        """
        self.agent_id = agent_id
        self.port = port
        self.use_user_simulator = use_user_simulator
        self.private_key, self.public_key = generate_ed25519_keypair()
        self.kid = "key-1"
        
        # Phase 3: Token storage
        self.auth_token = None
        self.refresh_token = None
        self.resource_token = None  # Store resource token for debug output
        
        # Phase 4: Manual mode - store pending request_token for user interaction
        self.pending_request_token = None
        self.pending_redirect_uri = None
        self.pending_auth_server = None
        self._manual_consent_event = None  # threading.Event to wait for callback (cross-thread safe)
        self._manual_consent_result = None  # Store auth token result
        
        # Create FastAPI app
        self.app = FastAPI(title="AAuth Agent")
        
        # Setup routes
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup FastAPI routes."""
        
        @self.app.get("/")
        async def root():
            return {"agent_id": self.agent_id, "status": "running"}
        
        @self.app.get("/jwks.json")
        async def jwks():
            """JWKS endpoint for Phase 2."""
            jwk = public_key_to_jwk(self.public_key, kid=self.kid)
            return generate_jwks([jwk])
        
        @self.app.get("/.well-known/aauth-agent")
        async def metadata():
            """Agent metadata endpoint per AAuth spec Section 8.1."""
            # Construct JWKS URI from agent_id
            jwks_uri = f"{self.agent_id}/jwks.json"
            return generate_agent_metadata(self.agent_id, jwks_uri)
        
        @self.app.get("/callback")
        async def callback(request: Request):
            """OAuth callback endpoint for Phase 4 user delegation flow."""
            return await self._handle_callback(request)
        
        @self.app.post("/request")
        async def remote_request(request: Request):
            """Remote control endpoint - make a signed request to a resource using agent's keys.
            
            Request body (JSON):
            {
                "resource_url": "http://127.0.0.1:8002/data-auth",
                "method": "GET",
                "headers": {},
                "body": null,
                "sig_scheme": "jwks"
            }
            
            Returns the response from the resource.
            """
            return await self._handle_remote_request(request)
    
    def sign_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        sig_scheme: str = "hwk",
        jwt: Optional[str] = None
    ) -> Dict[str, str]:
        """Sign an HTTP request.
        
        Args:
            method: HTTP method
            url: Target URL
            headers: Request headers
            body: Request body
            sig_scheme: Signature scheme - "hwk" (Phase 1), "jwks" (Phase 2), or "jwt" (Phase 3)
            jwt: JWT token for sig=jwt scheme (auth token for Phase 3)
            
        Returns:
            Dictionary with Signature-Input, Signature, and Signature-Key headers
        """
        debug = _is_debug_enabled()
        
        if headers is None:
            headers = {}
        
        if body is None:
            body = b""
        
        # Prepare kwargs for signature schemes
        kwargs = {}
        if sig_scheme == "jwks":
            kwargs["id"] = self.agent_id
            kwargs["kid"] = self.kid
            # Default to "aauth-agent" for AAuth agent pattern (backward compatible)
            # Can be set to None to use direct JWKS pattern (fetch {id} as JWKS)
            kwargs["well-known"] = "aauth-agent"
        elif sig_scheme == "jwt":
            if not jwt:
                raise ValueError("sig=jwt requires 'jwt' parameter")
            kwargs["jwt"] = jwt
            if debug:
                print(f"DEBUG AGENT: Using sig=jwt with auth token: {jwt[:100]}...", file=sys.stderr, flush=True)
        
        sig_headers = sign_request(
            method=method,
            target_uri=url,
            headers=headers,
            body=body,
            private_key=self.private_key,
            sig_scheme=sig_scheme,
            **kwargs
        )
        
        if debug and sig_scheme == "jwt":
            print(f"DEBUG AGENT: Signature-Key header constructed with jwt parameter", file=sys.stderr, flush=True)
            print(f"DEBUG AGENT:   Signature-Key: {sig_headers.get('Signature-Key', '')[:100]}...", file=sys.stderr, flush=True)
        
        return sig_headers
    
    async def request_resource(
        self,
        resource_url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        sig_scheme: str = "hwk"
    ) -> httpx.Response:
        """Make a signed request to a resource.
        
        Phase 3: Automatically handles auth token challenges and retries with auth token.
        
        Args:
            resource_url: Resource URL
            method: HTTP method
            headers: Request headers
            body: Request body
            sig_scheme: Signature scheme - "hwk" (Phase 1), "jwks" (Phase 2), or "jwt" (Phase 3)
            
        Returns:
            HTTP response
        """
        debug = _is_debug_enabled()
        
        if headers is None:
            headers = {}
        
        if body is None:
            body = b""
        
        # Phase 3: Use auth token if available and sig_scheme allows
        if sig_scheme != "jwt" and self.auth_token:
            # Try with auth token first
            if debug:
                print(f"DEBUG AGENT: Using stored auth token for request", file=sys.stderr, flush=True)
            sig_scheme = "jwt"
        
        # Sign the request
        sig_headers = self.sign_request(
            method, resource_url, headers, body,
            sig_scheme=sig_scheme,
            jwt=self.auth_token if sig_scheme == "jwt" else None
        )
        
        # Add signature headers to request
        request_headers = {**headers, **sig_headers}
        
        # Debug: Print HTTP request (curl-like format)
        if _is_http_debug_enabled():
            print("\n" + "=" * 80, file=sys.stderr)
            print(f">>> AGENT REQUEST to {resource_url}", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"{method} {resource_url} HTTP/1.1", file=sys.stderr)
            for name, value in sorted(request_headers.items()):
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
        
        # Make request
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=method,
                url=resource_url,
                headers=request_headers,
                content=body
            )
        
        # Debug: Print HTTP response (curl-like format)
        if _is_http_debug_enabled():
            print("\n" + "=" * 80, file=sys.stderr)
            print(f"<<< AGENT RESPONSE from {resource_url}", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"HTTP/1.1 {response.status_code} {response.reason_phrase}", file=sys.stderr)
            for name, value in sorted(response.headers.items()):
                # Truncate long values for readability
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
        
        # Phase 3: Handle auth token challenge
        if response.status_code == 401:
            agent_auth_header = response.headers.get("agent-auth", "")
            if debug:
                print(f"DEBUG AGENT: Received 401 response, checking Agent-Auth header", file=sys.stderr, flush=True)
                print(f"DEBUG AGENT:   Agent-Auth: {agent_auth_header}", file=sys.stderr, flush=True)
            
            # Check if this is an auth token challenge
            if "auth-token" in agent_auth_header.lower() and "resource_token" in agent_auth_header.lower():
                if debug:
                    print(f"DEBUG AGENT: Detected auth token challenge", file=sys.stderr, flush=True)
                
                # Extract resource_token and auth_server
                challenge_info = self._handle_auth_challenge(response)
                if challenge_info:
                    resource_token = challenge_info.get("resource_token")
                    auth_server = challenge_info.get("auth_server")
                    
                    if resource_token and auth_server:
                        # Store resource token for debug output
                        self.resource_token = resource_token
                        
                        if debug:
                            print(f"DEBUG AGENT: Extracted resource_token and auth_server", file=sys.stderr, flush=True)
                            print(f"DEBUG AGENT:   Resource token: {resource_token[:100]}...", file=sys.stderr, flush=True)
                            print(f"DEBUG AGENT:   Auth server: {auth_server}", file=sys.stderr, flush=True)
                        
                        # Request auth token
                        auth_token = await self._request_auth_token(resource_token, auth_server)
                        if auth_token:
                            if debug:
                                print(f"DEBUG AGENT: Auth token obtained, retrying request", file=sys.stderr, flush=True)
                            
                            # Retry request with auth token
                            return await self.request_resource(
                                resource_url=resource_url,
                                method=method,
                                headers=headers,
                                body=body,
                                sig_scheme="jwt"
                            )
        
        return response
    
    def _handle_auth_challenge(self, response: httpx.Response) -> Optional[Dict[str, str]]:
        """Parse Agent-Auth challenge header to extract resource_token and auth_server.
        
        Args:
            response: HTTP response with Agent-Auth header
            
        Returns:
            Dictionary with 'resource_token' and 'auth_server' keys, or None if not found
        """
        debug = _is_debug_enabled()
        
        agent_auth_header = response.headers.get("agent-auth", "")
        if not agent_auth_header:
            if debug:
                print(f"DEBUG AGENT: No Agent-Auth header found", file=sys.stderr, flush=True)
            return None
        
        if debug:
            print(f"DEBUG AGENT: Parsing Agent-Auth header: {agent_auth_header}", file=sys.stderr, flush=True)
        
        # Parse Agent-Auth header: httpsig; auth-token; resource_token="..."; auth_server="..."
        # Extract resource_token="..." and auth_server="..."
        result = {}
        
        # Extract resource_token
        resource_token_match = re.search(r'resource_token="([^"]+)"', agent_auth_header)
        if resource_token_match:
            result["resource_token"] = resource_token_match.group(1)
            if debug:
                print(f"DEBUG AGENT:   Extracted resource_token: {result['resource_token'][:100]}...", file=sys.stderr, flush=True)
        else:
            if debug:
                print(f"DEBUG AGENT:   No resource_token found in Agent-Auth header", file=sys.stderr, flush=True)
            return None
        
        # Extract auth_server
        auth_server_match = re.search(r'auth_server="([^"]+)"', agent_auth_header)
        if auth_server_match:
            result["auth_server"] = auth_server_match.group(1)
            if debug:
                print(f"DEBUG AGENT:   Extracted auth_server: {result['auth_server']}", file=sys.stderr, flush=True)
        else:
            if debug:
                print(f"DEBUG AGENT:   No auth_server found in Agent-Auth header", file=sys.stderr, flush=True)
            return None
        
        return result
    
    async def request_self_authorization(self, scope: str, auth_server: str, redirect_uri: Optional[str] = None) -> Optional[str]:
        """Request authorization directly from auth server (Phase 5: agent is resource).
        
        The agent requests authorization to itself, providing scope directly instead of a resource_token.
        This enables SSO and API access with a unified auth token.
        
        Args:
            scope: Space-separated scope values (e.g., "profile email")
            auth_server: Auth server identifier (HTTPS URL)
            redirect_uri: Optional redirect URI (defaults to {agent_id}/callback)
            
        Returns:
            Auth token string, or None if request failed
        """
        debug = _is_debug_enabled()
        http_debug = _is_http_debug_enabled()
        
        if redirect_uri is None:
            redirect_uri = f"{self.agent_id}/callback"
        
        if debug:
            print(f"DEBUG AGENT: Requesting self-authorization (Phase 5: agent is resource)", file=sys.stderr, flush=True)
            print(f"DEBUG AGENT:   Auth server: {auth_server}", file=sys.stderr, flush=True)
            print(f"DEBUG AGENT:   Scope: {scope}", file=sys.stderr, flush=True)
            print(f"DEBUG AGENT:   Redirect URI: {redirect_uri}", file=sys.stderr, flush=True)
        
        # Fetch auth server metadata to get token endpoint
        try:
            metadata_url = f"{auth_server}/.well-known/aauth-issuer"
            metadata = fetch_auth_metadata(metadata_url)
            token_endpoint = metadata.get("agent_token_endpoint")
            if debug:
                print(f"DEBUG AGENT:   Token endpoint: {token_endpoint}", file=sys.stderr, flush=True)
        except Exception as e:
            if debug:
                print(f"DEBUG AGENT:   Failed to fetch auth server metadata: {e}", file=sys.stderr, flush=True)
            return None
        
        # Build request body with scope (no resource_token)
        body_params = {
            "request_type": "auth",
            "scope": scope,
            "redirect_uri": redirect_uri
        }
        body_text = "&".join([f"{k}={v}" for k, v in body_params.items()])
        body_bytes = body_text.encode('utf-8')
        
        if debug:
            print(f"DEBUG AGENT:   Request body: {body_text}", file=sys.stderr, flush=True)
        
        # Sign request with sig=jwks (agent server identity)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        sig_headers = self.sign_request(
            method="POST",
            url=token_endpoint,
            headers=headers,
            body=body_bytes,
            sig_scheme="jwks"
        )
        
        request_headers = {**headers, **sig_headers}
        
        # Debug: Print HTTP request
        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print(f">>> AGENT REQUEST to {token_endpoint}", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"POST {token_endpoint} HTTP/1.1", file=sys.stderr)
            for name, value in sorted(request_headers.items()):
                display_value = value
                if len(display_value) > 100:
                    display_value = display_value[:97] + "..."
                print(f"{name}: {display_value}", file=sys.stderr)
            print(f"\n[Body ({len(body_bytes)} bytes)]", file=sys.stderr)
            print(body_text, file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)
        
        # Make request
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method="POST",
                url=token_endpoint,
                headers=request_headers,
                content=body_bytes
            )
        
        # Debug: Print HTTP response
        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print(f"<<< AGENT RESPONSE from {token_endpoint}", file=sys.stderr)
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
                print(f"DEBUG AGENT:   Self-authorization request failed: {response.status_code}", file=sys.stderr, flush=True)
                try:
                    error_data = response.json()
                    print(f"DEBUG AGENT:   Error: {json.dumps(error_data, indent=2)}", file=sys.stderr, flush=True)
                except:
                    print(f"DEBUG AGENT:   Error: {response.text}", file=sys.stderr, flush=True)
            return None
        
        # Parse response
        try:
            response_data = response.json()
            
            # Check for request_token (user consent required)
            request_token = response_data.get("request_token")
            if request_token:
                if debug:
                    print(f"DEBUG AGENT:   Request token received: {request_token[:50]}...", file=sys.stderr, flush=True)
                    print(f"DEBUG AGENT:   User consent required, handling request_token...", file=sys.stderr, flush=True)
                
                # Handle user consent flow
                auth_token = await self._handle_request_token(request_token, auth_server, redirect_uri)
                return auth_token
            
            # Direct grant (autonomous authorization)
            auth_token = response_data.get("auth_token")
            refresh_token = response_data.get("refresh_token")
            
            if debug:
                print(f"DEBUG AGENT:   Auth token received: {auth_token[:100]}...", file=sys.stderr, flush=True)
                if refresh_token:
                    print(f"DEBUG AGENT:   Refresh token received: {refresh_token[:100]}...", file=sys.stderr, flush=True)
            
            # Store tokens
            self.auth_token = auth_token
            self.refresh_token = refresh_token
            
            if debug:
                print(f"DEBUG AGENT:   Tokens stored successfully", file=sys.stderr, flush=True)
            
            return auth_token
        except Exception as e:
            if debug:
                print(f"DEBUG AGENT:   Failed to parse response: {e}", file=sys.stderr, flush=True)
            return None
    
    async def _request_auth_token(self, resource_token: str, auth_server: str) -> Optional[str]:
        """Request auth token from auth server.
        
        Args:
            resource_token: Resource token from challenge
            auth_server: Auth server identifier (HTTPS URL)
            
        Returns:
            Auth token string, or None if request failed
        """
        debug = _is_debug_enabled()
        http_debug = _is_http_debug_enabled()
        
        if debug:
            print(f"DEBUG AGENT: Requesting auth token from auth server", file=sys.stderr, flush=True)
            print(f"DEBUG AGENT:   Auth server: {auth_server}", file=sys.stderr, flush=True)
            print(f"DEBUG AGENT:   Resource token: {resource_token[:100]}...", file=sys.stderr, flush=True)
        
        # Fetch auth server metadata to get token endpoint
        try:
            metadata_url = f"{auth_server}/.well-known/aauth-issuer"
            metadata = fetch_auth_metadata(metadata_url)
            token_endpoint = metadata.get("agent_token_endpoint")
            if debug:
                print(f"DEBUG AGENT:   Token endpoint: {token_endpoint}", file=sys.stderr, flush=True)
        except Exception as e:
            if debug:
                print(f"DEBUG AGENT:   Failed to fetch auth server metadata: {e}", file=sys.stderr, flush=True)
            return None
        
        # Build request body (redirect_uri is REQUIRED per SPEC.md Section 9.3, even for autonomous flows)
        # For Phase 3 autonomous flow, we use a placeholder redirect_uri since user interaction isn't needed
        redirect_uri = f"{self.agent_id}/callback"  # Placeholder for Phase 3
        
        body_params = {
            "request_type": "auth",
            "resource_token": resource_token,
            "redirect_uri": redirect_uri
        }
        body_text = "&".join([f"{k}={v}" for k, v in body_params.items()])
        body_bytes = body_text.encode('utf-8')
        
        if debug:
            print(f"DEBUG AGENT:   redirect_uri: {redirect_uri} (required by spec, not used for Phase 3 autonomous)", file=sys.stderr, flush=True)
        
        if debug:
            print(f"DEBUG AGENT:   Request body: {body_text}", file=sys.stderr, flush=True)
        
        # Sign request with sig=jwks (agent server identity)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        sig_headers = self.sign_request(
            method="POST",
            url=token_endpoint,
            headers=headers,
            body=body_bytes,
            sig_scheme="jwks"
        )
        
        request_headers = {**headers, **sig_headers}
        
        # Debug: Print HTTP request
        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print(f">>> AGENT REQUEST to {token_endpoint}", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"POST {token_endpoint} HTTP/1.1", file=sys.stderr)
            for name, value in sorted(request_headers.items()):
                display_value = value
                if len(display_value) > 100:
                    display_value = display_value[:97] + "..."
                print(f"{name}: {display_value}", file=sys.stderr)
            print(f"\n[Body ({len(body_bytes)} bytes)]", file=sys.stderr)
            print(body_text, file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)
        
        # Make request
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method="POST",
                url=token_endpoint,
                headers=request_headers,
                content=body_bytes
            )
        
        # Debug: Print HTTP response
        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print(f"<<< AGENT RESPONSE from {token_endpoint}", file=sys.stderr)
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
                print(f"DEBUG AGENT:   Auth token request failed: {response.status_code}", file=sys.stderr, flush=True)
                try:
                    error_data = response.json()
                    print(f"DEBUG AGENT:   Error: {json.dumps(error_data, indent=2)}", file=sys.stderr, flush=True)
                except:
                    print(f"DEBUG AGENT:   Error: {response.text}", file=sys.stderr, flush=True)
            return None
        
        # Parse response
        try:
            response_data = response.json()
            
            # Phase 4: Check for request_token (user consent required)
            request_token = response_data.get("request_token")
            if request_token:
                if debug:
                    print(f"DEBUG AGENT:   Request token received: {request_token[:50]}...", file=sys.stderr, flush=True)
                    print(f"DEBUG AGENT:   User consent required, handling request_token...", file=sys.stderr, flush=True)
                
                # Handle user consent flow
                redirect_uri = f"{self.agent_id}/callback"
                auth_token = await self._handle_request_token(request_token, auth_server, redirect_uri)
                return auth_token
            
            # Phase 3: Direct grant (autonomous authorization)
            auth_token = response_data.get("auth_token")
            refresh_token = response_data.get("refresh_token")
            
            if debug:
                print(f"DEBUG AGENT:   Auth token received: {auth_token[:100]}...", file=sys.stderr, flush=True)
                if refresh_token:
                    print(f"DEBUG AGENT:   Refresh token received: {refresh_token[:100]}...", file=sys.stderr, flush=True)
            
            # Store tokens
            self.auth_token = auth_token
            self.refresh_token = refresh_token
            
            if debug:
                print(f"DEBUG AGENT:   Tokens stored successfully", file=sys.stderr, flush=True)
            
            return auth_token
        except Exception as e:
            if debug:
                print(f"DEBUG AGENT:   Failed to parse response: {e}", file=sys.stderr, flush=True)
            return None
    
    async def _handle_request_token(
        self,
        request_token: str,
        auth_server: str,
        redirect_uri: str
    ) -> Optional[str]:
        """Handle request_token response - complete user consent flow.
        
        Args:
            request_token: Request token from auth server
            auth_server: Auth server identifier
            redirect_uri: Agent's callback URI
            
        Returns:
            Auth token if successful, None otherwise
        """
        debug = _is_debug_enabled()
        
        if debug:
            print(f"DEBUG AGENT: Handling request_token", file=sys.stderr, flush=True)
            print(f"DEBUG AGENT:   Auth server: {auth_server}", file=sys.stderr, flush=True)
            print(f"DEBUG AGENT:   Redirect URI: {redirect_uri}", file=sys.stderr, flush=True)
        
        # Fetch auth server metadata to get agent_auth_endpoint
        try:
            metadata = fetch_auth_metadata(f"{auth_server}/.well-known/aauth-issuer")
            auth_endpoint = metadata.get("agent_auth_endpoint")
            
            if not auth_endpoint:
                if debug:
                    print(f"DEBUG AGENT:   No agent_auth_endpoint in metadata", file=sys.stderr, flush=True)
                return None
            
            if debug:
                print(f"DEBUG AGENT:   Auth endpoint: {auth_endpoint}", file=sys.stderr, flush=True)
            
            # Construct redirect URL
            redirect_url = f"{auth_endpoint}?request_token={request_token}&redirect_uri={redirect_uri}"
            
            if debug:
                print(f"DEBUG AGENT:   Redirect URL: {redirect_url}", file=sys.stderr, flush=True)
            
            # Check if we should use user simulator or wait for manual interaction
            if self.use_user_simulator:
                if debug:
                    print(f"DEBUG AGENT:   Using user simulator to complete flow...", file=sys.stderr, flush=True)
                
                # Use user simulator to complete the flow
                from participants.user_simulator import UserSimulator
                user_sim = UserSimulator()
                
                code = await user_sim.complete_flow(redirect_url, redirect_uri, auth_server)
                
                if not code:
                    if debug:
                        print(f"DEBUG AGENT:   Failed to obtain authorization code", file=sys.stderr, flush=True)
                    return None
                
                if debug:
                    print(f"DEBUG AGENT:   Authorization code received: {code[:20]}...", file=sys.stderr, flush=True)
                
                # Exchange code for tokens
                return await self._exchange_authorization_code(code, redirect_uri, auth_server)
            else:
                # Manual mode: Store request details and wait for user to complete consent
                # Always print the URL (not just in debug mode) so user knows what to do
                print(f"\n" + "=" * 80, file=sys.stderr)
                print("MANUAL CONSENT REQUIRED", file=sys.stderr)
                print("=" * 80, file=sys.stderr)
                print(f"\nPlease open the following URL in your browser:", file=sys.stderr)
                print(f"\n  {redirect_url}\n", file=sys.stderr)
                print("After granting consent, the agent will automatically exchange the code.", file=sys.stderr)
                print("Waiting for authorization code...", file=sys.stderr)
                print("=" * 80 + "\n", file=sys.stderr)
                
                if debug:
                    print(f"DEBUG AGENT:   Manual mode - waiting for user to complete consent in browser", file=sys.stderr, flush=True)
                
                # Store pending request details
                self.pending_request_token = request_token
                self.pending_redirect_uri = redirect_uri
                self.pending_auth_server = auth_server
                
                # Create threading.Event for cross-thread synchronization
                # (agent server runs in separate thread with its own event loop)
                self._manual_consent_event = threading.Event()
                self._manual_consent_result = None
                
                if debug:
                    print(f"DEBUG AGENT:   Created _manual_consent_event: {self._manual_consent_event}", file=sys.stderr, flush=True)
                    print(f"DEBUG AGENT:   Waiting for user to complete consent flow...", file=sys.stderr, flush=True)
                
                # Wait for callback to receive the code and exchange it
                # Use run_in_executor to wait on threading.Event without blocking event loop
                # Wait on threading.Event in a thread pool to avoid blocking the event loop
                import asyncio
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = asyncio.get_event_loop()
                
                if debug:
                    print(f"DEBUG AGENT:   Using event loop: {loop}", file=sys.stderr, flush=True)
                    print(f"DEBUG AGENT:   Calling run_in_executor to wait on event...", file=sys.stderr, flush=True)
                
                await loop.run_in_executor(None, self._manual_consent_event.wait)
                
                if debug:
                    print(f"DEBUG AGENT:   Event wait completed!", file=sys.stderr, flush=True)
                
                if debug:
                    print(f"DEBUG AGENT:   Consent flow completed", file=sys.stderr, flush=True)
                
                # Get the result (auth token or None)
                result = self._manual_consent_result
                self._manual_consent_event = None
                self._manual_consent_result = None
                
                return result
            
        except Exception as e:
            if debug:
                print(f"DEBUG AGENT:   Error handling request_token: {e}", file=sys.stderr, flush=True)
            return None
    
    async def _exchange_authorization_code(
        self,
        code: str,
        redirect_uri: str,
        auth_server: str
    ) -> Optional[str]:
        """Exchange authorization code for auth token.
        
        Args:
            code: Authorization code
            redirect_uri: Redirect URI used in original request
            auth_server: Auth server identifier
            
        Returns:
            Auth token if successful, None otherwise
        """
        debug = _is_debug_enabled()
        
        if debug:
            print(f"DEBUG AGENT: Exchanging authorization code", file=sys.stderr, flush=True)
            print(f"DEBUG AGENT:   Code: {code[:20]}...", file=sys.stderr, flush=True)
            print(f"DEBUG AGENT:   Auth server: {auth_server}", file=sys.stderr, flush=True)
        
        # Fetch token endpoint from metadata
        try:
            metadata = fetch_auth_metadata(f"{auth_server}/.well-known/aauth-issuer")
            token_endpoint = metadata.get("agent_token_endpoint")
            
            if not token_endpoint:
                if debug:
                    print(f"DEBUG AGENT:   No agent_token_endpoint in metadata", file=sys.stderr, flush=True)
                return None
            
            # Build request body
            body_data = {
                "request_type": "code",
                "code": code,
                "redirect_uri": redirect_uri
            }
            body_text = "&".join([f"{k}={v}" for k, v in body_data.items()])
            body_bytes = body_text.encode('utf-8')
            
            # Prepare headers for signing (sign_request will add Content-Digest)
            request_headers = {"Content-Type": "application/x-www-form-urlencoded"}
            
            # Sign request (this will modify request_headers to add Content-Digest)
            sig_headers = self.sign_request(
                method="POST",
                url=token_endpoint,
                headers=request_headers,
                body=body_bytes,
                sig_scheme="jwks"
            )
            
            # Make request (sig_headers includes Signature-Input, Signature, Signature-Key)
            # request_headers now includes Content-Digest (added by sign_request)
            async with httpx.AsyncClient() as client:
                headers = {
                    **request_headers,  # Includes Content-Type and Content-Digest
                    **sig_headers       # Includes Signature-Input, Signature, Signature-Key
                }
                
                response = await client.post(
                    token_endpoint,
                    headers=headers,
                    content=body_bytes
                )
            
            if response.status_code != 200:
                if debug:
                    print(f"DEBUG AGENT:   Code exchange failed: {response.status_code}", file=sys.stderr, flush=True)
                    try:
                        error_data = response.json()
                        print(f"DEBUG AGENT:   Error: {error_data}", file=sys.stderr, flush=True)
                    except:
                        print(f"DEBUG AGENT:   Error: {response.text}", file=sys.stderr, flush=True)
                return None
            
            # Parse response
            try:
                response_data = response.json()
                auth_token = response_data.get("auth_token")
                refresh_token = response_data.get("refresh_token")
                
                if debug:
                    print(f"DEBUG AGENT:   Auth token received: {auth_token[:100]}...", file=sys.stderr, flush=True)
                    if refresh_token:
                        print(f"DEBUG AGENT:   Refresh token received: {refresh_token[:100]}...", file=sys.stderr, flush=True)
                
                # Store tokens
                self.auth_token = auth_token
                self.refresh_token = refresh_token
                
                if debug:
                    print(f"DEBUG AGENT:   Tokens stored successfully", file=sys.stderr, flush=True)
                
                return auth_token
            except Exception as e:
                if debug:
                    print(f"DEBUG AGENT:   Failed to parse response: {e}", file=sys.stderr, flush=True)
                return None
                
        except Exception as e:
            if debug:
                print(f"DEBUG AGENT:   Error exchanging code: {e}", file=sys.stderr, flush=True)
            return None
    
    async def _handle_callback(self, request: Request):
        """Handle OAuth callback with authorization code.
        
        This endpoint receives the redirect from the auth server after user consent.
        """
        from fastapi.responses import HTMLResponse
        
        debug = _is_debug_enabled()
        
        # Extract code from query parameters
        code = request.query_params.get("code")
        error = request.query_params.get("error")
        error_description = request.query_params.get("error_description")
        
        if debug:
            print(f"DEBUG AGENT: Callback received", file=sys.stderr, flush=True)
            if code:
                print(f"DEBUG AGENT:   Code: {code[:20]}...", file=sys.stderr, flush=True)
            if error:
                print(f"DEBUG AGENT:   Error: {error}", file=sys.stderr, flush=True)
        
        if error:
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Authorization Failed</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 500px;
            margin: 50px auto;
            padding: 20px;
        }}
        .error {{
            background: #fee;
            border: 1px solid #fcc;
            padding: 15px;
            border-radius: 4px;
            color: #c33;
        }}
    </style>
</head>
<body>
    <h1>Authorization Failed</h1>
    <div class="error">
        <strong>Error:</strong> {error}<br>
        {error_description if error_description else ''}
    </div>
</body>
</html>"""
            return HTMLResponse(content=html, status_code=400)
        
        if code:
            # In manual mode, exchange the code for tokens
            if debug:
                print(f"DEBUG AGENT:   Callback received code, checking mode...", file=sys.stderr, flush=True)
                print(f"DEBUG AGENT:     use_user_simulator: {self.use_user_simulator}", file=sys.stderr, flush=True)
                print(f"DEBUG AGENT:     pending_redirect_uri: {self.pending_redirect_uri}", file=sys.stderr, flush=True)
                print(f"DEBUG AGENT:     _manual_consent_event: {self._manual_consent_event}", file=sys.stderr, flush=True)
            
            if not self.use_user_simulator and self.pending_redirect_uri:
                if debug:
                    print(f"DEBUG AGENT:   Manual mode - exchanging authorization code for tokens", file=sys.stderr, flush=True)
                
                # Exchange code for tokens
                auth_token = await self._exchange_authorization_code(
                    code,
                    self.pending_redirect_uri,
                    self.pending_auth_server
                )
                
                # Store result and signal the waiting coroutine
                self._manual_consent_result = auth_token
                
                if debug:
                    print(f"DEBUG AGENT:   Stored auth_token result, signaling event...", file=sys.stderr, flush=True)
                
                # Signal the event to wake up the waiting coroutine
                if self._manual_consent_event:
                    if debug:
                        print(f"DEBUG AGENT:   Setting _manual_consent_event...", file=sys.stderr, flush=True)
                    self._manual_consent_event.set()
                    if debug:
                        print(f"DEBUG AGENT:   Event set successfully", file=sys.stderr, flush=True)
                else:
                    if debug:
                        print(f"DEBUG AGENT:   WARNING: _manual_consent_event is None!", file=sys.stderr, flush=True)
                
                # Clear pending state AFTER signaling
                self.pending_request_token = None
                self.pending_redirect_uri = None
                self.pending_auth_server = None
                
                if auth_token:
                    if debug:
                        print(f"DEBUG AGENT:   ✓ Tokens obtained successfully!", file=sys.stderr, flush=True)
                    html = """<!DOCTYPE html>
<html>
<head>
    <title>Authorization Successful</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 500px;
            margin: 50px auto;
            padding: 20px;
        }}
        .success {{
            background: #efe;
            border: 1px solid #cfc;
            padding: 15px;
            border-radius: 4px;
            color: #3c3;
        }}
    </style>
</head>
<body>
    <h1>Authorization Successful</h1>
    <div class="success">
        Authorization code received and exchanged for tokens. The agent can now access the resource.
    </div>
</body>
</html>"""
                else:
                    html = """<!DOCTYPE html>
<html>
<head>
    <title>Authorization Error</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 500px;
            margin: 50px auto;
            padding: 20px;
        }}
        .error {{
            background: #fee;
            border: 1px solid #fcc;
            padding: 15px;
            border-radius: 4px;
            color: #c33;
        }}
    </style>
</head>
<body>
    <h1>Authorization Error</h1>
    <div class="error">
        Failed to exchange authorization code for tokens. Check the agent logs for details.
    </div>
</body>
</html>"""
                return HTMLResponse(content=html)
            else:
                # Automated mode - just return success page
                html = """<!DOCTYPE html>
<html>
<head>
    <title>Authorization Successful</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 500px;
            margin: 50px auto;
            padding: 20px;
        }}
        .success {{
            background: #efe;
            border: 1px solid #cfc;
            padding: 15px;
            border-radius: 4px;
            color: #3c3;
        }}
    </style>
</head>
<body>
    <h1>Authorization Successful</h1>
    <div class="success">
        Authorization code received. The agent will exchange it for tokens automatically.
    </div>
</body>
</html>"""
            return HTMLResponse(content=html)
        
        return HTMLResponse(
            content="<html><body><h1>Error</h1><p>No code or error parameter</p></body></html>",
            status_code=400
        )
    
    async def _handle_remote_request(self, request: Request):
        """Handle remote request endpoint - make signed request to resource using agent's keys."""
        from fastapi.responses import Response
        import json
        
        debug = _is_debug_enabled()
        
        try:
            # Parse request body
            body_data = await request.json()
            resource_url = body_data.get("resource_url")
            method = body_data.get("method", "GET")
            headers = body_data.get("headers", {})
            body = body_data.get("body")
            sig_scheme = body_data.get("sig_scheme", "jwks")
            
            if not resource_url:
                return JSONResponse(
                    status_code=400,
                    content={"error": "missing_resource_url", "error_description": "resource_url is required"}
                )
            
            if debug:
                print(f"DEBUG AGENT: Remote request received:", file=sys.stderr, flush=True)
                print(f"DEBUG AGENT:   Resource URL: {resource_url}", file=sys.stderr, flush=True)
                print(f"DEBUG AGENT:   Method: {method}", file=sys.stderr, flush=True)
                print(f"DEBUG AGENT:   Sig scheme: {sig_scheme}", file=sys.stderr, flush=True)
            
            # Convert body to bytes if provided
            body_bytes = None
            if body is not None:
                if isinstance(body, str):
                    body_bytes = body.encode('utf-8')
                elif isinstance(body, bytes):
                    body_bytes = body
                else:
                    body_bytes = json.dumps(body).encode('utf-8')
            
            # Make request using agent's keys
            response = await self.request_resource(
                resource_url=resource_url,
                method=method,
                headers=headers,
                body=body_bytes,
                sig_scheme=sig_scheme
            )
            
            # Return response
            response_body = await response.aread()
            
            return Response(
                content=response_body,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get("content-type", "application/json")
            )
            
        except Exception as e:
            if debug:
                print(f"DEBUG AGENT: Error handling remote request: {e}", file=sys.stderr, flush=True)
                import traceback
                traceback.print_exc()
            return JSONResponse(
                status_code=500,
                content={"error": "server_error", "error_description": str(e)}
            )
    
    def run(self):
        """Run the agent server."""
        import uvicorn
        uvicorn.run(self.app, host="0.0.0.0", port=self.port)


if __name__ == "__main__":
    agent = Agent("https://agent.example", port=8001)
    agent.run()

