"""Agent participant - acts as agent server using sig=jwks (no delegation)."""

from fastapi import FastAPI
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
import json
import re


def _is_debug_enabled(env_var: str = "AAUTH_DEBUG") -> bool:
    """Check if debug is enabled (defaults to True unless explicitly disabled)."""
    value = os.environ.get(env_var, "1")
    return value.lower() not in ("0", "false", "no", "off", "")


def _is_http_debug_enabled() -> bool:
    """Check if HTTP debug is enabled (defaults to True unless explicitly disabled)."""
    return _is_debug_enabled("AAUTH_DEBUG_HTTP")


class Agent:
    """Agent that requests access to resources."""
    
    def __init__(self, agent_id: str, port: int = 8001):
        """Initialize agent.
        
        Args:
            agent_id: Agent identifier (HTTPS URL)
            port: Port to run agent server on
        """
        self.agent_id = agent_id
        self.port = port
        self.private_key, self.public_key = generate_ed25519_keypair()
        self.kid = "key-1"
        
        # Phase 3: Token storage
        self.auth_token = None
        self.refresh_token = None
        
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
    
    def run(self):
        """Run the agent server."""
        import uvicorn
        uvicorn.run(self.app, host="0.0.0.0", port=self.port)


if __name__ == "__main__":
    agent = Agent("https://agent.example", port=8001)
    agent.run()

