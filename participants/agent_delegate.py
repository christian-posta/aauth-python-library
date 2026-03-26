"""Agent delegate participant - acts as agent delegate using agent tokens."""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx
from typing import Dict, Optional
import sys
import os
import json
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aauth.keys.keypair import generate_ed25519_keypair
from aauth.keys.jwk import public_key_to_jwk, generate_jwks
from aauth.signing.signer import sign_request
from aauth.tokens.agent_token import verify_agent_token
from aauth.tokens.auth_token import parse_token_claims
from aauth.debug import _is_debug_enabled, _is_http_debug_enabled


class AgentDelegate:
    """Agent delegate that uses agent tokens to prove delegated identity."""
    
    def __init__(self, agent_server_id: str, delegate_sub: str, port: Optional[int] = None):
        """Initialize agent delegate.
        
        Args:
            agent_server_id: Agent server identifier (HTTPS URL)
            delegate_sub: Delegate identifier (persists across key rotations)
            port: Optional port for delegate server (for demo purposes)
        """
        self.agent_server_id = agent_server_id
        self.delegate_sub = delegate_sub
        self.port = port
        
        # Generate ephemeral key pair (delegate's signing key)
        self.private_key, self.public_key = generate_ed25519_keypair()
        self.kid = "delegate-key-1"
        
        # Phase 6: Agent token storage
        self.agent_token = None
        self.agent_token_expires_at = None
        
        # Create FastAPI app (optional, for demo purposes)
        if port:
            self.app = FastAPI(title="AAuth Agent Delegate")
            self._setup_routes()
    
    def _setup_routes(self):
        """Setup FastAPI routes (for demo purposes)."""
        
        @self.app.get("/")
        async def root():
            return {
                "agent_server_id": self.agent_server_id,
                "delegate_sub": self.delegate_sub,
                "status": "running"
            }
    
    async def request_agent_token(self, aud: Optional[str] = None) -> Optional[str]:
        """Request agent token from agent server.
        
        Args:
            aud: Optional audience restriction
            
        Returns:
            Agent token string, or None if request failed
        """
        debug = _is_debug_enabled()
        http_debug = _is_http_debug_enabled()
        
        if debug:
            print(f"DEBUG DELEGATE: Requesting agent token from agent server", file=sys.stderr, flush=True)
            print(f"DEBUG DELEGATE:   Agent server: {self.agent_server_id}", file=sys.stderr, flush=True)
            print(f"DEBUG DELEGATE:   Delegate sub: {self.delegate_sub}", file=sys.stderr, flush=True)
        
        # Prepare delegate's public key as JWK
        delegate_jwk = public_key_to_jwk(self.public_key, kid=self.kid)
        
        # Build request body
        request_body = {
            "sub": self.delegate_sub,
            "cnf_jwk": delegate_jwk
        }
        if aud:
            request_body["aud"] = aud
        
        request_body_json = json.dumps(request_body)
        request_body_bytes = request_body_json.encode('utf-8')
        
        # For demo, we'll make a simple unsigned request to the agent server
        # In production, this would require proper authentication
        token_endpoint = f"{self.agent_server_id}/delegate/token"
        
        if debug:
            print(f"DEBUG DELEGATE:   Token endpoint: {token_endpoint}", file=sys.stderr, flush=True)
            print(f"DEBUG DELEGATE:   Request body: {request_body_json}", file=sys.stderr, flush=True)
        
        # Make request
        async with httpx.AsyncClient() as client:
            headers = {
                "Content-Type": "application/json"
            }
            
            if http_debug:
                print("\n" + "=" * 80, file=sys.stderr)
                print(f">>> DELEGATE REQUEST to {token_endpoint}", file=sys.stderr)
                print("=" * 80, file=sys.stderr)
                print(f"POST {token_endpoint} HTTP/1.1", file=sys.stderr)
                for name, value in sorted(headers.items()):
                    print(f"{name}: {value}", file=sys.stderr)
                print(f"\n[Body ({len(request_body_bytes)} bytes)]", file=sys.stderr)
                print(request_body_json, file=sys.stderr)
                print("=" * 80 + "\n", file=sys.stderr)
            
            response = await client.post(
                token_endpoint,
                headers=headers,
                json=request_body
            )
            
            if http_debug:
                print("\n" + "=" * 80, file=sys.stderr)
                print(f"<<< DELEGATE RESPONSE from {token_endpoint}", file=sys.stderr)
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
                print(f"DEBUG DELEGATE:   Agent token request failed: {response.status_code}", file=sys.stderr, flush=True)
                try:
                    error_data = response.json()
                    print(f"DEBUG DELEGATE:   Error: {json.dumps(error_data, indent=2)}", file=sys.stderr, flush=True)
                except:
                    print(f"DEBUG DELEGATE:   Error: {response.text}", file=sys.stderr, flush=True)
            return None
        
        # Parse response
        try:
            response_data = response.json()
            agent_token = response_data.get("agent_token")
            expires_in = response_data.get("expires_in", 3600)
            
            if debug:
                print(f"DEBUG DELEGATE:   Agent token received: {agent_token[:100]}...", file=sys.stderr, flush=True)
                print(f"DEBUG DELEGATE:   Expires in: {expires_in} seconds", file=sys.stderr, flush=True)
            
            # Store token
            self.agent_token = agent_token
            self.agent_token_expires_at = int(time.time()) + expires_in
            
            if debug:
                print(f"DEBUG DELEGATE:   Agent token stored successfully", file=sys.stderr, flush=True)
            
            return agent_token
        except Exception as e:
            if debug:
                print(f"DEBUG DELEGATE:   Failed to parse response: {e}", file=sys.stderr, flush=True)
            return None
    
    def sign_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        agent_token: Optional[str] = None
    ) -> Dict[str, str]:
        """Sign an HTTP request using agent token (scheme=jwt).
        
        Args:
            method: HTTP method
            url: Target URL
            headers: Request headers
            body: Request body
            agent_token: Agent token (if None, uses stored token)
            
        Returns:
            Dictionary with Signature-Input, Signature, and Signature-Key headers
        """
        debug = _is_debug_enabled()
        
        if headers is None:
            headers = {}
        
        if body is None:
            body = b""
        
        # Use provided token or stored token
        token_to_use = agent_token or self.agent_token
        if not token_to_use:
            raise ValueError("No agent token available. Call request_agent_token() first.")
        
        if debug:
            print(f"DEBUG DELEGATE: Signing request with agent token: {token_to_use[:100]}...", file=sys.stderr, flush=True)
        
        # Sign request with scheme=jwt and agent token
        sig_headers = sign_request(
            method=method,
            target_uri=url,
            headers=headers,
            body=body,
            private_key=self.private_key,
            sig_scheme="jwt",
            jwt=token_to_use
        )
        
        if debug:
            print(f"DEBUG DELEGATE: Signature-Key header constructed with agent token", file=sys.stderr, flush=True)
            print(f"DEBUG DELEGATE:   Signature-Key: {sig_headers.get('Signature-Key', '')[:100]}...", file=sys.stderr, flush=True)
        
        return sig_headers
    
    async def request_resource(
        self,
        resource_url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None
    ) -> httpx.Response:
        """Make a signed request to a resource using agent token.
        
        Args:
            resource_url: Resource URL
            method: HTTP method
            headers: Request headers
            body: Request body
            
        Returns:
            HTTP response
        """
        debug = _is_debug_enabled()
        
        if headers is None:
            headers = {}
        
        if body is None:
            body = b""
        
        # Ensure we have an agent token
        if not self.agent_token:
            if debug:
                print(f"DEBUG DELEGATE: No agent token, requesting one...", file=sys.stderr, flush=True)
            await self.request_agent_token()
        
        # Check if token is expired
        if self.agent_token_expires_at and int(time.time()) >= self.agent_token_expires_at:
            if debug:
                print(f"DEBUG DELEGATE: Agent token expired, requesting new one...", file=sys.stderr, flush=True)
            await self.request_agent_token()
        
        # Sign the request
        sig_headers = self.sign_request(
            method, resource_url, headers, body,
            agent_token=self.agent_token
        )
        
        # Add signature headers to request
        request_headers = {**headers, **sig_headers}
        
        # Debug: Print HTTP request
        http_debug = _is_http_debug_enabled()
        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print(f">>> DELEGATE REQUEST to {resource_url}", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"{method} {resource_url} HTTP/1.1", file=sys.stderr)
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
        
        # Make request
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=method,
                url=resource_url,
                headers=request_headers,
                content=body
            )
        
        # Debug: Print HTTP response
        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print(f"<<< DELEGATE RESPONSE from {resource_url}", file=sys.stderr)
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
        
        return response
    
    def run(self):
        """Run the delegate server (if port is configured)."""
        if not self.port:
            raise ValueError("Port not configured. Delegate server cannot run.")
        import uvicorn
        uvicorn.run(self.app, host="0.0.0.0", port=self.port)


if __name__ == "__main__":
    delegate = AgentDelegate("http://127.0.0.1:8001", "delegate-1", port=8004)
    delegate.run()

