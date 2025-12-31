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
from core.metadata import generate_agent_metadata


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
        sig_scheme: str = "hwk"
    ) -> Dict[str, str]:
        """Sign an HTTP request.
        
        Args:
            method: HTTP method
            url: Target URL
            headers: Request headers
            body: Request body
            sig_scheme: Signature scheme - "hwk" (Phase 1) or "jwks" (Phase 2)
            
        Returns:
            Dictionary with Signature-Input, Signature, and Signature-Key headers
        """
        if headers is None:
            headers = {}
        
        if body is None:
            body = b""
        
        # Prepare kwargs for sig=jwks
        kwargs = {}
        if sig_scheme == "jwks":
            kwargs["id"] = self.agent_id
            kwargs["kid"] = self.kid
        
        sig_headers = sign_request(
            method=method,
            target_uri=url,
            headers=headers,
            body=body,
            private_key=self.private_key,
            sig_scheme=sig_scheme,
            **kwargs
        )
        
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
        
        Args:
            resource_url: Resource URL
            method: HTTP method
            headers: Request headers
            body: Request body
            sig_scheme: Signature scheme - "hwk" (Phase 1) or "jwks" (Phase 2)
            
        Returns:
            HTTP response
        """
        import os
        import sys
        
        if headers is None:
            headers = {}
        
        if body is None:
            body = b""
        
        # Sign the request
        sig_headers = self.sign_request(method, resource_url, headers, body, sig_scheme=sig_scheme)
        
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
        
        return response
    
    def run(self):
        """Run the agent server."""
        import uvicorn
        uvicorn.run(self.app, host="0.0.0.0", port=self.port)


if __name__ == "__main__":
    agent = Agent("https://agent.example", port=8001)
    agent.run()

