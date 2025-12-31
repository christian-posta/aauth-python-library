"""Resource participant - protected API that validates signatures."""

from fastapi import FastAPI, Request, Response, Header
from fastapi.responses import JSONResponse
from typing import Optional, Dict
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.httpsig import verify_signature, parse_signature_key, parse_signature_input
from core.crypto_utils import jwk_to_public_key


class Resource:
    """Resource server that validates signatures."""
    
    def __init__(self, resource_id: str, port: int = 8002):
        """Initialize resource.
        
        Args:
            resource_id: Resource identifier (HTTPS URL)
            port: Port to run resource server on
        """
        self.resource_id = resource_id
        self.port = port
        
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
            """Protected endpoint that requires signature."""
            return await self._handle_protected_request(request, "GET")
        
        @self.app.post("/data")
        async def post_data(request: Request):
            """Protected endpoint that requires signature."""
            return await self._handle_protected_request(request, "POST")
    
    async def _handle_protected_request(self, request: Request, method: str):
        """Handle a protected request with signature verification."""
        import os
        import sys
        
        # Get request body first (can only be read once)
        body = await request.body()
        
        # Debug: Print incoming HTTP request (curl-like format)
        if os.environ.get("AAUTH_DEBUG_HTTP"):
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
        
        if not signature_input_header or not signature_header or not signature_key_header:
            response = Response(
                status_code=401,
                headers={"Agent-Auth": "httpsig"},
                content="Missing signature headers"
            )
            if os.environ.get("AAUTH_DEBUG_HTTP"):
                self._print_response_debug(response)
            return response
        
        # Parse signature key to determine scheme
        parsed_key = parse_signature_key(signature_key_header)
        scheme = parsed_key["scheme"]
        params = parsed_key["params"]
        
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
            # FastAPI's request.headers is case-insensitive, but we need exact values
            # Use request.headers.raw to get the exact header values as sent
            headers_dict = {}
            try:
                # Try to get raw headers first (more accurate)
                if hasattr(request, '_headers'):
                    for name, value in request._headers:
                        headers_dict[name.decode('latin-1')] = value.decode('latin-1')
                else:
                    # Fallback to regular headers
                    for name, value in request.headers.items():
                        headers_dict[name] = value
            except:
                # Fallback: use regular headers
                for name, value in request.headers.items():
                    headers_dict[name] = value
            
            # Verify signature
            import os
            if os.environ.get("AAUTH_DEBUG"):
                print(f"DEBUG RESOURCE: Method={method}, URI={target_uri}")
                print(f"DEBUG RESOURCE: Signature-Input={signature_input_header}")
                print(f"DEBUG RESOURCE: Signature-Key={signature_key_header[:80]}...")
                print(f"DEBUG RESOURCE: Headers keys={list(headers_dict.keys())}")
            
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
                import os
                if os.environ.get("AAUTH_DEBUG"):
                    print("DEBUG RESOURCE: Signature verification failed")
                response = Response(
                    status_code=401,
                    headers={"Agent-Auth": "httpsig"},
                    content="Invalid signature"
                )
                if os.environ.get("AAUTH_DEBUG_HTTP"):
                    self._print_response_debug(response)
                return response
            
            # Signature valid - return data
            response = JSONResponse({
                "message": "Access granted",
                "data": "This is protected data",
                "scheme": "hwk",
                "method": method
            })
            if os.environ.get("AAUTH_DEBUG_HTTP"):
                self._print_response_debug(response)
            return response
        
        else:
            response = Response(
                status_code=401,
                headers={"Agent-Auth": "httpsig"},
                content=f"Unsupported signature scheme: {scheme}"
            )
            if os.environ.get("AAUTH_DEBUG_HTTP"):
                self._print_response_debug(response)
            return response
    
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

