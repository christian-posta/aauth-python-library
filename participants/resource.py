"""Resource participant - protected API that validates signatures."""

from fastapi import FastAPI, Request, Response, Header
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.httpsig import verify_signature, parse_signature_key, parse_signature_input
from core.crypto_utils import jwk_to_public_key
from core.metadata import fetch_metadata
import httpx
from typing import Optional


def _is_debug_enabled(env_var: str = "AAUTH_DEBUG") -> bool:
    """Check if debug is enabled (defaults to True unless explicitly disabled)."""
    value = os.environ.get(env_var, "1")
    return value.lower() not in ("0", "false", "no", "off", "")


def _is_http_debug_enabled() -> bool:
    """Check if HTTP debug is enabled (defaults to True unless explicitly disabled)."""
    return _is_debug_enabled("AAUTH_DEBUG_HTTP")


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
    
    async def _handle_protected_request(self, request: Request, method: str, required_scheme: str = "hwk"):
        """Handle a protected request with signature verification.
        
        Args:
            request: FastAPI request object
            method: HTTP method
            required_scheme: Required signature scheme ("hwk" or "jwks")
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
        
        if not signature_input_header or not signature_header or not signature_key_header:
            response = Response(
                status_code=401,
                headers={"Agent-Auth": "httpsig"},
                content="Missing signature headers"
            )
            if _is_http_debug_enabled():
                self._print_response_debug(response)
            return response
        
        # Parse signature key to determine scheme
        try:
            parsed_key = parse_signature_key(signature_key_header)
        except Exception as e:
            response = Response(
                status_code=401,
                headers={"Agent-Auth": "httpsig"},
                content=f"Invalid Signature-Key header: {e}"
            )
            if _is_http_debug_enabled():
                self._print_response_debug(response)
            return response
        
        scheme = parsed_key["scheme"]
        params = parsed_key["params"]
        
        # Verify scheme matches required scheme
        if scheme != required_scheme:
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE: Scheme mismatch - required={required_scheme}, got={scheme}", file=sys.stderr, flush=True)
            response = Response(
                status_code=401,
                headers={"Agent-Auth": "httpsig"},
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
            # Extract agent_id and kid from Signature-Key
            agent_id = params.get("id")
            kid = params.get("kid")
            
            if not agent_id or not kid:
                response = Response(
                    status_code=401,
                    headers={"Agent-Auth": "httpsig"},
                    content="Missing id or kid in Signature-Key for sig=jwks"
                )
                if _is_http_debug_enabled():
                    self._print_response_debug(response)
                return response
            
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE: sig=jwks - agent_id={agent_id}, kid={kid}", file=sys.stderr, flush=True)
            
            # Create jwks_fetcher callback
            def jwks_fetcher(agent_id_param: str, kid_param: str):
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
        
        else:
            response = Response(
                status_code=401,
                headers={"Agent-Auth": "httpsig"},
                content=f"Unsupported signature scheme: {scheme}"
            )
            if _is_http_debug_enabled():
                self._print_response_debug(response)
            return response
    
    def _fetch_jwks_for_agent(self, agent_id: str, kid: str) -> Optional[Dict[str, Any]]:
        """Fetch JWKS for an agent using Mode 2 discovery (spec Section 10.7).
        
        Args:
            agent_id: Agent identifier (HTTPS URL)
            kid: Key identifier
            
        Returns:
            JWK dictionary if found, None otherwise
        """
        import os
        import sys
        
        if _is_debug_enabled():
            print(f"DEBUG RESOURCE: Fetching JWKS for agent_id={agent_id}, kid={kid}", file=sys.stderr, flush=True)
        
        try:
            # Step 1: Fetch metadata from agent
            metadata_url = f"{agent_id}/.well-known/aauth-agent"
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
            
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE: Fetching JWKS from {jwks_uri}", file=sys.stderr, flush=True)
            
            # Step 3: Fetch JWKS
            jwks_response = httpx.get(jwks_uri, timeout=10.0)
            jwks_response.raise_for_status()
            jwks_doc = jwks_response.json()
            
            if _is_debug_enabled():
                print(f"DEBUG RESOURCE: JWKS received: {jwks_doc}", file=sys.stderr, flush=True)
            
            # Step 4: Find key by kid
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

