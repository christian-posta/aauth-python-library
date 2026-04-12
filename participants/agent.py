"""Agent participant - acts as agent server using sig=jwks_uri.

Updated for SPEC_UPDATED.md:
- JSON request bodies for token endpoint
- Deferred responses: handles 202 + Location + polling
- Interaction codes replace authorization codes
- AAuth response header instead of Agent-Auth
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx
from typing import Dict, Optional, Any
import sys
import os
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aauth.keys.keypair import generate_ed25519_keypair
from aauth.keys.jwk import public_key_to_jwk, generate_jwks
from aauth.signing.signer import sign_request
from aauth.metadata.agent import generate_agent_metadata
from aauth.metadata.auth_server import fetch_auth_metadata
from aauth.agent.poller import poll_pending_url, PollingResult
from aauth.headers.aauth_header import parse_aauth_header, get_challenge_header_value
from aauth.debug import _is_debug_enabled, _is_http_debug_enabled
import json
import re
import threading
import time
import asyncio
from urllib.parse import urlparse

logger = logging.getLogger("aauth.agent")


class Agent:
    """Agent that requests access to resources."""
    
    def __init__(
        self,
        agent_id: str,
        port: int = 8001,
        use_user_simulator: bool = True,
        clarification_supported: bool = True,
        mm_url: Optional[str] = None,
    ):
        """Initialize agent.
        
        Args:
            agent_id: Agent identifier (HTTPS URL)
            port: Port to run agent server on
            use_user_simulator: If True, use user simulator for automated consent flow.
                               If False, pause and wait for manual browser interaction.
            clarification_supported: Whether this agent supports clarification chat.
            mm_url: Optional Mission Manager base URL; when set, auth token requests
                go to MM (which federates to the AS) instead of directly to the AS.
        """
        self.agent_id = agent_id
        self.port = port
        self.use_user_simulator = use_user_simulator
        self.clarification_supported = clarification_supported
        self.mm_url = mm_url.rstrip("/") if mm_url else None
        self.approved_mission: Optional[Dict[str, Any]] = None
        self.private_key, self.public_key = generate_ed25519_keypair()
        self.kid = "key-1"
        
        # Token storage
        self.auth_token = None
        self.resource_token = None  # Store resource token for debug output
        self.clarification_history = []

        # Phase 6: Agent delegation - track issued agent tokens
        self.issued_agent_tokens: Dict[str, Dict[str, Any]] = {}  # sub -> token details
        
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
        @self.app.get("/.well-known/aauth-agent.json")
        async def metadata():
            """Agent metadata endpoint per AAuth spec Section 13.1."""
            jwks_uri = f"{self.agent_id}/jwks.json"
            return generate_agent_metadata(
                self.agent_id,
                jwks_uri,
                clarification_supported=self.clarification_supported,
            )
        
        @self.app.get("/callback")
        async def callback(request: Request):
            """OAuth callback endpoint for Phase 4 user delegation flow."""
            return await self._handle_callback(request)
        
        @self.app.post("/delegate/token")
        async def delegate_token(request: Request):
            """Issue agent token to delegate (Phase 6: agent delegation).
            
            Request body (JSON):
            {
                "sub": "delegate-identifier",
                "cnf_jwk": { ... },
                "aud": "optional-audience"
            }
            
            Returns agent token (aa-agent+jwt).
            """
            return await self._handle_delegate_token_request(request)
        
        @self.app.post("/request")
        async def remote_request(request: Request):
            """Remote control endpoint - make a signed request to a resource using agent's keys.
            
            Request body (JSON):
            {
                "resource_url": "http://127.0.0.1:8002/data-auth",
                "method": "GET",
                "headers": {},
                "body": null,
                "sig_scheme": "jwks_uri"
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
            sig_scheme: Signature scheme - "hwk" (Phase 1), "jwks_uri" (Phase 2), or "jwt" (Phase 3)
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
        if sig_scheme in ("jwks", "jwks_uri"):
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
            sig_scheme: Signature scheme - "hwk" (Phase 1), "jwks_uri" (Phase 2), or "jwt" (Phase 3)
            
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
        
        # Handle auth token challenge (AAuth-Requirement, AAuth, or Agent-Auth header)
        if response.status_code == 401:
            aauth_header = get_challenge_header_value(response.headers)
            if debug:
                logger.debug(f"Received 401, challenge header: {aauth_header}")

            if aauth_header:
                parsed = parse_aauth_header(aauth_header)
                require = parsed.get("requirement") or parsed.get("require", "")
                # Fall back to old Agent-Auth format
                if not require and "resource_token" in aauth_header:
                    import re as _re
                    rt = _re.search(r'resource_token="([^"]+)"', aauth_header)
                    asrv = _re.search(r'auth_server="([^"]+)"', aauth_header)
                    if rt:
                        parsed["resource-token"] = rt.group(1)
                    if asrv:
                        parsed["auth-server"] = asrv.group(1)
                    require = "auth-token"

                if require == "auth-token":
                    resource_token_val = parsed.get("resource_token") or parsed.get("resource-token")
                    # Auth server from header (backward compat) or from resource token aud claim
                    auth_server = parsed.get("auth_server") or parsed.get("auth-server")
                    if not auth_server and resource_token_val:
                        try:
                            import jwt as jwt_lib
                            rt_payload = jwt_lib.decode(resource_token_val, options={"verify_signature": False})
                            auth_server = rt_payload.get("aud")
                        except Exception:
                            pass

                    if resource_token_val and auth_server:
                        self.resource_token = resource_token_val
                        if debug:
                            logger.debug(f"Auth token challenge: auth_server={auth_server} (from {'header' if parsed.get('auth_server') or parsed.get('auth-server') else 'resource token aud'})")

                        auth_token = await self._request_auth_token(resource_token_val, auth_server)
                        if auth_token:
                            if debug:
                                logger.debug("Auth token obtained, retrying request")
                            return await self.request_resource(
                                resource_url=resource_url,
                                method=method,
                                headers=headers,
                                body=body,
                                sig_scheme="jwt",
                            )

        # Handle deferred response directly from a resource (interaction chaining via Resource 1).
        if response.status_code == 202:
            pending_url = response.headers.get("location")
            try:
                pending_url = pending_url or response.json().get("location")
            except Exception:
                pass
            if pending_url:
                return await self._poll_resource_pending(response)

        return response

    async def _poll_resource_pending(self, initial_response: httpx.Response) -> httpx.Response:
        """Poll a resource-owned pending URL until terminal status."""
        debug = _is_debug_enabled()
        body = initial_response.json()
        pending_url = body.get("location") or initial_response.headers.get("location")
        interaction_endpoint = body.get("interaction_endpoint")
        code = body.get("code")
        interacted = False

        # Handle user interaction once when requested.
        if interaction_endpoint and code:
            interaction_url = f"{interaction_endpoint}?code={code}"
            if self.use_user_simulator:
                from participants.user_simulator import UserSimulator
                user_sim = UserSimulator()
                interacted = await user_sim.complete_interaction(interaction_url)
            else:
                interacted = True
            if not interacted:
                return httpx.Response(
                    status_code=500,
                    json={"error": "interaction_failed", "error_description": "User interaction did not complete"},
                )
            if debug:
                logger.debug(f"Completed chained interaction at {interaction_url}")

        async with httpx.AsyncClient() as client:
            for _ in range(60):
                sig_headers = self.sign_request(method="GET", url=pending_url, sig_scheme="jwks_uri")
                poll_response = await client.get(pending_url, headers=sig_headers)
                if poll_response.status_code != 202:
                    return poll_response

                poll_body = poll_response.json()
                if not interacted and (
                    poll_body.get("requirement") or poll_body.get("require")
                ) == "interaction":
                    poll_code = poll_body.get("code")
                    poll_interaction_endpoint = poll_body.get("interaction_endpoint") or interaction_endpoint
                    if poll_code and poll_interaction_endpoint and self.use_user_simulator:
                        from participants.user_simulator import UserSimulator
                        user_sim = UserSimulator()
                        interacted = await user_sim.complete_interaction(f"{poll_interaction_endpoint}?code={poll_code}")
                        if not interacted:
                            return httpx.Response(
                                status_code=500,
                                json={"error": "interaction_failed", "error_description": "User interaction did not complete"},
                            )

                retry_after = poll_response.headers.get("retry-after") or poll_response.headers.get("Retry-After")
                try:
                    wait_seconds = int(retry_after) if retry_after else 2
                except (TypeError, ValueError):
                    wait_seconds = 2
                await asyncio.sleep(max(wait_seconds, 0))

        return initial_response
    
    # NOTE: _handle_auth_challenge removed. AAuth header parsing now uses
    # parse_aauth_header() directly in request_resource().
    
    async def request_self_authorization(
        self,
        scope: str,
        auth_server: str,
        redirect_uri: Optional[str] = None,
    ) -> Optional[str]:
        """Request authorization directly from auth server (agent is resource / SSO).

        Args:
            scope: Space-separated scope values (e.g., "profile email")
            auth_server: Auth server identifier
            redirect_uri: Optional callback (reserved for interaction UX; ignored by reference AS)

        Returns:
            Auth token string, or None if request failed
        """
        debug = _is_debug_enabled()

        if debug:
            logger.debug(f"Requesting self-authorization: scope={scope}, auth_server={auth_server}")

        # Fetch auth server metadata
        try:
            metadata_url = f"{auth_server}/.well-known/aauth-issuer"
            metadata = await fetch_auth_metadata(metadata_url)
            token_endpoint = metadata.get("token_endpoint")
            if debug:
                logger.debug(f"Token endpoint: {token_endpoint}")
        except Exception as e:
            if debug:
                logger.debug(f"Failed to fetch auth server metadata: {e}")
            return None

        # Build JSON request body (self-access mode: scope, no resource_token)
        body_dict = {"scope": scope}
        if redirect_uri:
            body_dict["redirect_uri"] = redirect_uri
        return await self._send_token_request(
            token_endpoint, body_dict, auth_server, token_request_via="as"
        )

    async def _request_auth_token(self, resource_token: str, auth_server: str) -> Optional[str]:
        """Request auth token from auth server (resource access mode).

        When ``mm_url`` is configured, sends the request to the Mission Manager's
        ``token_endpoint`` (HTTPSig ``jwks_uri``); MM forwards to the AS.

        Args:
            resource_token: Resource token from AAuth challenge
            auth_server: Auth server identifier (``aud`` of the resource token)

        Returns:
            Auth token string, or None if request failed
        """
        debug = _is_debug_enabled()

        if debug:
            logger.debug(
                f"Requesting auth token: auth_server={auth_server} mm_url={self.mm_url}"
            )

        if self.mm_url:
            try:
                from aauth.metadata.mission_manager import fetch_mm_metadata_async

                metadata = await fetch_mm_metadata_async(self.mm_url)
                token_endpoint = metadata.get("token_endpoint")
                if debug:
                    logger.debug(f"MM token endpoint: {token_endpoint}")
            except Exception as e:
                if debug:
                    logger.debug(f"Failed to fetch mission manager metadata: {e}")
                return None
            if not token_endpoint:
                return None
            body_dict = {"resource_token": resource_token}
            return await self._send_token_request(
                token_endpoint, body_dict, self.mm_url, token_request_via="mm"
            )

        # Fetch auth server metadata (direct agent → AS)
        try:
            metadata_url = f"{auth_server}/.well-known/aauth-issuer"
            metadata = await fetch_auth_metadata(metadata_url)
            token_endpoint = metadata.get("token_endpoint")
            if debug:
                logger.debug(f"Token endpoint: {token_endpoint}")
        except Exception as e:
            if debug:
                logger.debug(f"Failed to fetch auth server metadata: {e}")
            return None

        # Build JSON request body (resource access mode)
        body_dict = {"resource_token": resource_token}
        return await self._send_token_request(
            token_endpoint, body_dict, auth_server, token_request_via="as"
        )

    async def propose_mission(self, proposal: str) -> Optional[Dict[str, Any]]:
        """POST ``mission_proposal`` to the configured Mission Manager; cache approved mission."""
        if not self.mm_url:
            return None
        from aauth.metadata.mission_manager import fetch_mm_metadata_async

        try:
            meta = await fetch_mm_metadata_async(self.mm_url)
            mission_endpoint = meta.get("mission_endpoint")
            if not mission_endpoint:
                return None
        except Exception:
            return None

        body_bytes = json.dumps({"mission_proposal": proposal}).encode("utf-8")
        base_headers = {"Content-Type": "application/json"}
        sig_headers = self.sign_request(
            method="POST",
            url=mission_endpoint,
            headers=base_headers,
            body=body_bytes,
            sig_scheme="jwks_uri",
        )
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                mission_endpoint,
                headers={**base_headers, **sig_headers, "Prefer": "wait=30"},
                content=body_bytes,
            )
        if resp.status_code != 200:
            return None
        data = resp.json()
        mission = (data.get("mission") or {}) if isinstance(data, dict) else {}
        s256 = mission.get("s256")
        if not s256:
            return None
        self.approved_mission = {
            "manager": self.mm_url,
            "s256": s256,
            "approved": mission.get("approved", ""),
        }
        return self.approved_mission

    async def request_resource_token_proactively(
        self,
        resource_base_url: str,
        scope: str,
    ) -> Optional[str]:
        """POST to resource ``authorization_endpoint`` (from metadata) for a resource token."""
        base = resource_base_url.rstrip("/")
        meta_url = f"{base}/.well-known/aauth-resource"
        async with httpx.AsyncClient() as client:
            r = await client.get(meta_url)
            if r.status_code != 200:
                authz = f"{base}/authorize"
            else:
                md = r.json()
                authz = md.get("authorization_endpoint") or f"{base}/authorize"

        body_bytes = json.dumps({"scope": scope}).encode("utf-8")
        base_headers = {"Content-Type": "application/json"}
        if self.approved_mission:
            from aauth.headers.aauth_header import build_aauth_mission_header

            base_headers["AAuth-Mission"] = build_aauth_mission_header(
                self.approved_mission["manager"],
                self.approved_mission["s256"],
            )
        sig_headers = self.sign_request(
            method="POST",
            url=authz,
            headers=base_headers,
            body=body_bytes,
            sig_scheme="jwks_uri",
        )
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                authz,
                headers={**base_headers, **sig_headers, "Prefer": "wait=30"},
                content=body_bytes,
            )
        if resp.status_code != 200:
            return None
        payload = resp.json()
        tok = payload.get("resource_token")
        if tok:
            self.resource_token = tok
        return tok

    async def _send_token_request(
        self,
        token_endpoint: str,
        body_dict: Dict[str, Any],
        auth_server: str,
        *,
        token_request_via: str = "as",
    ) -> Optional[str]:
        """Send a signed token request to obtain an **auth** token and handle the response.

        Handles both direct grant (200) and deferred response (202 + polling).

        Args:
            token_endpoint: Token endpoint URL (MM or AS ``/token``)
            body_dict: JSON request body
            auth_server: Peer identifier for deferred-response / polling (MM or AS URL)
            token_request_via: ``"mm"`` when posting to the Mission Manager, ``"as"`` when posting to the AS

        Returns:
            Auth token string, or None if request failed
        """
        debug = _is_debug_enabled()
        http_debug = _is_http_debug_enabled()

        body_text = json.dumps(body_dict)
        body_bytes = body_text.encode('utf-8')

        # Sign request
        headers = {"Content-Type": "application/json"}
        sig_headers = self.sign_request(
            method="POST",
            url=token_endpoint,
            headers=headers,
            body=body_bytes,
            sig_scheme="jwks_uri",
        )
        request_headers = {**headers, **sig_headers}
        request_headers["Prefer"] = "wait=30"

        if http_debug:
            via = "Mission Manager" if token_request_via == "mm" else "Authorization Server"
            print(
                f"\n>>> Outgoing: request auth token (agent → {via})",
                file=sys.stderr,
            )
            print(f"    POST {token_endpoint}", file=sys.stderr)
            print(f"Body: {body_text}", file=sys.stderr)

        # Make request
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_endpoint,
                headers=request_headers,
                content=body_bytes,
            )

        if http_debug:
            print(f"<<< {response.status_code} {response.text[:200]}", file=sys.stderr)

        # Direct grant (200)
        if response.status_code == 200:
            return self._process_token_response(response.json())

        # Deferred response (202) → start polling
        if response.status_code == 202:
            return await self._handle_deferred_response(response, auth_server)

        # Error
        if debug:
            logger.debug(f"Token request failed: {response.status_code} {response.text[:200]}")
        return None

    def _process_token_response(self, data: Dict[str, Any]) -> Optional[str]:
        """Process a successful token response (200 OK)."""
        auth_token = data.get("auth_token")
        if auth_token:
            self.auth_token = auth_token
            logger.debug(f"Auth token stored: {auth_token[:60]}...")
        return auth_token

    async def _handle_deferred_response(self, response: httpx.Response, auth_server: str) -> Optional[str]:
        """Handle a 202 deferred response by polling the pending URL.

        Uses the poller from aauth.agent.poller with synchronous polling
        adapted for async context.
        """
        debug = _is_debug_enabled()

        body = response.json()
        pending_url = body.get("location") or response.headers.get("location")
        # Check AAuth-Requirement header first, then fall back to body
        aauth_req_header = get_challenge_header_value(response.headers)
        if aauth_req_header:
            parsed_req = parse_aauth_header(aauth_req_header)
            require = parsed_req.get("requirement") or parsed_req.get("require")
            code = parsed_req.get("code") or body.get("code")
        else:
            require = body.get("requirement") or body.get("require")
            code = body.get("code")

        if not pending_url:
            if debug:
                logger.debug("No pending URL in 202 response")
            return None

        if debug:
            logger.debug(f"Deferred response: pending_url={pending_url}, require={require}, code={code}")

        # If interaction required, direct user to interaction endpoint
        if require == "interaction" and code:
            try:
                # Prefer url from AAuth-Requirement header, fall back to metadata
                interaction_endpoint = None
                if aauth_req_header:
                    parsed_req = parse_aauth_header(aauth_req_header)
                    interaction_endpoint = parsed_req.get("url")
                if not interaction_endpoint:
                    if self.mm_url and auth_server.rstrip("/") == self.mm_url.rstrip("/"):
                        # Token POST went to the MM; pending + consent still live on the AS that
                        # issued the 202 (pending URL host or resource token aud), not on the MM.
                        as_base = None
                        if pending_url:
                            as_base = f"{urlparse(pending_url).scheme}://{urlparse(pending_url).netloc}"
                        if not as_base and getattr(self, "resource_token", None):
                            try:
                                import jwt as jwt_lib

                                as_base = jwt_lib.decode(
                                    self.resource_token, options={"verify_signature": False}
                                ).get("aud")
                            except Exception:
                                pass
                        if as_base:
                            try:
                                metadata = await fetch_auth_metadata(
                                    f"{as_base.rstrip('/')}/.well-known/aauth-issuer"
                                )
                                interaction_endpoint = metadata.get("interaction_endpoint")
                            except Exception:
                                interaction_endpoint = None
                        if not interaction_endpoint and as_base:
                            interaction_endpoint = f"{as_base.rstrip('/')}/interact"
                    else:
                        try:
                            metadata = await fetch_auth_metadata(
                                f"{auth_server}/.well-known/aauth-issuer"
                            )
                            interaction_endpoint = metadata.get("interaction_endpoint")
                        except Exception:
                            interaction_endpoint = None
                if interaction_endpoint:
                    interaction_url = f"{interaction_endpoint}?code={code}"

                    if self.use_user_simulator:
                        if debug:
                            logger.debug(f"Using user simulator for interaction: {interaction_url}")
                        from participants.user_simulator import UserSimulator
                        user_sim = UserSimulator()
                        # Do not pass MM as auth_server_base; consent UI is on the AS host in interaction_url.
                        await user_sim.complete_interaction(interaction_url, None)
                    else:
                        print(f"\n{'='*60}", file=sys.stderr)
                        print("USER INTERACTION REQUIRED", file=sys.stderr)
                        print(f"Open: {interaction_url}", file=sys.stderr)
                        print(f"Code: {code}", file=sys.stderr)
                        print(f"{'='*60}\n", file=sys.stderr)
            except Exception as e:
                if debug:
                    logger.debug(f"Error directing user to interaction: {e}")

        # Poll pending URL using synchronous poller in executor
        import asyncio
        loop = asyncio.get_running_loop()

        def _sign_and_send_get(url):
            """Synchronous signed GET for the poller."""
            sig_h = self.sign_request(method="GET", url=url, sig_scheme="jwks_uri")
            sig_h = {**sig_h, "Prefer": "wait=15"}
            with httpx.Client() as client:
                return client.get(url, headers=sig_h)

        def _sign_and_send_post(url: str, body_dict: Dict[str, Any]):
            """Synchronous signed POST for clarification responses."""
            payload = json.dumps(body_dict).encode("utf-8")
            base_headers = {"Content-Type": "application/json"}
            sig_h = self.sign_request(
                method="POST",
                url=url,
                headers=base_headers,
                body=payload,
                sig_scheme="jwks_uri",
            )
            request_headers = {**base_headers, **sig_h}
            with httpx.Client() as client:
                return client.post(url, headers=request_headers, content=payload)

        def _on_clarification(_pending_url: str, question: str) -> Optional[str]:
            """Generate a deterministic clarification response for demos."""
            answer = (
                "This agent only requests access to fulfill the current task and "
                "uses the minimum required scope."
            )
            self.clarification_history.append({
                "question": question,
                "answer": answer,
            })
            if debug:
                logger.debug(f"Clarification question received: {question[:120]}")
                logger.debug(f"Clarification answer sent: {answer[:120]}")
            return answer

        result = await loop.run_in_executor(
            None,
            lambda: poll_pending_url(
                pending_url=pending_url,
                sign_and_send_get=_sign_and_send_get,
                on_clarification=_on_clarification if self.clarification_supported else None,
                sign_and_send_post=_sign_and_send_post if self.clarification_supported else None,
                max_polls=60,
                default_wait=2,
            ),
        )

        if result.success and result.auth_token:
            self.auth_token = result.auth_token
            if debug:
                logger.debug(f"Polling succeeded, auth token obtained")
            return result.auth_token

        if debug:
            logger.debug(f"Polling failed: {result.error} - {result.error_description}")
        return None
    
    
    async def _handle_delegate_token_request(self, request: Request):
        """Handle request from delegate for agent token (Phase 6: agent delegation).
        
        For demo purposes, this accepts a simple JSON request with delegate's public key.
        In production, this would require proper authentication/authorization.
        """
        from fastapi.responses import JSONResponse
        import json
        
        debug = _is_debug_enabled()
        http_debug = _is_http_debug_enabled()
        
        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print(">>> AGENT SERVER REQUEST received (delegate token)", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"{request.method} {request.url.path} HTTP/1.1", file=sys.stderr)
            for name, value in sorted(request.headers.items()):
                display_value = value
                if len(display_value) > 100:
                    display_value = display_value[:97] + "..."
                print(f"{name}: {display_value}", file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)
        
        try:
            body_data = await request.json()
        except Exception as e:
            if debug:
                print(f"DEBUG AGENT: Failed to parse request body: {e}", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": f"Failed to parse request body: {e}"}
            )
        
        if debug:
            print(f"DEBUG AGENT: Delegate token request: {json.dumps(body_data, indent=2)}", file=sys.stderr, flush=True)
        
        # Extract parameters
        delegate_sub = body_data.get("sub")
        cnf_jwk = body_data.get("cnf_jwk")
        aud = body_data.get("aud")
        
        if not delegate_sub:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Missing 'sub' parameter (delegate identifier)"}
            )
        
        if not cnf_jwk:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Missing 'cnf_jwk' parameter (delegate's public key)"}
            )
        
        if debug:
            print(f"DEBUG AGENT: Issuing agent token:", file=sys.stderr, flush=True)
            print(f"DEBUG AGENT:   Delegate sub: {delegate_sub}", file=sys.stderr, flush=True)
            print(f"DEBUG AGENT:   Delegate JWK: {json.dumps(cnf_jwk, indent=2)}", file=sys.stderr, flush=True)
            if aud:
                print(f"DEBUG AGENT:   Audience: {aud}", file=sys.stderr, flush=True)
        
        # Issue agent token
        from aauth.tokens.agent_token import create_agent_token
        
        agent_token = create_agent_token(
            iss=self.agent_id,
            sub=delegate_sub,
            cnf_jwk=cnf_jwk,
            private_key=self.private_key,
            kid=self.kid,
            exp=None,  # Default 1 hour
            aud=aud
        )
        
        # Store token details for tracking
        self.issued_agent_tokens[delegate_sub] = {
            "sub": delegate_sub,
            "cnf_jwk": cnf_jwk,
            "issued_at": int(time.time()),
            "aud": aud
        }
        
        if debug:
            print(f"DEBUG AGENT: Agent token issued: {agent_token[:100]}...", file=sys.stderr, flush=True)
        
        response_data = {
            "agent_token": agent_token,
            "expires_in": 3600  # 1 hour
        }
        
        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print("<<< AGENT SERVER RESPONSE", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(f"HTTP/1.1 200 OK", file=sys.stderr)
            print(f"Content-Type: application/json", file=sys.stderr)
            print(f"\n[Body]", file=sys.stderr)
            print(json.dumps(response_data, indent=2), file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)
        
        return JSONResponse(content=response_data)
    
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

