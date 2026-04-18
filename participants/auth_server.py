"""Access server participant - issues auth tokens for autonomous authorization.

Updated for SPEC_UPDATED.md:
- JSON request bodies (not form-encoded)
- Token endpoint mode detection by parameters (resource_token, scope, upstream_token, auth_token)
- Deferred responses: 202 + Location + pending URL polling
- Interaction codes (ABCD1234) replace authorization codes
- Pending URL endpoints: GET /pending/{id} for polling, POST for clarification
"""

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any, List
import sys
import os
import json
import time
import logging
from urllib.parse import urlparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aauth.signing.verifier import verify_signature
from aauth.signing.signature_key import parse_signature_key
from aauth.keys.keypair import generate_ed25519_keypair
from aauth.keys.jwk import public_key_to_jwk, generate_jwks, jwk_to_public_key, calculate_jwk_thumbprint
from aauth.metadata.auth_server import generate_auth_metadata, fetch_metadata as fetch_resource_metadata
from aauth.tokens.auth_token import verify_token, create_auth_token
from aauth.http.deferred import (
    generate_pending_id, generate_interaction_code,
    build_pending_response_body, build_pending_response_headers,
    build_success_response, build_polling_error_body,
    detect_token_request_mode,
)
from aauth.debug import _is_debug_enabled, _is_http_debug_enabled

logger = logging.getLogger("aauth.access_server")


class AccessServer:
    """Access server that issues auth tokens for autonomous authorization."""

    def __init__(
        self,
        auth_id: str,
        port: int = 8003,
        require_user_consent: bool = False,
        trusted_auth_servers: Optional[List[str]] = None,
        trusted_person_servers: Optional[List[str]] = None,
        trusted_mission_managers: Optional[List[str]] = None,  # deprecated: use trusted_person_servers
        clarification_questions: Optional[List[str]] = None,
        max_clarification_rounds: int = 5,
    ):
        """Initialize access server.

        Args:
            auth_id: Access server identifier (HTTPS URL)
            port: Port to run access server on
            trusted_auth_servers: List of trusted access server identifiers for call chaining
            trusted_person_servers: If set, ``POST /token`` may be called by a PS (HTTPSig ``jwks_uri``)
                with JSON body ``resource_token`` and ``agent_token`` (federation path).
            trusted_mission_managers: Deprecated alias for trusted_person_servers.
            require_user_consent: If True, require user consent for all requests (Phase 4 demo mode)
            clarification_questions: Optional queued clarification prompts for demo flows.
            max_clarification_rounds: Maximum clarification answers accepted.
        """
        self.auth_id = auth_id
        self.port = port
        self.require_user_consent = require_user_consent

        # Generate key pair for signing auth tokens
        self.private_key, self.public_key = generate_ed25519_keypair()
        self.kid = "auth-key-1"

        # Pending requests: pending_id -> request details
        # Replaces old request_token and authorization_codes dicts
        self.pending_requests: Dict[str, Dict[str, Any]] = {}
        self.clarification_questions = clarification_questions or []
        self.max_clarification_rounds = max_clarification_rounds

        self.users: Dict[str, Dict[str, str]] = {  # Simple in-memory user database
            "testuser": {"password": "testpass", "name": "Test User", "email": "testuser@example.com"}
        }

        # Federation trust - list of trusted access servers for call chaining
        self.trusted_auth_servers: List[str] = trusted_auth_servers if trusted_auth_servers else []
        # trusted_mission_managers is a deprecated alias for trusted_person_servers
        self.trusted_person_servers: List[str] = trusted_person_servers or trusted_mission_managers or []

        # Revocation: track issued auth token JTIs and revoked JTIs
        self.issued_tokens: Dict[str, Dict] = {}   # jti -> {aud, agent, ...}
        self.revoked_jtis: set = set()

        # Create FastAPI app
        self.app = FastAPI(title="AAuth Access Server")

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

        @self.app.get("/.well-known/aauth-access")
        @self.app.get("/.well-known/aauth-access.json")
        async def metadata():
            """Access server metadata endpoint per AAuth spec."""
            jwks_uri = f"{self.auth_id}/jwks.json"
            token_endpoint = f"{self.auth_id}/token"
            interaction_endpoint = f"{self.auth_id}/interact"
            return generate_auth_metadata(
                auth_id=self.auth_id,
                jwks_uri=jwks_uri,
                token_endpoint=token_endpoint,
                interaction_endpoint=interaction_endpoint,
                revocation_endpoint=f"{self.auth_id}/revoke",
            )

        @self.app.post("/revoke")
        async def revoke(request: Request):
            """Token revocation endpoint per AAuth spec Section 14."""
            return await self._handle_revocation(request)

        @self.app.post("/token")
        async def token_endpoint(request: Request):
            """Token endpoint per spec Section 11.

            Mode detection by parameters:
            - resource_token → resource access
            - scope (no resource_token) → self-access (SSO/1P)
            - resource_token + upstream_token → call chaining
            - auth_token → token refresh
            """
            return await self._handle_token_request(request)

        # --- Pending URL endpoints (Deferred Responses, spec Section 10) ---

        @self.app.get("/pending/{pending_id}")
        async def pending_get(pending_id: str, request: Request):
            """Poll pending URL with GET per spec Section 10.3."""
            return await self._handle_pending_get(pending_id, request)

        @self.app.post("/pending/{pending_id}")
        async def pending_post(pending_id: str, request: Request):
            """POST to pending URL for clarification response per spec §Clarification Chat."""
            return await self._handle_pending_post(pending_id, request)

        # --- Interaction endpoint (user-facing, spec Section 11.5) ---

        @self.app.get("/interact")
        async def interact_get(request: Request):
            """Interaction endpoint - user navigates here with code parameter."""
            return await self._handle_interact_get(request)

        @self.app.post("/interact")
        async def interact_post(request: Request):
            """Interaction endpoint - login and consent submission."""
            return await self._handle_interact_post(request)
    
    async def _handle_token_request(self, request: Request) -> Response:
        """Handle token request per spec Section 11.

        Accepts JSON body. Mode detection by parameters:
        - resource_token → resource access
        - scope (no resource_token) → self-access
        - resource_token + upstream_token → call chaining
        - auth_token → token refresh
        """
        debug = _is_debug_enabled()
        http_debug = _is_http_debug_enabled()

        # Get request body
        body_bytes = await request.body()
        body_text = body_bytes.decode('utf-8') if body_bytes else ""

        if http_debug:
            banner = "Incoming: POST /token (AS)"
            try:
                sk = request.headers.get("signature-key", "")
                if sk:
                    pk = parse_signature_key(sk)
                    sch = pk.get("scheme")
                    sid = (pk.get("params") or {}).get("id", "")
                    if sch in ("jwks", "jwks_uri") and sid:
                        trusted = {x.rstrip("/") for x in self.trusted_person_servers}
                        if trusted and sid.rstrip("/") in trusted:
                            banner = (
                                "Incoming: POST /token — Person Server → AS federation "
                                f"(Signature-Key id={sid})"
                            )
                        else:
                            banner = (
                                "Incoming: POST /token — direct from agent "
                                f"(Signature-Key id={sid})"
                            )
            except Exception:
                pass
            print("\n" + "=" * 80, file=sys.stderr)
            print(f">>> {banner}", file=sys.stderr)
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

        # Parse JSON request body (spec requires application/json)
        try:
            params_dict = json.loads(body_text) if body_text else {}
        except Exception as e:
            if debug:
                logger.debug(f"Failed to parse JSON request body: {e}")
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": f"Invalid JSON body: {e}"}
            )

        if debug:
            logger.debug(f"Token request params: {json.dumps(params_dict, indent=2)}")

        # Detect mode by parameters (spec Section 11.1)
        try:
            mode = detect_token_request_mode(params_dict)
        except ValueError as e:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": str(e)}
            )

        if debug:
            logger.debug(f"Token endpoint mode: {mode}")

        # Route to handler based on mode
        if mode == "token_refresh":
            return await self._handle_token_refresh(request, params_dict, body_bytes)
        # resource_access and self_access share the same authorization flow

        # PS federation: trusted PS calls AS with resource_token (+ optional upstream_token)
        # This covers both "resource_access" mode and "call_chaining" mode when caller is PS.
        if mode in ("resource_access", "call_chaining") and self.trusted_person_servers:
            try:
                pk = parse_signature_key(request.headers.get("signature-key", ""))
            except ValueError:
                pk = None
            if pk:
                sch = pk.get("scheme")
                ps_id = (pk.get("params") or {}).get("id")
                if sch in ("jwks", "jwks_uri") and ps_id and ps_id.rstrip("/") in {
                    x.rstrip("/") for x in self.trusted_person_servers
                }:
                    return await self._handle_ps_federated_token_request(request, params_dict, body_bytes)

        # Direct call chaining (no MM involved)
        if mode == "call_chaining":
            return await self._handle_call_chaining(request, params_dict, body_bytes)

        # Verify agent's HTTPSig signature
        headers_dict = dict(request.headers)
        method = request.method
        target_uri = str(request.url)

        if debug:
            logger.debug("Verifying agent's HTTPSig signature")

        # Extract signature headers
        signature_input_header = headers_dict.get("signature-input", "")
        signature_header = headers_dict.get("signature", "")
        signature_key_header = headers_dict.get("signature-key", "")

        if not signature_input_header or not signature_header or not signature_key_header:
            if debug:
                logger.debug("Missing signature headers")
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_signature", "error_description": "Missing signature headers"}
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
        
        # Extract agent identifier from signature.
        # agent_url  – the agent server's HTTP URL; used for resource-token validation and JWKS fetch.
        # agent_id   – the aauth:local@domain identifier; used in the issued auth token's `agent` claim.
        agent_url = None
        agent_id = None
        agent_jwk = None  # delegate's key from agent token (jwt/aa-agent+jwt scheme)

        if scheme in ("jwks", "jwks_uri"):
            raw_id = key_params.get("id")
            if raw_id:
                from aauth.identifiers import agent_identifier_from_server_url
                agent_url = raw_id
                agent_id = agent_identifier_from_server_url(raw_id)
            else:
                agent_url = None
                agent_id = None
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
            
            if typ == "aa-agent+jwt":
                # Phase 6: Agent token (delegated identity)
                if debug:
                    print(f"DEBUG AUTH:   Validating agent token (aa-agent+jwt)", file=sys.stderr, flush=True)
                
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
                    
                    # Per spec Section 12.1: the sub claim IS the aauth:local@domain identifier.
                    agent_sub = agent_claims.get("sub", "")
                    agent_id = agent_sub or agent_claims.get("iss", "")
                    # iss is the agent server's HTTP URL — used for resource-token expected_agent check
                    agent_url = agent_claims.get("iss", "")
                    cnf = agent_claims.get("cnf", {})
                    agent_jwk = cnf.get("jwk")  # Delegate's key for cnf.jwk in auth token

                    if debug:
                        print(f"DEBUG AUTH:   Agent token validated successfully", file=sys.stderr, flush=True)
                        print(f"DEBUG AUTH:     Agent identifier: {agent_id}", file=sys.stderr, flush=True)
                except Exception as e:
                    if debug:
                        print(f"DEBUG AUTH:   Agent token validation failed: {e}", file=sys.stderr, flush=True)
                        import traceback
                        traceback.print_exc()
                    return JSONResponse(
                        status_code=401,
                        content={"error": "invalid_token", "error_description": f"Invalid agent token: {e}"}
                    )
            
            elif typ == "aa-auth+jwt":
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
        
        # Verify signature
        # For agent tokens, we've already validated the JWT, but we still need to verify HTTPSig
        # using the delegate's key from cnf.jwk
        def jwks_fetcher(agent_id_param: str, kid_param: str = None):
            """Fetch JWKS for agent via metadata discovery.

            Fetches agent metadata from {id}/.well-known/aauth-agent.json,
            extracts jwks_uri, then fetches the JWKS document.
            """
            if debug:
                print(f"DEBUG AUTH:   Fetching JWKS for agent: {agent_id_param}, kid={kid_param}", file=sys.stderr, flush=True)
            try:
                import httpx
                from aauth.metadata.auth_server import fetch_metadata
                metadata_url = f"{agent_id_param}/.well-known/aauth-agent.json"
                if debug:
                    print(f"DEBUG AUTH:   Fetching metadata from {metadata_url}", file=sys.stderr, flush=True)
                metadata = fetch_metadata(metadata_url)
                jwks_uri = metadata.get("jwks_uri")
                if debug:
                    print(f"DEBUG AUTH:   JWKS URI from metadata: {jwks_uri}", file=sys.stderr, flush=True)
                
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
        
        # Extract parameters for mode routing
        resource_token = params_dict.get("resource_token")
        scope = params_dict.get("scope")
        purpose = params_dict.get("purpose")

        # Determine resource_id and scope based on mode
        agent_is_resource = (mode == "self_access")

        # JWK for agent_jkt / cnf: from JWKS (jwks_uri) or already set from aa-agent+jwt cnf (delegate)
        # Use agent_url (HTTP URL) for JWKS discovery, not agent_id (aauth:)
        if scheme in ("jwks", "jwks_uri"):
            agent_jwk = self._extract_agent_jwk(scheme, key_params, agent_url or agent_id, debug)

        if debug:
            logger.debug(f"agent_jwk for resource/cnf: {agent_jwk is not None}")

        # Determine resource_id and scope based on mode
        if agent_is_resource:
            resource_id = agent_id
            if not scope:
                scope = ""
            if debug:
                logger.debug(f"Self-access mode: resource_id={resource_id}, scope={scope}")
        else:
            # What the resource stores in the resource token's `agent` field depends on the scheme
            # used by the agent when it first challenged the resource:
            #   scheme=jwks_uri → resource stores the raw HTTP URL (agent_url)
            #   scheme=jwt (agent token) → resource stores the aauth: sub (agent_id)
            # Match accordingly so _verify_resource_token's equality check passes.
            if scheme in ("jwks", "jwks_uri"):
                expected_agent_for_rt = agent_url  # HTTP URL stored in resource token
            else:
                expected_agent_for_rt = agent_id   # aauth: identifier stored in resource token
            try:
                resource_claims = await self._verify_resource_token(resource_token, expected_agent_for_rt, agent_jwk)
            except Exception as e:
                if debug:
                    logger.debug(f"Resource token validation FAILED: {e}")
                return JSONResponse(
                    status_code=400,
                    content={"error": "invalid_resource_token", "error_description": str(e)}
                )
            resource_id = resource_claims.get("iss")
            scope = resource_claims.get("scope", "")
            if debug:
                logger.debug(f"Resource access mode: resource_id={resource_id}, scope={scope}")

        # Evaluate policy
        policy_result = self._evaluate_policy(agent_id, resource_id, scope)

        if debug:
            logger.debug(f"Policy evaluation: {json.dumps(policy_result, indent=2)}")

        # Determine agent key for cnf.jwk
        agent_key = self._resolve_agent_key(scheme, agent_jwk, debug)
        if agent_key is None:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Agent signing key not available"}
            )

        # Check whether the agent supports clarification chat (fetch metadata at agent
        # server URL — not ``agent_id``, which is the aauth: subject for jwks_uri).
        agent_clarification_supported = (
            self._agent_supports_clarification(agent_url, debug) if agent_url else False
        )

        # Check if user consent is required → deferred response (202)
        if policy_result.get("requires_user_consent"):
            return self._create_pending_request(
                agent_id=agent_id,
                resource_id=resource_id,
                scope=scope,
                agent_jwk=agent_key,
                purpose=purpose,
                agent_is_resource=agent_is_resource,
                clarification_supported=agent_clarification_supported,
            )

        # Direct grant (autonomous authorization) → 200
        if not policy_result.get("allowed"):
            return JSONResponse(
                status_code=403,
                content={"error": "denied", "error_description": policy_result.get("reason", "Access denied")}
            )

        # Issue auth token (direct grant)
        # act.sub = agent_id per spec Section 9.1 (actor claim required)
        auth_token = self._issue_auth_token(
            agent=agent_id,
            resource=resource_id,
            scope=scope,
            cnf_jwk=agent_key,
            act={"sub": agent_id},
        )

        if debug:
            logger.debug(f"Auth token issued: {auth_token[:80]}...")

        response_data = build_success_response(auth_token)

        if http_debug:
            print("\n" + "=" * 80, file=sys.stderr)
            print("<<< AUTH SERVER RESPONSE (200 Direct Grant)", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print(json.dumps(response_data, indent=2), file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)

        return JSONResponse(content=response_data)

    async def _handle_ps_federated_token_request(
        self,
        request: Request,
        params_dict: Dict[str, Any],
        body_bytes: bytes,
    ) -> Response:
        """AS token endpoint when called by a trusted Person Server (spec PS–AS federation)."""
        debug = _is_debug_enabled()
        headers_dict = dict(request.headers)
        method = request.method
        target_uri = str(request.url)
        signature_input_header = headers_dict.get("signature-input", "")
        signature_header = headers_dict.get("signature", "")
        signature_key_header = headers_dict.get("signature-key", "")

        def ps_jwks_fetcher(issuer_url: str, kid_param: Optional[str] = None):
            try:
                import httpx
                for path in ("/.well-known/aauth-person.json", "/.well-known/aauth-person"):
                    r = httpx.get(f"{issuer_url.rstrip('/')}{path}", timeout=10.0)
                    if r.status_code == 200:
                        ju = r.json().get("jwks_uri")
                        if not ju:
                            return None
                        jr = httpx.get(ju, timeout=10.0)
                        jr.raise_for_status()
                        return jr.json()
            except Exception:
                return None
            return None

        ok = verify_signature(
            method=method,
            target_uri=target_uri,
            headers=headers_dict,
            body=body_bytes,
            signature_input_header=signature_input_header,
            signature_header=signature_header,
            signature_key_header=signature_key_header,
            jwks_fetcher=ps_jwks_fetcher,
        )
        if not ok:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "invalid_signature",
                    "error_description": "Person Server signature verification failed",
                },
            )

        agent_token_str = params_dict.get("agent_token")
        resource_token_str = params_dict.get("resource_token")
        if not resource_token_str:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "resource_token required"},
            )

        from aauth.tokens.agent_token import verify_agent_token

        cnf_jwk = None
        agent_id_for_policy = None

        if agent_token_str:
            def agent_jwks_fetcher(issuer_url: str, kid_param: Optional[str] = None):
                try:
                    import httpx
                    from aauth.metadata.auth_server import fetch_metadata
                    metadata_url = f"{issuer_url}/.well-known/aauth-agent.json"
                    metadata = fetch_metadata(metadata_url)
                    jwks_uri = metadata.get("jwks_uri")
                    if not jwks_uri:
                        return None
                    response = httpx.get(jwks_uri, timeout=10.0)
                    response.raise_for_status()
                    return response.json()
                except Exception:
                    return None

            try:
                agent_claims = verify_agent_token(
                    token=agent_token_str,
                    jwks_fetcher=agent_jwks_fetcher,
                    expected_aud=None,
                )
            except Exception as e:
                return JSONResponse(
                    status_code=400,
                    content={"error": "invalid_agent_token", "error_description": str(e)},
                )

            cnf_jwk = agent_claims.get("cnf", {}).get("jwk")
            # sub is the aauth:local@domain identifier (used for agent claim + act)
            # iss is the agent server HTTP URL (used for resource-token validation and upstream_aud check)
            agent_id_for_policy = agent_claims.get("sub") or agent_claims.get("iss")
            agent_server_url_for_policy = agent_claims.get("iss")
            if not cnf_jwk or not agent_id_for_policy:
                return JSONResponse(status_code=400, content={"error": "invalid_agent_token"})

            try:
                # Resource token's `agent` field is the agent server HTTP URL (iss from agent token).
                resource_claims = await self._verify_resource_token(
                    resource_token_str, agent_server_url_for_policy, cnf_jwk
                )
            except Exception as e:
                return JSONResponse(
                    status_code=400,
                    content={"error": "invalid_resource_token", "error_description": str(e)},
                )
        else:
            # MM-signed request without separate agent_token JWT: verify resource token and
            # resolve agent signing key from agent JWKS using ``agent_jkt`` thumbprint.
            try:
                import jwt as pyjwt

                unverified = pyjwt.decode(
                    resource_token_str, options={"verify_signature": False}
                )
            except Exception as e:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_resource_token",
                        "error_description": str(e),
                    },
                )
            # The resource token's `agent` field contains the HTTP URL of the agent server
            # (used for JWKS discovery).  Convert to aauth: identifier for the auth token.
            agent_url_for_policy = unverified.get("agent")  # HTTP URL
            from aauth.identifiers import agent_identifier_from_server_url as _aauth_from_url
            agent_id_for_policy = (
                _aauth_from_url(agent_url_for_policy) if agent_url_for_policy else None
            )
            agent_server_url_for_policy = agent_url_for_policy  # HTTP URL for upstream_aud check
            thumb = unverified.get("agent_jkt")
            if not agent_url_for_policy:
                return JSONResponse(
                    status_code=400,
                    content={"error": "invalid_resource_token", "error_description": "missing agent claim"},
                )
            cnf_jwk = self._fetch_agent_jwk_by_jkt(agent_url_for_policy, thumb)
            if not cnf_jwk:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_resource_token",
                        "error_description": "Could not resolve agent JWK for agent_jkt",
                    },
                )
            try:
                # Resource token's `agent` is the HTTP URL — use agent_url_for_policy here
                resource_claims = await self._verify_resource_token(
                    resource_token_str, agent_url_for_policy, cnf_jwk
                )
            except Exception as e:
                return JSONResponse(
                    status_code=400,
                    content={"error": "invalid_resource_token", "error_description": str(e)},
                )

        resource_id = resource_claims.get("iss")
        scope = resource_claims.get("scope", "")
        purpose = params_dict.get("purpose")
        mission = resource_claims.get("mission")

        # Call Chaining: if upstream_token is provided, verify it before issuing auth token.
        upstream_token_str = params_dict.get("upstream_token")
        upstream_act = None  # act from upstream token for nested delegation chain
        if upstream_token_str:
            import jwt as jwt_lib
            try:
                upstream_payload = jwt_lib.decode(upstream_token_str, options={"verify_signature": False})
                upstream_iss = upstream_payload.get("iss")
                upstream_aud = upstream_payload.get("aud")
            except Exception as e:
                return JSONResponse(
                    status_code=400,
                    content={"error": "invalid_upstream_token", "error_description": str(e)},
                )
            if upstream_iss not in self.trusted_auth_servers:
                return JSONResponse(
                    status_code=401,
                    content={"error": "untrusted_auth_server", "error_description": f"Upstream AS not trusted: {upstream_iss}"},
                )
            # upstream_aud MUST match the intermediary's server URL (agent token iss).
            # agent_server_url_for_policy is the HTTP URL of the agent server (iss from agent token).
            if upstream_aud != agent_server_url_for_policy:
                return JSONResponse(
                    status_code=401,
                    content={"error": "invalid_upstream_token", "error_description": f"upstream_aud {upstream_aud!r} does not match agent server {agent_server_url_for_policy!r}"},
                )
            # Verify upstream token signature via upstream AS's JWKS
            try:
                upstream_header = jwt_lib.get_unverified_header(upstream_token_str)
                upstream_kid = upstream_header.get("kid")
                metadata_url = f"{upstream_iss}/.well-known/aauth-access"
                import httpx as _httpx
                meta_r = _httpx.get(metadata_url, timeout=10.0)
                meta_r.raise_for_status()
                jwks_uri = meta_r.json().get("jwks_uri")
                if not jwks_uri:
                    raise ValueError("upstream AS metadata missing jwks_uri")
                jwks_r = _httpx.get(jwks_uri, timeout=10.0)
                jwks_r.raise_for_status()
                upstream_jwks = jwks_r.json()
                signing_key = None
                for k in upstream_jwks.get("keys", []):
                    if k.get("kid") == upstream_kid:
                        signing_key = k
                        break
                if not signing_key:
                    raise ValueError(f"Key {upstream_kid} not in upstream AS JWKS")
                from aauth.keys.jwk import jwk_to_public_key as _jwk_to_pub
                upstream_pub = _jwk_to_pub(signing_key)
                jwt_lib.decode(
                    upstream_token_str, upstream_pub, algorithms=["EdDSA"],
                    options={"verify_signature": True, "verify_exp": True, "verify_aud": False},
                )
            except jwt_lib.ExpiredSignatureError:
                return JSONResponse(status_code=401, content={"error": "invalid_upstream_token", "error_description": "upstream token expired"})
            except Exception as e:
                return JSONResponse(status_code=401, content={"error": "invalid_upstream_token", "error_description": str(e)})

            # Collect upstream act for nested delegation chain in the downstream token.
            # Prefer explicit act; fall back to agent claim as a sub-only act object.
            upstream_act = upstream_payload.get("act") or {"sub": upstream_payload.get("agent", "")}

        policy_result = self._evaluate_policy(agent_id_for_policy, resource_id, scope)
        agent_clarification_supported = (
            self._agent_supports_clarification(agent_server_url_for_policy, debug)
            if agent_server_url_for_policy
            else False
        )

        if policy_result.get("requires_user_consent"):
            return self._create_pending_request(
                agent_id=agent_id_for_policy,
                resource_id=resource_id,
                scope=scope,
                agent_jwk=cnf_jwk,
                purpose=purpose,
                agent_is_resource=False,
                clarification_supported=agent_clarification_supported,
            )

        if not policy_result.get("allowed"):
            return JSONResponse(
                status_code=403,
                content={"error": "denied", "error_description": policy_result.get("reason", "Access denied")},
            )

        # Build act claim per spec.
        # Direct: act.sub = intermediary's aauth: identifier.
        # Call chaining: act.sub = intermediary's aauth: id, act.act = upstream act.
        act_claim: Dict[str, Any] = {"sub": agent_id_for_policy}
        if upstream_act:
            act_claim["act"] = upstream_act

        auth_token = self._issue_auth_token(
            agent=agent_id_for_policy,
            resource=resource_id,
            scope=scope,
            cnf_jwk=cnf_jwk,
            mission=mission,
            act=act_claim,
        )
        return JSONResponse(content=build_success_response(auth_token))

    def _fetch_agent_jwk_by_jkt(
        self, agent_id: str, agent_jkt: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Resolve agent signing JWK from agent JWKS using ``agent_jkt`` thumbprint."""
        if not agent_jkt:
            return None
        try:
            import httpx

            metadata_url = f"{agent_id}/.well-known/aauth-agent.json"
            metadata = fetch_resource_metadata(metadata_url)
            jwks_uri = metadata.get("jwks_uri")
            if not jwks_uri:
                return None
            response = httpx.get(jwks_uri, timeout=10.0)
            response.raise_for_status()
            jwks = response.json()
            for key in jwks.get("keys", []):
                try:
                    if calculate_jwk_thumbprint(key) == agent_jkt:
                        return key
                except Exception:
                    continue
        except Exception:
            return None
        return None

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
                expected_typ="aa-resource+jwt",
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

    def _extract_agent_jwk(self, scheme, key_params, agent_id, debug):
        """Extract agent's JWK from JWKS for agent_jkt verification and cnf.jwk.

        Discovers JWKS via agent metadata at {agent_id}/.well-known/aauth-agent.json.
        """
        agent_jwk = None
        if scheme in ("jwks", "jwks_uri"):
            kid = key_params.get("kid")
            if kid:
                try:
                    import httpx
                    from aauth.metadata.auth_server import fetch_metadata
                    metadata_url = f"{agent_id}/.well-known/aauth-agent.json"
                    metadata = fetch_metadata(metadata_url)
                    jwks_uri = metadata.get("jwks_uri")

                    if jwks_uri:
                        response = httpx.get(jwks_uri, timeout=10.0)
                        response.raise_for_status()
                        agent_jwks_doc = response.json()
                        for key in agent_jwks_doc.get("keys", []):
                            if key.get("kid") == kid:
                                agent_jwk = key
                                break
                except Exception as e:
                    if debug:
                        logger.debug(f"Error fetching agent JWKS for agent_jkt: {e}")
        return agent_jwk

    def _resolve_agent_key(self, scheme, agent_jwk, debug):
        """Resolve the agent key to use for cnf.jwk in the auth token."""
        if scheme == "jwt" and agent_jwk:
            return agent_jwk  # delegate's key from agent token
        elif scheme in ("jwks", "jwks_uri"):
            return agent_jwk  # agent server's key
        return None

    def _agent_supports_clarification(self, agent_server_base_url: str, debug: bool = False) -> bool:
        """Discover whether agent metadata declares clarification support.

        ``agent_server_base_url`` MUST be the agent's HTTP(S) issuer URL (same base used
        for JWKS discovery), e.g. ``https://agent.example`` or ``http://127.0.0.1:8001``.
        Do not pass an ``aauth:…`` subject identifier — well-known metadata has no
        defined URL for those.
        """
        try:
            metadata_url = f"{agent_server_base_url.rstrip('/')}/.well-known/aauth-agent.json"
            metadata = fetch_resource_metadata(metadata_url)
            return bool(metadata.get("clarification_supported", False))
        except Exception as e:
            if debug:
                logger.debug(f"Unable to fetch agent metadata for clarification support: {e}")
            return False

    def _create_pending_request(
        self,
        agent_id: str,
        resource_id: str,
        scope: str,
        agent_jwk: Dict[str, Any],
        purpose: Optional[str] = None,
        agent_is_resource: bool = False,
        clarification_supported: bool = False,
        act_claim: Optional[Dict[str, Any]] = None,
    ) -> Response:
        """Create a pending request and return 202 with Location + interaction code.

        Per spec Section 10.2 and 11.3.
        """
        debug = _is_debug_enabled()

        pending_id = generate_pending_id()
        interaction_code = generate_interaction_code()
        pending_url = f"{self.auth_id}/pending/{pending_id}"

        # Store pending request details
        self.pending_requests[pending_id] = {
            "agent": agent_id,
            "resource": resource_id,
            "scope": scope,
            "agent_jwk": agent_jwk,
            "purpose": purpose,
            "agent_is_resource": agent_is_resource,
            "interaction_code": interaction_code,
            "status": "pending",  # pending | approved | denied | expired
            "user_id": None,
            "created_at": int(time.time()),
            "expires_at": int(time.time()) + 600,  # 10 minutes
            "clarification_supported": clarification_supported,
            "clarification_questions": list(self.clarification_questions),
            "clarification_history": [],
            "act_claim": act_claim,
        }

        if debug:
            logger.debug(f"Created pending request: id={pending_id}, code={interaction_code}")

        # Build 202 response
        body = build_pending_response_body(
            location=pending_url,
            require="interaction",
            code=interaction_code,
        )
        headers = build_pending_response_headers(
            location=pending_url,
            retry_after=2,
            require="interaction",
            code=interaction_code,
            url=f"{self.auth_id}/interact",
        )

        return Response(
            content=json.dumps(body),
            status_code=202,
            headers=headers,
            media_type="application/json",
        )

    async def _handle_pending_get(self, pending_id: str, request: Request) -> Response:
        """Handle GET /pending/{id} - polling per spec Section 10.3."""
        debug = _is_debug_enabled()

        pending = self.pending_requests.get(pending_id)
        if not pending:
            return JSONResponse(status_code=404, content={"error": "not_found"})

        # Check expiration
        if int(time.time()) >= pending.get("expires_at", 0):
            pending["status"] = "expired"
            del self.pending_requests[pending_id]
            return JSONResponse(
                status_code=408,
                content=build_polling_error_body("expired", "Request expired"),
            )

        status = pending.get("status", "pending")

        # Terminal: approved → issue token
        if status == "approved":
            agent_id = pending["agent"]
            resource_id = pending["resource"]
            scope_val = pending["scope"]
            agent_jwk = pending["agent_jwk"]
            user_id = pending.get("user_id")

            auth_token = self._issue_auth_token(
                agent=agent_id,
                resource=resource_id,
                scope=scope_val,
                cnf_jwk=agent_jwk,
                sub=user_id,
                act=pending.get("act_claim"),
            )

            # Clean up pending request
            del self.pending_requests[pending_id]

            if debug:
                logger.debug(f"Pending {pending_id} approved, auth token issued")

            return JSONResponse(
                status_code=200,
                content=build_success_response(auth_token),
            )

        # Terminal: denied
        if status == "denied":
            del self.pending_requests[pending_id]
            return JSONResponse(
                status_code=403,
                content=build_polling_error_body("denied", "User denied consent"),
            )

        # Still pending → 202
        pending_url = f"{self.auth_id}/pending/{pending_id}"
        clarification = None
        if pending.get("clarification_supported"):
            questions = pending.get("clarification_questions") or []
            history = pending.get("clarification_history") or []
            if questions and len(history) < len(questions):
                clarification = questions[len(history)]

        # Return interacting status if user has arrived at interaction endpoint
        poll_status = pending.get("status", "pending")
        body = build_pending_response_body(location=pending_url, clarification=clarification, status=poll_status)
        # Spec §Clarification Chat (MUST): include AAuth-Requirement: requirement=clarification
        # in the header whenever the 202 body carries a clarification question.
        pending_require = "clarification" if clarification else None
        headers = build_pending_response_headers(location=pending_url, retry_after=2, require=pending_require)

        return Response(
            content=json.dumps(body),
            status_code=202,
            headers=headers,
            media_type="application/json",
        )

    async def _handle_pending_post(self, pending_id: str, request: Request) -> Response:
        """Handle POST /pending/{id} - clarification response per spec §Clarification Chat."""
        debug = _is_debug_enabled()

        pending = self.pending_requests.get(pending_id)
        if not pending:
            return JSONResponse(status_code=404, content={"error": "not_found"})

        try:
            body = json.loads(await request.body())
        except Exception:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Invalid JSON"},
            )

        clarification_response = body.get("clarification_response")
        if not clarification_response:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Missing clarification_response"},
            )

        history = pending.setdefault("clarification_history", [])
        if len(history) >= self.max_clarification_rounds:
            pending["status"] = "denied"
            return JSONResponse(
                status_code=403,
                content=build_polling_error_body("denied", "Clarification round limit exceeded"),
            )

        history.append({
            "response": clarification_response,
            "timestamp": int(time.time()),
        })
        if debug:
            logger.debug(f"Clarification response received for {pending_id}: {clarification_response[:80]}")

        # Return current status
        pending_url = f"{self.auth_id}/pending/{pending_id}"
        resp_body = build_pending_response_body(location=pending_url)
        return JSONResponse(status_code=202, content=resp_body)

    async def _handle_interact_get(self, request: Request) -> Response:
        """Handle GET /interact - user interaction endpoint per spec Section 11.5.

        User arrives with ?code=ABCD1234 (and optional &callback=...)
        """
        from fastapi.responses import HTMLResponse

        code = request.query_params.get("code")
        callback = request.query_params.get("callback")

        if not code:
            return HTMLResponse(
                status_code=400,
                content="<html><body><h1>Error</h1><p>Missing code parameter</p></body></html>",
            )

        # Find pending request by interaction code
        pending_id = None
        pending_details = None
        for pid, details in self.pending_requests.items():
            if details.get("interaction_code") == code:
                pending_id = pid
                pending_details = details
                break

        if not pending_details:
            return HTMLResponse(
                status_code=400,
                content="<html><body><h1>Error</h1><p>Invalid or expired interaction code</p></body></html>",
            )

        # Check expiration
        if int(time.time()) >= pending_details.get("expires_at", 0):
            pending_details["status"] = "expired"
            return HTMLResponse(
                status_code=400,
                content="<html><body><h1>Error</h1><p>Interaction code expired</p></body></html>",
            )

        # Mark as interacting — user has arrived at the interaction endpoint
        pending_details["status"] = "interacting"

        # Store callback URL if provided
        if callback:
            pending_details["callback"] = callback

        # Check if user is authenticated
        user_id = pending_details.get("user_id")
        if not user_id:
            return self._render_login_page(pending_id, code, pending_details)
        else:
            return self._render_consent_page(pending_id, code, pending_details, user_id)

    async def _handle_interact_post(self, request: Request) -> Response:
        """Handle POST /interact - login and consent form submission."""
        from fastapi.responses import RedirectResponse, HTMLResponse

        form_data = await request.form()
        pending_id = form_data.get("pending_id")
        code = form_data.get("code")
        action = form_data.get("action", "")
        username = form_data.get("username", "")
        password = form_data.get("password", "")
        consent = form_data.get("consent", "")

        if not pending_id or not code:
            return HTMLResponse(
                status_code=400,
                content="<html><body><h1>Error</h1><p>Missing pending_id or code</p></body></html>",
            )

        pending_details = self.pending_requests.get(pending_id)
        if not pending_details or pending_details.get("interaction_code") != code:
            return HTMLResponse(
                status_code=400,
                content="<html><body><h1>Error</h1><p>Invalid request</p></body></html>",
            )

        # Handle login
        if action == "login" or (username and password):
            user = self.users.get(username)
            if not user or user.get("password") != password:
                return self._render_login_page(
                    pending_id, code, pending_details,
                    error="Invalid username or password",
                )

            pending_details["user_id"] = username
            pending_details["user_name"] = user.get("name", username)
            pending_details["user_email"] = user.get("email", "")

            # Redirect back to show consent page
            interact_url = f"{self.auth_id}/interact?code={code}"
            return RedirectResponse(url=interact_url, status_code=303)

        # Handle consent
        if consent:
            user_id = pending_details.get("user_id")
            if not user_id:
                return self._render_login_page(
                    pending_id, code, pending_details,
                    error="Please authenticate first",
                )

            if consent == "grant":
                pending_details["status"] = "approved"
                # If callback was provided, redirect user there
                callback = pending_details.get("callback")
                if callback:
                    return RedirectResponse(url=callback, status_code=303)
                # Otherwise show completion page
                return HTMLResponse(content=self._render_completion_page(granted=True))

            elif consent == "deny":
                pending_details["status"] = "denied"
                callback = pending_details.get("callback")
                if callback:
                    return RedirectResponse(url=callback, status_code=303)
                return HTMLResponse(content=self._render_completion_page(granted=False))

        return HTMLResponse(
            status_code=400,
            content="<html><body><h1>Error</h1><p>Invalid request</p></body></html>",
        )

    def _render_completion_page(self, granted: bool) -> str:
        """Render a completion page after user consent."""
        if granted:
            return """<!DOCTYPE html><html><head><title>Access Granted</title>
<style>body{font-family:sans-serif;max-width:500px;margin:50px auto;padding:20px}
.ok{background:#efe;border:1px solid #cfc;padding:15px;border-radius:4px;color:#3a3}</style>
</head><body><h1>Access Granted</h1>
<div class="ok">You may close this window. The agent will receive the authorization automatically.</div>
</body></html>"""
        else:
            return """<!DOCTYPE html><html><head><title>Access Denied</title>
<style>body{font-family:sans-serif;max-width:500px;margin:50px auto;padding:20px}
.err{background:#fee;border:1px solid #fcc;padding:15px;border-radius:4px;color:#c33}</style>
</head><body><h1>Access Denied</h1>
<div class="err">You denied the request. You may close this window.</div>
</body></html>"""

    async def _handle_token_refresh(self, request: Request, params_dict: Dict, body_bytes: bytes) -> Response:
        """Handle token refresh per spec Section 11.6."""
        # For now, return not implemented
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "Token refresh not yet implemented"},
        )

    async def _handle_call_chaining(self, request: Request, params_dict: Dict, body_bytes: bytes) -> Response:
        """Handle call chaining (resource_token + upstream_token) per spec Section 11.1."""
        # Delegate to the existing token exchange logic (renamed)
        # Convert params_dict back to the format _handle_token_exchange expects
        return await self._handle_token_exchange(request, params_dict, body_bytes)

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
        agent_is_resource: bool = False,
        act: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> str:
        """Issue auth token per AAuth spec Section 9.1.

        Args:
            agent: Agent identifier (aauth:local@domain)
            resource: Resource identifier (audience)
            scope: Authorized scope
            cnf_jwk: Agent's public signing key (JWK format)
            sub: Optional user identifier
            agent_is_resource: Ignored (kept for caller compatibility during migration)
            act: Actor claim per RFC 8693 §4.1. ``{"sub": agent_id}`` for direct grants;
                 ``{"sub": intermediary_id, "act": upstream_act}`` for call chaining.

        Returns:
            Signed auth token JWT string
        """
        debug = _is_debug_enabled()

        if debug:
            print(f"DEBUG AUTH: Issuing auth token:", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Agent: {agent}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Resource (aud): {resource}", file=sys.stderr, flush=True)
            print(f"DEBUG AUTH:   Scope: {scope}", file=sys.stderr, flush=True)
            if sub:
                print(f"DEBUG AUTH:   User (sub): {sub}", file=sys.stderr, flush=True)

        # Derive pairwise pseudonymous sub per resource per spec Section 15.4.
        # Each resource sees a different sub for the same user, preserving privacy.
        pairwise_sub = None
        if sub:
            import hashlib as _hashlib
            raw = f"{sub}:{resource}:{self.auth_id}".encode("utf-8")
            pairwise_sub = _hashlib.sha256(raw).hexdigest()[:32]

        if debug and sub:
            print(f"DEBUG AUTH:   Pairwise sub: {pairwise_sub} (user={sub}, resource={resource})", file=sys.stderr, flush=True)

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
            sub=pairwise_sub,
            mission=kwargs.get("mission"),
            act=act,
        )
        
        if debug:
            print(f"DEBUG AUTH:   Auth token issued successfully", file=sys.stderr, flush=True)

        # Track issued token JTI for revocation support
        try:
            import jwt as _jwt
            payload_check = _jwt.decode(token, options={"verify_signature": False})
            jti = payload_check.get("jti")
            if jti:
                self.issued_tokens[jti] = {"aud": resource, "agent": agent, "scope": scope}
        except Exception:
            pass

        return token
    
    # NOTE: _generate_request_token, _generate_authorization_code, and _handle_code_exchange
    # have been removed. Replaced by deferred response pattern:
    # _create_pending_request → pending URL + interaction code → polling via GET /pending/{id}
    
    async def _handle_token_exchange_legacy(self, request, params_dict, body_bytes):
        """REMOVED: Code exchange no longer exists in updated spec."""
        return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "Code exchange removed; use deferred responses"})
    
    async def _handle_token_exchange(
        self,
        request: Request,
        params_dict: Dict[str, str],
        body_bytes: bytes
    ) -> Response:
        """Handle token exchange (request_type=exchange) per AAuth spec Section 9.10.
        
        Enables multi-hop resource access. When a resource needs to call a downstream
        resource, it exchanges the upstream auth token for a new token bound to its own key.

        Spec-compliant call chaining: ``Signature-Key`` carries the intermediary's
        ``aa-agent+jwt``; the JSON body MUST include ``resource_token``, ``upstream_token``,
        and ``agent_token`` (matching the Signature-Key JWT). Legacy mode: ``Signature-Key``
        carries the ``aa-auth+jwt`` upstream token (body may omit ``upstream_token``).
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
        
        if scheme != "jwt":
            if debug:
                print(f"DEBUG AUTH:   Token exchange requires scheme=jwt, got {scheme}", file=sys.stderr, flush=True)
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": "Token exchange requires scheme=jwt"}
            )
        
        sig_jwt = key_params.get("jwt")
        if not sig_jwt:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": "Missing jwt parameter in Signature-Key"}
            )

        import jwt as jwt_lib
        try:
            sk_header = jwt_lib.get_unverified_header(sig_jwt)
            sig_jwt_typ = sk_header.get("typ")
        except Exception as e:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": f"Invalid Signature-Key JWT: {e}"}
            )

        body_upstream = params_dict.get("upstream_token")
        body_agent_token = params_dict.get("agent_token")

        if sig_jwt_typ == "aa-agent+jwt":
            if not body_upstream:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_request",
                        "error_description": "upstream_token required in JSON body when Signature-Key carries aa-agent+jwt",
                    },
                )
            if body_agent_token and body_agent_token != sig_jwt:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_request",
                        "error_description": "agent_token in body must match the JWT in Signature-Key",
                    },
                )
            upstream_token = body_upstream
            agent_jwt_for_metadata = sig_jwt
        elif sig_jwt_typ == "aa-auth+jwt":
            upstream_token = sig_jwt
            agent_jwt_for_metadata = None
        else:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "invalid_request",
                    "error_description": f"Signature-Key jwt must be aa-agent+jwt or aa-auth+jwt, got {sig_jwt_typ!r}",
                },
            )

        if debug:
            print(f"DEBUG AUTH:   Upstream token: {upstream_token[:100]}...", file=sys.stderr, flush=True)
        
        try:
            upstream_header = jwt_lib.get_unverified_header(upstream_token)
            upstream_typ = upstream_header.get("typ")
            
            if debug:
                print(f"DEBUG AUTH:   Upstream token type: {upstream_typ}", file=sys.stderr, flush=True)
        except Exception as e:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_token", "error_description": f"Invalid upstream token: {e}"}
            )
        
        if upstream_typ != "aa-auth+jwt":
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_token", "error_description": f"upstream_token must be aa-auth+jwt, got {upstream_typ}"}
            )
        
        # Parse upstream token claims (without verification first)
        try:
            import jwt as jwt_lib
            upstream_payload = jwt_lib.decode(upstream_token, options={"verify_signature": False})
            upstream_iss = upstream_payload.get("iss")  # Upstream auth server
            upstream_aud = upstream_payload.get("aud")  # Should be the requesting resource
            upstream_agent = upstream_payload.get("agent")  # Original agent
            upstream_sub = upstream_payload.get("sub")  # User identifier
            upstream_cnf = upstream_payload.get("cnf", {})
            upstream_cnf_jwk = upstream_cnf.get("jwk")
            
            if debug:
                print(f"DEBUG AUTH:   Upstream token claims:", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:     iss (upstream auth server): {upstream_iss}", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:     aud (requesting resource): {upstream_aud}", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:     agent (original agent): {upstream_agent}", file=sys.stderr, flush=True)
                print(f"DEBUG AUTH:     sub (user): {upstream_sub}", file=sys.stderr, flush=True)
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
            from aauth.metadata.auth_server import fetch_metadata
            import httpx
            
            # Fetch upstream auth server metadata
            metadata_url = f"{upstream_iss}/.well-known/aauth-access"
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
                    from aauth.metadata.auth_server import fetch_metadata
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
                expected_typ="aa-resource+jwt",
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

        if agent_jwt_for_metadata:
            try:
                from aauth.tokens.agent_token import TokenError, verify_agent_token
                import httpx as _httpx

                def _agent_jwks_fetcher(issuer_url: str, kid_param=None):
                    try:
                        from aauth.metadata.auth_server import fetch_metadata

                        mu = f"{issuer_url.rstrip('/')}/.well-known/aauth-agent.json"
                        meta = fetch_metadata(mu)
                        ju = meta.get("jwks_uri")
                        if not ju:
                            return None
                        jr = _httpx.get(ju, timeout=10.0)
                        jr.raise_for_status()
                        return jr.json()
                    except Exception:
                        return None

                ag_claims = verify_agent_token(agent_jwt_for_metadata, _agent_jwks_fetcher)
                if ag_claims.get("iss", "").rstrip("/") != str(requesting_agent).rstrip("/"):
                    return JSONResponse(
                        status_code=401,
                        content={
                            "error": "invalid_token",
                            "error_description": "Agent token iss must match resource token agent",
                        },
                    )
            except TokenError as e:
                return JSONResponse(
                    status_code=401,
                    content={"error": "invalid_token", "error_description": str(e)},
                )

        upstream_act = upstream_payload.get("act") or {"sub": upstream_payload.get("agent", "")}
        act_claim: Dict[str, Any] = {"sub": requesting_agent}
        if upstream_act:
            act_claim["act"] = upstream_act
        
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
            from aauth.metadata.auth_server import fetch_metadata
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
            from aauth.signing.signature_input import parse_signature_input
            from aauth.signing.signature import parse_signature
            from urllib.parse import urlparse
            
            # Parse signature input to get covered components
            components, params = parse_signature_input(signature_input_header)
            
            # Reconstruct signature base
            parsed_uri = urlparse(target_uri)
            authority = parsed_uri.netloc
            path = parsed_uri.path or "/"
            query_string = parsed_uri.query if parsed_uri.query else None
            
            # Extract signature params (the part after "sig=") for @signature-params line
            # Signature-Input format: sig=("@method" "@authority" ...);created=...
            signature_params = signature_input_header.split("=", 1)[1] if "=" in signature_input_header else signature_input_header
            
            signature_base = build_signature_base(
                method=method,
                authority=authority,
                path=path,
                query=query_string,
                headers=headers_dict,
                body=body_bytes,
                signature_key_header=signature_key_header,
                covered_components=components,
                signature_params=signature_params
            )
            
            # Parse signature
            signature_bytes = parse_signature(signature_header, label=None)
            
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
        
        # Evaluate policy for the exchange.
        # For interaction chaining, consent-required policy must return deferred 202
        # so upstream Resource 1 can bubble interaction to the original agent.
        policy_result = self._evaluate_policy(requesting_agent, downstream_resource, scope)
        if policy_result.get("requires_user_consent"):
            return self._create_pending_request(
                agent_id=requesting_agent,
                resource_id=downstream_resource,
                scope=scope,
                agent_jwk=resource_jwk_for_cnf,
                purpose="Downstream access via interaction chaining",
                agent_is_resource=True,
                clarification_supported=False,
                act_claim=act_claim,
            )

        if not policy_result.get("allowed"):
            return JSONResponse(
                status_code=403,
                content={"error": "access_denied", "error_description": policy_result.get("reason", "Access denied")}
            )
        
        if debug:
            print(f"DEBUG AUTH:   Policy evaluation passed", file=sys.stderr, flush=True)
        
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
            act=act_claim,
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
    
    # NOTE: _handle_auth_get and _handle_auth_post removed.
    # Replaced by _handle_interact_get and _handle_interact_post
    # which use interaction codes instead of request_tokens.

    def _render_login_page(
        self,
        pending_id: str,
        code: str,
        request_details: Dict[str, Any],
        error: Optional[str] = None
    ) -> Response:
        """Render login page HTML for interaction endpoint."""
        from fastapi.responses import HTMLResponse

        agent = request_details.get("agent", "Unknown")
        resource = request_details.get("resource", "Unknown")
        error_html = f'<div style="color: red; margin: 10px 0;">{error}</div>' if error else ""

        html = f"""<!DOCTYPE html>
<html><head><title>AAuth Login</title>
<style>
body{{font-family:sans-serif;max-width:500px;margin:50px auto;padding:20px;background:#f5f5f5}}
.container{{background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1)}}
h1{{margin-top:0;color:#333}}
.info{{background:#f0f0f0;padding:15px;border-radius:4px;margin:20px 0;font-size:14px}}
.info strong{{display:block;margin-bottom:5px}}
label{{display:block;margin:10px 0 5px;font-weight:500}}
input[type="text"],input[type="password"]{{width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;font-size:14px;box-sizing:border-box}}
button{{width:100%;padding:12px;background:#007bff;color:#fff;border:none;border-radius:4px;font-size:16px;font-weight:500;cursor:pointer;margin-top:15px}}
button:hover{{background:#0056b3}}
.demo{{background:#e7f3ff;padding:10px;border-radius:4px;margin:15px 0;font-size:12px;color:#0066cc}}
</style></head>
<body><div class="container">
<h1>AAuth Login</h1>
<div class="info"><strong>Agent:</strong> {agent}<br><strong>Resource:</strong> {resource}</div>
<div class="info"><strong>Interaction Code:</strong> {code}</div>
{error_html}
<form method="POST" action="/interact">
<input type="hidden" name="pending_id" value="{pending_id}">
<input type="hidden" name="code" value="{code}">
<input type="hidden" name="action" value="login">
<label for="username">Username:</label>
<input type="text" id="username" name="username" required>
<label for="password">Password:</label>
<input type="password" id="password" name="password" required>
<div class="demo"><strong>Demo Credentials:</strong><br>Username: testuser / Password: testpass</div>
<button type="submit">Login</button>
</form></div></body></html>"""

        return HTMLResponse(content=html)

    def _render_consent_page(
        self,
        pending_id: str,
        code: str,
        request_details: Dict[str, Any],
        user_id: str
    ) -> Response:
        """Render consent page HTML for interaction endpoint."""
        from fastapi.responses import HTMLResponse

        agent = request_details.get("agent", "Unknown")
        resource = request_details.get("resource", "Unknown")
        scope = request_details.get("scope", "")
        purpose = request_details.get("purpose", "")
        user_name = request_details.get("user_name", user_id)

        scopes = scope.split() if scope else []
        scope_descs = {"data.read": "Read access to your data", "data.write": "Write access to your data", "data.delete": "Delete access to your data"}
        scope_list_html = "".join(f'<li><strong>{s}</strong> - {scope_descs.get(s, s)}</li>' for s in scopes) or '<li>No specific scopes requested</li>'
        purpose_html = f'<div class="info"><strong>Purpose:</strong> {purpose}</div>' if purpose else ""

        html = f"""<!DOCTYPE html>
<html><head><title>AAuth Authorization</title>
<style>
body{{font-family:sans-serif;max-width:600px;margin:50px auto;padding:20px;background:#f5f5f5}}
.container{{background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1)}}
h1{{margin-top:0;color:#333}}
.info{{background:#f0f0f0;padding:15px;border-radius:4px;margin:20px 0;font-size:14px}}
.info strong{{display:block;margin-bottom:5px}}
.scopes{{background:#fff9e6;padding:15px;border-radius:4px;margin:20px 0}}
.scopes ul{{margin:10px 0;padding-left:20px}}
.scopes li{{margin:5px 0}}
.buttons{{display:flex;gap:10px;margin-top:25px}}
button{{flex:1;padding:12px;border:none;border-radius:4px;font-size:16px;font-weight:500;cursor:pointer}}
.grant{{background:#28a745;color:#fff}}.grant:hover{{background:#218838}}
.deny{{background:#dc3545;color:#fff}}.deny:hover{{background:#c82333}}
</style></head>
<body><div class="container">
<h1>Authorize Access</h1>
<p>Hello, <strong>{user_name}</strong>!</p>
<div class="info"><strong>Agent:</strong> {agent}<br><strong>Resource:</strong> {resource}</div>
{purpose_html}
<div class="scopes"><strong>Permissions requested:</strong><ul>{scope_list_html}</ul></div>
<div class="buttons">
<form method="POST" action="/interact" style="flex:1">
<input type="hidden" name="pending_id" value="{pending_id}">
<input type="hidden" name="code" value="{code}">
<input type="hidden" name="consent" value="grant">
<button type="submit" class="grant">Grant Access</button>
</form>
<form method="POST" action="/interact" style="flex:1">
<input type="hidden" name="pending_id" value="{pending_id}">
<input type="hidden" name="code" value="{code}">
<input type="hidden" name="consent" value="deny">
<button type="submit" class="deny">Deny</button>
</form>
</div></div></body></html>"""

        return HTMLResponse(content=html)

    async def _handle_revocation(self, request: Request) -> Response:
        """Handle POST /revoke — revoke an issued auth token by JTI.

        Per spec Section 14: verify caller identity, check JTI is known, mark revoked.
        Returns 200 (revoked/already invalid) or 404 (JTI not recognized).
        """
        import json as _json
        import httpx as _httpx

        body_bytes = await request.body()
        try:
            body = _json.loads(body_bytes)
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "Body must be JSON"})

        jti = body.get("jti")
        if not jti:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "Missing 'jti'"})

        # Already revoked — idempotent
        if jti in self.revoked_jtis:
            return JSONResponse(content={"status": "revoked"})

        if jti not in self.issued_tokens:
            return JSONResponse(status_code=404, content={"error": "not_found", "error_description": "JTI not recognized"})

        # Verify caller signature (trusted PS or the token recipient)
        headers_dict = dict(request.headers)
        hl = {k.lower(): v for k, v in headers_dict.items()}
        sig_in = hl.get("signature-input", "")
        sig = hl.get("signature", "")
        sig_key = hl.get("signature-key", "")
        if not sig_in or not sig or not sig_key:
            return JSONResponse(status_code=401, content={"error": "invalid_signature", "error_description": "Missing signature headers"})

        try:
            from aauth.signing.signature_key import parse_signature_key
            pk = parse_signature_key(sig_key)
            caller_id = pk["params"].get("id") or pk["params"].get("uri")
        except Exception as e:
            return JSONResponse(status_code=401, content={"error": "invalid_signature", "error_description": str(e)})

        caller_trusted = caller_id and (
            caller_id in self.trusted_person_servers
            or caller_id == self.issued_tokens[jti].get("aud")
        )
        if not caller_trusted:
            return JSONResponse(status_code=403, content={"error": "forbidden", "error_description": "Not authorized to revoke"})

        def jwks_fetcher(issuer_url, kid_param=None):
            try:
                for path in ("/.well-known/aauth-person.json", "/.well-known/aauth-access.json",
                             "/.well-known/aauth-person", "/.well-known/aauth-access"):
                    r = _httpx.get(f"{issuer_url.rstrip('/')}{path}", timeout=10.0)
                    if r.status_code == 200:
                        jwks_uri = r.json().get("jwks_uri")
                        if jwks_uri:
                            j = _httpx.get(jwks_uri, timeout=10.0)
                            return j.json() if j.status_code == 200 else None
            except Exception:
                return None

        from aauth.signing.verifier import verify_signature
        ok = verify_signature(
            method=request.method,
            target_uri=str(request.url),
            headers=headers_dict,
            body=body_bytes,
            signature_input_header=sig_in,
            signature_header=sig,
            signature_key_header=sig_key,
            jwks_fetcher=jwks_fetcher,
        )
        if not ok:
            return JSONResponse(status_code=401, content={"error": "invalid_signature"})

        self.revoked_jtis.add(jti)
        logger.debug(f"Revoked token JTI {jti} (requested by {caller_id})")
        return JSONResponse(content={"status": "revoked"})

    async def revoke_token(self, jti: str, resource_url: str) -> bool:
        """Revoke an auth token at the resource's revocation endpoint.

        The AS signs the revocation request using its own key and sends it to
        the resource's ``/revoke`` endpoint.

        Args:
            jti: JTI of the auth token to revoke
            resource_url: Base URL of the resource (revocation_endpoint = resource_url + /revoke)

        Returns:
            True if successfully revoked, False otherwise
        """
        import json as _json
        import httpx as _httpx

        revoke_url = f"{resource_url.rstrip('/')}/revoke"
        body_dict = {"jti": jti}
        body_bytes = _json.dumps(body_dict).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        from aauth.signing.signer import sign_request
        sig_headers = sign_request(
            method="POST",
            target_uri=revoke_url,
            headers=headers,
            body=body_bytes,
            private_key=self.private_key,
            sig_scheme="jwks_uri",
            id=self.auth_id,
            kid=self.kid,
        )
        req_headers = {**headers, **sig_headers}
        try:
            async with _httpx.AsyncClient() as client:
                resp = await client.post(revoke_url, content=body_bytes, headers=req_headers, timeout=10.0)
            return resp.status_code == 200
        except Exception as e:
            logger.warning(f"Failed to revoke token {jti} at {revoke_url}: {e}")
            return False

    def run(self):
        """Run the auth server."""
        import uvicorn
        uvicorn.run(self.app, host="0.0.0.0", port=self.port)


# Backward-compatibility alias
AuthServer = AccessServer

if __name__ == "__main__":
    access_server = AccessServer("https://access.example", port=8003)
    access_server.run()

