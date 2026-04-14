"""Person Server participant — agents send token requests here; PS federates with AS."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import httpx
import jwt as pyjwt
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.responses import HTMLResponse

from aauth.debug import _is_debug_enabled, _is_http_debug_enabled
from aauth.errors import ERROR_INTERACTION_REQUIRED, ERROR_MISSION_TERMINATED
from aauth.headers.aauth_header import parse_aauth_capabilities_header
from aauth.headers.signature_key import parse_signature_key
from aauth.http.deferred import (
    build_pending_response_body,
    build_pending_response_headers,
    build_success_response,
    detect_token_request_mode,
)
from aauth.keys.jwk import generate_jwks, public_key_to_jwk
from aauth.keys.keypair import generate_ed25519_keypair
from aauth.metadata.mission_manager import generate_ps_metadata
from aauth.signing.signer import sign_request
from aauth.signing.verifier import verify_signature
from aauth.tokens.agent_token import verify_agent_token

logger = logging.getLogger("aauth.person_server")


class PersonServer:
    """Person Server: mission lifecycle + broker to authorization server(s)."""

    def __init__(
        self,
        ps_id: str,
        port: int = 8004,
        require_user_consent: bool = False,
        require_approval: bool = False,
        approval_delay: float = 2.0,
        approval_outcome: str = "approve",
        capabilities: Optional[List[str]] = None,
    ):
        self.ps_id = ps_id.rstrip("/")
        self.port = port
        self.require_user_consent = require_user_consent
        self.require_approval = require_approval
        self.approval_delay = approval_delay
        self.approval_outcome = approval_outcome
        # Capabilities the PS can provide on behalf of the user for an approved mission.
        # Per spec §Mission Approval: the agent unions these with its own capabilities
        # to produce the AAuth-Capabilities request header.
        self.capabilities: List[str] = capabilities if capabilities is not None else ["interaction"]
        self.private_key, self.public_key = generate_ed25519_keypair()
        self.kid = "ps-key-1"

        self.missions: Dict[str, Dict[str, Any]] = {}
        self.pending_requests: Dict[str, Dict[str, Any]] = {}
        # Revocation: track auth tokens issued/brokered under missions
        self.issued_tokens: Dict[str, Dict] = {}   # jti -> {aud, agent, ...}
        self.revoked_jtis: set = set()
        self.users: Dict[str, Dict[str, str]] = {
            "testuser": {"password": "testpass", "name": "Test User", "email": "testuser@example.com"}
        }

        self.app = FastAPI(title="AAuth Person Server")
        self._setup_routes()

    def _setup_routes(self) -> None:
        @self.app.get("/")
        async def root():
            return {"person_server": self.ps_id, "status": "running"}

        @self.app.get("/jwks.json")
        async def jwks():
            jwk = public_key_to_jwk(self.public_key, kid=self.kid)
            return generate_jwks([jwk])

        @self.app.get("/.well-known/aauth-person.json")
        @self.app.get("/.well-known/aauth-person")
        async def ps_meta():
            return generate_ps_metadata(
                person_server=self.ps_id,
                token_endpoint=f"{self.ps_id}/token",
                mission_endpoint=f"{self.ps_id}/mission",
                jwks_uri=f"{self.ps_id}/jwks.json",
                revocation_endpoint=f"{self.ps_id}/revoke",
            )

        @self.app.post("/revoke")
        async def revoke(request: Request):
            """Token revocation endpoint per AAuth spec Section 14."""
            return await self._handle_revocation(request)

        @self.app.post("/mission")
        async def mission(req: Request):
            return await self._handle_mission(req)

        @self.app.post("/token")
        async def token(req: Request):
            return await self._handle_token(req)

        @self.app.get("/pending/{pid}")
        async def pget(pid: str, request: Request):
            return await self._handle_pending_get(pid, request)

        @self.app.post("/pending/{pid}")
        async def ppost(pid: str, request: Request):
            return await self._handle_pending_post(pid, request)

        @self.app.delete("/pending/{pid}")
        async def pdel(pid: str, request: Request):
            return await self._handle_pending_delete(pid, request)

        @self.app.get("/interact")
        async def iget(request: Request):
            return await self._handle_interact_get(request)

        @self.app.post("/interact")
        async def ipost(request: Request):
            return await self._handle_interact_post(request)

    async def _handle_mission(self, request: Request) -> Response:
        """POST /mission — agent proposes a mission; PS verifies, approves, returns mission blob.

        Per spec §Mission Creation: agent MUST sign with scheme=jwt (agent token).
        Per spec §Mission Approval: response body IS the mission blob; s256 = SHA-256 of blob bytes.
        """
        body_bytes = await request.body()
        try:
            body = json.loads(body_bytes) if body_bytes else {}
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "Body must be JSON"})

        description = body.get("description", "")
        if not description:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "'description' is required"},
            )
        tools = body.get("tools", [])

        # Spec §Mission Creation: agent MUST present its agent token via Signature-Key with scheme=jwt.
        headers_dict = dict(request.headers)
        hl = {k.lower(): v for k, v in headers_dict.items()}
        sig_in = hl.get("signature-input", "")
        sig = hl.get("signature", "")
        sig_key = hl.get("signature-key", "")
        if not sig_in or not sig or not sig_key:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_signature", "error_description": "Missing signature headers"},
            )

        try:
            pk = parse_signature_key(sig_key)
            scheme = pk["scheme"]
            key_params = pk["params"]
        except Exception as e:
            return JSONResponse(status_code=401, content={"error": "invalid_request", "error_description": str(e)})

        if scheme != "jwt":
            return JSONResponse(
                status_code=401,
                content={
                    "error": "invalid_request",
                    "error_description": "Mission creation requires Signature-Key scheme=jwt with an agent token",
                },
            )

        jwt_tok = key_params.get("jwt")
        if not jwt_tok:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_request", "error_description": "scheme=jwt requires 'jwt' parameter"},
            )

        # Verify it is an agent token (aa-agent+jwt)
        try:
            token_header = pyjwt.get_unverified_header(jwt_tok)
            if token_header.get("typ") != "aa-agent+jwt":
                raise ValueError(f"expected aa-agent+jwt, got {token_header.get('typ')}")
            agent_payload_unverified = pyjwt.decode(jwt_tok, options={"verify_signature": False})
            agent_sub = agent_payload_unverified.get("sub", "")
        except Exception as e:
            return JSONResponse(status_code=401, content={"error": "invalid_agent_token", "error_description": str(e)})

        def agent_jwks_fetcher(iss: str, kid_param: str = None):
            try:
                meta = httpx.get(f"{iss.rstrip('/')}/.well-known/aauth-agent.json", timeout=10.0)
                meta.raise_for_status()
                ju = meta.json().get("jwks_uri")
                if not ju:
                    return None
                j = httpx.get(ju, timeout=10.0)
                j.raise_for_status()
                return j.json()
            except Exception:
                return None

        # Full agent token + HTTP signature verification
        try:
            verify_agent_token(jwt_tok, jwks_fetcher=agent_jwks_fetcher)
        except Exception as e:
            return JSONResponse(status_code=401, content={"error": "invalid_agent_token", "error_description": str(e)})

        ok = verify_signature(
            method=request.method,
            target_uri=str(request.url),
            headers=headers_dict,
            body=body_bytes,
            signature_input_header=sig_in,
            signature_header=sig,
            signature_key_header=sig_key,
            jwks_fetcher=agent_jwks_fetcher,
        )
        if not ok:
            return JSONResponse(status_code=401, content={"error": "invalid_signature"})

        # Build the mission blob (spec §Mission Approval required fields).
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        blob: Dict[str, Any] = {
            "approver": self.ps_id,
            "agent": agent_sub,
            "approved_at": now,
            "description": description,
        }
        if tools:
            blob["approved_tools"] = tools
        # capabilities: what this PS can provide on behalf of the user for this session.
        # The agent unions these with its own capabilities for AAuth-Capabilities (spec §AAuth-Capabilities).
        if self.capabilities:
            blob["capabilities"] = self.capabilities

        # s256 = base64url(SHA-256(blob_bytes)); blob_bytes are the exact response body bytes.
        blob_bytes = json.dumps(blob, separators=(",", ":"), sort_keys=True).encode("utf-8")
        digest = hashlib.sha256(blob_bytes).digest()
        s256 = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

        self.missions[s256] = {"blob": blob, "status": "active"}

        # AAuth-Mission response header (spec §Mission Approval)
        mission_header_val = f'approver="{self.ps_id}"; s256="{s256}"'
        return Response(
            content=blob_bytes,
            status_code=200,
            headers={"AAuth-Mission": mission_header_val},
            media_type="application/json",
        )

    def terminate_mission(self, s256: str) -> bool:
        """Terminate a mission by its s256 hash.

        Missions have two states: active or terminated (no suspended state).
        Returns True if the mission was found and terminated, False if not found.
        """
        mission = self.missions.get(s256)
        if mission is None:
            return False
        mission["status"] = "terminated"
        return True

    def _ps_jwks_fetcher(self, issuer_url: str, kid_param: Optional[str] = None):
        try:
            url = f"{issuer_url.rstrip('/')}/jwks.json"
            r = httpx.get(url, timeout=10.0)
            r.raise_for_status()
            return r.json()
        except Exception:
            return None

    async def _handle_token(self, request: Request) -> Response:
        body_bytes = await request.body()
        body_text = body_bytes.decode("utf-8") if body_bytes else "{}"
        try:
            params_dict = json.loads(body_text) if body_text else {}
        except Exception as e:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": str(e)})

        try:
            mode = detect_token_request_mode(params_dict)
        except ValueError as e:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": str(e)})

        if mode in ("token_refresh", "self_access"):
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "PS token endpoint expects resource_token"},
            )

        headers_dict = dict(request.headers)
        hl = {k.lower(): v for k, v in headers_dict.items()}
        sig_in = hl.get("signature-input", "")
        sig = hl.get("signature", "")
        sig_key = hl.get("signature-key", "")
        if not sig_in or not sig or not sig_key:
            return JSONResponse(status_code=401, content={"error": "invalid_signature", "error_description": "Missing signature headers"})

        try:
            pk = parse_signature_key(sig_key)
            scheme = pk["scheme"]
            key_params = pk["params"]
        except Exception as e:
            return JSONResponse(status_code=401, content={"error": "invalid_request", "error_description": str(e)})

        agent_token_for_as: Optional[str] = None
        jwt_tok: Optional[str] = None

        def agent_jwks_fetcher(iss: str, kid=None):
            try:
                meta = httpx.get(f"{iss.rstrip('/')}/.well-known/aauth-agent.json", timeout=10.0)
                meta.raise_for_status()
                ju = meta.json().get("jwks_uri")
                if not ju:
                    return None
                j = httpx.get(ju, timeout=10.0)
                j.raise_for_status()
                return j.json()
            except Exception:
                return None

        if scheme == "jwt":
            if not key_params.get("jwt"):
                return JSONResponse(
                    status_code=401,
                    content={"error": "invalid_request", "error_description": "sig=jwt requires jwt param"},
                )
            jwt_tok = key_params["jwt"]
            try:
                header = pyjwt.get_unverified_header(jwt_tok)
                if header.get("typ") != "aa-agent+jwt":
                    raise ValueError("not an agent token")
                verify_agent_token(jwt_tok, jwks_fetcher=agent_jwks_fetcher)
            except Exception as e:
                return JSONResponse(status_code=401, content={"error": "invalid_agent_token", "error_description": str(e)})
            agent_token_for_as = jwt_tok
        elif scheme in ("jwks", "jwks_uri"):
            pass
        else:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "invalid_request",
                    "error_description": "PS token requests require sig=jwt or sig=jwks_uri",
                },
            )

        def ps_jwks_fetcher(agent_id_param: str, kid_param: str = None):
            return self._ps_jwks_fetcher(agent_id_param, kid_param)

        verify_fetcher = agent_jwks_fetcher if scheme in ("jwks", "jwks_uri") else ps_jwks_fetcher

        ok = verify_signature(
            method=request.method,
            target_uri=str(request.url),
            headers=headers_dict,
            body=body_bytes,
            signature_input_header=sig_in,
            signature_header=sig,
            signature_key_header=sig_key,
            jwks_fetcher=verify_fetcher,
        )
        if not ok:
            return JSONResponse(status_code=401, content={"error": "invalid_signature"})

        # Check mission state if a mission reference is included.
        # Missions are two-state: active or terminated (no suspended state).
        mission_ref = params_dict.get("mission")
        if mission_ref:
            mission = self.missions.get(mission_ref)
            if mission is None or mission.get("status") != "active":
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": ERROR_MISSION_TERMINATED,
                        "error_description": "The referenced mission is terminated or does not exist",
                        "mission_status": "terminated",
                    },
                )

        resource_token = params_dict.get("resource_token")
        if not resource_token:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "resource_token required"})

        try:
            rt_payload = pyjwt.decode(resource_token, options={"verify_signature": False})
        except Exception as e:
            return JSONResponse(status_code=400, content={"error": "invalid_resource_token", "error_description": str(e)})

        as_url = rt_payload.get("aud")
        if not as_url:
            return JSONResponse(status_code=400, content={"error": "invalid_resource_token", "error_description": "no aud"})

        upstream_token = params_dict.get("upstream_token")

        if self.require_user_consent:
            # Check if agent declares the interaction capability.
            # If not, we cannot reach the user via interaction — return interaction_required.
            caps_header = headers_dict.get("AAuth-Capabilities") or headers_dict.get("aauth-capabilities") or ""
            capabilities = parse_aauth_capabilities_header(caps_header) if caps_header else []
            if "interaction" not in capabilities:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": ERROR_INTERACTION_REQUIRED,
                        "error_description": "User interaction is needed but the agent does not declare the 'interaction' capability",
                    },
                )
            return self._create_ps_pending(resource_token, agent_token_for_as, as_url, params_dict, upstream_token)

        if self.require_approval:
            return await self._create_ps_approval_pending(resource_token, agent_token_for_as, as_url, params_dict, upstream_token)

        resp = await self._forward_to_as(as_url, resource_token, agent_token_for_as, upstream_token)
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=dict(resp.headers),
            media_type=resp.headers.get("content-type", "application/json"),
        )

    def _create_ps_pending(
        self,
        resource_token: str,
        agent_token: Optional[str],
        as_url: str,
        params: Dict[str, Any],
        upstream_token: Optional[str] = None,
    ) -> JSONResponse:
        pid = uuid.uuid4().hex[:12]
        code = uuid.uuid4().hex[:8].upper()
        loc = f"{self.ps_id}/pending/{pid}"
        self.pending_requests[pid] = {
            "resource_token": resource_token,
            "agent_token": agent_token or "",
            "as_url": as_url,
            "interaction_code": code,
            "status": "pending",
            "params": params,
            "upstream_token": upstream_token or "",
        }
        body = build_pending_response_body(location=loc, require="interaction", code=code)
        hdrs = build_pending_response_headers(location=loc, retry_after=0, require="interaction", code=code, url=f"{self.ps_id}/interact")
        return JSONResponse(status_code=202, content=body, headers=hdrs)

    async def _create_ps_approval_pending(
        self,
        resource_token: str,
        agent_token: Optional[str],
        as_url: str,
        params: Dict[str, Any],
        upstream_token: Optional[str] = None,
    ) -> JSONResponse:
        """Create a direct-approval pending request (requirement=approval, no interaction code).

        Schedules a background task that simulates the MM contacting the user
        out-of-band (push notification, email, etc.) and resolving the pending
        request after ``approval_delay`` seconds.
        """
        pid = uuid.uuid4().hex[:12]
        loc = f"{self.ps_id}/pending/{pid}"
        self.pending_requests[pid] = {
            "resource_token": resource_token,
            "agent_token": agent_token or "",
            "as_url": as_url,
            "require_type": "approval",
            "status": "pending",
            "params": params,
            "upstream_token": upstream_token or "",
        }
        asyncio.ensure_future(self._auto_resolve_pending(pid))
        body = build_pending_response_body(location=loc, require="approval")
        hdrs = build_pending_response_headers(location=loc, retry_after=3, require="approval")
        return JSONResponse(status_code=202, content=body, headers=hdrs)

    async def _auto_resolve_pending(self, pid: str) -> None:
        """Background task: resolve a pending approval after ``approval_delay`` seconds.

        Simulates the MM contacting the user via push/email and receiving approval
        (or denial) out of band.
        """
        await asyncio.sleep(self.approval_delay)
        p = self.pending_requests.get(pid)
        if not p or p.get("status") != "pending":
            return
        if self.approval_outcome == "deny":
            p["status"] = "denied"
            return
        fwd = await self._forward_to_as(
            p["as_url"],
            p["resource_token"],
            p.get("agent_token") or None,
            p.get("upstream_token") or None,
        )
        if fwd.status_code == 200:
            data = fwd.json()
            auth_token = data.get("auth_token")
            p["auth_token"] = auth_token
            p["status"] = "approved"
            # Track JTI for revocation support
            if auth_token:
                try:
                    import jwt as _pyjwt
                    payload_check = _pyjwt.decode(auth_token, options={"verify_signature": False})
                    jti_val = payload_check.get("jti")
                    if jti_val:
                        self.issued_tokens[jti_val] = {
                            "aud": payload_check.get("aud"),
                            "agent": payload_check.get("agent"),
                        }
                except Exception:
                    pass
        else:
            p["status"] = "denied"

    async def _forward_to_as(
        self, as_url: str, resource_token: str, agent_token: Optional[str] = None,
        upstream_token: Optional[str] = None,
    ) -> httpx.Response:
        token_url = f"{as_url.rstrip('/')}/token"
        body_obj: Dict[str, Any] = {"resource_token": resource_token}
        if agent_token:
            body_obj["agent_token"] = agent_token
        if upstream_token:
            body_obj["upstream_token"] = upstream_token
        body_bytes = json.dumps(body_obj).encode("utf-8")

        def do_sign():
            hdrs: Dict[str, str] = {"Content-Type": "application/json"}
            return sign_request(
                method="POST",
                target_uri=token_url,
                headers=hdrs,
                body=body_bytes,
                private_key=self.private_key,
                sig_scheme="jwks_uri",
                id=self.ps_id,
                kid=self.kid,
            )

        sig_headers = await asyncio.to_thread(do_sign)
        req_headers = {k: v for k, v in sig_headers.items()}
        req_headers["Content-Type"] = "application/json"

        def post():
            return httpx.post(token_url, content=body_bytes, headers=req_headers, timeout=60.0)

        return await asyncio.to_thread(post)

    async def _handle_pending_get(self, pid: str, request: Request) -> Response:
        p = self.pending_requests.get(pid)
        if not p:
            # Per spec: once a terminal response has been returned, subsequent
            # requests to the pending URL MUST return 410 Gone.
            return Response(status_code=410)
        if p.get("status") == "approved" and p.get("auth_token"):
            auth_token = p["auth_token"]
            # Remove the pending request — terminal response; future polls return 410.
            del self.pending_requests[pid]
            return JSONResponse(content={"auth_token": auth_token, "expires_in": 3600})
        if p.get("status") == "denied":
            del self.pending_requests[pid]
            return JSONResponse(status_code=403, content={"error": "denied"})
        loc = f"{self.ps_id}/pending/{pid}"
        req_type = p.get("require_type", "interaction")
        code = p.get("interaction_code") if req_type == "interaction" else None
        body = build_pending_response_body(location=loc, require=req_type, code=code)
        interaction_url = f"{self.ps_id}/interact" if req_type == "interaction" else None
        return JSONResponse(status_code=202, content=body, headers=build_pending_response_headers(loc, 2, req_type, code, url=interaction_url))

    async def _handle_pending_post(self, pid: str, request: Request) -> Response:
        return JSONResponse(status_code=400, content={"error": "not_implemented"})

    async def _handle_pending_delete(self, pid: str, request: Request) -> Response:
        if pid in self.pending_requests:
            del self.pending_requests[pid]
            return Response(status_code=410)
        return JSONResponse(status_code=404, content={"error": "not_found"})

    async def _handle_interact_get(self, request: Request) -> Response:
        code = request.query_params.get("code", "")
        return HTMLResponse(
            f"<html><body><h1>PS Consent</h1><form method='post'><input name='consent' value='grant'/><button>Submit</button></form><p>code={code}</p></body></html>"
        )

    async def _handle_interact_post(self, request: Request) -> Response:
        form = await request.form()
        if form.get("consent") == "grant":
            for pid, p in list(self.pending_requests.items()):
                if p.get("status") == "pending":
                    at = p.get("agent_token") or None
                    ut = p.get("upstream_token") or None
                    fwd = await self._forward_to_as(p["as_url"], p["resource_token"], at or None, ut or None)
                    if fwd.status_code == 200:
                        data = fwd.json()
                        auth_token = data.get("auth_token")
                        p["auth_token"] = auth_token
                        p["status"] = "approved"
                        # Track JTI for revocation
                        if auth_token:
                            try:
                                tok_payload = pyjwt.decode(auth_token, options={"verify_signature": False})
                                jti_val = tok_payload.get("jti")
                                if jti_val:
                                    self.issued_tokens[jti_val] = {
                                        "aud": tok_payload.get("aud"),
                                        "agent": tok_payload.get("agent"),
                                    }
                            except Exception:
                                pass
                    break
        return HTMLResponse("<html><body>ok</body></html>")

    async def _handle_revocation(self, request: Request) -> Response:
        """Handle POST /revoke — revoke a brokered auth token by JTI.

        Per spec Section 14: verify caller identity, check JTI is known, mark revoked.
        """
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "Body must be JSON"})

        jti = body.get("jti")
        if not jti:
            return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "Missing 'jti'"})

        if jti in self.revoked_jtis:
            return JSONResponse(content={"status": "revoked"})

        if jti not in self.issued_tokens:
            return JSONResponse(status_code=404, content={"error": "not_found", "error_description": "JTI not recognized"})

        headers_dict = dict(request.headers)
        hl = {k.lower(): v for k, v in headers_dict.items()}
        sig_in = hl.get("signature-input", "")
        sig = hl.get("signature", "")
        sig_key = hl.get("signature-key", "")
        if not sig_in or not sig or not sig_key:
            return JSONResponse(status_code=401, content={"error": "invalid_signature", "error_description": "Missing signature headers"})

        # Accept revocation from the token's resource (aud) only
        try:
            from aauth.headers.signature_key import parse_signature_key
            pk = parse_signature_key(sig_key)
            caller_id = pk["params"].get("id") or pk["params"].get("uri")
        except Exception as e:
            return JSONResponse(status_code=401, content={"error": "invalid_signature", "error_description": str(e)})

        token_info = self.issued_tokens.get(jti, {})
        if caller_id != token_info.get("aud"):
            return JSONResponse(status_code=403, content={"error": "forbidden", "error_description": "Not authorized to revoke"})

        def jwks_fetcher(issuer_url, kid_param=None):
            try:
                for path in ("/.well-known/aauth-resource.json", "/.well-known/aauth-resource"):
                    r = httpx.get(f"{issuer_url.rstrip('/')}{path}", timeout=10.0)
                    if r.status_code == 200:
                        jwks_uri = r.json().get("jwks_uri")
                        if jwks_uri:
                            j = httpx.get(jwks_uri, timeout=10.0)
                            return j.json() if j.status_code == 200 else None
            except Exception:
                return None

        from aauth.signing.verifier import verify_signature
        body_bytes = json.dumps(body).encode("utf-8")
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
        return JSONResponse(content={"status": "revoked"})

    async def revoke_token(self, jti: str, resource_url: str) -> bool:
        """Revoke an auth token at the resource's revocation endpoint.

        The PS signs the revocation request and sends it to the resource's ``/revoke``.

        Args:
            jti: JTI of the auth token to revoke
            resource_url: Base URL of the resource

        Returns:
            True if successfully revoked, False otherwise
        """
        revoke_url = f"{resource_url.rstrip('/')}/revoke"
        body_obj = {"jti": jti}
        body_bytes = json.dumps(body_obj).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        sig_headers = sign_request(
            method="POST",
            target_uri=revoke_url,
            headers=headers,
            body=body_bytes,
            private_key=self.private_key,
            sig_scheme="jwks_uri",
            id=self.ps_id,
            kid=self.kid,
        )
        req_headers = {**headers, **sig_headers}
        try:
            resp = await asyncio.to_thread(
                lambda: httpx.post(revoke_url, content=body_bytes, headers=req_headers, timeout=10.0)
            )
            return resp.status_code == 200
        except Exception as e:
            logger.warning(f"Failed to revoke token {jti} at {revoke_url}: {e}")
            return False

    def run(self) -> None:
        """Run the Person Server (same pattern as ``Agent`` / ``Resource``)."""
        import uvicorn

        uvicorn.run(self.app, host="0.0.0.0", port=self.port)


# Backward-compatibility alias
MissionManager = PersonServer
