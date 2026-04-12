"""Mission Manager participant — agents send token requests here; MM federates with AS."""

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
from aauth.headers.signature_key import parse_signature_key
from aauth.http.deferred import (
    build_pending_response_body,
    build_pending_response_headers,
    build_success_response,
    detect_token_request_mode,
)
from aauth.keys.jwk import generate_jwks, public_key_to_jwk
from aauth.keys.keypair import generate_ed25519_keypair
from aauth.metadata.mission_manager import generate_mm_metadata
from aauth.signing.signer import sign_request
from aauth.signing.verifier import verify_signature
from aauth.tokens.agent_token import verify_agent_token

logger = logging.getLogger("aauth.mission_manager")


class MissionManager:
    """Mission Manager: mission lifecycle + broker to authorization server(s)."""

    def __init__(
        self,
        mm_id: str,
        port: int = 8004,
        require_user_consent: bool = False,
    ):
        self.mm_id = mm_id.rstrip("/")
        self.port = port
        self.require_user_consent = require_user_consent
        self.private_key, self.public_key = generate_ed25519_keypair()
        self.kid = "mm-key-1"

        self.missions: Dict[str, Dict[str, Any]] = {}
        self.pending_requests: Dict[str, Dict[str, Any]] = {}
        self.users: Dict[str, Dict[str, str]] = {
            "testuser": {"password": "testpass", "name": "Test User", "email": "testuser@example.com"}
        }

        self.app = FastAPI(title="AAuth Mission Manager")
        self._setup_routes()

    def _setup_routes(self) -> None:
        @self.app.get("/")
        async def root():
            return {"manager": self.mm_id, "status": "running"}

        @self.app.get("/jwks.json")
        async def jwks():
            jwk = public_key_to_jwk(self.public_key, kid=self.kid)
            return generate_jwks([jwk])

        @self.app.get("/.well-known/aauth-mission.json")
        @self.app.get("/.well-known/aauth-mission")
        async def mm_meta():
            return generate_mm_metadata(
                manager=self.mm_id,
                token_endpoint=f"{self.mm_id}/token",
                mission_endpoint=f"{self.mm_id}/mission",
                jwks_uri=f"{self.mm_id}/jwks.json",
            )

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
        body = await request.json()
        proposal = body.get("mission_proposal", "")
        if not proposal:
            return JSONResponse(status_code=400, content={"error": "invalid_request"})
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        approved = f"{proposal}\n\n## Approval\n- Approved at: {now}"
        digest = hashlib.sha256(approved.encode("utf-8")).digest()
        s256 = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        self.missions[s256] = {"approved": approved, "status": "active"}
        return JSONResponse(content={"mission": {"s256": s256, "approved": approved}})

    def _mm_jwks_fetcher(self, issuer_url: str, kid_param: Optional[str] = None):
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
                content={"error": "invalid_request", "error_description": "MM token endpoint expects resource_token"},
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
                    "error_description": "MM token requests require sig=jwt or sig=jwks_uri",
                },
            )

        def mm_jwks_fetcher(agent_id_param: str, kid_param: str = None):
            return self._mm_jwks_fetcher(agent_id_param, kid_param)

        verify_fetcher = agent_jwks_fetcher if scheme in ("jwks", "jwks_uri") else mm_jwks_fetcher

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

        if self.require_user_consent:
            return self._create_mm_pending(resource_token, agent_token_for_as, as_url, params_dict)

        resp = await self._forward_to_as(as_url, resource_token, agent_token_for_as)
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=dict(resp.headers),
            media_type=resp.headers.get("content-type", "application/json"),
        )

    def _create_mm_pending(
        self,
        resource_token: str,
        agent_token: Optional[str],
        as_url: str,
        params: Dict[str, Any],
    ) -> JSONResponse:
        pid = uuid.uuid4().hex[:12]
        code = uuid.uuid4().hex[:8].upper()
        loc = f"{self.mm_id}/pending/{pid}"
        self.pending_requests[pid] = {
            "resource_token": resource_token,
            "agent_token": agent_token or "",
            "as_url": as_url,
            "interaction_code": code,
            "status": "pending",
            "params": params,
        }
        body = build_pending_response_body(location=loc, require="interaction", code=code)
        hdrs = build_pending_response_headers(location=loc, retry_after=0, require="interaction", code=code)
        return JSONResponse(status_code=202, content=body, headers=hdrs)

    async def _forward_to_as(
        self, as_url: str, resource_token: str, agent_token: Optional[str] = None
    ) -> httpx.Response:
        token_url = f"{as_url.rstrip('/')}/token"
        body_obj: Dict[str, Any] = {"resource_token": resource_token}
        if agent_token:
            body_obj["agent_token"] = agent_token
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
                id=self.mm_id,
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
            return JSONResponse(status_code=404, content={"error": "not_found"})
        if p.get("status") == "approved" and p.get("auth_token"):
            return JSONResponse(content={"auth_token": p["auth_token"], "expires_in": 3600})
        if p.get("status") == "denied":
            return JSONResponse(status_code=403, content={"error": "denied"})
        loc = f"{self.mm_id}/pending/{pid}"
        body = build_pending_response_body(location=loc, require="interaction", code=p.get("interaction_code", ""))
        return JSONResponse(status_code=202, content=body, headers=build_pending_response_headers(loc, 2, "interaction", p.get("interaction_code", "")))

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
            f"<html><body><h1>MM Consent</h1><form method='post'><input name='consent' value='grant'/><button>Submit</button></form><p>code={code}</p></body></html>"
        )

    async def _handle_interact_post(self, request: Request) -> Response:
        form = await request.form()
        if form.get("consent") == "grant":
            for pid, p in list(self.pending_requests.items()):
                if p.get("status") == "pending":
                    at = p.get("agent_token") or None
                    fwd = await self._forward_to_as(p["as_url"], p["resource_token"], at or None)
                    if fwd.status_code == 200:
                        data = fwd.json()
                        p["auth_token"] = data.get("auth_token")
                        p["status"] = "approved"
                    break
        return HTMLResponse("<html><body>ok</body></html>")

    def run(self) -> None:
        """Run the Mission Manager (same pattern as ``Agent`` / ``Resource``)."""
        import uvicorn

        uvicorn.run(self.app, host="0.0.0.0", port=self.port)
