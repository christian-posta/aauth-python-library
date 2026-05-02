"""AAuth PS token exchange for three-party mode (SPEC §4.1.3)."""

import json
import httpx
import jwt as _jwt
from typing import Awaitable, Callable, Dict, Optional, Mapping

from ..errors import TokenError, MetadataError
from ..signing.signer import sign_request
from ..metadata.mission_manager import fetch_ps_metadata_async
from .poller import async_poll_pending_url


def extract_resource_token(headers: Mapping[str, str]) -> Optional[str]:
    """Extract resource_token from an AAuth 401 challenge response.

    Parses the AAuth-Requirement header to find the resource-token parameter
    per SPEC §6. If not found or header is missing, returns None.

    Args:
        headers: HTTP response headers (dict-like, case-insensitive access).

    Returns:
        resource_token JWT string if present, else None.
    """
    from ..headers.aauth_header import get_challenge_header_value, parse_aauth_header

    raw = get_challenge_header_value(headers)
    if not raw:
        return None
    try:
        parsed = parse_aauth_header(raw)
        return parsed.get("resource_token")
    except Exception:
        return None


async def exchange_resource_token(
    resource_token: str,
    private_key,
    agent_jwt: str,
    *,
    ps_discovery_timeout: float = 10.0,
    exchange_timeout: float = 30.0,
    on_interaction: Optional[Callable[[str, str], Awaitable[None]]] = None,
    on_clarification: Optional[Callable[[str, str], Awaitable[Optional[str]]]] = None,
    max_polls: int = 60,
) -> str:
    """Exchange a resource_token for an auth_token via the PS (SPEC §4.1.3).

    Three-party token exchange flow:
      1. Decode resource_token to get PS URL from ``aud`` claim.
      2. Discover PS token_endpoint via /.well-known/aauth-person.json
         (falls back to {aud}/token if metadata fetch fails).
      3. POST {resource_token} to PS, signed with aa-agent+jwt.
      4a. 200 → return auth_token directly.
      4b. 202 → poll the Location URL until a terminal response, honouring
          any interaction or clarification callbacks, then return auth_token.

    Args:
        resource_token: The resource token JWT from the 401 AAuth challenge.
        private_key: Agent's Ed25519 private key for request signing.
        agent_jwt: Agent token (aa-agent+jwt) for Signature-Key header.
        ps_discovery_timeout: Timeout in seconds for PS metadata fetch.
        exchange_timeout: Timeout in seconds for individual HTTP requests.
        on_interaction: Async callback invoked when the PS requires human
            interaction. Called with ``(pending_url, code)`` on the first
            poll that returns ``requirement=interaction``. The app should
            surface the URL and code to the user (e.g. via SSE).
        on_clarification: Async callback invoked when the PS asks a
            clarification question. Called with ``(pending_url, question)``
            and should return the user's answer string, or None to skip.
        max_polls: Maximum polling attempts before giving up (default 60).

    Returns:
        auth_token string (aa-auth+jwt) returned by the PS.

    Raises:
        TokenError: resource_token is malformed, PS returns a non-recoverable
                    error, or polling is exhausted/denied.
        MetadataError: PS metadata fetch encounters a hard error
                       (non-timeout, non-404 failures).
    """
    # Step 1: Decode resource_token to get PS URL from aud claim
    try:
        claims = _jwt.decode(resource_token, options={"verify_signature": False})
    except Exception as exc:
        raise TokenError(
            f"Cannot decode resource_token JWT: {exc}",
            token_type="aa-resource+jwt",
        )

    aud = claims.get("aud")
    if not aud:
        raise TokenError(
            "resource_token missing 'aud' claim — cannot locate PS",
            token_type="aa-resource+jwt",
        )

    # Step 2: Discover PS token_endpoint from metadata
    ps_base = aud.rstrip("/")
    token_endpoint = f"{ps_base}/token"  # fallback

    try:
        meta = await fetch_ps_metadata_async(ps_base, timeout=ps_discovery_timeout)
        discovered = meta.get("token_endpoint")
        if discovered:
            token_endpoint = discovered
    except Exception:
        # Metadata fetch failed — use default fallback endpoint
        pass

    # Step 3: Sign and POST resource_token to PS
    body = json.dumps({"resource_token": resource_token}, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json"}

    sig_headers = sign_request(
        method="POST",
        target_uri=token_endpoint,
        headers=headers,
        body=None,
        private_key=private_key,
        sig_scheme="jwt",
        jwt=agent_jwt,
    )
    headers.update(sig_headers)

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(exchange_timeout)
        ) as http_client:
            resp = await http_client.post(token_endpoint, headers=headers, content=body)
    except Exception as exc:
        raise TokenError(
            f"PS token_endpoint request failed: {exc}",
            token_type="aa-auth+jwt",
        )

    # Step 4a: Immediate success
    if resp.status_code == 200:
        try:
            data = resp.json()
        except Exception as exc:
            raise TokenError(
                f"PS response is not valid JSON: {exc}",
                token_type="aa-auth+jwt",
            )
        auth_token = data.get("auth_token")
        if not auth_token:
            raise TokenError(
                f"PS response missing 'auth_token'; response keys: {list(data.keys())}",
                token_type="aa-auth+jwt",
            )
        return auth_token

    # Step 4b: Deferred — PS needs human interaction or approval before issuing token
    if resp.status_code == 202:
        location = resp.headers.get("location") or resp.headers.get("Location")
        if not location:
            raise TokenError(
                "PS returned 202 but no Location header — cannot poll",
                token_type="aa-auth+jwt",
            )

        # Build async signing closures so the poller can make authenticated requests
        async def _signed_get(url: str):
            sig_hdrs = sign_request(
                method="GET",
                target_uri=url,
                headers={},
                body=None,
                private_key=private_key,
                sig_scheme="jwt",
                jwt=agent_jwt,
            )
            async with httpx.AsyncClient(timeout=httpx.Timeout(exchange_timeout)) as c:
                return await c.get(url, headers=sig_hdrs)

        async def _signed_post(url: str, body_dict: Dict):
            post_body = json.dumps(body_dict, separators=(",", ":")).encode()
            post_headers = {"Content-Type": "application/json"}
            sig_hdrs = sign_request(
                method="POST",
                target_uri=url,
                headers=post_headers,
                body=None,
                private_key=private_key,
                sig_scheme="jwt",
                jwt=agent_jwt,
            )
            post_headers.update(sig_hdrs)
            async with httpx.AsyncClient(timeout=httpx.Timeout(exchange_timeout)) as c:
                return await c.post(url, headers=post_headers, content=post_body)

        result = await async_poll_pending_url(
            pending_url=location,
            sign_and_send_get=_signed_get,
            max_polls=max_polls,
            on_interaction=on_interaction,
            on_clarification=on_clarification,
            sign_and_send_post=_signed_post if on_clarification else None,
        )

        if not result.success:
            raise TokenError(
                f"PS deferred exchange failed: {result.error} — {result.error_description}",
                token_type="aa-auth+jwt",
            )
        if not result.auth_token:
            raise TokenError(
                "PS polling succeeded but response missing 'auth_token'",
                token_type="aa-auth+jwt",
            )
        return result.auth_token

    raise TokenError(
        f"PS token_endpoint returned HTTP {resp.status_code}: {resp.text[:500]}",
        token_type="aa-auth+jwt",
    )
