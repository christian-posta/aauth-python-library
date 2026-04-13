"""Demo Phase 6: Agent delegation — delegate ``aa-agent+jwt``, resource identity, AS token.

The delegate obtains an agent token from the agent server (``POST /delegate/token``),
uses ``scheme=jwt`` for HTTP message signatures, obtains a resource token at
``POST /resource/token`` (JSON body; supports ``sig=jwt`` with ``aa-agent+jwt``), then
requests an auth token at the AS ``POST /token``. The auth token ``agent`` claim uses the
``local@domain`` identifier format (e.g. ``delegate-1@127.0.0.1:8001``) per the AAuth spec
Section 12.1. There is no ``agent_delegate`` claim — the delegate IS the agent.
"""

import asyncio
import json
import sys
import threading
from typing import List

import httpx
from uvicorn import Config, Server

from aauth.debug import print_stderr_localhost_port_map
from aauth.tokens.auth_token import parse_token_claims
from participants.agent import Agent
from participants.agent_delegate import AgentDelegate
from participants.auth_server import AuthServer
from participants.resource import Resource

_uvicorn_servers: List[Server] = []
_server_threads: List[threading.Thread] = []


def start_uvicorn(app, port: int, name: str) -> None:
    """Run uvicorn in a daemon thread and keep a ``Server`` handle for ``should_exit``."""

    def target() -> None:
        print(f"Starting {name}...", file=sys.stderr, flush=True)
        try:
            config = Config(app, host="0.0.0.0", port=port, log_level="error")
            server = Server(config=config)
            _uvicorn_servers.append(server)
            server.run()
        except Exception as e:
            print(f"{name} error: {e}", file=sys.stderr, flush=True)

    t = threading.Thread(target=target, daemon=True, name=name)
    _server_threads.append(t)
    t.start()


async def shutdown_uvicorn_servers() -> None:
    """Signal all demo servers to exit and wait for threads to finish."""
    if not _uvicorn_servers:
        return
    print("Shutting down servers...", file=sys.stderr, flush=True)
    for s in list(_uvicorn_servers):
        s.should_exit = True
    await asyncio.sleep(2.0)
    for t in _server_threads:
        t.join(timeout=15.0)
    _uvicorn_servers.clear()
    _server_threads.clear()
    print("Done.", file=sys.stderr, flush=True)


async def main() -> None:
    _uvicorn_servers.clear()
    _server_threads.clear()

    print("\n" + "=" * 80, file=sys.stderr)
    print("Phase 6: Agent delegation (delegate token + resource + AS)", file=sys.stderr)
    print(
        "Spec: agent server issues aa-agent+jwt binding cnf.jwk to delegate; delegate "
        "presents it via Signature-Key scheme=jwt.",
        file=sys.stderr,
    )
    print("=" * 80 + "\n", file=sys.stderr)

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"
    delegate_sub = "delegate-1"

    agent = Agent(agent_id, port=8001, use_user_simulator=False)
    delegate = AgentDelegate(agent_id, delegate_sub, port=None)
    resource = Resource(resource_id, port=8002, auth_server=as_id)
    auth = AuthServer(as_id, port=8003, require_user_consent=False)

    start_uvicorn(agent.app, agent.port, "Agent")
    start_uvicorn(resource.app, resource.port, "Resource")
    start_uvicorn(auth.app, auth.port, "Auth Server")

    print("Waiting for servers to start...", file=sys.stderr, flush=True)
    await asyncio.sleep(2)
    print_stderr_localhost_port_map(agent, resource, auth)

    try:
        print("TEST 1: Delegate obtains agent token from agent server", file=sys.stderr)
        agent_token = await delegate.request_agent_token()
        assert agent_token, "agent token missing"
        claims = parse_token_claims(agent_token)
        assert claims["header"].get("typ") == "aa-agent+jwt"
        assert claims["payload"].get("iss") == agent_id
        assert claims["payload"].get("sub") == delegate_sub
        assert (claims["payload"].get("cnf") or {}).get("jwk")
        print("\n" + "=" * 80, file=sys.stderr)
        print("AGENT TOKEN (aa-agent+jwt) — decoded", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(claims["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(claims["payload"], indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("  ✓ aa-agent+jwt claims OK", file=sys.stderr)

        print("\nTEST 2: Delegate GET /data-jwks with agent token (identity)", file=sys.stderr)
        r2 = await delegate.request_resource(f"{resource_id}/data-jwks")
        assert r2.status_code == 200, r2.text
        data2 = r2.json()
        assert data2.get("token_type") == "aa-agent+jwt"
        print(f"  ✓ resource response: token_type=aa-agent+jwt", file=sys.stderr)

        print("\nTEST 3: Resource token + auth token (JSON POST /token)", file=sys.stderr)
        rt_json = json.dumps({"scope": "data.read"})
        rt_body = rt_json.encode("utf-8")
        rt_headers = {"Content-Type": "application/json"}
        rt_sig = delegate.sign_request(
            "POST",
            f"{resource_id}/resource/token",
            rt_headers,
            rt_body,
        )
        async with httpx.AsyncClient() as client:
            rt_resp = await client.post(
                f"{resource_id}/resource/token",
                headers={**rt_headers, **rt_sig},
                content=rt_body,
            )
        assert rt_resp.status_code == 200, rt_resp.text
        resource_token = rt_resp.json().get("resource_token")
        assert resource_token
        rt_claims = parse_token_claims(resource_token)
        print("\n" + "=" * 80, file=sys.stderr)
        print("RESOURCE TOKEN (aa-resource+jwt) — decoded", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(rt_claims["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(rt_claims["payload"], indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        token_json = json.dumps({"resource_token": resource_token})
        token_body = token_json.encode("utf-8")
        tok_headers = {"Content-Type": "application/json"}
        tok_sig = delegate.sign_request(
            "POST",
            f"{as_id}/token",
            tok_headers,
            token_body,
        )
        async with httpx.AsyncClient() as client:
            auth_resp = await client.post(
                f"{as_id}/token",
                headers={**tok_headers, **tok_sig},
                content=token_body,
            )
        assert auth_resp.status_code == 200, auth_resp.text
        auth_token = auth_resp.json().get("auth_token")
        assert auth_token
        auth_claims = parse_token_claims(auth_token)
        auth_payload = auth_claims["payload"]
        print("\n" + "=" * 80, file=sys.stderr)
        print("AUTH TOKEN (aa-auth+jwt) — decoded", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(auth_claims["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(auth_payload, indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        # Per spec: agent identifier is local@domain derived from agent token iss/sub
        from urllib.parse import urlparse
        _domain = urlparse(agent_id).netloc
        expected_agent = f"{delegate_sub}@{_domain}"
        assert auth_payload.get("agent") == expected_agent, (
            f"Expected agent={expected_agent!r}, got {auth_payload.get('agent')!r}"
        )
        assert "data.read" in (auth_payload.get("scope") or "")
        print(
            f"  ✓ auth token: agent={expected_agent}, scope=data.read (aa-auth+jwt payload OK)",
            file=sys.stderr,
        )

        print("\nPhase 6 delegation demo complete.", file=sys.stderr)
    finally:
        await shutdown_uvicorn_servers()


if __name__ == "__main__":
    asyncio.run(main())
