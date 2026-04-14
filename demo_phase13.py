"""Demo Phase 13: Direct Approval — requirement=approval polling without user redirect.

Per spec Section 4.5.6, the MM contacts the user via an out-of-band channel
(push notification, email, existing session) instead of asking the agent to
redirect the user.  The agent receives ``AAuth-Requirement: requirement=approval``
with no interaction URL or code and simply polls the pending URL.

Flow:
  Agent → Resource:  GET /data-auth (unsigned)
  Resource → Agent:  401 + resource token (AAuth-Requirement: requirement=auth-token)
  Agent → MM:        POST /token + resource_token (signed)
  MM → Agent:        202 Accepted + Location + AAuth-Requirement: requirement=approval
  [MM sends push notification to user — simulated by a background task]
  [User approves after ``approval_delay`` seconds]
  Agent → MM:        GET /pending/{pid}  (signed, Prefer: wait=15, repeated)
  MM → Agent:        200 OK + auth_token          (once approved)
  Agent → Resource:  GET /data-auth (auth token, scheme=jwks_uri)
  Resource → Agent:  200 OK

TEST 1: Full direct-approval happy path (MM auto-approves after 2 s).
TEST 2: Denied terminal state — MM auto-denies after 2 s; agent polls and
        receives 403; asserts auth_token is None.
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
from participants.auth_server import AccessServer
from participants.mission_manager import PersonServer
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
    print("Phase 13: Direct Approval (requirement=approval — no user redirect)", file=sys.stderr)
    print(
        "Spec: MM returns 202 + requirement=approval; agent polls only.\n"
        "MM contacts user out-of-band; user approves; agent gets auth token.",
        file=sys.stderr,
    )
    print("=" * 80 + "\n", file=sys.stderr)

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"
    ps_id = "http://127.0.0.1:8004"

    # PS configured for direct approval (simulates push/email approval after 2 s).
    agent = Agent(agent_id, port=8001, mm_url=ps_id)
    resource = Resource(resource_id, port=8002, auth_server=as_id)
    auth = AccessServer(as_id, port=8003, trusted_person_servers=[ps_id])
    ps = PersonServer(ps_id, port=8004, require_approval=True, approval_delay=2.0, approval_outcome="approve")

    start_uvicorn(agent.app, agent.port, "Agent")
    start_uvicorn(resource.app, resource.port, "Resource")
    start_uvicorn(auth.app, auth.port, "Access Server")
    start_uvicorn(ps.app, ps.port, "Person Server")

    print("Waiting for servers to start...", file=sys.stderr, flush=True)
    await asyncio.sleep(2)
    print_stderr_localhost_port_map(agent, resource, auth)

    try:
        # ------------------------------------------------------------------
        print("TEST 1: Direct approval — MM returns requirement=approval, agent polls", file=sys.stderr)

        response = await agent.request_resource(
            resource_url=f"{resource_id}/data-auth",
            method="GET",
            sig_scheme="jwks_uri",
        )
        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}: {response.text}"
        )
        data = response.json()
        assert data.get("token_type") == "aa-auth+jwt"

        # Inspect the resource token captured from the 401 challenge.
        rt = agent.resource_token
        assert rt, "Agent should have captured resource token from 401 challenge"
        rt_claims = parse_token_claims(rt)
        print("\n" + "=" * 80, file=sys.stderr)
        print("RESOURCE TOKEN (aa-resource+jwt) — captured from 401 challenge", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(rt_claims["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(rt_claims["payload"], indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        # Inspect the auth token the MM obtained via direct approval.
        auth_token = agent.auth_token
        assert auth_token, "Agent should have stored auth_token after polling"
        at_claims = parse_token_claims(auth_token)
        print("\n" + "=" * 80, file=sys.stderr)
        print("AUTH TOKEN (aa-auth+jwt) — obtained via direct approval polling", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(at_claims["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(at_claims["payload"], indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        assert at_claims["header"].get("typ") == "aa-auth+jwt"
        assert at_claims["payload"].get("iss") == as_id
        assert at_claims["payload"].get("aud") == resource_id
        assert at_claims["payload"].get("agent") == agent_id
        print("  ✓ TEST 1 PASSED: direct approval flow complete; resource returned 200", file=sys.stderr)
        print(f"  Response: {data}", file=sys.stderr)

        # ------------------------------------------------------------------
        print(
            "\nTEST 2: Denied terminal state — MM denies after 2 s; agent gets 403",
            file=sys.stderr,
        )

        # Start a second MM (port 8014) configured to deny, and a second agent (port 8011).
        ps2_id = "http://127.0.0.1:8014"
        agent2_id = "http://127.0.0.1:8011"

        ps2 = PersonServer(
            ps2_id, port=8014,
            require_approval=True,
            approval_delay=2.0,
            approval_outcome="deny",
        )
        agent2 = Agent(agent2_id, port=8011, mm_url=ps2_id)
        start_uvicorn(ps2.app, 8014, "Person Server 2 (deny)")
        start_uvicorn(agent2.app, 8011, "Agent 2")
        await asyncio.sleep(1)

        # Agent2 gets a resource token via the same resource (which uses AS on 8003).
        # Then sends it to MM2 which will deny — auth_token comes back as None.
        resource_token2 = await agent2.request_resource_token_proactively(resource_id, "data.read")
        assert resource_token2, "resource_token2 missing"

        auth_token2 = await agent2._request_auth_token(resource_token2, as_id)
        assert auth_token2 is None, (
            f"Expected None (denied), got token: {auth_token2}"
        )
        print("  ✓ TEST 2 PASSED: MM denied approval → agent received 403 → auth_token is None", file=sys.stderr)
        print(f"  (polling terminated with 403 denied after {ps2.approval_delay}s)", file=sys.stderr)

        print("\nPhase 13 direct approval demo complete.", file=sys.stderr)
    finally:
        await shutdown_uvicorn_servers()


if __name__ == "__main__":
    asyncio.run(main())
