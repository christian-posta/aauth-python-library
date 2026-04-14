"""Demo Phase 11: PS–AS Trust — federated token path via Person Server.

The agent is configured with ``mm_url`` so its auth token requests go to the PS's
``token_endpoint`` instead of the AS directly.  The PS verifies the resource token,
then calls the AS using its own HTTP Message Signature (``scheme=jwks_uri``).  The AS
trusts the PS (``trusted_person_servers``) and issues an auth token.  The agent
never speaks to the AS directly.

TEST 2 shows the contrast: an identical agent WITHOUT ``mm_url`` calls the AS
directly — the AS grants it too, but the signing path (and audit trail) differs.
"""

import asyncio
import json
import sys
import threading
from typing import List

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
    print("Phase 11: PS–AS Trust (federated token path via Person Server)", file=sys.stderr)
    print(
        "Spec: Agent sends resource token to PS token_endpoint; PS signs request\n"
        "with its own key (scheme=jwks_uri); AS verifies PS identity and issues auth token.",
        file=sys.stderr,
    )
    print("=" * 80 + "\n", file=sys.stderr)

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"
    ps_id = "http://127.0.0.1:8004"

    # Agent WITH mm_url — all auth token requests go through the PS.
    agent = Agent(agent_id, port=8001, mm_url=ps_id)
    resource = Resource(resource_id, port=8002, auth_server=as_id)
    auth = AccessServer(as_id, port=8003, trusted_person_servers=[ps_id])
    ps = PersonServer(ps_id, port=8004)

    start_uvicorn(agent.app, agent.port, "Agent")
    start_uvicorn(resource.app, resource.port, "Resource")
    start_uvicorn(auth.app, auth.port, "Access Server")
    start_uvicorn(ps.app, ps.port, "Person Server")

    print("Waiting for servers to start...", file=sys.stderr, flush=True)
    await asyncio.sleep(2)
    print_stderr_localhost_port_map(agent, resource, auth)

    try:
        # ------------------------------------------------------------------
        print(
            "TEST 1: Reactive PS-federated flow — 401 challenge → PS → AS → auth token",
            file=sys.stderr,
        )

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

        # Display the resource token the agent captured from the 401 challenge.
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

        # Display the auth token the MM obtained from the AS.
        auth_token = agent.auth_token
        assert auth_token, "Agent should have stored auth_token"
        at_claims = parse_token_claims(auth_token)
        print("\n" + "=" * 80, file=sys.stderr)
        print("AUTH TOKEN (aa-auth+jwt) — issued by AS via PS federation", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(at_claims["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(at_claims["payload"], indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        # Verify token chain
        assert at_claims["header"].get("typ") == "aa-auth+jwt"
        assert at_claims["payload"].get("iss") == as_id
        assert at_claims["payload"].get("aud") == resource_id
        assert at_claims["payload"].get("agent") == agent_id
        print("  ✓ TEST 1 PASSED: PS-federated auth token obtained; resource returned 200", file=sys.stderr)
        print(f"  Final response: {data}", file=sys.stderr)

        # ------------------------------------------------------------------
        print(
            "\nTEST 2: Direct flow (no MM) — same resource, agent calls AS directly",
            file=sys.stderr,
        )

        # Start a second agent (port 8011) without mm_url — calls AS directly.
        agent2_id = "http://127.0.0.1:8011"
        agent2 = Agent(agent2_id, port=8011)  # no mm_url
        start_uvicorn(agent2.app, agent2.port, "Agent2")
        await asyncio.sleep(1)

        response2 = await agent2.request_resource(
            resource_url=f"{resource_id}/data-auth",
            method="GET",
            sig_scheme="jwks_uri",
        )
        assert response2.status_code == 200, (
            f"Expected 200, got {response2.status_code}: {response2.text}"
        )

        auth_token2 = agent2.auth_token
        assert auth_token2, "Agent2 should have stored auth_token"
        at2_claims = parse_token_claims(auth_token2)
        print("\n" + "=" * 80, file=sys.stderr)
        print("AUTH TOKEN 2 (aa-auth+jwt) — issued directly by AS (no MM)", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(at2_claims["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(at2_claims["payload"], indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        # Both paths produce valid aa-auth+jwt from the same AS.
        assert at2_claims["header"].get("typ") == "aa-auth+jwt"
        assert at2_claims["payload"].get("iss") == as_id
        assert at2_claims["payload"].get("aud") == resource_id
        assert at2_claims["payload"].get("agent") == agent2_id
        print("  ✓ TEST 2 PASSED: Direct AS path also works; same AS issued both tokens", file=sys.stderr)
        print(f"  PS-federated iss: {at_claims['payload']['iss']}  (via PS → AS)", file=sys.stderr)
        print(f"  Direct AS iss:    {at2_claims['payload']['iss']}  (agent → AS)", file=sys.stderr)

        print("\nPhase 11 PS–AS trust demo complete.", file=sys.stderr)
    finally:
        await shutdown_uvicorn_servers()


if __name__ == "__main__":
    asyncio.run(main())
