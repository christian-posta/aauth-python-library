"""Demo Phase 10: Proactive Resource Authorization — POST /authorize + AAuth-Mission.

The agent proposes a mission to its MM (which auto-approves in this demo), then
proactively obtains a resource token from the resource's ``authorization_endpoint``
(``POST /authorize``) by including an ``AAuth-Mission`` header.  The agent then sends
the resource token to the MM's ``token_endpoint``; the MM federates with the resource's
AS and returns an auth token.  The agent presents the auth token to access the resource.

Key spec references:
- Resource authorization endpoint: AAuth spec Section 8 (Resource Token Issuance)
- AAuth-Mission header: AAuth spec Section 7 (Missions)
- MM token endpoint / MM→AS federation: AAuth spec Section 10 (Authorization)
"""

import asyncio
import json
import sys
import threading
from typing import List

import jwt as jwt_lib
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
    print("Phase 10: Proactive Resource Authorization (POST /authorize + AAuth-Mission)", file=sys.stderr)
    print(
        "Spec: Agent proposes mission → PS approves; agent POSTs /authorize with\n"
        "AAuth-Mission to get resource token; PS federates with AS to get auth token.",
        file=sys.stderr,
    )
    print("=" * 80 + "\n", file=sys.stderr)

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"
    ps_id = "http://127.0.0.1:8004"

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
        print("TEST 1: Mission proposal → resource token with mission claim", file=sys.stderr)

        mission = await agent.propose_mission("Read user data for analytics (Phase 10 demo).")
        assert mission and mission.get("s256"), "Mission proposal failed"
        print(f"  Mission approved: s256={mission['s256'][:24]}...", file=sys.stderr)

        resource_token = await agent.request_resource_token_proactively(resource_id, "data.read")
        assert resource_token, "resource_token missing"

        rt_claims = parse_token_claims(resource_token)
        assert rt_claims["header"].get("typ") == "aa-resource+jwt"
        rt_payload = rt_claims["payload"]
        assert rt_payload.get("mission"), "resource token missing mission claim"
        assert rt_payload["mission"].get("s256") == mission["s256"], "mission s256 mismatch"

        print("\n" + "=" * 80, file=sys.stderr)
        print("RESOURCE TOKEN (aa-resource+jwt) — decoded", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(rt_claims["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(rt_payload, indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print(
            f"  ✓ TEST 1 PASSED: resource token typ=aa-resource+jwt, mission.s256 matches",
            file=sys.stderr,
        )

        # ------------------------------------------------------------------
        print(
            "\nTEST 2: PS→AS federation — resource token → auth token with mission claim",
            file=sys.stderr,
        )

        auth_token = await agent._request_auth_token(resource_token, as_id)
        assert auth_token, "auth_token missing"

        auth_claims = parse_token_claims(auth_token)
        assert auth_claims["header"].get("typ") == "aa-auth+jwt"
        auth_payload = auth_claims["payload"]
        assert auth_payload.get("mission"), "auth token missing mission claim"
        assert auth_payload["mission"].get("s256") == mission["s256"], "auth token mission s256 mismatch"

        print("\n" + "=" * 80, file=sys.stderr)
        print("AUTH TOKEN (aa-auth+jwt) — decoded", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(auth_claims["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(auth_payload, indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print(
            f"  ✓ TEST 2 PASSED: auth token typ=aa-auth+jwt, mission.s256 preserved through PS→AS",
            file=sys.stderr,
        )

        # ------------------------------------------------------------------
        print("\nTEST 3: Access resource with auth token (scheme=jwt)", file=sys.stderr)

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
        print("  ✓ TEST 3 PASSED: Resource access granted with auth token", file=sys.stderr)
        print(f"  Response: {data}", file=sys.stderr)

        print("\nPhase 10 proactive authorization demo complete.", file=sys.stderr)
    finally:
        await shutdown_uvicorn_servers()


if __name__ == "__main__":
    asyncio.run(main())
