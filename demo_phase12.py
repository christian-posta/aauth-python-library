"""Demo Phase 12: Mission Lifecycle — proposal → approval → token use → resource access.

Walks the complete mission lifecycle end-to-end:

1. Discover MM metadata (``/.well-known/aauth-mission.json``) to locate the
   ``mission_endpoint``.
2. Agent proposes a mission; MM auto-approves and returns the mission text + ``s256``.
3. Agent proactively obtains a resource token from the resource's
   ``authorization_endpoint`` (``POST /authorize``) including the ``AAuth-Mission``
   header — the resource token carries the mission claim.
4. Agent sends the resource token to the MM's ``token_endpoint``; MM federates with
   the AS and returns an auth token — the auth token also carries the mission claim.
5. Agent presents the auth token to the resource (``scheme=jwt``) and gets 200.

The ``mission.s256`` hash is verified at every step to confirm it is preserved
across the full token chain: mission → resource token → auth token → resource.
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
from participants.auth_server import AuthServer
from participants.mission_manager import MissionManager
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
    print("Phase 12: Mission Lifecycle (proposal → approval → token chain → access)", file=sys.stderr)
    print(
        "Spec: Agent proposes mission at MM mission_endpoint; mission.s256 flows\n"
        "through resource token → auth token → resource response.",
        file=sys.stderr,
    )
    print("=" * 80 + "\n", file=sys.stderr)

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"
    mm_id = "http://127.0.0.1:8004"

    agent = Agent(agent_id, port=8001, mm_url=mm_id)
    resource = Resource(resource_id, port=8002, auth_server=as_id)
    auth = AuthServer(as_id, port=8003, trusted_mission_managers=[mm_id])
    mm = MissionManager(mm_id, port=8004)

    start_uvicorn(agent.app, agent.port, "Agent")
    start_uvicorn(resource.app, resource.port, "Resource")
    start_uvicorn(auth.app, auth.port, "Auth Server")
    start_uvicorn(mm.app, mm.port, "Mission Manager")

    print("Waiting for servers to start...", file=sys.stderr, flush=True)
    await asyncio.sleep(2)
    print_stderr_localhost_port_map(agent, resource, auth)

    try:
        # ------------------------------------------------------------------
        print("TEST 1: Discover MM metadata and propose mission", file=sys.stderr)

        async with httpx.AsyncClient() as client:
            mm_meta_resp = await client.get(f"{mm_id}/.well-known/aauth-mission.json")
        assert mm_meta_resp.status_code == 200, f"MM metadata fetch failed: {mm_meta_resp.status_code}"
        mm_meta = mm_meta_resp.json()
        mission_endpoint = mm_meta.get("mission_endpoint")
        assert mission_endpoint, "MM metadata missing mission_endpoint"
        print(f"  MM metadata: mission_endpoint = {mission_endpoint}", file=sys.stderr)

        mission = await agent.propose_mission(
            "Analyze customer feedback for Q4 reporting and produce a summary."
        )
        assert mission and mission.get("s256"), "Mission proposal failed"
        s256 = mission["s256"]
        print(f"  Mission approved: s256 = {s256[:24]}...", file=sys.stderr)
        print("  ✓ TEST 1 PASSED: mission_endpoint discovered; mission approved with s256", file=sys.stderr)

        # ------------------------------------------------------------------
        print("\nTEST 2: Proactive resource token carries mission.s256", file=sys.stderr)

        resource_token = await agent.request_resource_token_proactively(resource_id, "data.read")
        assert resource_token, "resource_token missing"

        rt_claims = parse_token_claims(resource_token)
        assert rt_claims["header"].get("typ") == "aa-resource+jwt"
        rt_payload = rt_claims["payload"]
        rt_mission = rt_payload.get("mission") or {}
        assert rt_mission.get("s256") == s256, (
            f"resource token mission.s256 mismatch: {rt_mission.get('s256')!r} != {s256!r}"
        )
        assert rt_mission.get("manager") == mm_id

        print("\n" + "=" * 80, file=sys.stderr)
        print("RESOURCE TOKEN (aa-resource+jwt) — decoded", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(rt_claims["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(rt_payload, indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print(
            f"  ✓ TEST 2 PASSED: resource token mission.s256 matches approved mission",
            file=sys.stderr,
        )

        # ------------------------------------------------------------------
        print(
            "\nTEST 3: Auth token (via MM→AS federation) carries mission.s256",
            file=sys.stderr,
        )

        auth_token = await agent._request_auth_token(resource_token, as_id)
        assert auth_token, "auth_token missing"

        at_claims = parse_token_claims(auth_token)
        assert at_claims["header"].get("typ") == "aa-auth+jwt"
        at_payload = at_claims["payload"]
        at_mission = at_payload.get("mission") or {}
        assert at_mission.get("s256") == s256, (
            f"auth token mission.s256 mismatch: {at_mission.get('s256')!r} != {s256!r}"
        )
        assert at_payload.get("iss") == as_id
        assert at_payload.get("aud") == resource_id
        assert at_payload.get("agent") == agent_id

        print("\n" + "=" * 80, file=sys.stderr)
        print("AUTH TOKEN (aa-auth+jwt) — decoded", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(at_claims["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(at_payload, indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print(
            f"  ✓ TEST 3 PASSED: auth token mission.s256 preserved through MM→AS federation",
            file=sys.stderr,
        )

        # ------------------------------------------------------------------
        print("\nTEST 4: Resource access with mission-bearing auth token", file=sys.stderr)

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
        print("  ✓ TEST 4 PASSED: Resource granted access with mission-bearing auth token", file=sys.stderr)
        print(f"  Response: {data}", file=sys.stderr)

        print(
            f"\n  mission.s256 verified at every step: mission → resource token → auth token → access",
            file=sys.stderr,
        )
        print(f"  s256 = {s256}", file=sys.stderr)
        print("\nPhase 12 mission lifecycle demo complete.", file=sys.stderr)
    finally:
        await shutdown_uvicorn_servers()


if __name__ == "__main__":
    asyncio.run(main())
