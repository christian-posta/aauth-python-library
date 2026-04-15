"""Demo Phase 12: Mission Lifecycle — proposal → approval → token use → resource access.

Walks the complete mission lifecycle end-to-end (SPEC.md: Mission, Mission Approval,
PS token endpoint, PS–AS federation):

1. Discover Person Server metadata (``/.well-known/aauth-person.json``) for
   ``mission_endpoint`` and ``token_endpoint``.
2. Agent ``POST``s a mission proposal; PS returns the **mission blob** body and
   ``AAuth-Mission`` response header (``approver``, ``s256``); ``s256`` hashes the
   exact response body bytes.
3. Agent proactively obtains a resource token (``POST /authorize``) with
   ``AAuth-Mission`` request header; HTTPSig uses ``scheme=jwt`` (agent token), per
   authorization-endpoint mission examples.
4. Agent ``POST``s ``resource_token`` to the PS ``token_endpoint`` (not the AS
   directly); PS federates to the AS and returns an auth token bearing ``mission``.
5. Agent accesses ``GET /data-auth`` with the auth token (``scheme=jwt``).

The demo asserts ``mission.s256`` matches the approved mission through: resource
token, auth token, and the auth token presented for resource access.
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
    print("Phase 12: Mission Lifecycle (proposal → approval → token chain → access)", file=sys.stderr)
    print(
        "Spec: Agent proposes mission at PS mission_endpoint; mission.s256 flows\n"
        "through resource token → auth token → resource response.",
        file=sys.stderr,
    )
    print("=" * 80 + "\n", file=sys.stderr)

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"
    ps_id = "http://127.0.0.1:8004"

    agent = Agent(agent_id, port=8001, ps_url=ps_id)
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
        print("TEST 1: Discover PS metadata and propose mission", file=sys.stderr)

        async with httpx.AsyncClient() as client:
            ps_meta_resp = await client.get(f"{ps_id}/.well-known/aauth-person.json")
        assert ps_meta_resp.status_code == 200, f"PS metadata fetch failed: {ps_meta_resp.status_code}"
        ps_meta = ps_meta_resp.json()
        mission_endpoint = ps_meta.get("mission_endpoint")
        assert mission_endpoint, "PS metadata missing mission_endpoint"
        print(f"  PS metadata: mission_endpoint = {mission_endpoint}", file=sys.stderr)

        mission = await agent.propose_mission(
            "Analyze customer feedback for Q4 reporting and produce a summary."
        )
        assert mission and mission.get("s256"), "Mission proposal failed"
        s256 = mission["s256"]
        print(f"  Mission approved: s256 = {s256[:24]}...", file=sys.stderr)
        print("  ✓ TEST 1 PASSED: PS mission_endpoint discovered; mission approved with s256", file=sys.stderr)

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
        assert rt_mission.get("approver") == ps_id

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
            "\nTEST 3: Auth token (via PS→AS federation) carries mission.s256",
            file=sys.stderr,
        )

        # Normative flow: agent → PS token_endpoint; PS federates to AS (aud on resource token).
        # Second argument is only used when no PS is configured; pass PS id for clarity.
        auth_token = await agent._request_auth_token(resource_token, ps_id)
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
        # Auth token `agent` is the agent identifier (aauth:local@domain), not the HTTP iss URL.
        assert at_payload.get("agent") == agent.agent_sub

        print("\n" + "=" * 80, file=sys.stderr)
        print("AUTH TOKEN (aa-auth+jwt) — decoded", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(at_claims["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(at_payload, indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print(
            f"  ✓ TEST 3 PASSED: auth token mission.s256 preserved through PS→AS federation",
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
        # Same JWT the resource verified — mission.s256 must still match approved mission.
        assert agent.auth_token, "agent should hold auth token after access"
        access_claims = parse_token_claims(agent.auth_token)
        access_mission = access_claims["payload"].get("mission") or {}
        assert access_mission.get("s256") == s256, (
            f"resource access auth token mission.s256 mismatch: "
            f"{access_mission.get('s256')!r} != {s256!r}"
        )
        print("  ✓ TEST 4 PASSED: Resource granted access; auth token mission.s256 matches", file=sys.stderr)
        print(f"  Response: {data}", file=sys.stderr)

        print(
            f"\n  mission.s256 verified at every step: mission → resource token → auth token → access",
            file=sys.stderr,
        )
        print(f"  s256 = {s256}", file=sys.stderr)
        print("\nPhase 12 PS mission lifecycle demo complete.", file=sys.stderr)
    finally:
        await shutdown_uvicorn_servers()


if __name__ == "__main__":
    asyncio.run(main())
