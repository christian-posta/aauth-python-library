“””Demo Phase 5: Missions — PS approval, AAuth-Mission, mission in resource token.

Replaces the older “agent-as-resource” Phase 5 demo. For self-access / scope-only
tokens see PHASE5-agent-is-resource.md and ``Agent.request_self_authorization``.
“””

import asyncio
import json
import sys
import threading
from typing import List

import jwt
from uvicorn import Config, Server

from participants.agent import Agent
from participants.auth_server import AccessServer
from participants.mission_manager import PersonServer
from participants.resource import Resource

# Filled by ``start_uvicorn`` threads; used for graceful shutdown.
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


async def main():
    _uvicorn_servers.clear()
    _server_threads.clear()

    print("\n" + "=" * 80, file=sys.stderr)
    print("Phase 5: Missions (PS + resource + AS)", file=sys.stderr)
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

    try:
        # Test 1: mission proposal
        print("TEST 1: Mission proposal → MM returns s256", file=sys.stderr)
        m = await agent.propose_mission("Analyze customer feedback for Q2 reporting.")
        assert m and m.get("s256")
        print(f"  ✓ s256 = {m['s256'][:32]}...", file=sys.stderr)

        # Test 2: proactive resource token includes mission
        print("\nTEST 2: POST /authorize with AAuth-Mission → mission in JWT", file=sys.stderr)
        rt = await agent.request_resource_token_proactively(resource_id, "data.read")
        assert rt
        hdr = jwt.get_unverified_header(rt)
        payload = jwt.decode(rt, options={"verify_signature": False})
        assert hdr.get("typ") == "aa-resource+jwt"
        miss = payload.get("mission")
        assert miss and miss.get("approver") and miss.get("s256")
        print(f"  ✓ mission claim: {json.dumps(miss)}", file=sys.stderr)

        print("\nPhase 5 missions demo complete.", file=sys.stderr)
    finally:
        await shutdown_uvicorn_servers()


if __name__ == "__main__":
    asyncio.run(main())
