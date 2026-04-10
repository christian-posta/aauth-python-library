"""Demo Phase 10: Resource authorization endpoint (proactive resource tokens).

Exercises ``POST /authorize`` with JSON ``{"scope": ...}`` and optional
``AAuth-Mission`` after mission approval. Requires resource metadata to list
``authorization_endpoint`` (see ``/.well-known/aauth-resource``).
"""

import asyncio
import threading

import httpx
import uvicorn

from participants.agent import Agent
from participants.auth_server import AuthServer
from participants.mission_manager import MissionManager
from participants.resource import Resource


async def run_phase10_demo():
    print("=" * 60)
    print("Phase 10 Demo: Resource authorization endpoint")
    print("=" * 60)

    agent_id = "http://127.0.0.1:8011"
    resource_id = "http://127.0.0.1:8012"
    as_id = "http://127.0.0.1:8013"
    mm_id = "http://127.0.0.1:8014"

    agent = Agent(agent_id, port=8011, mm_url=mm_id)
    resource = Resource(resource_id, port=8012, auth_server=as_id)
    auth = AuthServer(as_id, port=8013, trusted_mission_managers=[mm_id])
    mm = MissionManager(mm_id, port=8014)

    threads = [
        threading.Thread(
            target=lambda: uvicorn.run(agent.app, host="0.0.0.0", port=8011, log_level="error"),
            daemon=True,
        ),
        threading.Thread(
            target=lambda: uvicorn.run(resource.app, host="0.0.0.0", port=8012, log_level="error"),
            daemon=True,
        ),
        threading.Thread(
            target=lambda: uvicorn.run(auth.app, host="0.0.0.0", port=8013, log_level="error"),
            daemon=True,
        ),
        threading.Thread(
            target=lambda: uvicorn.run(mm.app, host="0.0.0.0", port=8014, log_level="error"),
            daemon=True,
        ),
    ]
    for t in threads:
        t.start()
    await asyncio.sleep(2)

    print("\n1. Fetch resource metadata (authorization_endpoint)...")
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{resource_id}/.well-known/aauth-resource")
        md = r.json()
        assert "authorization_endpoint" in md
        print(f"   authorization_endpoint = {md['authorization_endpoint']}")

    print("\n2. Propose mission to MM...")
    m = await agent.propose_mission("Read user data for analytics (demo).")
    assert m
    print(f"   mission s256 = {m['s256'][:16]}...")

    print("\n3. POST /authorize with AAuth-Mission (proactive resource token)...")
    tok = await agent.request_resource_token_proactively(resource_id, "data.read")
    assert tok
    print(f"   resource_token (prefix) = {tok[:40]}...")

    print("\nPhase 10 demo completed.")
    return True


if __name__ == "__main__":
    asyncio.run(run_phase10_demo())
