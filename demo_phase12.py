"""Demo Phase 12: Mission lifecycle (proposal → approval → token use).

Uses Mission Manager ``/mission`` for approval, then proactive authorization
with ``AAuth-Mission`` and an auth-token request via MM.
"""

import asyncio
import threading

import uvicorn

from participants.agent import Agent
from participants.auth_server import AuthServer
from participants.mission_manager import MissionManager
from participants.resource import Resource


async def run_phase12_demo():
    print("=" * 60)
    print("Phase 12 Demo: Mission lifecycle")
    print("=" * 60)

    agent_id = "http://127.0.0.1:8211"
    resource_id = "http://127.0.0.1:8212"
    as_id = "http://127.0.0.1:8213"
    mm_id = "http://127.0.0.1:8214"

    agent = Agent(agent_id, port=8211, mm_url=mm_id)
    resource = Resource(resource_id, port=8212, auth_server=as_id)
    auth = AuthServer(as_id, port=8213, trusted_mission_managers=[mm_id])
    mm = MissionManager(mm_id, port=8214)

    for app, port in (
        (agent.app, 8211),
        (resource.app, 8212),
        (auth.app, 8213),
        (mm.app, 8214),
    ):
        threading.Thread(
            target=lambda a=app, p=port: uvicorn.run(
                a, host="0.0.0.0", port=p, log_level="error"
            ),
            daemon=True,
        ).start()

    await asyncio.sleep(2)

    print("\n1. Mission proposal + approval")
    m = await agent.propose_mission("Demo mission: export reports for Q1.")
    print(f"   approved s256 = {m['s256'][:24]}...")

    print("\n2. Resource token with mission claim")
    rt = await agent.request_resource_token_proactively(resource_id, "data.read")
    print(f"   resource_token acquired: {bool(rt)}")

    print("\n3. Auth token via MM")
    at = await agent._request_auth_token(rt, as_id)
    print(f"   auth_token acquired: {bool(at)}")

    print("\nPhase 12 demo completed.")
    return True


if __name__ == "__main__":
    asyncio.run(run_phase12_demo())
