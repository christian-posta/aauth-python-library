"""Demo Phase 11: MM–AS trust (federated token path).

Starts Agent, Resource, Auth Server (trusts MM), and Mission Manager. Agent
obtains a resource token (via 401 challenge or /authorize), then requests an
auth token through MM; AS verifies MM's ``jwks_uri`` signature.
"""

import asyncio
import threading

import uvicorn

from flows.autonomous import run_autonomous_flow
from participants.agent import Agent
from participants.auth_server import AuthServer
from participants.mission_manager import MissionManager
from participants.resource import Resource


async def run_phase11_demo():
    print("=" * 60)
    print("Phase 11 Demo: MM–AS federation (trusted Mission Manager)")
    print("=" * 60)

    agent_id = "http://127.0.0.1:8111"
    resource_id = "http://127.0.0.1:8112"
    as_id = "http://127.0.0.1:8113"
    mm_id = "http://127.0.0.1:8114"

    agent = Agent(agent_id, port=8111, mm_url=mm_id)
    resource = Resource(resource_id, port=8112, auth_server=as_id)
    auth = AuthServer(as_id, port=8113, trusted_mission_managers=[mm_id])
    mm = MissionManager(mm_id, port=8114)

    for target in (
        (agent.app, 8111),
        (resource.app, 8112),
        (auth.app, 8113),
        (mm.app, 8114),
    ):
        threading.Thread(
            target=lambda a=target[0], p=target[1]: uvicorn.run(
                a, host="0.0.0.0", port=p, log_level="error"
            ),
            daemon=True,
        ).start()

    await asyncio.sleep(2)

    resp = await run_autonomous_flow(
        agent,
        resource,
        auth,
        resource_url="http://127.0.0.1:8112/data-auth",
    )
    print(f"\nFinal status: {resp.status_code}")
    if resp.status_code == 200:
        print("Phase 11 demo: autonomous flow via MM completed.")
    return resp


if __name__ == "__main__":
    asyncio.run(run_phase11_demo())
