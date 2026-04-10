"""Demo Phase 5: Missions — MM approval, AAuth-Mission, mission in resource token.

Replaces the older “agent-as-resource” Phase 5 demo. For self-access / scope-only
tokens see PHASE5-agent-is-resource.md and ``Agent.request_self_authorization``.
"""

import asyncio
import json
import sys
import threading

import jwt
import uvicorn

from participants.agent import Agent
from participants.auth_server import AuthServer
from participants.mission_manager import MissionManager
from participants.resource import Resource


def run_server(app, port: int):
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")


async def main():
    print("\n" + "=" * 80, file=sys.stderr)
    print("Phase 5: Missions (MM + resource + AS)", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"
    mm_id = "http://127.0.0.1:8004"

    agent = Agent(agent_id, port=8001, mm_url=mm_id)
    resource = Resource(resource_id, port=8002, auth_server=as_id)
    auth = AuthServer(as_id, port=8003, trusted_mission_managers=[mm_id])
    mm = MissionManager(mm_id, port=8004)

    for app, port in (
        (agent.app, 8001),
        (resource.app, 8002),
        (auth.app, 8003),
        (mm.app, 8004),
    ):
        threading.Thread(target=run_server, args=(app, port), daemon=True).start()

    await asyncio.sleep(2)

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
    assert miss and miss.get("manager") and miss.get("s256")
    print(f"  ✓ mission claim: {json.dumps(miss)}", file=sys.stderr)

    print("\nPhase 5 missions demo complete.", file=sys.stderr)
    print("Servers on 8001–8004. Ctrl+C to exit.", file=sys.stderr)
    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    asyncio.run(main())
