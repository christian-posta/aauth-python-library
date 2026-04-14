"""Demo Phase 14: Resource-managed two-party mode (AAuth-Access opaque token).

Access mode: Resource-managed (two-party)
- No Person Server or Access Server involved.
- Agent calls the resource's /authorize endpoint directly.
- Resource issues an opaque AAuth-Access token and returns it in the response header.
- Agent echoes it back as Authorization: AAuth <token> on subsequent requests.
- Resource rolls the token on each successful request (prevents replay).

This demonstrates the simplest AAuth authorization mode — the resource manages
its own access control without delegating to an external authorization server.

Protocol flow:
  Agent                              Resource
    |                                   |
    |-- GET /data-two-party ----------->|  (no token yet)
    |<- 401 AAuth-Requirement ----------|  (requirement=auth-token; resource-token=...)
    |                                   |
    |-- POST /authorize + sig --------->|  (identity signature, gets access token)
    |<- 200 AAuth-Access: <token> ------|
    |                                   |
    |-- GET /data-two-party ----------->|  (Authorization: AAuth <token>)
    |<- 200 AAuth-Access: <new_token> --|  (rolling token refresh)
    |                                   |
    |-- GET /data-two-party ----------->|  (Authorization: AAuth <new_token>)
    |<- 200 AAuth-Access: <newer_tok> --|
"""

import asyncio
import threading
import uvicorn
from participants.agent import Agent
from participants.resource import Resource


async def run_demo():
    print("=" * 65)
    print("Phase 14: Resource-Managed Two-Party Mode (AAuth-Access)")
    print("=" * 65)

    # Two-party resource: manages its own access tokens, no AS/PS needed.
    agent = Agent("http://127.0.0.1:8001", port=8001)
    resource = Resource("http://127.0.0.1:8002", port=8002, two_party_mode=True)

    print("\n1. Starting servers...")
    for server, port in [(agent, 8001), (resource, 8002)]:
        t = threading.Thread(
            target=lambda s=server, p=port: uvicorn.run(s.app, host="127.0.0.1", port=p, log_level="error"),
            daemon=True,
        )
        t.start()
    await asyncio.sleep(2)
    print("   Agent  : http://127.0.0.1:8001")
    print("   Resource: http://127.0.0.1:8002 (two-party mode)")

    # Step 1: First request without a token — resource returns 401 with AAuth-Requirement
    print("\n2. First request (no token) — expect 401 AAuth-Requirement...")
    response = await agent.request_resource(
        resource_url="http://127.0.0.1:8002/data-two-party",
        method="GET",
        sig_scheme="jwks_uri",
    )
    print(f"   Status: {response.status_code}")
    if response.status_code == 200:
        print("   Agent obtained AAuth-Access token and accessed the resource!")
        data = response.json()
        print(f"   Response: {data.get('message')}")
        access_token = agent.aauth_access_token
        print(f"   AAuth-Access token stored: {access_token[:20]}..." if access_token else "   (no token stored)")
    else:
        print(f"   Unexpected status: {response.status_code} — {response.text[:120]}")
        return

    # Step 2: Second request — agent echoes token, resource rolls it
    print("\n3. Second request (with AAuth-Access token) — expect rolling refresh...")
    old_token = agent.aauth_access_token
    response2 = await agent.request_resource(
        resource_url="http://127.0.0.1:8002/data-two-party",
        method="GET",
        sig_scheme="jwks_uri",
    )
    print(f"   Status: {response2.status_code}")
    if response2.status_code == 200:
        new_token = agent.aauth_access_token
        token_rolled = old_token != new_token
        print(f"   Token rolled: {'YES' if token_rolled else 'NO (unexpected)'}")
        data2 = response2.json()
        print(f"   Response: {data2.get('message')}")
    else:
        print(f"   Unexpected: {response2.status_code} — {response2.text[:120]}")

    # Step 3: Request with revoked/wrong token — should be rejected
    print("\n4. Clearing stored token — expect 401 on next request...")
    agent.aauth_access_token = None
    response3 = await agent.request_resource(
        resource_url="http://127.0.0.1:8002/data-two-party",
        method="GET",
        sig_scheme="jwks_uri",
    )
    print(f"   Status: {response3.status_code}")
    if response3.status_code == 200:
        print("   Agent re-authorized and accessed resource again (authorize flow repeated)")
    else:
        print(f"   Status: {response3.status_code}")

    print("\n" + "=" * 65)
    print("Phase 14 Demo Complete!")
    print("Key takeaways:")
    print("  - No PS or AS required for two-party mode")
    print("  - Resource issues and manages its own AAuth-Access tokens")
    print("  - Token rolls on each successful request (prevents replay)")
    print("  - Agent stores token in agent.aauth_access_token automatically")
    print("=" * 65)


if __name__ == "__main__":
    asyncio.run(run_demo())
