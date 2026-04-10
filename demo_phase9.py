"""Demo script for Phase 9: Interaction Chaining."""

import asyncio
import sys
import threading
from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AuthServer


def run_server(server, name):
    print(f"Starting {name}...", file=sys.stderr, flush=True)
    try:
        server.run()
    except KeyboardInterrupt:
        print(f"{name} stopped", file=sys.stderr, flush=True)


async def main():
    print("\n" + "=" * 80, file=sys.stderr)
    print("Phase 9: Interaction Chaining Demo", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print("\nThis demo shows downstream interaction bubbling via Resource 1 (MM optional):", file=sys.stderr)
    print("1. Agent requests Resource 1 /data-chain-auth", file=sys.stderr)
    print("2. Resource 1 calls Resource 2 and triggers downstream auth", file=sys.stderr)
    print("3. Downstream Auth Server returns 202 interaction required", file=sys.stderr)
    print("4. Resource 1 returns its own 202 + pending URL + interaction code", file=sys.stderr)
    print("5. User goes to Resource 1 interaction endpoint and gets redirected downstream", file=sys.stderr)
    print("6. Resource 1 polls downstream pending URL and returns final response to agent", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)

    agent_id = "http://127.0.0.1:8001"
    resource1_id = "http://127.0.0.1:8002"
    auth1_id = "http://127.0.0.1:8003"
    resource2_id = "http://127.0.0.1:8004"
    auth2_id = "http://127.0.0.1:8005"

    auth1 = AuthServer(auth1_id, port=8003, require_user_consent=False)
    auth2 = AuthServer(
        auth2_id,
        port=8005,
        require_user_consent=True,
        trusted_auth_servers=[auth1_id],
    )
    resource2 = Resource(resource2_id, port=8004, auth_server=auth2_id)
    resource1 = Resource(
        resource1_id,
        port=8002,
        auth_server=auth1_id,
        downstream_resource_url=f"{resource2_id}/data-auth",
    )
    agent = Agent(agent_id, port=8001, use_user_simulator=True)

    threads = [
        threading.Thread(target=run_server, args=(agent, "Agent"), daemon=True),
        threading.Thread(target=run_server, args=(resource1, "Resource 1"), daemon=True),
        threading.Thread(target=run_server, args=(resource2, "Resource 2"), daemon=True),
        threading.Thread(target=run_server, args=(auth1, "Auth Server 1"), daemon=True),
        threading.Thread(target=run_server, args=(auth2, "Auth Server 2"), daemon=True),
    ]
    for thread in threads:
        thread.start()

    print("Waiting for servers to start...", file=sys.stderr, flush=True)
    await asyncio.sleep(2)

    response = await agent.request_resource(
        resource_url=f"{resource1_id}/data-chain-auth",
        method="GET",
        sig_scheme="jwks_uri",
    )
    print("\n" + "=" * 80, file=sys.stderr)
    print("RESULT", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print(f"Status: {response.status_code}", file=sys.stderr)
    try:
        print(f"Body: {response.json()}", file=sys.stderr)
    except Exception:
        print(f"Body: {response.text}", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)

    if response.status_code == 200:
        print("Phase 9 demo passed.", file=sys.stderr, flush=True)
    else:
        print("Phase 9 demo failed.", file=sys.stderr, flush=True)


if __name__ == "__main__":
    asyncio.run(main())
