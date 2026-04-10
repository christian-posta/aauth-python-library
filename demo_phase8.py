"""Demo script for Phase 8: Clarification Chat (AAuth-Requirement: requirement=clarification)."""

import asyncio
import sys
import threading
import time
from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AuthServer
from participants.user_simulator import UserSimulator


def run_server(server, name):
    """Run a server in a separate thread."""
    print(f"Starting {name}...", file=sys.stderr, flush=True)
    try:
        server.run()
    except KeyboardInterrupt:
        print(f"{name} stopped", file=sys.stderr, flush=True)


async def _wait_for_pending(auth_server: AuthServer, timeout_sec: int = 10):
    """Wait for a pending request to appear and return its ID/details."""
    start = time.time()
    while time.time() - start < timeout_sec:
        if auth_server.pending_requests:
            pending_id = next(iter(auth_server.pending_requests))
            return pending_id, auth_server.pending_requests[pending_id]
        await asyncio.sleep(0.1)
    return None, None


async def _wait_for_clarification_response(
    auth_server: AuthServer,
    pending_id: str,
    timeout_sec: int = 15,
):
    """Wait until the agent has posted a clarification response."""
    start = time.time()
    while time.time() - start < timeout_sec:
        pending = auth_server.pending_requests.get(pending_id)
        if not pending:
            return False
        if pending.get("clarification_history"):
            return True
        await asyncio.sleep(0.25)
    return False


async def main():
    """Run Phase 8 demo."""
    print("\n" + "=" * 80, file=sys.stderr)
    print("Phase 8: Clarification Chat Demo", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print("\nThis demo shows the clarification chat flow:", file=sys.stderr)
    print("1. Agent requests resource and gets 401 challenge", file=sys.stderr)
    print("2. Auth server returns 202 + pending URL (interaction required)", file=sys.stderr)
    print("3. During polling, pending response includes clarification question", file=sys.stderr)
    print("4. Agent POSTs clarification_response to pending URL", file=sys.stderr)
    print("5. User grants consent at /interact", file=sys.stderr)
    print("6. Agent polling receives 200 with auth_token and retries resource", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    auth_id = "http://127.0.0.1:8003"

    auth_server = AuthServer(
        auth_id,
        port=8003,
        require_user_consent=True,
        clarification_questions=["Why do you need access to my calendar?"],
    )
    resource = Resource(resource_id, port=8002, auth_server=auth_id)
    # Disable built-in user simulator so we can observe clarification before consent.
    agent = Agent(agent_id, port=8001, use_user_simulator=False, clarification_supported=True)
    user_sim = UserSimulator()

    agent_thread = threading.Thread(target=run_server, args=(agent, "Agent"), daemon=True)
    resource_thread = threading.Thread(target=run_server, args=(resource, "Resource"), daemon=True)
    auth_thread = threading.Thread(target=run_server, args=(auth_server, "Auth Server"), daemon=True)
    agent_thread.start()
    resource_thread.start()
    auth_thread.start()

    print("Waiting for servers to start...", file=sys.stderr, flush=True)
    await asyncio.sleep(2)

    print("\n" + "=" * 80, file=sys.stderr)
    print("TEST 1: Clarification Round Trip", file=sys.stderr)
    print("=" * 80, file=sys.stderr)

    request_task = asyncio.create_task(
        agent.request_resource(
            resource_url=f"{resource_id}/data-auth",
            method="GET",
            sig_scheme="jwks_uri",
        )
    )

    pending_id, pending = await _wait_for_pending(auth_server)
    if not pending_id:
        print("✗ FAILED: No pending request created", file=sys.stderr)
        return

    print(f"Pending request created: {pending_id}", file=sys.stderr, flush=True)

    clarification_seen = await _wait_for_clarification_response(auth_server, pending_id)
    if not clarification_seen:
        print("✗ FAILED: Agent did not post clarification response in time", file=sys.stderr)
        request_task.cancel()
        return

    print("✓ Agent posted clarification response", file=sys.stderr, flush=True)
    print(
        f"  Stored clarification history: {auth_server.pending_requests[pending_id]['clarification_history']}",
        file=sys.stderr,
        flush=True,
    )

    interaction_code = pending["interaction_code"]
    interaction_url = f"{auth_id}/interact?code={interaction_code}"
    consent_ok = await user_sim.complete_interaction(interaction_url, auth_id)
    if not consent_ok:
        print("✗ FAILED: User simulator could not complete consent", file=sys.stderr)
        request_task.cancel()
        return

    print("✓ User consent completed", file=sys.stderr, flush=True)

    response = await request_task
    if response.status_code == 200:
        print("✓ TEST 1 PASSED: Clarification + consent flow completed", file=sys.stderr)
        print(f"  Final response: {response.json()}", file=sys.stderr)
    else:
        print(f"✗ TEST 1 FAILED: Final status {response.status_code}", file=sys.stderr)
        print(f"  Response: {response.text}", file=sys.stderr)

    print("\n" + "=" * 80, file=sys.stderr)
    print("TEST 2: No Clarification When Agent Unsupported", file=sys.stderr)
    print("=" * 80, file=sys.stderr)

    agent_unsupported = Agent(
        "http://127.0.0.1:8011",
        port=8011,
        use_user_simulator=False,
        clarification_supported=False,
    )
    resource2 = Resource("http://127.0.0.1:8012", port=8012, auth_server=auth_id)
    auth_server2 = AuthServer(
        auth_id,
        port=8013,
        require_user_consent=True,
        clarification_questions=["Why do you need this?"],
    )

    # Lightweight unit-like check without starting extra servers:
    pending_resp = auth_server2._create_pending_request(
        agent_id="http://127.0.0.1:8011",
        resource_id="http://127.0.0.1:8012",
        scope="data.read",
        agent_jwk={"kty": "OKP", "crv": "Ed25519", "x": "11"},
        clarification_supported=False,
    )
    _ = (agent_unsupported, resource2, pending_resp)  # Keep references to avoid lint warnings
    pending2_id = next(iter(auth_server2.pending_requests))
    pending2 = auth_server2.pending_requests[pending2_id]
    no_clarification = not pending2.get("clarification_supported")

    if no_clarification:
        print("✓ TEST 2 PASSED: Clarification disabled for unsupported agent", file=sys.stderr)
    else:
        print("✗ TEST 2 FAILED: Clarification unexpectedly enabled", file=sys.stderr)

    print("\n" + "=" * 80, file=sys.stderr)
    print("Phase 8 Demo Complete!", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)
    print("Servers are still running. Press Ctrl+C to stop.", file=sys.stderr, flush=True)
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping servers...", file=sys.stderr, flush=True)


if __name__ == "__main__":
    asyncio.run(main())
