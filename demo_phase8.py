"""Demo Phase 8: Clarification Chat — AAuth-Requirement: requirement=clarification.

The AS poses a clarification question to the agent during user consent.
The agent (``clarification_supported=True``) POSTs a ``clarification_response`` to the
pending URL before consent completes, per SPEC.md §Clarification Chat.  The AS records
the answer and includes it in the consent context before issuing an auth token.

TEST 2 shows that when the agent declares ``clarification_supported=False`` in its
metadata (and omits ``clarification`` from ``AAuth-Capabilities``), the AS skips
clarification entirely (still issues a token after consent).
"""

import asyncio
import json
import sys
import threading
import time
from typing import List, Optional, Tuple

from uvicorn import Config, Server

from aauth.debug import print_stderr_localhost_port_map
from aauth.tokens.auth_token import parse_token_claims
from participants.agent import Agent
from participants.auth_server import AccessServer
from participants.resource import Resource
from participants.user_simulator import UserSimulator

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


async def _wait_for_pending(
    auth_server: AccessServer, timeout_sec: int = 10
) -> Tuple[Optional[str], Optional[dict]]:
    """Poll ``auth_server.pending_requests`` until a request appears or timeout."""
    start = time.time()
    while time.time() - start < timeout_sec:
        if auth_server.pending_requests:
            pending_id = next(iter(auth_server.pending_requests))
            return pending_id, auth_server.pending_requests[pending_id]
        await asyncio.sleep(0.1)
    return None, None


async def _wait_for_clarification_response(
    auth_server: AccessServer,
    pending_id: str,
    timeout_sec: int = 15,
) -> bool:
    """Wait until the agent has posted a clarification response to the pending URL."""
    start = time.time()
    while time.time() - start < timeout_sec:
        pending = auth_server.pending_requests.get(pending_id)
        if not pending:
            return False
        if pending.get("clarification_history"):
            return True
        await asyncio.sleep(0.25)
    return False


async def main() -> None:
    _uvicorn_servers.clear()
    _server_threads.clear()

    print("\n" + "=" * 80, file=sys.stderr)
    print("Phase 8: Clarification Chat (AAuth-Requirement: requirement=clarification)", file=sys.stderr)
    print(
        "Spec: AS poses a clarification question to the agent during consent; agent\n"
        "POSTs clarification_response to pending URL; AS records answer before issuing token.",
        file=sys.stderr,
    )
    print("=" * 80 + "\n", file=sys.stderr)

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    as_id = "http://127.0.0.1:8003"

    # auto_interact=False: the demo controls consent timing — consent is triggered
    # AFTER the clarification round-trip completes (see _wait_for_clarification_response
    # below).  Without this flag the agent would print the interaction URL immediately
    # upon receiving the first 202, causing a premature consent before clarification.
    agent = Agent(agent_id, port=8001, clarification_supported=True, auto_interact=False)
    resource = Resource(resource_id, port=8002, auth_server=as_id)
    auth = AccessServer(
        as_id,
        port=8003,
        require_user_consent=True,
        clarification_questions=["Why do you need access to my calendar?"],
    )
    user_sim = UserSimulator()

    start_uvicorn(agent.app, agent.port, "Agent")
    start_uvicorn(resource.app, resource.port, "Resource")
    start_uvicorn(auth.app, auth.port, "Access Server")

    print("Waiting for servers to start...", file=sys.stderr, flush=True)
    await asyncio.sleep(2)
    print_stderr_localhost_port_map(agent, resource, auth)

    try:
        # ------------------------------------------------------------------
        print("TEST 1: Clarification Round Trip (clarification_supported=True)", file=sys.stderr)

        # Start agent request in background — it will poll pending URL and
        # POST clarification_response automatically.
        request_task = asyncio.create_task(
            agent.request_resource(
                resource_url=f"{resource_id}/data-auth",
                method="GET",
                sig_scheme="jwks_uri",
            )
        )

        pending_id, pending = await _wait_for_pending(auth, timeout_sec=10)
        assert pending_id, "No pending request created"
        print(f"  Pending request created: {pending_id}", file=sys.stderr, flush=True)

        clarification_seen = await _wait_for_clarification_response(auth, pending_id)
        assert clarification_seen, "Agent did not post clarification response in time"
        history = auth.pending_requests[pending_id]["clarification_history"]
        print("  Agent posted clarification response", file=sys.stderr, flush=True)
        print(f"  Clarification history: {json.dumps(history)}", file=sys.stderr)

        # Trigger user consent now that the clarification round trip is done.
        interaction_code = pending["interaction_code"]
        interaction_url = f"{as_id}/interact?code={interaction_code}"
        consent_ok = await user_sim.complete_interaction(interaction_url, as_id)
        assert consent_ok, "User consent failed"
        print("  User consent completed", file=sys.stderr, flush=True)

        response = await request_task
        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}: {response.text}"
        )

        auth_token = agent.auth_token
        assert auth_token, "Agent should have stored auth_token"
        auth_claims = parse_token_claims(auth_token)
        print("\n" + "=" * 80, file=sys.stderr)
        print("AUTH TOKEN (aa-auth+jwt) — decoded", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(auth_claims["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(auth_claims["payload"], indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("  ✓ TEST 1 PASSED: Clarification + consent flow completed", file=sys.stderr)
        print(f"  Final response: {response.json()}", file=sys.stderr)

        # ------------------------------------------------------------------
        print(
            "\nTEST 2: No Clarification for Unsupported Agent (clarification_supported=False)",
            file=sys.stderr,
        )

        agent2_id = "http://127.0.0.1:8011"
        agent2 = Agent(
            agent2_id, port=8011, use_user_simulator=True, clarification_supported=False
        )
        start_uvicorn(agent2.app, agent2.port, "Agent2")
        await asyncio.sleep(1)  # let agent2 server bind

        response2 = await agent2.request_resource(
            resource_url=f"{resource_id}/data-auth",
            method="GET",
            sig_scheme="jwks_uri",
        )
        assert response2.status_code == 200, (
            f"Expected 200, got {response2.status_code}: {response2.text}"
        )
        assert not agent2.clarification_history, (
            "Agent2 should have no clarification history"
        )

        auth_token2 = agent2.auth_token
        assert auth_token2, "Agent2 should have stored auth_token"
        auth_claims2 = parse_token_claims(auth_token2)
        print("\n" + "=" * 80, file=sys.stderr)
        print("AUTH TOKEN 2 (aa-auth+jwt) — decoded (no clarification)", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Header:", file=sys.stderr)
        print(json.dumps(auth_claims2["header"], indent=2), file=sys.stderr)
        print("\nPayload:", file=sys.stderr)
        print(json.dumps(auth_claims2["payload"], indent=2), file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("  ✓ TEST 2 PASSED: No clarification for unsupported agent", file=sys.stderr)
        print(f"  Agent2 clarification_history: {agent2.clarification_history}", file=sys.stderr)

        print("\nPhase 8 clarification demo complete.", file=sys.stderr)
    finally:
        await shutdown_uvicorn_servers()


if __name__ == "__main__":
    asyncio.run(main())
