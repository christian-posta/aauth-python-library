"""Demo Phase 7: Call Chaining — Resource 1 acts as agent to access Resource 2 via MM.

Per spec Section "Call Chaining": when Resource 1 needs to call Resource 2 to fulfil a
request, it acts as an agent. It sends the downstream resource token (from Resource 2's
challenge) plus the upstream auth token (that Agent 1 used to access Resource 1) to its
own Person Server. The PS evaluates the chain and federates with Resource 2's AS to
issue a downstream auth token. Resource 1 then accesses Resource 2 with that token.
"""

import asyncio
import json
import sys
import threading
from typing import List
from urllib.parse import urlparse

import httpx
from uvicorn import Config, Server

from aauth.tokens.auth_token import parse_token_claims
from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AccessServer
from participants.mission_manager import PersonServer
from flows.autonomous import run_autonomous_flow

_uvicorn_servers: List[Server] = []
_server_threads: List[threading.Thread] = []


def start_uvicorn(app, port: int, name: str) -> None:
    """Run uvicorn in a daemon thread and keep a Server handle for should_exit."""

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
    print("Phase 7: Call Chaining — Resource 1 -> MM -> AS2 -> Resource 2", file=sys.stderr)
    print(
        "Per spec: Resource 1 acts as agent; sends resource_token + upstream_token to its PS. "
        "PS federates with AS2 which verifies the chain and issues a downstream auth token.",
        file=sys.stderr,
    )
    print("=" * 80 + "\n", file=sys.stderr)

    agent_id    = "http://127.0.0.1:8001"
    resource1_id = "http://127.0.0.1:8002"
    as1_id      = "http://127.0.0.1:8003"
    ps_id       = "http://127.0.0.1:8004"
    resource2_id = "http://127.0.0.1:8005"
    as2_id      = "http://127.0.0.1:8006"

    agent1   = Agent(agent_id, port=8001, use_user_simulator=False, mm_url=ps_id)
    resource1 = Resource(resource1_id, port=8002, auth_server=as1_id, mm_url=ps_id)
    as1      = AccessServer(as1_id, port=8003, require_user_consent=False,
                          trusted_person_servers=[ps_id])
    ps       = PersonServer(ps_id, port=8004, require_user_consent=False)
    resource2 = Resource(resource2_id, port=8005, auth_server=as2_id)
    as2      = AccessServer(as2_id, port=8006, require_user_consent=False,
                          trusted_person_servers=[ps_id],
                          trusted_auth_servers=[as1_id])

    start_uvicorn(agent1.app,   8001, "Agent 1")
    start_uvicorn(resource1.app, 8002, "Resource 1")
    start_uvicorn(as1.app,      8003, "Access Server 1")
    start_uvicorn(ps.app,       8004, "Person Server")
    start_uvicorn(resource2.app, 8005, "Resource 2")
    start_uvicorn(as2.app,      8006, "Access Server 2")

    print("Waiting for servers to start...", file=sys.stderr, flush=True)
    await asyncio.sleep(2)

    print("\n" + "-" * 80, file=sys.stderr)
    print("127.0.0.1 port map (JWT iss / aud / agent URLs below refer to these):", file=sys.stderr)
    print(f"  8001  Agent 1              — iss for agent identity; /.well-known/aauth-agent.json", file=sys.stderr)
    print(f"  8002  Resource 1           — iss in resource tokens; also acts as agent for Resource 2", file=sys.stderr)
    print(f"  8003  Access Server 1       — iss in auth tokens for Resource 1; aud in Resource 1 tokens", file=sys.stderr)
    print(f"  8004  Person Server        — Agent 1 + Resource 1 send token requests here", file=sys.stderr)
    print(f"  8005  Resource 2           — downstream resource; iss in Resource 2 tokens", file=sys.stderr)
    print(f"  8006  Access Server 2      — iss in downstream auth tokens; aud in Resource 2 tokens", file=sys.stderr)
    print("-" * 80 + "\n", file=sys.stderr)

    all_passed = True

    # --- TEST 1: Agent 1 -> Resource 1 via MM (autonomous flow) ---
    print("=" * 80, file=sys.stderr)
    print("TEST 1: Agent 1 accesses Resource 1 via Person Server", file=sys.stderr)
    print("=" * 80, file=sys.stderr)

    auth_token_for_resource1 = None
    try:
        response = await run_autonomous_flow(
            agent=agent1,
            resource=resource1,
            auth_server=as1,
            resource_url=f"{resource1_id}/data-auth",
            method="GET",
        )
        auth_token_for_resource1 = agent1.auth_token
        assert auth_token_for_resource1, "No auth token stored on agent after autonomous flow"
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        claims = parse_token_claims(auth_token_for_resource1)
        payload = claims["payload"]
        print(f"  Resource token (from challenge) decoded — agent: {payload.get('agent', '?')}", file=sys.stderr)
        print(f"  Auth token claims:", file=sys.stderr)
        print(f"    iss   = {payload.get('iss')}", file=sys.stderr)
        print(f"    aud   = {payload.get('aud')}", file=sys.stderr)
        print(f"    agent = {payload.get('agent')}", file=sys.stderr)
        assert payload.get("iss") == as1_id, f"iss mismatch: {payload.get('iss')}"
        assert payload.get("aud") == resource1_id, f"aud mismatch: {payload.get('aud')}"
        assert payload.get("agent") == agent_id, f"agent mismatch: {payload.get('agent')}"
        print("PASSED: TEST 1", file=sys.stderr)
    except Exception as exc:
        print(f"FAILED: TEST 1 — {exc}", file=sys.stderr)
        import traceback; traceback.print_exc(file=sys.stderr)
        all_passed = False

    # --- TEST 2: Resource 1 acts as agent, calls Resource 2 via MM (call chaining) ---
    print("\n" + "=" * 80, file=sys.stderr)
    print("TEST 2: Resource 1 calls Resource 2 via MM (call chaining per spec)", file=sys.stderr)
    print("=" * 80, file=sys.stderr)

    if not auth_token_for_resource1:
        print("SKIPPED: TEST 2 (TEST 1 did not produce auth token)", file=sys.stderr)
        all_passed = False
    else:
        try:
            downstream_response = await resource1.call_downstream_resource(
                downstream_url=f"{resource2_id}/data-auth",
                method="GET",
                upstream_auth_token=auth_token_for_resource1,
            )
            assert downstream_response.status_code == 200, (
                f"Expected 200, got {downstream_response.status_code}: {downstream_response.text}"
            )
            resp_data = downstream_response.json()
            print(f"  Resource 2 response: {json.dumps(resp_data)}", file=sys.stderr)
            print("PASSED: TEST 2", file=sys.stderr)
        except Exception as exc:
            print(f"FAILED: TEST 2 — {exc}", file=sys.stderr)
            import traceback; traceback.print_exc(file=sys.stderr)
            all_passed = False

    # --- TEST 3: Verify downstream auth token claims ---
    print("\n" + "=" * 80, file=sys.stderr)
    print("TEST 3: Verify downstream auth token claims (iss=AS2, aud=resource2, agent=resource1)", file=sys.stderr)
    print("=" * 80, file=sys.stderr)

    downstream_token = resource1.last_downstream_auth_token
    if not downstream_token:
        print("FAILED: TEST 3 — no downstream auth token captured on resource1", file=sys.stderr)
        all_passed = False
    else:
        try:
            claims = parse_token_claims(downstream_token)
            payload = claims["payload"]
            print(f"  Downstream auth token claims:", file=sys.stderr)
            print(f"    iss   = {payload.get('iss')}", file=sys.stderr)
            print(f"    aud   = {payload.get('aud')}", file=sys.stderr)
            print(f"    agent = {payload.get('agent')}", file=sys.stderr)
            assert payload.get("iss") == as2_id, f"iss mismatch: expected {as2_id}, got {payload.get('iss')}"
            assert payload.get("aud") == resource2_id, f"aud mismatch: expected {resource2_id}, got {payload.get('aud')}"
            assert payload.get("agent") == resource1_id, f"agent mismatch: expected {resource1_id}, got {payload.get('agent')}"
            print("PASSED: TEST 3", file=sys.stderr)
        except Exception as exc:
            print(f"FAILED: TEST 3 — {exc}", file=sys.stderr)
            import traceback; traceback.print_exc(file=sys.stderr)
            all_passed = False

    print("\n" + "=" * 80, file=sys.stderr)
    if all_passed:
        print("ALL TESTS PASSED", file=sys.stderr)
    else:
        print("SOME TESTS FAILED", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)

    await shutdown_uvicorn_servers()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr, flush=True)
