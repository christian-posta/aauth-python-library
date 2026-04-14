"""Demo script for Phase 4: User Delegation."""

import argparse
import asyncio
import sys
import threading
import traceback
from typing import List

from uvicorn import Config, Server

from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AccessServer
from participants.mission_manager import PersonServer
from participants.user_simulator import UserSimulator
from flows.user_delegated import run_user_delegated_flow
from aauth.debug import print_stderr_localhost_port_map

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
    """Run Phase 4 demo."""
    _uvicorn_servers.clear()
    _server_threads.clear()

    parser = argparse.ArgumentParser(description="Phase 4: User Delegation Demo")
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Enable manual browser testing (disables user simulator)",
    )
    args = parser.parse_args()

    print("\n" + "=" * 80, file=sys.stderr)
    print("Phase 4: User Delegation Demo", file=sys.stderr)
    print("Spec: agents send token requests to the Person Server; PS federates with the AS.", file=sys.stderr)
    print("=" * 80, file=sys.stderr)

    if args.manual:
        print("\nMODE: Manual Browser Testing", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("This demo shows user delegation with manual browser interaction:", file=sys.stderr)
        print("1. Agent requests resource (401 + resource token in AAuth header)", file=sys.stderr)
        print("2. Agent POSTs resource token to PS /token; PS forwards to AS (may return 202 + pending)", file=sys.stderr)
        print("3. **OPEN THE INTERACTION URL** (often on the AS: /interact?code=…)", file=sys.stderr)
        print("4. Authenticate and grant consent in the browser", file=sys.stderr)
        print("5. Agent polls pending URL (GET) until 200 with auth_token — no authorization code", file=sys.stderr)
        print("6. Agent retries resource request with auth token", file=sys.stderr)
        print("7. Resource validates auth token and grants access", file=sys.stderr)
        print("\nDemo Credentials:", file=sys.stderr)
        print("  Username: testuser", file=sys.stderr)
        print("  Password: testpass", file=sys.stderr)
    else:
        print("\nMODE: Automated (with User Simulator)", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("This demo shows user delegation (PS → AS federation + consent):", file=sys.stderr)
        print("1. Agent requests resource (401 + resource token in AAuth header)", file=sys.stderr)
        print("2. Agent POSTs resource token to PS /token; PS calls AS /token (202 + pending + code)", file=sys.stderr)
        print("3. User simulator completes interaction at AS /interact (consent)", file=sys.stderr)
        print("4. Agent polls pending URL until auth_token (deferred responses; SPEC Section 10)", file=sys.stderr)
        print("5. Agent retries resource request with auth token", file=sys.stderr)
        print("6. Resource validates auth token and grants access", file=sys.stderr)

    print("\nDebug output is enabled by default.", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)

    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    auth_id = "http://127.0.0.1:8003"
    ps_id = "http://127.0.0.1:8004"

    use_user_simulator = not args.manual

    agent = Agent(agent_id, port=8001, use_user_simulator=use_user_simulator, mm_url=ps_id)
    resource = Resource(resource_id, port=8002, auth_server=auth_id)
    auth_server = AccessServer(
        auth_id,
        port=8003,
        require_user_consent=True,
        trusted_person_servers=[ps_id],
    )
    ps = PersonServer(ps_id, port=8004, require_user_consent=False)

    start_uvicorn(agent.app, agent.port, "Agent")
    start_uvicorn(resource.app, resource.port, "Resource")
    start_uvicorn(auth_server.app, auth_server.port, "Access Server")
    start_uvicorn(ps.app, ps.port, "Person Server")

    print("Waiting for servers to start...", file=sys.stderr, flush=True)
    await asyncio.sleep(2)

    print_stderr_localhost_port_map(agent, resource, auth_server)

    try:
        test_results = []

        # =========================================================================
        # Test 1: User delegation flow
        # =========================================================================
        print("\n" + "=" * 80, file=sys.stderr)
        if args.manual:
            print("TEST 1: User Delegation Flow (Manual Browser Testing)", file=sys.stderr)
        else:
            print("TEST 1: User Delegation Flow (Automated)", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("Description: Agent gets 401 + resource token, POSTs PS /token (PS → AS), may receive 202 + pending URL,", file=sys.stderr)
        print("             user completes interaction at AS /interact, agent polls pending URL for auth_token,", file=sys.stderr)
        print("             then retries the resource with scheme=jwt (auth token).", file=sys.stderr)
        print("=" * 80 + "\n", file=sys.stderr)

        test1_passed = False
        test1_error = None

        try:
            if args.manual:
                print("\n" + "=" * 80, file=sys.stderr)
                print("MANUAL TESTING MODE", file=sys.stderr)
                print("=" * 80, file=sys.stderr)
                print("Deferred flow uses 202 + pending URL + interaction code (SPEC_UPDATED Sections 4.5.4, 10).", file=sys.stderr)
                print(f"Open {auth_id}/interact?code=<code> when the agent logs the interaction URL.", file=sys.stderr)
                print("This script currently falls back to the user simulator for the same steps.", file=sys.stderr)
                print("=" * 80 + "\n", file=sys.stderr)

                await agent.request_resource(
                    resource_url=f"{resource_id}/data-auth",
                    method="GET",
                    sig_scheme="jwks_uri",
                )

                print("\n" + "=" * 80, file=sys.stderr)
                print("NOTE: True manual mode would pause and print the interaction URL from the 202 response.", file=sys.stderr)
                print("Continuing with the user simulator (same protocol path as automated mode).", file=sys.stderr)
                print("=" * 80 + "\n", file=sys.stderr)

                user_sim = UserSimulator()
                response = await run_user_delegated_flow(
                    agent=agent,
                    resource=resource,
                    auth_server=auth_server,
                    user_simulator=user_sim,
                    resource_url=f"{resource_id}/data-auth",
                    method="GET",
                )
            else:
                user_sim = UserSimulator()
                response = await run_user_delegated_flow(
                    agent=agent,
                    resource=resource,
                    auth_server=auth_server,
                    user_simulator=user_sim,
                    resource_url=f"{resource_id}/data-auth",
                    method="GET",
                )

            if response.status_code == 200:
                test1_passed = True
                try:
                    data = response.json()
                    print(f"\n✓ TEST 1 PASSED: Status {response.status_code}", file=sys.stderr)
                    print(f"  Response: {data}", file=sys.stderr)
                except Exception:
                    print(f"\n✓ TEST 1 PASSED: Status {response.status_code}", file=sys.stderr)
                    print(f"  Response text: {response.text}", file=sys.stderr)
            else:
                test1_error = f"Status {response.status_code}: {response.text}"
                print(f"\n✗ TEST 1 FAILED: Status {response.status_code}", file=sys.stderr)
                print(f"  Error: {response.text}", file=sys.stderr)

        except Exception as e:
            test1_error = str(e)
            print("\n✗ TEST 1 FAILED: Exception occurred", file=sys.stderr)
            print(f"  Error: {e}", file=sys.stderr, flush=True)
            traceback.print_exc()

        test_results.append(("TEST 1: User Delegation Flow", test1_passed, test1_error))

        # =========================================================================
        # Summary
        # =========================================================================
        print("\n" + "=" * 80, file=sys.stderr)
        print("TEST SUMMARY", file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        for test_name, passed, error in test_results:
            status = "✓ PASSED" if passed else "✗ FAILED"
            print(f"{status}: {test_name}", file=sys.stderr)
            if error:
                print(f"  Error: {error}", file=sys.stderr)

        total_tests = len(test_results)
        passed_tests = sum(1 for _, passed, _ in test_results if passed)
        failed_tests = total_tests - passed_tests

        print("\n" + "-" * 80, file=sys.stderr)
        print(f"Total: {total_tests} | Passed: {passed_tests} | Failed: {failed_tests}", file=sys.stderr)
        print("=" * 80 + "\n", file=sys.stderr)

        if args.manual:
            print("\n" + "=" * 80, file=sys.stderr)
            print("MANUAL TESTING NOTES", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print("For hands-on browser testing, run this demo again and watch stderr for the interaction URL.", file=sys.stderr)
            print("Typical interaction URL shape:", file=sys.stderr)
            print(f"  {auth_id}/interact?code=<interaction_code>", file=sys.stderr)
            print("Login: testuser / testpass — then grant consent.", file=sys.stderr)
            print(f"Agent polls GET {auth_id}/pending/<id> until 200 with auth_token.", file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)

    finally:
        await shutdown_uvicorn_servers()


if __name__ == "__main__":
    asyncio.run(main())
