"""Demo script for Phase 3: Autonomous Authorization."""

import asyncio
import sys
import threading
import time
from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AuthServer
from flows.autonomous import run_autonomous_flow
from aauth.tokens.auth_token import parse_token_claims


def run_server(server, name):
    """Run a server in a separate thread."""
    print(f"Starting {name}...", file=sys.stderr, flush=True)
    try:
        server.run()
    except KeyboardInterrupt:
        print(f"{name} stopped", file=sys.stderr, flush=True)


async def main():
    """Run Phase 3 demo."""
    print("\n" + "=" * 80, file=sys.stderr)
    print("Phase 3: Autonomous Authorization Demo", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print("\nThis demo shows the complete autonomous authorization flow:", file=sys.stderr)
    print("1. Agent requests resource (gets resource token challenge)", file=sys.stderr)
    print("2. Agent presents resource token to auth server", file=sys.stderr)
    print("3. Auth server issues auth token", file=sys.stderr)
    print("4. Agent retries resource request with auth token", file=sys.stderr)
    print("5. Resource validates auth token and grants access", file=sys.stderr)
    print("\nTest 1: Standard flow (no txn)", file=sys.stderr)
    print("Test 2: Flow with txn for request correlation (spec Section 8.1, 9.1)", file=sys.stderr)
    print("\nDebug output is enabled by default.", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)

    # Create participants
    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    auth_id = "http://127.0.0.1:8003"

    agent = Agent(agent_id, port=8001)
    # Resource WITHOUT txn for Test 1
    resource = Resource(resource_id, port=8002, auth_server=auth_id, enable_txn=False)
    auth_server = AuthServer(auth_id, port=8003)

    # Start servers in background threads
    agent_thread = threading.Thread(target=run_server, args=(agent, "Agent"), daemon=True)
    resource_thread = threading.Thread(target=run_server, args=(resource, "Resource"), daemon=True)
    auth_thread = threading.Thread(target=run_server, args=(auth_server, "Auth Server"), daemon=True)

    agent_thread.start()
    resource_thread.start()
    auth_thread.start()

    # Wait for servers to start
    print("Waiting for servers to start...", file=sys.stderr, flush=True)
    await asyncio.sleep(2)

    # Prompt before starting test
    print("\n" + "=" * 80, file=sys.stderr)
    print("Ready to start test. Press Enter to begin...", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    input()

    # Track test results
    test_results = []

    # =========================================================================
    # Test 1: Standard autonomous authorization flow (no txn)
    # =========================================================================
    print("\n" + "=" * 80, file=sys.stderr)
    print("TEST 1: Autonomous Authorization Flow (no txn)", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print("Description: Standard flow. The resource token has no txn claim,", file=sys.stderr)
    print("             so the auth token should also have no txn claim.", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)

    test1_passed = False
    test1_error = None

    try:
        response = await run_autonomous_flow(
            agent=agent,
            resource=resource,
            auth_server=auth_server,
            resource_url=f"{resource_id}/data-auth",
            method="GET"
        )

        if response.status_code == 200:
            data = response.json()
            print(f"\n  Access granted: {data.get('message')}", file=sys.stderr)

            # Inspect the auth token
            auth_token = agent.auth_token
            if auth_token:
                claims = parse_token_claims(auth_token)
                payload = claims["payload"]
                has_txn = "txn" in payload

                print(f"\n  Auth token claims:", file=sys.stderr)
                print(f"    jti: {payload.get('jti')}", file=sys.stderr)
                print(f"    txn: {'(not present)' if not has_txn else payload['txn']}", file=sys.stderr)

                if not has_txn:
                    test1_passed = True
                    print(f"\n  ✓ txn correctly absent (resource did not include txn)", file=sys.stderr)
                else:
                    test1_error = "txn should not be present when resource has enable_txn=False"
                    print(f"\n  ✗ txn unexpectedly present: {payload['txn']}", file=sys.stderr)
            else:
                test1_error = "No auth token stored on agent"
        else:
            test1_error = f"Status {response.status_code}: {response.text}"
            print(f"\n✗ TEST 1 FAILED: Status {response.status_code}", file=sys.stderr)

    except Exception as e:
        test1_error = str(e)
        print(f"\n✗ TEST 1 FAILED: {e}", file=sys.stderr, flush=True)
        import traceback
        traceback.print_exc()

    status = "✓ PASSED" if test1_passed else "✗ FAILED"
    print(f"\n{status}: TEST 1: Autonomous Authorization Flow (no txn)", file=sys.stderr)
    test_results.append(("TEST 1: Autonomous Authorization (no txn)", test1_passed, test1_error))

    # =========================================================================
    # Test 2: Autonomous authorization flow WITH txn
    # =========================================================================
    print("\n" + "=" * 80, file=sys.stderr)
    print("TEST 2: Autonomous Authorization Flow (with txn)", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print("Description: Resource includes txn in resource token for request", file=sys.stderr)
    print("             correlation. Auth server carries txn forward into auth", file=sys.stderr)
    print("             token per spec Section 16.2.3.", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)

    # Enable txn on the resource for this test
    resource.enable_txn = True
    # Clear agent's stored auth token so autonomous flow runs fresh
    agent.auth_token = None

    test2_passed = False
    test2_error = None

    try:
        response = await run_autonomous_flow(
            agent=agent,
            resource=resource,
            auth_server=auth_server,
            resource_url=f"{resource_id}/data-auth",
            method="GET"
        )

        if response.status_code == 200:
            data = response.json()
            print(f"\n  Access granted: {data.get('message')}", file=sys.stderr)

            # Inspect the auth token
            auth_token = agent.auth_token
            if auth_token:
                claims = parse_token_claims(auth_token)
                payload = claims["payload"]
                auth_txn = payload.get("txn")

                print(f"\n  Auth token claims:", file=sys.stderr)
                print(f"    jti: {payload.get('jti')}", file=sys.stderr)
                print(f"    txn: {auth_txn or '(not present)'}", file=sys.stderr)

                if auth_txn:
                    # Verify it's a valid UUID (that's what we generate)
                    import uuid
                    try:
                        uuid.UUID(auth_txn)
                        test2_passed = True
                        print(f"\n  ✓ txn present and valid: {auth_txn}", file=sys.stderr)
                        print(f"    This txn correlates the resource token, auth token,", file=sys.stderr)
                        print(f"    and original request across all parties and audit logs.", file=sys.stderr)
                    except ValueError:
                        test2_error = f"txn is not a valid UUID: {auth_txn}"
                        print(f"\n  ✗ txn format invalid: {auth_txn}", file=sys.stderr)
                else:
                    test2_error = "txn should be present when resource has enable_txn=True"
                    print(f"\n  ✗ txn missing from auth token", file=sys.stderr)
            else:
                test2_error = "No auth token stored on agent"
        else:
            test2_error = f"Status {response.status_code}: {response.text}"
            print(f"\n✗ TEST 2 FAILED: Status {response.status_code}", file=sys.stderr)

    except Exception as e:
        test2_error = str(e)
        print(f"\n✗ TEST 2 FAILED: {e}", file=sys.stderr, flush=True)
        import traceback
        traceback.print_exc()

    # Reset txn flag
    resource.enable_txn = False

    status = "✓ PASSED" if test2_passed else "✗ FAILED"
    print(f"\n{status}: TEST 2: Autonomous Authorization Flow (with txn)", file=sys.stderr)
    test_results.append(("TEST 2: Autonomous Authorization (with txn)", test2_passed, test2_error))

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

    # Keep servers running
    print("Servers are still running. Press Ctrl+C to stop.", file=sys.stderr, flush=True)
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping servers...", file=sys.stderr, flush=True)


if __name__ == "__main__":
    asyncio.run(main())
