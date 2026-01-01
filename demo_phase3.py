"""Demo script for Phase 3: Autonomous Authorization."""

import asyncio
import sys
import threading
import time
from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AuthServer
from flows.autonomous import run_autonomous_flow


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
    print("\nDebug output is enabled by default.", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)
    
    # Create participants
    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    auth_id = "http://127.0.0.1:8003"
    
    agent = Agent(agent_id, port=8001)
    resource = Resource(resource_id, port=8002, auth_server=auth_id)
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
    
    # Track test results
    test_results = []
    
    # Test 1: Autonomous authorization flow
    print("\n" + "=" * 80, file=sys.stderr)
    print("TEST 1: Autonomous Authorization Flow", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print("Description: Agent requests protected resource, receives resource token challenge,", file=sys.stderr)
    print("             obtains auth token from auth server, and successfully accesses resource.", file=sys.stderr)
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
            test1_passed = True
            try:
                data = response.json()
                print(f"\n✓ TEST 1 PASSED: Status {response.status_code}", file=sys.stderr)
                print(f"  Response: {data}", file=sys.stderr)
            except:
                print(f"\n✓ TEST 1 PASSED: Status {response.status_code}", file=sys.stderr)
                print(f"  Response text: {response.text}", file=sys.stderr)
        else:
            test1_error = f"Status {response.status_code}: {response.text}"
            print(f"\n✗ TEST 1 FAILED: Status {response.status_code}", file=sys.stderr)
            print(f"  Error: {response.text}", file=sys.stderr)
        
    except Exception as e:
        test1_error = str(e)
        print(f"\n✗ TEST 1 FAILED: Exception occurred", file=sys.stderr)
        print(f"  Error: {e}", file=sys.stderr, flush=True)
        import traceback
        traceback.print_exc()
    
    test_results.append(("TEST 1: Autonomous Authorization Flow", test1_passed, test1_error))
    
    # Print summary
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

