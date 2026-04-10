"""Demo script for Phase 4: User Delegation."""

import asyncio
import sys
import threading
import time
from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AuthServer
from participants.user_simulator import UserSimulator
from flows.user_delegated import run_user_delegated_flow


def run_server(server, name):
    """Run a server in a separate thread."""
    print(f"Starting {name}...", file=sys.stderr, flush=True)
    try:
        server.run()
    except KeyboardInterrupt:
        print(f"{name} stopped", file=sys.stderr, flush=True)


async def main():
    """Run Phase 4 demo."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Phase 4: User Delegation Demo")
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Enable manual browser testing (disables user simulator)"
    )
    args = parser.parse_args()
    
    print("\n" + "=" * 80, file=sys.stderr)
    print("Phase 4: User Delegation Demo", file=sys.stderr)
    print("Optional: set Agent(mm_url=...) so token POSTs go to a Mission Manager.", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    
    if args.manual:
        print("\nMODE: Manual Browser Testing", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("This demo shows the user delegation flow with manual browser interaction:", file=sys.stderr)
        print("1. Agent requests resource (401 + resource token in AAuth header)", file=sys.stderr)
        print("2. Agent POSTs to token endpoint; auth server returns 202 + Location (pending URL)", file=sys.stderr)
        print("3. **OPEN THE INTERACTION URL** (interaction code in 202 body / AAuth header)", file=sys.stderr)
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
        print("This demo shows the complete user delegation flow:", file=sys.stderr)
        print("1. Agent requests resource (401 + resource token in AAuth header)", file=sys.stderr)
        print("2. Agent POSTs to token endpoint; auth server returns 202 + pending URL + interaction code", file=sys.stderr)
        print("3. User simulator completes interaction at /interact (consent)", file=sys.stderr)
        print("4. Agent polls pending URL until auth_token is returned (SPEC_UPDATED Section 10)", file=sys.stderr)
        print("5. Agent retries resource request with auth token", file=sys.stderr)
        print("6. Resource validates auth token and grants access", file=sys.stderr)
    
    print("\nDebug output is enabled by default.", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)
    
    # Create participants
    agent_id = "http://127.0.0.1:8001"
    resource_id = "http://127.0.0.1:8002"
    auth_id = "http://127.0.0.1:8003"
    
    # In manual mode, disable user simulator so agent waits for browser interaction
    use_user_simulator = not args.manual
    
    agent = Agent(agent_id, port=8001, use_user_simulator=use_user_simulator)
    resource = Resource(resource_id, port=8002, auth_server=auth_id)
    auth_server = AuthServer(auth_id, port=8003, require_user_consent=True)
    
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
    if args.manual:
        print("Ready to start test (Manual Browser Testing mode).", file=sys.stderr)
        print("Press Enter to begin...", file=sys.stderr)
    else:
        print("Ready to start test. Press Enter to begin...", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    input()
    
    # Track test results
    test_results = []
    
    # Test 1: User delegation flow
    print("\n" + "=" * 80, file=sys.stderr)
    if args.manual:
        print("TEST 1: User Delegation Flow (Manual Browser Testing)", file=sys.stderr)
    else:
        print("TEST 1: User Delegation Flow (Automated)", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print("Description: Agent gets 401 + resource token, POSTs token endpoint, receives 202 + pending URL,", file=sys.stderr)
    print("             user completes interaction at auth server /interact, agent polls pending URL for auth_token,", file=sys.stderr)
    print("             then retries the resource with scheme=jwt (auth token).", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)
    
    test1_passed = False
    test1_error = None
    
    try:
        if args.manual:
            # Manual mode: full browser-driven interaction is not wired here; we fall back to the user simulator.
            print("\n" + "=" * 80, file=sys.stderr)
            print("MANUAL TESTING MODE", file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            print("Deferred flow uses 202 + pending URL + interaction code (SPEC_UPDATED Sections 4.5.4, 10).", file=sys.stderr)
            print(f"Open {auth_id}/interact?code=<code> when the agent logs the interaction URL.", file=sys.stderr)
            print("This script currently falls back to the user simulator for the same steps.", file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)

            # Make initial request
            response = await agent.request_resource(
                resource_url=f"{resource_id}/data-auth",
                method="GET",
                sig_scheme="jwks_uri"
            )
            
            print("\n" + "=" * 80, file=sys.stderr)
            print("NOTE: True manual mode would pause and print the interaction URL from the 202 response.", file=sys.stderr)
            print("Continuing with the user simulator (same protocol path as automated mode).", file=sys.stderr)
            print("=" * 80 + "\n", file=sys.stderr)
            
            # Fall back to automated flow
            user_sim = UserSimulator()
            response = await run_user_delegated_flow(
                agent=agent,
                resource=resource,
                auth_server=auth_server,
                user_simulator=user_sim,
                resource_url=f"{resource_id}/data-auth",
                method="GET"
            )
        else:
            # Automated flow with user simulator
            user_sim = UserSimulator()
            response = await run_user_delegated_flow(
                agent=agent,
                resource=resource,
                auth_server=auth_server,
                user_simulator=user_sim,
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
    
    test_results.append(("TEST 1: User Delegation Flow", test1_passed, test1_error))
    
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
    if args.manual:
        print("\n" + "=" * 80, file=sys.stderr)
        print("MANUAL TESTING INSTRUCTIONS", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("To test manually:", file=sys.stderr)
        print("1. Run without --manual so the user simulator drives /interact, or extend the agent to print", file=sys.stderr)
        print("   the interaction URL from the 202 response (code in JSON body / AAuth header).", file=sys.stderr)
        print("2. Open the interaction URL in your browser, e.g.:", file=sys.stderr)
        print(f"   {auth_id}/interact?code=<interaction_code>&callback=<optional_callback_url>", file=sys.stderr)
        print("3. Login with: testuser / testpass", file=sys.stderr)
        print("4. Grant consent", file=sys.stderr)
        print(f"5. Agent polls GET {auth_id}/pending/<id> until 200 with auth_token (no OAuth authorization code)", file=sys.stderr)
        print("=" * 80 + "\n", file=sys.stderr)
    
    print("Servers are still running. Press Ctrl+C to stop.", file=sys.stderr, flush=True)
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping servers...", file=sys.stderr, flush=True)


if __name__ == "__main__":
    asyncio.run(main())

