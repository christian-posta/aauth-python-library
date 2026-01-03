"""Demo script for Phase 5: Agent is Resource."""

import asyncio
import sys
import threading
import json
from participants.agent import Agent
from participants.auth_server import AuthServer
from participants.user_simulator import UserSimulator
from core.tokens import parse_token_claims


def run_server(server, name):
    """Run a server in a separate thread."""
    print(f"Starting {name}...", file=sys.stderr, flush=True)
    try:
        server.run()
    except KeyboardInterrupt:
        print(f"{name} stopped", file=sys.stderr, flush=True)


async def main():
    """Run Phase 5 demo."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Phase 5: Agent is Resource Demo")
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Enable manual browser testing (disables user simulator)"
    )
    args = parser.parse_args()
    
    print("\n" + "=" * 80, file=sys.stderr)
    print("Phase 5: Agent is Resource Demo", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    
    if args.manual:
        print("\nMODE: Manual Browser Testing", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("This demo shows the agent-is-resource flow with manual browser interaction:", file=sys.stderr)
        print("1. Agent requests self-authorization with scope (no resource_token)", file=sys.stderr)
        print("2. Auth server returns request_token", file=sys.stderr)
        print("3. **YOU WILL BE PROMPTED TO OPEN A URL IN YOUR BROWSER**", file=sys.stderr)
        print("4. Authenticate and grant consent in the browser", file=sys.stderr)
        print("5. Agent exchanges authorization code for auth token", file=sys.stderr)
        print("6. Verify auth token claims (aud=agent, agent omitted, sub present)", file=sys.stderr)
        print("\nDemo Credentials:", file=sys.stderr)
        print("  Username: testuser", file=sys.stderr)
        print("  Password: testpass", file=sys.stderr)
    else:
        print("\nMODE: Automated (with User Simulator)", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("This demo shows the complete agent-is-resource flow:", file=sys.stderr)
        print("1. Agent requests self-authorization with scope (no resource_token)", file=sys.stderr)
        print("2. Auth server returns request_token", file=sys.stderr)
        print("3. User simulator completes consent flow automatically", file=sys.stderr)
        print("4. Agent exchanges authorization code for auth token", file=sys.stderr)
        print("5. Verify auth token claims (aud=agent, agent omitted, sub present)", file=sys.stderr)
    
    print("\nDebug output is enabled by default.", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)
    
    # Create participants
    agent_id = "http://127.0.0.1:8001"
    auth_id = "http://127.0.0.1:8003"
    
    # In manual mode, disable user simulator so agent waits for browser interaction
    use_user_simulator = not args.manual
    
    agent = Agent(agent_id, port=8001, use_user_simulator=use_user_simulator)
    auth_server = AuthServer(auth_id, port=8003, require_user_consent=True)
    
    # Start servers in background threads
    agent_thread = threading.Thread(target=run_server, args=(agent, "Agent"), daemon=True)
    auth_thread = threading.Thread(target=run_server, args=(auth_server, "Auth Server"), daemon=True)
    
    agent_thread.start()
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
    
    # Test 1: Agent requests self-authorization
    print("\n" + "=" * 80, file=sys.stderr)
    if args.manual:
        print("TEST 1: Agent is Resource Flow (Manual Browser Testing)", file=sys.stderr)
    else:
        print("TEST 1: Agent is Resource Flow (Automated)", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print("Description: Agent requests self-authorization with scope, user grants consent,", file=sys.stderr)
    print("             agent receives auth token with aud=agent and agent claim omitted.", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)
    
    test1_passed = False
    test1_error = None
    
    try:
        # Request self-authorization
        scope = "profile email"
        redirect_uri = f"{agent_id}/callback"
        
        print(f"Requesting self-authorization with scope: {scope}", file=sys.stderr, flush=True)
        auth_token = await agent.request_self_authorization(
            scope=scope,
            auth_server=auth_id,
            redirect_uri=redirect_uri
        )
        
        if not auth_token:
            test1_error = "Failed to obtain auth token"
            print(f"\n✗ TEST 1 FAILED: {test1_error}", file=sys.stderr)
        else:
            # Verify auth token claims
            print(f"\n✓ Auth token obtained: {auth_token[:100]}...", file=sys.stderr, flush=True)
            
            # Parse token claims (without verification for inspection)
            claims = parse_token_claims(auth_token)
            payload = claims["payload"]
            
            print(f"\nVerifying auth token claims:", file=sys.stderr, flush=True)
            print(f"  Token payload: {json.dumps(payload, indent=2)}", file=sys.stderr, flush=True)
            
            # Verify claims
            errors = []
            
            # Check aud = agent identifier
            if payload.get("aud") != agent_id:
                errors.append(f"aud claim mismatch: expected {agent_id}, got {payload.get('aud')}")
            else:
                print(f"  ✓ aud claim correct: {payload.get('aud')}", file=sys.stderr, flush=True)
            
            # Check agent claim is omitted
            if "agent" in payload:
                errors.append(f"agent claim should be omitted but was present: {payload.get('agent')}")
            else:
                print(f"  ✓ agent claim correctly omitted", file=sys.stderr, flush=True)
            
            # Check sub claim is present (user identifier)
            if not payload.get("sub"):
                errors.append("sub claim missing (user identifier should be present)")
            else:
                print(f"  ✓ sub claim present: {payload.get('sub')}", file=sys.stderr, flush=True)
            
            # Check scope
            if payload.get("scope") != scope:
                errors.append(f"scope mismatch: expected {scope}, got {payload.get('scope')}")
            else:
                print(f"  ✓ scope correct: {payload.get('scope')}", file=sys.stderr, flush=True)
            
            if errors:
                test1_error = "; ".join(errors)
                print(f"\n✗ TEST 1 FAILED: Token validation errors", file=sys.stderr)
                for error in errors:
                    print(f"  - {error}", file=sys.stderr)
            else:
                test1_passed = True
                print(f"\n✓ TEST 1 PASSED: All token claims validated correctly", file=sys.stderr)
                print(f"  - aud = agent identifier: ✓", file=sys.stderr)
                print(f"  - agent claim omitted: ✓", file=sys.stderr)
                print(f"  - sub (user identifier) present: ✓", file=sys.stderr)
                print(f"  - scope correct: ✓", file=sys.stderr)
        
    except Exception as e:
        test1_error = str(e)
        print(f"\n✗ TEST 1 FAILED: Exception occurred", file=sys.stderr)
        print(f"  Error: {e}", file=sys.stderr, flush=True)
        import traceback
        traceback.print_exc()
    
    test_results.append(("TEST 1: Agent is Resource Flow", test1_passed, test1_error))
    
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
        print("1. The agent will request self-authorization", file=sys.stderr)
        print("2. Open the authorization URL in your browser", file=sys.stderr)
        print("3. Login with: testuser / testpass", file=sys.stderr)
        print("4. Grant consent", file=sys.stderr)
        print("5. The agent will automatically exchange the code for tokens", file=sys.stderr)
        print("=" * 80 + "\n", file=sys.stderr)
    
    print("Servers are still running. Press Ctrl+C to stop.", file=sys.stderr, flush=True)
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping servers...", file=sys.stderr, flush=True)


if __name__ == "__main__":
    asyncio.run(main())

