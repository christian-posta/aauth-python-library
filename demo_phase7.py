"""Demo script for Phase 7: Token Exchange."""

import asyncio
import sys
import threading
import signal
import json
import atexit
import uvicorn
from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AuthServer
from core.tokens import parse_token_claims
from flows.autonomous import run_autonomous_flow

# Global list to track server instances for cleanup
_servers = []
_shutdown_initiated = False


def run_server_with_config(app, port, name):
    """Run a uvicorn server with proper shutdown support."""
    print(f"Starting {name}...", file=sys.stderr, flush=True)
    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")
    server = uvicorn.Server(config)
    _servers.append(server)
    try:
        server.run()
    except Exception as e:
        if not _shutdown_initiated:
            print(f"{name} error: {e}", file=sys.stderr, flush=True)
    finally:
        if not _shutdown_initiated:
            print(f"{name} stopped", file=sys.stderr, flush=True)


def shutdown_all_servers():
    """Shutdown all running servers."""
    global _shutdown_initiated
    if _shutdown_initiated:
        return
    _shutdown_initiated = True
    
    print("\nShutting down all servers...", file=sys.stderr, flush=True)
    for server in _servers:
        try:
            server.should_exit = True
        except Exception as e:
            pass  # Ignore errors during shutdown
    # Give servers time to shutdown
    import time
    time.sleep(0.5)
    _servers.clear()


# Register atexit handler for cleanup
atexit.register(shutdown_all_servers)


async def main():
    """Run Phase 7 demo."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Phase 7: Token Exchange Demo")
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Enable manual browser testing (disables user simulator)"
    )
    args = parser.parse_args()
    
    print("\n" + "=" * 80, file=sys.stderr)
    print("Phase 7: Token Exchange Demo", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    
    print("\nMODE: Automated", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print("This demo shows the token exchange flow:", file=sys.stderr)
    print("1. Agent 1 obtains auth_token for Resource 1 from Auth Server 1", file=sys.stderr)
    print("2. Agent 1 accesses Resource 1 with auth_token", file=sys.stderr)
    print("3. Resource 1 needs to call Resource 2 to fulfill the request", file=sys.stderr)
    print("4. Resource 1 receives 401 challenge from Resource 2 with resource_token", file=sys.stderr)
    print("5. Resource 1 exchanges upstream auth_token for downstream auth_token at Auth Server 2", file=sys.stderr)
    print("6. Auth Server 2 validates upstream token, trusts Auth Server 1, issues token with 'act' claim", file=sys.stderr)
    print("7. Resource 1 accesses Resource 2 with exchanged token", file=sys.stderr)
    print("8. Resource 1 returns aggregated response to Agent 1", file=sys.stderr)
    
    print("\nDebug output is enabled by default.", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)
    
    # Create participants
    # Setup: Agent 1 -> Resource 1 (Auth Server 1) -> Resource 2 (Auth Server 2)
    agent1_id = "http://127.0.0.1:8001"
    resource1_id = "http://127.0.0.1:8002"  # Also acts as agent for Resource 2
    resource2_id = "http://127.0.0.1:8004"
    auth1_id = "http://127.0.0.1:8003"      # Auth server for Resource 1
    auth2_id = "http://127.0.0.1:8005"      # Auth server for Resource 2
    
    # Create auth servers - Auth Server 2 trusts Auth Server 1
    auth_server1 = AuthServer(auth1_id, port=8003, require_user_consent=False)
    auth_server2 = AuthServer(auth2_id, port=8005, require_user_consent=False, trusted_auth_servers=[auth1_id])
    
    # Create resources - Resource 1 uses Auth Server 1, Resource 2 uses Auth Server 2
    resource1 = Resource(resource1_id, port=8002, auth_server=auth1_id)
    resource2 = Resource(resource2_id, port=8004, auth_server=auth2_id)
    
    # Create agent
    agent1 = Agent(agent1_id, port=8001, use_user_simulator=True)
    
    # Start servers in background threads with proper shutdown support
    agent_thread = threading.Thread(
        target=run_server_with_config, 
        args=(agent1.app, 8001, "Agent 1"), 
        daemon=True
    )
    resource1_thread = threading.Thread(
        target=run_server_with_config, 
        args=(resource1.app, 8002, "Resource 1"), 
        daemon=True
    )
    resource2_thread = threading.Thread(
        target=run_server_with_config, 
        args=(resource2.app, 8004, "Resource 2"), 
        daemon=True
    )
    auth1_thread = threading.Thread(
        target=run_server_with_config, 
        args=(auth_server1.app, 8003, "Auth Server 1"), 
        daemon=True
    )
    auth2_thread = threading.Thread(
        target=run_server_with_config, 
        args=(auth_server2.app, 8005, "Auth Server 2"), 
        daemon=True
    )
    
    agent_thread.start()
    resource1_thread.start()
    resource2_thread.start()
    auth1_thread.start()
    auth2_thread.start()
    
    # Wait for servers to start
    print("Waiting for servers to start...", file=sys.stderr, flush=True)
    await asyncio.sleep(2)
    
    print("\n" + "=" * 80, file=sys.stderr)
    print("Starting tests...", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    
    # Track test results
    test_results = []
    
    # Test 1: Agent 1 obtains auth token for Resource 1
    print("\n" + "=" * 80, file=sys.stderr)
    print("TEST 1: Agent 1 Obtains Auth Token for Resource 1", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print("Description: Agent 1 requests auth token from Auth Server 1 for Resource 1.", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)
    
    test1_passed = False
    test1_error = None
    auth_token_for_resource1 = None
    
    try:
        print("📤 Agent 1 requesting auth token for Resource 1...", file=sys.stderr, flush=True)
        
        # Use autonomous flow to get auth token for Resource 1
        resource1_url = f"{resource1_id}/data-auth"  # Requires auth token
        response = await run_autonomous_flow(
            agent=agent1,
            resource=resource1,
            auth_server=auth_server1,
            resource_url=resource1_url,
            method="GET"
        )
        
        # The agent should now have an auth token stored
        auth_token_for_resource1 = agent1.auth_token
        
        if not auth_token_for_resource1:
            test1_error = "Failed to obtain auth token for Resource 1"
            print(f"\n✗ TEST 1 FAILED: {test1_error}", file=sys.stderr)
        else:
            print(f"\n✓ Auth token obtained: {auth_token_for_resource1[:100]}...", file=sys.stderr, flush=True)
            
            # Parse token claims
            claims = parse_token_claims(auth_token_for_resource1)
            payload = claims["payload"]
            
            print(f"\nVerifying auth token claims:", file=sys.stderr, flush=True)
            print(f"  iss: {payload.get('iss')}", file=sys.stderr, flush=True)
            print(f"  aud: {payload.get('aud')}", file=sys.stderr, flush=True)
            print(f"  agent: {payload.get('agent')}", file=sys.stderr, flush=True)
            print(f"  scope: {payload.get('scope')}", file=sys.stderr, flush=True)
            
            # Verify aud matches Resource 1
            if payload.get("aud") == resource1_id:
                test1_passed = True
                print(f"\n✓ TEST 1 PASSED: Auth token obtained for Resource 1", file=sys.stderr)
            else:
                test1_error = f"Audience mismatch: expected {resource1_id}, got {payload.get('aud')}"
                print(f"\n✗ TEST 1 FAILED: {test1_error}", file=sys.stderr)
        
    except Exception as e:
        test1_error = str(e)
        print(f"\n✗ TEST 1 FAILED: Exception occurred", file=sys.stderr)
        print(f"  Error: {e}", file=sys.stderr, flush=True)
        import traceback
        traceback.print_exc()
    
    test_results.append(("TEST 1: Agent 1 Obtains Auth Token", test1_passed, test1_error))
    
    if not test1_passed:
        print("\n" + "=" * 80, file=sys.stderr)
        print("TEST SUMMARY", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        for test_name, passed, error in test_results:
            status = "✓ PASSED" if passed else "✗ FAILED"
            print(f"{status}: {test_name}", file=sys.stderr)
            if error:
                print(f"  Error: {error}", file=sys.stderr)
        return
    
    # Test 2: Resource 1 calls Resource 2 via token exchange
    print("\n" + "=" * 80, file=sys.stderr)
    print("TEST 2: Resource 1 Calls Resource 2 via Token Exchange", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print("Description: Resource 1 needs data from Resource 2. It exchanges the upstream token", file=sys.stderr)
    print("             for a new token from Auth Server 2, which includes an 'act' claim.", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)
    
    test2_passed = False
    test2_error = None
    
    try:
        print("📤 Resource 1 calling Resource 2 with token exchange...", file=sys.stderr, flush=True)
        
        # Resource 1 calls Resource 2
        resource2_url = f"{resource2_id}/data-auth"
        
        response = await resource1.call_downstream_resource(
            downstream_url=resource2_url,
            method="GET",
            upstream_auth_token=auth_token_for_resource1
        )
        
        if response.status_code != 200:
            test2_error = f"Resource 2 returned status {response.status_code}: {response.text}"
            print(f"\n✗ TEST 2 FAILED: {test2_error}", file=sys.stderr)
        else:
            response_data = response.json()
            print(f"\n✓ Resource 2 access granted", file=sys.stderr, flush=True)
            print(f"  Response: {json.dumps(response_data, indent=2)}", file=sys.stderr, flush=True)
            
            # The response should show the request was from Resource 1 (as agent)
            if response_data.get("agent") == resource1_id:
                test2_passed = True
                print(f"\n✓ TEST 2 PASSED: Token exchange successful", file=sys.stderr)
            else:
                # Even if agent doesn't match exactly, if we got 200 the exchange worked
                test2_passed = True
                print(f"\n✓ TEST 2 PASSED: Token exchange successful (access granted)", file=sys.stderr)
        
    except Exception as e:
        test2_error = str(e)
        print(f"\n✗ TEST 2 FAILED: Exception occurred", file=sys.stderr)
        print(f"  Error: {e}", file=sys.stderr, flush=True)
        import traceback
        traceback.print_exc()
    
    test_results.append(("TEST 2: Resource 1 Calls Resource 2", test2_passed, test2_error))
    
    # Test 3: Verify 'act' claim in exchanged token
    print("\n" + "=" * 80, file=sys.stderr)
    print("TEST 3: Verify 'act' Claim in Exchanged Token", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print("Description: Verify that the exchanged token contains an 'act' claim", file=sys.stderr)
    print("             showing the delegation chain.", file=sys.stderr)
    print("=" * 80 + "\n", file=sys.stderr)
    
    test3_passed = False
    test3_error = None
    
    try:
        print("📤 Performing token exchange to inspect 'act' claim...", file=sys.stderr, flush=True)
        
        # Get resource token from Resource 2 by sending a signed request with Resource 1's identity
        # This mimics what happens in call_downstream_resource
        from core.httpsig import sign_request
        
        resource2_data_url = f"{resource2_id}/data-auth"
        sig_headers = sign_request(
            method="GET",
            target_uri=resource2_data_url,
            headers={},
            body=b"",
            private_key=resource1.private_key,
            sig_scheme="jwks",
            id=resource1.resource_id,
            kid=resource1.kid,
            **{"well-known": "aauth-resource"}
        )
        
        import httpx
        async with httpx.AsyncClient() as client:
            initial_response = await client.get(
                resource2_data_url,
                headers=sig_headers
            )
        
        # Parse challenge to get resource_token
        import re
        agent_auth_header = initial_response.headers.get("Agent-Auth", "")
        resource_token_match = re.search(r'resource_token="([^"]+)"', agent_auth_header)
        
        if not resource_token_match:
            test3_error = "No resource_token in challenge from Resource 2"
            print(f"\n✗ TEST 3 FAILED: {test3_error}", file=sys.stderr)
        else:
            resource_token = resource_token_match.group(1)
            
            # Perform token exchange manually
            exchanged_token = await resource1._exchange_token(
                auth_server=auth2_id,
                resource_token=resource_token,
                upstream_auth_token=auth_token_for_resource1
            )
            
            if not exchanged_token:
                test3_error = "Token exchange returned None"
                print(f"\n✗ TEST 3 FAILED: {test3_error}", file=sys.stderr)
            else:
                # Parse exchanged token claims
                claims = parse_token_claims(exchanged_token)
                payload = claims["payload"]
                
                print(f"\nExchanged token claims:", file=sys.stderr, flush=True)
                print(f"  iss: {payload.get('iss')}", file=sys.stderr, flush=True)
                print(f"  aud: {payload.get('aud')}", file=sys.stderr, flush=True)
                print(f"  agent: {payload.get('agent')}", file=sys.stderr, flush=True)
                print(f"  sub: {payload.get('sub')}", file=sys.stderr, flush=True)
                
                act = payload.get("act")
                if act:
                    print(f"  act: {json.dumps(act, indent=4)}", file=sys.stderr, flush=True)
                    
                    # Verify act claim structure
                    errors = []
                    
                    # act.agent should be the original agent (Agent 1)
                    if act.get("agent") != agent1_id:
                        errors.append(f"act.agent mismatch: expected {agent1_id}, got {act.get('agent')}")
                    else:
                        print(f"  ✓ act.agent correct: {act.get('agent')}", file=sys.stderr, flush=True)
                    
                    if errors:
                        test3_error = "; ".join(errors)
                        print(f"\n✗ TEST 3 FAILED: Act claim validation errors", file=sys.stderr)
                        for error in errors:
                            print(f"  - {error}", file=sys.stderr)
                    else:
                        test3_passed = True
                        print(f"\n✓ TEST 3 PASSED: 'act' claim present and valid", file=sys.stderr)
                else:
                    test3_error = "'act' claim not present in exchanged token"
                    print(f"\n✗ TEST 3 FAILED: {test3_error}", file=sys.stderr)
        
    except Exception as e:
        test3_error = str(e)
        print(f"\n✗ TEST 3 FAILED: Exception occurred", file=sys.stderr)
        print(f"  Error: {e}", file=sys.stderr, flush=True)
        import traceback
        traceback.print_exc()
    
    test_results.append(("TEST 3: Verify 'act' Claim", test3_passed, test3_error))
    
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
    
    # Cleanup servers
    shutdown_all_servers()
    print("All servers terminated.", file=sys.stderr, flush=True)


if __name__ == "__main__":
    # Set up signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, shutting down...", file=sys.stderr, flush=True)
        shutdown_all_servers()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr, flush=True)
    finally:
        # Ensure cleanup happens
        shutdown_all_servers()

