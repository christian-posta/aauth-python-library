"""Autonomous authorization flow orchestrator for Phase 3."""

import asyncio
import sys
import json
from typing import Optional
import httpx

from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AuthServer
from core import _is_debug_enabled, _is_jwt_token_debug_enabled
from aauth.tokens.auth_token import parse_token_claims


async def run_autonomous_flow(
    agent: Agent,
    resource: Resource,
    auth_server: AuthServer,
    resource_url: str = "http://127.0.0.1:8002/data-auth",
    method: str = "GET"
) -> httpx.Response:
    """Run the complete autonomous authorization flow.
    
    Flow:
    1. Agent requests resource (gets resource token challenge)
    2. Agent presents resource token to auth server
    3. Auth server issues auth token
    4. Agent retries resource request with auth token
    5. Resource validates auth token and grants access
    
    Args:
        agent: Agent instance
        resource: Resource instance
        auth_server: Auth server instance
        resource_url: Resource URL to access
        method: HTTP method
        
    Returns:
        Final HTTP response from resource
    """
    debug = _is_debug_enabled()
    
    if debug:
        print("\n" + "=" * 80, file=sys.stderr)
        print("PHASE 3: AUTONOMOUS AUTHORIZATION FLOW", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print(f"Agent: {agent.agent_id}", file=sys.stderr)
        print(f"Resource: {resource.resource_id}", file=sys.stderr)
        print(f"Auth Server: {auth_server.auth_id}", file=sys.stderr)
        print(f"Resource URL: {resource_url}", file=sys.stderr)
        print("=" * 80 + "\n", file=sys.stderr)
    
    # Step 1: Agent requests resource (should get resource token challenge)
    if debug:
        print("Step 1: Agent requests resource (expecting resource token challenge)", file=sys.stderr, flush=True)
    
    response = await agent.request_resource(
        resource_url=resource_url,
        method=method,
        sig_scheme="jwks"  # Use agent identity
    )
    
    if debug:
        print(f"Step 1 result: Status {response.status_code}", file=sys.stderr, flush=True)
        if response.status_code == 200:
            print("Step 1: SUCCESS - Resource granted access immediately", file=sys.stderr, flush=True)
            return response
        elif response.status_code == 401:
            print("Step 1: Received 401 challenge (expected)", file=sys.stderr, flush=True)
        else:
            print(f"Step 1: Unexpected status code: {response.status_code}", file=sys.stderr, flush=True)
            return response
    
    # Extract and decode resource token (if JWT token debug is enabled)
    # Note: The agent stores the resource_token when it receives the 401 challenge,
    # so we can access it from agent.resource_token even if the response is already 200 (after retry)
    jwt_token_debug = _is_jwt_token_debug_enabled()
    if jwt_token_debug and agent.resource_token:
        print("\n" + "=" * 80, file=sys.stderr, flush=True)
        print("RESOURCE TOKEN (decoded)", file=sys.stderr, flush=True)
        print("=" * 80, file=sys.stderr, flush=True)
        try:
            claims = parse_token_claims(agent.resource_token)
            print(f"Header:", file=sys.stderr, flush=True)
            print(json.dumps(claims["header"], indent=2), file=sys.stderr, flush=True)
            print(f"\nPayload:", file=sys.stderr, flush=True)
            print(json.dumps(claims["payload"], indent=2), file=sys.stderr, flush=True)
            print("=" * 80 + "\n", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"Failed to decode resource token: {e}", file=sys.stderr, flush=True)
    
    # Step 2-4: Agent should have automatically handled the challenge
    # (request_resource handles 401 responses and retries with auth token)
    if debug:
        print("\nSteps 2-4: Agent automatically handled challenge and retried with auth token", file=sys.stderr, flush=True)
        if agent.auth_token:
            print(f"Agent now has auth token: {agent.auth_token[:100]}...", file=sys.stderr, flush=True)
        else:
            print("Agent does not have auth token - challenge handling may have failed", file=sys.stderr, flush=True)
    
    # Decode and print auth token (if JWT token debug is enabled)
    if jwt_token_debug and agent.auth_token:
        print("\n" + "=" * 80, file=sys.stderr, flush=True)
        print("AUTH TOKEN (decoded)", file=sys.stderr, flush=True)
        print("=" * 80, file=sys.stderr, flush=True)
        try:
            claims = parse_token_claims(agent.auth_token)
            print(f"Header:", file=sys.stderr, flush=True)
            print(json.dumps(claims["header"], indent=2), file=sys.stderr, flush=True)
            print(f"\nPayload:", file=sys.stderr, flush=True)
            print(json.dumps(claims["payload"], indent=2), file=sys.stderr, flush=True)
            print("=" * 80 + "\n", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"Failed to decode auth token: {e}", file=sys.stderr, flush=True)
    
    # The response should be the final response after retry
    if debug:
        print(f"\nFinal result: Status {response.status_code}", file=sys.stderr, flush=True)
        if response.status_code == 200:
            print("SUCCESS: Resource granted access with auth token", file=sys.stderr, flush=True)
        else:
            print(f"FAILED: Resource returned status {response.status_code}", file=sys.stderr, flush=True)
            try:
                error_text = response.text
                print(f"Error: {error_text}", file=sys.stderr, flush=True)
            except:
                pass
    
    return response


if __name__ == "__main__":
    # Example usage
    agent = Agent("http://127.0.0.1:8001", port=8001)
    resource = Resource("http://127.0.0.1:8002", port=8002, auth_server="http://127.0.0.1:8003")
    auth_server = AuthServer("http://127.0.0.1:8003", port=8003)
    
    # Note: In a real scenario, you'd run these in separate processes
    # This is just for demonstration
    print("Note: Run agent, resource, and auth_server in separate terminals")
    print("Then call run_autonomous_flow() with the instances")

