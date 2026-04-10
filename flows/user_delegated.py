"""User delegation flow orchestrator for Phase 4.

When ``agent.mm_url`` is set, token **POST**s go to the Mission Manager; the
user simulator should complete interaction at the MM or AS as returned in the
202 response (see ``Agent._handle_deferred_response``).
"""

import asyncio
import sys
import json
from typing import Optional
import httpx

from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AuthServer
from participants.user_simulator import UserSimulator
from aauth.debug import _is_debug_enabled, _is_jwt_token_debug_enabled
from aauth.tokens.auth_token import parse_token_claims


async def run_user_delegated_flow(
    agent: Agent,
    resource: Resource,
    auth_server: AuthServer,
    user_simulator: UserSimulator,
    resource_url: str = "http://127.0.0.1:8002/data-auth",
    method: str = "GET"
) -> httpx.Response:
    """Run the complete user delegation flow (automated with user simulator).

    Flow (SPEC_UPDATED.md Sections 4.5.4, 10):
    1. Agent requests resource (401 + resource token in AAuth header)
    2. Agent POSTs resource token to auth server token endpoint → 202 + Location + interaction code
    3. User simulator completes consent at auth server /interact
    4. Agent polls pending URL (GET) until 200 with auth_token
    5. Agent retries resource request with auth token
    6. Resource validates auth token and grants access

    Args:
        agent: Agent instance
        resource: Resource instance
        auth_server: Auth server instance
        user_simulator: User simulator instance
        resource_url: Resource URL to access
        method: HTTP method
        
    Returns:
        Final HTTP response from resource
    """
    debug = _is_debug_enabled()
    
    if debug:
        print("\n" + "=" * 80, file=sys.stderr)
        print("PHASE 4: USER DELEGATION FLOW (Automated)", file=sys.stderr)
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
        sig_scheme="jwks_uri"
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
    
    # Steps 2–5: Agent handles 401, token POST, 202 + pending URL, polling, retry with auth token.
    if debug:
        print("\nSteps 2-5: Agent handled challenge, deferred response (202), and polling", file=sys.stderr, flush=True)
        if agent.auth_token:
            print(f"Agent now has auth token: {agent.auth_token[:100]}...", file=sys.stderr, flush=True)
        else:
            print("Agent does not have auth token - flow may have failed", file=sys.stderr, flush=True)
    
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


async def run_user_delegated_flow_manual(
    agent: Agent,
    resource: Resource,
    auth_server: AuthServer,
    resource_url: str = "http://127.0.0.1:8002/data-auth",
    method: str = "GET"
) -> httpx.Response:
    """Run the user delegation flow with manual browser interaction (placeholder).

    Intended flow (SPEC_UPDATED.md): same as automated — 202, interaction code, /interact,
    polling pending URL for auth_token; there is no authorization code exchange.

    This function is not fully implemented for hands-off manual browser testing; use
    ``demo_phase4.py`` and extend the agent to surface the interaction URL if needed.

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
        print("PHASE 4: USER DELEGATION FLOW (Manual Browser Testing)", file=sys.stderr)
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
        sig_scheme="jwks_uri"
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
    
    # Check if agent has auth token (autonomous flow succeeded)
    if agent.auth_token:
        if debug:
            print("Agent already has auth token (autonomous flow succeeded)", file=sys.stderr, flush=True)
        return response
    
    if debug:
        print("\nNote: Manual browser path not fully wired; use demo_phase4.py --manual or automated flow.", file=sys.stderr, flush=True)
    
    return response


if __name__ == "__main__":
    # Example usage
    agent = Agent("http://127.0.0.1:8001", port=8001)
    resource = Resource("http://127.0.0.1:8002", port=8002, auth_server="http://127.0.0.1:8003")
    auth_server = AuthServer("http://127.0.0.1:8003", port=8003, require_user_consent=True)
    user_sim = UserSimulator()
    
    print("Note: Run agent, resource, and auth_server in separate terminals")
    print("Then call run_user_delegated_flow() with the instances")

