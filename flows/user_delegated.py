"""User delegation flow orchestrator for Phase 4."""

import asyncio
import sys
from typing import Optional
import httpx

from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AuthServer
from participants.user_simulator import UserSimulator


def _is_debug_enabled(env_var: str = "AAUTH_DEBUG") -> bool:
    """Check if debug is enabled (defaults to True unless explicitly disabled)."""
    import os
    value = os.environ.get(env_var, "1")
    return value.lower() not in ("0", "false", "no", "off", "")


async def run_user_delegated_flow(
    agent: Agent,
    resource: Resource,
    auth_server: AuthServer,
    user_simulator: UserSimulator,
    resource_url: str = "http://127.0.0.1:8002/data-auth",
    method: str = "GET"
) -> httpx.Response:
    """Run the complete user delegation flow (automated with user simulator).
    
    Flow:
    1. Agent requests resource (gets resource token challenge)
    2. Agent presents resource token to auth server (gets request_token)
    3. User simulator completes consent flow
    4. Agent exchanges authorization code for auth token
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
        sig_scheme="jwks"
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
    
    # Step 2-5: Agent should have automatically handled the challenge
    # (request_resource handles 401, gets request_token, uses user simulator, exchanges code)
    if debug:
        print("\nSteps 2-5: Agent automatically handled challenge, user consent, and code exchange", file=sys.stderr, flush=True)
        if agent.auth_token:
            print(f"Agent now has auth token: {agent.auth_token[:100]}...", file=sys.stderr, flush=True)
        else:
            print("Agent does not have auth token - flow may have failed", file=sys.stderr, flush=True)
    
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
    """Run the user delegation flow with manual browser interaction.
    
    Flow:
    1. Agent requests resource (gets resource token challenge)
    2. Agent presents resource token to auth server (gets request_token)
    3. **PAUSES** - Displays URL for user to open in browser
    4. User opens URL, authenticates, and grants consent
    5. Agent detects authorization code from callback
    6. Agent exchanges authorization code for auth token
    7. Agent retries resource request with auth token
    8. Resource validates auth token and grants access
    
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
        sig_scheme="jwks"
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
    
    # Check if we need to handle request_token manually
    # The agent's _request_auth_token should have stored the request_token
    # For manual flow, we need to intercept and display the URL
    
    # For now, the agent will use user simulator automatically
    # In a true manual flow, we'd need to modify the agent to pause and display URL
    # This will be handled in the demo script
    
    if debug:
        print("\nNote: For true manual testing, use demo_phase4.py", file=sys.stderr, flush=True)
        print("This flow uses user simulator for automated testing", file=sys.stderr, flush=True)
    
    return response


if __name__ == "__main__":
    # Example usage
    agent = Agent("http://127.0.0.1:8001", port=8001)
    resource = Resource("http://127.0.0.1:8002", port=8002, auth_server="http://127.0.0.1:8003")
    auth_server = AuthServer("http://127.0.0.1:8003", port=8003, require_user_consent=True)
    user_sim = UserSimulator()
    
    print("Note: Run agent, resource, and auth_server in separate terminals")
    print("Then call run_user_delegated_flow() with the instances")

