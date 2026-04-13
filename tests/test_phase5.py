"""Tests for Phase 5: Agent is Resource."""

import pytest
import asyncio
import threading
import time
from participants.agent import Agent
from participants.auth_server import AuthServer
from participants.user_simulator import UserSimulator
from aauth.tokens.auth_token import parse_token_claims


def run_server(server):
    """Run a server in a separate thread."""
    try:
        server.run()
    except:
        pass


@pytest.fixture
def agent_id():
    return "http://127.0.0.1:8001"


@pytest.fixture
def auth_id():
    return "http://127.0.0.1:8003"


@pytest.fixture
def agent(agent_id):
    return Agent(agent_id, port=8001, use_user_simulator=True)


@pytest.fixture
def auth_server(auth_id):
    return AuthServer(auth_id, port=8003, require_user_consent=True)


@pytest.mark.asyncio
async def test_agent_is_resource_flow(agent, auth_server, agent_id, auth_id):
    """Test that agent can request authorization to itself."""
    # Start agent server so auth server can fetch JWKS for signature verification
    agent_thread = threading.Thread(target=run_server, args=(agent,), daemon=True)
    agent_thread.start()

    # Start auth server in background
    auth_thread = threading.Thread(target=run_server, args=(auth_server,), daemon=True)
    auth_thread.start()

    # Wait for servers to start
    await asyncio.sleep(1)
    
    try:
        # Request self-authorization
        scope = "profile email"
        redirect_uri = f"{agent_id}/callback"
        
        auth_token = await agent.request_self_authorization(
            scope=scope,
            auth_server=auth_id,
            redirect_uri=redirect_uri
        )
        
        # Verify token was obtained
        assert auth_token is not None, "Auth token should be obtained"
        
        # Parse token claims
        claims = parse_token_claims(auth_token)
        payload = claims["payload"]
        
        # Verify aud = agent identifier
        assert payload.get("aud") == agent_id, f"aud should be agent identifier, got {payload.get('aud')}"
        
        # Verify agent claim is present (required by spec Section 9.1)
        assert "agent" in payload, "agent claim is required per spec Section 9.1"

        # Verify sub claim is present (user identifier)
        assert payload.get("sub") is not None, "sub claim should be present after user consent"
        
        # Verify scope
        assert payload.get("scope") == scope, f"scope should match requested scope, got {payload.get('scope')}"
        
    finally:
        # Cleanup
        pass


@pytest.mark.asyncio
async def test_auth_token_claims_when_agent_is_resource(agent, auth_server, agent_id, auth_id):
    """Test that auth token has correct claims when agent is resource."""
    # Start agent server so auth server can fetch JWKS for signature verification
    agent_thread = threading.Thread(target=run_server, args=(agent,), daemon=True)
    agent_thread.start()

    # Start auth server in background
    auth_thread = threading.Thread(target=run_server, args=(auth_server,), daemon=True)
    auth_thread.start()

    # Wait for servers to start
    await asyncio.sleep(1)
    
    try:
        # Request self-authorization
        scope = "profile email"
        redirect_uri = f"{agent_id}/callback"
        
        auth_token = await agent.request_self_authorization(
            scope=scope,
            auth_server=auth_id,
            redirect_uri=redirect_uri
        )
        
        assert auth_token is not None
        
        # Parse and verify claims
        claims = parse_token_claims(auth_token)
        payload = claims["payload"]
        header = claims["header"]
        
        # Verify token type
        assert header.get("typ") == "aa-auth+jwt", "Token type should be aa-auth+jwt"
        
        # Verify aud = agent identifier
        assert payload.get("aud") == agent_id
        
        # Verify agent claim is present (required by spec Section 9.1)
        assert "agent" in payload

        # Verify sub is present
        assert "sub" in payload
        assert payload.get("sub") == "testuser"  # From user simulator
        
        # Verify scope
        assert payload.get("scope") == scope
        
        # Verify cnf.jwk is present
        assert "cnf" in payload
        assert "jwk" in payload["cnf"]
        
    finally:
        pass

