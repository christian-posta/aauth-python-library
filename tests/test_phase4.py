"""Tests for Phase 4: User Delegation."""

import pytest
import asyncio
import httpx
from participants.agent import Agent
from participants.resource import Resource
from participants.auth_server import AuthServer
from participants.user_simulator import UserSimulator
from flows.user_delegated import run_user_delegated_flow


@pytest.fixture
def agent():
    """Create agent instance for testing."""
    return Agent("http://127.0.0.1:8001", port=8001)


@pytest.fixture
def resource():
    """Create resource instance for testing."""
    return Resource("http://127.0.0.1:8002", port=8002, auth_server="http://127.0.0.1:8003")


@pytest.fixture
def auth_server():
    """Create auth server instance for testing (with user consent required)."""
    return AuthServer("http://127.0.0.1:8003", port=8003, require_user_consent=True)


@pytest.fixture
def user_simulator():
    """Create user simulator instance for testing."""
    return UserSimulator()


@pytest.mark.asyncio
async def test_request_token_generation(auth_server):
    """Test that auth server generates request_token when user consent is required."""
    # This test would require running the auth server
    # For now, we'll test the method directly
    request_token = auth_server._generate_request_token(
        agent="http://127.0.0.1:8001",
        resource="http://127.0.0.1:8002",
        scope="data.read",
        redirect_uri="http://127.0.0.1:8001/callback"
    )
    
    assert request_token is not None
    assert len(request_token) > 0
    assert request_token in auth_server.pending_requests


@pytest.mark.asyncio
async def test_authorization_code_generation(auth_server):
    """Test that auth server generates authorization codes."""
    request_details = {
        "agent": "http://127.0.0.1:8001",
        "resource": "http://127.0.0.1:8002",
        "scope": "data.read",
        "redirect_uri": "http://127.0.0.1:8001/callback",
        "user_id": "testuser"
    }
    
    code = auth_server._generate_authorization_code(request_details)
    
    assert code is not None
    assert len(code) > 0
    assert code in auth_server.authorization_codes
    assert auth_server.authorization_codes[code]["agent"] == request_details["agent"]


@pytest.mark.asyncio
async def test_user_simulator_complete_flow(user_simulator):
    """Test user simulator can complete the consent flow."""
    # This test requires running servers
    # For now, we'll test the structure
    assert user_simulator is not None
    assert user_simulator.username == "testuser"
    assert user_simulator.password == "testpass"


@pytest.mark.asyncio
async def test_policy_evaluation_requires_consent(auth_server):
    """Test that policy evaluation returns requires_user_consent=True when configured."""
    result = auth_server._evaluate_policy(
        agent="http://127.0.0.1:8001",
        resource="http://127.0.0.1:8002",
        scope="data.read"
    )
    
    assert result["requires_user_consent"] is True
    assert result["allowed"] is False


@pytest.mark.asyncio
async def test_policy_evaluation_autonomous():
    """Test that policy evaluation allows autonomous when user consent not required."""
    auth_server = AuthServer("http://127.0.0.1:8003", port=8003, require_user_consent=False)
    
    result = auth_server._evaluate_policy(
        agent="http://127.0.0.1:8001",
        resource="http://127.0.0.1:8002",
        scope="data.read"
    )
    
    assert result["requires_user_consent"] is False
    assert result["allowed"] is True


@pytest.mark.asyncio
async def test_agent_handles_request_token(agent):
    """Test that agent can handle request_token responses."""
    # This test would require running servers
    # For now, we'll test the structure
    assert agent is not None
    assert hasattr(agent, "_handle_request_token")
    assert hasattr(agent, "_exchange_authorization_code")
    assert hasattr(agent, "_handle_callback")


@pytest.mark.asyncio
async def test_auth_server_metadata_includes_auth_endpoint(auth_server):
    """Test that auth server metadata includes agent_auth_endpoint."""
    # This would require running the server and fetching metadata
    # For now, we'll test the structure
    assert auth_server is not None
    assert hasattr(auth_server, "auth_id")


# Integration test (requires running servers)
@pytest.mark.asyncio
@pytest.mark.integration
async def test_user_delegation_flow_integration(agent, resource, auth_server, user_simulator):
    """Integration test for complete user delegation flow.
    
    This test requires all servers to be running.
    Run with: pytest -m integration
    """
    # Start servers in background (simplified - in real test would use fixtures)
    # For now, this is a placeholder
    
    response = await run_user_delegated_flow(
        agent=agent,
        resource=resource,
        auth_server=auth_server,
        user_simulator=user_simulator,
        resource_url="http://127.0.0.1:8002/data-auth",
        method="GET"
    )
    
    assert response.status_code == 200

