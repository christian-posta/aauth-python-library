"""Tests for Phase 4: User Delegation."""

import json

import pytest
from starlette.testclient import TestClient

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


def test_create_pending_request_returns_202_with_interaction_code(auth_server):
    """When consent is required, pending state uses 202 + Location + interaction code (SPEC_UPDATED 10, 11.3)."""
    agent_jwk = {"kty": "OKP", "crv": "Ed25519", "x": "11"}
    resp = auth_server._create_pending_request(
        agent_id="http://127.0.0.1:8001",
        resource_id="http://127.0.0.1:8002",
        scope="data.read",
        agent_jwk=agent_jwk,
    )
    assert resp.status_code == 202
    body = json.loads(resp.body.decode())
    assert body["status"] == "pending"
    assert body["location"]
    assert body["require"] == "interaction"
    assert body["code"]
    assert len(auth_server.pending_requests) == 1
    pending_id = next(iter(auth_server.pending_requests))
    stored = auth_server.pending_requests[pending_id]
    assert stored["interaction_code"] == body["code"]
    assert stored["status"] == "pending"


def test_auth_server_metadata_includes_token_and_interaction_endpoints(auth_server):
    """Metadata exposes token_endpoint and interaction_endpoint (SPEC_UPDATED 13.2), not legacy agent/auth paths."""
    client = TestClient(auth_server.app)
    r = client.get("/.well-known/aauth-issuer.json")
    assert r.status_code == 200
    data = r.json()
    assert data["issuer"] == auth_server.auth_id
    assert "token_endpoint" in data
    assert "interaction_endpoint" in data
    assert str(data["interaction_endpoint"]).rstrip("/").endswith("interact")
    assert "jwks_uri" in data


@pytest.mark.asyncio
async def test_user_simulator_complete_flow(user_simulator):
    """Test user simulator can complete the consent flow."""
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
async def test_agent_supports_deferred_token_flow(agent):
    """Agent handles 202 deferred responses and token requests (no request_token / code exchange)."""
    assert agent is not None
    assert hasattr(agent, "_handle_deferred_response")
    assert hasattr(agent, "_request_auth_token")


# Integration test (requires running servers)
@pytest.mark.asyncio
@pytest.mark.integration
async def test_user_delegation_flow_integration(agent, resource, auth_server, user_simulator):
    """Integration test for complete user delegation flow.

    This test requires all servers to be running.
    Run with: pytest -m integration
    """
    response = await run_user_delegated_flow(
        agent=agent,
        resource=resource,
        auth_server=auth_server,
        user_simulator=user_simulator,
        resource_url="http://127.0.0.1:8002/data-auth",
        method="GET"
    )

    assert response.status_code == 200
