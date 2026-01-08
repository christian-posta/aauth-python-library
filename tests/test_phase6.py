"""Tests for Phase 6: Agent Delegation."""

import pytest
import asyncio
import threading
import time
from participants.agent import Agent
from participants.agent_delegate import AgentDelegate
from participants.resource import Resource
from participants.auth_server import AuthServer
from core.tokens import parse_token_claims, verify_agent_token


def run_server(server):
    """Run a server in a separate thread."""
    try:
        server.run()
    except:
        pass


@pytest.fixture
def agent_server_id():
    return "http://127.0.0.1:8001"


@pytest.fixture
def resource_id():
    return "http://127.0.0.1:8002"


@pytest.fixture
def auth_id():
    return "http://127.0.0.1:8003"


@pytest.fixture
def delegate_sub():
    return "delegate-1"


@pytest.fixture
def agent_server(agent_server_id):
    return Agent(agent_server_id, port=8001, use_user_simulator=True)


@pytest.fixture
def delegate(agent_server_id, delegate_sub):
    return AgentDelegate(agent_server_id, delegate_sub, port=None)


@pytest.fixture
def resource(resource_id, auth_id):
    return Resource(resource_id, port=8002, auth_server=auth_id)


@pytest.fixture
def auth_server(auth_id):
    return AuthServer(auth_id, port=8003, require_user_consent=False)


@pytest.mark.asyncio
async def test_agent_token_creation(agent_server, delegate, agent_server_id, delegate_sub):
    """Test that agent server can issue agent tokens to delegates."""
    # Start agent server in background
    agent_thread = threading.Thread(target=run_server, args=(agent_server,), daemon=True)
    agent_thread.start()
    
    # Wait for server to start
    await asyncio.sleep(1)
    
    try:
        # Request agent token
        agent_token = await delegate.request_agent_token()
        
        # Verify token was obtained
        assert agent_token is not None, "Agent token should be obtained"
        
        # Parse token claims
        claims = parse_token_claims(agent_token)
        payload = claims["payload"]
        header = claims["header"]
        
        # Verify token type
        assert header.get("typ") == "agent+jwt", "Token type should be agent+jwt"
        
        # Verify issuer is agent server
        assert payload.get("iss") == agent_server_id, "iss should be agent server identifier"
        
        # Verify delegate identifier
        assert payload.get("sub") == delegate_sub, "sub should be delegate identifier"
        
        # Verify cnf.jwk is present
        assert "cnf" in payload, "cnf claim should be present"
        assert "jwk" in payload["cnf"], "cnf.jwk should be present"
        
    finally:
        pass


@pytest.mark.asyncio
async def test_agent_token_validation(agent_server, delegate, agent_server_id, delegate_sub):
    """Test that agent tokens can be validated correctly."""
    # Start agent server in background
    agent_thread = threading.Thread(target=run_server, args=(agent_server,), daemon=True)
    agent_thread.start()
    
    # Wait for server to start
    await asyncio.sleep(1)
    
    try:
        # Request agent token
        agent_token = await delegate.request_agent_token()
        assert agent_token is not None
        
        # Create JWKS fetcher
        def jwks_fetcher(issuer_url: str):
            import httpx
            from core.metadata import fetch_metadata
            try:
                metadata_url = f"{issuer_url}/.well-known/aauth-agent"
                metadata = fetch_metadata(metadata_url)
                jwks_uri = metadata.get("jwks_uri")
                if not jwks_uri:
                    return None
                response = httpx.get(jwks_uri, timeout=10.0)
                response.raise_for_status()
                return response.json()
            except:
                return None
        
        # Verify agent token
        claims = verify_agent_token(
            token=agent_token,
            jwks_fetcher=jwks_fetcher,
            expected_aud=None
        )
        
        # Verify claims
        assert claims.get("iss") == agent_server_id
        assert claims.get("sub") == delegate_sub
        assert "cnf" in claims
        assert "jwk" in claims["cnf"]
        
    finally:
        pass


@pytest.mark.asyncio
async def test_delegate_resource_access(agent_server, delegate, resource, agent_server_id, delegate_sub, resource_id):
    """Test that delegate can access resource using agent token."""
    # Start servers in background
    agent_thread = threading.Thread(target=run_server, args=(agent_server,), daemon=True)
    resource_thread = threading.Thread(target=run_server, args=(resource,), daemon=True)
    
    agent_thread.start()
    resource_thread.start()
    
    # Wait for servers to start
    await asyncio.sleep(1)
    
    try:
        # Request agent token
        agent_token = await delegate.request_agent_token()
        assert agent_token is not None
        
        # Access resource using agent token
        resource_url = f"{resource_id}/data-jwks"
        response = await delegate.request_resource(resource_url)
        
        # Verify access was granted
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        
        response_data = response.json()
        assert response_data.get("scheme") == "jwt", "Response should indicate jwt scheme was used"
        
    finally:
        pass

