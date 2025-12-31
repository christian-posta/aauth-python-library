"""Tests for Phase 1: Pseudonymous flow with sig=hwk."""

import pytest
import httpx
from participants.agent import Agent
from participants.resource import Resource
import asyncio


@pytest.fixture
def agent():
    """Create an agent instance."""
    return Agent("https://agent.example", port=8001)


@pytest.fixture
def resource():
    """Create a resource instance."""
    return Resource("https://resource.example", port=8002)


@pytest.mark.asyncio
async def test_phase1_pseudonymous_flow(agent, resource):
    """Test Phase 1: Agent signs request with sig=hwk, resource validates."""
    import uvicorn
    import threading
    
    # Start resource server in background
    resource_thread = threading.Thread(
        target=lambda: uvicorn.run(resource.app, host="0.0.0.0", port=8002, log_level="error"),
        daemon=True
    )
    resource_thread.start()
    
    # Wait for server to start
    await asyncio.sleep(1)
    
    # Agent makes signed request to resource
    response = await agent.request_resource(
        resource_url="http://localhost:8002/data",
        method="GET"
    )
    
    # Should succeed with valid signature
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Access granted"
    assert data["scheme"] == "hwk"


@pytest.mark.asyncio
async def test_phase1_unsigned_request_fails(resource):
    """Test that unsigned requests are rejected."""
    import uvicorn
    import threading
    
    # Start resource server in background
    resource_thread = threading.Thread(
        target=lambda: uvicorn.run(resource.app, host="0.0.0.0", port=8002, log_level="error"),
        daemon=True
    )
    resource_thread.start()
    
    # Wait for server to start
    await asyncio.sleep(1)
    
    # Make unsigned request
    async with httpx.AsyncClient() as client:
        response = await client.get("http://localhost:8002/data")
    
    # Should be rejected
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_phase1_post_request(agent, resource):
    """Test Phase 1 with POST request and body."""
    import uvicorn
    import threading
    
    # Start resource server in background
    resource_thread = threading.Thread(
        target=lambda: uvicorn.run(resource.app, host="0.0.0.0", port=8002, log_level="error"),
        daemon=True
    )
    resource_thread.start()
    
    # Wait for server to start
    await asyncio.sleep(1)
    
    # Agent makes signed POST request with body
    body = b'{"action": "create", "data": "test"}'
    response = await agent.request_resource(
        resource_url="http://localhost:8002/data",
        method="POST",
        headers={"Content-Type": "application/json"},
        body=body
    )
    
    # Should succeed with valid signature
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Access granted"
    assert data["method"] == "POST"

