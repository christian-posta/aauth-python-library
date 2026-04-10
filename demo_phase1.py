"""Demo script for Phase 1: Pseudonymous flow."""

import asyncio
import httpx
from participants.agent import Agent
from participants.resource import Resource
import uvicorn
import threading
import time


async def run_phase1_demo():
    """Run Phase 1 demo: Agent signs request, resource validates."""
    print("=" * 60)
    print("Phase 1 Demo: Pseudonymous Flow (sig=hwk)")
    print("401 challenges use Signature-Requirement: requirement=pseudonym (or identity).")
    print("=" * 60)
    
    # Create participants
    agent = Agent("https://agent.example", port=8001)
    resource = Resource("https://resource.example", port=8002)
    
    # Start resource server in background thread
    print("\n1. Starting resource server on port 8002...")
    resource_thread = threading.Thread(
        target=lambda: uvicorn.run(
            resource.app,
            host="0.0.0.0",
            port=8002,
            log_level="error"
        ),
        daemon=True
    )
    resource_thread.start()
    
    # Wait for server to start
    await asyncio.sleep(2)
    print("   ✓ Resource server running")
    
    # Test 1: Unsigned request (should fail)
    print("\n2. Testing unsigned request (should fail)...")
    async with httpx.AsyncClient() as client:
        response = await client.get("http://localhost:8002/data")
        print(f"   Status: {response.status_code}")
        if response.status_code == 401:
            print("   ✓ Correctly rejected unsigned request")
        else:
            print(f"   ✗ Unexpected status: {response.status_code}")
    
    # Test 2: Signed request (should succeed)
    print("\n3. Testing signed request (should succeed)...")
    response = await agent.request_resource(
        resource_url="http://localhost:8002/data",
        method="GET"
    )
    print(f"   Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"   ✓ Request successful!")
        print(f"   Response: {data['message']}")
        print(f"   Scheme: {data['scheme']}")
    else:
        print(f"   ✗ Request failed: {response.status_code}")
        print(f"   Response: {response.text}")
    
    # Test 3: POST request with body
    print("\n4. Testing POST request with body...")
    body = b'{"action": "create", "data": "test data"}'
    response = await agent.request_resource(
        resource_url="http://localhost:8002/data",
        method="POST",
        headers={"Content-Type": "application/json"},
        body=body
    )
    print(f"   Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"   ✓ POST request successful!")
        print(f"   Method: {data['method']}")
    else:
        print(f"   ✗ POST request failed: {response.status_code}")
        print(f"   Response: {response.text}")
    
    print("\n" + "=" * 60)
    print("Phase 1 Demo Complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(run_phase1_demo())

